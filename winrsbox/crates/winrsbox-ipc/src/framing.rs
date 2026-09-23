//! Length-prefixed bincode framing for the hook↔launcher pipe protocol.
//!
//! Split out of lib.rs (the framing helpers now live with their tests;
//! lib.rs keeps the protocol types, `IpcError` and the shared session
//! config, re-exporting the wire surface exactly as before). Alongside the
//! classic allocating `write_msg`/`read_msg` pair this module offers
//! `write_msg_with_buf`/`read_msg_with_buf`, which reuse caller-owned
//! scratch buffers so steady-state IPC traffic stops allocating — and
//! pre-zeroing — a fresh Vec per frame. The MAX_MSG_LEN guards and their
//! error texts are shared by every path via `encode_msg_into` /
//! `frame_len_guard` / `decode_frame`, so the policy cannot drift.

use std::io::{self, Read, Write};
use serde::{Deserialize, Serialize};
use crate::IpcError;

pub const MAX_MSG_LEN: usize = 16 * 1024 * 1024;

/// Soft cap for reusable scratch buffers: a single huge frame may
/// transiently grow a buffer beyond this, but capacity is shrunk back so
/// a 16 MiB peak is never pinned per connection/slot (review invariant).
pub(crate) const SCRATCH_SOFT_CAP: usize = 256 * 1024;

/// Release transient peak capacity above [`SCRATCH_SOFT_CAP`]. Must be
/// called on a scratch buffer that no longer carries frame bytes (i.e.
/// after a clear): `Vec::shrink_to` never drops capacity below the current
/// length, so shrinking a buffer still holding the body would pin it.
pub(crate) fn shrink_scratch(buf: &mut Vec<u8>) {
    if buf.capacity() > SCRATCH_SOFT_CAP {
        buf.shrink_to(SCRATCH_SOFT_CAP);
    }
}

/// Encode + size-guard shared by `encode_msg`, `write_msg`,
/// `write_msg_with_buf` and the timed client write path
/// (`SyncClient::send_with_timeout`) so the MAX_MSG_LEN policy and its
/// error text cannot drift between the legacy and buffer-reusing paths.
/// `enc` is cleared first and the encoded body is appended into whatever
/// spare capacity it already has.
pub(crate) fn encode_msg_into<T: Serialize>(msg: &T, enc: &mut Vec<u8>) -> Result<(), IpcError> {
    enc.clear();
    bincode::serde::encode_into_std_write(msg, enc, bincode::config::standard())
        .map_err(|e| IpcError::Encode(e.to_string()))?;
    if enc.len() > MAX_MSG_LEN {
        return Err(IpcError::Encode(format!("message too large to send: {} bytes (max {MAX_MSG_LEN})", enc.len())));
    }
    Ok(())
}

/// Legacy all-in-one encode (allocates a fresh Vec); the guard policy is
/// `encode_msg_into`.
pub(crate) fn encode_msg<T: Serialize>(msg: &T) -> Result<Vec<u8>, IpcError> {
    let mut bytes = Vec::new();
    encode_msg_into(msg, &mut bytes)?;
    Ok(bytes)
}

/// Reject a length prefix that is larger than we are ever willing to
/// allocate for. Shared by `read_msg` and the timed client read path so the
/// "message too large" Decode message stays identical on both.
pub(crate) fn frame_len_guard(len: usize) -> Result<(), IpcError> {
    if len > MAX_MSG_LEN {
        return Err(IpcError::Decode(format!("message too large: {len} bytes (max {MAX_MSG_LEN})")));
    }
    Ok(())
}

/// Decode one body buffer. Shared by `read_msg` and the timed client read
/// path (a zero-length body errors here exactly as it does in `read_msg`,
/// via bincode — there is no separate empty-body special case). The
/// MAX_MSG_LEN decode limit is the inner defence: `frame_len_guard` only
/// covers the outer frame length, and this bound is what stops hostile
/// nested length prefixes from translating into huge allocations.
pub(crate) fn decode_frame<T: for<'de> Deserialize<'de>>(buf: &[u8]) -> Result<T, IpcError> {
    let (val, _) = bincode::serde::decode_from_slice(
        buf,
        bincode::config::standard().with_limit::<MAX_MSG_LEN>(),
    )
    .map_err(|e| IpcError::Decode(e.to_string()))?;
    Ok(val)
}

/// Write a length-prefixed bincode message.
pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<(), IpcError> {
    let bytes = encode_msg(msg)?;
    let len = bytes.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&bytes)?;
    Ok(())
}

/// Read a length-prefixed bincode message.
pub fn read_msg<R: Read, T: for<'de> Deserialize<'de>>(r: &mut R) -> Result<T, IpcError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    frame_len_guard(len)?;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    decode_frame(&buf)
}

/// [`read_msg`] into a caller-owned scratch buffer: reuses the buffer's
/// spare capacity across messages instead of allocating (and pre-zeroing) a
/// fresh Vec per frame. Wire behaviour, guard policy and error variants are
/// identical to `read_msg`. On return the buffer is empty, with capacity
/// capped at [`SCRATCH_SOFT_CAP`] so a one-off huge frame is never pinned
/// for the life of the connection.
pub fn read_msg_with_buf<R: Read, T: for<'de> Deserialize<'de>>(r: &mut R, buf: &mut Vec<u8>) -> Result<T, IpcError> {
    buf.clear();
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    frame_len_guard(len)?;
    // Append into spare capacity instead of pre-zeroing a fresh alloc:
    // `take` bounds the read at exactly one frame even if the peer keeps
    // talking, and the length check below catches a short read.
    r.take(len as u64).read_to_end(buf)?;
    if buf.len() != len {
        return Err(IpcError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("truncated frame: read {} of {len} bytes", buf.len()),
        )));
    }
    let val = decode_frame(buf)?;
    // Shrink only once the frame bytes are gone (`shrink_to` never drops
    // capacity below len): a >SCRATCH_SOFT_CAP peak must be released.
    buf.clear();
    shrink_scratch(buf);
    Ok(val)
}

/// [`write_msg`] with a caller-owned encode scratch buffer: encodes into
/// `enc`, reusing its spare capacity across messages, then emits the same
/// two `write_all` calls (prefix, body) as `write_msg` — no syscall
/// behaviour change. The size guard and error text are the shared
/// `encode_msg_into` policy.
pub fn write_msg_with_buf<W: Write, T: Serialize>(w: &mut W, msg: &T, enc: &mut Vec<u8>) -> Result<(), IpcError> {
    if let Err(e) = encode_msg_into(msg, enc) {
        // An oversized encode can transiently have grown `enc` past the
        // soft cap; release it so the failure is not pinned (see the
        // SCRATCH_SOFT_CAP review invariant).
        enc.clear();
        shrink_scratch(enc);
        return Err(e);
    }
    let len = enc.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(enc)?;
    enc.clear();
    shrink_scratch(enc);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use crate::{AllocKind, InjectKind, LogLevel, Req, Resp};

    #[test]
    fn req_hello_roundtrip() {
        let msg = Req::Hello { pid: 42, exe_path: r"c:\app.exe".into() };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec {
            Req::Hello { pid, exe_path } => {
                assert_eq!(pid, 42);
                assert_eq!(exe_path, r"c:\app.exe");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn req_spawned_child_roundtrip() {
        let msg = Req::SpawnedChild { parent_pid: 1, child_pid: 2, child_exe: "child.exe".into() };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec {
            Req::SpawnedChild { parent_pid, child_pid, child_exe } => {
                assert_eq!(parent_pid, 1);
                assert_eq!(child_pid, 2);
                assert_eq!(child_exe, "child.exe");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn req_decide_roundtrip() {
        let msg = Req::Decide { dos_path: r"c:\x".into(), write: true };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec {
            Req::Decide { dos_path, write } => {
                assert_eq!(dos_path, r"c:\x");
                assert!(write);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn req_record_overlay_roundtrip() {
        let msg = Req::RecordOverlay { orig: "a".into(), overlay: "b".into() };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec {
            Req::RecordOverlay { orig, overlay } => {
                assert_eq!(orig, "a");
                assert_eq!(overlay, "b");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn req_log_roundtrip() {
        let msg = Req::Log { pid: 42, level: LogLevel::Warn, msg: "hi".into() };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec {
            Req::Log { pid, level, msg } => {
                assert_eq!(pid, 42);
                assert!(matches!(level, LogLevel::Warn));
                assert_eq!(msg, "hi");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn req_register_child_roundtrip() {
        let msg = Req::RegisterChild { pid: 7 };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec {
            Req::RegisterChild { pid } => assert_eq!(pid, 7),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_ok_roundtrip() {
        let msg = Resp::Ok;
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Resp = read_msg(&mut buf).unwrap();
        assert!(matches!(dec, Resp::Ok));
    }

    #[test]
    fn resp_decision_roundtrip() {
        let msg = Resp::Decision(policy::Decision {
            mode: policy::Mode::Cow,
            overlay: Some(std::path::PathBuf::from(r"\sb\c\x")),
            cow_from: None,
            mock_payload: None,
        });
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Resp = read_msg(&mut buf).unwrap();
        match dec {
            Resp::Decision(d) => {
                assert_eq!(d.mode, policy::Mode::Cow);
                assert_eq!(d.overlay.unwrap(), std::path::PathBuf::from(r"\sb\c\x"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_err_roundtrip() {
        let msg = Resp::Err("boom".into());
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Resp = read_msg(&mut buf).unwrap();
        match dec {
            Resp::Err(e) => assert_eq!(e, "boom"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn req_memory_violation_roundtrip() {
        let msg = Req::MemoryViolation {
            pid: 123,
            exe: r"c:\app.exe".into(),
            kind: AllocKind::Allocate,
            requested_protect: 0x40,
            region_size: 4096,
            target_address: 0x7ff800000000,
            caller_pc: 0x7ff8a1234567,
            caller_module: Some(r"c:\windows\system32\ntdll.dll".into()),
            stack_top: vec![0x7ff8a1234567, 0x7ff8a1234568],
        };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec {
            Req::MemoryViolation { pid, kind, requested_protect, stack_top, .. } => {
                assert_eq!(pid, 123);
                assert_eq!(kind, AllocKind::Allocate);
                assert_eq!(requested_protect, 0x40);
                assert_eq!(stack_top.len(), 2);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn req_escape_violation_roundtrip() {
        let msg = Req::EscapeViolation {
            pid: 321,
            exe: r"c:\app\evil.exe".into(),
            vector: "alpc-port".into(),
            detail: r"\RPC Control\OLE58BCCC182C1065EBB0".into(),
            caller_pc: 0x7ff8a1234567,
            caller_module: Some(r"c:\windows\system32\combase.dll".into()),
            stack_top: vec![0x7ff8a1234567, 0x7ff8a1234568],
        };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec {
            Req::EscapeViolation { pid, vector, detail, stack_top, .. } => {
                assert_eq!(pid, 321);
                assert_eq!(vector, "alpc-port");
                assert_eq!(detail, r"\RPC Control\OLE58BCCC182C1065EBB0");
                assert_eq!(stack_top.len(), 2);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn req_injection_violation_roundtrip() {
        let msg = Req::InjectionViolation {
            pid: 100,
            exe: r"c:\app\evil.exe".into(),
            kind: InjectKind::ContextHijack,
            target_pid: 200,
            start_address: 0xDEADBEEF,
            caller_pc: 0x7ff8a1234567,
            caller_module: Some(r"c:\app\evil.exe".into()),
            stack_top: vec![0x7ff8a1234567],
        };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec {
            Req::InjectionViolation { pid, kind, target_pid, .. } => {
                assert_eq!(pid, 100);
                assert_eq!(kind, InjectKind::ContextHijack);
                assert_eq!(target_pid, 200);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn read_msg_oversized_returns_decode() {
        let mut buf = Cursor::new(Vec::new());
        let len = (MAX_MSG_LEN as u32) + 1;
        buf.write_all(&len.to_le_bytes()).unwrap();
        buf.write_all(&[0u8; 64]).unwrap();
        buf.set_position(0);
        let res: Result<Req, IpcError> = read_msg(&mut buf);
        let err = res.unwrap_err();
        match err {
            IpcError::Decode(msg) => assert!(msg.contains("too large"), "got: {msg}"),
            other => panic!("expected Decode, got: {other:?}"),
        }
    }

    #[test]
    fn read_msg_truncated_returns_io() {
        let mut buf = Cursor::new(Vec::new());
        buf.write_all(&100u32.to_le_bytes()).unwrap();
        buf.set_position(0);
        let res: Result<Req, IpcError> = read_msg(&mut buf);
        assert!(res.is_err());
        match res.unwrap_err() {
            IpcError::Io(_) => {}
            other => panic!("expected Io, got: {other:?}"),
        }
    }

    #[test]
    fn req_reg_decide_roundtrip() {
        let msg = Req::RegDecide { key_path: r"hklm\software\foo".into(), value_name: Some("bar".into()), write: false };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec {
            Req::RegDecide { key_path, value_name, write } => {
                assert_eq!(key_path, r"hklm\software\foo");
                assert_eq!(value_name, Some("bar".into()));
                assert!(!write);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn req_reg_write_roundtrip() {
        use policy::reg::{RegData, RegType, RegValue};
        let val = RegValue { typ: RegType::Sz, data: RegData::String("hello".into()) };
        let msg = Req::RegWrite { key_path: "k".into(), value_name: "v".into(), value: val.clone() };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec { Req::RegWrite { value, .. } => assert_eq!(value, val), _ => panic!() }
    }

    #[test]
    fn req_net_decide_roundtrip() {
        let msg = Req::NetDecide { host: "api.github.com".into(), port: 443 };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec { Req::NetDecide { host, port } => { assert_eq!(host, "api.github.com"); assert_eq!(port, 443); }, _ => panic!() }
    }

    #[test]
    fn req_mem_decide_roundtrip() {
        let msg = Req::MemDecide { target_pid: 1234, op: "CreateRemoteThread".into() };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec { Req::MemDecide { target_pid, op } => { assert_eq!(target_pid, 1234); assert_eq!(op, "CreateRemoteThread"); }, _ => panic!() }
    }

    #[test]
    fn resp_reg_decision_roundtrip() {
        let msg = Resp::RegDecision { mode: policy::Mode::Cow, value_json: Some(vec![42]) };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Resp = read_msg(&mut buf).unwrap();
        match dec { Resp::RegDecision { mode, value_json } => { assert_eq!(mode, policy::Mode::Cow); assert_eq!(value_json, Some(vec![42])); }, _ => panic!() }
    }

    #[test]
    fn resp_net_decision_roundtrip() {
        let msg = Resp::NetDecision { allow: true };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Resp = read_msg(&mut buf).unwrap();
        match dec { Resp::NetDecision { allow } => assert!(allow), _ => panic!() }
    }

    #[test]
    fn req_clear_overlay_roundtrip() {
        let msg = Req::ClearOverlay { path: r"d:\ext\file.txt".into() };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec {
            Req::ClearOverlay { path } => assert_eq!(path, r"d:\ext\file.txt"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn req_record_whiteout_roundtrip() {
        let msg = Req::RecordWhiteout { path: r"d:\ext\file.txt".into() };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec {
            Req::RecordWhiteout { path } => assert_eq!(path, r"d:\ext\file.txt"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn req_clear_whiteout_roundtrip() {
        let msg = Req::ClearWhiteout { path: r"d:\revive.txt".into() };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec {
            Req::ClearWhiteout { path } => assert_eq!(path, r"d:\revive.txt"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn req_whiteouts_under_roundtrip() {
        let msg = Req::WhiteoutsUnder { dir: r"d:\foo".into() };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec {
            Req::WhiteoutsUnder { dir } => assert_eq!(dir, r"d:\foo"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_whiteouts_roundtrip() {
        let msg = Resp::Whiteouts(vec!["a.txt".into(), "b.log".into()]);
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Resp = read_msg(&mut buf).unwrap();
        match dec {
            Resp::Whiteouts(names) => assert_eq!(names, vec!["a.txt".to_string(), "b.log".to_string()]),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_whiteouts_empty_roundtrip() {
        let msg = Resp::Whiteouts(vec![]);
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Resp = read_msg(&mut buf).unwrap();
        match dec {
            Resp::Whiteouts(names) => assert!(names.is_empty()),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn req_overlay_children_with_case_roundtrip() {
        let msg = Req::OverlayChildrenWithCase {
            dir: r"c:\localappdata\uv\cache\builds-v0\.tmpabcd".into(),
        };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec {
            Req::OverlayChildrenWithCase { dir } => {
                assert_eq!(dir, r"c:\localappdata\uv\cache\builds-v0\.tmpabcd");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_overlay_children_with_case_roundtrip() {
        let msg = Resp::OverlayChildrenWithCase(vec![
            ("mixed_case_dir".to_string(), "Mixed_Case_Dir".to_string()),
            ("lib64".to_string(), "Lib64".to_string()),
        ]);
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Resp = read_msg(&mut buf).unwrap();
        match dec {
            Resp::OverlayChildrenWithCase(pairs) => {
                assert_eq!(pairs.len(), 2);
                assert_eq!(pairs[0], ("mixed_case_dir".to_string(), "Mixed_Case_Dir".to_string()));
                assert_eq!(pairs[1], ("lib64".to_string(), "Lib64".to_string()));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_overlay_children_with_case_empty_roundtrip() {
        let msg = Resp::OverlayChildrenWithCase(vec![]);
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Resp = read_msg(&mut buf).unwrap();
        match dec {
            Resp::OverlayChildrenWithCase(pairs) => assert!(pairs.is_empty()),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn req_record_overlay_case_roundtrip() {
        let msg = Req::RecordOverlayCase {
            path: r"c:\test\mixed_case_dir".into(),
            original_basename: "Mixed_Case_Dir".into(),
        };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec {
            Req::RecordOverlayCase { path, original_basename } => {
                assert_eq!(path, r"c:\test\mixed_case_dir");
                assert_eq!(original_basename, "Mixed_Case_Dir");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn req_overlay_children_roundtrip() {
        let msg = Req::OverlayChildren { dir: r"c:\users\computer\desktop\pc\vv".into() };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec {
            Req::OverlayChildren { dir } => assert_eq!(dir, r"c:\users\computer\desktop\pc\vv"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_overlay_children_roundtrip() {
        let msg = Resp::OverlayChildren(vec![
            policy::OverlayChildMeta {
                name: "probe_cmd.txt".to_string(),
                is_dir: false,
                size: 12,
                creation_time: 133_700_000_000_000_000,
                last_access_time: 133_700_000_000_000_000,
                last_write_time: 133_700_000_000_000_000,
            },
            policy::OverlayChildMeta {
                name: "some_dir".to_string(),
                is_dir: true,
                size: 0,
                creation_time: 133_700_000_000_000_000,
                last_access_time: 133_700_000_000_000_000,
                last_write_time: 133_700_000_000_000_000,
            },
        ]);
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Resp = read_msg(&mut buf).unwrap();
        match dec {
            Resp::OverlayChildren(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].name, "probe_cmd.txt");
                assert!(!entries[0].is_dir);
                assert_eq!(entries[0].size, 12);
                assert_eq!(entries[1].name, "some_dir");
                assert!(entries[1].is_dir);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resp_overlay_children_empty_roundtrip() {
        let msg = Resp::OverlayChildren(vec![]);
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Resp = read_msg(&mut buf).unwrap();
        match dec {
            Resp::OverlayChildren(entries) => assert!(entries.is_empty()),
            _ => panic!("wrong variant"),
        }
    }
    /// Encode a u64 as a bincode `standard()` varint: a 0xFD width-discriminant
    /// byte followed by the little-endian u64 (bincode 2.x varints are not
    /// LEB128; 0xFD is the u64 discriminator).
    fn varint_u64(v: u64) -> Vec<u8> {
        let mut out = vec![0xFD];
        out.extend_from_slice(&v.to_le_bytes());
        out
    }

    /// A hostile inner length prefix (u64::MAX) must be rejected before any
    /// huge pre-allocation: the test completing in milliseconds is the point.
    #[test]
    fn decode_frame_rejects_huge_inner_length_prefix() {
        assert_eq!(varint_u64(300), vec![0xFD, 0x2C, 0x01, 0, 0, 0, 0, 0, 0]);
        let payload = varint_u64(u64::MAX);
        let res: Result<Vec<u8>, IpcError> = decode_frame(&payload);
        match res.unwrap_err() {
            IpcError::Decode(_) => {}
            other => panic!("expected Decode, got: {other:?}"),
        }
    }

    /// One byte past the limit must also be rejected: boundary proof the cap
    /// fires just past MAX_MSG_LEN, not only at absurd values.
    #[test]
    fn decode_frame_rejects_inner_length_just_over_limit() {
        let payload = varint_u64((MAX_MSG_LEN + 1) as u64);
        let res: Result<Vec<u8>, IpcError> = decode_frame(&payload);
        match res.unwrap_err() {
            IpcError::Decode(_) => {}
            other => panic!("expected Decode, got: {other:?}"),
        }
    }

    /// In-limit payloads must be unaffected by the bounded decode config.
    #[test]
    fn decode_frame_in_limit_vec_roundtrip() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        let bytes = encode_msg(&data).unwrap();
        let dec: Vec<u8> = decode_frame(&bytes).unwrap();
        assert_eq!(dec, data);
    }

    /// Three different-size messages through ONE scratch buffer: stale bytes
    /// from the long first frame must never leak into the later short frames
    /// (each decode must match its own request), and the buffer must be
    /// released between messages while its capacity is retained for reuse.
    #[test]
    fn read_msg_with_buf_reuses_buffer_across_messages_no_leakage() {
        let long_path = format!(r"c:\{}", "very-long-distinctive-path-".repeat(12));
        let mut stream = Cursor::new(Vec::new());
        write_msg(&mut stream, &Req::Hello { pid: 1, exe_path: long_path.clone() }).unwrap();
        write_msg(&mut stream, &Req::NetDecide { host: "short".into(), port: 1 }).unwrap();
        write_msg(&mut stream, &Req::Hello { pid: 2, exe_path: r"c:\b.exe".into() }).unwrap();
        stream.set_position(0);

        let mut buf = Vec::new();
        let dec: Req = read_msg_with_buf(&mut stream, &mut buf).unwrap();
        match dec {
            Req::Hello { pid, exe_path } => {
                assert_eq!(pid, 1);
                assert_eq!(exe_path, long_path);
            }
            other => panic!("wrong variant: {other:?}"),
        }
        let long_cap = buf.capacity();
        assert!(long_cap > 256, "the long first frame should have grown the scratch");

        let dec: Req = read_msg_with_buf(&mut stream, &mut buf).unwrap();
        match dec {
            Req::NetDecide { host, port } => {
                assert_eq!(host, "short");
                assert_eq!(port, 1);
            }
            other => panic!("wrong variant: {other:?}"),
        }
        assert!(buf.is_empty(), "buffer must not carry frame bytes between messages");
        assert_eq!(buf.capacity(), long_cap, "capacity is retained for reuse, not reallocated");

        let dec: Req = read_msg_with_buf(&mut stream, &mut buf).unwrap();
        match dec {
            Req::Hello { pid, exe_path } => {
                assert_eq!(pid, 2);
                assert_eq!(exe_path, r"c:\b.exe");
            }
            other => panic!("wrong variant: {other:?}"),
        }
        assert!(buf.is_empty());
        assert_eq!(stream.position() as usize, stream.get_ref().len(), "exactly three frames in the stream");
    }

    /// One `enc` scratch across three writes into one sink: each message
    /// round-trips and the encode buffer keeps its capacity for the smaller
    /// follow-up messages (no realloc, no shrink for small frames).
    #[test]
    fn write_msg_with_buf_roundtrip_sequence_reuses_encode_buffer() {
        let long_path = format!(r"c:\{}", "encode-reuse-".repeat(24));
        let mut sink = Cursor::new(Vec::new());
        let mut enc = Vec::new();

        write_msg_with_buf(&mut sink, &Req::Hello { pid: 1, exe_path: long_path.clone() }, &mut enc).unwrap();
        let cap = enc.capacity();
        assert!(cap >= long_path.len(), "encode buffer covers the body");

        write_msg_with_buf(&mut sink, &Req::NetDecide { host: "short".into(), port: 7 }, &mut enc).unwrap();
        assert_eq!(enc.capacity(), cap, "smaller message reuses capacity, no realloc");

        write_msg_with_buf(&mut sink, &Req::RegisterChild { pid: 9 }, &mut enc).unwrap();
        assert_eq!(enc.capacity(), cap);

        sink.set_position(0);
        let mut buf = Vec::new();
        let dec: Req = read_msg_with_buf(&mut sink, &mut buf).unwrap();
        match dec {
            Req::Hello { pid, exe_path } => {
                assert_eq!(pid, 1);
                assert_eq!(exe_path, long_path);
            }
            other => panic!("wrong variant: {other:?}"),
        }
        let dec: Req = read_msg_with_buf(&mut sink, &mut buf).unwrap();
        match dec {
            Req::NetDecide { host, port } => {
                assert_eq!(host, "short");
                assert_eq!(port, 7);
            }
            other => panic!("wrong variant: {other:?}"),
        }
        let dec: Req = read_msg_with_buf(&mut sink, &mut buf).unwrap();
        match dec {
            Req::RegisterChild { pid } => assert_eq!(pid, 9),
            other => panic!("wrong variant: {other:?}"),
        }
        assert_eq!(sink.position() as usize, sink.get_ref().len(), "exactly three frames in the stream");
    }

    /// A body above SCRATCH_SOFT_CAP (~800 KiB, deterministic and bounded —
    /// not a stress test) may transiently grow the scratch, but capacity is
    /// shrunk back so the peak is never pinned in the buffer.
    #[test]
    fn read_msg_with_buf_shrinks_oversized_scratch() {
        let names: Vec<String> = (0..20_000)
            .map(|i| format!("name-{i:06}-{}.txt", "p".repeat(24)))
            .collect();
        let expected = names.clone();
        let mut stream = Cursor::new(Vec::new());
        write_msg(&mut stream, &Resp::Whiteouts(names)).unwrap();
        stream.set_position(0);

        let mut buf = Vec::new();
        let dec: Resp = read_msg_with_buf(&mut stream, &mut buf).unwrap();
        match dec {
            Resp::Whiteouts(v) => assert_eq!(v, expected),
            other => panic!("wrong variant: {other:?}"),
        }
        assert!(buf.is_empty());
        assert!(
            buf.capacity() <= SCRATCH_SOFT_CAP,
            "scratch capacity {} pinned above soft cap {SCRATCH_SOFT_CAP}",
            buf.capacity(),
        );
    }

    /// Mirror of `read_msg_truncated_returns_io` on the buffer-reusing path:
    /// a short frame is the same IpcError::Io variant.
    #[test]
    fn read_msg_with_buf_truncated_returns_io() {
        let mut buf = Cursor::new(Vec::new());
        buf.write_all(&100u32.to_le_bytes()).unwrap();
        buf.set_position(0);
        let mut scratch = Vec::new();
        let res: Result<Req, IpcError> = read_msg_with_buf(&mut buf, &mut scratch);
        assert!(res.is_err());
        match res.unwrap_err() {
            IpcError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof, "got: {e}"),
            other => panic!("expected Io, got: {other:?}"),
        }
    }

    /// Mirror of `read_msg_oversized_returns_decode` on the buffer-reusing
    /// path: the guard fires before any big allocation into the scratch.
    #[test]
    fn read_msg_with_buf_oversized_returns_decode() {
        let mut buf = Cursor::new(Vec::new());
        let len = (MAX_MSG_LEN as u32) + 1;
        buf.write_all(&len.to_le_bytes()).unwrap();
        buf.write_all(&[0u8; 64]).unwrap();
        buf.set_position(0);
        let mut scratch = Vec::new();
        let res: Result<Req, IpcError> = read_msg_with_buf(&mut buf, &mut scratch);
        let err = res.unwrap_err();
        match err {
            IpcError::Decode(msg) => assert!(msg.contains("too large"), "got: {msg}"),
            other => panic!("expected Decode, got: {other:?}"),
        }
        assert_eq!(scratch.capacity(), 0, "guard must fire before any read into the scratch");
    }
}
