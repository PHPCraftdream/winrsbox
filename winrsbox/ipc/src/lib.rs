use std::io::{self, Read, Write};
use policy::Decision;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PIPE_PREFIX: &str = r"\\.\pipe\fs-sandbox-";

pub const MAX_MSG_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub enum LogLevel { Trace, Info, Warn, Error }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AllocKind {
    Allocate,
    Protect,
    MapView,
    Write,
}

impl std::fmt::Display for AllocKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allocate => f.write_str("Allocate"),
            Self::Protect => f.write_str("Protect"),
            Self::MapView => f.write_str("MapView"),
            Self::Write => f.write_str("Write"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InjectKind {
    CreateRemoteThread,
    QueueApc,
    ContextHijack,
}

impl std::fmt::Display for InjectKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreateRemoteThread => f.write_str("CreateRemoteThread"),
            Self::QueueApc => f.write_str("QueueApc"),
            Self::ContextHijack => f.write_str("ContextHijack"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Req {
    Hello { pid: u32, exe_path: String },
    SpawnedChild { parent_pid: u32, child_pid: u32, child_exe: String },
    Decide { dos_path: String, write: bool },
    RecordOverlay { orig: String, overlay: String },
    Log { pid: u32, level: LogLevel, msg: String },
    RegisterChild { pid: u32 },
    InjectionViolation {
        pid: u32,
        exe: String,
        kind: InjectKind,
        target_pid: u32,
        start_address: u64,
        caller_pc: u64,
        caller_module: Option<String>,
        stack_top: Vec<u64>,
    },
    PreLaunchViolation {
        launcher_pid: u32,
        target_exe: String,
        hits: Vec<(u64, String)>, // (offset, kind name)
    },
    MemoryViolation {
        pid: u32,
        exe: String,
        kind: AllocKind,
        requested_protect: u32,
        region_size: u64,
        target_address: u64,
        caller_pc: u64,
        caller_module: Option<String>,
        stack_top: Vec<u64>,
    },
    RegDecide { key_path: String, value_name: Option<String>, write: bool },
    RegWrite { key_path: String, value_name: String, value_json: Vec<u8> },
    RegDeleteValue { key_path: String, value_name: String },
    RegDeleteKey { key_path: String },
    NetDecide { host: String, port: u16 },
    MemDecide { target_pid: u32, op: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Resp {
    Decision(Decision),
    Ok,
    Err(String),
    RegDecision { mode: String, value_json: Option<Vec<u8>> },
    NetDecision { allow: bool },
    MemDecision { allow: bool },
}

#[derive(Error, Debug)]
pub enum IpcError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("encode: {0}")]
    Encode(String),
    #[error("decode: {0}")]
    Decode(String),
}

/// Write a length-prefixed bincode message.
pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<(), IpcError> {
    let bytes = bincode::serde::encode_to_vec(msg, bincode::config::standard())
        .map_err(|e| IpcError::Encode(e.to_string()))?;
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
    if len > MAX_MSG_LEN {
        return Err(IpcError::Decode(format!("message too large: {len} bytes (max {MAX_MSG_LEN})")));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    let (val, _) = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
        .map_err(|e| IpcError::Decode(e.to_string()))?;
    Ok(val)
}

/// Sync IPC client (для hook.dll — без tokio).
pub struct SyncClient {
    pipe: std::fs::File,
}

impl SyncClient {
    /// Открыть соединение к launcher pipe. Retry до 10 раз с 50ms паузой.
    pub fn connect(pipe_name: &str) -> Result<Self, IpcError> {
        for _ in 0..10 {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(pipe_name)
            {
                Ok(f) => return Ok(Self { pipe: f }),
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
        Err(IpcError::Io(io::Error::new(io::ErrorKind::TimedOut, "pipe connect timeout")))
    }

    pub fn send(&mut self, req: &Req) -> Result<Resp, IpcError> {
        write_msg(&mut self.pipe, req)?;
        read_msg(&mut self.pipe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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
        buf.write_all(&vec![0u8; 64]).unwrap();
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
        let msg = Req::RegWrite { key_path: "k".into(), value_name: "v".into(), value_json: vec![1,2,3] };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Req = read_msg(&mut buf).unwrap();
        match dec { Req::RegWrite { value_json, .. } => assert_eq!(value_json, vec![1,2,3]), _ => panic!() }
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
        let msg = Resp::RegDecision { mode: "cow".into(), value_json: Some(vec![42]) };
        let mut buf = Cursor::new(Vec::new());
        write_msg(&mut buf, &msg).unwrap();
        buf.set_position(0);
        let dec: Resp = read_msg(&mut buf).unwrap();
        match dec { Resp::RegDecision { mode, value_json } => { assert_eq!(mode, "cow"); assert_eq!(value_json, Some(vec![42])); }, _ => panic!() }
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
}
