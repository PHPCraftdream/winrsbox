use std::io::{self, Read, Write};
use policy::Decision;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PIPE_PREFIX: &str = r"\\.\pipe\fs-sandbox-";

pub const MAX_MSG_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub enum LogLevel { Trace, Info, Warn, Error }

#[derive(Debug, Serialize, Deserialize)]
pub enum Req {
    Hello { pid: u32, exe_path: String },
    SpawnedChild { parent_pid: u32, child_pid: u32, child_exe: String },
    Decide { dos_path: String, write: bool },
    RecordOverlay { orig: String, overlay: String },
    Log { pid: u32, level: LogLevel, msg: String },
    RegisterChild { pid: u32 },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Resp {
    Decision(Decision),
    Ok,
    Err(String),
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
}
