use std::io;
use policy::Decision;
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod guard_level;
pub use guard_level::GuardLevel;

mod sync_client;
mod timed_pipe;
pub use sync_client::{CONNECT_RETRY_ATTEMPTS, CONNECT_RETRY_INTERVAL_MS, SEND_TIMEOUT, SyncClient};

// Wire framing lives in `framing` with its tests; the pub surface is
// re-exported here unchanged (`ipc::write_msg`/`read_msg`/`MAX_MSG_LEN`),
// and the crate-internal helpers stay `pub(crate)`.
mod framing;
pub use framing::{read_msg, read_msg_with_buf, write_msg, write_msg_with_buf, MAX_MSG_LEN};
pub(crate) use framing::{decode_frame, encode_msg_into, frame_len_guard};

pub const PIPE_PREFIX: &str = r"\\.\pipe\fs-sandbox-";
// ─── Session-config shared section ────────────────────────────────────────────
//
// Some hosted processes lose `FS_SANDBOX_*` environment variables — most
// reliably reproducible under MSYS2 first-run setup, where helper child
// processes inherit a scrubbed environment. The hook needs PIPE_NAME and
// friends regardless. We publish them via a small named shared section so
// every hooked process in the same Windows session can read them without
// depending on inherited env vars.
//
// `Local\` namespace = session-scoped (per Windows logon session). No
// SeCreateGlobalPrivilege required, no cross-session leakage.
pub const SESSION_CONFIG_SECTION_NAME: &str = "Local\\WinRsBoxSession";
pub const SESSION_CONFIG_SECTION_SIZE: usize = 4096;
/// "WRSB" little-endian.
pub const SESSION_CONFIG_MAGIC: u32 = 0x42535257;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionConfig {
    pub pipe_name: String,
    pub dll_path: String,
    pub cwd: String,
    /// Absolute path of the sandbox overlay storage dir (where CoW files and
    /// policy.redb live). Published so the hook can recognise overlay paths
    /// on delete and convert them back to virtual DOS paths via
    /// `policy::path::unmirror_from_overlay`.
    ///
    /// When the overlay spans multiple volumes (same-volume overlay layout),
    /// `overlay_roots` carries the full per-drive root list; `sandbox_root`
    /// remains the primary (project-drive) root for backward compat.
    #[serde(default)]
    pub sandbox_root: String,
    /// All overlay roots (per-drive, same-volume layout). Non-empty = multi-
    /// volume layout; the hook masks paths against EVERY root and derives the
    /// drive letter from the root that matched. When empty, the hook falls
    /// back to `sandbox_root` (legacy single-root behaviour).
    #[serde(default)]
    pub overlay_roots: Vec<String>,
    pub trace: bool,
    pub guard: GuardLevel,
    /// Identity of the launcher process that authored this section and owns
    /// the pipe: the hook verifies the pipe server's PID (and its kernel
    /// creation time, defending against PID reuse) against these before
    /// trusting any response. Defaults keep pre-identity sections decodable.
    #[serde(default)]
    pub launcher_pid: u32,
    #[serde(default)]
    pub launcher_create_time: u64,
    pub allow_rwx: bool,
    pub disable_hooks: String,
}

impl SessionConfig {
    /// Encode for writing to the shared section: 4-byte magic, 4-byte body
    /// length, then bincode body. Fails if the encoded size would exceed the
    /// shared section reserve.
    pub fn to_section_bytes(&self) -> Result<Vec<u8>, IpcError> {
        let body = bincode::serde::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| IpcError::Encode(e.to_string()))?;
        if 8 + body.len() > SESSION_CONFIG_SECTION_SIZE {
            return Err(IpcError::Encode(format!(
                "session config encodes to {} bytes, max {}",
                8 + body.len(),
                SESSION_CONFIG_SECTION_SIZE,
            )));
        }
        let mut out = Vec::with_capacity(8 + body.len());
        out.extend_from_slice(&SESSION_CONFIG_MAGIC.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode from raw section bytes. Validates magic + body length so a
    /// torn / uninitialised section yields a `Decode` error rather than UB.
    /// The MAX_MSG_LEN decode limit is the inner defence: the outer body
    /// length is already guarded, and this bound stops hostile nested length
    /// prefixes inside the body from becoming huge allocations.
    pub fn from_section_bytes(buf: &[u8]) -> Result<Self, IpcError> {
        if buf.len() < 8 {
            return Err(IpcError::Decode("session section too short".into()));
        }
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != SESSION_CONFIG_MAGIC {
            return Err(IpcError::Decode(format!(
                "session section magic mismatch: 0x{magic:08x}",
            )));
        }
        let len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
        if len == 0 || 8 + len > buf.len() {
            return Err(IpcError::Decode(format!(
                "session section body length {len} invalid",
            )));
        }
        let (cfg, _) = bincode::serde::decode_from_slice(
            &buf[8..8 + len],
            bincode::config::standard().with_limit::<MAX_MSG_LEN>(),
        )
        .map_err(|e| IpcError::Decode(e.to_string()))?;
        Ok(cfg)
    }
}

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
    /// Record the original-case basename for an overlay entry.
    /// Sent immediately after `RecordOverlay` when the caller has access
    /// to the original-case path. The policy daemon stores the basename
    /// in `OVERLAY_CASE` so the directory-enumeration hook can restore
    /// original case for overlay-only directories (e.g. uv's temp build
    /// envs that exist only inside the sandbox).
    RecordOverlayCase { path: String, original_basename: String },
    /// Remove an OVERLAY_IDX entry. Called when an overlay copy is physically
    /// deleted so the index doesn't keep pointing at a missing file (which
    /// would defeat a concurrent whiteout).
    ClearOverlay { path: String },
    /// Record a whiteout (tombstone) for a virtual path. Hides the real lower
    /// file from the sandbox view without touching the real disk.
    RecordWhiteout { path: String },
    /// Clear a whiteout marker (revive) — called when a create re-materialises
    /// a previously-deleted path in the overlay.
    ClearWhiteout { path: String },
    /// Return the filenames of whiteouted direct children of `dir`.
    WhiteoutsUnder { dir: String },
    /// Return `(lowercase_name, original_case_name)` pairs for overlay entries
    /// that are direct children of `dir` AND have a recorded original-case
    /// basename. Used by the hook's `build_case_map` to restore case for
    /// overlay-only directories that have no real-disk counterpart.
    OverlayChildrenWithCase { dir: String },
    /// Return `(basename, is_dir)` pairs for ALL overlay entries (OVERLAY_IDX)
    /// that are direct children of `dir`, regardless of case-record presence.
    /// Used by the enum-hook to inject overlay-only files/dirs into a real
    /// directory's listing (the "passthrough directory with sparse overlay
    /// children" merge that `physical_overlay_path` defers to enumeration for).
    OverlayChildren { dir: String },
    Log { pid: u32, level: LogLevel, msg: String },
    RegisterChild { pid: u32 },
    RecordCleanImage { key: String },
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
    /// A sandboxed process tried to reach an escape-class endpoint that has no
    /// legitimate use from inside the sandbox — a COM-activation / DCOM /
    /// WMI / privilege-escalation / persistence broker, whether via a denied
    /// CLSID activation (`vector = "com-clsid"`, `detail` = class name) or a
    /// direct ALPC connect to the broker port (`vector = "alpc-port"`, `detail`
    /// = port name). The hook treats this as a deliberate containment-escape
    /// attempt and self-terminates the process (fail-stop) rather than merely
    /// denying — a denied process just keeps probing other vectors. Reported so
    /// the launcher counts it as a violation and records it for forensics.
    EscapeViolation {
        pid: u32,
        exe: String,
        vector: String,
        detail: String,
        caller_pc: u64,
        caller_module: Option<String>,
        stack_top: Vec<u64>,
    },
    RegDecide { key_path: String, value_name: Option<String>, write: bool },
    RegWrite { key_path: String, value_name: String, value: policy::reg::RegValue },
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
    RegDecision { mode: policy::Mode, value_json: Option<Vec<u8>> },
    NetDecision { allow: bool },
    MemDecision { allow: bool },
    /// Filenames of whiteouted direct children of a directory (for enumerate hiding).
    /// The server caps the per-call listing size (enforced launcher-side in
    /// pipe_server): oversized listings come back truncated to a prefix,
    /// never as an error.
    Whiteouts(Vec<String>),
    /// `(lowercase_name, original_case_name)` pairs for overlay entries that are
    /// direct children of the queried directory and have a recorded case.
    /// The server caps the per-call listing size (enforced launcher-side in
    /// pipe_server): oversized listings come back truncated to a prefix,
    /// never as an error.
    OverlayChildrenWithCase(Vec<(String, String)>),
    /// `(basename, is_dir)` pairs for overlay-only direct children of the
    /// queried directory (see `Req::OverlayChildren`).
    /// The server caps the per-call listing size (enforced launcher-side in
    /// pipe_server): oversized listings come back truncated to a prefix,
    /// never as an error.
    OverlayChildren(Vec<policy::OverlayChildMeta>),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_config_roundtrip_minimal() {
        let cfg = SessionConfig {
            pipe_name: r"\\.\pipe\fs-sandbox-12345".into(),
            dll_path: r"D:\bin\hook.dll".into(),
            cwd: r"D:\sandbox\workdir".into(),
            sandbox_root: r"D:\sandbox".into(),
            overlay_roots: vec![],
            trace: true,
            guard: GuardLevel::Scan,
            launcher_pid: 0,
            launcher_create_time: 0,
            allow_rwx: false,
            disable_hooks: String::new(),
        };
        let bytes = cfg.to_section_bytes().unwrap();
        let dec = SessionConfig::from_section_bytes(&bytes).unwrap();
        assert_eq!(dec.pipe_name, cfg.pipe_name);
        assert_eq!(dec.dll_path, cfg.dll_path);
        assert_eq!(dec.cwd, cfg.cwd);
        assert_eq!(dec.sandbox_root, r"D:\sandbox");
        assert!(dec.trace);
        assert_eq!(dec.guard, GuardLevel::Scan);
    }

    #[test]
    fn session_config_section_size_bound() {
        let huge = "x".repeat(SESSION_CONFIG_SECTION_SIZE + 1);
        let cfg = SessionConfig {
            pipe_name: huge,
            ..Default::default()
        };
        assert!(cfg.to_section_bytes().is_err(),
            "oversized config must be rejected, not silently truncated");
    }

    #[test]
    fn session_config_rejects_bad_magic() {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let err = SessionConfig::from_section_bytes(&buf).unwrap_err();
        match err {
            IpcError::Decode(msg) => assert!(msg.contains("magic"), "got: {msg}"),
            other => panic!("expected Decode, got: {other:?}"),
        }
    }

    #[test]
    fn session_config_rejects_short_buffer() {
        let buf = [0u8; 4];
        assert!(SessionConfig::from_section_bytes(&buf).is_err());
    }
    /// Typed guard + launcher identity must survive the section roundtrip.
    #[test]
    fn session_config_section_roundtrip_with_guard_enum_and_identity() {
        let cfg = SessionConfig {
            pipe_name: r"\\.\pipe\fs-sandbox-typed".into(),
            dll_path: r"D:\bin\hook.dll".into(),
            guard: GuardLevel::Static,
            launcher_pid: 4242,
            launcher_create_time: 0x1AAA_BBBB_CCCC_DDDD,
            ..Default::default()
        };
        let dec = SessionConfig::from_section_bytes(&cfg.to_section_bytes().unwrap()).unwrap();
        assert_eq!(dec.guard, GuardLevel::Static);
        assert_eq!(dec.launcher_pid, 4242);
        assert_eq!(dec.launcher_create_time, 0x1AAA_BBBB_CCCC_DDDD);
        assert_eq!(dec.pipe_name, cfg.pipe_name);
    }

    /// Decode-side defaults: `#[serde(default)]` on the identity fields and
    /// `#[default]` on `GuardLevel::None` must agree with what a pre-identity
    /// section body decodes to: guard None, zeroed launcher identity.
    #[test]
    fn session_config_decodes_without_identity_fields() {
        let d = SessionConfig::default();
        assert_eq!(d.guard, GuardLevel::None);
        assert_eq!(d.launcher_pid, 0);
        assert_eq!(d.launcher_create_time, 0);
    }
}
