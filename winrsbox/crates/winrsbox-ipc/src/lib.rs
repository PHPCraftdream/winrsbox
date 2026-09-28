use std::io;
use policy::Decision;
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod guard_level;
pub use guard_level::GuardLevel;

mod folder_section;
pub use folder_section::{
    FolderSectionError, FolderSectionSnapshot, FolderSectionView, FOLDER_SECTION_MAGIC,
    FOLDER_SECTION_SEQLOCK_MAX_RETRIES, FOLDER_SECTION_SIZE, FOLDER_SECTION_VERSION,
    MAX_LAUNCHERS, PIPE_NAME_WCHARS,
};

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
    /// Name of the per-folder broker section (`folder_section`). Empty =
    /// no folder broker; the hook uses `pipe_name`/`launcher_pid` above.
    #[serde(default)]
    pub folder_section_name: String,
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
    VerifyMicrosoftImage { base_address: u64 },
    DeviceDriveMap,
    /// MP-3: sent by a joining launcher process (never a guest — a launcher
    /// is never a member of the folder job by construction) to join this
    /// folder's broker. Authenticated by the broker from KERNEL facts alone
    /// (client PID from `GetNamedPipeClientProcessId`, NOT folder-job
    /// membership, matching token SID, matching image path) — `launcher_pid`/
    /// `launcher_create_time` are cross-checked against those facts, never
    /// trusted on their own. A connection that fails the normal job-based
    /// admission check gets exactly one shot at this request; anything else
    /// (wrong variant, second request) is a fail-closed disconnect.
    Attach { launcher_pid: u32, launcher_create_time: u64 },
    /// MP-6: sent by an attached client launcher, on the SAME connection its
    /// `Attach` succeeded on, to forward one already-serialized
    /// `sandbox.log.jsonl` line for the broker (the sole owner of that file)
    /// to append verbatim. Rejected on any other (guest) connection.
    LauncherLog { line: String },
    /// MP-6: sent by an attached client launcher, on its Attach connection,
    /// to fetch the folder's decision counters for its own exit summary — a
    /// client runs no pipe server of its own, so every guest in the folder
    /// (including the client's) is already counted by the broker. Rejected
    /// on any other (guest) connection.
    SessionStats,
    /// MP-9: a CLI process (`winrsbox rule add ...`, same image, never a
    /// job-papки member — same admission class as `Attach` above) applying
    /// a policy mutation/read while a broker already owns `policy.redb`.
    /// Valid as the first request on a connection that failed the normal
    /// job-membership admission check, exactly like `Attach` — see
    /// `pipe_server::mutate`'s pre-admission dispatcher. No job/section
    /// handles are exchanged; the connection closes after one response.
    PolicyMutate { op: policy::db::PolicyOp },
    /// MP-8: liveness probe. Valid in two places (see
    /// `docs/multiprocess-broker-plan.md`, "Зависание брокера"): (a) sent
    /// periodically by an attached launcher over its long-lived `Attach`
    /// connection (`main::session::run_launcher_session_loop`), and (b) a
    /// one-shot pre-admission exchange — same admission class as
    /// `PolicyMutate` above — for a caller (e.g. `winrsbox broker status`)
    /// that only wants to know whether the broker is alive and answering,
    /// without a full `Attach`.
    Ping,
    /// MP-8: `winrsbox broker status`. Pre-admission, one-shot, same
    /// admission class as `PolicyMutate`/`Ping` — asks the broker for its
    /// own identity/health snapshot: pid, generation, pipe, trusted
    /// launchers, and how many processes are currently in the folder job.
    BrokerStatus,
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
    ImagePublisher { trusted: bool },
    DeviceDriveMap(Vec<(u8, String)>),
    /// MP-3: successful `Attach`. The handle VALUES are already valid in the
    /// caller's own address space — the broker duplicated them there via
    /// `DuplicateHandle` before sending this response, so no further IPC
    /// round-trip is needed to use them.
    Attached {
        folder_job_handle: u64,
        folder_section_handle: u64,
        folder_section_name: String,
        broker_pid: u32,
        broker_create_time: u64,
        pipe_name: String,
        generation: u64,
        /// MP-6: snapshot of "this folder has at least one configured net
        /// rule" at Attach time, so a client can compute its own
        /// `net_guarded` without opening the policy DB (see `main::client`).
        /// Taken once, not live — same staleness class as every other value
        /// this response hands out.
        has_net_rules: bool,
    },
    /// MP-6: `Req::SessionStats` reply. Folder-wide counters (the broker's
    /// pipe server is shared by every session in the folder) — not scoped to
    /// the requesting launcher's own guest tree; see `Req::SessionStats`.
    SessionStats {
        decide: u64,
        redirect: u64,
        deny: u64,
        mock: u64,
        cow: u64,
        violations: u64,
    },
    /// MP-9: result of a `Req::PolicyMutate`. `Resp::Err` covers both a
    /// rejected/unsupported connection (no live `Policy` on this
    /// connection — never happens on a real broker) and a `PolicyError`
    /// from executing the op — same shape the CLI already prints for a
    /// direct-mode failure.
    PolicyMutated(policy::db::PolicyOpResult),
    /// MP-8: `Req::Ping` reply — the answering broker's own identity and
    /// current folder-section generation, read fresh on every ping (not
    /// cached), so a stuck writer (odd generation) is visible to the
    /// prober too, and so a caller that raced a failover can tell WHICH
    /// broker just answered.
    Pong { broker_pid: u32, broker_create_time: u64, generation: u64 },
    /// MP-8: `Req::BrokerStatus` reply.
    BrokerStatus {
        broker_pid: u32,
        broker_create_time: u64,
        generation: u64,
        pipe_name: String,
        trusted_launchers: Vec<(u32, u64)>,
        /// Kernel-truth `JobObjectBasicAccountingInformation.ActiveProcesses`
        /// of the folder job — every guest currently running in this state
        /// dir, across every session, broker's own included.
        active_processes: u32,
    },
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
    fn device_drive_map_roundtrip() {
        let mut wire = Vec::new();
        write_msg(&mut wire, &Req::DeviceDriveMap).unwrap();
        let request: Req = read_msg(&mut std::io::Cursor::new(wire)).unwrap();
        assert!(matches!(request, Req::DeviceDriveMap));
        let expected = vec![(b'D', r"\Device\HarddiskVolume77".to_owned())];
        let mut wire = Vec::new();
        write_msg(&mut wire, &Resp::DeviceDriveMap(expected.clone())).unwrap();
        let response: Resp = read_msg(&mut std::io::Cursor::new(wire)).unwrap();
        let Resp::DeviceDriveMap(actual) = response else { panic!("wrong drive-map response"); };
        assert_eq!(actual, expected);
    }

    /// MP-6: launcher-only requests round-trip like any other `Req`/`Resp`.
    #[test]
    fn launcher_log_and_session_stats_roundtrip() {
        let mut wire = Vec::new();
        write_msg(&mut wire, &Req::LauncherLog { line: r#"{"event":"exit"}"#.into() }).unwrap();
        let req: Req = read_msg(&mut std::io::Cursor::new(wire)).unwrap();
        match req {
            Req::LauncherLog { line } => assert_eq!(line, r#"{"event":"exit"}"#),
            other => panic!("expected LauncherLog, got {other:?}"),
        }

        let mut wire = Vec::new();
        write_msg(&mut wire, &Req::SessionStats).unwrap();
        let req: Req = read_msg(&mut std::io::Cursor::new(wire)).unwrap();
        assert!(matches!(req, Req::SessionStats));

        let mut wire = Vec::new();
        write_msg(&mut wire, &Resp::SessionStats {
            decide: 1, redirect: 2, deny: 3, mock: 4, cow: 5, violations: 6,
        }).unwrap();
        let resp: Resp = read_msg(&mut std::io::Cursor::new(wire)).unwrap();
        match resp {
            Resp::SessionStats { decide, redirect, deny, mock, cow, violations } => {
                assert_eq!((decide, redirect, deny, mock, cow, violations), (1, 2, 3, 4, 5, 6));
            }
            other => panic!("expected SessionStats, got {other:?}"),
        }
    }

    /// MP-8: `Ping`/`Pong` and `BrokerStatus`/`Resp::BrokerStatus` round-trip
    /// like any other `Req`/`Resp` pair.
    #[test]
    fn ping_pong_roundtrip() {
        let mut wire = Vec::new();
        write_msg(&mut wire, &Req::Ping).unwrap();
        let req: Req = read_msg(&mut std::io::Cursor::new(wire)).unwrap();
        assert!(matches!(req, Req::Ping));

        let mut wire = Vec::new();
        write_msg(&mut wire, &Resp::Pong { broker_pid: 42, broker_create_time: 0xAABB, generation: 6 })
            .unwrap();
        let resp: Resp = read_msg(&mut std::io::Cursor::new(wire)).unwrap();
        match resp {
            Resp::Pong { broker_pid, broker_create_time, generation } => {
                assert_eq!((broker_pid, broker_create_time, generation), (42, 0xAABB, 6));
            }
            other => panic!("expected Pong, got {other:?}"),
        }
    }

    #[test]
    fn broker_status_roundtrip() {
        let mut wire = Vec::new();
        write_msg(&mut wire, &Req::BrokerStatus).unwrap();
        let req: Req = read_msg(&mut std::io::Cursor::new(wire)).unwrap();
        assert!(matches!(req, Req::BrokerStatus));

        let mut wire = Vec::new();
        write_msg(&mut wire, &Resp::BrokerStatus {
            broker_pid: 7,
            broker_create_time: 0x1234_5678,
            generation: 2,
            pipe_name: r"\\.\pipe\fs-sandbox-7".into(),
            trusted_launchers: vec![(7, 0x1234_5678), (9, 0x9999)],
            active_processes: 3,
        }).unwrap();
        let resp: Resp = read_msg(&mut std::io::Cursor::new(wire)).unwrap();
        match resp {
            Resp::BrokerStatus {
                broker_pid, broker_create_time, generation, pipe_name, trusted_launchers, active_processes,
            } => {
                assert_eq!(broker_pid, 7);
                assert_eq!(broker_create_time, 0x1234_5678);
                assert_eq!(generation, 2);
                assert_eq!(pipe_name, r"\\.\pipe\fs-sandbox-7");
                assert_eq!(trusted_launchers, vec![(7, 0x1234_5678), (9, 0x9999)]);
                assert_eq!(active_processes, 3);
            }
            other => panic!("expected BrokerStatus, got {other:?}"),
        }
    }

    #[test]
    fn image_publisher_request_and_response_roundtrip() {
        let mut wire = Vec::new();
        write_msg(&mut wire, &Req::VerifyMicrosoftImage { base_address: 0x12345678 }).unwrap();
        let decoded: Req = read_msg(&mut std::io::Cursor::new(wire)).unwrap();
        assert!(matches!(decoded, Req::VerifyMicrosoftImage { base_address: 0x12345678 }));
        for trusted in [false, true] {
            let mut wire = Vec::new();
            write_msg(&mut wire, &Resp::ImagePublisher { trusted }).unwrap();
            let decoded: Resp = read_msg(&mut std::io::Cursor::new(wire)).unwrap();
            assert!(matches!(decoded, Resp::ImagePublisher { trusted: actual } if actual == trusted));
        }
    }

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
            folder_section_name: String::new(),
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
