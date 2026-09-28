// Effective install-time configuration, resolved from the trusted session
// section ONLY (review XA 2026-09-20, S02).
//
// Historically install_hooks read the security config
// (FS_SANDBOX_PIPE/DLL/CWD/ROOT/GUARD/ALLOW_RWX/DISABLE_HOOKS/TRACE) from the
// environment FIRST and loaded the trusted shared-memory section SECOND via
// `OnceLock::set` — which can never overwrite an env-accepted value. The
// environment block is guest-writable, so one `SetEnvironmentVariable` before
// (or without) any launcher permanently pinned the hook's whole config. This
// module inverts that: the section is the single source of truth and the
// environment is reduced to the opaque section-name identifier (plus two test
// aids the spawn gate polices). No environment variable is consulted here;
// the pins in checks/hooks_core_security_tests.rs (W1) keep it that way.
//
// When the section is ABSENT the resolution fails closed: everything empty,
// guard Static — the strongest tier (unknown provenance ⇒ maximum
// restriction; the process also has no pipe name and fails closed on every
// IPC decision) and, since chunk 2, a spawn with no trusted DLL_PATH
// terminates the child instead of resuming it unprotected.

/// The effective install-time configuration, already stripped of its
/// provenance: either a faithful copy of the trusted session section, or the
/// fail-closed default (see [`resolve_effective_config`]).
pub(crate) struct EffectiveConfig {
    pub(crate) pipe_name: String,
    pub(crate) dll_path: String,
    pub(crate) cwd: String,
    pub(crate) sandbox_root: String,
    pub(crate) overlay_roots: Vec<String>,
    pub(crate) trace: bool,
    pub(crate) guard: ipc::GuardLevel,
    /// Identity of the launcher process that authored the section and owns
    /// the pipe (S02 #1 remainder): pinned so `verify_pipe_server_identity`
    /// can check WHO owns the pipe server before any answer is trusted.
    pub(crate) launcher_pid: u32,
    pub(crate) launcher_create_time: u64,
    pub(crate) allow_rwx: bool,
    pub(crate) disable_hooks: String,
    /// Name of the per-folder broker section (MP-5). Empty ⇒ no folder
    /// broker for this session — the hook uses `pipe_name`/`launcher_pid`
    /// above (single-broker/legacy mode) instead of a live `snapshot()`.
    pub(crate) folder_section_name: String,
}

/// Resolve the effective install-time configuration from the trusted session
/// section. PURE: takes no environment input and touches no global state.
///
/// * `Some(cfg)` — every field comes from the section, ignoring the
///   environment entirely.
/// * `None` — [`fail_closed`]: pipe/dll/cwd/root/overlay_roots empty, trace
///   off, launcher identity zeroed, guard [`ipc::GuardLevel::Static`]
///   (strongest tier: unknown provenance ⇒ maximum restriction; the process
///   will also find no pipe name and fail closed on every IPC decision), RWX
///   not allowed, nothing disabled.
pub(crate) fn resolve_effective_config(section: Option<&ipc::SessionConfig>) -> EffectiveConfig {
    match section {
        Some(cfg) => EffectiveConfig {
            pipe_name: cfg.pipe_name.clone(),
            dll_path: cfg.dll_path.clone(),
            cwd: cfg.cwd.clone(),
            sandbox_root: cfg.sandbox_root.clone(),
            overlay_roots: cfg.overlay_roots.clone(),
            trace: cfg.trace,
            guard: cfg.guard,
            launcher_pid: cfg.launcher_pid,
            launcher_create_time: cfg.launcher_create_time,
            allow_rwx: cfg.allow_rwx,
            disable_hooks: cfg.disable_hooks.clone(),
            folder_section_name: cfg.folder_section_name.clone(),
        },
        None => fail_closed(),
    }
}

/// The no-config default: maximum restriction, nothing permitted, nothing
/// wired up. Every consumer fails closed on it (no pipe → deny-by-default
/// IPC decisions, no DLL_PATH → children are not resumed unprotected).
fn fail_closed() -> EffectiveConfig {
    EffectiveConfig {
        pipe_name: String::new(),
        dll_path: String::new(),
        cwd: String::new(),
        sandbox_root: String::new(),
        overlay_roots: Vec::new(),
        trace: false,
        guard: ipc::GuardLevel::Static,
        launcher_pid: 0,
        launcher_create_time: 0,
        allow_rwx: false,
        disable_hooks: String::new(),
        folder_section_name: String::new(),
    }
}

/// The guard level captured from the trusted section at install time.
/// Decision code reads this (via [`trusted_guard`]) and never the
/// environment. Unset ⇒ Static (fail closed), which is also what a process
/// booted without a section sees.
pub(crate) static TRUSTED_GUARD: std::sync::OnceLock<ipc::GuardLevel> = std::sync::OnceLock::new();

/// The pinned launcher identity (S02 #1 remainder): PID + kernel creation
/// time of the process that authored the session section and owns the pipe.
/// Zero = not pinned ⇒ the pipe server can never be verified (fail closed).
/// `launcher_create_time` defends against PID reuse: a PID alone can be
/// recycled by a different process, its creation time cannot.
pub(crate) static TRUSTED_LAUNCHER_PID: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);
pub(crate) static TRUSTED_LAUNCHER_CREATE_TIME: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Verify that the SERVER side of the connected pipe is trusted before
/// trusting anything it says (review XA 2026-09-20, S02 #1 remainder;
/// extended for MP-5's per-folder broker set). Without this, anything that
/// can set the child's environment before hook install (a hostile parent)
/// points the hook at an attacker pipe answering `Decision::Passthrough` to
/// every path.
///
/// Two disjoint paths, chosen by whether a folder section is configured for
/// this session (`ipc_client::folder_section_view()`):
///
/// * **Folder section present (MP-5)**: the server must be the broker OR a
///   tracked launcher in the freshest `snapshot()` of the trusted-launcher
///   set — not the single PID pinned below. A snapshot read failure (torn
///   section, stuck-odd seqlock) fails closed immediately: this is NOT a
///   signal to fall back to the legacy pinned-PID path below, since that
///   would trust a possibly-stale single identity instead of reporting the
///   real failure.
/// * **No folder section**: the original single pinned `(pid, create_time)`
///   check — unchanged from before MP-5.
///
/// Fails closed when: no identity is pinned/trusted, the server PID cannot
/// be queried, the PID isn't in the trusted set, or (PID-reuse defence) the
/// live process's kernel creation time differs from every trusted entry —
/// including the case where the live creation time reads back as zero,
/// which must never be treated as a wildcard match against a similarly
/// unpopulated/default section entry.
pub(crate) fn verify_pipe_server_identity(client: &ipc::SyncClient) -> Result<(), String> {
    let mut actual_pid: u32 = 0;
    // SAFETY: the raw handle is the client's own live pipe handle, valid for
    // the duration of the borrow; `actual_pid` is a valid out-pointer.
    // std RawHandle and winapi HANDLE are both *mut c_void on Windows.
    // (winapi 0.3 binds GetNamedPipeServerProcessId under um::winbase, not
    // um::namedpipeapi.)
    let ok = unsafe {
        winapi::um::winbase::GetNamedPipeServerProcessId(
            client.pipe_raw_handle() as winapi::shared::ntdef::HANDLE,
            &mut actual_pid,
        )
    };
    if ok == 0 || actual_pid == 0 {
        return Err(format!(
            "pipe server PID unqueryable (GetNamedPipeServerProcessId failed, ok={ok})"
        ));
    }

    if let Some(view) = crate::ipc_client::folder_section_view() {
        let snapshot = view
            .snapshot()
            .map_err(|e| format!("folder section snapshot failed: {e}"))?;
        let actual_ct = match crate::process_tracker::query_process_create_time(actual_pid) {
            None => return Err("pipe server process unqueryable".into()),
            Some(ct) => ct,
        };
        return folder_section_trust_check(&snapshot, actual_pid, actual_ct);
    }

    let expected_pid = TRUSTED_LAUNCHER_PID.load(std::sync::atomic::Ordering::Relaxed);
    if expected_pid == 0 {
        return Err("no trusted launcher identity pinned — refusing to trust pipe server".into());
    }
    if actual_pid != expected_pid {
        return Err(format!(
            "pipe server PID {actual_pid} != trusted launcher PID {expected_pid}"
        ));
    }
    let expected_ct = TRUSTED_LAUNCHER_CREATE_TIME.load(std::sync::atomic::Ordering::Relaxed);
    if expected_ct != 0 {
        match crate::process_tracker::query_process_create_time(actual_pid) {
            None => return Err("pipe server process unqueryable".into()),
            Some(live) if live != expected_ct => {
                return Err(format!(
                    "pipe server PID {actual_pid} was reused (creation time {live:#018x} != pinned {expected_ct:#018x})"
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// The MP-5 trust decision against a folder-section snapshot, pulled out of
/// [`verify_pipe_server_identity`] as a pure function (no Windows API calls)
/// so the full match matrix — trusted broker, trusted launcher, PID outside
/// the set, PID match with a mismatched create_time, and a zero create_time
/// — is directly unit-testable without a live pipe/process for every case.
///
/// `actual_create_time == 0` is rejected unconditionally, even if some
/// section entry also reads zero (e.g. an unpopulated/default slot): treating
/// that as a match would be a silent wildcard, the exact bypass shape the
/// pre-MP-5 `expected_ct == 0` skip allowed on the legacy single-PID path.
fn folder_section_trust_check(
    snapshot: &ipc::FolderSectionSnapshot,
    actual_pid: u32,
    actual_create_time: u64,
) -> Result<(), String> {
    if actual_create_time == 0 {
        return Err("pipe server process reports zero creation time — refusing to trust".into());
    }
    if !snapshot.is_trusted_server(actual_pid, actual_create_time) {
        return Err(format!(
            "pipe server (pid={actual_pid}, create_time={actual_create_time:#018x}) not in \
             folder section trusted set (generation {})",
            snapshot.generation
        ));
    }
    Ok(())
}

/// The install-time guard level, failing closed to
/// [`ipc::GuardLevel::Static`] before install_hooks ran (unit-test context).
pub(crate) fn trusted_guard() -> ipc::GuardLevel {
    TRUSTED_GUARD.get().copied().unwrap_or(ipc::GuardLevel::Static)
}

/// Publish the resolved configuration into the install-time statics. Called
/// ONCE from install_hooks before any hook is enabled; like every
/// install-time `OnceLock` write it is a no-op on later calls.
///
/// Empty strings are skipped (leaving the static unset) so the fail-closed
/// `None` resolution leaves no `Some("")` placeholders behind — consumers
/// distinguish "unset" (fail closed) from a value.
pub(crate) fn apply_effective_config(cfg: &EffectiveConfig) {
    if !cfg.pipe_name.is_empty() {
        let _ = crate::ipc_client::PIPE_NAME.set(cfg.pipe_name.clone());
    }
    if !cfg.dll_path.is_empty() {
        let _ = crate::ipc_client::DLL_PATH.set(cfg.dll_path.clone());
    }
    if !cfg.cwd.is_empty() {
        let _ = crate::ipc_client::SANDBOX_CWD.set(cfg.cwd.clone());
    }
    if !cfg.sandbox_root.is_empty() {
        let _ = crate::ipc_client::SANDBOX_ROOT.set(cfg.sandbox_root.clone());
    }
    if !cfg.overlay_roots.is_empty() {
        let _ = crate::ipc_client::OVERLAY_ROOTS.set(cfg.overlay_roots.clone());
    }
    if cfg.trace {
        crate::ipc_client::TRACE_ENABLED.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let _ = TRUSTED_GUARD.set(cfg.guard);
    TRUSTED_LAUNCHER_PID.store(cfg.launcher_pid, std::sync::atomic::Ordering::Relaxed);
    TRUSTED_LAUNCHER_CREATE_TIME
        .store(cfg.launcher_create_time, std::sync::atomic::Ordering::Relaxed);
    // MP-5: open+map the folder broker section once, here, at install time.
    // Called from install_hooks under DllMain's loader lock — see
    // `ipc_client::open_folder_section`'s doc for why that's safe (plain
    // kernel32 calls, no LoadLibrary, same pattern the session section load
    // one step earlier in install_hooks already uses). A failure here is
    // logged and otherwise non-fatal: `folder_section_view()` stays `None`
    // and every caller falls back to the pinned `TRUSTED_LAUNCHER_PID`/
    // `PIPE_NAME` values set just above, from the same trusted section.
    if !cfg.folder_section_name.is_empty() {
        if let Err(e) = crate::ipc_client::open_folder_section(&cfg.folder_section_name) {
            crate::ipc_client::fail_log(&format!("folder section open failed: {e}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_section_cfg() -> ipc::SessionConfig {
        ipc::SessionConfig {
            pipe_name: r"\\.\pipe\winrsbox-trusted-boot-test".into(),
            dll_path: r"D:\bin\hook.dll".into(),
            cwd: r"D:\sandbox".into(),
            sandbox_root: r"D:\sandbox_overlay".into(),
            overlay_roots: vec![r"D:\sandbox_overlay".into(), r"C:\overlay".into()],
            trace: true,
            guard: ipc::GuardLevel::Static,
            launcher_pid: 0,
            launcher_create_time: 0,
            allow_rwx: true,
            disable_hooks: "reg,net".into(),
            folder_section_name: r"Local\WinRsBoxFolder-test".into(),
        }
    }

    /// The contract this module exists for: with a trusted section present,
    /// EVERY effective field is the section's field — including the launcher
    /// identity the pipe-server verifier pins. The function takes no
    /// environment input by construction, so a win here cannot be environ-
    /// ment-contaminated — and the W1 pin keeps the callers that way too.
    #[test]
    fn section_fields_win_for_every_field() {
        let cfg = full_section_cfg();
        let eff = resolve_effective_config(Some(&cfg));
        assert_eq!(eff.pipe_name, cfg.pipe_name);
        assert_eq!(eff.dll_path, cfg.dll_path);
        assert_eq!(eff.cwd, cfg.cwd);
        assert_eq!(eff.sandbox_root, cfg.sandbox_root);
        assert_eq!(eff.overlay_roots, cfg.overlay_roots);
        assert!(eff.trace);
        assert_eq!(eff.guard, ipc::GuardLevel::Static);
        assert_eq!(eff.launcher_pid, cfg.launcher_pid);
        assert_eq!(eff.launcher_create_time, cfg.launcher_create_time);
        assert!(eff.allow_rwx);
        assert_eq!(eff.disable_hooks, "reg,net");
        assert_eq!(eff.folder_section_name, cfg.folder_section_name);
    }

    /// Absent section ⇒ fail closed: strongest guard tier, everything empty
    /// or off. (The OnceLock-backed `trusted_guard()` is deliberately NOT
    /// exercised here — it is once-per-test-binary and install-time code
    /// owns it; the None-arm contract it serves is pinned via the resolve
    /// result below, whose guard is what `apply_effective_config` stores.)
    #[test]
    fn resolve_none_is_fail_closed() {
        let eff = resolve_effective_config(None);
        assert!(eff.pipe_name.is_empty());
        assert!(eff.dll_path.is_empty());
        assert!(eff.cwd.is_empty());
        assert!(eff.sandbox_root.is_empty());
        assert!(eff.overlay_roots.is_empty());
        assert!(!eff.trace);
        assert_eq!(eff.guard, ipc::GuardLevel::Static, "unknown provenance ⇒ maximum restriction");
        assert_eq!(eff.launcher_pid, 0, "fail-closed default must pin NO identity");
        assert_eq!(eff.launcher_create_time, 0);
        assert!(!eff.allow_rwx);
        assert!(eff.disable_hooks.is_empty());
        assert!(eff.folder_section_name.is_empty());
    }
}

#[cfg(test)]
mod pipe_server_identity_tests {
    //! Behavioral coverage for `verify_pipe_server_identity` (S02 #1
    //! remainder): each test spins a REAL named-pipe server in this test
    //! process, connects a `SyncClient` to it, and exercises the verifier
    //! against the pinned identity atomics.
    //!
    //! The atomics are process-wide, so the tests serialize on a mutex —
    //! same ENV_LOCK pattern as hooks_core_security_tests / nested_detection
    //! tests, added after exactly that class of parallel-test flake.

    use super::*;

    static IDENTITY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Holds BOTH the local atomics lock and the shared
    /// `FOLDER_SECTION_OVERRIDE_LOCK` (see that static's doc in
    /// `ipc_client::folder_section_client`): every test here calls
    /// `verify_pipe_server_identity`, which reads `folder_section_view()`,
    /// so even a legacy-path test that never touches the override must
    /// still block a concurrent folder-section test in the other module
    /// from flipping it mid-run.
    fn identity_lock() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        (
            IDENTITY_LOCK.lock().unwrap_or_else(|e| e.into_inner()),
            crate::ipc_client::FOLDER_SECTION_OVERRIDE_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        )
    }

    /// Heap-backed, 8-byte-aligned stand-in for a mapped folder section —
    /// same technique as `ipc_client::folder_section_client`'s own tests
    /// (that module's doc explains why a `Vec<u64>` and not the private
    /// `RawFolderSection` type).
    fn folder_section_storage() -> Vec<u64> {
        vec![0u64; ipc::FOLDER_SECTION_SIZE.div_ceil(8)]
    }

    fn folder_section_view_of(storage: &mut [u64]) -> ipc::FolderSectionView {
        let ptr = storage.as_mut_ptr().cast::<u8>();
        // SAFETY: storage holds ipc::FOLDER_SECTION_SIZE.div_ceil(8) u64
        // words (>= FOLDER_SECTION_SIZE bytes), 8-byte aligned by Vec<u64>'s
        // own allocation guarantee; the caller keeps `storage` alive for at
        // least as long as the returned view is used.
        unsafe { ipc::FolderSectionView::new(ptr) }
    }

    fn set_folder_section_override(view: Option<ipc::FolderSectionView>) {
        *crate::ipc_client::FOLDER_SECTION_TEST_OVERRIDE
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = view;
    }

    /// Create a live pipe-server instance with a unique-per-test name and
    /// connect a `SyncClient` to it. The server handle is intentionally
    /// leaked for the process lifetime (documented hazard-free: the test
    /// binary exits right after) so the instance cannot disappear under a
    /// parallel test that derived its own name from `line!()`.
    fn connected_client(line: u32) -> (winapi::shared::ntdef::HANDLE, ipc::SyncClient, String) {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        let name = format!(r"\\.\pipe\winrsbox-identity-test-{}-{}", std::process::id(), line);
        let wide: Vec<u16> = OsStr::new(&name).encode_wide().chain(Some(0)).collect();
        // SAFETY: `wide` is a NUL-terminated UTF-16 name; the security
        // attributes pointer is null (default DACL) and the mode constants
        // are the documented values: PIPE_ACCESS_DUPLEX (3),
        // PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT (0).
        let server = unsafe {
            winapi::um::namedpipeapi::CreateNamedPipeW(
                wide.as_ptr(),
                3,    // PIPE_ACCESS_DUPLEX
                0,    // PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
                1,    // nMaxInstances
                4096, // nOutBufferSize
                4096, // nInBufferSize
                0,    // nDefaultTimeOut
                std::ptr::null_mut(),
            )
        };
        assert!(
            !server.is_null() && server != winapi::um::handleapi::INVALID_HANDLE_VALUE,
            "CreateNamedPipeW failed for {name}",
        );
        // Returns on attempt 1 against the live server above.
        let client = ipc::SyncClient::connect(&name).expect("connect to own pipe server");
        (server, client, name)
    }

    fn own_create_time() -> u64 {
        crate::process_tracker::query_process_create_time(std::process::id())
            .expect("own process creation time must be queryable")
    }

    /// Happy path: the pipe server lives in the pinned launcher process (the
    /// test process stands in for it) and its creation time matches.
    #[test]
    fn verify_accepts_server_in_pinned_launcher_process() {
        let _lock = identity_lock();
        let (_server, client, _name) = connected_client(line!());
        TRUSTED_LAUNCHER_PID.store(std::process::id(), std::sync::atomic::Ordering::Relaxed);
        TRUSTED_LAUNCHER_CREATE_TIME
            .store(own_create_time(), std::sync::atomic::Ordering::Relaxed);
        assert_eq!(verify_pipe_server_identity(&client), Ok(()));
    }

    /// A pipe server owned by any other process (here: a fabricated
    /// different PID) must be rejected — the forged-pipe-server attack.
    #[test]
    fn verify_rejects_server_pid_other_than_pinned_launcher() {
        let _lock = identity_lock();
        let (_server, client, _name) = connected_client(line!());
        TRUSTED_LAUNCHER_PID.store(
            std::process::id().wrapping_add(0x1111_1111),
            std::sync::atomic::Ordering::Relaxed,
        );
        TRUSTED_LAUNCHER_CREATE_TIME.store(own_create_time(), std::sync::atomic::Ordering::Relaxed);
        let err = verify_pipe_server_identity(&client).unwrap_err();
        assert!(err.contains("trusted launcher PID"), "mismatch must name both PIDs: {err}");
    }

    /// PID-reuse defence: the PID matches but the pinned kernel creation
    /// time belongs to a previous boot of that PID — reject.
    #[test]
    fn verify_rejects_reused_pid_with_mismatched_creation_time() {
        let _lock = identity_lock();
        let (_server, client, _name) = connected_client(line!());
        TRUSTED_LAUNCHER_PID.store(std::process::id(), std::sync::atomic::Ordering::Relaxed);
        TRUSTED_LAUNCHER_CREATE_TIME.store(
            0x0000_1234_5678_9abc,
            std::sync::atomic::Ordering::Relaxed,
        );
        let err = verify_pipe_server_identity(&client).unwrap_err();
        assert!(err.contains("reused"), "creation-time mismatch must read as PID reuse: {err}");
    }

    /// Fail closed: with NO pinned identity (zero) the verifier must refuse
    /// to trust ANY pipe server — including a perfectly live one.
    #[test]
    fn verify_fails_closed_when_no_identity_pinned() {
        let _lock = identity_lock();
        let (_server, client, _name) = connected_client(line!());
        TRUSTED_LAUNCHER_PID.store(0, std::sync::atomic::Ordering::Relaxed);
        TRUSTED_LAUNCHER_CREATE_TIME.store(0, std::sync::atomic::Ordering::Relaxed);
        let err = verify_pipe_server_identity(&client).unwrap_err();
        assert!(err.contains("no trusted launcher identity pinned"), "got: {err}");
    }

    // ── MP-5: folder-section path ───────────────────────────────────────────
    //
    // These exercise verify_pipe_server_identity end-to-end (real pipe, real
    // process) with a folder section installed via the ipc_client test seam
    // (FOLDER_SECTION_TEST_OVERRIDE) instead of TRUSTED_LAUNCHER_PID/
    // _CREATE_TIME — the folder-section branch never reads those atomics.

    /// Trusted broker identity in the section ⇒ accept.
    #[test]
    fn verify_accepts_broker_from_folder_section() {
        let _lock = identity_lock();
        let (_server, client, _name) = connected_client(line!());
        let mut storage = folder_section_storage();
        let view = folder_section_view_of(&mut storage);
        view.init(std::process::id(), own_create_time(), "p").expect("init");
        set_folder_section_override(Some(view));

        assert_eq!(verify_pipe_server_identity(&client), Ok(()));

        set_folder_section_override(None);
    }

    /// A tracked launcher (not the broker) in the section's trusted set ⇒
    /// accept — the whole point of MP-5's set-of-launchers over a single PID.
    #[test]
    fn verify_accepts_tracked_launcher_from_folder_section() {
        let _lock = identity_lock();
        let (_server, client, _name) = connected_client(line!());
        let mut storage = folder_section_storage();
        let view = folder_section_view_of(&mut storage);
        // Broker is some other (non-existent) identity; the live test process
        // is trusted only via the launcher-set entry.
        view.init(0xFFFF_FFFE, 0xDEAD_BEEF, "p").expect("init");
        view.add_launcher(std::process::id(), own_create_time()).expect("add_launcher");
        set_folder_section_override(Some(view));

        assert_eq!(verify_pipe_server_identity(&client), Ok(()));

        set_folder_section_override(None);
    }

    /// The live PID is neither the broker nor any tracked launcher ⇒ reject.
    #[test]
    fn verify_rejects_pid_outside_folder_section_set() {
        let _lock = identity_lock();
        let (_server, client, _name) = connected_client(line!());
        let mut storage = folder_section_storage();
        let view = folder_section_view_of(&mut storage);
        view.init(0xFFFF_FFFE, 0xDEAD_BEEF, "p").expect("init");
        view.add_launcher(0xFFFF_FFFD, 0x00C0_FFEE).expect("add_launcher");
        set_folder_section_override(Some(view));

        let err = verify_pipe_server_identity(&client).unwrap_err();
        assert!(err.contains("not in"), "got: {err}");

        set_folder_section_override(None);
    }

    /// PID matches the broker but the live creation time doesn't (PID reuse,
    /// folder-section flavor) ⇒ reject.
    #[test]
    fn verify_rejects_pid_match_create_time_mismatch_in_folder_section() {
        let _lock = identity_lock();
        let (_server, client, _name) = connected_client(line!());
        let mut storage = folder_section_storage();
        let view = folder_section_view_of(&mut storage);
        view.init(std::process::id(), 0x0000_1234_5678_9abc, "p").expect("init");
        set_folder_section_override(Some(view));

        let err = verify_pipe_server_identity(&client).unwrap_err();
        assert!(err.contains("not in"), "got: {err}");

        set_folder_section_override(None);
    }

    /// A section stuck with an odd generation (writer crashed mid-write)
    /// must fail closed on `snapshot()` — NOT silently fall back to the
    /// legacy pinned-PID path, even if TRUSTED_LAUNCHER_PID happens to be
    /// set to the live PID (proving the folder-section branch really is
    /// exclusive of the legacy one, not merely additive).
    #[test]
    fn verify_rejects_when_folder_section_generation_stuck_odd() {
        let _lock = identity_lock();
        let (_server, client, _name) = connected_client(line!());
        let mut storage = folder_section_storage();
        let view = folder_section_view_of(&mut storage);
        view.init(std::process::id(), own_create_time(), "p").expect("init");
        // Force the seqlock generation permanently odd, as if a writer
        // crashed mid-write. Offsets per folder_section's own module doc:
        // magic:u32 @0, version:u32 @4, generation:u64 @8 (no padding).
        // SAFETY: storage is a valid, live mapping for this view; offset 8
        // is `generation`'s documented repr(C) position.
        unsafe {
            let gen_ptr = storage.as_mut_ptr().cast::<u8>().add(8).cast::<u64>();
            std::sync::atomic::AtomicU64::from_ptr(gen_ptr)
                .store(1, std::sync::atomic::Ordering::SeqCst);
        }
        set_folder_section_override(Some(view));
        TRUSTED_LAUNCHER_PID.store(std::process::id(), std::sync::atomic::Ordering::Relaxed);
        TRUSTED_LAUNCHER_CREATE_TIME.store(own_create_time(), std::sync::atomic::Ordering::Relaxed);

        let err = verify_pipe_server_identity(&client).unwrap_err();
        assert!(
            err.contains("snapshot failed"),
            "a stuck seqlock must fail closed with a snapshot error, not fall back \
             silently to the legacy pinned-PID path (which would have accepted \
             this exact PID/create_time): got {err}"
        );

        set_folder_section_override(None);
    }
}

#[cfg(test)]
mod folder_section_trust_check_tests {
    //! Pure unit coverage for `folder_section_trust_check` — no live pipe or
    //! process needed, so the zero-create-time case (impossible to induce
    //! against a REAL process via `query_process_create_time`, which never
    //! returns 0 for a live process) is directly testable here.

    use super::*;

    fn snapshot_with(
        broker: (u32, u64),
        launchers: Vec<(u32, u64)>,
    ) -> ipc::FolderSectionSnapshot {
        let mut storage = vec![0u64; ipc::FOLDER_SECTION_SIZE.div_ceil(8)];
        let ptr = storage.as_mut_ptr().cast::<u8>();
        // SAFETY: storage is sized/aligned per FolderSectionView::new's
        // contract and outlives the view built from it (both local to this
        // function; the returned Snapshot is an owned copy).
        let view = unsafe { ipc::FolderSectionView::new(ptr) };
        view.init(broker.0, broker.1, "p").expect("init");
        for (pid, ct) in launchers {
            view.add_launcher(pid, ct).expect("add_launcher");
        }
        view.snapshot().expect("snapshot")
    }

    #[test]
    fn trusts_the_broker() {
        let snap = snapshot_with((10, 100), vec![]);
        assert_eq!(folder_section_trust_check(&snap, 10, 100), Ok(()));
    }

    #[test]
    fn trusts_a_tracked_launcher() {
        let snap = snapshot_with((10, 100), vec![(20, 200)]);
        assert_eq!(folder_section_trust_check(&snap, 20, 200), Ok(()));
    }

    #[test]
    fn rejects_pid_outside_the_set() {
        let snap = snapshot_with((10, 100), vec![(20, 200)]);
        let err = folder_section_trust_check(&snap, 30, 300).unwrap_err();
        assert!(err.contains("not in"), "got: {err}");
    }

    #[test]
    fn rejects_matching_pid_with_mismatched_create_time() {
        let snap = snapshot_with((10, 100), vec![]);
        let err = folder_section_trust_check(&snap, 10, 999).unwrap_err();
        assert!(err.contains("not in"), "got: {err}");
    }

    /// The bypass this function exists to close: a zero live creation time
    /// must never be trusted, even against a snapshot whose own default/
    /// unpopulated entries also read zero (which, absent this check, would
    /// make `is_trusted_server(pid, 0)` a wildcard match).
    #[test]
    fn rejects_zero_actual_create_time_even_against_a_zeroed_default_entry() {
        // A freshly-init'd-then-untouched slot pattern: broker_create_time
        // left at 0 is achievable directly since init() takes it verbatim.
        let snap = snapshot_with((10, 0), vec![]);
        let err = folder_section_trust_check(&snap, 10, 0).unwrap_err();
        assert!(err.contains("zero creation time"), "got: {err}");
    }
}
