//! Folder section (MP-5): read-only mapped view of the per-folder broker
//! section, opened once at install time when
//! `SessionConfig::folder_section_name` is non-empty. `folder_section_view()`
//! returning `None` means no folder broker for this session (single-process
//! mode, or the open below failed) — callers fall back to the fixed
//! `PIPE_NAME`/`TRUSTED_LAUNCHER_PID` pinned from the same trusted session
//! section, exactly as before MP-5.
//!
//! Split out of `ipc_client/mod.rs` (layout-guard: `MAX_FILE_LINES`), same
//! reason `session_section_tests.rs` was split out earlier.

use super::{fail_log, PIPE_NAME};

/// Owns the section handle and mapped view for the process lifetime. Never
/// closed/unmapped: the DLL is never unloaded, so there is nothing to release
/// until process exit reclaims every handle anyway (same posture as
/// `PIPE_NAME`/`SESSION_SECTION_NAME` and every other install-time OnceLock
/// in this module).
struct FolderSectionMapping {
    #[allow(dead_code)] // kept alive only to document/own the mapping; never read
    handle: winapi::shared::ntdef::HANDLE,
    // Only read by the #[cfg(not(test))] folder_section_view() below — the
    // #[cfg(test)] build reads FOLDER_SECTION_TEST_OVERRIDE instead, so this
    // field is legitimately dead code under `cfg(test)` alone.
    #[cfg_attr(test, allow(dead_code))]
    ptr: *mut u8,
}

// SAFETY: `ptr` addresses OS-backed shared memory read exclusively through
// `ipc::FolderSectionView`'s volatile/atomic accessors (see that type's own
// Send/Sync rationale) — nothing here is thread-affine. `handle` is a kernel
// object handle, documented safe to use from any thread.
unsafe impl Send for FolderSectionMapping {}
unsafe impl Sync for FolderSectionMapping {}

static FOLDER_SECTION: std::sync::OnceLock<FolderSectionMapping> = std::sync::OnceLock::new();

/// Open and map `name` read-only as a folder section (MP-5). Called exactly
/// once, from `trusted_boot::apply_effective_config`, itself called from
/// `install_hooks` during `DllMain(DLL_PROCESS_ATTACH)` with the loader lock
/// held. Safe there for the same reason `load_session_config_named` already
/// runs one step earlier in that same call: `OpenFileMappingW`/
/// `MapViewOfFile` are plain kernel32 calls that never call `LoadLibrary` or
/// wait on another DLL's init state — they are not on Microsoft's list of
/// DllMain-unsafe operations, unlike CreateThread/COM/most CRT init paths.
/// Doing this eagerly (rather than lazily on first connect) also means the
/// per-connect hot path (`ensure_ipc_and`, called on every hooked file
/// operation) never has to open/map anything — only `snapshot()` runs there,
/// and only when reconnecting.
///
/// A failure here (bad name, DACL denial, section gone) is logged and
/// otherwise silent: `folder_section_view()` stays `None`, so every caller
/// falls back to the plain `PIPE_NAME`/`TRUSTED_LAUNCHER_PID` values already
/// pinned from the same trusted `SessionConfig` — stale-after-failover but
/// not attacker-controlled, so this is an availability degradation, not a
/// security bypass; the existing `IPC_FAIL_THRESHOLD` self-terminate still
/// applies if that stale pipe is truly dead.
pub(crate) fn open_folder_section(name: &str) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use winapi::shared::minwindef::FALSE;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::memoryapi::{
        MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, FILE_MAP_READ,
    };

    let wide: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();
    // SAFETY: wide is a NUL-terminated UTF-16 name; FALSE = handle not
    // inheritable by child processes.
    let (h, open_error) = unsafe {
        let handle = OpenFileMappingW(FILE_MAP_READ, FALSE, wide.as_ptr());
        (handle, GetLastError())
    };
    if h.is_null() {
        return Err(format!("OpenFileMappingW(folder section) failed: {open_error}"));
    }
    // SAFETY: h is the valid mapping handle returned above; requesting
    // exactly FOLDER_SECTION_SIZE bytes matches the writer's reservation.
    let (view, map_error) = unsafe {
        let view = MapViewOfFile(h, FILE_MAP_READ, 0, 0, ipc::FOLDER_SECTION_SIZE);
        (view, GetLastError())
    };
    if view.is_null() {
        // SAFETY: h is valid (OpenFileMappingW succeeded above).
        unsafe { CloseHandle(h) };
        return Err(format!("MapViewOfFile(folder section) failed: {map_error}"));
    }
    // `set` is a silent no-op if already populated, matching every other
    // install-time OnceLock here (install_hooks runs at most once per
    // process). Guard against leaking this handle/view on that path anyway.
    if FOLDER_SECTION
        .set(FolderSectionMapping { handle: h, ptr: view as *mut u8 })
        .is_err()
    {
        // SAFETY: view/h are the valid, still-owned resources obtained above;
        // nothing else can have touched them since FOLDER_SECTION lost the race.
        unsafe {
            UnmapViewOfFile(view);
            CloseHandle(h);
        }
    }
    Ok(())
}

/// The current folder-section view, if a folder broker is configured for
/// this session and opened successfully. `None` ⇒ legacy single-broker mode:
/// callers use the fixed `PIPE_NAME`/`TRUSTED_LAUNCHER_PID` pinned at install
/// time instead.
#[cfg(not(test))]
pub(crate) fn folder_section_view() -> Option<ipc::FolderSectionView> {
    FOLDER_SECTION
        .get()
        // SAFETY: `ptr` was mapped by `open_folder_section` for
        // `ipc::FOLDER_SECTION_SIZE` bytes, 8-byte aligned (MapViewOfFile is
        // always page-aligned), and stays valid for the process lifetime —
        // exactly `FolderSectionView::new`'s contract.
        .map(|m| unsafe { ipc::FolderSectionView::new(m.ptr) })
}

/// Test seam: the real `folder_section_view` reads a process-wide `OnceLock`
/// that can only ever be populated once per test binary, which cannot serve
/// the many distinct folder-section fixtures (different pid/create_time/
/// generation) each test in `session_section_tests`/`trusted_boot` needs.
/// Same shim pattern as `ensure_pipe_name_loaded`/`overlay_delivery` in
/// `mod.rs`: production code never sees this path.
#[cfg(test)]
pub(crate) static FOLDER_SECTION_TEST_OVERRIDE: std::sync::Mutex<Option<ipc::FolderSectionView>> =
    std::sync::Mutex::new(None);

/// Serializes every test that reads or writes `FOLDER_SECTION_TEST_OVERRIDE`
/// — shared across this module's own tests AND `trusted_boot`'s
/// `pipe_server_identity_tests` (which calls `verify_pipe_server_identity`,
/// itself calling `folder_section_view()`). Two independent locks would not
/// suffice: `cargo test` runs test functions from different modules
/// concurrently by default, so anything less than one shared lock over this
/// one process-wide static lets a folder-section test in one module flip
/// the override out from under a legacy-path test in the other.
#[cfg(test)]
pub(crate) static FOLDER_SECTION_OVERRIDE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn folder_section_view() -> Option<ipc::FolderSectionView> {
    *FOLDER_SECTION_TEST_OVERRIDE.lock().unwrap_or_else(|e| e.into_inner())
}

/// MP-7 §3: bounded retry budget for ONLY the `SeqlockRetryExhausted`
/// snapshot error — the signal that a writer is mid-write, which during a
/// failover means the winning launcher is between `rebuild()`'s two
/// generation stores (or, more commonly, the OLD broker crashed mid-write
/// and left it stuck until the winner's `rebuild()` fixes it). MP-0
/// measured redb/broker recovery after `TerminateProcess`ing the previous
/// owner at 7-12 ms, first attempt; this budget (5 * 20 ms = 100 ms)
/// comfortably covers that with margin, while staying a small fraction of
/// `IPC_FAIL_THRESHOLD`'s per-call connect budget (multiple seconds) so it
/// cannot itself cause a fail-closed self-terminate. Every OTHER snapshot
/// error (bad magic/version/launchers_len/pipe-name encoding) is real
/// corruption, not "broker is mid-handoff" — those still fail immediately,
/// exactly as before this change. This does not extend trust to anything
/// new: the retried snapshot still comes from the same trusted mapping,
/// under the same seqlock discipline, just re-read a few more times.
const SNAPSHOT_RETRY_ATTEMPTS: u32 = 5;
const SNAPSHOT_RETRY_INTERVAL_MS: u64 = 20;

/// Resolve the pipe name to dial for a fresh connection attempt — called
/// ONLY from the `opt.is_none()` reconnect branch of `ensure_ipc_and`, never
/// on the per-call decide hot path. With a folder section, the name comes
/// from a fresh `snapshot()` every time: the broker's pipe can change
/// (failover) without any hook restart. Without one, `PIPE_NAME` (fixed at
/// install time) is the only source, exactly as before MP-5.
pub(crate) fn resolve_connect_pipe_name() -> Option<String> {
    let Some(view) = folder_section_view() else {
        return PIPE_NAME.get().cloned();
    };
    let mut last_stuck_err = None;
    for attempt in 0..SNAPSHOT_RETRY_ATTEMPTS {
        match view.snapshot() {
            Ok(snap) => return Some(snap.pipe_name),
            Err(e @ ipc::FolderSectionError::SeqlockRetryExhausted(_)) => {
                last_stuck_err = Some(e);
                if attempt + 1 < SNAPSHOT_RETRY_ATTEMPTS {
                    std::thread::sleep(std::time::Duration::from_millis(SNAPSHOT_RETRY_INTERVAL_MS));
                }
            }
            Err(e) => {
                fail_log(&format!(
                    "folder section snapshot failed while resolving pipe name: {e}"
                ));
                return None;
            }
        }
    }
    fail_log(&format!(
        "folder section snapshot stuck (seqlock) after {SNAPSHOT_RETRY_ATTEMPTS} attempts \
         (~{}ms): {}",
        SNAPSHOT_RETRY_ATTEMPTS as u64 * SNAPSHOT_RETRY_INTERVAL_MS,
        last_stuck_err.expect("loop only exits here via the SeqlockRetryExhausted arm"),
    ));
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shared with trusted_boot's pipe_server_identity_tests — see
    // FOLDER_SECTION_OVERRIDE_LOCK's doc for why one shared lock (not one
    // per module) is required.
    fn override_lock() -> std::sync::MutexGuard<'static, ()> {
        FOLDER_SECTION_OVERRIDE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Heap-backed, 8-byte-aligned stand-in for a mapped folder section. The
    /// `winrsbox-ipc::folder_section` tests build the private `RawFolderSection`
    /// directly; from outside that crate a `Vec<u64>` sized in 8-byte words
    /// gives both the minimum size and the alignment `FolderSectionView::new`
    /// requires, without needing to see the private layout.
    fn folder_section_storage() -> Vec<u64> {
        vec![0u64; ipc::FOLDER_SECTION_SIZE.div_ceil(8)]
    }

    fn view_of(storage: &mut [u64]) -> ipc::FolderSectionView {
        let ptr = storage.as_mut_ptr().cast::<u8>();
        // SAFETY: storage holds ipc::FOLDER_SECTION_SIZE.div_ceil(8) u64
        // words (>= FOLDER_SECTION_SIZE bytes), 8-byte aligned by Vec<u64>'s
        // own allocation guarantee; the caller keeps `storage` alive for at
        // least as long as the returned view is used.
        unsafe { ipc::FolderSectionView::new(ptr) }
    }

    /// Without a folder section, resolution must fall back to `PIPE_NAME`
    /// unchanged — the pre-MP-5 behavior.
    #[test]
    fn resolve_connect_pipe_name_without_folder_section_uses_pipe_name() {
        let _lock = override_lock();
        *FOLDER_SECTION_TEST_OVERRIDE.lock().unwrap() = None;
        // PIPE_NAME is a OnceLock set at most once per test binary by other
        // tests; this test only asserts the "no folder section" branch reads
        // it, whatever it currently holds (possibly unset).
        assert_eq!(resolve_connect_pipe_name(), PIPE_NAME.get().cloned());
    }

    /// THE MP-5 core: after `set_broker` republishes a new pipe name, the
    /// very next resolution (no hook restart) must see it — proving the
    /// hook never latches the pipe name the way the old `OnceLock<String>
    /// PIPE_NAME` did.
    #[test]
    fn resolve_connect_pipe_name_reflects_set_broker_without_restart() {
        let _lock = override_lock();
        let mut storage = folder_section_storage();
        let view = view_of(&mut storage);
        view.init(111, 222, r"\\.\pipe\winrsbox-broker-old").expect("init");
        *FOLDER_SECTION_TEST_OVERRIDE.lock().unwrap() = Some(view);

        assert_eq!(
            resolve_connect_pipe_name().as_deref(),
            Some(r"\\.\pipe\winrsbox-broker-old")
        );

        view.set_broker(999, 888, r"\\.\pipe\winrsbox-broker-new").expect("set_broker");

        assert_eq!(
            resolve_connect_pipe_name().as_deref(),
            Some(r"\\.\pipe\winrsbox-broker-new"),
            "failover must be visible on the very next resolution, no restart"
        );

        *FOLDER_SECTION_TEST_OVERRIDE.lock().unwrap() = None;
    }

    /// MP-7 §3: a TRANSIENTLY stuck-odd section (the failover window
    /// between the old broker dying and the winner's `rebuild()` call) must
    /// still resolve successfully, as long as it clears within the bounded
    /// retry budget — this is the hook-side half of the failover-window
    /// coverage the plan calls for.
    #[test]
    fn resolve_connect_pipe_name_retries_through_a_transient_stuck_generation() {
        let _lock = override_lock();
        let mut storage = folder_section_storage();
        let view = view_of(&mut storage);
        view.init(1, 1, "old").expect("init");
        // Force stuck-odd, as if a writer crashed mid-write.
        unsafe {
            let gen_ptr = storage.as_mut_ptr().cast::<u8>().add(8).cast::<u64>();
            std::sync::atomic::AtomicU64::from_ptr(gen_ptr)
                .store(1, std::sync::atomic::Ordering::SeqCst);
        }
        *FOLDER_SECTION_TEST_OVERRIDE.lock().unwrap() = Some(view);

        // A concurrent "failover winner" fixes the section shortly after —
        // well within the retry budget. The delay counts from the moment the
        // thread is running, so a slow spawn on a loaded machine cannot eat
        // the budget; a fix landing before the first read passes as well.
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let fixer = std::thread::spawn(move || {
            ready_tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
            view.rebuild(9, 99, r"\\.\pipe\winrsbox-broker-new", &[(9, 99)])
                .expect("rebuild");
        });
        ready_rx.recv().unwrap();

        assert_eq!(
            resolve_connect_pipe_name().as_deref(),
            Some(r"\\.\pipe\winrsbox-broker-new"),
            "must recover once the failover winner rebuilds the section"
        );
        fixer.join().unwrap();

        *FOLDER_SECTION_TEST_OVERRIDE.lock().unwrap() = None;
    }

    /// A folder section that cannot be read (stuck-odd seqlock) must resolve
    /// to `None`, not silently fall back to `PIPE_NAME` — a stale pipe name
    /// picked up from the legacy path here would defeat the whole point of
    /// reading fresh on every reconnect. This also pins the OTHER half of
    /// MP-7 §3: a PERMANENTLY stuck section must still give up (bounded
    /// retry, not infinite) and return `None`.
    #[test]
    fn resolve_connect_pipe_name_none_when_snapshot_fails() {
        let _lock = override_lock();
        let mut storage = folder_section_storage();
        let view = view_of(&mut storage);
        view.init(1, 1, "p").expect("init");
        // Force the seqlock generation permanently odd, as if a writer
        // crashed mid-write — see trusted_boot's identical helper for the
        // offset rationale (magic:u32 @0, version:u32 @4, generation:u64 @8,
        // no padding between them).
        // SAFETY: storage is a valid, live mapping for this view; offset 8
        // is `generation`'s documented repr(C) position.
        unsafe {
            let gen_ptr = storage.as_mut_ptr().cast::<u8>().add(8).cast::<u64>();
            std::sync::atomic::AtomicU64::from_ptr(gen_ptr)
                .store(1, std::sync::atomic::Ordering::SeqCst);
        }
        *FOLDER_SECTION_TEST_OVERRIDE.lock().unwrap() = Some(view);

        assert_eq!(resolve_connect_pipe_name(), None);

        *FOLDER_SECTION_TEST_OVERRIDE.lock().unwrap() = None;
    }
}
