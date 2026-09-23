use super::*;

mod basics;
mod alloc_ex_sibling;
mod manual_alloc_trampoline;

// ---------------------------------------------------------------------------
// decide_mapview_protection tests
// ---------------------------------------------------------------------------

#[test]
fn decide_image_section_always_allowed() {
    // SEC_IMAGE sections: all protect values allowed, including RWX variants.
    assert!(decide_mapview_protection(true, false, PAGE_EXECUTE_WRITECOPY));
    assert!(decide_mapview_protection(true, false, PAGE_EXECUTE_READWRITE));
    assert!(decide_mapview_protection(true, false, PAGE_EXECUTE_READ));
    assert!(decide_mapview_protection(true, false, PAGE_EXECUTE));
    assert!(decide_mapview_protection(true, false, 0x04)); // PAGE_READWRITE
}

#[test]
fn decide_file_backed_non_exec_allowed() {
    // MEM_MAPPED without execute: no threat.
    assert!(decide_mapview_protection(false, true, 0x02)); // PAGE_READONLY
    assert!(decide_mapview_protection(false, true, 0x04)); // PAGE_READWRITE
}

#[test]
fn decide_file_backed_exec_allowed_for_clr() {
    // CLR maps .ni.dll/.dll as file-backed (MEM_MAPPED) with
    // PAGE_EXECUTE_WRITECOPY. This must be allowed — blocking it
    // terminates .NET / PowerShell at startup (bug #80).
    assert!(decide_mapview_protection(false, true, PAGE_EXECUTE_WRITECOPY));
    assert!(decide_mapview_protection(false, true, PAGE_EXECUTE_READ));
}

#[test]
fn decide_private_exec_denied() {
    // Anonymous (MEM_PRIVATE) executable mapping: shellcode pattern → deny.
    assert!(!decide_mapview_protection(false, false, PAGE_EXECUTE_WRITECOPY));
    assert!(!decide_mapview_protection(false, false, PAGE_EXECUTE_READWRITE));
    assert!(!decide_mapview_protection(false, false, PAGE_EXECUTE_READ));
    assert!(!decide_mapview_protection(false, false, PAGE_EXECUTE));
}

#[test]
fn decide_private_non_exec_allowed() {
    // Anonymous non-executable mapping: fine (data).
    assert!(decide_mapview_protection(false, false, 0x04)); // PAGE_READWRITE
    assert!(decide_mapview_protection(false, false, 0x02)); // PAGE_READONLY
}

#[test]
fn decide_vquery_fail_exec_denied() {
    // When VirtualQuery fails (is_file_backed=false, is_image=false),
    // treat as anonymous → deny if executable.
    assert!(!decide_mapview_protection(false, false, PAGE_EXECUTE));
    // Non-executable with VirtualQuery failure: allow.
    assert!(decide_mapview_protection(false, false, 0x04));
}

// -------------------------------------------------------------------------
// Hook-integrity protection (P0-01) tests
// -------------------------------------------------------------------------

#[test]
fn grants_write_matrix() {
    assert!(grants_write(0x04)); // PAGE_READWRITE — the P0-01 hole
    assert!(grants_write(0x08)); // PAGE_WRITECOPY (CoW image write)
    assert!(grants_write(PAGE_EXECUTE_READWRITE));
    assert!(grants_write(PAGE_EXECUTE_WRITECOPY));
    // Modifiers must not defeat the bit test.
    assert!(grants_write(0x04 | 0x100)); // PAGE_READWRITE | PAGE_GUARD
    // Read/execute-only grants are not write grants.
    assert!(!grants_write(0x02)); // PAGE_READONLY
    assert!(!grants_write(0x01)); // PAGE_NOACCESS
    assert!(!grants_write(PAGE_EXECUTE));
    assert!(!grants_write(PAGE_EXECUTE_READ));
    assert!(!grants_write(0));
}

#[test]
fn critical_range_response_matrix() {
    use CriticalRangeResponse::{Allow, Terminate, Verify};
    // Regression core: a WRITE grant on a critical range terminates even
    // though the pre-fix logic only inspected EXECUTE grants and let
    // PAGE_READWRITE straight through.
    assert_eq!(critical_range_response(true, grants_write(0x04)), Terminate);
    assert_eq!(critical_range_response(true, grants_write(PAGE_EXECUTE_READWRITE)), Terminate);
    assert_eq!(critical_range_response(true, grants_write(0x08)), Terminate);
    // Non-write protection changes on critical ranges: allow + verify.
    assert_eq!(critical_range_response(true, grants_write(PAGE_EXECUTE_READ)), Verify);
    assert_eq!(critical_range_response(true, grants_write(0x01)), Verify);
    // Outside critical ranges the pre-fix behaviour is preserved.
    assert_eq!(critical_range_response(false, grants_write(0x04)), Allow);
    assert_eq!(critical_range_response(false, grants_write(PAGE_EXECUTE_READWRITE)), Allow);
}

#[test]
fn overlaps_critical_exec_covers_hooked_ntdll_stubs() {
    // The P0-01 scenario: making a HOOKED ntdll page writable must land in
    // the deny zone. Both the module base and a real syscall-stub export
    // are executable MEM_IMAGE pages of a critical module.
    // SAFETY: ntdll.dll is always loaded; GetProcAddress on a valid module
    // with a NUL-terminated name.
    let (ntdll_base, ntdll_create_file) = unsafe {
        let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let hmod = winapi::um::libloaderapi::GetModuleHandleW(name.as_ptr());
        assert!(!hmod.is_null());
        let proc_addr = winapi::um::libloaderapi::GetProcAddress(
            hmod,
            b"NtCreateFile\0".as_ptr() as *const i8,
        );
        assert!(
            !proc_addr.is_null(),
            "NtCreateFile export must resolve"
        );
        (hmod, proc_addr)
    };
    let stub = ntdll_create_file as usize as *const c_void;
    assert!(overlaps_critical_exec(ntdll_base as *const c_void, 0x2000));
    assert!(
        overlaps_critical_exec(stub, 16),
        "a hooked ntdll stub address must be inside the critical-exec deny zone"
    );
    // Non-critical memory stays outside the deny zone.
    let heap = vec![0u8; 64];
    assert!(!overlaps_critical_exec(heap.as_ptr() as *const c_void, 64));
    assert!(!overlaps_critical_exec(std::ptr::null(), 64));
    assert!(!overlaps_critical_exec(ntdll_base as *const c_void, 0));
}

#[test]
fn overlaps_critical_exec_covers_own_image() {
    // hook.dll's own image is not under System32; the own-image span check
    // must classify it as critical. In the unit-test binary this resolves
    // to the test executable — the span logic under test is identical.
    assert!(overlaps_critical_exec(own_image_marker as *const c_void, 16));
}

#[test]
fn own_image_span_resolution() {
    let (base, end) = own_image_span().expect("own image span must resolve");
    assert!(end > base);
    let marker = own_image_marker as *const () as usize;
    assert!(marker >= base && marker < end);
    let heap = vec![0u8; 64];
    let hp = heap.as_ptr() as usize;
    assert!(hp < base || hp >= end);
}

#[test]
fn detour_tamper_detection() {
    // Snapshot intact → clean.
    assert_eq!(
        first_tampered_detour(&[(0x1000, [0xE9, 0x10])], |_| Some([0xE9, 0x10])),
        None
    );
    // Original ntdll prologue restored (4c 8b d1 ...) → tampered.
    assert_eq!(
        first_tampered_detour(&[(0x1000, [0xE9, 0x10])], |_| Some([0x4C, 0x8B])),
        Some(0x1000)
    );
    // x64 absolute-jump detour form (ff 25 ...) is a valid patched prologue.
    assert_eq!(
        first_tampered_detour(&[(0x2000, [0xFF, 0x25])], |_| Some([0xFF, 0x25])),
        None
    );
    // Unreadable page → fail closed.
    assert_eq!(first_tampered_detour(&[(0x3000, [0xE9, 0x10])], |_| None), Some(0x3000));
    // Multi-entry watch: reports the tampered entry.
    let watch = [(0x1000, [0xE9, 0x10]), (0x2000, [0xFF, 0x25])];
    assert_eq!(
        first_tampered_detour(&watch, |a| if a == 0x2000 {
            Some([0x4C, 0x8B])
        } else {
            Some([0xE9, 0x10])
        }),
        Some(0x2000)
    );
}

#[test]
fn detour_bytes_tampered_fail_closed() {
    assert!(!detour_bytes_tampered([0xE9, 0x10], Some([0xE9, 0x10])));
    assert!(detour_bytes_tampered([0xE9, 0x10], Some([0x4C, 0x8B])));
    assert!(detour_bytes_tampered([0xE9, 0x10], None));
}

#[test]
fn detour_watch_is_clean_in_test_process() {
    // The unit-test binary never runs install(), so the watch is empty and
    // verification is a no-op; under a real sandboxed process the watch
    // holds every installed detour and this same call must return None
    // while the hooks are intact. Pins the no-tamper contract end to end.
    let watch = DETOUR_WATCH.lock().unwrap();
    assert_eq!(first_tampered_detour(&watch, read_code_bytes), None);
}

// -------------------------------------------------------------------------
// Full-region chunked scan (audit 2026-09-19, Medium — 64 MB scan cap)
// -------------------------------------------------------------------------

#[test]
fn region_scan_empty_is_clean() {
    assert!(!region_has_direct_syscalls_with(&[], 0x1000, false, 4));
    assert!(!region_has_direct_syscalls(&[], 0x1000, false));
}

#[test]
fn region_scan_finds_syscall_in_first_chunk() {
    let mut bytes = [0x90u8; 64];
    bytes[2] = 0x0F;
    bytes[3] = 0x05;
    assert!(region_has_direct_syscalls_with(&bytes, 0x1000, false, 4));
    assert!(!region_has_direct_syscalls_with(&[0x90u8; 64], 0x1000, false, 4));
}

#[test]
fn region_scan_finds_syscall_straddling_chunk_boundary() {
    // chunk_size 4 with a 15-byte forward overlap: the 0F 05 pair starts
    // one byte before the chunk boundary and must still be decoded.
    let mut bytes = [0x90u8; 64];
    bytes[3] = 0x0F;
    bytes[4] = 0x05;
    assert!(region_has_direct_syscalls_with(&bytes, 0x1000, false, 4));
}

#[test]
fn region_scan_finds_syscall_in_last_chunk() {
    let mut bytes = [0x90u8; 64];
    bytes[62] = 0x0F;
    bytes[63] = 0x05;
    assert!(region_has_direct_syscalls_with(&bytes, 0x1000, false, 4));
}

#[test]
fn region_scan_clean_region_stays_clean_with_cache() {
    let bytes = [0x90u8; 64];
    assert!(!region_has_direct_syscalls_with(&bytes, 0x42000, true, 4));
    // Second transition of the same pages: cache-served, same verdict.
    assert!(!region_has_direct_syscalls_with(&bytes, 0x42000, true, 4));
}

#[test]
fn region_scan_covers_full_chunked_region() {
    // Region larger than one decode chunk: coverage must NOT stop at the
    // chunk size (the old code skipped regions past a 64 MB cap entirely).
    let n = SCAN_CHUNK_BYTES + 1;
    let base = 0x7000_0000usize;
    // Hit straddling the first chunk boundary.
    let mut mid = vec![0x90u8; n];
    mid[SCAN_CHUNK_BYTES - 1] = 0x0F;
    mid[SCAN_CHUNK_BYTES] = 0x05;
    assert!(
        region_has_direct_syscalls(&mid, base, false),
        "syscall at the first chunk boundary must be found"
    );
    // Fresh region: hit only in the final partial chunk — proves the tail
    // is scanned. A cap here would be fail-open by construction.
    let mut tail = vec![0x90u8; n];
    tail[n - 2] = 0x0F;
    tail[n - 1] = 0x05;
    assert!(
        region_has_direct_syscalls(&tail, base + 0x1000, false),
        "syscall in the final partial chunk must be found"
    );
}

// -------------------------------------------------------------------------
// Scan-cache single-hash (XA review 2026-09-20, guard:939 + cache:26): a
// miss must hash the chunk ONCE — the key computed for the lookup is
// reused for the clean insert, and the miss path scans via the bool
// predicate without re-hashing.
// -------------------------------------------------------------------------

/// The compute-key counter is process-global and cargo test runs tests on
/// parallel threads, so the reset → scan → assert sequence runs under the
/// scan_cache measurement gate (compute_key itself never takes that gate —
/// the production path stays lock-free).
#[test]
fn scan_cache_miss_hashes_each_chunk_exactly_once() {
    crate::scan_cache::with_compute_key_gate(|| {
        crate::scan_cache::reset_compute_key_calls();
        let bytes = [0x90u8; 256];
        // 4 chunks: lookup_keyed hashes once per chunk; the miss path
        // scans via the bool predicate and the clean insert reuses the key.
        assert!(!region_has_direct_syscalls_with(&bytes, 0x41000, true, 64));
        assert_eq!(
            crate::scan_cache::compute_key_calls(),
            4,
            "first pass: exactly one hash per chunk"
        );
        // Second pass: all four chunks are cache hits — lookup hashes only.
        assert!(!region_has_direct_syscalls_with(&bytes, 0x41000, true, 64));
        assert_eq!(
            crate::scan_cache::compute_key_calls(),
            8,
            "second pass: one hash per chunk for the lookup, none for the insert"
        );
    });
}

// -------------------------------------------------------------------------
// Foreign NtWriteVirtualMemory decision (audit 2026-09-19, Medium)
// -------------------------------------------------------------------------

#[test]
fn foreign_write_decision_matrix() {
    const SELF: u32 = 4242;
    // Unresolvable identity (pid 0): an invalid handle, or — a documented
    // GetProcessId failure mode (XA review R02) — a handle with mutation
    // rights but no PROCESS_QUERY_LIMITED_INFORMATION. Unknown identity is
    // denied exactly like a known-foreign target, never a pass-through.
    assert_eq!(foreign_write_decision(0, SELF, false), ForeignWriteDecision::Deny);
    assert_eq!(foreign_write_decision(0, SELF, true), ForeignWriteDecision::Deny);
    // Real handle to self (defensive — is_current_process catches it first).
    assert_eq!(foreign_write_decision(SELF, SELF, false), ForeignWriteDecision::Allow);
    // Owned child: legitimate launcher injection.
    assert_eq!(foreign_write_decision(777, SELF, true), ForeignWriteDecision::Allow);
    // Regression core: ANY other target is denied. The old code
    // content-scanned the buffer and allowed everything whose shape it
    // did not recognise.
    assert_eq!(foreign_write_decision(999, SELF, false), ForeignWriteDecision::Deny);
    assert_eq!(foreign_write_decision(4, SELF, false), ForeignWriteDecision::Deny);
}

// -------------------------------------------------------------------------
// pid-0 deny helpers (XA review R02): unresolvable identity is not a pass
// -------------------------------------------------------------------------

#[test]
fn map_foreign_denied_matrix() {
    const SELF: u32 = 4242;
    // pid 0 = unresolvable identity (XA R02) → denied, like any foreign.
    assert!(map_foreign_denied(0, SELF));
    // Self via a real handle passes (the pseudo-handle is caught before
    // this decision runs).
    assert!(!map_foreign_denied(SELF, SELF));
    // Any real foreign target is denied.
    assert!(map_foreign_denied(999, SELF));
}

#[test]
fn unmap_foreign_denied_matrix() {
    const SELF: u32 = 4242;
    // pid 0 = unresolvable identity (XA R02) → denied, like any foreign.
    assert!(unmap_foreign_denied(0, SELF));
    // Self passes.
    assert!(!unmap_foreign_denied(SELF, SELF));
    // Any real foreign target is denied (owned children included —
    // unmapping their image is Process Hollowing).
    assert!(unmap_foreign_denied(999, SELF));
    assert!(unmap_foreign_denied(777, SELF));
}

#[test]
fn protect_foreign_exec_kill_matrix() {
    // pid 0 with an executable protect: unresolvable identity (XA R02)
    // → killed like any foreign target.
    assert!(protect_foreign_exec_kill(0, false, PAGE_EXECUTE_READWRITE));
    // pid 0 with a non-executable protect: keeps passing, matching the
    // existing foreign policy for data allocations.
    assert!(!protect_foreign_exec_kill(0, false, PAGE_READWRITE));
    // Tracked owned child: legitimate launcher injection, never a kill.
    assert!(!protect_foreign_exec_kill(777, true, PAGE_EXECUTE_READWRITE));
    // Real foreign target with an executable protect: the injection
    // primitive itself.
    assert!(protect_foreign_exec_kill(999, false, PAGE_EXECUTE));
}

/// The pid-0 deny paths above rely on the tracker contract that pid 0 is
/// never a tracked child (mark_spawned is gated on child_pid != 0 in
/// core/hooks/spawn.rs) — pin it, so a tracker change re-opens R02 loudly.
#[test]
fn pid_zero_is_never_a_tracked_child() {
    assert!(!crate::process_tracker::is_owned_child(0));
}

// -------------------------------------------------------------------------
// allow_rwx snapshot (audit 2026-09-19 High)
// -------------------------------------------------------------------------

/// Serializes env-mutating tests: the environment is process-wide while
/// cargo test runs tests on parallel threads (same pattern as launcher
/// nested_detection_tests::ENV_LOCK, added after exactly that flake).
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// RAII guard restoring FS_SANDBOX_ALLOW_RWX on drop.
struct AllowRwxEnvGuard(Option<std::ffi::OsString>);

impl AllowRwxEnvGuard {
    fn capture() -> Self {
        AllowRwxEnvGuard(std::env::var_os("FS_SANDBOX_ALLOW_RWX"))
    }
}

impl Drop for AllowRwxEnvGuard {
    fn drop(&mut self) {
        match &self.0 {
            Some(v) => std::env::set_var("FS_SANDBOX_ALLOW_RWX", v),
            None => std::env::remove_var("FS_SANDBOX_ALLOW_RWX"),
        }
    }
}

/// Regression core: the guest sets FS_SANDBOX_ALLOW_RWX after startup —
/// the per-decision gate must keep following the install-time snapshot,
/// not the (guest-writable) environment.
#[test]
fn allow_rwx_snapshot_ignores_later_env_set() {
    let _lock = env_lock();
    let _g = AllowRwxEnvGuard::capture();
    std::env::remove_var("FS_SANDBOX_ALLOW_RWX");
    test_set_allow_rwx(false);
    std::env::set_var("FS_SANDBOX_ALLOW_RWX", "1");
    assert!(
        !allow_rwx(),
        "post-startup FS_SANDBOX_ALLOW_RWX=1 must not flip the snapshot"
    );
}

#[test]
fn allow_rwx_snapshot_true_survives_env_removal() {
    let _lock = env_lock();
    let _g = AllowRwxEnvGuard::capture();
    std::env::set_var("FS_SANDBOX_ALLOW_RWX", "1");
    test_set_allow_rwx(true);
    std::env::remove_var("FS_SANDBOX_ALLOW_RWX");
    assert!(
        allow_rwx(),
        "post-startup env removal must not flip the snapshot"
    );
}

// -----------------------------------------------------------------
// Sibling-entry closure (audit High) tests: see tests::alloc_ex_sibling.

// -----------------------------------------------------------------
// S03 (XA review 2026-09-20): fault-safe guarded read for the
// protect-hook content scan. The scan must (a) return an error
// verdict for unreadable caller-controlled memory instead of
// faulting — an in-window fault dispatches the guest's own VEH with
// anti_rec still set — and (b) keep finding syscall bytes through
// the copy. The negative control reproduces the exact pre-fix
// dereference in a THROWAWAY CHILD PROCESS, because an unguarded
// fault cannot be caught in-process on Windows: no Rust or
// test-harness construct catches a hardware access violation, the
// child dies with STATUS_ACCESS_VIOLATION, and the parent asserts
// on that exit code.
// -----------------------------------------------------------------

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use winapi::um::winnt::{
    EXCEPTION_POINTERS, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE,
    STATUS_ACCESS_VIOLATION,
};

/// Serializes every test below that registers a vectored exception
/// handler: the VEH list is process-wide, so concurrent registration /
/// counters would make the fault-count assertions racy.
static S03_VEH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

static S03_VEH_HITS: AtomicUsize = AtomicUsize::new(0);
static S03_VEH_ARMED: AtomicBool = AtomicBool::new(false);
static S03_VEH_LO: AtomicUsize = AtomicUsize::new(0);
static S03_VEH_HI: AtomicUsize = AtomicUsize::new(0);

/// VEH that only COUNTS access violations inside the armed range, then
/// always continues search. Proves the guarded read raises NO
/// user-mode exception: if any AV reached exception dispatch inside the
/// watched range, this counter would move.
unsafe extern "system" fn s03_veh_counter(info: *mut EXCEPTION_POINTERS) -> i32 {
    if S03_VEH_ARMED.load(Ordering::Acquire) {
        let rec = unsafe { (*info).ExceptionRecord };
        if !rec.is_null() {
            let code = unsafe { (*rec).ExceptionCode };
            if code as u32 == STATUS_ACCESS_VIOLATION {
                let fault = unsafe { (*rec).ExceptionInformation[1] };
                let lo = S03_VEH_LO.load(Ordering::Relaxed);
                let hi = S03_VEH_HI.load(Ordering::Relaxed);
                if lo != 0 && fault >= lo && fault < hi {
                    S03_VEH_HITS.fetch_add(1, Ordering::Release);
                }
            }
        }
    }
    0 // EXCEPTION_CONTINUE_SEARCH — we only observe, never interfere
}

struct S03Veh {
    _lock: std::sync::MutexGuard<'static, ()>,
    handle: *mut winapi::ctypes::c_void,
}

impl S03Veh {
    /// Register the counting VEH and arm it for the half-open range.
    /// The process-wide VEH list is serialized via the held mutex for
    /// the lifetime of the guard.
    fn arm(range_base: *const u8, range_len: usize) -> S03Veh {
        let lock = S03_VEH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        S03_VEH_HITS.store(0, Ordering::SeqCst);
        S03_VEH_LO.store(range_base as usize, Ordering::SeqCst);
        S03_VEH_HI.store(range_base as usize + range_len, Ordering::SeqCst);
        S03_VEH_ARMED.store(true, Ordering::Release);
        // SAFETY: handler is a valid vectored-handler fn; NULL return
        // means registration failed, which we refuse to skip.
        let handle = unsafe {
            winapi::um::errhandlingapi::AddVectoredExceptionHandler(1, Some(s03_veh_counter))
        };
        assert!(!handle.is_null(), "AddVectoredExceptionHandler must succeed");
        S03Veh { _lock: lock, handle }
    }

    fn hits(&self) -> usize {
        S03_VEH_HITS.load(Ordering::Acquire)
    }
}

impl Drop for S03Veh {
    fn drop(&mut self) {
        // SAFETY: handle came from AddVectoredExceptionHandler above.
        unsafe { winapi::um::errhandlingapi::RemoveVectoredExceptionHandler(self.handle) };
        S03_VEH_ARMED.store(false, Ordering::SeqCst);
        S03_VEH_LO.store(0, Ordering::SeqCst);
        S03_VEH_HI.store(0, Ordering::SeqCst);
    }
}

/// Allocate `pages` committed RW pages; returns the page-aligned base.
/// Refuses NULL — a NULL base would fault in the tests' own setup.
fn s03_alloc_rw_pages(pages: usize) -> *mut u8 {
    // SAFETY: plain VirtualAlloc with commit+reserve; NULL on failure,
    // which we assert on.
    let p = unsafe {
        winapi::um::memoryapi::VirtualAlloc(
            std::ptr::null_mut(),
            pages * 4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    assert!(!p.is_null(), "VirtualAlloc must succeed for S03 tests");
    p as *mut u8
}

unsafe fn s03_protect(addr: *mut u8, size: usize, protect: u32) {
    let mut old: u32 = 0;
    // SAFETY: addr..addr+size is a live allocation from s03_alloc_rw_pages.
    let ok = winapi::um::memoryapi::VirtualProtect(addr as *mut winapi::ctypes::c_void, size, protect, &mut old);
    assert!(ok != 0, "VirtualProtect must succeed for S03 tests");
}

unsafe fn s03_free(addr: *mut u8) {
    // SAFETY: addr is the base returned by VirtualAlloc; MEM_RELEASE
    // with size 0 frees the whole allocation.
    let ok = winapi::um::memoryapi::VirtualFree(addr as *mut winapi::ctypes::c_void, 0, MEM_RELEASE);
    assert!(ok != 0, "VirtualFree must succeed for S03 tests");
}

#[test]
fn s03_guarded_copy_fails_on_noaccess_page_without_fault() {
    let page = s03_alloc_rw_pages(1);
    unsafe { std::ptr::write_bytes(page, 0x90, 4096) };
    unsafe { s03_protect(page, 4096, PAGE_NOACCESS) };
    let veh = S03Veh::arm(page, 4096);
    // Enter the exact S03 window condition: anti_rec held while the
    // guarded copy (inside the scan) runs.
    let _g = crate::anti_rec::enter().unwrap();
    let verdict = guarded_scan_region(page, 4096, false);
    drop(_g);
    assert_eq!(
        verdict,
        GuardedScanVerdict::Unreadable,
        "guarded copy must report failure for PAGE_NOACCESS"
    );
    assert_eq!(
        veh.hits(),
        0,
        "guarded copy must not raise ANY user-mode exception (guest VEH would observe anti_rec)"
    );
    // The window must have survived the failed read and been released
    // normally afterwards — a fault would have skipped this drop.
    assert!(!crate::anti_rec::in_hook(), "anti_rec must be clear after the guarded copy");
    drop(veh);
    unsafe { s03_protect(page, 4096, PAGE_READWRITE) };
    unsafe { s03_free(page) };
}

#[test]
fn s03_guarded_copy_reads_readable_memory() {
    // Positive control: the guarded copy must actually READ the memory,
    // not just always fail — otherwise the failure tests would be
    // vacuous. guarded_region_copy is private to detours, so the copy is
    // observed through its only in-scope caller (guarded_scan_region):
    // syscall bytes at the very END of a readable page can only be found
    // if the FULL page was copied (the strict full-length contract).
    let page = s03_alloc_rw_pages(1);
    unsafe { std::ptr::write_bytes(page, 0xA5, 4096) };
    unsafe { page.add(4094).write(0x0F) };
    unsafe { page.add(4095).write(0x05) };
    let veh = S03Veh::arm(page, 4096);
    let verdict = guarded_scan_region(page, 4096, false);
    assert_eq!(
        verdict,
        GuardedScanVerdict::SyscallsFound,
        "guarded copy must succeed on a readable page (full length copied)"
    );
    assert_eq!(veh.hits(), 0, "copying readable memory must not fault");
    drop(veh);
    // Control arm: same-size readable page WITHOUT syscall bytes must
    // come back Clean — the verdict is content-driven, not hardwired.
    let clean = s03_alloc_rw_pages(1);
    unsafe { std::ptr::write_bytes(clean, 0xA5, 4096) };
    assert_eq!(guarded_scan_region(clean, 4096, false), GuardedScanVerdict::Clean);
    unsafe { s03_free(page) };
    unsafe { s03_free(clean) };
}

#[test]
fn s03_guarded_scan_unreadable_region_is_unreadable_not_fault() {
    let page = s03_alloc_rw_pages(1);
    unsafe { std::ptr::write_bytes(page, 0x90, 4096) };
    unsafe { s03_protect(page, 4096, PAGE_NOACCESS) };
    let veh = S03Veh::arm(page, 4096);
    let verdict = guarded_scan_region(page, 4096, false);
    assert_eq!(verdict, GuardedScanVerdict::Unreadable);
    assert_eq!(veh.hits(), 0, "scan of unreadable memory must not fault");
    drop(veh);
    unsafe { s03_protect(page, 4096, PAGE_READWRITE) };
    unsafe { s03_free(page) };
}

#[test]
fn s03_guarded_scan_partial_readable_region_is_unreadable() {
    // One readable page followed by one NOACCESS page: a partial copy
    // must fail the WHOLE region (fail-closed), not scan the readable
    // part and allow the protect.
    let pages = s03_alloc_rw_pages(2);
    unsafe { std::ptr::write_bytes(pages, 0x90, 8192) };
    unsafe { s03_protect(pages.add(4096), 4096, PAGE_NOACCESS) };
    let veh = S03Veh::arm(pages, 8192);
    let verdict = guarded_scan_region(pages, 8192, false);
    assert_eq!(verdict, GuardedScanVerdict::Unreadable);
    assert_eq!(veh.hits(), 0, "partial copy must fail cleanly, not fault");
    drop(veh);
    unsafe { s03_protect(pages, 8192, PAGE_READWRITE) };
    unsafe { s03_free(pages) };
}

#[test]
fn s03_guarded_scan_finds_syscall_bytes_in_readable_region() {
    // Positive control for the copy+scan pipeline: syscall bytes in a
    // readable region must still be found through the guarded copy.
    let page = s03_alloc_rw_pages(1);
    unsafe { std::ptr::write_bytes(page, 0x90, 4096) };
    unsafe { page.add(1024).write(0x0F) };
    unsafe { page.add(1025).write(0x05) };
    let verdict = guarded_scan_region(page, 4096, false);
    assert_eq!(verdict, GuardedScanVerdict::SyscallsFound);
    unsafe { s03_free(page) };
}

#[test]
fn s03_protect_scan_response_maps_verdicts_fail_closed() {
    use GuardedScanVerdict as V;
    assert_eq!(protect_scan_response(V::Clean), ProtectScanResponse::Proceed);
    assert_eq!(protect_scan_response(V::SyscallsFound), ProtectScanResponse::Kill);
    // The load-bearing mapping: unreadable MUST deny, never proceed —
    // skipping the scan would let unreadable syscall payloads become
    // executable unscanned.
    assert_eq!(protect_scan_response(V::Unreadable), ProtectScanResponse::Deny);
}

const S03_RAW_PROBE_ENV: &str = "WINRSBOX_S03_RAW_READ_PROBE";
// Full libtest path — `--exact` matches the whole `module::path::name`,
// not just the trailing segment.
const S03_NEGATIVE_TEST_NAME: &str =
    "memory_guard::tests::s03_negative_unguarded_raw_read_faults_on_noaccess_page";

#[test]
fn s03_negative_unguarded_raw_read_faults_on_noaccess_page() {
    if std::env::var(S03_RAW_PROBE_ENV).is_ok() {
        // CHILD role (spawned by the parent below with the probe env
        // set): reproduce the EXACT pre-fix dereference — a
        // from_raw_parts slice over caller-controlled PAGE_NOACCESS
        // memory, dereferenced by the scanner — and die on it. Nothing
        // here may catch the fault: the point is that the pre-fix path
        // has no guard.
        let page = s03_alloc_rw_pages(1);
        unsafe { std::ptr::write_bytes(page, 0x90, 4096) };
        unsafe { s03_protect(page, 4096, PAGE_NOACCESS) };
        // SAFETY: this dereference is INTENDED to raise an access
        // violation (negative control for the guarded fix); the process
        // must die here, which the parent asserts via the exit code.
        let bytes = unsafe { std::slice::from_raw_parts(page, 4096) };
        let _ = ::policy::scan::find_direct_syscalls(bytes, page as u64);
        // Unreachable when the fault fires. Reaching this means the
        // negative control is broken and the parent's exit-code assert
        // fails loudly.
        unsafe { s03_protect(page, 4096, PAGE_READWRITE) };
        unsafe { s03_free(page) };
        return;
    }

    // PARENT role: run this test binary again, only this test, with the
    // probe env set, and require the unguarded read to have killed the
    // child with STATUS_ACCESS_VIOLATION (0xC0000005).
    let exe = std::env::current_exe().expect("current_exe must resolve the test binary");
    let status = std::process::Command::new(exe)
        .args([S03_NEGATIVE_TEST_NAME, "--exact"])
        .env(S03_RAW_PROBE_ENV, "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("spawning the negative-control child must succeed");
    assert_eq!(
        status.code(),
        Some(0xC0000005u32 as i32),
        "pre-fix unguarded read must fault with STATUS_ACCESS_VIOLATION; got {status:?}"
    );
}

// ---------------------------------------------------------------------------
// S06 (XA review 2026-09-20) — protect-scan page rounding, TOCTOU record,
// sibling-cap structural guard
// ---------------------------------------------------------------------------

#[test]
fn s06_page_rounding_covers_bytes_outside_passed_range() {
    // Rounding must (a) keep the caller range covered and (b) extend to the
    // full pages the kernel flips — bytes outside [addr, addr+size) on both
    // edges.
    let (start, len) = page_round_scan_range(0x1234, 0x10).expect("in-range values must round");
    assert_eq!(start, 0x1000);
    // 0x1234..0x1244 lies entirely inside page 0x1000 → exactly one page.
    assert_eq!(len, 0x1000);
    assert!(start < 0x1234, "must extend below the passed range");
    assert!(start + len > 0x1244, "must extend above the passed range");

    // Two-page span: a range ending inside the NEXT page rounds out to both.
    let (start, len) = page_round_scan_range(0x1FF4, 0x10).expect("in-range values must round");
    assert_eq!(start, 0x1000);
    assert_eq!(len, 0x2000);

    // Overflow → None → the hook fails closed (Deny), never skips the scan.
    assert_eq!(page_round_scan_range(usize::MAX, 8), None);
    assert_eq!(page_round_scan_range(usize::MAX - 4, 8), None);
}

#[test]
fn s06_rounded_scan_finds_syscall_outside_caller_range_same_page() {
    // A syscall pair on the SAME page but outside the caller-passed byte
    // range is invisible to the unrounded scan and must be found by the
    // rounded range the protect hook actually scans (S06 gap 1).
    let page = s03_alloc_rw_pages(1);
    unsafe { std::ptr::write_bytes(page, 0x90, 4096) };
    unsafe { page.add(4000).write(0x0F) };
    unsafe { page.add(4001).write(0x05) };
    // The caller passes a clean 8-byte range at page+16 (same page).
    let inner = unsafe { page.add(16) };
    assert_eq!(
        guarded_scan_region(inner, 8, false),
        GuardedScanVerdict::Clean,
        "pre-condition: unrounded scan must not see beyond the passed range"
    );
    let (start, len) = page_round_scan_range(page as usize + 16, 8).unwrap();
    assert_eq!(start, page as usize);
    assert_eq!(len, 4096);
    assert_eq!(
        guarded_scan_region(start as *const u8, len, false),
        GuardedScanVerdict::SyscallsFound,
        "page-rounded scan must cover the neighboring bytes the kernel flips"
    );
    unsafe { s03_free(page) };
}

const S06_TOCTOU_LIMITATION_MARKER: &str = "KNOWN LIMITATION (TOCTOU)";

/// S06 gap 5: the TOCTOU residual on the scan itself must stay recorded in
/// detours.rs. If this fails, the limitation text was deleted — restore it
/// (see `guarded_scan_region_twice`) or close the race for real; deleting
/// the record is not an option.
#[test]
fn s06_toctou_limitation_stays_documented() {
    let src = include_str!("detours.rs");
    assert!(
        src.contains(S06_TOCTOU_LIMITATION_MARKER),
        "the S06 TOCTOU known-limitation record vanished from memory_guard/detours.rs"
    );
}

/// S06 gap 4 (hook side): the child-image scan (core/hooks/spawn.rs) must
/// not carry the silent 64 MiB truncation cap — the tail of a large section
/// used to go unchecked. Structural on purpose: the cap is a one-line
/// regression magnet.
#[test]
fn s06_child_scan_has_no_64mib_cap() {
    let src = include_str!("../../core/hooks/spawn.rs");
    assert!(
        !src.contains("64 * 1024 * 1024"),
        "the 64 MiB scan cap must stay out of the child-image scan (S06 gap 4)"
    );
}
