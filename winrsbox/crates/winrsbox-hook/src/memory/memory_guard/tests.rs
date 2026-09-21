use super::*;

#[test]
fn is_executable_page_readwrite() {
    assert!(!is_executable(0x04)); // PAGE_READWRITE
}

#[test]
fn is_executable_page_execute() {
    assert!(is_executable(PAGE_EXECUTE));
}

#[test]
fn is_executable_page_execute_read() {
    assert!(is_executable(PAGE_EXECUTE_READ));
}

#[test]
fn is_executable_page_execute_readwrite() {
    assert!(is_executable(PAGE_EXECUTE_READWRITE));
}

#[test]
fn is_executable_page_execute_writecopy() {
    assert!(is_executable(PAGE_EXECUTE_WRITECOPY));
}

#[test]
fn is_executable_page_noaccess() {
    assert!(!is_executable(0x01)); // PAGE_NOACCESS
}

#[test]
fn is_executable_page_readonly() {
    assert!(!is_executable(0x02)); // PAGE_READONLY
}

#[test]
fn is_executable_combined_guard() {
    // PAGE_EXECUTE_READ | PAGE_GUARD (0x100)
    assert!(is_executable(0x20 | 0x100));
}

#[test]
fn is_executable_zero() {
    assert!(!is_executable(0));
}

#[test]
fn protect_name_covers_all_exec() {
    assert_eq!(protect_name(PAGE_EXECUTE_READWRITE), "PAGE_EXECUTE_READWRITE");
    assert_eq!(protect_name(PAGE_EXECUTE_WRITECOPY), "PAGE_EXECUTE_WRITECOPY");
    assert_eq!(protect_name(PAGE_EXECUTE_READ), "PAGE_EXECUTE_READ");
    assert_eq!(protect_name(PAGE_EXECUTE), "PAGE_EXECUTE");
    assert_eq!(protect_name(0x04), "non-execute");
}

#[test]
fn is_address_in_module_null() {
    assert!(!is_address_in_module(std::ptr::null()));
}

#[test]
fn is_address_in_module_ntdll() {
    // GetModuleHandleW("ntdll.dll") gives us an address inside ntdll.
    // SAFETY: ntdll.dll is always loaded.
    let hmod = unsafe {
        let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        winapi::um::libloaderapi::GetModuleHandleW(name.as_ptr())
    };
    assert!(!hmod.is_null());
    // The module handle IS the base address — it's inside the module.
    assert!(is_address_in_module(hmod as *const c_void));
}

#[test]
fn is_address_in_module_heap_allocation() {
    // Heap allocation is NOT in any module.
    let v = vec![0u8; 64];
    assert!(!is_address_in_module(v.as_ptr() as *const c_void));
}

#[test]
fn module_path_for_ntdll() {
    let hmod = unsafe {
        let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        winapi::um::libloaderapi::GetModuleHandleW(name.as_ptr())
    };
    let path = module_path_for_address(hmod as *const c_void);
    assert!(path.is_some());
    let p = path.unwrap().to_lowercase();
    assert!(p.contains("ntdll.dll"), "got: {p}");
}

#[test]
fn module_path_for_heap_is_none() {
    let v = vec![0u8; 64];
    assert!(module_path_for_address(v.as_ptr() as *const c_void).is_none());
}

#[test]
fn nt_current_process_check() {
    assert!(is_current_process(-1isize as HANDLE));
    assert!(!is_current_process(std::ptr::null_mut()));
    assert!(!is_current_process(42usize as HANDLE));
}

#[test]
fn critical_dll_detection() {
    assert!(is_critical_dll("ntdll.dll"));
    assert!(is_critical_dll("kernel32.dll"));
    assert!(is_critical_dll("kernelbase.dll"));
    assert!(is_critical_dll("hook.dll"));
    assert!(!is_critical_dll("user32.dll"));
    assert!(!is_critical_dll("evil.dll"));
    assert!(!is_critical_dll(""));
}

#[test]
fn extract_basename_lower_works() {
    assert_eq!(extract_basename_lower(r"C:\Windows\System32\ntdll.dll"), "ntdll.dll");
    assert_eq!(extract_basename_lower(r"\Device\HarddiskVolume3\Windows\System32\kernel32.dll"), "kernel32.dll");
    assert_eq!(extract_basename_lower("hook.dll"), "hook.dll");
    assert_eq!(extract_basename_lower(""), "");
}

#[test]
fn is_image_mapping_for_ntdll_base() {
    // ntdll's base should be MEM_IMAGE
    let hmod = unsafe {
        let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        winapi::um::libloaderapi::GetModuleHandleW(name.as_ptr())
    };
    assert!(!hmod.is_null());
    assert!(is_image_mapping(hmod as *const c_void));
}

#[test]
fn is_image_mapping_for_heap_is_false() {
    let v = vec![0u8; 64];
    assert!(!is_image_mapping(v.as_ptr() as *const c_void));
}

#[test]
fn is_system_dll_path_under_matches_whole_components() {
    // Previously-trusted layouts stay trusted under an explicit canonical
    // root; matching is whole-component, never substring.
    let root = r"\Device\HarddiskVolume3\Windows";
    assert!(is_system_dll_path_under(r"\Device\HarddiskVolume3\Windows\System32\user32.dll", root));
    assert!(is_system_dll_path_under(r"\Device\HarddiskVolume3\Windows\SysWOW64\kernel32.dll", root));
    assert!(is_system_dll_path_under(r"\device\harddiskvolume3\windows\system32\ntdll.dll", root));
    assert!(is_system_dll_path_under(
        r"\Device\HarddiskVolume3\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll",
        root
    ));
    assert!(is_system_dll_path_under(
        r"\Device\HarddiskVolume3\Windows\assembly\NativeImages_v4.0.30319_64\mscorlib\abc\mscorlib.ni.dll",
        root
    ));
    // A different volume's Windows tree is not this root.
    assert!(!is_system_dll_path_under(r"\Device\HarddiskVolume9\Windows\System32\user32.dll", root));
    // Component boundary: System32X / System32.evildir must not match.
    assert!(!is_system_dll_path_under(r"\Device\HarddiskVolume3\Windows\System32X\evil.dll", root));
    assert!(!is_system_dll_path_under(r"\Device\HarddiskVolume3\Windows\System32.evildir\evil.dll", root));
    // Nested look-alike: the trusted component must sit directly under
    // the root, not deeper in the tree.
    assert!(!is_system_dll_path_under(r"\Device\HarddiskVolume3\Windows\spoof\system32\evil.dll", root));
}

#[test]
fn is_system_dll_path_rejects_spoofed_substring() {
    // Regression (audit 2026-09-19, Medium): the old implementation
    // trusted any path CONTAINING `\windows\system32\`. Every one of
    // these must be untrusted.
    assert!(!is_system_dll_path(r"\Device\HarddiskVolume9\tmp\windows\system32\evil.dll"));
    assert!(!is_system_dll_path(r"C:\tmp\windows\system32\evil.dll"));
    assert!(!is_system_dll_path(
        r"\Device\HarddiskVolume3\Users\x\AppData\Local\Temp\windows\system32\evil.dll"
    ));
    // Pre-existing negatives keep failing closed.
    assert!(!is_system_dll_path(r"\Device\HarddiskVolume3\Users\x\AppData\evil.dll"));
    assert!(!is_system_dll_path(r"\Device\HarddiskVolume3\Program Files\app\plugin.dll"));
    assert!(!is_system_dll_path(""));
}

#[test]
fn is_system_dll_path_anchored_fallback() {
    // Fallback (root resolution unavailable): component-anchored at a
    // volume root — still never a substring match.
    assert!(is_system_dll_path_anchored(r"\Device\HarddiskVolume3\Windows\System32\ntdll.dll"));
    assert!(is_system_dll_path_anchored(r"C:\Windows\SysWOW64\kernel32.dll"));
    assert!(!is_system_dll_path_anchored(r"C:\tmp\windows\system32\evil.dll"));
    assert!(!is_system_dll_path_anchored(r"\Device\HarddiskVolume3\tmp\windows\system32\evil.dll"));
    assert!(!is_system_dll_path_anchored(r"\Device\HarddiskVolume3\Windows\System32X\evil.dll"));
    assert!(!is_system_dll_path_anchored(""));
}

#[test]
fn is_system_dll_path_real_root_resolution() {
    // Production path: prefixes resolved from the loader's own ntdll
    // mapping. The real System32 must be trusted; the same tail planted
    // one component deeper must not.
    match trusted_windows_root_nt() {
        Some(root) => {
            assert!(is_system_dll_path(&format!("{}\\system32\\user32.dll", root)));
            assert!(is_system_dll_path(&format!("{}\\syswow64\\kernel32.dll", root)));
            assert!(!is_system_dll_path(&format!("{}\\spoof\\system32\\user32.dll", root)));
        }
        None => {
            // Root unresolved in this environment: the fallback must
            // still reject the substring spoof.
            assert!(!is_system_dll_path(r"C:\tmp\windows\system32\evil.dll"));
        }
    }
}

#[test]
fn get_mapped_file_basename_for_ntdll() {
    let hmod = unsafe {
        let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        winapi::um::libloaderapi::GetModuleHandleW(name.as_ptr())
    };
    let basename = get_mapped_file_basename(hmod as *const c_void);
    assert!(basename.is_some());
    assert_eq!(basename.unwrap(), "ntdll.dll");
}

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
// Foreign NtWriteVirtualMemory decision (audit 2026-09-19, Medium)
// -------------------------------------------------------------------------

#[test]
fn foreign_write_decision_matrix() {
    const SELF: u32 = 4242;
    // Unresolvable handle: pass through, the original call fails on its own.
    assert_eq!(foreign_write_decision(0, SELF, false), ForeignWriteDecision::PassThrough);
    assert_eq!(foreign_write_decision(0, SELF, true), ForeignWriteDecision::PassThrough);
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
// Sibling-entry closure (audit High): NtAllocateVirtualMemoryEx must
// apply the SAME allocation decision as the classic hook. The decision
// itself is shared (alloc_decision_kill_required) and asserted here.
// The hook bodies cannot be invoked from unit tests because their deny
// path terminates the process (report_and_terminate -> !), so Ex
// entry-point presence is pinned by the sibling-drift check in hooks.rs
// and by alloc_sibling_exports_resolve_in_ntdll below.
// -----------------------------------------------------------------

/// Open a real handle to a process that is neither ours nor a tracked
/// child.
///
/// This used to open PID 4 (System). System does exist on every Windows
/// host, but OPENING it requires elevation — the assert fired on any
/// ordinary developer machine or CI runner, which made the two tests below
/// depend on how the suite happened to be launched rather than on the code
/// under test.
///
/// A process we spawned ourselves is openable unconditionally and is still
/// "foreign" for this guard's purposes: `alloc_decision_kill_required`
/// classifies by `process_tracker::is_owned_child`, and `mark_spawned` is
/// never called under `cargo test`, so the child is not a tracked child.
/// The handle stays valid after the child exits, and `GetProcessId` keeps
/// working on it, so there is no race to lose.
fn foreign_process_handle() -> HANDLE {
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    let child = std::process::Command::new("cmd.exe")
        .args(["/c", "exit"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawning a helper process must succeed");
    let pid = child.id();
    // SAFETY: OpenProcess with query-limited access on a process we just
    // created; returns NULL on failure, which we refuse to skip.
    let h = unsafe {
        winapi::um::processthreadsapi::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    };
    assert!(
        !h.is_null(),
        "OpenProcess on our own helper child (pid {pid}) must succeed"
    );
    h
}

#[test]
fn alloc_decision_foreign_exec_terminated() {
    let h = foreign_process_handle();
    // The VirtualAlloc2 attack shape: an executable allocation into a
    // foreign, non-owned process — exactly what the Ex sibling must
    // catch (pre-fix this call rode the unhooked Ex export).
    assert!(
        alloc_decision_kill_required(h, PAGE_EXECUTE_READWRITE, false),
        "foreign exec allocation must be a kill decision"
    );
    assert!(
        alloc_decision_kill_required(h, PAGE_EXECUTE, false),
        "foreign PAGE_EXECUTE allocation must be a kill decision"
    );
    // SAFETY: handle from OpenProcess above.
    unsafe { winapi::um::handleapi::CloseHandle(h) };
}

#[test]
fn alloc_decision_foreign_non_exec_allowed() {
    let h = foreign_process_handle();
    assert!(
        !alloc_decision_kill_required(h, PAGE_READWRITE, false),
        "foreign non-executable allocation must pass"
    );
    // SAFETY: handle from OpenProcess above.
    unsafe { winapi::um::handleapi::CloseHandle(h) };
}

#[test]
fn alloc_decision_self_rwx_static_mode() {
    // Serialize ALLOW_RWX access with the snapshot tests.
    let _lock = env_lock();
    // GUARD_MODE is install-time state and install() never runs under
    // --lib tests; pin it here (OnceLock.set is a no-op if already set).
    GUARD_MODE.set("static".to_string()).ok();
    test_set_allow_rwx(false);
    // Self RWX-direct in static (hard containment): kill decision.
    // SAFETY: GetCurrentProcess always returns the pseudo handle.
    let cur = unsafe { winapi::um::processthreadsapi::GetCurrentProcess() };
    assert!(
        alloc_decision_kill_required(cur, PAGE_EXECUTE_READWRITE, false),
        "self RWX-direct must be a kill decision in static mode"
    );
    // Documented escape hatch: the ALLOW_RWX snapshot permits it.
    test_set_allow_rwx(true);
    assert!(
        !alloc_decision_kill_required(cur, PAGE_EXECUTE_READWRITE, false),
        "allow_rwx must suppress the self-RWX kill"
    );
    test_set_allow_rwx(false);
}

/// Regression: under `--guard static`, hook.dll terminated its own
/// process during DllMain. `install_hooks` installs memory_guard FIRST
/// and holds `anti_rec` across every later guard's `enable()`; each of
/// those allocates an RWX trampoline, which the already-armed allocation
/// hook scored as a self-RWX-direct allocation. Init never signalled and
/// the launcher killed the child, so NO target could start under
/// `static` — `node.exe` and `cmd.exe` alike, i.e. not a JIT issue.
///
/// The decision itself must not change; only the gate the hooks apply.
#[test]
fn install_window_suppresses_static_self_rwx_kill() {
    let _lock = env_lock();
    GUARD_MODE.set("static".to_string()).ok();
    test_set_allow_rwx(false);
    // SAFETY: GetCurrentProcess always returns the pseudo handle.
    let cur = unsafe { winapi::um::processthreadsapi::GetCurrentProcess() };

    // Outside the window nothing is softened: a guest RWX-direct
    // allocation in static mode is still a kill.
    assert!(!in_trusted_hook_window());
    assert!(
        alloc_kill_gate(cur, PAGE_EXECUTE_READWRITE),
        "guest self-RWX in static must still be killed"
    );

    // Inside the install window the same allocation is ours.
    let window = crate::anti_rec::enter().expect("window must be free here");
    assert!(in_trusted_hook_window());
    assert!(
        !alloc_kill_gate(cur, PAGE_EXECUTE_READWRITE),
        "detour trampolines allocated during install must not be killed"
    );
    // The underlying decision is untouched — only the gate differs.
    assert!(alloc_decision_kill_required(cur, PAGE_EXECUTE_READWRITE, false));

    drop(window);
    assert!(!in_trusted_hook_window());
    assert!(alloc_kill_gate(cur, PAGE_EXECUTE_READWRITE));
}

/// The window must not blanket-suppress the foreign-process class: an
/// executable allocation in a process we do not own is the injection
/// primitive and is killed at every guard level.
#[test]
fn install_window_does_not_suppress_foreign_exec_kill() {
    let h = foreign_process_handle();
    let window = crate::anti_rec::enter().expect("window must be free here");
    assert!(
        alloc_kill_gate(h, PAGE_EXECUTE_READWRITE),
        "foreign exec allocation must be killed even inside the window"
    );
    drop(window);
    // SAFETY: handle from OpenProcess above.
    unsafe { winapi::um::handleapi::CloseHandle(h) };
}

#[test]
fn alloc_decision_self_benign_pass() {
    // Current-process pseudo handle + non-exec protect: the JIT/loader
    // path — never a kill decision in any mode.
    // SAFETY: GetCurrentProcess always returns the pseudo handle.
    let cur = unsafe { winapi::um::processthreadsapi::GetCurrentProcess() };
    assert!(!alloc_decision_kill_required(cur, PAGE_READWRITE, false));

    // A REAL handle to our own process resolves through GetProcessId and
    // takes the same self branch (guards the handle-comparison path).
    // SAFETY: OpenProcess on our own pid with query-limited access.
    let h = unsafe {
        winapi::um::processthreadsapi::OpenProcess(
            0x1000,
            0,
            winapi::um::processthreadsapi::GetCurrentProcessId(),
        )
    };
    if !h.is_null() {
        assert!(is_current_process(h));
        assert!(!alloc_decision_kill_required(h, PAGE_READWRITE, false));
        // SAFETY: handle from OpenProcess above.
        unsafe { winapi::um::handleapi::CloseHandle(h) };
    }
}

/// Export-name tripwire for the alloc siblings: a typo'd / renamed
/// export would fail install fatally, but resolution is pinned here so
/// the drift check's list-vs-source test cannot silently rot either.
#[test]
fn alloc_sibling_exports_resolve_in_ntdll() {
    // SAFETY: GetProcAddress wrapper over the always-loaded ntdll.
    unsafe {
        for name in [
            "NtAllocateVirtualMemory\0",
            "NtAllocateVirtualMemoryEx\0",
        ] {
            assert!(
                crate::hooks::ntdll_export(name.as_bytes()).is_some(),
                "ntdll export must resolve: {name}"
            );
        }
    }
}
