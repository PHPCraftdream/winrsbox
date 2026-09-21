use super::*;

// escape_alloc_rwx does a RWX-DIRECT NtAllocate (no W^X transition) — the one
// pattern that evades the NtProtect content-scan. Per the M4 tier split this is
// blunt-killed ONLY under `static` (hard containment); `full`/`scan` allow it so
// RWX-direct JIT (node/V8 — see real-world claude.cmd) works.
#[test] #[serial]
fn static_kills_alloc_rwx() {
    let r = run_payload("escape_alloc_rwx", "static");
    assert!(!r.status.success(),
        "escape_alloc_rwx should be killed under static\nstderr: {}", r.stderr);
    let v = r.read_violations();
    assert!(v.contains("Allocate"),
        "escape_alloc_rwx under static: violations should contain Allocate\nlog: {}\nstderr: {}", v, r.stderr);
}

#[test] #[serial]
fn full_allows_alloc_rwx_for_jit() {
    // M4 acceptance: full mode is JIT-safe. A bare RWX-direct allocation (as
    // node/V8 performs) must NOT be killed under full — that was breaking
    // claude.cmd / every node-based tool. Containment for full rests on the
    // ntdll hooks + NtProtect content-scan, not a blunt RWX-direct kill.
    let r = run_payload("escape_alloc_rwx", "full");
    assert!(r.status.success() || r.status.code() == Some(0),
        "escape_alloc_rwx should run under full (JIT-safe)\nexit={:?}\nstdout: {}\nstderr: {}",
        r.status.code(), r.stdout, r.stderr);
    let v = r.read_violations();
    assert!(v.is_empty(),
        "escape_alloc_rwx under full: no violation expected (JIT-safe)\nlog: {}", v);
}

#[test] #[serial] fn strict_kills_jit_protect()    { assert_killed!("escape_jit_protect", "Protect"); }
#[test] #[serial] fn strict_kills_heap_to_exec()   { assert_killed!("escape_heap_to_exec", "Protect"); }
#[test] #[serial] fn strict_kills_stack_exec()     { assert_killed!("escape_stack_exec", "Protect"); }
#[test]
#[serial]
fn strict_kills_map_anon_rwx() {
    // Run under scan: our user-mode NtMapViewOfSection hook catches the
    // anonymous RWX section map regardless of tier. (Post-M4 note: full no
    // longer carries the kernel DynamicCodePolicy — that moved to static — so
    // this exercises the user-mode MapView path directly, which is what we
    // want to pin.)
    let r = run_payload("escape_map_anon_rwx", "scan");
    assert!(!r.status.success(), "escape_map_anon_rwx should have been killed\nexit={:?}\nstdout: {}\nstderr: {}", r.status.code(), r.stdout, r.stderr);
    let v = r.read_violations();
    assert!(v.contains("MapView") || v.contains("Allocate"),
        "violations should contain MapView or Allocate\nlog: {}\nstderr: {}", v, r.stderr);
}
#[test] #[serial] fn strict_kills_ntdll_double_map() { assert_killed!("escape_ntdll_double_map", "MapView"); }
#[test]
#[serial]
fn strict_kills_remote_thread() { assert_killed!("escape_remote_thread", "CreateRemoteThread"); }
#[test]
#[serial]
fn strict_kills_thread_hijack() { assert_killed!("escape_thread_hijack", "ContextHijack"); }
#[test]
#[serial]
fn strict_kills_hwbp_injection() { assert_killed!("escape_hwbp_injection", "ContextHijack"); }
#[test]
#[serial]
fn strict_kills_apc_injection() { assert_killed!("escape_apc_injection", "QueueApc"); }

#[test]
#[serial]
fn strict_kills_apc_ex_injection() {
    // NtQueueApcThreadEx — Windows 10+ early-bird APC variant
    let r = run_payload("escape_apc_ex", "full");
    // Exit code 7 = NtQueueApcThreadEx export not found (older Windows) → skip
    if r.status.code() == Some(7) {
        eprintln!("NtQueueApcThreadEx not available, skipping");
        return;
    }
    assert!(!r.status.success(), "escape_apc_ex should have been killed\nstderr: {}", r.stderr);
    let v = r.read_violations();
    assert!(v.contains("QueueApc"),
        "escape_apc_ex: violations should contain QueueApc\nlog: {}\nstderr: {}", v, r.stderr);
}

// ═══════════════════════════════════════════════════════════════════════════
// P9-A: Cross-process memory ops on external (non-owned) processes
// ═══════════════════════════════════════════════════════════════════════════

// Note: with proc_guard active, NtOpenProcess on a non-owned PID with dangerous
// access (VM_OPERATION/VM_WRITE) is denied *before* memory_guard sees any RWX
// allocation — handle returns NULL, payload exits with non-zero. If proc_guard
// is bypassed (e.g. direct syscall to NtOpenProcess), memory_guard still kicks
// in on the RWX call. Either outcome means the attack was stopped.
#[test]
#[serial]
fn strict_kills_foreign_alloc_rwx() {
    let r = run_payload("escape_foreign_alloc_rwx", "full");
    assert!(!r.status.success(),
        "escape_foreign_alloc_rwx should be blocked (proc_guard) or killed (memory_guard)\nstderr: {}", r.stderr);

    // What this test actually asserts: the payload never reaches its
    // objective. It prints this line only after the foreign RWX allocation
    // returns, so its absence is the proof — stronger than matching on which
    // gate fired.
    assert!(
        !r.stderr.contains("NtAllocateVirtualMemory returned"),
        "payload reached the foreign RWX allocation — it must be stopped before that\nstderr: {}",
        r.stderr,
    );

    // Which gate stops it is a diagnostic detail and legitimately varies:
    //   * empty   — proc_guard denied NtOpenProcess on the non-owned PID, so
    //               no memory operation ever happened;
    //   * Write   — `run_payload` sets FS_SANDBOX_NO_TRACK for these payloads
    //               so the spawned child counts as external. CreateProcessW
    //               writes the process-parameter block into that child itself,
    //               which is then a cross-process write into a process the
    //               sandbox does not own — the audit's fail-stop terminates
    //               there, BEFORE the payload gets to allocate. Strictly more
    //               containment than the old content-scan, which let that
    //               write through (it carries no syscall opcodes) and only
    //               caught the attack one step later;
    //   * Allocate — the original gate, still correct when the write passes.
    let v = r.read_violations();
    assert!(v.is_empty() || v.contains("Allocate") || v.contains("Write"),
        "unexpected violation kind: {}\nstderr: {}", v, r.stderr);
}

#[test]
#[serial]
fn strict_kills_foreign_write_syscall() {
    let r = run_payload("escape_foreign_write_syscall", "full");
    assert!(!r.status.success(),
        "escape_foreign_write_syscall should be blocked (proc_guard) or killed (memory_guard)\nstderr: {}", r.stderr);
    let v = r.read_violations();
    assert!(v.is_empty() || v.contains("Write"),
        "unexpected violation kind: {}\nstderr: {}", v, r.stderr);
}

// ═══════════════════════════════════════════════════════════════════════════
// Process guard: cross-process injection, dangerous spawns, parent spoof
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn strict_blocks_inject_remote() {
    let r = run_payload("escape_inject_remote", "scan");
    // 7 = explorer absent (CI/sparse env). Treat as skip.
    if r.status.code() == Some(7) { eprintln!("explorer.exe not running, skipping"); return; }
    assert_eq!(r.status.code(), Some(5),
        "OpenProcess(VM_WRITE|CREATE_THREAD) on explorer should be blocked\nstderr: {}", r.stderr);
}

// ═══════════════════════════════════════════════════════════════════════════
// NtUnmapViewOfSection — foreign-process unmap (Process Hollowing closure)
//
// Payload uses PROCESS_VM_READ only to bypass proc_guard's OpenProcess deny,
// ensuring the test exercises the memory_guard NtUnmapViewOfSection hook.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn strict_blocks_unmap_foreign() {
    let r = run_payload("escape_unmap_foreign", "scan");
    if r.status.code() == Some(7) || r.status.code() == Some(8) { return; }
    assert_eq!(r.status.code(), Some(5),
        "NtUnmapViewOfSection on foreign process should be blocked\nstderr: {}", r.stderr);
}

// ═══════════════════════════════════════════════════════════════════════════
// NtMapViewOfSection — foreign-process map (Process Hollowing step 3)
//
// Payload uses PROCESS_VM_READ only to bypass proc_guard's OpenProcess deny,
// ensuring the test exercises the memory_guard NtMapViewOfSection hook.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn strict_blocks_map_foreign() {
    let r = run_payload("escape_map_foreign", "scan");
    if r.status.code() == Some(7) || r.status.code() == Some(8) { return; }
    assert_eq!(r.status.code(), Some(5),
        "NtMapViewOfSection into foreign process should be blocked\nstderr: {}", r.stderr);
}

// ═══════════════════════════════════════════════════════════════════════════
// Job guard: breakaway + reassignment escape vectors
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn strict_blocks_job_reassign() {
    let r = run_payload("escape_job_reassign", "scan");
    assert_eq!(r.status.code(), Some(5),
        "Job reassign should be denied\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_job_breakaway() {
    let r = run_payload("escape_job_breakaway", "scan");
    assert_eq!(r.status.code(), Some(5),
        "CreateProcess(BREAKAWAY) should fail\nstderr: {}", r.stderr);
}

// ═══════════════════════════════════════════════════════════════════════════
// DLL sideloading defense — PreferSystem32Images + NoRemoteImages
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn strict_blocks_dll_sideload() {
    let r = run_payload("escape_dll_sideload", "scan");
    assert_eq!(r.status.code(), Some(5),
        "PreferSystem32Images + NoRemoteImages mitigations should be applied\nstderr: {}", r.stderr);
}

// ═══════════════════════════════════════════════════════════════════════════
// System guard: NtShutdownSystem + NtSetSystemInformation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn strict_blocks_shutdown() {
    let r = run_payload("escape_shutdown", "scan");
    assert_eq!(r.status.code(), Some(5),
        "ExitWindowsEx/NtShutdownSystem should be blocked\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_set_system_info() {
    let r = run_payload("escape_set_system_info", "scan");
    if r.status.code() == Some(8) { return; }
    assert_eq!(r.status.code(), Some(5),
        "NtSetSystemInformation should be blocked\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_create_debug_object() {
    let r = run_payload("escape_debug_object", "scan");
    if r.status.code() == Some(8) { return; }
    assert_eq!(r.status.code(), Some(5),
        "NtCreateDebugObject should be blocked\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_raise_hard_error() {
    let r = run_payload("escape_raise_hard_error", "scan");
    if r.status.code() == Some(8) { return; }
    assert_eq!(r.status.code(), Some(5),
        "NtRaiseHardError should be blocked\nstderr: {}", r.stderr);
}
