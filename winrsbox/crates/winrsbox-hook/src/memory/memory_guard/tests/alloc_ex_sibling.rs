// Sibling-entry closure (audit High): NtAllocateVirtualMemoryEx must
// apply the SAME allocation decision as the classic hook. The decision
// itself is shared (alloc_decision_kill_required) and asserted here.
// The hook bodies cannot be invoked from unit tests because their deny
// path terminates the process (report_and_terminate -> !), so Ex
// entry-point presence is pinned by the sibling-drift check in hooks.rs
// and by alloc_sibling_exports_resolve_in_ntdll below.

use super::*;

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

/// Open a real handle to a foreign process that holds MUTATION rights but
/// deliberately NO PROCESS_QUERY_LIMITED_INFORMATION (and no SYNCHRONIZE).
///
/// XA review R02: `GetProcessId` is documented to return 0 not only for an
/// invalid handle but also for a handle that lacks
/// PROCESS_QUERY_LIMITED_INFORMATION — i.e. "unknown identity". The
/// pre-fix code read that 0 as "invalid handle, let it pass", fail-opening
/// the guard for exactly the handle class an attacker would mint. This
/// helper mints such a handle so the premise is observed from the OS, not
/// assumed.
fn foreign_process_handle_no_query_rights() -> HANDLE {
    use winapi::um::winnt::{PROCESS_TERMINATE, PROCESS_VM_OPERATION, PROCESS_VM_WRITE};
    let child = std::process::Command::new("cmd.exe")
        .args(["/c", "exit"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawning a helper process must succeed");
    let pid = child.id();
    // SAFETY: OpenProcess with mutation-only access rights (no query
    // right) on a process we just created; returns NULL on failure, which
    // we refuse to skip.
    let h = unsafe {
        winapi::um::processthreadsapi::OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_TERMINATE,
            0,
            pid,
        )
    };
    assert!(
        !h.is_null(),
        "OpenProcess (mutation rights, no query right) on our own helper child (pid {pid}) must succeed"
    );
    h
}

/// R02 regression: an allocation whose target identity cannot be resolved
/// (`GetProcessId` → 0 because the handle has mutation rights but no
/// PROCESS_QUERY_LIMITED_INFORMATION) must be killed when executable,
/// exactly like a known-foreign target — not passed through.
#[test]
fn alloc_decision_unknown_identity_pid0_killed() {
    let h = foreign_process_handle_no_query_rights();
    // The R02 premise, queried from the OS: does this mutation-only handle
    // resolve at all?
    // SAFETY: GetProcessId is safe on any HANDLE.
    let resolved_pid = unsafe { winapi::um::processthreadsapi::GetProcessId(h) };
    if resolved_pid == 0 {
        // The documented missing-query-right failure mode: unknown identity
        // (pid 0) flows into the decision below directly.
    } else {
        // OBSERVED on Windows 10.0.19045: GetProcessId resolves a
        // mutation-only own-child handle — the documented
        // PROCESS_QUERY_LIMITED_INFORMATION requirement is not enforced for
        // this handle class on this build. The decision below then takes the
        // known-foreign path with the same kill verdict; the unknown-identity
        // (pid 0) branch is covered host-independently by the pure decision
        // matrix tests in memory_guard::tests.
    }
    // Either way — unresolvable identity or known foreign — the executable
    // allocation into this handle's target must be a kill decision.
    assert!(
        alloc_decision_kill_required(h, PAGE_EXECUTE_READWRITE, false),
        "unresolvable-identity exec allocation must be a kill decision"
    );
    // Non-executable foreign allocation keeps passing, as before.
    assert!(
        !alloc_decision_kill_required(h, PAGE_READWRITE, false),
        "foreign non-executable allocation must pass"
    );
    // SAFETY: handle from OpenProcess above.
    unsafe { winapi::um::handleapi::CloseHandle(h) };
}
