use super::*;

// ═══════════════════════════════════════════════════════════════════════════
// Strict mode: clean payloads MUST NOT be terminated
// ═══════════════════════════════════════════════════════════════════════════

#[test] #[serial] fn strict_allows_clean_noop()    { assert_alive!("clean_noop", "full"); }
#[test] #[serial] fn strict_allows_normal_alloc()  { assert_alive!("clean_normal_alloc", "full"); }

// ═══════════════════════════════════════════════════════════════════════════
// Weak mode: escape payloads should NOT be terminated
// ═══════════════════════════════════════════════════════════════════════════

#[test] #[serial] fn weak_allows_alloc_rwx()       { assert_alive!("escape_alloc_rwx", "none"); }
#[test] #[serial] fn weak_allows_jit_protect()     { assert_alive!("escape_jit_protect", "none"); }

// ═══════════════════════════════════════════════════════════════════════════
// Content-aware: clean JIT pattern MUST NOT be terminated
// ═══════════════════════════════════════════════════════════════════════════

#[test] #[serial] fn strict_allows_clean_jit()         { assert_alive!("clean_jit_pattern", "scan"); }
#[test] #[serial] fn strict_allows_legit_unpacker()   { assert_alive!("legit_unpacker_sim", "scan"); }
#[test] #[serial] fn strict_allows_legit_self_patch() { assert_alive!("legit_self_patching", "scan"); }

// ═══════════════════════════════════════════════════════════════════════════
// Content-aware: malicious unpacker MUST be terminated
// ═══════════════════════════════════════════════════════════════════════════

#[test] #[serial] fn strict_kills_unpacker_syscall()    { assert_killed!("escape_unpacker_syscall", "Protect"); }
#[test] #[serial] fn strict_kills_self_modify_syscall() { assert_killed!("escape_self_modify_syscall", "Protect"); }

// ═══════════════════════════════════════════════════════════════════════════
// P2: Known bypass — direct syscall (executable documentation)
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// P3: Pre-launch code integrity scan
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn pre_launch_refuses_static_syscall() {
    let r = run_payload("escape_static_syscall", "full");
    assert!(!r.status.success(),
        "escape_static_syscall should be refused at launch\nstderr: {}", r.stderr);
    let v = r.read_violations();
    assert!(v.contains("PreLaunchViolation") || v.contains("syscall"),
        "violations log should contain pre-launch entry\nlog: {v}\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn pre_launch_promotes_bypass_direct_syscall() {
    // Previously a known-limitation #[ignore]; pre-launch scan now catches it.
    let r = run_payload("bypass_direct_syscall", "full");
    assert!(!r.status.success(),
        "bypass_direct_syscall must now be caught by pre-launch scan\nstderr: {}", r.stderr);
}

// ═══════════════════════════════════════════════════════════════════════════
// Kernel: ProcessDynamicCodePolicy (static mode only)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn static_blocks_dynamic_code() {
    // escape_dynamic_code does a bare VirtualAlloc(PAGE_EXECUTE_READWRITE) —
    // RWX-direct. Per the M4 tier split this is blocked ONLY under `static`
    // (our memory_guard NtAllocate hook terminates with 0xC0000005, and the
    // kernel's runtime ProcessDynamicCodePolicy would also refuse it). Under
    // `full`/`scan` it's allowed so RWX-direct JIT works.
    let r = run_payload("escape_dynamic_code", "static");
    assert!(!r.status.success(),
        "dynamic code should be blocked under static guard\nexit={:?}\nstderr: {}", r.status.code(), r.stderr);
}

// ═══════════════════════════════════════════════════════════════════════════
// Job Objects
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn memory_limit_enforced() {
    // Run with --memory-limit 1 (1 GB). Payload tries to alloc 12.8 GB.
    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let payload = find_binary("escape_memory_bomb");
    let env = TestEnv::setup("memory_bomb");

    // Clean fallback logs
    let tmp = std::env::temp_dir();
    if let Ok(entries) = std::fs::read_dir(&tmp) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("fs-sandbox-violation-") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    let output = std::process::Command::new(&launcher)
        .arg("-d")
        .arg("--memory-limit").arg("1")
        .arg("--").arg(payload.to_str().unwrap())
        .current_dir(&env.project_root)
        .env("FS_SANDBOX_DLL", hook_dll.to_str().unwrap())
        .output().expect("run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Payload should fail to allocate beyond 1 GB
    assert!(!output.status.success(),
        "memory bomb should be stopped\nexit={:?}\nstderr: {stderr}", output.status.code());
}

fn weak_mode_skips_pre_launch_scan() {
    let r = run_payload("escape_static_syscall", "none");
    // With --weak, scan is skipped, payload runs (and the syscall itself
    // either returns an invalid SSN error or behaves OS-defined).
    assert!(r.status.success() || r.status.code() == Some(0),
        "weak mode should not block static syscall\nstderr: {}", r.stderr);
}
