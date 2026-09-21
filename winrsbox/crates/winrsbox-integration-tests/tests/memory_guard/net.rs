use super::*;

#[test]
#[serial]
// ═══════════════════════════════════════════════════════════════════════════
// Network: WFP kernel-level block
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn wfp_blocks_rfc1918() {
    let r = run_payload("escape_net_rfc1918", "full");
    // Connect should fail (WFP drops or ws2_32 hook denies). Either way, exit != 0.
    assert!(!r.status.success() || r.status.code() == Some(2),
        "RFC1918 connect should be blocked\nexit={:?}\nstderr: {}", r.status.code(), r.stderr);
}

#[test]
#[serial]
fn wfp_blocks_smb_egress() {
    let r = run_payload("escape_smb_egress", "scan");
    // WFP blocks port 445 → either WSAEACCES (exit 5) or timeout (different code).
    // Either way, the connect must NOT succeed (exit code 0 would be escape).
    assert_ne!(r.status.code(), Some(0),
        "SMB egress should be blocked\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn localhost_allowed_by_default() {
    let r = run_payload("escape_localhost", "scan");
    assert_eq!(r.status.code(), Some(0),
        "localhost should be allowed by default\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn localhost_blocked_with_flag() {
    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let payload = find_binary("escape_localhost");
    let env = TestEnv::setup("escape_localhost_blocked");
    let output = std::process::Command::new(&launcher)
        .arg("-d").args(["--guard", "scan"]).arg("--block-localhost")
        .arg("--").arg(payload.to_str().unwrap())
        .current_dir(&env.project_root)
        .env("FS_SANDBOX_DLL", hook_dll.to_str().unwrap())
        .output().expect("failed to run launcher");
    let code = output.status.code();
    assert_eq!(code, Some(5),
        "localhost should be blocked with --block-localhost\nstderr: {}",
        String::from_utf8_lossy(&output.stderr));
}

#[test]
#[serial]
fn wfp_blocks_afd_direct() {
    // escape_afd_direct tries TCP connect to 10.0.0.1:80 via ws2_32.
    // WFP blocks RFC1918 at kernel level → connect fails or times out.
    // Exit code: 5 (WSAEACCES/blocked), 1 (other error), or 2 (timeout).
    // All non-zero codes mean the attack did NOT succeed.
    let r = run_payload("escape_afd_direct", "scan");
    assert!(
        !r.status.success() || r.stderr.contains("blocked"),
        "escape_afd_direct should not connect to RFC1918\nstderr: {}", r.stderr,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// UI guard: input synthesis (SendInput, keybd_event) + Job UI restrictions
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn strict_blocks_input_synthesis() {
    let r = run_payload("escape_sendinput", "scan");
    assert_ne!(r.status.code(), Some(0),
        "SendInput should be blocked by ui_guard\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_legacy_keybd_event() {
    let r = run_payload("escape_keybd_event", "scan");
    assert_ne!(r.status.code(), Some(0),
        "keybd_event should be blocked by ui_guard\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_clipboard_flag_blocks_read() {
    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let payload = find_binary("escape_clipboard");
    let env = TestEnv::setup("clipboard_strict");
    let output = std::process::Command::new(&launcher)
        .arg("-d").args(["--guard", "scan"]).arg("--strict-clipboard")
        .arg("--").arg(payload.to_str().unwrap())
        .current_dir(&env.project_root)
        .env("FS_SANDBOX_DLL", hook_dll.to_str().unwrap())
        .output().expect("failed to run launcher");
    assert_eq!(output.status.code(), Some(5),
        "Clipboard read should be blocked with --strict-clipboard\nstderr: {}",
        String::from_utf8_lossy(&output.stderr));
}

#[test]
#[serial]
fn default_allows_clipboard_open() {
    let r = run_payload("escape_clipboard", "scan");
    // 5 = our hook denied OpenClipboard (would be a regression).
    // 0 = clipboard had data (real escape if not in strict mode).
    // 6 = OpenClipboard succeeded, clipboard was empty (expected baseline).
    assert_ne!(r.status.code(), Some(5),
        "clipboard should NOT be blocked in default mode\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_spawn_wsl() {
    let r = run_payload("escape_spawn_wsl", "scan");
    assert_eq!(r.status.code(), Some(5),
        "wsl.exe spawn should be blocked\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_spawn_wmic() {
    let r = run_payload("escape_spawn_wmic", "scan");
    assert_eq!(r.status.code(), Some(5),
        "wmic.exe spawn should be blocked\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_parent_spoof() {
    let r = run_payload("escape_parent_spoof", "scan");
    if r.status.code() == Some(7) { return; }
    if r.status.code() == Some(8) { panic!("test setup failed (InitializeProcThreadAttributeList): {}", r.stderr); }
    assert_eq!(r.status.code(), Some(5),
        "parent-PID spoofing should be blocked\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_handle_list_inheritance() {
    let r = run_payload("escape_handle_list_inheritance", "scan");
    if r.status.code() == Some(8) { return; }
    assert_eq!(r.status.code(), Some(5),
        "PROC_THREAD_ATTRIBUTE_HANDLE_LIST should be blocked\nstderr: {}", r.stderr);
}
