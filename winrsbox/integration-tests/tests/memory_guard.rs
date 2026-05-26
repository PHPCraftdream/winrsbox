// E2E tests for memory guard.
//
// Tests run winrsbox launcher with escape payloads and verify:
// - Strict mode (default): escape payloads are terminated
// - Weak mode (--weak): escape payloads run to completion
//
// All tests use #[serial] to avoid race conditions between parallel
// sandbox instances (WFP filter collision, pipe name collision, etc.).
// - Clean payloads: always run to completion
//
// Requires: cargo build -p integration-tests --bins --release
//           cargo build -p winrsbox --release
//           cargo build -p hook --release

use serial_test::serial;
use std::path::{Path, PathBuf};
use std::process::Command;

fn find_binary(name: &str) -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let target_dir = Path::new(manifest).parent().unwrap().join("target");

    // Try release first, then debug
    for profile in ["release", "debug"] {
        let p = target_dir.join(profile).join(format!("{name}.exe"));
        if p.exists() {
            return p;
        }
    }
    panic!("{name}.exe not found in target/release or target/debug — build first");
}

fn find_launcher() -> PathBuf { find_binary("winrsbox") }
fn find_hook_dll() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let target_dir = Path::new(manifest).parent().unwrap().join("target");
    for profile in ["release", "debug"] {
        let p = target_dir.join(profile).join("hook.dll");
        if p.exists() {
            return p;
        }
    }
    panic!("hook.dll not found");
}

struct TestEnv {
    project_root: PathBuf,
    state_dir: PathBuf,
}

impl TestEnv {
    fn setup(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!("fs-sandbox-memguard-{name}"));
        let project_root = base.join("project");
        let state_dir = base.join(".winrsbox").join("project");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&project_root).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();

        let cfg = state_dir.join("sandbox.ktav");
        std::fs::write(&cfg, "defaults: {\n    read: passthrough\n    write: cow\n}\nrules: []\n").unwrap();
        std::fs::create_dir_all(state_dir.join("workdir")).unwrap();

        TestEnv { project_root, state_dir }
    }

    fn violations_log(&self) -> PathBuf {
        self.state_dir.join("violations.log")
    }

    fn read_violations(&self) -> String {
        match std::fs::read_to_string(self.violations_log()) {
            Ok(s) => s,
            Err(_) => String::new(),
        }
    }
}

struct RunResult {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
    env: TestEnv,
}

impl RunResult {
    /// Read violation data from all available sources: state-dir violations.log
    /// and per-PID fallback logs in %TEMP%.
    fn read_violations(&self) -> String {
        let mut combined = String::new();
        // 1. State-dir violations.log
        combined.push_str(&self.env.read_violations());
        // 2. Fallback logs in %TEMP% — scan for any matching the launcher run
        let tmp = std::env::temp_dir();
        if let Ok(entries) = std::fs::read_dir(&tmp) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with("fs-sandbox-violation-") && name.ends_with(".log") {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        combined.push_str(&content);
                    }
                }
            }
        }
        combined
    }
}

fn run_payload(payload_name: &str, guard: &str) -> RunResult {
    // Clean up any leftover fallback logs
    let tmp = std::env::temp_dir();
    if let Ok(entries) = std::fs::read_dir(&tmp) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("fs-sandbox-violation-") && name.ends_with(".log") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let payload = find_binary(payload_name);
    let env = TestEnv::setup(payload_name);

    let mut cmd = Command::new(&launcher);
    cmd.arg("-d");
    if guard != "full" {
        cmd.args(["--guard", guard]);
    }
    cmd.arg("--").arg(payload.to_str().unwrap());
    cmd.current_dir(&env.project_root);
    cmd.env("FS_SANDBOX_DLL", hook_dll.to_str().unwrap());
    // Cross-process foreign-target tests: payload spawns child, we want the
    // child to be treated as external (not as our owned injection target).
    if payload_name.starts_with("escape_foreign_") {
        cmd.env("FS_SANDBOX_NO_TRACK", "1");
    }

    let output = cmd.output().expect("failed to run launcher");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    RunResult { status: output.status, stdout, stderr, env }
}

// ═══════════════════════════════════════════════════════════════════════════
// Strict mode: escape payloads MUST be terminated
// ═══════════════════════════════════════════════════════════════════════════

macro_rules! assert_killed {
    ($name:expr, $kind:expr) => {{
        let r = run_payload($name, "full");
        assert!(!r.status.success(), "{} should have been killed\nstderr: {}", $name, r.stderr);
        let v = r.read_violations();
        assert!(v.contains($kind), "{}: violations should contain {}\nlog: {}\nstderr: {}", $name, $kind, v, r.stderr);
    }};
}

macro_rules! assert_alive {
    ($name:expr, $guard:expr) => {{
        let r = run_payload($name, $guard);
        assert!(r.status.success() || r.status.code() == Some(0),
            "{} should not be killed\nstdout: {}\nstderr: {}", $name, r.stdout, r.stderr);
        let v = r.read_violations();
        assert!(v.is_empty(), "{}: no violations expected\nlog: {}", $name, v);
    }};
}

#[test] #[serial] fn strict_kills_alloc_rwx()      { assert_killed!("escape_alloc_rwx", "Allocate"); }
#[test] #[serial] fn strict_kills_jit_protect()    { assert_killed!("escape_jit_protect", "Protect"); }
#[test] #[serial] fn strict_kills_heap_to_exec()   { assert_killed!("escape_heap_to_exec", "Protect"); }
#[test] #[serial] fn strict_kills_stack_exec()     { assert_killed!("escape_stack_exec", "Protect"); }
#[test]
#[serial]
fn strict_kills_map_anon_rwx() {
    // Under full guard, kernel's DynamicCodePolicy blocks at kernel level — no
    // violation IPC (our hook sees the NtMapViewOfSection fail). Under scan, our
    // user-mode hook catches it.
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
    // If we got a violation, it should be Allocate. If empty, proc_guard denied at OpenProcess.
    let v = r.read_violations();
    assert!(v.is_empty() || v.contains("Allocate"),
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
// P9-B: Registry runtime hooks — persistence vector denial
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn strict_denies_reg_appinit_persistence() {
    let r = run_payload("escape_reg_appinit", "full");
    // Payload exits with code 5 (ERROR_ACCESS_DENIED) when registry write
    // is correctly denied by our hook+IPC.
    let stderr_lower = r.stderr.to_ascii_lowercase();
    assert!(
        r.status.code() == Some(5) || stderr_lower.contains("status=5"),
        "payload should report ERROR_ACCESS_DENIED on registry write to persistence path\nexit={:?}\nstderr: {}",
        r.status.code(), r.stderr
    );
}

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

// ═══════════════════════════════════════════════════════════════════════════
// Kernel: ProcessDynamicCodePolicy (full mode)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn kernel_blocks_dynamic_code_full() {
    let r = run_payload("escape_dynamic_code", "full");
    // Under full: kernel returns error, payload exits non-zero with error code.
    // Under our user-mode: terminate with 0xC0000005.
    assert!(!r.status.success(),
        "dynamic code should be blocked under full guard\nexit={:?}\nstderr: {}", r.status.code(), r.stderr);
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

// ═══════════════════════════════════════════════════════════════════════════
// P2: SystemQuery device write access block
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn strict_blocks_systemquery_write() {
    let r = run_payload("escape_systemquery_write", "scan");
    assert_eq!(r.status.code(), Some(5),
        "escape_systemquery_write should exit 5 (blocked)\nstderr: {}", r.stderr);
    assert!(r.stderr.contains("blocked"),
        "stderr should contain 'blocked'\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_junction_creation() {
    let r = run_payload("escape_junction", "scan");
    assert_eq!(r.status.code(), Some(5),
        "escape_junction should exit 5 (blocked)\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_hardlink_creation() {
    let r = run_payload("escape_hardlink", "scan");
    assert_eq!(r.status.code(), Some(5),
        "escape_hardlink should exit 5 (blocked)\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_alpc_com_activation() {
    let r = run_payload("escape_alpc_com", "scan");
    assert_eq!(r.status.code(), Some(5),
        "escape_alpc_com should exit 5 (blocked)\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_token_privilege_enable() {
    let r = run_payload("escape_token_priv", "scan");
    assert_eq!(r.status.code(), Some(5),
        "escape_token_priv should exit 5 (blocked)\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_denies_fs_system_write() {
    // Clean any prior canary in real C:\Windows
    let canary = std::path::Path::new(r"C:\Windows\winrsbox-escape-canary.txt");
    let _ = std::fs::remove_file(canary);
    let r = run_payload("escape_fs_system_write", "scan");
    // Acceptable: exit 5 (deny) or exit 6 (CoW absorbed). Exit 0 = real escape.
    let code = r.status.code();
    assert!(code == Some(5) || code == Some(6),
        "fs_system_write should be denied or CoW-absorbed, got {:?}\nstderr: {}",
        code, r.stderr);
    // Verify the real C:\Windows directory is untouched
    assert!(!canary.exists(),
        "CANARY LEAKED to real C:\\Windows — CoW isolation failed!");
}

#[test]
#[serial]
fn cow_isolation_keeps_file_in_overlay() {
    // Clean any prior canary
    if let Ok(home) = std::env::var("USERPROFILE") {
        let _ = std::fs::remove_file(
            std::path::PathBuf::from(home).join("Desktop").join("winrsbox-cow-canary.dat")
        );
    }
    let r = run_payload("escape_cow_isolation", "scan");
    assert_eq!(r.status.code(), Some(0),
        "cow_isolation payload should exit 0 (write succeeded into overlay)\nstderr: {}", r.stderr);
    // Verify the file does NOT appear on the real filesystem
    if let Ok(home) = std::env::var("USERPROFILE") {
        let real_path = std::path::PathBuf::from(home).join("Desktop").join("winrsbox-cow-canary.dat");
        assert!(!real_path.exists(),
            "canary leaked to real FS at {}", real_path.display());
    }
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
fn strict_blocks_pipe_scm() {
    let r = run_payload("escape_pipe_scm", "scan");
    assert_eq!(r.status.code(), Some(5),
        "SCM pipe should be blocked\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_shadow_copy() {
    let r = run_payload("escape_shadow_copy", "scan");
    assert_eq!(r.status.code(), Some(5),
        "shadow copy should be blocked\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_raw_disk() {
    // Hard-block: classify_device returns Unknown for any path containing
    // "physicaldrive". Note: even without our block, opening PhysicalDrive0
    // from a non-admin process is denied by kernel ACL — this test confirms
    // the path is rejected but does not distinguish our block from the ACL.
    let r = run_payload("escape_raw_disk", "scan");
    assert_eq!(r.status.code(), Some(5),
        "raw disk should be blocked\nstderr: {}", r.stderr);
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
fn lolbas_regsvr32_blocked() {
    let r = run_payload("escape_lolbas_regsvr32", "scan");
    assert_ne!(r.status.code(), Some(0),
        "regsvr32 LOLBAS should not succeed\nstderr: {}", r.stderr);
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
