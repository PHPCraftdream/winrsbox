// E2E tests for memory guard.
//
// Tests run winrsbox launcher with escape payloads and verify:
// - Strict mode (default): escape payloads are terminated
// - Weak mode (--weak): escape payloads run to completion
// - Clean payloads: always run to completion
//
// Requires: cargo build -p integration-tests --bins --release
//           cargo build -p winrsbox --release
//           cargo build -p hook --release

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

fn run_payload(payload_name: &str, guard_none: bool) -> RunResult {
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
    if guard_none {
        cmd.args(["--guard", "none"]);
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
        let r = run_payload($name, false);
        assert!(!r.status.success(), "{} should have been killed\nstderr: {}", $name, r.stderr);
        let v = r.read_violations();
        assert!(v.contains($kind), "{}: violations should contain {}\nlog: {}\nstderr: {}", $name, $kind, v, r.stderr);
    }};
}

macro_rules! assert_alive {
    ($name:expr, $weak:expr) => {{
        let r = run_payload($name, $weak);
        assert!(r.status.success() || r.status.code() == Some(0),
            "{} should not be killed\nstdout: {}\nstderr: {}", $name, r.stdout, r.stderr);
        let v = r.read_violations();
        assert!(v.is_empty(), "{}: no violations expected\nlog: {}", $name, v);
    }};
}

#[test] fn strict_kills_alloc_rwx()      { assert_killed!("escape_alloc_rwx", "Allocate"); }
#[test] fn strict_kills_jit_protect()    { assert_killed!("escape_jit_protect", "Protect"); }
#[test] fn strict_kills_heap_to_exec()   { assert_killed!("escape_heap_to_exec", "Protect"); }
#[test] fn strict_kills_stack_exec()     { assert_killed!("escape_stack_exec", "Protect"); }
#[test]
fn strict_kills_map_anon_rwx() {
    let r = run_payload("escape_map_anon_rwx", false);
    assert!(!r.status.success(), "escape_map_anon_rwx should have been killed\nexit={:?}\nstdout: {}\nstderr: {}", r.status.code(), r.stdout, r.stderr);
    let v = r.read_violations();
    assert!(v.contains("MapView") || v.contains("Allocate"),
        "violations should contain MapView or Allocate\nlog: {}\nstderr: {}", v, r.stderr);
}
#[test] fn strict_kills_ntdll_double_map() { assert_killed!("escape_ntdll_double_map", "MapView"); }
#[test]
fn strict_kills_remote_thread() { assert_killed!("escape_remote_thread", "CreateRemoteThread"); }
#[test]
fn strict_kills_thread_hijack() { assert_killed!("escape_thread_hijack", "ContextHijack"); }

// ═══════════════════════════════════════════════════════════════════════════
// P9-A: Cross-process memory ops on external (non-owned) processes
// ═══════════════════════════════════════════════════════════════════════════

#[test] fn strict_kills_foreign_alloc_rwx()     { assert_killed!("escape_foreign_alloc_rwx", "Allocate"); }
#[test] fn strict_kills_foreign_write_syscall() { assert_killed!("escape_foreign_write_syscall", "Write"); }

// ═══════════════════════════════════════════════════════════════════════════
// P9-B: Registry runtime hooks — persistence vector denial
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn strict_denies_reg_appinit_persistence() {
    let r = run_payload("escape_reg_appinit", false);
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

#[test] fn strict_allows_clean_noop()    { assert_alive!("clean_noop", false); }
#[test] fn strict_allows_normal_alloc()  { assert_alive!("clean_normal_alloc", false); }

// ═══════════════════════════════════════════════════════════════════════════
// Weak mode: escape payloads should NOT be terminated
// ═══════════════════════════════════════════════════════════════════════════

#[test] fn weak_allows_alloc_rwx()       { assert_alive!("escape_alloc_rwx", true); }
#[test] fn weak_allows_jit_protect()     { assert_alive!("escape_jit_protect", true); }

// ═══════════════════════════════════════════════════════════════════════════
// Content-aware: clean JIT pattern MUST NOT be terminated
// ═══════════════════════════════════════════════════════════════════════════

#[test] fn strict_allows_clean_jit()         { assert_alive!("clean_jit_pattern", false); }
#[test] fn strict_allows_legit_unpacker()   { assert_alive!("legit_unpacker_sim", false); }
#[test] fn strict_allows_legit_self_patch() { assert_alive!("legit_self_patching", false); }

// ═══════════════════════════════════════════════════════════════════════════
// Content-aware: malicious unpacker MUST be terminated
// ═══════════════════════════════════════════════════════════════════════════

#[test] fn strict_kills_unpacker_syscall()    { assert_killed!("escape_unpacker_syscall", "Protect"); }
#[test] fn strict_kills_self_modify_syscall() { assert_killed!("escape_self_modify_syscall", "Protect"); }

// ═══════════════════════════════════════════════════════════════════════════
// P2: Known bypass — direct syscall (executable documentation)
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// P3: Pre-launch code integrity scan
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn pre_launch_refuses_static_syscall() {
    let r = run_payload("escape_static_syscall", false);
    assert!(!r.status.success(),
        "escape_static_syscall should be refused at launch\nstderr: {}", r.stderr);
    let v = r.read_violations();
    assert!(v.contains("PreLaunchViolation") || v.contains("syscall"),
        "violations log should contain pre-launch entry\nlog: {v}\nstderr: {}", r.stderr);
}

#[test]
fn pre_launch_promotes_bypass_direct_syscall() {
    // Previously a known-limitation #[ignore]; pre-launch scan now catches it.
    let r = run_payload("bypass_direct_syscall", false);
    assert!(!r.status.success(),
        "bypass_direct_syscall must now be caught by pre-launch scan\nstderr: {}", r.stderr);
}

#[test]
fn weak_mode_skips_pre_launch_scan() {
    let r = run_payload("escape_static_syscall", true);
    // With --weak, scan is skipped, payload runs (and the syscall itself
    // either returns an invalid SSN error or behaves OS-defined).
    assert!(r.status.success() || r.status.code() == Some(0),
        "weak mode should not block static syscall\nstderr: {}", r.stderr);
}
