// E2E tests for memory guard.
//
// Tests run winrsbox launcher with escape payloads and verify per-tier behavior:
// - full (default): user-mode hooks + content-scan terminate escape payloads;
//   RWX-direct allocation is allowed (JIT-safe).
// - static: full + ProhibitDynamicCode — also blunt-kills RWX-direct.
// - none (-g none): no memory protection; escape payloads run to completion.
//
// All tests use #[serial] to avoid race conditions between parallel
// sandbox instances (WFP filter collision, pipe name collision, etc.).
// - Clean payloads: always run to completion
//
// Requires a prior `cargo build --workspace` with the SAME profile these
// tests are compiled for — `cargo test` alone does not refresh
// target/<profile>/winrsbox.exe (it builds the bin as a test harness into
// deps/), so without it the suite launches the previous launcher. The
// artifact lookup in tests/common/mod.rs enforces this rather than letting
// it pass quietly; see the note there for what that silence once cost.
//
//     cargo build --workspace            &&  cargo test -p integration-tests
//     cargo build --workspace --release  &&  cargo test -p integration-tests --release

use serial_test::serial;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Exit code of a payload killed by the escape-class fail-stop
/// (`hooks::report_and_terminate_escape`, which calls `TerminateProcess`
/// with `0xC0000005`). Since commit 8c9ddd5 the sandbox no longer lets an
/// escape-class COM/ALPC broker attempt return an error to the guest — it
/// terminates the process, so the guest cannot observe the refusal and
/// retry a different vector. Tests that predate that change asserted
/// `Some(5)` (the clean-deny contract) and must assert this instead.
const EXIT_FAIL_STOP: i32 = 0xC000_0005_u32 as i32;

#[path = "../common/mod.rs"] mod common;
use common::{find_binary, find_hook_dll, find_launcher, target_dir};

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

mod proc;
mod persist;
mod modes;
mod fs;
mod broker;
mod net;
