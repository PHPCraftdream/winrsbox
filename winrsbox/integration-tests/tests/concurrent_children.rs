// E2E test for M-T2 (test coverage audit): one launcher spawns ONE
// sandboxed parent which in turn spawns TWO concurrent children. Each
// child writes to a different absolute path outside the cwd, so both
// writes go through CoW.
//
// Exercises:
//   - IPC pipe server handling two children's Hello + Decide messages
//     interleaved
//   - process_tracker with multiple owned PIDs simultaneously
//   - two independent CoW overlays for two different paths
//
// A bug where child A's record_overlay invalidates child B's expectations,
// or where the pipe server serializes too aggressively and causes one
// child to time out waiting for Hello, would be caught here.
//
// Requires: cargo build -p integration-tests --bins --release
//           cargo build -p winrsbox --release
//           cargo build -p hook --release

use serial_test::serial;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Resolve the workspace target dir, respecting `CARGO_TARGET_DIR`
/// (set when the workspace uses a non-default target dir) and falling
/// back to `<workspace>/target` for the standard in-tree layout.
fn target_dir() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let workspace_root = Path::new(manifest).parent().unwrap();
    std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root.join("target"))
}

fn find_binary(name: &str) -> PathBuf {
    let target_dir = target_dir();
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
    let target_dir = target_dir();
    for profile in ["release", "debug"] {
        let p = target_dir.join(profile).join("hook.dll");
        if p.exists() {
            return p;
        }
    }
    panic!("hook.dll not found");
}

struct TestEnv {
    base: PathBuf,
    project_root: PathBuf,
    state_dir: PathBuf,
}

impl TestEnv {
    fn setup(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!("fs-sandbox-concurrent-{name}"));
        let project_root = base.join("project");
        let state_dir = base.join(".winrsbox").join("project");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&project_root).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();

        let cfg = state_dir.join("sandbox.ktav");
        std::fs::write(
            &cfg,
            "defaults: {\n    read: passthrough\n    write: cow\n}\nrules: []\n",
        )
        .unwrap();
        std::fs::create_dir_all(state_dir.join("workdir")).unwrap();

        TestEnv { base, project_root, state_dir }
    }

    /// Mirrors policy::path::mirror_into_overlay logic: strip the colon,
    /// normalize slashes, drop leading backslash, join under workdir/.
    fn overlay_for(&self, dos_path: &str) -> PathBuf {
        let lower = dos_path.to_lowercase();
        let sanitized = lower.replace(':', "").replace('/', "\\");
        let sanitized = sanitized.trim_start_matches('\\');
        self.state_dir.join("workdir").join(sanitized)
    }
}

#[test]
#[serial]
fn two_concurrent_children_both_succeed() {
    let env = TestEnv::setup("both_ok");
    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let writer = find_binary("clean_write_one_file");
    let parent = find_binary("spawn_two_children");

    // Children write to paths OUTSIDE project_root so defaults (write: cow)
    // apply. We use sibling files under <base>/outside_*.txt — both paths
    // are absolute and have no overlapping prefix, so they map to distinct
    // overlay locations.
    let target_a = env.base.join("outside_a.txt");
    let target_b = env.base.join("outside_b.txt");

    // Pre-clean the real targets so a stale leak from a previous run can't
    // mask a regression.
    let _ = std::fs::remove_file(&target_a);
    let _ = std::fs::remove_file(&target_b);

    let mut cmd = Command::new(&launcher);
    cmd.arg("-d");
    cmd.args(["--guard", "none"]); // we don't need memory guard here
    cmd.arg("--")
        .arg(parent.to_str().unwrap())
        .arg(writer.to_str().unwrap())
        .arg(target_a.to_str().unwrap())
        .arg(target_b.to_str().unwrap());
    cmd.current_dir(&env.project_root);
    cmd.env("FS_SANDBOX_DLL", hook_dll.to_str().unwrap());

    let output = cmd.output().expect("failed to run launcher");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(0),
        "parent should report 0 — both children succeeded.\nstdout: {stdout}\nstderr: {stderr}",
    );

    // Neither write should have leaked to the real filesystem.
    assert!(
        !target_a.exists(),
        "child_a.txt LEAKED to real path: {} — CoW isolation failed!",
        target_a.display(),
    );
    assert!(
        !target_b.exists(),
        "child_b.txt LEAKED to real path: {} — CoW isolation failed!",
        target_b.display(),
    );

    // Both writes should have landed in the CoW overlay.
    let overlay_a = env.overlay_for(&target_a.to_string_lossy());
    let overlay_b = env.overlay_for(&target_b.to_string_lossy());
    assert!(
        overlay_a.exists(),
        "child A's file missing from overlay at {}\nstdout: {stdout}\nstderr: {stderr}",
        overlay_a.display(),
    );
    assert!(
        overlay_b.exists(),
        "child B's file missing from overlay at {}\nstdout: {stdout}\nstderr: {stderr}",
        overlay_b.display(),
    );

    // The two overlay paths must be distinct — if they collide, the test is
    // not actually testing concurrency on independent files.
    assert_ne!(
        overlay_a, overlay_b,
        "overlay paths collided — bad test setup, not exercising concurrency",
    );

    let content_a = std::fs::read_to_string(&overlay_a)
        .unwrap_or_else(|e| panic!("read {}: {e}", overlay_a.display()));
    let content_b = std::fs::read_to_string(&overlay_b)
        .unwrap_or_else(|e| panic!("read {}: {e}", overlay_b.display()));
    assert_eq!(content_a, "hello from A");
    assert_eq!(content_b, "hello from B");
}
