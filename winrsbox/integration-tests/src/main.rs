// Integration test runner for winrsbox.
//
// Runs as a standalone binary from workdir/bin/. Requires:
//   - winrsbox.exe + hook.dll  → in bin/ at repo root
//   - target-app.exe, chain.exe, cwd-child.exe → in workdir/bin/
//
// Usage: cargo run -p integration-tests --release
//        or: workdir/bin/integration-tests.exe  (after build.cmd deploys it)

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

// ─── Path Discovery ──────────────────────────────────────────────────────────

struct Paths {
    launcher: PathBuf,
    hook_dll: PathBuf,
    chain_exe: PathBuf,
    target_app: PathBuf,
    cwd_child: PathBuf,
}

impl Paths {
    fn discover() -> Self {
        let exe = std::env::current_exe().expect("current_exe");
        let workdir_bin = exe.parent().expect("workdir_bin").to_owned();

        // workdir_bin = <repo>/workdir/bin/  (this binary lives here)
        // bin_dir      = <repo>/bin/         (winrsbox.exe + hook.dll)
        let bin_dir = workdir_bin
            .parent() // workdir/
            .expect("workdir")
            .parent() // repo root
            .expect("repo_root")
            .join("bin");

        Paths {
            launcher: bin_dir.join("winrsbox.exe"),
            hook_dll: bin_dir.join("hook.dll"),
            chain_exe: workdir_bin.join("chain.exe"),
            target_app: workdir_bin.join("target-app.exe"),
            cwd_child: workdir_bin.join("cwd-child.exe"),
        }
    }

    fn assert_all_exist(&self) {
        let bins = [
            ("winrsbox.exe", &self.launcher),
            ("hook.dll", &self.hook_dll),
            ("target-app.exe", &self.target_app),
            ("chain.exe", &self.chain_exe),
            ("cwd-child.exe", &self.cwd_child),
        ];
        let mut missing = false;
        for (name, p) in bins {
            if !p.exists() {
                eprintln!("ERROR: {name} not found at {}", p.display());
                missing = true;
            }
        }
        if missing {
            eprintln!("       Run build.cmd first.");
            std::process::exit(2);
        }
    }
}

// ─── Per-test Environment ────────────────────────────────────────────────────

struct Env {
    project_root: PathBuf,
    state_dir: PathBuf,
}

impl Env {
    fn setup(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!("fs-sandbox-integ-{name}"));
        let project_root = base.join("project");
        // State dir is auto-discovered: <parent>/.winrsbox/<project-name>/
        let state_dir = base.join(".winrsbox").join("project");
        // Fresh slate for each test.
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&project_root).unwrap();
        Env { project_root, state_dir }
    }

    fn write_config(&self, extra: &str) {
        // Ensure state dir exists.
        fs::create_dir_all(&self.state_dir).unwrap();
        let cfg_path = self.state_dir.join("sandbox.ktav");

        // ktav config (sandbox_root is no longer in the config).
        let ktav = format!(
            "defaults: {{\n\
             \x20   read: passthrough\n\
             \x20   write: cow\n\
             }}\n\
             \n\
             rules: [\n\
             \x20   {{\n\
             \x20       prefix: C:\\Windows\n\
             \x20       read: passthrough\n\
             \x20       write: deny\n\
             \x20   }}\n\
             \x20   {{\n\
             \x20       prefix: C:\\Users\\Computer\\.ssh\n\
             \x20       read: deny\n\
             \x20       write: deny\n\
             \x20   }}\n\
             ]\n\
             {extra}\n",
            extra = extra,
        );
        fs::write(&cfg_path, ktav).unwrap();
    }

    /// Map a DOS path to its expected overlay location in state_dir/workdir.
    /// Mirrors policy::path::mirror_into_overlay logic.
    fn overlay_for(&self, dos_path: &str) -> PathBuf {
        let lower = dos_path.to_lowercase();
        let sanitized = lower.replace(':', "").replace('/', "\\");
        let sanitized = sanitized.trim_start_matches('\\');
        self.state_dir.join("workdir").join(sanitized)
    }
}

// ─── Launcher Invocation ─────────────────────────────────────────────────────

struct RunResult {
    #[allow(dead_code)]
    success: bool,
    stdout: String,
    stderr: String,
}

fn launch(paths: &Paths, env: &Env, target: &str, args: &[&str]) -> RunResult {
    let result = Command::new(&paths.launcher)
        .arg("-d")
        .arg("--").arg(target)
        .args(args)
        .current_dir(&env.project_root)
        .env("FS_SANDBOX_DLL", &paths.hook_dll)
        .output();

    match result {
        Ok(out) => RunResult {
            success: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        },
        Err(e) => RunResult {
            success: false,
            stdout: String::new(),
            stderr: e.to_string(),
        },
    }
}

// ─── Test Runner ─────────────────────────────────────────────────────────────

fn run_test(name: &str, f: impl FnOnce() -> Result<(), String>) -> bool {
    print!("  {name:<50}");
    let t0 = Instant::now();
    match f() {
        Ok(()) => {
            println!("PASS  ({:.2?})", t0.elapsed());
            true
        }
        Err(reason) => {
            println!("FAIL  ({:.2?})", t0.elapsed());
            for line in reason.lines() {
                println!("      {line}");
            }
            false
        }
    }
}

// ─── Test: full Go target-app (8 base scenarios) ─────────────────────────────

fn test_full_target_app(paths: &Paths) -> Result<(), String> {
    let env = Env::setup("full");
    env.write_config(
        "mocks: [\n\
         \x20   {\n\
         \x20       path: C:\\fake\\token.txt\n\
         \x20       content_inline: (\n\
         \x20           MOCKED_TOKEN_123\n\
         \x20       )\n\
         \x20   }\n\
         ]\n",
    );

    let res = launch(paths, &env, paths.target_app.to_str().unwrap(), &[]);

    // Check each scenario marker in launcher stdout.
    let combined = format!("{}\n{}", res.stdout, res.stderr);
    let want = [
        "[escape-write] ok",
        "[hosts-read] ok",
        "[ssh-deny] ok",
        "[inside-write] ok",
        "[inside-read] ok",
        "[mock-read] ok",
        "[child-escape-run] ok",
        "[child-inside-run] ok",
    ];
    let mut missing = Vec::new();
    for marker in want {
        if !combined.contains(marker) {
            missing.push(marker);
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "Missing output markers: {:?}\nstdout:\n{}",
            missing, combined
        ));
    }

    // Escape file must NOT have leaked outside sandbox.
    let escape_real = env.project_root.parent().unwrap().join("escape.txt");
    if escape_real.exists() {
        return Err(format!("escape.txt leaked to real path: {}", escape_real.display()));
    }

    // Escape file MUST be in overlay.
    let escape_lower = escape_real.to_string_lossy().to_lowercase();
    let escape_ov = env.overlay_for(&escape_lower);
    if !escape_ov.exists() {
        return Err(format!("escape.txt not in overlay at {}", escape_ov.display()));
    }

    // inside.txt MUST exist in project_root (passthrough write).
    let inside = env.project_root.join("inside.txt");
    if !inside.exists() {
        return Err(format!("inside.txt missing from project_root at {}", inside.display()));
    }

    Ok(())
}

// ─── Test: chain injection depth ≥ 3  (task #11) ────────────────────────────
//
// target → chain(3) → chain(2) → chain(1) → chain(0)
// Each depth writes <base>-<depth>.txt outside project_root → CoW to overlay.
// Verifies all 4 files appear in overlay and NONE at the real path.

fn test_chain_depth3(paths: &Paths) -> Result<(), String> {
    let env = Env::setup("chain");
    env.write_config("");

    // Use an unusual path prefix that almost certainly doesn't exist on the system.
    let base_path = r"C:\zz-fs-sandbox-chain-integ\marker";

    let res = launch(
        paths,
        &env,
        paths.chain_exe.to_str().unwrap(),
        &["3", base_path],
    );

    let combined = format!("{}\n{}", res.stdout, res.stderr);

    // 1. stdout must show all 4 depths wrote successfully.
    for depth in 0..=3usize {
        let marker = format!("[depth-{depth}] wrote");
        if !combined.contains(&marker) {
            return Err(format!(
                "depth-{depth} did not write.\nCombined output:\n{combined}"
            ));
        }
    }

    // 2. Launcher must have registered ≥ 3 child PIDs (chain(2), chain(1), chain(0)).
    let child_count = combined.matches("[sandbox] child registered").count();
    if child_count < 3 {
        return Err(format!(
            "Expected ≥3 child registrations, got {child_count}.\nOutput:\n{combined}"
        ));
    }

    // 3. Real paths must NOT exist (would indicate sandbox escape).
    // 4. Overlay paths MUST exist.
    let base_lower = base_path.to_lowercase();
    let mut errors = Vec::new();
    for depth in 0..=3usize {
        let real = PathBuf::from(format!("{base_path}-{depth}.txt"));
        if real.exists() {
            errors.push(format!("ESCAPE: real path exists: {}", real.display()));
        }

        let ov = env.overlay_for(&format!("{base_lower}-{depth}.txt"));
        if !ov.exists() {
            errors.push(format!("MISSING overlay: {}", ov.display()));
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("\n"));
    }

    Ok(())
}

// ─── Test: CoW write isolation across two separate runs ──────────────────────
//
// Run A writes a file. Run B (fresh sandbox) must NOT see Run A's overlay.

fn test_sandbox_isolation(paths: &Paths) -> Result<(), String> {
    // Run A — write escape.txt
    let env_a = Env::setup("iso-a");
    env_a.write_config("");
    // PowerShell one-liner as target: create a file outside project_root.
    let outside_path = r"C:\zz-fs-sandbox-iso-test\iso.txt";
    let ps_cmd = format!("[System.IO.File]::WriteAllText('{outside_path}', 'run-a')");
    launch(
        paths, &env_a,
        "powershell.exe",
        &["-NonInteractive", "-Command", &ps_cmd],
    );

    // Overlay in env_a must have the file.
    let ov_a = env_a.overlay_for(&outside_path.to_lowercase());
    if !ov_a.exists() {
        return Err(format!("Run A: overlay missing at {}", ov_a.display()));
    }

    // Run B — fresh sandbox, same target path.
    let env_b = Env::setup("iso-b");
    env_b.write_config("");
    let res_b = launch(
        paths, &env_b,
        "powershell.exe",
        &["-NonInteractive", "-Command", &ps_cmd],
    );

    let ov_b = env_b.overlay_for(&outside_path.to_lowercase());
    if !ov_b.exists() {
        return Err(format!(
            "Run B: overlay missing at {}\nstdout: {}\nstderr: {}",
            ov_b.display(), res_b.stdout, res_b.stderr
        ));
    }

    // Sanity: the two overlays are in different directories.
    if ov_a == ov_b {
        return Err("env_a and env_b share the same overlay path (isolation broken)".into());
    }

    Ok(())
}

// ─── Test: child process CWD propagation ─────────────────────────────────────
//
// cwd-child.exe --spawn <outfile>
//   spawns itself with its CWD explicitly set to USERPROFILE (simulating a
//   terminal emulator that opens shells in home dir), then the child writes
//   its own CWD to <outfile>.
//
// Our hook patches RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath
// in every grandchild while it is still suspended, so the grandchild starts
// in project_root instead of home dir.

fn test_child_cwd(paths: &Paths) -> Result<(), String> {
    let env = Env::setup("child-cwd");
    env.write_config("");

    // Output file written by the grandchild inside project_root (passthrough).
    let outfile = env.project_root.join("cwd-report.txt");
    let outfile_str = outfile.to_str().unwrap();

    let res = launch(
        paths,
        &env,
        paths.cwd_child.to_str().unwrap(),
        &["--spawn", outfile_str],
    );

    // cwd-child prints a marker when it succeeds.
    let combined = format!("{}\n{}", res.stdout, res.stderr);
    if !combined.contains("[cwd-child] cwd=") {
        return Err(format!(
            "cwd-child did not produce expected marker.\nOutput:\n{combined}"
        ));
    }

    // The grandchild must have written the outfile.
    if !outfile.exists() {
        return Err(format!(
            "cwd-report.txt missing; grandchild may not have run.\nOutput:\n{combined}"
        ));
    }

    let reported = fs::read_to_string(&outfile)
        .map_err(|e| format!("read cwd-report.txt: {e}"))?;
    let reported = reported.trim();

    let expected = env.project_root.to_string_lossy();
    // Case-insensitive comparison (Windows paths).
    if reported.to_lowercase() != expected.to_lowercase() {
        return Err(format!(
            "grandchild CWD mismatch.\n  expected: {expected}\n  got:      {reported}\nOutput:\n{combined}"
        ));
    }

    Ok(())
}

// ─── main ────────────────────────────────────────────────────────────────────

fn main() {
    let paths = Paths::discover();
    paths.assert_all_exist();

    println!("=== fs-sandbox Integration Tests ===\n");
    println!("  launcher  : {}", paths.launcher.display());
    println!("  hook.dll  : {}", paths.hook_dll.display());
    println!("  chain     : {}", paths.chain_exe.display());
    println!("  target    : {}", paths.target_app.display());
    println!("  cwd-child : {}", paths.cwd_child.display());
    println!();

    let mut passed = 0usize;
    let mut failed = 0usize;

    macro_rules! test {
        ($label:literal, $fn:expr) => {{
            if run_test($label, || $fn(&paths)) {
                passed += 1;
            } else {
                failed += 1;
            }
        }};
    }

    test!(
        "full target-app (8 base scenarios)",
        test_full_target_app
    );
    test!(
        "chain injection depth≥3 (→child1→child2→child3)",
        test_chain_depth3
    );
    test!(
        "sandbox isolation across two runs",
        test_sandbox_isolation
    );
    test!(
        "child process CWD propagation (grandchild sees project_root)",
        test_child_cwd
    );

    println!("\n=== {passed} passed, {failed} failed ===");
    std::process::exit(if failed > 0 { 1 } else { 0 });
}
