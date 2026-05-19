// Real-world program tests — verify sandbox doesn't break normal software.
// Tests are #[ignore]'d by default — run with `cargo test -- --ignored`.
// Each test checks if the program exists in PATH; skips cleanly if not.

use std::path::{Path, PathBuf};
use std::process::Command;

fn find_binary(name: &str) -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let target_dir = Path::new(manifest).parent().unwrap().join("target");
    for profile in ["release", "debug"] {
        let p = target_dir.join(profile).join(format!("{name}.exe"));
        if p.exists() { return p; }
    }
    panic!("{name}.exe not found");
}

fn find_launcher() -> PathBuf { find_binary("winrsbox") }
fn find_hook_dll() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let target_dir = Path::new(manifest).parent().unwrap().join("target");
    for profile in ["release", "debug"] {
        let p = target_dir.join(profile).join("hook.dll");
        if p.exists() { return p; }
    }
    panic!("hook.dll not found");
}

fn which(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var("PATH").ok()?;
    for dir in path_var.split(';') {
        let p = Path::new(dir).join(name);
        if p.exists() { return Some(p); }
    }
    None
}

fn run_real_program(program: &str, args: &[&str], guard: &str) -> (bool, String, String) {
    let launcher = find_launcher();
    let hook_dll = find_hook_dll();

    let base = std::env::temp_dir().join(format!("fs-sandbox-real-{}", program.replace('.', "_")));
    let project = base.join("project");
    let state = base.join(".winrsbox").join("project");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(state.join("workdir")).unwrap();
    std::fs::write(state.join("sandbox.ktav"),
        "defaults: {\n    read: passthrough\n    write: cow\n}\nrules: []\n").unwrap();

    let mut cmd = Command::new(&launcher);
    cmd.arg("-d");
    if guard != "full" { cmd.args(["--guard", guard]); }
    cmd.arg("--").arg(program);
    for a in args { cmd.arg(a); }
    cmd.current_dir(&project);
    cmd.env("FS_SANDBOX_DLL", hook_dll.to_str().unwrap());

    let output = cmd.output().expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output.status.success() || output.status.code() == Some(0), stdout, stderr)
}

// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[ignore = "requires powershell in PATH"]
fn real_powershell_under_scan() {
    if which("powershell.exe").is_none() {
        eprintln!("SKIP: powershell.exe not in PATH");
        return;
    }
    let (ok, stdout, stderr) = run_real_program(
        "powershell.exe", &["-NoProfile", "-Command", "Write-Output 'sandbox-ok'"], "scan",
    );
    assert!(ok, "powershell should work in scan mode\nstdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("sandbox-ok") || stderr.contains("sandbox-ok"),
        "expected 'sandbox-ok' in output\nstdout: {stdout}");
}

#[test]
#[ignore = "requires git in PATH"]
fn real_git_version_under_scan() {
    if which("git.exe").is_none() {
        eprintln!("SKIP: git.exe not in PATH");
        return;
    }
    let (ok, stdout, stderr) = run_real_program("git.exe", &["--version"], "scan");
    assert!(ok, "git should work in scan mode\nstdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("git version") || stderr.contains("git version"),
        "expected 'git version'\nstdout: {stdout}");
}

#[test]
#[ignore = "requires node in PATH"]
fn real_node_under_scan() {
    if which("node.exe").is_none() {
        eprintln!("SKIP: node.exe not in PATH");
        return;
    }
    let (ok, stdout, stderr) = run_real_program(
        "node.exe", &["-e", "console.log('sandbox-ok-' + Math.sqrt(4))"], "scan",
    );
    assert!(ok, "node should work in scan mode\nstdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("sandbox-ok-2") || stderr.contains("sandbox-ok-2"),
        "expected 'sandbox-ok-2'\nstdout: {stdout}");
}

#[test]
#[ignore = "requires python in PATH"]
fn real_python_under_scan() {
    if which("python.exe").is_none() && which("python3.exe").is_none() {
        eprintln!("SKIP: python not in PATH");
        return;
    }
    let py = if which("python.exe").is_some() { "python.exe" } else { "python3.exe" };
    let (ok, stdout, stderr) = run_real_program(
        py, &["-c", "import sys; print(f'sandbox-ok-{sys.version_info.major}')"], "scan",
    );
    assert!(ok, "python should work in scan mode\nstdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("sandbox-ok-3") || stderr.contains("sandbox-ok-3"),
        "expected 'sandbox-ok-3'\nstdout: {stdout}");
}

#[test]
#[ignore = "requires cargo in PATH"]
fn real_cargo_version_under_scan() {
    if which("cargo.exe").is_none() {
        eprintln!("SKIP: cargo.exe not in PATH");
        return;
    }
    let (ok, stdout, stderr) = run_real_program("cargo.exe", &["--version"], "scan");
    assert!(ok, "cargo should work in scan mode\nstdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("cargo") || stderr.contains("cargo"),
        "expected 'cargo' in output\nstdout: {stdout}");
}
