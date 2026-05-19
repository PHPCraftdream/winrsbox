use assert_cmd::Command;
use std::path::PathBuf;

fn winrsbox_path() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_root = PathBuf::from(manifest_dir).parent().unwrap().to_path_buf();
    workspace_root.join("target").join("debug").join("winrsbox.exe")
}

fn dev_test_path() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let root = PathBuf::from(manifest_dir).parent().unwrap().parent().unwrap().to_path_buf();
    root.join("workdir").join("bin").join("dev-test.exe")
}

/// Run a target under sandbox and return (exit_code, stdout, stderr)
fn run_sandboxed(target_args: &[&str]) -> (i32, String, String) {
    let mut args = vec!["-d", "--"];
    let dev_test = dev_test_path();
    let dev_test_str = dev_test.to_string_lossy().to_string();
    args.push(&dev_test_str);
    args.extend(target_args);

    let out = Command::new(winrsbox_path())
        .args(&args)
        .timeout(std::time::Duration::from_secs(30))
        .output()
        .expect("failed to run winrsbox");

    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (code, stdout, stderr)
}

#[test]
#[ignore] // requires built dev-test.exe and admin for DLL injection
fn dev_e2e_blocks_cldflt() {
    let (code, stdout, _) = run_sandboxed(&["open-cldflt"]);
    assert!(stdout.contains("BLOCKED"), "CldFlt should be blocked, got: {stdout}");
    assert_eq!(code, 0);
}

#[test]
#[ignore]
fn dev_e2e_blocks_physicaldrive() {
    let (code, stdout, _) = run_sandboxed(&["open-physicaldrive"]);
    assert!(stdout.contains("BLOCKED"), "PhysicalDrive should be blocked, got: {stdout}");
    assert_eq!(code, 0);
}

#[test]
#[ignore]
fn dev_e2e_allows_normal_file() {
    let (code, stdout, _) = run_sandboxed(&["open-normal-file"]);
    assert!(stdout.contains("OK"), "Normal file should work, got: {stdout}");
    assert_eq!(code, 0);
}

#[test]
#[ignore]
fn dev_e2e_allows_named_pipe() {
    let (code, stdout, _) = run_sandboxed(&["open-named-pipe"]);
    assert!(stdout.contains("OK"), "Named pipe namespace should be accessible, got: {stdout}");
    assert_eq!(code, 0);
}
