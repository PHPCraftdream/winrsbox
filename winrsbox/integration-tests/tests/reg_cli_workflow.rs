use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn winrsbox_path() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_root = PathBuf::from(manifest_dir).parent().unwrap().to_path_buf();
    workspace_root.join("target").join("debug").join("winrsbox.exe")
}

fn winrsbox() -> Command {
    let mut cmd = Command::new(winrsbox_path());
    cmd.timeout(std::time::Duration::from_secs(15));
    cmd
}

fn make_state(tmp: &tempfile::TempDir) -> PathBuf {
    let state = tmp.path().join("state");
    std::fs::create_dir_all(state.join("workdir")).unwrap();
    std::fs::create_dir_all(state.join("workreg")).unwrap();
    std::fs::create_dir_all(state.join("mock-dirs")).unwrap();
    state
}

fn cmd_with_state(state: &PathBuf) -> Command {
    let mut cmd = winrsbox();
    cmd.env("WINRSBOX_STATE_DIR", state);
    cmd
}

// ─── Full cycle ──────────────────────────────────────────────────────────────

#[test]
fn reg_cli_full_cycle() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);

    cmd_with_state(&state)
        .args(["regrule", "add", r"--prefix=HKLM\Software\Test", "--write=deny"])
        .assert().success();

    cmd_with_state(&state)
        .args(["regmock", "add", r"--path=HKLM\Crypto\Guid", "--type=REG_SZ", "--data=FAKE"])
        .assert().success();

    cmd_with_state(&state)
        .args(["regdefaults", "set", "--read=passthrough", "--write=cow"])
        .assert().success();

    let export_out = cmd_with_state(&state).args(["export"]).output().unwrap();
    assert!(export_out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&export_out.stdout).unwrap();
    assert!(json["reg_rules"].as_array().unwrap().len() >= 1);
    assert!(json["reg_mocks"].as_array().unwrap().len() >= 1);
}

#[test]
fn reg_cli_regrule_list_json() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);

    cmd_with_state(&state)
        .args(["regrule", "add", r"--prefix=HKLM\Test", "--write=deny"])
        .assert().success();

    let out = cmd_with_state(&state)
        .args(["regrule", "list", "--json"])
        .output().unwrap();
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["reg_rules"].as_array().unwrap().len(), 1);
}

#[test]
fn reg_cli_regwhy_json_output() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);

    cmd_with_state(&state)
        .args(["regrule", "add", r"--prefix=HKLM\Secrets", "--write=deny", "--read=deny"])
        .assert().success();

    let out = cmd_with_state(&state)
        .args(["regwhy", r"HKLM\Secrets\Key", "--value=x", "--json"])
        .output().unwrap();
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["decision"].as_str().unwrap(), "deny");
}

#[test]
fn reg_cli_export_import_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);

    cmd_with_state(&state)
        .args(["regrule", "add", r"--prefix=HKLM\App", "--write=cow"])
        .assert().success();

    let export_out = cmd_with_state(&state)
        .args(["export"])
        .output().unwrap();
    assert!(export_out.status.success(), "export failed: {}", String::from_utf8_lossy(&export_out.stderr));
    let export_json = export_out.stdout.clone();
    assert!(!export_json.is_empty(), "export produced empty output");

    let tmp2 = tempfile::tempdir().unwrap();
    let state2 = make_state(&tmp2);

    cmd_with_state(&state2)
        .args(["import", "--replace"])
        .write_stdin(export_json)
        .assert().success();

    let list_out = cmd_with_state(&state2)
        .args(["regrule", "list", "--json"])
        .output().unwrap();
    let json: serde_json::Value = serde_json::from_slice(&list_out.stdout).unwrap();
    assert_eq!(json["reg_rules"].as_array().unwrap().len(), 1);
}

// ─── Error paths ─────────────────────────────────────────────────────────────

#[test]
fn reg_cli_regrule_missing_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);
    cmd_with_state(&state)
        .args(["regrule", "add"])
        .assert().code(1)
        .stderr(predicates::str::contains("prefix"));
}

#[test]
fn reg_cli_regmock_invalid_type() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);
    cmd_with_state(&state)
        .args(["regmock", "add", "--path=HKLM\\x", "--type=BOGUS", "--data=x"])
        .assert().code(1)
        .stderr(predicates::str::contains("invalid"));
}

#[test]
fn reg_cli_regmock_bad_dword() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);
    cmd_with_state(&state)
        .args(["regmock", "add", "--path=HKLM\\x", "--type=REG_DWORD", "--data=abc"])
        .assert().code(1);
}

// ─── Help ────────────────────────────────────────────────────────────────────

#[test]
fn reg_cli_help_lists_reg_commands() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);
    cmd_with_state(&state)
        .args(["--help"])
        .assert().success()
        .stdout(predicates::str::contains("regrule"))
        .stdout(predicates::str::contains("regmock"))
        .stdout(predicates::str::contains("regdefaults"))
        .stdout(predicates::str::contains("regwhy"));
}

#[test]
fn reg_cli_regrule_help() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);
    cmd_with_state(&state)
        .args(["regrule", "--help"])
        .assert().success()
        .stdout(predicates::str::contains("EXAMPLES"));
}
