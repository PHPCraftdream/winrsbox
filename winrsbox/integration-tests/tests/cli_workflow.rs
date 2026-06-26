use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

/// Resolve path to the winrsbox binary.
///
/// Respects `CARGO_TARGET_DIR` (set by cargo when the workspace uses a
/// non-default target dir, e.g. via env or `.cargo/config.toml`), falling
/// back to `<workspace>/target/debug` for the standard layout. Without this,
/// these integration tests silently break (13 false failures) whenever the
/// workspace target dir is not the in-tree `target/`.
fn winrsbox_path() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_root = PathBuf::from(manifest_dir).parent().unwrap().to_path_buf();
    let target_root = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root.join("target"));
    target_root.join("debug").join("winrsbox.exe")
}

fn winrsbox() -> Command {
    let mut cmd = Command::new(winrsbox_path());
    cmd.timeout(std::time::Duration::from_secs(15));
    cmd
}

fn make_state(tmp: &tempfile::TempDir) -> PathBuf {
    let state = tmp.path().join("state");
    std::fs::create_dir_all(state.join("workdir")).unwrap();
    std::fs::create_dir_all(state.join("mock-dirs")).unwrap();
    state
}

/// Helper: build a command with WINRSBOX_STATE_DIR set.
fn cmd_with_state(state: &PathBuf) -> Command {
    let mut cmd = winrsbox();
    cmd.env("WINRSBOX_STATE_DIR", state);
    cmd
}

// ─── Group 1: CLI integration tests ──────────────────────────────────────

#[test]
fn cli_full_cycle() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);

    // Add rules
    cmd_with_state(&state)
        .args(["rule", "add", "--prefix=C:\\Secret", "--write=deny"])
        .assert().success();

    cmd_with_state(&state)
        .args(["rule", "add", "--prefix=C:\\Users\\*", "--write=cow"])
        .assert().success();

    // Add mock
    cmd_with_state(&state)
        .args(["mock", "add", "--path=C:\\fake\\token.txt", "--content=secret"])
        .assert().success();

    // Set defaults
    cmd_with_state(&state)
        .args(["defaults", "set", "--read=passthrough", "--write=cow"])
        .assert().success();

    // Export
    let export_out = cmd_with_state(&state)
        .args(["export"])
        .output().unwrap();
    assert!(export_out.status.success());
    let export_json: serde_json::Value = serde_json::from_slice(&export_out.stdout).unwrap();
    assert_eq!(export_json["schema_version"], 1);
    assert_eq!(export_json["rules"].as_array().unwrap().len(), 2);

    // Import into clean state
    let tmp2 = tempfile::tempdir().unwrap();
    let state2 = make_state(&tmp2);

    cmd_with_state(&state2)
        .args(["import", "--replace"])
        .write_stdin(serde_json::to_string(&export_json).unwrap())
        .assert().success();

    // List in new state
    let list_out = cmd_with_state(&state2)
        .args(["rule", "list", "--json"])
        .output().unwrap();
    assert!(list_out.status.success());
    let list_json: serde_json::Value = serde_json::from_slice(&list_out.stdout).unwrap();
    assert_eq!(list_json["rules"].as_array().unwrap().len(), 2);
}

#[test]
fn cli_why_after_crud() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);

    // Add rules with different specificity
    cmd_with_state(&state)
        .args(["rule", "add", "--prefix=C:\\Windows", "--write=deny"])
        .assert().success();

    cmd_with_state(&state)
        .args(["rule", "add", "--prefix=C:\\Windows\\System32", "--write=cow"])
        .assert().success();

    // Why
    let out = cmd_with_state(&state)
        .args(["why", r"C:\Windows\System32\foo.dll", "--write", "--json"])
        .output().unwrap();
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["schema_version"], 1);
    let chain = json["chain"].as_array().unwrap();
    assert!(!chain.is_empty(), "chain must not be empty");
    assert_eq!(json["decision"].as_str().unwrap(), "cow");
}

#[test]
fn cli_what_if_no_mutation() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);

    cmd_with_state(&state)
        .args(["rule", "add", "--prefix=C:\\Project", "--write=cow"])
        .assert().success();

    let before = cmd_with_state(&state).args(["export"]).output().unwrap();
    assert!(before.status.success());
    let before_json = before.stdout.clone();

    cmd_with_state(&state)
        .args(["what-if", "rule", "add", "--prefix=C:\\Secret", "--write=deny", "--", r"C:\Secret\x.txt"])
        .assert().success();

    let after = cmd_with_state(&state).args(["export"]).output().unwrap();
    assert!(after.status.success());
    assert_eq!(before_json, after.stdout, "state must not change after what-if");
}

#[test]
fn cli_export_import_roundtrip_replace() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);

    cmd_with_state(&state)
        .args(["rule", "add", "--prefix=C:\\Test", "--write=deny"])
        .assert().success();

    let export_out = cmd_with_state(&state).args(["export"]).output().unwrap();
    let export_json = export_out.stdout.clone();

    let tmp2 = tempfile::tempdir().unwrap();
    let state2 = make_state(&tmp2);

    cmd_with_state(&state2)
        .args(["import", "--replace"])
        .write_stdin(export_json.clone())
        .assert().success();

    let reexport = cmd_with_state(&state2).args(["export"]).output().unwrap();
    assert!(reexport.status.success());
    let json1: serde_json::Value = serde_json::from_slice(&export_json).unwrap();
    let json2: serde_json::Value = serde_json::from_slice(&reexport.stdout).unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn cli_export_import_roundtrip_merge() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);

    cmd_with_state(&state)
        .args(["rule", "add", "--prefix=C:\\RuleA", "--write=deny"])
        .assert().success();

    let import_json = serde_json::json!({
        "schema_version": 1,
        "defaults": { "read": "passthrough", "write": "cow" },
        "rules": [{ "id": "rule-b", "prefix": "c:\\ruleb", "read": "passthrough", "write": "cow" }],
        "mocks": [],
        "mockdirs": []
    });

    cmd_with_state(&state)
        .args(["import"])
        .write_stdin(serde_json::to_string(&import_json).unwrap())
        .assert().success();

    let list_out = cmd_with_state(&state)
        .args(["rule", "list", "--json"])
        .output().unwrap();
    let list: serde_json::Value = serde_json::from_slice(&list_out.stdout).unwrap();
    let rules = list["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2, "merge should keep existing rule A and add rule B");
}

#[test]
fn cli_ktav_import() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);

    let ktav_path = tmp.path().join("test.ktav");
    std::fs::write(&ktav_path, "defaults: {\n    read: passthrough\n    write: cow\n}\n\nrules: [\n    {\n        prefix: c:\\\\ktav-test\n        write: deny\n    }\n]\n").unwrap();

    cmd_with_state(&state)
        .args(["import", "--ktav", &ktav_path.to_string_lossy()])
        .assert().success();

    let list_out = cmd_with_state(&state)
        .args(["rule", "list", "--json"])
        .output().unwrap();
    let list: serde_json::Value = serde_json::from_slice(&list_out.stdout).unwrap();
    let rules = list["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1);
    assert!(rules[0]["prefix"].as_str().unwrap().contains("ktav-test"));
}

#[test]
fn cli_unknown_subcommand_error() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);

    cmd_with_state(&state)
        .args(["nonsense"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicates::str::contains("unknown subcommand")
            .or(predicates::str::contains("no subcommand")));
}

// ─── Group 2: Back-compat dispatcher ─────────────────────────────────────

#[test]
fn dispatch_cli_takes_priority() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);

    cmd_with_state(&state)
        .args(["rule", "list", "--json"])
        .assert()
        .success();
}

#[test]
fn dispatch_help_works() {
    winrsbox()
        .args(["--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("winrsbox"));
}

// ─── Group 3: Exit codes ─────────────────────────────────────────────────

#[test]
fn exit_zero_on_rule_list() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);

    cmd_with_state(&state)
        .args(["rule", "list"])
        .assert()
        .code(0);
}

#[test]
fn exit_one_on_missing_required_arg() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);

    cmd_with_state(&state)
        .args(["rule", "add"])
        .assert()
        .code(1)
        .stderr(predicates::str::contains("prefix"));
}

#[test]
fn exit_one_on_invalid_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);

    cmd_with_state(&state)
        .args(["rule", "add", "--prefix=C:\\Test", "--read=bogus"])
        .assert()
        .code(1)
        .stderr(predicates::str::contains("invalid mode"));
}

#[test]
fn exit_one_on_remove_unknown_id() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_state(&tmp);

    cmd_with_state(&state)
        .args(["rule", "remove", "--id=does-not-exist"])
        .assert()
        .code(1)
        .stderr(predicates::str::contains("not found"));
}
