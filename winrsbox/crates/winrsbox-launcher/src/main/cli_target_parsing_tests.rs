//! Issue C (#63), iteration 3: regression test for the FULL argv→target
//! chain that feeds `build_delegation_command`. The orchestrator reported
//! that the nested launcher received only the bare executable (`cmd.exe`)
//! without `/c "echo ..."`, which would mean clap's `trailing_var_arg`
//! collection dropped everything after the inner `--`.
//!
//! These tests invoke the clap parser directly (`Cli::try_parse_from`)
//! against the exact argv shape produced when an outer launcher spawns a
//! nested launcher — `winrsbox.exe --cwd X -- <target...>` — and assert
//! `cli.target` carries every trailing token verbatim. They do NOT start
//! the sandbox, so they run anywhere without hook.dll / admin rights.

use super::Cli;
use clap::Parser;

/// The exact nested-delegation shape from the acceptance test:
///     winrsbox.exe --cwd X -- cmd.exe /c "echo DELEGATED_ARG_OK"
/// clap must collect THREE entries into `target`.
#[test]
fn nested_argv_preserves_full_target_after_inner_dashdash() {
    let argv = [
        "winrsbox.exe",
        "--cwd",
        r"D:\nest_sbx",
        "--",
        "cmd.exe",
        "/c",
        "echo DELEGATED_ARG_OK",
    ];
    let cli = Cli::try_parse_from(argv).expect("parse nested argv");
    assert_eq!(
        cli.target,
        vec![
            "cmd.exe".to_string(),
            "/c".to_string(),
            "echo DELEGATED_ARG_OK".to_string(),
        ],
        "clap must forward every token after `--` into cli.target",
    );
    assert!(!cli.init, "init flag must not be set by trailing tokens");
}

/// A nested launcher may itself be invoked with its own `--` plus a
/// complex target (e.g. multi-word echo with spaces). The trailing
/// collection must NOT split quoted arguments on whitespace.
#[test]
fn nested_argv_preserves_quoted_multiword_target() {
    let argv = [
        "winrsbox.exe",
        "--cwd",
        r"D:\nest_sbx",
        "--",
        "cmd.exe",
        "/c",
        "echo hello world from nested",
    ];
    let cli = Cli::try_parse_from(argv).expect("parse multiword argv");
    assert_eq!(
        cli.target,
        vec![
            "cmd.exe".to_string(),
            "/c".to_string(),
            "echo hello world from nested".to_string(),
        ],
    );
}

/// Hyphen-prefixed tokens after `--` (e.g. `-c`, `--flag`) must land in
/// `target`, not be re-interpreted as launcher options. With
/// `allow_hyphen_values=true` + `trailing_var_arg=true` on the `target`
/// field, the first `--` terminates option parsing and everything
/// afterwards is positional — this test pins that behaviour.
#[test]
fn nested_argv_treats_hyphen_tokens_as_target() {
    let argv = [
        "winrsbox.exe",
        "--",
        "node",
        "-e",
        "console.log(1)",
        "--unhandled-rejections=strict",
    ];
    let cli = Cli::try_parse_from(argv).expect("parse hyphen argv");
    assert_eq!(
        cli.target,
        vec![
            "node".to_string(),
            "-e".to_string(),
            "console.log(1)".to_string(),
            "--unhandled-rejections=strict".to_string(),
        ],
    );
    // sanity: launcher's own --debug was NOT set by the trailing `-e`
    assert!(!cli.debug);
}

/// End-to-end glue check: feed the parsed `cli.target` straight into
/// `build_delegation_command` and confirm the `Command` argv matches the
/// original input byte-for-byte. This catches any silent dropping or
/// re-quoting between clap collection and the delegation builder.
#[test]
fn parse_then_build_command_roundtrip() {
    use super::build_delegation_command;
    let argv = [
        "winrsbox.exe",
        "--cwd",
        r"D:\nest_sbx",
        "--",
        "cmd.exe",
        "/c",
        "echo DELEGATED_ARG_OK",
    ];
    let cli = Cli::try_parse_from(argv).expect("parse");
    let cmd = build_delegation_command(&cli.target);
    assert_eq!(cmd.get_program(), std::ffi::OsStr::new("cmd.exe"));
    let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
    assert_eq!(args, ["/c", "echo DELEGATED_ARG_OK"]);
}
