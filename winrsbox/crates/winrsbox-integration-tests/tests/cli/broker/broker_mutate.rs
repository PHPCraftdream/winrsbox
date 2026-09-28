// MP-9 E2E: while a broker session is running (with a long-lived guest
// already inside it), `winrsbox rule add ...` in the SAME folder must not
// fail with `DatabaseAlreadyOpen` — it is relayed through the broker
// (`ipc::Req::PolicyMutate`, `pipe_server::mutate`), `rule list` reflects
// it, and — the real point of MP-9 — the ALREADY-RUNNING guest's own
// repeated read of the newly-denied path flips from success to an error
// WITHOUT the guest OR the broker ever restarting, proving the broker's
// live decide cache was invalidated in place
// (`policy::db::PolicyOp::touches_fs_snapshot`, `Policy::invalidate_snapshot`).
//
// Observable criterion chosen (per the task's own menu of options): a deny
// rule on a file the long-lived guest keeps rereading, rather than a
// `why`-style broker round trip — `why`/`what-if` are NOT relayed through
// the broker by this stage (they run the full decide/overlay/mock engine,
// not a single `policy::db::*` call, and were left out of MP-9's scope —
// see the plan doc), so they would themselves fail with `DatabaseAlreadyOpen`
// while this test's broker is running and could not serve as the observable
// signal here.
//
// Requires: cargo build -p integration-tests --bins
//           cargo build -p winrsbox
//           cargo build -p hook

use assert_cmd::Command as AssertCommand;
use serial_test::serial;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[path = "../../common/mod.rs"]
mod common;
use common::{find_binary, find_hook_dll, find_launcher};

/// Mirrors `sandbox::discover_state_dir` (bin-crate-private, unreachable from
/// this test crate): `<project_root's parent>\.winrsbox\<name>`.
fn state_dir_for(project_root: &Path) -> PathBuf {
    project_root
        .parent()
        .expect("project_root has a parent")
        .join(".winrsbox")
        .join(project_root.file_name().expect("project_root has a name"))
}

const HOSTS_PATH: &str = r"C:\Windows\System32\drivers\etc\hosts";

fn poll_until_some<T>(budget: Duration, mut probe: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(v) = probe() {
            return Some(v);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Blocking-readline-until-match, bounded by `budget`. Each `read_line` call
/// itself has no per-call timeout, but the fixture (`clean_fileio`'s reread
/// loop) writes a flushed line at least every 200ms, so in practice this
/// returns well inside `budget` on a healthy run; only a genuinely stuck
/// guest would block past it (with the outer `#[test]` harness/CI timeout as
/// the final backstop, same as every other blocking-child-IO integration
/// test in this suite).
fn read_line_matching(r: &mut impl BufRead, needle: &str, budget: Duration) -> Option<String> {
    let deadline = Instant::now() + budget;
    let mut line = String::new();
    loop {
        line.clear();
        match r.read_line(&mut line) {
            Ok(0) => return None, // EOF — child exited
            Ok(_) => {
                if line.contains(needle) {
                    return Some(line.trim().to_string());
                }
            }
            Err(_) => return None,
        }
        if Instant::now() >= deadline {
            return None;
        }
    }
}

#[test]
#[serial]
fn cli_rule_add_while_session_running_is_relayed_and_guest_sees_it_live() {
    let base = std::env::temp_dir().join("fs-sandbox-mp9-mutate");
    let project_root = base.join("project");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&project_root).unwrap();

    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let fileio: PathBuf = find_binary("clean_fileio");

    // First session: broker + a long-lived guest that loops rereading
    // HOSTS_PATH every 200ms for up to 30s — "первая сессия держит
    // долгоживущего гостя".
    let mut broker_cmd = Command::new(&launcher);
    broker_cmd.arg("-d");
    broker_cmd.args(["--guard", "none"]);
    broker_cmd.arg("--").arg(&fileio);
    broker_cmd.current_dir(&project_root);
    broker_cmd.env("FS_SANDBOX_DLL", &hook_dll);
    broker_cmd.env("WINRSBOX_MP9_LOOP_PATH", HOSTS_PATH);
    broker_cmd.env("WINRSBOX_MP9_LOOP_SECS", "30");
    broker_cmd.stdout(Stdio::piped());
    broker_cmd.stderr(Stdio::null());
    let mut broker = broker_cmd.spawn().expect("spawn broker launcher");

    let state_dir = state_dir_for(&project_root);
    let broker_json_path = state_dir.join("broker.json");
    poll_until_some(Duration::from_secs(5), || {
        winrsbox::contain::session_section::read_broker_json(&broker_json_path).ok()
    })
    .expect("broker.json must appear and parse");
    assert!(
        broker.try_wait().unwrap().is_none(),
        "broker launcher exited early — it never got to open policy.redb"
    );

    let mut stdout = BufReader::new(broker.stdout.take().expect("broker stdout must be piped"));

    // The guest must read the file successfully at least once before any
    // rule exists (default read mode is passthrough).
    let first_line = read_line_matching(&mut stdout, "loop-read:", Duration::from_secs(15))
        .expect("guest must print at least one loop-read line");
    assert!(
        first_line.contains("ok"),
        "expected an ok read before any deny rule exists: {first_line}"
    );

    // `winrsbox rule add` in the SAME folder while the session is running —
    // direct `redb::Database::create` would fail with `DatabaseAlreadyOpen`
    // here (the broker holds it); `cli::PolicyBackend` relays this as
    // `ipc::Req::PolicyMutate` instead, and must still succeed.
    AssertCommand::new(&launcher)
        .env("WINRSBOX_STATE_DIR", &state_dir)
        .args(["rule", "add", &format!("--prefix={HOSTS_PATH}"), "--read=deny"])
        .timeout(Duration::from_secs(10))
        .assert()
        .success();

    // `rule list` (also relayed) must show it.
    let list_out = AssertCommand::new(&launcher)
        .env("WINRSBOX_STATE_DIR", &state_dir)
        .args(["rule", "list", "--json"])
        .timeout(Duration::from_secs(10))
        .output()
        .expect("run rule list");
    let list_json = String::from_utf8_lossy(&list_out.stdout).into_owned();
    let list_stderr = String::from_utf8_lossy(&list_out.stderr).into_owned();
    assert!(
        list_json.to_lowercase().contains("drivers"),
        "rule list must show the newly-added rule: stdout={list_json} status={:?} stderr={list_stderr}",
        list_out.status,
    );

    // The real MP-9 point: the ALREADY-RUNNING guest's very next loop
    // iteration observes the new rule — no restart of the guest, and none
    // of the broker either (checked again below).
    let denied_line = read_line_matching(&mut stdout, "loop-read: err", Duration::from_secs(15))
        .expect("the running guest must see the deny rule without restarting");
    assert!(
        denied_line.to_lowercase().contains("denied") || denied_line.to_lowercase().contains("access"),
        "expected an access-denied style error, got: {denied_line}"
    );

    assert!(
        broker.try_wait().unwrap().is_none(),
        "broker (and its guest) must still be the SAME running process — never restarted"
    );

    let _ = broker.kill();
    let _ = broker.wait();
    let _ = std::fs::remove_dir_all(&base);
}
