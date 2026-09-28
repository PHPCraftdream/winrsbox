// MP-8 E2E: `winrsbox broker status`/`winrsbox broker restart`, and the
// client's Ping-timeout warning against a hung broker.
//
// (a) `broker status` while a broker + attached client are running shows
//     the broker's pid and the client in its trusted-launcher set.
// (b) `broker restart` terminates the broker; the attached client's own
//     session keeps running (MP-7 failover) and becomes the new broker;
//     `broker status` afterward reports the NEW broker's pid.
// (c) a broker that freezes every `Ping` reply past the client's own
//     timeout (test seam: WINRSBOX_TEST_FREEZE_PING_MS, debug builds only —
//     see main::session::run_launcher_session_loop) makes the client print
//     a Ping-timeout WARNING to its own stderr, without killing anything.
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
use winapi::shared::minwindef::FALSE;
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{MapViewOfFile, OpenFileMappingW, FILE_MAP_READ};

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

/// Same technique as `broker_attach.rs`/`broker_failover_kill.rs`: open a
/// folder section read-only, by name — no special access needed, the
/// section's DACL already grants `SECTION_QUERY | SECTION_MAP_READ` to the
/// current user.
fn open_folder_section_read_only(name: &str) -> ipc::FolderSectionView {
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: wide is a NUL-terminated UTF-16 name.
    let handle = unsafe { OpenFileMappingW(FILE_MAP_READ, FALSE, wide.as_ptr()) };
    assert!(!handle.is_null(), "OpenFileMappingW({name}) failed");
    // SAFETY: handle is the section just opened above; FOLDER_SECTION_SIZE
    //         matches the layout every writer reserves.
    let view = unsafe { MapViewOfFile(handle, FILE_MAP_READ, 0, 0, ipc::FOLDER_SECTION_SIZE) };
    assert!(!view.is_null(), "MapViewOfFile({name}) failed");
    // SAFETY: the mapping keeps the section alive independent of this
    //         handle once mapped.
    unsafe { CloseHandle(handle) };
    // SAFETY: view points to FOLDER_SECTION_SIZE read-only bytes, page-
    //         aligned per MapViewOfFile's contract; only `snapshot()` (a
    //         read-only method) is ever called on this view.
    unsafe { ipc::FolderSectionView::new(view.cast()) }
}

fn spawn_sleeper_session(
    launcher: &Path,
    hook_dll: &Path,
    sleeper: &Path,
    project_root: &Path,
    extra_env: &[(&str, &str)],
) -> std::process::Child {
    let mut cmd = Command::new(launcher);
    cmd.arg("-d");
    cmd.args(["--guard", "none"]);
    cmd.arg("--").arg(sleeper);
    cmd.current_dir(project_root);
    cmd.env("FS_SANDBOX_DLL", hook_dll);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());
    cmd.spawn().expect("spawn launcher")
}

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
fn broker_status_shows_broker_pid_and_attached_client() {
    let base = std::env::temp_dir().join("fs-sandbox-mp8-status");
    let project_root = base.join("project");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&project_root).unwrap();

    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let sleeper: PathBuf = find_binary("clean_sleep");
    let state_dir = state_dir_for(&project_root);
    let broker_json_path = state_dir.join("broker.json");

    let mut broker = spawn_sleeper_session(&launcher, &hook_dll, &sleeper, &project_root, &[]);
    let doc0 = poll_until_some(Duration::from_secs(5), || {
        winrsbox::contain::session_section::read_broker_json(&broker_json_path).ok()
    })
    .expect("broker.json must appear and parse");
    assert_eq!(doc0.broker_pid, broker.id());

    let mut client = spawn_sleeper_session(&launcher, &hook_dll, &sleeper, &project_root, &[]);
    let section_view = open_folder_section_read_only(&doc0.folder_section_name);
    poll_until_some(Duration::from_secs(10), || {
        section_view.snapshot().ok().filter(|s| s.launchers.iter().any(|&(pid, _)| pid == client.id()))
    })
    .expect("client must Attach before status is queried");

    let out = AssertCommand::new(&launcher)
        .env("WINRSBOX_STATE_DIR", &state_dir)
        .args(["broker", "status"])
        .timeout(Duration::from_secs(10))
        .output()
        .expect("run broker status");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(out.status.success(), "broker status must succeed: stdout={stdout} status={:?}", out.status);
    assert!(
        stdout.contains(&format!("pid={}", broker.id())),
        "status output must show the broker's own pid: {stdout}"
    );
    assert!(
        stdout.contains(&format!("pid={}", client.id())),
        "status output must list the attached client as a trusted launcher: {stdout}"
    );

    let _ = broker.kill();
    let _ = broker.wait();
    let _ = client.kill();
    let _ = client.wait();
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
#[serial]
fn broker_restart_fails_over_and_status_reports_the_new_broker() {
    let base = std::env::temp_dir().join("fs-sandbox-mp8-restart");
    let project_root = base.join("project");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&project_root).unwrap();

    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let sleeper: PathBuf = find_binary("clean_sleep");
    let state_dir = state_dir_for(&project_root);
    let broker_json_path = state_dir.join("broker.json");

    let mut broker = spawn_sleeper_session(&launcher, &hook_dll, &sleeper, &project_root, &[]);
    let doc0 = poll_until_some(Duration::from_secs(5), || {
        winrsbox::contain::session_section::read_broker_json(&broker_json_path).ok()
    })
    .expect("broker.json must appear and parse");
    assert_eq!(doc0.broker_pid, broker.id());

    let mut client = spawn_sleeper_session(&launcher, &hook_dll, &sleeper, &project_root, &[]);
    let section_view = open_folder_section_read_only(&doc0.folder_section_name);
    poll_until_some(Duration::from_secs(10), || {
        section_view.snapshot().ok().filter(|s| s.launchers.iter().any(|&(pid, _)| pid == client.id()))
    })
    .expect("client must Attach before restart");

    // `winrsbox broker restart` — CLI-driven kill, not a test-side TerminateProcess.
    AssertCommand::new(&launcher)
        .env("WINRSBOX_STATE_DIR", &state_dir)
        .args(["broker", "restart"])
        .timeout(Duration::from_secs(10))
        .assert()
        .success();

    // The old broker process must actually be gone.
    let broker_exited = poll_until_some(Duration::from_secs(10), || broker.try_wait().ok().flatten());
    assert!(broker_exited.is_some(), "broker restart must have actually terminated the old broker process");

    // The client's own session must be unaffected and must become the new
    // broker (MP-7 failover, triggered by `broker restart` exactly like a
    // real crash).
    let new_doc = poll_until_some(Duration::from_secs(15), || {
        winrsbox::contain::session_section::read_broker_json(&broker_json_path)
            .ok()
            .filter(|d| d.broker_pid == client.id())
    })
    .expect("the surviving client must become the new broker after `broker restart`");
    assert_ne!(new_doc.pipe_name, doc0.pipe_name, "the new broker must publish a fresh pipe name");
    assert!(client.try_wait().unwrap().is_none(), "the client's own session must survive the restart");

    // `broker status` afterward must report the NEW broker, not the dead one.
    let out = AssertCommand::new(&launcher)
        .env("WINRSBOX_STATE_DIR", &state_dir)
        .args(["broker", "status"])
        .timeout(Duration::from_secs(10))
        .output()
        .expect("run broker status after restart");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(out.status.success(), "broker status after restart must succeed: stdout={stdout}");
    assert!(
        stdout.contains(&format!("pid={}", client.id())),
        "status after restart must show the NEW broker's pid (the former client): {stdout}"
    );

    let _ = client.kill();
    let _ = client.wait();
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
#[serial]
fn hung_broker_makes_the_client_print_a_ping_timeout_warning() {
    let base = std::env::temp_dir().join("fs-sandbox-mp8-hung-ping");
    let project_root = base.join("project");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&project_root).unwrap();

    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let sleeper: PathBuf = find_binary("clean_sleep");
    let state_dir = state_dir_for(&project_root);
    let broker_json_path = state_dir.join("broker.json");

    // First launcher becomes the broker; every `Ping` it answers (including
    // on its own client's Attach connection) is delayed past the client's
    // 2s PING_TIMEOUT by this debug-build-only test seam — see
    // `main::session::run_launcher_session_loop`.
    let mut broker = spawn_sleeper_session(
        &launcher, &hook_dll, &sleeper, &project_root,
        &[("WINRSBOX_TEST_FREEZE_PING_MS", "4000")],
    );
    let doc0 = poll_until_some(Duration::from_secs(5), || {
        winrsbox::contain::session_section::read_broker_json(&broker_json_path).ok()
    })
    .expect("broker.json must appear and parse");
    assert_eq!(doc0.broker_pid, broker.id());

    let mut client = spawn_sleeper_session(&launcher, &hook_dll, &sleeper, &project_root, &[]);
    let mut client_stderr =
        BufReader::new(client.stderr.take().expect("client stderr must be piped"));

    let warning = read_line_matching(&mut client_stderr, "Ping", Duration::from_secs(20))
        .expect("the client must print a Ping-related warning against the frozen broker");
    assert!(
        warning.to_lowercase().contains("warning"),
        "expected a WARNING line about the stuck Ping, got: {warning}"
    );

    // Nothing was auto-killed: both processes must still be running — the
    // whole point of "warn, never auto-terminate a hung broker".
    assert!(broker.try_wait().unwrap().is_none(), "the frozen broker must not have been killed automatically");
    assert!(client.try_wait().unwrap().is_none(), "the client must still be running its own session");

    let _ = broker.kill();
    let _ = broker.wait();
    let _ = client.kill();
    let _ = client.wait();
    let _ = std::fs::remove_dir_all(&base);
}
