// MP-7 E2E: TerminateProcess the broker's own launcher (simulating a crash)
// while a second launcher (client) is attached and running its own guest.
// The client must survive completely unaffected, then win the failover
// race and become the new broker — observable via `broker.json`'s
// `broker_pid` changing to the client's own pid and a fresh pipe name. A
// THIRD launcher, started fresh in the same folder afterward, must attach
// to the NEW broker successfully (not `EXIT_CONFLICT`, and without itself
// racing the client for the broker role — `policy.redb` is already held).
//
// Requires: cargo build -p integration-tests --bins
//           cargo build -p winrsbox
//           cargo build -p hook

use assert_cmd::Command as AssertCommand;
use serial_test::serial;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use winapi::shared::minwindef::FALSE;
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{MapViewOfFile, OpenFileMappingW, FILE_MAP_READ};

#[path = "../../../common/mod.rs"]
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

/// Same technique as `broker_attach.rs`: open a folder section read-only, by
/// name — no special access needed, the section's DACL already grants
/// `SECTION_QUERY | SECTION_MAP_READ` to the current user.
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

fn spawn_sleeper_session(launcher: &Path, hook_dll: &Path, sleeper: &Path, project_root: &Path) -> std::process::Child {
    let mut cmd = Command::new(launcher);
    cmd.arg("-d");
    cmd.args(["--guard", "none"]);
    cmd.arg("--").arg(sleeper);
    cmd.current_dir(project_root);
    cmd.env("FS_SANDBOX_DLL", hook_dll);
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    cmd.spawn().expect("spawn launcher")
}

#[test]
#[serial]
fn broker_death_failover_client_survives_and_a_new_launcher_attaches() {
    let base = std::env::temp_dir().join("fs-sandbox-mp7-failover-kill");
    let project_root = base.join("project");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&project_root).unwrap();

    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let sleeper: PathBuf = find_binary("clean_sleep");
    let writer: PathBuf = find_binary("clean_write_one_file");
    let broker_json_path = state_dir_for(&project_root).join("broker.json");

    // First launcher: the broker, with a long-lived guest.
    let mut broker = spawn_sleeper_session(&launcher, &hook_dll, &sleeper, &project_root);
    let doc0 = poll_until_some(Duration::from_secs(5), || {
        winrsbox::contain::session_section::read_broker_json(&broker_json_path).ok()
    })
    .expect("broker.json must appear and parse");
    assert_eq!(doc0.broker_pid, broker.id());
    assert!(
        broker.try_wait().unwrap().is_none(),
        "broker launcher exited early — it never got to open policy.redb"
    );

    // Second launcher: the client, ALSO with a long-lived guest — attaches
    // to the first (same pattern as broker_attach.rs).
    let mut client = spawn_sleeper_session(&launcher, &hook_dll, &sleeper, &project_root);
    let section_view = open_folder_section_read_only(&doc0.folder_section_name);
    let attached = poll_until_some(Duration::from_secs(10), || {
        section_view
            .snapshot()
            .ok()
            .filter(|s| s.launchers.iter().any(|&(pid, _)| pid == client.id()))
    });
    assert!(attached.is_some(), "client must Attach to the first broker before it dies");
    assert!(client.try_wait().unwrap().is_none(), "client must be running its own session");

    // Kill the broker's LAUNCHER process by its own child PID (simulates a
    // crash) — its guest dies with it via KILL_ON_JOB_CLOSE, as designed;
    // that is not what this test is about.
    broker.kill().expect("TerminateProcess the broker launcher");
    broker.wait().ok();

    // The client's MP-7 failover watcher must detect the death and become
    // the new broker: broker.json's identity changes to the client's own
    // pid, with a freshly generated pipe name.
    let new_doc = poll_until_some(Duration::from_secs(15), || {
        winrsbox::contain::session_section::read_broker_json(&broker_json_path)
            .ok()
            .filter(|d| d.broker_pid == client.id())
    })
    .expect("the surviving client must become the new broker after the old one dies");
    assert_ne!(
        new_doc.pipe_name, doc0.pipe_name,
        "the new broker must publish a fresh pipe name, not reuse the dead one"
    );

    // The client's own session (guest) must be completely unaffected by it
    // having taken over the broker role in-process.
    assert!(
        client.try_wait().unwrap().is_none(),
        "the client (now the new broker) must keep running its own guest session"
    );

    // A third launcher, started fresh in the SAME folder, must successfully
    // Attach to the NEW broker rather than failing with EXIT_CONFLICT or
    // itself racing for the (already-held) broker role.
    let marker = base.join("third_marker.txt");
    let third_output = AssertCommand::new(&launcher)
        .arg("-d")
        .args(["--guard", "none", "--verbose"])
        .arg("--")
        .arg(&writer)
        .arg(&marker)
        .arg("third-launcher-after-failover")
        .current_dir(&project_root)
        .env("FS_SANDBOX_DLL", &hook_dll)
        .timeout(Duration::from_secs(20))
        .output()
        .expect("run third launcher");
    let third_stderr = String::from_utf8_lossy(&third_output.stderr).into_owned();
    assert_eq!(
        third_output.status.code(),
        Some(0),
        "third launcher must Attach to the new broker and run its guest successfully; stderr: {third_stderr}"
    );
    // `clean_write_one_file` exits 0 only if its own `std::fs::write` call
    // succeeded (see its doc) — already asserted above. It must NOT be
    // re-checked via `marker.exists()` on the host: an unconfigured path
    // defaults to CoW (see `broker_client_session.rs`), so the write is
    // redirected to the overlay and never touches the real path at all.

    // The client must still be the SOLE broker afterward — the third
    // launcher's own startup role-decision must not have raced it away.
    let after_third = winrsbox::contain::session_section::read_broker_json(&broker_json_path)
        .expect("broker.json must remain readable");
    assert_eq!(
        after_third.broker_pid,
        client.id(),
        "the client must remain the one and only broker after the third launcher's session"
    );

    let _ = client.kill();
    let _ = client.wait();
    let _ = std::fs::remove_dir_all(&base);
}
