// MP-7 E2E: the broker's OWN target exits (a one-shot write, not a
// long-lived guest) while a client with a long-lived guest is attached in
// the SAME folder. The broker must not linger waiting on the unrelated
// client's session — its process must exit within a reasonable, bounded
// time once its own target is done — and the client's own session must be
// completely unaffected by the broker's exit.
//
// Requires: cargo build -p integration-tests --bins
//           cargo build -p winrsbox
//           cargo build -p hook

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use serial_test::serial;
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

/// Poll `try_wait` until the child exits or `budget` elapses. Returns the
/// exit status once observed.
fn wait_with_timeout(child: &mut Child, budget: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(status) = child.try_wait().ok().flatten() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
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

#[test]
#[serial]
fn broker_exits_promptly_after_its_own_target_finishes_while_a_client_keeps_running() {
    let base = std::env::temp_dir().join("fs-sandbox-mp7-failover-graceful");
    let project_root = base.join("project");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&project_root).unwrap();

    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let sleeper: PathBuf = find_binary("clean_sleep");
    let writer: PathBuf = find_binary("clean_write_one_file");
    let marker = base.join("broker_marker.txt");

    // Broker's OWN target is a one-shot write, not a long-lived guest — it
    // should finish (and the broker process along with it) quickly,
    // regardless of anything else going on in the folder.
    let mut broker_cmd = Command::new(&launcher);
    broker_cmd.arg("-d");
    broker_cmd.args(["--guard", "none"]);
    broker_cmd.arg("--").arg(&writer).arg(&marker).arg("broker-own-write");
    broker_cmd.current_dir(&project_root);
    broker_cmd.env("FS_SANDBOX_DLL", &hook_dll);
    broker_cmd.stdout(Stdio::null());
    broker_cmd.stderr(Stdio::null());
    let mut broker = broker_cmd.spawn().expect("spawn broker launcher");

    let broker_json_path = state_dir_for(&project_root).join("broker.json");
    let doc = poll_until_some(Duration::from_secs(5), || {
        winrsbox::contain::session_section::read_broker_json(&broker_json_path).ok()
    })
    .expect("broker.json must appear and parse");
    assert_eq!(doc.broker_pid, broker.id());

    // Attach a client with a LONG-LIVED guest before the broker's own quick
    // target has a chance to finish.
    let mut client_cmd = Command::new(&launcher);
    client_cmd.arg("-d");
    client_cmd.args(["--guard", "none"]);
    client_cmd.arg("--").arg(&sleeper);
    client_cmd.current_dir(&project_root);
    client_cmd.env("FS_SANDBOX_DLL", &hook_dll);
    client_cmd.stdout(Stdio::null());
    client_cmd.stderr(Stdio::null());
    let mut client = client_cmd.spawn().expect("spawn client launcher");

    let section_view = open_folder_section_read_only(&doc.folder_section_name);
    let attached = poll_until_some(Duration::from_secs(10), || {
        section_view
            .snapshot()
            .ok()
            .filter(|s| s.launchers.iter().any(|&(pid, _)| pid == client.id()))
    });
    assert!(attached.is_some(), "client must Attach while the broker's own target is still running");

    // The broker's own target is a quick one-shot write: the broker process
    // must exit within a bounded, reasonable time — NOT wait around for the
    // unrelated client's still-running (long-lived) guest.
    let status = wait_with_timeout(&mut broker, Duration::from_secs(10));
    assert!(
        status.is_some(),
        "broker must exit within 10s of its own target finishing, even with a client's \
         session still alive in the same folder — the terminal must not hang"
    );
    // `clean_write_one_file` exits 0 only if its own `std::fs::write` call
    // succeeded (see its doc) — proof enough that the target actually ran
    // to completion under the sandbox. It must NOT be re-checked via
    // `marker.exists()` on the host: an unconfigured path defaults to CoW
    // (see `broker_client_session.rs`), so the write is redirected to the
    // overlay and never touches the real path at all.
    assert_eq!(status.unwrap().code(), Some(0), "broker's own target wrote successfully, so it must exit 0");

    // The client's own session must be completely unaffected by the
    // broker's exit (whether or not it has since won the MP-7 failover race
    // is NOT what this test is about — see broker_failover_kill.rs for that).
    assert!(
        client.try_wait().unwrap().is_none(),
        "client's own session must be unaffected by the broker's exit"
    );

    let _ = client.kill();
    let _ = client.wait();
    let _ = std::fs::remove_dir_all(&base);
}
