// MP-3/MP-6 E2E: two `winrsbox` in the same, brand-new folder. The first is
// the broker (MP-2); the second, on hitting `DatabaseAlreadyOpen`, sends
// `Attach` and (MP-6) then runs a REAL session of its own — hook injection,
// job objects, the works — instead of MP-3's "attach then print+exit" smoke
// test. This test proves the protocol works end to end: the broker
// duplicates handles into the second launcher and registers it in the
// folder section's trusted-launcher set, observable from a THIRD party
// (this test process) by opening the section read-only, by name, off
// `broker.json` — no special access, exactly what any same-user reader
// gets. Since the client now stays running for its own session (it no
// longer exits right after Attach), this test polls for the generation
// bump instead of waiting for client exit.
//
// Requires: cargo build -p integration-tests --bins
//           cargo build -p winrsbox
//           cargo build -p hook

use serial_test::serial;
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

/// Open a folder section by name, read-only — the section's DACL grants
/// `SECTION_QUERY | SECTION_MAP_READ` to the current user
/// (`contain::session_section::create_owned_readonly_section`), so a plain
/// same-user open needs nothing special. The handle is closed right after
/// mapping: the view stays valid regardless (backed by the broker's own
/// long-lived handle to the same kernel object), matching the pattern in
/// `contain::session_section`'s own tests.
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
    //         handle once mapped; the broker's own long-lived handle keeps
    //         the underlying object alive regardless.
    unsafe { CloseHandle(handle) };
    // SAFETY: view points to FOLDER_SECTION_SIZE read-only bytes, page-
    //         aligned per MapViewOfFile's contract; only `snapshot()` (a
    //         read-only method) is ever called on this view.
    unsafe { ipc::FolderSectionView::new(view.cast()) }
}

#[test]
#[serial]
fn second_launcher_attaches_and_broker_sees_it_in_the_folder_section() {
    let base = std::env::temp_dir().join("fs-sandbox-mp3-attach");
    let project_root = base.join("project");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&project_root).unwrap();

    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let sleeper: PathBuf = find_binary("clean_sleep");

    let mut broker_cmd = Command::new(&launcher);
    broker_cmd.arg("-d");
    broker_cmd.args(["--guard", "none"]);
    broker_cmd.arg("--").arg(&sleeper);
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
    assert!(
        broker.try_wait().unwrap().is_none(),
        "broker launcher exited early — it never got to open policy.redb"
    );

    let section_view = open_folder_section_read_only(&doc.folder_section_name);
    let initial = section_view.snapshot().expect("initial snapshot");
    assert_eq!(initial.broker_pid, doc.broker_pid);
    assert!(initial.launchers.is_empty(), "no launcher attached yet");
    assert_eq!(initial.generation, 0, "init() leaves the section at generation 0");

    // MP-6: the client now runs a real session (hook injection, job
    // objects) instead of exiting right after Attach — spawn it and keep it
    // running, same as the broker.
    let mut client_cmd = Command::new(&launcher);
    client_cmd.arg("-d");
    client_cmd.args(["--guard", "none"]);
    client_cmd.arg("--").arg(&sleeper);
    client_cmd.current_dir(&project_root);
    client_cmd.env("FS_SANDBOX_DLL", &hook_dll);
    client_cmd.stdout(Stdio::null());
    client_cmd.stderr(Stdio::null());
    let mut client = client_cmd.spawn().expect("spawn client launcher");

    let after = poll_until_some(Duration::from_secs(10), || {
        section_view.snapshot().ok().filter(|s| s.generation > initial.generation)
    });
    assert!(
        after.is_some(),
        "folder section generation must have advanced past {} after a successful Attach",
        initial.generation,
    );
    let after = after.unwrap();
    assert!(
        after.launchers.iter().any(|(pid, _)| *pid == client.id()),
        "the client's own pid must appear in the trusted-launcher set: {:?}",
        after.launchers,
    );

    assert!(
        client.try_wait().unwrap().is_none(),
        "client must be running its own session now, not exited (MP-3's smoke-exit is gone)"
    );
    assert!(
        broker.try_wait().unwrap().is_none(),
        "broker must be unaffected by the client attaching"
    );

    let _ = client.kill();
    let _ = client.wait();
    let _ = broker.kill();
    let _ = broker.wait();
    let _ = std::fs::remove_dir_all(&base);
}
