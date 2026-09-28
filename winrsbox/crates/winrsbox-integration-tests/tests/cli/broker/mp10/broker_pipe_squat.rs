// MP-10 §A/§B2 E2E: a guest pre-creates a named pipe under the OLD,
// predictable name scheme (`fs-sandbox-<pid>`) for the PID that is about to
// win the MP-7 failover race, BEFORE the real broker dies — exactly the
// attack `docs/multiprocess-broker-plan.md`'s "Что важно о модели угроз" /
// MP-7 review note describes: a guest squatting the winner's guessable pipe
// name with `FILE_FLAG_FIRST_PIPE_INSTANCE` would make the real winner's own
// first-instance bind fail (fatal, per the plan). MP-10 §A's fix
// (`contain::session_section::random_pipe_name`) makes the name unguessable,
// so the squat — even at the EXACT pid the test knows will win, which a real
// attacker normally could not — must simply not matter: the winner never
// tries the predictable name at all.
//
// Companion unit test:
// `pipe_server::tests::pipe_accept_loop_tests::
// pipe_accept_loop_fails_closed_when_first_instance_name_is_already_taken`
// proves the OTHER half — that a genuine collision on whatever name IS used
// fails closed rather than degrading silently.
//
// Requires: cargo build -p integration-tests --bins
//           cargo build -p winrsbox
//           cargo build -p hook

use assert_cmd::Command as AssertCommand;
use serial_test::serial;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr::null_mut;
use std::time::{Duration, Instant};
use winapi::shared::minwindef::FALSE;
use winapi::shared::ntdef::HANDLE;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::memoryapi::{MapViewOfFile, OpenFileMappingW, FILE_MAP_READ};
use winapi::um::namedpipeapi::CreateNamedPipeW;
use winapi::um::winbase::{PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT};

#[path = "../../../common/mod.rs"]
mod common;
use common::{find_binary, find_hook_dll, find_launcher};

/// Not re-exported by `winapi::um::winbase` in every version pinned here —
/// hardcoded to the documented, stable Win32 value (winbase.h) rather than
/// risk a version-specific import path; MUST match the value the launcher's
/// own `windows`-crate `FILE_FLAG_FIRST_PIPE_INSTANCE` constant carries.
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;

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
    // SAFETY: the mapping keeps the section alive independent of this handle.
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

/// Squat a named pipe under the OLD predictable scheme
/// (`\\.\pipe\fs-sandbox-<pid>`) with `FILE_FLAG_FIRST_PIPE_INSTANCE` — the
/// exact call a real broker's own startup (or a failover winner) makes.
/// Returns the raw handle (leaked as `isize` to cross the caller's stack
/// frame safely); the caller closes it with `CloseHandle`.
fn squat_predictable_pipe_name(pid: u32) -> isize {
    let name = format!(r"\\.\pipe\fs-sandbox-{pid}");
    let wide: Vec<u16> = OsStr::new(&name).encode_wide().chain(Some(0)).collect();
    // SAFETY: wide is a NUL-terminated UTF-16 name; null_mut() = default
    //         security descriptor (this test's own process, same user as
    //         everything else here — no privilege boundary being tested).
    let h = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            null_mut(),
        )
    };
    assert!(
        h != INVALID_HANDLE_VALUE,
        "test setup: squatting {name} (FIRST_PIPE_INSTANCE) failed, err={}",
        unsafe { GetLastError() },
    );
    h as isize
}

#[test]
#[serial]
fn squatting_the_predictable_pid_pipe_name_does_not_block_the_failover_winner() {
    let base = std::env::temp_dir().join("fs-sandbox-mp10-pipe-squat");
    let project_root = base.join("project");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&project_root).unwrap();

    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let sleeper: PathBuf = find_binary("clean_sleep");
    let writer: PathBuf = find_binary("clean_write_one_file");
    let broker_json_path = state_dir_for(&project_root).join("broker.json");

    // Session A: the broker, with a long-lived guest.
    let mut broker = spawn_sleeper_session(&launcher, &hook_dll, &sleeper, &project_root);
    let doc0 = poll_until_some(Duration::from_secs(5), || {
        winrsbox::contain::session_section::read_broker_json(&broker_json_path).ok()
    })
    .expect("broker.json must appear and parse");
    assert!(broker.try_wait().unwrap().is_none(), "broker launcher exited early");

    // Session B: the client that will win the failover race — the only
    // surviving launcher in the folder once A dies, same deterministic
    // setup `broker_failover_kill.rs` relies on.
    let mut client = spawn_sleeper_session(&launcher, &hook_dll, &sleeper, &project_root);
    let section_view = open_folder_section_read_only(&doc0.folder_section_name);
    let attached = poll_until_some(Duration::from_secs(10), || {
        section_view.snapshot().ok().filter(|s| s.launchers.iter().any(|&(pid, _)| pid == client.id()))
    });
    assert!(attached.is_some(), "client must Attach to the first broker before it dies");

    // The attack: squat the OLD predictable name for the PID this test
    // KNOWS will become the new broker — something a real guest could only
    // do by luck, but that is exactly the point: even a successful guess
    // must not matter anymore. Done BEFORE killing the broker, so it is
    // fully in place before the failover race starts.
    let squatter = squat_predictable_pipe_name(client.id());

    broker.kill().expect("TerminateProcess the broker launcher");
    broker.wait().ok();

    let predictable_name = format!(r"\\.\pipe\fs-sandbox-{}", client.id());
    let new_doc = poll_until_some(Duration::from_secs(15), || {
        winrsbox::contain::session_section::read_broker_json(&broker_json_path)
            .ok()
            .filter(|d| d.broker_pid == client.id())
    })
    .expect(
        "the surviving client must become the new broker even though its predictable pipe \
         name is squatted — a pre-MP-10 §A fix would have failed here (fatal collision)",
    );
    assert_ne!(
        new_doc.pipe_name, predictable_name,
        "the new broker's pipe name must be random, not the squatted predictable name"
    );

    assert!(
        client.try_wait().unwrap().is_none(),
        "the client (now the new broker) must keep running its own guest session, unaffected \
         by the squatted predictable name"
    );

    // A third launcher must still be able to Attach to the new (randomly
    // named) broker — proves the system is fully functional, not merely
    // "didn't crash".
    let marker = base.join("third_marker.txt");
    let third_output = AssertCommand::new(&launcher)
        .arg("-d")
        .args(["--guard", "none", "--verbose"])
        .arg("--")
        .arg(&writer)
        .arg(&marker)
        .arg("third-launcher-after-squatted-failover")
        .current_dir(&project_root)
        .env("FS_SANDBOX_DLL", &hook_dll)
        .timeout(Duration::from_secs(20))
        .output()
        .expect("run third launcher");
    assert_eq!(
        third_output.status.code(),
        Some(0),
        "third launcher must Attach to the new broker and run its guest successfully; stderr: {}",
        String::from_utf8_lossy(&third_output.stderr),
    );

    // SAFETY: squatter is the handle returned by CreateNamedPipeW above,
    //         never closed elsewhere on this path.
    unsafe { CloseHandle(squatter as HANDLE) };
    let _ = client.kill();
    let _ = client.wait();
    let _ = std::fs::remove_dir_all(&base);
}
