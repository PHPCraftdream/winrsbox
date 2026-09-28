// MP-10 §B3 E2E: a GUEST belonging to a DIFFERENT session of the SAME
// folder (session B's own target, not its launcher) connects directly to
// the broker's pipe and sends `Attach`/`PolicyMutate` — the broker-only
// requests. Being a member of the folder job (kernel-truth admission,
// `contain::jobctl::FolderJob`) is enough to be treated as an ordinary,
// trusted GUEST connection (`pipe_server::mod.rs::handle_connection`), but
// that dispatch must still reject both requests outright
// (`Resp::Err("... not valid on an admitted connection")`) — job membership
// authorizes Hello/Decide/RegisterChild-style guest traffic, never the
// broker-role requests a launcher sends pre-admission.
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
    // SAFETY: the mapping keeps the section alive independent of this handle.
    unsafe { CloseHandle(handle) };
    // SAFETY: view points to FOLDER_SECTION_SIZE read-only bytes, page-
    //         aligned per MapViewOfFile's contract; only `snapshot()` (a
    //         read-only method) is ever called on this view.
    unsafe { ipc::FolderSectionView::new(view.cast()) }
}

#[test]
#[serial]
fn other_sessions_guest_cannot_attach_or_mutate_policy() {
    let base = std::env::temp_dir().join("fs-sandbox-mp10-guest-attach-denied");
    let project_root = base.join("project");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&project_root).unwrap();

    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let sleeper: PathBuf = find_binary("clean_sleep");
    let prober: PathBuf = find_binary("escape_broker_attach_from_guest");

    // Session A: the broker, with a long-lived guest.
    let mut broker_cmd = Command::new(&launcher);
    broker_cmd.arg("-d");
    broker_cmd.args(["--guard", "none"]);
    broker_cmd.arg("--").arg(&sleeper);
    broker_cmd.current_dir(&project_root);
    broker_cmd.env("FS_SANDBOX_DLL", &hook_dll);
    broker_cmd.stdout(Stdio::null());
    broker_cmd.stderr(Stdio::null());
    let mut broker = broker_cmd.spawn().expect("spawn broker launcher (session A)");

    let broker_json_path = state_dir_for(&project_root).join("broker.json");
    let doc0 = poll_until_some(Duration::from_secs(5), || {
        winrsbox::contain::session_section::read_broker_json(&broker_json_path).ok()
    })
    .expect("broker.json must appear and parse");
    assert!(broker.try_wait().unwrap().is_none(), "broker launcher exited early");

    let section_view = open_folder_section_read_only(&doc0.folder_section_name);
    let initial_generation = section_view.snapshot().expect("initial snapshot").generation;

    // Session B: a DIFFERENT session in the SAME folder. Its guest is the
    // MP-10 prober — receives the broker's pipe name as an argument (it
    // cannot read `.winrsbox`/`broker.json` itself, sandboxed) and attempts
    // Attach then PolicyMutate directly against the broker's pipe. Session
    // B's own LAUNCHER legitimately Attaches for itself first (normal
    // MP-3/MP-6 flow, unrelated to this test) — the prober's OWN connection
    // attempts, from inside the guest, are what must be rejected.
    let session_b_output = Command::new(&launcher)
        .arg("-d")
        .args(["--guard", "none", "--verbose"])
        .arg("--")
        .arg(&prober)
        .arg(&doc0.pipe_name)
        .current_dir(&project_root)
        .env("FS_SANDBOX_DLL", &hook_dll)
        .output()
        .expect("run session B (prober guest)");
    let session_b_stdout = String::from_utf8_lossy(&session_b_output.stdout).into_owned();
    let session_b_stderr = String::from_utf8_lossy(&session_b_output.stderr).into_owned();

    assert_eq!(
        session_b_output.status.code(),
        Some(0),
        "the prober guest must observe BOTH Attach and PolicyMutate rejected (Resp::Err) — \
         a nonzero exit means one of them was NOT rejected (security failure) or the connect \
         itself failed; stdout={session_b_stdout} stderr={session_b_stderr}",
    );
    assert!(
        session_b_stdout.contains("attach: rejected as expected"),
        "prober stdout must record the Attach rejection: {session_b_stdout}"
    );
    assert!(
        session_b_stdout.contains("policy_mutate: rejected as expected"),
        "prober stdout must record the PolicyMutate rejection: {session_b_stdout}"
    );

    // The broker must be completely unaffected: still alive, own session
    // (sleeper guest) still running.
    assert!(
        broker.try_wait().unwrap().is_none(),
        "broker must remain alive and unaffected by the guest's rejected requests"
    );

    // The trusted-launcher set only grew from session B's OWN launcher
    // legitimately Attaching (normal MP-3/MP-6 flow) — never from the
    // guest's rejected Attach attempt, which used the GUEST's own pid, not
    // the launcher's.
    let after = section_view.snapshot().expect("post-session-B snapshot");
    assert!(
        after.generation > initial_generation,
        "generation must still have advanced from session B's OWN launcher's legitimate Attach"
    );

    let _ = broker.kill();
    let _ = broker.wait();
    let _ = std::fs::remove_dir_all(&base);
}
