// MP-6 E2E acceptance test: a client launcher runs a REAL session (no DB,
// no pipe server of its own) whose guest write reaches the SAME shared CoW
// state the broker owns.
//
// The two overlay roots (project-drive workdir AND the %LOCALAPPDATA% C:
// root) are both keyed purely by `project_root` — deterministic paths ANY
// process could compute, broker or not — so raw file presence under them
// proves nothing broker-specific by itself. What MP-6 actually has to get
// right is that the client's guest, despite never touching `policy.redb`,
// causes exactly the same durable state a broker-side write would: an
// `OVERLAY_IDX` entry in the ONE shared database. A client with a stray
// second DB (impossible — that's the whole reason for the broker/client
// split, see `docs/multiprocess-broker-plan.md`) or one that silently ran
// unsandboxed would both leave no such entry. So the test's load-bearing
// check is re-opening `policy.redb` (after both launchers have exited, so
// the exclusive lock is free) and confirming the client's write is indexed
// there — not just that a file exists on disk.
//
// Secondary checks cover the rest of MP-6's acceptance criteria: both
// launchers exit with the expected codes, and the broker's own
// `sandbox.log.jsonl` contains an entry that could only have come from the
// client (forwarded over `ipc::Req::LauncherLog` — see `main::client` /
// `main::session::run_launcher_session_loop`), proving the log-forwarding
// and `SessionStats` paths actually round-trip end to end.
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
fn client_guest_write_lands_in_the_shared_overlay_index() {
    let base = std::env::temp_dir().join("fs-sandbox-mp6-session");
    let project_root = base.join("project");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&project_root).unwrap();

    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let sleeper: PathBuf = find_binary("clean_sleep");
    let writer: PathBuf = find_binary("clean_write_one_file");

    // Outside project_root (same drive) — default `write: cow` applies,
    // same layout `concurrent_children.rs` exercises for a single session.
    let marker = base.join("client_marker.txt");
    let _ = std::fs::remove_file(&marker);

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
    let initial_generation = section_view.snapshot().expect("initial snapshot").generation;

    // The client's guest is short-lived (write one file, exit 0) — its
    // LAUNCHER runs the whole session (Attach, hook inject, wait for the
    // guest, own-job drain, SessionStats fetch, exit) and then exits too, so
    // a plain blocking `.output()` is fine here (unlike broker_attach.rs's
    // sleeper-guest client, which never exits on its own).
    let client_output = AssertCommand::new(&launcher)
        .arg("-d")
        .args(["--guard", "none", "--verbose"])
        .arg("--")
        .arg(&writer)
        .arg(&marker)
        .arg("shared-cow-from-client")
        .current_dir(&project_root)
        .env("FS_SANDBOX_DLL", &hook_dll)
        .timeout(Duration::from_secs(20))
        .output()
        .expect("run client launcher");
    let client_stderr = String::from_utf8_lossy(&client_output.stderr).into_owned();

    assert_eq!(
        client_output.status.code(),
        Some(0),
        "client launcher must exit 0 (its guest's write must succeed via the shared \
         policy the broker owns); stderr: {client_stderr}"
    );
    assert!(
        client_stderr.contains("[sandbox] exit=0"),
        "client's own exit summary (SessionStats-backed, --verbose) must print: {client_stderr}"
    );

    // Attach happened (generation bumped). Its removal from the trusted set
    // runs on the broker's own background exit-watch task (`main::broker::
    // spawn_launcher_exit_watch`, woken by `WaitForSingleObject` on the
    // client's process handle) — asynchronous relative to `.output()`
    // returning, so poll for it rather than asserting immediately.
    let after = poll_until_some(Duration::from_secs(3), || {
        section_view.snapshot().ok().filter(|s| s.generation > initial_generation)
    });
    assert!(after.is_some(), "folder section generation must advance after the client's Attach");
    let removed = poll_until_some(Duration::from_secs(5), || {
        section_view.snapshot().ok().filter(|s| s.launchers.is_empty())
    });
    assert!(
        removed.is_some(),
        "the client must be removed from the trusted set once its launcher exits"
    );

    assert!(
        broker.try_wait().unwrap().is_none(),
        "broker must be unaffected by the client's whole session"
    );

    // The guest write must never leak to the real path — same CoW isolation
    // invariant `concurrent_children.rs` checks for a single session.
    assert!(!marker.exists(), "client's write LEAKED to the real path: {}", marker.display());

    // The broker's sandbox.log.jsonl must contain a line forwarded from the
    // client over ipc::Req::LauncherLog (main::client's init_remote sender +
    // main::session::run_launcher_session_loop's append_raw_line) — proves
    // the log-forwarding path actually round-tripped, not just that the
    // session ran.
    let jsonl_path = state_dir_for(&project_root).join("sandbox.log.jsonl");
    let jsonl = poll_until_some(Duration::from_secs(2), || std::fs::read_to_string(&jsonl_path).ok())
        .expect("sandbox.log.jsonl must exist");
    assert!(
        jsonl.contains("attached to broker pid="),
        "broker's own sandbox.log.jsonl must contain the client's forwarded \
         launcher_diag line (proves LauncherLog forwarding worked):\n{jsonl}"
    );

    let _ = broker.kill();
    let _ = broker.wait();

    // Load-bearing check: re-open policy.redb (now free — both launchers
    // are gone) from a THIRD process and confirm the client's write is
    // indexed under OVERLAY_IDX. This is the actual MP-6 correctness proof
    // (see the module doc): a client that bypassed the broker's shared
    // policy state, or wrote unsandboxed, would leave no such entry even
    // though the raw file would still (or would never) exist.
    let state_dir = state_dir_for(&project_root);
    let policy = policy::Policy::open_or_create(
        &state_dir.join("policy.redb"),
        state_dir.join("workdir"),
        state_dir.join("mock-dirs"),
        project_root.clone(),
    )
    .expect("policy.redb must be free once both launchers have exited");
    // `overlay_values_under_root` returns the OVERLAY-SIDE path for every
    // OVERLAY_IDX entry recorded under `root` (see `sandbox::inject::
    // complete_c_overlay_migration`'s use of the same call, on the legacy
    // root) — not the original virtual path — so query it with the workdir
    // root, not `base`.
    let indexed = policy
        .overlay_values_under_root(&state_dir.join("workdir"))
        .expect("overlay_values_under_root");
    let marker_entry = indexed
        .iter()
        .find(|p| p.file_name().map(|n| n == "client_marker.txt").unwrap_or(false));
    assert!(
        marker_entry.is_some(),
        "client's write must be indexed in the SHARED policy.redb under {}: got {indexed:?}",
        state_dir.join("workdir").display(),
    );
    let overlay_content = std::fs::read_to_string(marker_entry.unwrap())
        .unwrap_or_else(|e| panic!("read {}: {e}", marker_entry.unwrap().display()));
    assert_eq!(
        overlay_content, "shared-cow-from-client",
        "the indexed overlay file must actually hold the client's write"
    );

    let _ = std::fs::remove_dir_all(&base);
}
