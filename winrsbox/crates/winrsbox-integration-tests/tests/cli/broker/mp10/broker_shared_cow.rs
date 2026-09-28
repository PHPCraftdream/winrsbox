// MP-10 §B1 E2E: multiple `winrsbox` sessions in the same folder share ONE
// CoW overlay/index through the broker's single `policy.redb` — a guest of
// one session can read back what a guest of a DIFFERENT session wrote,
// through the exact same virtual path, even though that path was never
// touched on the real disk (default `write: cow` redirects it).
//
// Two directions are covered, by two different mechanisms (see the plan's
// "выбери наблюдаемый критерий" note — both offered criteria are exercised
// here since each is cheap given the existing fixtures):
//   - session A (the broker's own long-lived guest) writes marker_a; a LATER
//     session C's guest reads it back LIVE, in-session, via `WINRSBOX_READ_
//     PATH` (`clean_write_one_file`'s MP-10 read mode) — proves live
//     cross-session redirection, not just eventual on-disk state.
//   - session B (a client)'s write of marker_b, plus session A's marker_a,
//     are BOTH still present and correct in the ONE shared `OVERLAY_IDX`
//     after every launcher has exited (reopened by a third process, same
//     load-bearing check `broker_client_session.rs` uses) — proves neither
//     write was lost or shadowed by the other under a shared index.
//
// Requires: cargo build -p integration-tests --bins
//           cargo build -p winrsbox
//           cargo build -p hook

use assert_cmd::Command as AssertCommand;
use serial_test::serial;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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

/// Recursively find a file named `file_name` under `dir` and return its
/// content. The CoW overlay mirrors the original absolute path underneath
/// `workdir` (drive-keyed subdirectories) — exact structure is an
/// implementation detail this test does not need to reproduce; scanning by
/// leaf name is the same technique `broker_client_session.rs`'s post-hoc
/// check effectively performs via `overlay_values_under_root`, applied here
/// directly on disk so it also works WHILE the broker still holds
/// `policy.redb` (a live re-open is not possible from this process then).
fn find_overlay_file_content(dir: &Path, file_name: &str) -> Option<String> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.file_name().map(|n| n == file_name).unwrap_or(false) {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    return Some(content);
                }
            }
        }
    }
    None
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

#[test]
#[serial]
fn two_sessions_share_the_cow_overlay_and_see_each_others_writes() {
    let base = std::env::temp_dir().join("fs-sandbox-mp10-shared-cow");
    let project_root = base.join("project");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&project_root).unwrap();

    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let sleeper: PathBuf = find_binary("clean_sleep");
    let writer: PathBuf = find_binary("clean_write_one_file");

    // Outside project_root, same drive — default `write: cow` applies (same
    // layout `broker_client_session.rs`/`concurrent_children.rs` use).
    let marker_a = base.join("marker_a.txt");
    let marker_b = base.join("marker_b.txt");
    let _ = std::fs::remove_file(&marker_a);
    let _ = std::fs::remove_file(&marker_b);

    // Session A: the broker. Its guest is the long-lived sleeper, extended
    // (MP-10) to write marker_a BEFORE sleeping — gives the broker's own
    // session a CoW write of its own without ending the process the broker
    // is bound to.
    let mut broker_cmd = Command::new(&launcher);
    broker_cmd.arg("-d");
    broker_cmd.args(["--guard", "none"]);
    broker_cmd.arg("--").arg(&sleeper);
    broker_cmd.current_dir(&project_root);
    broker_cmd.env("FS_SANDBOX_DLL", &hook_dll);
    broker_cmd.env("WINRSBOX_SLEEP_WRITE_PATH", &marker_a);
    broker_cmd.env("WINRSBOX_SLEEP_WRITE_CONTENT", "from-session-A");
    broker_cmd.stdout(Stdio::null());
    broker_cmd.stderr(Stdio::null());
    let mut broker = broker_cmd.spawn().expect("spawn broker launcher (session A)");

    let broker_json_path = state_dir_for(&project_root).join("broker.json");
    poll_until_some(Duration::from_secs(5), || {
        winrsbox::contain::session_section::read_broker_json(&broker_json_path).ok()
    })
    .expect("broker.json must appear and parse");
    assert!(
        broker.try_wait().unwrap().is_none(),
        "broker launcher exited early — it never got to open policy.redb"
    );
    // The sleeper writes marker_a synchronously before it starts sleeping,
    // but the write happens inside the freshly-injected guest, asynchronous
    // relative to broker.json appearing — poll the overlay directly on disk
    // (see `find_overlay_file_content`'s doc) for the actual write to land,
    // rather than racing session B/C's spawn against it.
    let workdir = state_dir_for(&project_root).join("workdir");
    let session_a_written = poll_until_some(Duration::from_secs(10), || {
        find_overlay_file_content(&workdir, "marker_a.txt")
    });
    assert_eq!(
        session_a_written.as_deref(),
        Some("from-session-A"),
        "session A's guest must have written marker_a to the overlay before sessions B/C start"
    );

    // Session B: a client whose guest writes marker_b, then exits (mirrors
    // `broker_client_session.rs`).
    let session_b_output = AssertCommand::new(&launcher)
        .arg("-d")
        .args(["--guard", "none"])
        .arg("--")
        .arg(&writer)
        .arg(&marker_b)
        .arg("from-session-B")
        .current_dir(&project_root)
        .env("FS_SANDBOX_DLL", &hook_dll)
        .timeout(Duration::from_secs(20))
        .output()
        .expect("run session B (client write)");
    assert_eq!(
        session_b_output.status.code(),
        Some(0),
        "session B's guest write must succeed via the shared policy the broker owns; stderr: {}",
        String::from_utf8_lossy(&session_b_output.stderr),
    );

    // Session C: a SEPARATE client whose guest reads back marker_a — the
    // file session A's guest wrote, never touched on the real disk. Success
    // here means session C's `decide()` found the SAME OVERLAY_IDX entry
    // session A's write created, live, through the one shared policy.redb —
    // the actual thing MP-10 §B1 exists to prove (not just eventual on-disk
    // state — see `broker_client_session.rs`'s own note on why raw file
    // presence proves nothing broker-specific by itself).
    let session_c_output = AssertCommand::new(&launcher)
        .arg("-d")
        .args(["--guard", "none"])
        .arg("--")
        .arg(&writer)
        .current_dir(&project_root)
        .env("FS_SANDBOX_DLL", &hook_dll)
        .env("WINRSBOX_READ_PATH", &marker_a)
        .timeout(Duration::from_secs(20))
        .output()
        .expect("run session C (client read of session A's write)");
    let session_c_stdout = String::from_utf8_lossy(&session_c_output.stdout).into_owned();
    assert_eq!(
        session_c_output.status.code(),
        Some(0),
        "session C's guest must read back session A's write through the shared overlay; \
         stdout={session_c_stdout} stderr={}",
        String::from_utf8_lossy(&session_c_output.stderr),
    );
    assert!(
        session_c_stdout.contains("read: ok from-session-A"),
        "session C must see session A's exact content, live, cross-session: {session_c_stdout}"
    );

    assert!(broker.try_wait().unwrap().is_none(), "broker must be unaffected by sessions B/C");

    // Neither write ever touched the real path — CoW isolation is preserved
    // across sessions, same invariant `concurrent_children.rs` checks for a
    // single session.
    assert!(!marker_a.exists(), "session A's write LEAKED to the real path: {}", marker_a.display());
    assert!(!marker_b.exists(), "session B's write LEAKED to the real path: {}", marker_b.display());

    let _ = broker.kill();
    let _ = broker.wait();

    // Load-bearing post-hoc check (mirrors `broker_client_session.rs`):
    // reopen the ONE shared policy.redb (now free) and confirm BOTH marker_a
    // and marker_b are indexed under OVERLAY_IDX with correct content —
    // neither write shadowed or lost the other in the shared index.
    let state_dir = state_dir_for(&project_root);
    let policy = policy::Policy::open_or_create(
        &state_dir.join("policy.redb"),
        state_dir.join("workdir"),
        state_dir.join("mock-dirs"),
        project_root.clone(),
    )
    .expect("policy.redb must be free once the broker has exited");
    let indexed = policy
        .overlay_values_under_root(&state_dir.join("workdir"))
        .expect("overlay_values_under_root");
    for (name, expected) in [("marker_a.txt", "from-session-A"), ("marker_b.txt", "from-session-B")] {
        let entry = indexed.iter().find(|p| p.file_name().map(|n| n == name).unwrap_or(false));
        assert!(entry.is_some(), "{name} must be indexed in the SHARED policy.redb: got {indexed:?}");
        let content = std::fs::read_to_string(entry.unwrap())
            .unwrap_or_else(|e| panic!("read {}: {e}", entry.unwrap().display()));
        assert_eq!(content, expected, "{name}'s indexed overlay content must be intact");
    }

    let _ = std::fs::remove_dir_all(&base);
}
