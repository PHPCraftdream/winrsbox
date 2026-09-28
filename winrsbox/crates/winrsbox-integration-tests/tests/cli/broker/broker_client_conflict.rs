// MP-2 originally: two `winrsbox` launched in the same, brand-new folder —
// the second saw DatabaseAlreadyOpen and exited with `cli::EXIT_CONFLICT`
// (full client support, actually connecting to the broker, was MP-6).
//
// MP-6: a second launcher in the same folder is no longer a conflict — it
// attaches to the broker and runs a real session of its own. This test now
// proves exactly that: neither launcher ever sees `EXIT_CONFLICT`, both run
// their own long-lived targets concurrently, and killing one leaves the
// other completely unaffected (the folder-broker design's whole point —
// see `docs/multiprocess-broker-plan.md`). The shared-CoW acceptance
// criterion for MP-6 lives in `broker_client_session.rs`; this test stays
// the lighter "no conflict, both survive" smoke test.
//
// Requires: cargo build -p integration-tests --bins
//           cargo build -p winrsbox
//           cargo build -p hook

use serial_test::serial;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

#[path = "../../common/mod.rs"]
mod common;
use common::{find_binary, find_hook_dll, find_launcher};

#[test]
#[serial]
fn second_launcher_in_same_folder_attaches_instead_of_conflicting() {
    let base = std::env::temp_dir().join("fs-sandbox-mp6-no-conflict");
    let project_root = base.join("project");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&project_root).unwrap();

    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    // Sleeps ~30s — keeps both launchers (and the broker's policy.redb
    // handle) alive for the whole test.
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

    // The broker opens policy.redb very early (well before its 100ms
    // pipe-server warm-up sleep) — this window is generous relative to
    // that.
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        broker.try_wait().unwrap().is_none(),
        "broker launcher exited early — it never got to open policy.redb"
    );

    let mut client_cmd = Command::new(&launcher);
    client_cmd.arg("-d");
    client_cmd.args(["--guard", "none"]);
    client_cmd.arg("--").arg(&sleeper);
    client_cmd.current_dir(&project_root);
    client_cmd.env("FS_SANDBOX_DLL", &hook_dll);
    client_cmd.stdout(Stdio::null());
    client_cmd.stderr(Stdio::null());
    let mut client = client_cmd.spawn().expect("spawn client launcher");

    // Give the client's Attach + guest launch + hook-init handshake time to
    // complete (generous relative to the sub-second exchange MP-3 measured).
    std::thread::sleep(Duration::from_millis(2000));
    assert!(
        client.try_wait().unwrap().is_none(),
        "client launcher must be running a real session now, not exiting \
         with EXIT_CONFLICT — MP-6 replaced that path"
    );
    assert!(
        broker.try_wait().unwrap().is_none(),
        "broker must be unaffected by the client attaching"
    );

    // Killing the client must not touch the broker's own session.
    let _ = client.kill();
    let _ = client.wait();
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        broker.try_wait().unwrap().is_none(),
        "broker launcher must still be running after the client exits"
    );

    let _ = broker.kill();
    let _ = broker.wait();
    let _ = std::fs::remove_dir_all(&base);
}

/// A third launcher, started only after the broker already has one client
/// attached, must ALSO attach successfully rather than conflicting with the
/// existing client — proves the trusted-launcher SET (not a single slot)
/// is what admission is checked against.
#[test]
#[serial]
fn a_second_client_also_attaches_while_the_first_is_still_running() {
    let base = std::env::temp_dir().join("fs-sandbox-mp6-two-clients");
    let project_root = base.join("project");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&project_root).unwrap();

    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let sleeper: PathBuf = find_binary("clean_sleep");

    let spawn_session = |dir: &std::path::Path| -> std::process::Child {
        let mut cmd = Command::new(&launcher);
        cmd.arg("-d");
        cmd.args(["--guard", "none"]);
        cmd.arg("--").arg(&sleeper);
        cmd.current_dir(dir);
        cmd.env("FS_SANDBOX_DLL", &hook_dll);
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
        cmd.spawn().expect("spawn launcher")
    };

    let mut broker = spawn_session(&project_root);
    std::thread::sleep(Duration::from_millis(1500));
    assert!(broker.try_wait().unwrap().is_none(), "broker must still be running");

    let mut client_a = spawn_session(&project_root);
    std::thread::sleep(Duration::from_millis(1500));
    assert!(client_a.try_wait().unwrap().is_none(), "first client must still be running");

    let mut client_b = spawn_session(&project_root);
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        client_b.try_wait().unwrap().is_none(),
        "second client must also attach and run, not conflict with the first"
    );
    assert!(broker.try_wait().unwrap().is_none());
    assert!(client_a.try_wait().unwrap().is_none());

    for child in [&mut client_b, &mut client_a, &mut broker] {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = std::fs::remove_dir_all(&base);
}
