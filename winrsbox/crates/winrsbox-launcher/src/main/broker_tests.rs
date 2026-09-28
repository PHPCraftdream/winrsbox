use super::*;

// ─── is_database_already_open: real redb, no mocking ──────────────────

#[test]
fn is_database_already_open_matches_a_real_second_open_in_the_same_process() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("policy.redb");

    let _owner = Policy::open_or_create(
        &db_path,
        dir.path().join("workdir"),
        dir.path().join("mock-dirs"),
        dir.path().to_path_buf(),
    )
    .expect("first open must succeed");

    let second = Policy::open_or_create(
        &db_path,
        dir.path().join("workdir"),
        dir.path().join("mock-dirs"),
        dir.path().to_path_buf(),
    );
    // `Policy` doesn't implement `Debug`, so `expect_err` isn't available.
    let err = match second {
        Ok(_) => panic!("second open of the same file must fail"),
        Err(e) => e,
    };
    assert!(
        is_database_already_open(&err),
        "expected DatabaseAlreadyOpen, got: {err}"
    );
}

#[test]
fn is_database_already_open_rejects_other_errors() {
    // A path whose parent directory doesn't exist fails with an io
    // error, not DatabaseAlreadyOpen — must not be misclassified.
    let bogus = Path::new("Z:\\definitely\\does\\not\\exist\\policy.redb");
    let err = match Policy::open_or_create(
        bogus,
        PathBuf::from("Z:\\nope\\workdir"),
        PathBuf::from("Z:\\nope\\mock-dirs"),
        PathBuf::from("Z:\\nope"),
    ) {
        Ok(_) => panic!("bogus path must fail to open"),
        Err(e) => e,
    };
    assert!(!is_database_already_open(&err), "unexpected match: {err}");
}

// ─── resolve_client_role: pure, dependency-injected ────────────────────

#[test]
fn becomes_broker_on_first_successful_open() {
    let outcome = resolve_client_role(
        5,
        || Some(42u32),
        || None,
        |_, _| false,
        || panic!("must not sleep when the first open succeeds"),
    );
    assert!(matches!(outcome, ClientOutcome::BecameBroker(42)));
}

#[test]
fn becomes_broker_after_recovering_within_the_retry_budget() {
    let mut attempts = 0u32;
    let outcome = resolve_client_role(
        5,
        || {
            attempts += 1;
            if attempts >= 3 { Some(attempts) } else { None }
        },
        || None,
        |_, _| false,
        || {},
    );
    match outcome {
        ClientOutcome::BecameBroker(a) => assert_eq!(a, 3),
        _ => panic!("expected BecameBroker"),
    }
}

#[test]
fn reports_existing_broker_once_broker_json_verifies_alive() {
    let outcome: ClientOutcome<()> = resolve_client_role(
        10,
        || None,
        || Some((777u32, 999u64)),
        |pid, ct| pid == 777 && ct == 999,
        || panic!("must not sleep once a live broker is verified"),
    );
    match outcome {
        ClientOutcome::ExistingBroker { pid } => assert_eq!(pid, 777),
        _ => panic!("expected ExistingBroker"),
    }
}

#[test]
fn ignores_broker_json_when_the_identified_process_is_not_alive() {
    // broker_alive always false (e.g. stale broker.json, create_time
    // mismatch / dead process) — must exhaust retries, not report a
    // broker that couldn't be verified.
    let mut sleeps = 0u32;
    let outcome: ClientOutcome<()> = resolve_client_role(
        4,
        || None,
        || Some((5u32, 5u64)),
        |_, _| false,
        || sleeps += 1,
    );
    assert!(matches!(outcome, ClientOutcome::Unavailable));
    assert_eq!(sleeps, 3, "sleeps between attempts, not after the last one");
}

#[test]
fn unavailable_when_broker_json_is_missing_and_open_never_succeeds() {
    let mut sleeps = 0u32;
    let outcome: ClientOutcome<()> = resolve_client_role(
        3,
        || None,
        || None,
        |_, _| unreachable!("broker_alive must not run without a broker_json result"),
        || sleeps += 1,
    );
    assert!(matches!(outcome, ClientOutcome::Unavailable));
    assert_eq!(sleeps, 2);
}

#[test]
fn broker_json_reappearing_mid_retry_short_circuits_further_sleeps() {
    let mut attempt = 0u32;
    let outcome: ClientOutcome<()> = resolve_client_role(
        10,
        || None,
        move || {
            attempt += 1;
            if attempt >= 2 { Some((11u32, 22u64)) } else { None }
        },
        |pid, ct| pid == 11 && ct == 22,
        || {},
    );
    match outcome {
        ClientOutcome::ExistingBroker { pid } => assert_eq!(pid, 11),
        _ => panic!("expected ExistingBroker"),
    }
}

// ─── client_conflict_message ───────────────────────────────────────────

#[test]
fn conflict_message_names_the_verified_broker_pid() {
    let msg = client_conflict_message(Some(4242));
    assert!(msg.contains("4242"));
    assert!(msg.contains("broker"));
}

#[test]
fn conflict_message_degrades_gracefully_without_a_pid() {
    let msg = client_conflict_message(None);
    assert!(!msg.contains("pid None"));
    assert!(msg.contains("locked"));
}

// ─── setup_broker_folder ───────────────────────────────────────────────

#[test]
fn setup_broker_folder_writes_a_broker_json_matching_the_folder_section() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pipe_name = format!(r"\\.\pipe\winrsbox-broker-role-test-{}", std::process::id());
    let state = setup_broker_folder(dir.path(), &pipe_name, 1234, 0xAAAA_BBBB)
        .expect("setup_broker_folder");

    let doc = session_section::read_broker_json(
        &dir.path().join(session_section::BROKER_JSON_FILE_NAME),
    )
    .expect("read broker.json");
    assert_eq!(doc.broker_pid, 1234);
    assert_eq!(doc.broker_create_time, 0xAAAA_BBBB);
    assert_eq!(doc.pipe_name, pipe_name);
    assert_eq!(doc.folder_section_name, state.folder_section_name);
    assert_eq!(doc.generation, 0);

    let snap = state.folder_section.view().snapshot().expect("snapshot");
    assert_eq!(snap.broker_pid, 1234);
    assert_eq!(snap.broker_create_time, 0xAAAA_BBBB);
    assert_eq!(snap.pipe_name, pipe_name);
}

// ─── MP-3: handle_attach_connection end-to-end ─────────────────────────

mod attach_tests {
    use super::*;
    use jobctl::FolderJob;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows::Win32::System::JobObjects::IsProcessInJob;
    use windows::Win32::System::Memory::{FILE_MAP_READ, FILE_MAP_WRITE, MapViewOfFile};
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows::Win32::System::Threading::CREATE_NO_WINDOW;

    /// A same-process broker/client pair: `own_create_time()` is the SAME
    /// live creation time both sides use, so the test process passes
    /// authentication as its own "joining launcher".
    fn own_create_time() -> u64 {
        crate::pipe_server::query_process_create_time(std::process::id())
            .expect("own process creation time must be queryable")
    }

    /// A bare, unsecured named-pipe server instance for same-process
    /// tests — production uses the hardened `pipe_server::security`
    /// machinery, irrelevant here (both ends are this test process).
    fn test_pipe_server(name: &str) -> HANDLE {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: wide is a NUL-terminated UTF-16 name; None = default
        //         security descriptor, fine for a same-process test pipe.
        unsafe {
            CreateNamedPipeW(
                windows::core::PCWSTR(wide.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                None,
            )
        }
    }

    /// Spawn a connected client (`ipc::SyncClient`) against a fresh named
    /// pipe and return the SERVER-side handle once connected — what
    /// `handle_attach_connection`'s `conn` parameter expects.
    fn connected_pair(tag: &str) -> (HANDLE, ipc::SyncClient) {
        let name = format!(r"\\.\pipe\winrsbox-mp3-attach-{}-{tag}", std::process::id());
        let server = test_pipe_server(&name);
        // HANDLE (a raw pointer newtype) is not Send; cross the thread
        // boundary as the isize repr, matching the pattern used
        // throughout pipe_server/mod.rs's own accept loop.
        let server_raw = server.0 as isize;
        let accept = std::thread::spawn(move || {
            let h = HANDLE(server_raw as *mut _);
            // SAFETY: h is the valid pipe handle created above.
            unsafe { ConnectNamedPipe(h, None).ok() };
            server_raw
        });
        let client = ipc::SyncClient::connect(&name).expect("client connect");
        let server_raw = accept.join().expect("accept thread must not panic");
        (HANDLE(server_raw as *mut _), client)
    }

    fn test_ctx(broker_pid: u32, broker_create_time: u64) -> AttachContext {
        let (section, name) = session_section::FolderSection::create().expect("create folder section");
        section.view().init(broker_pid, broker_create_time, "p").expect("init");
        let dir = tempfile::tempdir().expect("tempdir for test policy");
        let policy = Policy::open_or_create(
            &dir.path().join("policy.redb"),
            dir.path().join("workdir"),
            dir.path().join("mock-dirs"),
            dir.path().to_path_buf(),
        )
        .expect("open test policy");
        // Leak the tempdir so the policy file outlives this function —
        // test-only, freed when the OS reclaims the process's temp dir.
        std::mem::forget(dir);
        AttachContext {
            folder_section: Arc::new(FolderSectionWriter::new(section)),
            folder_section_name: name,
            broker_pid,
            broker_create_time,
            pipe_name: r"\\.\pipe\winrsbox-mp3-broker".into(),
            policy: Arc::new(policy),
            stats: Arc::new(crate::pipe_server::Stats::default()),
        }
    }

    /// Real, short-lived, suspended child process — a stand-in for "some
    /// other process" whose job membership we can probe without ever
    /// touching the test binary's OWN job membership (that would risk
    /// polluting every other test in this process, since job assignment
    /// is process-wide, not per-thread).
    fn spawn_probe_child() -> std::process::Child {
        std::process::Command::new("cmd")
            .args(["/C", "ping -n 2 127.0.0.1 >nul"])
            .creation_flags(CREATE_NO_WINDOW.0 | windows::Win32::System::Threading::CREATE_SUSPENDED.0)
            .spawn()
            .expect("spawn probe child")
    }

    // `handle_attach_connection`'s success path spawns a background
    // exit-watch task via `tokio::spawn`, which panics without an active
    // Tokio runtime. MP-6: on success it also runs the launcher-session
    // loop (LauncherLog/SessionStats) for as long as the connection stays
    // open, so it can no longer be awaited inline before the client thread
    // has even read the response — run it concurrently via
    // `spawn_blocking`, mirroring how the real accept-worker hands it off,
    // and only join it after the client side closes its connection.
    //
    // NOT `#[tokio::test]`: the exit-watch task's `WaitForSingleObject`
    // targets THIS test process's own PID (same-process broker/client
    // pair, see `own_create_time`) and so never signals within the test —
    // `#[tokio::test]`'s generated wrapper drops its Runtime on return,
    // which blocks the calling thread until every spawned blocking task
    // (including that eternally-parked one) finishes, hanging forever. A
    // manually built runtime + `shutdown_background()` detaches instead of
    // waiting — exactly the same class of hang `main()`'s own doc comment
    // describes for the production pipe-accept loop.
    #[test]
    fn attaches_self_and_duplicates_working_handles() {
        let rt = tokio::runtime::Runtime::new().expect("build test runtime");
        rt.block_on(attaches_self_and_duplicates_working_handles_body());
        rt.shutdown_background();
    }
    async fn attaches_self_and_duplicates_working_handles_body() {
        let job = Arc::new(FolderJob::create().expect("create folder job"));
        let pid = std::process::id();
        let ct = own_create_time();
        let ctx = test_ctx(pid, ct);
        let (server, mut client) = connected_pair("ok");

        // `client.send` writes the request AND blocks reading the
        // response — exactly the exchange `handle_attach_connection`
        // (read one request, write one response) expects on the other
        // end. Concurrent, since both sides block until the other acts.
        let sent = std::thread::spawn(move || {
            let resp = client
                .send(&ipc::Req::Attach { launcher_pid: pid, launcher_create_time: ct })
                .expect("send Attach");
            (client, resp)
        });
        let (job2, ctx2) = (Arc::clone(&job), ctx.clone());
        // HANDLE (*mut c_void) is not Send — cross the spawn_blocking
        // boundary as the isize repr, matching the pattern used throughout
        // pipe_server/mod.rs's own accept loop.
        let server_raw = server.0 as isize;
        let attach_task = tokio::task::spawn_blocking(move || {
            handle_attach_connection(HANDLE(server_raw as *mut _), pid, &job2, &ctx2)
        });
        let (client, resp) = sent.join().expect("client thread must not panic");

        let ipc::Resp::Attached {
            folder_job_handle, folder_section_handle, folder_section_name,
            broker_pid, broker_create_time, generation, ..
        } = resp
        else {
            panic!("expected Attached, got {resp:?}");
        };
        assert_eq!(folder_section_name, ctx.folder_section_name);
        assert_eq!(broker_pid, pid);
        assert_eq!(broker_create_time, ct);
        // init() leaves generation 0 (a raw store, not a seqlock cycle);
        // add_launcher's ONE write cycle (begin_write + end_write) bumps
        // it by exactly 2.
        assert_eq!(generation, 2);

        // Prove the DUPLICATED job handle really names the same kernel
        // job object: assign a throwaway child to the ORIGINAL job, then
        // confirm IsProcessInJob sees it via the duplicated handle too —
        // without ever touching this test process's own job membership.
        let job_h = HANDLE(folder_job_handle as *mut _);
        let mut probe = spawn_probe_child();
        job.assign_process(HANDLE(probe.as_raw_handle())).expect("assign probe to original job");
        let mut in_job = windows::core::BOOL(0);
        // SAFETY: probe's handle is valid (just spawned); job_h is the
        //         duplicated handle returned in the Attach response.
        unsafe { IsProcessInJob(HANDLE(probe.as_raw_handle()), Some(job_h), &mut in_job) }
            .expect("IsProcessInJob via the duplicated handle");
        assert!(in_job.as_bool(), "duplicated job handle must see the same membership as the original");
        let _ = probe.kill();
        let _ = probe.wait();

        // The duplicated section handle reads back live broker state.
        // SAFETY: folder_section_handle is the value the Attach response
        //         just duplicated into this (the caller's) process.
        let mapped = unsafe {
            MapViewOfFile(
                HANDLE(folder_section_handle as *mut _),
                FILE_MAP_READ | FILE_MAP_WRITE,
                0,
                0,
                ipc::FOLDER_SECTION_SIZE,
            )
        };
        assert!(!mapped.Value.is_null());
        // SAFETY: mapped.Value points to FOLDER_SECTION_SIZE bytes of
        //         RW-mapped memory, page-aligned per MapViewOfFile.
        let section_view = unsafe { ipc::FolderSectionView::new(mapped.Value.cast()) };
        let snap = section_view.snapshot().expect("snapshot via duplicated section handle");
        assert_eq!(snap.broker_pid, pid);
        assert!(snap.launchers.contains(&(pid, ct)), "launcher must be registered");

        unsafe { windows::Win32::System::Memory::UnmapViewOfFile(mapped).ok() };
        unsafe { CloseHandle(job_h).ok() };
        unsafe { CloseHandle(HANDLE(folder_section_handle as *mut _)).ok() };

        // MP-6: closing the client connection unblocks the session loop
        // inside handle_attach_connection — it only returns once the
        // connection breaks.
        drop(client);
        let attached = attach_task.await.expect("attach task must not panic");
        assert!(attached, "self must be able to Attach");
    }

    // NOT `#[tokio::test]` — see the comment on
    // `attaches_self_and_duplicates_working_handles` above: the first
    // Attach's exit-watch task parks on this test process's own PID and
    // never signals, which would hang `#[tokio::test]`'s implicit Runtime
    // Drop forever.
    #[test]
    fn second_attach_of_the_same_launcher_is_rejected_as_a_duplicate() {
        let rt = tokio::runtime::Runtime::new().expect("build test runtime");
        rt.block_on(second_attach_of_the_same_launcher_is_rejected_as_a_duplicate_body());
        rt.shutdown_background();
    }
    async fn second_attach_of_the_same_launcher_is_rejected_as_a_duplicate_body() {
        let job = Arc::new(FolderJob::create().expect("create folder job"));
        let pid = std::process::id();
        let ct = own_create_time();
        let ctx = test_ctx(pid, ct);

        let (server1, mut client1) = connected_pair("dup1");
        let sent1 = std::thread::spawn(move || {
            let resp = client1
                .send(&ipc::Req::Attach { launcher_pid: pid, launcher_create_time: ct })
                .expect("send Attach");
            (client1, resp)
        });
        // MP-6: the first Attach now stays connected for the launcher's
        // session — run it concurrently, same as the test above.
        let (job2, ctx2) = (Arc::clone(&job), ctx.clone());
        // HANDLE (*mut c_void) is not Send — see the same conversion above.
        let server1_raw = server1.0 as isize;
        let attach1_task = tokio::task::spawn_blocking(move || {
            handle_attach_connection(HANDLE(server1_raw as *mut _), pid, &job2, &ctx2)
        });
        let (client1, resp1) = sent1.join().expect("client thread must not panic");
        let ipc::Resp::Attached { folder_job_handle, folder_section_handle, .. } = resp1 else {
            panic!("expected Attached");
        };

        let (server2, mut client2) = connected_pair("dup2");
        let sent2 = std::thread::spawn(move || {
            client2.send(&ipc::Req::Attach { launcher_pid: pid, launcher_create_time: ct })
        });
        assert!(
            !handle_attach_connection(server2, pid, &job, &ctx),
            "a second Attach from the same (pid, create_time) must be rejected"
        );
        disconnect_and_close(server2);
        let _ = sent2.join();

        drop(client1);
        assert!(
            attach1_task.await.expect("attach task must not panic"),
            "first Attach must succeed"
        );
        unsafe { CloseHandle(HANDLE(folder_job_handle as *mut _)).ok() };
        unsafe { CloseHandle(HANDLE(folder_section_handle as *mut _)).ok() };
    }

    #[test]
    fn a_non_attach_request_is_rejected() {
        let job = FolderJob::create().expect("create folder job");
        let pid = std::process::id();
        let ct = own_create_time();
        let ctx = test_ctx(pid, ct);
        let (server, mut client) = connected_pair("wrong-req");

        let sent = std::thread::spawn(move || {
            client.send(&ipc::Req::Hello { pid, exe_path: "x".into() })
        });
        let attached = handle_attach_connection(server, pid, &job, &ctx);
        assert!(!attached, "a non-Attach request must not attach");
        // `handle_attach_connection` never writes a response on this
        // path (production's `PipeConnGuard` would tear the connection
        // down here, unblocking the client's pending read immediately
        // instead of waiting out SEND_TIMEOUT); replicate that so the
        // spawned client thread returns promptly.
        disconnect_and_close(server);
        let _ = sent.join();
    }

    #[test]
    fn wrong_launcher_pid_in_the_request_is_rejected() {
        let job = FolderJob::create().expect("create folder job");
        let pid = std::process::id();
        let ct = own_create_time();
        let ctx = test_ctx(pid, ct);
        let (server, mut client) = connected_pair("bad-pid");

        let sent = std::thread::spawn(move || {
            client.send(&ipc::Req::Attach { launcher_pid: pid.wrapping_add(1), launcher_create_time: ct })
        });
        let attached = handle_attach_connection(server, pid, &job, &ctx);
        assert!(!attached, "a claimed launcher_pid != kernel client pid must be rejected");
        disconnect_and_close(server);
        let _ = sent.join();
    }

    /// Mirror of `PipeConnGuard::drop` (`pipe_server/conn.rs`) for tests
    /// that call `handle_attach_connection` directly, without the real
    /// accept loop's guard — see the two rejection tests above.
    fn disconnect_and_close(h: HANDLE) {
        // SAFETY: h is the valid server-side pipe handle for this test's
        //         connection, not closed anywhere else on this path.
        unsafe {
            windows::Win32::System::Pipes::DisconnectNamedPipe(h).ok();
            CloseHandle(h).ok();
        }
    }

}
