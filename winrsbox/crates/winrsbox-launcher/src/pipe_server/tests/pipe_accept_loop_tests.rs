    use super::*;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};

    /// MP-10 §B2 unit companion: `pipe_accept_loop`'s claim of the pipe
    /// namespace (`create_pipe_instance(..., is_first = true)`,
    /// `FILE_FLAG_FIRST_PIPE_INSTANCE`) MUST fail the whole loop — not just
    /// log a warning and keep running with fewer workers — when the name is
    /// already occupied. This is the fail-closed guarantee the random pipe
    /// name (`contain::session_section::random_pipe_name`) depends on: a
    /// guest that raced to pre-create the (now unguessable) name would
    /// otherwise let a real broker silently start in a half-alive state
    /// instead of refusing to run at all.
    #[tokio::test]
    async fn pipe_accept_loop_fails_closed_when_first_instance_name_is_already_taken() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .subsec_nanos();
        let name = format!(r"\\.\pipe\winrsbox-mp10-taken-{}-{}", std::process::id(), nanos);
        let sec = security::build_pipe_security().expect("build_pipe_security");
        let name_wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();

        // Simulates a guest that pre-created the pipe name before the real
        // broker got there — exactly the race the random name is meant to
        // make unwinnable in practice, exercised here directly on a known
        // name to prove the *failure handling*, independent of whether the
        // name itself is guessable.
        let squatter = create_pipe_instance(&name_wide, &sec, true).expect("squat the pipe name");

        let dir = tempfile::tempdir().unwrap();
        let policy = Arc::new(
            policy::Policy::open_or_create(
                &dir.path().join("policy.redb"),
                dir.path().join("sb"),
                dir.path().join("md"),
                dir.path().join("proj"),
            )
            .unwrap(),
        );
        let reg_policy =
            Arc::new(policy::RegistryPolicy::open(policy.db(), dir.path().join("workreg")).unwrap());
        let stats = Arc::new(Stats::default());
        let hot_stats = HotStats::new();
        let flusher = Arc::new(winrsbox::observe::hot_stats::ThrottledFlusher::new(
            Arc::clone(&hot_stats),
            dir.path().join("hot-stats.json"),
        ));

        let result = pipe_accept_loop(
            &name,
            policy,
            reg_policy,
            stats,
            Arc::new(crossbeam_queue::SegQueue::new()),
            dir.path().join("violations.log"),
            hot_stats,
            flusher,
            Arc::new(AtomicU32::new(0)),
            None,
            None,
        )
        .await;

        assert!(
            result.is_err(),
            "pipe_accept_loop must fail closed (return Err), never silently start with fewer workers, \
             when the FIRST_PIPE_INSTANCE name is already occupied"
        );
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("collision") || msg.contains("FIRST_PIPE_INSTANCE"),
            "error must name the actual cause (pipe name collision), not a generic failure: {msg}"
        );

        // SAFETY: squatter is the valid handle returned by create_pipe_instance above.
        unsafe { CloseHandle(HANDLE(squatter as *mut _)).ok() };
    }
