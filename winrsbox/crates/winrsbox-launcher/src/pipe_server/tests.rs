    use super::*;

    // ─── audit Critical #2: RecordOverlay rejection is counted + surfaced ───

    #[test]
    fn record_overlay_dispatch_rejects_escape_and_accepts_mirror() {
        let dir = tempfile::tempdir().unwrap();
        let p = policy::Policy::open_or_create(
            &dir.path().join("policy.redb"),
            dir.path().join("sb"),
            dir.path().join("md"),
            dir.path().join("proj"),
        )
        .unwrap();
        let stats = Stats::default();
        let hot = HotStats::default();
        let orig = r"d:\proj\f.txt";

        // Escape attempt: a real user-profile persistence location.
        let resp = handle_record_overlay(
            &p,
            &stats,
            &hot,
            4242,
            orig,
            r"c:\users\victim\appdata\roaming\microsoft\windows\start menu\programs\startup\pwn.bat",
        );
        assert!(matches!(resp, Resp::Err(_)), "escape attempt must be rejected, got {resp:?}");
        assert_eq!(
            stats.violations.load(Ordering::Relaxed),
            1,
            "rejection must be counted as a violation"
        );

        // Legitimate record: mirror(orig) → Ok, no violation counted.
        let mirror = policy::path::mirror_into_overlay_layout(orig, p.overlay_layout());
        let resp = handle_record_overlay(&p, &stats, &hot, 4242, orig, &mirror.to_string_lossy());
        assert!(matches!(resp, Resp::Ok), "mirror(orig) must be accepted, got {resp:?}");
        assert_eq!(stats.violations.load(Ordering::Relaxed), 1);

        // The accepted record drives later reads into the overlay.
        let d = p.decide(orig, false);
        assert_eq!(d.mode, policy::Mode::Cow);
        assert_eq!(d.overlay, Some(mirror));
    }

    // ─── original 6 patterns (kept to lock in baseline coverage) ─────────────

    #[test]
    fn persistence_appinit_dlls_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows"
        ));
    }

    #[test]
    fn persistence_appinit_wow6432_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
        ));
    }

    #[test]
    fn persistence_ifeo_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe"
        ));
    }

    #[test]
    fn persistence_silent_process_exit_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\evil.exe"
        ));
    }

    #[test]
    fn persistence_appcert_dlls_denied() {
        assert!(is_persistence_denied(
            r"HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls"
        ));
    }

    #[test]
    fn persistence_services_denied() {
        assert!(is_persistence_denied(
            r"HKLM\System\CurrentControlSet\Services\EvilSvc"
        ));
    }

    // ─── H-S4 new patterns: one test per entry ──────────────────────────────

    #[test]
    fn persistence_run_key_denied() {
        assert!(is_persistence_denied(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MyEvil"
        ));
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
        ));
    }

    #[test]
    fn persistence_runonce_key_denied() {
        assert!(is_persistence_denied(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\Stage2"
        ));
    }

    #[test]
    fn persistence_runonceex_key_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001"
        ));
    }

    #[test]
    fn persistence_startup_approved_run_denied() {
        assert!(is_persistence_denied(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
        ));
    }

    #[test]
    fn persistence_winlogon_userinit_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"
        ));
    }

    #[test]
    fn persistence_winlogon_shell_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"
        ));
    }

    #[test]
    fn persistence_winlogon_notify_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\evilpkg"
        ));
    }

    #[test]
    fn persistence_drivers32_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32"
        ));
    }

    #[test]
    fn persistence_app_paths_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\notepad.exe"
        ));
    }

    #[test]
    fn persistence_classes_clsid_denied() {
        assert!(is_persistence_denied(
            r"HKCU\Software\Classes\CLSID\{0000000A-0000-0000-C000-000000000046}\InprocServer32"
        ));
        assert!(is_persistence_denied(
            r"HKLM\Software\Classes\CLSID\{deadbeef-1234-5678-9abc-def012345678}\LocalServer32"
        ));
    }

    #[test]
    fn persistence_shell_open_command_denied() {
        // File-association hijack — substring catches every extension and hive.
        assert!(is_persistence_denied(
            r"HKCU\Software\Classes\txtfile\shell\open\command"
        ));
        assert!(is_persistence_denied(
            r"HKLM\Software\Classes\ms-settings\shell\open\command"
        ));
    }

    #[test]
    fn persistence_context_menu_handlers_denied() {
        assert!(is_persistence_denied(
            r"HKCU\Software\Classes\*\shellex\ContextMenuHandlers\Evil"
        ));
    }

    #[test]
    fn persistence_cmd_autorun_denied() {
        assert!(is_persistence_denied(
            r"HKCU\Software\Microsoft\Command Processor\AutoRun"
        ));
    }

    #[test]
    fn persistence_lsa_notification_packages_denied() {
        assert!(is_persistence_denied(
            r"HKLM\System\CurrentControlSet\Control\Lsa\Notification Packages"
        ));
    }

    #[test]
    fn persistence_lsa_authentication_packages_denied() {
        assert!(is_persistence_denied(
            r"HKLM\System\CurrentControlSet\Control\Lsa\Authentication Packages"
        ));
    }

    #[test]
    fn persistence_lsa_security_packages_denied() {
        assert!(is_persistence_denied(
            r"HKLM\System\CurrentControlSet\Control\Lsa\Security Packages"
        ));
    }

    #[test]
    fn persistence_office_trusted_locations_denied() {
        // Any Office version / app combo matches via `\security\trusted locations`.
        assert!(is_persistence_denied(
            r"HKCU\Software\Microsoft\Office\16.0\Word\Security\Trusted Locations\Location99"
        ));
        assert!(is_persistence_denied(
            r"HKCU\Software\Microsoft\Office\15.0\Excel\Security\Trusted Locations"
        ));
    }

    // ─── negative cases — make sure we did not over-block ───────────────────

    #[test]
    fn persistence_benign_software_key_allowed() {
        // Plain HKCU\Software\MyApp\Settings is *not* in the persistence list.
        // (The handler routes it to "silent_ok" — that branch is outside this
        // pure function; is_persistence_denied must answer false here.)
        assert!(!is_persistence_denied(r"HKCU\Software\MyApp\Settings"));
    }

    #[test]
    fn persistence_empty_path_allowed() {
        assert!(!is_persistence_denied(""));
    }

    #[test]
    fn non_software_write_is_not_passthrough() {
        // H3: writes outside \software\ must NOT fall to passthrough.
        // The RegDecide handler routes them to silent_ok (absorbed).
        // This test pins the invariant at the is_persistence_denied level:
        // non-persistence keys that are also outside \software\ must still
        // be handled (the handler's else-if-write branch catches them).
        assert!(!is_persistence_denied(r"HKCU\Console\FaceName"));
        assert!(!is_persistence_denied(r"HKCU\Keyboard Layout\Preload"));
    }

    // ─── Audit C1/C4: segment-anchored matching, boundaries pinned ──────────

    #[test]
    fn persistence_run_key_root_and_value_denied() {
        // C4: the Run key root itself (a value write AT Run) must be denied,
        // not just subkeys under it.
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
        ));
        assert!(is_persistence_denied(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Evil"
        ));
    }

    #[test]
    fn persistence_services_root_and_subkey_denied() {
        // C4: hive root (no trailing component) AND subkey both denied.
        assert!(is_persistence_denied(r"HKLM\System\CurrentControlSet\Services"));
        assert!(is_persistence_denied(
            r"HKLM\System\CurrentControlSet\Services\EvilSvc"
        ));
    }

    #[test]
    fn persistence_classes_clsid_root_and_subkey_denied() {
        // De-trailing-slashed entry still matches both forms.
        assert!(is_persistence_denied(r"HKCU\Software\Classes\CLSID"));
        assert!(is_persistence_denied(
            r"HKCU\Software\Classes\CLSID\{0000000A-0000-0000-C000-000000000046}\InprocServer32"
        ));
    }

    #[test]
    fn persistence_does_not_overmatch_midsegment() {
        // C1: the critical negatives. A fragment must match only at segment
        // boundaries — never mid-segment. These would all FALSE-POSITIVE under
        // the old naive `.contains()` and must now be allowed.
        assert!(!is_persistence_denied(r"HKCU\Software\MyVendor\Runtime\Settings")); // "run" inside "runtime"
        assert!(!is_persistence_denied(r"HKCU\Software\MyVendor\ServicesManager\Cfg")); // "services" inside "servicesmanager"
        assert!(!is_persistence_denied(r"HKCU\Software\Brundlefly\Data")); // "run" mid-segment
        assert!(!is_persistence_denied(r"HKCU\Software\Classes\CLSIDExtra\X")); // "clsid" inside "clsidextra"
    }

    #[test]
    fn persistence_segment_aligned_anywhere_is_denied() {
        // A segment-aligned persistence path is denied wherever it appears,
        // even nested under an attacker-crafted parent — the sandbox must never
        // write it anywhere. This is intended (documented in segment_contains).
        assert!(is_persistence_denied(
            r"HKCU\Software\X\System\CurrentControlSet\Services\Fake"
        ));
        // ...but a NON-segment-aligned lookalike must NOT match.
        assert!(!is_persistence_denied(
            r"HKCU\Software\XSystem\CurrentControlSet\ServicesY\Fake"
        ));
    }

    #[test]
    fn segment_contains_boundary_semantics() {
        // Direct unit test of the matcher's anchoring.
        assert!(segment_contains(r"a\run", r"\run")); // end-of-string
        assert!(segment_contains(r"a\run\b", r"\run")); // followed by '\'
        assert!(!segment_contains(r"a\runtime", r"\run")); // followed by other char
        assert!(!segment_contains(r"arun", r"\run")); // no left boundary
        assert!(segment_contains(r"x\run\run", r"\run")); // second occurrence anchored
    }

    // ─── ENV_VALUE_NAME_ALLOWLIST (PERSISTENCE-DENY exception) ──────────────

    #[test]
    fn env_allowlist_exact_match_path() {
        assert!(is_env_value_allowed(Some("Path")));
        assert!(is_env_value_allowed(Some("PATH")));
        assert!(is_env_value_allowed(Some("PATHEXT")));
    }

    #[test]
    fn env_allowlist_vendor_prefix_hermes() {
        assert!(is_env_value_allowed(Some("HERMES_HOME")));
        assert!(is_env_value_allowed(Some("HERMES_GIT_BASH_PATH")));
        assert!(is_env_value_allowed(Some("hermes_anything")));
    }

    #[test]
    fn env_allowlist_python_prefix() {
        assert!(is_env_value_allowed(Some("PYTHONPATH")));
        assert!(is_env_value_allowed(Some("PYTHONHOME")));
    }

    #[test]
    fn env_allowlist_none_value_name_denied() {
        // No value name → can't prove benign → fail-closed (not allowed).
        assert!(!is_env_value_allowed(None));
    }

    #[test]
    fn env_allowlist_dangerous_name_denied() {
        // The actual logon-script persistence vector must NOT match the
        // allowlist — it stays hard-DENIED even under HKCU\Environment.
        assert!(!is_env_value_allowed(Some("UserInitMprLogonScript")));
        // Unknown / arbitrary attacker value-name → denied.
        assert!(!is_env_value_allowed(Some("evil_persistence")));
        assert!(!is_env_value_allowed(Some("TEMP")));
    }

    #[test]
    fn persistence_count_pinned() {
        // Pin the list length so a silently-dropped entry fails a test.
        assert_eq!(
            PERSISTENCE_DENY_SUFFIXES.len(),
            25,
            "PERSISTENCE_DENY_SUFFIXES length drifted — update tests + threat model"
        );
    }

    // ─── Audit M-A3: handler concurrency cap ────────────────────────────────

    #[test]
    fn handler_cap_is_reasonable() {
        // Cap should be high enough to handle a normal sandbox burst (one
        // process spawning a few children + their Hello / Decide messages)
        // but low enough to bound resource use and keep room in tokio's
        // 512-thread blocking pool for the accept-side ConnectNamedPipe
        // task and any other launcher subsystems.
        assert!(MAX_CONCURRENT_HANDLERS >= 32);
        assert!(MAX_CONCURRENT_HANDLERS <= 256);
    }

    /// Pin the accept pool size. Must clear the empirically-observed
    /// MSYS2 first-run burst (~8 concurrent helper spawns) with headroom,
    /// and stay well under the kernel-imposed max-instances cap (255)
    /// that `create_pipe_instance` passes to `CreateNamedPipeW`.
    #[test]
    fn accept_pool_size_in_sane_range() {
        assert!(
            PIPE_ACCEPT_POOL_SIZE >= 16,
            "PIPE_ACCEPT_POOL_SIZE={PIPE_ACCEPT_POOL_SIZE} cannot absorb MSYS2's 27-process burst",
        );
        assert!(
            PIPE_ACCEPT_POOL_SIZE <= 64,
            "PIPE_ACCEPT_POOL_SIZE={PIPE_ACCEPT_POOL_SIZE} too high — \
             each instance costs 128 KiB pipe buffers and a tokio task",
        );
    }

    /// `create_pipe_instance` is a thin FFI wrapper; its main contract is
    /// returning a usable handle as `isize` (Send across `.await`) and
    /// honouring `is_first` for the FIRST_PIPE_INSTANCE flag. We can't
    /// CreateNamedPipeW in a unit test without a unique pipe name, so this
    /// test verifies the happy path against a one-off name and immediately
    /// closes the returned handle.
    #[test]
    fn create_pipe_instance_returns_valid_handle() {
        use windows::Win32::Foundation::HANDLE;
        let name = format!(
            r"\\.\pipe\winrsbox-unit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        );
        let wide: Vec<u16> = OsStr::new(&name)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let sec = build_pipe_security().expect("pipe SD build");
        let ph = create_pipe_instance(&wide, &sec, true)
            .expect("first instance must create on a fresh pipe name");
        assert_ne!(ph, 0, "handle must be non-null");
        unsafe { CloseHandle(HANDLE(ph as *mut _)).ok() };
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handler_semaphore_caps_in_flight_acquisitions() {
        // Mirror the runtime invariant: only MAX_CONCURRENT_HANDLERS permits
        // can be held at once. The 129th acquire must not complete while
        // 128 are still alive.
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_HANDLERS));
        let mut permits = Vec::with_capacity(MAX_CONCURRENT_HANDLERS);
        for _ in 0..MAX_CONCURRENT_HANDLERS {
            permits.push(sem.clone().acquire_owned().await.unwrap());
        }
        // A 129th acquire must time out — semaphore is full.
        let timeout = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            sem.clone().acquire_owned(),
        )
        .await;
        assert!(
            timeout.is_err(),
            "extra acquire should block while all {MAX_CONCURRENT_HANDLERS} permits are held",
        );
        // Releasing one permit must let the next acquire succeed promptly.
        drop(permits.pop());
        let after = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            sem.clone().acquire_owned(),
        )
        .await
        .expect("acquire should succeed once a permit is freed");
        assert!(after.is_ok());
    }

    // ─── C3: pipe security descriptor & PID validation ──────────────────────

    /// `build_pipe_security` should succeed on any normal user token.
    #[test]
    fn c3_pipe_security_builds_for_current_user() {
        let sec = build_pipe_security().expect("SD construction failed");
        // The SECURITY_ATTRIBUTES should reference a non-null SD pointer.
        assert!(!sec.sa.lpSecurityDescriptor.is_null());
        // SDDL string lookup pointer equality holds — sd and sa point to same buf.
        assert_eq!(sec.sd.0, sec.sa.lpSecurityDescriptor);
    }

    #[test]
    fn persistence_per_user_classes_clsid_denied() {
        // H2: per-user COM hijack via HKU\<SID>_Classes\CLSID
        assert!(is_persistence_denied(
            r"hku\s-1-5-21-123456789-123456789-123456789-1001_classes\clsid\{deadbeef}\InprocServer32"
        ));
    }

    #[test]
    fn persistence_hkcu_environment_denied() {
        // M6: HKCU\Environment for logon persistence
        assert!(is_persistence_denied(r"hkcu\environment"));
        assert!(is_persistence_denied(
            r"hkcu\environment\UserInitMprLogonScript"
        ));
    }

    /// `is_owned_client_pid` accepts the root PID via the root fast-path only
    /// when the live creation-time probe matches the pinned fingerprint
    /// (chicken-and-egg between Hello and validation). An unknown/zero
    /// fingerprint fail-closes, so a recycled root PID is rejected.
    #[test]
    fn c3_owned_pid_matches_root_target() {
        let root = 12345u32;
        // Verified identity: live probe returns the pinned fingerprint → accept.
        assert!(is_owned_client_pid_impl(
            root,
            root,
            0x01D9_0000_0000_0001,
            &|pid| if pid == 12345 { Some(0x01D9_0000_0000_0001) } else { None },
            &|_| None,
        ));
        // Unknown pinned fingerprint (0) → fail-closed even for the root PID.
        assert!(!is_owned_client_pid_impl(
            root,
            root,
            0,
            &|pid| if pid == 12345 { Some(0x01D9_0000_0000_0001) } else { None },
            &|_| None,
        ));
        // Mismatched creation time (recycled root PID) → rejected.
        assert!(!is_owned_client_pid_impl(
            root,
            root,
            0x01D9_0000_0000_0001,
            &|pid| if pid == 12345 { Some(42) } else { None },
            &|_| None,
        ));
    }

    /// `is_owned_client_pid` rejects PID 0 and any unknown PID when no map entry.
    #[test]
    fn c3_owned_pid_rejects_zero_and_unknown() {
        assert!(!is_owned_client_pid(0, 12345));
        // 99999 is neither root nor in the map.
        assert!(!is_owned_client_pid(99999, 12345));
    }

    // ─── PID-reuse hardening: map & parent-walk paths (root path covered by ──
    // ─── the two c3 tests above; every test below passes root_target_pid=0) ──

    /// A recycled PID must not inherit a dead process's trust: a stored
    /// creation-time fingerprint that no longer matches the live probe is a
    /// PID-reuse collision — reject AND prune the stale entry so the impostor
    /// can never pass a later re-check against the corpse's identity.
    #[test]
    fn reused_pid_different_create_time_rejected_and_pruned() {
        let pid = 0x5A01_0001u32;
        let t1 = 0x01D9_0000_0000_0010u64;
        crate::sandbox::proc_table::global_proc_info().pin().insert(
            pid,
            crate::sandbox::proc_table::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("c:\\victim.exe"),
                create_time: t1,
            },
        );
        // Live kernel probe would report a different creation time → the PID
        // was recycled for a foreign process.
        assert!(!is_owned_client_pid_impl(
            pid,
            0,
            0,
            &|p: u32| if p == pid { Some(t1 + 7) } else { None },
            &|_| None,
        ));
        assert!(
            crate::sandbox::proc_table::global_proc_info().pin().get(&pid).is_none(),
            "stale entry must be pruned on fingerprint mismatch"
        );
    }

    /// A tracked PID the kernel can no longer probe is gone (or unopenable) —
    /// reject AND prune, so the entry cannot vouch for whatever reuses the PID.
    #[test]
    fn dead_pid_rejected_and_pruned() {
        let pid = 0x5A02_0001u32;
        let t2 = 0x01D9_0000_0000_0020u64;
        crate::sandbox::proc_table::global_proc_info().pin().insert(
            pid,
            crate::sandbox::proc_table::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("c:\\victim.exe"),
                create_time: t2,
            },
        );
        assert!(!is_owned_client_pid_impl(
            pid,
            0,
            0,
            &|_| None, // kernel probe finds nothing — the process is gone
            &|_| None,
        ));
        assert!(
            crate::sandbox::proc_table::global_proc_info().pin().get(&pid).is_none(),
            "dead entry must be pruned"
        );
    }

    /// The happy path: a tracked entry whose live creation time matches its
    /// stored fingerprint exactly is the SAME live process — accept, and
    /// crucially do NOT prune (the entry must survive for future connections).
    #[test]
    fn genuine_owned_child_still_accepted() {
        let pid = 0x5A03_0001u32;
        let t3 = 0x01D9_0000_0000_0030u64;
        crate::sandbox::proc_table::global_proc_info().pin().insert(
            pid,
            crate::sandbox::proc_table::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("c:\\victim.exe"),
                create_time: t3,
            },
        );
        assert!(is_owned_client_pid_impl(
            pid,
            0,
            0,
            &|p: u32| if p == pid { Some(t3) } else { None },
            &|_| None,
        ));
        assert!(
            crate::sandbox::proc_table::global_proc_info().pin().get(&pid).is_some(),
            "a verified live entry must NOT be pruned"
        );
        crate::sandbox::proc_table::global_proc_info().pin().remove(&pid);
        assert!(crate::sandbox::proc_table::global_proc_info().pin().get(&pid).is_none());
    }

    /// `create_time == 0` is the "unknown at insert" sentinel. Fail closed
    /// regardless of what the live probe reports — an unverified entry must
    /// never grant trust.
    #[test]
    fn zero_fingerprint_entry_fail_closed() {
        let pid = 0x5A04_0001u32;
        crate::sandbox::proc_table::global_proc_info().pin().insert(
            pid,
            crate::sandbox::proc_table::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("c:\\victim.exe"),
                create_time: 0,
            },
        );
        assert!(!is_owned_client_pid_impl(
            pid,
            0,
            0,
            &|_| Some(0x1234),
            &|_| None,
        ));
        crate::sandbox::proc_table::global_proc_info().pin().remove(&pid);
    }

    /// A PID with no map entry is not ours — no probe result can change that.
    #[test]
    fn untracked_pid_rejected() {
        let pid = 0x5A05_0001u32;
        assert!(!is_owned_client_pid_impl(
            pid,
            0,
            0,
            &|_| Some(0x01D9_0000_0000_0099),
            &|_| None,
        ));
    }

    /// Race-resilience path: a child connecting before its SpawnedChild was
    /// processed has no map entry of its own, but its kernel-vouched parent
    /// is tracked AND creation-time verified — accept via the parent walk.
    #[test]
    fn parent_walk_accepts_verified_ancestor() {
        let child = 0x5A06_0001u32;
        let parent = 0x5A06_0002u32;
        let t6 = 0x01D9_0000_0000_0060u64;
        crate::sandbox::proc_table::global_proc_info().pin().insert(
            parent,
            crate::sandbox::proc_table::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("c:\\victim.exe"),
                create_time: t6,
            },
        );
        assert!(is_owned_client_pid_impl(
            child,
            0,
            0,
            &|p: u32| if p == parent { Some(t6) } else { None },
            &|p: u32| if p == child { Some(parent) } else { None },
        ));
        crate::sandbox::proc_table::global_proc_info().pin().remove(&parent);
    }

    /// A REUSED parent PID must not vouch for the client: the stored
    /// fingerprint no longer matches the live parent probe → reject, and the
    /// stale parent entry is pruned so the impostor cannot vouch next time.
    #[test]
    fn parent_walk_rejects_reused_parent_pid() {
        let child = 0x5A07_0001u32;
        let parent = 0x5A07_0002u32;
        let t7a = 0x01D9_0000_0000_0070u64;
        let t7b = 0x01D9_0000_0000_0071u64;
        crate::sandbox::proc_table::global_proc_info().pin().insert(
            parent,
            crate::sandbox::proc_table::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("c:\\victim.exe"),
                create_time: t7a,
            },
        );
        assert!(!is_owned_client_pid_impl(
            child,
            0,
            0,
            &|p: u32| if p == parent { Some(t7b) } else { None },
            &|p: u32| if p == child { Some(parent) } else { None },
        ));
        assert!(
            crate::sandbox::proc_table::global_proc_info().pin().get(&parent).is_none(),
            "reused parent's stale entry must be pruned"
        );
    }

    /// A parent the kernel can no longer probe is dead — it cannot vouch for
    /// the client. Reject AND prune its stale entry.
    #[test]
    fn parent_walk_rejects_dead_parent() {
        let child = 0x5A08_0001u32;
        let parent = 0x5A08_0002u32;
        let t8 = 0x01D9_0000_0000_0080u64;
        crate::sandbox::proc_table::global_proc_info().pin().insert(
            parent,
            crate::sandbox::proc_table::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("c:\\victim.exe"),
                create_time: t8,
            },
        );
        assert!(!is_owned_client_pid_impl(
            child,
            0,
            0,
            &|_| None, // parent probe finds nothing — the parent is gone
            &|p: u32| if p == child { Some(parent) } else { None },
        ));
        assert!(
            crate::sandbox::proc_table::global_proc_info().pin().get(&parent).is_none(),
            "dead parent's stale entry must be pruned"
        );
    }

    /// Round-trip against the REAL kernel query: our own live process verifies
    /// under its true fingerprint, and fails closed under a fingerprint that
    /// cannot match (exactly the PID-reuse condition) — with the stale entry
    /// pruned by the gate itself.
    #[test]
    fn live_kernel_roundtrip_self_pid() {
        let self_pid = std::process::id();
        // Guard against a stale entry for this PID left by any other test.
        crate::sandbox::proc_table::global_proc_info().pin().remove(&self_pid);
        let real_ct = query_process_create_time(self_pid)
            .expect("own live process must be queryable");
        assert_ne!(real_ct, 0);

        // True fingerprint → accepted, and the entry survives.
        crate::sandbox::proc_table::global_proc_info().pin().insert(
            self_pid,
            crate::sandbox::proc_table::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("self.exe"),
                create_time: real_ct,
            },
        );
        assert!(is_owned_client_pid_impl(
            self_pid,
            0,
            0,
            &query_process_create_time,
            &|_| None,
        ));
        crate::sandbox::proc_table::global_proc_info().pin().remove(&self_pid);
        assert!(crate::sandbox::proc_table::global_proc_info().pin().get(&self_pid).is_none());

        // A fingerprint that cannot match the live process = PID-reuse
        // condition → rejected AND the stale entry is pruned by the gate.
        crate::sandbox::proc_table::global_proc_info().pin().insert(
            self_pid,
            crate::sandbox::proc_table::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("self.exe"),
                create_time: real_ct.wrapping_add(1),
            },
        );
        assert!(!is_owned_client_pid_impl(
            self_pid,
            0,
            0,
            &query_process_create_time,
            &|_| None,
        ));
        assert!(
            crate::sandbox::proc_table::global_proc_info().pin().get(&self_pid).is_none(),
            "mismatched self entry must be pruned by the gate"
        );
    }

    // --- audit Medium WFP: NetDecide must decide, not always-allow ----------

    fn net_rule(
        id: &str,
        host: &str,
        port: Option<u16>,
        mode: policy::net::NetMode,
    ) -> policy::net::NetRule {
        policy::net::NetRule { id: id.into(), host_pattern: host.into(), port, mode }
    }

    #[test]
    fn net_decide_no_rules_stays_open() {
        // Pins the migration contract: existing sandboxes with an empty
        // net_rules table keep the historical allow behavior; deny-by-default
        // is opt-in via a --host='*' deny rule (as the netrule help documents).
        let (allow, rule) = net_decide(&[], "8.8.8.8", 443);
        assert!(allow);
        assert_eq!(rule, None);
    }

    #[test]
    fn net_decide_star_deny_blocks_all() {
        // The documented deny-by-default configuration.
        let rules = [net_rule("d1", "*", None, policy::net::NetMode::Deny)];
        let (allow, rule) = net_decide(&rules, "8.8.8.8", 443);
        assert!(!allow);
        assert_eq!(rule.as_deref(), Some("d1"));
    }

    #[test]
    fn net_decide_exact_deny_blocks_only_target() {
        let rules = [net_rule("d1", "6.6.6.6", None, policy::net::NetMode::Deny)];
        let (allow, _) = net_decide(&rules, "6.6.6.6", 443);
        assert!(!allow);
        let (allow, _) = net_decide(&rules, "8.8.8.8", 443);
        assert!(allow);
    }

    #[test]
    fn net_decide_port_scoped_rule_matches_port_exactly() {
        let rules = [net_rule("d1", "6.6.6.6", Some(80), policy::net::NetMode::Deny)];
        let (allow, _) = net_decide(&rules, "6.6.6.6", 80);
        assert!(!allow);
        let (allow, _) = net_decide(&rules, "6.6.6.6", 443);
        assert!(allow);
    }

    #[test]
    fn net_decide_deny_wins_over_allow_on_conflict() {
        // Conflicting matching rules must fail closed.
        let rules = [
            net_rule("a1", "10.0.0.0/8", None, policy::net::NetMode::Allow),
            net_rule("d1", "10.0.0.0/8", None, policy::net::NetMode::Deny),
        ];
        let (allow, rule) = net_decide(&rules, "10.1.2.3", 443);
        assert!(!allow, "conflicting rules must fail closed");
        assert_eq!(rule.as_deref(), Some("d1"));
    }

    #[test]
    fn net_decide_cidr_deny_matches_v4_range() {
        let rules = [net_rule("d1", "10.0.0.0/8", None, policy::net::NetMode::Deny)];
        let (allow, _) = net_decide(&rules, "10.255.0.1", 443);
        assert!(!allow);
        let (allow, _) = net_decide(&rules, "11.0.0.1", 443);
        assert!(allow);
    }

    #[test]
    fn net_decide_log_mode_is_decision_neutral() {
        let rules = [net_rule("l1", "9.9.9.9", None, policy::net::NetMode::Log)];
        let (allow, rule) = net_decide(&rules, "9.9.9.9", 53);
        assert!(allow);
        assert_eq!(rule, None);
        let rules = [
            net_rule("l1", "9.9.9.9", None, policy::net::NetMode::Log),
            net_rule("d1", "9.9.9.9", None, policy::net::NetMode::Deny),
        ];
        let (allow, _) = net_decide(&rules, "9.9.9.9", 53);
        assert!(!allow);
    }

    #[test]
    fn net_decide_hostname_pattern_does_not_match_ip_literal() {
        // Documents the DNS gap honestly: the hook reports numeric
        // addresses (DNS is not hooked), so hostname rules only fire when a
        // hostname string is actually reported. IP/CIDR rules are the
        // range control -- this test must keep failing loudly if someone
        // makes hostname patterns fuzzy-match IPs without deciding to.
        let rules = [net_rule("d1", "*.github.com", None, policy::net::NetMode::Deny)];
        let (allow, _) = net_decide(&rules, "140.82.121.4", 443);
        assert!(allow, "hostname deny rule must not silently pretend to cover IP connects");
    }

    #[test]
    fn net_decide_exact_hostname_rule_matches_hostname_string() {
        let rules = [net_rule("a1", "internal.svc", None, policy::net::NetMode::Allow)];
        let (allow, rule) = net_decide(&rules, "internal.svc", 8080);
        assert!(allow);
        assert_eq!(rule.as_deref(), Some("a1"));
    }

    #[test]
    fn handle_net_decide_reads_rules_from_policy_db() {
        // Full plumbing through the real redb DB the pipe handler uses:
        // upsert via policy::db, decide via handle_net_decide.
        let dir = tempfile::tempdir().unwrap();
        let p = policy::Policy::open_or_create(
            &dir.path().join("policy.redb"),
            dir.path().join("sb"),
            dir.path().join("md"),
            dir.path().join("proj"),
        )
        .unwrap();

        // Fresh DB: no rules -> allow (same as legacy behavior).
        let (allow, _) = handle_net_decide(&p, "8.8.8.8", 443);
        assert!(allow);

        policy::db::net_rule_upsert(
            &p.db(),
            &net_rule("d1", "8.8.8.8", Some(443), policy::net::NetMode::Deny),
        )
        .unwrap();
        let (allow, rule) = handle_net_decide(&p, "8.8.8.8", 443);
        assert!(!allow);
        assert_eq!(rule.as_deref(), Some("d1"));
    }
    // --- violations.log forging: guest-controlled strings stay one record ---

    /// Hostile guest-controlled string carrying everything the old hand-built
    /// writer failed to escape: a quote, backslashes, a newline, a CR, a tab
    /// and a complete forged record with a different pid.
    fn hostile_guest_string() -> String {
        "c:\\evil\" \n {\"pid\":666,\"exe\":\"forged\",\"kind\":\"Injection\"}\r\n\t\\ more \\"
            .to_string()
    }

    #[test]
    fn violation_log_records_cannot_be_forged_by_guest_strings() {
        let dir = tempfile::tempdir().unwrap();
        let vlog = dir.path().join("violations.log");
        let hostile = hostile_guest_string();

        let injection = injection_violation_record(
            1,
            &hostile,
            ipc::InjectKind::CreateRemoteThread,
            2,
            0xdead_beef,
            0x7ff0_1234,
            Some(&hostile),
            &[0x1000, 0x2000],
        );
        let memory = memory_violation_record(
            1,
            &hostile,
            ipc::AllocKind::Allocate,
            0x40,
            4096,
            0x5000,
            0x7ff0_5678,
            None,
            &[0x3000],
        );
        let escape = escape_violation_record(
            1,
            &hostile,
            &hostile,
            &hostile,
            0x7ff0_abcd,
            Some(&hostile),
            &[0x4000],
        );
        for record in [&injection, &memory, &escape] {
            append_violation_record(&vlog, record.clone());
        }

        let raw = std::fs::read_to_string(&vlog).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 3, "3 records must stay exactly 3 lines: {raw}");
        // Every line must parse as exactly ONE record identical to the Value
        // handed to the writer: nothing split, nothing forged, no corruption.
        // The forged pid=666 object may only appear as escaped string content.
        for (line, expected) in lines.iter().zip([&injection, &memory, &escape]) {
            let parsed: serde_json::Value = serde_json::from_str(line)
                .expect("each violations.log line must be one complete JSON record");
            assert_eq!(&parsed, expected, "record must round-trip byte-exact");
        }
    }
