
// ---------------------------------------------------------------------------
// P0-04 / P1-01 / P2-01 regression tests (hooks-core security fixes)
// ---------------------------------------------------------------------------
    use super::*;

    // ── P2-01: NULL UNICODE_STRING.Buffer must fail closed ─────────────────
    //
    // Without the null check, `from_raw_parts(null_ptr, 1)` mints a slice
    // whose first read dereferences address 0 — an access violation that
    // kills the process (nothing wraps hook bodies in SEH/catch_unwind).
    // Against the unfixed code these tests crash the test binary, which is
    // exactly the failure mode the fix removes.

    #[test]
    fn extract_raw_nt_path_null_buffer_fails_closed() {
        let ustr = UNICODE_STRING {
            Length: 2,
            MaximumLength: 2,
            Buffer: std::ptr::null_mut(),
        };
        // Keep both locals in THIS frame: attrs.ObjectName points at ustr.
        let attrs = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &ustr as *const UNICODE_STRING as *mut UNICODE_STRING,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let got = unsafe { extract_raw_nt_path(&attrs) };
        assert!(got.is_none(), "NULL Buffer must resolve to None, got {got:?}");
    }

    #[test]
    fn resolve_for_hook_null_buffer_fails_closed() {
        let ustr = UNICODE_STRING {
            Length: 2,
            MaximumLength: 2,
            Buffer: std::ptr::null_mut(),
        };
        let attrs = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &ustr as *const UNICODE_STRING as *mut UNICODE_STRING,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let got = unsafe { resolve_for_hook(&attrs) };
        assert!(got.is_none(), "NULL Buffer must resolve to None, got {got:?}");
    }

    /// An empty ObjectName paired with a RootDirectory names the directory
    /// that handle already points at. Rust's `remove_dir_all` uses exactly
    /// this shape — it reopens the directory relative to its parent with
    /// FILE_DELETE_ON_CLOSE and an empty name — and treating it as
    /// unresolvable pushed every such delete into the fail-closed dead end.
    /// A sandboxed `codex` reported it as
    /// `WARNING: failed to clean up stale arg0 temp dirs: Access is denied`,
    /// with a single `fs_block_unresolved_write` in the trace and no path to
    /// identify it by.
    #[test]
    fn empty_name_with_root_directory_resolves_to_that_directory() {
        use std::os::windows::ffi::OsStrExt;

        let dir = std::env::temp_dir().join("winrsbox-emptyname-probe");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create probe dir");

        // A directory handle needs FILE_FLAG_BACKUP_SEMANTICS.
        let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: `wide` is a NUL-terminated path; all other arguments are
        //         the documented constants for opening a directory handle.
        let handle = unsafe {
            winapi::um::fileapi::CreateFileW(
                wide.as_ptr(),
                winapi::um::winnt::GENERIC_READ,
                winapi::um::winnt::FILE_SHARE_READ
                    | winapi::um::winnt::FILE_SHARE_WRITE
                    | winapi::um::winnt::FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                winapi::um::fileapi::OPEN_EXISTING,
                0x0200_0000, // FILE_FLAG_BACKUP_SEMANTICS — required for a directory handle
                std::ptr::null_mut(),
            )
        };
        assert!(
            handle != winapi::um::handleapi::INVALID_HANDLE_VALUE,
            "could not open a directory handle for the probe",
        );

        // Length 0 / Buffer null — the empty-name form.
        let ustr = UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: std::ptr::null_mut(),
        };
        let mut attrs = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: handle as *mut _,
            ObjectName: &ustr as *const UNICODE_STRING as *mut UNICODE_STRING,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let got = unsafe { resolve_for_hook(&attrs) };
        attrs.Attributes = 0x1000; // OBJ_DONT_REPARSE
        let no_follow = unsafe { resolve_for_hook(&attrs) }.unwrap();
        let kernel_path = String::from_utf16_lossy(&no_follow.1.unwrap());
        assert!(kernel_path.to_ascii_lowercase().starts_with(r"\device\"));
        // SAFETY: handle came from CreateFileW above and is not used after.
        unsafe { winapi::um::handleapi::CloseHandle(handle) };
        let _ = std::fs::remove_dir_all(&dir);

        let (dos, pre_resolved) = got.expect(
            "empty name + RootDirectory must resolve to the handle's own \
             directory, not fall into the unresolvable dead end",
        );
        let want = dir.to_string_lossy().to_ascii_lowercase();
        assert_eq!(dos, want, "resolved path must be the directory itself");
        // Relative opens carry the pre-resolved NT path for the kernel.
        assert!(pre_resolved.is_some(), "relative open must carry pre_resolved");
        assert!(
            !dos.ends_with('\\'),
            "no separator may be appended for an empty name: {dos}",
        );
    }

    /// The empty-name carve-out must not become a blanket bypass: with no
    /// name AND no directory handle there is nothing to resolve, and the
    /// caller's fail-closed dead end must still apply.
    #[test]
    fn empty_name_without_root_directory_stays_unresolvable() {
        let ustr = UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: std::ptr::null_mut(),
        };
        let attrs = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &ustr as *const UNICODE_STRING as *mut UNICODE_STRING,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        assert!(unsafe { resolve_for_hook(&attrs) }.is_none());

        // Same for a NULL ObjectName with no handle.
        let attrs_null = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: std::ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        assert!(unsafe { resolve_for_hook(&attrs_null) }.is_none());
    }

    // ── P1-01: child scan gate + pipeline ──────────────────────────────────

    #[test]
    fn child_scan_enabled_matches_launcher_guard_levels() {
        // launcher/src/main.rs scans the root under Full | Static only.
        // Typed ipc::GuardLevel now — the case-sensitive string compare this
        // test used to pin ("FULL" must NOT scan) was exactly the S02 #2
        // bug shape: the spawn gate was case-insensitive while this executor
        // was case-sensitive. GuardLevel::parse_loose normalizes case once
        // at the section boundary; after that the enum cannot disagree.
        assert!(child_scan_enabled(ipc::GuardLevel::Full));
        assert!(child_scan_enabled(ipc::GuardLevel::Static));
        assert!(!child_scan_enabled(ipc::GuardLevel::Scan));
        assert!(!child_scan_enabled(ipc::GuardLevel::None));
    }

    #[test]
    fn scan_pipeline_runs_on_own_image() {
        // Smoke test of the full remote-read pipeline (QIP → PEB → image
        // base → PE headers → .text → iced-x86 scan) against a handle we
        // know is valid: our own pseudo-handle. Whether HITS may exist in
        // this binary is policy::scan's business (its own tests) and cannot
        // be asserted here — so only the pipeline outcome is.
        // SAFETY: GetCurrentProcess is a constant pseudo-handle call.
        let h = unsafe { winapi::um::processthreadsapi::GetCurrentProcess() };
        match scan_image_for_direct_syscalls(h) {
            Ok(()) => {}
            // S06 widened the scan to every executable section with a
            // multi-entry decode (XA review 2026-09-20) — sensitive enough
            // that std/runtime code linked into the TEST BINARY itself can
            // legitimately trip it. That is a content finding, not a
            // pipeline failure, and is exactly what the comment above says
            // this smoke test does not assert about.
            Err(e) if e.contains("direct syscall instruction") => {}
            Err(e) => panic!("scan pipeline failed on own image: {e}"),
        }
    }

    // ── P0-04 + P1-01 structural pins ──────────────────────────────────────
    //
    // The create→inject race is fixed by code ORDER, and the scan by CALL
    // PRESENCE inside the spawn hook; neither is observable from a unit test
    // without a real spawned child. These textual pin tests follow the
    // established precedent of inject.rs::intentional_leak_pin_tests.

    fn spawn_hook_body() -> String {
        let src = crate::hooks::module_source("hooks");
        let src = src.as_str();
        // rfind, not find: module_source (kept in mod.rs) contains this very
        // literal in its doc comment, and mod.rs sorts before spawn.rs in the
        // concatenation, so the last occurrence is the real definition. The
        // spawn hook is the last section of the last scanned file, so there is
        // no trailing section separator anymore: cut at EOF instead.
        let fn_start = src
            .rfind("fn hook_nt_create_user_process")
            .expect("hook_nt_create_user_process must exist");
        let rest = &src[fn_start..];
        let body_end = rest
            .find("// ---------------------------------------------------------------------------")
            .unwrap_or(rest.len());
        rest[..body_end].to_string()
    }

    #[test]
    fn injection_precedes_child_registration_in_spawn_hook() {
        // Two ordering invariants in hook_nt_create_user_process:
        //   1. mark_spawned (local memory_guard authorization record) BEFORE
        //      inject_via_apc;
        //   2. inject_via_apc BEFORE ipc_register_child / ipc_spawned_child
        //      (the two blocking IPC round-trips).
        let body = spawn_hook_body();
        let mark_off = body
            .find("process_tracker::mark_spawned(")
            .expect("spawn hook must call process_tracker::mark_spawned");
        let inject_off = body
            .find("inject::inject_via_apc(")
            .expect("spawn hook must call inject::inject_via_apc");
        let register_off = body
            .find("ipc_register_child(")
            .expect("spawn hook must call ipc_register_child");
        assert!(
            mark_off < inject_off,
            "regression: mark_spawned must be ordered BEFORE inject_via_apc — \
             memory_guard's cross-process NtAllocate/NtProtect/NtWriteVirtualMemory \
             gates consult process_tracker::is_owned_child for exactly the writes \
             injection performs; without the local record the DLL-path write loses \
             its is_owned_child fast path (opcode-scanned on every spawn) and the \
             VirtualAllocEx lands in the terminate-if-executable foreign branch"
        );
        assert!(
            inject_off < register_off,
            "P0-04 regression: injection must be ordered BEFORE ipc_register_child \
             in hook_nt_create_user_process — the two blocking IPC round-trips \
             must not delay the APC queue while the suspended child is visible \
             system-wide (a same-user thread can ResumeThread it and win the \
             race, leaving the child running with no hooks)"
        );
    }

    #[test]
    fn spawn_hook_acks_child_bootstrap_after_resume_before_registration() {
        // S02 #3 (review XA 2026-09-20) orderings inside
        // hook_nt_create_user_process, pinned textually because the detour
        // cannot run in a unit test:
        //   1. the per-child ack event is created BEFORE injection — its
        //      unguessable name rides into the child through inject_via_apc's
        //      cross-process env patch, so it must exist first;
        //   2. the ack-create failure path terminates the child and returns
        //      the original status — no unguessable name, no child (fail
        //      closed);
        //   3. NtResumeThread happens BEFORE the bounded ack wait — the queued
        //      APC cannot fire before resume, so waiting first would deadlock;
        //   4. the ack wait happens BEFORE the two registration IPC calls, and
        //      the timeout branch terminates the child — a no-ack child is
        //      never registered with the launcher and never left running;
        //   5. registration is keyed on BOTH inject_failed and ack_failed.
        let body = spawn_hook_body();
        let create_off = body
            .find("create_child_init_ack(")
            .expect("spawn hook must create the per-child bootstrap ack event");
        let inject_off = body
            .find("inject::inject_via_apc(")
            .expect("spawn hook must call inject::inject_via_apc");
        let resume_off = body
            .find("NtResumeThread")
            .expect("spawn hook must resume the child thread");
        let wait_off = body
            .find("wait_for_ack(")
            .expect("spawn hook must wait bounded for the per-child bootstrap ack");
        let register_off = body
            .find("ipc_register_child(")
            .expect("spawn hook must call ipc_register_child");
        assert!(
            create_off < inject_off,
            "the per-child ack event must be created BEFORE inject_via_apc — its name \
             is delivered through the injection env patch, which happens inside the \
             inject call"
        );
        let create_to_inject = &body[create_off..inject_off];
        assert!(
            create_to_inject.contains("TerminateProcess") && create_to_inject.contains("return status"),
            "an ack-event creation failure must terminate the child and return the \
             original syscall status (fail closed, launcher-failure precedent)"
        );
        assert!(
            resume_off < wait_off,
            "the bootstrap ack wait must be ordered AFTER NtResumeThread — the queued \
             APC cannot fire before the initial thread runs, so waiting before resume \
             would deadlock every spawn for the full timeout"
        );
        assert!(
            wait_off < register_off,
            "the ack wait must be ordered BEFORE the registration IPC — a child that \
             never confirms its own guard must be terminated (timeout branch) before \
             the launcher ever hears about it"
        );
        let wait_to_register = &body[wait_off..register_off];
        assert!(
            wait_to_register.contains("TerminateProcess"),
            "the ack-timeout branch must terminate the child: a spawn whose hook.dll \
             never confirmed (e.g. the known cmd.exe DllMain limitation) must not be \
             left running unconfirmed"
        );
        assert!(
            wait_to_register.contains("ack_failed = true"),
            "the ack timeout must raise the ack_failed flag that gates registration"
        );
        assert!(
            body.contains("!inject_failed && !ack_failed"),
            "registration must be skipped for BOTH inject-failed and ack-failed \
             children (dead/never-going-to-run child: nothing for the launcher to \
             act on)"
        );
    }

    #[test]
    fn spawn_hook_scans_child_image_and_gates_on_guard() {
        let body = spawn_hook_body();
        assert!(
            body.contains("scan_image_for_direct_syscalls("),
            "P1-01 regression: hook_nt_create_user_process must scan the child's \
             image for direct syscalls — the launcher scans the root target \
             only, so every process below the root otherwise keeps the \
             direct-syscall bypass open"
        );
        assert!(
            body.contains("child_scan_enabled("),
            "P1-01 regression: child scan must stay gated on the captured guard \
             level (full/static only, never re-read from env)"
        );
    }

    // ── `..` lexical fold in resolve_for_hook (audit Critical #1) ──────────

    /// Build OBJECT_ATTRIBUTES with a UTF-16 ObjectName (RootDirectory null,
    /// i.e. the absolute branch) and run resolve_for_hook on it.
    fn resolve_abs(nt_path: &str) -> Option<(String, Option<Vec<u16>>)> {
        let buf: Vec<u16> = nt_path.encode_utf16().collect();
        let len_bytes = (buf.len() * 2) as u16;
        let us = UNICODE_STRING {
            Length: len_bytes,
            MaximumLength: len_bytes,
            Buffer: buf.as_ptr() as *mut u16,
        };
        let oa = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &us as *const UNICODE_STRING as *mut UNICODE_STRING,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        // SAFETY: us/oa/buf are valid locals for the duration of the call.
        unsafe { resolve_for_hook(&oa) }
    }

    #[test]
    fn resolve_for_hook_folds_parent_dir_escape_absolute() {
        // THE regression (audit Critical #1): the exploit create
        // `NtCreateFile("\??\d:\<root>\..\..\payload.exe",
        // CREATE_ALWAYS)` must resolve to the FOLDED dos path so policy
        // classifies it outside project_root (Cow/Deny), never Passthrough.
        // Unfixed, resolve_for_hook returned the unfolded string and the
        // containment prefix test matched the root while the kernel resolved
        // the `..` segments outside the sandbox.
        let got = resolve_abs(r"\??\D:\proj\..\..\outside.exe")
            .expect("absolute DOS-form path must resolve");
        assert_eq!(got.0, r"d:\outside.exe");
        // S04: absolute opens carry the FOLDED snapshot — the kernel opens
        // exactly the bytes policy decided on, never a re-read of the guest
        // buffer (unmirror carve-out + sans-reparse equivalence preserved:
        // policy's dos may be the virtual view, the snapshot stays the
        // folded physical form).
        assert_eq!(
            got.1.as_deref(),
            Some(r"\??\D:\outside.exe".encode_utf16().collect::<Vec<u16>>().as_slice()),
        );
    }

    #[test]
    fn resolve_for_hook_folds_dotdot_inside_root() {
        // Legitimate callers with `..` inside the root keep working: the
        // folded path stays under the root and decision == kernel target.
        let got = resolve_abs(r"\??\D:\proj\sub\..\file.txt").unwrap();
        assert_eq!(got.0, r"d:\proj\file.txt");
    }

    #[test]
    fn resolve_for_hook_folds_curdir_inside_root() {
        let got = resolve_abs(r"\??\D:\proj\.\file.txt").unwrap();
        assert_eq!(got.0, r"d:\proj\file.txt");
    }

    #[test]
    fn resolve_for_hook_folds_forward_slash_dotdot() {
        // The object manager accepts `/` as a separator; the fold must
        // normalize and pop across it.
        let got = resolve_abs(r"\??\D:\proj/sub/../../outside.exe").unwrap();
        assert_eq!(got.0, r"d:\outside.exe");
    }

    #[test]
    fn resolve_for_hook_clamps_dotdot_past_drive_root() {
        // `..` past the volume root clamps at the drive, like the kernel.
        let got = resolve_abs(r"\??\D:\..\..\x").unwrap();
        assert_eq!(got.0, r"d:\x");
    }

    #[test]
    fn resolve_for_hook_extended_prefix_fold() {
        // `\\?\` skips Win32-side normalization but NOT kernel-side
        // `..` resolution, so the exploit class works through it too — and
        // the fold must handle it identically.
        let got = resolve_abs(r"\\?\D:\proj\..\..\outside.exe").unwrap();
        assert_eq!(got.0, r"d:\outside.exe");
    }

    #[test]
    fn resolve_for_hook_folds_relative_case_through_lower() {
        // Original case is folded away by nt_to_dos_lower; what matters is
        // that the dot fold happens BEFORE that point so segments like
        // `Sub` still pop correctly.
        let got = resolve_abs(r"\??\D:\proj\Sub\..\FILE.txt").unwrap();
        assert_eq!(got.0, r"d:\proj\file.txt");
    }

    // ── Guard configuration snapshot (audit 2026-09-19 High) ───────────────
    //
    // The environment block is guest-writable: a sandboxed process can
    // SetEnvironmentVariable forged guard values into its own block, and any
    // child it spawns inherits the forgery. Decision code therefore reads
    // ONLY the install-time snapshot (GUARD_ENV / DISABLED_HOOK_CATS, both
    // captured in install_hooks before any guest code has run), and the
    // spawn gate denies any child whose inherited environment carries guard
    // settings that differ from that snapshot.

    /// Serializes env-mutating tests: the environment is process-wide while
    /// cargo test runs tests on parallel threads (same pattern as
    /// memory_guard.rs tests::ENV_LOCK and launcher nested_detection_tests,
    /// both added after exactly that class of flake).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// RAII guard restoring FS_SANDBOX_DISABLE_HOOKS on drop.
    struct DisableHooksEnvGuard(Option<std::ffi::OsString>);

    impl DisableHooksEnvGuard {
        fn capture() -> Self {
            DisableHooksEnvGuard(std::env::var_os("FS_SANDBOX_DISABLE_HOOKS"))
        }
    }

    impl Drop for DisableHooksEnvGuard {
        fn drop(&mut self) {
            match &self.0 {
                Some(v) => std::env::set_var("FS_SANDBOX_DISABLE_HOOKS", v),
                None => std::env::remove_var("FS_SANDBOX_DISABLE_HOOKS"),
            }
        }
    }

    /// Canonical section name every seeded snapshot shares (the OnceLock is
    /// set once per test-binary process; all tests must agree on the value).
    const TRUSTED_SECTION: &str = "Local\\WinRsBoxSession-trusted";

    /// Pin the canonical install-time snapshot the guard tests assert
    /// against. The OnceLocks can only be set once per test-binary process;
    /// every caller must use these exact values so parallel tests agree.
    ///
    /// Since review XA 2026-09-20, S02 the snapshot carries only the two
    /// non-config inputs (section name + no_track); guard/allow_rwx/
    /// disable_hooks live in trusted_boot's EffectiveConfig and are never
    /// consulted from the environment.
    fn seed_guard_snapshot() {
        let _ = GUARD_ENV.set(GuardEnvSnapshot {
            no_track: false,
            section: TRUSTED_SECTION.into(),
        });
        let snap = GUARD_ENV.get().expect("GUARD_ENV seeded above");
        assert!(!snap.no_track, "GUARD_ENV seeded with a conflicting no_track");
        assert_eq!(
            snap.section,
            TRUSTED_SECTION,
            "GUARD_ENV seeded with a conflicting section name"
        );
        let _ = DISABLED_HOOK_CATS.set(vec!["reg".to_string()]);
        assert_eq!(
            DISABLED_HOOK_CATS.get().map(|c| c.as_slice()),
            Some(&["reg".to_string()][..]),
            "DISABLED_HOOK_CATS seeded with a conflicting category list"
        );
    }

    /// Regression core (audit 2026-09-19 High): the guest sets
    /// FS_SANDBOX_DISABLE_HOOKS after startup — the category gate must keep
    /// following the install-time snapshot, not the guest-writable
    /// environment. Old behaviour re-read the env var at each consumer and
    /// flipped categories on/off at the guest's whim.
    #[test]
    fn hook_category_disabled_ignores_post_startup_env_mutation() {
        let _lock = env_lock();
        let _env = DisableHooksEnvGuard::capture();
        seed_guard_snapshot();

        // The kill switch first: the guest forges categories into its own
        // block after startup. The gate must not follow (old behaviour
        // disabled the fs hooks and the whole memory guard here).
        std::env::set_var("FS_SANDBOX_DISABLE_HOOKS", "fs,memory");
        assert!(
            !hook_category_disabled("fs"),
            "post-startup FS_SANDBOX_DISABLE_HOOKS=fs must not disable the fs hooks"
        );
        assert!(
            !hook_category_disabled("memory"),
            "post-startup FS_SANDBOX_DISABLE_HOOKS=memory must not disable the memory guard"
        );
        assert!(
            hook_category_disabled("reg"),
            "the trusted category must stay disabled regardless of env state"
        );

        // Scrubbed to empty — the snapshot still wins.
        std::env::set_var("FS_SANDBOX_DISABLE_HOOKS", "");
        assert!(hook_category_disabled("reg"));
        assert!(!hook_category_disabled("fs"));

        // Removed entirely — still the snapshot (trusted baseline: only
        // "reg"; a scrub must not re-enable anything).
        std::env::remove_var("FS_SANDBOX_DISABLE_HOOKS");
        assert!(hook_category_disabled("reg"));
        assert!(!hook_category_disabled("fs"));
        assert!(!hook_category_disabled("memory"));
    }

    /// The spawn gate must deny any spawn whose inherited environment
    /// carries a security-config variable AT ALL (deny-on-presence, review
    /// XA 2026-09-20, S02): the trusted session section is the only config
    /// source, so an inherited FS_SANDBOX_GUARD/ALLOW_RWX/DISABLE_HOOKS/
    /// PIPE/DLL/CWD/ROOT value has no honest explanation. The old
    /// compare-to-snapshot semantics (a "trusted value re-cased passes")
    /// died with the env config source. Absence and unrelated variables
    /// stay allowed; section and no_track keep their compare-to-snapshot
    /// rules.
    #[test]
    fn guard_env_mismatch_denies_forged_child_guard_env() {
        let trusted = GuardEnvSnapshot {
            no_track: false,
            section: TRUSTED_SECTION.into(),
        };

        // The three guard-level knobs are now denied on ANY presence —
        // including the old "matches the trusted value" and "reads like a
        // denial" spellings that used to pass.
        for (name, value) in [
            ("FS_SANDBOX_GUARD", "full"),       // the trusted value itself: still denied
            ("fs_sandbox_guard", "FULL"),       // re-cased trusted value: still denied
            ("FS_SANDBOX_GUARD", "none"),       // downgrade
            ("fs_sandbox_allow_rwx", "0"),      // presence-only enable: denied
            ("FS_SANDBOX_ALLOW_RWX", "1"),      // even when RWX would be allowed: denied
            ("FS_SANDBOX_DISABLE_HOOKS", "memory"), // the exact audit attack
            ("FS_SANDBOX_DISABLE_HOOKS", "reg"), // the trusted list itself: still denied
            ("FS_SANDBOX_DISABLE_HOOKS", " REG , reg "), // equivalent re-spelling: still denied
        ] {
            let reason = guard_env_mismatch(
                &[(name.to_string(), value.to_string())],
                &trusted,
            );
            assert!(
                reason.as_ref().is_some_and(|m| m.contains(&name.to_ascii_uppercase())),
                "inherited {name}={value:?} must be denied on presence alone, got {reason:?}"
            );
        }

        // The four config-path variables joined the deny list with S02:
        // an inherited pipe/dll/cwd/root has no legitimate source either.
        for (name, value) in [
            ("FS_SANDBOX_PIPE", r"\\.\pipe\winrsbox-ipc"),
            ("FS_SANDBOX_DLL", r"D:\evil\hook.dll"),
            ("FS_SANDBOX_CWD", r"D:\sandbox"),
            ("FS_SANDBOX_ROOT", r"D:\overlay"),
        ] {
            let reason = guard_env_mismatch(
                &[(name.to_string(), value.to_string())],
                &trusted,
            );
            assert!(
                reason.as_ref().is_some_and(|m| m.contains(name)),
                "inherited {name} must be denied on presence alone, got {reason:?}"
            );
        }

        // Every deny message carries the single-source-of-truth explanation.
        let reason = guard_env_mismatch(
            &[("FS_SANDBOX_GUARD".to_string(), "none".to_string())],
            &trusted,
        )
        .expect("guard presence must be denied");
        assert!(
            reason.contains("trusted session section"),
            "deny reason must name the trusted section as the only config channel: {reason}"
        );

        // FS_SANDBOX_NO_TRACK keeps its compare-to-snapshot rule: denied
        // unless the snapshot carries it. It makes mark_spawned skip the
        // child, which makes the injector's own cross-process writes look
        // foreign to memory_guard — injection then fails and the child is
        // terminated before resume. That is a guest self-DoS rather than an
        // escape, but a guard-relevant variable outside the gate is
        // precisely the drift the gate exists to catch.
        assert!(
            guard_env_mismatch(
                &[("FS_SANDBOX_NO_TRACK".to_string(), "1".to_string())],
                &trusted,
            )
            .is_some_and(|m| m.contains("FS_SANDBOX_NO_TRACK")),
            "forged FS_SANDBOX_NO_TRACK must be denied",
        );
        // When the launcher itself set it (integration tests do), a child
        // inheriting the same value matches the snapshot and is allowed.
        let trusted_no_track = GuardEnvSnapshot {
            no_track: true,
            section: TRUSTED_SECTION.into(),
        };
        assert_eq!(
            guard_env_mismatch(
                &[("FS_SANDBOX_NO_TRACK".to_string(), "1".to_string())],
                &trusted_no_track,
            ),
            None,
        );

        // No guard variables at all: the child's hook boots with the
        // fail-closed trusted-section defaults — allowed.
        assert_eq!(guard_env_mismatch(&[], &trusted), None);
        assert_eq!(
            guard_env_mismatch(&[("PATH".to_string(), r"C:\Windows".to_string())], &trusted),
            None,
            "non-guard variables must not trip the gate"
        );

        // Retired-but-unrelated variables are ignored this chunk (trace, the
        // init-event / diagnostic escapes, and the per-child ack var — which
        // trusted parent code appends into the child's env AFTER this gate
        // ran — are not security config).
        assert_eq!(
            guard_env_mismatch(
                &[
                    ("FS_SANDBOX_TRACE".to_string(), "1".to_string()),
                    ("FS_SANDBOX_INIT_EVENT".to_string(), "some-event".to_string()),
                    ("FS_SANDBOX_CHILD_INIT_EVENT".to_string(), "some-child-ack-event".to_string()),
                ],
                &trusted,
            ),
            None,
            "non-config, non-guard variables stay ignored"
        );

        // One forged variable among legitimate ones is still caught.
        let observed = vec![
            ("FS_SANDBOX_PIPE".to_string(), "winrsbox-ipc".to_string()),
            ("FS_SANDBOX_DISABLE_HOOKS".to_string(), "fs".to_string()),
        ];
        assert!(guard_env_mismatch(&observed, &trusted).is_some());
    }

    /// A child with no process-parameters block inherits no environment at
    /// all — nothing to vouch for, nothing to deny; its hook boots with the
    /// fail-safe defaults. (Seeding GUARD_ENV pins that the gate reaches the
    /// null-params check rather than returning early on an empty snapshot.)
    #[test]
    fn child_guard_env_violation_null_params_fail_safe() {
        seed_guard_snapshot();
        assert_eq!(child_guard_env_violation(std::ptr::null_mut()), None);
    }

    /// The session-section name is guard-relevant: a forged name would point
    /// the child's hook at an attacker-authored section carrying a poisoned
    /// pipe_name / dll_path. The trusted value re-stated passes (that is what
    /// ordinary inheritance looks like); a different value is denied; ANY
    /// value is denied when this process itself booted without a name.
    /// Old behaviour: the gate ignored FS_SANDBOX_SECTION entirely.
    #[test]
    fn guard_env_mismatch_denies_forged_section_name() {
        let trusted = GuardEnvSnapshot {
            no_track: false,
            section: TRUSTED_SECTION.into(),
        };
        assert_eq!(
            guard_env_mismatch(
                &[(crate::inject::SECTION_ENV_VAR.to_string(), TRUSTED_SECTION.to_string())],
                &trusted,
            ),
            None,
            "ordinary inheritance of the trusted section name is not a forgery"
        );
        let reason = guard_env_mismatch(
            &[(
                crate::inject::SECTION_ENV_VAR.to_string(),
                "Local\\WinRsBoxSession-evil".to_string(),
            )],
            &trusted,
        );
        assert!(
            reason.is_some_and(|m| m.contains("FS_SANDBOX_SECTION")),
            "a forged session-section name must be denied"
        );
        let trusted_no_name = GuardEnvSnapshot {
            no_track: false,
            section: String::new(),
        };
        let reason = guard_env_mismatch(
            &[(
                crate::inject::SECTION_ENV_VAR.to_string(),
                "Local\\WinRsBoxSession-anything".to_string(),
            )],
            &trusted_no_name,
        );
        assert!(
            reason.is_some(),
            "any inherited section name must be denied when we booted without one"
        );
        // Absence stays allowed (the spawn hook injects the true value into
        // the child after this gate runs — env-scrubbed children).
        assert_eq!(
            guard_env_mismatch(&[], &trusted_no_name),
            None,
            "absence of the section name must stay allowed"
        );
    }

    // ── S02 (review XA 2026-09-20): trusted-section-only security config ──
    //
    // Structural pins for the chunk-2 fix. The shared-memory session section
    // (read via trusted_boot::resolve_effective_config) is the ONLY source of
    // install-time security config; the guest-forgeable environment carries
    // only the opaque section name (FS_SANDBOX_SECTION) plus the two test
    // aids (FS_SANDBOX_INIT_EVENT, FS_SANDBOX_NO_TRACK). The guard level is
    // the typed ipc::GuardLevel, never a String compared by bytes.

    /// The eight retired env-var names, in their quoted literal form.
    /// `FS_SANDBOX_SECTION`, `FS_SANDBOX_INIT_EVENT` and `FS_SANDBOX_NO_TRACK`
    /// are ALLOWED and must never join this list.
    const RETIRED_CONFIG_ENV_VARS: [&str; 8] = [
        "FS_SANDBOX_PIPE",
        "FS_SANDBOX_DLL",
        "FS_SANDBOX_CWD",
        "FS_SANDBOX_ROOT",
        "FS_SANDBOX_GUARD",
        "FS_SANDBOX_ALLOW_RWX",
        "FS_SANDBOX_DISABLE_HOOKS",
        "FS_SANDBOX_TRACE",
    ];

    /// W1: no hooks-module source may read security config from the
    /// environment — not via `env::var("FS_SANDBOX_PIPE")` nor by naming any
    /// retired variable as a quoted literal anywhere in the module. Env reads
    /// happened BEFORE the section loaded and `OnceLock::set` could never
    /// overwrite env-accepted values, so a forged variable permanently
    /// overrode the trusted config (review XA 2026-09-20, S02 #1).
    #[test]
    fn install_hooks_never_reads_security_config_from_env() {
        let src = crate::hooks::module_source("hooks");
        for name in RETIRED_CONFIG_ENV_VARS {
            let quoted = format!("\"{name}\"");
            assert!(
                !src.contains(&quoted),
                "hooks module must not reference security-config env var {name} — \
                 config is delivered ONLY through the trusted session section"
            );
        }
    }

    /// W2: the guard level is the typed `ipc::GuardLevel`, not a String
    /// compared by bytes. The ad-hoc String was compared case-insensitively
    /// at the spawn gate but case-sensitively at executors, so "FULL" passed
    /// the gate and then failed every `== "static"`-style executor check
    /// (review XA 2026-09-20, S02 #2). Exact byte sequences only — the words
    /// legitimately occur inside doc comments.
    #[test]
    fn guard_level_is_typed_not_string_compared() {
        let src = crate::hooks::module_source("hooks");
        assert!(
            src.contains("GuardLevel"),
            "hooks module must use the typed ipc::GuardLevel for the guard level"
        );
        for cmp in ["== \"full\"", "== \"static\"", "!= \"none\""] {
            assert!(
                !src.contains(cmp),
                "guard level must be compared as ipc::GuardLevel, not by string: found {cmp}"
            );
        }
    }

    /// W3: the spawn gate must deny the retired config variables on PRESENCE
    /// alone. Since the section is the only config source, an inherited
    /// FS_SANDBOX_* config value has no legitimate explanation left — the
    /// gate's match list must name all seven (lowercase; entries are
    /// normalized on read).
    #[test]
    fn spawn_gate_denies_config_env_on_presence() {
        let src = crate::hooks::module_source("spawn");
        for name in [
            "fs_sandbox_pipe",
            "fs_sandbox_dll",
            "fs_sandbox_cwd",
            "fs_sandbox_root",
            "fs_sandbox_guard",
            "fs_sandbox_allow_rwx",
            "fs_sandbox_disable_hooks",
        ] {
            assert!(
                src.contains(name),
                "spawn gate must deny inherited {name} on presence alone: security \
                 config is delivered only through the trusted session section"
            );
        }
    }

    /// RED WITNESS (chunk 3, review XA 2026-09-20 S02 #1 remainder): the IPC
    /// client must verify WHO owns the pipe server before trusting any
    /// answer. The pipe name arrives via the (hook-only) session section, but
    /// a hostile parent — or anything that can set the child's environment
    /// before hook install — can otherwise point the child at an attacker
    /// pipe answering `Decision::Passthrough` to everything. The defence is
    /// two-fold and BOTH halves are pinned here, structurally:
    ///   1. the raw server-PID query (`GetNamedPipeServerProcessId`) appears
    ///      in ipc_client's module source, and
    ///   2. the connect path actually calls
    ///      `trusted_boot::verify_pipe_server_identity`.
    /// `module_source("ipc_client")` resolves src/ipc/ipc_client.rs (unique
    /// file stem under src/ — same runtime-read mechanism as the W1/W2/W3
    /// pins above, immune to the include_str! file-vs-directory trap).
    #[test]
    fn ipc_connect_verifies_pipe_server_identity() {
        let src = crate::hooks::module_source("ipc_client");
        assert!(
            src.contains("GetNamedPipeServerProcessId"),
            "ipc_client must query the pipe server's owning PID \
             (GetNamedPipeServerProcessId) — without it any process that can \
             create a pipe with the session's name can impersonate the launcher"
        );
        assert!(
            src.contains("verify_pipe_server_identity"),
            "ipc_client must run trusted_boot::verify_pipe_server_identity on \
             every fresh connection — a connected pipe whose server is not the \
             pinned launcher (PID + kernel creation time) must be discarded \
             like a failed connect"
        );
    }

    // ── S10: fail-closed required hook categories + mitigation checks ──────

    /// Extract the `install_hooks` body from the hooks module source (same
    /// runtime-read mechanism as `spawn_hook_body` above): from the fn
    /// signature to the next `pub unsafe fn` (`uninstall_hooks`, which
    /// follows it in mod.rs).
    fn install_hooks_body() -> String {
        let src = crate::hooks::module_source("hooks");
        let src = src.as_str();
        let fn_start = src
            .find("pub unsafe fn install_hooks")
            .expect("install_hooks must exist in the hooks module");
        let rest = &src[fn_start..];
        let body_end = rest
            .find("pub unsafe fn uninstall_hooks")
            .expect("uninstall_hooks must follow install_hooks in hooks/mod.rs");
        rest[..body_end].to_string()
    }

    /// S10: each REQUIRED hook category (reg/net/alpc/service/shell/system)
    /// must propagate its install failure with `install()?` — Err escapes
    /// install_hooks, DllMain returns FALSE and the launcher kills the child
    /// — and ui must remain the ONLY buffered (optional) site.
    #[test]
    fn install_hooks_fails_closed_on_required_category_errors() {
        let body = install_hooks_body();
        for site in [
            "crate::reg_hooks::install()?;",
            "crate::net_hooks::install()?;",
            "crate::alpc_guard::install()?;",
            "crate::service_guard::install()?;",
            "crate::shell_guard::install()?;",
            "crate::system_guard::install()?;",
        ] {
            assert!(
                body.contains(site),
                "REQUIRED category site `{site}` is missing from install_hooks — \
                 its install failure must abort the install (Err → DllMain FALSE → \
                 launcher kills the child), not be buffered away"
            );
        }
        let buffered = body.match_indices("buffer_install_error").count();
        assert_eq!(
            buffered, 1,
            "exactly one buffered install site may remain in install_hooks — \
             the OPTIONAL ui category; every other category must fail closed"
        );
        assert!(
            body.contains("if let Err(e) = crate::ui_guard::install()"),
            "the single buffered site must be the ui category's if-let — \
             ui_guard is the one OPTIONAL category (no SECURITY.md containment \
             promise depends on it) and degrades loudly-but-gracefully"
        );
    }

    /// R04 F4: the OPTIONAL ui category must keep buffering every failure
    /// mode — detour init, detour enable, missing user32 export, missing
    /// win32u.dll — so each surfaces as the S10 degraded-init signal instead
    /// of being silently swallowed or aborting the install.
    #[test]
    fn ui_guard_failures_buffer_into_the_degraded_init_signal() {
        let src = crate::hooks::module_source("ui_guard");
        for needle in [
            "ui_guard: detour init ",
            "ui_guard: detour enable ",
            "ui_guard: export not found: ",
            "ui_guard: win32u.dll not loaded",
        ] {
            assert!(
                src.contains(needle),
                "ui_guard install must buffer `{needle}` — the ui category is \
                 OPTIONAL and degrades via the S10 degraded-init event"
            );
        }
    }

    /// S10: the init_ack module (moved out of hooks/mod.rs) must keep the
    /// verify-after-set mitigation machinery, the `Result`-returning
    /// apply_mitigations signature, and the degraded-init env name the
    /// launcher (chunk 3, launch_prep.rs) shares as a cross-crate contract.
    #[test]
    fn init_ack_verifies_mitigations_and_pins_degraded_event_env() {
        let src = crate::hooks::module_source("init_ack");
        for needle in [
            "GetProcessMitigationPolicy",
            "mitigation_failure_is_fatal",
            "-> Result<(), String>",
            "FS_SANDBOX_INIT_DEGRADED_EVENT",
            "install_errors_pending",
        ] {
            assert!(
                src.contains(needle),
                "init_ack module source must contain `{needle}` — apply_mitigations \
                 must check every SetProcessMitigationPolicy BOOL and verify-after-set \
                 policies 2/8, and the degraded-event env name is a pinned \
                 hook↔launcher contract"
            );
        }
        assert!(
            src.contains("FS_SANDBOX_CHILD_INIT_EVENT"),
            "init_ack module source must contain `FS_SANDBOX_CHILD_INIT_EVENT` — \
             the per-child bootstrap-ack env name is the same cross-side pinned \
             hook↔launcher contract as the degraded-event literal above"
        );
    }
