
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
        let attrs = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: handle as *mut _,
            ObjectName: &ustr as *const UNICODE_STRING as *mut UNICODE_STRING,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let got = unsafe { resolve_for_hook(&attrs) };
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
        assert!(child_scan_enabled(Some("full")));
        assert!(child_scan_enabled(Some("static")));
        assert!(!child_scan_enabled(Some("scan")));
        assert!(!child_scan_enabled(Some("none")));
        assert!(!child_scan_enabled(Some("FULL")), "exact match only — launcher writes lowercase");
        assert!(!child_scan_enabled(Some("")));
        assert!(!child_scan_enabled(None), "unset guard (unit-test context) must not scan");
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
        let result = scan_image_for_direct_syscalls(h);
        assert!(result.is_ok(), "scan pipeline failed on own image: {result:?}");
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
        // Absolute opens keep pre_resolved = None (kernel gets the original
        // ObjectName verbatim; unmirror carve-out + sans-reparse equivalence).
        assert!(got.1.is_none());
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
    fn seed_guard_snapshot() {
        let _ = GUARD_ENV.set(GuardEnvSnapshot {
            guard: "full".into(),
            disabled: "reg".into(),
            allow_rwx: false,
            no_track: false,
            section: TRUSTED_SECTION.into(),
        });
        let snap = GUARD_ENV.get().expect("GUARD_ENV seeded above");
        assert_eq!(snap.guard, "full", "GUARD_ENV seeded with a conflicting guard level");
        assert_eq!(snap.disabled, "reg", "GUARD_ENV seeded with a conflicting disable list");
        assert!(!snap.allow_rwx, "GUARD_ENV seeded with a conflicting RWX allowance");
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
    /// carries guard settings that differ from the trusted snapshot — that
    /// forgery is how a guest booted its children with the memory guard
    /// off. Absence of the variables and equivalent restatements of the
    /// trusted values must stay allowed (no false positives).
    #[test]
    fn guard_env_mismatch_denies_forged_child_guard_env() {
        let trusted = GuardEnvSnapshot {
            guard: "full".into(),
            disabled: "reg".into(),
            allow_rwx: false,
            no_track: false,
            section: TRUSTED_SECTION.into(),
        };

        // FS_SANDBOX_NO_TRACK is gated like the rest. It makes mark_spawned
        // skip the child, which makes the injector's own cross-process writes
        // look foreign to memory_guard — injection then fails and the child is
        // terminated before resume. That is a guest self-DoS rather than an
        // escape, but a guard-relevant variable outside the gate is precisely
        // the drift the gate exists to catch, so forging it is refused.
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
            guard: "full".into(),
            disabled: "reg".into(),
            allow_rwx: false,
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

        // No guard variables at all: the child's hook boots with fail-safe
        // defaults (guard "full", nothing disabled, RWX off) — allowed.
        assert_eq!(guard_env_mismatch(&[], &trusted), None);
        assert_eq!(
            guard_env_mismatch(&[("PATH".to_string(), r"C:\Windows".to_string())], &trusted),
            None,
            "non-guard variables must not trip the gate"
        );

        // Forged disable list — the exact attack from the audit finding.
        let reason = guard_env_mismatch(
            &[("FS_SANDBOX_DISABLE_HOOKS".to_string(), "memory".to_string())],
            &trusted,
        );
        assert!(
            reason.is_some(),
            "a child inheriting FS_SANDBOX_DISABLE_HOOKS=memory must be denied"
        );
        assert!(reason.unwrap().contains("forged"));

        // An equivalent re-spelling of the trusted list passes (case,
        // whitespace, order and duplicates are normalized on both sides).
        assert_eq!(
            guard_env_mismatch(
                &[("FS_SANDBOX_DISABLE_HOOKS".to_string(), " REG , reg ".to_string())],
                &trusted,
            ),
            None,
            "an equivalent restatement of the trusted disable list is not a forgery"
        );

        // Forged RWX enable: presence-only semantics — ANY value counts as
        // an enable, including one that reads like a denial.
        let reason = guard_env_mismatch(
            &[("fs_sandbox_allow_rwx".to_string(), "0".to_string())],
            &trusted,
        );
        assert!(
            reason.is_some(),
            "FS_SANDBOX_ALLOW_RWX=0 still means present; the hook treats existence as enable"
        );

        // With RWX genuinely allowed by the snapshot, the variable passes.
        let trusted_rwx = GuardEnvSnapshot {
            guard: "full".into(),
            disabled: "reg".into(),
            allow_rwx: true,
            no_track: false,
            section: TRUSTED_SECTION.into(),
        };
        assert_eq!(
            guard_env_mismatch(
                &[("FS_SANDBOX_ALLOW_RWX".to_string(), "1".to_string())],
                &trusted_rwx,
            ),
            None,
        );

        // Forged guard-level downgrade.
        let reason = guard_env_mismatch(
            &[("FS_SANDBOX_GUARD".to_string(), "none".to_string())],
            &trusted,
        );
        assert!(
            reason.is_some(),
            "a child inheriting FS_SANDBOX_GUARD=none must be denied"
        );
        assert_eq!(
            guard_env_mismatch(&[("FS_SANDBOX_GUARD".to_string(), "FULL".to_string())], &trusted),
            None,
            "the trusted guard level, re-cased, passes"
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
            guard: "full".into(),
            disabled: "reg".into(),
            allow_rwx: false,
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
            guard: "full".into(),
            disabled: "reg".into(),
            allow_rwx: false,
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
