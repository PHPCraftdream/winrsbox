    use super::*;

    /// Lock-in the convention that IMAGE_FILE_MACHINE_UNKNOWN (=0) is the
    /// sentinel "process is NOT WoW64" value, and that the I386 constant
    /// (which a 32-bit Windows binary reports) is distinct from it. If the
    /// SDK ever renumbers these or someone copy-pastes the wrong constant
    /// into enforce_native_x64, this test will catch it.
    #[test]
    fn wow64_constant_is_distinct_from_native() {
        assert_eq!(IMAGE_FILE_MACHINE_UNKNOWN, 0);
        assert_ne!(IMAGE_FILE_MACHINE_I386, 0);
        assert_eq!(IMAGE_FILE_MACHINE_I386, 0x014C);
        // STATUS_DLL_INIT_FAILED is the NTSTATUS we use as the termination
        // exit code; it must remain in the "fatal error" space (top bit set).
        assert!(STATUS_DLL_INIT_FAILED & 0xC000_0000 == 0xC000_0000);
    }

    /// The auto-generated default config must be valid ktav that round-trips
    /// into a `policy::db::Config`. This pins the template against ktav format
    /// drift (e.g. an inline `{ ... }` compound or a stray quote sneaking in)
    /// and against the ktav crate's own breaking changes across versions.
    #[test]
    fn default_config_ktav_parses() {
        let cfg: policy::db::Config = ktav::from_str(DEFAULT_CONFIG_KTAV)
            .expect("DEFAULT_CONFIG_KTAV must be valid ktav");
        // Sanity: the template ships at least the C:\Windows deny rule.
        assert!(
            cfg.rules.iter().any(|r| r.prefix.eq_ignore_ascii_case(r"c:\windows")),
            "default config should contain a C:\\Windows rule",
        );
        // Backslashes must be single (ktav has no escape) — a path with `\\`
        // would mean the template was written with JSON-style escaping.
        assert!(
            !cfg.rules.iter().any(|r| r.prefix.contains(r"\\")),
            "default config rule prefixes must use single backslashes",
        );
    }

    // ── Finding-1 regression: guest must not overwrite the sandbox's own
    //    hook.dll / launcher artifacts ──────────────────────────────────────

    /// The npm global install drops the launcher + hook.dll into
    /// `%APPDATA%\\Roaming\\npm\\node_modules\\winrsbox\\native\\`, and the
    /// default template passes that whole tree through (writable). Without
    /// the deny carve-outs a sandboxed process can overwrite hook.dll on the
    /// real disk — the next launch would inject attacker-controlled code
    /// OUTSIDE the sandbox. This test loads DEFAULT_CONFIG_KTAV into a real
    /// Policy and pins the deny/passthrough boundary.
    #[test]
    fn install_dir_write_denied_despite_npm_passthrough() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = policy::Policy::open_or_create(
            &db_path,
            sandbox,
            mock_dirs,
            project,
        ).unwrap();

        let cfg_path = dir.path().join("cfg.ktav");
        std::fs::write(&cfg_path, DEFAULT_CONFIG_KTAV).unwrap();
        p.load_config(&cfg_path).unwrap();

        // The injection target itself: guest writes must be denied...
        let d = p.decide(r"c:\users\bob\appdata\roaming\npm\node_modules\winrsbox\native\hook.dll", true);
        assert_eq!(d.mode, policy::Mode::Deny, "guest write to hook.dll must be denied");
        // ...while reads stay passthrough (the sandbox still runs its own code).
        let d = p.decide(r"c:\users\bob\appdata\roaming\npm\node_modules\winrsbox\native\hook.dll", false);
        assert_eq!(d.mode, policy::Mode::Passthrough, "reads of hook.dll must stay passthrough");

        // The carve-out covers the whole package dir, not just native/.
        let d = p.decide(r"c:\users\bob\appdata\roaming\npm\node_modules\winrsbox\scripts\winrsbox-cli.js", true);
        assert_eq!(d.mode, policy::Mode::Deny, "guest write to the package dir must be denied");

        // PATH shims next to the package dir (npm also drops winrsbox.cmd there).
        let d = p.decide(r"c:\users\bob\appdata\roaming\npm\winrsbox.cmd", true);
        assert_eq!(d.mode, policy::Mode::Deny, "guest write to the PATH shim must be denied");

        // The carve-out is narrow: the rest of the npm tree stays writable.
        let d = p.decide(r"c:\users\bob\appdata\roaming\npm\docs\readme.md", true);
        assert_eq!(d.mode, policy::Mode::Passthrough, "unrelated npm paths must stay passthrough");

        // Prefix-variant install location (%USERPROFILE%\\.npm).
        let d = p.decide(r"c:\users\bob\.npm\node_modules\winrsbox\package.json", true);
        assert_eq!(d.mode, policy::Mode::Deny, "guest write under .npm install must be denied");

        // Toolchain prefixes stay writable by design (documented choice).
        let d = p.decide(r"c:\users\bob\.cargo\bin\cargo.exe", true);
        assert_eq!(d.mode, policy::Mode::Passthrough, ".cargo passthrough is deliberate");
    }

    // ── Change-2 integrity self-verification ─────────────────────────────────

    /// Write an integrity.json manifest next to the staged exe, using EXACTLY
    /// the shape the npm installer emits.
    fn write_integrity_manifest(dir: &Path, exe_digest: &str, dll_digest: &str) {
        let manifest = serde_json::json!({
            "version": "0.1.0",
            "algorithm": "sha256",
            "files": {
                "winrsbox.exe": exe_digest,
                "hook.dll": dll_digest,
            }
        });
        std::fs::write(
            dir.join("integrity.json"),
            serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn integrity_manifest_accepts_untampered_staged_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("winrsbox.exe");
        let dll = dir.path().join("hook.dll");
        std::fs::write(&exe, b"fake-exe-bytes").unwrap();
        std::fs::write(&dll, b"fake-dll-bytes").unwrap();

        // The oracle here is the hash function vs the comparison logic (tests
        // 3/4 below are the negative controls), so computing the digests with
        // the same sha256_file helper is fine.
        let exe_digest = digest_to_hex(&sha256_file(&exe).unwrap());
        let dll_digest = digest_to_hex(&sha256_file(&dll).unwrap());
        write_integrity_manifest(dir.path(), &exe_digest, &dll_digest);

        verify_staged_artifacts_in(&exe, &dll).unwrap();
    }

    #[test]
    fn integrity_manifest_rejects_tampered_dll() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("winrsbox.exe");
        let dll = dir.path().join("hook.dll");
        std::fs::write(&exe, b"fake-exe-bytes").unwrap();
        std::fs::write(&dll, b"fake-dll-bytes").unwrap();
        let exe_digest = digest_to_hex(&sha256_file(&exe).unwrap());
        let dll_digest = digest_to_hex(&sha256_file(&dll).unwrap());
        write_integrity_manifest(dir.path(), &exe_digest, &dll_digest);

        // Flip the dll contents AFTER the manifest was written → must refuse.
        std::fs::write(&dll, b"fake-dll-bytes-TAMPERED").unwrap();
        assert!(
            verify_staged_artifacts_in(&exe, &dll).is_err(),
            "a tampered hook.dll must fail the integrity check"
        );
    }

    #[test]
    fn integrity_manifest_rejects_tampered_exe() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("winrsbox.exe");
        let dll = dir.path().join("hook.dll");
        std::fs::write(&exe, b"fake-exe-bytes").unwrap();
        std::fs::write(&dll, b"fake-dll-bytes").unwrap();
        let exe_digest = digest_to_hex(&sha256_file(&exe).unwrap());
        let dll_digest = digest_to_hex(&sha256_file(&dll).unwrap());
        write_integrity_manifest(dir.path(), &exe_digest, &dll_digest);

        std::fs::write(&exe, b"fake-exe-bytes-TAMPERED").unwrap();
        assert!(
            verify_staged_artifacts_in(&exe, &dll).is_err(),
            "a tampered winrsbox.exe must fail the integrity check"
        );
    }

    #[test]
    fn integrity_manifest_missing_manifest_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("winrsbox.exe");
        let dll = dir.path().join("hook.dll");
        std::fs::write(&exe, b"fake-exe-bytes").unwrap();
        std::fs::write(&dll, b"fake-dll-bytes").unwrap();
        // No integrity.json → unmanaged deployment, verification is a no-op.
        assert!(!dir.path().join("integrity.json").exists());
        verify_staged_artifacts_in(&exe, &dll).unwrap();
    }

    #[test]
    fn integrity_manifest_malformed_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("winrsbox.exe");
        let dll = dir.path().join("hook.dll");
        std::fs::write(&exe, b"fake-exe-bytes").unwrap();
        std::fs::write(&dll, b"fake-dll-bytes").unwrap();
        // Malformed manifest (no `files`, no `algorithm`) → fail closed.
        std::fs::write(dir.path().join("integrity.json"), "{}").unwrap();
        assert!(
            verify_staged_artifacts_in(&exe, &dll).is_err(),
            "a malformed integrity manifest must fail closed"
        );
    }

    // --- build_cmdline: Windows command lines are UTF-16 ---

    /// Non-ASCII arguments must survive build_cmdline intact. The pre-fix
    /// writer iterated as_bytes() and pushed each byte as a char (Latin-1),
    /// so any argument that needed quoting (contains a space) and carried
    /// non-ASCII was corrupted on its way to CreateProcessW. Regression:
    /// path with spaces + Cyrillic + CJK.
    #[test]
    fn build_cmdline_preserves_non_ascii_args() {
        let arg = "D:\\проект новый\\отчёт финал.txt".to_string();
        let cmdline = build_cmdline(&[arg.clone()]);
        // Contains a space -> must be quoted...
        assert!(
            cmdline.starts_with("\"") && cmdline.ends_with("\""),
            "arg must be quoted: {cmdline}"
        );
        // ...and the quoted content must be the original, char for char.
        assert_eq!(
            &cmdline[1..cmdline.len() - 1],
            arg,
            "non-ASCII arg must survive intact"
        );

        // Multibyte chars adjacent to a backslash run (trailing-backslash case).
        let arg2 = "D:\\目录 目录\\bin\\".to_string();
        let cmdline2 = build_cmdline(&[arg2.clone()]);
        assert_eq!(
            &cmdline2[1..cmdline2.len() - 1],
            "D:\\目录 目录\\bin\\\\",
            "trailing backslash doubled, non-ASCII chars intact"
        );
    }

    /// ASCII CommandLineToArgvW escaping must be unchanged by the UTF-8 fix.
    #[test]
    fn build_cmdline_ascii_escaping_unchanged() {
        assert_eq!(build_cmdline(&[String::new()]), "\"\"");
        assert_eq!(build_cmdline(&["plain".to_string()]), "plain");
        assert_eq!(
            build_cmdline(&["a b\\".to_string()]),
            "\"a b\\\\\"",
            "trailing ASCII backslash must still be doubled"
        );
        assert_eq!(
            build_cmdline(&["say \"hi\"\\".to_string()]),
            "\"say \\\"hi\\\"\\\\\"",
            "embedded quotes + trailing backslash escaping unchanged"
        );
    }

    // --- console ownership ---

    /// Hiding the console is only ours to do when nothing else is attached.
    /// The launcher is a console-subsystem binary, so started from a `cmd.exe`
    /// prompt it shares that prompt's console — and the old unconditional
    /// `ShowWindow(SW_HIDE)` hid the OPERATOR'S window.
    #[test]
    fn console_is_hidden_only_when_we_are_the_sole_attached_process() {
        // Launched from a shell: the shell plus us. Never hide.
        assert!(!hide_console_allowed(2), "inherited console must not be hidden");
        // Deeper chains (shell -> wrapper -> launcher) are inherited too.
        assert!(!hide_console_allowed(3));
        assert!(!hide_console_allowed(17));
        // Our own console (Explorer / shortcut / CREATE_NEW_CONSOLE): hide it.
        assert!(hide_console_allowed(1));
        // No console at all — GetConsoleProcessList yields 0; nothing to hide.
        assert!(!hide_console_allowed(0));
    }

    /// Ctrl+C and Ctrl+Break are swallowed so the sandboxed program decides
    /// what they mean; the launcher staying alive is what keeps the Job
    /// Object — and therefore the whole process tree — from being torn down.
    /// Close/logoff/shutdown are NOT swallowed: the operator is ending the
    /// session and the default teardown must run.
    #[test]
    fn ctrl_handler_swallows_interrupts_but_not_session_end() {
        use windows::Win32::System::Console::{
            CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT, CTRL_LOGOFF_EVENT,
            CTRL_SHUTDOWN_EVENT,
        };
        // SAFETY: the handler is a pure function of its argument — no state,
        //         no pointers, safe to call directly.
        let handled = |e: u32| unsafe { console_ctrl_handler(e).as_bool() };
        assert!(handled(CTRL_C_EVENT), "Ctrl+C must not kill the launcher");
        assert!(handled(CTRL_BREAK_EVENT), "Ctrl+Break must not kill the launcher");
        assert!(!handled(CTRL_CLOSE_EVENT), "console close must tear the session down");
        assert!(!handled(CTRL_LOGOFF_EVENT));
        assert!(!handled(CTRL_SHUTDOWN_EVENT));
    }

    // --- resolve_target: PATHEXT expansion CreateProcessW does not do ---

    /// `PATH`/`PATHEXT` are process-wide, so these tests must not overlap —
    /// with each other or with anything else reading them. Poison-tolerant:
    /// a panic in one test must not cascade into "all the rest failed too".
    fn path_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The original report: `winrsbox cx` died with
    /// `CreateProcessW failed: The system cannot find the file specified.
    /// (0x80070002)` because `CreateProcessW` appends only `.exe` to a bare
    /// name. A `.bat` on PATH must resolve to its full path; kernel32 then
    /// rewrites it to `%COMSPEC% /c` on its own.
    #[test]
    fn resolve_target_expands_pathext_for_a_bare_batch_name() {
        let _lock = path_env_lock();
        let dir = std::env::temp_dir().join("winrsbox-resolve-bat");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bat = dir.join("wrs_probe_shim.bat");
        std::fs::write(&bat, "@echo off\r\n").unwrap();

        let saved_path = std::env::var("PATH").unwrap_or_default();
        let saved_ext = std::env::var("PATHEXT").ok();
        std::env::set_var("PATH", format!("{};{saved_path}", dir.display()));
        std::env::set_var("PATHEXT", ".COM;.EXE;.BAT;.CMD");

        let resolved = resolve_target("wrs_probe_shim");

        std::env::set_var("PATH", &saved_path);
        match saved_ext {
            Some(v) => std::env::set_var("PATHEXT", v),
            None => std::env::remove_var("PATHEXT"),
        }
        let _ = std::fs::remove_dir_all(&dir);

        let resolved = resolved.expect("bare .bat name must resolve via PATHEXT");
        assert!(
            resolved.to_ascii_lowercase().ends_with("wrs_probe_shim.bat"),
            "expected the .bat, got {resolved}",
        );
        assert!(
            std::path::Path::new(&resolved).is_absolute(),
            "resolution must yield a full path (WFP app_id / pre-scan need it), got {resolved}",
        );
    }

    /// A bare `.exe` name must resolve to a full path too. This is the case
    /// that silently cost containment: `wfp::app_id_from_path` cannot
    /// canonicalize a bare name, so `add_filter` refused to install the
    /// RFC1918 egress filters and `winrsbox node` simply ran without them.
    #[test]
    fn resolve_target_yields_full_path_for_a_bare_exe_name() {
        let _lock = path_env_lock();
        let resolved = resolve_target("cmd").expect("cmd must resolve — it is in System32");
        let lower = resolved.to_ascii_lowercase();
        assert!(lower.ends_with("cmd.exe"), "expected cmd.exe, got {resolved}");
        assert!(std::path::Path::new(&resolved).is_absolute());
        assert!(
            std::fs::canonicalize(&resolved).is_ok(),
            "the resolved path must canonicalize — that is exactly what app_id_from_path does",
        );
    }

    /// A name that already carries a launchable extension resolves without
    /// another extension being appended (CreateProcessW's own rule).
    #[test]
    fn resolve_target_keeps_an_explicit_extension() {
        let _lock = path_env_lock();
        let resolved = resolve_target("cmd.exe").expect("cmd.exe must resolve");
        let lower = resolved.to_ascii_lowercase();
        assert!(lower.ends_with("cmd.exe"), "got {resolved}");
        assert!(!lower.ends_with("cmd.exe.exe"), "extension must not be appended twice");
    }

    /// An absolute path is returned as itself, not re-searched on PATH.
    #[test]
    fn resolve_target_accepts_an_absolute_path() {
        let _lock = path_env_lock();
        let dir = std::env::temp_dir().join("winrsbox-resolve-abs");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bat = dir.join("wrs_probe_abs.cmd");
        std::fs::write(&bat, "@echo off\r\n").unwrap();

        let resolved = resolve_target(bat.to_str().unwrap());
        let _ = std::fs::remove_dir_all(&dir);

        let resolved = resolved.expect("an existing absolute path must resolve");
        assert!(resolved.to_ascii_lowercase().ends_with("wrs_probe_abs.cmd"));
    }

    /// Failure must name the target and say where it was looked for, instead
    /// of surfacing the raw `0x80070002` from deep inside CreateProcessW.
    #[test]
    fn resolve_target_reports_a_missing_target_usefully() {
        let _lock = path_env_lock();
        let err = resolve_target("winrsbox-no-such-command-xyzzy")
            .expect_err("a nonexistent bare name must not resolve")
            .to_string();
        assert!(err.contains("winrsbox-no-such-command-xyzzy"), "err: {err}");
        assert!(err.contains("PATH"), "err must say where it searched: {err}");

        let err = resolve_target(r"C:\winrsbox\no\such\path\nope.exe")
            .expect_err("a nonexistent explicit path must not resolve")
            .to_string();
        assert!(err.contains("does not exist"), "err: {err}");
    }
