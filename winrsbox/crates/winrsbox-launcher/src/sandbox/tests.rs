    use super::*;
    use super::inject::{digest_to_hex, sha256_file, verify_staged_artifacts_in};
    use windows::Win32::Security::TOKEN_QUERY;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

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

    /// S06 gap 4 (launcher side): the pre-launch image scan (sandbox/inject.rs)
    /// must not carry the silent 64 MiB truncation cap — the tail of a large
    /// section used to go unchecked. Structural on purpose: the cap is a
    /// one-line regression magnet. (Same include_str! pattern as the
    /// forbidden-literal test in launch_prep.rs.)
    #[test]
    fn s06_pre_launch_scan_has_no_64mib_cap() {
        let src = include_str!("inject.rs");
        assert!(
            !src.contains("64 * 1024 * 1024"),
            "the 64 MiB scan cap must stay out of the pre-launch scan (S06 gap 4)"
        );
    }

    // ── S07: per-project C: overlay root (full-path key + no-reparse) ────────

    /// S07 fixture root INSIDE the worktree (gitignored target/): creating
    /// real junctions/symlinks needs a genuine NTFS path inside the project,
    /// not tempfile's %TEMP% (same pattern as the policy crate's
    /// s05-fixtures). pid + run nanos + a per-run counter: no collisions
    /// between or within test runs.
    fn s07_fixture_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("s07-fixtures")
            .join(format!(
                "s07-{}-{}-{}-{}",
                tag,
                std::process::id(),
                nanos,
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&base).expect("create s07 fixture dir");
        base
    }

    /// Create a real NTFS junction (mount point) at `link` → `target`.
    /// Junctions need no privilege (unlike symlink_dir). Mirrors the
    /// FSCTL_SET_REPARSE_POINT dance in crates/winrsbox-integration-tests/
    /// src/bin/fs/links/escape_junction.rs; uses the already-enabled windows
    /// crate features (Win32_Storage_FileSystem, Win32_System_IO,
    /// Win32_Foundation) with hand-defined reparse consts so no new feature
    /// is pulled in.
    fn create_junction(link: &Path, target: &Path) -> Result<(), String> {
        use windows::Win32::Foundation::{CloseHandle, GENERIC_WRITE};
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, OPEN_EXISTING,
        };
        use windows::Win32::System::IO::DeviceIoControl;

        // Hand-defined (matching winnt.h) so no extra windows feature is needed.
        const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
        const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;

        // Canonicalized absolute target without the \?\ prefix; the substitute
        // name must be an NT path (\??\…), the print name is display-only.
        let abs = target.canonicalize().map_err(|e| e.to_string())?;
        let abs_str = abs.to_string_lossy();
        let abs_str = abs_str.strip_prefix(r"\?\").unwrap_or(&abs_str);
        let substitute = format!(r"\??\{abs_str}");
        let print_name = abs_str.to_string();

        let sub_wide: Vec<u16> = substitute.encode_utf16().collect();
        let print_wide: Vec<u16> = print_name.encode_utf16().collect();
        let sub_bytes = sub_wide.len() * 2;
        let print_bytes = print_wide.len() * 2;

        // REPARSE_DATA_BUFFER for IO_REPARSE_TAG_MOUNT_POINT: header
        // ReparseTag(4) + ReparseDataLength(2) + Reserved(2), then the
        // mount-point fields SubstituteNameOffset/Length +
        // PrintNameOffset/Length, then both names (NUL-terminated).
        let header_size = 8;
        let mount_header = 8;
        let data_len = mount_header + sub_bytes + 2 + print_bytes + 2;
        let total = header_size + data_len;

        let mut buf = vec![0u8; total];
        // ReparseTag
        buf[0..4].copy_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
        // ReparseDataLength (Reserved stays 0, SubstituteNameOffset stays 0)
        buf[4..6].copy_from_slice(&(data_len as u16).to_le_bytes());
        // SubstituteNameLength
        buf[10..12].copy_from_slice(&(sub_bytes as u16).to_le_bytes());
        // PrintNameOffset = sub_bytes + 2
        buf[12..14].copy_from_slice(&((sub_bytes + 2) as u16).to_le_bytes());
        // PrintNameLength
        buf[14..16].copy_from_slice(&(print_bytes as u16).to_le_bytes());
        // SubstituteName + PrintName (the +2 gaps hold the NUL terminators)
        for (i, &w) in sub_wide.iter().enumerate() {
            let o = 16 + i * 2;
            buf[o..o + 2].copy_from_slice(&w.to_le_bytes());
        }
        let off2 = 16 + sub_bytes + 2;
        for (i, &w) in print_wide.iter().enumerate() {
            let o = off2 + i * 2;
            buf[o..o + 2].copy_from_slice(&w.to_le_bytes());
        }

        let mut link_wide: Vec<u16> = link.to_string_lossy().encode_utf16().collect();
        link_wide.push(0);

        // A mount point can only be SET on an existing EMPTY directory (the
        // reparse data then turns it into the junction) — same flow as
        // escape_junction.rs, whose target dir is created up front.
        std::fs::create_dir_all(link).map_err(|e| e.to_string())?;

        // SAFETY: link_wide is a valid NUL-terminated UTF-16 buffer kept alive
        // for the whole call; the returned handle (if any) is owned by us and
        // closed on every path below.
        let h = unsafe {
            CreateFileW(
                PCWSTR(link_wide.as_ptr()),
                GENERIC_WRITE.0 | FILE_WRITE_ATTRIBUTES.0,
                FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(
                    FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0,
                ),
                None,
            )
        }
        .map_err(|e| format!("CreateFileW on {}: {e}", link.display()))?;

        // SAFETY: h is an open handle we own; buf is a fully initialized
        // REPARSE_DATA_BUFFER of exactly the length passed; out-buffer and
        // overlapped are unused (synchronous call).
        unsafe {
            DeviceIoControl(
                h,
                FSCTL_SET_REPARSE_POINT,
                Some(buf.as_ptr() as *const std::ffi::c_void),
                buf.len() as u32,
                None,
                0,
                None,
                None,
            )
        }
        .map_err(|e| e.to_string())?;

        // SAFETY: h is the handle CreateFileW returned to us above.
        unsafe { CloseHandle(h).map_err(|e| e.to_string())? };
        Ok(())
    }

    /// S07 core regression: two projects that differ ONLY in their parent
    /// directory (same basename) used to share one C: overlay root keyed by
    /// the basename, so they read/overwrote each other's CoW data. The key
    /// must encode the FULL project path, be distinct per project, stable
    /// across calls/re-runs, and always end in `workdir`.
    #[test]
    fn s07_same_basename_projects_get_distinct_c_overlay_roots() {
        let parent_a = tempfile::tempdir().expect("tempdir for project A");
        let parent_b = tempfile::tempdir().expect("tempdir for project B");
        let proj_a = parent_a.path().join("proj");
        let proj_b = parent_b.path().join("proj");
        std::fs::create_dir(&proj_a).expect("create project A");
        std::fs::create_dir(&proj_b).expect("create project B");
        // Guard the premise: the fixtures must really share the basename.
        assert_eq!(
            proj_a.file_name(),
            proj_b.file_name(),
            "fixtures must share the last path component or the test is vacuous"
        );
        let local = tempfile::tempdir().expect("LOCALAPPDATA stand-in tempdir");

        let root_a = super::ensure_c_overlay_root(local.path(), &proj_a)
            .expect("create C: overlay root for project A");
        let root_b = super::ensure_c_overlay_root(local.path(), &proj_b)
            .expect("create C: overlay root for project B");

        assert_ne!(
            root_a, root_b,
            "same-basename projects must NOT share a C: overlay root (S07)"
        );
        assert!(root_a.ends_with("workdir"), "root A must end in workdir: {}", root_a.display());
        assert!(root_b.ends_with("workdir"), "root B must end in workdir: {}", root_b.display());
        assert!(root_a.is_dir(), "root A must exist as a dir: {}", root_a.display());
        assert!(root_b.is_dir(), "root B must exist as a dir: {}", root_b.display());

        // Stability: a second run for the same project must reuse the root.
        let again = super::ensure_c_overlay_root(local.path(), &proj_a)
            .expect("re-create C: overlay root for project A");
        assert_eq!(root_a, again, "the C: root key must be stable across calls");
    }

    /// S07 hardening: a junction planted at the per-project key component of
    /// the shared C: tree (attacker-planted redirect) must make
    /// ensure_c_overlay_root fail loudly instead of creating the overlay
    /// behind the junction. Negative control: removing the LINK (not its
    /// target) must let the same call succeed and return the same path.
    #[test]
    fn s07_c_overlay_root_refuses_junction_at_key_component() {
        let base = s07_fixture_dir("junction-key");
        let link_target = base.join("link-target");
        let proj = base.join("proj");
        let localapp = base.join("localapp");
        std::fs::create_dir_all(&link_target).expect("create link-target dir");
        std::fs::create_dir_all(&proj).expect("create proj dir");
        std::fs::create_dir_all(localapp.join(".winrsbox")).expect("create localapp/.winrsbox");

        let key = super::c_overlay_key(&proj);
        let link = localapp.join(".winrsbox").join(&key);
        create_junction(&link, &link_target).expect("create junction at key component");

        let err = super::ensure_c_overlay_root(&localapp, &proj)
            .expect_err("junction at the C: root key component must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("reparse point"),
            "error must name the symlink/junction (reparse point) refusal: {msg}"
        );

        // Negative control: remove the LINK (not link-target) → must succeed.
        std::fs::remove_dir(&link).expect("remove the junction link");
        let c_root = super::ensure_c_overlay_root(&localapp, &proj)
            .expect("after removing the junction the root must be creatable");
        assert_eq!(
            c_root,
            localapp.join(".winrsbox").join(&key).join("workdir"),
            "the returned root must be the canonical key path"
        );
        assert!(c_root.is_dir(), "root must exist after the fix-up call");
        assert!(link_target.is_dir(), "junction target must be untouched");

        let _ = std::fs::remove_dir_all(&base);
    }

    /// A partial copy fails closed, preserves the source and resumes after
    /// the destination conflict is resolved.
    #[test]
    fn s07_legacy_c_overlay_partial_copy_is_retryable_and_scoped_to_index() {
        let base = s07_fixture_dir("legacy-merge");
        let proj = base.join("proj");
        let localapp = base.join("localapp");
        std::fs::create_dir_all(&proj).expect("create proj dir");
        let legacy = super::legacy_c_overlay_root(&localapp, &proj);
        assert_eq!(legacy, localapp.join(".winrsbox").join("proj").join("workdir"));
        std::fs::create_dir_all(legacy.join(r"users\me")).expect("create legacy tree");
        std::fs::write(legacy.join(r"users\me\a.txt"), "legacy-a").expect("write a");
        std::fs::write(legacy.join(r"users\me\b.txt"), "legacy-b").expect("write b");

        let c_root = super::ensure_c_overlay_root(&localapp, &proj).expect("create C: root");
        std::fs::create_dir_all(c_root.join(r"users\me")).expect("create new tree");
        std::fs::write(c_root.join(r"users\me\b.txt"), "new-b").expect("write new b");

        let policy = policy::Policy::open_or_create(
            &base.join("policy.redb"),
            legacy.clone(),
            base.join("mock-dirs"),
            proj.clone(),
        )
        .expect("open policy");
        let overlay_a = legacy.join(r"users\me\a.txt").to_string_lossy().into_owned();
        let overlay_b = legacy.join(r"users\me\b.txt").to_string_lossy().into_owned();
        policy.record_overlay(r"c:\users\me\a.txt", &overlay_a).expect("index a");
        policy.record_overlay(r"c:\users\me\b.txt", &overlay_b).expect("index b");

        assert_eq!(policy.overlay_values_under_root(&legacy).expect("read index").len(), 2);
        let indexed = vec![
            PathBuf::from(format!("{}\\USERS\\ME\\A.TXT", legacy.display())),
            PathBuf::from(format!("{}\\USERS\\ME\\B.TXT", legacy.display())),
        ];
        let err = super::migrate_legacy_c_overlay(&localapp, &legacy, &c_root, &indexed)
            .expect_err("a conflicting indexed entry must abort migration");
        assert!(err.to_string().contains("refusing to overwrite"));
        assert_eq!(std::fs::read_to_string(c_root.join(r"users\me\a.txt")).unwrap(), "legacy-a");
        assert_eq!(std::fs::read_to_string(c_root.join(r"users\me\b.txt")).unwrap(), "new-b");
        assert!(legacy.join(r"users\me\a.txt").exists(), "source remains after partial copy");
        assert!(legacy.join(r"users\me\b.txt").exists(), "conflicting source remains in legacy");
        assert_eq!(
            policy.overlay_values_under_root(&legacy).expect("read index after failure").len(),
            2,
            "failed migration does not rebase the index"
        );
        assert!(!policy.legacy_c_overlay_migration_complete(&c_root).expect("read marker"));

        std::fs::remove_file(c_root.join(r"users\me\b.txt")).expect("resolve destination conflict");
        assert_eq!(
            super::migrate_legacy_c_overlay(&localapp, &legacy, &c_root, &indexed).expect("retry"),
            (1, false),
            "the already copied entry is verified and the unresolved entry is copied"
        );
        assert_eq!(
            policy
                .rebase_legacy_c_overlay_and_mark_complete(&legacy, &c_root)
                .expect("rebase after complete copy"),
            2
        );
        assert!(policy.legacy_c_overlay_migration_complete(&c_root).expect("read marker"));
        assert!(policy.overlay_values_under_root(&legacy).expect("read legacy index").is_empty());
        assert_eq!(policy.overlay_values_under_root(&c_root).expect("read new index").len(), 2);
        assert_eq!(std::fs::read_to_string(c_root.join(r"users\me\a.txt")).unwrap(), "legacy-a");
        assert_eq!(std::fs::read_to_string(c_root.join(r"users\me\b.txt")).unwrap(), "legacy-b");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn s07_legacy_overlay_hole_below_indexed_directory_blocks_rebase() {
        let base = s07_fixture_dir("legacy-index-hole");
        let proj = base.join("proj");
        let localapp = base.join("localapp");
        std::fs::create_dir_all(&proj).expect("create project");
        let legacy = super::legacy_c_overlay_root(&localapp, &proj);
        std::fs::create_dir_all(legacy.join(r"users\me")).expect("create legacy tree");
        let hole = legacy.join(r"users\me\relative-open.txt");
        std::fs::write(&hole, "unindexed CoW data").expect("write relative-open CoW data");
        let c_root = super::ensure_c_overlay_root(&localapp, &proj).expect("create C: root");

        let policy = policy::Policy::open_or_create(
            &base.join("policy.redb"),
            legacy.clone(),
            base.join("mock-dirs"),
            proj.clone(),
        )
        .expect("open policy");
        let directory_overlay = legacy.join(r"users\me").to_string_lossy().into_owned();
        policy
            .record_overlay(r"c:\users\me", &directory_overlay)
            .expect("index directory only");
        let indexed = policy.overlay_values_under_root(&legacy).expect("read index");
        assert_eq!(indexed.len(), 1);

        let err = super::migrate_legacy_c_overlay(&localapp, &legacy, &c_root, &indexed)
            .expect_err("an unindexed file below an indexed directory must block migration");
        assert!(err.to_string().contains(hole.to_string_lossy().as_ref()));
        assert!(hole.exists(), "unindexed source data remains recoverable");
        assert!(
            !c_root.join(r"users\me\relative-open.txt").exists(),
            "preflight detects the hole before copying or rebasing"
        );
        assert_eq!(policy.overlay_values_under_root(&legacy).expect("read index after failure").len(), 1);
        assert!(!policy.legacy_c_overlay_migration_complete(&c_root).expect("read marker"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn s07_empty_policy_leaves_shared_legacy_data_unattributed() {
        let base = s07_fixture_dir("legacy-unattributed");
        let proj = base.join("proj");
        let localapp = base.join("localapp");
        std::fs::create_dir_all(&proj).expect("create project");
        let legacy = super::legacy_c_overlay_root(&localapp, &proj);
        std::fs::create_dir_all(&legacy).expect("create legacy root");
        let shared_file = legacy.join("another-project.txt");
        std::fs::write(&shared_file, "unattributed").expect("write shared legacy entry");
        let c_root = super::ensure_c_overlay_root(&localapp, &proj).expect("create C: root");
        let policy = policy::Policy::open_or_create(
            &base.join("policy.redb"),
            legacy.clone(),
            base.join("mock-dirs"),
            proj.clone(),
        )
        .expect("open empty policy");

        assert_eq!(
            super::migrate_legacy_c_overlay(&localapp, &legacy, &c_root, &[])
                .expect("leave shared legacy data untouched"),
            (0, true)
        );
        assert!(shared_file.exists());
        assert!(!c_root.join("another-project.txt").exists());
        assert_eq!(
            policy
                .rebase_legacy_c_overlay_and_mark_complete(&legacy, &c_root)
                .expect("mark empty policy migration complete"),
            0
        );
        assert!(policy.legacy_c_overlay_migration_complete(&c_root).expect("read marker"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn s07_legacy_c_overlay_absent_is_noop_and_junction_refused() {
        let base = s07_fixture_dir("legacy-junction");
        let proj = base.join("proj");
        let localapp = base.join("localapp");
        let elsewhere = base.join("elsewhere");
        std::fs::create_dir_all(&proj).expect("create proj dir");
        std::fs::create_dir_all(elsewhere.join("workdir")).expect("create junction target");
        std::fs::create_dir_all(&localapp).expect("create localapp dir");
        let c_root = super::ensure_c_overlay_root(&localapp, &proj).expect("create C: root");
        let legacy = super::legacy_c_overlay_root(&localapp, &proj);
        assert_eq!(super::migrate_legacy_c_overlay(&localapp, &legacy, &c_root, &[]).expect("absent"), (0, false));

        create_junction(&localapp.join(".winrsbox").join("proj"), &elsewhere).expect("junction");
        std::fs::write(elsewhere.join(r"workdir\x.txt"), "x").expect("write x");
        super::migrate_legacy_c_overlay(&localapp, &legacy, &c_root, &[])
            .expect_err("legacy chain through a junction must be refused");
        assert!(elsewhere.join(r"workdir\x.txt").exists(), "junction target untouched");
        let _ = std::fs::remove_dir(localapp.join(".winrsbox").join("proj"));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// S07 hardening: the same refusal applies when the junction sits one
    /// level up, at the shared `.winrsbox` component — the whole chain is
    /// validated, not just the leaf.
    #[test]
    fn s07_c_overlay_root_refuses_junction_at_winrsbox_component() {
        let base = s07_fixture_dir("junction-winrsbox");
        let link_target = base.join("link-target");
        let proj = base.join("proj");
        let localapp = base.join("localapp");
        std::fs::create_dir_all(&link_target).expect("create link-target dir");
        std::fs::create_dir_all(&proj).expect("create proj dir");
        std::fs::create_dir_all(&localapp).expect("create localapp dir");

        create_junction(&localapp.join(".winrsbox"), &link_target)
            .expect("create junction at .winrsbox");

        let err = super::ensure_c_overlay_root(&localapp, &proj)
            .expect_err("junction at the .winrsbox component must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("reparse point"),
            "error must name the symlink/junction (reparse point) refusal: {msg}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// S07 hardening: symbolic links (not just junctions) are equally
    /// rejected at the key component. Graceful skip when the process lacks
    /// SeCreateSymbolicLinkPrivilege / Developer Mode — same convention as
    /// the policy crate's S05 tests.
    #[test]
    fn s07_c_overlay_root_refuses_symlink_at_key_component() {
        let base = s07_fixture_dir("symlink-key");
        let link_target = base.join("link-target");
        let proj = base.join("proj");
        let localapp = base.join("localapp");
        std::fs::create_dir_all(&link_target).expect("create link-target dir");
        std::fs::create_dir_all(&proj).expect("create proj dir");
        std::fs::create_dir_all(localapp.join(".winrsbox")).expect("create localapp/.winrsbox");

        let key = super::c_overlay_key(&proj);
        let link = localapp.join(".winrsbox").join(&key);
        if let Err(e) = std::os::windows::fs::symlink_dir(&link_target, &link) {
            eprintln!(
                "SKIPPED S07 symlink case: creating the symlink fixture failed ({e}) — \
                 needs SeCreateSymbolicLinkPrivilege or Developer Mode"
            );
            let _ = std::fs::remove_dir_all(&base);
            return;
        }

        let err = super::ensure_c_overlay_root(&localapp, &proj)
            .expect_err("symlink at the C: root key component must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("reparse point"),
            "error must name the symlink/junction (reparse point) refusal: {msg}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    // ── S11: published roots fold to the canonical NTFS identity ─────────────

    /// The launcher publishes cwd/sandbox_root/overlay_roots (SessionConfig)
    /// and the root target's exe through `fold_published`. Oracles are
    /// hardcoded kernel-truth literals: Cyrillic СЕКРЕТ folds to секрет (the
    /// S11 bypass — the old ASCII-only publication left it uppercase and the
    /// hook's kernel-folded spelling never matched), while İ (U+0130), ς
    /// (U+03C2) and ẞ (U+1E9E) are IDENTITY under the kernel upcase table
    /// (see winrsbox-policy/src/path/case_fold.rs docs) even though Rust's
    /// locale-aware folds would move them. Every ASCII root must stay
    /// byte-identical to the historic `to_ascii_lowercase` publication.
    #[test]
    fn s11_published_roots_fold_to_kernel_identity() {
        // Non-ASCII now folds (kernel table), unlike the pre-S11 publication.
        assert_eq!(
            crate::fold_published(r"D:\СЕКРЕТ\proj"),
            r"d:\секрет\proj"
        );
        // ASCII roots: byte-identical to the old behavior.
        let ascii_root = r"D:\Dev\MyProj";
        assert_eq!(
            crate::fold_published(ascii_root),
            ascii_root.to_ascii_lowercase()
        );
        // Kernel-identity facts the locale fold gets wrong: these must NOT move.
        assert_eq!(
            crate::fold_published("C:\\W\u{0130}NDOWS"),
            "c:\\w\u{0130}ndows"
        );
        assert_eq!(crate::fold_published("C:\\\u{03C2}"), "c:\\\u{03C2}");
        assert_eq!(crate::fold_published("C:\\\u{1E9E}"), "c:\\\u{1E9E}");
    }

    // ── R04-1c: launch_suspended now creates the root guest under a
    //    privilege-reduced token via CreateProcessAsUserW ──────────────────

    /// `launch_suspended` with a harmless real target (`cmd.exe`, same
    /// convention `probe.rs::probe_child` uses) must produce a suspended
    /// child whose ACTUAL primary token is privilege-reduced — verified the
    /// same way `guest_token.rs`'s own tests and `probe.rs` do
    /// (`OpenProcessToken` + `GetTokenInformation`, here via
    /// `guest_token::verify_guest_token_shape`, the exact function
    /// `launch_suspended` itself already ran internally before returning).
    /// The child is terminated here without ever being resumed — same
    /// cleanup discipline every other suspended-process test in this
    /// codebase (`probe.rs::probe_child`) already follows.
    #[test]
    fn launch_suspended_produces_a_privilege_reduced_child_token() {
        let cwd = std::env::temp_dir();
        let target_args = vec!["cmd.exe".to_string(), "/c".to_string(), "exit".to_string()];

        let pi = launch_suspended(&cwd, &target_args, crate::GuardLevel::None)
            .expect("launch_suspended must succeed for a harmless cmd.exe target");

        // Independent re-verification (launch_suspended already ran this
        // check internally before returning Ok — this proves the guarantee
        // holds from the OUTSIDE too, not just that the internal check ran).
        let mut child_token = HANDLE::default();
        // SAFETY: pi.hProcess is the valid suspended process handle just
        // returned by launch_suspended above; TOKEN_QUERY is read-only.
        let opened = unsafe { OpenProcessToken(pi.hProcess, TOKEN_QUERY, &mut child_token) };

        // Compute the expected shape the same way launch_suspended did: this
        // process's own Administrators-enabled state at the time of launch.
        let own_token_for_check = unsafe {
            let mut t = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut t).ok();
            t
        };
        let source_admin_enabled = guest_token::administrators_state(own_token_for_check)
            .map(|(enabled, _)| enabled)
            .unwrap_or(false);
        unsafe { CloseHandle(own_token_for_check).ok() };

        let verify_result = opened
            .context("OpenProcessToken(child) failed")
            .and_then(|_| guest_token::verify_guest_token_shape(child_token, source_admin_enabled));
        if child_token != HANDLE::default() {
            // SAFETY: child_token was opened by us above (if opened.is_ok()).
            unsafe { CloseHandle(child_token).ok() };
        }

        // Cleanup FIRST (never let an assertion failure leak a live suspended
        // process): terminate, never resume, then close both handles.
        // SAFETY: pi.hProcess/pi.hThread are our own just-created handles;
        // the process is still CREATE_SUSPENDED — TerminateProcess is safe.
        unsafe {
            let _ = TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread).ok();
            CloseHandle(pi.hProcess).ok();
        }

        verify_result.expect(
            "child process token must pass verify_guest_token_shape \
             (privilege-reduced, Administrators deny-only if source was admin-enabled)",
        );
    }

    /// `build_guest_token`'s own failure path (forced via an invalid source
    /// token handle) must surface as an `Err` all the way through — this is
    /// the failure-surfacing contract `launch_suspended` relies on to abort
    /// the launch instead of falling back to an unrestricted token.
    /// `launch_suspended` itself always opens a VALID source token
    /// internally, so this test exercises the same underlying guarantee one
    /// layer down, at the boundary `launch_suspended` depends on — mirroring
    /// `guest_token.rs`'s own `build_guest_token_propagates_error_on_invalid_handle`.
    #[test]
    fn build_guest_token_failure_does_not_panic_and_is_an_err() {
        let bogus = HANDLE(0xDEAD_BEEF_usize as *mut std::ffi::c_void);
        let result = winrsbox::contain::guest::build_guest_token(bogus);
        assert!(
            result.is_err(),
            "build_guest_token must return Err (not panic) for an invalid token handle — \
             this is what makes launch_suspended's '?' on the same call abort the launch \
             instead of silently continuing with an unrestricted token"
        );
    }
