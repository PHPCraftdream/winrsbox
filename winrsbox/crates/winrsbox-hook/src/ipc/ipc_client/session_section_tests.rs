    use super::*;

    fn unique_section_name(tag: &str) -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        format!(
            r"Local\WinRsBoxSessionHookTest-{}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
            tag
        )
    }

    fn unique_cfg() -> ipc::SessionConfig {
        ipc::SessionConfig {
            pipe_name: format!(r"\\.\pipe\winrsbox-hook-section-test-{}", std::process::id()),
            dll_path: r"D:\bin\hook.dll".into(),
            cwd: r"D:\sandbox".into(),
            sandbox_root: r"D:\sandbox_root".into(),
            overlay_roots: vec![],
            trace: false,
            guard: ipc::GuardLevel::Full,
            launcher_pid: 0,
            launcher_create_time: 0,
            allow_rwx: false,
            disable_hooks: String::new(),
        }
    }

    /// RAII owner for the section object created by `publish_for_test`;
    /// closing the last handle destroys the object so nothing leaks into
    /// the ambient `Local\` namespace after the test.
    struct SectionHandle(winapi::shared::ntdef::HANDLE);

    impl Drop for SectionHandle {
        fn drop(&mut self) {
            // SAFETY: handle came from CreateFileMappingW, closed exactly once.
            unsafe { winapi::um::handleapi::CloseHandle(self.0) };
        }
    }

    /// Create a section under `name` and write `bytes` into it. Unique
    /// per-process names keep this free of ambient-state coupling: a second
    /// `cargo test` in a sibling worktree can never collide.
    fn publish_for_test(name: &str, bytes: &[u8]) -> SectionHandle {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use winapi::um::memoryapi::{CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_WRITE};
        use winapi::um::winnt::PAGE_READWRITE;
        let wide: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();
        let size = ipc::SESSION_CONFIG_SECTION_SIZE;
        // SAFETY: pagefile-backed section (INVALID_HANDLE_VALUE); wide is a
        //         null-terminated UTF-16 name; size fits u32.
        let h = unsafe {
            CreateFileMappingW(
                winapi::um::handleapi::INVALID_HANDLE_VALUE,
                std::ptr::null_mut(),
                PAGE_READWRITE,
                0,
                size as u32,
                wide.as_ptr(),
            )
        };
        assert!(!h.is_null(), "CreateFileMappingW failed for {name}");
        // SAFETY: h is the valid handle returned above; the view covers
        //         `size` bytes and bytes.len() <= size by the ipc encoder.
        unsafe {
            let view = MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, size);
            assert!(!view.is_null(), "MapViewOfFile failed");
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), view as *mut u8, bytes.len());
            UnmapViewOfFile(view);
        }
        SectionHandle(h)
    }

    /// A name that does not exist must yield None without touching any
    /// global. (The pre-fix behaviour opened the well-known constant
    /// unconditionally and could read a LIVE launcher's config, poisoning
    /// PIPE_NAME / OVERLAY_ROOTS for the whole test binary.)
    #[test]
    fn missing_section_yields_none_and_touches_no_globals() {
        let name = unique_section_name("missing");
        let error = load_session_config_named(&name).unwrap_err();
        assert!(error.contains("OpenFileMappingW"), "unexpected error: {error}");
        assert!(try_load_session_config_named(&name).is_none());
        assert!(PIPE_NAME.get().is_none(), "a failed lookup must not set PIPE_NAME");
        assert!(
            session_section_name().is_none(),
            "no injected name in the test binary ⇒ no section name"
        );
    }

    /// Round-trip through the exact reader the hook uses at install time.
    #[test]
    fn named_section_roundtrip() {
        let name = unique_section_name("roundtrip");
        let cfg = unique_cfg();
        let bytes = cfg.to_section_bytes().expect("config must encode");
        let _owner = publish_for_test(&name, &bytes);
        let got = try_load_session_config_named(&name).expect("config must decode");
        assert_eq!(got.pipe_name, cfg.pipe_name);
        assert_eq!(got.dll_path, cfg.dll_path);
        assert_eq!(got.overlay_roots, cfg.overlay_roots);
        assert!(!got.trace);
    }

    /// The guess-resistance core: with NO injected name, the install-time
    /// entry point must not open ANY section. Against the old behaviour this
    /// function opened `ipc::SESSION_CONFIG_SECTION_NAME` unconditionally —
    /// this test pins that a process which never received the name through
    /// the injection channel cannot even attempt a guess.
    #[test]
    fn no_injected_name_means_no_section_attempt() {
        assert!(session_section_name().is_none());
        assert_eq!(try_load_session_config_from_section(), None);
        assert!(PIPE_NAME.get().is_none());
    }

    /// Pin: the runtime (non-test) part of this module must not reference
    /// the retired legacy constant. Reintroducing a constant-name fallback
    /// (the exact defect this change removes) fails here.
    #[test]
    fn module_never_references_the_legacy_constant() {
        let src = include_str!("mod.rs");
        // Anchor on a `#[cfg(test)]` line DIRECTLY followed by `mod ` so the
        // indented `#[cfg(test)] _drop_probe` field attribute (test-only, but
        // part of the runtime struct) does not truncate the runtime slice.
        let runtime =
            &src[..src.find("#[cfg(test)]\nmod ").expect("test module anchor")];
        assert!(
            !runtime.contains("SESSION_CONFIG_SECTION_NAME"),
            "the hook must never open a well-known section name; the name can \
             only come from the injection channel (FS_SANDBOX_SECTION)"
        );
    }

    /// The guess-resistance core, made deterministic: even when a section
    /// DOES exist under the retired well-known constant, a process that
    /// never received the real session name must not read that decoy as its
    /// config. Old behaviour opened `ipc::SESSION_CONFIG_SECTION_NAME`
    /// unconditionally at fallback time, so this decoy would have been
    /// consumed and PIPE_NAME poisoned with the decoy's pipe name.
    #[test]
    fn decoy_under_legacy_constant_is_not_consumed_without_injected_name() {
        let legacy = ipc::SESSION_CONFIG_SECTION_NAME;

        // Refuse to run against a live object: an old-build launcher may
        // genuinely own the legacy name on this machine, and writing a decoy
        // into ITS section is not ours to do. (Probe first, skip if taken.)
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use winapi::shared::minwindef::FALSE;
        let wide: Vec<u16> = OsStr::new(legacy).encode_wide().chain(Some(0)).collect();
        // SAFETY: wide is a null-terminated UTF-16 name; read-only probe.
        let existing = unsafe {
            winapi::um::memoryapi::OpenFileMappingW(
                winapi::um::memoryapi::FILE_MAP_READ,
                FALSE,
                wide.as_ptr(),
            )
        };
        if !existing.is_null() {
            // SAFETY: existing is the valid handle just returned above.
            unsafe { winapi::um::handleapi::CloseHandle(existing) };
            return;
        }

        let cfg = unique_cfg();
        let bytes = cfg.to_section_bytes().expect("config must encode");
        let _decoy = publish_for_test(legacy, &bytes);

        // The invariant: with NO injected name the fallback must not open
        // ANY section — the decoy stays unread, PIPE_NAME stays unset.
        assert_eq!(try_load_session_config_from_section(), None);
        assert!(
            PIPE_NAME.get().is_none(),
            "a legacy-constant decoy must not poison PIPE_NAME when no name was injected"
        );
    }
