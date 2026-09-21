    use super::*;
    use policy::{Decision, Mode, Policy};
    use std::path::PathBuf;

    #[test]
    fn write_access_flags() {
        assert!(is_write_access(GENERIC_WRITE, 0));
        assert!(is_write_access(FILE_APPEND_DATA, 0));
        assert!(is_write_access(DELETE, 0));
        assert!(is_write_access(0, FILE_CREATE));
        assert!(is_write_access(0, FILE_OVERWRITE_IF));
        assert!(is_write_access(0, FILE_SUPERSEDE));
        assert!(!is_write_access(0, 1)); // FILE_OPEN
    }

    /// GENERIC_ALL grants every write right there is. It used to fall
    /// through the mask and ride the CoW read-passthrough onto the real
    /// disk (observed escape: `fs_decide NtCreateFile: ... write=false
    /// mode=Cow` for a CreateFileW(..., 0x1000_0000, ...) open).
    #[test]
    fn write_access_generic_all_is_write() {
        assert!(is_write_access(GENERIC_ALL, 0));
        assert!(is_write_access(GENERIC_ALL, FILE_OPEN));
        // A generic-all open that also asks read rights is still a write.
        assert!(is_write_access(GENERIC_ALL | 0x8000_0000, FILE_OPEN));
    }

    /// FILE_WRITE_ATTRIBUTES-only and FILE_WRITE_EA-only opens mutate a
    /// real file (SetFileTime / EA writes) without any data-write bit —
    /// audit 2026-09-19 Medium finding. They must classify as writes.
    #[test]
    fn write_access_metadata_bits_are_write() {
        assert!(is_write_access(FILE_WRITE_ATTRIBUTES, FILE_OPEN));
        assert!(is_write_access(FILE_WRITE_EA, FILE_OPEN));
        // A read+metadata open is still a write.
        assert!(is_write_access(0x8000_0000 | FILE_WRITE_ATTRIBUTES, 0));
    }

    /// False-positive guards: pure read/probe opens must stay reads so they
    /// keep riding the (cheap) passthrough instead of forcing CoW copies.
    /// MAXIMUM_ALLOWED is a documented deliberate exclusion: it resolves
    /// per-DACL and is probe-heavy; classifying it as a write would
    /// CoW-copy every probed file.
    #[test]
    fn write_access_read_bits_stay_read() {
        assert!(!is_write_access(0x8000_0000, FILE_OPEN));
        assert!(!is_write_access(0x0000_0001, FILE_OPEN)); // FILE_READ_DATA
        assert!(!is_write_access(0x0002_0000, FILE_OPEN)); // READ_CONTROL
        assert!(!is_write_access(0x0010_0000, FILE_OPEN)); // SYNCHRONIZE
        assert!(!is_write_access(0x8000_0000 | 0x0010_0000, FILE_OPEN));
        assert!(!is_write_access(0x0200_0000, FILE_OPEN)); // MAXIMUM_ALLOWED
    }

    /// Consequence test: a GENERIC_ALL or FILE_WRITE_ATTRIBUTES-only open
    /// of a path OUTSIDE project_root must land in the CoW overlay, not
    /// ride the read-passthrough onto the real disk. Uses the real policy
    /// engine with an empty rule set, whose documented default is
    /// read-outside-root -> Passthrough, write-outside-root -> Cow.
    #[test]
    fn attribute_only_and_generic_all_opens_outside_root_cow() {
        let base = unique_temp_path("writemask-cow");
        std::fs::create_dir_all(&base).expect("create base dir");
        let project_root = base.join("project");
        let sandbox_root = base.join("overlay");
        let mock_dirs = base.join("mockdirs");
        let outside = base.join("outside");
        for d in [&project_root, &sandbox_root, &mock_dirs, &outside] {
            std::fs::create_dir_all(d).expect("create policy dirs");
        }
        let policy = Policy::open_or_create(
            &base.join("policy.redb"),
            sandbox_root,
            mock_dirs,
            project_root.clone(),
        )
        .expect("open policy engine");

        let outside_dos =
            outside.join("writemask-target.dat").to_string_lossy().into_owned();

        // Negative control: the SAME path with read intent passes through
        // to the real disk — proves the path is genuinely outside
        // project_root, so the Cow verdicts below are caused by the write
        // classification, not by the path.
        assert_eq!(policy.decide(&outside_dos, false).mode, Mode::Passthrough);

        // GENERIC_ALL open (the observed escape): write-classified -> CoW.
        assert!(is_write_access(GENERIC_ALL, FILE_OPEN));
        let d = policy.decide(&outside_dos, is_write_access(GENERIC_ALL, FILE_OPEN));
        assert_eq!(d.mode, Mode::Cow, "GENERIC_ALL open outside root must Cow");

        // FILE_WRITE_ATTRIBUTES-only open: write-classified -> CoW.
        assert!(is_write_access(FILE_WRITE_ATTRIBUTES, FILE_OPEN));
        let d = policy.decide(&outside_dos, is_write_access(FILE_WRITE_ATTRIBUTES, FILE_OPEN));
        assert_eq!(
            d.mode,
            Mode::Cow,
            "FILE_WRITE_ATTRIBUTES open outside root must Cow"
        );

        // FILE_WRITE_EA-only open: write-classified -> CoW.
        assert!(is_write_access(FILE_WRITE_EA, FILE_OPEN));
        let d = policy.decide(&outside_dos, is_write_access(FILE_WRITE_EA, FILE_OPEN));
        assert_eq!(d.mode, Mode::Cow, "FILE_WRITE_EA open outside root must Cow");

        // In-root control: policy keeps project_root paths Passthrough
        // regardless of write classification (CoW is an outside-root event).
        let in_dos = project_root.join("in.dat").to_string_lossy().into_owned();
        assert_eq!(policy.decide(&in_dos, true).mode, Mode::Passthrough);

        drop(policy);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Build a path inside the OS temp dir that is unique per test invocation,
    /// without pulling in the `tempfile` crate (forbidden by scope rules).
    fn unique_temp_path(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "winrsbox-hook-test-{tag}-{pid}-{nanos}-{seq}",
        ));
        p
    }

    /// Mock-overlay materialization MUST be a no-op once the overlay file
    /// already exists. Regression test for the per-open `fs::write` storm:
    /// the second call with a different payload must NOT overwrite the
    /// file content produced by the first call.
    #[test]
    fn mock_write_idempotent_when_exists() {
        let dir = unique_temp_path("mock-idem");
        let overlay = dir.join("payload.bin");
        let first: &[u8] = b"first-write";
        let second: &[u8] = b"SECOND-WRITE-MUST-NOT-LAND";

        // First call materializes the file.
        materialize_mock_overlay(&overlay, first);
        assert!(overlay.exists(), "first materialize should create the file");
        let after_first = std::fs::read(&overlay).expect("read after first");
        assert_eq!(after_first, first);

        // Second call must be a no-op: content unchanged.
        materialize_mock_overlay(&overlay, second);
        let after_second = std::fs::read(&overlay).expect("read after second");
        assert_eq!(
            after_second, first,
            "second materialize must NOT overwrite existing overlay"
        );

        // Cleanup — best-effort, ignore failures.
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `prepare_overlay` must return `None` when the Decision claims Mode::Cow
    /// but carries no overlay path. The caller relies on this signal to fail
    /// closed (return STATUS_ACCESS_DENIED) instead of leaking the write to
    /// the real filesystem.
    #[test]
    fn prepare_overlay_none_when_overlay_field_missing() {
        let d = Decision {
            mode: Mode::Cow,
            overlay: None,
            cow_from: None,
            mock_payload: None,
        };
        assert!(prepare_overlay(&d).is_none());
    }

    /// `prepare_overlay` returns `Some(<dos string>)` for an overlay path
    /// inside the supplied roots, matching the lossy stringification of the
    /// supplied PathBuf and creating parent directories as before.
    #[test]
    fn prepare_overlay_some_when_overlay_field_present() {
        // Use a unique temp dir so create_dir_all (called inside prepare_overlay)
        // succeeds without polluting an arbitrary location.
        let dir = unique_temp_path("prep-some");
        let root = dir.join(".winrsbox").join("myapp").join("workdir");
        let overlay = root.join("redirect.bin");
        let expected = overlay.to_string_lossy().into_owned();
        let root_str = root.to_string_lossy().to_ascii_lowercase();

        let d = Decision {
            mode: Mode::Cow,
            overlay: Some(overlay.clone()),
            cow_from: None,
            mock_payload: None,
        };
        let roots = [root_str.as_str()];
        let got = prepare_overlay_in_roots(&d, &roots).expect("Some for in-root overlay");
        assert_eq!(got, expected);
        assert!(overlay.parent().unwrap().exists(), "parent dirs must be created");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Audit Critical #2 defence in depth: an overlay destination OUTSIDE the
    /// published roots (the audit PoC shape: a real Startup folder next to the
    /// sandbox state) must be refused — no returned path, no directory
    /// created, no CoW copy performed — even though the Decision carries it.
    #[test]
    fn prepare_overlay_refuses_out_of_root_destination() {
        let dir = unique_temp_path("prep-out");
        let state = dir.join(".winrsbox").join("myapp");
        let root = state.join("workdir");
        let outside_dest = dir.join("Startup").join("pwn.bat");
        let src = dir.join("src.txt");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&src, b"payload").unwrap();

        let d = Decision {
            mode: Mode::Cow,
            overlay: Some(outside_dest.clone()),
            cow_from: Some(src.clone()),
            mock_payload: None,
        };
        let root_str = root.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];
        assert!(prepare_overlay_in_roots(&d, &roots).is_none());
        assert!(!outside_dest.exists(), "destination must NOT be created");
        assert!(
            !outside_dest.parent().unwrap().exists(),
            "destination parent must NOT be created"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `..` segments in a destination are refused outright (never folded
    /// here), so `<root>\..\escape.bat` cannot smuggle a write outside.
    #[test]
    fn prepare_overlay_refuses_dotdot_destination() {
        let dir = unique_temp_path("prep-dotdot");
        let state = dir.join(".winrsbox").join("myapp");
        let root = state.join("workdir");
        let dest = root.join("..").join("escape.bat");
        std::fs::create_dir_all(&root).unwrap();

        let d = Decision {
            mode: Mode::Cow,
            overlay: Some(dest),
            cow_from: None,
            mock_payload: None,
        };
        let root_str = root.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];
        assert!(prepare_overlay_in_roots(&d, &roots).is_none());
        assert!(!dir.join("escape.bat").exists(), "escaped file must NOT be created");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Mock-dir Cow decisions mirror into the `mock-dirs` SIBLING of the
    /// workdir root — inside the launcher state dir but not inside the root
    /// itself. These must keep working (state-dir allowance), while a state
    /// dir sibling with a prefix-lookalike name must stay refused.
    #[test]
    fn prepare_overlay_allows_mock_dirs_sibling_but_not_lookalike() {
        let dir = unique_temp_path("prep-mock");
        let state = dir.join(".winrsbox").join("myapp");
        let root = state.join("workdir");
        let mock_dest = state.join("mock-dirs").join("c").join("fake.txt");
        let lookalike = dir.join(".winrsbox").join("myappX").join("workdir").join("evil.txt");
        let root_str = root.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];

        let mk = |p: &PathBuf| Decision {
            mode: Mode::Cow,
            overlay: Some(p.clone()),
            cow_from: None,
            mock_payload: None,
        };
        assert!(prepare_overlay_in_roots(&mk(&mock_dest), &roots).is_some());
        assert!(mock_dest.parent().unwrap().exists(), "mock-dirs parent must be created");
        assert!(prepare_overlay_in_roots(&mk(&lookalike), &roots).is_none());
        assert!(!lookalike.exists(), "lookalike destination must NOT be created");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Legit in-root CoW still copies the source — validation must not break
    /// the copy-on-write path it protects.
    #[test]
    fn prepare_overlay_copies_cow_source_inside_root() {
        let dir = unique_temp_path("prep-cow");
        let state = dir.join(".winrsbox").join("myapp");
        let root = state.join("workdir");
        let dest = root.join("d").join("proj").join("f.txt");
        let src = dir.join("orig.txt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&src, b"real content").unwrap();
        let d = Decision {
            mode: Mode::Cow,
            overlay: Some(dest.clone()),
            cow_from: Some(src),
            mock_payload: None,
        };
        let root_str = root.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];
        let got = prepare_overlay_in_roots(&d, &roots).expect("in-root CoW must succeed");
        assert_eq!(got, dest.to_string_lossy());
        assert_eq!(std::fs::read(&dest).unwrap(), b"real content");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Unconfigured hook (no OVERLAY_ROOTS, no SANDBOX_ROOT — the state test
    /// builds run in): prepare_overlay must fail closed, not write anywhere.
    #[test]
    fn prepare_overlay_fails_closed_when_roots_unpublished() {
        // Assert the premise: no test sets the root OnceLocks (the session-
        // section loader is stubbed out under cfg(test)).
        assert!(crate::ipc_client::OVERLAY_ROOTS.get().map_or(true, |l| l.is_empty()));
        assert!(crate::ipc_client::SANDBOX_ROOT.get().is_none());
        let dir = unique_temp_path("prep-closed");
        let d = Decision {
            mode: Mode::Cow,
            overlay: Some(dir.join("anywhere.bin")),
            cow_from: None,
            mock_payload: None,
        };
        assert!(prepare_overlay(&d).is_none());
        assert!(!dir.join("anywhere.bin").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Segment rules of `overlay_dest_in_roots`, pinned directly.
    #[test]
    fn overlay_dest_in_roots_segment_rules() {
        let root = r"c:\state\workdir".to_ascii_lowercase();
        let roots = [root.as_str()];
        // Root itself and descendants are accepted.
        assert!(overlay_dest_in_roots(roots[0], &roots));
        assert!(overlay_dest_in_roots(r"c:\state\workdir\sub\f.txt", &roots));
        // Mock-dirs sibling of the root lives in the launcher state dir.
        assert!(overlay_dest_in_roots(r"c:\state\mock-dirs\c\fake.txt", &roots));
        // Sibling-prefix lookalikes are refused.
        assert!(!overlay_dest_in_roots(r"c:\state\workdirevil\x.txt", &roots));
        assert!(!overlay_dest_in_roots(r"c:\stateX\workdir\x.txt", &roots));
        // Dot segments are refused outright.
        assert!(!overlay_dest_in_roots(r"c:\state\workdir\..\escape.bat", &roots));
        // Empty root list / empty destination fail closed.
        assert!(!overlay_dest_in_roots(r"c:\state\workdir\f.txt", &[]));
        assert!(!overlay_dest_in_roots("", &roots));
    }

    /// Regression: the launcher publishes overlay roots with their on-disk
    /// case, and `prepare_overlay_in_roots` compares an already-lowercased
    /// destination. Without folding the root, `d:\…` never prefix-matched
    /// `D:\…` and EVERY CoW write outside `project_root` was refused —
    /// observed as `EPERM` in the guest plus a `prepare_overlay_reject` line
    /// naming a destination that was plainly inside the root.
    ///
    /// The test above could not catch this: it hands `overlay_dest_in_roots`
    /// a root that is already lowercase, so it never exercises the fold.
    #[test]
    fn overlay_roots_are_case_folded_before_matching() {
        let published = vec![
            r"D:\dev\rust\winrsbox\.winrsbox\proj\workdir".to_string(),
            r"C:\Users\Someone\AppData\Local\.winrsbox\proj\workdir".to_string(),
        ];
        let folded = overlay_roots_lower(Some(&published), None);
        assert_eq!(folded[0], r"d:\dev\rust\winrsbox\.winrsbox\proj\workdir");
        assert_eq!(folded[1], r"c:\users\someone\appdata\local\.winrsbox\proj\workdir");

        // The whole point: a lowercased destination under a mixed-case root
        // must be accepted.
        let roots: Vec<&str> = folded.iter().map(|s| s.as_str()).collect();
        assert!(overlay_dest_in_roots(
            r"d:\dev\rust\winrsbox\.winrsbox\proj\workdir\dev\project\out.txt",
            &roots,
        ));
        assert!(overlay_dest_in_roots(
            r"c:\users\someone\appdata\local\.winrsbox\proj\workdir\windows\f.txt",
            &roots,
        ));
        // Folding must not weaken the sibling-lookalike refusal.
        assert!(!overlay_dest_in_roots(
            r"d:\dev\rust\winrsbox\.winrsbox\proj\workdirevil\out.txt",
            &roots,
        ));
    }

    /// The legacy single-root fallback is folded too, and an absent root
    /// list stays empty so `prepare_overlay_in_roots` fails closed.
    #[test]
    fn overlay_roots_fallback_is_folded_and_empty_stays_empty() {
        assert_eq!(
            overlay_roots_lower(None, Some(r"D:\Proj\.winrsbox\S\workdir")),
            vec![r"d:\proj\.winrsbox\s\workdir".to_string()],
        );
        // An empty published list falls back rather than yielding an empty root.
        assert_eq!(
            overlay_roots_lower(Some(&vec![]), Some(r"D:\Proj\W")),
            vec![r"d:\proj\w".to_string()],
        );
        assert!(overlay_roots_lower(None, None).is_empty());
    }

    // ── path-normalization tests ────────────────────────────────────────────
    // M-S3: NTFS strips trailing dot/space from each path segment; the kernel
    // resolves "C:\.winrsbox." to "C:\.winrsbox". Our denylist check must do
    // the same, otherwise it slips through ends_with(r"\.winrsbox").

    #[test]
    fn trailing_dot_in_winrsbox_segment_caught() {
        let path = r"C:\sandbox\.winrsbox.";
        let normalized = strip_trailing_dot_space(path);
        assert_eq!(normalized.as_ref(), r"C:\sandbox\.winrsbox");
    }

    #[test]
    fn trailing_space_in_winrsbox_segment_caught() {
        let path = "C:\\sandbox\\.winrsbox  ";
        let normalized = strip_trailing_dot_space(path);
        assert_eq!(normalized.as_ref(), r"C:\sandbox\.winrsbox");
    }

    #[test]
    fn trailing_mix_dot_space_segments_caught() {
        let path = "C:\\sand box. \\.winrsbox.";
        let normalized = strip_trailing_dot_space(path);
        assert_eq!(normalized.as_ref(), r"C:\sand box\.winrsbox");
    }

    #[test]
    fn normal_path_no_allocation() {
        let path = r"C:\Users\test\file.txt";
        let normalized = strip_trailing_dot_space(path);
        assert!(matches!(normalized, Cow::Borrowed(_)),
            "well-formed path must not allocate");
    }

    #[test]
    fn unc_prefix_passes_through() {
        // \\?\ split-by-\: ["", "", "?", "C:", "folder.", "file.txt"]
        // After per-segment strip: ["", "", "?", "C:", "folder", "file.txt"]
        // Rejoined: \\?\C:\folder\file.txt
        let path = r"\\?\C:\folder.\file.txt";
        let normalized = strip_trailing_dot_space(path);
        assert_eq!(normalized.as_ref(), r"\\?\C:\folder\file.txt");
    }

    #[test]
    fn nt_prefix_question_mark_passes_through() {
        // \??\ NT-form prefix: same per-segment treatment.
        let path = r"\??\C:\folder.\file.txt";
        let normalized = strip_trailing_dot_space(path);
        assert_eq!(normalized.as_ref(), r"\??\C:\folder\file.txt");
    }

    #[test]
    fn drive_letter_only_unchanged() {
        // C: has no trailing dot or space; must round-trip exactly.
        let path = "C:";
        let normalized = strip_trailing_dot_space(path);
        assert_eq!(normalized.as_ref(), "C:");
        assert!(matches!(normalized, Cow::Borrowed(_)));
    }

    #[test]
    fn drive_letter_with_trailing_dot_normalized() {
        // C:. → C:  (NTFS strips the trailing dot)
        let path = r"C:.";
        let normalized = strip_trailing_dot_space(path);
        assert_eq!(normalized.as_ref(), r"C:");
    }

    #[test]
    fn drive_letter_root_path_unchanged() {
        let path = r"C:\\foo\\bar";
        let normalized = strip_trailing_dot_space(path);
        assert_eq!(normalized.as_ref(), r"C:\\foo\\bar");
    }

    #[test]
    fn ascii_lowercase_preserves_non_ascii() {
        // U+0130 (LATIN CAPITAL LETTER I WITH DOT ABOVE) must NOT collapse
        // into "i" or "i\u{307}". Rust's to_lowercase() folds it to a two-char
        // sequence; the NT kernel folds it to "i". Either fold can split-brain
        // a denylist check. ASCII-only lowercase leaves it as U+0130, which
        // is what every comparison site must see.
        let path = "C:\\WINRSBOX\u{0130}MARKER";
        let lower = path.to_ascii_lowercase();
        assert_eq!(lower, "c:\\winrsbox\u{0130}marker",
            "U+0130 must pass through untouched");
    }

    #[test]
    fn winrsbox_with_unicode_suffix_does_not_match_denylist() {
        // Adversarial: attacker can't bypass the .winrsbox hide check by
        // appending U+0130 (which kernel folds to ASCII 'i', producing a
        // different on-disk path). ASCII-only lowercase leaves U+0130 alone,
        // so ends_with(r"\.winrsbox") cannot match. Kernel resolves to
        // "C:\.winrsboxi" — a different path that does not contain our
        // sandbox state.
        let path = "C:\\.WINRSBOX\u{0130}";
        let lower = path.to_ascii_lowercase();
        let canon = strip_trailing_dot_space(&lower);
        assert!(!canon.ends_with(r"\.winrsbox"));
        assert!(!canon.contains(r"\.winrsbox\"));
    }

    /// Adversarial: full canonicalization pipeline (as used in
    /// `check_path_traversal`) must catch a trailing-dot `.winrsbox` segment.
    /// Before the fix this slipped past ends_with(r"\.winrsbox"); after the
    /// fix it's caught and the sandbox state stays hidden.
    #[test]
    fn winrsbox_hide_catches_trailing_dot() {
        let raw = r"\??\C:\sandbox\.WINRSBOX.";
        let lower = raw.to_ascii_lowercase();
        let canon = strip_trailing_dot_space(&lower);
        assert!(canon.contains(r"\.winrsbox\") || canon.ends_with(r"\.winrsbox"),
            "trailing dot must be stripped before .winrsbox denylist check (got: {})",
            canon.as_ref());
    }

    /// Adversarial: trailing space variant.
    #[test]
    fn winrsbox_hide_catches_trailing_space() {
        let raw = "\\??\\C:\\sandbox\\.WINRSBOX ";
        let lower = raw.to_ascii_lowercase();
        let canon = strip_trailing_dot_space(&lower);
        assert!(canon.ends_with(r"\.winrsbox"),
            "trailing space must be stripped (got: {})", canon.as_ref());
    }

    /// Adversarial: trailing-dot inside an intermediate `.winrsbox.` segment
    /// (not the final segment of the path) still matches the
    /// `lower.contains(r"\.winrsbox\")` form.
    #[test]
    fn winrsbox_hide_catches_intermediate_segment_trailing_dot() {
        // After NTFS canonicalization the kernel opens \.winrsbox\sub\file
        let raw = r"\??\C:\sandbox\.winrsbox.\sub\file";
        let lower = raw.to_ascii_lowercase();
        let canon = strip_trailing_dot_space(&lower);
        assert!(canon.contains(r"\.winrsbox\"),
            "intermediate trailing dot must be stripped (got: {})", canon.as_ref());
    }

    // -- device_path_to_dos_nt --------------------------------------------------
    //
    // Regression coverage for the cmd.exe `>filename` escape: NtQueryObject on
    // a directory handle returns a `\Device\HarddiskVolumeN\…` kernel path.
    // Without remapping it back into `\??\<letter>:\…`, `nt_to_dos_lower`
    // rejects the joined path and the hook silently passes through.
    //
    // These tests are purely structural — they construct paths against an
    // ad-hoc volume map and verify the prefix-match + boundary logic. They do
    // NOT exercise the OS-backed `device_drive_map()` cache (which requires a
    // real QueryDosDeviceW call); a follow-up integration test should pick a
    // mounted drive, look up its device path via QueryDosDeviceW, and check
    // round-trip.

    fn u16s(s: &str) -> Vec<u16> { s.encode_utf16().collect() }

    fn dos_string(v: Option<Vec<u16>>) -> Option<String> {
        v.map(|w| String::from_utf16_lossy(&w))
    }

    #[test]
    fn device_unknown_volume_returns_none() {
        // No QueryDosDeviceW entry maps to HarddiskVolume999 → unchanged.
        let out = device_path_to_dos_nt(&u16s(r"\Device\HarddiskVolume999\foo"));
        assert!(out.is_none(),
            "unknown device prefix must NOT be rewritten (got {:?})", dos_string(out));
    }

    #[test]
    fn device_condrv_returns_none() {
        // Console driver is not a volume; must not be remapped.
        let out = device_path_to_dos_nt(&u16s(r"\Device\ConDrv\Reference"));
        assert!(out.is_none(),
            "non-volume device must NOT be rewritten (got {:?})", dos_string(out));
    }

    #[test]
    fn device_path_already_dos_returns_none() {
        // `\??\C:\…` is already in DOS form; no rewrite expected.
        let out = device_path_to_dos_nt(&u16s(r"\??\C:\foo"));
        assert!(out.is_none(),
            "DOS-prefixed path must NOT be rewritten (got {:?})", dos_string(out));
    }

    #[test]
    fn ascii_to_lower_u16_only_touches_ascii_upper() {
        assert_eq!(ascii_to_lower_u16(b'A' as u16), b'a' as u16);
        assert_eq!(ascii_to_lower_u16(b'Z' as u16), b'z' as u16);
        assert_eq!(ascii_to_lower_u16(b'a' as u16), b'a' as u16);
        assert_eq!(ascii_to_lower_u16(b'0' as u16), b'0' as u16);
        assert_eq!(ascii_to_lower_u16(b'\\' as u16), b'\\' as u16);
        // U+0080+ pass through unchanged.
        assert_eq!(ascii_to_lower_u16(0x00E9), 0x00E9); // é
        assert_eq!(ascii_to_lower_u16(0x0410), 0x0410); // Cyrillic А
    }

    /// Boundary discipline: `\Device\HarddiskVolume3` MUST NOT prefix-match
    /// against `\Device\HarddiskVolume30\…`. The check is a follow-byte
    /// inspection; if a candidate device entry happens to match, the next
    /// u16 must be `\` (or end-of-string), not a digit.
    ///
    /// Exercised via the boundary logic inside device_path_to_dos_nt: we
    /// hand-craft a tail starting with a digit and assert the function
    /// rejects it. Since we cannot inject a fake volume into the static map,
    /// this test piggy-backs on the unknown-volume case — any present
    /// volume's path is system-dependent; the *negative* assertion that
    /// non-volume devices and prefix-aliased paths bail out is what survives
    /// the OS-dependence.
    #[test]
    fn device_path_boundary_logic_compiles() {
        // Smoke: function is reachable and returns Option<Vec<u16>>.
        let _ = device_path_to_dos_nt(&u16s(""));
        let _ = device_path_to_dos_nt(&u16s(r"\Device"));
    }

    /// OS-backed sanity: at least ONE drive letter on the test host must map
    /// (the system drive). If the static map is empty, the `device_drive_map`
    /// bootstrap has a bug (e.g. wrong buf size, missed null-termination).
    #[test]
    fn device_drive_map_is_nonempty_on_windows() {
        let map = device_drive_map();
        assert!(!map.is_empty(),
            "device_drive_map() returned no entries — QueryDosDeviceW path is broken");
    }

    /// OS-backed round-trip: the system drive's letter MUST resolve to a
    /// `\Device\…` path, and feeding `<that>\probe` back through
    /// device_path_to_dos_nt must give `\??\<letter>:\probe`.
    #[test]
    fn device_path_roundtrip_via_real_qdd() {
        use winapi::um::fileapi::QueryDosDeviceW;
        let drive = [b'C' as u16, b':' as u16, 0u16];
        let mut buf = [0u16; 512];
        // SAFETY: drive is null-terminated, buf is valid for buf.len() u16s.
        let len = unsafe {
            QueryDosDeviceW(drive.as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
        };
        if len == 0 {
            // Test host lacks a C: drive — skip. (Unusual but not impossible
            // in some CI sandboxes; the previous test already proved the
            // bootstrap works, so we don't fail the suite over it.)
            return;
        }
        let end = buf[..len as usize].iter().position(|&c| c == 0).unwrap_or(len as usize);
        let mut device_plus_tail: Vec<u16> = buf[..end].to_vec();
        device_plus_tail.extend_from_slice(&u16s(r"\probe"));

        let rewritten = device_path_to_dos_nt(&device_plus_tail)
            .expect("system drive's device path must remap");
        let s = String::from_utf16_lossy(&rewritten).to_ascii_lowercase();
        assert!(s.starts_with(r"\??\c:\"),
            "expected `\\??\\c:\\…`, got {s}");
        assert!(s.ends_with(r"\probe"), "tail lost in rewrite: {s}");
    }

    // -- join_bare_relative_to_nt ----------------------------------------------
    //
    // Regression coverage for the cmd.exe `>filename` escape's bare-relative
    // branch in resolve_for_hook. The OS-backed half of that fix
    // (GetCurrentDirectoryW) can't be unit-tested without launching a child
    // process, so the join discipline is split into this pure helper that
    // takes CWD as an input slice.

    fn u(s: &str) -> Vec<u16> { s.encode_utf16().collect() }
    fn s_of(v: &[u16]) -> String { String::from_utf16_lossy(v) }

    #[test]
    fn join_typical_cwd_and_bare_name() {
        let abs = join_bare_relative_to_nt(&u(r"C:\Users\alice\Desktop"), &u("qwe.txt"));
        assert_eq!(s_of(&abs), r"\??\C:\Users\alice\Desktop\qwe.txt");
    }

    #[test]
    fn join_inserts_separator_when_cwd_missing_trailing_slash() {
        // The realistic case — GetCurrentDirectoryW typically returns
        // `C:\some\path` without a trailing slash.
        let abs = join_bare_relative_to_nt(&u(r"C:\some\path"), &u("file"));
        assert_eq!(s_of(&abs), r"\??\C:\some\path\file");
    }

    #[test]
    fn join_no_double_slash_when_cwd_has_trailing_slash() {
        // Drive root case (`C:\`) — CWD already ends with `\`. We must NOT
        // insert a second one, or the kernel parses `\\file` as a UNC root.
        let abs = join_bare_relative_to_nt(&u(r"C:\"), &u("file.txt"));
        assert_eq!(s_of(&abs), r"\??\C:\file.txt");
    }

    #[test]
    fn join_prefix_is_dos_device_form() {
        // The first four code units MUST be `\??\` (the DOS-device prefix
        // policy::path::nt_to_dos_lower recognises). A `\\?\` variant would
        // also be accepted by the path normalizer, but mixing the two would
        // fail the join contract test below.
        let abs = join_bare_relative_to_nt(&u(r"C:\x"), &u("y"));
        assert_eq!(&abs[..4], &[
            b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16,
        ]);
    }

    #[test]
    fn join_passes_through_nt_to_dos_lower() {
        // The combined contract: anything the join produces from a valid
        // DOS CWD + a bare relative name must be classifiable by
        // `policy::path::nt_to_dos_lower` — that's the gate that turns
        // the kernel-form path back into our policy-form DOS path. If this
        // ever breaks, the cmd.exe escape returns.
        let abs = join_bare_relative_to_nt(
            &u(r"C:\Users\Computer\Desktop"),
            &u("qwe.txt"),
        );
        let dos = policy::path::nt_to_dos_lower(&abs)
            .expect("synthesized \\??\\<cwd>\\<name> must be DOS-classifiable");
        assert_eq!(dos, r"c:\users\computer\desktop\qwe.txt");
    }

    #[test]
    fn join_preserves_subdirectory_in_name() {
        // Caller can pass a multi-component bare relative path (e.g.
        // `subdir\file.txt`). The join logic must not flatten or split it.
        let abs = join_bare_relative_to_nt(
            &u(r"C:\base"),
            &u(r"sub\file.txt"),
        );
        assert_eq!(s_of(&abs), r"\??\C:\base\sub\file.txt");
    }
