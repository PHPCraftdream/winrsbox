
// ---------------------------------------------------------------------------
// C1/C2 regression — resolved-path denylist catches .winrsbox in joined paths
// ---------------------------------------------------------------------------
    use super::*;

    #[test]
    fn resolved_winrsbox_relative_caught() {
        let joined = r"c:\sandbox\.winrsbox\policy.json";
        let canon = canonicalize_for_denylist(joined);
        assert!(
            canonical_denylist_status(&canon).is_some(),
            ".winrsbox in resolved DOS path must be denied"
        );
    }

    #[test]
    fn resolved_winrsbox_bare_segment_caught() {
        let joined = r"c:\sandbox\.winrsbox";
        let canon = canonicalize_for_denylist(joined);
        assert!(canonical_denylist_status(&canon).is_some());
    }

    #[test]
    fn resolved_normal_path_not_blocked() {
        let joined = r"c:\sandbox\src\main.rs";
        let canon = canonicalize_for_denylist(joined);
        assert!(canonical_denylist_status(&canon).is_none());
    }

    #[test]
    fn canonicalize_already_canonical_borrows() {
        let p = r"c:\sandbox\src\main.rs";
        assert!(
            matches!(canonicalize_for_denylist(p), Cow::Borrowed(_)),
            "already-canonical path must return Cow::Borrowed (zero alloc)"
        );
    }

    #[test]
    fn canonicalize_folds_forward_slash() {
        let p = r"c:/sandbox/src/main.rs";
        let canon = canonicalize_for_denylist(p);
        assert!(matches!(canon, Cow::Owned(_)));
        assert_eq!(&*canon, r"c:\sandbox\src\main.rs");
    }

    #[test]
    fn canonicalize_lowercases_uppercase() {
        let p = r"C:\Sandbox\SRC\Main.RS";
        let canon = canonicalize_for_denylist(p);
        assert!(matches!(canon, Cow::Owned(_)));
        assert_eq!(&*canon, r"c:\sandbox\src\main.rs");
    }

    #[test]
    fn canonicalize_strips_trailing_dot() {
        let p = r"c:\sandbox\src.\main.rs";
        let canon = canonicalize_for_denylist(p);
        assert!(matches!(canon, Cow::Owned(_)));
        // Reference: old algorithm
        let lowered = p.to_ascii_lowercase().replace('/', "\\");
        let reference = strip_trailing_dot_space(&lowered);
        assert_eq!(&*canon, &*reference);
    }

    /// The Owned (needs-change) branch MUST produce byte-for-byte the same
    /// output as the original `s.to_ascii_lowercase().replace('/', "\\")`
    /// then `strip_trailing_dot_space`. Non-ASCII chars must be preserved
    /// verbatim (NOT per-byte mojibake'd into U+0080..U+00FF). This path has
    /// an uppercase ASCII letter (forcing the Owned branch) AND a non-ASCII
    /// segment, which is exactly where a per-byte fold would diverge.
    #[test]
    fn canonicalize_preserves_non_ascii_on_owned_branch() {
        let p = "C:\\Users\\Ω\\Naïve/Файл.TXT";
        let canon = canonicalize_for_denylist(p);
        assert!(matches!(canon, Cow::Owned(_)));
        // Reference: exactly the pre-optimization algorithm.
        let lowered = p.to_ascii_lowercase().replace('/', "\\");
        let reference = strip_trailing_dot_space(&lowered).into_owned();
        assert_eq!(&*canon, reference,
            "Owned branch must match the original transform byte-for-byte, \
             preserving non-ASCII UTF-8");
        // And the non-ASCII chars survive as real chars (not mojibake).
        assert!(canon.contains('ω') || canon.contains('Ω'),
            "Greek omega must survive the fold as a real char");
        assert!(canon.contains('ф') || canon.contains('Ф'),
            "Cyrillic char must survive the fold");
    }

    /// A path that is already canonical EXCEPT it contains a non-ASCII char
    /// must still borrow (the non-ASCII char itself triggers no transform).
    #[test]
    fn canonicalize_non_ascii_already_canonical_borrows() {
        let p = "c:\\users\\наvöl\\file.txt"; // lowercase, no slash, no trailing dot/space
        assert!(
            matches!(canonicalize_for_denylist(p), Cow::Borrowed(_)),
            "lowercase non-ASCII path with no '/' or trailing dot/space must borrow"
        );
    }

    #[test]
    fn device_volume_classified_as_harddisk() {
        let path = r"\device\harddiskvolume3\windows\system32";
        assert_eq!(
            policy::dev::classify_device(path),
            policy::dev::DeviceKind::HarddiskVolume,
        );
    }

    #[test]
    fn device_volume_not_unknown() {
        let path = r"device\harddiskvolume1\users\test\file.txt";
        assert!(
            !matches!(
                policy::dev::classify_device(path),
                policy::dev::DeviceKind::Unknown
            ),
            "HarddiskVolume must not be Unknown (would be blocked by check_device_block already)"
        );
    }
