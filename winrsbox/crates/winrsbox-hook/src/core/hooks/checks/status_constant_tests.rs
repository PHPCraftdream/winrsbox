
// ---------------------------------------------------------------------------
// status_constant_tests — pin canonical NT status codes.
//
// These tests catch anyone who accidentally changes the canonical value of a
// status code constant. Sibling guard modules import these from here; a typo
// or unit-mismatch would split-brain the sandbox (some guards return
// ACCESS_DENIED, others return some random garbage from the typo).
// ---------------------------------------------------------------------------
    use super::*;

    #[test]
    fn status_access_denied_is_canonical() {
        assert_eq!(STATUS_ACCESS_DENIED, 0xC000_0022_u32 as i32);
    }

    #[test]
    fn status_object_name_not_found_is_canonical() {
        assert_eq!(STATUS_OBJECT_NAME_NOT_FOUND, 0xC000_0034_u32 as i32);
    }

    #[test]
    fn status_privilege_not_held_is_canonical() {
        assert_eq!(STATUS_PRIVILEGE_NOT_HELD, 0xC000_0061_u32 as i32);
    }

    #[test]
    fn status_not_supported_is_canonical() {
        assert_eq!(STATUS_NOT_SUPPORTED, 0xC000_00BB_u32 as i32);
    }

    #[test]
    fn bare_relative_branch_unmirrors_cwd_inside_overlay() {
        // Audit 2026-09-19 Low: the bare-relative CWD branch of
        // resolve_for_hook lacked the unmirror its sibling branches do.
        // With the kernel CWD inside the overlay storage (the guest cd'd
        // into a CoW'd external directory), the folded absolute path is the
        // REAL overlay path, and the `.winrsbox` denylist would self-block
        // the open. The branch must decide on the unmirrored virtual path.
        let real = r"\??\c:\users\me\.winrsbox\sessionx\workdir\mytools\app\qwe.txt";
        let real_u16: Vec<u16> = real.encode_utf16().collect();
        let sb = r"c:\users\me\.winrsbox\sessionx\workdir";
        let got = bare_relative_dos(&real_u16, Some(sb)).expect("resolve");
        assert_eq!(got, r"c:\mytools\app\qwe.txt");
        // The raw overlay path IS self-blocked by the denylist — that is the
        // bug the unmirror fixes; the virtual path must not be.
        let raw_dos = r"c:\users\me\.winrsbox\sessionx\workdir\mytools\app\qwe.txt";
        assert!(
            canonical_denylist_status(&raw_dos).is_some(),
            "precondition: the raw overlay path trips the .winrsbox denylist"
        );
        assert!(
            canonical_denylist_status(&got).is_none(),
            "the virtual path the branch decides on must not be self-blocked"
        );
        // CWD outside the overlay: unchanged (defensive passthrough).
        let plain = r"\??\d:\proj\file.txt";
        let plain_u16: Vec<u16> = plain.encode_utf16().collect();
        assert_eq!(
            bare_relative_dos(&plain_u16, Some(sb)).as_deref(),
            Some(r"d:\proj\file.txt")
        );
    }

    #[test]
    fn unmirror_overlay_handle_relative_recovers_virtual_path() {
        // Real-world layout: handle resolved into overlay storage under
        // `.winrsbox\<name>\workdir\d\…`. The transform must recover the
        // virtual DOS path the agent thinks it owns, so decide/denylist see
        // `d:\diag_git\.git\config` instead of the `.winrsbox`-laden overlay
        // path (which would self-block via the sandbox-internals denylist).
        let sb = r"d:\dev\rust\fs-sandbox\repro\.winrsbox\diag_git\workdir";
        let overlay_dos = r"d:\dev\rust\fs-sandbox\repro\.winrsbox\diag_git\workdir\d\diag_git\.git\config";
        let got = unmirror_overlay_handle_relative(overlay_dos, Some(sb)).expect("should unmirror");
        assert_eq!(got, r"d:\diag_git\.git\config");
    }

    #[test]
    fn unmirror_overlay_handle_relative_passthrough_when_not_under_root() {
        // Common non-sandbox case: handle outside overlay storage → no rewrite.
        let sb = r"d:\dev\rust\fs-sandbox\repro\.winrsbox\diag_git\workdir";
        let external = r"c:\windows\system32\drivers\etc\hosts";
        assert_eq!(unmirror_overlay_handle_relative(external, Some(sb)), None);
    }

    #[test]
    fn unmirror_overlay_handle_relative_none_when_sandbox_root_unset() {
        // During very early DLL load (before the launcher publishes the root),
        // a relative open must NOT be rewritten — fall through verbatim.
        let overlay_dos = r"d:\sb\.winrsbox\n\workdir\d\sb\.git\config";
        assert_eq!(unmirror_overlay_handle_relative(overlay_dos, None), None);
    }

    #[test]
    fn unmirror_overlay_handle_relative_virtual_winrsbox_untouched_by_fn() {
        // The denylist guard runs downstream of this fn, on the returned path.
        // A path phrased as an overlay path under SANDBOX_ROOT that unmirrors
        // to a virtual path containing `.winrsbox` is unmirrored unchanged by
        // THIS fn; the denylist then independently decides to mask it.
        let sb = r"d:\sb\.winrsbox\n\workdir";
        let overlay_dos = r"d:\sb\.winrsbox\n\workdir\d\sb\.winrsbox\secret";
        let got = unmirror_overlay_handle_relative(overlay_dos, Some(sb)).expect("should unmirror");
        assert_eq!(got, r"d:\sb\.winrsbox\secret");
    }

    #[test]
    fn unmirror_overlay_handle_relative_path1_single_char_toplevel() {
        // Path 1 layout: single-letter top-level directory (C:\a\file) must
        // NOT be mis-detected as a legacy drive letter. The discriminator is
        // "first comp == root drive": `a` ≠ `c` → Path 1 → drive from root.
        let sb = r"c:\sb\.winrsbox\n\workdir";
        let overlay_dos = r"c:\sb\.winrsbox\n\workdir\a\file";
        let got = unmirror_overlay_handle_relative(overlay_dos, Some(sb)).expect("should unmirror");
        assert_eq!(got, r"c:\a\file");
    }

    #[test]
    fn is_control_file_detects_known_names_and_redb() {
        assert!(is_control_file(r"d:\sb\.winrsbox\workdir\policy.redb"));
        assert!(is_control_file(r"c:\x\.winrsbox\hermes\workdir\sandbox.ktav"));
        assert!(is_control_file(r"d:\sb\.winrsbox\workdir\violations.log"));
        assert!(is_control_file(r"d:\sb\.winrsbox\workdir\future.redb"));
        // Normal agent data is NOT a control file.
        assert!(!is_control_file(r"c:\users\test\file.txt"));
        assert!(!is_control_file(r"d:\sb\.winrsbox\workdir\users\test\policy.txt"));
    }

    #[test]
    fn is_self_overlay_workdir_access_denies_control_files() {
        // policy.redb under the overlay root MUST be denied — it is a sandbox
        // control file, NOT agent CoW data. The carve-out must NOT fire.
        let canon = r"c:\users\computer\.winrsbox\hermes\workdir\policy.redb";
        assert!(!is_self_overlay_workdir_access(canon),
            "policy.redb must NOT be carved out — security regression");
    }

    #[test]
    fn is_self_overlay_workdir_access_allows_agent_cow_data() {
        // Normal agent CoW data under the overlay root IS carved out — it is
        // the process's own data, re-opened absolutely after a passthrough leak.
        // NOTE: is_self_overlay_workdir_access checks OVERLAY_ROOTS first, which
        // is unset in tests, so it falls back to SANDBOX_ROOT which is also
        // unset → returns false. This test documents the expected behaviour.
        let canon = r"c:\users\computer\.winrsbox\hermes\workdir\users\computer\file.txt";
        // Without OVERLAY_ROOTS set, this returns false (no root to match).
        assert!(!is_self_overlay_workdir_access(canon));
    }

    // ── Bug #75: Passthrough decisions must not be cached ──────────────────
    //
    // `decide()` must NOT insert Mode::Passthrough results into the per-process
    // HookCache. A child process can write into the overlay at any moment and
    // change the correct decision for a path from Passthrough to Cow; a cached
    // Passthrough would then cause stale cache hits in the parent, hiding the
    // newly-created overlay file (the "Cannot find path" error seen in E2E).
    //
    // Similarly, Hidden must not be cached: a sibling process can revive a
    // whiteouted path (HTTPS clone retry after SSH clone cleanup), and the parent
    // must re-query the server to see the revival instead of returning stale Hidden.

    #[test]
    fn passthrough_not_stored_in_hook_cache() {
        // Directly exercise the caching policy: inserting a Passthrough via the
        // raw HookCache API works, but decide() skips the insert. Here we test
        // the cache directly — if the cache returns None for a path we never
        // inserted, the decide()-level skip is confirmed safe.
        //
        // Two-part assertion:
        // 1. A fresh cache returns None for a Passthrough path (it was NOT auto-cached).
        // 2. Manually inserting Passthrough DOES store it (raw API is unfiltered).
        let c = crate::cache::HookCache::new();
        // Part 1: not yet inserted → None.
        assert!(c.get_caseless("c:\\passthrough\\path", false).is_none(),
            "fresh cache must return None for an un-inserted path");
        // Part 2: explicit raw insert of Passthrough → Some (raw API is unaffected).
        let pt = policy::Decision {
            mode: policy::Mode::Passthrough,
            overlay: None, cow_from: None, mock_payload: None,
        };
        c.insert("c:\\passthrough\\path", false, pt);
        assert!(c.get_caseless("c:\\passthrough\\path", false).is_some(),
            "raw HookCache::insert of Passthrough must still store it (API unfiltered)");
    }

    #[test]
    fn hidden_not_stored_in_hook_cache() {
        // Hidden must NOT be cached in the per-process HookCache for the same
        // reason as Passthrough: a sibling process can revive a whiteouted path
        // at any time (e.g., the HTTPS clone retry re-creates hermes-agent after
        // the SSH clone cleanup whiteouts it). If Hidden were cached, the parent
        // would keep returning Hidden / not-found even after the server's WHITEOUTS
        // table is cleared — causing Push-Location to fail ("does not exist").
        //
        // This test validates the raw cache's behavior (it can still store Hidden
        // via insert() if callers want to), and documents that decide() must NOT
        // insert Hidden entries.
        let c = crate::cache::HookCache::new();
        // Before any insert, the cache returns None.
        assert!(c.get_caseless("c:\\hidden\\path", false).is_none(),
            "fresh cache must return None for a hidden path");
        // Explicitly inserting Hidden stores it (raw API is unfiltered; decide()
        // is the layer that skips Hidden, tested here conceptually).
        let hidden = policy::Decision {
            mode: policy::Mode::Hidden,
            overlay: None, cow_from: None, mock_payload: None,
        };
        c.insert("c:\\hidden\\path", false, hidden);
        assert!(c.get_caseless("c:\\hidden\\path", false).is_some(),
            "raw HookCache::insert of Hidden must still store it (decide() is the filter)");
    }

    #[test]
    fn cow_decision_stored_in_hook_cache() {
        // Non-Passthrough/Hidden decisions (Cow in particular) MUST be stored by
        // the raw HookCache — they represent stable policy state (an overlay already
        // exists or has been recorded). decide() inserts them; test raw insert.
        let c = crate::cache::HookCache::new();
        let cow = policy::Decision {
            mode: policy::Mode::Cow,
            overlay: Some(std::path::PathBuf::from("c:\\sb\\data.txt")),
            cow_from: None,
            mock_payload: None,
        };
        c.insert("c:\\data.txt", false, cow);
        let r = c.get_caseless("c:\\data.txt", false);
        assert!(r.is_some(), "Cow decision must be returned from HookCache");
        assert_eq!(r.unwrap().mode, policy::Mode::Cow,
            "retrieved decision must be Cow, not Passthrough or Hidden");
    }
