use super::*;
use super::inspect::InspectedStr;

#[test]
fn ms_windows_store_uri_denied() {
    assert!(is_shell_target_denied(
        "ms-windows-store://app/0123"
    ));
}

#[test]
fn ms_settings_uri_denied_case_insensitive() {
    assert!(is_shell_target_denied("MS-Settings:network"));
    assert!(is_shell_target_denied("ms-SETTINGS:privacy"));
    assert!(is_shell_target_denied("Ms-Settings:"));
}

#[test]
fn shell_appsfolder_aumid_denied() {
    assert!(is_shell_target_denied(
        "shell:AppsFolder\\Microsoft.WindowsCalculator_8wekyb3d8bbwe!App"
    ));
    // Forward-slash variant — some callers normalize the separator.
    assert!(is_shell_target_denied(
        "shell:appsfolder/Microsoft.WindowsCalculator_8wekyb3d8bbwe!App"
    ));
    // Case-insensitive on the scheme/folder name.
    assert!(is_shell_target_denied(
        "SHELL:APPSFOLDER\\Microsoft.WindowsCalculator_8wekyb3d8bbwe!App"
    ));
}

#[test]
fn runas_scheme_denied() {
    assert!(is_shell_target_denied("runas:c:\\windows\\notepad.exe"));
    assert!(is_shell_target_denied("RunAs:something"));
}

#[test]
fn benign_targets_not_denied() {
    // Plain filesystem path.
    assert!(!is_shell_target_denied("C:\\Windows\\notepad.exe"));
    // Web URI — intentionally allowed (see module docs).
    assert!(!is_shell_target_denied("https://example.com"));
    assert!(!is_shell_target_denied("http://example.com/page"));
    // Empty string.
    assert!(!is_shell_target_denied(""));
    // Non-shell-app prefix that just happens to start with "shell:".
    assert!(!is_shell_target_denied("shell:Downloads"));
    // A scheme that shares a prefix with a denied scheme but is distinct.
    assert!(!is_shell_target_denied("ms-mybrand:foo"));
    // A short non-matching token.
    assert!(!is_shell_target_denied("a"));
}

#[test]
fn coverage_of_every_listed_prefix() {
    // Smoke-check every entry in SHELL_DENY_PREFIXES so a typo in the
    // table is caught at test time. We append a trivial "x" suffix so
    // each test target actually has the prefix plus something.
    for p in SHELL_DENY_PREFIXES {
        let mut t = String::from(*p);
        t.push('x');
        assert!(
            is_shell_target_denied(&t),
            "expected to be denied: {}",
            t
        );
        // Uppercased variant must also match.
        let t_upper: String = t.to_ascii_uppercase();
        assert!(
            is_shell_target_denied(&t_upper),
            "expected to be denied (uppercased): {}",
            t_upper
        );
    }
}

/// Hook smoke: a null `lp_file` for ShellExecuteW must NOT be denied —
/// the classifier returns false for null / empty strings, leaving the
/// original API to handle the malformed call. This locks in the
/// "let original surface its own error" behavior.
#[test]
fn null_target_not_denied_by_classifier() {
    // Direct classifier check — no FFI needed.
    assert!(!is_shell_target_denied(""));
}

/// `read_lpcwstr` must report `Absent` for a null pointer (no UB, no
/// panic) — same semantics the old `Option::None` return had.
#[test]
fn read_lpcwstr_handles_null() {
    // SAFETY: explicitly passing a null pointer to test the null-path.
    let result = unsafe { read_lpcwstr(std::ptr::null()) };
    assert!(matches!(result, InspectedStr::Absent));
}

/// `read_lpcwstr` must correctly decode a normal null-terminated UTF-16
/// buffer constructed in Rust, reporting it as a fully inspected `Value`.
#[test]
fn read_lpcwstr_decodes_terminated_buffer() {
    let s: Vec<u16> = "ms-settings:network\0".encode_utf16().collect();
    // SAFETY: `s` is a properly null-terminated UTF-16 buffer that lives
    // for the duration of this call.
    let decoded = unsafe { read_lpcwstr(s.as_ptr()) };
    match decoded {
        InspectedStr::Value(v) => assert_eq!(v, "ms-settings:network"),
        other => panic!("expected InspectedStr::Value, got {other:?}"),
    }
}

/// Pin the size of `SHELL_DENY_PREFIXES`. Update this number deliberately
/// when adding or removing entries.
#[test]
fn shell_deny_list_count_pinned() {
    assert_eq!(SHELL_DENY_PREFIXES.len(), 37);
}

/// Sanity check: `PREFIX_INSPECT_CHARS` must be large enough to cover the
/// longest denylist entry. `microsoft-edge-holographic:` is 27 chars.
#[test]
fn prefix_inspect_chars_accommodates_longest_entry() {
    let longest = SHELL_DENY_PREFIXES
        .iter()
        .map(|s| s.len())
        .max()
        .unwrap_or(0);
    assert!(
        longest <= PREFIX_INSPECT_CHARS,
        "longest denylist entry ({longest}) exceeds PREFIX_INSPECT_CHARS ({PREFIX_INSPECT_CHARS})"
    );
}

/// New schemes added in H2/H3: Microsoft Edge variants.
#[test]
fn microsoft_edge_uri_denied() {
    assert!(is_shell_target_denied("microsoft-edge:https://evil.example/"));
    assert!(is_shell_target_denied("MICROSOFT-EDGE:about:blank"));
    assert!(is_shell_target_denied("microsoft-edge-holographic:foo"));
}

/// New schemes: tel / sms / webcal / mailto handlers.
#[test]
fn telephony_and_calendar_schemes_denied() {
    assert!(is_shell_target_denied("tel:+15555550100"));
    assert!(is_shell_target_denied("sms:+15555550100?body=hi"));
    assert!(is_shell_target_denied("webcal://example.com/cal.ics"));
    assert!(is_shell_target_denied("mailto:alice@example.com"));
}

/// New schemes: news / feed / nntp / search-ms.
#[test]
fn news_feed_search_schemes_denied() {
    assert!(is_shell_target_denied("feed://example.com/rss"));
    assert!(is_shell_target_denied("news:alt.test"));
    assert!(is_shell_target_denied("nntp://news.example.com/group"));
    assert!(is_shell_target_denied("search-ms:query=test"));
}

/// New schemes: third-party app activations.
#[test]
fn third_party_app_schemes_denied() {
    assert!(is_shell_target_denied("steam://run/12345"));
    assert!(is_shell_target_denied("epicgames://launch"));
    assert!(is_shell_target_denied("spotify:track:abc"));
    assert!(is_shell_target_denied("discord://invite/foo"));
    assert!(is_shell_target_denied("slack://open"));
    assert!(is_shell_target_denied("zoommtg://zoom.us/join?confno=123"));
    assert!(is_shell_target_denied("msteams://teams.microsoft.com/l/team/..."));
}

/// `lpParameters` substring scan: explorer.exe + shell:AppsFolder\... and
/// cmd.exe + /c start ms-windows-store://... must both deny via the
/// params channel.
#[test]
fn lp_parameters_uri_denied() {
    // Classic escape: launcher target is benign, payload hides in args.
    assert!(is_shell_params_denied("shell:AppsFolder\\evil"));
    assert!(is_shell_params_denied("/c start ms-windows-store://app/0"));
    // shell_deny_reason should report `params` (not `file`) for these;
    // an empty verb is the default-verb launch path and stays allowed.
    assert_eq!(
        shell_deny_reason("", "explorer.exe", "shell:AppsFolder\\evil"),
        Some("params")
    );
    assert_eq!(
        shell_deny_reason("", "cmd.exe", "/c start ms-windows-store://app/0"),
        Some("params")
    );
    // Confirms case-insensitive substring scan picks up an embedded URI.
    assert!(is_shell_params_denied(
        "/c \"start MICROSOFT-EDGE:https://evil/\""
    ));
}

/// Benign parameters must not be denied — guards against regressions
/// where the params substring scan would flag harmless text.
#[test]
fn lp_parameters_benign_not_denied() {
    assert!(!is_shell_params_denied("/c echo hello"));
    assert!(!is_shell_params_denied("--flag value"));
    assert!(!is_shell_params_denied(""));
    // File-only deny still works through the combined helper (empty verb
    // is allowed, so the file verdict surfaces unchanged).
    assert_eq!(
        shell_deny_reason("", "ms-settings:network", "/c echo hi"),
        Some("file")
    );
    assert_eq!(shell_deny_reason("", "notepad.exe", "/c echo hi"), None);
}

/// Coverage mirror for the WinRT side (lives in com_guard) — verifies
/// every shell deny prefix matches via the params substring scan as well.
/// Renamed to match the requested test name.
#[test]
fn coverage_of_every_listed_winrt_prefix_via_params() {
    for p in SHELL_DENY_PREFIXES {
        // Embed the prefix inside a benign-looking parameter string.
        let wrapped = format!("/c start {p}target");
        assert!(
            is_shell_params_denied(&wrapped),
            "expected params to be denied: {wrapped}"
        );
    }
}

// -----------------------------------------------------------------
// M6 — Unicode-scheme detection.
// -----------------------------------------------------------------

/// A scheme whose name contains a non-ASCII homoglyph/fold (here U+1E9E
/// LATIN CAPITAL SHARP S inside `R...NAS:`) is flagged as suspicious so it
/// cannot slip past the ASCII byte-wise denylist.
#[test]
fn unicode_scheme_runas_denied() {
    assert!(is_suspicious_unicode_scheme("R\u{1E9E}NAS:x"));
}

/// A plain ASCII scheme is NOT flagged by the Unicode check — it is the
/// `SHELL_DENY_PREFIXES` denylist's job to match `runas:` and friends.
#[test]
fn ascii_scheme_not_flagged_by_unicode_check() {
    assert!(!is_suspicious_unicode_scheme("runas:x"));
    // And the denylist does catch it, confirming separation of concerns.
    assert!(is_shell_target_denied("runas:x"));
}

/// A drive-letter path with a Unicode filename must NOT be flagged: the
/// only early colon is the `C:` drive letter, which is explicitly exempt.
#[test]
fn drive_letter_path_not_flagged() {
    assert!(!is_suspicious_unicode_scheme("C:\\Users\\документ.txt"));
    // Lowercase drive letter too.
    assert!(!is_suspicious_unicode_scheme("d:\\папка\\файл.txt"));
}

/// A UNC path with a Unicode filename and no early colon must NOT be
/// flagged (step 2 returns false when no `:` precedes path separators).
#[test]
fn unicode_filename_no_scheme_not_flagged() {
    assert!(!is_suspicious_unicode_scheme("\\\\server\\share\\документ.txt"));
}

/// A plain relative path with no colon at all is not a scheme.
#[test]
fn plain_relative_path_not_flagged() {
    assert!(!is_suspicious_unicode_scheme("notepad.exe"));
}

/// Extra coverage: an all-ASCII relative path that contains a colon only
/// AFTER a separator (so the first colon is not in a scheme position) is
/// not treated as a Unicode scheme. The first `:` is found before the
/// backslash here, but the scheme portion is ASCII, so step 5 applies.
#[test]
fn ascii_scheme_with_unicode_after_colon_not_flagged() {
    // ASCII scheme, Unicode only in the opaque part → handled by denylist,
    // not by the Unicode-scheme check.
    assert!(!is_suspicious_unicode_scheme("mailto:документ@пример.рф"));
}

/// Empty input is never a scheme.
#[test]
fn empty_not_flagged_as_unicode_scheme() {
    assert!(!is_suspicious_unicode_scheme(""));
}

/// The combined `shell_deny_reason` reports `unicode_scheme` for a
/// homoglyph scheme passed via `lpFile`, and still reports `file` /
/// `params` for ASCII denylist hits.
#[test]
fn shell_deny_reason_reports_unicode_scheme() {
    assert_eq!(
        shell_deny_reason("", "R\u{1E9E}NAS:notepad.exe", ""),
        Some("unicode_scheme")
    );
    // ASCII denylist hit still wins as `file`.
    assert_eq!(shell_deny_reason("", "runas:x", ""), Some("file"));
    // Benign drive-letter path with Unicode filename → not denied.
    assert_eq!(
        shell_deny_reason("", "C:\\Users\\документ.txt", "/c echo hi"),
        None
    );
}

// -----------------------------------------------------------------
// code-quality #1 — SHELLEXECUTEINFOW cbSize validation.
// -----------------------------------------------------------------

/// Documents the layout invariant the `hook_shell_execute_ex_w` cbSize
/// guard relies on: a write of `hInstApp` is in-bounds only when the
/// caller's `cbSize` is at least `offset_of!(hInstApp) + size_of::<HINSTANCE>()`.
/// If a fabricated struct's `cbSize` is smaller than that, the hook must
/// deny WITHOUT writing `hInstApp` (return FALSE only). We cannot easily
/// exercise the detoured FFI path in a `--lib` unit test (the detour is
/// not installed), so we lock the offset arithmetic that drives that
/// decision here.
#[test]
fn cbsize_too_small_does_not_write_past_struct() {
    let full = core::mem::size_of::<SHELLEXECUTEINFOW>();
    let hinstapp_off = core::mem::offset_of!(SHELLEXECUTEINFOW, hInstApp);
    let hinstapp_end = hinstapp_off + core::mem::size_of::<HINSTANCE>();

    // hInstApp must lie fully inside the struct.
    assert!(hinstapp_end <= full, "hInstApp field extends past struct end");
    // The field has non-zero size and a non-zero offset (it is not the
    // first field), so a too-small struct really can omit it.
    assert!(hinstapp_off > 0);

    // Mirror the runtime decision for a few representative cbSize values.
    let writes_hinstapp = |cb: usize| cb >= hinstapp_end;
    // A struct truncated before hInstApp must NOT be written.
    assert!(!writes_hinstapp(hinstapp_off));
    assert!(!writes_hinstapp(hinstapp_end - 1));
    assert!(!writes_hinstapp(0));
    // A full / oversized struct may be written.
    assert!(writes_hinstapp(hinstapp_end));
    assert!(writes_hinstapp(full));
    assert!(writes_hinstapp(full + 16));
}

/// `is_shell_params_denied` must not panic on multi-byte UTF-8 input that
/// crosses the 1024-byte scan cap.
#[test]
fn params_scan_handles_multibyte_boundary() {
    // Build a >1024-byte string whose 1024th byte falls inside a
    // multi-byte character. Each '€' is 3 UTF-8 bytes.
    let mut s = String::new();
    while s.len() < 1100 {
        s.push('€');
    }
    // Must not panic; benign content should not match.
    assert!(!is_shell_params_denied(&s));
}

// -----------------------------------------------------------------
// FIX 2 — lpVerb allowlist classification.
// -----------------------------------------------------------------

/// `runas` (any ASCII casing) must classify as an escalation verb —
/// the UAC-elevation twin of the already-denied `runas:` URI scheme.
#[test]
fn runas_verb_classified_as_escalation() {
    assert_eq!(shell_verb_deny_reason("runas"), Some("verb_escalation"));
    assert_eq!(shell_verb_deny_reason("RunAs"), Some("verb_escalation"));
    assert_eq!(shell_verb_deny_reason("RUNAS"), Some("verb_escalation"));
}

/// Locks in every allowlist decision. `runasadmin` proves the match is
/// EXACT (a prefix match would wrongly inherit `runas`'s verdict), and
/// the Cyrillic-а homoglyph proves non-ASCII lookalikes fail closed.
#[test]
fn shell_verbs_allowlist_decisions() {
    // Allowed: the default verb (also what a NULL lpVerb decodes to via
    // `InspectedStr::as_deref` of `Absent`) and ordinary association
    // dispatch — ASCII case-insensitive in every casing.
    assert_eq!(shell_verb_deny_reason(""), None);
    assert_eq!(shell_verb_deny_reason("open"), None);
    assert_eq!(shell_verb_deny_reason("OPEN"), None);
    assert_eq!(shell_verb_deny_reason("Open"), None);
    assert_eq!(shell_verb_deny_reason("edit"), None);
    assert_eq!(shell_verb_deny_reason("print"), None);
    // Explorer-hosted shell UI — different-parent escape surface.
    assert_eq!(shell_verb_deny_reason("explore"), Some("verb_explorer"));
    assert_eq!(shell_verb_deny_reason("EXPLORE"), Some("verb_explorer"));
    assert_eq!(shell_verb_deny_reason("find"), Some("verb_explorer"));
    // Exact-match proof: NOT prefix-matched against `runas`.
    assert_eq!(shell_verb_deny_reason("runasadmin"), Some("verb_unknown"));
    // Not a verb at all.
    assert_eq!(shell_verb_deny_reason("frobnicate"), Some("verb_unknown"));
    // Homoglyph lookalike (Cyrillic а U+0430) must not pass as `runas`.
    assert_eq!(shell_verb_deny_reason("run\u{430}s"), Some("verb_unknown"));
}

/// The combined gate must consult the verb FIRST: `runas` denies even
/// with a benign target, while an allowed verb leaves the pre-existing
/// file / params verdicts untouched.
#[test]
fn shell_deny_reason_reports_runas_escalation() {
    assert_eq!(
        shell_deny_reason("runas", "notepad.exe", ""),
        Some("verb_escalation")
    );
    assert_eq!(shell_deny_reason("open", "notepad.exe", "/c echo hi"), None);
}

// -----------------------------------------------------------------
// FIX 1 — full-params scan + fail-closed inspection verdict.
// -----------------------------------------------------------------

/// Regression for the old 1024-byte scan cutoff: a payload pushed past
/// byte 1024 (behind whitespace padding) was never seen and sailed
/// through. The full-string scan must deny it both via the direct
/// params classifier and through the combined gate.
#[test]
fn padded_params_beyond_old_1024_cutoff_denied() {
    // The dangerous URI starts past byte 1024.
    let padded = format!("{}{}", " ".repeat(1100), "/c start ms-windows-store://app/0");
    assert!(is_shell_params_denied(&padded));
    assert_eq!(shell_deny_reason("", "cmd.exe", &padded), Some("params"));
}

/// The reader must refuse to hand back a truncated view: with no NUL in
/// range the result is `Unterminated` (fail-closed input for
/// `uninspected_deny_reason`), never a silently cut 4096-unit string.
/// Boundary cases: NUL at index 4095 → `Value` of 4095 chars; NUL at
/// index 4096 (cap reached first) → `Unterminated`.
#[test]
fn unterminated_lpcwstr_is_refused() {
    // 5000 non-zero units, no terminator anywhere within the cap.
    let no_nul: Vec<u16> = vec![0x41u16; 5000];
    // SAFETY: `no_nul` outlives the call; the reader's scan is bounded
    // by `MAX_TARGET_CHARS`, well inside this allocation.
    let r = unsafe { read_lpcwstr(no_nul.as_ptr()) };
    assert!(matches!(r, InspectedStr::Unterminated));

    // Just under the cap: 4095 'A' units + NUL at index 4095 → Value.
    let under: Vec<u16> = {
        let mut v = vec![0x41u16; MAX_TARGET_CHARS - 1];
        v.push(0);
        v
    };
    // SAFETY: NUL-terminated buffer that outlives the call.
    let r = unsafe { read_lpcwstr(under.as_ptr()) };
    match r {
        InspectedStr::Value(s) => assert_eq!(s.chars().count(), MAX_TARGET_CHARS - 1),
        other => panic!("expected InspectedStr::Value, got {other:?}"),
    }

    // Exactly at the cap: 4096 'A' units + NUL at index 4096 — the scan
    // hits MAX_TARGET_CHARS before seeing the terminator → Unterminated.
    let at_cap: Vec<u16> = {
        let mut v = vec![0x41u16; MAX_TARGET_CHARS];
        v.push(0);
        v
    };
    // SAFETY: buffer outlives the call; the bounded scan stops at the cap.
    let r = unsafe { read_lpcwstr(at_cap.as_ptr()) };
    assert!(matches!(r, InspectedStr::Unterminated));
}

/// `uninspected_deny_reason` must refuse the whole call when ANY argument
/// is `Unterminated` (checked file → params → verb, so the log names the
/// first such argument), and let an all-inspected call through to the
/// classifier chain.
#[test]
fn uninspected_argument_denies_call() {
    let verb = InspectedStr::Value("open".into());
    let file = InspectedStr::Value("notepad.exe".into());
    let params = InspectedStr::Value("/c echo hi".into());
    // All fully inspected → no refusal here.
    assert_eq!(uninspected_deny_reason(&verb, &file, &params), None);
    // Each position in isolation, in file → params → verb precedence.
    assert_eq!(
        uninspected_deny_reason(&verb, &InspectedStr::Unterminated, &params),
        Some("uninspected_file")
    );
    assert_eq!(
        uninspected_deny_reason(&verb, &file, &InspectedStr::Unterminated),
        Some("uninspected_params")
    );
    assert_eq!(
        uninspected_deny_reason(&InspectedStr::Unterminated, &file, &params),
        Some("uninspected_verb")
    );
    // Multiple Unterminated args still report the highest-precedence tag.
    assert_eq!(
        uninspected_deny_reason(
            &InspectedStr::Unterminated,
            &InspectedStr::Unterminated,
            &params
        ),
        Some("uninspected_file")
    );
}

// -----------------------------------------------------------------
// Sibling-entry closure (audit High): ShellExecuteA / ShellExecuteExA
// must reach the same classifier chain as the W hooks. The direct
// hook-body calls below take the DENY path, which returns before the
// trampoline is ever touched (the detour is not installed under --lib
// tests), so they are safe to drive here. Benign calls are asserted
// only through the seam fn — a None verdict through the hook body
// would call the (uninstalled) trampoline.
// -----------------------------------------------------------------

/// NUL-terminated ANSI buffer for fabricating LPCSTR arguments.
fn ansi_buf(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

#[test]
fn read_lpcstr_decodes_terminated_buffer() {
    let s = ansi_buf("ms-settings:network");
    // SAFETY: `s` is a NUL-terminated ANSI buffer outliving the call.
    let decoded = unsafe { read_lpcstr(s.as_ptr()) };
    match decoded {
        InspectedStr::Value(v) => assert_eq!(v, "ms-settings:network"),
        other => panic!("expected InspectedStr::Value, got {other:?}"),
    }
}

#[test]
fn read_lpcstr_absent_for_null_and_empty() {
    // SAFETY: explicit null-pointer path.
    let r = unsafe { read_lpcstr(std::ptr::null()) };
    assert!(matches!(r, InspectedStr::Absent));
    let empty = b"\0".to_vec();
    // SAFETY: zero-length terminated buffer outlives the call.
    let r = unsafe { read_lpcstr(empty.as_ptr()) };
    assert!(matches!(r, InspectedStr::Absent));
}

#[test]
fn read_lpcstr_unterminated_beyond_cap() {
    let no_nul = vec![0x41u8; MAX_TARGET_CHARS + 8];
    // SAFETY: buffer outlives the call; the scan is bounded by the cap.
    let r = unsafe { read_lpcstr(no_nul.as_ptr()) };
    assert!(matches!(r, InspectedStr::Unterminated));
}

#[test]
fn shell_execute_a_seam_classifies_like_the_w_chain() {
    let verb_none = std::ptr::null();
    let file_settings = ansi_buf("ms-settings:network");
    let file_benign = ansi_buf(r"C:\Windows\notepad.exe");
    let params_store = ansi_buf("/c start ms-windows-store://app/0");
    let verb_runas = ansi_buf("runas");

    // SAFETY: all pointers are valid NUL-terminated buffers or null.
    unsafe {
        assert_eq!(
            shell_execute_a_deny_reason(verb_none, file_settings.as_ptr(), std::ptr::null()),
            Some("file")
        );
        assert_eq!(
            shell_execute_a_deny_reason(verb_runas.as_ptr(), file_benign.as_ptr(), std::ptr::null()),
            Some("verb_escalation")
        );
        assert_eq!(
            shell_execute_a_deny_reason(verb_none, file_benign.as_ptr(), params_store.as_ptr()),
            Some("params")
        );
        // Benign call: every classifier declines — the A hook would let
        // the original run (asserted via the seam, not the hook body).
        assert_eq!(
            shell_execute_a_deny_reason(verb_none, file_benign.as_ptr(), std::ptr::null()),
            None
        );
    }
}

#[test]
fn shell_execute_a_hook_denies_dangerous_target() {
    let file = ansi_buf("MS-Settings:network");
    // SAFETY: deny path returns SE_ERR_ACCESSDENIED without touching the
    // (uninstalled) trampoline.
    let got = unsafe {
        hook_shell_execute_a(
            std::ptr::null_mut(), // hwnd
            std::ptr::null(),     // lpOperation (default verb)
            file.as_ptr(),        // lpFile
            std::ptr::null(),     // lpParameters
            std::ptr::null(),     // lpDirectory
            0,                    // nShowCmd
        )
    };
    assert_eq!(got as usize, SE_ERR_ACCESSDENIED, "A hook must deny via lpFile");
}

#[test]
fn shell_execute_a_hook_denies_unterminated_argument() {
    // Fail-closed parity with the W hook: an lpFile with no NUL within
    // the inspection cap must refuse the whole call.
    let file = vec![0x41u8; MAX_TARGET_CHARS + 8];
    // SAFETY: deny path returns before call_original.
    let got = unsafe {
        hook_shell_execute_a(
            std::ptr::null_mut(),
            std::ptr::null(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    assert_eq!(got as usize, SE_ERR_ACCESSDENIED, "uninspected lpFile must deny");
}

#[test]
fn shell_execute_ex_a_hook_denies_and_sets_hinstapp() {
    let verb = ansi_buf("open");
    let file = ansi_buf(r"runas:c:\x");
    let mut info = SHELLEXECUTEINFOA {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOA>() as u32,
        fMask: 0,
        hwnd: std::ptr::null_mut(),
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: std::ptr::null(),
        lpDirectory: std::ptr::null(),
        nShow: 0,
        hInstApp: std::ptr::null_mut(),
    };
    // SAFETY: deny path writes only our own fabricated struct's hInstApp
    // and returns FALSE without touching the trampoline.
    let got = unsafe { hook_shell_execute_ex_a(&mut info) };
    assert_eq!(got, FALSE, "ExA hook must deny the runas target");
    assert_eq!(
        info.hInstApp as usize, SE_ERR_ACCESSDENIED,
        "denial must be reported via hInstApp per the shellapi contract"
    );
}

#[test]
fn shell_execute_ex_a_too_small_cbsize_denies_without_hinstapp_write() {
    let file = ansi_buf("ms-settings:network");
    // cbSize covers up to lpParameters but NOT hInstApp.
    let lpparameters_end =
        (core::mem::offset_of!(SHELLEXECUTEINFOA, lpParameters)
            + core::mem::size_of::<*const u8>()) as u32;
    let mut info = SHELLEXECUTEINFOA {
        cbSize: lpparameters_end,
        fMask: 0,
        hwnd: std::ptr::null_mut(),
        lpVerb: std::ptr::null(),
        lpFile: file.as_ptr(),
        lpParameters: std::ptr::null(),
        lpDirectory: std::ptr::null(),
        nShow: 0,
        hInstApp: std::ptr::null_mut(),
    };
    // SAFETY: deny path; the struct is our own stack allocation and the
    // hook must NOT write hInstApp past the declared cbSize.
    let got = unsafe { hook_shell_execute_ex_a(&mut info) };
    assert_eq!(got, FALSE, "truncated struct must still be denied");
    assert!(
        info.hInstApp.is_null(),
        "hInstApp must NOT be written when cbSize cannot hold it"
    );
}

/// Export-name tripwire: a typo'd / renamed shell32 export silently
/// skips its detour (all installers log-and-skip). Pin resolution.
#[test]
fn shell_a_exports_resolve_in_shell32() {
    // SAFETY: GetProcAddress wrapper over LoadLibraryW("shell32.dll");
    // safe outside DllMain constraints in tests.
    unsafe {
        for name in [
            b"ShellExecuteW\0".as_slice(),
            b"ShellExecuteExW\0".as_slice(),
            b"ShellExecuteA\0".as_slice(),
            b"ShellExecuteExA\0".as_slice(),
        ] {
            let addr = shell32_export(name);
            let name_str = String::from_utf8_lossy(name);
            assert!(addr.is_some(), "shell32 export must resolve: {name_str}");
        }
    }
}
