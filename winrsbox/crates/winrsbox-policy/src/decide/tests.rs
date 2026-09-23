use super::{cache_key, path_contained_in, db, Mode, PathBuf, Policy, Snapshot};

/// Build a real Policy exactly like lib.rs tests do: fresh redb db,
/// sandbox/mock-dirs/project dirs inside one tempfile::TempDir. The TempDir
/// is returned so it stays alive (it deletes itself on drop).
fn make_policy() -> (tempfile::TempDir, Policy) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("policy.redb");
    let sandbox = dir.path().join("sb");
    let mock_dirs = dir.path().join("md");
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&sandbox).unwrap();
    std::fs::create_dir_all(&mock_dirs).unwrap();
    std::fs::create_dir_all(&project).unwrap();
    let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
    (dir, p)
}

#[test]
fn path_contained_exact_match() {
    assert!(path_contained_in(r"c:\proj", r"c:\proj"));
    assert!(path_contained_in(r"c:\proj", r"c:\proj\"));
}

#[test]
fn path_contained_subdir_match() {
    assert!(path_contained_in(r"c:\proj\src\main.rs", r"c:\proj"));
}

#[test]
fn path_not_contained_sibling_prefix() {
    // The bug this guards against: a sibling dir whose name starts with
    // the root must NOT be treated as inside the root.
    assert!(!path_contained_in(r"c:\projevil\file", r"c:\proj"));
    assert!(!path_contained_in(r"c:\projects\foo", r"c:\proj"));
    assert!(!path_contained_in(r"c:\proj.txt", r"c:\proj"));
}

#[test]
fn path_not_contained_disjoint() {
    assert!(!path_contained_in(r"c:\other", r"c:\proj"));
}

#[test]
fn path_contained_empty_root_refused() {
    // An empty/unset root must never match every path.
    assert!(!path_contained_in(r"c:\any\path", ""));
    assert!(!path_contained_in(r"c:\any\path", r"\"));
}

#[test]
fn cache_key_write_flag_differs() {
    assert_ne!(cache_key("foo", false, None, None), cache_key("foo", true, None, None));
}

#[test]
fn cache_key_case_sensitive() {
    assert_ne!(cache_key("FOO", false, None, None), cache_key("foo", false, None, None));
}

#[test]
fn cache_key_deterministic() {
    assert_eq!(cache_key("a", false, None, None), cache_key("a", false, None, None));
}

// ── Composite cache key tests ────────────────────────────────────────────

#[test]
fn composite_key_different_depth() {
    let k1 = cache_key("c:\\test", false, Some(0), None);
    let k2 = cache_key("c:\\test", false, Some(1), None);
    assert_ne!(k1, k2, "different depth must produce different keys");
}

#[test]
fn composite_key_different_exe() {
    let k1 = cache_key("c:\\test", false, None, Some("app.exe"));
    let k2 = cache_key("c:\\test", false, None, Some("other.exe"));
    assert_ne!(k1, k2, "different exe must produce different keys");
}

#[test]
fn composite_key_none_vs_some_zero_depth() {
    let k_none = cache_key("c:\\test", false, None, None);
    let k_zero = cache_key("c:\\test", false, Some(0), None);
    assert_ne!(k_none, k_zero, "None vs Some(0) depth must differ (tag byte)");
}

#[test]
fn composite_key_none_vs_some_empty_exe() {
    let k_none = cache_key("c:\\test", false, None, None);
    let k_empty = cache_key("c:\\test", false, None, Some(""));
    assert_ne!(k_none, k_empty, "None vs Some(\"\") exe must differ");
}

#[test]
fn composite_key_same_params_equal() {
    let k1 = cache_key("c:\\path\\file.txt", true, Some(2), Some("app.exe"));
    let k2 = cache_key("c:\\path\\file.txt", true, Some(2), Some("app.exe"));
    assert_eq!(k1, k2, "identical params must produce identical keys");
}

#[test]
fn composite_key_collision_sanity() {
    let mut keys = std::collections::HashSet::new();
    for i in 0u8..250 {
        for d in [None, Some(i % 5)] {
            let exe_name = format!("exe{}.bin", i);
            let exe_opt: Option<&str> = if i % 3 == 0 { None } else { Some(&exe_name) };
            let k = cache_key(
                &format!("c:\\path\\file{}", i),
                i % 2 == 0,
                d,
                exe_opt,
            );
            assert!(keys.insert(k), "collision at i={i} d={d:?}");
        }
    }
    assert!(keys.len() >= 400, "expected ~500 unique keys, got {}", keys.len());
}

// ── Dot-fold decide regression tests (audit Critical #1) ───────────────

#[test]
fn decide_dotdot_escape_write_is_cow_not_passthrough() {
    let (_dir, p) = make_policy();
    // Same crate → may read the pub(crate) field directly.
    let root = p.inner.project_root_lower.clone();
    // THE regression: unfixed, `d:\<root>\..\..\outside.exe` prefix-matches
    // the root and is classified Passthrough, while the kernel resolves the
    // `..` segments and creates the file on the real disk outside the
    // sandbox. After the lexical fold it must be isolated (Cow).
    let escape = format!(r"{}\..\..\outside.exe", root);
    let d = p.decide(&escape, true);
    assert_ne!(d.mode, Mode::Passthrough, "dotdot escape must NOT be Passthrough (audit Critical #1)");
    assert_eq!(d.mode, Mode::Cow);
    let ov = d.overlay.as_ref().expect("Cow decision must carry an overlay path");
    assert!(!ov.to_string_lossy().contains(".."), "overlay path {ov:?} must not contain '..'");
}

#[test]
fn decide_dotdot_inside_root_still_passthrough() {
    let (_dir, p) = make_policy();
    let root = p.inner.project_root_lower.clone();
    // Legitimate callers with `..` inside the root keep working.
    let inside = format!(r"{}\sub\..\file.txt", root);
    let d = p.decide(&inside, true);
    assert_eq!(d.mode, Mode::Passthrough);
}

#[test]
fn decide_curdir_inside_root_still_passthrough() {
    let (_dir, p) = make_policy();
    let root = p.inner.project_root_lower.clone();
    let inside = format!(r"{}\.\file.txt", root);
    let d = p.decide(&inside, true);
    assert_eq!(d.mode, Mode::Passthrough);
}

#[test]
fn decide_dotdot_sibling_after_root_is_cow() {
    let (_dir, p) = make_policy();
    let root = p.inner.project_root_lower.clone();
    // `<root>\..\sibling.txt` resolves to root's parent → outside → Cow.
    let sibling = format!(r"{}\..\sibling.txt", root);
    let d = p.decide(&sibling, true);
    assert_eq!(d.mode, Mode::Cow);
}

#[test]
fn path_contained_refuses_unfolded_dot_segments() {
    // Fail-closed backstop: unfolded `.`/`..` segments are refused.
    assert!(!path_contained_in(r"c:\proj\..\..\x", r"c:\proj"));
    assert!(!path_contained_in(r"c:\proj\sub\..\f", r"c:\proj"));
    assert!(!path_contained_in(r"c:/proj/../x", r"c:\proj"));
    // Pinned positive: the boundary logic is unchanged for clean paths.
    assert!(path_contained_in(r"c:\proj\sub", r"c:\proj"));
}

// ── Case-fold consistency (canonical NTFS-identity fold, S11) ───────────
//
// The policy side folds every path with the canonical NTFS-identity fold
// (kernel upcase/downcase tables via ntdll, see path::case_fold). Under
// that fold U+0130 (İ) is IDENTITY — the kernel table does not fold it —
// so a policy-key writer that Unicode-folds instead (Rust's locale-aware
// to_lowercase maps İ to "i\u{307}") produces keys a non-ASCII path can
// never read back: a containment-relevant inconsistency. This test pins
// the policy side to the canonical fold.

#[test]
fn overlay_index_non_ascii_write_then_read_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("policy.redb");
    let sandbox = dir.path().join("sb");
    let mock_dirs = dir.path().join("md");
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&sandbox).unwrap();
    std::fs::create_dir_all(&mock_dirs).unwrap();
    std::fs::create_dir_all(&project).unwrap();
    let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();

    let orig = "d:\\ext\\Klas\u{0130}r\\DOSYA.txt";
    let target = r"d:\sb\ov\target.bin";
    p.record_overlay(orig, target).unwrap();

    let d = p.decide(orig, false);
    assert_eq!(d.mode, Mode::Cow);
    assert_eq!(d.overlay, Some(PathBuf::from(target)));
}

#[test]
fn decide_exe_scoped_rule_matches_lowercased_exe() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("policy.redb");
    let sandbox = dir.path().join("sb");
    let mock_dirs = dir.path().join("md");
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&sandbox).unwrap();
    std::fs::create_dir_all(&mock_dirs).unwrap();
    std::fs::create_dir_all(&project).unwrap();

    {
        let rdb = redb::Database::create(&db_path).unwrap();
        { let txn = rdb.begin_write().unwrap(); txn.open_table(db::RULES).unwrap(); txn.commit().unwrap(); }
        db::rule_upsert(&rdb, &db::RuleRow {
            id: "deny-locked".into(),
            prefix: r"d:\locked".into(),
            mode_read: db::RuleMode::Deny,
            mode_write: db::RuleMode::Deny,
            when: Some(db::WhenFilter { depth: None, exe: Some(r"C:\Tools\MyApp.EXE".into()) }),
        }).unwrap();
    } // drop the raw handle before the Policy opens the same file

    let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
    let d = p.decide_with_context(r"d:\locked\f.txt", true, None, Some(r"c:\tools\myapp.exe"));
    assert_eq!(d.mode, Mode::Deny);
}

// ── RecordOverlay wire validation (audit Critical #2) ──────────────────

#[test]
fn validate_record_overlay_accepts_canonical_mirror() {
    let (_dir, p) = make_policy();
    let orig = r"d:\proj\f.txt";
    let mirror =
        crate::path::mirror_into_overlay_layout(orig, &p.inner.overlay_layout);
    let mirror_str = mirror.to_string_lossy().into_owned();
    assert!(p.validate_record_overlay(orig, &mirror_str));
    // Case-insensitive: the hook sends the root in its original case.
    assert!(p.validate_record_overlay(orig, &mirror_str.to_ascii_uppercase()));
    // Trailing separator tolerated (key-normalization parity).
    assert!(p.validate_record_overlay(orig, &format!("{mirror_str}\\")));
    // The accepted value round-trips into a Cow read decision.
    p.record_overlay(orig, &mirror_str).unwrap();
    let d = p.decide(orig, false);
    assert_eq!(d.mode, Mode::Cow);
    assert_eq!(d.overlay, Some(mirror));
}

#[test]
fn validate_record_overlay_accepts_mock_dirs_mirror() {
    let (_dir, p) = make_policy();
    let orig = r"d:\proj\f.txt";
    let mock_mirror = crate::path::mirror_into_overlay(orig, &p.inner.mock_dirs_root);
    let mock_str = mock_mirror.to_string_lossy().into_owned();
    assert!(p.validate_record_overlay(orig, &mock_str));
    // Identity is per-orig: the same value for another path is rejected.
    assert!(!p.validate_record_overlay(r"d:\proj\g.txt", &mock_str));
}

#[test]
fn validate_record_overlay_rejects_outside_roots() {
    let (_dir, p) = make_policy();
    let orig = r"d:\proj\f.txt";
    // The audit PoC: a real user-profile persistence location.
    let poc = r"C:\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\pwn.bat";
    assert!(!p.validate_record_overlay(orig, poc));
    // Sibling-prefix lookalike of the sandbox root.
    let sb = p.inner.overlay_layout.primary();
    let sib = format!("{}evil\\x.txt", sb.to_string_lossy());
    assert!(!p.validate_record_overlay(orig, &sib));
    // Empty value.
    assert!(!p.validate_record_overlay(orig, ""));
}

#[test]
fn validate_record_overlay_rejects_in_root_wrong_mirror() {
    let (_dir, p) = make_policy();
    let orig = r"d:\proj\f.txt";
    let sb = p.inner.overlay_layout.primary();
    // Inside the sandbox but NOT the mirror of orig (wrong name).
    let wrong = sb.join("proj").join("other.txt");
    assert!(!p.validate_record_overlay(orig, &wrong.to_string_lossy()));
    // Dot-segment smuggling at the root boundary.
    let dots = sb.join("..").join("escape.bat");
    assert!(!p.validate_record_overlay(orig, &dots.to_string_lossy()));
}

#[test]
fn project_root_with_turkish_dotted_i_is_passthrough() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("policy.redb");
    let sandbox = dir.path().join("sb");
    let mock_dirs = dir.path().join("md");
    let project = dir.path().join(format!("Proj\u{0130}ct"));
    std::fs::create_dir_all(&sandbox).unwrap();
    std::fs::create_dir_all(&mock_dirs).unwrap();
    std::fs::create_dir_all(&project).unwrap();
    let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project.clone()).unwrap();

    let root_display = project.to_str().unwrap();
    let d = p.decide(&format!(r"{}\alt\dosya.txt", root_display), true);
    assert_eq!(d.mode, Mode::Passthrough);
}

// ── decide_traced must mirror compute (audit 2026-09-19 Low) ──────────────

#[test]
fn decide_traced_write_fallback_is_cow_like_compute() {
    let (_dir, p) = make_policy();
    // Outside project_root, no explicit rule and no default rule.
    let path = r"c:\elsewhere\newfile.txt";
    let live = p.decide(path, true);
    assert!(
        matches!(live.mode, Mode::Cow),
        "compute must isolate an external write (precondition)"
    );
    let traced = p.decide_traced(path, true, None, None);
    assert!(
        matches!(traced.decision, db::RuleMode::Cow),
        "with no rule and no default, compute isolates the write (Cow); the trace must report the same decision, not Passthrough"
    );
    assert!(
        traced.target_path.is_some(),
        "traced Cow must carry the overlay target like compute's Cow"
    );
}

#[test]
fn decide_traced_read_through_reports_cow_like_compute() {
    let (_dir, p) = make_policy();
    // Simulate a previously CoW'd file: an OVERLAY_IDX entry orig -> overlay.
    let orig = r"c:\elsewhere\config.json";
    p.record_overlay(orig, r"c:\sb-overlay\elsewhere\config.json")
        .unwrap();
    let live = p.decide(orig, false);
    assert!(
        matches!(live.mode, Mode::Cow),
        "compute's read-through must serve the overlay copy (precondition)"
    );
    let traced = p.decide_traced(orig, false, None, None);
    assert!(
        matches!(traced.decision, db::RuleMode::Cow),
        "trace must mirror compute's read-through: an indexed read is Cow, not Passthrough"
    );
}

#[test]
fn decide_traced_whiteout_revived_by_physical_overlay_agrees_with_compute() {
    let (dir, p) = make_policy();
    let orig = r"c:\elsewhere\gone.txt";
    p.record_whiteout(orig).unwrap();
    // Materialize the physical mirror exactly as mirror_into_overlay_layout
    // would: <sandbox_root>\<rest> (Path-1, drive implicit in the root).
    let phys = dir.path().join("sb").join("elsewhere").join("gone.txt");
    std::fs::create_dir_all(phys.parent().unwrap()).unwrap();
    std::fs::write(&phys, b"x").unwrap();

    let live = p.decide(orig, false);
    assert!(
        matches!(live.mode, Mode::Cow),
        "compute must treat the physically-revived path as live Cow (precondition)"
    );
    let traced = p.decide_traced(orig, false, None, None);
    assert!(
        matches!(traced.decision, db::RuleMode::Cow),
        "trace must not report a whiteout the engine already superseded by a physical overlay file"
    );
}

// ── Rule-index semantics pins (perf refactor must not change matching) ──
//
// Snapshot::best_explicit_rule_match is now index-driven (decide/rule_index.rs:
// literal-segment trie + wildcard list). These tests pin that the precompiled
// index is semantically IDENTICAL to the old linear re-glob-per-rule scan
// (db::best_rule_match_full): a differential test replays the old algorithm
// verbatim as an oracle over a fixture exercising every matcher corner
// (literal trie, `*`/`?` globs, globstars mid/trailing/leading, zero-segment
// patterns, depth/exe when-filters, specificity ties) across the full
// (path × depth × exe) cross product, plus targeted pins for each
// tie-break/when semantic that must never regress.

/// Hand-set ids so winners are assertable by name (rule_upsert would
/// generate opaque ids; we bypass it entirely).
fn idx_row(
    id: &str,
    prefix: &str,
    mr: db::RuleMode,
    mw: db::RuleMode,
    when: Option<db::WhenFilter>,
) -> db::RuleRow {
    db::RuleRow {
        id: id.to_string(),
        prefix: prefix.to_string(),
        mode_read: mr,
        mode_write: mw,
        when,
    }
}

/// The shared fixture. Rules are listed in redb's ascending ASCII key order
/// (the order the snapshot loads them in) — that IS "table order", which
/// defines the old scan order and the new earliest-index tie-break. Covers:
/// literal trie hits (nested), single-segment `*`/`?` globs, globstars
/// (mid / trailing / leading), a zero-segment `\\` pattern that filters to
/// nothing and therefore matches EVERY path, when.depth, when.exe stored
/// MIXED CASE (raw insert — rule_upsert would have lowercased it), and
/// equal-specificity tie groups.
fn fixture_rows() -> Vec<db::RuleRow> {
    use db::RuleMode::{Cow, Deny, Passthrough, Redirect};
    vec![
        idx_row("r-default", "", Passthrough, Cow, None),
        idx_row("r-globstar-lead", r"**\tmp", Deny, Deny, None),
        // `\\` splits into ZERO segments → prefix_match([], _) is true → matches EVERY path.
        idx_row("r-slashonly", r"\\", Passthrough, Passthrough, None),
        idx_row("r-tie-star", r"c:\a*", Deny, Deny, None), // spec 4
        idx_row("r-tie-q", r"c:\a?", Redirect, Redirect, None), // spec 4 — ties with r-tie-star
        idx_row("r-tie-lit", r"c:\ab", Deny, Deny, None), // spec 5
        idx_row("r-tie-glob", r"c:\ab\**", Cow, Cow, None), // spec 6 (`**` adds 0, the `\` counts)
        idx_row("r-both", r"c:\both", Cow, Cow, Some(db::WhenFilter { depth: Some(1), exe: Some("app.exe".into()) })),
        idx_row("r-globstar-mid", r"c:\data\**\secrets", Deny, Deny, None),
        idx_row("r-depth", r"c:\deep", Deny, Deny, Some(db::WhenFilter { depth: Some(2), exe: None })),
        idx_row("r-exe", r"c:\exetool", Deny, Deny, Some(db::WhenFilter { depth: None, exe: Some(r"C:\Tools\APP.EXE".into()) })),
        idx_row("r-glob-q", r"c:\file?.txt", Deny, Deny, None),
        idx_row("r-globstar-trail", r"c:\logs\**", Cow, Cow, None),
        idx_row("r-lit-src", r"c:\proj\src", Deny, Deny, None),
        idx_row("r-lit-main", r"c:\proj\src\main.rs", Cow, Cow, None),
        idx_row("r-glob-users", r"c:\users\*\seed", Redirect, Redirect, None),
        idx_row("r-w-plain", r"c:\w", Passthrough, Passthrough, None), // spec 4
        idx_row("r-w-when", r"c:\w?", Deny, Deny, Some(db::WhenFilter { depth: None, exe: Some("app.exe".into()) })), // spec 4+1+7
    ]
}

/// Real Policy with RAW-inserted rows (bincode-encoded straight into the
/// RULES table, like db::tests::make_db_with_rules) so mixed-case when.exe
/// survives — rule_upsert would ensure_lower it before storing. The default
/// row (empty prefix) is included by the caller like db/tests does.
fn make_policy_with_rows(rows: &[db::RuleRow]) -> (tempfile::TempDir, Policy) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("policy.redb");
    {
        let rdb = redb::Database::create(&db_path).unwrap();
        {
            let txn = rdb.begin_write().unwrap();
            let mut table = txn.open_table(db::RULES).unwrap();
            for row in rows {
                let enc = bincode::serde::encode_to_vec(row, bincode::config::standard()).unwrap();
                table.insert(row.prefix.as_str(), enc.as_slice()).unwrap();
            }
            drop(table);
            txn.commit().unwrap();
        }
    } // drop the raw handle before the Policy opens the same file
    let sandbox = dir.path().join("sb");
    let mock_dirs = dir.path().join("md");
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&sandbox).unwrap();
    std::fs::create_dir_all(&mock_dirs).unwrap();
    std::fs::create_dir_all(&project).unwrap();
    let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
    (dir, p)
}

fn make_index_fixture() -> (tempfile::TempDir, Policy) {
    make_policy_with_rows(&fixture_rows())
}

/// The OLD algorithm, verbatim: scan the rules in table order (the snapshot
/// loaded them in redb ascending-key order), skip non-matching / when-filtered
/// rules, keep the FIRST strictly-higher specificity — i.e. highest spec,
/// earliest index on ties. Returns the winner's id.
fn reference_best_match<'a>(
    snap: &'a Snapshot,
    lower_path: &str,
    depth: Option<u8>,
    exe_lower: Option<&str>,
) -> Option<&'a str> {
    let mut best: Option<(usize, &'a str)> = None;
    for sr in &snap.rules {
        if !crate::path::pattern_matches_prefix(&sr.pattern, lower_path) {
            continue;
        }
        if let Some(when) = &sr.row.when {
            if let Some(min_depth) = when.depth {
                // None runtime depth NEVER skips (the old `None => {}` arm).
                if let Some(d) = depth {
                    if d < min_depth {
                        continue;
                    }
                }
            }
            if let Some(exe_pattern) = &when.exe {
                match exe_lower {
                    Some(exe) if crate::path::pattern_matches_exact(&crate::ensure_lower(exe_pattern), exe) => {}
                    _ => continue,
                }
            }
        }
        let mut spec = crate::path::pattern_specificity(&sr.pattern);
        if sr.row.when.is_some() {
            spec += 1;
        }
        if let Some(exe) = sr.row.when.as_ref().and_then(|w| w.exe.as_deref()) {
            spec += crate::path::pattern_specificity(exe);
        }
        match best {
            None => best = Some((spec, sr.row.id.as_str())),
            Some((s, _)) if spec > s => best = Some((spec, sr.row.id.as_str())),
            _ => {}
        }
    }
    best.map(|(_, id)| id)
}

fn explicit_winner<'a>(snap: &'a Snapshot, path: &str, depth: Option<u8>, exe: Option<&str>) -> Option<&'a str> {
    snap.best_explicit_rule_match(path, depth, exe).map(|r| r.id.as_str())
}

#[test]
fn rule_index_matches_reference_on_full_cross_product() {
    let (_dir, p) = make_index_fixture();
    let snap = p.inner.snapshot.load();
    let paths: &[&str] = &[
        r"c:\proj\src\lib.rs",
        r"c:\proj\src\main.rs",
        r"c:\proj\src",
        r"c:\proj\other\f.txt",
        r"c:\proj",
        r"c:\users\bob\seed",
        r"c:\users\bob\seed\deep\f",
        r"c:\users\alice\other",
        r"c:\filea.txt",
        r"c:\filez.tx",
        r"c:\file?.txt",
        r"c:\data\secrets",
        r"c:\data\a\b\secrets",
        r"c:\data\a\b\secrets\z",
        r"c:\data\a\x",
        r"c:\data\a\secrets\b",
        r"c:\logs",
        r"c:\logs\a\b\c",
        r"c:\tmp\u",
        r"x:\tmp\tmp\u",
        r"c:\deep",
        r"c:\deep\d1\d2",
        r"c:\exetool\f.exe",
        r"c:\both\f",
        r"c:\aa\z",
        r"c:\ab\z",
        r"c:\wx\f",
        r"\\",
        r"c:\\double\\slash",
        r"c:\proj\", // trailing separator — FILTERED segment split must absorb it
        r"c:\unrelated\x",
    ];
    let depths: &[Option<u8>] = &[None, Some(0), Some(1), Some(2), Some(3)];
    let exes: &[Option<&str>] = &[
        None,
        Some(""),
        Some("app.exe"),
        Some(r"c:\tools\app.exe"),
        Some("C:\\TOOLS\\APP.EXE"), // runtime exe is compared VERBATIM (only the stored pattern is lowered)
        Some(r"c:\other\app.exe"),
        Some(r"c:\tools\other.exe"),
    ];
    for &path in paths {
        for &depth in depths {
            for &exe in exes {
                let want = reference_best_match(&snap, path, depth, exe);
                let got = snap.best_explicit_rule_match(path, depth, exe).map(|r| r.id.as_str());
                assert_eq!(got, want, "explicit: path={path:?} depth={depth:?} exe={exe:?}");
                let want_default = want.or(snap.default_rule.as_ref().map(|r| r.id.as_str()));
                let got_default = snap.best_rule_match(path, depth, exe).map(|r| r.id.as_str());
                assert_eq!(got_default, want_default, "with-default: path={path:?} depth={depth:?} exe={exe:?}");
            }
        }
    }
}

#[test]
fn tie_break_equal_spec_prefers_earliest_table_index() {
    let (_dir, p) = make_index_fixture();
    let snap = p.inner.snapshot.load();
    // `c:\aa\z` matches r-tie-star (spec 4) and r-tie-q (spec 4). ASCII key
    // order loads `c:\a*` before `c:\a?`, so the earliest-index tie-break
    // must pick the star rule — not the later one, not "wildcards by kind".
    assert_eq!(explicit_winner(&snap, r"c:\aa\z", None, None), Some("r-tie-star"));
}

#[test]
fn globstar_specificity_precompute_matches_old_recompute() {
    let (_dir, p) = make_index_fixture();
    let snap = p.inner.snapshot.load();
    // `c:\ab\z` matches r-tie-lit (spec 5) and r-tie-glob `c:\ab\**`. The
    // globstar itself adds 0, but the extra `\` before it counts, so the
    // glob rule's precompiled spec is 6 — HIGHER than the literal's 5, and
    // the winner regardless of table order. Pins that the index's globstar
    // specificity is computed exactly like the old decide-time recompute
    // (pattern_specificity counts non-wildcard chars including backslashes).
    assert_eq!(explicit_winner(&snap, r"c:\ab\z", None, None), Some("r-tie-glob"));
}

#[test]
fn higher_specificity_wins_over_earlier() {
    let (_dir, p) = make_index_fixture();
    let snap = p.inner.snapshot.load();
    // Deeper literal sorts AFTER its parent but has strictly higher spec —
    // it must win despite r-lit-src coming first in table order.
    assert_eq!(explicit_winner(&snap, r"c:\proj\src\main.rs", None, None), Some("r-lit-main"));
}

#[test]
fn globstar_mid_requires_later_segments() {
    let (_dir, p) = make_index_fixture();
    let snap = p.inner.snapshot.load();
    // Mid-pattern `**` spans ≥0 whole segments; the trailing literal must
    // still match (including backtracking at `c:\data\a\secrets\b`).
    assert_eq!(explicit_winner(&snap, r"c:\data\a\b\secrets\z", None, None), Some("r-globstar-mid"));
    assert_eq!(explicit_winner(&snap, r"c:\data\a\b\secrets", None, None), Some("r-globstar-mid"));
    assert_eq!(explicit_winner(&snap, r"c:\data\a\secrets", None, None), Some("r-globstar-mid"));
    // Zero-width globstar: `c:\data\secrets` with `**` consuming nothing.
    assert_eq!(explicit_winner(&snap, r"c:\data\secrets", None, None), Some("r-globstar-mid"));
    // Missing the later `secrets` segment → the globstar rule must NOT fire.
    // (r-slashonly is the every-path baseline, so "no match" here means the
    // baseline is the only survivor.)
    assert_eq!(explicit_winner(&snap, r"c:\data\a\x", None, None), Some("r-slashonly"));
    assert_eq!(explicit_winner(&snap, r"c:\data\x", None, None), Some("r-slashonly"));
}

#[test]
fn globstar_trailing_and_leading() {
    let (_dir, p) = make_index_fixture();
    let snap = p.inner.snapshot.load();
    // TRAILING `**` matches zero or more remaining segments — including none.
    assert_eq!(explicit_winner(&snap, r"c:\logs", None, None), Some("r-globstar-trail"));
    assert_eq!(explicit_winner(&snap, r"c:\logs\a\b", None, None), Some("r-globstar-trail"));
    // LEADING `**` anchors only the final literal segment.
    assert_eq!(explicit_winner(&snap, r"c:\x\y\tmp\f", None, None), Some("r-globstar-lead"));
    assert_eq!(explicit_winner(&snap, r"c:\tmp", None, None), Some("r-globstar-lead"));
}

#[test]
fn when_depth_none_runtime_never_skips() {
    let (_dir, p) = make_index_fixture();
    let snap = p.inner.snapshot.load();
    // Below the minimum → r-depth filtered out (only the every-path baseline left).
    assert_eq!(explicit_winner(&snap, r"c:\deep", Some(1), None), Some("r-slashonly"));
    // At/above the minimum → r-depth wins (spec 8 beats baseline 2).
    assert_eq!(explicit_winner(&snap, r"c:\deep", Some(2), None), Some("r-depth"));
    assert_eq!(explicit_winner(&snap, r"c:\deep", Some(3), None), Some("r-depth"));
    // THE pin: a None runtime depth must NOT fail the depth filter — the old
    // algorithm's `None => {}` arm lets the rule through, and the index's
    // `if let (Some(d), Some(min))` must do exactly the same.
    assert_eq!(explicit_winner(&snap, r"c:\deep", None, None), Some("r-depth"));
}

#[test]
fn when_exe_precomputed_lowercase_matches() {
    let (_dir, p) = make_index_fixture();
    let snap = p.inner.snapshot.load();
    let path = r"c:\exetool\f.exe";
    // Stored MIXED CASE (`C:\Tools\APP.EXE` — raw insert). Matching it with a
    // lowercase runtime exe proves the pattern was lowered; the index lowers
    // at load what the old code lowered per decision — identical result.
    assert_eq!(explicit_winner(&snap, path, None, Some(r"c:\tools\app.exe")), Some("r-exe"));
    // The runtime exe is compared verbatim in BOTH implementations (the
    // exe_lower contract is pre-lowered input): a mixed-case exe must NOT
    // match the lowered pattern — the index must not fold more than the old
    // decide-time code did.
    assert_eq!(explicit_winner(&snap, path, None, Some("C:\\TOOLS\\APP.EXE")), Some("r-slashonly"));
    assert_eq!(explicit_winner(&snap, path, None, Some(r"c:\tools\other.exe")), Some("r-slashonly"));
    // No exe at all → exe-scoped rule filtered out.
    assert_eq!(explicit_winner(&snap, path, None, None), Some("r-slashonly"));
}

#[test]
fn when_bonus_breaks_spec_tie() {
    let (_dir, p) = make_index_fixture();
    let snap = p.inner.snapshot.load();
    // r-w-when (`c:\w?` + when.exe "app.exe") matches `c:\wx` (its `?` needs
    // exactly one char); the plain rule `c:\w` does not match this path —
    // the exe-scoped rule wins outright when its exe matches.
    let path = r"c:\wx\f";
    assert_eq!(explicit_winner(&snap, path, None, Some("app.exe")), Some("r-w-when"));
    // On `c:\w\f` only the plain rule can match; the exe filter is what
    // removes r-w-when from every path, and here the plain rule also outranks
    // the match-everything r-slashonly (spec 4 vs 2).
    let plain_path = r"c:\w\f";
    assert_eq!(explicit_winner(&snap, plain_path, None, None), Some("r-w-plain"));
    // Non-matching exe → r-w-when filtered → plain rule wins.
    assert_eq!(explicit_winner(&snap, plain_path, None, Some("other.exe")), Some("r-w-plain"));
}

#[test]
fn slashonly_rule_matches_every_path() {
    let (_dir, p) = make_index_fixture();
    let snap = p.inner.snapshot.load();
    // `\\` filters to ZERO segments → it lives in the trie ROOT's rule list
    // and must be a candidate for every path, including drive-less, doubled-
    // separator, and empty-after-filter shapes. No other rule matches these
    // paths, so r-slashonly must be the winner each time.
    assert_eq!(explicit_winner(&snap, r"z:\plain\note", None, None), Some("r-slashonly"));
    assert_eq!(explicit_winner(&snap, r"\\", None, None), Some("r-slashonly"));
    assert_eq!(explicit_winner(&snap, r"x:\y", None, None), Some("r-slashonly"));
}

#[test]
fn best_rule_match_default_fallback_preserved() {
    // Minimal fixture: default row + one explicit rule that matches nothing
    // under z:. (The full fixture can't show a None explicit match because
    // r-slashonly matches every path.)
    let rows = vec![
        idx_row("r-default", "", db::RuleMode::Passthrough, db::RuleMode::Cow, None),
        idx_row("r-unrelated", r"c:\elsewhere", db::RuleMode::Deny, db::RuleMode::Deny, None),
    ];
    let (_dir, p) = make_policy_with_rows(&rows);
    let snap = p.inner.snapshot.load();
    let path = r"z:\nowhere\f";
    // Explicit lookup: None — the default catch-all must NOT leak in.
    assert!(snap.best_explicit_rule_match(path, None, None).is_none());
    // With-default lookup: falls back to the default row, modes intact.
    let d = snap.best_rule_match(path, None, None).expect("default fallback must fire");
    assert_eq!(d.id, "r-default");
    assert!(matches!(d.mode_write, db::RuleMode::Cow));
}

// ── S05: pre-existing in-root alias must not inherit write trust ─────────
//
// (docs/review-xa-2026-09-20, P1: junction/symlink inside project_root
// escapes write containment.) These tests need REAL junction/symlink/
// hardlink fixtures, so the Policy itself is built inside the worktree
// (gitignored target/) — tempfile's %TEMP% root would sit OUTSIDE the
// project_root and the aliases could not be created under it.

/// S05 fixture root INSIDE the worktree (gitignored target/): real junctions,
/// symlinks and hardlinks are created here with the actual Windows APIs, and
/// the Policy's project/sandbox/mock-dirs roots live here too so the aliases
/// are inside `project_root`.
fn make_policy_under_worktree() -> (PathBuf, Policy) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    // pid + run timestamp + per-test counter: no collisions between or
    // within test runs (redb refuses to open the same file twice).
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("s05-fixtures")
        .join(format!(
            "pol-{}-{}-{}",
            std::process::id(),
            nanos,
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
    let db_path = base.join("policy.redb");
    let sandbox = base.join("sb");
    let mock_dirs = base.join("md");
    let project = base.join("proj");
    std::fs::create_dir_all(&sandbox).unwrap();
    std::fs::create_dir_all(&mock_dirs).unwrap();
    std::fs::create_dir_all(&project).unwrap();
    let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
    (base, p)
}

#[test]
fn s05_in_root_hardlinked_file_write_is_isolated() {
    let (base, p) = make_policy_under_worktree();
    let root = p.inner.project_root_lower.clone();
    let outside = base.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let src = outside.join("shared.txt");
    std::fs::write(&src, b"shared").unwrap();
    let in_tree = base.join("proj").join("shared.txt");
    std::fs::hard_link(&src, &in_tree).unwrap();

    // THE regression: unfixed, the in-root NAME is Passthrough for writes and
    // the write lands on the one shared file object — i.e. on `outside`.
    let w = p.decide(&format!(r"{root}\shared.txt"), true);
    assert_eq!(
        w.mode,
        Mode::Cow,
        "multi-link in-root file must NOT inherit write trust from its path string"
    );
    assert!(
        w.overlay.is_some(),
        "Cow decision must carry an overlay path"
    );
    // Reads stay globally authorized: alias detection is write-side only.
    let r = p.decide(&format!(r"{root}\shared.txt"), false);
    assert_eq!(r.mode, Mode::Passthrough, "reads keep the legacy short-circuit");
}

#[test]
fn s05_in_root_alias_under_outside_dir_write_is_isolated() {
    let (base, p) = make_policy_under_worktree();
    let root = p.inner.project_root_lower.clone();
    let outside2 = base.join("outside2");
    std::fs::create_dir_all(&outside2).unwrap();
    std::fs::write(outside2.join("f.txt"), b"x").unwrap();
    let link = base.join("proj").join("link");
    if let Err(e) = std::os::windows::fs::symlink_dir(&outside2, &link) {
        eprintln!(
            "SKIPPED S05 symlink case: symlink_dir failed with {e}; creating \
             directory symlinks requires SeCreateSymbolicLinkPrivilege or \
             Windows Developer Mode"
        );
        return;
    }
    let alias = format!(r"{root}\link\f.txt");
    let w = p.decide(&alias, true);
    assert_eq!(
        w.mode,
        Mode::Cow,
        "write through an in-root symlink to an outside dir must be isolated"
    );
    let r = p.decide(&alias, false);
    assert_eq!(r.mode, Mode::Passthrough, "reads keep the legacy short-circuit");
}

#[test]
fn s05_in_root_alias_missing_tail_write_is_isolated() {
    let (base, p) = make_policy_under_worktree();
    let root = p.inner.project_root_lower.clone();
    let outside2 = base.join("outside2");
    std::fs::create_dir_all(&outside2).unwrap();
    let link = base.join("proj").join("link");
    if let Err(e) = std::os::windows::fs::symlink_dir(&outside2, &link) {
        eprintln!(
            "SKIPPED S05 symlink case: symlink_dir failed with {e}; creating \
             directory symlinks requires SeCreateSymbolicLinkPrivilege or \
             Windows Developer Mode"
        );
        return;
    }
    // Nothing named `new\created.txt` exists anywhere — the kernel will
    // resolve the create through the deepest EXISTING ancestor, which IS the
    // alias; that ancestor must be resolved by handle.
    let alias = format!(r"{root}\link\new\created.txt");
    let w = p.decide(&alias, true);
    assert_eq!(
        w.mode,
        Mode::Cow,
        "create-new through an in-root alias must be isolated (missing-tail walk)"
    );
}

#[test]
fn s05_in_root_plain_file_write_still_passthrough() {
    let (base, p) = make_policy_under_worktree();
    let root = p.inner.project_root_lower.clone();
    std::fs::write(base.join("proj").join("plain.txt"), b"plain").unwrap();
    // NEGATIVE CONTROL: a single-link in-root file keeps full write trust —
    // the alias gate must not over-block legitimate project writes.
    let d = p.decide(&format!(r"{root}\plain.txt"), true);
    assert_eq!(d.mode, Mode::Passthrough);
}

#[test]
fn s05_in_root_missing_file_write_still_passthrough() {
    let (_base, p) = make_policy_under_worktree();
    let root = p.inner.project_root_lower.clone();
    // Create-new under a missing intermediate dir: the deepest existing
    // ancestor is the (honest) project root itself — not an escape.
    let d = p.decide(&format!(r"{root}\newdir\created.txt"), true);
    assert_eq!(d.mode, Mode::Passthrough);
}

#[test]
fn s05_traced_in_root_alias_write_matches_compute() {
    let (base, p) = make_policy_under_worktree();
    let root = p.inner.project_root_lower.clone();
    let outside = base.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let src = outside.join("shared.txt");
    std::fs::write(&src, b"shared").unwrap();
    std::fs::hard_link(&src, base.join("proj").join("shared.txt")).unwrap();

    let alias = format!(r"{root}\shared.txt");
    let live = p.decide(&alias, true);
    assert!(
        matches!(live.mode, Mode::Cow),
        "compute must isolate the aliased in-root write (precondition)"
    );
    let traced = p.decide_traced(&alias, true, None, None);
    assert!(
        matches!(traced.decision, db::RuleMode::Cow),
        "trace must report the same decision the live path takes (compute/trace parity)"
    );
}

#[test]
fn s05_in_root_write_to_root_itself_still_passthrough() {
    let (_base, p) = make_policy_under_worktree();
    let root = p.inner.project_root_lower.clone();
    // The root dir itself: its canonical form equals the root anchor, so the
    // alias gate accepts it — trust on the root string is intact.
    let d = p.decide(&root, true);
    assert_eq!(d.mode, Mode::Passthrough);
}
