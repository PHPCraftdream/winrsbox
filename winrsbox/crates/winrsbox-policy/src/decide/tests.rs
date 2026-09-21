use super::{cache_key, path_contained_in, db, Mode, PathBuf, Policy};

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

// ── ASCII-only case-fold consistency (ensure_lower vs to_lowercase) ─────
//
// The hook side folds every path with to_ascii_lowercase(); kernel
// canonicalization is ASCII-only too (see ensure_lower). Any policy-key
// writer that Unicode-folds instead produces keys that a non-ASCII path
// (e.g. U+0130 İ) can never read back — a containment-relevant
// inconsistency. These tests pin the policy side to the canonical fold.

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
