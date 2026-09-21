use crate::*;
use super::make_policy_with_project;
// ── Whiteout (OverlayFS tombstone) tests ──────────────────────────────

#[test]
fn record_whiteout_then_is_whiteouted_true() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    assert!(!p.is_whiteouted(r"d:\ext\file.txt"), "no marker before record");
    p.record_whiteout(r"d:\ext\File.txt").unwrap();
    assert!(p.is_whiteouted(r"d:\ext\file.txt"), "marker present after record");
    assert!(p.is_whiteouted(r"D:\EXT\FILE.TXT"), "marker lookup is case-insensitive");
}

#[test]
fn clear_whiteout_removes_marker() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    p.record_whiteout(r"d:\ext\file.txt").unwrap();
    assert!(p.is_whiteouted(r"d:\ext\file.txt"));
    p.clear_whiteout(r"d:\ext\file.txt").unwrap();
    assert!(!p.is_whiteouted(r"d:\ext\file.txt"), "marker gone after clear");
}

/// Bug #78: clear_whiteout must also remove descendant whiteouts.
///
/// Scenario: SSH clone fails → git cleanup whiteouts the repo dir AND all
/// children (.git, .git\config, …). HTTPS retry re-creates the repo dir
/// (reviving its own whiteout) but `.git` keeps its stale whiteout so git's
/// subsequent FILE_OPEN for `.git` sees Hidden → clone failure.
///
/// The fix: `clear_whiteout(parent)` bulk-removes all `parent\*` entries.
#[test]
fn clear_whiteout_cascades_to_children() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    // Simulate SSH-clone whiteouts: parent dir + children + deeper children.
    p.record_whiteout(r"d:\repo\hermes-agent").unwrap();
    p.record_whiteout(r"d:\repo\hermes-agent\.git").unwrap();
    p.record_whiteout(r"d:\repo\hermes-agent\.git\config").unwrap();
    p.record_whiteout(r"d:\repo\hermes-agent\.git\HEAD").unwrap();
    // Unrelated sibling prefix — must NOT be touched.
    p.record_whiteout(r"d:\repo\hermes-agent-old\file.txt").unwrap();

    // Revival of parent:
    p.clear_whiteout(r"d:\repo\hermes-agent").unwrap();

    assert!(!p.is_whiteouted(r"d:\repo\hermes-agent"), "parent whiteout cleared");
    assert!(!p.is_whiteouted(r"d:\repo\hermes-agent\.git"), ".git child cleared");
    assert!(!p.is_whiteouted(r"d:\repo\hermes-agent\.git\config"), "deep child cleared");
    assert!(!p.is_whiteouted(r"d:\repo\hermes-agent\.git\HEAD"), "deep child cleared");
    // Sibling prefix must survive.
    assert!(p.is_whiteouted(r"d:\repo\hermes-agent-old\file.txt"),
        "sibling-prefix entry must not be touched");
}

#[test]
fn record_whiteout_invalidates_cache() {
    // record_overlay clears the cache; record_whiteout must do the same
    // so a subsequent decide() observes the marker.
    let (_dir, p, _project) = make_policy_with_project("proj");
    let path = r"d:\ext\wh\file.txt";
    // Prime the cache with a default decide (no marker).
    let d1 = p.decide(path, false);
    assert_ne!(d1.mode, Mode::Hidden);
    // Record the marker.
    p.record_whiteout(path).unwrap();
    // Now decide must reflect the whiteout.
    let d2 = p.decide(path, false);
    assert_eq!(d2.mode, Mode::Hidden, "cache must be invalidated so whiteout is seen");
}

#[test]
fn whiteout_persists_across_db_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("policy.redb");
    let sandbox = dir.path().join("sb");
    let mock_dirs = dir.path().join("md");
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&sandbox).unwrap();
    std::fs::create_dir_all(&mock_dirs).unwrap();
    std::fs::create_dir_all(&project).unwrap();
    {
        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
        p.record_whiteout(r"d:\persist\file.txt").unwrap();
        assert!(p.is_whiteouted(r"d:\persist\file.txt"));
    }
    // Reopen: the WHITEOUTS table is durable.
    let sandbox2 = dir.path().join("sb");
    let mock_dirs2 = dir.path().join("md");
    let project2 = dir.path().join("proj");
    let p = Policy::open_or_create(&db_path, sandbox2, mock_dirs2, project2).unwrap();
    assert!(p.is_whiteouted(r"d:\persist\file.txt"), "whiteout must survive db reopen");
}

#[test]
fn whiteouts_under_returns_direct_children_only() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    p.record_whiteout(r"d:\foo\a.txt").unwrap();
    p.record_whiteout(r"d:\foo\b.log").unwrap();
    // Descendant of a subdir — NOT a direct child of d:\foo.
    p.record_whiteout(r"d:\foo\sub\deep.txt").unwrap();
    // Different directory entirely.
    p.record_whiteout(r"d:\bar\c.txt").unwrap();

    let names = p.whiteouts_under(r"d:\foo");
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(sorted, vec!["a.txt".to_string(), "b.log".to_string()],
        "whiteouts_under must return only direct children, got {names:?}");
}

#[test]
fn whiteouts_under_empty_when_no_match() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    p.record_whiteout(r"d:\foo\a.txt").unwrap();
    let names = p.whiteouts_under(r"d:\empty");
    assert!(names.is_empty(), "no whiteouts under an unrelated dir");
}

#[test]
fn whiteouts_under_sibling_prefix_not_confused() {
    // d:\foo vs d:\foobar — must not cross-contaminate.
    let (_dir, p, _project) = make_policy_with_project("proj");
    p.record_whiteout(r"d:\foobar\evil.txt").unwrap();
    let names = p.whiteouts_under(r"d:\foo");
    assert!(names.is_empty(), "d:\\foo must not see d:\\foobar's children");
}

#[test]
fn whiteouts_under_excludes_revived_overlay_child() {
    // Regression for #81 (ghost coherence): a whiteout on a child that ALSO
    // has a live physical overlay must NOT be reported as hidden — `compute`
    // revives such a name to Mode::Cow (VISIBLE), so enumeration must agree.
    // A blocked physical delete (RecordWhiteoutKeepOverlay) leaves whiteout
    // + overlay both present; if `whiteouts_under` still hid it, the parent
    // dir would be un-removable: read_dir reports empty, the kernel rmdir
    // hits the physical child → STATUS_DIRECTORY_NOT_EMPTY (145) / POSIX
    // STATUS_REPARSE_POINT_ENCOUNTERED (4395), and recursive delete diverges.
    let (_dir, p, _project) = make_policy_with_project("proj");

    // Materialize a physical overlay file for the "alive" child (simulates a
    // delete that was blocked and left the overlay copy behind).
    let alive = p.decide(r"d:\ghost\alive.txt", true).overlay
        .expect("write decision yields a Cow overlay path");
    std::fs::create_dir_all(alive.parent().unwrap()).unwrap();
    std::fs::write(&alive, b"x").unwrap();

    // Both children carry a whiteout; only "gone" lacks a live overlay.
    p.record_whiteout(r"d:\ghost\gone.txt").unwrap();
    p.record_whiteout(r"d:\ghost\alive.txt").unwrap();

    let names = p.whiteouts_under(r"d:\ghost");
    assert_eq!(names, vec!["gone.txt".to_string()],
        "only the bare whiteout hides; the revived (whiteout+overlay) child must stay visible, got {names:?}");

    // Coherence with compute(): alive → Cow (visible), gone → Hidden.
    assert_eq!(p.decide(r"d:\ghost\alive.txt", false).mode, Mode::Cow,
        "revived child must resolve to Cow in compute()");
    assert_eq!(p.decide(r"d:\ghost\gone.txt", false).mode, Mode::Hidden,
        "bare whiteout must resolve to Hidden in compute()");
}

// ── decide() + whiteout integration tests ─────────────────────────────

#[test]
fn external_whiteouted_path_decides_hidden() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    let path = r"d:\ext\doomed.txt";
    // Before whiteout: passthrough read (read-through to real disk).
    assert_eq!(p.decide(path, false).mode, Mode::Passthrough);
    p.record_whiteout(path).unwrap();
    // After whiteout: Hidden (no overlay entry).
    let d = p.decide(path, false);
    assert_eq!(d.mode, Mode::Hidden, "whiteouted external path must be Hidden on read");
    assert!(d.overlay.is_none(), "Hidden must carry no overlay path");
    // Write disposition is also hidden — a pure open-for-write (no create)
    // still sees the path as gone. The revive happens only when disposition
    // is a create, which the hook layer handles by clearing the whiteout
    // BEFORE re-deciding.
    let d = p.decide(path, true);
    assert_eq!(d.mode, Mode::Hidden);
}

#[test]
fn whiteout_then_overlay_revives_to_cow() {
    // After a whiteout, if an overlay entry is recorded (revive via create),
    // decide must return Cow pointing at the overlay — NOT Hidden.
    let (_dir, p, _project) = make_policy_with_project("proj");
    let path = r"d:\ext\phoenix.txt";
    p.record_whiteout(path).unwrap();
    assert_eq!(p.decide(path, false).mode, Mode::Hidden);

    // Simulate the hook recording the overlay after a revive-create.
    let overlay = r"D:\sb\d\ext\phoenix.txt";
    p.record_overlay(path, overlay).unwrap();
    let d = p.decide(path, false);
    assert_eq!(d.mode, Mode::Cow, "revive (overlay present) must override whiteout");
    assert_eq!(
        d.overlay.as_ref().map(|o| o.to_string_lossy().into_owned()),
        Some(overlay.to_string()),
    );
}

#[test]
fn rename_revive_clears_whiteout_then_overlay_visible() {
    // Regression for the git-config "unknown error reading configuration
    // files" bug. The hook's rename handler now revives a whiteouted
    // destination before redirecting the rename into the overlay. This test
    // pins the policy-side sequence that revive performs:
    //   1. external path is whiteouted (e.g. by a prior `rm -rf .git`).
    //   2. rename handler calls clear_whiteout (revive) on the dest.
    //   3. rename handler records the new overlay entry for dest.
    //   4. decide(dest, write=true) MUST return Cow (not Hidden), and a
    //      subsequent read MUST also see Cow pointing at the new overlay —
    //      otherwise git's follow-up `git config --get` / `git add` reopen
    //      sees Hidden and fails with "unknown error reading config".
    let (_dir, p, _project) = make_policy_with_project("proj");
    let dest = r"d:\repo\.git\config";

    // (1) prior delete whiteouted the path, no overlay present.
    p.record_whiteout(dest).unwrap();
    assert_eq!(p.decide(dest, true).mode, Mode::Hidden);
    assert_eq!(p.decide(dest, false).mode, Mode::Hidden);

    // (2) hook rename-revive: clear_whiteout.
    p.clear_whiteout(dest).unwrap();
    // After clear, with no overlay, decide falls through to default
    // (write=Cow, read=Passthrough) — the rename will create the overlay.
    assert_eq!(p.decide(dest, true).mode, Mode::Cow);

    // (3) hook records the overlay destination after the rename.
    let overlay = r"D:\sb\d\repo\.git\config";
    p.record_overlay(dest, overlay).unwrap();

    // (4) the follow-up reopen (write=false) MUST see the new overlay.
    let d_read = p.decide(dest, false);
    assert_eq!(d_read.mode, Mode::Cow, "reopened dest must resolve to overlay, not Hidden/Passthrough");
    assert_eq!(
        d_read.overlay.as_ref().map(|o| o.to_string_lossy().into_owned()),
        Some(overlay.to_string()),
    );
}

#[test]
fn whiteout_inside_project_root_is_passthrough() {
    // Whiteout markers only apply to external paths. A path inside
    // project_root short-circuits to Passthrough regardless of any marker
    // in the WHITEOUTS table (the agent mutates its own dir for real).
    let (_dir, p, project) = make_policy_with_project("proj");
    let inside = project.join("src").join("main.rs");
    // Even if a stray whiteout exists for an inside-project path, it must
    // not take effect.
    p.record_whiteout(inside.to_str().unwrap()).unwrap();
    let d = p.decide(inside.to_str().unwrap(), false);
    assert_eq!(d.mode, Mode::Passthrough, "whiteout must not apply inside project_root");
    assert!(d.overlay.is_none());
}

// ── Regression: delete-then-stat must see Hidden ──────────────────────
//
// This is the exact sequence the acceptance repro exercises:
//   1. A write to an external path records an overlay entry (Cow).
//   2. The delete hook physically removes the overlay copy AND clears the
//      OVERLAY_IDX entry, then records a whiteout.
//   3. A subsequent read (write=false) of the same path must return
//      Mode::Hidden — NOT Cow, NOT Passthrough.
//
// The bug this pins: if the OVERLAY_IDX entry is NOT cleared on delete,
// `compute` sees (whiteout=true, has_overlay=true) and falls through to
// the normal flow, which returns Cow pointing at the now-missing overlay
// file. The caller then sees the real lower file instead of not-found.
#[test]
fn delete_overlay_then_whiteout_read_is_hidden() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    let path = r"d:\ext\doomed.txt";

    // Step 1: external write → Cow + overlay entry recorded (simulates the
    // hook recording the overlay after a CoW write).
    p.record_overlay(path, r"D:\sb\d\ext\doomed.txt").unwrap();
    let d_write = p.decide(path, true);
    assert_eq!(d_write.mode, Mode::Cow, "write must be Cow with overlay present");
    // Read also sees Cow (read-through to overlay).
    assert_eq!(p.decide(path, false).mode, Mode::Cow);

    // Step 2: delete — the hook clears the overlay index entry (the file is
    // gone) AND records a whiteout.
    p.clear_overlay(path).unwrap();
    p.record_whiteout(path).unwrap();

    // Step 3: read must be Hidden.
    let d_read = p.decide(path, false);
    assert_eq!(
        d_read.mode,
        Mode::Hidden,
        "after delete (clear_overlay + record_whiteout), read must be Hidden, got {:?}",
        d_read.mode,
    );

    // And a write-decide (pure open, not create) must also be Hidden.
    let d_write2 = p.decide(path, true);
    assert_eq!(
        d_write2.mode,
        Mode::Hidden,
        "after delete, write-decide must be Hidden too, got {:?}",
        d_write2.mode,
    );
}

