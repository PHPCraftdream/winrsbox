use super::make_policy_with_project;
// ── OVERLAY_CASE tests (variant B hybrid case-rewrite) ──────────────────

/// 7.1 — Backward compat: existing OVERLAY_IDX entries (without any
/// OVERLAY_CASE record) yield an empty Vec from overlay_children_with_case.
/// No panic, no corruption.
#[test]
fn overlay_case_legacy_entries_yield_empty() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    // Write to OVERLAY_IDX only (simulating a legacy entry).
    p.record_overlay(r"c:\test\some_dir", r"C:\sb\test\some_dir").unwrap();
    // overlay_children_with_case on the parent must return empty (no case
    // record exists for the child).
    let pairs = p.overlay_children_with_case(r"c:\test");
    assert!(
        pairs.is_empty(),
        "legacy entry without case record must yield empty pairs, got: {:?}", pairs
    );
}

/// 7.2 — Roundtrip: record a case for a new entry, retrieve it.
#[test]
fn overlay_case_roundtrip() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    // Simulate an overlay write with original case "Mixed_Case_Dir".
    let lower_path = r"c:\localappdata\uv\cache\builds-v0\.tmpabcd\mixed_case_dir";
    let parent = r"c:\localappdata\uv\cache\builds-v0\.tmpabcd";
    p.record_overlay(lower_path, r"C:\sb\mixed_case_dir").unwrap();
    p.record_overlay_case(lower_path, "Mixed_Case_Dir");
    let pairs = p.overlay_children_with_case(parent);
    assert_eq!(pairs.len(), 1, "expected 1 pair, got: {:?}", pairs);
    let (lower, original) = &pairs[0];
    assert_eq!(lower, "mixed_case_dir");
    assert_eq!(original, "Mixed_Case_Dir");
}

/// 7.3 — Already-lowercase basename is NOT stored (optimization guard).
#[test]
fn overlay_case_lowercase_basename_not_stored() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    let lower_path = r"c:\test\lowercase_dir";
    p.record_overlay(lower_path, r"C:\sb\lowercase_dir").unwrap();
    p.record_overlay_case(lower_path, "lowercase_dir"); // all lowercase → no-op
    let pairs = p.overlay_children_with_case(r"c:\test");
    assert!(
        pairs.is_empty(),
        "all-lowercase basename must not be stored, got: {:?}", pairs
    );
}

/// 7.4 — Multiple children, only those with case records returned.
#[test]
fn overlay_case_multiple_children_mixed() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    let parent = r"c:\test";
    // child_a: has case record
    p.record_overlay(r"c:\test\child_a", r"C:\sb\child_a").unwrap();
    p.record_overlay_case(r"c:\test\child_a", "Child_A");
    // child_b: all-lowercase → no case record stored
    p.record_overlay(r"c:\test\child_b", r"C:\sb\child_b").unwrap();
    p.record_overlay_case(r"c:\test\child_b", "child_b");
    // child_c: has case record
    p.record_overlay(r"c:\test\child_c", r"C:\sb\child_c").unwrap();
    p.record_overlay_case(r"c:\test\child_c", "Child_C");

    let pairs = p.overlay_children_with_case(parent);
    assert_eq!(pairs.len(), 2, "only 2 children have case records, got: {:?}", pairs);
    let names: Vec<&str> = pairs.iter().map(|(_, o)| o.as_str()).collect();
    assert!(names.contains(&"Child_A"), "Child_A must be in pairs");
    assert!(names.contains(&"Child_C"), "Child_C must be in pairs");
}

/// 7.5 — Direct-child boundary: descendants beyond one level not included.
#[test]
fn overlay_case_only_direct_children() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    let parent = r"c:\test";
    // Direct child.
    p.record_overlay(r"c:\test\Direct_Child", r"C:\sb\direct_child").unwrap();
    p.record_overlay_case(r"c:\test\direct_child", "Direct_Child");
    // Grandchild — must NOT appear under parent.
    p.record_overlay(r"c:\test\Direct_Child\Grandchild", r"C:\sb\direct_child\grandchild").unwrap();
    p.record_overlay_case(r"c:\test\direct_child\grandchild", "Grandchild");

    let pairs = p.overlay_children_with_case(parent);
    assert_eq!(pairs.len(), 1, "only direct child; grandchild must be excluded, got: {:?}", pairs);
    assert_eq!(pairs[0].1, "Direct_Child");
}

// ── Regression ratchet: Pattern #1 — overlay-only mixed-case dir via OVERLAY_CASE
//
// Scenario: the real host disk has no such directory (overlay-only creation,
// e.g. `%LOCALAPPDATA%\uv\cache\builds-v0\.tmpXXXX` inside the sandbox).
// The hook writes via `record_overlay` (lowercase key) + `record_overlay_case`
// (original basename with mixed case). A subsequent dir enumeration queries
// `overlay_children_with_case(parent)` — the IPC fallback path in
// `build_case_map_with_fallback`. This test asserts the full policy-side
// chain: record + query → pair returned → lower matches physical name,
// original matches the name the user actually typed.
//
// REGRESSION TARGET: if `record_overlay_case` becomes a no-op (e.g. the
// OVERLAY_CASE table write is silently skipped) OR `overlay_children_with_case`
// filters too aggressively, this test fails — catching a re-introduction
// of the "overlay-only dir listed with wrong case" bug (#74 variant B).
#[test]
fn overlay_case_integration_overlay_only_dir() {
    let (_dir, p, _project) = make_policy_with_project("proj");

    // Simulates: hook processes NtCreateFile for
    //   C:\LocalAppData\uv\cache\builds-v0\.tmpAbCd\My_Package-1.2.3
    // Physical overlay path is lowercase.  Original basename has mixed case.
    let parent_lower    = r"c:\localappdata\uv\cache\builds-v0\.tmpabcd";
    let child_lower     = r"c:\localappdata\uv\cache\builds-v0\.tmpabcd\my_package-1.2.3";
    let original_name   = "My_Package-1.2.3";
    let overlay_phys    = r"C:\sb\localappdata\uv\cache\builds-v0\.tmpabcd\my_package-1.2.3";

    // Step 1: hook records overlay entry (lowercase key → physical path).
    p.record_overlay(child_lower, overlay_phys).unwrap();

    // Step 2: hook records the original-case basename.
    p.record_overlay_case(child_lower, original_name);

    // Step 3: dir-filter queries the policy daemon for overlay-only children.
    // This is what `build_case_map_with_fallback`'s IPC fallback calls server-side.
    let pairs = p.overlay_children_with_case(parent_lower);

    assert_eq!(
        pairs.len(), 1,
        "exactly one child with a case record expected, got: {:?}", pairs
    );
    let (lower_got, original_got) = &pairs[0];
    assert_eq!(lower_got, "my_package-1.2.3",
        "lowercase key must match the physical storage name");
    assert_eq!(original_got, original_name,
        "original name must be the mixed-case name recorded at write time");

    // Step 4 (invariant): a purely-lowercase basename is NOT stored, so it
    // never appears in the IPC response.  Git object directories use names
    // like "4b825dc642cb6eb9a060e54bf8d69288fbee4904" — all hex lowercase.
    // These must NOT pollute the OVERLAY_CASE table (optimization guard, also
    // the mechanism that kept the `72d46d9` case-preservation fix from
    // corrupting all-lowercase git object names on the HTTPS retry).
    let git_objects_lower = r"c:\localappdata\uv\cache\builds-v0\.tmpabcd\git_objects";
    let git_obj_name      = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
    p.record_overlay(
        &format!("{}\\{}", git_objects_lower, git_obj_name),
        &format!("C:\\sb\\{}", git_obj_name),
    ).unwrap();
    p.record_overlay_case(
        &format!("{}\\{}", git_objects_lower, git_obj_name),
        git_obj_name, // all-lowercase → must be silently skipped
    );
    let git_pairs = p.overlay_children_with_case(git_objects_lower);
    assert!(
        git_pairs.is_empty(),
        "all-lowercase git object name must NOT be stored in OVERLAY_CASE; got: {:?}", git_pairs
    );
}

// ── Regression ratchet: Pattern #5 — proxy for "large git clone unaffected"
//
// The real `72d46d9` regression broke large `git clone` because the
// case-preservation hook rewrote git's lowercase-hex object filenames
// (e.g. "4b825dc6…") incorrectly.  A full git clone is too slow/flaky
// for CI.  This proxy test confirms the deterministic policy-side property
// that guards against the regression:
//
//   "An all-lowercase path stored in OVERLAY_CASE via record_overlay_case
//    is silently dropped (optimization), so overlay_children_with_case
//    returns empty for a directory containing only lowercase-hex-named
//    overlay entries — exactly the guarantee that stops the rewrite hook
//    from ever touching git object file names."
//
// REGRESSION TARGET: if `record_overlay_case` is changed to store
// all-lowercase names too (removing the `to_ascii_lowercase()` guard),
// the second assertion fails and `overlay_children_with_case` starts
// returning entries for git object dirs — re-introducing the `72d46d9` bug.
//
// NOTE: A live end-to-end test requires network + 5–10 min clone time and
// is deliberately manual-only (see docs/checkpoints/ for the 3/3 manual
// verification record). This proxy covers the deterministic half.
#[test]
fn git_clone_case_proxy_lowercase_hex_objects_not_stored() {
    let (_dir, p, _project) = make_policy_with_project("proj");

    // Simulate a git object pack layout inside the sandbox overlay.
    // All names are lowercase hex — representative of real git pack files.
    let git_objects_dir = r"c:\repo\.git\objects\pack";
    let hex_names = [
        "pack-4b825dc642cb6eb9a060e54bf8d69288fbee4904.idx",
        "pack-4b825dc642cb6eb9a060e54bf8d69288fbee4904.pack",
        "pack-deadbeefcafe0000000000000000000000000000.idx",
    ];

    for name in &hex_names {
        let full_lower = format!("{}\\{}", git_objects_dir, name);
        let phys       = format!("C:\\sb\\repo\\.git\\objects\\pack\\{}", name);
        p.record_overlay(&full_lower, &phys).unwrap();
        // Hook calls record_overlay_case with the original name; for all-
        // lowercase git names the original IS the lowercase → no-op.
        p.record_overlay_case(&full_lower, name);
    }

    // The IPC fallback (overlay_children_with_case) must return empty:
    // git object names are all-lowercase, so OVERLAY_CASE has no entries
    // for this directory. The dir-filter rewrite path then has nothing to
    // do and leaves the buffer unchanged — no corruption of git pack index.
    let pairs = p.overlay_children_with_case(git_objects_dir);
    assert!(
        pairs.is_empty(),
        "no OVERLAY_CASE entries must exist for all-lowercase git object names; \
         got {pairs:?} — reverting would re-introduce the 72d46d9 regression"
    );

    // Sanity: a second directory with a mixed-case overlay entry IS stored
    // and returned.  This confirms the mechanism works and the empty result
    // above is because of the all-lowercase filter, not a broken table.
    let mixed_dir  = r"c:\repo\src";
    let mixed_full = r"c:\repo\src\MyModule";
    p.record_overlay(mixed_full, r"C:\sb\repo\src\mymodule").unwrap();
    p.record_overlay_case(mixed_full, "MyModule");
    let mixed_pairs = p.overlay_children_with_case(mixed_dir);
    assert_eq!(mixed_pairs.len(), 1,
        "mixed-case entry must be stored and retrievable; control group");
    assert_eq!(mixed_pairs[0].1, "MyModule");
}

// ── overlay_children (enum-merge fix: ghost-file listing bug) ──────────
//
// `overlay_children(dir)` returns ALL overlay-only direct children of
// `dir` — regardless of whether an OVERLAY_CASE record exists — because
// the enum-hook injects them into real directory listings so a CoW'd
// file outside project_root is no longer invisible to `dir`/`ls` while
// still readable via direct open (the "ghost file" bug).

#[test]
fn overlay_children_returns_direct_children_only() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    p.record_overlay(r"d:\out\a.txt", r"C:\sb\out\a.txt").unwrap();
    p.record_overlay(r"d:\out\b.log", r"C:\sb\out\b.log").unwrap();
    // Descendant of a subdir — NOT a direct child of d:\out.
    p.record_overlay(r"d:\out\sub\deep.txt", r"C:\sb\out\sub\deep.txt").unwrap();
    // Different directory entirely.
    p.record_overlay(r"d:\bar\c.txt", r"C:\sb\bar\c.txt").unwrap();

    let mut names: Vec<String> = p.overlay_children(r"d:\out")
        .into_iter().map(|e| e.name).collect();
    names.sort();
    assert_eq!(names, vec!["a.txt".to_string(), "b.log".to_string()],
        "overlay_children must return only direct children");
}

#[test]
fn overlay_children_empty_when_no_match() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    p.record_overlay(r"d:\out\a.txt", r"C:\sb\out\a.txt").unwrap();
    let entries = p.overlay_children(r"d:\empty");
    assert!(entries.is_empty(), "no overlay entries under an unrelated dir");
}

#[test]
fn overlay_children_sibling_prefix_not_confused() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    p.record_overlay(r"d:\outbar\evil.txt", r"C:\sb\outbar\evil.txt").unwrap();
    let entries = p.overlay_children(r"d:\out");
    assert!(entries.is_empty(), "d:\\out must not see d:\\outbar's children");
}

/// No OVERLAY_CASE record exists (legacy / lowercase-created entry) →
/// the raw lowercase key segment is used as the basename, not dropped.
/// This is the key behavioral difference from `overlay_children_with_case`,
/// which requires a case record and would return nothing here.
#[test]
fn overlay_children_falls_back_to_lowercase_without_case_record() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    p.record_overlay(r"d:\out\probe_cmd.txt", r"C:\sb\out\probe_cmd.txt").unwrap();
    let entries = p.overlay_children(r"d:\out");
    assert_eq!(entries.len(), 1, "got: {:?}", entries);
    assert_eq!(entries[0].name, "probe_cmd.txt");
}

/// When an OVERLAY_CASE record exists, the original-case name wins over
/// the lowercase key.
#[test]
fn overlay_children_uses_case_record_when_present() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    p.record_overlay(r"d:\out\mixed_case_dir", r"C:\sb\out\mixed_case_dir").unwrap();
    p.record_overlay_case(r"d:\out\mixed_case_dir", "Mixed_Case_Dir");
    let entries = p.overlay_children(r"d:\out");
    assert_eq!(entries.len(), 1, "got: {:?}", entries);
    assert_eq!(entries[0].name, "Mixed_Case_Dir");
}

/// `is_dir` reflects the real type of the physical overlay node: a file
/// on disk at the overlay path → false.
#[test]
fn overlay_children_is_dir_false_for_file() {
    let (dir, p, _project) = make_policy_with_project("proj");
    let phys = dir.path().join("overlay_file.txt");
    std::fs::write(&phys, b"x").unwrap();
    p.record_overlay(r"d:\out\probe.txt", phys.to_str().unwrap()).unwrap();
    let entries = p.overlay_children(r"d:\out");
    assert_eq!(entries.len(), 1, "got: {:?}", entries);
    assert_eq!(entries[0].name, "probe.txt");
    assert!(!entries[0].is_dir);
}

/// `is_dir` → true when the physical overlay node is a real directory.
#[test]
fn overlay_children_is_dir_true_for_directory() {
    let (dir, p, _project) = make_policy_with_project("proj");
    let phys = dir.path().join("overlay_subdir");
    std::fs::create_dir_all(&phys).unwrap();
    p.record_overlay(r"d:\out\subdir", phys.to_str().unwrap()).unwrap();
    let entries = p.overlay_children(r"d:\out");
    assert_eq!(entries.len(), 1, "got: {:?}", entries);
    assert_eq!(entries[0].name, "subdir");
    assert!(entries[0].is_dir);
}

/// The overlay physical path doesn't exist on disk (e.g. race / stale
/// index entry) → is_dir defaults to false and all metadata is zeroed,
/// rather than panicking.
#[test]
fn overlay_children_missing_physical_path_defaults_zeroed() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    p.record_overlay(r"d:\out\stale.txt", r"C:\sb\does\not\exist.txt").unwrap();
    let entries = p.overlay_children(r"d:\out");
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(e.name, "stale.txt");
    assert!(!e.is_dir);
    assert_eq!(e.size, 0);
    assert_eq!(e.creation_time, 0);
    assert_eq!(e.last_access_time, 0);
    assert_eq!(e.last_write_time, 0);
}

/// A real physical overlay file's size and write time are reported
/// verbatim — this is what lets `dir` show a plausible size/date instead
/// of the placeholder 0-byte / 1601-01-01 that a synthesized zeroed
/// entry would otherwise show (the merged-listing metadata mismatch a
/// live agent flagged as a stealth defect).
#[test]
fn overlay_children_reports_real_size_and_nonzero_write_time() {
    let (dir, p, _project) = make_policy_with_project("proj");
    let phys = dir.path().join("overlay_file.txt");
    std::fs::write(&phys, b"twelve bytes").unwrap(); // 12 bytes
    p.record_overlay(r"d:\out\probe.txt", phys.to_str().unwrap()).unwrap();
    let entries = p.overlay_children(r"d:\out");
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(e.size, 12);
    assert!(e.last_write_time > 0, "a just-written file must have a nonzero FILETIME");
    assert!(e.creation_time > 0);
}

/// A physical overlay directory reports size 0 (directories have no
/// EndOfFile) but still a real, nonzero write time.
#[test]
fn overlay_children_directory_reports_zero_size_nonzero_time() {
    let (dir, p, _project) = make_policy_with_project("proj");
    let phys = dir.path().join("overlay_subdir");
    std::fs::create_dir_all(&phys).unwrap();
    p.record_overlay(r"d:\out\subdir", phys.to_str().unwrap()).unwrap();
    let entries = p.overlay_children(r"d:\out");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].size, 0);
    assert!(entries[0].last_write_time > 0);
}

// ── Regression ratchet: Pattern #2 — multi-level whiteout cascade
//
// NOTE: `clear_whiteout_cascades_to_children` already covers this at the
// policy level with dir + .git + .git\config + .git\HEAD + sibling prefix.
// Verification that it exists (OBSERVED):
//   winrsbox/policy/src/lib.rs:643  fn clear_whiteout_cascades_to_children
//
// No additional test needed; the existing one is already the tight regression
// guard.  Listed here for completeness of the ratchet inventory.

// ── Regression ratchet: Pattern #3 — Passthrough/Hidden not cached by decide()
//
// The two tests `passthrough_not_stored_in_hook_cache` and
// `hidden_not_stored_in_hook_cache` in hook/src/hooks.rs test the RAW
// HookCache API, not the decide()-level skip at line 233:
//
//     if !matches!(d.mode, Mode::Passthrough | Mode::Hidden) {
//         cache().insert(dos_path, write, d.clone());
//     }
//
// Testing this skip directly requires calling decide(), which calls
// ipc_decide() (live IPC to the policy server) and is therefore not
// exercisable at unit-test level without a running winrsbox server.
//
// CONSEQUENCE: the decide()-skip branch is covered by E2E/manual tests only
// (Hermes install verification, Bug #75/#78 notes in the commit log).
// The unit tests confirm the cache CAN store Passthrough/Hidden via raw
// insert — i.e. the filter is in decide(), not the cache data structure.
// This is the strongest assertion possible at unit level.  Intentionally
// left as manual-only for the decide() path.

// ── Regression ratchet: Pattern #4 — partial-delete whiteout branches
//
// All four branches of decide_post_delete() are tested in
// hook/src/fs_metadata_guard.rs (OBSERVED):
//   - decide_post_delete_success_removes_idx
//   - decide_post_delete_not_empty_records_whiteout_keeps_overlay
//   - decide_post_delete_sharing_violation_records_whiteout_keeps_overlay
//   - decide_post_delete_other_error_skips
// No additional coverage needed here.
