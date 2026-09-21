use super::*;

#[test]
fn literal_prefix() {
    assert!(pattern_matches_prefix(r"c:\windows", r"c:\windows\system32\foo"));
    assert!(pattern_matches_prefix(r"c:\windows", r"c:\windows"));
    assert!(!pattern_matches_prefix(r"c:\windows", r"c:\users"));
}

#[test]
fn star_in_segment() {
    assert!(pattern_matches_prefix(r"c:\users\*\.ssh", r"c:\users\alice\.ssh\id_rsa"));
    assert!(pattern_matches_prefix(r"c:\users\*", r"c:\users\bob"));
    assert!(!pattern_matches_prefix(r"c:\users\*\.ssh", r"c:\users\alice\docs"));
}

#[test]
fn star_partial_segment() {
    assert!(segment_match("foo*", "foobar"));
    assert!(segment_match("*bar", "foobar"));
    assert!(segment_match("f*o*r", "foobar"));
    assert!(!segment_match("foo*", "fobar"));
}

#[test]
fn specificity_orders_rules() {
    let a = pattern_specificity(r"c:\users\*\.ssh");
    let b = pattern_specificity(r"c:\users\alice\.ssh");
    assert!(b > a);
}

#[test]
fn exact_match_no_extra_segments() {
    assert!(pattern_matches_exact(r"c:\fake\token.txt", r"c:\fake\token.txt"));
    assert!(!pattern_matches_exact(r"c:\fake\token.txt", r"c:\fake\token.txt\sub"));
    assert!(pattern_matches_exact(r"c:\fake\*.txt", r"c:\fake\token.txt"));
    assert!(!pattern_matches_exact(r"c:\fake\*.txt", r"c:\fake\token.exe"));
}

// ── segment_match edge cases ────────────────────────────────────────────

#[test]
fn segment_match_question_mark() {
    assert!(segment_match("f?o", "foo"));
    assert!(segment_match("???", "abc"));
    // BUG: segment_match("f?o", "fdo") returns true because ? matches 'd' and then 'o' == 'o'
    // This is correct glob behavior — ? matches any single char. The test was wrong.
    assert!(segment_match("f?o", "fdo")); // ? matches 'd', then 'o'=='o' → true
    assert!(!segment_match("?", "ab"));     // ? does not match empty
}

#[test]
fn segment_match_star_only() {
    assert!(segment_match("*", ""));
    assert!(segment_match("*", "anything"));
    assert!(segment_match("*", "multi part with spaces"));
}

#[test]
fn segment_match_multiple_stars() {
    assert!(segment_match("*a*", "bar"));
    assert!(segment_match("*a*", "a"));
    assert!(!segment_match("*a*", "bcd"));
}

#[test]
fn segment_match_empty_pattern_empty_text() {
    assert!(segment_match("", ""));
}

#[test]
fn segment_match_empty_pattern_nonempty_text() {
    assert!(!segment_match("", "x"));
}

#[test]
fn segment_match_nonempty_pattern_empty_text() {
    assert!(!segment_match("x", ""));
    assert!(segment_match("*", "")); // star matches empty
}

// ── pattern_matches_prefix edge cases ───────────────────────────────────

#[test]
fn prefix_empty_pattern() {
    assert!(pattern_matches_prefix("", r"c:\anything"));
    assert!(pattern_matches_prefix("", ""));
}

#[test]
fn prefix_path_shorter_than_pattern() {
    assert!(!pattern_matches_prefix(r"c:\a\b\c", r"c:\a"));
}

#[test]
fn prefix_consecutive_backslashes_do_not_bypass() {
    // Hostile doubled / extra separators collapse like the NT parser does,
    // so they still match a deny rule (audit C1).
    assert!(pattern_matches_prefix(r"c:\windows\system32", "c:\\\\windows\\\\system32\\\\cmd.exe"));
    assert!(pattern_matches_prefix(r"c:\windows", "c:\\\\windows\\foo"));
    // Trailing separators are harmless too.
    assert!(pattern_matches_prefix(r"c:\windows", "c:\\windows\\"));
    // Sanity: genuinely different paths still do not match.
    assert!(!pattern_matches_prefix(r"c:\windows", r"c:\winnt\system32"));
}

#[test]
fn prefix_unicode_segments() {
    assert!(pattern_matches_prefix(r"c:\привет", r"c:\привет\file.txt"));
    assert!(!pattern_matches_prefix(r"c:\привет", r"c:\пока"));
}

#[test]
fn prefix_question_mark_wildcard() {
    assert!(pattern_matches_prefix(r"c:\???\test", r"c:\abc\test\file"));
    assert!(!pattern_matches_prefix(r"c:\??\test", r"c:\abc\test"));
}

// ── pattern_matches_exact edge cases ─────────────────────────────────────

#[test]
fn exact_empty_both() {
    assert!(pattern_matches_exact("", ""));
}

#[test]
fn exact_empty_pattern_nonempty_path() {
    assert!(!pattern_matches_exact("", "x"));
}

#[test]
fn exact_wildcard_star() {
    assert!(pattern_matches_exact(r"c:\*\*.txt", r"c:\sub\file.txt"));
    assert!(!pattern_matches_exact(r"c:\*\*.txt", r"c:\sub\file.exe"));
}

#[test]
fn exact_different_lengths() {
    assert!(!pattern_matches_exact(r"c:\a", r"c:\a\b"));
    assert!(!pattern_matches_exact(r"c:\a\b", r"c:\a"));
}

// ── ** globstar tests ──────────────────────────────────────────────────────

#[test]
fn globstar_prefix_basic() {
    assert!(pattern_matches_prefix(r"c:\users\**\.ssh", r"c:\users\alice\.ssh"));
    assert!(pattern_matches_prefix(r"c:\users\**\.ssh", r"c:\users\alice\sub\.ssh"));
    assert!(pattern_matches_prefix(r"c:\users\**\.ssh", r"c:\users\.ssh"));
}

#[test]
fn globstar_prefix_trailing() {
    assert!(pattern_matches_prefix(r"c:\**", r"c:\anything"));
    assert!(pattern_matches_prefix(r"c:\**", r"c:\a\b\c"));
    assert!(pattern_matches_prefix(r"c:\**", r"c:"));
}

#[test]
fn globstar_prefix_miss() {
    assert!(!pattern_matches_prefix(r"c:\users\**\.ssh", r"c:\users\alice\docs"));
    assert!(!pattern_matches_prefix(r"c:\**\.ssh", r"c:\users\docs"));
}

#[test]
fn globstar_prefix_multiple() {
    assert!(pattern_matches_prefix(r"c:\**\foo\**\.bar", r"c:\foo\.bar"));
    assert!(pattern_matches_prefix(r"c:\**\foo\**\.bar", r"c:\x\foo\.bar"));
    assert!(pattern_matches_prefix(r"c:\**\foo\**\.bar", r"c:\x\foo\y\.bar"));
    assert!(pattern_matches_prefix(r"c:\**\foo\**\.bar", r"c:\foo\y\z\.bar"));
    assert!(pattern_matches_prefix(r"c:\**\foo\**\.bar", r"c:\a\b\foo\c\d\.bar"));
}

#[test]
fn globstar_prefix_at_start() {
    assert!(pattern_matches_prefix(r"**\.ssh", r"c:\users\alice\.ssh"));
    assert!(pattern_matches_prefix(r"**\.ssh", r".ssh"));
}

#[test]
fn globstar_prefix_consecutive() {
    // Two ** in a row is equivalent to one **
    assert!(pattern_matches_prefix(r"c:\**\**\foo", r"c:\a\b\foo"));
    assert!(pattern_matches_prefix(r"c:\**\**\foo", r"c:\foo"));
}

#[test]
fn globstar_mixed_star_treated_as_single() {
    // **foo is NOT globstar — treated as regular single-segment glob
    assert!(pattern_matches_prefix(r"c:\**foo", r"c:\barfoo"));
    // Still a single segment match — no multi-segment
    assert!(!pattern_matches_prefix(r"c:\**foo", r"c:\a\barfoo"));
}

#[test]
fn globstar_exact_basic() {
    assert!(pattern_matches_exact(r"c:\**\foo.txt", r"c:\foo.txt"));
    assert!(pattern_matches_exact(r"c:\**\foo.txt", r"c:\sub\foo.txt"));
    assert!(pattern_matches_exact(r"c:\**\foo.txt", r"c:\a\b\c\foo.txt"));
    assert!(!pattern_matches_exact(r"c:\**\foo.txt", r"c:\bar.exe"));
}

#[test]
fn globstar_exact_trailing() {
    assert!(pattern_matches_exact(r"c:\**", r"c:\foo"));
    assert!(pattern_matches_exact(r"c:\**", r"c:\a\b\c"));
    assert!(pattern_matches_exact(r"c:\**", r"c:"));
    assert!(!pattern_matches_exact(r"c:\**", r"d:\foo"));
}

#[test]
fn globstar_exact_miss() {
    // Extra segments after the pattern = mismatch
    assert!(!pattern_matches_exact(r"c:\**\foo", r"c:\a\foo\extra"));
}

#[test]
fn globstar_specificity_zero() {
    // ** counts as 0 literals (like *)
    assert_eq!(pattern_specificity("**"), 0);
    // c:\**\foo → non-wildcard chars: c, :, \, \, f, o, o = 7
    assert_eq!(pattern_specificity(r"c:\**\foo"), 7);
}

// ── proptest: pattern_matches_prefix invariants ─────────────────────────

proptest::proptest! {
    #[test]
    fn proptest_prefix_empty_always_true(path: String) {
        proptest::prop_assert!(pattern_matches_prefix("", &path));
    }

    #[test]
    fn proptest_prefix_self_match(path: String) {
        proptest::prop_assert!(pattern_matches_prefix(&path, &path));
    }

    #[test]
    fn proptest_prefix_subpath_extends(
        prefix in "[a-z]{1,4}(\\\\[a-z]{1,4}){0,3}",
        suffix in "(\\\\[a-z]{1,4}){1,3}",
    ) {
        let path = format!("{prefix}{suffix}");
        proptest::prop_assert!(pattern_matches_prefix(&prefix, &path));
    }

    #[test]
    fn proptest_segment_match_literal(a: String, b: String) {
        let has_wild = a.contains('*') || a.contains('?');
        if !has_wild {
            proptest::prop_assert_eq!(segment_match(&a, &b), a == b);
        }
    }
}
