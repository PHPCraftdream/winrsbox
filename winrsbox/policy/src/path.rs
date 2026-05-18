use std::path::{Path, PathBuf};

/// Strip NT prefix and return DOS path (lowercase).
/// Handles \??\ and \\?\ prefixes.
/// Returns None for device paths, UNC \Device\... etc.
pub fn nt_to_dos(raw: &[u16]) -> Option<String> {
    _nt_to_dos_impl(raw, false)
}

/// Same as `nt_to_dos` but ASCII-lowercases the result in-place during
/// UTF-16 → UTF-8 conversion, avoiding a separate `to_lowercase()` pass.
/// Non-ASCII bytes are preserved as-is (sufficient for Windows paths which
/// are overwhelmingly ASCII; rare non-ASCII falls through unchanged).
pub fn nt_to_dos_lower(raw: &[u16]) -> Option<String> {
    _nt_to_dos_impl(raw, true)
}

fn _nt_to_dos_impl(raw: &[u16], lowercase: bool) -> Option<String> {
    // Trim trailing NUL units
    let raw = match raw.iter().position(|&u| u == 0) {
        Some(pos) => &raw[..pos],
        None => raw,
    };

    // Try stripping known NT prefixes by comparing raw u16 values (all ASCII).
    let stripped = strip_nt_prefix(raw)?;

    // Reject UNC paths
    if starts_with_u16_ascii(stripped, b"UNC\\") || starts_with_u16_ascii(stripped, b"\\\\") {
        return None;
    }

    // Must look like a drive-letter path: second u16 must be ':' (0x3A)
    if stripped.len() >= 2 && stripped[1] == 0x3A {
        Some(u16_slice_to_ascii_lower(stripped, lowercase))
    } else {
        None
    }
}

/// Returns the path slice after stripping `\??\`, `\\?\`, or `\\.\\`.
/// Returns None for `\Device\...` style paths (single leading backslash).
fn strip_nt_prefix(raw: &[u16]) -> Option<&[u16]> {
    // \??\ = [0x5C, 0x3F, 0x3F, 0x5C]
    if raw.len() > 4 && raw[0] == 0x5C && raw[1] == 0x3F && raw[2] == 0x3F && raw[3] == 0x5C {
        return Some(&raw[4..]);
    }
    // \\?\ = [0x5C, 0x5C, 0x3F, 0x5C]
    if raw.len() > 4 && raw[0] == 0x5C && raw[1] == 0x5C && raw[2] == 0x3F && raw[3] == 0x5C {
        return Some(&raw[4..]);
    }
    // \\.\\ = [0x5C, 0x5C, 0x2E, 0x5C]
    if raw.len() > 4 && raw[0] == 0x5C && raw[1] == 0x5C && raw[2] == 0x2E && raw[3] == 0x5C {
        return Some(&raw[4..]);
    }
    // Reject lone \Device\... paths (single backslash not followed by another)
    if !raw.is_empty() && raw[0] == 0x5C && (raw.len() < 2 || raw[1] != 0x5C) {
        return None;
    }
    Some(raw)
}

fn starts_with_u16_ascii(slice: &[u16], prefix: &[u8]) -> bool {
    if slice.len() < prefix.len() {
        return false;
    }
    slice[..prefix.len()].iter().zip(prefix.iter()).all(|(&u, &b)| u == b as u16)
}

/// Convert UTF-16 slice to String, optionally ASCII-lowercasing in one pass.
/// Non-ASCII codepoints are passed through to `char::from_u32` unchanged;
/// if they can't be decoded they become the replacement character (matching
/// the behaviour of `String::from_utf16_lossy`).
fn u16_slice_to_ascii_lower(raw: &[u16], lowercase: bool) -> String {
    let mut out = String::with_capacity(raw.len());
    for &u in raw {
        let c = if lowercase && u >= 0x41 && u <= 0x5A {
            // ASCII A-Z → a-z
            char::from_u32((u + 0x20) as u32).unwrap()
        } else {
            char::from_u32(u as u32).unwrap_or('\u{FFFD}')
        };
        out.push(c);
    }
    out
}

/// DOS path → NT path as null-terminated UTF-16.
pub fn dos_to_nt(dos: &str) -> Vec<u16> {
    let nt = format!(r"\??\{}", dos);
    let mut v: Vec<u16> = nt.encode_utf16().collect();
    v.push(0);
    v
}

/// C:\Users\x\foo.txt + sandbox_root → <root>\C\Users\x\foo.txt
pub fn mirror_into_overlay(dos_lower: &str, root: &Path) -> PathBuf {
    // Replace "C:" with "C" as a directory component
    let sanitized = dos_lower
        .replace(':', "")
        .replace('/', "\\");
    // Remove leading backslash if present
    let sanitized = sanitized.trim_start_matches('\\');
    root.join(sanitized)
}

// ─── Glob matching ───────────────────────────────────────────────────────────
//
// pattern_matches_prefix returns true if `pattern` matches `path` treating
// `\` as the segment separator. Each segment in the pattern is matched
// against the corresponding segment in the path with `*` and `?` wildcards
// (single-segment globbing). The path may have ADDITIONAL trailing segments
// beyond the pattern — this is a prefix match, not equality.

pub fn pattern_matches_prefix(pattern: &str, path: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    let mut pat_it = pattern.split('\\');
    let mut path_it = path.split('\\');
    loop {
        match (pat_it.next(), path_it.next()) {
            (Some(p), Some(s)) => {
                if !segment_match(p, s) {
                    return false;
                }
            }
            (None, _) => return true, // all pattern segments matched → prefix hit
            (Some(_), None) => return false, // path shorter than pattern
        }
    }
}

/// Match a single path segment against a glob pattern that may contain
/// `*` (zero or more chars) and `?` (one char). Backslash is NOT permitted
/// inside a segment (segments come from splitting on `\`).
/// Works on raw bytes — glob wildcards are ASCII, and Windows path segments
/// are overwhelmingly ASCII.
pub fn segment_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    // Fast path: no wildcards → direct equality.
    if !p.contains(&b'*') && !p.contains(&b'?') {
        return p == t;
    }
    // Two-pointer with backtrack — standard glob algorithm.
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_p, mut star_t): (Option<usize>, usize) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_p = Some(pi);
            star_t = ti;
            pi += 1;
        } else if let Some(sp) = star_p {
            pi = sp + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Number of literal (non-wildcard) characters in a pattern. Used to rank
/// matching rules: more literal chars = more specific = higher priority.
pub fn pattern_specificity(pattern: &str) -> usize {
    pattern.chars().filter(|c| *c != '*' && *c != '?').count()
}

/// Exact match with glob support: pattern matches path exactly (no extra
/// trailing segments). Used for file mocks where the mock must match a
/// specific file path, optionally with wildcards.
pub fn pattern_matches_exact(pattern: &str, path: &str) -> bool {
    if pattern.is_empty() {
        return path.is_empty();
    }
    let mut pat_it = pattern.split('\\').peekable();
    let mut path_it = path.split('\\').peekable();
    loop {
        let p = pat_it.next();
        let s = path_it.next();
        match (p, s) {
            (Some(pp), Some(ss)) => {
                if !segment_match(pp, ss) {
                    return false;
                }
            }
            (None, None) => return true,  // both exhausted simultaneously
            _ => return false,            // different segment counts
        }
    }
}

#[cfg(test)]
mod glob_tests {
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
}

#[cfg(test)]
mod conv_tests {
    use super::*;

    // ── nt_to_dos ──────────────────────────────────────────────────────────

    #[test]
    fn nt_to_dos_dos_device_prefix() {
        let raw: Vec<u16> = r"\??\C:\foo".encode_utf16().collect();
        assert_eq!(nt_to_dos(&raw), Some("C:\\foo".to_string()));
    }

    #[test]
    fn nt_to_dos_extended_prefix() {
        let raw: Vec<u16> = r"\\?\C:\foo".encode_utf16().collect();
        assert_eq!(nt_to_dos(&raw), Some("C:\\foo".to_string()));
    }

    #[test]
    fn nt_to_dos_no_prefix() {
        let raw: Vec<u16> = r"C:\foo".encode_utf16().collect();
        assert_eq!(nt_to_dos(&raw), Some("C:\\foo".to_string()));
    }

    #[test]
    fn nt_to_dos_device_path() {
        let raw: Vec<u16> = r"\Device\HarddiskVolume3\foo".encode_utf16().collect();
        assert_eq!(nt_to_dos(&raw), None);
    }

    #[test]
    fn nt_to_dos_unc_path() {
        let raw: Vec<u16> = r"\??\UNC\server\share".encode_utf16().collect();
        assert_eq!(nt_to_dos(&raw), None);
    }

    #[test]
    fn nt_to_dos_empty() {
        assert_eq!(nt_to_dos(&[]), None);
    }

    #[test]
    fn nt_to_dos_trailing_nul() {
        let raw: Vec<u16> = vec![b'C' as u16, b':' as u16, b'\\' as u16, b'x' as u16, 0];
        assert_eq!(nt_to_dos(&raw), Some("C:\\x".to_string()));
    }

    // ── dos_to_nt ──────────────────────────────────────────────────────────

    #[test]
    fn dos_to_nt_basic() {
        let nt = dos_to_nt(r"C:\foo");
        assert!(nt.last() == Some(&0), "must end with NUL");
        let s: String = nt.iter().take(nt.len() - 1)
            .filter_map(|&u| char::from_u32(u as u32))
            .collect();
        assert!(s.starts_with(r"\??\"), "must start with NT prefix: got {s}");
        assert!(s.ends_with(r"C:\foo"), "must end with original path: got {s}");
        assert_eq!(nt.len(), 4 + r"C:\foo".len() + 1);
    }

    #[test]
    fn dos_to_nt_utf16_content() {
        let nt = dos_to_nt("D:\\bar");
        let expected: Vec<u16> = r"\??\D:\bar".encode_utf16().chain(std::iter::once(0)).collect();
        assert_eq!(nt, expected);
    }

    // ── mirror_into_overlay ────────────────────────────────────────────────

    #[test]
    fn mirror_basic() {
        let root = std::path::Path::new(r"\sb");
        let result = mirror_into_overlay(r"c:\users\x\foo.txt", root);
        assert_eq!(result, std::path::PathBuf::from(r"\sb\c\users\x\foo.txt"));
    }

    #[test]
    fn mirror_forward_slash() {
        let root = std::path::Path::new(r"\sb");
        let result = mirror_into_overlay("d:/users/x", root);
        assert_eq!(result, std::path::PathBuf::from(r"\sb\d\users\x"));
    }

    #[test]
    fn mirror_leading_backslash_after_colon_strip() {
        let root = std::path::Path::new(r"\sb");
        let result = mirror_into_overlay(r"\x\y", root);
        assert_eq!(result, std::path::PathBuf::from(r"\sb\x\y"));
    }

    // pretty_assertions demo: shadows std assert_eq for richer diffs on mismatch.
    #[test]
    fn mirror_basic_pretty() {
        use pretty_assertions::assert_eq;
        let root = std::path::Path::new(r"\sb");
        assert_eq!(
            mirror_into_overlay(r"c:\users\alice\foo.txt", root),
            std::path::PathBuf::from(r"\sb\c\users\alice\foo.txt"),
        );
    }

    // proptest demo: any DOS path that survives nt_to_dos round-trips through
    // dos_to_nt and back to the same string.
    proptest::proptest! {
        #[test]
        fn dos_to_nt_to_dos_roundtrip(
            drive in "[A-Z]",
            tail in "[A-Za-z0-9_]{1,16}(\\\\[A-Za-z0-9_]{1,16}){0,4}",
        ) {
            let dos = format!("{drive}:\\{tail}");
            let nt = dos_to_nt(&dos);
            let nt_no_nul = &nt[..nt.len() - 1];
            let back = nt_to_dos(nt_no_nul).expect("round-trip should succeed");
            proptest::prop_assert_eq!(back, dos);
        }
    }
}
