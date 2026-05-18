use std::path::{Path, PathBuf};

/// Strip NT prefix and return DOS path (lowercase).
/// Handles \??\ and \\?\ prefixes.
/// Returns None for device paths, UNC \Device\... etc.
pub fn nt_to_dos(raw: &[u16]) -> Option<String> {
    let s = String::from_utf16_lossy(raw);
    let s = s.trim_end_matches('\0');

    let stripped = if let Some(r) = s.strip_prefix(r"\??\") {
        r
    } else if let Some(r) = s.strip_prefix(r"\\?\") {
        r
    } else if let Some(r) = s.strip_prefix(r"\\.\\") {
        r
    } else {
        // Absolute NT path without prefix (\Device\..., \BaseNamedObjects\...)
        if s.starts_with('\\') && !s.starts_with(r"\\") {
            return None;
        }
        s
    };

    // UNC: UNC\server\share
    if stripped.starts_with("UNC\\") || stripped.starts_with(r"\\") {
        return None;
    }

    // Must look like a drive letter path: X:\...
    if stripped.len() >= 2 && stripped.chars().nth(1) == Some(':') {
        Some(stripped.to_string())
    } else {
        None
    }
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
    let pat_segs: Vec<&str> = pattern.split('\\').collect();
    let path_segs: Vec<&str> = path.split('\\').collect();
    if path_segs.len() < pat_segs.len() {
        return false;
    }
    pat_segs
        .iter()
        .zip(path_segs.iter())
        .all(|(p, x)| segment_match(p, x))
}

/// Match a single path segment against a glob pattern that may contain
/// `*` (zero or more chars) and `?` (one char). Backslash is NOT permitted
/// inside a segment (segments come from splitting on `\`).
pub fn segment_match(pattern: &str, text: &str) -> bool {
    // Fast path: no wildcards → direct equality.
    if !pattern.contains('*') && !pattern.contains('?') {
        return pattern == text;
    }
    // Two-pointer with backtrack — standard glob algorithm.
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_p, mut star_t): (Option<usize>, usize) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
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
    while pi < p.len() && p[pi] == '*' {
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
    let pat_segs: Vec<&str> = pattern.split('\\').collect();
    let path_segs: Vec<&str> = path.split('\\').collect();
    if pat_segs.len() != path_segs.len() {
        return false;
    }
    pat_segs
        .iter()
        .zip(path_segs.iter())
        .all(|(p, x)| segment_match(p, x))
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
