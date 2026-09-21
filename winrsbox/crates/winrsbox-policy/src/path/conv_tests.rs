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

#[test]
fn nt_to_dos_dot_device_prefix() {
    let raw: Vec<u16> = r"\\.\C:\foo".encode_utf16().collect();
    assert_eq!(nt_to_dos(&raw), Some("C:\\foo".to_string()));
}

#[test]
fn nt_to_dos_double_backslash_unc() {
    let raw: Vec<u16> = r"\\server\share\foo".encode_utf16().collect();
    assert_eq!(nt_to_dos(&raw), None);
}

#[test]
fn nt_to_dos_no_drive_letter() {
    let raw: Vec<u16> = r"\??\foo\bar".encode_utf16().collect();
    assert_eq!(nt_to_dos(&raw), None);
}

#[test]
fn nt_to_dos_lower_casefold() {
    let raw: Vec<u16> = r"\??\C:\Users\ALICE\FOO.TXT".encode_utf16().collect();
    let result = nt_to_dos_lower(&raw).unwrap();
    assert_eq!(result, "c:\\users\\alice\\foo.txt");
}

#[test]
fn nt_to_dos_non_ascii_preserved() {
    let raw: Vec<u16> = r"\??\C:\привет.txt".encode_utf16().collect();
    let result = nt_to_dos(&raw).unwrap();
    assert!(result.contains("привет"));
}

#[test]
fn nt_to_dos_lower_non_ascii_preserved() {
    let raw: Vec<u16> = r"\??\C:\ФУΓ.txt".encode_utf16().collect();
    let result = nt_to_dos_lower(&raw).unwrap();
    assert!(result.contains("ФУΓ"));
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

#[test]
fn mirror_preserves_drive_as_dir() {
    let root = std::path::Path::new(r"/sandbox");
    let result = mirror_into_overlay(r"d:\file.txt", root);
    assert_eq!(result, std::path::PathBuf::from(r"/sandbox/d\file.txt"));
}

#[test]
fn mirror_deeply_nested() {
    let root = std::path::Path::new(r"\sb");
    let result = mirror_into_overlay(r"c:\a\b\c\d\e\f.txt", root);
    assert_eq!(result, std::path::PathBuf::from(r"\sb\c\a\b\c\d\e\f.txt"));
}

// ── path-traversal escape regression (audit fix #1 — CRITICAL) ──────

#[test]
fn mirror_dotdot_stripped() {
    let root = std::path::Path::new(r"\sb");
    let result = mirror_into_overlay(r"c:\allowed\..\..\..\windows\system32\evil.dll", root);
    assert!(
        result.starts_with(root),
        "overlay path {result:?} must stay under sandbox root {root:?}",
    );
    assert!(
        !result.to_str().unwrap().contains(".."),
        "overlay path {result:?} must not contain '..' components",
    );
    assert_eq!(result, std::path::PathBuf::from(r"\sb\c\allowed\windows\system32\evil.dll"));
}

#[test]
fn mirror_absolute_component_stripped() {
    let root = std::path::Path::new(r"\sb");
    let evil = r"\windows\system32\evil.dll";
    let result = mirror_into_overlay(evil, root);
    assert!(result.starts_with(root));
}

#[test]
fn mirror_curdir_stripped() {
    let root = std::path::Path::new(r"\sb");
    let result = mirror_into_overlay(r"c:\users\.\.\file.txt", root);
    assert!(!result.to_str().unwrap().contains(r"\."));
}

#[test]
fn mirror_many_dotdot_does_not_escape() {
    let root = std::path::Path::new(r"\sb");
    let traversal = r"c:\a\..\..\..\..\..\..\..\..\windows\system32\cmd.exe";
    let result = mirror_into_overlay(traversal, root);
    assert!(
        result.starts_with(root),
        "even many '..' must not escape root: {result:?}",
    );
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

#[test]
fn ascii_lower_handles_surrogate_pairs() {
    // U+1F600 (😀) = surrogate pair 0xD83D 0xDE00 in UTF-16
    let input: [u16; 6] = [b'A' as u16, b'b' as u16, 0xD83D, 0xDE00, b'C' as u16, b'd' as u16];
    let out = u16_slice_to_ascii_lower(&input, true);
    assert!(out.starts_with("ab"), "expected lowercase ab prefix: {:?}", out);
    assert!(out.ends_with("cd"), "expected lowercase cd suffix: {:?}", out);
    assert!(out.contains('\u{1F600}'), "emoji preserved: {:?}", out);
    assert_eq!(out, "ab\u{1F600}cd");

    // Without lowercase flag — A and C stay uppercase
    let out_no_lower = u16_slice_to_ascii_lower(&input, false);
    assert_eq!(out_no_lower, "Ab\u{1F600}Cd");
}

// ── fold_dos_dots ──────────────────────────────────────────────────────

#[test]
fn fold_dos_basic() {
    assert_eq!(fold_dos_dots(r"c:\proj\sub\..\file.txt"), r"c:\proj\file.txt");
}

#[test]
fn fold_dos_multi_dotdot() {
    assert_eq!(fold_dos_dots(r"c:\proj\..\..\outside.exe"), r"c:\outside.exe");
}

#[test]
fn fold_dos_clamped_at_root() {
    // `..` past the volume root clamps at the anchor, like the kernel does.
    assert_eq!(fold_dos_dots(r"c:\..\..\x"), r"c:\x");
    assert_eq!(fold_dos_dots(r"\..\..\..\y"), r"\y");
}

#[test]
fn fold_dos_curdir_dropped() {
    assert_eq!(fold_dos_dots(r"c:\proj\.\x"), r"c:\proj\x");
    assert_eq!(fold_dos_dots(r"c:\proj\.\.\file.txt"), r"c:\proj\file.txt");
}

#[test]
fn fold_dos_forward_slash_normalized() {
    // `/` is accepted as a separator and normalized to `\` in rewritten output.
    assert_eq!(fold_dos_dots(r"c:\proj/..\..\x"), r"c:\x");
    assert_eq!(fold_dos_dots(r"c:\a/b/../c"), r"c:\a\c");
}

#[test]
fn fold_dos_drive_anchor_preserved() {
    // The leading `x:` anchor is preserved verbatim, including its case.
    assert_eq!(fold_dos_dots(r"D:\x\..\y"), r"D:\y");
    assert_eq!(fold_dos_dots(r"c:\proj\sub\..\file.txt"), r"c:\proj\file.txt");
}

#[test]
fn fold_dos_empty_interior_segments_collapsed() {
    assert_eq!(fold_dos_dots(r"c:\a\\b\..\c"), r"c:\a\c");
}

#[test]
fn fold_dos_borrowed_fast_path() {
    // No `.`/`..` segment, no interior empty segment → Borrowed, no alloc.
    let r = fold_dos_dots(r"c:\proj\");
    assert!(matches!(r, std::borrow::Cow::Borrowed(_)));
    let r = fold_dos_dots(r"c:\a\b\c.txt");
    assert!(matches!(r, std::borrow::Cow::Borrowed(_)));
}

#[test]
fn fold_dos_relative_path_unchanged() {
    // A bare relative name has no anchor to clamp against → unchanged.
    let r = fold_dos_dots(r"relative\path");
    assert!(matches!(r, std::borrow::Cow::Borrowed(_)));
    assert_eq!(r, r"relative\path");
    // Even with dots — folding an unanchored path is undefined → unchanged.
    let r = fold_dos_dots(r"relative\..\x");
    assert!(matches!(r, std::borrow::Cow::Borrowed(_)));
    assert_eq!(r, r"relative\..\x");
}

#[test]
fn fold_dos_trailing_separator_preserved() {
    assert_eq!(fold_dos_dots(r"c:\proj\sub\..\"), r"c:\proj\");
    assert_eq!(fold_dos_dots(r"c:\proj\sub\..\file"), r"c:\proj\file");
}

// ── fold_nt_dots ───────────────────────────────────────────────────────

#[test]
fn fold_nt_basic() {
    let raw: Vec<u16> = r"\??\C:\proj\..\..\payload.exe".encode_utf16().collect();
    let out = fold_nt_dots(&raw);
    let expected: Vec<u16> = r"\??\C:\payload.exe".encode_utf16().collect();
    assert_eq!(&*out, &expected[..]);
}

#[test]
fn fold_nt_extended_and_device_prefixes() {
    let raw: Vec<u16> = r"\\?\C:\a\.\b".encode_utf16().collect();
    let expected: Vec<u16> = r"\\?\C:\a\b".encode_utf16().collect();
    assert_eq!(&*fold_nt_dots(&raw), &expected[..]);

    let raw: Vec<u16> = r"\??\C:\..\..\x".encode_utf16().collect();
    let expected: Vec<u16> = r"\??\C:\x".encode_utf16().collect();
    assert_eq!(&*fold_nt_dots(&raw), &expected[..]);
}

#[test]
fn fold_nt_unrecognized_prefix_unchanged() {
    // \Device\... style paths have no NT drive prefix → Borrowed unchanged.
    let raw: Vec<u16> = r"\Device\HarddiskVolume1\x".encode_utf16().collect();
    let r = fold_nt_dots(&raw);
    assert!(matches!(r, std::borrow::Cow::Borrowed(_)));
    assert_eq!(&*r, &raw[..]);
}

#[test]
fn fold_nt_case_and_surrogate_pair_preserved() {
    // U+1F600 (😀) = surrogate pair 0xD83D 0xDE00; uppercase C: must stay
    // uppercase — every non-folded unit passes through verbatim.
    let mut raw: Vec<u16> = r"\??\C:\a\".encode_utf16().collect();
    raw.extend_from_slice(&[0xD83D, 0xDE00]);
    raw.extend(r"\sub\..\file".encode_utf16());
    let out = fold_nt_dots(&raw);
    let mut expected: Vec<u16> = r"\??\C:\a\".encode_utf16().collect();
    expected.extend_from_slice(&[0xD83D, 0xDE00]);
    expected.extend(r"\file".encode_utf16());
    assert_eq!(&*out, &expected[..]);
}

#[test]
fn fold_nt_forward_slash_normalized() {
    let raw: Vec<u16> = r"\??\C:\a/b\..\c".encode_utf16().collect();
    let expected: Vec<u16> = r"\??\C:\a\c".encode_utf16().collect();
    assert_eq!(&*fold_nt_dots(&raw), &expected[..]);
}

#[test]
fn fold_nt_borrowed_fast_path() {
    let raw: Vec<u16> = r"\??\C:\a\b".encode_utf16().collect();
    let r = fold_nt_dots(&raw);
    assert!(matches!(r, std::borrow::Cow::Borrowed(_)));
}

#[test]
fn fold_nt_trailing_separator_preserved() {
    let raw: Vec<u16> = r"\??\C:\a\..\".encode_utf16().collect();
    let expected: Vec<u16> = r"\??\C:\".encode_utf16().collect();
    assert_eq!(&*fold_nt_dots(&raw), &expected[..]);
}

#[test]
fn fold_dos_and_nt_agree() {
    // Cross-check: folding a DOS string and its \??\-prefixed UTF-16
    // encoding yields the same tail once the 4-unit prefix is stripped.
    let dos = r"c:\proj\sub\..\file.txt";
    let folded_dos = fold_dos_dots(dos);
    let mut raw: Vec<u16> = vec![0x5C, 0x3F, 0x3F, 0x5C]; // \??\
    raw.extend(dos.encode_utf16());
    let folded_nt = fold_nt_dots(&raw);
    let nt_tail = String::from_utf16(&folded_nt[4..]).unwrap();
    assert_eq!(&*folded_dos, nt_tail.as_str());
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
