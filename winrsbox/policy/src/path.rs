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

/// Same as `nt_to_dos_lower` but PRESERVES the original case of the path.
/// Used by the hook to build the physical overlay path: the overlay file must
/// be created with the original case so that case-sensitive consumers (Python
/// importlib's FileFinder caches os.listdir() results and does case-SENSITIVE
/// set lookups) can resolve modules whose names contain uppercase letters.
pub fn nt_to_dos_preserve(raw: &[u16]) -> Option<String> {
    _nt_to_dos_impl(raw, false)
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
/// Uses `char::decode_utf16` to correctly handle surrogate pairs (non-BMP
/// codepoints such as emoji, CJK extension B, etc.). Lone surrogates become
/// the replacement character U+FFFD, matching `String::from_utf16_lossy`.
fn u16_slice_to_ascii_lower(raw: &[u16], lowercase: bool) -> String {
    let mut out = String::with_capacity(raw.len());
    for r in std::char::decode_utf16(raw.iter().copied()) {
        match r {
            Ok(c) if lowercase && c.is_ascii_uppercase() => {
                out.push((c as u8 + 0x20) as char);
            }
            Ok(c) => {
                out.push(c);
            }
            Err(_) => {
                out.push('\u{FFFD}');
            }
        }
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
///
/// Only `Normal` path components are pushed onto `root`. Any `..`, absolute
/// prefix, root directory, or `.` component is silently dropped, preventing
/// a crafted DOS path from traversing outside the overlay root.
pub fn mirror_into_overlay(dos_lower: &str, root: &Path) -> PathBuf {
    let sanitized = dos_lower
        .replace(':', "")
        .replace('/', "\\");
    let sanitized = sanitized.trim_start_matches('\\');
    let mut out = root.to_path_buf();
    for component in Path::new(sanitized).components() {
        match component {
            std::path::Component::Normal(c) => out.push(c),
            _ => {}
        }
    }
    out
}

// ─── Same-volume overlay layout (fixes drive-letter identity leak) ──────────
//
// Background: the kernel's GetFinalPathNameByHandleW (class
// FileNormalizedNameInformation) reports a path as <volume-letter> + <volume-
// relative tail>, where the letter is taken from the PHYSICAL volume of the
// handle. When an overlay for a C:\... virtual path lived on a different
// volume (D:), the handle's volume was D:, so the reported path got D:
// glued on — a drive-letter identity leak (Bug A). user-mode masking of the
// class-48 tail can recover the path tail but NOT change the drive letter.
//
// Fix (Path 1, "same-volume overlay"): store the overlay for each virtual
// drive on that SAME drive. Then handle volume == virtual volume, and the
// kernel glues the correct letter. The existing class-48 masking becomes
// fully correct.
//
// `OverlayLayout` resolves, for a given virtual DOS path, the overlay root
// that lives on the same volume. `primary_root` is the project drive's root
// (kept as the default/fallback for backward compatibility and for drives
// with no explicit root); `per_drive` overrides roots for specific drives
// (e.g. C: → %LOCALAPPDATA%\.winrsbox\… so installers writing to
// C:\Users\…\AppData land on C:).

/// Overlay root layout: maps a virtual drive letter to the overlay root that
/// lives on that same volume. `primary_root` is the fallback (typically the
/// project drive's root).
#[derive(Debug, Clone)]
pub struct OverlayLayout {
    /// Fallback root, used for any drive without an explicit override. Always
    /// the project drive's overlay root for backward compatibility.
    primary_root: PathBuf,
    /// Per-drive overrides: drive letter (lowercase) → root on that volume.
    /// E.g. 'c' → C:\Users\…\AppData\Local\.winrsbox\<session>\workdir.
    per_drive: std::collections::BTreeMap<char, PathBuf>,
}

impl OverlayLayout {
    /// Create a layout with just a primary (fallback) root — equivalent to
    /// the legacy single-root behaviour.
    pub fn single(primary_root: PathBuf) -> Self {
        Self { primary_root, per_drive: Default::default() }
    }

    /// Create a layout with a primary fallback and a set of per-drive roots.
    pub fn new(
        primary_root: PathBuf,
        per_drive: impl IntoIterator<Item = (char, PathBuf)>,
    ) -> Self {
        let per_drive = per_drive
            .into_iter()
            .map(|(c, p)| (c.to_ascii_lowercase(), p))
            .collect();
        Self { primary_root, per_drive }
    }

    /// Add (or replace) the overlay root for a given drive letter.
    pub fn set_drive_root(&mut self, drive: char, root: PathBuf) {
        self.per_drive.insert(drive.to_ascii_lowercase(), root);
    }

    /// The primary/fallback root (project drive).
    pub fn primary(&self) -> &Path { &self.primary_root }

    /// Resolve the overlay root for a virtual DOS path's drive. If the path's
    /// drive has an explicit same-volume root, use it; otherwise fall back to
    /// `primary_root`. Returns the chosen root.
    pub fn root_for(&self, dos_lower: &str) -> &Path {
        let drive = dos_lower.chars().next().unwrap_or('\0').to_ascii_lowercase();
        if drive.is_ascii_alphabetic() {
            if let Some(r) = self.per_drive.get(&drive) {
                return r;
            }
        }
        &self.primary_root
    }

    /// Iterate (drive, root) for every same-volume root, including primary.
    /// Used by `unmirror` to find which root a given overlay path belongs to.
    pub fn all_roots(&self) -> impl Iterator<Item = (Option<char>, PathBuf)> + '_ {
        let primary = std::iter::once((None, self.primary_root.clone()));
        let per = self.per_drive.iter().map(|(&c, p)| (Some(c), p.clone()));
        primary.chain(per)
    }
}

/// Mirror a virtual DOS path into the overlay, choosing the overlay root by
/// the virtual path's drive (same-volume layout). The resulting path lives on
/// the same volume as the virtual path, so kernel-reported drive letters are
/// correct. Layout is `<root>\<rest>` (NO drive component — the drive is
/// implicit in the chosen root's volume).
pub fn mirror_into_overlay_layout(dos_lower: &str, layout: &OverlayLayout) -> PathBuf {
    let root = layout.root_for(dos_lower);
    // Strip the drive letter from the virtual path so it isn't doubled into
    // the layout (the drive is encoded by WHICH root was chosen).
    let rest = dos_to_volume_relative(dos_lower);
    let sanitized = rest.replace('/', "\\").trim_start_matches('\\').to_string();
    let mut out = root.to_path_buf();
    for component in Path::new(&sanitized).components() {
        match component {
            std::path::Component::Normal(c) => out.push(c),
            _ => {}
        }
    }
    out
}

/// Inverse of `mirror_into_overlay_layout`: given an overlay path and the
/// same-volume layout, recover the virtual DOS path `<drive>:\<rest>`. Finds
/// which root the overlay path lives under, takes that root's drive, and
/// prepends it. Returns None when the path matches no root.
pub fn unmirror_from_overlay_layout(overlay_path: &Path, layout: &OverlayLayout) -> Option<String> {
    for (drive_opt, root) in layout.all_roots() {
        if let Ok(rest) = overlay_path.strip_prefix(&root) {
            let drive_letter = drive_opt.unwrap_or_else(|| {
                // Primary root with no explicit drive: derive from the root path
                // and lowercase it (virtual paths are conventionally lowercase).
                root.to_string_lossy()
                    .chars()
                    .next()
                    .filter(|c| c.is_ascii_alphabetic())
                    .map(|c| c.to_ascii_lowercase())
                    .unwrap_or('c')
            });
            let mut virtual_dos = format!("{}:", drive_letter);
            for c in rest.components() {
                match c {
                    std::path::Component::Normal(s) => {
                        virtual_dos.push('\\');
                        virtual_dos.push_str(s.to_str()?);
                    }
                    _ => return None,
                }
            }
            return Some(virtual_dos);
        }
    }
    None
}



/// Inverse of `mirror_into_overlay`: given an overlay path that lives under
/// `root` in the layout `<root>\<drive>\<rest>`, recover the virtual DOS path
/// `<drive>:\<rest>`. Returns None when `overlay_path` is not under `root`,
/// or when the first component after `root` is not a single ASCII letter (the
/// only legal drive-letter form produced by `mirror_into_overlay`).
///
/// Used by the delete hook to turn a sandbox-internal overlay file path back
/// into the virtual path the agent sees, so a whiteout marker can be recorded
/// against the correct key.
pub fn unmirror_from_overlay(overlay_path: &Path, root: &Path) -> Option<String> {
    let rest = overlay_path.strip_prefix(root).ok()?;
    let mut comps = rest.components();
    // First component must be a single drive letter (Normal), e.g. "c".
    let drive = comps.next()?.as_os_str().to_str()?;
    if drive.len() != 1 || !drive.as_bytes()[0].is_ascii_alphabetic() {
        return None;
    }
    let mut virtual_dos = format!("{}:", drive);
    for c in comps {
        match c {
            std::path::Component::Normal(s) => {
                virtual_dos.push('\\');
                virtual_dos.push_str(s.to_str()?);
            }
            _ => return None,
        }
    }
    Some(virtual_dos)
}

/// Strip the leading `<letter>:` drive-letter prefix from a DOS path, returning
/// the volume-relative form (`\rest\of\path`). This is the inverse of gluing a
/// drive letter back on, and matches the semantics of `FILE_NAME_INFORMATION`.
/// `FileName` field: a path relative to the volume, beginning with `\`, with
/// NO drive letter.
///
/// Returns the input unchanged when no ASCII `<letter>:` prefix is present
/// (defensive — callers that already hold a volume-relative path pass through).
pub fn dos_to_volume_relative(dos: &str) -> &str {
    let b = dos.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        &dos[2..]
    } else {
        dos
    }
}

// ─── Glob matching ───────────────────────────────────────────────────────────
//
// pattern_matches_prefix returns true if `pattern` matches `path` treating
// `\` as the segment separator. Each segment in the pattern is matched
// against the corresponding segment in the path with `*` and `?` wildcards
// (single-segment globbing). The path may have ADDITIONAL trailing segments
// beyond the pattern — this is a prefix match, not equality.

/// Returns true if `seg` is cleanly-bounded `**` — the entire segment
/// consists of exactly two asterisks.
fn is_globstar(seg: &str) -> bool {
    seg == "**"
}

pub fn pattern_matches_prefix(pattern: &str, path: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    // Drop empty segments from consecutive / leading / trailing backslashes: the
    // NT path parser collapses `\\` to a single separator, so a hostile
    // `c:\\windows\\system32` must still match a `c:\windows\system32` deny rule
    // rather than splitting into `["c:", "", "windows", ...]` and failing the
    // match at the empty segment. Both sides are filtered symmetrically so
    // equivalent path forms still compare equal.
    let pat_segs: Vec<&str> = pattern.split('\\').filter(|s| !s.is_empty()).collect();
    let path_segs: Vec<&str> = path.split('\\').filter(|s| !s.is_empty()).collect();
    prefix_match(&pat_segs, &path_segs)
}

fn prefix_match(pat: &[&str], path: &[&str]) -> bool {
    let (mut pi, mut si) = (0usize, 0usize);
    let (mut star_pi, mut star_si) = (None::<usize>, 0usize);
    loop {
        // Consume trailing ** in pattern
        while pi < pat.len() && is_globstar(pat[pi]) {
            star_pi = Some(pi);
            star_si = si;
            pi += 1;
        }
        if pi == pat.len() {
            return true; // prefix match: all pattern segments consumed
        }
        if si == path.len() {
            return false; // path shorter than remaining pattern
        }
        if segment_match(pat[pi], path[si]) {
            pi += 1;
            si += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_si += 1;
            si = star_si;
        } else {
            return false;
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
    let pat_segs: Vec<&str> = pattern.split('\\').collect();
    let path_segs: Vec<&str> = path.split('\\').collect();
    exact_match(&pat_segs, &path_segs)
}

fn exact_match(pat: &[&str], path: &[&str]) -> bool {
    let (mut pi, mut si) = (0usize, 0usize);
    let (mut star_pi, mut star_si) = (None::<usize>, 0usize);
    loop {
        // Consume consecutive ** in pattern
        while pi < pat.len() && is_globstar(pat[pi]) {
            star_pi = Some(pi);
            star_si = si;
            pi += 1;
        }
        if pi == pat.len() && si == path.len() {
            return true;
        }
        if pi == pat.len() {
            // Pattern exhausted but path remains — try backtracking
            if let Some(sp) = star_pi {
                pi = sp + 1;
                star_si += 1;
                si = star_si;
                continue;
            }
            return false;
        }
        if si == path.len() {
            return false; // path shorter than remaining pattern
        }
        if segment_match(pat[pi], path[si]) {
            pi += 1;
            si += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_si += 1;
            si = star_si;
        } else {
            return false;
        }
    }
}

#[cfg(test)]
mod unmirror_tests {
    use super::*;

    #[test]
    fn unmirror_roundtrip_file() {
        let root = PathBuf::from(r"D:\sb");
        let virtual_dos = r"c:\users\alice\file.txt";
        let overlay = mirror_into_overlay(virtual_dos, &root);
        assert_eq!(overlay, PathBuf::from(r"D:\sb\c\users\alice\file.txt"));
        let back = unmirror_from_overlay(&overlay, &root).unwrap();
        assert_eq!(back, virtual_dos);
    }

    #[test]
    fn unmirror_drive_root_only() {
        let root = PathBuf::from(r"D:\sb");
        let overlay = mirror_into_overlay(r"d:\", &root);
        let back = unmirror_from_overlay(&overlay, &root).unwrap();
        assert_eq!(back, r"d:");
    }

    #[test]
    fn unmirror_not_under_root_returns_none() {
        let root = PathBuf::from(r"D:\sb");
        let alien = PathBuf::from(r"D:\elsewhere\c\file.txt");
        assert!(unmirror_from_overlay(&alien, &root).is_none());
    }

    #[test]
    fn unmirror_first_component_not_drive_letter() {
        let root = PathBuf::from(r"D:\sb");
        // "cd" is two chars — not a drive letter.
        let overlay = PathBuf::from(r"D:\sb\cd\file.txt");
        assert!(unmirror_from_overlay(&overlay, &root).is_none());
    }

    #[test]
    fn mirror_unmirror_case_preserved() {
        // mirror_into_overlay preserves case of the components (only strips ':');
        // unmirror_from_overlay does not lowercase. The virtual DOS path roundtrips.
        let root = PathBuf::from(r"D:\sb");
        let virtual_dos = r"D:\Users\Alice";
        let overlay = mirror_into_overlay(virtual_dos, &root);
        let back = unmirror_from_overlay(&overlay, &root).unwrap();
        assert_eq!(back, virtual_dos);
    }

    #[test]
    fn dos_to_volume_relative_strips_drive_letter() {
        assert_eq!(dos_to_volume_relative(r"d:\proj\.git\HEAD"), r"\proj\.git\HEAD");
        assert_eq!(dos_to_volume_relative(r"D:\proj"), r"\proj");
        assert_eq!(dos_to_volume_relative(r"c:\"), r"\");
    }

    #[test]
    fn dos_to_volume_relative_passthrough_without_drive() {
        assert_eq!(dos_to_volume_relative(r"\already\relative"), r"\already\relative");
        assert_eq!(dos_to_volume_relative(r"bare"), r"bare");
        assert_eq!(dos_to_volume_relative(""), "");
    }

    #[test]
    fn unmirror_then_volume_relative_roundtrip() {
        // Full round-trip: virtual DOS → overlay → unmirror → strip drive.
        // The volume-relative form is what FileNameInformation must return.
        let root = PathBuf::from(r"C:\Users\me\.winrsbox\sbx\workdir");
        let virtual_dos = r"d:\proj\.git\HEAD";
        let overlay = mirror_into_overlay(virtual_dos, &root);
        let back = unmirror_from_overlay(&overlay, &root).unwrap();
        let vol_rel = dos_to_volume_relative(&back);
        assert_eq!(vol_rel, r"\proj\.git\HEAD");
    }

    // ── OverlayLayout (same-volume) tests ──────────────────────────────────

    #[test]
    fn layout_single_uses_primary_root() {
        // No per-drive overrides → every drive uses primary_root.
        let layout = OverlayLayout::single(PathBuf::from(r"D:\proj\.winrsbox\sbx\workdir"));
        assert_eq!(layout.root_for(r"c:\users\me"), Path::new(r"D:\proj\.winrsbox\sbx\workdir"));
        assert_eq!(layout.root_for(r"d:\foo"), Path::new(r"D:\proj\.winrsbox\sbx\workdir"));
    }

    #[test]
    fn layout_per_drive_override_for_c() {
        // C: has an explicit same-volume root (on C:); D: falls back to primary.
        let layout = OverlayLayout::new(
            PathBuf::from(r"D:\proj\.winrsbox\sbx\workdir"),
            [('c', PathBuf::from(r"C:\Users\me\AppData\Local\.winrsbox\sbx\workdir"))],
        );
        assert_eq!(layout.root_for(r"c:\users\me\appdata"), Path::new(r"C:\Users\me\AppData\Local\.winrsbox\sbx\workdir"));
        assert_eq!(layout.root_for(r"d:\proj"), Path::new(r"D:\proj\.winrsbox\sbx\workdir"));
        // case-insensitive drive match
        assert_eq!(layout.root_for(r"C:\Users"), Path::new(r"C:\Users\me\AppData\Local\.winrsbox\sbx\workdir"));
    }

    #[test]
    fn layout_mirror_roundtrip_c_drive() {
        // mirror c:\... → C:-root overlay (same volume); unmirror recovers c:\...
        let layout = OverlayLayout::new(
            PathBuf::from(r"D:\proj\.winrsbox\sbx\workdir"),
            [('c', PathBuf::from(r"C:\Users\me\AppData\Local\.winrsbox\sbx\workdir"))],
        );
        let virtual_dos = r"c:\users\me\appdata\local\clonebug";
        let overlay = mirror_into_overlay_layout(virtual_dos, &layout);
        // Must live on C: (same volume as virtual) — NOT on D:.
        assert!(overlay.starts_with(r"C:\Users\me\AppData\Local\.winrsbox\sbx\workdir"),
            "C: overlay must be on C: volume, got {}", overlay.display());
        assert_eq!(overlay, Path::new(r"C:\Users\me\AppData\Local\.winrsbox\sbx\workdir\users\me\appdata\local\clonebug"));
        let back = unmirror_from_overlay_layout(&overlay, &layout).unwrap();
        assert_eq!(back, r"c:\users\me\appdata\local\clonebug");
    }

    #[test]
    fn layout_mirror_roundtrip_d_drive_uses_primary() {
        // d:\... has no override → uses primary_root (which is on D:).
        let layout = OverlayLayout::new(
            PathBuf::from(r"D:\proj\.winrsbox\sbx\workdir"),
            [('c', PathBuf::from(r"C:\Users\me\AppData\Local\.winrsbox\sbx\workdir"))],
        );
        let virtual_dos = r"d:\proj\repo\.git\HEAD";
        let overlay = mirror_into_overlay_layout(virtual_dos, &layout);
        assert!(overlay.starts_with(r"D:\proj\.winrsbox\sbx\workdir"));
        let back = unmirror_from_overlay_layout(&overlay, &layout).unwrap();
        assert_eq!(back, r"d:\proj\repo\.git\HEAD");
    }

    #[test]
    fn layout_unmirror_unknown_path_returns_none() {
        let layout = OverlayLayout::single(PathBuf::from(r"D:\proj\.winrsbox\sbx\workdir"));
        let alien = Path::new(r"E:\unrelated\path");
        assert!(unmirror_from_overlay_layout(alien, &layout).is_none());
    }

    #[test]
    fn layout_no_drive_letter_uses_primary() {
        // A path with no leading drive letter falls back to primary_root.
        let layout = OverlayLayout::single(PathBuf::from(r"D:\proj\.winrsbox\sbx\workdir"));
        assert_eq!(layout.root_for(r"\relative\path"), Path::new(r"D:\proj\.winrsbox\sbx\workdir"));
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
