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

/// Lexically fold `.` and `..` segments in a lowercase DOS path WITHOUT
/// touching the filesystem — a `canonicalize()` syscall here would be both a
/// TOCTOU and a recursion hazard inside a hook. This mirrors what Win32's
/// `RtlDosPathNameToNtPathName` does for every normal Win32 caller before the
/// path reaches the kernel, so after folding, the path the policy decides on
/// is the path the kernel will act on. (Kernel-side resolution differs from a
/// lexical fold only when an intermediate segment is a reparse point; that
/// pre-existing traversal class is defended separately by denying reparse-
/// point creation in the metadata guard.)
///
/// Anchor: a leading drive prefix (`x:`) or a leading `\`. A bare relative
/// name has no defined root to clamp against and is returned unchanged.
/// `.` segments are dropped; `..` pops one segment, clamped at the anchor
/// (the kernel clamps at the volume root the same way). Empty interior
/// segments are collapsed. `/` is treated as a separator (the NT object
/// manager accepts it as one) and normalized to `\` in rewritten output.
/// Leading anchor and a single trailing separator are preserved verbatim.
///
/// Returns `Cow::Borrowed` unchanged when the path contains no `.`/`..`
/// segment and no interior empty segment (hot path — no allocation).
pub fn fold_dos_dots(dos: &str) -> std::borrow::Cow<'_, str> {
    let is_sep = |c: char| c == '\\' || c == '/';

    // Fast path: no `.`/`..` segment and no interior empty segment (the
    // leading anchor and a single trailing separator are not "interior")
    // → borrow, no allocation.
    let mut needs_fold = false;
    {
        let mut it = dos.split(is_sep).peekable();
        let mut idx = 0usize;
        while let Some(seg) = it.next() {
            let is_last = it.peek().is_none();
            if seg == "." || seg == ".." {
                needs_fold = true;
                break;
            }
            if seg.is_empty() && idx > 0 && !is_last {
                needs_fold = true;
                break;
            }
            idx += 1;
        }
    }
    if !needs_fold {
        return std::borrow::Cow::Borrowed(dos);
    }

    // Anchor: `<letter>:` + optional separator, or a bare leading separator —
    // preserved verbatim. Anything else is a bare relative name with no
    // defined root to clamp against → returned unchanged.
    let b = dos.as_bytes();
    let anchor_len = if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        if b.len() >= 3 && (b[2] == b'\\' || b[2] == b'/') { 3 } else { 2 }
    } else if b.first() == Some(&b'\\') || b.first() == Some(&b'/') {
        1
    } else {
        return std::borrow::Cow::Borrowed(dos);
    };

    let trailing = dos.ends_with(is_sep);
    let mut stack: Vec<&str> = Vec::new();
    for seg in dos[anchor_len..].split(is_sep) {
        match seg {
            "" => {}  // empty interior segment — collapse
            "." => {} // current-dir segment — drop
            ".." => {
                // Pop one segment; clamped at the anchor when the stack is
                // empty (the kernel clamps at the volume root the same way).
                let _ = stack.pop();
            }
            s => stack.push(s),
        }
    }

    let mut out = String::with_capacity(dos.len());
    out.push_str(&dos[..anchor_len]);
    for s in &stack {
        if !out.ends_with(is_sep) {
            out.push('\\');
        }
        out.push_str(s);
    }
    if trailing && !out.ends_with(is_sep) {
        out.push('\\');
    }
    std::borrow::Cow::Owned(out)
}

/// UTF-16 twin of [`fold_dos_dots`] for NT-form paths (`\??\C:\…`,
/// `\\?\C:\…`, `\\.\C:\…`). Folds `.`/`..` segments lexically, preserving the
/// NT prefix - including the `<letter>:` drive, which `..` cannot pop,
/// mirroring the kernel's clamp at the volume root - and every non-folded
/// byte (case, non-ASCII UTF-16 units) verbatim, so the result still
/// round-trips through `nt_to_dos_lower`.
/// Paths without one of those prefixes are returned unchanged (Borrowed) — a
/// lexical fold of an unanchored path has no defined root to clamp against.
/// Same fold rules as `fold_dos_dots`: `.` dropped, `..` pops clamped at the
/// prefix anchor, interior empty segments collapsed, `/` treated as a
/// separator and normalized to `\` in rewritten output.
pub fn fold_nt_dots(raw: &[u16]) -> std::borrow::Cow<'_, [u16]> {
    // Recognized 4-unit NT prefixes (mirrors `strip_nt_prefix`):
    // `\??\` = [0x5C,0x3F,0x3F,0x5C], `\\?\` = [0x5C,0x5C,0x3F,0x5C],
    // `\\.\` = [0x5C,0x5C,0x2E,0x5C].
    let has_nt_prefix = raw.len() > 4
        && ((raw[0] == 0x5C && raw[1] == 0x3F && raw[2] == 0x3F && raw[3] == 0x5C)
            || (raw[0] == 0x5C && raw[1] == 0x5C && raw[2] == 0x3F && raw[3] == 0x5C)
            || (raw[0] == 0x5C && raw[1] == 0x5C && raw[2] == 0x2E && raw[3] == 0x5C));
    if !has_nt_prefix {
        // Unanchored — no defined root to clamp against → unchanged.
        return std::borrow::Cow::Borrowed(raw);
    }

    const SEP: u16 = 0x5C; // '\'
    const FSLASH: u16 = 0x2F; // '/'
    const DOT: u16 = 0x2E; // '.'
    let is_sep = |&u: &u16| u == SEP || u == FSLASH;

    // Fast path: no `.`/`..` segment and no interior empty segment → borrow.
    // (The empty segment at idx 0 belongs to the prefix's leading `\`.)
    let mut needs_fold = false;
    {
        let mut it = raw.split(is_sep).peekable();
        let mut idx = 0usize;
        while let Some(seg) = it.next() {
            let is_last = it.peek().is_none();
            match seg {
                [DOT] | [DOT, DOT] => {
                    needs_fold = true;
                    break;
                }
                [] if idx > 0 && !is_last => {
                    needs_fold = true;
                    break;
                }
                _ => {}
            }
            idx += 1;
        }
    }
    if !needs_fold {
        return std::borrow::Cow::Borrowed(raw);
    }

    // Anchor length: the 4-unit NT prefix plus the `<letter>:` drive prefix
    // and its following separator when present. The drive must NOT be
    // poppable by `..` -- the kernel clamps at the volume root, exactly like
    // `fold_dos_dots` clamps at `x:`. (Popping it would turn
    // `\??\C:\a\..\..\b` into `\??\b` instead of `\??\C:\b`.)
    let mut anchor = 4usize;
    if raw.len() >= 6 && matches!(raw[4], 0x41..=0x5A | 0x61..=0x7A) && raw[5] == 0x3A {
        if raw.len() >= 7 && is_sep(&raw[6]) {
            anchor = 7;
        } else {
            // Drive-relative NT form (`\??\C:proj\..`) resolves against the
            // per-process current directory of that drive -- no defined
            // lexical anchor, so leave it unchanged.
            return std::borrow::Cow::Borrowed(raw);
        }
    }

    let trailing = matches!(raw.last(), Some(&u) if u == SEP || u == FSLASH);
    let mut stack: Vec<&[u16]> = Vec::new();
    for seg in raw[anchor..].split(is_sep) {
        match seg {
            [] | [DOT] => {} // empty interior segment / current-dir — collapse
            [DOT, DOT] => {
                // Pop one segment; clamped at the prefix+drive anchor.
                let _ = stack.pop();
            }
            s => stack.push(s),
        }
    }

    let mut out: Vec<u16> = Vec::with_capacity(raw.len());
    out.extend_from_slice(&raw[..anchor]);
    for s in &stack {
        if !matches!(out.last(), Some(&u) if u == SEP || u == FSLASH) {
            out.push(SEP);
        }
        out.extend_from_slice(s);
    }
    if trailing && !matches!(out.last(), Some(&u) if u == SEP || u == FSLASH) {
        out.push(SEP);
    }
    std::borrow::Cow::Owned(out)
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


/// Strip trailing `\` / `/` separators from a DOS path used as an OVERLAY_IDX
/// or WHITEOUTS key. NT allows opening a directory with a trailing separator
/// (`d:\foo\`), and the hook's `dos_path` extraction preserves it, so a create
/// at `d:\foo\` and a subsequent open at `d:\foo` would otherwise key the
/// overlay index differently — leaving the directory invisible to later
/// readers (observed with git's `.git/info` directory). Root (`d:\`) is
/// preserved.
pub(crate) fn trim_trailing_sep(s: &str) -> &str {
    let bytes = s.as_bytes();
    // Preserve drive roots like `d:\`.
    if bytes.len() <= 3 { return s; }
    let mut end = bytes.len();
    while end > 1 && (bytes[end - 1] == b'\\' || bytes[end - 1] == b'/') {
        end -= 1;
    }
    if end == bytes.len() { s } else { &s[..end] }
}

#[cfg(test)]
mod unmirror_tests;
#[cfg(test)]
mod glob_tests;
#[cfg(test)]
mod conv_tests;
