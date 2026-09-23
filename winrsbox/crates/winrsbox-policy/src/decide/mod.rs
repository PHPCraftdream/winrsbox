use std::path::PathBuf;
use std::sync::Arc;
use xxhash_rust::xxh3::Xxh3;
use redb::ReadableTable as _;

use crate::{db, path, ensure_lower, trim_trailing_sep, PolicyError};

// ── Traced decision types for `why` / `what-if` ──────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Verdict {
    Match { specificity: usize },
    Skip { reason: String },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConsideredRule {
    pub id: String,
    pub prefix: String,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TracedDecision {
    pub decision: db::RuleMode,
    pub target_path: Option<PathBuf>,
    pub rule_id: Option<String>,
    pub rule_prefix: Option<String>,
    pub mock_match: Option<String>,
    pub mockdir_match: Option<String>,
    pub chain: Vec<ConsideredRule>,
}

/// One overlay-only direct child of a directory, as returned by
/// `Policy::overlay_children` — everything the enum-hook needs to
/// synthesize a plausible `NtQueryDirectoryFile` record (name, type, size,
/// times).
///
/// `size`/`*_time` are a live stat of the physical overlay path. A missing
/// or unreadable path (stale index entry) defaults every field to zero
/// rather than erroring — enumeration must never break because of one bad
/// entry. `*_time` fields are raw Windows FILETIME (100ns intervals since
/// 1601-01-01), matching `std::os::windows::fs::MetadataExt` verbatim — no
/// conversion needed before writing them into a `FILE_DIRECTORY_INFORMATION`-
/// family record's `LARGE_INTEGER` fields.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OverlayChildMeta {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
}

/// Stat a physical overlay path, returning `(is_dir, size, creation_time,
/// last_access_time, last_write_time)`. A missing/unreadable path defaults
/// every field to zero — see `OverlayChildMeta` doc comment.
fn stat_overlay_phys(overlay_phys: &str) -> (bool, u64, u64, u64, u64) {
    use std::os::windows::fs::MetadataExt;
    match std::fs::metadata(overlay_phys) {
        Ok(md) => (
            md.is_dir(),
            if md.is_dir() { 0 } else { md.file_size() },
            md.creation_time(),
            md.last_access_time(),
            md.last_write_time(),
        ),
        Err(_) => (false, 0, 0, 0, 0),
    }
}

// ── Snapshot ──────────────────────────────────────────────────────────────

pub(crate) struct SnapshotRule {
    pub(crate) pattern: String,
    pub(crate) row: db::RuleRow,
}

pub(crate) struct Snapshot {
    pub(crate) rules: Vec<SnapshotRule>,
    pub(crate) default_rule: Option<db::RuleRow>,
    pub(crate) mocks_exact: rustc_hash::FxHashMap<String, Vec<u8>>,
    pub(crate) mocks_glob: Vec<(String, Vec<u8>)>,
    pub(crate) mock_dirs: Vec<String>,
    /// Precompiled rule index (literal-segment trie + wildcard list), built
    /// once per snapshot load. `index.compiled(i)` corresponds to `rules[i]`.
    pub(crate) index: rule_index::RuleIndex,
}

impl Snapshot {
    pub(crate) fn load_from_db(db: &redb::Database) -> Result<Self, PolicyError> {
        let txn = db.begin_read()?;
        let mut rules = Vec::new();
        let mut default_rule = None;
        if let Ok(table) = txn.open_table(db::RULES) {
            for entry in table.range::<&str>(..).into_iter().flatten() {
                let Ok((key, value)) = entry else { continue };
                let pattern = key.value().to_owned();
                let Some(row) = db::decode_rule(value.value()) else { continue };
                if pattern.is_empty() {
                    default_rule = Some(row);
                } else {
                    rules.push(SnapshotRule { pattern, row });
                }
            }
        }
        let mut mocks_exact = rustc_hash::FxHashMap::default();
        let mut mocks_glob = Vec::new();
        if let Ok(table) = txn.open_table(db::MOCKS) {
            for entry in table.range::<&str>(..).into_iter().flatten() {
                let Ok((key, value)) = entry else { continue };
                let pattern = key.value().to_owned();
                let payload = value.value().to_vec();
                if pattern.contains('*') || pattern.contains('?') {
                    mocks_glob.push((pattern, payload));
                } else {
                    mocks_exact.insert(pattern, payload);
                }
            }
        }
        let mut mock_dirs = Vec::new();
        if let Ok(table) = txn.open_table(db::MOCK_DIRS) {
            for entry in table.range::<&str>(..).into_iter().flatten() {
                let Ok((key, _)) = entry else { continue };
                mock_dirs.push(key.value().to_owned());
            }
        }
        // Rules are fully populated above — precompile the matching index
        // once per snapshot load instead of re-splitting/re-scoring every
        // rule on every decision.
        let index = rule_index::RuleIndex::build(&rules);
        Ok(Snapshot { rules, default_rule, mocks_exact, mocks_glob, mock_dirs, index })
    }

    pub(crate) fn find_mock_payload(&self, lower_path: &str) -> Option<Vec<u8>> {
        if let Some(payload) = self.mocks_exact.get(lower_path) {
            return Some(payload.clone());
        }
        for (pattern, payload) in &self.mocks_glob {
            if path::pattern_matches_exact(pattern, lower_path) {
                return Some(payload.clone());
            }
        }
        None
    }

    pub(crate) fn matched_mock_dir(&self, lower_path: &str) -> Option<&str> {
        let mut best: Option<(usize, &str)> = None;
        for pattern in &self.mock_dirs {
            if !path::pattern_matches_prefix(pattern, lower_path) { continue; }
            let spec = path::pattern_specificity(pattern);
            match &best {
                None => best = Some((spec, pattern)),
                Some((s, _)) if spec > *s => best = Some((spec, pattern)),
                _ => {}
            }
        }
        best.map(|(_, p)| p.as_ref())
    }

    pub(crate) fn best_rule_match(&self, lower_path: &str, depth: Option<u8>, exe_lower: Option<&str>) -> Option<&db::RuleRow> {
        self.best_explicit_rule_match(lower_path, depth, exe_lower)
            .or(self.default_rule.as_ref())
    }

    /// Like `best_rule_match` but only considers explicit (non-empty-prefix)
    /// rules — never falls back to the default catch-all rule. Returns `None`
    /// when no explicit rule's prefix matches `lower_path`.
    ///
    /// Used to distinguish "matched an explicit rule" from "fell through to the
    /// default rule": a path outside `project_root` that hits only the default
    /// must NOT be CoW-redirected into the overlay (see `compute`).
    ///
    /// Matching is index-driven: literal rules are found via the segment trie
    /// (they match by construction — the trie walk proves the segment
    /// prefix), while wildcard rules are re-checked right in the candidate
    /// loop below, via `path::prefix_match` on the rule's precompiled
    /// FILTERED segments against the already-split path — the same glob
    /// algorithm (globstar semantics included) as the old per-rule
    /// `pattern_matches_prefix`, but with zero allocation and no re-splits.
    /// The path is split once (FILTERED, mirroring `pattern_matches_prefix`)
    /// and the exe once (UNFILTERED, mirroring `pattern_matches_exact`). Tie-break: highest precompiled
    /// specificity, then earliest table index — order-independent and
    /// identical to the old in-order strict-`>` scan.
    pub(crate) fn best_explicit_rule_match(
        &self,
        lower_path: &str,
        depth: Option<u8>,
        exe_lower: Option<&str>,
    ) -> Option<&db::RuleRow> {
        let path_segs: Vec<&str> = lower_path.split('\\').filter(|s| !s.is_empty()).collect();
        let exe_segs: Option<Vec<&str>> = exe_lower.map(|e| e.split('\\').collect());
        let candidates = self.index.candidate_indices(&path_segs);
        let mut best: Option<(usize, usize)> = None;
        for idx in candidates {
            let cr = self.index.compiled(idx);
            // Wildcard filter: trie candidates match by construction, but
            // wildcard candidates are appended unconditionally by
            // `candidate_indices` — re-check each against the request path
            // here, using the precompiled FILTERED segments (same
            // `prefix_match` backtracking the old per-rule glob ran).
            if cr.wildcard && !path::prefix_match(&cr.segs, &path_segs) { continue; }
            // Depth filter: skip ONLY when both the runtime depth and the
            // rule minimum are Some and the depth is below the minimum. A
            // None runtime depth never skips (old code's `None => {}` arm).
            if let (Some(d), Some(min_depth)) = (depth, cr.when_min_depth) {
                if d < min_depth { continue; }
            }
            if let Some(exe_pattern_segs) = &cr.when_exe_segs {
                match exe_segs.as_deref() {
                    Some(exe) if path::exact_match(exe_pattern_segs, exe) => {}
                    _ => continue,
                }
            }
            let spec = cr.spec;
            match best {
                None => best = Some((spec, idx)),
                Some((s, i)) if spec > s || (spec == s && idx < i) => best = Some((spec, idx)),
                _ => {}
            }
        }
        best.map(|(_, idx)| &self.rules[idx].row)
    }
}

// ── Cache key ─────────────────────────────────────────────────────────────

/// Compute a composite cache key: `(path_hash u64 || ctx_hash u64)` as u128.
///
/// `path_hash` covers the path bytes + write flag.
/// `ctx_hash` covers depth + exe_lower (the "when" filter context).
/// Both hashes are produced by independent `Xxh3` instances.
/// Bit-concatenation (not XOR) preserves full entropy of both hashes.
pub(crate) fn cache_key(path: &str, write: bool, depth: Option<u8>, exe_lower: Option<&str>) -> u128 {
    let mut h1 = Xxh3::new();
    h1.update(path.as_bytes());
    h1.update(&[if write { 1u8 } else { 0u8 }]);
    let path_hash = h1.digest();

    let mut h2 = Xxh3::new();
    if let Some(d) = depth {
        h2.update(&[1, d]);   // tag byte disambiguates None vs Some(0)
    } else {
        h2.update(&[0]);
    }
    if let Some(e) = exe_lower {
        h2.update(&[1]);
        h2.update(e.as_bytes());
    } else {
        h2.update(&[0]);
    }
    let ctx_hash = h2.digest();

    ((path_hash as u128) << 64) | (ctx_hash as u128)
}

pub(crate) fn passthrough() -> Decision {
    Decision { mode: Mode::Passthrough, overlay: None, cow_from: None, mock_payload: None }
}

/// True iff `dos_path` currently names an existing file that is NOT a reparse
/// point (no symlink / junction / mount-point / other reparse tag).
///
/// Uses `symlink_metadata` (no-follow on Windows) and tests the
/// `FILE_ATTRIBUTE_REPARSE_POINT` bit, so junctions — which `is_symlink()`
/// would miss — are rejected too. Used only as defense-in-depth when recording
/// a CoW source; the binding TOCTOU check is re-done at copy time in the hook.
fn path_is_plain_file(dos_path: &str) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    match std::fs::symlink_metadata(dos_path) {
        Ok(md) => md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        Err(_) => false,
    }
}

/// Consult the PHYSICAL overlay mirror tree (not the index) for whether a
/// virtual path is alive in the overlay. The overlay tree is the source of
/// truth; `OVERLAY_IDX` is only a cache that can have holes — most notably
/// from relative-open creates against an already-overlay-redirected directory
/// handle (the kernel creates the file under the overlay, but the create does
/// not flow through the index-recording Cow branch). Without this physical
/// check, reads of such files (e.g. a cloned repo's `.git`, `agent/`,
/// `readme.md`) miss the index and passthrough to the real disk, where they
/// don't exist → `STATUS_OBJECT_NAME_NOT_FOUND`. This makes the model behave
/// like a real OverlayFS: presence is defined by the overlay filesystem, the
/// index just accelerates the common hit path.
///
/// `lower` is the lowercased virtual DOS path; `sandbox_root` is the overlay
/// storage root. Returns the concrete overlay DOS path when the file/dir
/// exists there, else `None`. Uses `symlink_metadata` (no-follow) so a
/// reparse point planted in the overlay is not falsely reported as a live
/// regular node.
///
/// Only returns `Some` if the overlay entry is either a FILE or a DIRECTORY
/// that does NOT exist on the real filesystem. A directory that exists in the
/// overlay AND on the real disk is a "passthrough directory with sparse overlay
/// children" — opening it through the overlay would expose an INCOMPLETE
/// listing (missing real-disk entries such as Python's stdlib `Lib/` modules
/// that were not written during a particular session). For such directories the
/// merged-view requirement falls on `NtQueryDirectoryFile`'s enum-hook instead;
/// here we fall through so the caller opens the real-disk directory and the
/// enum hook can later inject overlay-only entries.
///
/// Exception: if the overlay directory is in OVERLAY_IDX the caller already
/// handled it above (index fast-path) and never reaches here, so we don't need
/// to re-check OVERLAY_IDX.
fn physical_overlay_path(lower: &str, layout: &path::OverlayLayout) -> Option<PathBuf> {
    let mirror = path::mirror_into_overlay_layout(lower, layout);
    match std::fs::symlink_metadata(&mirror) {
        Ok(meta) if meta.is_dir() => {
            // Overlay directory exists. Check if the REAL path also exists as a
            // directory (both present → passthrough directory with sparse overlay
            // children → fall through so real-disk directory handle is used).
            let real = std::path::Path::new(lower);
            if real.is_dir() {
                // Both overlay and real exist → incomplete merged directory:
                // do NOT redirect; let the caller passthrough to real disk.
                None
            } else {
                // Only overlay has the directory (e.g. new clone destination):
                // redirect so the opener gets a valid directory handle.
                Some(mirror)
            }
        }
        Ok(_) => Some(mirror), // file (or other non-dir) → always redirect
        Err(_) => None,
    }
}

/// Segment-aware path containment check: returns true iff `path_lower`
/// equals `root_lower` or is a descendant of it. Prevents the sibling-prefix
/// bug where naive `starts_with` matches `c:\proj` against `c:\projevil\...`.
///
/// Both inputs MUST already be normalized to the same casefold (lowercase)
/// and use `\` separators. An empty root refuses to match (defense against
/// misconfiguration where an unset root would otherwise match every path).
/// A path that still contains `.`/`..` segments is refused (returns false) —
/// callers fold first via `path::fold_dos_dots`.
pub(crate) fn path_contained_in(path_lower: &str, root_lower: &str) -> bool {
    // Fail-closed backstop (audit Critical #1): a path still carrying a
    // `.`/`..` segment was never folded (see `path::fold_dos_dots`) — refuse
    // to call it contained rather than prefix-matching a string the kernel
    // will resolve differently. Mirrors the rename guard's dots-only
    // rejection (fs_metadata_guard::dest_is_escape) so the create-side and
    // rename-side containment cannot drift apart.
    if path_lower.split(|c| c == '\\' || c == '/').any(|seg| seg == "." || seg == "..") {
        return false;
    }
    let root = root_lower.trim_end_matches('\\');
    if root.is_empty() {
        return false;
    }
    if !path_lower.starts_with(root) {
        return false;
    }
    let n = root.len();
    path_lower.len() == n || path_lower.as_bytes().get(n) == Some(&b'\\')
}

/// Lowercase final DOS path of `p` via handle-based resolution
/// (std::fs::canonicalize opens the object and asks the kernel for its final
/// path, so junctions/symlinks in EVERY component are resolved). Strips the
/// `\\?\` verbatim prefix; a `\\?\UNC\...` result is normalized to `\\...`
/// form (it can then never segment-contain a DOS root). Returns None when the
/// object cannot be resolved.
fn canonical_dos_lower(p: &std::path::Path) -> Option<String> {
    let canon = std::fs::canonicalize(p).ok()?;
    let mut s = canon.to_string_lossy().into_owned();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        s = format!(r"\\{rest}");
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        s = rest.to_owned();
    }
    // Canonical NTFS-identity fold (see path::case_fold): the canonical
    // form borrows `s`'s buffer untouched when it is already folded, so the
    // common all-lowercase case stays allocation-free.
    match crate::path::nt_case_fold(&s) {
        std::borrow::Cow::Borrowed(_) => Some(s),
        std::borrow::Cow::Owned(f) => Some(f),
    }
}

/// `BY_HANDLE_FILE_INFORMATION` (win32 `fileapi.h`, laid out by hand to keep
/// the policy crate free of winapi/windows crates — kernel32 is linked by
/// every `*windows*` target anyway). FILETIME members are modeled as `u32`
/// pairs: their real alignment is 4, so a `u64` field would pad the struct
/// wrongly. Only `attributes` and `number_of_links` are ever read.
#[repr(C)]
struct ByHandleFileInfo {
    attributes: u32,
    creation_low: u32,
    creation_high: u32,
    access_low: u32,
    access_high: u32,
    write_low: u32,
    write_high: u32,
    volume_serial: u32,
    size_high: u32,
    size_low: u32,
    number_of_links: u32,
    index_high: u32,
    index_low: u32,
}

unsafe extern "system" {
    fn GetFileInformationByHandle(
        file: std::os::windows::io::RawHandle,
        info: *mut ByHandleFileInfo,
    ) -> i32;
}

/// Link count of the file object named by `p`, or `None` when it cannot be
/// determined. std's `MetadataExt::number_of_links()` would be exactly this,
/// but that accessor is unstable (`windows_by_handle`) — hence the
/// dependency-free kernel32 FFI above. The object is opened query-only
/// (desired access 0 + `FILE_FLAG_BACKUP_SEMANTICS`): no data-access rights
/// are needed and directories can be opened too.
fn number_of_links(p: &std::path::Path) -> Option<u32> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let f = std::fs::OpenOptions::new()
        .access_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(p)
        .ok()?;
    let mut info = ByHandleFileInfo {
        attributes: 0,
        creation_low: 0,
        creation_high: 0,
        access_low: 0,
        access_high: 0,
        write_low: 0,
        write_high: 0,
        volume_serial: 0,
        size_high: 0,
        size_low: 0,
        number_of_links: 0,
        index_high: 0,
        index_low: 0,
    };
    // SAFETY: `f.as_raw_handle()` is a live handle for the duration of the
    // call (owned by `f`, dropped only after this scope) and `info` is a
    // correctly-sized, repr(C) mapping of the win32 struct the API writes.
    let ok = unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut info) };
    if ok == 0 { None } else { Some(info.number_of_links) }
}

/// S05 (docs/review-xa-2026-09-20): true when `dos_path` — already
/// string-contained in `root_lower` — resolves, through the REAL filesystem,
/// to an object outside the root, or shares its file object with names we
/// cannot see. Such a pre-existing alias (junction/symlink/mount point in any
/// component, or a multi-link file) must not inherit in-root write trust from
/// its path string. WRITE-side decision input only; reads are globally
/// authorized and never consult this.
///
/// Cases, in order:
/// - Final component exists:
///   - a multi-link FILE (link count > 1) is refused outright: a
///     hardlink shares one underlying file object with its other names, so
///     string containment of this name proves nothing about where writes
///     land. Directories are exempt (NTFS cannot hardlink dirs and a dir's
///     link count legitimately exceeds 1 via its children's `..` entries).
///     An undeterminable link count on a file fails closed (refused).
///   - otherwise the whole path is resolved by handle (canonicalize). If the
///     final path is not segment-contained in `root_lower` — OR in the
///     root's own canonical form, so a project root that is itself reached
///     through a pre-existing alias keeps working — this is an escape. An
///     unresolvable path fails closed (true).
/// - Final component missing (create-new): the kernel will resolve the create
///   through the deepest EXISTING ancestor. That ancestor is resolved by
///   handle, the missing tail re-appended, and the joined result checked the
///   same way. If nothing anywhere on the chain exists there is nothing to
///   traverse — not an escape.
pub(crate) fn path_aliases_outside_root(dos_path: &str, root_lower: &str) -> bool {
    // Root anchor: containment is accepted against the configured string
    // root OR its own canonical form, so a project root that is itself
    // reached through a junction/subst drive keeps working. Canonicalizing
    // the root fails → fall back to the string root alone.
    let root_canon = canonical_dos_lower(std::path::Path::new(root_lower));
    let contained = |c: &str| {
        path_contained_in(c, root_lower)
            || root_canon.as_deref().is_some_and(|rc| path_contained_in(c, rc))
    };

    let p = std::path::Path::new(dos_path);
    match std::fs::symlink_metadata(p) {
        // Final component exists.
        Ok(md) => {
            // Multi-link FILE: one underlying file object answers to names we
            // cannot see — containment of THIS name proves nothing about
            // where writes land. Undeterminable on a file fails closed.
            // Directories are exempt (see doc comment).
            if !md.is_dir() && number_of_links(p).is_none_or(|n| n > 1) {
                return true;
            }
            match canonical_dos_lower(p) {
                // Unresolvable in-root object: fail closed.
                None => true,
                Some(c) => !contained(&c),
            }
        }
        // Final component missing (create-new): the kernel resolves the
        // create through the deepest EXISTING ancestor — walk up to it,
        // resolve it by handle, re-append the missing tail.
        Err(_) => {
            let mut tail: Vec<std::ffi::OsString> = Vec::new();
            let mut cur = p;
            loop {
                if std::fs::symlink_metadata(cur).is_ok() {
                    break; // deepest existing ancestor found
                }
                match cur.parent() {
                    Some(parent) => {
                        if let Some(name) = cur.file_name() {
                            tail.push(name.to_os_string());
                        }
                        cur = parent;
                    }
                    // Popped past the drive root without finding anything
                    // that exists: nothing to traverse — not an escape.
                    None => return false,
                }
            }
            // Fail closed when the ancestor cannot be resolved.
            let Some(anc) = canonical_dos_lower(cur) else { return true };
            // Re-append the missing tail in reverse pop order.
            let mut joined = anc;
            for seg in tail.iter().rev() {
                joined.push('\\');
                joined.push_str(&seg.to_string_lossy());
            }
            !contained(&joined)
        }
    }
}

// ── Policy decide methods (impl block lives here, Policy defined in lib.rs) ──

use crate::Policy;

impl Policy {
    /// Rewrite every `OVERLAY_IDX` value under `old_root` to the same relative
    /// path under `new_root` (segment-aware, ASCII case-insensitive prefix).
    /// Needed when an overlay root moves: review S07 re-keyed the C: root, and
    /// rows recorded against the old root point outside the published roots,
    /// so the hook refuses every write to them. Returns the rewritten count.
    pub fn rebase_overlay_root(
        &self,
        old_root: &std::path::Path,
        new_root: &std::path::Path,
    ) -> Result<usize, PolicyError> {
        let old_owned = old_root.to_string_lossy();
        let old_lower = old_owned.trim_end_matches('\\').to_ascii_lowercase();
        let new_owned = new_root.to_string_lossy();
        let new = new_owned.trim_end_matches('\\');
        if old_lower.is_empty() || old_lower == new.to_ascii_lowercase() {
            return Ok(0);
        }
        let txn = self.inner.db.begin_write()?;
        let rewritten;
        {
            let mut t = txn.open_table(db::OVERLAY_IDX)?;
            let mut updates = Vec::new();
            for row in t.iter()? {
                let (k, v) = row?;
                if let Some(rest) = strip_root_prefix(v.value(), &old_lower) {
                    updates.push((k.value().to_string(), format!("{new}{rest}")));
                }
            }
            for (k, v) in &updates {
                t.insert(k.as_str(), v.as_str())?;
            }
            rewritten = updates.len();
        }
        txn.commit()?;
        if rewritten > 0 {
            self.inner.cache.clear();
        }
        Ok(rewritten)
    }
}

/// `value` with the `root_lower` prefix removed when `value` equals the root
/// or lies beneath it (next byte is `\`); None otherwise.
fn strip_root_prefix<'a>(value: &'a str, root_lower: &str) -> Option<&'a str> {
    let head = value.get(..root_lower.len())?;
    if !head.eq_ignore_ascii_case(root_lower) {
        return None;
    }
    let rest = &value[root_lower.len()..];
    (rest.is_empty() || rest.starts_with('\\')).then_some(rest)
}


#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum Mode {
    Passthrough,
    Deny,
    Cow,
    Mock,
    /// OverlayFS-style whiteout: the path is hidden from the sandbox's merged
    /// view (open → not-found, absent from enumeration). The real lower file
    /// is never touched. A create at the same path clears the marker (revive)
    /// and re-enters the CoW overlay.
    Hidden,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Decision {
    pub mode: Mode,
    pub overlay: Option<PathBuf>,
    pub cow_from: Option<PathBuf>,
    pub mock_payload: Option<Vec<u8>>,
}

mod overlay;
mod rule_index;
#[cfg(test)]
mod tests;
