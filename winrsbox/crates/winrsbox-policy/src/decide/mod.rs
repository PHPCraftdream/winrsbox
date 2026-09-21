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
        Ok(Snapshot { rules, default_rule, mocks_exact, mocks_glob, mock_dirs })
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
    pub(crate) fn best_explicit_rule_match(
        &self,
        lower_path: &str,
        depth: Option<u8>,
        exe_lower: Option<&str>,
    ) -> Option<&db::RuleRow> {
        let mut best: Option<(usize, &db::RuleRow)> = None;
        for sr in &self.rules {
            if !path::pattern_matches_prefix(&sr.pattern, lower_path) { continue; }
            if let Some(ref when) = sr.row.when {
                if let Some(min_depth) = when.depth {
                    match depth {
                        Some(d) if d < min_depth => continue,
                        None => {}
                        _ => {}
                    }
                }
                if let Some(ref exe_pattern) = when.exe {
                    match exe_lower {
                        Some(exe) if path::pattern_matches_exact(&ensure_lower(exe_pattern), exe) => {}
                        _ => continue,
                    }
                }
            }
            let mut spec = path::pattern_specificity(&sr.pattern);
            if sr.row.when.is_some() { spec += 1; }
            if let Some(ref when) = sr.row.when {
                if let Some(ref exe) = when.exe {
                    spec += path::pattern_specificity(exe);
                }
            }
            match &best {
                None => best = Some((spec, &sr.row)),
                Some((s, _)) if spec > *s => best = Some((spec, &sr.row)),
                _ => {}
            }
        }
        best.map(|(_, r)| r)
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

// ── Policy decide methods (impl block lives here, Policy defined in lib.rs) ──

use crate::Policy;


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
#[cfg(test)]
mod tests;
