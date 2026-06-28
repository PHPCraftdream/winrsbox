use std::path::PathBuf;
use std::sync::Arc;
use xxhash_rust::xxh3::Xxh3;
use redb::ReadableTable as _;

use crate::{db, path, ensure_lower, trim_trailing_sep, Mode, Decision, PolicyError};

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
                        Some(exe) if path::pattern_matches_exact(exe_pattern, exe) => {}
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
pub(crate) fn path_contained_in(path_lower: &str, root_lower: &str) -> bool {
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

impl Policy {
    /// Decide what to do with a DOS path (legacy — no depth/exe context).
    pub fn decide(&self, dos_path: &str, write_access: bool) -> Decision {
        self.decide_with_context(dos_path, write_access, None, None)
    }

    /// Decide with optional depth and exe context for when-filter support.
    pub fn decide_with_context(
        &self,
        dos_path: &str,
        write_access: bool,
        depth: Option<u8>,
        exe_lower: Option<&str>,
    ) -> Decision {
        let key = cache_key(dos_path, write_access, depth, exe_lower);
        if let Some(d) = self.inner.cache.get(&key) {
            return (*d).clone();
        }
        let d = self.compute(dos_path, write_access, depth, exe_lower);
        self.inner.cache.insert(key, Arc::new(d.clone()));
        d
    }

    pub fn record_overlay(&self, orig: &str, overlay: &str) -> Result<(), PolicyError> {
        let txn = self.inner.db.begin_write()?;
        {
            let mut t = txn.open_table(db::OVERLAY_IDX)?;
            // Normalize trailing separators (create-at-`d:\foo\` vs open-at-
            // `d:\foo`) so the index key matches the lookup path used in
            // `compute`. Without this, a directory created with a trailing
            // separator disappears from later readers.
            let lower = orig.to_lowercase();
            let key = trim_trailing_sep(&lower);
            t.insert(key, overlay)?;
        }
        txn.commit()?;
        // Invalidate cache entries for all possible (depth, exe) combos for this path.
        // We can't know which combos are cached, so invalidate with None context
        // (the default-lookup key) — sufficient because record_overlay only runs
        // after a write decision, which uses the process's actual context.
        // For safety, we clear the entire cache on overlay recording (rare event).
        self.inner.cache.clear();
        Ok(())
    }

    /// Record the original-case basename for an overlay entry.
    ///
    /// Writes to `OVERLAY_CASE` using the same lowercase-virtual-path key
    /// as `OVERLAY_IDX`. The value is the caller-supplied original-case
    /// basename (e.g. `"Mixed_Case_Dir"`). No-op if `original_basename` is
    /// empty or already lowercase (nothing to preserve).
    ///
    /// This method is intentionally infallible from the caller's perspective:
    /// failure to record case is non-fatal — the hook's `build_case_map`
    /// falls back to real-disk enumeration for entries without a case record.
    pub fn record_overlay_case(&self, lower_path: &str, original_basename: &str) {
        if original_basename.is_empty() {
            return;
        }
        // Only worth storing when case differs from lowercase (optimization).
        if original_basename == original_basename.to_ascii_lowercase() {
            return;
        }
        let key = trim_trailing_sep(lower_path);
        let _ = (|| -> Result<(), PolicyError> {
            let txn = self.inner.db.begin_write()?;
            {
                let mut t = txn.open_table(db::OVERLAY_CASE)?;
                t.insert(key, original_basename)?;
            }
            txn.commit()?;
            Ok(())
        })();
    }

    /// Return `(lowercase_name, original_case_name)` pairs for all direct
    /// children of `dir` that have a recorded original-case basename in
    /// `OVERLAY_CASE`.
    ///
    /// `dir` must be the lowercase virtual DOS path of the parent directory
    /// (e.g. `c:\localappdata\uv\cache\builds-v0\.tmpXXXXXX`). Only
    /// DIRECT children (single path segment beyond `dir\`) are returned.
    ///
    /// Returns an empty Vec on any error or when no children with case
    /// records exist.
    pub fn overlay_children_with_case(&self, dir: &str) -> Vec<(String, String)> {
        let dir_lower = ensure_lower(dir);
        let dir_trimmed = dir_lower.trim_end_matches('\\');
        if dir_trimmed.is_empty() {
            return Vec::new();
        }
        let prefix_with_sep = format!("{}\\", dir_trimmed);
        let Ok(txn) = self.inner.db.begin_read() else { return Vec::new() };
        let Ok(t) = txn.open_table(db::OVERLAY_CASE) else { return Vec::new() };
        let mut out = Vec::new();
        let iter = if let Ok(iter) = t.range(prefix_with_sep.as_str()..) {
            iter
        } else {
            return Vec::new();
        };
        for entry in iter.flatten() {
            let key = entry.0.value();
            let Some(rest) = key.strip_prefix(&prefix_with_sep) else { break };
            // Direct children only — no further backslash.
            if rest.contains('\\') {
                continue;
            }
            let original_name = entry.1.value().to_owned();
            out.push((rest.to_owned(), original_name));
        }
        out
    }

    /// Record a whiteout (delete-marker / tombstone) for `path`. The real
    /// lower file is never touched; the marker only hides the path from the
    /// sandbox's merged view. Keyed on the ASCII-lowercased virtual DOS path.
    /// Clears the entire decide-cache (same conservative approach as
    /// `record_overlay`) so subsequent `decide` calls observe the marker.
    pub fn record_whiteout(&self, path: &str) -> Result<(), PolicyError> {
        let lower_raw = ensure_lower(path);
        let lower = trim_trailing_sep(&lower_raw);
        let txn = self.inner.db.begin_write()?;
        {
            let mut t = txn.open_table(db::WHITEOUTS)?;
            t.insert(lower, ())?;
        }
        txn.commit()?;
        self.inner.cache.clear();
        Ok(())
    }

    /// Remove a whiteout marker for `path` (revive). Called when a create at a
    /// whiteouted path re-materialises the file in the overlay.
    ///
    /// Also removes all descendent whiteouts (paths under `path\`). This is
    /// the OverlayFS revival semantic: re-creating a parent directory implies a
    /// clean slate for its entire subtree. Without this, a retry-clone scenario
    /// where a failed SSH clone whiteouts both the parent dir and all its
    /// children (`.git`, `.git\config`, …) leaves the children permanently
    /// hidden even after the parent is re-created by the HTTPS retry, because
    /// git opens `.git` with FILE_OPEN (not FILE_CREATE), bypassing the
    /// per-path revive gate (bug #78).
    pub fn clear_whiteout(&self, path: &str) -> Result<(), PolicyError> {
        let lower_raw = ensure_lower(path);
        let lower = trim_trailing_sep(&lower_raw);
        let txn = self.inner.db.begin_write()?;
        {
            let mut t = txn.open_table(db::WHITEOUTS)?;
            // Remove exact entry.
            t.remove(lower)?;
            // Remove all descendant entries: keys with prefix `lower\`.
            let prefix = format!("{}\\", lower);
            let child_keys: Vec<String> = t
                .range(prefix.as_str()..)
                .map(|iter| {
                    iter.flatten()
                        .map(|(k, _v)| k.value().to_owned())
                        .take_while(|k| k.starts_with(&prefix))
                        .collect()
                })
                .unwrap_or_default();
            for k in child_keys {
                t.remove(k.as_str())?;
            }
        }
        txn.commit()?;
        self.inner.cache.clear();
        Ok(())
    }

    /// Remove an OVERLAY_IDX entry for `path`. Called by the delete hook when
    /// it physically deletes an overlay copy: the overlay file is gone, so the
    /// index must not keep pointing at it (otherwise `compute` would treat a
    /// whiteouted path as "revived" and fall through to the now-missing
    /// overlay, surfacing the real lower file instead of Hidden).
    pub fn clear_overlay(&self, path: &str) -> Result<(), PolicyError> {
        let lower_raw = ensure_lower(path);
        let lower = trim_trailing_sep(&lower_raw);
        let txn = self.inner.db.begin_write()?;
        {
            let mut t = txn.open_table(db::OVERLAY_IDX)?;
            t.remove(lower)?;
        }
        txn.commit()?;
        self.inner.cache.clear();
        Ok(())
    }

    /// True iff a whiteout marker currently exists for `path`.
    pub fn is_whiteouted(&self, path: &str) -> bool {
        let lower_raw = ensure_lower(path);
        let lower = trim_trailing_sep(&lower_raw);
        let Ok(txn) = self.inner.db.begin_read() else { return false };
        let Ok(t) = txn.open_table(db::WHITEOUTS) else { return false };
        t.get(lower).ok().flatten().is_some()
    }

    /// True iff an overlay entry exists for the (already lowercased) `lower`.
    /// Used internally to distinguish a pure whiteout (Hidden) from a revived
    /// whiteout (overlay present → Cow).
    fn has_overlay(&self, lower: &str) -> bool {
        let Ok(txn) = self.inner.db.begin_read() else { return false };
        let Ok(t) = txn.open_table(db::OVERLAY_IDX) else { return false };
        t.get(lower).ok().flatten().is_some()
    }

    /// Return the set of whiteouted paths that are direct children of `dir`
    /// (i.e. `dir\<single-segment>`). Returns only the trailing segment
    /// (filename), not the full path, so the enumerate hook can match it
    /// against directory entry names. Used to hide whiteouted entries from
    /// directory listings.
    ///
    /// `dir` is matched case-insensitively and with a trailing-backslash
    /// boundary so a whiteout for `c:\foo\bar` is reported under `c:\foo`
    /// but NOT under `c:\foobar`.
    pub fn whiteouts_under(&self, dir: &str) -> Vec<String> {
        let dir_lower = ensure_lower(dir);
        let dir_trimmed = dir_lower.trim_end_matches('\\');
        if dir_trimmed.is_empty() {
            return Vec::new();
        }
        let prefix_with_sep = format!("{}\\", dir_trimmed);
        let Ok(txn) = self.inner.db.begin_read() else { return Vec::new() };
        let Ok(t) = txn.open_table(db::WHITEOUTS) else { return Vec::new() };
        let mut out = Vec::new();
        // range over keys >= prefix_with_sep; stop once we pass the dir's scope.
        let iter = if let Ok(iter) = t.range(prefix_with_sep.as_str()..) {
            iter
        } else {
            return Vec::new();
        };
        for entry in iter.flatten() {
            let key = entry.0.value();
            // Must start with `dir\` — otherwise it's a different directory.
            let Some(rest) = key.strip_prefix(&prefix_with_sep) else { break };
            // A direct child has no further backslash. Descendants of a
            // subdirectory (e.g. `dir\sub\file`) are not direct children of
            // `dir` and must not be reported here — enumeration of `dir`
            // would list `sub`, not `file`.
            if rest.contains('\\') {
                continue;
            }
            // Also stop if this key is a sibling-prefix miss (e.g. dir=`c:\foo`
            // and key=`c:\foobar\baz`): the range lower bound placed it
            // lexicographically after `c:\foo\`, but `c:\foobar` lacks the
            // separator so strip_prefix already broke above. Still, guard.
            out.push(rest.to_owned());
        }
        out
    }

    /// Traced decision for `why` / `what-if` — no caching, full chain info.
    pub fn decide_traced(
        &self,
        dos_path: &str,
        write_access: bool,
        depth: Option<u8>,
        exe_lower: Option<&str>,
    ) -> TracedDecision {
        let lower_raw = ensure_lower(dos_path);
        let lower_owned: String = trim_trailing_sep(&lower_raw).to_string();
        let lower: &str = &lower_owned;

        // project_root always passthrough
        if path_contained_in(lower, &self.inner.project_root_lower) {
            return TracedDecision {
                decision: db::RuleMode::Passthrough,
                target_path: None,
                rule_id: None,
                rule_prefix: None,
                mock_match: None,
                mockdir_match: None,
                chain: vec![],
            };
        }

        // Whiteout check mirrors `compute`: a hidden external path is reported
        // as Passthrough in the trace's RuleMode field (there is no RuleMode::Hidden
        // — Hidden is a policy::Mode only the hook layer consumes), but with an
        // empty chain and no rule so `why` shows no rule drove the decision.
        // The authoritative Mode::Hidden outcome is produced by `compute`.
        if self.is_whiteouted(dos_path) && !self.has_overlay(&lower) {
            return TracedDecision {
                decision: db::RuleMode::Passthrough,
                target_path: None,
                rule_id: Some("whiteout".into()),
                rule_prefix: None,
                mock_match: None,
                mockdir_match: None,
                chain: vec![],
            };
        }

        let txn = match self.inner.db.begin_read() {
            Ok(t) => t,
            Err(_) => return TracedDecision {
                decision: db::RuleMode::Passthrough,
                target_path: None,
                rule_id: None,
                rule_prefix: None,
                mock_match: None,
                mockdir_match: None,
                chain: vec![],
            },
        };

        // Check mocks
        if let Some(payload) = db::find_mock_payload(&txn, &lower) {
            let _ = payload; // we know it matched
            let overlay = path::mirror_into_overlay_layout(&lower, &self.inner.overlay_layout);
            return TracedDecision {
                decision: db::RuleMode::Cow, // mocks use Cow overlay path
                target_path: Some(overlay),
                rule_id: None,
                rule_prefix: None,
                mock_match: Some(lower.to_string()),
                mockdir_match: None,
                chain: vec![],
            };
        }

        // Check mock dirs
        if let Some(matched) = db::matched_mock_dir(&txn, &lower) {
            let overlay = path::mirror_into_overlay(&lower, &self.inner.mock_dirs_root);
            return TracedDecision {
                decision: db::RuleMode::Cow,
                target_path: Some(overlay),
                rule_id: None,
                rule_prefix: None,
                mock_match: None,
                mockdir_match: Some(matched),
                chain: vec![],
            };
        }

        // Trace through rules
        let mut chain = Vec::new();
        let table = match txn.open_table(db::RULES) {
            Ok(t) => t,
            Err(_) => return TracedDecision {
                decision: db::RuleMode::Passthrough,
                target_path: None,
                rule_id: None,
                rule_prefix: None,
                mock_match: None,
                mockdir_match: None,
                chain: vec![],
            },
        };

        let mut best: Option<(usize, db::RuleRow)> = None;
        let mut best_prefix: Option<String> = None;
        let mut default_row: Option<db::RuleRow> = None;

        for entry in table.range::<&str>(..).ok().into_iter().flatten() {
            let Ok((key, value)) = entry else { continue };
            let pattern = key.value();
            if pattern.is_empty() {
                default_row = db::decode_rule(value.value());
                continue;
            }
            let Some(row) = db::decode_rule(value.value()) else { continue };

            // Check prefix match
            if !path::pattern_matches_prefix(pattern, &lower) {
                chain.push(ConsideredRule {
                    id: row.id.clone(),
                    prefix: pattern.to_owned(),
                    verdict: Verdict::Skip { reason: "prefix mismatch".into() },
                });
                continue;
            }

            // Check when filter
            if let Some(ref when) = row.when {
                if let Some(min_depth) = when.depth {
                    if depth.is_some() && depth.unwrap() < min_depth {
                        chain.push(ConsideredRule {
                            id: row.id.clone(),
                            prefix: pattern.to_owned(),
                            verdict: Verdict::Skip { reason: format!("depth filter: need >= {min_depth}"), },
                        });
                        continue;
                    }
                }
                if let Some(ref exe_pattern) = when.exe {
                    if exe_lower.is_none() || !path::pattern_matches_exact(exe_pattern, exe_lower.unwrap()) {
                        chain.push(ConsideredRule {
                            id: row.id.clone(),
                            prefix: pattern.to_owned(),
                            verdict: Verdict::Skip { reason: "exe filter mismatch".into() },
                        });
                        continue;
                    }
                }
            }

            let mut spec = path::pattern_specificity(pattern);
            if row.when.is_some() { spec += 1; }
            if let Some(ref when) = row.when {
                if let Some(ref exe) = when.exe {
                    spec += path::pattern_specificity(exe);
                }
            }

            chain.push(ConsideredRule {
                id: row.id.clone(),
                prefix: pattern.to_owned(),
                verdict: Verdict::Match { specificity: spec },
            });

            match &best {
                None => { best_prefix = Some(pattern.to_owned()); best = Some((spec, row)); }
                Some((s, _)) if spec > *s => { best_prefix = Some(pattern.to_owned()); best = Some((spec, row)); }
                _ => {}
            }
        }

        // Mirror `compute`: fold in the configured default catch-all rule so
        // `why` / `what-if` report the same decision the live path takes. With
        // no explicit match, the default rule drives the outcome (read=pass,
        // write=cow under the merged-view isolation model), and when even the
        // default is absent the fallback is the hard-coded (Passthrough, Cow)
        // pair from `compute`.
        let matched = best.map(|(_, r)| r).or(default_row);
        let (decision, rule_id, rule_prefix) = match &matched {
            Some(row) => {
                let mode = if write_access { row.mode_write } else { row.mode_read };
                (mode, Some(row.id.clone()), best_prefix.clone().or_else(|| Some(String::new())))
            }
            None => (db::RuleMode::Passthrough, None, None),
        };

        let target_path = match decision {
            db::RuleMode::Deny => None,
            db::RuleMode::Passthrough => None,
            db::RuleMode::Cow | db::RuleMode::Redirect => {
                Some(path::mirror_into_overlay_layout(&lower, &self.inner.overlay_layout))
            }
        };

        TracedDecision {
            decision,
            target_path,
            rule_id,
            rule_prefix,
            mock_match: None,
            mockdir_match: None,
            chain,
        }
    }

    /// Decide the fate of a DOS path under the **merged-view overlay** model.
    ///
    /// This is the core isolation policy, conceptually identical to OverlayFS
    /// or Sandboxie's sandbox: there is exactly one place an agent may mutate
    /// the real disk (its own `project_root`); every other write is isolated
    /// inside the sandbox overlay and never reaches the real disk.
    ///
    /// | Operation            | inside `project_root`            | outside `project_root`                 |
    /// |----------------------|----------------------------------|----------------------------------------|
    /// | Read                 | passthrough (real disk)          | overlay if recorded, else real disk    |
    /// | Write / create       | passthrough (real disk)          | **CoW → overlay** (isolated)           |
    /// | Delete / rename      | passthrough (real disk)          | blocked (`ACCESS_DENIED`) in the hook  |
    ///
    /// Resolution order:
    /// 1. **`project_root` short-circuit** — the agent's own dir is always real
    ///    (passthrough), regardless of any rule. This is the only path that may
    ///    hit the real disk for writes.
    /// 2. **Mock payload / mock dir** — synthesized content, never real disk.
    /// 3. **Rule lookup** via `best_rule_match` (explicit prefix rule, else the
    ///    configured default catch-all rule). An explicit rule may force
    ///    `Deny` (block) or `Passthrough` (override the default and touch the
    ///    real disk — use sparingly).
    /// 4. **Default** when nothing matched: read = `Passthrough` (read-through
    ///    will still consult `OVERLAY_IDX` so a previously-isolated file is
    ///    seen), write = `Cow` (isolate into the overlay). This is what makes
    ///    external writes land in the sandbox instead of on the real disk.
    ///
    /// The read-through branch inside the `Passthrough` arm consults
    /// `OVERLAY_IDX` so that a file previously CoW'd into the overlay is
    /// returned from there on read — the agent sees its own isolated view.
    pub(crate) fn compute(&self, dos_path: &str, write_access: bool, depth: Option<u8>, exe_lower: Option<&str>) -> Decision {
        let lower_raw = ensure_lower(dos_path);
        // Normalize trailing separators so OVERLAY_IDX / WHITEOUTS key lookups
        // agree across create-at-`d:\foo\` and open-at-`d:\foo` callers.
        let lower_owned: std::borrow::Cow<'_, str> = match lower_raw {
            std::borrow::Cow::Borrowed(b) => {
                let t = trim_trailing_sep(b);
                if std::ptr::eq(t.as_ptr(), b.as_ptr()) && t.len() == b.len() {
                    std::borrow::Cow::Borrowed(b)
                } else {
                    std::borrow::Cow::Owned(t.to_string())
                }
            }
            other => {
                let t = trim_trailing_sep(&other);
                if t.len() == other.len() { other } else { std::borrow::Cow::Owned(t.to_string()) }
            }
        };
        let lower: &str = lower_owned.as_ref();

        if path_contained_in(lower, &self.inner.project_root_lower) {
            return Decision { mode: Mode::Passthrough, overlay: None, cow_from: None, mock_payload: None };
        }

        // ── Whiteout (OverlayFS tombstone) check ────────────────────────────
        //
        // A path outside project_root may carry a whiteout marker recorded by a
        // previous delete. If it does, and there is no overlay entry for it
        // (i.e. it was not revived by a subsequent create), the merged view
        // hides it: open → not-found, absent from enumeration. We model that
        // with Mode::Hidden.
        //
        // If an overlay entry EXISTS (the agent re-created the file in the
        // overlay after deleting it), the whiteout is effectively superseded
        // — the file is alive in the overlay and reads resolve there. In that
        // case we fall through to the normal flow, which returns Mode::Cow
        // pointing at the overlay.
        //
        // Both tables are consulted in one read txn to keep this cheap.
        if let Ok(txn) = self.inner.db.begin_read() {
            let is_whiteouted = txn.open_table(db::WHITEOUTS)
                .ok()
                .and_then(|t| t.get(&*lower).ok().flatten().is_some().then_some(()))
                .is_some();
            if is_whiteouted {
                // "Alive in the overlay" = present in the index OR physically
                // materialized (relative-create holes). Either means the path
                // was revived after the delete; fall through to Cow below.
                let idx_hit = txn.open_table(db::OVERLAY_IDX)
                    .ok()
                    .and_then(|t| t.get(&*lower).ok().flatten().map(|_| ()))
                    .is_some();
                let phys_hit = !idx_hit
                    && physical_overlay_path(&lower, &self.inner.overlay_layout).is_some();
                if !(idx_hit || phys_hit) {
                    return Decision { mode: Mode::Hidden, overlay: None, cow_from: None, mock_payload: None };
                }
                // alive: fall through (revive) — normal flow returns Cow below.
            }
        }

        let snap = self.inner.snapshot.load();

        if let Some(payload) = snap.find_mock_payload(&lower) {
            let overlay = path::mirror_into_overlay_layout(&lower, &self.inner.overlay_layout);
            return Decision {
                mode: Mode::Mock,
                overlay: Some(overlay),
                cow_from: None,
                mock_payload: Some(payload),
            };
        }

        if snap.matched_mock_dir(&lower).is_some() {
            let overlay = path::mirror_into_overlay(&lower, &self.inner.mock_dirs_root);
            return Decision {
                mode: Mode::Cow,
                overlay: Some(overlay),
                cow_from: None,
                mock_payload: None,
            };
        }

        let rule = snap.best_rule_match(&lower, depth, exe_lower);

        // Merged-view default: a path outside project_root that matched no
        // explicit rule (and no configured default) is isolated — reads
        // passthrough (the read-through arm below still consults OVERLAY_IDX),
        // writes go CoW into the overlay so the real disk is never touched.
        // `best_rule_match` already folds in the configured default catch-all
        // rule, so an operator-supplied default overrides this fallback.
        let (mode_read, mode_write) = rule
            .map(|r| (r.mode_read, r.mode_write))
            .unwrap_or((db::RuleMode::Passthrough, db::RuleMode::Cow));

        let effective_mode = if write_access { mode_write } else { mode_read };

        match effective_mode {
            db::RuleMode::Deny => Decision { mode: Mode::Deny, overlay: None, cow_from: None, mock_payload: None },
            db::RuleMode::Passthrough => {
                if !write_access {
                    // Index first (fast path): an exact-key hit redirects the
                    // read into the overlay.
                    if let Ok(txn) = self.inner.db.begin_read() {
                        if let Ok(t) = txn.open_table(db::OVERLAY_IDX) {
                            if let Ok(Some(v)) = t.get(&*lower) {
                                let ov = PathBuf::from(v.value());
                                return Decision { mode: Mode::Cow, overlay: Some(ov), cow_from: None, mock_payload: None };
                            }
                        }
                    }
                    // Index MISS → consult the PHYSICAL overlay mirror tree
                    // (source of truth). This catches files that exist in the
                    // overlay but were never indexed (relative-open-create
                    // holes, e.g. a cloned repo's `.git`/`agent/`). Without it,
                    // the read passthroughs to the real disk and fails with
                    // STATUS_OBJECT_NAME_NOT_FOUND. The mirror check is a single
                    // local stat; HookCache amortizes it across repeated reads.
                    if let Some(ov) = physical_overlay_path(&lower, &self.inner.overlay_layout) {
                        return Decision { mode: Mode::Cow, overlay: Some(ov), cow_from: None, mock_payload: None };
                    }
                }
                passthrough()
            }
            db::RuleMode::Cow | db::RuleMode::Redirect => {
                let overlay = path::mirror_into_overlay_layout(&lower, &self.inner.overlay_layout);
                let existing_overlay = if let Ok(txn) = self.inner.db.begin_read() {
                    if let Ok(t) = txn.open_table(db::OVERLAY_IDX) {
                        t.get(&*lower).ok().flatten().map(|v| PathBuf::from(v.value()))
                    } else { None }
                } else { None };
                if let Some(ov) = existing_overlay {
                    return Decision { mode: Mode::Cow, overlay: Some(ov), cow_from: None, mock_payload: None };
                }
                // Defense in depth: only record a CoW source if the path is a
                // real, non-reparse file *at decision time*. The authoritative
                // TOCTOU fix lives at the copy site (hook::hooks::prepare_overlay,
                // src_is_reparse_point) because decision-time is far from
                // copy-time and the source is attacker-influenceable in between;
                // this merely avoids ever recording a known-reparse source.
                let cow_from = if write_access && path_is_plain_file(dos_path) {
                    Some(PathBuf::from(dos_path))
                } else {
                    None
                };
                Decision { mode: Mode::Cow, overlay: Some(overlay), cow_from, mock_payload: None }
            }
        }
    }
}

// ── Inner accessor (needed by decide.rs to reach PolicyInner fields) ──────
// PolicyInner is pub(crate) in lib.rs; fields accessed via pub(crate) visibility.

#[cfg(test)]
mod tests {
    use super::{cache_key, path_contained_in};

    #[test]
    fn path_contained_exact_match() {
        assert!(path_contained_in(r"c:\proj", r"c:\proj"));
        assert!(path_contained_in(r"c:\proj", r"c:\proj\"));
    }

    #[test]
    fn path_contained_subdir_match() {
        assert!(path_contained_in(r"c:\proj\src\main.rs", r"c:\proj"));
    }

    #[test]
    fn path_not_contained_sibling_prefix() {
        // The bug this guards against: a sibling dir whose name starts with
        // the root must NOT be treated as inside the root.
        assert!(!path_contained_in(r"c:\projevil\file", r"c:\proj"));
        assert!(!path_contained_in(r"c:\projects\foo", r"c:\proj"));
        assert!(!path_contained_in(r"c:\proj.txt", r"c:\proj"));
    }

    #[test]
    fn path_not_contained_disjoint() {
        assert!(!path_contained_in(r"c:\other", r"c:\proj"));
    }

    #[test]
    fn path_contained_empty_root_refused() {
        // An empty/unset root must never match every path.
        assert!(!path_contained_in(r"c:\any\path", ""));
        assert!(!path_contained_in(r"c:\any\path", r"\"));
    }

    #[test]
    fn cache_key_write_flag_differs() {
        assert_ne!(cache_key("foo", false, None, None), cache_key("foo", true, None, None));
    }

    #[test]
    fn cache_key_case_sensitive() {
        assert_ne!(cache_key("FOO", false, None, None), cache_key("foo", false, None, None));
    }

    #[test]
    fn cache_key_deterministic() {
        assert_eq!(cache_key("a", false, None, None), cache_key("a", false, None, None));
    }

    // ── Composite cache key tests ────────────────────────────────────────────

    #[test]
    fn composite_key_different_depth() {
        let k1 = cache_key("c:\\test", false, Some(0), None);
        let k2 = cache_key("c:\\test", false, Some(1), None);
        assert_ne!(k1, k2, "different depth must produce different keys");
    }

    #[test]
    fn composite_key_different_exe() {
        let k1 = cache_key("c:\\test", false, None, Some("app.exe"));
        let k2 = cache_key("c:\\test", false, None, Some("other.exe"));
        assert_ne!(k1, k2, "different exe must produce different keys");
    }

    #[test]
    fn composite_key_none_vs_some_zero_depth() {
        let k_none = cache_key("c:\\test", false, None, None);
        let k_zero = cache_key("c:\\test", false, Some(0), None);
        assert_ne!(k_none, k_zero, "None vs Some(0) depth must differ (tag byte)");
    }

    #[test]
    fn composite_key_none_vs_some_empty_exe() {
        let k_none = cache_key("c:\\test", false, None, None);
        let k_empty = cache_key("c:\\test", false, None, Some(""));
        assert_ne!(k_none, k_empty, "None vs Some(\"\") exe must differ");
    }

    #[test]
    fn composite_key_same_params_equal() {
        let k1 = cache_key("c:\\path\\file.txt", true, Some(2), Some("app.exe"));
        let k2 = cache_key("c:\\path\\file.txt", true, Some(2), Some("app.exe"));
        assert_eq!(k1, k2, "identical params must produce identical keys");
    }

    #[test]
    fn composite_key_collision_sanity() {
        let mut keys = std::collections::HashSet::new();
        for i in 0u8..250 {
            for d in [None, Some(i % 5)] {
                let exe_name = format!("exe{}.bin", i);
                let exe_opt: Option<&str> = if i % 3 == 0 { None } else { Some(&exe_name) };
                let k = cache_key(
                    &format!("c:\\path\\file{}", i),
                    i % 2 == 0,
                    d,
                    exe_opt,
                );
                assert!(keys.insert(k), "collision at i={i} d={d:?}");
            }
        }
        assert!(keys.len() >= 400, "expected ~500 unique keys, got {}", keys.len());
    }
}
