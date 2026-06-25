use std::path::PathBuf;
use std::sync::Arc;
use xxhash_rust::xxh3::Xxh3;

use crate::{db, path, ensure_lower, Mode, Decision, PolicyError};

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
            t.insert(orig.to_lowercase().as_str(), overlay)?;
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

    /// Traced decision for `why` / `what-if` — no caching, full chain info.
    pub fn decide_traced(
        &self,
        dos_path: &str,
        write_access: bool,
        depth: Option<u8>,
        exe_lower: Option<&str>,
    ) -> TracedDecision {
        let lower = ensure_lower(dos_path);

        // project_root always passthrough
        if path_contained_in(&lower, &self.inner.project_root_lower) {
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
            let overlay = path::mirror_into_overlay(&lower, &self.inner.sandbox_root);
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
                Some(path::mirror_into_overlay(&lower, &self.inner.sandbox_root))
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
        let lower = ensure_lower(dos_path);

        if path_contained_in(&lower, &self.inner.project_root_lower) {
            return Decision { mode: Mode::Passthrough, overlay: None, cow_from: None, mock_payload: None };
        }

        let snap = self.inner.snapshot.load();

        if let Some(payload) = snap.find_mock_payload(&lower) {
            let overlay = path::mirror_into_overlay(&lower, &self.inner.sandbox_root);
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
                    if let Ok(txn) = self.inner.db.begin_read() {
                        if let Ok(t) = txn.open_table(db::OVERLAY_IDX) {
                            if let Ok(Some(v)) = t.get(&*lower) {
                                let ov = PathBuf::from(v.value());
                                return Decision { mode: Mode::Cow, overlay: Some(ov), cow_from: None, mock_payload: None };
                            }
                        }
                    }
                }
                passthrough()
            }
            db::RuleMode::Cow | db::RuleMode::Redirect => {
                let overlay = path::mirror_into_overlay(&lower, &self.inner.sandbox_root);
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
