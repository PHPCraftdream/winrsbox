pub mod path;
pub mod db;
pub mod reg;
pub mod reg_overlay;
pub mod scan;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use quick_cache::sync::Cache;
use xxhash_rust::xxh3::Xxh3;
use thiserror::Error;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum Mode {
    Passthrough,
    Deny,
    Cow,
    Mock,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Decision {
    pub mode: Mode,
    pub overlay: Option<PathBuf>,
    pub cow_from: Option<PathBuf>,
    pub mock_payload: Option<Vec<u8>>,
}

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

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("redb: {0}")]
    Db(#[from] redb::Error),
    #[error("redb database: {0}")]
    DbOpen(#[from] redb::DatabaseError),
    #[error("redb storage: {0}")]
    DbStorage(#[from] redb::StorageError),
    #[error("redb transaction: {0}")]
    DbTxn(#[from] redb::TransactionError),
    #[error("redb table: {0}")]
    DbTable(#[from] redb::TableError),
    #[error("redb commit: {0}")]
    DbCommit(#[from] redb::CommitError),
    #[error("ktav: {0}")]
    Ktav(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

fn ensure_lower(s: &str) -> std::borrow::Cow<'_, str> {
    if s.bytes().all(|b| !b.is_ascii_uppercase()) {
        std::borrow::Cow::Borrowed(s)
    } else {
        std::borrow::Cow::Owned(s.to_lowercase())
    }
}

pub struct Policy {
    inner: Arc<PolicyInner>,
}

struct PolicyInner {
    db: redb::Database,
    cache: Cache<u128, Arc<Decision>>,
    snapshot: arc_swap::ArcSwap<Snapshot>,
    sandbox_root: PathBuf,
    mock_dirs_root: PathBuf,
    project_root_lower: String,
}

struct Snapshot {
    rules: Vec<SnapshotRule>,
    default_rule: Option<db::RuleRow>,
    mocks_exact: rustc_hash::FxHashMap<String, Vec<u8>>,
    mocks_glob: Vec<(String, Vec<u8>)>,
    mock_dirs: Vec<String>,
}

struct SnapshotRule {
    pattern: String,
    row: db::RuleRow,
}

impl Snapshot {
    fn load_from_db(db: &redb::Database) -> Result<Self, PolicyError> {
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

    fn find_mock_payload(&self, lower_path: &str) -> Option<Vec<u8>> {
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

    fn matched_mock_dir(&self, lower_path: &str) -> Option<&str> {
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

    fn best_rule_match(&self, lower_path: &str, depth: Option<u8>, exe_lower: Option<&str>) -> Option<&db::RuleRow> {
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
        best.map(|(_, r)| r).or(self.default_rule.as_ref())
    }
}

impl Policy {
    pub fn open_or_create(
        db_path: &Path,
        sandbox_root: PathBuf,
        mock_dirs_root: PathBuf,
        project_root: PathBuf,
    ) -> Result<Self, PolicyError> {
        let db = redb::Database::create(db_path)?;
        // Ensure tables exist
        {
            let txn = db.begin_write()?;
            txn.open_table(db::RULES)?;
            txn.open_table(db::MOCKS)?;
            txn.open_table(db::MOCK_DIRS)?;
            txn.open_table(db::OVERLAY_IDX)?;
            txn.commit()?;
        }
        let project_root_lower = project_root.to_string_lossy().to_lowercase();
        let snapshot = Arc::new(Snapshot::load_from_db(&db)?);
        Ok(Self {
            inner: Arc::new(PolicyInner {
                db,
                cache: Cache::new(16384),
                snapshot: arc_swap::ArcSwap::from(snapshot),
                sandbox_root,
                mock_dirs_root,
                project_root_lower,
            }),
        })
    }

    pub fn load_config(&self, path: &Path) -> Result<(), PolicyError> {
        let src = std::fs::read_to_string(path)?;
        let cfg: db::Config = ktav::from_str(&src)
            .map_err(|e| PolicyError::Ktav(e.to_string()))?;
        db::apply_config(&self.inner.db, &cfg)?;
        let new_snap = Arc::new(Snapshot::load_from_db(&self.inner.db)?);
        self.inner.snapshot.store(new_snap);
        self.inner.cache.clear();
        Ok(())
    }

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

    pub fn sandbox_root(&self) -> &Path {
        &self.inner.sandbox_root
    }

    pub fn mock_dirs_root(&self) -> &Path {
        &self.inner.mock_dirs_root
    }

    pub fn project_root(&self) -> &str {
        &self.inner.project_root_lower
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
        if lower.starts_with(self.inner.project_root_lower.trim_end_matches('\\')) {
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

    pub fn db(&self) -> &redb::Database {
        &self.inner.db
    }

    fn compute(&self, dos_path: &str, write_access: bool, depth: Option<u8>, exe_lower: Option<&str>) -> Decision {
        let lower = ensure_lower(dos_path);

        if lower.starts_with(self.inner.project_root_lower.trim_end_matches('\\')) {
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
                let cow_from = if write_access && std::path::Path::new(dos_path).exists() {
                    Some(PathBuf::from(dos_path))
                } else {
                    None
                };
                Decision { mode: Mode::Cow, overlay: Some(overlay), cow_from, mock_payload: None }
            }
        }
    }
}

fn passthrough() -> Decision {
    Decision { mode: Mode::Passthrough, overlay: None, cow_from: None, mock_payload: None }
}

/// Compute a composite cache key: `(path_hash u64 || ctx_hash u64)` as u128.
///
/// `path_hash` covers the path bytes + write flag.
/// `ctx_hash` covers depth + exe_lower (the "when" filter context).
/// Both hashes are produced by independent `Xxh3` instances.
/// Bit-concatenation (not XOR) preserves full entropy of both hashes.
fn cache_key(path: &str, write: bool, depth: Option<u8>, exe_lower: Option<&str>) -> u128 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn cache_key(path: &str, write: bool, depth: Option<u8>, exe_lower: Option<&str>) -> u128 {
        use xxhash_rust::xxh3::Xxh3;
        let mut h1 = Xxh3::new();
        h1.update(path.as_bytes());
        h1.update(&[if write { 1u8 } else { 0u8 }]);
        let path_hash = h1.digest();

        let mut h2 = Xxh3::new();
        if let Some(d) = depth {
            h2.update(&[1, d]);
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

    #[test]
    fn fresh_db_defaults_passthrough_cow() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(
            &db_path,
            sandbox,
            mock_dirs,
            project,
        ).unwrap();

        let d = p.decide(r"c:\some\path", false);
        assert_eq!(d.mode, Mode::Passthrough);

        let d = p.decide(r"c:\some\path", true);
        assert_eq!(d.mode, Mode::Cow);
    }

    #[test]
    fn deny_rule_on_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(
            &db_path,
            sandbox,
            mock_dirs,
            project,
        ).unwrap();

        let cfg_path = dir.path().join("config.ktv");
        let mut f = std::fs::File::create(&cfg_path).unwrap();
        let cfg = "defaults: {\n\
            \x20   read: passthrough\n\
            \x20   write: cow\n\
            }\n\
            \n\
            rules: [\n\
            \x20   {\n\
            \x20       prefix: c:\\test\n\
            \x20       write: deny\n\
            \x20   }\n\
            ]";
        write!(f, "{}", cfg).unwrap();
        drop(f);

        p.load_config(&cfg_path).unwrap();
        let d = p.decide("c:\\test\\x", true);
        assert_eq!(d.mode, Mode::Deny);
    }

    #[test]
    fn record_overlay_then_read_cow() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(
            &db_path,
            sandbox,
            mock_dirs,
            project,
        ).unwrap();

        let overlay_path = dir.path().join("sb").join("c").join("data.txt");
        p.record_overlay(r"c:\data.txt", overlay_path.to_str().unwrap()).unwrap();

        let d = p.decide(r"c:\data.txt", false);
        assert_eq!(d.mode, Mode::Cow);
        assert!(d.overlay.is_some());
    }

    #[test]
    fn project_root_always_passthrough() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(
            &db_path,
            sandbox,
            mock_dirs,
            project.clone(),
        ).unwrap();

        let cfg_path = dir.path().join("config.ktv");
        let mut f = std::fs::File::create(&cfg_path).unwrap();
        let cfg = "defaults: {\n\
            \x20   read: deny\n\
            \x20   write: deny\n\
            }\n\
            \n\
            rules: [\n\
            \x20   {\n\
            \x20       prefix: c:\\deny_all\n\
            \x20       read: deny\n\
            \x20       write: deny\n\
            \x20   }\n\
            ]";
        write!(f, "{}", cfg).unwrap();
        drop(f);
        p.load_config(&cfg_path).unwrap();

        let inside = project.join("src").join("main.rs");
        let d = p.decide(inside.to_str().unwrap(), false);
        assert_eq!(d.mode, Mode::Passthrough);

        let d = p.decide(inside.to_str().unwrap(), true);
        assert_eq!(d.mode, Mode::Passthrough);
    }

    #[test]
    fn mock_dirs_prefix_cow() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(
            &db_path,
            sandbox,
            mock_dirs.clone(),
            project,
        ).unwrap();

        let cfg_path = dir.path().join("config.ktv");
        let mut f = std::fs::File::create(&cfg_path).unwrap();
        write!(f, "defaults: {{\n\
            read: passthrough\n\
            write: cow\n\
        }}\n\
        \n\
        mock_dirs: [\n\
            {{\n\
                prefix: c:\\fake\n\
            }}\n\
        ]\n\
        ").unwrap();
        drop(f);
        p.load_config(&cfg_path).unwrap();

        let d = p.decide(r"c:\fake\sub\file.txt", false);
        assert_eq!(d.mode, Mode::Cow);
        let expected = mock_dirs.join("c").join("fake").join("sub").join("file.txt");
        assert_eq!(d.overlay.unwrap(), expected);
    }

    // ── Additional policy integration tests ─────────────────────────────────

    #[test]
    fn decide_cache_hit_returns_same_decision() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
        let d1 = p.decide(r"c:\some\path", false);
        let d2 = p.decide(r"c:\some\path", false);
        assert_eq!(d1.mode, d2.mode);
        assert_eq!(d1.overlay, d2.overlay);
    }

    #[test]
    fn decide_cow_write_nonexistent_file_no_cow_from() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
        let d = p.decide(r"c:\nonexistent\file.txt", true);
        assert_eq!(d.mode, Mode::Cow);
        assert!(d.cow_from.is_none(), "cow_from should be None for non-existent files");
        assert!(d.overlay.is_some());
    }

    #[test]
    fn record_overlay_invalidates_cache() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();

        // First call: default passthrough for read
        let d1 = p.decide(r"c:\data.txt", false);
        assert_eq!(d1.mode, Mode::Passthrough);

        // Record overlay
        let overlay = dir.path().join("sb").join("c").join("data.txt");
        p.record_overlay(r"c:\data.txt", overlay.to_str().unwrap()).unwrap();

        // Second call: should see Cow now
        let d2 = p.decide(r"c:\data.txt", false);
        assert_eq!(d2.mode, Mode::Cow);
    }

    #[test]
    fn sandbox_root_accessor() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox.clone(), mock_dirs, project).unwrap();
        assert_eq!(p.sandbox_root(), sandbox);
    }

    #[test]
    fn mock_dirs_root_accessor() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs.clone(), project).unwrap();
        assert_eq!(p.mock_dirs_root(), mock_dirs);
    }

    #[test]
    fn project_root_accessor_lowercase() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("ProjDir");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
        // project_root should be lowercased
        assert!(p.project_root().contains("projdir"));
        assert!(!p.project_root().contains("ProjDir"));
    }

    #[test]
    fn decide_with_mock_file() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();

        let cfg_path = dir.path().join("config.ktv");
        let mut f = std::fs::File::create(&cfg_path).unwrap();
        // NOTE: ktav includes the quotes as part of the string value
        write!(f, "defaults: {{\n\
            read: passthrough\n\
            write: cow\n\
        }}\n\
        \n\
        mocks: [\n\
            {{\n\
                path: c:\\fake\\token.txt\n\
                content_inline: secret data\n\
            }}\n\
        ]\n\
        ").unwrap();
        drop(f);
        p.load_config(&cfg_path).unwrap();

        let d = p.decide(r"c:\fake\token.txt", false);
        assert_eq!(d.mode, Mode::Mock);
        assert_eq!(d.mock_payload.unwrap(), b"secret data");
    }

    #[test]
    fn load_config_invalid_ktav_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();

        let cfg_path = dir.path().join("bad.ktv");
        std::fs::write(&cfg_path, "{{{{invalid}}}}").unwrap();
        let result = p.load_config(&cfg_path);
        assert!(result.is_err());
    }

    #[test]
    fn load_config_missing_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
        let result = p.load_config(dir.path().join("nonexistent.ktv").as_path());
        assert!(result.is_err());
    }
}
