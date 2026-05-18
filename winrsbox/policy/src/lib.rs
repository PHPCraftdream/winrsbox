pub mod path;
mod db;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use quick_cache::sync::Cache;
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

pub struct Policy {
    inner: Arc<PolicyInner>,
}

struct PolicyInner {
    db: redb::Database,
    cache: Cache<u64, Decision>,
    sandbox_root: PathBuf,
    mock_dirs_root: PathBuf,
    project_root_lower: String,
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
        Ok(Self {
            inner: Arc::new(PolicyInner {
                db,
                cache: Cache::new(16384),
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
        // Invalidate cache after reload — create new cache by dropping old entries via clear
        self.inner.cache.clear();
        Ok(())
    }

    /// Decide what to do with a DOS path (lowercase-normalised before call is fine but not required).
    pub fn decide(&self, dos_path: &str, write_access: bool) -> Decision {
        let key = cache_key(dos_path, write_access);
        if let Some(d) = self.inner.cache.get(&key) {
            return d;
        }
        let d = self.compute(dos_path, write_access);
        // NOTE: check-then-insert race is intentional — IPC decisions are idempotent;
        // duplicate inserts under contention add latency but not incorrectness.
        self.inner.cache.insert(key, d.clone());
        d
    }

    pub fn record_overlay(&self, orig: &str, overlay: &str) -> Result<(), PolicyError> {
        let txn = self.inner.db.begin_write()?;
        {
            let mut t = txn.open_table(db::OVERLAY_IDX)?;
            t.insert(orig.to_lowercase().as_str(), overlay)?;
        }
        txn.commit()?;
        // Invalidate cache entry so next read sees overlay
        let key_r = cache_key(orig, false);
        let key_w = cache_key(orig, true);
        self.inner.cache.remove(&key_r);
        self.inner.cache.remove(&key_w);
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

    fn compute(&self, dos_path: &str, write_access: bool) -> Decision {
        let lower = dos_path.to_lowercase();

        // project_root always passthrough (read AND write)
        if lower.starts_with(self.inner.project_root_lower.trim_end_matches('\\')) {
            return Decision { mode: Mode::Passthrough, overlay: None, cow_from: None, mock_payload: None };
        }

        // Check deny / mock via DB
        let txn = match self.inner.db.begin_read() {
            Ok(t) => t,
            Err(_) => return passthrough(),
        };

        // File mock (exact match with glob support on the mock key).
        if let Some(payload) = db::find_mock_payload(&txn, &lower) {
            let overlay = path::mirror_into_overlay(&lower, &self.inner.sandbox_root);
            return Decision {
                mode: Mode::Mock,
                overlay: Some(overlay),
                cow_from: None,
                mock_payload: Some(payload),
            };
        }

        // Mock dir (glob prefix match) — entire subtree is redirected to
        // <mock_dirs_root>/<mirror>/. Behaves like Cow with pre-populated
        // overlay: reads see whatever the user put there; writes land there
        // too (and persist across runs unless the user wipes mock-dirs/).
        if db::matched_mock_dir(&txn, &lower).is_some() {
            let overlay = path::mirror_into_overlay(&lower, &self.inner.mock_dirs_root);
            return Decision {
                mode: Mode::Cow,
                overlay: Some(overlay),
                cow_from: None,
                mock_payload: None,
            };
        }

        // Best-match rule (glob-aware, picks the most specific pattern).
        let rule = db::best_rule_match(&txn, &lower);

        let (mode_read, mode_write) = rule
            .map(|r| (r.mode_read, r.mode_write))
            .unwrap_or((db::RuleMode::Passthrough, db::RuleMode::Cow));

        let effective_mode = if write_access { mode_write } else { mode_read };

        match effective_mode {
            db::RuleMode::Deny => Decision { mode: Mode::Deny, overlay: None, cow_from: None, mock_payload: None },
            db::RuleMode::Passthrough => {
                // Даже при passthrough-read проверяем overlay_idx: файл мог быть
                // перенаправлен в overlay предыдущей записью (в т.ч. из дочернего процесса).
                if !write_access {
                    if let Ok(t) = txn.open_table(db::OVERLAY_IDX) {
                        if let Ok(Some(v)) = t.get(lower.as_str()) {
                            let ov = PathBuf::from(v.value());
                            return Decision { mode: Mode::Cow, overlay: Some(ov), cow_from: None, mock_payload: None };
                        }
                    }
                }
                passthrough()
            }
            db::RuleMode::Cow | db::RuleMode::Redirect => {
                let overlay = path::mirror_into_overlay(&lower, &self.inner.sandbox_root);
                // Check overlay index (read path: does overlay already exist?)
                let existing_overlay = if let Ok(t) = txn.open_table(db::OVERLAY_IDX) {
                    t.get(lower.as_str()).ok().flatten().map(|v| PathBuf::from(v.value()))
                } else {
                    None
                };
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

fn cache_key(path: &str, write: bool) -> u64 {
    use xxhash_rust::xxh3::Xxh3;
    let mut h = Xxh3::new();
    h.update(path.as_bytes());
    h.update(&[if write { 1u8 } else { 0u8 }]);
    h.digest()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn cache_key(path: &str, write: bool) -> u64 {
        use xxhash_rust::xxh3::Xxh3;
        let mut h = Xxh3::new();
        h.update(path.as_bytes());
        h.update(&[if write { 1u8 } else { 0u8 }]);
        h.digest()
    }

    #[test]
    fn cache_key_write_flag_differs() {
        assert_ne!(cache_key("foo", false), cache_key("foo", true));
    }

    #[test]
    fn cache_key_case_sensitive() {
        assert_ne!(cache_key("FOO", false), cache_key("foo", false));
    }

    #[test]
    fn cache_key_deterministic() {
        assert_eq!(cache_key("a", false), cache_key("a", false));
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
}
