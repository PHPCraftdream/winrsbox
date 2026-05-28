//! Policy type definitions, constructors, and simple accessors.
//!
//! The `Policy` struct and `PolicyInner` live here, along with `open_or_create`,
//! `load_config`, and trivial accessors (`sandbox_root`, `mock_dirs_root`,
//! `project_root`, `db`). The decide-flow methods (`decide`, `decide_with_context`,
//! `record_overlay`, `decide_traced`, `compute`) live in `decide.rs`.
//!
//! `lib.rs` is a thin façade: module declarations + public re-exports +
//! crate-level types (`Mode`, `Decision`, `PolicyError`).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use quick_cache::sync::Cache;

use crate::{db, decide, Decision, PolicyError};

pub struct Policy {
    pub(crate) inner: Arc<PolicyInner>,
}

pub(crate) struct PolicyInner {
    pub(crate) db: redb::Database,
    pub(crate) cache: Cache<u128, Arc<Decision>>,
    pub(crate) snapshot: arc_swap::ArcSwap<decide::Snapshot>,
    pub(crate) sandbox_root: PathBuf,
    pub(crate) mock_dirs_root: PathBuf,
    pub(crate) project_root_lower: String,
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
            txn.open_table(db::REG_RULES)?;
            txn.open_table(db::REG_MOCKS)?;
            txn.open_table(db::DEV_RULES)?;
            txn.open_table(db::NET_RULES)?;
            txn.commit()?;
        }
        let project_root_lower = project_root.to_string_lossy().to_lowercase();
        let snapshot = Arc::new(decide::Snapshot::load_from_db(&db)?);
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
        let new_snap = Arc::new(decide::Snapshot::load_from_db(&self.inner.db)?);
        self.inner.snapshot.store(new_snap);
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

    pub fn db(&self) -> &redb::Database {
        &self.inner.db
    }
}
