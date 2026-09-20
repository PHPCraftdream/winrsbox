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
    pub(crate) db: Arc<redb::Database>,
    pub(crate) cache: Cache<u128, Arc<Decision>>,
    pub(crate) snapshot: arc_swap::ArcSwap<decide::Snapshot>,
    /// Same-volume overlay layout: maps a virtual drive to an overlay root on
    /// that same volume, so kernel-reported drive letters (from the handle's
    /// physical volume) are correct. Falls back to a single primary root.
    pub(crate) overlay_layout: crate::path::OverlayLayout,
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
        Self::open_or_create_with_layout(
            db_path,
            crate::path::OverlayLayout::single(sandbox_root),
            mock_dirs_root,
            project_root,
        )
    }

    /// Open the policy with an explicit same-volume overlay layout (per-drive
    /// roots). Used by the launcher to place the overlay for each virtual
    /// drive on that same drive (fixes the drive-letter identity leak).
    pub fn open_or_create_with_layout(
        db_path: &Path,
        overlay_layout: crate::path::OverlayLayout,
        mock_dirs_root: PathBuf,
        project_root: PathBuf,
    ) -> Result<Self, PolicyError> {
        let db: Arc<redb::Database> = Arc::new(redb::Database::create(db_path)?);
        // Ensure tables exist
        {
            let txn = db.begin_write()?;
            txn.open_table(db::RULES)?;
            txn.open_table(db::MOCKS)?;
            txn.open_table(db::MOCK_DIRS)?;
            txn.open_table(db::OVERLAY_IDX)?;
            txn.open_table(db::WHITEOUTS)?;
            txn.open_table(db::REG_RULES)?;
            txn.open_table(db::REG_MOCKS)?;
            txn.open_table(db::DEV_RULES)?;
            txn.open_table(db::NET_RULES)?;
            txn.commit()?;
        }
        let project_root_lower = crate::ensure_lower(&project_root.to_string_lossy()).into_owned();
        let snapshot = Arc::new(decide::Snapshot::load_from_db(&db)?);
        Ok(Self {
            inner: Arc::new(PolicyInner {
                db,
                cache: Cache::new(16384),
                snapshot: arc_swap::ArcSwap::from(snapshot),
                overlay_layout,
                mock_dirs_root,
                project_root_lower,
            }),
        })
    }

    /// Share the underlying policy DB with another policy subsystem (e.g.
    /// `RegistryPolicy`) so both FS and registry decisions read/write the
    /// same on-disk store without a second file handle.
    pub fn db(&self) -> Arc<redb::Database> {
        Arc::clone(&self.inner.db)
    }

    /// The overlay layout (per-drive same-volume roots).
    pub fn overlay_layout(&self) -> &crate::path::OverlayLayout {
        &self.inner.overlay_layout
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

    /// The primary overlay root (project drive). Kept for backward compat
    /// with callers that publish FS_SANDBOX_ROOT; prefer `overlay_layout()`
    /// for per-drive resolution.
    pub fn sandbox_root(&self) -> &Path {
        self.inner.overlay_layout.primary()
    }

    pub fn mock_dirs_root(&self) -> &Path {
        &self.inner.mock_dirs_root
    }

    pub fn project_root(&self) -> &str {
        &self.inner.project_root_lower
    }

    // Thin db-mutation forwarders used by `winrsbox why --what-if` to apply a
    // hypothetical rule against this Policy's own db, then analyse. These exist
    // so callers don't need a raw `&redb::Database` handle out of the Policy —
    // the storage backend stays an internal detail of the policy crate.
    // (The standalone CLI commands that operate on the on-disk db file by path
    // still use the `policy::db::*` free functions directly; that is the public
    // config-management API and is intentionally exposed.)

    /// Reload the decide snapshot and drop cached decisions after a rule
    /// mutation. `compute` reads rules/mocks from `inner.snapshot` and
    /// `decide_with_context` adds a decision cache on top, so a mutation
    /// that skips this leaves both stale until some unrelated invalidation
    /// happens to fire (audit 2026-09-19 Low: rule_upsert does not refresh
    /// the snapshot/cache). Mirrors `load_config`.
    fn refresh_after_mutation(&self) -> Result<(), PolicyError> {
        let new_snap = Arc::new(decide::Snapshot::load_from_db(&self.inner.db)?);
        self.inner.snapshot.store(new_snap);
        self.inner.cache.clear();
        Ok(())
    }

    /// Upsert a filesystem rule into this policy's backing store.
    pub fn rule_upsert(&self, row: &db::RuleRow) -> Result<(), PolicyError> {
        db::rule_upsert(&self.inner.db, row)?;
        self.refresh_after_mutation()
    }

    /// Remove every filesystem rule whose prefix matches `prefix` (lowercased).
    pub fn rule_remove_by_prefix(&self, prefix: &str) -> Result<bool, PolicyError> {
        let removed = db::rule_remove_by_prefix(&self.inner.db, prefix)?;
        self.refresh_after_mutation()?;
        Ok(removed)
    }

    /// Set the default read/write modes for unmatched paths.
    pub fn defaults_set(
        &self,
        read: Option<db::RuleMode>,
        write: Option<db::RuleMode>,
    ) -> Result<(), PolicyError> {
        db::defaults_set(&self.inner.db, read, write)?;
        self.refresh_after_mutation()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same construction as decide.rs tests: fresh redb db, all roots inside
    /// one TempDir that stays alive until drop.
    fn make_policy() -> (tempfile::TempDir, Policy) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
        (dir, p)
    }

    #[test]
    fn rule_upsert_takes_effect_without_load_config() {
        let (_dir, p) = make_policy();
        let path = r"c:\elsewhere\target.txt";
        // Precondition: no rule yet, so the merged-view default isolates the write.
        assert!(matches!(
            p.decide(path, true).mode,
            crate::Mode::Cow
        ));

        let row = db::RuleRow {
            id: "t-deny".into(),
            prefix: r"c:\elsewhere".into(),
            mode_read: db::RuleMode::Passthrough,
            mode_write: db::RuleMode::Deny,
            when: None,
        };
        p.rule_upsert(&row).unwrap();

        let d = p.decide(path, true);
        assert!(
            matches!(d.mode, crate::Mode::Deny),
            "a freshly upserted rule must drive the very next decide \n             without an unrelated snapshot refresh (got {:?})",
            d.mode
        );
    }

    #[test]
    fn rule_remove_takes_effect_without_load_config() {
        let (_dir, p) = make_policy();
        let path = r"c:\elsewhere\target.txt";
        let row = db::RuleRow {
            id: "t-deny".into(),
            prefix: r"c:\elsewhere".into(),
            mode_read: db::RuleMode::Passthrough,
            mode_write: db::RuleMode::Deny,
            when: None,
        };
        p.rule_upsert(&row).unwrap();
        assert!(matches!(p.decide(path, true).mode, crate::Mode::Deny));

        let removed = p.rule_remove_by_prefix(r"c:\elsewhere").unwrap();
        assert!(removed, "rule must be found and removed");

        assert!(
            matches!(p.decide(path, true).mode, crate::Mode::Cow),
            "after removal the merged-view default (Cow) must drive the \n             next decide, not the stale snapshot"
        );
    }

    #[test]
    fn defaults_set_takes_effect_without_load_config() {
        let (_dir, p) = make_policy();
        let path = r"c:\elsewhere\target.txt";
        p.defaults_set(Some(db::RuleMode::Passthrough), Some(db::RuleMode::Deny))
            .unwrap();
        assert!(
            matches!(p.decide(path, true).mode, crate::Mode::Deny),
            "a freshly set default must drive the next decide without an \n             unrelated snapshot refresh"
        );
    }
}
