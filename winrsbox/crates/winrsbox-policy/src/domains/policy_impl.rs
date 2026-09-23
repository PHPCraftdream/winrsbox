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
    /// Pre-parsed net rules for one persisted generation (db::NET_RULES_GEN).
    /// Net rules are only written out-of-process (CLI `winrsbox netrule ...`),
    /// so the persisted generation counter is the ONLY cross-process
    /// invalidation signal — `net_rule_decide` re-reads the table only when
    /// it changed and publishes the fresh snapshot atomically via ArcSwap
    /// (readers always decide against exactly one consistent snapshot).
    pub(crate) net_snapshot: arc_swap::ArcSwap<crate::net::NetSnapshot>,
    /// Full net-rule table re-reads since open (test seam: stays constant
    /// while rules are unchanged, +1 per observed change).
    pub(crate) net_snapshot_rebuilds: std::sync::atomic::AtomicUsize,
    /// Same-volume overlay layout: maps a virtual drive to an overlay root on
    /// that same volume, so kernel-reported drive letters (from the handle's
    /// physical volume) are correct. Falls back to a single primary root.
    pub(crate) overlay_layout: crate::path::OverlayLayout,
    pub(crate) mock_dirs_root: PathBuf,
    pub(crate) project_root_lower: String,
    /// In-memory (parent → direct-children) index over the `OVERLAY_IDX`
    /// table: lowercase-trimmed parent virtual DOS path → child basenames
    /// sorted bytewise. Purely derived state — rebuilt from whatever
    /// `OVERLAY_IDX` rows exist at every `Policy` open (so legacy DBs need
    /// no migration) and maintained incrementally by `record_overlay` /
    /// `clear_overlay`, the table's only two writers. Lock recovery matches
    /// the crate's fail-safe style: a poisoned lock is recovered via
    /// `into_inner()` rather than propagated.
    pub(crate) overlay_children_idx:
        std::sync::RwLock<rustc_hash::FxHashMap<Box<str>, Vec<Box<str>>>>,
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
        // Rebuild the in-memory overlay parent→children index from
        // `OVERLAY_IDX` (one read txn). Derived state only: whatever rows
        // exist — legacy DB included — are folded in here, so no migration
        // machinery is needed and the index can never disagree with the DB
        // at open time.
        let overlay_children_idx = {
            let txn = db.begin_read()?;
            let mut map: rustc_hash::FxHashMap<Box<str>, Vec<Box<str>>> =
                rustc_hash::FxHashMap::default();
            if let Ok(t) = txn.open_table(db::OVERLAY_IDX) {
                for entry in t.range::<&str>(..).into_iter().flatten() {
                    let Ok((k, _)) = entry else { continue };
                    let key = k.value();
                    let (parent, name) = match key.rsplit_once('\\') {
                        Some((p, n)) => (p, n),
                        // A key without `\` (bare drive like `d:`) maps to
                        // parent "" — never returned by lookups, since the
                        // queried dir is always non-empty after trailing-
                        // separator trim. Consistent and harmless.
                        None => ("", key),
                    };
                    map.entry(parent.into()).or_default().push(name.into());
                }
            }
            for children in map.values_mut() {
                children.sort_unstable();
                children.dedup();
            }
            map
        };
        // Compile the net-rule snapshot once at open; per-request refreshes
        // are generation-gated in `net_rule_decide` (a DB that never had a
        // netrule write has no NET_RULES_GEN table → generation 0).
        let net_gen = db::net_rule_generation(&db)?;
        let net_snapshot = Arc::new(crate::net::NetSnapshot::load_from_db(&db, net_gen)?);
        Ok(Self {
            inner: Arc::new(PolicyInner {
                db,
                cache: Cache::new(16384),
                snapshot: arc_swap::ArcSwap::from(snapshot),
                net_snapshot: arc_swap::ArcSwap::from(net_snapshot),
                net_snapshot_rebuilds: std::sync::atomic::AtomicUsize::new(0),
                overlay_layout,
                mock_dirs_root,
                project_root_lower,
                overlay_children_idx: std::sync::RwLock::new(overlay_children_idx),
            }),
        })
    }

    /// Share the underlying policy DB with another policy subsystem (e.g.
    /// `RegistryPolicy`) so both FS and registry decisions read/write the
    /// same on-disk store without a second file handle.
    pub fn db(&self) -> Arc<redb::Database> {
        Arc::clone(&self.inner.db)
    }

    /// NetDecide via the versioned net-rule snapshot. The persisted
    /// generation is checked per call (one O(1) single-key read — the ONLY
    /// cross-process invalidation signal, since `winrsbox netrule ...` runs
    /// in a separate process); the full rule table is re-read and re-parsed
    /// only when the generation changed, and the new snapshot is published
    /// atomically via ArcSwap (readers always decide against exactly one
    /// consistent snapshot — no partially-applied rule set is ever visible).
    /// Errors fail closed at the caller.
    pub fn net_rule_decide(&self, host: &str, port: u16) -> Result<(bool, Option<String>), crate::PolicyError> {
        let gen = db::net_rule_generation(&self.inner.db)?;
        let snap = self.inner.net_snapshot.load();
        if snap.gen != gen {
            let fresh = std::sync::Arc::new(crate::net::NetSnapshot::load_from_db(&self.inner.db, gen)?);
            self.inner.net_snapshot_rebuilds.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.net_snapshot.store(fresh);
            return Ok(self.inner.net_snapshot.load().decide(host, port));
        }
        Ok(snap.decide(host, port))
    }

    /// Number of full net-rule table re-reads since open (test seam: stays
    /// constant while rules are unchanged, +1 per observed change).
    pub fn net_snapshot_rebuild_count(&self) -> usize {
        self.inner.net_snapshot_rebuilds.load(std::sync::atomic::Ordering::Relaxed)
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

    #[test]
    fn net_rule_decide_observes_out_of_process_write() {
        let (_dir, p) = make_policy();
        // Snapshot starts empty: everything allows.
        assert_eq!(p.net_rule_decide("example.com", 443).unwrap(), (true, None));

        // Out-of-process write: the CLI mutates the SAME db via the free
        // functions, bypassing this Policy object entirely.
        db::net_rule_upsert(&p.db(), &crate::net::NetRule {
            id: "d1".into(),
            host_pattern: "8.8.8.8".into(),
            port: Some(443),
            mode: crate::net::NetMode::Deny,
        })
        .unwrap();

        // The very next decide must observe the new persisted generation —
        // no stale window.
        assert_eq!(
            p.net_rule_decide("8.8.8.8", 443).unwrap(),
            (false, Some("d1".into()))
        );
        assert_eq!(p.net_snapshot_rebuild_count(), 1);

        // Unchanged rules ⇒ generation check hits, no re-read happens.
        assert_eq!(
            p.net_rule_decide("8.8.8.8", 443).unwrap(),
            (false, Some("d1".into()))
        );
        assert_eq!(p.net_rule_decide("other.com", 443).unwrap(), (true, None));
        assert_eq!(p.net_snapshot_rebuild_count(), 1);

        db::net_rule_remove(&p.db(), "d1").unwrap();
        assert_eq!(p.net_rule_decide("8.8.8.8", 443).unwrap(), (true, None));
        assert_eq!(p.net_snapshot_rebuild_count(), 2);
        assert_eq!(p.net_rule_decide("8.8.8.8", 443).unwrap(), (true, None));
        assert_eq!(p.net_snapshot_rebuild_count(), 2);
    }

    #[test]
    fn net_rule_generation_bumps_on_upsert_remove_clear() {
        let (_dir, p) = make_policy();
        let dbp = p.db();
        assert_eq!(db::net_rule_generation(&dbp).unwrap(), 0, "fresh db has no gen yet");
        let rule = crate::net::NetRule {
            id: "r1".into(),
            host_pattern: "*.example.com".into(),
            port: None,
            mode: crate::net::NetMode::Allow,
        };
        db::net_rule_upsert(&dbp, &rule).unwrap();
        assert_eq!(db::net_rule_generation(&dbp).unwrap(), 1);
        // Idempotent id: still a write, still bumps.
        db::net_rule_upsert(&dbp, &rule).unwrap();
        assert_eq!(db::net_rule_generation(&dbp).unwrap(), 2);
        assert!(db::net_rule_remove(&dbp, "r1").unwrap());
        assert_eq!(db::net_rule_generation(&dbp).unwrap(), 3);
        // Absent id: no-op bump is harmless but still advances the counter.
        assert!(!db::net_rule_remove(&dbp, "absent").unwrap());
        assert_eq!(db::net_rule_generation(&dbp).unwrap(), 4);
        db::net_rule_clear(&dbp).unwrap();
        assert_eq!(db::net_rule_generation(&dbp).unwrap(), 5);
    }

    #[test]
    fn net_rule_generation_absent_table_reads_zero() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        // A database that never had a single write: NET_RULES_GEN was never
        // created, and the read path must NOT auto-create it (redb only
        // auto-creates tables in write txns).
        let db = redb::Database::create(&db_path).unwrap();
        assert_eq!(db::net_rule_generation(&db).unwrap(), 0);
    }
}
