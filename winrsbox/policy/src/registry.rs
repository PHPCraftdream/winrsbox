use std::sync::Arc;
use std::path::PathBuf;
use quick_cache::sync::Cache;

use crate::{db, path, reg, reg_overlay, Mode, PolicyError};
use crate::decide::{cache_key, SnapshotRule};

// ── Registry Policy ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RegDecision {
    pub mode: Mode,
    pub overlay_value: Option<reg::RegValue>,
    pub mock_value: Option<reg::RegValue>,
}

pub struct RegistryPolicy {
    pub(crate) db: Arc<redb::Database>,
    pub(crate) cache: Cache<u128, Arc<RegDecision>>,
    pub(crate) reg_snapshot: arc_swap::ArcSwap<RegSnapshot>,
    pub(crate) overlay: std::sync::Mutex<reg_overlay::RegOverlay>,
}

pub(crate) struct RegSnapshot {
    pub(crate) rules: Vec<SnapshotRule>,
    pub(crate) default_rule: Option<db::RuleRow>,
    pub(crate) mocks: rustc_hash::FxHashMap<String, Vec<u8>>,
}

impl RegSnapshot {
    pub(crate) fn load_from_db(db: &redb::Database) -> Result<Self, PolicyError> {
        let txn = db.begin_read()?;
        let mut rules = Vec::new();
        let mut default_rule = None;
        if let Ok(table) = txn.open_table(db::REG_RULES) {
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
        let mut mocks = rustc_hash::FxHashMap::default();
        if let Ok(table) = txn.open_table(db::REG_MOCKS) {
            for entry in table.range::<&str>(..).into_iter().flatten() {
                let Ok((key, value)) = entry else { continue };
                mocks.insert(key.value().to_owned(), value.value().to_vec());
            }
        }
        Ok(RegSnapshot { rules, default_rule, mocks })
    }

    pub(crate) fn best_rule_match(&self, lower_path: &str, depth: Option<u8>, exe_lower: Option<&str>) -> Option<&db::RuleRow> {
        let mut best: Option<(usize, &db::RuleRow)> = None;
        for sr in &self.rules {
            if !path::pattern_matches_prefix(&sr.pattern, lower_path) { continue; }
            if let Some(ref when) = sr.row.when {
                if let Some(min_depth) = when.depth {
                    match depth {
                        Some(d) if d < min_depth => continue,
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
            let spec = path::pattern_specificity(&sr.pattern);
            match &best {
                None => best = Some((spec, &sr.row)),
                Some((s, _)) if spec > *s => best = Some((spec, &sr.row)),
                _ => {}
            }
        }
        best.map(|(_, r)| r).or(self.default_rule.as_ref())
    }
}

impl RegistryPolicy {
    pub fn open(
        db: Arc<redb::Database>,
        workreg_root: PathBuf,
    ) -> Result<Self, PolicyError> {
        let reg_snapshot = Arc::new(RegSnapshot::load_from_db(&db)?);
        let overlay = reg_overlay::RegOverlay::load_from_disk(workreg_root)
            .map_err(|e| PolicyError::Ktav(e))?;
        Ok(Self {
            db,
            cache: Cache::new(8192),
            reg_snapshot: arc_swap::ArcSwap::from(reg_snapshot),
            overlay: std::sync::Mutex::new(overlay),
        })
    }

    pub fn reload_snapshot(&self) -> Result<(), PolicyError> {
        let new = Arc::new(RegSnapshot::load_from_db(&self.db)?);
        self.reg_snapshot.store(new);
        self.cache.clear();
        Ok(())
    }

    pub fn decide(&self, key_path: &str, value_name: Option<&str>, write: bool) -> RegDecision {
        self.decide_with_context(key_path, value_name, write, None, None)
    }

    pub fn decide_with_context(
        &self,
        key_path: &str,
        value_name: Option<&str>,
        write: bool,
        depth: Option<u8>,
        exe_lower: Option<&str>,
    ) -> RegDecision {
        let lower = crate::ensure_lower(key_path);
        let vname = value_name.map(|v| crate::ensure_lower(v));
        let cache_path = match &vname {
            Some(v) => format!("{lower}\\{v}"),
            None => lower.to_string(),
        };
        let key = cache_key(&cache_path, write, depth, exe_lower);
        if let Some(d) = self.cache.get(&key) {
            return (*d).clone();
        }
        let d = self.compute_reg(&lower, value_name, write, depth, exe_lower);
        self.cache.insert(key, Arc::new(d.clone()));
        d
    }

    fn compute_reg(
        &self,
        lower_key: &str,
        value_name: Option<&str>,
        write: bool,
        depth: Option<u8>,
        exe_lower: Option<&str>,
    ) -> RegDecision {
        let snap = self.reg_snapshot.load();

        // Check mock
        if let Some(vname) = value_name {
            let mock_path = format!("{lower_key}\\{}", vname.to_lowercase());
            if let Some(payload) = snap.mocks.get(&mock_path) {
                if let Ok(val) = serde_json::from_slice::<reg::RegValue>(payload) {
                    return RegDecision { mode: Mode::Mock, overlay_value: None, mock_value: Some(val) };
                }
            }
        }

        // Check overlay (for reads — return overlay value if exists)
        if !write {
            if let Some(vname) = value_name {
                let vname_lower = vname.to_lowercase();
                let ov = self.overlay.lock().unwrap();
                if ov.is_key_deleted(lower_key) {
                    return RegDecision { mode: Mode::Deny, overlay_value: None, mock_value: None };
                }
                if let Some(entry) = ov.get(lower_key, &vname_lower) {
                    match entry {
                        reg::RegEntry::Value(v) => {
                            return RegDecision { mode: Mode::Cow, overlay_value: Some(v.clone()), mock_value: None };
                        }
                        reg::RegEntry::Deleted => {
                            return RegDecision { mode: Mode::Deny, overlay_value: None, mock_value: None };
                        }
                    }
                }
            }
        }

        // Rule match
        let rule = snap.best_rule_match(lower_key, depth, exe_lower);
        let (mode_read, mode_write) = rule
            .map(|r| (r.mode_read, r.mode_write))
            .unwrap_or((db::RuleMode::Passthrough, db::RuleMode::Cow));
        let effective = if write { mode_write } else { mode_read };

        match effective {
            db::RuleMode::Deny => RegDecision { mode: Mode::Deny, overlay_value: None, mock_value: None },
            db::RuleMode::Passthrough => RegDecision { mode: Mode::Passthrough, overlay_value: None, mock_value: None },
            db::RuleMode::Cow | db::RuleMode::Redirect => RegDecision { mode: Mode::Cow, overlay_value: None, mock_value: None },
        }
    }

    pub fn write_to_overlay(&self, key_path: &str, value_name: &str, value: reg::RegValue) -> Result<(), String> {
        let lower_key = key_path.to_lowercase();
        let lower_name = value_name.to_lowercase();
        self.overlay.lock().unwrap().set(&lower_key, &lower_name, value)?;
        self.cache.clear();
        Ok(())
    }

    pub fn delete_value_in_overlay(&self, key_path: &str, value_name: &str) -> Result<(), String> {
        let lower_key = key_path.to_lowercase();
        let lower_name = value_name.to_lowercase();
        self.overlay.lock().unwrap().delete_value(&lower_key, &lower_name)?;
        self.cache.clear();
        Ok(())
    }

    pub fn delete_key_in_overlay(&self, key_path: &str) -> Result<(), String> {
        self.overlay.lock().unwrap().delete_key(&key_path.to_lowercase())?;
        self.cache.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::{db, reg};

    fn make_reg_policy() -> (tempfile::TempDir, RegistryPolicy) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let workreg = dir.path().join("workreg");
        std::fs::create_dir_all(&workreg).unwrap();
        let rdb = redb::Database::create(&db_path).unwrap();
        { let txn = rdb.begin_write().unwrap(); txn.open_table(db::REG_RULES).unwrap(); txn.open_table(db::REG_MOCKS).unwrap(); txn.commit().unwrap(); }
        let db = Arc::new(rdb);
        let rp = RegistryPolicy::open(db, workreg).unwrap();
        (dir, rp)
    }

    fn make_reg_policy_with_deny() -> (tempfile::TempDir, RegistryPolicy) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let workreg = dir.path().join("workreg");
        std::fs::create_dir_all(&workreg).unwrap();
        let rdb = redb::Database::create(&db_path).unwrap();
        { let txn = rdb.begin_write().unwrap(); txn.open_table(db::REG_RULES).unwrap(); txn.open_table(db::REG_MOCKS).unwrap(); txn.commit().unwrap(); }
        let db = Arc::new(rdb);
        db::reg_rule_upsert(&db, &db::RuleRow {
            id: "deny-secrets".into(),
            prefix: r"hklm\software\secrets".into(),
            mode_read: db::RuleMode::Deny,
            mode_write: db::RuleMode::Deny,
            when: None,
        }).unwrap();
        let rp = RegistryPolicy::open(db, workreg).unwrap();
        (dir, rp)
    }

    #[test]
    fn reg_decide_passthrough_default() {
        let (_dir, rp) = make_reg_policy();
        let d = rp.decide(r"hklm\software\foo", Some("bar"), false);
        assert_eq!(d.mode, Mode::Passthrough);
    }

    #[test]
    fn reg_decide_deny_rule() {
        let (_dir, rp) = make_reg_policy_with_deny();
        let d = rp.decide(r"hklm\software\secrets\key1", Some("val"), false);
        assert_eq!(d.mode, Mode::Deny);
    }

    #[test]
    fn reg_decide_write_default_cow() {
        let (_dir, rp) = make_reg_policy();
        let d = rp.decide(r"hklm\software\foo", Some("bar"), true);
        assert_eq!(d.mode, Mode::Cow);
    }

    #[test]
    fn reg_write_overlay_then_read() {
        let (_dir, rp) = make_reg_policy();
        rp.write_to_overlay(
            r"hklm\software\test", "myval",
            reg::RegValue { typ: reg::RegType::Dword, data: reg::RegData::U32(42) },
        ).unwrap();
        let d = rp.decide(r"hklm\software\test", Some("myval"), false);
        assert_eq!(d.mode, Mode::Cow);
        let val = d.overlay_value.unwrap();
        assert_eq!(val.data, reg::RegData::U32(42));
    }

    #[test]
    fn reg_delete_value_returns_deny() {
        let (_dir, rp) = make_reg_policy();
        rp.write_to_overlay(
            r"hklm\test", "val",
            reg::RegValue { typ: reg::RegType::Sz, data: reg::RegData::String("x".into()) },
        ).unwrap();
        rp.delete_value_in_overlay(r"hklm\test", "val").unwrap();
        let d = rp.decide(r"hklm\test", Some("val"), false);
        assert_eq!(d.mode, Mode::Deny);
    }

    #[test]
    fn reg_delete_key_returns_deny() {
        let (_dir, rp) = make_reg_policy();
        rp.delete_key_in_overlay(r"hklm\test\sub").unwrap();
        let d = rp.decide(r"hklm\test\sub", Some("anything"), false);
        assert_eq!(d.mode, Mode::Deny);
    }

    #[test]
    fn reg_cache_hit() {
        let (_dir, rp) = make_reg_policy();
        rp.decide(r"hklm\software\foo", Some("bar"), false);
        let d2 = rp.decide(r"hklm\software\foo", Some("bar"), false);
        assert_eq!(d2.mode, Mode::Passthrough);
    }

    #[test]
    fn reg_mock_returns_value() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let workreg = dir.path().join("workreg");
        std::fs::create_dir_all(&workreg).unwrap();
        let rdb = redb::Database::create(&db_path).unwrap();
        { let txn = rdb.begin_write().unwrap(); txn.open_table(db::REG_RULES).unwrap(); txn.open_table(db::REG_MOCKS).unwrap(); txn.commit().unwrap(); }
        let db = Arc::new(rdb);
        let mock_val = reg::RegValue { typ: reg::RegType::Sz, data: reg::RegData::String("FAKE_GUID".into()) };
        let payload = serde_json::to_vec(&mock_val).unwrap();
        db::reg_mock_upsert(&db, r"hklm\software\crypto\machineguid", &payload).unwrap();
        let rp = RegistryPolicy::open(db, workreg).unwrap();
        let d = rp.decide(r"hklm\software\crypto", Some("machineguid"), false);
        assert_eq!(d.mode, Mode::Mock);
        assert_eq!(d.mock_value.unwrap().data, reg::RegData::String("FAKE_GUID".into()));
    }

    #[test]
    fn reg_write_clears_cache() {
        let (_dir, rp) = make_reg_policy();
        let d1 = rp.decide(r"hklm\test", Some("val"), false);
        assert_eq!(d1.mode, Mode::Passthrough);
        rp.write_to_overlay(
            r"hklm\test", "val",
            reg::RegValue { typ: reg::RegType::Dword, data: reg::RegData::U32(1) },
        ).unwrap();
        let d2 = rp.decide(r"hklm\test", Some("val"), false);
        assert_eq!(d2.mode, Mode::Cow);
    }
}
