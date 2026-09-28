//! MP-9: generic policy mutation/read operations
//! (`docs/multiprocess-broker-plan.md`, "CLI при идущей сессии").
//!
//! A CLI process (`winrsbox rule add ...`) normally opens `policy.redb`
//! directly and calls the `policy::db::*` free functions in this module.
//! While a session is running, the broker holds the only handle to that
//! file and the CLI's own `redb::Database::create` fails with
//! `DatabaseAlreadyOpen`. [`PolicyOp`] packages one such call (plus its
//! arguments) so it can cross the IPC boundary to the broker
//! (`ipc::Req::PolicyMutate`), which executes it via [`exec`] against its
//! own already-open db and returns a [`PolicyOpResult`]. [`exec`] is the
//! single source of truth for both paths: a CLI process with no broker
//! calls it directly against its own transient db handle, so the two paths
//! can never observably diverge.
use super::{DefaultsRow, RuleMode, RuleRow, DEFAULTS};
use crate::PolicyError;
use serde::{Deserialize, Serialize};

/// A single policy mutation/read, fully self-contained so it can be
/// serialized across the broker IPC boundary and executed identically
/// whether the caller holds `db` directly or is a CLI process relaying
/// through the broker's already-open one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyOp {
    RuleUpsert(RuleRow),
    RuleRemoveById(String),
    RuleRemoveByPrefix(String),
    RuleList,
    RuleClear,
    MockUpsert { path: String, payload: Vec<u8> },
    MockRemoveByPath(String),
    MockList,
    MockDirUpsert(String),
    MockDirRemoveByPrefix(String),
    MockDirList,
    DefaultsGet,
    DefaultsSet { read: Option<RuleMode>, write: Option<RuleMode> },
    RegRuleUpsert(RuleRow),
    RegRuleRemoveById(String),
    RegRuleRemoveByPrefix(String),
    RegRuleList,
    RegRuleClear,
    RegDefaultsGet,
    RegMockUpsert { path: String, payload: Vec<u8> },
    RegMockRemove(String),
    RegMockList,
    DevRuleUpsert(RuleRow),
    DevRuleRemoveById(String),
    DevRuleRemoveByPrefix(String),
    DevRuleList,
    DevRuleClear,
    NetRuleUpsert(crate::net::NetRule),
    NetRuleRemove(String),
    NetRuleList,
    NetRuleClear,
    MemPolicyGet,
    MemPolicySet(crate::mem::MemPolicy),
}

impl PolicyOp {
    /// True for ops that change what `Policy`'s decide snapshot reads
    /// (rules, mocks, mock dirs, defaults all live in `decide::Snapshot`) —
    /// a caller holding a live `Policy` over the same db must call
    /// `Policy::invalidate_snapshot` afterward so an already-running
    /// session observes the change without restarting.
    pub fn touches_fs_snapshot(&self) -> bool {
        matches!(
            self,
            Self::RuleUpsert(_)
                | Self::RuleRemoveById(_)
                | Self::RuleRemoveByPrefix(_)
                | Self::RuleClear
                | Self::MockUpsert { .. }
                | Self::MockRemoveByPath(_)
                | Self::MockDirUpsert(_)
                | Self::MockDirRemoveByPrefix(_)
                | Self::DefaultsSet { .. }
        )
    }

    /// True for ops that change `RegistryPolicy`'s snapshot — a caller
    /// holding a live `RegistryPolicy` over the same db must call
    /// `RegistryPolicy::reload_snapshot` afterward.
    pub fn touches_reg_snapshot(&self) -> bool {
        matches!(
            self,
            Self::RegRuleUpsert(_)
                | Self::RegRuleRemoveById(_)
                | Self::RegRuleRemoveByPrefix(_)
                | Self::RegRuleClear
                | Self::RegMockUpsert { .. }
                | Self::RegMockRemove(_)
        )
    }
}

/// Result of executing a [`PolicyOp`], mirroring the return shape of the
/// underlying `policy::db::*` free function it wraps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyOpResult {
    Unit,
    Bool(bool),
    Rules(Vec<RuleRow>),
    Mocks(Vec<(String, Vec<u8>)>),
    Strings(Vec<String>),
    Defaults(DefaultsRow),
    NetRules(Vec<crate::net::NetRule>),
    MemPolicy(crate::mem::MemPolicy),
}

/// Execute `op` against `db`. Domain-agnostic and cache-agnostic: it never
/// touches an in-memory snapshot/cache. A bare CLI process (own, transient
/// `redb::Database` handle, no live `Policy`) needs no refresh at all. A
/// caller that also holds a `Policy`/`RegistryPolicy` over this same `db`
/// (the broker) must check `touches_fs_snapshot`/`touches_reg_snapshot` and
/// refresh accordingly — seeing every reachable command listed here (used
/// by `pipe_server::mutate`, MP-9) confirms none was missed.
pub fn exec(db: &redb::Database, op: &PolicyOp) -> Result<PolicyOpResult, PolicyError> {
    use PolicyOp::*;
    Ok(match op {
        RuleUpsert(row) => {
            super::rule_upsert(db, row)?;
            PolicyOpResult::Unit
        }
        RuleRemoveById(id) => PolicyOpResult::Bool(super::rule_remove_by_id(db, id)?),
        RuleRemoveByPrefix(p) => PolicyOpResult::Bool(super::rule_remove_by_prefix(db, p)?),
        RuleList => PolicyOpResult::Rules(super::rule_list(db)?),
        RuleClear => {
            super::rule_clear(db)?;
            PolicyOpResult::Unit
        }
        MockUpsert { path, payload } => {
            // Mocks are keyed by (lowercased) path — the id argument is
            // unused by `mock_upsert` itself (see its own doc); passing ""
            // matches every existing direct caller.
            super::mock_upsert(db, "", path, payload)?;
            PolicyOpResult::Unit
        }
        MockRemoveByPath(p) => PolicyOpResult::Bool(super::mock_remove_by_path(db, p)?),
        MockList => PolicyOpResult::Mocks(super::mock_list(db)?),
        MockDirUpsert(p) => {
            super::mockdir_upsert(db, p)?;
            PolicyOpResult::Unit
        }
        MockDirRemoveByPrefix(p) => PolicyOpResult::Bool(super::mockdir_remove_by_prefix(db, p)?),
        MockDirList => PolicyOpResult::Strings(super::mockdir_list(db)?),
        DefaultsGet => PolicyOpResult::Defaults(super::defaults_get(db)?),
        DefaultsSet { read, write } => {
            super::defaults_set(db, *read, *write)?;
            PolicyOpResult::Unit
        }
        RegRuleUpsert(row) => {
            super::reg_rule_upsert(db, row)?;
            PolicyOpResult::Unit
        }
        RegRuleRemoveById(id) => PolicyOpResult::Bool(super::reg_rule_remove_by_id(db, id)?),
        RegRuleRemoveByPrefix(p) => PolicyOpResult::Bool(super::reg_rule_remove_by_prefix(db, p)?),
        RegRuleList => PolicyOpResult::Rules(super::reg_rule_list(db)?),
        RegRuleClear => {
            super::reg_rule_clear(db)?;
            PolicyOpResult::Unit
        }
        RegDefaultsGet => PolicyOpResult::Defaults(super::reg_defaults_get(db)?),
        RegMockUpsert { path, payload } => {
            super::reg_mock_upsert(db, path, payload)?;
            PolicyOpResult::Unit
        }
        RegMockRemove(p) => PolicyOpResult::Bool(super::reg_mock_remove(db, p)?),
        RegMockList => PolicyOpResult::Mocks(super::reg_mock_list(db)?),
        DevRuleUpsert(row) => {
            super::dev_rule_upsert(db, row)?;
            PolicyOpResult::Unit
        }
        DevRuleRemoveById(id) => PolicyOpResult::Bool(super::dev_rule_remove_by_id(db, id)?),
        DevRuleRemoveByPrefix(p) => PolicyOpResult::Bool(super::dev_rule_remove_by_prefix(db, p)?),
        DevRuleList => PolicyOpResult::Rules(super::dev_rule_list(db)?),
        DevRuleClear => {
            super::dev_rule_clear(db)?;
            PolicyOpResult::Unit
        }
        NetRuleUpsert(rule) => {
            super::net_rule_upsert(db, rule)?;
            PolicyOpResult::Unit
        }
        NetRuleRemove(id) => PolicyOpResult::Bool(super::net_rule_remove(db, id)?),
        NetRuleList => PolicyOpResult::NetRules(super::net_rule_list(db)?),
        NetRuleClear => {
            super::net_rule_clear(db)?;
            PolicyOpResult::Unit
        }
        MemPolicyGet => PolicyOpResult::MemPolicy(mem_policy_get(db)?),
        MemPolicySet(pol) => {
            mem_policy_set(db, pol)?;
            PolicyOpResult::Unit
        }
    })
}

/// Mirrors the CLI's previous inline `mem_policy` DEFAULTS-table access
/// (`cli/netdev/memdefaults.rs`) so the direct and broker paths store/read
/// it identically. No cache exists for this value today (each decide reads
/// it fresh), so no snapshot/refresh call is needed after a write.
fn mem_policy_get(db: &redb::Database) -> Result<crate::mem::MemPolicy, PolicyError> {
    let txn = db.begin_read()?;
    let pol = if let Ok(t) = txn.open_table(DEFAULTS) {
        t.get("mem_policy")
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_slice::<crate::mem::MemPolicy>(v.value()).ok())
    } else {
        None
    };
    Ok(pol.unwrap_or_default())
}

fn mem_policy_set(db: &redb::Database, pol: &crate::mem::MemPolicy) -> Result<(), PolicyError> {
    let json = serde_json::to_vec(pol)
        .map_err(|e| PolicyError::Ktav(format!("serialize mem_policy: {e}")))?;
    let txn = db.begin_write()?;
    {
        let mut t = txn.open_table(DEFAULTS)?;
        t.insert("mem_policy", json.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::WhenFilter;

    /// Mirrors `cli::open_db`'s table pre-creation: `defaults_get`/`_set`
    /// (and the other read paths) `open_table` inside a READ txn, which
    /// fails with `TableDoesNotExist` unless some WRITE txn created the
    /// table first — real callers always go through `open_db` or
    /// `Policy::open_or_create_with_layout` for this, so tests must too.
    fn tmp_db() -> (tempfile::TempDir, redb::Database) {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("policy.redb")).unwrap();
        {
            let txn = db.begin_write().unwrap();
            txn.open_table(crate::db::RULES).unwrap();
            txn.open_table(crate::db::MOCKS).unwrap();
            txn.open_table(crate::db::MOCK_DIRS).unwrap();
            txn.open_table(crate::db::REG_RULES).unwrap();
            txn.open_table(crate::db::REG_MOCKS).unwrap();
            txn.open_table(crate::db::DEV_RULES).unwrap();
            txn.open_table(crate::db::NET_RULES).unwrap();
            txn.commit().unwrap();
        }
        (dir, db)
    }

    #[test]
    fn rule_upsert_then_list_roundtrips_through_exec() {
        let (_dir, db) = tmp_db();
        let row = RuleRow {
            id: "r1".into(),
            prefix: "c:\\test".into(),
            mode_read: RuleMode::Passthrough,
            mode_write: RuleMode::Deny,
            when: Some(WhenFilter { depth: Some(1), exe: None }),
        };
        assert!(matches!(exec(&db, &PolicyOp::RuleUpsert(row)), Ok(PolicyOpResult::Unit)));
        let PolicyOpResult::Rules(rules) = exec(&db, &PolicyOp::RuleList).unwrap() else {
            panic!("expected Rules");
        };
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "r1");
    }

    #[test]
    fn rule_remove_by_id_reports_not_found() {
        let (_dir, db) = tmp_db();
        let PolicyOpResult::Bool(found) =
            exec(&db, &PolicyOp::RuleRemoveById("nope".into())).unwrap()
        else {
            panic!("expected Bool");
        };
        assert!(!found);
    }

    #[test]
    fn mock_upsert_list_remove_roundtrip() {
        let (_dir, db) = tmp_db();
        exec(&db, &PolicyOp::MockUpsert { path: "c:\\m".into(), payload: b"hi".to_vec() }).unwrap();
        let PolicyOpResult::Mocks(mocks) = exec(&db, &PolicyOp::MockList).unwrap() else {
            panic!("expected Mocks");
        };
        assert_eq!(mocks, vec![("c:\\m".to_string(), b"hi".to_vec())]);
        let PolicyOpResult::Bool(removed) =
            exec(&db, &PolicyOp::MockRemoveByPath("c:\\m".into())).unwrap()
        else {
            panic!("expected Bool");
        };
        assert!(removed);
    }

    #[test]
    fn mockdir_upsert_list_remove_roundtrip() {
        let (_dir, db) = tmp_db();
        exec(&db, &PolicyOp::MockDirUpsert("c:\\d".into())).unwrap();
        let PolicyOpResult::Strings(dirs) = exec(&db, &PolicyOp::MockDirList).unwrap() else {
            panic!("expected Strings");
        };
        assert_eq!(dirs, vec!["c:\\d".to_string()]);
    }

    #[test]
    fn defaults_get_set_roundtrip() {
        let (_dir, db) = tmp_db();
        exec(
            &db,
            &PolicyOp::DefaultsSet { read: Some(RuleMode::Deny), write: None },
        )
        .unwrap();
        let PolicyOpResult::Defaults(d) = exec(&db, &PolicyOp::DefaultsGet).unwrap() else {
            panic!("expected Defaults");
        };
        assert!(matches!(d.read, RuleMode::Deny));
    }

    #[test]
    fn reg_rule_upsert_list_clear_roundtrip() {
        let (_dir, db) = tmp_db();
        let row = RuleRow {
            id: "rr1".into(),
            prefix: "hklm\\x".into(),
            mode_read: RuleMode::Passthrough,
            mode_write: RuleMode::Deny,
            when: None,
        };
        exec(&db, &PolicyOp::RegRuleUpsert(row)).unwrap();
        let PolicyOpResult::Rules(rules) = exec(&db, &PolicyOp::RegRuleList).unwrap() else {
            panic!("expected Rules");
        };
        assert_eq!(rules.len(), 1);
        exec(&db, &PolicyOp::RegRuleClear).unwrap();
        let PolicyOpResult::Rules(rules) = exec(&db, &PolicyOp::RegRuleList).unwrap() else {
            panic!("expected Rules");
        };
        assert!(rules.is_empty());
    }

    #[test]
    fn net_rule_upsert_list_clear_roundtrip() {
        let (_dir, db) = tmp_db();
        let rule = crate::net::NetRule {
            id: "n1".into(),
            host_pattern: "*.example.com".into(),
            port: Some(443),
            mode: crate::net::NetMode::Allow,
        };
        exec(&db, &PolicyOp::NetRuleUpsert(rule)).unwrap();
        let PolicyOpResult::NetRules(rules) = exec(&db, &PolicyOp::NetRuleList).unwrap() else {
            panic!("expected NetRules");
        };
        assert_eq!(rules.len(), 1);
        exec(&db, &PolicyOp::NetRuleClear).unwrap();
        let PolicyOpResult::NetRules(rules) = exec(&db, &PolicyOp::NetRuleList).unwrap() else {
            panic!("expected NetRules");
        };
        assert!(rules.is_empty());
    }

    #[test]
    fn dev_rule_upsert_list_remove_roundtrip() {
        let (_dir, db) = tmp_db();
        let row = RuleRow {
            id: "d1".into(),
            prefix: "usb\\vid_1234".into(),
            mode_read: RuleMode::Deny,
            mode_write: RuleMode::Deny,
            when: None,
        };
        exec(&db, &PolicyOp::DevRuleUpsert(row)).unwrap();
        let PolicyOpResult::Bool(removed) =
            exec(&db, &PolicyOp::DevRuleRemoveById("d1".into())).unwrap()
        else {
            panic!("expected Bool");
        };
        assert!(removed);
    }

    #[test]
    fn mem_policy_get_defaults_when_unset() {
        let (_dir, db) = tmp_db();
        let PolicyOpResult::MemPolicy(pol) = exec(&db, &PolicyOp::MemPolicyGet).unwrap() else {
            panic!("expected MemPolicy");
        };
        assert_eq!(pol.cross_process, crate::mem::MemMode::Deny);
    }

    #[test]
    fn mem_policy_set_then_get_roundtrip() {
        let (_dir, db) = tmp_db();
        let pol = crate::mem::MemPolicy { cross_process: crate::mem::MemMode::Allow, allow_child_pids: false };
        exec(&db, &PolicyOp::MemPolicySet(pol)).unwrap();
        let PolicyOpResult::MemPolicy(got) = exec(&db, &PolicyOp::MemPolicyGet).unwrap() else {
            panic!("expected MemPolicy");
        };
        assert_eq!(got.cross_process, crate::mem::MemMode::Allow);
        assert!(!got.allow_child_pids);
    }

    #[test]
    fn touches_fs_snapshot_covers_exactly_the_fs_domain_ops() {
        assert!(PolicyOp::RuleUpsert(RuleRow {
            id: String::new(), prefix: String::new(),
            mode_read: RuleMode::Passthrough, mode_write: RuleMode::Cow, when: None,
        }).touches_fs_snapshot());
        assert!(!PolicyOp::MockDirList.touches_fs_snapshot());
        assert!(!PolicyOp::NetRuleList.touches_fs_snapshot());
        assert!(!PolicyOp::RegRuleList.touches_fs_snapshot());
    }

    #[test]
    fn touches_reg_snapshot_covers_exactly_the_reg_domain_mutations() {
        assert!(PolicyOp::RegRuleRemoveById("x".into()).touches_reg_snapshot());
        assert!(!PolicyOp::RegRuleList.touches_reg_snapshot());
        assert!(!PolicyOp::RuleClear.touches_reg_snapshot());
    }
}
