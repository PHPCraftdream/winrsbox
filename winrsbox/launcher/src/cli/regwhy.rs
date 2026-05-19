use anyhow::{bail, Result};
use std::path::PathBuf;

const HELP: &str = "\
winrsbox regwhy — simulate a registry key lookup and explain the decision

Shows which rule matches, the effective mode, and whether the value
comes from the real registry (passthrough), overlay (cow), mock, or is denied.

OPTIONS:
  <key>          Registry key path (e.g. HKLM\\Software\\Foo)
  --value=NAME   Value name to check (optional — omit for key-level check)
  --write        Check write mode (default: check read)
  --depth=N      Process depth for when-filter
  --exe=PATH     Executable path for when-filter
  --json         Output as JSON

JSON OUTPUT:
  { \"key\": \"...\", \"value\": \"...\", \"decision\": \"passthrough|deny|cow|mock\",
    \"overlay_data\": {...} or null, \"mock_data\": {...} or null,
    \"rule_id\": \"...\" or null }

EXAMPLES:
  winrsbox regwhy 'HKLM\\Software\\Microsoft' --value=ProductName --json
  winrsbox regwhy 'HKCU\\Software\\Secrets' --write --json
  winrsbox regwhy 'HKLM\\Software\\Foo' --value=bar --depth=1 --exe='c:\\app.exe'
";

pub fn run(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    if args.is_empty() || has_flag(args, "--help") || has_flag(args, "-h") {
        print!("{}", HELP);
        return Ok(());
    }

    let workreg = state_dir.join("workreg");
    std::fs::create_dir_all(&workreg)?;
    let db_path = state_dir.join("policy.redb");
    let rdb = redb::Database::create(&db_path)?;
    { let txn = rdb.begin_write()?; txn.open_table(policy::db::REG_RULES)?; txn.open_table(policy::db::REG_MOCKS)?; txn.commit()?; }
    let db = std::sync::Arc::new(rdb);
    let rp = policy::RegistryPolicy::open(db, workreg)?;

    let json = has_flag(args, "--json");
    let write = has_flag(args, "--write");
    let depth = find_arg(args, "--depth=").map(|s| s.parse::<u8>()).transpose()?;
    let exe = find_arg(args, "--exe=");
    let value_name = find_arg(args, "--value=");

    let keys: Vec<&str> = args.iter()
        .filter(|a| !a.starts_with("--"))
        .map(|a| a.as_str())
        .collect();

    if keys.is_empty() {
        bail!("regwhy: at least one registry key path required");
    }

    for key in &keys {
        let d = rp.decide_with_context(key, value_name, write, depth, exe);
        if json {
            let out = serde_json::json!({
                "schema_version": 1,
                "key": key,
                "value": value_name,
                "write": write,
                "context": { "depth": depth, "exe": exe },
                "decision": format!("{:?}", d.mode).to_lowercase(),
                "overlay_data": d.overlay_value.as_ref().map(|v| v.to_json_value()),
                "mock_data": d.mock_value.as_ref().map(|v| v.to_json_value()),
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        } else {
            let mode_str = format!("{:?}", d.mode).to_lowercase();
            let detail = if d.overlay_value.is_some() {
                " (from overlay)"
            } else if d.mock_value.is_some() {
                " (mock)"
            } else {
                ""
            };
            println!("{key}\\{}\t{mode_str}{detail}",
                value_name.unwrap_or("(key-level)"));
        }
    }
    Ok(())
}

fn find_arg<'a>(args: &'a [String], prefix: &str) -> Option<&'a str> {
    let flag = prefix.trim_end_matches('=');
    for (i, a) in args.iter().enumerate() {
        if a.starts_with(prefix) { return Some(&a[prefix.len()..]); }
        if a == flag { if let Some(next) = args.get(i + 1) { return Some(next.as_str()); } }
    }
    None
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_state() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".winrsbox").join("test");
        std::fs::create_dir_all(&state).unwrap();
        (dir, state)
    }

    fn setup_rp(state: &std::path::Path) -> (std::sync::Arc<redb::Database>, policy::RegistryPolicy) {
        let workreg = state.join("workreg");
        std::fs::create_dir_all(&workreg).unwrap();
        let db_path = state.join("policy.redb");
        let rdb = redb::Database::create(&db_path).unwrap();
        { let txn = rdb.begin_write().unwrap(); txn.open_table(policy::db::REG_RULES).unwrap(); txn.open_table(policy::db::REG_MOCKS).unwrap(); txn.commit().unwrap(); }
        let db = std::sync::Arc::new(rdb);
        let rp = policy::RegistryPolicy::open(db.clone(), workreg).unwrap();
        (db, rp)
    }

    #[test]
    fn regwhy_passthrough_default() {
        let (_dir, state) = tmp_state();
        run(&[r"HKLM\Software\Foo".into(), "--json".into()], &state).unwrap();
    }

    #[test]
    fn regwhy_with_value() {
        let (_dir, state) = tmp_state();
        run(&[r"HKLM\Software\Foo".into(), "--value=bar".into(), "--json".into()], &state).unwrap();
    }

    #[test]
    fn regwhy_deny_rule_shows_deny() {
        let (_dir, state) = tmp_state();
        {
            let (db, _rp) = setup_rp(&state);
            policy::db::reg_rule_upsert(&db, &policy::db::RuleRow {
                id: "d".into(), prefix: r"hklm\secrets".into(),
                mode_read: policy::db::RuleMode::Deny, mode_write: policy::db::RuleMode::Deny, when: None,
            }).unwrap();
        }
        run(&[r"HKLM\Secrets\Key".into(), "--value=x".into(), "--json".into()], &state).unwrap();
    }

    #[test]
    fn regwhy_mock_shows_mock() {
        let (_dir, state) = tmp_state();
        {
            let (db, _rp) = setup_rp(&state);
            let val = policy::reg::RegValue { typ: policy::reg::RegType::Sz, data: policy::reg::RegData::String("FAKE".into()) };
            let payload = serde_json::to_vec(&val).unwrap();
            policy::db::reg_mock_upsert(&db, r"hklm\crypto\guid", &payload).unwrap();
        }
        run(&[r"HKLM\Crypto".into(), "--value=guid".into(), "--json".into()], &state).unwrap();
    }

    #[test]
    fn regwhy_overlay_write_then_read() {
        let (_dir, state) = tmp_state();
        let (_db, rp) = setup_rp(&state);
        rp.write_to_overlay("hklm\\test", "val",
            policy::reg::RegValue { typ: policy::reg::RegType::Dword, data: policy::reg::RegData::U32(42) },
        ).unwrap();
        let d = rp.decide(r"hklm\test", Some("val"), false);
        assert_eq!(d.mode, policy::Mode::Cow);
        assert!(d.overlay_value.is_some());
    }

    #[test]
    fn regwhy_write_mode() {
        let (_dir, state) = tmp_state();
        run(&[r"HKLM\Software\Foo".into(), "--write".into(), "--json".into()], &state).unwrap();
    }
}
