use anyhow::{bail, Result};
use policy::db::{self, RuleMode};

const HELP: &str = "\
winrsbox devrule — manage device access rules

Controls which Windows device paths (\\Device\\...) sandboxed processes can open.
Default policy: DENY all unknown devices. Only whitelisted devices are accessible.

SUBCOMMANDS:
  add      Add or update a device rule (upsert by id)
  remove   Remove a rule by --id or --prefix
  list     List all device rules (--json)
  clear    Remove all device rules (requires --force)

OPTIONS:
  --prefix=PATH    Device path prefix (e.g. \\Device\\HarddiskVolume) [required]
  --read=MODE      passthrough|deny [default: deny]
  --write=MODE     passthrough|deny [default: deny]
  --id=NAME        Explicit rule id

Safe defaults (auto-created if no rules exist):
  \\Device\\HarddiskVolume*  passthrough (normal disk access)
  \\Device\\NamedPipe\\*     passthrough (IPC)
  \\Device\\ConDrv           passthrough (console)
  \\Device\\Null             passthrough
  Everything else            DENY (blocks kernel driver exploits)

EXAMPLES:
  winrsbox devrule add --prefix='\\Device\\Afd' --read=passthrough --write=passthrough
  winrsbox devrule add --prefix='\\Device\\CldFlt' --read=deny --write=deny
  winrsbox devrule list --json
  winrsbox devrule clear --force
";

pub fn run(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    if args.is_empty() || has_flag(args, "--help") || has_flag(args, "-h") {
        print!("{}", HELP);
        return Ok(());
    }
    let sub = args[0].to_lowercase();
    let rest = &args[1..];
    match sub.as_str() {
        "add" => run_add(rest, state_dir),
        "remove" => run_remove(rest, state_dir),
        "list" => run_list(rest, state_dir),
        "clear" => run_clear(rest, state_dir),
        _ => bail!("devrule: unknown subcommand '{}'", sub),
    }
}

fn parse_mode(s: &str) -> Result<RuleMode> {
    match s {
        "passthrough" => Ok(RuleMode::Passthrough),
        "deny" => Ok(RuleMode::Deny),
        _ => bail!("invalid device mode '{}', expected passthrough|deny", s),
    }
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

fn run_add(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let prefix = find_arg(args, "--prefix=")
        .ok_or_else(|| anyhow::anyhow!("devrule add: --prefix required"))?;
    let prefix_lower = prefix.to_lowercase();
    let read_mode = find_arg(args, "--read=").map(parse_mode).transpose()?.unwrap_or(RuleMode::Deny);
    let write_mode = find_arg(args, "--write=").map(parse_mode).transpose()?.unwrap_or(RuleMode::Deny);
    let explicit_id = find_arg(args, "--id=").map(String::from);
    let id = explicit_id.unwrap_or_else(|| crate::cli::id::generate_id("devrule", &[&prefix_lower]));

    let row = db::RuleRow { id: id.clone(), prefix: prefix_lower, mode_read: read_mode, mode_write: write_mode, when: None };
    db::dev_rule_upsert(&db, &row)?;
    println!("{id}");
    Ok(())
}

fn run_remove(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    if let Some(id) = find_arg(args, "--id=") {
        if !db::dev_rule_remove_by_id(&db, id)? {
            bail!("devrule: rule '{}' not found", id);
        }
    } else if let Some(prefix) = find_arg(args, "--prefix=") {
        let txn = db.begin_write()?;
        { let mut t = txn.open_table(db::DEV_RULES)?; t.remove(prefix.to_lowercase().as_str())?; }
        txn.commit()?;
    } else {
        bail!("devrule remove: --id or --prefix required");
    }
    Ok(())
}

fn run_list(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let rules = db::dev_rule_list(&db)?;
    if has_flag(args, "--json") {
        let out = serde_json::json!({
            "schema_version": 1,
            "dev_rules": rules.iter().map(|r| serde_json::json!({
                "id": r.id, "prefix": r.prefix,
                "read": db::mode_to_string(r.mode_read),
                "write": db::mode_to_string(r.mode_write),
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        for r in &rules {
            println!("{}\t{}\tread={}\twrite={}", r.id, r.prefix,
                db::mode_to_string(r.mode_read), db::mode_to_string(r.mode_write));
        }
    }
    Ok(())
}

fn run_clear(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    if !has_flag(args, "--force") { bail!("devrule clear: requires --force"); }
    let db = super::open_db(state_dir)?;
    db::dev_rule_clear(&db)?;
    Ok(())
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

    #[test]
    fn devrule_add_and_list() {
        let (_dir, state) = tmp_state();
        run_add(&["--prefix=\\device\\cldflt".into(), "--read=deny".into(), "--write=deny".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let rules = db::dev_rule_list(&db).unwrap();
        assert_eq!(rules.len(), 1);
        assert!(matches!(rules[0].mode_read, RuleMode::Deny));
    }

    #[test]
    fn devrule_remove_by_id() {
        let (_dir, state) = tmp_state();
        run_add(&["--prefix=\\device\\foo".into(), "--id=myid".into()], &state).unwrap();
        run_remove(&["--id=myid".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        assert!(db::dev_rule_list(&db).unwrap().is_empty());
    }

    #[test]
    fn devrule_clear_needs_force() {
        let (_dir, state) = tmp_state();
        assert!(run_clear(&[], &state).is_err());
    }

    #[test]
    fn devrule_default_is_deny() {
        let (_dir, state) = tmp_state();
        run_add(&["--prefix=\\device\\test".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let rules = db::dev_rule_list(&db).unwrap();
        assert!(matches!(rules[0].mode_read, RuleMode::Deny));
        assert!(matches!(rules[0].mode_write, RuleMode::Deny));
    }
}
