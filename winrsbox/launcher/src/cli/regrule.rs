use anyhow::{bail, Result};
use policy::db::{self, RuleMode};

const HELP: &str = "\
winrsbox regrule — manage registry sandbox rules

SUBCOMMANDS:
  add      Add or update a registry rule (upsert by id)
  remove   Remove a rule by --id or --prefix
  list     List all registry rules (--json for machine output)
  clear    Remove all registry rules (requires --force)

RULE ADD OPTIONS:
  --prefix=PATTERN   Registry key prefix with glob support [required]
                     Example: HKLM\\\\Software\\\\MyApp
  --read=MODE        Read policy: passthrough|deny|cow [default: passthrough]
  --write=MODE       Write policy: passthrough|deny|cow [default: cow]
  --depth=N          Only apply at process depth >= N
  --exe=GLOB         Only apply when exe path matches glob
  --id=NAME          Explicit rule id (default: auto-generated)

EXAMPLES:
  winrsbox regrule add --prefix='HKLM\\\\Software\\\\Secrets' --write=deny
  winrsbox regrule add --id=allow-hkcu --prefix='HKCU\\\\Software' --write=cow
  winrsbox regrule remove --id=allow-hkcu
  winrsbox regrule list --json
  winrsbox regrule clear --force
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
        _ => bail!("regrule: unknown subcommand '{}'. Run 'winrsbox regrule --help'.", sub),
    }
}

fn parse_mode(s: &str) -> Result<RuleMode> {
    match s {
        "passthrough" => Ok(RuleMode::Passthrough),
        "deny" => Ok(RuleMode::Deny),
        "cow" => Ok(RuleMode::Cow),
        "redirect" => Ok(RuleMode::Redirect),
        _ => bail!("invalid mode '{}', expected passthrough|deny|cow|redirect", s),
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
        .ok_or_else(|| anyhow::anyhow!("regrule add: --prefix is required"))?;
    let prefix_lower = prefix.to_lowercase();
    let read_mode = find_arg(args, "--read=").map(parse_mode).transpose()?.unwrap_or(RuleMode::Passthrough);
    let write_mode = find_arg(args, "--write=").map(parse_mode).transpose()?.unwrap_or(RuleMode::Cow);
    let depth = find_arg(args, "--depth=").map(|s| s.parse::<u8>()).transpose()?;
    let exe = find_arg(args, "--exe=").map(String::from);
    let explicit_id = find_arg(args, "--id=").map(String::from);
    let id = explicit_id.unwrap_or_else(|| crate::cli::id::generate_id("regrule", &[&prefix_lower]));

    let when = if depth.is_some() || exe.is_some() {
        Some(db::WhenFilter { depth, exe })
    } else {
        None
    };
    let row = db::RuleRow { id: id.clone(), prefix: prefix_lower, mode_read: read_mode, mode_write: write_mode, when };
    db::reg_rule_upsert(&db, &row)?;
    println!("{id}");
    Ok(())
}

fn run_remove(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    if let Some(id) = find_arg(args, "--id=") {
        if !db::reg_rule_remove_by_id(&db, id)? {
            bail!("regrule: rule with id '{}' not found", id);
        }
    } else if let Some(prefix) = find_arg(args, "--prefix=") {
        let lower = prefix.to_lowercase();
        let txn = db.begin_write()?;
        { let mut t = txn.open_table(db::REG_RULES)?; t.remove(lower.as_str())?; }
        txn.commit()?;
    } else {
        bail!("regrule remove: --id or --prefix required");
    }
    Ok(())
}

fn run_list(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let rules = db::reg_rule_list(&db)?;
    let json = has_flag(args, "--json");
    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "reg_rules": rules.iter().map(|r| serde_json::json!({
                "id": r.id, "prefix": r.prefix,
                "read": db::mode_to_string(r.mode_read),
                "write": db::mode_to_string(r.mode_write),
                "when": r.when.as_ref().map(|w| serde_json::json!({"depth": w.depth, "exe": w.exe})),
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
    if !has_flag(args, "--force") {
        bail!("regrule clear: requires --force flag");
    }
    let db = super::open_db(state_dir)?;
    db::reg_rule_clear(&db)?;
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
    fn regrule_add_and_list() {
        let (_dir, state) = tmp_state();
        run_add(&[
            "--prefix=hklm\\software\\test".into(), "--write=deny".into(),
        ], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let rules = db::reg_rule_list(&db).unwrap();
        assert_eq!(rules.len(), 1);
        assert!(matches!(rules[0].mode_write, RuleMode::Deny));
    }

    #[test]
    fn regrule_remove_by_id() {
        let (_dir, state) = tmp_state();
        run_add(&[
            "--prefix=hklm\\test".into(), "--write=deny".into(), "--id=myid".into(),
        ], &state).unwrap();
        run_remove(&["--id=myid".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        assert!(db::reg_rule_list(&db).unwrap().is_empty());
    }

    #[test]
    fn regrule_clear_needs_force() {
        let (_dir, state) = tmp_state();
        assert!(run_clear(&[], &state).is_err());
    }

    #[test]
    fn regrule_add_idempotent() {
        let (_dir, state) = tmp_state();
        run_add(&["--prefix=hklm\\test".into(), "--write=deny".into()], &state).unwrap();
        run_add(&["--prefix=hklm\\test".into(), "--write=deny".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        assert_eq!(db::reg_rule_list(&db).unwrap().len(), 1);
    }
}
