use anyhow::{bail, Result};
use policy::db;

const HELP: &str = "\
winrsbox regdefaults — manage default registry read/write policy

Default modes apply when no specific registry rule matches a key.

SUBCOMMANDS:
  set    Set default modes (--read=MODE --write=MODE)
  show   Show current defaults (--json)

MODES: passthrough | deny | cow | redirect

EXAMPLES:
  winrsbox regdefaults set --read=passthrough --write=cow
  winrsbox regdefaults show --json
";

pub fn run(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    if args.is_empty() || has_flag(args, "--help") || has_flag(args, "-h") {
        print!("{}", HELP);
        return Ok(());
    }
    let sub = args[0].to_lowercase();
    let rest = &args[1..];
    match sub.as_str() {
        "set" => run_set(rest, state_dir),
        "show" => run_show(rest, state_dir),
        _ => bail!("regdefaults: unknown subcommand '{}'", sub),
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

fn parse_mode(s: &str) -> Result<db::RuleMode> {
    match s {
        "passthrough" => Ok(db::RuleMode::Passthrough),
        "deny" => Ok(db::RuleMode::Deny),
        "cow" => Ok(db::RuleMode::Cow),
        "redirect" => Ok(db::RuleMode::Redirect),
        _ => bail!("invalid mode '{}'", s),
    }
}

fn run_set(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let read = find_arg(args, "--read=").map(parse_mode).transpose()?;
    let write = find_arg(args, "--write=").map(parse_mode).transpose()?;
    if read.is_none() && write.is_none() {
        bail!("regdefaults set: at least --read or --write required");
    }
    let row = db::RuleRow {
        id: String::new(),
        prefix: String::new(),
        mode_read: read.unwrap_or(db::RuleMode::Passthrough),
        mode_write: write.unwrap_or(db::RuleMode::Cow),
        when: None,
    };
    db::reg_rule_upsert(&db, &row)?;
    Ok(())
}

fn run_show(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let txn = db.begin_read()?;
    let t = txn.open_table(db::REG_RULES)?;
    let defaults = if let Some(v) = t.get("")? {
        db::decode_rule(v.value())
    } else {
        None
    };
    let (r, w) = defaults
        .map(|d| (d.mode_read, d.mode_write))
        .unwrap_or((db::RuleMode::Passthrough, db::RuleMode::Cow));

    if has_flag(args, "--json") {
        println!("{}", serde_json::json!({
            "schema_version": 1,
            "reg_defaults": { "read": db::mode_to_string(r), "write": db::mode_to_string(w) },
        }));
    } else {
        println!("read={} write={}", db::mode_to_string(r), db::mode_to_string(w));
    }
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
    fn regdefaults_set_and_show() {
        let (_dir, state) = tmp_state();
        run_set(&["--read=deny".into(), "--write=deny".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let txn = db.begin_read().unwrap();
        let t = txn.open_table(db::REG_RULES).unwrap();
        let v = t.get("").unwrap().unwrap();
        let row = db::decode_rule(v.value()).unwrap();
        assert!(matches!(row.mode_read, db::RuleMode::Deny));
        assert!(matches!(row.mode_write, db::RuleMode::Deny));
    }
}
