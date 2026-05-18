use anyhow::{bail, Result};
use policy::db::{self, RuleMode};

const HELP: &str = "\
winrsbox rule — manage sandbox rules

SUBCOMMANDS:
  add      Add or update a rule (upsert by id)
  remove   Remove a rule by --id or --prefix
  list     List all rules (--json for machine output)
  show     Show a single rule by --id (--json)
  clear    Remove all rules (requires --force)

RULE ADD OPTIONS:
  --prefix=PATTERN   Path prefix with glob support (* ? **) [required]
  --read=MODE        Read policy: passthrough|deny|cow|redirect [default: passthrough]
  --write=MODE       Write policy: passthrough|deny|cow|redirect [default: cow]
  --depth=N          Only apply at process depth >= N (0 = root target)
  --exe=GLOB         Only apply when exe path matches glob
  --id=NAME          Explicit rule id (default: auto-generated from args)

EXAMPLES:
  winrsbox rule add --prefix='C:\\Users\\*\\AppData' --write=deny
  winrsbox rule add --id=allow-tmp --prefix='C:\\Temp' --write=cow --depth=1
  winrsbox rule remove --id=allow-tmp
  winrsbox rule remove --prefix='C:\\Temp'
  winrsbox rule list --json
  winrsbox rule clear --force
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
        "show" => run_show(rest, state_dir),
        "clear" => run_clear(rest, state_dir),
        _ => bail!("rule: unknown subcommand '{}'. Run 'winrsbox rule --help'.", sub),
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
    args.iter().find(|a| a.starts_with(prefix)).map(|a| &a[prefix.len()..])
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn run_add(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let prefix = find_arg(args, "--prefix=")
        .or_else(|| find_arg(args, "--prefix="))
        .ok_or_else(|| anyhow::anyhow!("rule add: --prefix is required"))?;
    let prefix_lower = prefix.to_lowercase();

    let read_mode = find_arg(args, "--read=").map(parse_mode).transpose()?.unwrap_or(RuleMode::Passthrough);
    let write_mode = find_arg(args, "--write=").map(parse_mode).transpose()?.unwrap_or(RuleMode::Cow);
    let depth = find_arg(args, "--depth=").map(|s| s.parse::<u8>()).transpose()?;
    let exe = find_arg(args, "--exe=").map(String::from);
    let explicit_id = find_arg(args, "--id=").map(String::from);

    let id = explicit_id.unwrap_or_else(|| crate::cli::id::generate_id("rule", &[&prefix_lower]));

    let when = if depth.is_some() || exe.is_some() {
        Some(db::WhenFilter { depth, exe })
    } else {
        None
    };

    let row = db::RuleRow {
        id,
        prefix: prefix_lower,
        mode_read: read_mode,
        mode_write: write_mode,
        when,
    };

    db::rule_upsert(&db, &row)?;
    println!("{}", row.id);
    Ok(())
}

fn run_remove(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    if let Some(id) = find_arg(args, "--id=") {
        let removed = db::rule_remove_by_id(&db, id)?;
        if !removed { bail!("rule not found: {}", id); }
    } else if let Some(prefix) = find_arg(args, "--prefix=") {
        let removed = db::rule_remove_by_prefix(&db, prefix)?;
        if !removed { bail!("rule not found with prefix: {}", prefix); }
    } else {
        bail!("rule remove: --id or --prefix required");
    }
    Ok(())
}

fn run_list(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let json = has_flag(args, "--json");
    let write_filter = find_arg(args, "--write=");
    let depth_min = find_arg(args, "--depth-min=").map(|s| s.parse::<u8>()).transpose()?;

    let mut rules = db::rule_list(&db)?;
    // Sort by prefix for stable output
    rules.sort_by(|a, b| a.prefix.cmp(&b.prefix));

    let filtered: Vec<_> = rules.into_iter().filter(|r| {
        if let Some(ref wf) = write_filter {
            if db::mode_to_string(r.mode_write) != *wf { return false; }
        }
        if let Some(min) = depth_min {
            if r.when.as_ref().and_then(|w| w.depth).map_or(true, |d| d < min) { return false; }
        }
        true
    }).collect();

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "rules": filtered.iter().map(|r| serde_json::json!({
                "id": r.id,
                "prefix": r.prefix,
                "read": db::mode_to_string(r.mode_read),
                "write": db::mode_to_string(r.mode_write),
                "when": r.when.as_ref().map(|w| serde_json::json!({
                    "depth": w.depth,
                    "exe": w.exe,
                })),
            })).collect::<Vec<_>>()
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        for r in &filtered {
            let when_str = r.when.as_ref().map(|w| {
                let mut parts = vec![];
                if let Some(d) = w.depth { parts.push(format!("depth>={d}")); }
                if let Some(ref e) = w.exe { parts.push(format!("exe={e}")); }
                format!(" [{}]", parts.join(", "))
            }).unwrap_or_default();
            println!("{}\t{}\t{}\t{}{}", r.id, r.prefix,
                db::mode_to_string(r.mode_read), db::mode_to_string(r.mode_write), when_str);
        }
    }
    Ok(())
}

fn run_show(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let id = find_arg(args, "--id=").ok_or_else(|| anyhow::anyhow!("rule show: --id required"))?;
    let json = has_flag(args, "--json");

    let rules = db::rule_list(&db)?;
    let rule = rules.iter().find(|r| r.id == id)
        .ok_or_else(|| anyhow::anyhow!("rule not found: {}", id))?;

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "rule": {
                "id": rule.id,
                "prefix": rule.prefix,
                "read": db::mode_to_string(rule.mode_read),
                "write": db::mode_to_string(rule.mode_write),
                "when": rule.when.as_ref().map(|w| serde_json::json!({
                    "depth": w.depth,
                    "exe": w.exe,
                })),
            }
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("id:       {}", rule.id);
        println!("prefix:   {}", rule.prefix);
        println!("read:     {}", db::mode_to_string(rule.mode_read));
        println!("write:    {}", db::mode_to_string(rule.mode_write));
        if let Some(ref w) = rule.when {
            if let Some(d) = w.depth { println!("depth:    >= {}", d); }
            if let Some(ref e) = w.exe { println!("exe:      {}", e); }
        }
    }
    Ok(())
}

fn run_clear(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    if !has_flag(args, "--force") {
        bail!("rule clear: --force required to prevent accidental data loss");
    }
    let db = super::open_db(state_dir)?;
    db::rule_clear(&db)?;
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
    fn rule_add_and_list() {
        let (_dir, state) = tmp_state();
        let id = run_add(
            &["--prefix=C:\\Users\\*".into(), "--write=deny".into()],
            &state,
        ).unwrap();
        // run_add prints the id, let's verify via list
        let db = super::super::open_db(&state).unwrap();
        let rules = db::rule_list(&db).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].prefix, "c:\\users\\*");
        assert!(matches!(rules[0].mode_write, RuleMode::Deny));
    }

    #[test]
    fn rule_add_upsert_same_id() {
        let (_dir, state) = tmp_state();
        run_add(&["--prefix=C:\\Test".into(), "--write=deny".into()], &state).unwrap();
        run_add(&["--prefix=C:\\Test".into(), "--write=cow".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let rules = db::rule_list(&db).unwrap();
        assert_eq!(rules.len(), 1); // upsert, not duplicate
        assert!(matches!(rules[0].mode_write, RuleMode::Cow));
    }

    #[test]
    fn rule_add_idempotent_auto_id() {
        let (_dir, state) = tmp_state();
        let id1 = run_add_return_id(&["--prefix=C:\\Test".into()], &state);
        let id2 = run_add_return_id(&["--prefix=C:\\Test".into()], &state);
        assert_eq!(id1, id2, "same args should produce same auto-id");
        let db = super::super::open_db(&state).unwrap();
        let rules = db::rule_list(&db).unwrap();
        assert_eq!(rules.len(), 1);
    }

    fn run_add_return_id(args: &[String], state: &std::path::Path) -> String {
        let db = super::super::open_db(state).unwrap();
        let prefix = find_arg(args, "--prefix=").unwrap();
        let prefix_lower = prefix.to_lowercase();
        let write_mode = find_arg(args, "--write=").map(parse_mode).transpose().unwrap_or(None).unwrap_or(RuleMode::Cow);
        let id = crate::cli::id::generate_id("rule", &[&prefix_lower]);
        let row = db::RuleRow { id: id.clone(), prefix: prefix_lower, mode_read: RuleMode::Passthrough, mode_write: write_mode, when: None };
        db::rule_upsert(&db, &row).unwrap();
        id
    }

    #[test]
    fn rule_remove_by_id() {
        let (_dir, state) = tmp_state();
        let db = super::super::open_db(&state).unwrap();
        let prefix_lower = "c:\\toremove";
        let id = crate::cli::id::generate_id("rule", &[prefix_lower]);
        let row = db::RuleRow { id: id.clone(), prefix: prefix_lower.into(), mode_read: RuleMode::Passthrough, mode_write: RuleMode::Cow, when: None };
        db::rule_upsert(&db, &row).unwrap();
        drop(db);

        run_remove(&[format!("--id={}", id)], &state).unwrap();
        let db2 = super::super::open_db(&state).unwrap();
        let rules = db::rule_list(&db2).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn rule_remove_by_prefix() {
        let (_dir, state) = tmp_state();
        run_add(&["--prefix=C:\\ToRemove".into()], &state).unwrap();
        run_remove(&["--prefix=C:\\ToRemove".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let rules = db::rule_list(&db).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn rule_list_filter_write() {
        let (_dir, state) = tmp_state();
        run_add(&["--prefix=C:\\Deny".into(), "--write=deny".into()], &state).unwrap();
        run_add(&["--prefix=C:\\Cow".into(), "--write=cow".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let all = db::rule_list(&db).unwrap();
        let filtered: Vec<_> = all.into_iter().filter(|r| matches!(r.mode_write, RuleMode::Deny)).collect();
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn rule_clear_force() {
        let (_dir, state) = tmp_state();
        run_add(&["--prefix=C:\\A".into()], &state).unwrap();
        run_add(&["--prefix=C:\\B".into()], &state).unwrap();
        run_clear(&["--force".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let rules = db::rule_list(&db).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn rule_clear_no_force_errors() {
        let (_dir, state) = tmp_state();
        assert!(run_clear(&[], &state).is_err());
    }

    #[test]
    fn rule_id_deterministic() {
        let id1 = crate::cli::id::generate_id("rule", &["c:\\test"]);
        let id2 = crate::cli::id::generate_id("rule", &["c:\\test"]);
        assert_eq!(id1, id2);
        let id3 = crate::cli::id::generate_id("rule", &["c:\\other"]);
        assert_ne!(id1, id3);
    }

    #[test]
    fn rule_add_with_when() {
        let (_dir, state) = tmp_state();
        run_add(&[
            "--prefix=C:\\Secret".into(),
            "--write=deny".into(),
            "--depth=2".into(),
            "--exe=myapp.exe".into(),
        ], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let rules = db::rule_list(&db).unwrap();
        assert_eq!(rules.len(), 1);
        let when = rules[0].when.as_ref().unwrap();
        assert_eq!(when.depth, Some(2));
        assert_eq!(when.exe.as_deref(), Some("myapp.exe"));
    }
}
