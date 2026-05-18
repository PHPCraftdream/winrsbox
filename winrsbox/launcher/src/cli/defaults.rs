use anyhow::{bail, Result};

pub fn run(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    if args.is_empty() { bail!("defaults: expected subcommand (set, show)"); }
    let sub = args[0].to_lowercase();
    let rest = &args[1..];
    match sub.as_str() {
        "set" => run_set(rest, state_dir),
        "show" => run_show(rest, state_dir),
        _ => bail!("defaults: unknown subcommand '{}'", sub),
    }
}

fn find_arg<'a>(args: &'a [String], prefix: &str) -> Option<&'a str> {
    args.iter().find(|a| a.starts_with(prefix)).map(|a| &a[prefix.len()..])
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn parse_mode(s: &str) -> Result<policy::db::RuleMode> {
    match s {
        "passthrough" => Ok(policy::db::RuleMode::Passthrough),
        "deny" => Ok(policy::db::RuleMode::Deny),
        "cow" => Ok(policy::db::RuleMode::Cow),
        "redirect" => Ok(policy::db::RuleMode::Redirect),
        _ => bail!("invalid mode '{}', expected passthrough|deny|cow|redirect", s),
    }
}

fn run_set(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let read = find_arg(args, "--read=").map(parse_mode).transpose()?;
    let write = find_arg(args, "--write=").map(parse_mode).transpose()?;
    policy::db::defaults_set(&db, read, write)?;
    Ok(())
}

fn run_show(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let defaults = policy::db::defaults_get(&db)?;
    let json = has_flag(args, "--json");

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "defaults": {
                "read": policy::db::mode_to_string(defaults.read),
                "write": policy::db::mode_to_string(defaults.write),
            }
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("read:  {}", policy::db::mode_to_string(defaults.read));
        println!("write: {}", policy::db::mode_to_string(defaults.write));
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
    fn defaults_set_and_show() {
        let (_dir, state) = tmp_state();
        run_set(&["--read=deny".into(), "--write=deny".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let defaults = policy::db::defaults_get(&db).unwrap();
        assert!(matches!(defaults.read, policy::db::RuleMode::Deny));
        assert!(matches!(defaults.write, policy::db::RuleMode::Deny));
    }

    #[test]
    fn defaults_set_partial() {
        let (_dir, state) = tmp_state();
        // Default is Passthrough/Cow
        run_set(&["--write=deny".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let defaults = policy::db::defaults_get(&db).unwrap();
        assert!(matches!(defaults.read, policy::db::RuleMode::Passthrough)); // unchanged
        assert!(matches!(defaults.write, policy::db::RuleMode::Deny));
    }
}
