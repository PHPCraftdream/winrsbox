use anyhow::{bail, Result};
use policy::net::{NetMode, NetRule};

const HELP: &str = "\
winrsbox netrule — manage network access rules

Controls which hosts/ports sandboxed processes can connect to.
Default policy: configurable (typically deny-by-default for agents).

SUBCOMMANDS:
  add      Add or update a network rule
  remove   Remove by --id
  list     List all rules (--json)
  clear    Remove all (requires --force)

OPTIONS:
  --host=PATTERN   Host glob: exact, *.domain.com, or * (all) [required]
  --port=N         Port number (optional — matches all ports if omitted)
  --mode=MODE      allow|deny|log [default: deny]
  --id=NAME        Explicit rule id

EXAMPLES:
  winrsbox netrule add --host='*.github.com' --port=443 --mode=allow
  winrsbox netrule add --host='*' --mode=deny              # deny all by default
  winrsbox netrule add --host='localhost' --mode=allow      # always allow localhost
  winrsbox netrule add --host='10.0.0.0/8' --mode=deny     # deny private network
  winrsbox netrule list --json
  winrsbox netrule remove --id=ID
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
        _ => bail!("netrule: unknown subcommand '{}'", sub),
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

fn parse_net_mode(s: &str) -> Result<NetMode> {
    match s {
        "allow" => Ok(NetMode::Allow),
        "deny" => Ok(NetMode::Deny),
        "log" => Ok(NetMode::Log),
        _ => bail!("invalid network mode '{}', expected allow|deny|log", s),
    }
}

fn run_add(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let host = find_arg(args, "--host=")
        .ok_or_else(|| anyhow::anyhow!("netrule add: --host required"))?
        .to_lowercase();
    let port = find_arg(args, "--port=").map(|s| s.parse::<u16>()).transpose()?;
    let mode = find_arg(args, "--mode=").map(parse_net_mode).transpose()?.unwrap_or(NetMode::Deny);
    let explicit_id = find_arg(args, "--id=").map(String::from);
    let id = explicit_id.unwrap_or_else(|| {
        let port_str = port.map(|p| p.to_string()).unwrap_or_default();
        crate::cli::id::generate_id("netrule", &[&host, &port_str])
    });
    let rule = NetRule { id: id.clone(), host_pattern: host, port, mode };
    policy::db::net_rule_upsert(&db, &rule)?;
    println!("{id}");
    Ok(())
}

fn run_remove(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let id = find_arg(args, "--id=").ok_or_else(|| anyhow::anyhow!("netrule remove: --id required"))?;
    if !policy::db::net_rule_remove(&db, id)? {
        bail!("netrule: rule '{}' not found", id);
    }
    Ok(())
}

fn run_list(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let rules = policy::db::net_rule_list(&db)?;
    if has_flag(args, "--json") {
        let out = serde_json::json!({
            "schema_version": 1,
            "net_rules": rules.iter().map(|r| serde_json::json!({
                "id": r.id, "host": r.host_pattern, "port": r.port,
                "mode": format!("{:?}", r.mode).to_lowercase(),
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        for r in &rules {
            let port_str = r.port.map(|p| p.to_string()).unwrap_or_else(|| "*".into());
            println!("{}\t{}:{}\t{:?}", r.id, r.host_pattern, port_str, r.mode);
        }
    }
    Ok(())
}

fn run_clear(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    if !has_flag(args, "--force") { bail!("netrule clear: requires --force"); }
    let db = super::open_db(state_dir)?;
    policy::db::net_rule_clear(&db)?;
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
    fn netrule_add_and_list() {
        let (_dir, state) = tmp_state();
        run_add(&["--host=*.github.com".into(), "--port=443".into(), "--mode=allow".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let rules = policy::db::net_rule_list(&db).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].mode, NetMode::Allow);
        assert_eq!(rules[0].port, Some(443));
    }

    #[test]
    fn netrule_remove() {
        let (_dir, state) = tmp_state();
        run_add(&["--host=evil.com".into(), "--mode=deny".into(), "--id=evil".into()], &state).unwrap();
        run_remove(&["--id=evil".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        assert!(policy::db::net_rule_list(&db).unwrap().is_empty());
    }

    #[test]
    fn netrule_default_deny() {
        let (_dir, state) = tmp_state();
        run_add(&["--host=*".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let rules = policy::db::net_rule_list(&db).unwrap();
        assert_eq!(rules[0].mode, NetMode::Deny);
    }

    #[test]
    fn netrule_clear_needs_force() {
        let (_dir, state) = tmp_state();
        assert!(run_clear(&[], &state).is_err());
    }

    #[test]
    fn netrule_invalid_mode_errors() {
        let (_dir, state) = tmp_state();
        let result = run_add(&["--host=x".into(), "--mode=bogus".into()], &state);
        assert!(result.is_err());
    }
}
