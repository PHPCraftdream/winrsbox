use anyhow::{bail, Result};

const HELP: &str = "\
winrsbox memdefaults — manage cross-process memory operation policy

Controls whether sandboxed processes can write memory, create threads,
or allocate memory in OTHER processes. Self-process operations are always allowed.

SUBCOMMANDS:
  set    Set policy (--cross-process=allow|deny --allow-children=true|false)
  show   Show current policy (--json)

By default: cross-process=deny, allow-children=true.
This blocks WriteProcessMemory, CreateRemoteThread, NtAllocateVirtualMemory,
NtProtectVirtualMemory targeting foreign processes — except sandbox children.

EXAMPLES:
  winrsbox memdefaults set --cross-process=deny
  winrsbox memdefaults set --cross-process=deny --allow-children=false
  winrsbox memdefaults show --json
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
        _ => bail!("memdefaults: unknown subcommand '{}'", sub),
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

fn run_set(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let cross = find_arg(args, "--cross-process=");
    let children = find_arg(args, "--allow-children=");

    let mode = match cross {
        Some("deny") => policy::mem::MemMode::Deny,
        Some("allow") => policy::mem::MemMode::Allow,
        Some(other) => bail!("invalid mode '{}', expected allow|deny", other),
        None => policy::mem::MemMode::Deny,
    };
    let allow_children = match children {
        Some("true") | Some("yes") | None => true,
        Some("false") | Some("no") => false,
        Some(other) => bail!("invalid --allow-children '{}', expected true|false", other),
    };

    let pol = policy::mem::MemPolicy { cross_process: mode, allow_child_pids: allow_children };
    let json = serde_json::to_vec(&pol)?;

    let db = super::open_db(state_dir)?;
    let txn = db.begin_write()?;
    {
        let mut t = txn.open_table(policy::db::DEFAULTS)?;
        t.insert("mem_policy", json.as_slice())?;
    }
    txn.commit()?;
    println!("cross-process={:?} allow-children={}", pol.cross_process, pol.allow_child_pids);
    Ok(())
}

fn run_show(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let txn = db.begin_read()?;
    let pol = if let Ok(t) = txn.open_table(policy::db::DEFAULTS) {
        if let Ok(Some(v)) = t.get("mem_policy") {
            serde_json::from_slice::<policy::mem::MemPolicy>(v.value()).ok()
        } else { None }
    } else { None };
    let pol = pol.unwrap_or_default();

    if has_flag(args, "--json") {
        println!("{}", serde_json::json!({
            "schema_version": 1,
            "mem_policy": {
                "cross_process": format!("{:?}", pol.cross_process).to_lowercase(),
                "allow_children": pol.allow_child_pids,
            },
        }));
    } else {
        println!("cross-process={:?} allow-children={}", pol.cross_process, pol.allow_child_pids);
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
    fn memdefaults_set_deny() {
        let (_dir, state) = tmp_state();
        run_set(&["--cross-process=deny".into()], &state).unwrap();
    }

    #[test]
    fn memdefaults_set_allow() {
        let (_dir, state) = tmp_state();
        run_set(&["--cross-process=allow".into(), "--allow-children=false".into()], &state).unwrap();
    }

    #[test]
    fn memdefaults_show() {
        let (_dir, state) = tmp_state();
        run_set(&["--cross-process=deny".into()], &state).unwrap();
        run_show(&["--json".into()], &state).unwrap();
    }

    #[test]
    fn memdefaults_invalid_mode() {
        let (_dir, state) = tmp_state();
        assert!(run_set(&["--cross-process=bogus".into()], &state).is_err());
    }
}
