use anyhow::{bail, Result};

pub fn run(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    if args.is_empty() { bail!("mockdir: expected subcommand (add, remove, list)"); }
    let sub = args[0].to_lowercase();
    let rest = &args[1..];
    match sub.as_str() {
        "add" => run_add(rest, state_dir),
        "remove" => run_remove(rest, state_dir),
        "list" => run_list(rest, state_dir),
        _ => bail!("mockdir: unknown subcommand '{}'", sub),
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
    let prefix = find_arg(args, "--prefix=").ok_or_else(|| anyhow::anyhow!("mockdir add: --prefix is required"))?;
    let prefix_lower = prefix.to_lowercase();
    let id = find_arg(args, "--id=").map(String::from)
        .unwrap_or_else(|| crate::cli::id::generate_id("mockdir", &[&prefix_lower]));

    policy::db::mockdir_upsert(&db, &prefix_lower)?;
    println!("{}", id);
    Ok(())
}

fn run_remove(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    if let Some(prefix) = find_arg(args, "--prefix=") {
        let removed = policy::db::mockdir_remove_by_prefix(&db, prefix)?;
        if !removed { bail!("mockdir not found: {}", prefix); }
    } else {
        bail!("mockdir remove: --prefix required");
    }
    Ok(())
}

fn run_list(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let json = has_flag(args, "--json");
    let dirs = policy::db::mockdir_list(&db)?;

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "mockdirs": dirs,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        for d in &dirs {
            println!("{}", d);
        }
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
    fn mockdir_add_and_list() {
        let (_dir, state) = tmp_state();
        run_add(&["--prefix=C:\\Fake".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let dirs = policy::db::mockdir_list(&db).unwrap();
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0], "c:\\fake");
    }

    #[test]
    fn mockdir_remove() {
        let (_dir, state) = tmp_state();
        run_add(&["--prefix=C:\\Fake".into()], &state).unwrap();
        run_remove(&["--prefix=C:\\Fake".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let dirs = policy::db::mockdir_list(&db).unwrap();
        assert!(dirs.is_empty());
    }

    #[test]
    fn mockdir_idempotent_id() {
        let id1 = crate::cli::id::generate_id("mockdir", &["c:\\fake"]);
        let id2 = crate::cli::id::generate_id("mockdir", &["c:\\fake"]);
        assert_eq!(id1, id2);
    }
}
