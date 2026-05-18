use anyhow::{bail, Result};

pub fn run(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    if args.is_empty() { bail!("mock: expected subcommand (add, remove, list, show)"); }
    let sub = args[0].to_lowercase();
    let rest = &args[1..];
    match sub.as_str() {
        "add" => run_add(rest, state_dir),
        "remove" => run_remove(rest, state_dir),
        "list" => run_list(rest, state_dir),
        "show" => run_show(rest, state_dir),
        _ => bail!("mock: unknown subcommand '{}'", sub),
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
    let path = find_arg(args, "--path=").ok_or_else(|| anyhow::anyhow!("mock add: --path is required"))?;
    let content_str = find_arg(args, "--content=");
    let file_path = find_arg(args, "--file=");
    let stdin_flag = has_flag(args, "--stdin");
    let base64_str = find_arg(args, "--base64=");

    // Mutual exclusion check
    let mut count = 0;
    if content_str.is_some() { count += 1; }
    if file_path.is_some() { count += 1; }
    if stdin_flag { count += 1; }
    if base64_str.is_some() { count += 1; }
    if count > 1 {
        bail!("mock add: --content, --file, --stdin, and --base64 are mutually exclusive");
    }

    let payload: Vec<u8> = if let Some(content) = content_str {
        content.as_bytes().to_vec()
    } else if let Some(file) = file_path {
        std::fs::read(file)?
    } else if stdin_flag {
        use std::io::Read;
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    } else if let Some(b64) = base64_str {
        use base64::prelude::*;
        BASE64_STANDARD.decode(b64)?
    } else {
        // Default: empty payload
        Vec::new()
    };

    let id = find_arg(args, "--id=").map(String::from)
        .unwrap_or_else(|| {
            let path_lower = path.to_lowercase();
            crate::cli::id::generate_id("mock", &[&path_lower])
        });

    policy::db::mock_upsert(&db, &id, path, &payload)?;
    println!("{}", id);
    Ok(())
}

fn run_remove(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    if let Some(_id) = find_arg(args, "--id=") {
        // Mocks are keyed by path; to remove by id we'd need an id→path index.
        // For now, require --path for removal.
        bail!("mock remove: --id not yet supported for mocks, use --path");
    } else if let Some(path) = find_arg(args, "--path=") {
        let removed = policy::db::mock_remove_by_path(&db, path)?;
        if !removed { bail!("mock not found: {}", path); }
    } else {
        bail!("mock remove: --path required");
    }
    Ok(())
}

fn run_list(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let json = has_flag(args, "--json");
    let mocks = policy::db::mock_list(&db)?;

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "mocks": mocks.iter().map(|(path, payload)| serde_json::json!({
                "path": path,
                "size": payload.len(),
            })).collect::<Vec<_>>()
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        for (path, payload) in &mocks {
            println!("{}\t{}bytes", path, payload.len());
        }
    }
    Ok(())
}

fn run_show(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let _json = has_flag(args, "--json");
    // Show by path (mocks keyed by path)
    let path = find_arg(args, "--path=");
    let id = find_arg(args, "--id=");

    let db = super::open_db(state_dir)?;
    let mocks = policy::db::mock_list(&db)?;

    if let Some(p) = path {
        let mock = mocks.iter().find(|(mp, _)| mp.eq_ignore_ascii_case(p));
        if let Some((mp, payload)) = mock {
            println!("path: {}", mp);
            println!("size: {} bytes", payload.len());
            if _json {
                let out = serde_json::json!({
                    "schema_version": 1,
                    "mock": { "path": mp, "size": payload.len() }
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
        } else {
            bail!("mock not found: {}", p);
        }
    } else if let Some(_i) = id {
        bail!("mock show by --id not yet supported, use --path");
    } else {
        bail!("mock show: --path or --id required");
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
    fn mock_add_content_and_list() {
        let (_dir, state) = tmp_state();
        run_add(&["--path=C:\\fake\\token.txt".into(), "--content=hello".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let mocks = policy::db::mock_list(&db).unwrap();
        assert_eq!(mocks.len(), 1);
        assert_eq!(mocks[0].1, b"hello");
    }

    #[test]
    fn mock_add_file_source() {
        let (_dir, state) = tmp_state();
        let tmp_file = state.join("payload.bin");
        std::fs::write(&tmp_file, b"file content").unwrap();
        run_add(&[
            "--path=C:\\fake\\data.bin".into(),
            format!("--file={}", tmp_file.display()),
        ], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let mocks = policy::db::mock_list(&db).unwrap();
        assert_eq!(mocks[0].1, b"file content");
    }

    #[test]
    fn mock_add_base64_source() {
        let (_dir, state) = tmp_state();
        run_add(&[
            "--path=C:\\fake\\b64.dat".into(),
            "--base64=aGVsbG8=".into(),
        ], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let mocks = policy::db::mock_list(&db).unwrap();
        assert_eq!(mocks[0].1, b"hello");
    }

    #[test]
    fn mock_add_mutual_exclusion() {
        let (_dir, state) = tmp_state();
        let result = run_add(&[
            "--path=C:\\fake\\x".into(),
            "--content=a".into(),
            "--base64=Yg==".into(),
        ], &state);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn mock_remove_by_path() {
        let (_dir, state) = tmp_state();
        run_add(&["--path=C:\\fake\\del.txt".into(), "--content=x".into()], &state).unwrap();
        run_remove(&["--path=C:\\fake\\del.txt".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let mocks = policy::db::mock_list(&db).unwrap();
        assert!(mocks.is_empty());
    }

    #[test]
    fn mock_idempotent_auto_id() {
        let p1 = "C:\\Fake\\test.txt".to_lowercase();
        let id1 = crate::cli::id::generate_id("mock", &[&p1]);
        let id2 = crate::cli::id::generate_id("mock", &[&p1]);
        assert_eq!(id1, id2);
    }
}
