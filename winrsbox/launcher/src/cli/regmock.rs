use anyhow::{bail, Result};
use policy::db;
use policy::reg::{RegType, RegValue, RegData};

const HELP: &str = "\
winrsbox regmock — manage registry value mocks

Mocks return fake registry values without touching the real registry.

SUBCOMMANDS:
  add      Add a mock registry value
  remove   Remove a mock by --path
  list     List all registry mocks (--json)

OPTIONS:
  --path=KEY\\VALUE   Full path: registry key + value name [required]
  --type=TYPE         REG_SZ|REG_DWORD|REG_QWORD|REG_BINARY|REG_MULTI_SZ|REG_EXPAND_SZ
  --data=DATA         Value data (string for SZ, number for DWORD, base64 for BINARY)

EXAMPLES:
  winrsbox regmock add --path='HKLM\\Software\\Crypto\\MachineGuid' --type=REG_SZ --data='FAKE-GUID'
  winrsbox regmock add --path='HKCU\\Software\\App\\Version' --type=REG_DWORD --data=42
  winrsbox regmock remove --path='HKLM\\Software\\Crypto\\MachineGuid'
  winrsbox regmock list --json
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
        _ => bail!("regmock: unknown subcommand '{}'", sub),
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
    let path = find_arg(args, "--path=")
        .ok_or_else(|| anyhow::anyhow!("regmock add: --path required"))?
        .to_lowercase();
    let type_str = find_arg(args, "--type=")
        .ok_or_else(|| anyhow::anyhow!("regmock add: --type required"))?;
    let data_str = find_arg(args, "--data=").unwrap_or("");

    let typ = RegType::from_name(type_str)
        .ok_or_else(|| anyhow::anyhow!("invalid registry type '{type_str}'"))?;
    let data = match typ {
        RegType::Sz | RegType::ExpandSz => RegData::String(data_str.to_owned()),
        RegType::Dword => RegData::U32(data_str.parse().map_err(|_| anyhow::anyhow!("invalid DWORD: {data_str}"))?),
        RegType::Qword => RegData::U64(data_str.parse().map_err(|_| anyhow::anyhow!("invalid QWORD: {data_str}"))?),
        RegType::MultiSz => RegData::Strings(data_str.split("\\0").map(String::from).collect()),
        RegType::Binary => {
            use base64::Engine;
            let bytes = base64::prelude::BASE64_STANDARD.decode(data_str)
                .map_err(|e| anyhow::anyhow!("invalid base64: {e}"))?;
            RegData::Bytes(bytes)
        }
        _ => RegData::None,
    };

    let val = RegValue { typ, data };
    let payload = serde_json::to_vec(&val)?;
    db::reg_mock_upsert(&db, &path, &payload)?;
    println!("mock added: {path}");
    Ok(())
}

fn run_remove(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let path = find_arg(args, "--path=")
        .ok_or_else(|| anyhow::anyhow!("regmock remove: --path required"))?
        .to_lowercase();
    if !db::reg_mock_remove(&db, &path)? {
        bail!("regmock: mock '{}' not found", path);
    }
    Ok(())
}

fn run_list(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let db = super::open_db(state_dir)?;
    let mocks = db::reg_mock_list(&db)?;
    let json = has_flag(args, "--json");
    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "reg_mocks": mocks.iter().map(|(path, payload)| {
                let val: Option<RegValue> = serde_json::from_slice(payload).ok();
                serde_json::json!({
                    "path": path,
                    "type": val.as_ref().map(|v| v.typ.name()),
                    "data": val.as_ref().map(|v| v.to_json_value()["data"].clone()),
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        for (path, payload) in &mocks {
            let val: Option<RegValue> = serde_json::from_slice(payload).ok();
            println!("{}\t{}", path, val.map(|v| v.typ.name()).unwrap_or("?"));
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
    fn regmock_add_sz() {
        let (_dir, state) = tmp_state();
        run_add(&[
            "--path=hklm\\software\\crypto\\guid".into(),
            "--type=REG_SZ".into(),
            "--data=FAKE-GUID".into(),
        ], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let mocks = db::reg_mock_list(&db).unwrap();
        assert_eq!(mocks.len(), 1);
    }

    #[test]
    fn regmock_add_dword() {
        let (_dir, state) = tmp_state();
        run_add(&[
            "--path=hklm\\test\\count".into(),
            "--type=REG_DWORD".into(),
            "--data=42".into(),
        ], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        let mocks = db::reg_mock_list(&db).unwrap();
        let val: RegValue = serde_json::from_slice(&mocks[0].1).unwrap();
        assert_eq!(val.data, RegData::U32(42));
    }

    #[test]
    fn regmock_remove() {
        let (_dir, state) = tmp_state();
        run_add(&[
            "--path=hklm\\test\\val".into(), "--type=REG_SZ".into(), "--data=x".into(),
        ], &state).unwrap();
        run_remove(&["--path=hklm\\test\\val".into()], &state).unwrap();
        let db = super::super::open_db(&state).unwrap();
        assert!(db::reg_mock_list(&db).unwrap().is_empty());
    }

    #[test]
    fn regmock_invalid_type_errors() {
        let (_dir, state) = tmp_state();
        let result = run_add(&[
            "--path=hklm\\test\\val".into(), "--type=BOGUS".into(), "--data=x".into(),
        ], &state);
        assert!(result.is_err());
    }
}
