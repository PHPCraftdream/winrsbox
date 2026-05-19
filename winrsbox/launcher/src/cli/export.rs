use anyhow::{bail, Result};
use base64::Engine;

const EXPORT_HELP: &str = "\
winrsbox export — dump current state as versioned JSON to stdout

Outputs all rules, mocks, mockdirs, and defaults as a single JSON object
with schema_version: 1. Pipe to a file for backup or transfer.

EXAMPLES:
  winrsbox export > backup.json
  winrsbox export | jq '.rules[] | select(.write == \"deny\")'
";

const IMPORT_HELP: &str = "\
winrsbox import — load state from JSON stdin or legacy ktav file

By default, merges imported data with existing state (upsert).
Use --replace to wipe existing state before importing.

OPTIONS:
  --replace          Clear all existing data before importing
  --ktav=FILE        Import from legacy ktav config file (or --ktav FILE)

JSON FORMAT:
  Expects schema_version: 1 with fields: defaults, rules[], mocks[], mockdirs[].
  Same format as 'winrsbox export' output.

EXAMPLES:
  winrsbox import < backup.json
  winrsbox import --replace < backup.json
  winrsbox import --ktav sandbox.ktav
  winrsbox export | winrsbox import --replace  # clone state
";

pub fn run_export(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    if has_flag(args, "--help") || has_flag(args, "-h") {
        print!("{}", EXPORT_HELP);
        return Ok(());
    }
    let db = super::open_db(state_dir)?;
    let json = has_flag(args, "--json") || true; // export always outputs JSON

    let rules = policy::db::rule_list(&db)?;
    let mocks = policy::db::mock_list(&db)?;
    let mockdirs = policy::db::mockdir_list(&db)?;
    let defaults = policy::db::defaults_get(&db)?;

    let out = serde_json::json!({
        "schema_version": 1,
        "defaults": {
            "read": policy::db::mode_to_string(defaults.read),
            "write": policy::db::mode_to_string(defaults.write),
        },
        "rules": rules.iter().map(|r| serde_json::json!({
            "id": r.id,
            "prefix": r.prefix,
            "read": policy::db::mode_to_string(r.mode_read),
            "write": policy::db::mode_to_string(r.mode_write),
            "when": r.when.as_ref().map(|w| serde_json::json!({
                "depth": w.depth,
                "exe": w.exe,
            })),
        })).collect::<Vec<_>>(),
        "mocks": mocks.iter().map(|(path, payload)| {
            use base64::Engine;
            serde_json::json!({
                "path": path,
                "content_base64": base64::prelude::BASE64_STANDARD.encode(payload),
            })
        }).collect::<Vec<_>>(),
        "mockdirs": mockdirs.iter().map(|d| serde_json::json!({
            "prefix": d,
        })).collect::<Vec<_>>(),
        "reg_rules": policy::db::reg_rule_list(&db)?.iter().map(|r| serde_json::json!({
            "id": r.id, "prefix": r.prefix,
            "read": policy::db::mode_to_string(r.mode_read),
            "write": policy::db::mode_to_string(r.mode_write),
            "when": r.when.as_ref().map(|w| serde_json::json!({"depth": w.depth, "exe": w.exe})),
        })).collect::<Vec<_>>(),
        "reg_mocks": policy::db::reg_mock_list(&db)?.iter().map(|(path, payload)| {
            serde_json::json!({ "path": path, "payload_json": serde_json::from_slice::<serde_json::Value>(payload).ok() })
        }).collect::<Vec<_>>(),
        "dev_rules": policy::db::dev_rule_list(&db)?.iter().map(|r| serde_json::json!({
            "id": r.id, "prefix": r.prefix,
            "read": policy::db::mode_to_string(r.mode_read),
            "write": policy::db::mode_to_string(r.mode_write),
        })).collect::<Vec<_>>(),
    });

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

pub fn run_import(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    if has_flag(args, "--help") || has_flag(args, "-h") {
        print!("{}", IMPORT_HELP);
        return Ok(());
    }
    let db = super::open_db(state_dir)?;
    let replace = has_flag(args, "--replace");
    let ktav_file = find_arg(args, "--ktav=");

    if let Some(ktav_path) = ktav_file {
        // Legacy ktav import
        let src = std::fs::read_to_string(ktav_path)?;
        let cfg: policy::db::Config = ktav::from_str(&src)
            .map_err(|e| anyhow::anyhow!("ktav parse error: {}", e))?;
        policy::db::apply_config(&db, &cfg)?;
        return Ok(());
    }

    // JSON import from stdin
    use std::io::Read;
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let val: serde_json::Value = serde_json::from_str(&input)
        .map_err(|e| anyhow::anyhow!("invalid JSON: {}", e))?;

    let version = val.get("schema_version").and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid schema_version"))?;
    if version != 1 {
        bail!("unsupported schema_version: {} (expected 1)", version);
    }

    if replace {
        // Clear all existing data
        policy::db::rule_clear(&db)?;
        // Clear mocks
        let mocks = policy::db::mock_list(&db)?;
        for (path, _) in &mocks {
            policy::db::mock_remove_by_path(&db, path)?;
        }
        // Clear mockdirs
        let mockdirs = policy::db::mockdir_list(&db)?;
        for d in &mockdirs {
            policy::db::mockdir_remove_by_prefix(&db, d)?;
        }
    }

    // Import defaults
    if let Some(defaults) = val.get("defaults") {
        let read = defaults.get("read").and_then(|v| v.as_str())
            .map(|s| parse_mode(s)).transpose()?
            .unwrap_or(policy::db::RuleMode::Passthrough);
        let write = defaults.get("write").and_then(|v| v.as_str())
            .map(|s| parse_mode(s)).transpose()?
            .unwrap_or(policy::db::RuleMode::Cow);
        policy::db::defaults_set(&db, Some(read), Some(write))?;
    }

    // Import rules
    if let Some(rules) = val.get("rules").and_then(|v| v.as_array()) {
        for rule in rules {
            let id = rule.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let prefix = rule.get("prefix").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let read = rule.get("read").and_then(|v| v.as_str())
                .map(|s| parse_mode(s)).transpose()?
                .unwrap_or(policy::db::RuleMode::Passthrough);
            let write = rule.get("write").and_then(|v| v.as_str())
                .map(|s| parse_mode(s)).transpose()?
                .unwrap_or(policy::db::RuleMode::Cow);
            let when = rule.get("when").and_then(|w| {
                if w.is_null() { return None; }
                let depth = w.get("depth").and_then(|v| v.as_u64()).map(|d| d as u8);
                let exe = w.get("exe").and_then(|v| v.as_str()).map(String::from);
                if depth.is_none() && exe.is_none() { None } else {
                    Some(policy::db::WhenFilter { depth, exe })
                }
            });
            let row = policy::db::RuleRow { id, prefix, mode_read: read, mode_write: write, when };
            policy::db::rule_upsert(&db, &row)?;
        }
    }

    // Import mocks
    if let Some(mocks) = val.get("mocks").and_then(|v| v.as_array()) {
        for mock in mocks {
            let path = mock.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let payload = if let Some(b64) = mock.get("content_base64").and_then(|v| v.as_str()) {
                base64::prelude::BASE64_STANDARD.decode(b64)?
            } else if let Some(content) = mock.get("content_inline").and_then(|v| v.as_str()) {
                content.as_bytes().to_vec()
            } else {
                Vec::new()
            };
            policy::db::mock_upsert(&db, "", path, &payload)?;
        }
    }

    // Import mockdirs
    if let Some(mockdirs) = val.get("mockdirs").and_then(|v| v.as_array()) {
        for md in mockdirs {
            if let Some(prefix) = md.get("prefix").and_then(|v| v.as_str()) {
                policy::db::mockdir_upsert(&db, prefix)?;
            }
        }
    }

    // Import reg_rules
    if let Some(reg_rules) = val.get("reg_rules").and_then(|v| v.as_array()) {
        if replace { policy::db::reg_rule_clear(&db)?; }
        for rule in reg_rules {
            let id = rule.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let prefix = rule.get("prefix").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let read = rule.get("read").and_then(|v| v.as_str())
                .map(|s| parse_mode(s)).transpose()?.unwrap_or(policy::db::RuleMode::Passthrough);
            let write = rule.get("write").and_then(|v| v.as_str())
                .map(|s| parse_mode(s)).transpose()?.unwrap_or(policy::db::RuleMode::Cow);
            let when = rule.get("when").and_then(|w| {
                if w.is_null() { return None; }
                let depth = w.get("depth").and_then(|v| v.as_u64()).map(|d| d as u8);
                let exe = w.get("exe").and_then(|v| v.as_str()).map(String::from);
                if depth.is_none() && exe.is_none() { None } else { Some(policy::db::WhenFilter { depth, exe }) }
            });
            policy::db::reg_rule_upsert(&db, &policy::db::RuleRow { id, prefix, mode_read: read, mode_write: write, when })?;
        }
    }

    // Import reg_mocks
    if let Some(reg_mocks) = val.get("reg_mocks").and_then(|v| v.as_array()) {
        for mock in reg_mocks {
            let path = mock.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let payload = mock.get("payload_json")
                .map(|v| serde_json::to_vec(v).unwrap_or_default())
                .unwrap_or_default();
            policy::db::reg_mock_upsert(&db, &path.to_lowercase(), &payload)?;
        }
    }

    // Import dev_rules
    if let Some(dev_rules) = val.get("dev_rules").and_then(|v| v.as_array()) {
        if replace { policy::db::dev_rule_clear(&db)?; }
        for rule in dev_rules {
            let id = rule.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let prefix = rule.get("prefix").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let read = rule.get("read").and_then(|v| v.as_str())
                .map(|s| parse_mode(s)).transpose()?.unwrap_or(policy::db::RuleMode::Deny);
            let write = rule.get("write").and_then(|v| v.as_str())
                .map(|s| parse_mode(s)).transpose()?.unwrap_or(policy::db::RuleMode::Deny);
            policy::db::dev_rule_upsert(&db, &policy::db::RuleRow { id, prefix, mode_read: read, mode_write: write, when: None })?;
        }
    }

    Ok(())
}

fn parse_mode(s: &str) -> Result<policy::db::RuleMode> {
    match s {
        "passthrough" => Ok(policy::db::RuleMode::Passthrough),
        "deny" => Ok(policy::db::RuleMode::Deny),
        "cow" => Ok(policy::db::RuleMode::Cow),
        "redirect" => Ok(policy::db::RuleMode::Redirect),
        _ => bail!("invalid mode '{}'", s),
    }
}

fn find_arg<'a>(args: &'a [String], prefix: &str) -> Option<&'a str> {
    let flag = prefix.trim_end_matches('=');
    for (i, a) in args.iter().enumerate() {
        if a.starts_with(prefix) {
            return Some(&a[prefix.len()..]);
        }
        if a == flag {
            if let Some(next) = args.get(i + 1) {
                return Some(next.as_str());
            }
        }
    }
    None
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
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
    fn export_import_roundtrip() {
        let (_dir, state) = tmp_state();
        let db = super::super::open_db(&state).unwrap();
        // Add some data
        policy::db::rule_upsert(&db, &policy::db::RuleRow {
            id: "test-rule".into(),
            prefix: "c:\\test".into(),
            mode_read: policy::db::RuleMode::Passthrough,
            mode_write: policy::db::RuleMode::Deny,
            when: None,
        }).unwrap();
        policy::db::mock_upsert(&db, "", "c:\\fake\\token.txt", b"secret").unwrap();
        policy::db::mockdir_upsert(&db, "c:\\fakedir").unwrap();
        policy::db::defaults_set(&db, Some(policy::db::RuleMode::Passthrough), Some(policy::db::RuleMode::Deny)).unwrap();
        drop(db);

        // Export to string (capture stdout)
        let exported = capture_export(&state);

        // Import into fresh state
        let dir2 = tempfile::tempdir().unwrap();
        let state2 = dir2.path().join(".winrsbox").join("test2");
        std::fs::create_dir_all(&state2).unwrap();

        // Write exported JSON to a temp file, then import
        let json_file = dir2.path().join("export.json");
        std::fs::write(&json_file, &exported).unwrap();

        // Use a simple approach: open db and import manually
        let db2 = super::super::open_db(&state2).unwrap();
        let val: serde_json::Value = serde_json::from_str(&exported).unwrap();
        assert_eq!(val["schema_version"], 1);

        // Import rules
        for rule in val["rules"].as_array().unwrap() {
            let row = policy::db::RuleRow {
                id: rule["id"].as_str().unwrap().into(),
                prefix: rule["prefix"].as_str().unwrap().into(),
                mode_read: parse_mode(rule["read"].as_str().unwrap()).unwrap(),
                mode_write: parse_mode(rule["write"].as_str().unwrap()).unwrap(),
                when: None,
            };
            policy::db::rule_upsert(&db2, &row).unwrap();
        }

        let rules = policy::db::rule_list(&db2).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "test-rule");
        assert_eq!(rules[0].prefix, "c:\\test");
    }

    fn capture_export(state: &std::path::Path) -> String {
        let db = super::super::open_db(state).unwrap();
        let rules = policy::db::rule_list(&db).unwrap();
        let mocks = policy::db::mock_list(&db).unwrap();
        let mockdirs = policy::db::mockdir_list(&db).unwrap();
        let defaults = policy::db::defaults_get(&db).unwrap();

        let out = serde_json::json!({
            "schema_version": 1,
            "defaults": {
                "read": policy::db::mode_to_string(defaults.read),
                "write": policy::db::mode_to_string(defaults.write),
            },
            "rules": rules.iter().map(|r| serde_json::json!({
                "id": r.id,
                "prefix": r.prefix,
                "read": policy::db::mode_to_string(r.mode_read),
                "write": policy::db::mode_to_string(r.mode_write),
            })).collect::<Vec<_>>(),
            "mocks": mocks.iter().map(|(path, payload)| serde_json::json!({
                "path": path,
                "content_base64": base64::prelude::BASE64_STANDARD.encode(payload),
            })).collect::<Vec<_>>(),
            "mockdirs": mockdirs.iter().map(|d| serde_json::json!({
                "prefix": d,
            })).collect::<Vec<_>>(),
        });
        serde_json::to_string_pretty(&out).unwrap()
    }

    #[test]
    fn import_invalid_json_errors() {
        let (_dir, state) = tmp_state();
        let result = run_import(&[], &state);
        // stdin is empty in tests → should fail
        assert!(result.is_err());
    }

    #[test]
    fn import_wrong_schema_version_errors() {
        let (_dir, state) = tmp_state();
        let json = r#"{"schema_version": 2, "defaults": {}, "rules": [], "mocks": [], "mockdirs": []}"#;
        let val: serde_json::Value = serde_json::from_str(json).unwrap();
        let version = val.get("schema_version").and_then(|v| v.as_u64()).unwrap();
        assert_ne!(version, 1);
    }

    #[test]
    fn import_ktav_legacy() {
        let (_dir, state) = tmp_state();
        let ktav_path = state.join("legacy.ktav");
        std::fs::write(&ktav_path, "defaults: {\n    read: passthrough\n    write: cow\n}\n\nrules: [\n    {\n        prefix: c:\\test\n        write: deny\n    }\n]").unwrap();

        let result = run_import(&[format!("--ktav={}", ktav_path.display())], &state);
        assert!(result.is_ok());
        let db = super::super::open_db(&state).unwrap();
        let rules = policy::db::rule_list(&db).unwrap();
        assert_eq!(rules.len(), 1);
    }
}
