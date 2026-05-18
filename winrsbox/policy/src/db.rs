use crate::path::{pattern_matches_exact, pattern_matches_prefix, pattern_specificity};
use redb::{ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

pub const RULES: TableDefinition<&str, &[u8]> = TableDefinition::new("rules");
pub const MOCKS: TableDefinition<&str, &[u8]> = TableDefinition::new("mocks");
pub const MOCK_DIRS: TableDefinition<&str, ()> = TableDefinition::new("mock_dirs");
pub const OVERLAY_IDX: TableDefinition<&str, &str> = TableDefinition::new("overlay_idx");

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RuleMode { Passthrough, Deny, Cow, Redirect }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleRow {
    pub mode_read: RuleMode,
    pub mode_write: RuleMode,
    pub when: Option<WhenFilter>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Config {
    pub sandbox_root: Option<String>,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub rules: Vec<RuleEntry>,
    #[serde(default)]
    pub mocks: Vec<MockEntry>,
    #[serde(default)]
    pub mock_dirs: Vec<MockDirEntry>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Defaults {
    #[serde(default = "default_passthrough")]
    pub read: String,
    #[serde(default = "default_cow")]
    pub write: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WhenFilter {
    pub depth: Option<u8>,
    pub exe: Option<String>,
}

fn default_passthrough() -> String { "passthrough".into() }
fn default_cow() -> String { "cow".into() }

#[derive(Debug, Deserialize)]
pub struct RuleEntry {
    pub prefix: String,
    pub read: Option<String>,
    pub write: Option<String>,
    pub when: Option<WhenFilter>,
}

#[derive(Debug, Deserialize)]
pub struct MockEntry {
    pub path: String,
    pub content_inline: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MockDirEntry {
    pub prefix: String,
}

pub fn parse_mode(s: &str, default: RuleMode) -> RuleMode {
    match s {
        "passthrough" | "allow" => RuleMode::Passthrough,
        "deny" => RuleMode::Deny,
        "cow" => RuleMode::Cow,
        "redirect" => RuleMode::Redirect,
        _ => default,
    }
}

pub fn apply_config(db: &redb::Database, cfg: &Config) -> Result<(), crate::PolicyError> {
    let default_read = parse_mode(&cfg.defaults.read, RuleMode::Passthrough);
    let default_write = parse_mode(&cfg.defaults.write, RuleMode::Cow);

    let txn = db.begin_write()?;
    {
        let mut rules = txn.open_table(RULES)?;
        let mut mocks = txn.open_table(MOCKS)?;
        let mut mock_dirs = txn.open_table(MOCK_DIRS)?;

        // Wipe old entries so removed config items don't linger.
        // redb's Table::retain takes a closure; the empty closure removes all.
        // We use drain to iterate and remove.
        let old_rule_keys: Vec<String> = rules
            .iter()?
            .filter_map(|r| r.ok())
            .map(|(k, _)| k.value().to_owned())
            .collect();
        for k in old_rule_keys {
            rules.remove(k.as_str())?;
        }
        let old_mock_keys: Vec<String> = mocks
            .iter()?
            .filter_map(|r| r.ok())
            .map(|(k, _)| k.value().to_owned())
            .collect();
        for k in old_mock_keys {
            mocks.remove(k.as_str())?;
        }
        let old_md_keys: Vec<String> = mock_dirs
            .iter()?
            .filter_map(|r| r.ok())
            .map(|(k, _)| k.value().to_owned())
            .collect();
        for k in old_md_keys {
            mock_dirs.remove(k.as_str())?;
        }

        // Default rule (empty key = catch-all)
        let default_row = RuleRow { mode_read: default_read, mode_write: default_write, when: None };
        let encoded = bincode::serde::encode_to_vec(&default_row, bincode::config::standard())
            .map_err(|e| crate::PolicyError::Ktav(format!("serialize: {e}")))?;
        rules.insert("", encoded.as_slice())?;

        for rule in &cfg.rules {
            let mr = parse_mode(rule.read.as_deref().unwrap_or("passthrough"), default_read);
            let mw = parse_mode(rule.write.as_deref().unwrap_or("cow"), default_write);
            let row = RuleRow { mode_read: mr, mode_write: mw, when: rule.when.clone() };
            let enc = bincode::serde::encode_to_vec(&row, bincode::config::standard())
                .map_err(|e| crate::PolicyError::Ktav(format!("serialize: {e}")))?;
            let key = rule.prefix.to_lowercase();
            rules.insert(key.as_str(), enc.as_slice())?;
        }

        for mock in &cfg.mocks {
            let payload = mock.content_inline.as_deref().unwrap_or("").as_bytes().to_vec();
            let key = mock.path.to_lowercase();
            mocks.insert(key.as_str(), payload.as_slice())?;
        }

        for md in &cfg.mock_dirs {
            let key = md.prefix.to_lowercase();
            mock_dirs.insert(key.as_str(), ())?;
        }
    }
    txn.commit()?;
    Ok(())
}

fn decode_rule(bytes: &[u8]) -> Option<RuleRow> {
    bincode::serde::decode_from_slice::<RuleRow, _>(bytes, bincode::config::standard())
        .ok()
        .map(|(r, _)| r)
}

/// Find the most specific rule matching `lower_path`. Iterates every rule
/// (rules support `*` / `?` globs per path segment) and returns the one with
/// the highest specificity. Falls back to the default (empty) rule.
pub fn best_rule_match(
    txn: &redb::ReadTransaction,
    lower_path: &str,
    depth: Option<u8>,
    exe_lower: Option<&str>,
) -> Option<RuleRow> {
    let table = txn.open_table(RULES).ok()?;
    let mut best: Option<(usize, RuleRow)> = None;
    let mut default_row: Option<RuleRow> = None;

    for entry in table.iter().ok()? {
        let Ok((key, value)) = entry else { continue };
        let pattern = key.value();
        if pattern.is_empty() {
            default_row = decode_rule(value.value());
            continue;
        }
        if !pattern_matches_prefix(pattern, lower_path) {
            continue;
        }
        let Some(row) = decode_rule(value.value()) else { continue };
        // Apply when filter
        if let Some(ref when) = row.when {
            if let Some(min_depth) = when.depth {
                // depth filter: rule applies at this depth and deeper (>=)
                // None depth (legacy callers) treated as max-permissive: always pass
                if depth.is_some() && depth.unwrap() < min_depth {
                    continue;
                }
            }
            if let Some(ref exe_pattern) = when.exe {
                if exe_lower.is_none() || !pattern_matches_exact(exe_pattern, exe_lower.unwrap()) {
                    continue;
                }
            }
        }
        let mut spec = pattern_specificity(pattern);
        if row.when.is_some() {
            spec += 1; // bonus for having a when filter
        }
        if let Some(ref when) = row.when {
            if let Some(ref exe) = when.exe {
                spec += pattern_specificity(exe);
            }
        }
        match &best {
            None => best = Some((spec, row)),
            Some((s, _)) if spec > *s => best = Some((spec, row)),
            _ => {}
        }
    }
    best.map(|(_, r)| r).or(default_row)
}

/// Find a mock payload that exactly matches `lower_path` (with glob support
/// in the mock key — `c:\fake\*.txt` will match any file in `c:\fake\` with
/// `.txt` extension). Returns the raw payload bytes.
pub fn find_mock_payload(txn: &redb::ReadTransaction, lower_path: &str) -> Option<Vec<u8>> {
    let table = txn.open_table(MOCKS).ok()?;
    // Fast path: exact literal match.
    if let Ok(Some(v)) = table.get(lower_path) {
        return Some(v.value().to_vec());
    }
    // Slow path: iterate, look for glob matches.
    for entry in table.iter().ok()? {
        let Ok((key, value)) = entry else { continue };
        let pattern = key.value();
        if pattern_matches_exact(pattern, lower_path) {
            return Some(value.value().to_vec());
        }
    }
    None
}

/// Check if `lower_path` falls under any configured mock_dirs prefix.
/// Returns the matched pattern (for diagnostic) when found.
pub fn matched_mock_dir(txn: &redb::ReadTransaction, lower_path: &str) -> Option<String> {
    let table = txn.open_table(MOCK_DIRS).ok()?;
    let mut best: Option<(usize, String)> = None;
    for entry in table.iter().ok()? {
        let Ok((key, _)) = entry else { continue };
        let pattern = key.value().to_owned();
        if !pattern_matches_prefix(&pattern, lower_path) {
            continue;
        }
        let spec = pattern_specificity(&pattern);
        match &best {
            None => best = Some((spec, pattern)),
            Some((s, _)) if spec > *s => best = Some((spec, pattern)),
            _ => {}
        }
    }
    best.map(|(_, p)| p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mode_passthrough() {
        assert!(matches!(parse_mode("passthrough", RuleMode::Deny), RuleMode::Passthrough));
    }

    #[test]
    fn parse_mode_allow() {
        assert!(matches!(parse_mode("allow", RuleMode::Deny), RuleMode::Passthrough));
    }

    #[test]
    fn parse_mode_deny() {
        assert!(matches!(parse_mode("deny", RuleMode::Passthrough), RuleMode::Deny));
    }

    #[test]
    fn parse_mode_cow() {
        assert!(matches!(parse_mode("cow", RuleMode::Passthrough), RuleMode::Cow));
    }

    #[test]
    fn parse_mode_redirect() {
        assert!(matches!(parse_mode("redirect", RuleMode::Passthrough), RuleMode::Redirect));
    }

    #[test]
    fn parse_mode_unknown_returns_default() {
        assert!(matches!(parse_mode("bogus", RuleMode::Cow), RuleMode::Cow));
        assert!(matches!(parse_mode("", RuleMode::Deny), RuleMode::Deny));
    }

    #[test]
    fn decode_rule_roundtrip() {
        let row = RuleRow { mode_read: RuleMode::Cow, mode_write: RuleMode::Deny, when: None };
        let enc = bincode::serde::encode_to_vec(&row, bincode::config::standard()).unwrap();
        let dec = decode_rule(&enc).unwrap();
        assert!(matches!(dec.mode_read, RuleMode::Cow));
        assert!(matches!(dec.mode_write, RuleMode::Deny));
    }

    #[test]
    fn decode_rule_garbage_returns_none() {
        assert!(decode_rule(b"\xde\xad\xbe\xef").is_none());
        assert!(decode_rule(b"").is_none());
    }

    // Table-driven equivalent of the parse_mode_* tests above, kept as a
    // template for future enum→string mappings.
    #[rstest::rstest]
    #[case("passthrough", RuleMode::Deny, RuleMode::Passthrough)]
    #[case("allow",       RuleMode::Deny, RuleMode::Passthrough)]
    #[case("deny",        RuleMode::Passthrough, RuleMode::Deny)]
    #[case("cow",         RuleMode::Passthrough, RuleMode::Cow)]
    #[case("redirect",    RuleMode::Passthrough, RuleMode::Redirect)]
    #[case("bogus",       RuleMode::Cow, RuleMode::Cow)]
    #[case("",            RuleMode::Deny, RuleMode::Deny)]
    fn parse_mode_table(#[case] input: &str, #[case] default: RuleMode, #[case] expected: RuleMode) {
        assert!(matches!(parse_mode(input, default), m if std::mem::discriminant(&m) == std::mem::discriminant(&expected)));
    }

    // ── best_rule_match tests ───────────────────────────────────────────────

    fn make_db_with_rules(rules: &[(&str, RuleMode, RuleMode)]) -> (tempfile::TempDir, redb::Database) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.redb");
        let db = redb::Database::create(&db_path).unwrap();
        {
            let txn = db.begin_write().unwrap();
            {
                let mut table = txn.open_table(RULES).unwrap();
                let default_row = RuleRow { mode_read: RuleMode::Passthrough, mode_write: RuleMode::Cow, when: None };
                let enc = bincode::serde::encode_to_vec(&default_row, bincode::config::standard()).unwrap();
                table.insert("", enc.as_slice()).unwrap();
                for (prefix, mr, mw) in rules {
                    let row = RuleRow { mode_read: *mr, mode_write: *mw, when: None };
                    let enc = bincode::serde::encode_to_vec(&row, bincode::config::standard()).unwrap();
                    table.insert(prefix.to_lowercase().as_str(), enc.as_slice()).unwrap();
                }
            }
            txn.commit().unwrap();
        }
        (dir, db)
    }

    #[test]
    fn best_rule_match_default_only() {
        let (_dir, db) = make_db_with_rules(&[]);
        let txn = db.begin_read().unwrap();
        let rule = best_rule_match(&txn, r"c:\unknown\path", None, None).unwrap();
        assert!(matches!(rule.mode_read, RuleMode::Passthrough));
        assert!(matches!(rule.mode_write, RuleMode::Cow));
    }

    #[test]
    fn best_rule_match_exact_prefix() {
        let (_dir, db) = make_db_with_rules(&[
            (r"c:\test", RuleMode::Deny, RuleMode::Deny),
        ]);
        let txn = db.begin_read().unwrap();
        let rule = best_rule_match(&txn, r"c:\test\sub\file", None, None).unwrap();
        assert!(matches!(rule.mode_read, RuleMode::Deny));
    }

    #[test]
    fn best_rule_match_most_specific_wins() {
        let (_dir, db) = make_db_with_rules(&[
            (r"c:\users", RuleMode::Passthrough, RuleMode::Cow),
            (r"c:\users\alice\.ssh", RuleMode::Deny, RuleMode::Deny),
        ]);
        let txn = db.begin_read().unwrap();
        let rule = best_rule_match(&txn, r"c:\users\alice\.ssh\id_rsa", None, None).unwrap();
        assert!(matches!(rule.mode_read, RuleMode::Deny));
    }

    #[test]
    fn best_rule_match_glob_pattern() {
        let (_dir, db) = make_db_with_rules(&[
            (r"c:\users\*", RuleMode::Deny, RuleMode::Deny),
        ]);
        let txn = db.begin_read().unwrap();
        let rule = best_rule_match(&txn, r"c:\users\alice\file", None, None).unwrap();
        assert!(matches!(rule.mode_read, RuleMode::Deny));
    }

    #[test]
    fn best_rule_match_no_match_returns_default() {
        let (_dir, db) = make_db_with_rules(&[
            (r"c:\restricted", RuleMode::Deny, RuleMode::Deny),
        ]);
        let txn = db.begin_read().unwrap();
        let rule = best_rule_match(&txn, r"c:\public\file", None, None).unwrap();
        assert!(matches!(rule.mode_read, RuleMode::Passthrough));
    }

    // ── find_mock_payload tests ─────────────────────────────────────────────

    fn make_db_with_mocks(mocks: &[(&str, &[u8])]) -> (tempfile::TempDir, redb::Database) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.redb");
        let db = redb::Database::create(&db_path).unwrap();
        {
            let txn = db.begin_write().unwrap();
            {
                let mut table = txn.open_table(MOCKS).unwrap();
                for (path, payload) in mocks {
                    table.insert(path.to_lowercase().as_str(), *payload).unwrap();
                }
            }
            txn.commit().unwrap();
        }
        (dir, db)
    }

    #[test]
    fn find_mock_exact_match() {
        let (_dir, db) = make_db_with_mocks(&[
            (r"c:\fake\token.txt", b"secret"),
        ]);
        let txn = db.begin_read().unwrap();
        let payload = find_mock_payload(&txn, r"c:\fake\token.txt").unwrap();
        assert_eq!(payload, b"secret");
    }

    #[test]
    fn find_mock_glob_match() {
        let (_dir, db) = make_db_with_mocks(&[
            (r"c:\fake\*.txt", b"text_file"),
        ]);
        let txn = db.begin_read().unwrap();
        let payload = find_mock_payload(&txn, r"c:\fake\token.txt").unwrap();
        assert_eq!(payload, b"text_file");
    }

    #[test]
    fn find_mock_no_match() {
        let (_dir, db) = make_db_with_mocks(&[
            (r"c:\fake\token.txt", b"secret"),
        ]);
        let txn = db.begin_read().unwrap();
        assert!(find_mock_payload(&txn, r"c:\fake\other.exe").is_none());
    }

    #[test]
    fn find_mock_empty_payload() {
        let (_dir, db) = make_db_with_mocks(&[
            (r"c:\empty.dat", b""),
        ]);
        let txn = db.begin_read().unwrap();
        let payload = find_mock_payload(&txn, r"c:\empty.dat").unwrap();
        assert!(payload.is_empty());
    }

    // ── matched_mock_dir tests ──────────────────────────────────────────────

    fn make_db_with_mock_dirs(dirs: &[&str]) -> (tempfile::TempDir, redb::Database) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.redb");
        let db = redb::Database::create(&db_path).unwrap();
        {
            let txn = db.begin_write().unwrap();
            {
                let mut table = txn.open_table(MOCK_DIRS).unwrap();
                for prefix in dirs {
                    table.insert(prefix.to_lowercase().as_str(), ()).unwrap();
                }
            }
            txn.commit().unwrap();
        }
        (dir, db)
    }

    #[test]
    fn matched_mock_dir_hit() {
        let (_dir, db) = make_db_with_mock_dirs(&[r"c:\fake"]);
        let txn = db.begin_read().unwrap();
        let result = matched_mock_dir(&txn, r"c:\fake\sub\file.txt");
        assert!(result.is_some());
    }

    #[test]
    fn matched_mock_dir_miss() {
        let (_dir, db) = make_db_with_mock_dirs(&[r"c:\fake"]);
        let txn = db.begin_read().unwrap();
        assert!(matched_mock_dir(&txn, r"c:\real\file.txt").is_none());
    }

    #[test]
    fn matched_mock_dir_most_specific() {
        let (_dir, db) = make_db_with_mock_dirs(&[
            r"c:\fake",
            r"c:\fake\deep",
        ]);
        let txn = db.begin_read().unwrap();
        let result = matched_mock_dir(&txn, r"c:\fake\deep\file.txt");
        assert_eq!(result.unwrap(), r"c:\fake\deep");
    }

    #[test]
    fn matched_mock_dir_empty_db() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.redb");
        let db = redb::Database::create(&db_path).unwrap();
        {
            let txn = db.begin_write().unwrap();
            {
                let _ = txn.open_table(MOCK_DIRS).unwrap();
            }
            txn.commit().unwrap();
        }
        let txn = db.begin_read().unwrap();
        assert!(matched_mock_dir(&txn, r"c:\anything").is_none());
    }

    // ── apply_config tests ──────────────────────────────────────────────────

    #[test]
    fn when_filter_deserialization_from_ktav() {
        let ktav = r#"
defaults: {
    read: passthrough
    write: cow
}

rules: [
    {
        prefix: c:\test
        write: deny
        when: {
            depth: 1
            exe: c:\bin\target-app.exe
        }
    }
]
"#;
        let cfg: Config = ktav::from_str(ktav).unwrap();
        assert_eq!(cfg.rules.len(), 1);
        let rule = &cfg.rules[0];
        assert_eq!(rule.prefix, r"c:\test");
        let when = rule.when.as_ref().unwrap();
        assert_eq!(when.depth, Some(1));
        assert_eq!(when.exe.as_deref(), Some(r"c:\bin\target-app.exe"));
    }

    #[test]
    fn when_filter_depth_only_deserialization() {
        let ktav = "defaults: {\n\
            \x20   read: passthrough\n\
            \x20   write: cow\n\
            }\n\
            \n\
            rules: [\n\
            \x20   {\n\
            \x20       prefix: c:\\test\n\
            \x20       write: deny\n\
            \x20       when: {\n\
            \x20           depth: 2\n\
            \x20       }\n\
            \x20   }\n\
            ]";
        let cfg: Config = ktav::from_str(ktav).unwrap();
        let when = cfg.rules[0].when.as_ref().unwrap();
        assert_eq!(when.depth, Some(2));
        assert_eq!(when.exe, None);
    }

    #[test]
    fn when_filter_exe_only_deserialization() {
        let ktav = "defaults: {\n\
            \x20   read: passthrough\n\
            \x20   write: cow\n\
            }\n\
            \n\
            rules: [\n\
            \x20   {\n\
            \x20       prefix: c:\\test\n\
            \x20       write: deny\n\
            \x20       when: {\n\
            \x20           exe: c:\\app.exe\n\
            \x20       }\n\
            \x20   }\n\
            ]";
        let cfg: Config = ktav::from_str(ktav).unwrap();
        let when = cfg.rules[0].when.as_ref().unwrap();
        assert_eq!(when.depth, None);
        assert_eq!(when.exe.as_deref(), Some(r"c:\app.exe"));
    }

    #[test]
    fn rule_without_when_is_none() {
        let ktav = "defaults: {\n\
        \x20   read: passthrough\n\
        \x20   write: cow\n\
        }\n\
        \n\
        rules: [\n\
        \x20   {\n\
        \x20       prefix: c:\\test\n\
        \x20       write: deny\n\
        \x20   }\n\
        ]";
        let cfg: Config = ktav::from_str(ktav).unwrap();
        assert!(cfg.rules[0].when.is_none());
    }

    #[test]
    fn apply_config_replaces_rules() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.redb");
        let db = redb::Database::create(&db_path).unwrap();
        {
            let txn = db.begin_write().unwrap();
            {
                txn.open_table(RULES).unwrap();
                txn.open_table(MOCKS).unwrap();
                txn.open_table(MOCK_DIRS).unwrap();
            }
            txn.commit().unwrap();
        }

        let cfg1 = Config {
            sandbox_root: None,
            defaults: Defaults { read: "passthrough".into(), write: "cow".into() },
            rules: vec![RuleEntry { prefix: r"c:\old".into(), read: Some("deny".into()), write: None, when: None }],
            mocks: vec![],
            mock_dirs: vec![],
        };
        apply_config(&db, &cfg1).unwrap();

        let cfg2 = Config {
            sandbox_root: None,
            defaults: Defaults { read: "passthrough".into(), write: "cow".into() },
            rules: vec![RuleEntry { prefix: r"c:\new".into(), read: Some("deny".into()), write: None, when: None }],
            mocks: vec![],
            mock_dirs: vec![],
        };
        apply_config(&db, &cfg2).unwrap();

        let txn = db.begin_read().unwrap();
        // Old rule should be gone
        let rule = best_rule_match(&txn, r"c:\old\path", None, None);
        assert!(matches!(rule.unwrap().mode_read, RuleMode::Passthrough));

        // New rule should match
        let rule = best_rule_match(&txn, r"c:\new\path", None, None);
        assert!(matches!(rule.unwrap().mode_read, RuleMode::Deny));
    }

    #[test]
    fn apply_config_adds_mocks() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.redb");
        let db = redb::Database::create(&db_path).unwrap();
        {
            let txn = db.begin_write().unwrap();
            {
                txn.open_table(RULES).unwrap();
                txn.open_table(MOCKS).unwrap();
                txn.open_table(MOCK_DIRS).unwrap();
            }
            txn.commit().unwrap();
        }

        let cfg = Config {
            sandbox_root: None,
            defaults: Defaults::default(),
            rules: vec![],
            mocks: vec![MockEntry { path: r"c:\mock.txt".into(), content_inline: Some("hello".into()) }],
            mock_dirs: vec![],
        };
        apply_config(&db, &cfg).unwrap();

        let txn = db.begin_read().unwrap();
        let payload = find_mock_payload(&txn, r"c:\mock.txt").unwrap();
        assert_eq!(payload, b"hello");
    }

    // ── when filter tests ───────────────────────────────────────────────────

    fn make_db_with_rules_and_when(
        rules: &[(&str, RuleMode, RuleMode, Option<WhenFilter>)],
    ) -> (tempfile::TempDir, redb::Database) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.redb");
        let db = redb::Database::create(&db_path).unwrap();
        {
            let txn = db.begin_write().unwrap();
            {
                let mut table = txn.open_table(RULES).unwrap();
                let default_row = RuleRow { mode_read: RuleMode::Passthrough, mode_write: RuleMode::Cow, when: None };
                let enc = bincode::serde::encode_to_vec(&default_row, bincode::config::standard()).unwrap();
                table.insert("", enc.as_slice()).unwrap();
                for (prefix, mr, mw, when) in rules {
                    let row = RuleRow { mode_read: *mr, mode_write: *mw, when: when.clone() };
                    let enc = bincode::serde::encode_to_vec(&row, bincode::config::standard()).unwrap();
                    table.insert(prefix.to_lowercase().as_str(), enc.as_slice()).unwrap();
                }
            }
            txn.commit().unwrap();
        }
        (dir, db)
    }

    #[test]
    fn when_depth_filter_pass() {
        let (_dir, db) = make_db_with_rules_and_when(&[
            (r"c:\test", RuleMode::Deny, RuleMode::Deny, Some(WhenFilter { depth: Some(1), exe: None })),
        ]);
        let txn = db.begin_read().unwrap();
        // depth=1 >= required depth=1 → rule applies
        let rule = best_rule_match(&txn, r"c:\test\file", Some(1), None).unwrap();
        assert!(matches!(rule.mode_read, RuleMode::Deny));
    }

    #[test]
    fn when_depth_filter_too_shallow() {
        let (_dir, db) = make_db_with_rules_and_when(&[
            (r"c:\test", RuleMode::Deny, RuleMode::Deny, Some(WhenFilter { depth: Some(1), exe: None })),
        ]);
        let txn = db.begin_read().unwrap();
        // depth=0 < required depth=1 → rule skipped, falls to default
        let rule = best_rule_match(&txn, r"c:\test\file", Some(0), None).unwrap();
        assert!(matches!(rule.mode_read, RuleMode::Passthrough));
    }

    #[test]
    fn when_depth_filter_none_is_max_permissive() {
        let (_dir, db) = make_db_with_rules_and_when(&[
            (r"c:\test", RuleMode::Deny, RuleMode::Deny, Some(WhenFilter { depth: Some(1), exe: None })),
        ]);
        let txn = db.begin_read().unwrap();
        // depth=None (legacy caller) → treated as max-permissive → rule applies
        let rule = best_rule_match(&txn, r"c:\test\file", None, None).unwrap();
        assert!(matches!(rule.mode_read, RuleMode::Deny));
    }

    #[test]
    fn when_exe_filter_match() {
        let (_dir, db) = make_db_with_rules_and_when(&[
            (r"c:\test", RuleMode::Deny, RuleMode::Deny, Some(WhenFilter {
                depth: None,
                exe: Some(r"c:\bin\target-app.exe".into()),
            })),
        ]);
        let txn = db.begin_read().unwrap();
        let rule = best_rule_match(&txn, r"c:\test\file", Some(0), Some(r"c:\bin\target-app.exe")).unwrap();
        assert!(matches!(rule.mode_read, RuleMode::Deny));
    }

    #[test]
    fn when_exe_filter_miss() {
        let (_dir, db) = make_db_with_rules_and_when(&[
            (r"c:\test", RuleMode::Deny, RuleMode::Deny, Some(WhenFilter {
                depth: None,
                exe: Some(r"c:\bin\target-app.exe".into()),
            })),
        ]);
        let txn = db.begin_read().unwrap();
        // exe doesn't match → skip rule → default passthrough
        let rule = best_rule_match(&txn, r"c:\test\file", Some(0), Some(r"c:\bin\other.exe")).unwrap();
        assert!(matches!(rule.mode_read, RuleMode::Passthrough));
    }

    #[test]
    fn when_exe_filter_none_exe_skips() {
        let (_dir, db) = make_db_with_rules_and_when(&[
            (r"c:\test", RuleMode::Deny, RuleMode::Deny, Some(WhenFilter {
                depth: None,
                exe: Some(r"c:\bin\target-app.exe".into()),
            })),
        ]);
        let txn = db.begin_read().unwrap();
        // exe_lower=None but rule requires exe → skip
        let rule = best_rule_match(&txn, r"c:\test\file", Some(0), None).unwrap();
        assert!(matches!(rule.mode_read, RuleMode::Passthrough));
    }

    #[test]
    fn when_both_filters_must_match() {
        let (_dir, db) = make_db_with_rules_and_when(&[
            (r"c:\test", RuleMode::Deny, RuleMode::Deny, Some(WhenFilter {
                depth: Some(2),
                exe: Some(r"c:\dir\app.exe".into()),
            })),
        ]);
        let txn = db.begin_read().unwrap();
        // Both match
        let rule = best_rule_match(&txn, r"c:\test\file", Some(3), Some(r"c:\dir\app.exe")).unwrap();
        assert!(matches!(rule.mode_read, RuleMode::Deny));
        // Depth ok but exe wrong
        let rule = best_rule_match(&txn, r"c:\test\file", Some(3), Some(r"c:\dir\other.exe")).unwrap();
        assert!(matches!(rule.mode_read, RuleMode::Passthrough));
        // Exe ok but depth too shallow
        let rule = best_rule_match(&txn, r"c:\test\file", Some(1), Some(r"c:\dir\app.exe")).unwrap();
        assert!(matches!(rule.mode_read, RuleMode::Passthrough));
    }

    #[test]
    fn specificity_with_when_higher() {
        let (_dir, db) = make_db_with_rules_and_when(&[
            (r"c:\test", RuleMode::Passthrough, RuleMode::Cow, None),
            (r"c:\test", RuleMode::Deny, RuleMode::Deny, Some(WhenFilter { depth: Some(0), exe: None })),
        ]);
        let txn = db.begin_read().unwrap();
        // Rule with when has +1 specificity bonus → wins
        let rule = best_rule_match(&txn, r"c:\test\file", Some(0), None).unwrap();
        assert!(matches!(rule.mode_read, RuleMode::Deny));
    }

    #[test]
    fn back_compat_rule_without_when() {
        let (_dir, db) = make_db_with_rules(&[
            (r"c:\test", RuleMode::Deny, RuleMode::Deny),
        ]);
        let txn = db.begin_read().unwrap();
        // Rule without when works regardless of depth/exe
        let rule = best_rule_match(&txn, r"c:\test\file", Some(5), Some(r"anything.exe")).unwrap();
        assert!(matches!(rule.mode_read, RuleMode::Deny));
        let rule = best_rule_match(&txn, r"c:\test\file", None, None).unwrap();
        assert!(matches!(rule.mode_read, RuleMode::Deny));
    }
}
