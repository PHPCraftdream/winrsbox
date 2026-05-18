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

fn default_passthrough() -> String { "passthrough".into() }
fn default_cow() -> String { "cow".into() }

#[derive(Debug, Deserialize)]
pub struct RuleEntry {
    pub prefix: String,
    pub read: Option<String>,
    pub write: Option<String>,
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
        let default_row = RuleRow { mode_read: default_read, mode_write: default_write };
        let encoded = bincode::serde::encode_to_vec(&default_row, bincode::config::standard())
            .map_err(|e| crate::PolicyError::Ktav(format!("serialize: {e}")))?;
        rules.insert("", encoded.as_slice())?;

        for rule in &cfg.rules {
            let mr = parse_mode(rule.read.as_deref().unwrap_or("passthrough"), default_read);
            let mw = parse_mode(rule.write.as_deref().unwrap_or("cow"), default_write);
            let row = RuleRow { mode_read: mr, mode_write: mw };
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
pub fn best_rule_match(txn: &redb::ReadTransaction, lower_path: &str) -> Option<RuleRow> {
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
        let spec = pattern_specificity(pattern);
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
        let row = RuleRow { mode_read: RuleMode::Cow, mode_write: RuleMode::Deny };
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
}
