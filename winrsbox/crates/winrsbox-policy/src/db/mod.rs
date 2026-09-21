use crate::path::{pattern_matches_exact, pattern_matches_prefix, pattern_specificity};
use redb::{ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

pub const RULES: TableDefinition<&str, &[u8]> = TableDefinition::new("rules");
pub const MOCKS: TableDefinition<&str, &[u8]> = TableDefinition::new("mocks");
pub const MOCK_DIRS: TableDefinition<&str, ()> = TableDefinition::new("mock_dirs");
pub const OVERLAY_IDX: TableDefinition<&str, &str> = TableDefinition::new("overlay_idx");

/// Optional case-preservation index for overlay entries.
///
/// Key   = lowercase virtual DOS path (same key space as OVERLAY_IDX).
/// Value = original-case basename of the virtual path at the time of
///         first overlay write (e.g. "Mixed_Case_Dir" for
///         `c:\test_case\mixed_case_dir`).
///
/// Legacy entries (written before this field existed) simply have no
/// record here; reads return `None` and callers fall back to the
/// real-disk case (same as before). This table is intentionally
/// separate from OVERLAY_IDX so the existing ~24k entries need no
/// migration and the schema change is 100 % backward compatible.
pub const OVERLAY_CASE: TableDefinition<&str, &str> = TableDefinition::new("overlay_case");

/// Whiteout markers (OverlayFS-style tombstones). Key = lowercase virtual DOS
/// path that has been "deleted" from the sandbox's merged view. The real lower
/// file is untouched; the presence of the key here makes the path appear
/// not-found to open/create and hides it from directory enumeration. A
/// subsequent create at the same path clears the marker (revive) and re-enters
/// the CoW overlay.
pub const WHITEOUTS: TableDefinition<&str, ()> = TableDefinition::new("whiteouts");

pub const REG_RULES: TableDefinition<&str, &[u8]> = TableDefinition::new("reg_rules");
pub const REG_MOCKS: TableDefinition<&str, &[u8]> = TableDefinition::new("reg_mocks");
pub const DEV_RULES: TableDefinition<&str, &[u8]> = TableDefinition::new("dev_rules");
pub const NET_RULES: TableDefinition<&str, &[u8]> = TableDefinition::new("net_rules");

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RuleMode { Passthrough, Deny, Cow, Redirect }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleRow {
    pub id: String,
    pub prefix: String,
    pub mode_read: RuleMode,
    pub mode_write: RuleMode,
    pub when: Option<WhenFilter>,
}

// ── Defaults table ────────────────────────────────────────────────────────
pub const DEFAULTS: TableDefinition<&str, &[u8]> = TableDefinition::new("defaults");

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
    /// Per-folder log verbosity (overridden by CLI `--log-level` if explicitly set).
    /// Values: error / warn / info / trace. Defaults to "info" if unset.
    #[serde(default)]
    pub log_level: Option<String>,
    /// Network containment. `guarded` turns it on; anything else (including
    /// the default, unset) means the sandbox does not touch the network at
    /// all — no WFP filters are registered and the `connect` hook is not
    /// installed.
    ///
    /// Off by default on purpose. When it is off, a sandboxed program's
    /// traffic is indistinguishable from running that program directly: it
    /// already connects from its own process with its own image (the hook
    /// never proxied anything), and with no filters registered the sandbox
    /// leaves no trace in the system's network configuration either.
    ///
    /// The trade is explicit and documented in SECURITY.md: with this unset,
    /// a sandboxed process can reach anything the user can, including RFC1918
    /// hosts and SMB shares. Filesystem, registry, process and memory
    /// containment are unaffected.
    #[serde(default)]
    pub network: Option<String>,
}

impl Config {
    /// True when `network: guarded` is set. Compared ASCII-case-insensitively;
    /// every other value, including absent, means "do not touch the network".
    pub fn network_guarded(&self) -> bool {
        self.network
            .as_deref()
            .map(|v| v.trim().eq_ignore_ascii_case("guarded"))
            .unwrap_or(false)
    }
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

/// Generate a deterministic ID: `<kind>-<8hex>` from xxh3 of sorted args.
pub fn generate_id(kind: &str, args: &[&str]) -> String {
    let mut parts: Vec<&str> = args.to_vec();
    parts.sort();
    let mut hasher = xxhash_rust::xxh3::Xxh3::new();
    for p in &parts {
        hasher.update(p.as_bytes());
        hasher.update(&[0]); // separator
    }
    let hash = hasher.digest();
    format!("{}-{:08x}", kind, hash & 0xFFFFFFFF)
}

pub fn mode_to_string(m: RuleMode) -> &'static str {
    match m {
        RuleMode::Passthrough => "passthrough",
        RuleMode::Deny => "deny",
        RuleMode::Cow => "cow",
        RuleMode::Redirect => "redirect",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultsRow {
    pub read: RuleMode,
    pub write: RuleMode,
}

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
        let default_row = RuleRow { id: "".into(), prefix: String::new(), mode_read: default_read, mode_write: default_write, when: None };
        let encoded = bincode::serde::encode_to_vec(&default_row, bincode::config::standard())
            .map_err(|e| crate::PolicyError::Ktav(format!("serialize: {e}")))?;
        rules.insert("", encoded.as_slice())?;

        for rule in &cfg.rules {
            let mr = parse_mode(rule.read.as_deref().unwrap_or("passthrough"), default_read);
            let mw = parse_mode(rule.write.as_deref().unwrap_or("cow"), default_write);
            let prefix_lower = crate::ensure_lower(&rule.prefix).into_owned();
            let id = generate_id("rule", &[&prefix_lower]);
            let when = rule.when.clone().map(|mut w| {
                if let Some(ref e) = w.exe { w.exe = Some(crate::ensure_lower(e).into_owned()); }
                w
            });
            let row = RuleRow { id, prefix: prefix_lower.clone(), mode_read: mr, mode_write: mw, when };
            let enc = bincode::serde::encode_to_vec(&row, bincode::config::standard())
                .map_err(|e| crate::PolicyError::Ktav(format!("serialize: {e}")))?;
            rules.insert(prefix_lower.as_str(), enc.as_slice())?;
        }

        for mock in &cfg.mocks {
            let payload = mock.content_inline.as_deref().unwrap_or("").as_bytes().to_vec();
            let key = crate::ensure_lower(&mock.path).into_owned();
            mocks.insert(key.as_str(), payload.as_slice())?;
        }

        for md in &cfg.mock_dirs {
            let key = crate::ensure_lower(&md.prefix).into_owned();
            mock_dirs.insert(key.as_str(), ())?;
        }
    }
    txn.commit()?;
    Ok(())
}

pub fn decode_rule(bytes: &[u8]) -> Option<RuleRow> {
    bincode::serde::decode_from_slice::<RuleRow, _>(bytes, bincode::config::standard())
        .ok()
        .map(|(r, _)| r)
}

/// Find the most specific rule matching `lower_path`. Iterates every rule
/// (rules support `*` / `?` globs per path segment) and returns the one with
/// the highest specificity. Falls back to the default (empty) rule.
/// Returns (key, RuleRow) so callers can see the matched prefix/id.
pub fn best_rule_match_full(
    txn: &redb::ReadTransaction,
    lower_path: &str,
    depth: Option<u8>,
    exe_lower: Option<&str>,
) -> Option<(String, RuleRow)> {
    let table = txn.open_table(RULES).ok()?;
    let mut best: Option<(usize, String, RuleRow)> = None;
    let mut default_row: Option<(String, RuleRow)> = None;

    for entry in table.iter().ok()? {
        let Ok((key, value)) = entry else { continue };
        let pattern = key.value();
        if pattern.is_empty() {
            default_row = decode_rule(value.value()).map(|r| (pattern.to_owned(), r));
            continue;
        }
        if !pattern_matches_prefix(pattern, lower_path) {
            continue;
        }
        let Some(row) = decode_rule(value.value()) else { continue };
        // Apply when filter
        if let Some(ref when) = row.when {
            if let Some(min_depth) = when.depth {
                if depth.is_some() && depth.unwrap() < min_depth {
                    continue;
                }
            }
            if let Some(ref exe_pattern) = when.exe {
                if exe_lower.is_none() || !pattern_matches_exact(&crate::ensure_lower(exe_pattern), exe_lower.unwrap()) {
                    continue;
                }
            }
        }
        let mut spec = pattern_specificity(pattern);
        if row.when.is_some() {
            spec += 1;
        }
        if let Some(ref when) = row.when {
            if let Some(ref exe) = when.exe {
                spec += pattern_specificity(exe);
            }
        }
        match &best {
            None => best = Some((spec, pattern.to_owned(), row)),
            Some((s, _, _)) if spec > *s => best = Some((spec, pattern.to_owned(), row)),
            _ => {}
        }
    }
    best.map(|(_, k, r)| (k, r)).or(default_row)
}

/// Convenience wrapper returning just the RuleRow.
pub fn best_rule_match(
    txn: &redb::ReadTransaction,
    lower_path: &str,
    depth: Option<u8>,
    exe_lower: Option<&str>,
) -> Option<RuleRow> {
    best_rule_match_full(txn, lower_path, depth, exe_lower).map(|(_, r)| r)
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

// ── CRUD operations ────────────────────────────────────────────────────────

pub fn rule_upsert(db: &redb::Database, row: &RuleRow) -> Result<(), crate::PolicyError> {
    let prefix_lower = crate::ensure_lower(&row.prefix).into_owned();
    let mut stored = row.clone();
    stored.prefix = prefix_lower.clone();
    if let Some(ref mut w) = stored.when {
        if let Some(ref e) = w.exe { w.exe = Some(crate::ensure_lower(e).into_owned()); }
    }
    let enc = bincode::serde::encode_to_vec(&stored, bincode::config::standard())
        .map_err(|e| crate::PolicyError::Ktav(format!("serialize: {e}")))?;
    let txn = db.begin_write()?;
    {
        let mut table = txn.open_table(RULES)?;
        table.insert(prefix_lower.as_str(), enc.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

pub fn rule_remove_by_id(db: &redb::Database, id: &str) -> Result<bool, crate::PolicyError> {
    let txn = db.begin_write()?;
    let removed = {
        let mut table = txn.open_table(RULES)?;
        let mut found = false;
        let keys_to_remove: Vec<String> = table
            .iter()?
            .filter_map(|e| e.ok())
            .filter(|(k, v)| {
                if k.value() == "" { return false; } // never remove default
                decode_rule(v.value()).map(|r| r.id == id).unwrap_or(false)
            })
            .map(|(k, _)| k.value().to_owned())
            .collect();
        for k in &keys_to_remove {
            table.remove(k.as_str())?;
            found = true;
        }
        found
    };
    txn.commit()?;
    Ok(removed)
}

pub fn rule_remove_by_prefix(db: &redb::Database, prefix: &str) -> Result<bool, crate::PolicyError> {
    let key = crate::ensure_lower(prefix).into_owned();
    let txn = db.begin_write()?;
    let removed = {
        let mut table = txn.open_table(RULES)?;
        let x = table.remove(key.as_str())?.is_some();
        x
    };
    txn.commit()?;
    Ok(removed)
}

pub fn rule_list(db: &redb::Database) -> Result<Vec<RuleRow>, crate::PolicyError> {
    let txn = db.begin_read()?;
    let table = txn.open_table(RULES)?;
    let mut rules = Vec::new();
    for entry in table.iter()? {
        let Ok((key, value)) = entry else { continue };
        if key.value().is_empty() { continue; } // skip default
        if let Some(row) = decode_rule(value.value()) {
            rules.push(row);
        }
    }
    Ok(rules)
}

pub fn rule_clear(db: &redb::Database) -> Result<(), crate::PolicyError> {
    let txn = db.begin_write()?;
    {
        let mut table = txn.open_table(RULES)?;
        let keys: Vec<String> = table.iter()?.filter_map(|e| e.ok())
            .filter(|(k, _)| !k.value().is_empty())
            .map(|(k, _)| k.value().to_owned())
            .collect();
        for k in keys {
            table.remove(k.as_str())?;
        }
    }
    txn.commit()?;
    Ok(())
}

pub fn mock_upsert(db: &redb::Database, _id: &str, path: &str, payload: &[u8]) -> Result<(), crate::PolicyError> {
    let key = crate::ensure_lower(path).into_owned();
    let txn = db.begin_write()?;
    {
        let mut table = txn.open_table(MOCKS)?;
        table.insert(key.as_str(), payload)?;
    }
    txn.commit()?;
    Ok(())
}

pub fn mock_remove_by_id(_db: &redb::Database, _id: &str) -> Result<bool, crate::PolicyError> {
    // Mocks don't store id inline in the table; we'll match by iterating
    // For now, mocks use path as key so we need a different approach
    // We store a MOCKS_META table for id → path mapping
    Ok(false)
}

pub fn mock_remove_by_path(db: &redb::Database, path: &str) -> Result<bool, crate::PolicyError> {
    let key = crate::ensure_lower(path).into_owned();
    let txn = db.begin_write()?;
    let removed = {
        let mut table = txn.open_table(MOCKS)?;
        let x = table.remove(key.as_str())?.is_some();
        x
    };
    txn.commit()?;
    Ok(removed)
}

pub fn mock_list(db: &redb::Database) -> Result<Vec<(String, Vec<u8>)>, crate::PolicyError> {
    let txn = db.begin_read()?;
    let table = txn.open_table(MOCKS)?;
    let mut mocks = Vec::new();
    for entry in table.iter()? {
        let Ok((key, value)) = entry else { continue };
        mocks.push((key.value().to_owned(), value.value().to_vec()));
    }
    Ok(mocks)
}

pub fn mockdir_upsert(db: &redb::Database, prefix: &str) -> Result<(), crate::PolicyError> {
    let key = crate::ensure_lower(prefix).into_owned();
    let txn = db.begin_write()?;
    {
        let mut table = txn.open_table(MOCK_DIRS)?;
        table.insert(key.as_str(), ())?;
    }
    txn.commit()?;
    Ok(())
}

pub fn mockdir_remove_by_prefix(db: &redb::Database, prefix: &str) -> Result<bool, crate::PolicyError> {
    let key = crate::ensure_lower(prefix).into_owned();
    let txn = db.begin_write()?;
    let removed = {
        let mut table = txn.open_table(MOCK_DIRS)?;
        let x = table.remove(key.as_str())?.is_some();
        x
    };
    txn.commit()?;
    Ok(removed)
}

pub fn mockdir_list(db: &redb::Database) -> Result<Vec<String>, crate::PolicyError> {
    let txn = db.begin_read()?;
    let table = txn.open_table(MOCK_DIRS)?;
    let mut dirs = Vec::new();
    for entry in table.iter()? {
        let Ok((key, _)) = entry else { continue };
        dirs.push(key.value().to_owned());
    }
    Ok(dirs)
}

pub fn defaults_get(db: &redb::Database) -> Result<DefaultsRow, crate::PolicyError> {
    // Read from the default rule (empty key in RULES table)
    let txn = db.begin_read()?;
    let table = txn.open_table(RULES)?;
    if let Some(value) = table.get("").ok().flatten() {
        if let Some(row) = decode_rule(value.value()) {
            return Ok(DefaultsRow { read: row.mode_read, write: row.mode_write });
        }
    }
    Ok(DefaultsRow { read: RuleMode::Passthrough, write: RuleMode::Cow })
}

pub fn defaults_set(db: &redb::Database, read: Option<RuleMode>, write: Option<RuleMode>) -> Result<(), crate::PolicyError> {
    let current = defaults_get(db)?;
    let read = read.unwrap_or(current.read);
    let write = write.unwrap_or(current.write);
    let row = RuleRow { id: String::new(), prefix: String::new(), mode_read: read, mode_write: write, when: None };
    let enc = bincode::serde::encode_to_vec(&row, bincode::config::standard())
        .map_err(|e| crate::PolicyError::Ktav(format!("serialize: {e}")))?;
    let txn = db.begin_write()?;
    {
        let mut table = txn.open_table(RULES)?;
        table.insert("", enc.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}


// ─── Registry CRUD ───────────────────────────────────────────────────────────

pub fn reg_rule_upsert(db: &redb::Database, row: &RuleRow) -> Result<(), crate::PolicyError> {
    let prefix_lower = crate::ensure_lower(&row.prefix).into_owned();
    let mut stored = row.clone();
    stored.prefix = prefix_lower.clone();
    if let Some(ref mut w) = stored.when {
        if let Some(ref e) = w.exe { w.exe = Some(crate::ensure_lower(e).into_owned()); }
    }
    let enc = bincode::serde::encode_to_vec(&stored, bincode::config::standard())
        .map_err(|e| crate::PolicyError::Ktav(format!("serialize: {e}")))?;
    let txn = db.begin_write()?;
    { let mut t = txn.open_table(REG_RULES)?; t.insert(stored.prefix.as_str(), enc.as_slice())?; }
    txn.commit()?;
    Ok(())
}

pub fn reg_rule_remove_by_id(db: &redb::Database, id: &str) -> Result<bool, crate::PolicyError> {
    let txn = db.begin_write()?;
    let mut found = false;
    {
        let mut t = txn.open_table(REG_RULES)?;
        let keys: Vec<String> = t.range::<&str>(..)?.filter_map(|r| r.ok())
            .filter_map(|(k, v)| {
                let row = decode_rule(v.value())?;
                if row.id == id { Some(k.value().to_owned()) } else { None }
            }).collect();
        for k in keys { t.remove(k.as_str())?; found = true; }
    }
    txn.commit()?;
    Ok(found)
}

pub fn reg_rule_list(db: &redb::Database) -> Result<Vec<RuleRow>, crate::PolicyError> {
    let txn = db.begin_read()?;
    let t = txn.open_table(REG_RULES)?;
    let mut out = Vec::new();
    for entry in t.range::<&str>(..)?.flatten() {
        let (_, v) = entry;
        if let Some(row) = decode_rule(v.value()) {
            out.push(row);
        }
    }
    Ok(out)
}

pub fn reg_rule_clear(db: &redb::Database) -> Result<(), crate::PolicyError> {
    let txn = db.begin_write()?;
    {
        let mut t = txn.open_table(REG_RULES)?;
        let keys: Vec<String> = t.range::<&str>(..)?.filter_map(|r| r.ok())
            .map(|(k, _)| k.value().to_owned()).collect();
        for k in keys { t.remove(k.as_str())?; }
    }
    txn.commit()?;
    Ok(())
}

pub fn reg_mock_upsert(db: &redb::Database, path: &str, payload: &[u8]) -> Result<(), crate::PolicyError> {
    let key = crate::ensure_lower(path).into_owned();
    let txn = db.begin_write()?;
    { let mut t = txn.open_table(REG_MOCKS)?; t.insert(key.as_str(), payload)?; }
    txn.commit()?;
    Ok(())
}

pub fn reg_mock_remove(db: &redb::Database, path: &str) -> Result<bool, crate::PolicyError> {
    let key = crate::ensure_lower(path).into_owned();
    let txn = db.begin_write()?;
    let removed;
    { let mut t = txn.open_table(REG_MOCKS)?; removed = t.remove(key.as_str())?.is_some(); }
    txn.commit()?;
    Ok(removed)
}

pub fn reg_mock_list(db: &redb::Database) -> Result<Vec<(String, Vec<u8>)>, crate::PolicyError> {
    let txn = db.begin_read()?;
    let t = txn.open_table(REG_MOCKS)?;
    let mut out = Vec::new();
    for entry in t.range::<&str>(..)?.flatten() {
        let (k, v) = entry;
        out.push((k.value().to_owned(), v.value().to_vec()));
    }
    Ok(out)
}


// ─── Device CRUD ─────────────────────────────────────────────────────────────

pub fn dev_rule_upsert(db: &redb::Database, row: &RuleRow) -> Result<(), crate::PolicyError> {
    let enc = bincode::serde::encode_to_vec(row, bincode::config::standard())
        .map_err(|e| crate::PolicyError::Ktav(format!("serialize: {e}")))?;
    let txn = db.begin_write()?;
    { let mut t = txn.open_table(DEV_RULES)?; t.insert(row.prefix.as_str(), enc.as_slice())?; }
    txn.commit()?;
    Ok(())
}

pub fn dev_rule_remove_by_id(db: &redb::Database, id: &str) -> Result<bool, crate::PolicyError> {
    let txn = db.begin_write()?;
    let mut found = false;
    {
        let mut t = txn.open_table(DEV_RULES)?;
        let keys: Vec<String> = t.range::<&str>(..)?.filter_map(|r| r.ok())
            .filter_map(|(k, v)| {
                let row = decode_rule(v.value())?;
                if row.id == id { Some(k.value().to_owned()) } else { None }
            }).collect();
        for k in keys { t.remove(k.as_str())?; found = true; }
    }
    txn.commit()?;
    Ok(found)
}

pub fn dev_rule_list(db: &redb::Database) -> Result<Vec<RuleRow>, crate::PolicyError> {
    let txn = db.begin_read()?;
    let t = txn.open_table(DEV_RULES)?;
    let mut out = Vec::new();
    for entry in t.range::<&str>(..)?.flatten() {
        let (_, v) = entry;
        if let Some(row) = decode_rule(v.value()) { out.push(row); }
    }
    Ok(out)
}

pub fn dev_rule_clear(db: &redb::Database) -> Result<(), crate::PolicyError> {
    let txn = db.begin_write()?;
    {
        let mut t = txn.open_table(DEV_RULES)?;
        let keys: Vec<String> = t.range::<&str>(..)?.filter_map(|r| r.ok())
            .map(|(k, _)| k.value().to_owned()).collect();
        for k in keys { t.remove(k.as_str())?; }
    }
    txn.commit()?;
    Ok(())
}

// ─── Network CRUD ────────────────────────────────────────────────────────────

pub fn net_rule_upsert(db: &redb::Database, rule: &crate::net::NetRule) -> Result<(), crate::PolicyError> {
    let enc = bincode::serde::encode_to_vec(rule, bincode::config::standard())
        .map_err(|e| crate::PolicyError::Ktav(format!("serialize: {e}")))?;
    let txn = db.begin_write()?;
    { let mut t = txn.open_table(NET_RULES)?; t.insert(rule.id.as_str(), enc.as_slice())?; }
    txn.commit()?;
    Ok(())
}

pub fn net_rule_remove(db: &redb::Database, id: &str) -> Result<bool, crate::PolicyError> {
    let txn = db.begin_write()?;
    let removed;
    { let mut t = txn.open_table(NET_RULES)?; removed = t.remove(id)?.is_some(); }
    txn.commit()?;
    Ok(removed)
}

pub fn net_rule_list(db: &redb::Database) -> Result<Vec<crate::net::NetRule>, crate::PolicyError> {
    let txn = db.begin_read()?;
    let t = txn.open_table(NET_RULES)?;
    let mut out = Vec::new();
    for entry in t.range::<&str>(..)?.flatten() {
        let (_, v) = entry;
        if let Ok((rule, _)) = bincode::serde::decode_from_slice::<crate::net::NetRule, _>(v.value(), bincode::config::standard()) {
            out.push(rule);
        }
    }
    Ok(out)
}

pub fn net_rule_clear(db: &redb::Database) -> Result<(), crate::PolicyError> {
    let txn = db.begin_write()?;
    {
        let mut t = txn.open_table(NET_RULES)?;
        let keys: Vec<String> = t.range::<&str>(..)?.filter_map(|r| r.ok())
            .map(|(k, _)| k.value().to_owned()).collect();
        for k in keys { t.remove(k.as_str())?; }
    }
    txn.commit()?;
    Ok(())
}
#[cfg(test)]
mod tests;
