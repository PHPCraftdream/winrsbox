use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegType {
    None,
    Sz,
    ExpandSz,
    Binary,
    Dword,
    DwordBe,
    Link,
    MultiSz,
    Qword,
    Other(u32),
}

impl RegType {
    pub fn from_u32(t: u32) -> Self {
        match t {
            0 => Self::None,
            1 => Self::Sz,
            2 => Self::ExpandSz,
            3 => Self::Binary,
            4 => Self::Dword,
            5 => Self::DwordBe,
            6 => Self::Link,
            7 => Self::MultiSz,
            11 => Self::Qword,
            other => Self::Other(other),
        }
    }

    pub fn to_u32(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Sz => 1,
            Self::ExpandSz => 2,
            Self::Binary => 3,
            Self::Dword => 4,
            Self::DwordBe => 5,
            Self::Link => 6,
            Self::MultiSz => 7,
            Self::Qword => 11,
            Self::Other(v) => v,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::None => "REG_NONE",
            Self::Sz => "REG_SZ",
            Self::ExpandSz => "REG_EXPAND_SZ",
            Self::Binary => "REG_BINARY",
            Self::Dword => "REG_DWORD",
            Self::DwordBe => "REG_DWORD_BIG_ENDIAN",
            Self::Link => "REG_LINK",
            Self::MultiSz => "REG_MULTI_SZ",
            Self::Qword => "REG_QWORD",
            Self::Other(_) => "REG_OTHER",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "REG_NONE" => Some(Self::None),
            "REG_SZ" => Some(Self::Sz),
            "REG_EXPAND_SZ" => Some(Self::ExpandSz),
            "REG_BINARY" => Some(Self::Binary),
            "REG_DWORD" => Some(Self::Dword),
            "REG_DWORD_BIG_ENDIAN" => Some(Self::DwordBe),
            "REG_LINK" => Some(Self::Link),
            "REG_MULTI_SZ" => Some(Self::MultiSz),
            "REG_QWORD" => Some(Self::Qword),
            _ => Option::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RegData {
    String(String),
    Strings(Vec<String>),
    U32(u32),
    U64(u64),
    Bytes(Vec<u8>),
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegValue {
    pub typ: RegType,
    pub data: RegData,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RegEntry {
    Value(RegValue),
    Deleted,
}

// ─── JSON codec ──────────────────────────────────────────────────────────────

impl RegValue {
    pub fn to_json_value(&self) -> serde_json::Value {
        let data = match &self.data {
            RegData::String(s) => serde_json::Value::String(s.clone()),
            RegData::Strings(v) => serde_json::Value::Array(
                v.iter().map(|s| serde_json::Value::String(s.clone())).collect(),
            ),
            RegData::U32(n) => serde_json::json!(*n),
            RegData::U64(n) => serde_json::Value::String(n.to_string()),
            RegData::Bytes(b) => {
                use base64::Engine;
                serde_json::Value::String(base64::prelude::BASE64_STANDARD.encode(b))
            }
            RegData::None => serde_json::Value::Null,
        };
        serde_json::json!({ "type": self.typ.name(), "data": data })
    }

    pub fn from_json_value(val: &serde_json::Value) -> Option<Self> {
        let typ_str = val.get("type")?.as_str()?;
        let typ = RegType::from_name(typ_str)?;
        let data_val = val.get("data")?;

        let data = match typ {
            RegType::Sz | RegType::ExpandSz => {
                RegData::String(data_val.as_str()?.to_owned())
            }
            RegType::MultiSz => {
                let arr = data_val.as_array()?;
                let strs: Vec<String> = arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                RegData::Strings(strs)
            }
            RegType::Dword | RegType::DwordBe => {
                RegData::U32(data_val.as_u64()? as u32)
            }
            RegType::Qword => {
                let s = data_val.as_str()?;
                RegData::U64(s.parse().ok()?)
            }
            RegType::Binary | RegType::Other(_) => {
                use base64::Engine;
                let s = data_val.as_str()?;
                let bytes = base64::prelude::BASE64_STANDARD.decode(s).ok()?;
                RegData::Bytes(bytes)
            }
            RegType::None | RegType::Link => RegData::None,
        };
        Some(RegValue { typ, data })
    }
}

pub fn parse_values_json(raw: &str) -> Result<rustc_hash::FxHashMap<String, RegEntry>, String> {
    let obj: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| format!("JSON parse error: {e}"))?;
    let map = obj.as_object().ok_or("expected JSON object")?;
    let mut result = rustc_hash::FxHashMap::default();
    for (key, val) in map {
        let name = key.to_lowercase();
        if let Some(typ_str) = val.get("type").and_then(|v| v.as_str()) {
            if typ_str == "DELETED" {
                result.insert(name, RegEntry::Deleted);
                continue;
            }
        }
        match RegValue::from_json_value(val) {
            Some(rv) => { result.insert(name, RegEntry::Value(rv)); }
            Option::None => return Err(format!("invalid value for key '{key}'")),
        }
    }
    Ok(result)
}

pub fn serialize_values_json(values: &rustc_hash::FxHashMap<String, RegEntry>) -> String {
    let mut obj = serde_json::Map::new();
    for (name, entry) in values {
        let val = match entry {
            RegEntry::Value(rv) => rv.to_json_value(),
            RegEntry::Deleted => serde_json::json!({ "type": "DELETED" }),
        };
        obj.insert(name.clone(), val);
    }
    serde_json::to_string_pretty(&serde_json::Value::Object(obj))
        .unwrap_or_default()
}

// ─── NT path conversion ─────────────────────────────────────────────────────

pub fn nt_to_friendly(raw: &[u16]) -> Option<String> {
    let s = String::from_utf16_lossy(raw);
    let s = s.trim_end_matches('\0');
    let lower = s.to_lowercase();

    let stripped = lower.strip_prefix(r"\registry\")?;

    if let Some(rest) = stripped.strip_prefix("machine\\") {
        Some(format!("hklm\\{rest}"))
    } else if let Some(rest) = stripped.strip_prefix("user\\") {
        if let Some(after_sid) = rest.find('\\') {
            let sid = &rest[..after_sid];
            let path = &rest[after_sid + 1..];
            if sid.rsplit('-').next() == Some("500") || rest.starts_with(".default") {
                Some(format!("hkcu\\{path}"))
            } else {
                Some(format!("hku\\{sid}\\{path}"))
            }
        } else {
            Some(format!("hku\\{rest}"))
        }
    } else if let Some(rest) = stripped.strip_prefix("classes\\") {
        Some(format!("hkcr\\{rest}"))
    } else {
        Option::None
    }
}

pub fn friendly_to_overlay(friendly: &str, root: &Path) -> PathBuf {
    let sanitized = friendly.replace('/', "\\");
    let sanitized = sanitized.trim_start_matches('\\');
    let mut out = root.to_path_buf();
    for component in std::path::Path::new(sanitized).components() {
        match component {
            std::path::Component::Normal(c) => out.push(c),
            _ => {}
        }
    }
    out
}

pub fn values_json_path(overlay_key_dir: &Path) -> PathBuf {
    overlay_key_dir.join("values.json")
}

pub fn deleted_marker_path(overlay_key_dir: &Path) -> PathBuf {
    overlay_key_dir.join("_deleted")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── RegType roundtrip ────────────────────────────────────────────────

    #[test]
    fn reg_type_u32_roundtrip() {
        for t in [RegType::None, RegType::Sz, RegType::ExpandSz, RegType::Binary,
                  RegType::Dword, RegType::DwordBe, RegType::Link, RegType::MultiSz,
                  RegType::Qword, RegType::Other(42)] {
            assert_eq!(RegType::from_u32(t.to_u32()), t);
        }
    }

    #[test]
    fn reg_type_name_roundtrip() {
        for t in [RegType::None, RegType::Sz, RegType::ExpandSz, RegType::Binary,
                  RegType::Dword, RegType::MultiSz, RegType::Qword] {
            assert_eq!(RegType::from_name(t.name()), Some(t));
        }
    }

    // ── JSON codec ───────────────────────────────────────────────────────

    #[test]
    fn json_roundtrip_sz() {
        let v = RegValue { typ: RegType::Sz, data: RegData::String("hello world".into()) };
        let json = v.to_json_value();
        let v2 = RegValue::from_json_value(&json).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn json_roundtrip_expand_sz() {
        let v = RegValue { typ: RegType::ExpandSz, data: RegData::String("%SystemRoot%\\foo".into()) };
        let json = v.to_json_value();
        let v2 = RegValue::from_json_value(&json).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn json_roundtrip_multi_sz() {
        let v = RegValue { typ: RegType::MultiSz, data: RegData::Strings(vec!["a".into(), "b".into(), "c".into()]) };
        let json = v.to_json_value();
        let v2 = RegValue::from_json_value(&json).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn json_roundtrip_dword() {
        let v = RegValue { typ: RegType::Dword, data: RegData::U32(0xDEADBEEF) };
        let json = v.to_json_value();
        let v2 = RegValue::from_json_value(&json).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn json_roundtrip_qword() {
        let v = RegValue { typ: RegType::Qword, data: RegData::U64(0x1234_5678_9ABC_DEF0) };
        let json = v.to_json_value();
        let v2 = RegValue::from_json_value(&json).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn json_roundtrip_qword_precision() {
        let big = u64::MAX - 1;
        let v = RegValue { typ: RegType::Qword, data: RegData::U64(big) };
        let json = v.to_json_value();
        assert_eq!(json["data"].as_str().unwrap(), big.to_string());
        let v2 = RegValue::from_json_value(&json).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn json_roundtrip_binary() {
        let v = RegValue { typ: RegType::Binary, data: RegData::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]) };
        let json = v.to_json_value();
        let v2 = RegValue::from_json_value(&json).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn json_roundtrip_none() {
        let v = RegValue { typ: RegType::None, data: RegData::None };
        let json = v.to_json_value();
        let v2 = RegValue::from_json_value(&json).unwrap();
        assert_eq!(v, v2);
    }

    // ── values.json parse/serialize ──────────────────────────────────────

    #[test]
    fn values_json_roundtrip() {
        let mut vals = rustc_hash::FxHashMap::default();
        vals.insert("name".into(), RegEntry::Value(RegValue {
            typ: RegType::Sz, data: RegData::String("test".into()),
        }));
        vals.insert("count".into(), RegEntry::Value(RegValue {
            typ: RegType::Dword, data: RegData::U32(42),
        }));
        vals.insert("removed".into(), RegEntry::Deleted);

        let json = serialize_values_json(&vals);
        let parsed = parse_values_json(&json).unwrap();
        assert_eq!(vals, parsed);
    }

    #[test]
    fn values_json_empty() {
        let vals = rustc_hash::FxHashMap::default();
        let json = serialize_values_json(&vals);
        let parsed = parse_values_json(&json).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn values_json_invalid() {
        assert!(parse_values_json("not json").is_err());
        assert!(parse_values_json("[]").is_err());
    }

    // ── NT path conversion ───────────────────────────────────────────────

    #[test]
    fn nt_to_friendly_hklm() {
        let raw: Vec<u16> = r"\Registry\Machine\Software\Foo".encode_utf16().collect();
        assert_eq!(nt_to_friendly(&raw), Some(r"hklm\software\foo".into()));
    }

    #[test]
    fn nt_to_friendly_hkcu() {
        let raw: Vec<u16> = r"\Registry\User\S-1-5-21-123-500\Software\Bar".encode_utf16().collect();
        assert_eq!(nt_to_friendly(&raw), Some(r"hkcu\software\bar".into()));
    }

    #[test]
    fn nt_to_friendly_hku() {
        let raw: Vec<u16> = r"\Registry\User\S-1-5-21-999\Software".encode_utf16().collect();
        assert_eq!(nt_to_friendly(&raw), Some(r"hku\s-1-5-21-999\software".into()));
    }

    #[test]
    fn nt_to_friendly_hkcr() {
        let raw: Vec<u16> = r"\Registry\Classes\CLSID".encode_utf16().collect();
        assert_eq!(nt_to_friendly(&raw), Some(r"hkcr\clsid".into()));
    }

    #[test]
    fn nt_to_friendly_invalid() {
        let raw: Vec<u16> = r"\Device\HarddiskVolume".encode_utf16().collect();
        assert_eq!(nt_to_friendly(&raw), Option::None);
    }

    #[test]
    fn nt_to_friendly_trailing_nul() {
        let mut raw: Vec<u16> = r"\Registry\Machine\Foo".encode_utf16().collect();
        raw.push(0);
        assert_eq!(nt_to_friendly(&raw), Some(r"hklm\foo".into()));
    }

    // ── friendly_to_overlay ──────────────────────────────────────────────

    #[test]
    fn overlay_path_basic() {
        let root = Path::new(r"C:\sb\workreg");
        let result = friendly_to_overlay(r"hklm\software\foo", root);
        assert_eq!(result, PathBuf::from(r"C:\sb\workreg\hklm\software\foo"));
    }

    #[test]
    fn overlay_path_no_leading_slash() {
        let root = Path::new(r"\sb");
        let result = friendly_to_overlay(r"\hklm\foo", root);
        assert_eq!(result, PathBuf::from(r"\sb\hklm\foo"));
    }

    // ── registry overlay escape regression (audit fix #4) ──────────────

    #[test]
    fn overlay_dotdot_stripped() {
        let root = Path::new(r"C:\sb\workreg");
        let evil = r"hklm\software\..\..\..\windows\system32";
        let result = friendly_to_overlay(evil, root);
        assert!(
            result.starts_with(root),
            "registry overlay {result:?} must stay under root {root:?}",
        );
        assert!(
            !result.to_str().unwrap().contains(".."),
            "registry overlay {result:?} must not contain '..' components",
        );
    }

    #[test]
    fn overlay_many_dotdot_does_not_escape() {
        let root = Path::new(r"\sb\reg");
        let traversal = r"hklm\a\..\..\..\..\..\..\..\evil";
        let result = friendly_to_overlay(traversal, root);
        assert!(
            result.starts_with(root),
            "even many '..' must not escape: {result:?}",
        );
    }

    // ── SID RID-500 heuristic regression (audit fix #5) ────────────────

    #[test]
    fn sid_with_500_substring_not_hkcu() {
        let raw: Vec<u16> = r"\Registry\User\S-1-5-21-1234-5001500-9012-1000\Software\Foo".encode_utf16().collect();
        let result = nt_to_friendly(&raw).unwrap();
        assert!(
            result.starts_with("hku\\"),
            "SID with -500 substring (not RID) must route to HKU, got: {result}",
        );
        assert!(
            result.contains("s-1-5-21-1234-5001500-9012-1000"),
            "SID must be preserved in HKU path: {result}",
        );
    }

    #[test]
    fn sid_with_exact_rid_500_is_hkcu() {
        let raw: Vec<u16> = r"\Registry\User\S-1-5-21-123-456-789-500\Software\Bar".encode_utf16().collect();
        let result = nt_to_friendly(&raw).unwrap();
        assert!(
            result.starts_with("hkcu\\"),
            "SID with exact RID 500 must route to HKCU, got: {result}",
        );
    }
}
