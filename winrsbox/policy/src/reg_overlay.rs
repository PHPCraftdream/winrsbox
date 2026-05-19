use crate::reg::{self, RegEntry, RegValue};
use rustc_hash::{FxHashMap, FxHashSet};
use std::path::{Path, PathBuf};

pub struct RegOverlay {
    values: FxHashMap<String, RegEntry>,
    deleted_keys: FxHashSet<String>,
    root: PathBuf,
}

fn composite_key(key: &str, name: &str) -> String {
    format!("{key}|{name}")
}

impl RegOverlay {
    pub fn new(root: PathBuf) -> Self {
        Self {
            values: FxHashMap::default(),
            deleted_keys: FxHashSet::default(),
            root,
        }
    }

    pub fn load_from_disk(root: PathBuf) -> Result<Self, String> {
        let mut overlay = Self::new(root);
        if !overlay.root.exists() {
            return Ok(overlay);
        }
        overlay.walk_dir(&overlay.root.clone(), "")?;
        Ok(overlay)
    }

    fn walk_dir(&mut self, dir: &Path, friendly_prefix: &str) -> Result<(), String> {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            let path = entry.path();

            if path.is_file() && name == "values.json" {
                let raw = std::fs::read_to_string(&path)
                    .map_err(|e| format!("read {}: {e}", path.display()))?;
                let parsed = reg::parse_values_json(&raw)?;
                let key = friendly_prefix.trim_end_matches('\\');
                for (vname, ventry) in parsed {
                    self.values.insert(composite_key(key, &vname), ventry);
                }
            } else if path.is_file() && name == "_deleted" {
                let key = friendly_prefix.trim_end_matches('\\');
                self.deleted_keys.insert(key.to_owned());
            } else if path.is_dir() {
                let child_prefix = if friendly_prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{friendly_prefix}\\{name}")
                };
                self.walk_dir(&path, &child_prefix)?;
            }
        }
        Ok(())
    }

    pub fn get(&self, key: &str, name: &str) -> Option<&RegEntry> {
        self.values.get(&composite_key(key, name))
    }

    pub fn is_key_deleted(&self, key: &str) -> bool {
        self.deleted_keys.contains(key)
    }

    pub fn set(&mut self, key: &str, name: &str, value: RegValue) -> Result<(), String> {
        self.values.insert(composite_key(key, name), RegEntry::Value(value));
        self.flush_key(key)
    }

    pub fn delete_value(&mut self, key: &str, name: &str) -> Result<(), String> {
        self.values.insert(composite_key(key, name), RegEntry::Deleted);
        self.flush_key(key)
    }

    pub fn delete_key(&mut self, key: &str) -> Result<(), String> {
        self.deleted_keys.insert(key.to_owned());
        let dir = reg::friendly_to_overlay(key, &self.root);
        std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;
        let marker = reg::deleted_marker_path(&dir);
        std::fs::write(&marker, b"").map_err(|e| format!("write _deleted: {e}"))?;
        Ok(())
    }

    pub fn enumerate_overlay_values(&self, key: &str) -> Vec<(String, RegEntry)> {
        let prefix = format!("{key}|");
        self.values.iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(k, v)| {
                let vname = k[prefix.len()..].to_owned();
                (vname, v.clone())
            })
            .collect()
    }

    fn flush_key(&self, key: &str) -> Result<(), String> {
        let dir = reg::friendly_to_overlay(key, &self.root);
        std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;

        let prefix = format!("{key}|");
        let mut vals: FxHashMap<String, RegEntry> = FxHashMap::default();
        for (k, v) in &self.values {
            if k.starts_with(&prefix) {
                let vname = k[prefix.len()..].to_owned();
                vals.insert(vname, v.clone());
            }
        }

        let json = reg::serialize_values_json(&vals);
        let target = reg::values_json_path(&dir);
        let tmp = target.with_extension("json.tmp");
        std::fs::write(&tmp, json.as_bytes()).map_err(|e| format!("write tmp: {e}"))?;
        std::fs::rename(&tmp, &target).map_err(|e| format!("rename: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reg::{RegData, RegType, RegValue};

    fn tmp_root() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("workreg");
        std::fs::create_dir_all(&root).unwrap();
        (dir, root)
    }

    #[test]
    fn new_overlay_is_empty() {
        let (_dir, root) = tmp_root();
        let ov = RegOverlay::new(root);
        assert!(ov.get("hklm\\foo", "bar").is_none());
        assert!(!ov.is_key_deleted("hklm\\foo"));
    }

    #[test]
    fn set_then_get() {
        let (_dir, root) = tmp_root();
        let mut ov = RegOverlay::new(root);
        let val = RegValue { typ: RegType::Dword, data: RegData::U32(42) };
        ov.set("hklm\\software\\test", "count", val.clone()).unwrap();
        let entry = ov.get("hklm\\software\\test", "count").unwrap();
        assert_eq!(*entry, RegEntry::Value(val));
    }

    #[test]
    fn set_persists_to_disk() {
        let (_dir, root) = tmp_root();
        let mut ov = RegOverlay::new(root.clone());
        ov.set("hklm\\test", "name", RegValue { typ: RegType::Sz, data: RegData::String("hello".into()) }).unwrap();

        let json_path = root.join("hklm\\test\\values.json");
        assert!(json_path.exists(), "values.json should exist on disk");

        let raw = std::fs::read_to_string(&json_path).unwrap();
        assert!(raw.contains("hello"));
    }

    #[test]
    fn delete_value_creates_tombstone() {
        let (_dir, root) = tmp_root();
        let mut ov = RegOverlay::new(root);
        ov.set("hklm\\test", "val", RegValue { typ: RegType::Dword, data: RegData::U32(1) }).unwrap();
        ov.delete_value("hklm\\test", "val").unwrap();
        assert_eq!(*ov.get("hklm\\test", "val").unwrap(), RegEntry::Deleted);
    }

    #[test]
    fn delete_key_marks_deleted() {
        let (_dir, root) = tmp_root();
        let mut ov = RegOverlay::new(root.clone());
        ov.delete_key("hklm\\test\\sub").unwrap();
        assert!(ov.is_key_deleted("hklm\\test\\sub"));
        assert!(root.join("hklm\\test\\sub\\_deleted").exists());
    }

    #[test]
    fn load_from_disk_roundtrip() {
        let (_dir, root) = tmp_root();
        {
            let mut ov = RegOverlay::new(root.clone());
            ov.set("hklm\\app", "ver", RegValue { typ: RegType::Sz, data: RegData::String("1.0".into()) }).unwrap();
            ov.set("hklm\\app", "count", RegValue { typ: RegType::Dword, data: RegData::U32(5) }).unwrap();
            ov.delete_key("hklm\\removed").unwrap();
        }
        let ov2 = RegOverlay::load_from_disk(root).unwrap();
        assert_eq!(*ov2.get("hklm\\app", "ver").unwrap(),
            RegEntry::Value(RegValue { typ: RegType::Sz, data: RegData::String("1.0".into()) }));
        assert_eq!(*ov2.get("hklm\\app", "count").unwrap(),
            RegEntry::Value(RegValue { typ: RegType::Dword, data: RegData::U32(5) }));
        assert!(ov2.is_key_deleted("hklm\\removed"));
    }

    #[test]
    fn load_from_disk_empty_dir() {
        let (_dir, root) = tmp_root();
        let ov = RegOverlay::load_from_disk(root).unwrap();
        assert!(ov.get("hklm\\x", "y").is_none());
    }

    #[test]
    fn load_from_disk_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("doesnotexist");
        let ov = RegOverlay::load_from_disk(root).unwrap();
        assert!(ov.get("hklm\\x", "y").is_none());
    }

    #[test]
    fn enumerate_overlay_values_works() {
        let (_dir, root) = tmp_root();
        let mut ov = RegOverlay::new(root);
        ov.set("hklm\\app", "a", RegValue { typ: RegType::Sz, data: RegData::String("x".into()) }).unwrap();
        ov.set("hklm\\app", "b", RegValue { typ: RegType::Dword, data: RegData::U32(1) }).unwrap();
        ov.set("hklm\\other", "c", RegValue { typ: RegType::Dword, data: RegData::U32(2) }).unwrap();

        let vals = ov.enumerate_overlay_values("hklm\\app");
        assert_eq!(vals.len(), 2);
        let names: Vec<&str> = vals.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
    }

    #[test]
    fn atomic_write_no_tmp_leftover() {
        let (_dir, root) = tmp_root();
        let mut ov = RegOverlay::new(root.clone());
        ov.set("hklm\\test", "x", RegValue { typ: RegType::Sz, data: RegData::String("v".into()) }).unwrap();
        let tmp_path = root.join("hklm\\test\\values.json.tmp");
        assert!(!tmp_path.exists(), "temp file should not remain after atomic write");
    }

    #[test]
    fn overwrite_value() {
        let (_dir, root) = tmp_root();
        let mut ov = RegOverlay::new(root);
        ov.set("hklm\\test", "x", RegValue { typ: RegType::Dword, data: RegData::U32(1) }).unwrap();
        ov.set("hklm\\test", "x", RegValue { typ: RegType::Dword, data: RegData::U32(99) }).unwrap();
        let entry = ov.get("hklm\\test", "x").unwrap();
        assert_eq!(*entry, RegEntry::Value(RegValue { typ: RegType::Dword, data: RegData::U32(99) }));
    }
}
