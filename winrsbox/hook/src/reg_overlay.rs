// Registry CoW overlay — stores sandboxed registry writes in a HashMap.
// Reads check overlay first, then fall back to the real registry.
//
// This is Phase 2 "in-memory overlay" — not a real hive file.
// Data persists for the lifetime of the sandboxed process.
// For cross-session persistence, the overlay could be serialized to
// <state_dir>/reg-overlay.json on process exit (future work).

use std::collections::HashMap;
use std::sync::Mutex;

static OVERLAY: std::sync::OnceLock<Mutex<RegOverlay>> = std::sync::OnceLock::new();

pub fn overlay() -> &'static Mutex<RegOverlay> {
    OVERLAY.get_or_init(|| Mutex::new(RegOverlay::new()))
}

#[derive(Debug)]
pub struct RegOverlay {
    /// key_path (lowercase) → { value_name → RegValue }
    keys: HashMap<String, HashMap<String, RegValue>>,
    /// Tombstones: key_path → set of deleted value names
    tombstones: HashMap<String, Vec<String>>,
    /// Deleted keys (the key itself was deleted)
    deleted_keys: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RegValue {
    pub value_type: u32,
    pub data: Vec<u8>,
}

impl RegOverlay {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            tombstones: HashMap::new(),
            deleted_keys: Vec::new(),
        }
    }

    /// Write a value to the overlay.
    pub fn set_value(&mut self, key_path: &str, value_name: &str, value_type: u32, data: &[u8]) {
        let lower = key_path.to_ascii_lowercase();
        // Remove from tombstones if previously deleted
        if let Some(ts) = self.tombstones.get_mut(&lower) {
            ts.retain(|v| !v.eq_ignore_ascii_case(value_name));
        }
        let values = self.keys.entry(lower).or_insert_with(HashMap::new);
        values.insert(value_name.to_ascii_lowercase(), RegValue {
            value_type,
            data: data.to_vec(),
        });
    }

    /// Read a value from the overlay. Returns None if not in overlay
    /// (caller should fall back to real registry).
    pub fn get_value(&self, key_path: &str, value_name: &str) -> Option<&RegValue> {
        let lower = key_path.to_ascii_lowercase();
        let vname = value_name.to_ascii_lowercase();
        // Check tombstone first
        if let Some(ts) = self.tombstones.get(&lower) {
            if ts.iter().any(|v| v.eq_ignore_ascii_case(&vname)) {
                return None; // deleted in overlay — don't fall back
            }
        }
        self.keys.get(&lower)?.get(&vname)
    }

    /// Check if a value was tombstoned (deleted in overlay).
    pub fn is_tombstoned(&self, key_path: &str, value_name: &str) -> bool {
        let lower = key_path.to_ascii_lowercase();
        let vname = value_name.to_ascii_lowercase();
        if let Some(ts) = self.tombstones.get(&lower) {
            return ts.iter().any(|v| v.eq_ignore_ascii_case(&vname));
        }
        false
    }

    /// Delete a value (add tombstone).
    pub fn delete_value(&mut self, key_path: &str, value_name: &str) {
        let lower = key_path.to_ascii_lowercase();
        let vname = value_name.to_ascii_lowercase();
        // Remove from overlay values
        if let Some(values) = self.keys.get_mut(&lower) {
            values.remove(&vname);
        }
        // Add tombstone
        self.tombstones.entry(lower).or_insert_with(Vec::new).push(vname);
    }

    /// Delete an entire key.
    pub fn delete_key(&mut self, key_path: &str) {
        let lower = key_path.to_ascii_lowercase();
        self.keys.remove(&lower);
        self.deleted_keys.push(lower);
    }

    /// Check if a key was deleted in overlay.
    pub fn is_key_deleted(&self, key_path: &str) -> bool {
        let lower = key_path.to_ascii_lowercase();
        self.deleted_keys.iter().any(|k| lower.starts_with(k))
    }

    /// Check if overlay has any values for a key.
    pub fn has_key(&self, key_path: &str) -> bool {
        let lower = key_path.to_ascii_lowercase();
        self.keys.contains_key(&lower)
    }

    pub fn stats(&self) -> (usize, usize, usize) {
        let values: usize = self.keys.values().map(|v| v.len()).sum();
        let tombstones: usize = self.tombstones.values().map(|v| v.len()).sum();
        (self.keys.len(), values, tombstones)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_get() {
        let mut ov = RegOverlay::new();
        ov.set_value(r"HKCU\Software\Test", "MyValue", 1, b"hello");
        let v = ov.get_value(r"HKCU\Software\Test", "MyValue").unwrap();
        assert_eq!(v.data, b"hello");
        assert_eq!(v.value_type, 1);
    }

    #[test]
    fn case_insensitive() {
        let mut ov = RegOverlay::new();
        ov.set_value(r"HKCU\Software\Test", "Value", 1, b"x");
        assert!(ov.get_value(r"hkcu\software\test", "value").is_some());
    }

    #[test]
    fn tombstone() {
        let mut ov = RegOverlay::new();
        ov.set_value(r"HKCU\Software\Test", "V", 1, b"x");
        ov.delete_value(r"HKCU\Software\Test", "V");
        assert!(ov.get_value(r"HKCU\Software\Test", "V").is_none());
        assert!(ov.is_tombstoned(r"HKCU\Software\Test", "V"));
    }

    #[test]
    fn delete_key() {
        let mut ov = RegOverlay::new();
        ov.set_value(r"HKCU\Software\Test", "V", 1, b"x");
        ov.delete_key(r"HKCU\Software\Test");
        assert!(ov.is_key_deleted(r"HKCU\Software\Test"));
        assert!(ov.is_key_deleted(r"HKCU\Software\Test\SubKey"));
    }

    #[test]
    fn stats() {
        let mut ov = RegOverlay::new();
        ov.set_value(r"HKCU\Software\A", "V1", 1, b"x");
        ov.set_value(r"HKCU\Software\A", "V2", 1, b"y");
        ov.set_value(r"HKCU\Software\B", "V3", 1, b"z");
        ov.delete_value(r"HKCU\Software\B", "V3");
        let (keys, values, tombstones) = ov.stats();
        assert_eq!(keys, 2);
        assert_eq!(values, 2); // V1, V2 remain; V3 removed from overlay
        assert_eq!(tombstones, 1);
    }
}
