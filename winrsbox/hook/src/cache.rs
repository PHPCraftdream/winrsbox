// Thread-safe in-process LRU for policy decisions.
// Avoids an IPC round-trip on every Nt* call.
// Capacity 8192 entries; xxh3 key = lowercase path bytes + write flag byte.

use policy::Decision;
use quick_cache::sync::Cache;

pub struct HookCache {
    inner: Cache<u64, Decision>,
}

impl HookCache {
    pub fn new() -> Self {
        Self { inner: Cache::new(8192) }
    }

    fn key(dos_lower: &str, write: bool) -> u64 {
        use xxhash_rust::xxh3::Xxh3;
        let mut h = Xxh3::new();
        h.update(dos_lower.as_bytes());
        h.update(&[u8::from(write)]);
        h.digest()
    }

    /// Lowercase-ASCII a byte slice into a stack buffer and hash in one shot.
    /// Falls back to heap for paths > 512 bytes (exceedingly rare).
    fn caseless_key(path: &str, write: bool) -> u64 {
        use xxhash_rust::xxh3::Xxh3;
        let bytes = path.as_bytes();
        let mut h = Xxh3::new();
        if bytes.len() <= 512 {
            let mut buf = [0u8; 512];
            for (i, &b) in bytes.iter().enumerate() {
                buf[i] = b.to_ascii_lowercase();
            }
            h.update(&buf[..bytes.len()]);
        } else {
            // Rare long path: process in chunks to avoid per-byte update overhead.
            let mut buf = [0u8; 512];
            let mut remaining = bytes;
            while !remaining.is_empty() {
                let chunk_len = remaining.len().min(512);
                let chunk = &remaining[..chunk_len];
                for (i, &b) in chunk.iter().enumerate() {
                    buf[i] = b.to_ascii_lowercase();
                }
                h.update(&buf[..chunk_len]);
                remaining = &remaining[chunk_len..];
            }
        }
        h.update(&[u8::from(write)]);
        h.digest()
    }

    pub fn insert(&self, dos_lower: &str, write: bool, decision: Decision) {
        self.inner.insert(Self::key(dos_lower, write), decision);
    }

    pub fn invalidate(&self, dos_lower: &str) {
        self.inner.remove(&Self::key(dos_lower, false));
        self.inner.remove(&Self::key(dos_lower, true));
    }

    /// Compute cache key from a str that may be mixed-case: lowercases per byte
    /// (ASCII only — Windows paths are ASCII in the overwhelming majority of cases)
    /// without allocating a String.
    pub fn get_caseless(&self, path: &str, write: bool) -> Option<Decision> {
        let k = Self::caseless_key(path, write);
        self.inner.get(&k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy::{Decision, Mode};

    #[test]
    fn caseless_matches_lowercased() {
        let cache = HookCache::new();
        let d = Decision { mode: Mode::Passthrough, overlay: None, cow_from: None, mock_payload: None };
        cache.insert("c:\\users\\alice\\foo.txt", false, d.clone());
        assert!(cache.get_caseless("C:\\Users\\Alice\\Foo.TXT", false).is_some());
        assert!(cache.get_caseless("c:\\users\\alice\\foo.txt", false).is_some());
    }

    #[test]
    fn write_flag_prevents_cross_hit() {
        let cache = HookCache::new();
        let d = Decision { mode: Mode::Passthrough, overlay: None, cow_from: None, mock_payload: None };
        cache.insert("c:\\x", false, d.clone());
        assert!(cache.get_caseless("c:\\x", true).is_none());
    }

    #[test]
    fn invalidate_removes_both_flags() {
        let cache = HookCache::new();
        let d = Decision { mode: Mode::Passthrough, overlay: None, cow_from: None, mock_payload: None };
        cache.insert("c:\\x", false, d.clone());
        cache.insert("c:\\x", true, d.clone());
        cache.invalidate("c:\\x");
        assert!(cache.get_caseless("c:\\x", false).is_none());
        assert!(cache.get_caseless("c:\\x", true).is_none());
    }

    #[test]
    fn different_paths_no_collision() {
        let cache = HookCache::new();
        let d1 = Decision { mode: Mode::Passthrough, overlay: None, cow_from: None, mock_payload: None };
        let d2 = Decision { mode: Mode::Deny, overlay: None, cow_from: None, mock_payload: None };
        cache.insert("c:\\a", false, d1);
        cache.insert("c:\\b", false, d2);
        let r = cache.get_caseless("c:\\a", false);
        assert!(r.is_some());
        assert_eq!(r.unwrap().mode, Mode::Passthrough);
        let r = cache.get_caseless("c:\\b", false);
        assert!(r.is_some());
        assert_eq!(r.unwrap().mode, Mode::Deny);
    }

    #[test]
    fn non_ascii_preserved() {
        let cache = HookCache::new();
        let d = Decision { mode: Mode::Passthrough, overlay: None, cow_from: None, mock_payload: None };
        cache.insert("c:\\\u{03A9}.txt", false, d.clone());
        let r = cache.get_caseless("c:\\\u{03A9}.txt", false);
        assert!(r.is_some());
    }
}
