// Content scan cache — memoizes (addr, size, content_hash) → is_clean.
// Avoids re-scanning unchanged JIT pages on repeated VirtualProtect transitions.
//
// Key: xxhash3(addr ++ size ++ bytes) → u128
// Value: bool (true = clean, no syscall found)
//
// Invalidation: hash naturally changes if bytes differ.
// Size bounded by capacity (LRU-like via quick_cache).

use quick_cache::sync::Cache;
use xxhash_rust::xxh3::Xxh3;

pub struct ScanCache {
    cache: Cache<u128, bool>,
}

impl ScanCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::new(8192), // up to 8K scanned regions cached
        }
    }

    fn compute_key(addr: usize, size: usize, bytes: &[u8]) -> u128 {
        let mut h = Xxh3::new();
        h.update(&addr.to_le_bytes());
        h.update(&size.to_le_bytes());
        h.update(bytes);
        h.digest128()
    }

    /// Lookup cached result. Returns Some(is_clean) if cached, None if miss.
    pub fn lookup(&self, addr: usize, size: usize, bytes: &[u8]) -> Option<bool> {
        let key = Self::compute_key(addr, size, bytes);
        self.cache.get(&key)
    }

    /// Store scan result.
    pub fn insert(&self, addr: usize, size: usize, bytes: &[u8], clean: bool) {
        let key = Self::compute_key(addr, size, bytes);
        self.cache.insert(key, clean);
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miss_returns_none() {
        let c = ScanCache::new();
        assert_eq!(c.lookup(0x1000, 64, &[0x90; 64]), None);
    }

    #[test]
    fn hit_after_insert() {
        let c = ScanCache::new();
        let bytes = [0x90u8; 64];
        c.insert(0x1000, 64, &bytes, true);
        assert_eq!(c.lookup(0x1000, 64, &bytes), Some(true));
    }

    #[test]
    fn miss_on_different_bytes() {
        let c = ScanCache::new();
        c.insert(0x1000, 64, &[0x90; 64], true);
        // Change one byte → different hash → miss
        let mut changed = [0x90u8; 64];
        changed[0] = 0x0F;
        assert_eq!(c.lookup(0x1000, 64, &changed), None);
    }

    #[test]
    fn miss_on_different_addr() {
        let c = ScanCache::new();
        c.insert(0x1000, 64, &[0x90; 64], true);
        assert_eq!(c.lookup(0x2000, 64, &[0x90; 64]), None);
    }

    #[test]
    fn stores_false_for_dirty() {
        let c = ScanCache::new();
        c.insert(0x1000, 64, &[0x0F, 0x05], false);
        assert_eq!(c.lookup(0x1000, 64, &[0x0F, 0x05]), Some(false));
    }

    #[test]
    fn concurrent_access() {
        use std::sync::Arc;
        let c = Arc::new(ScanCache::new());
        let mut handles = vec![];
        for i in 0..8 {
            let cc = c.clone();
            handles.push(std::thread::spawn(move || {
                let bytes = vec![i as u8; 64];
                cc.insert(i * 0x1000, 64, &bytes, true);
                assert_eq!(cc.lookup(i * 0x1000, 64, &bytes), Some(true));
            }));
        }
        for h in handles { h.join().unwrap(); }
    }
}
