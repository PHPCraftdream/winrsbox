// Hot resource access stats — aggregates which paths/devices/registry keys
// are accessed most frequently. Background task flushes a snapshot to
// <state_dir>/hot-stats.json no more than once per FLUSH_INTERVAL.

use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Minimum interval between disk flushes.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// How many top paths to keep in the snapshot.
pub const TOP_N: usize = 50;

#[derive(Default)]
pub struct HotStats {
    /// Per-path access counters. Keyed by lowercased DOS path.
    pub fs_paths: papaya::HashMap<Arc<str>, PathCounters>,
    /// Per-registry-key counters.
    pub reg_keys: papaya::HashMap<Arc<str>, PathCounters>,
    /// Per-network-host counters.
    pub net_hosts: papaya::HashMap<Arc<str>, PathCounters>,
    /// Total event counts (cheap atomics).
    pub totals: Totals,
}

#[derive(Default)]
pub struct Totals {
    pub fs_decides: AtomicU64,
    pub fs_denies: AtomicU64,
    pub fs_cows: AtomicU64,
    pub fs_mocks: AtomicU64,
    pub reg_decides: AtomicU64,
    pub reg_denies: AtomicU64,
    pub net_decides: AtomicU64,
    pub net_denies: AtomicU64,
    pub violations: AtomicU64,
    pub hellos: AtomicU64,
    pub children: AtomicU64,
}

#[derive(Default)]
pub struct PathCounters {
    pub reads: AtomicU64,
    pub writes: AtomicU64,
    pub denies: AtomicU64,
}

impl HotStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record_fs(&self, path: &str, write: bool, denied: bool) {
        let key: Arc<str> = path.into();
        let map = self.fs_paths.pin();
        // get-or-insert
        let counters = match map.get(&key) {
            Some(c) => c,
            None => {
                map.insert(key.clone(), PathCounters::default());
                map.get(&key).expect("just inserted")
            }
        };
        if denied {
            counters.denies.fetch_add(1, Ordering::Relaxed);
        } else if write {
            counters.writes.fetch_add(1, Ordering::Relaxed);
        } else {
            counters.reads.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_reg(&self, key_path: &str, write: bool, denied: bool) {
        let key: Arc<str> = key_path.into();
        let map = self.reg_keys.pin();
        let counters = match map.get(&key) {
            Some(c) => c,
            None => {
                map.insert(key.clone(), PathCounters::default());
                map.get(&key).expect("just inserted")
            }
        };
        if denied {
            counters.denies.fetch_add(1, Ordering::Relaxed);
        } else if write {
            counters.writes.fetch_add(1, Ordering::Relaxed);
        } else {
            counters.reads.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_net(&self, host: &str, denied: bool) {
        let key: Arc<str> = host.into();
        let map = self.net_hosts.pin();
        let counters = match map.get(&key) {
            Some(c) => c,
            None => {
                map.insert(key.clone(), PathCounters::default());
                map.get(&key).expect("just inserted")
            }
        };
        if denied {
            counters.denies.fetch_add(1, Ordering::Relaxed);
        } else {
            counters.reads.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Build a JSON-serializable snapshot of current state.
    pub fn snapshot(&self) -> Snapshot {
        let fs_map = self.fs_paths.pin();
        let mut fs_top: Vec<TopEntry> = fs_map.iter()
            .map(|(k, v)| TopEntry {
                path: k.to_string(),
                reads: v.reads.load(Ordering::Relaxed),
                writes: v.writes.load(Ordering::Relaxed),
                denies: v.denies.load(Ordering::Relaxed),
            })
            .collect();
        fs_top.sort_by(|a, b| (b.reads + b.writes + b.denies).cmp(&(a.reads + a.writes + a.denies)));
        fs_top.truncate(TOP_N);

        let reg_map = self.reg_keys.pin();
        let mut reg_top: Vec<TopEntry> = reg_map.iter()
            .map(|(k, v)| TopEntry {
                path: k.to_string(),
                reads: v.reads.load(Ordering::Relaxed),
                writes: v.writes.load(Ordering::Relaxed),
                denies: v.denies.load(Ordering::Relaxed),
            })
            .collect();
        reg_top.sort_by(|a, b| (b.reads + b.writes + b.denies).cmp(&(a.reads + a.writes + a.denies)));
        reg_top.truncate(TOP_N);

        let net_map = self.net_hosts.pin();
        let mut net_top: Vec<TopEntry> = net_map.iter()
            .map(|(k, v)| TopEntry {
                path: k.to_string(),
                reads: v.reads.load(Ordering::Relaxed),
                writes: 0,
                denies: v.denies.load(Ordering::Relaxed),
            })
            .collect();
        net_top.sort_by(|a, b| (b.reads + b.denies).cmp(&(a.reads + a.denies)));
        net_top.truncate(TOP_N);

        Snapshot {
            ts: chrono_ts(),
            totals: TotalsSnapshot {
                fs_decides: self.totals.fs_decides.load(Ordering::Relaxed),
                fs_denies: self.totals.fs_denies.load(Ordering::Relaxed),
                fs_cows: self.totals.fs_cows.load(Ordering::Relaxed),
                fs_mocks: self.totals.fs_mocks.load(Ordering::Relaxed),
                reg_decides: self.totals.reg_decides.load(Ordering::Relaxed),
                reg_denies: self.totals.reg_denies.load(Ordering::Relaxed),
                net_decides: self.totals.net_decides.load(Ordering::Relaxed),
                net_denies: self.totals.net_denies.load(Ordering::Relaxed),
                violations: self.totals.violations.load(Ordering::Relaxed),
                hellos: self.totals.hellos.load(Ordering::Relaxed),
                children: self.totals.children.load(Ordering::Relaxed),
            },
            fs_top,
            reg_top,
            net_top,
        }
    }
}

#[derive(Serialize)]
pub struct Snapshot {
    pub ts: String,
    pub totals: TotalsSnapshot,
    pub fs_top: Vec<TopEntry>,
    pub reg_top: Vec<TopEntry>,
    pub net_top: Vec<TopEntry>,
}

#[derive(Serialize)]
pub struct TotalsSnapshot {
    pub fs_decides: u64,
    pub fs_denies: u64,
    pub fs_cows: u64,
    pub fs_mocks: u64,
    pub reg_decides: u64,
    pub reg_denies: u64,
    pub net_decides: u64,
    pub net_denies: u64,
    pub violations: u64,
    pub hellos: u64,
    pub children: u64,
}

#[derive(Serialize)]
pub struct TopEntry {
    pub path: String,
    pub reads: u64,
    pub writes: u64,
    pub denies: u64,
}

fn chrono_ts() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{secs}")
}

/// Throttled writer: writes a snapshot to `<state_dir>/hot-stats.json`
/// no more than once per FLUSH_INTERVAL. Safe to call from any thread.
pub struct ThrottledFlusher {
    stats: Arc<HotStats>,
    path: PathBuf,
    last_flush: std::sync::Mutex<Instant>,
}

impl ThrottledFlusher {
    pub fn new(stats: Arc<HotStats>, path: PathBuf) -> Self {
        Self {
            stats,
            path,
            last_flush: std::sync::Mutex::new(Instant::now() - FLUSH_INTERVAL),
        }
    }

    /// If enough time has passed since the last flush, write a snapshot.
    /// Otherwise, no-op. Returns true if a flush occurred.
    pub fn maybe_flush(&self) -> bool {
        let mut last = match self.last_flush.try_lock() {
            Ok(l) => l,
            Err(_) => return false, // another thread is already flushing
        };
        if last.elapsed() < FLUSH_INTERVAL {
            return false;
        }
        *last = Instant::now();
        drop(last);

        let snapshot = self.stats.snapshot();
        let json = match serde_json::to_string_pretty(&snapshot) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // Write atomically: tmp file + rename
        let tmp = self.path.with_extension("json.tmp");
        if std::fs::write(&tmp, &json).is_err() { return false; }
        let _ = std::fs::rename(&tmp, &self.path);
        true
    }

    /// Force a flush regardless of interval (used on shutdown).
    pub fn flush_now(&self) {
        let snapshot = self.stats.snapshot();
        if let Ok(json) = serde_json::to_string_pretty(&snapshot) {
            let _ = std::fs::write(&self.path, json);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_fs_increments() {
        let s = HotStats::new();
        s.record_fs("c:\\test", false, false);
        s.record_fs("c:\\test", false, false);
        s.record_fs("c:\\test", true, false);
        s.record_fs("c:\\test", false, true);

        let snap = s.snapshot();
        let entry = snap.fs_top.iter().find(|e| e.path == "c:\\test").unwrap();
        assert_eq!(entry.reads, 2);
        assert_eq!(entry.writes, 1);
        assert_eq!(entry.denies, 1);
    }

    #[test]
    fn top_n_sorted_by_total() {
        let s = HotStats::new();
        for _ in 0..10 { s.record_fs("a", false, false); }
        for _ in 0..5  { s.record_fs("b", false, false); }
        for _ in 0..20 { s.record_fs("c", false, false); }

        let snap = s.snapshot();
        assert_eq!(snap.fs_top[0].path, "c");
        assert_eq!(snap.fs_top[1].path, "a");
        assert_eq!(snap.fs_top[2].path, "b");
    }

    #[test]
    fn throttle_blocks_rapid_writes() {
        let tmp = std::env::temp_dir().join("winrsbox-hot-stats-test.json");
        let _ = std::fs::remove_file(&tmp);
        let stats = HotStats::new();
        stats.record_fs("c:\\x", false, false);
        let f = ThrottledFlusher::new(stats, tmp.clone());

        // First flush should succeed (we initialize last_flush in the past).
        assert!(f.maybe_flush(), "first flush should succeed");
        // Immediate second flush should be throttled.
        assert!(!f.maybe_flush(), "second flush within 5s should be throttled");

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn snapshot_serializes() {
        let s = HotStats::new();
        s.record_fs("c:\\app.exe", false, false);
        s.record_reg(r"HKLM\Software\Test", true, true);
        s.record_net("api.anthropic.com:443", false);

        let snap = s.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        assert!(json.contains("c:\\\\app.exe"));
        assert!(json.contains("HKLM"));
        assert!(json.contains("anthropic"));
    }
}
