// Hot resource access stats — aggregates which paths/devices/registry keys
// are accessed most frequently. Background task flushes a snapshot to
// <state_dir>/hot-stats.json no more than once per FLUSH_INTERVAL.

use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Minimum interval between disk flushes.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// How many top paths to keep in the snapshot.
pub const TOP_N: usize = 50;

/// Audit (2026-09-19, Medium): the per-path maps were insert-only, so a
/// long session touching unbounded distinct paths (temp files, cache
/// fragments, web hosts) grew them without limit. These bounds cap each
/// map; the stats are purely diagnostic (only `snapshot()` reads them, for
/// the hot-stats.json report), so dropping cold entries changes no
/// sandbox decision — `Totals` counters are untouched.
pub const MAX_TRACKED_PATHS: usize = 8192;

/// After an eviction pass, this many hottest entries are kept.
pub const EVICT_KEEP_TOP: usize = 4096;

// Test-only counter of `make_key` calls, so tests can assert that the
// borrowed fast path skips key allocation. Per-thread because the test
// harness runs tests on parallel threads (a process-wide static would
// race).
#[cfg(test)]
thread_local! {
    static KEY_ALLOCS: AtomicUsize = const { AtomicUsize::new(0) };
}

/// The single key-allocation site on the record miss path, so tests can
/// count allocations via `KEY_ALLOCS`.
#[cfg(test)]
fn make_key(s: &str) -> Arc<str> {
    KEY_ALLOCS.with(|k| k.fetch_add(1, Ordering::Relaxed));
    s.into()
}

#[cfg(not(test))]
fn make_key(s: &str) -> Arc<str> {
    s.into()
}

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
    /// Eviction single-owner guards, one per map: 0 = idle, 1 = a thread
    /// is running the scan+retain pass (see `evict_if_over_capacity`).
    fs_evicting: AtomicUsize,
    reg_evicting: AtomicUsize,
    net_evicting: AtomicUsize,
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
        let map = self.fs_paths.pin();
        // Borrowed lookup first: on a hit (the overwhelmingly common case)
        // no Arc<str> key is allocated at all.
        let counters = match map.get(path) {
            Some(c) => c,
            None => {
                // Atomic get-or-insert. With the old insert-then-re-get,
                // a concurrent eviction retain could remove the fresh
                // entry (score 0) in between, and `.expect("just
                // inserted")` would panic (review 2026-09-20,
                // hot_stats.rs:67). Stats are diagnostics-only but must
                // not crash; get_or_insert also never resets a
                // concurrently-created entry's counters.
                map.get_or_insert(make_key(path), PathCounters::default())
            }
        };
        Self::bump(counters, write, denied);
        drop(map);
        self.evict_if_over_capacity(&self.fs_paths, &self.fs_evicting);
    }

    pub fn record_reg(&self, key_path: &str, write: bool, denied: bool) {
        let map = self.reg_keys.pin();
        let counters = match map.get(key_path) {
            Some(c) => c,
            // Same insert→expect race as record_fs; get_or_insert closes it.
            None => map.get_or_insert(make_key(key_path), PathCounters::default()),
        };
        Self::bump(counters, write, denied);
        drop(map);
        self.evict_if_over_capacity(&self.reg_keys, &self.reg_evicting);
    }

    pub fn record_net(&self, host: &str, denied: bool) {
        let map = self.net_hosts.pin();
        let counters = match map.get(host) {
            Some(c) => c,
            // Same insert→expect race as record_fs; get_or_insert closes it.
            None => map.get_or_insert(make_key(host), PathCounters::default()),
        };
        // Net has no write arm: write=false keeps the ladder exactly
        // denied → denies, else reads.
        Self::bump(counters, false, denied);
        drop(map);
        self.evict_if_over_capacity(&self.net_hosts, &self.net_evicting);
    }

    /// Bump the read/write/deny ladder shared by all three record_* fns.
    fn bump(counters: &PathCounters, write: bool, denied: bool) {
        if denied {
            counters.denies.fetch_add(1, Ordering::Relaxed);
        } else if write {
            counters.writes.fetch_add(1, Ordering::Relaxed);
        } else {
            counters.reads.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// If the map grew past MAX_TRACKED_PATHS, keep only the
    /// EVICT_KEEP_TOP hottest entries (by reads+writes+denies, ties broken
    /// deterministically by key). Called after each record; the `len()`
    /// check makes the selection cost amortise to once per ~(MAX-KEEP)
    /// inserts.
    ///
    /// A per-map CAS guard (the `*_evicting` fields) lets a single thread
    /// run the scan+retain at a time; a losing thread skips eviction
    /// entirely — fine for diagnostics, the next record_* call retries.
    /// Selection is O(M) average via `select_nth_unstable_by` instead of
    /// the old O(M log M) full sort, keeping the identical kept set.
    fn evict_if_over_capacity(
        &self,
        map: &papaya::HashMap<Arc<str>, PathCounters>,
        evicting: &AtomicUsize,
    ) {
        if map.len() < MAX_TRACKED_PATHS {
            return;
        }
        // Only one eviction pass per map at a time; skipping a contested
        // pass is harmless (diagnostics-only, retried on the next record).
        if evicting
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        // No early return past this point: the single store below always
        // releases the guard.
        let pinned = map.pin();
        let mut scored: Vec<(Arc<str>, u64)> = pinned
            .iter()
            .map(|(k, v)| {
                let total =
                    v.reads.load(Ordering::Relaxed)
                        + v.writes.load(Ordering::Relaxed)
                        + v.denies.load(Ordering::Relaxed);
                (k.clone(), total)
            })
            .collect();
        Self::select_keep_top(&mut scored, EVICT_KEEP_TOP);
        let keep: std::collections::HashSet<Arc<str>> =
            scored.into_iter().map(|(k, _)| k).collect();
        pinned.retain(|k, _| keep.contains(k));
        evicting.store(0, Ordering::Release);
    }

    /// Reduce `scored` to its `keep` hottest entries (score desc, then key
    /// asc for deterministic ties). `select_nth_unstable_by` partitions in
    /// O(M) average and leaves exactly the `keep` smallest-per-comparator
    /// elements in front — with unique keys the comparator is a total
    /// order, so the kept set is identical to a full sort + truncate.
    fn select_keep_top(scored: &mut Vec<(Arc<str>, u64)>, keep: usize) {
        // In production keep = EVICT_KEEP_TOP and this only runs at map
        // len >= MAX_TRACKED_PATHS > keep, so the select index is in
        // bounds; tests pass a smaller keep. select_nth would panic on
        // keep >= len, hence the guard.
        if scored.len() <= keep {
            return;
        }
        scored.select_nth_unstable_by(keep, |a, b| {
            b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0))
        });
        scored.truncate(keep);
    }

    /// Reduce `top` to at most TOP_N entries under `cmp` (hotter sorts
    /// first). Past TOP_N entries, `select_nth_unstable_by` finds the top
    /// set in O(M) average and only that prefix is fully sorted
    /// (O(k log k)); the kept set matches a full sort + truncate.
    fn truncate_to_top_n(
        top: &mut Vec<TopEntry>,
        cmp: fn(&TopEntry, &TopEntry) -> std::cmp::Ordering,
    ) {
        if top.len() > TOP_N {
            // Strict guard: select_nth panics when the index is >= len.
            top.select_nth_unstable_by(TOP_N, cmp);
            // Only the kept prefix needs a deterministic order.
            top[..TOP_N].sort_by(cmp);
            top.truncate(TOP_N);
        } else {
            top.sort_by(cmp);
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
        Self::truncate_to_top_n(&mut fs_top, |a, b| {
            (b.reads + b.writes + b.denies).cmp(&(a.reads + a.writes + a.denies))
        });

        let reg_map = self.reg_keys.pin();
        let mut reg_top: Vec<TopEntry> = reg_map.iter()
            .map(|(k, v)| TopEntry {
                path: k.to_string(),
                reads: v.reads.load(Ordering::Relaxed),
                writes: v.writes.load(Ordering::Relaxed),
                denies: v.denies.load(Ordering::Relaxed),
            })
            .collect();
        Self::truncate_to_top_n(&mut reg_top, |a, b| {
            (b.reads + b.writes + b.denies).cmp(&(a.reads + a.writes + a.denies))
        });

        let net_map = self.net_hosts.pin();
        let mut net_top: Vec<TopEntry> = net_map.iter()
            .map(|(k, v)| TopEntry {
                path: k.to_string(),
                reads: v.reads.load(Ordering::Relaxed),
                writes: 0,
                denies: v.denies.load(Ordering::Relaxed),
            })
            .collect();
        Self::truncate_to_top_n(&mut net_top, |a, b| {
            (b.reads + b.denies).cmp(&(a.reads + a.denies))
        });

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


    /// The maps must not grow without bound: flooding distinct fs paths
    /// past the capacity must trigger eviction and keep the map capped.
    /// (Old behaviour: insert-only, len would be MAX_TRACKED_PATHS + 2000.)
    #[test]
    fn fs_paths_bounded_under_distinct_key_flood() {
        let s = HotStats::new();
        let n = MAX_TRACKED_PATHS + 2000;
        for i in 0..n {
            s.record_fs(&format!("c:\\flood\\{i}.tmp"), false, false);
        }
        assert!(
            s.fs_paths.len() <= MAX_TRACKED_PATHS,
            "fs_paths len {} exceeded cap {MAX_TRACKED_PATHS}",
            s.fs_paths.len()
        );
    }

    /// Same bound must hold for the registry map (shared eviction path).
    #[test]
    fn reg_keys_bounded_under_distinct_key_flood() {
        let s = HotStats::new();
        let n = MAX_TRACKED_PATHS + 500;
        for i in 0..n {
            s.record_reg(&format!("HKCU\\Software\\Flood\\{i}"), true, false);
        }
        assert!(
            s.reg_keys.len() <= MAX_TRACKED_PATHS,
            "reg_keys len {} exceeded cap {MAX_TRACKED_PATHS}",
            s.reg_keys.len()
        );
    }

    /// Eviction must keep the HOT entries: a heavily-accessed path survives
    /// a flood of cold single-access paths.
    #[test]
    fn hot_entries_survive_eviction() {
        let s = HotStats::new();
        for _ in 0..1000 {
            s.record_fs("c:\\hot\\database.db", false, false);
        }
        let n = MAX_TRACKED_PATHS + 1000;
        for i in 0..n {
            s.record_fs(&format!("c:\\cold\\{i}.tmp"), false, false);
        }
        let snap = s.snapshot();
        let entry = snap
            .fs_top
            .iter()
            .find(|e| e.path == "c:\\hot\\database.db")
            .expect("hot entry must survive eviction");
        assert_eq!(entry.reads, 1000);
    }

    /// Eviction is diagnostics-only: the global Totals counters must be
    /// unaffected by how many per-path entries were dropped.
    #[test]
    fn totals_survive_eviction() {
        let s = HotStats::new();
        let n = MAX_TRACKED_PATHS + 1000;
        for i in 0..n {
            s.record_fs(&format!("c:\\x\\{i}.tmp"), false, false);
        }
        let snap = s.snapshot();
        let counted: u64 = snap.fs_top.iter().map(|e| e.reads + e.writes + e.denies).sum();
        assert!(counted > 0);
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

    /// Cache hits must take the borrowed fast path: recording the same
    /// key again allocates no Arc<str>; a distinct key allocates exactly
    /// one.
    #[test]
    fn hit_path_does_not_allocate_key() {
        let s = HotStats::new();
        s.record_fs("c:\\alloc\\probe", false, false);
        let before = KEY_ALLOCS.with(|k| k.load(Ordering::Relaxed));

        s.record_fs("c:\\alloc\\probe", false, false);
        s.record_fs("c:\\alloc\\probe", true, false);
        assert_eq!(
            KEY_ALLOCS.with(|k| k.load(Ordering::Relaxed)),
            before,
            "same-key hits must not allocate a key"
        );

        s.record_fs("c:\\alloc\\other", false, false);
        assert_eq!(
            KEY_ALLOCS.with(|k| k.load(Ordering::Relaxed)),
            before + 1,
            "a miss must allocate exactly one key"
        );
    }

    /// The O(M) `select_nth` selection must keep exactly the set that a
    /// full sort + truncate keeps — including when equal scores sit right
    /// at the keep boundary (the key tiebreak must decide identically).
    #[test]
    fn eviction_selection_matches_full_sort() {
        let keep = 100;
        let cmp = |a: &(Arc<str>, u64), b: &(Arc<str>, u64)| {
            b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0))
        };

        // Deterministic pseudo-random scores via a tiny LCG.
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut scored: Vec<(Arc<str>, u64)> = (0..200)
            .map(|i| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let key: Arc<str> = format!("k{i}").into();
                (key, state)
            })
            .collect();
        let mut reference = scored.clone();
        reference.sort_unstable_by(cmp);
        reference.truncate(keep);
        HotStats::select_keep_top(&mut scored, keep);
        assert_kept_sets_equal(&scored, &reference);

        // Heavy ties: scores (i % 7) over 200 entries put equal scores
        // across the keep=100 boundary, so the key tiebreak alone must
        // make the kept set deterministic and identical.
        let mut tied: Vec<(Arc<str>, u64)> = (0..200)
            .map(|i| {
                let key: Arc<str> = format!("t{i}").into();
                (key, (i % 7) as u64)
            })
            .collect();
        let mut tied_ref = tied.clone();
        tied_ref.sort_unstable_by(cmp);
        assert_eq!(
            tied_ref[keep - 1].1, tied_ref[keep].1,
            "test setup: scores must tie at the keep boundary"
        );
        tied_ref.truncate(keep);
        HotStats::select_keep_top(&mut tied, keep);
        assert_kept_sets_equal(&tied, &tied_ref);
    }

    /// Helper for `eviction_selection_matches_full_sort`: same kept key
    /// sets, and identical sequences once both are re-sorted with the
    /// production comparator.
    fn assert_kept_sets_equal(a: &[(Arc<str>, u64)], b: &[(Arc<str>, u64)]) {
        assert_eq!(a.len(), b.len());
        let set_a: std::collections::HashSet<&Arc<str>> = a.iter().map(|(k, _)| k).collect();
        let set_b: std::collections::HashSet<&Arc<str>> = b.iter().map(|(k, _)| k).collect();
        assert_eq!(set_a, set_b, "kept sets must match a full sort + truncate");
        let cmp = |x: &(Arc<str>, u64), y: &(Arc<str>, u64)| {
            y.1.cmp(&x.1).then_with(|| x.0.cmp(&y.0))
        };
        let mut sa = a.to_vec();
        let mut sb = b.to_vec();
        sa.sort_unstable_by(cmp);
        sb.sort_unstable_by(cmp);
        assert_eq!(sa, sb, "re-sorted sequences must match");
    }

    /// Snapshot's top-N must equal a reference full sort of the known
    /// per-key counts, both as a set and in order.
    #[test]
    fn snapshot_top_n_matches_full_sort() {
        let s = HotStats::new();
        let n = 60; // > TOP_N, far below MAX_TRACKED_PATHS (no eviction)
        // 7 is coprime to 60, so the counts 1..=60 are all distinct.
        for i in 0..n {
            let reads = (i * 7 % n) + 1;
            for _ in 0..reads {
                s.record_fs(&format!("c:\\top\\{i}"), false, false);
            }
        }

        let mut reference: Vec<(String, u64)> = (0..n)
            .map(|i| (format!("c:\\top\\{i}"), ((i * 7 % n) + 1) as u64))
            .collect();
        reference.sort_by_key(|e| std::cmp::Reverse(e.1));
        reference.truncate(TOP_N);

        let snap = s.snapshot();
        assert_eq!(snap.fs_top.len(), TOP_N);
        for (entry, (path, reads)) in snap.fs_top.iter().zip(&reference) {
            assert_eq!(&entry.path, path);
            assert_eq!(entry.reads, *reads);
        }
    }

    /// Regression for the review 2026-09-20 race (hot_stats.rs:67): with
    /// the old insert-then-`.expect("just inserted")` sequence, a
    /// concurrent eviction retain could remove the just-inserted entry
    /// (score 0) between the two calls and panic this thread; the atomic
    /// get_or_insert makes that impossible, so a clean join is the
    /// assertion that matters here.
    #[test]
    fn concurrent_record_and_eviction_no_panic() {
        let s = HotStats::new();
        // Pre-flood past capacity (as in the flood tests) so the map sits
        // near the cap and the threads below push it over it again.
        for i in 0..MAX_TRACKED_PATHS + 500 {
            s.record_fs(&format!("c:\\preflood\\{i}.tmp"), false, false);
        }

        let mut handles = Vec::new();
        for t in 0..4u32 {
            let s = Arc::clone(&s);
            handles.push(std::thread::spawn(move || {
                for i in 0..2000u32 {
                    s.record_fs(&format!("c:\\race\\{t}\\{i}"), false, false);
                    // Re-touch shared hot keys so inserts and the
                    // eviction retain genuinely interleave.
                    s.record_fs(&format!("c:\\race\\hot\\{}", i % 3), i % 2 == 0, false);
                }
            }));
        }
        for h in handles {
            h.join().expect("recording thread must not panic");
        }
        assert!(s.fs_paths.len() <= MAX_TRACKED_PATHS);
    }
}
