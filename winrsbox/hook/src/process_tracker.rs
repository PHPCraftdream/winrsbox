// Process tracker — keeps a map of PIDs we (this process) have spawned.
//
// Used by memory_guard and reg_hooks to distinguish "our injection target"
// (allow internal IPC operations like VirtualAllocEx + WriteProcessMemory
// from our own NtCreateUserProcess hook's inject_via_apc) vs "external
// process" (apply policy / block by default).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct SpawnedProcess {
    pub parent_pid: u32,
    pub exe_path: String,
    pub spawned_at_ms: u64,
}

static SPAWNED: OnceLock<Mutex<HashMap<u32, SpawnedProcess>>> = OnceLock::new();

fn map() -> &'static Mutex<HashMap<u32, SpawnedProcess>> {
    SPAWNED.get_or_init(|| Mutex::new(HashMap::new()))
}

fn with_lock<R>(f: impl FnOnce(&mut HashMap<u32, SpawnedProcess>) -> R) -> R {
    let mut guard = map().lock().unwrap_or_else(|p| p.into_inner());
    f(&mut *guard)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Mark `child_pid` as spawned by `parent_pid` with the given exe path.
/// Honors FS_SANDBOX_NO_TRACK env var (testing aid — simulates external process).
pub fn mark_spawned(child_pid: u32, parent_pid: u32, exe_path: String) {
    if std::env::var_os("FS_SANDBOX_NO_TRACK").is_some() {
        return;
    }
    with_lock(|m| {
        m.insert(child_pid, SpawnedProcess {
            parent_pid,
            exe_path,
            spawned_at_ms: now_ms(),
        });
    });
}

/// Returns true if `pid` is a process we (or one of our descendants)
/// have spawned via NtCreateUserProcess.
pub fn is_owned_child(pid: u32) -> bool {
    with_lock(|m| m.contains_key(&pid))
}

/// Get parent PID if known.
pub fn parent_of(pid: u32) -> Option<u32> {
    with_lock(|m| m.get(&pid).map(|p| p.parent_pid))
}

/// Get full info if known.
pub fn info_of(pid: u32) -> Option<SpawnedProcess> {
    with_lock(|m| m.get(&pid).cloned())
}

/// Remove a tracked PID (e.g., on process exit).
pub fn untrack(pid: u32) {
    with_lock(|m| { m.remove(&pid); });
}

/// Number of currently tracked PIDs.
pub fn count() -> usize {
    with_lock(|m| m.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests share the global SPAWNED map; use sufficiently high distinct
    // PIDs to avoid cross-test collisions when run in parallel.

    #[test]
    fn mark_and_lookup() {
        mark_spawned(0x10001, 0x10000, "c:\\a.exe".into());
        assert!(is_owned_child(0x10001));
        assert_eq!(parent_of(0x10001), Some(0x10000));
        assert_eq!(info_of(0x10001).unwrap().exe_path, "c:\\a.exe");
    }

    #[test]
    fn unknown_pid_not_owned() {
        assert!(!is_owned_child(0x99999999));
        assert_eq!(parent_of(0x99999999), None);
    }

    #[test]
    fn untrack_removes_entry() {
        mark_spawned(0x10002, 0x10000, "c:\\b.exe".into());
        assert!(is_owned_child(0x10002));
        untrack(0x10002);
        assert!(!is_owned_child(0x10002));
    }

    #[test]
    fn count_increments() {
        let before = count();
        mark_spawned(0x10003, 0x10000, "c:\\c.exe".into());
        mark_spawned(0x10004, 0x10000, "c:\\d.exe".into());
        assert!(count() >= before + 2);
        untrack(0x10003);
        untrack(0x10004);
    }

    #[test]
    fn re_mark_overwrites() {
        mark_spawned(0x10005, 0x10000, "c:\\old.exe".into());
        mark_spawned(0x10005, 0x10000, "c:\\new.exe".into());
        assert_eq!(info_of(0x10005).unwrap().exe_path, "c:\\new.exe");
    }

    #[test]
    fn concurrent_marks() {
        use std::sync::Arc;
        let barrier = Arc::new(std::sync::Barrier::new(4));
        let mut handles = vec![];
        for i in 0..4u32 {
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let pid = 0x20000 + i;
                b.wait();
                mark_spawned(pid, 0x20000, format!("c:\\t{i}.exe"));
                assert!(is_owned_child(pid));
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        for i in 0..4u32 {
            assert!(is_owned_child(0x20000 + i));
            untrack(0x20000 + i);
        }
    }
}
