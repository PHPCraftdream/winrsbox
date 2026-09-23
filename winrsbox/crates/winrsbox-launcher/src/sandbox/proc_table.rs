// ─── Lock-free PID → ProcInfo storage ─────────────────────────────────────────

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

#[derive(Debug, Clone)]
pub(crate) struct ProcInfo {
    pub(crate) depth: u8,
    pub(crate) exe_lower: Arc<str>,
    /// Process creation time as a Windows FILETIME (100ns ticks since 1601)
    /// packed into a u64, captured from the kernel at insert time. The pipe
    /// gate re-queries the live PID's creation time and requires an exact
    /// match, so a recycled PID can never inherit a dead process's trust.
    /// `0` is the "unknown" sentinel — the gate fail-closes on it.
    pub(crate) create_time: u64,
}

static PROC_INFO: std::sync::OnceLock<papaya::HashMap<u32, ProcInfo>> = std::sync::OnceLock::new();

pub(crate) fn global_proc_info() -> &'static papaya::HashMap<u32, ProcInfo> {
    PROC_INFO.get_or_init(papaya::HashMap::new)
}

/// S09: depth of a freshly spawned child = parent depth + 1, saturating at
/// u8::MAX. A plain `+` panics (debug) or wraps to 0 (release) at 255 — and a
/// wrap to 0 would make a maximally deep spawn chain look like the ROOT
/// process for depth-scoped policy. Saturation is safe for policy semantics:
/// `when.depth` filters are MINIMUM bounds (`d < min_depth` → skip), so
/// u8::MAX passes every depth filter and can never be mistaken for a shallow
/// root chain. `#[allow(dead_code)]` because the pipe server's SpawnedChild
/// insert still computes `parent_depth + 1` inline; this replaces that call
/// site.
#[allow(dead_code)]
pub(crate) fn child_depth(parent_depth: u8) -> u8 {
    parent_depth.saturating_add(1)
}

/// Creation-time fingerprint of the root sandboxed target, published together
/// with `root_target_pid` right after CreateProcessW (long before the resumed
/// child can connect). `0` = not yet published / unknown; the gate fail-closes.
static ROOT_CREATE_TIME: AtomicU64 = AtomicU64::new(0);

pub(crate) fn root_create_time() -> u64 {
    ROOT_CREATE_TIME.load(Ordering::Acquire)
}

/// Publish the root target's creation-time fingerprint (see `ROOT_CREATE_TIME`).
pub(crate) fn publish_root_create_time(v: u64) {
    ROOT_CREATE_TIME.store(v, Ordering::Release);
}

#[cfg(test)]
mod proc_info_tests {
    use super::*;

    #[test]
    fn insert_and_lookup() {
        let map: papaya::HashMap<u32, ProcInfo> = papaya::HashMap::new();
        map.pin().insert(100, ProcInfo { depth: 0, exe_lower: Arc::from("c:\\app.exe"), create_time: 0 });
        let info = map.pin().get(&100).cloned().unwrap();
        assert_eq!(info.depth, 0);
        assert_eq!(&*info.exe_lower, "c:\\app.exe");
    }

    #[test]
    fn lookup_missing_returns_none() {
        let map: papaya::HashMap<u32, ProcInfo> = papaya::HashMap::new();
        assert!(map.pin().get(&999).is_none());
    }

    #[test]
    fn remove_entry() {
        let map: papaya::HashMap<u32, ProcInfo> = papaya::HashMap::new();
        map.pin().insert(200, ProcInfo { depth: 1, exe_lower: Arc::from("child.exe"), create_time: 0 });
        assert!(map.pin().remove(&200).is_some());
        assert!(map.pin().get(&200).is_none());
    }

    #[test]
    fn concurrent_insert_and_lookup() {
        use std::sync::Arc;
        let map = Arc::new(papaya::HashMap::<u32, ProcInfo>::new());
        let mut handles = vec![];
        for i in 0..4 {
            let m = map.clone();
            handles.push(std::thread::spawn(move || {
                let pid = 1000 + i;
                m.pin().insert(pid, ProcInfo {
                    depth: i as u8,
                    exe_lower: Arc::from(format!("proc_{i}.exe").leak() as &str),
                    create_time: 0,
                });
                assert!(m.pin().get(&pid).is_some());
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // All 4 entries should be visible
        for i in 0..4u32 {
            assert!(map.pin().get(&(1000 + i)).is_some());
        }
    }

    #[test]
    fn depth_chain_root_child_grandchild() {
        let map: papaya::HashMap<u32, ProcInfo> = papaya::HashMap::new();
        // Root
        map.pin().insert(10, ProcInfo { depth: 0, exe_lower: Arc::from("root.exe"), create_time: 0 });
        // Child
        map.pin().insert(20, ProcInfo { depth: 1, exe_lower: Arc::from("child.exe"), create_time: 0 });
        // Grandchild
        map.pin().insert(30, ProcInfo { depth: 2, exe_lower: Arc::from("grandchild.exe"), create_time: 0 });

        assert_eq!(map.pin().get(&10).unwrap().depth, 0);
        assert_eq!(map.pin().get(&20).unwrap().depth, 1);
        assert_eq!(map.pin().get(&30).unwrap().depth, 2);
    }

    #[test]
    fn overwrite_updates_value() {
        let map: papaya::HashMap<u32, ProcInfo> = papaya::HashMap::new();
        map.pin().insert(50, ProcInfo { depth: 0, exe_lower: Arc::from("old.exe"), create_time: 0 });
        map.pin().insert(50, ProcInfo { depth: 1, exe_lower: Arc::from("new.exe"), create_time: 0 });
        let info = map.pin().get(&50).cloned().unwrap();
        assert_eq!(info.depth, 1);
        assert_eq!(&*info.exe_lower, "new.exe");
    }

    /// S09 boundary pin: `child_depth` saturates at u8::MAX — 255 + 1 must
    /// stay 255, never wrap to 0 (a wrap would make a maximally deep spawn
    /// chain look like the ROOT process for depth-scoped policy).
    #[test]
    fn child_depth_saturates_at_u8_max() {
        assert_eq!(child_depth(0), 1);
        assert_eq!(child_depth(254), 255);
        // the wrap-to-0 pin: saturation, not `+`
        assert_eq!(child_depth(255), 255);
    }
}
