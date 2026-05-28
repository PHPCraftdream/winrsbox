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
    /// Process creation timestamp as a Windows FILETIME (100ns ticks since
    /// 1601), packed into a u64, captured at `mark_spawned` time. Used to
    /// defend against PID-reuse poisoning (M2): when a tracked child dies
    /// without routing through our NtTerminateProcess untrack hook (e.g. the
    /// Job Object's KILL_ON_JOB_CLOSE or a kernel kill), its stale entry would
    /// otherwise mark a recycled PID as "owned". The OS guarantees a fresh
    /// creation time for the recycling process, so a mismatch unmasks the
    /// foreign PID.
    ///
    /// `0` is a sentinel for "creation time unknown" — the transient query
    /// handle could not be opened at mark time. In that case the verification
    /// is skipped and `is_owned_child` falls back to membership-only (the PID
    /// is still treated as owned). This is a deliberate fail-open ONLY for the
    /// timestamp check; it never grants ownership to an *untracked* PID.
    pub create_time: u64,
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

/// Query the creation timestamp (FILETIME, packed into u64) of a live process
/// by PID. Opens a transient `PROCESS_QUERY_LIMITED_INFORMATION` handle, calls
/// `GetProcessTimes`, closes the handle. Returns `None` if the process cannot
/// be opened (gone / access denied) or the query fails.
///
/// PROCESS_QUERY_LIMITED_INFORMATION (0x1000) is intentionally NOT part of
/// proc_guard's DANGEROUS_ACCESS mask, so this open is permitted even on our
/// own children and even when proc_guard's NtOpenProcess hook inspects it.
///
/// Anti-recursion analysis (M2):
/// This routes through `OpenProcess` → `NtOpenProcess`, which proc_guard hooks.
/// Two cases:
///   1. We are called from a hook that holds the thread-local `anti_rec` guard
///      (the `is_owned_child` callers in proc_guard's NtOpenProcess /
///      NtSetInformationProcess hooks, and `mark_spawned`'s caller
///      hook_nt_create_user_process). The nested `NtOpenProcess` hook calls
///      `anti_rec::enter()`, sees the flag already set, and forwards straight to
///      the original syscall — no checks, no recursion.
///   2. We are called from a path that does NOT hold the `anti_rec` guard
///      (memory_guard's NtAllocateVirtualMemory uses a SEPARATE alloc-only TLS
///      flag, so `anti_rec` is clear there). The nested `NtOpenProcess` hook
///      runs its real check, but our access mask is only 0x1000 which is not in
///      DANGEROUS_ACCESS, so `dangerous == 0` and it forwards to the original.
///      Critically, that path never re-enters `is_owned_child` (the membership
///      check is gated behind `dangerous != 0`), so there is no recursion.
///
/// Either way the call is bounded (one OpenProcess) and cannot self-block.
/// GetProcessTimes → NtQueryInformationProcess and CloseHandle → NtClose are
/// not hooked, so they add no re-entry surface.
pub fn query_process_create_time(pid: u32) -> Option<u64> {
    use winapi::shared::minwindef::FILETIME;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::{GetProcessTimes, OpenProcess};
    use winapi::um::winnt::PROCESS_QUERY_LIMITED_INFORMATION;

    if pid == 0 {
        return None;
    }

    // SAFETY: OpenProcess is a stable kernel32 export. We pass a non-zero PID
    // and `bInheritHandle = FALSE`. It returns NULL on failure (process gone /
    // access denied), which we check before use. No pointers are dereferenced.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }

    let mut create = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut exit = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut kernel = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut user = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };

    // SAFETY: `handle` is a valid process handle just returned by OpenProcess
    // (checked non-null above). The four FILETIME out-params are stack-owned,
    // fully initialized, and outlive the call. GetProcessTimes writes only into
    // them and returns non-zero on success.
    let ok = unsafe {
        GetProcessTimes(handle, &mut create, &mut exit, &mut kernel, &mut user)
    };

    // SAFETY: `handle` is the valid handle from OpenProcess; closing it exactly
    // once here is correct and it is not used afterwards.
    unsafe { CloseHandle(handle); }

    if ok == 0 {
        return None;
    }

    Some(((create.dwHighDateTime as u64) << 32) | (create.dwLowDateTime as u64))
}

/// Mark `child_pid` as spawned by `parent_pid` with the given exe path.
/// Honors FS_SANDBOX_NO_TRACK env var (testing aid — simulates external process).
pub fn mark_spawned(child_pid: u32, parent_pid: u32, exe_path: String) {
    if std::env::var_os("FS_SANDBOX_NO_TRACK").is_some() {
        return;
    }
    // Fingerprint the PID's creation time so a later PID reuse can be detected
    // (M2). Query OUTSIDE the map lock to keep the critical section tiny and to
    // avoid holding the lock across a syscall. `None` → 0 sentinel ("unknown",
    // verification skipped — see SpawnedProcess::create_time docs).
    let create_time = query_process_create_time(child_pid).unwrap_or(0);
    with_lock(|m| {
        m.insert(child_pid, SpawnedProcess {
            parent_pid,
            exe_path,
            spawned_at_ms: now_ms(),
            create_time,
        });
    });
}

/// Returns true if `pid` is a process we (or one of our descendants)
/// have spawned via NtCreateUserProcess.
///
/// PID-reuse hardening (M2): if the tracked entry carries a non-zero creation
/// time, the live PID's creation time is re-queried and must match. A mismatch
/// (PID recycled by the OS for a foreign process) or a failed live query
/// (process is gone) yields `false`. When the stored creation time is the `0`
/// sentinel ("unknown" at mark time) we cannot verify, so we fall back to
/// membership-only.
pub fn is_owned_child(pid: u32) -> bool {
    // Capture the stored fingerprint under the lock, then release it before the
    // syscall (keep the critical section minimal; never hold the lock across an
    // OpenProcess that re-enters proc_guard's hook).
    let stored_create_time = match with_lock(|m| m.get(&pid).map(|p| p.create_time)) {
        Some(ct) => ct,
        None => return false, // not tracked → foreign
    };

    if stored_create_time == 0 {
        // Creation time was unknown at mark time → cannot verify, trust
        // membership (which we already confirmed above).
        return true;
    }

    match query_process_create_time(pid) {
        // Live process: owned only if the fingerprint still matches. A mismatch
        // means the PID was recycled for a different process.
        Some(live_create_time) => live_create_time == stored_create_time,
        // Process is gone (or unqueryable) → it is not a live owned child.
        None => false,
    }
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

    // -----------------------------------------------------------------------
    // M2 — PID-reuse creation-time fingerprint
    // -----------------------------------------------------------------------

    #[test]
    fn create_time_zero_falls_back_to_membership() {
        // Fabricate an entry whose create_time is the "unknown" sentinel (0).
        // is_owned_child must then return the pure membership result without
        // attempting (or being able to fail) the live verification.
        let pid = 0x30001u32;
        with_lock(|m| {
            m.insert(pid, SpawnedProcess {
                parent_pid: 1,
                exe_path: "c:\\unknown.exe".into(),
                spawned_at_ms: now_ms(),
                create_time: 0,
            });
        });
        assert!(
            is_owned_child(pid),
            "create_time==0 entry must be trusted on membership alone"
        );
        untrack(pid);
        assert!(!is_owned_child(pid), "after untrack, no longer owned");
    }

    #[test]
    fn mark_records_create_time() {
        // Mark the *current* test process: it is alive, so query_process_create_time
        // succeeds and stores a non-zero fingerprint, and is_owned_child re-queries
        // the same live PID and the fingerprint matches.
        let self_pid = std::process::id();
        mark_spawned(self_pid, 0, "self.exe".into());

        let stored = info_of(self_pid).expect("self pid should be tracked");
        assert_ne!(
            stored.create_time, 0,
            "creation time of the live self process must be queryable and non-zero"
        );
        assert!(
            is_owned_child(self_pid),
            "self pid with a matching live creation time must read as owned"
        );

        untrack(self_pid);
        assert!(!is_owned_child(self_pid));
    }

    #[test]
    fn pid_reuse_different_create_time_not_owned() {
        // Simulate a stale entry that lingered after the original child died:
        // store a FABRICATED non-zero create_time for a PID that (almost
        // certainly) is not live. is_owned_child re-queries the live PID:
        //   - If the PID is dead → query returns None → not owned (the common,
        //     deterministic case this test asserts).
        //   - If the PID happened to be reused by a live process, its real
        //     creation time would differ from our fabricated value → not owned.
        // Either branch yields `false`.
        //
        // LIMITATION: a faithful end-to-end reuse test (child spawns, dies, OS
        // recycles the exact PID for a foreign process within the test) is
        // non-deterministic and racy on Windows, so it is not attempted here.
        // We assert the security-relevant invariant instead: a stored
        // fingerprint that does not match the live process is never "owned".
        let fake_pid = 0x7FFE_0001u32; // high, unlikely-to-be-live PID
        with_lock(|m| {
            m.insert(fake_pid, SpawnedProcess {
                parent_pid: 1,
                exe_path: "c:\\stale.exe".into(),
                spawned_at_ms: now_ms(),
                create_time: 0xDEAD_BEEF_0000_0001, // fabricated, cannot match reality
            });
        });
        assert!(
            !is_owned_child(fake_pid),
            "a tracked PID whose live creation time does not match (or is gone) \
             must not be treated as an owned child"
        );
        untrack(fake_pid);
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
