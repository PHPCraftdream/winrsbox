use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, FILETIME, HANDLE},
        System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    },
};

// ─── PID-reuse hardening: creation-time fingerprints ─────────────────────────

/// Read a process's creation timestamp (Windows FILETIME, 100ns ticks since
/// 1601, packed into a u64) from an already-open process handle. Returns 0 on
/// failure. Launcher-side mirror of hook-side
/// `process_tracker::create_time_from_handle`.
pub(crate) fn process_create_time_from_handle(h: HANDLE) -> u64 {
    if h.is_invalid() {
        return 0;
    }
    let mut create = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: h is a caller-owned valid process handle. The four FILETIME
    //         out-params are stack-owned, fully initialized, and outlive the
    //         call; GetProcessTimes writes only into them.
    let ok = unsafe { GetProcessTimes(h, &mut create, &mut exit, &mut kernel, &mut user) };
    if ok.is_err() {
        return 0;
    }
    ((create.dwHighDateTime as u64) << 32) | (create.dwLowDateTime as u64)
}

/// Query the creation timestamp of a LIVE process by PID. Opens a transient
/// PROCESS_QUERY_LIMITED_INFORMATION handle, reads the creation time, closes
/// the handle. Returns None if the process cannot be opened (gone / access
/// denied) or the query fails. This access right is not part of proc_guard's
/// dangerous-access surface and the launcher is outside the sandbox anyway.
pub(crate) fn query_process_create_time(pid: u32) -> Option<u64> {
    if pid == 0 {
        return None;
    }
    // SAFETY: pid is a non-zero PID; bInheritHandle=false. Failure (process
    //         gone / access denied) yields Err, which `?` maps to None before
    //         the handle is ever used.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()? };
    let ct = process_create_time_from_handle(h);
    // SAFETY: h was opened by us above and is closed exactly once here.
    unsafe { CloseHandle(h).ok() };
    if ct == 0 { None } else { Some(ct) }
}

// ─── C3 Part 3: validate that the connecting client is one of our own PIDs ────

/// Return true iff `client_pid` is either the root sandboxed target or any
/// process we have already tracked in `global_proc_info` (root + SpawnedChild
/// grandchildren + Hello'd processes).
///
/// Chicken-and-egg note: the very first IPC the launcher sees is the root
/// child's `Hello`, sent before any `SpawnedChild` has fired. The launcher
/// inserts the root PID into `global_proc_info` **before** `ResumeThread`
/// in `main.rs` (the PROC_INFO insert block immediately precedes
/// `ResumeThread(proc_info.hThread)`), so by the time hook.dll's
/// `CreateFileW(\\.\pipe\...)` returns, the root PID is already a key in
/// the map. The explicit `root_target_pid` match below is therefore mostly
/// defence-in-depth: even if the insertion order were ever reordered, the
/// connection from the root would still pass.
///
/// PID-reuse hardening: map membership alone is no longer sufficient. Every
/// entry in `global_proc_info` carries the process's kernel creation-time
/// fingerprint captured at insert time, and every acceptance path (tracked
/// entry, root fast-path, ancestor walk) re-queries the live PID's creation
/// time and requires an exact match. A recycled PID has a different creation
/// time, so it can never inherit a dead process's trust — and the stale entry
/// it collided with is pruned on detection (see `tracked_entry_still_owned`).
pub(crate) fn is_owned_client_pid(client_pid: u32, root_target_pid: u32) -> bool {
    is_owned_client_pid_impl(
        client_pid,
        root_target_pid,
        crate::sandbox::proc_table::root_create_time(),
        &|pid| query_process_create_time(pid),
        &|pid| get_parent_pid(pid),
    )
}

/// Injectable probe signatures so the ownership decision is unit-testable
/// without spawning real processes.
type LiveCreateFn<'a> = &'a dyn Fn(u32) -> Option<u64>;
type ParentPidFn<'a> = &'a dyn Fn(u32) -> Option<u32>;

/// Testable core of the gate. `root_create_time` is the pinned fingerprint of
/// the root target (0 = unknown → the root fast-path fail-closes);
/// `live_create_time` / `parent_of` are the kernel probes, injectable in tests.
pub(crate) fn is_owned_client_pid_impl(
    client_pid: u32,
    root_target_pid: u32,
    root_create_time: u64,
    live_create_time: LiveCreateFn<'_>,
    parent_of: ParentPidFn<'_>,
) -> bool {
    if client_pid == 0 {
        return false;
    }
    if tracked_entry_still_owned(client_pid, live_create_time) {
        return true;
    }
    if root_target_pid != 0 && client_pid == root_target_pid {
        // Defence-in-depth fast path for the root target (normally its map
        // entry, inserted before ResumeThread, already answered above). Still
        // creation-time verified: a recycled root PID must not pass.
        return root_create_time != 0
            && live_create_time(client_pid) == Some(root_create_time);
    }
    walk_parents_to_owned_impl(
        client_pid,
        root_target_pid,
        root_create_time,
        live_create_time,
        parent_of,
    )
}

/// True iff `pid` has a tracked entry AND still describes the same live
/// process. Every tracked entry carries the creation-time fingerprint
/// captured at insert; the live PID's creation time is re-queried and must
/// match exactly. A mismatch means the OS recycled the PID for a foreign
/// process; a failed probe means the tracked process is gone (or unopenable).
/// Both reject the client AND prune the stale entry, so a reused PID can
/// never inherit trust. A `0` stored fingerprint ("unknown at insert time")
/// fail-closes.
fn tracked_entry_still_owned(pid: u32, live_create_time: LiveCreateFn<'_>) -> bool {
    // Copy the fingerprint out and drop the map guard before any syscall.
    let stored = {
        let map = crate::sandbox::proc_table::global_proc_info().pin();
        match map.get(&pid) {
            Some(entry) => entry.create_time,
            None => return false,
        }
    };
    if stored == 0 {
        return false;
    }
    match live_create_time(pid) {
        Some(t) if t == stored => true,
        Some(_) => {
            eprintln!(
                "[pipe] stale entry pid={pid}: creation-time mismatch (PID reused) — pruning"
            );
            prune_stale_entry(pid);
            false
        }
        None => {
            eprintln!("[pipe] stale entry pid={pid}: process gone — pruning");
            prune_stale_entry(pid);
            false
        }
    }
}

fn prune_stale_entry(pid: u32) {
    crate::sandbox::proc_table::global_proc_info().pin().remove(&pid);
}

/// Walk `pid`'s kernel-vouched parent chain (up to MAX_DEPTH ancestors).
/// An ancestor passes only if its tracked entry is creation-time verified
/// (or it is the root target with a verified fingerprint). Returns true on
/// first match; false if the chain runs out, loops, or reaches a
/// non-sandbox process. This keeps the race-resilience behaviour (a child
/// connecting before its SpawnedChild was processed) while closing the
/// reused-parent-PID hole.
fn walk_parents_to_owned_impl(
    pid: u32,
    root_target_pid: u32,
    root_create_time: u64,
    live_create_time: LiveCreateFn<'_>,
    parent_of: ParentPidFn<'_>,
) -> bool {
    const MAX_DEPTH: u32 = 16;
    let mut current = pid;
    let mut seen = std::collections::HashSet::with_capacity(MAX_DEPTH as usize);
    for _ in 0..MAX_DEPTH {
        if !seen.insert(current) {
            return false; // cycle detected
        }
        let parent = match parent_of(current) {
            Some(0) | None => return false,
            Some(p) => p,
        };
        if tracked_entry_still_owned(parent, live_create_time) {
            return true;
        }
        if root_target_pid != 0
            && parent == root_target_pid
            && root_create_time != 0
            && live_create_time(parent) == Some(root_create_time)
        {
            return true;
        }
        current = parent;
    }
    false
}

/// Open the process with `PROCESS_QUERY_LIMITED_INFORMATION` and query
/// `PROCESS_BASIC_INFORMATION` to read `InheritedFromUniqueProcessId`.
/// Returns `None` on any failure (process gone, access denied, etc.).
fn get_parent_pid(pid: u32) -> Option<u32> {
    #[repr(C)]
    #[derive(Default)]
    struct ProcessBasicInformation {
        exit_status: i32,
        _pad0: u32,
        peb_base_address: usize,
        affinity_mask: usize,
        base_priority: i32,
        _pad1: u32,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }
    type FnNtQueryInformationProcess = unsafe extern "system" fn(
        HANDLE, u32, *mut core::ffi::c_void, u32, *mut u32,
    ) -> i32;
    static QIP: std::sync::OnceLock<Option<FnNtQueryInformationProcess>> =
        std::sync::OnceLock::new();
    let qip = (*QIP.get_or_init(|| {
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        let ntdll: Vec<u16> = OsStr::new("ntdll.dll")
            .encode_wide()
            .chain(Some(0))
            .collect();
        // SAFETY: ntdll.dll is always loaded; literal name.
        let hmod = match unsafe { GetModuleHandleW(PCWSTR(ntdll.as_ptr())) } {
            Ok(h) => h,
            Err(_) => return None,
        };
        // SAFETY: hmod is valid; export name is null-terminated ASCII.
        let addr = match unsafe {
            GetProcAddress(hmod, windows::core::s!("NtQueryInformationProcess"))
        } {
            Some(a) => a,
            None => return None,
        };
        // SAFETY: addr is the real NtQueryInformationProcess export.
        Some(unsafe { std::mem::transmute::<_, FnNtQueryInformationProcess>(addr) })
    }))?;

    // SAFETY: pid is from kernel-vouched GetNamedPipeClientProcessId.
    let h = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?
    };
    let mut info = ProcessBasicInformation::default();
    let mut ret_len = 0u32;
    // SAFETY: h is valid; info sized correctly.
    let status = unsafe {
        qip(
            h,
            0,
            &mut info as *mut _ as *mut _,
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut ret_len,
        )
    };
    // SAFETY: h was opened by us.
    unsafe { CloseHandle(h).ok() };
    if status < 0 {
        return None;
    }
    Some(info.inherited_from_unique_process_id as u32)
}
