use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use winrsbox::observe::jsonl_log;
use windows::{
    core::{HRESULT, PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE},
        System::Threading::{
            GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
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

// ─── S09: kernel-truth identity gates (image path, exe context, kinship) ─────

/// Kernel-truth image path of a live process, via QueryFullProcessImageNameW.
/// Opens a transient `PROCESS_QUERY_LIMITED_INFORMATION` handle — the
/// documented minimum access right required by QueryFullProcessImageNameW, so
/// no stronger handle (and no new privilege surface) is needed — reads the
/// path, closes the handle exactly once on every path. Returns None if the
/// process cannot be opened (gone / access denied), the path cannot fit a
/// 32768-u16 buffer, or the query fails.
///
/// S09 rationale: this is the kernel's record of what the process is actually
/// running. The exe string a guest reports in its `Hello` is read from
/// guest-controlled memory, so a compromised guest can claim anything; the
/// image path the kernel reports cannot be spoofed by user-mode code inside
/// the guest, which makes it the only safe key for exe-scoped policy rules.
pub(crate) fn query_process_image_path(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    // SAFETY: pid is a non-zero PID; bInheritHandle=false. Failure (process
    //         gone / access denied) yields Err, which `?` maps to None before
    //         the handle is ever used.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()? };
    let result = image_path_from_handle(h);
    // SAFETY: h was opened by us above and is closed exactly once here.
    unsafe { CloseHandle(h).ok() };
    result
}

/// Compare a guest-claimed exe path against the kernel-truth exe path for
/// spoof detection. Both sides go through `fold_published` (canonical
/// NTFS-identity case fold, matching the policy db's `when.exe` key fold)
/// and then `policy::path::fold_dos_dots` (lexical `.`/`..` collapse,
/// clamped at the drive/root anchor — see its doc comment). `kernel_folded`
/// is expected already `fold_published`-folded (both call sites pass the
/// `lower`/`kl` they already computed); folding it again is a no-op.
///
/// This closes false-positive spoof reports from launchers that relaunch
/// through a literal `..` segment — e.g. Git for Windows' `bin\bash.exe`
/// re-execing `usr\bin\bash.exe` via `bin\..\usr\bin\bash.exe` — without
/// weakening real detection: the kernel path is still the only path used to
/// decide policy, this fold only changes what counts as "the same path" for
/// the diagnostic comparison. A `..` that pops above the anchor clamps at
/// the drive root exactly like Windows does (`fold_dos_dots`'s own
/// contract), so it still only matches a kernel path that resolves to the
/// same clamped location — it cannot fold into agreement with an unrelated
/// path.
pub(crate) fn exe_paths_match(claimed_exe: &str, kernel_folded: &str) -> bool {
    let claimed_folded = crate::fold_published(claimed_exe);
    policy::path::fold_dos_dots(&claimed_folded) == policy::path::fold_dos_dots(kernel_folded)
}

/// [`query_process_image_path`]'s probe, reusable against an ALREADY-OPEN
/// process handle. MP-3's Attach authentication opens the client process
/// exactly once (PID-reuse race avoidance) and reuses that single handle for
/// every check, including this one — see
/// `security::authenticate_attach_client`.
pub(crate) fn image_path_from_handle(h: HANDLE) -> Option<String> {
    let mut size = 1024u32;
    loop {
        let mut buf = vec![0u16; size as usize];
        let mut len = size;
        // SAFETY: h is a valid process handle (caller's contract); buf is a
        //         fully initialized UTF-16 buffer of `size` u16s that
        //         outlives the call; QueryFullProcessImageNameW writes only
        //         into buf and `len`.
        match unsafe {
            QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len)
        } {
            Ok(()) => {
                // `len` is the number of u16s written; trim any trailing NULs
                // before decoding.
                let written = (len as usize).min(buf.len());
                let mut path = &buf[..written];
                while path.last() == Some(&0) {
                    path = &path[..path.len() - 1];
                }
                if path.is_empty() {
                    return None;
                }
                return Some(String::from_utf16_lossy(path));
            }
            // Buffer too small: double and retry, capped at 32768 u16s so a
            // pathological target can never spin this loop forever.
            Err(e) if e.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) => {
                if size >= 32768 {
                    return None;
                }
                size = size.saturating_mul(2);
            }
            Err(_) => return None,
        }
    }
}

/// Testable core: given the kernel image-path probe, decide the exe context
/// for a Hello. `Ok((kernel_folded, claimed_differs))` uses ONLY the
/// kernel path; `Err` means the kernel path could not be resolved (fail
/// closed).
///
/// After S09 the guest-claimed exe string is diagnostics-only: a compromised
/// guest can report any path it likes, so the exe context served to policy
/// must come from `query_process_image_path` (kernel truth). The bool flags a
/// mismatch between what the guest claimed and what the kernel says, so the
/// caller can log a spoof warning while still deciding from the kernel path.
pub(crate) fn hello_exe_context_impl(
    client_pid: u32,
    claimed_exe: &str,
    image_path_of: &dyn Fn(u32) -> Option<String>,
) -> Result<(String, bool), ()> {
    let kernel = image_path_of(client_pid).ok_or(())?;
    // S11: canonical NTFS-identity fold (kernel tables) — the same fold the
    // policy db applies to `when.exe` rule keys; ASCII input folds
    // byte-identically to the historic ASCII-only lowercase.
    let lower = crate::fold_published(&kernel);
    let spoof = !exe_paths_match(claimed_exe, &lower);
    Ok((lower, spoof))
}

/// Production binding of `hello_exe_context_impl` to the real kernel probe.
pub(crate) fn hello_exe_context(client_pid: u32, claimed_exe: &str) -> Result<(String, bool), ()> {
    hello_exe_context_impl(client_pid, claimed_exe, &query_process_image_path)
}

/// Testable core of the SpawnedChild kinship proof (S09 point 2): true iff
/// the kernel records `client_pid` as the direct creator of `child_pid`.
///
/// WHY kernel `InheritedFromUniqueProcessId` is the chosen proof:
/// * Windows never reparents — the creator PID the kernel records at
///   `CreateProcess` is immutable for the child's lifetime and survives the
///   parent's death, so the check is race-free.
/// * A hostile parent naming an arbitrary unrelated PID as the child fails:
///   the kernel records the REAL creator, not the claimed one.
/// * PID reuse of `child_pid` is covered separately by the caller's
///   creation-time fingerprint when the child itself connects.
/// * Job membership is NOT used: the sandbox Job object exists, but its
///   handle is not plumbed into the pipe server — and direct-child semantics
///   is exactly what a SpawnedChild report claims, so kernel parentage
///   proves precisely that claim.
pub(crate) fn spawned_child_kinship_impl(
    child_pid: u32,
    client_pid: u32,
    parent_of: ParentPidFn<'_>,
) -> bool {
    child_pid != 0 && parent_of(child_pid) == Some(client_pid)
}

/// Production binding of `spawned_child_kinship_impl` to the real kernel
/// parent probe (`NtQueryInformationProcess` → InheritedFromUniqueProcessId).
pub(crate) fn spawned_child_kinship(child_pid: u32, client_pid: u32) -> bool {
    spawned_child_kinship_impl(child_pid, client_pid, &get_parent_pid)
}

/// Decide-context gate for the Hello-first state machine (S09 point 3).
/// Returns `(depth, exe_lower)` of the tracked entry for the connection's
/// kernel-vouched PID.
///
/// Before S09, a Decide arriving on a connection that had not said Hello was
/// served with `(None, None)`, which makes exe-scoped rules be SKIPPED — a
/// permissive fall-through. Here `Err` means refuse: it covers both "never
/// Hello'd" (no connection PID) and "Hello'd but the entry is no longer
/// live / pruned" (the identity broke between Hello and Decide) — strictly
/// more fail-closed than the old `(None, None)` fallback.
pub(crate) fn decide_context(conn_pid: Option<u32>) -> Result<(u8, std::sync::Arc<str>), ()> {
    let pid = conn_pid.ok_or(())?;
    let map = crate::sandbox::proc_table::global_proc_info().pin();
    let info = map.get(&pid).ok_or(())?;
    Ok((info.depth, std::sync::Arc::clone(&info.exe_lower)))
}

/// MP-4: resolve the depth to record for a Hello'd PID that has NO existing
/// `global_proc_info` entry. Walks `pid`'s kernel-vouched parent chain (same
/// bound and cycle guard as `walk_parents_to_owned_impl`) looking for an
/// ancestor that IS tracked, and returns `ancestor.depth + 1` (saturating,
/// via `proc_table::child_depth`) on the first hit.
///
/// This covers two cases uniformly: (a) a legitimate child whose own `Hello`
/// raced ahead of its parent's `SpawnedChild` report reaching this launcher
/// (pre-existing possible race — kernel parentage still resolves it), and
/// (b) a job-admitted guest of ANOTHER session's broker-managed folder
/// (MP-4), which this launcher has never seen via `Hello` or `SpawnedChild`
/// and whose ancestry lives entirely outside this launcher's tracker.
///
/// If no tracked ancestor is found within the walk (chain exhausted, a
/// cycle, or every ancestor is untracked/unopenable), returns `u8::MAX` —
/// the documented conservative/fail-closed depth: `when.depth` policy
/// filters are MINIMUM bounds (`d < min_depth` → rule skipped), so `u8::MAX`
/// passes every depth-scoped rule and can never be mistaken for a shallow,
/// more-trusted root chain (see `proc_table::child_depth`'s doc comment).
/// Using `0` here instead — the naive "new process" default — would make an
/// unrelated session's guest look like a trusted root process to depth-scoped
/// policy, which is exactly the permissive gap MP-4 closes.
pub(crate) fn resolve_new_entry_depth(pid: u32) -> u8 {
    resolve_new_entry_depth_impl(
        pid,
        &|p| {
            crate::sandbox::proc_table::global_proc_info()
                .pin()
                .get(&p)
                .map(|e| e.depth)
        },
        &get_parent_pid,
    )
}

type TrackedDepthFn<'a> = &'a dyn Fn(u32) -> Option<u8>;

/// Testable core of [`resolve_new_entry_depth`].
fn resolve_new_entry_depth_impl(
    pid: u32,
    tracked_depth: TrackedDepthFn<'_>,
    parent_of: ParentPidFn<'_>,
) -> u8 {
    const MAX_DEPTH: u32 = 16;
    let mut current = pid;
    let mut seen = std::collections::HashSet::with_capacity(MAX_DEPTH as usize);
    for _ in 0..MAX_DEPTH {
        if !seen.insert(current) {
            break; // cycle detected — fail closed below
        }
        let parent = match parent_of(current) {
            Some(0) | None => break,
            Some(p) => p,
        };
        if let Some(d) = tracked_depth(parent) {
            return crate::sandbox::proc_table::child_depth(d);
        }
        current = parent;
    }
    u8::MAX
}

// ─── C3 Part 3 / MP-4: validate that the connecting client is one of our own ──

/// Return true iff `client_pid` is admitted to this pipe server.
///
/// MP-4: when `folder_job` is `Some` (this launcher is the folder's broker),
/// kernel job membership (`IsProcessInJob`) is the sole admission gate — a
/// fact the kernel enforces (breakaway denied by construction on the folder
/// job, see `contain::jobctl::FolderJob`) and therefore stronger than any
/// PID-lineage tracked by this launcher alone. A guest belonging to ANOTHER
/// session's launcher in the same folder is admitted here even though this
/// launcher never saw it via `Hello`/`SpawnedChild`; a process outside the
/// folder job is rejected even if its PID happens to collide with a stale
/// tracker/root entry. See `is_owned_client_pid_impl` for the no-folder-job
/// (single-process) path, unchanged from before MP-4.
///
/// Chicken-and-egg note (no-folder-job path): the very first IPC the launcher
/// sees is the root child's `Hello`, sent before any `SpawnedChild` has
/// fired. The launcher inserts the root PID into `global_proc_info` **before**
/// `ResumeThread` in `main.rs` (the PROC_INFO insert block immediately
/// precedes `ResumeThread(proc_info.hThread)`), so by the time hook.dll's
/// `CreateFileW(\\.\pipe\...)` returns, the root PID is already a key in
/// the map. The explicit `root_target_pid` match is therefore mostly
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
pub(crate) fn is_owned_client_pid(
    client_pid: u32,
    root_target_pid: u32,
    folder_job: Option<&winrsbox::contain::jobctl::FolderJob>,
) -> bool {
    match folder_job {
        Some(job) => {
            let probe = |pid: u32| folder_job_contains_pid(job, pid);
            is_owned_client_pid_impl(
                client_pid,
                root_target_pid,
                crate::sandbox::proc_table::root_create_time(),
                &|pid| query_process_create_time(pid),
                &|pid| get_parent_pid(pid),
                Some(&probe),
            )
        }
        None => is_owned_client_pid_impl(
            client_pid,
            root_target_pid,
            crate::sandbox::proc_table::root_create_time(),
            &|pid| query_process_create_time(pid),
            &|pid| get_parent_pid(pid),
            None,
        ),
    }
}

/// Kernel-truth job-membership probe backing [`is_owned_client_pid`]'s
/// `folder_job` gate. Opens exactly ONE `PROCESS_QUERY_LIMITED_INFORMATION`
/// handle to `pid` and uses that SAME handle for the `IsProcessInJob` call —
/// a single open avoids the PID-reuse race a two-open sequence would
/// introduce (open once to check membership, open again later for something
/// else): the handle keeps identifying the exact kernel process object
/// opened at this instant, regardless of what a later caller finds the PID
/// number reused for. Returns false if the process cannot be opened (already
/// gone/reaped, or PID 0) or the kernel query fails — fail closed.
fn folder_job_contains_pid(job: &winrsbox::contain::jobctl::FolderJob, pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: pid is a non-zero PID from GetNamedPipeClientProcessId (kernel-
    //         vouched); bInheritHandle=false. Failure (process gone/access
    //         denied) yields Err, mapped to `false` before the handle is used.
    let h = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(h) => h,
        Err(_) => return false,
    };
    let result = job.contains(h).unwrap_or(false);
    // SAFETY: h was opened by us immediately above and is closed exactly
    //         once here.
    unsafe { CloseHandle(h).ok() };
    result
}

/// Injectable probe signatures so the ownership decision is unit-testable
/// without spawning real processes.
type LiveCreateFn<'a> = &'a dyn Fn(u32) -> Option<u64>;
type ParentPidFn<'a> = &'a dyn Fn(u32) -> Option<u32>;
type FolderJobProbeFn<'a> = &'a dyn Fn(u32) -> bool;

/// Testable core of the gate. `root_create_time` is the pinned fingerprint of
/// the root target (0 = unknown → the root fast-path fail-closes);
/// `live_create_time` / `parent_of` are the kernel probes, injectable in
/// tests. `folder_job_contains`, when `Some`, makes job membership the sole
/// (necessary AND sufficient) admission test — the tracker/root/ancestor
/// path below is skipped entirely, per MP-4 (it remains available as
/// decision CONTEXT via `decide_context`/`resolve_new_entry_depth`, just not
/// as an admission gate once a folder job exists).
pub(crate) fn is_owned_client_pid_impl(
    client_pid: u32,
    root_target_pid: u32,
    root_create_time: u64,
    live_create_time: LiveCreateFn<'_>,
    parent_of: ParentPidFn<'_>,
    folder_job_contains: Option<FolderJobProbeFn<'_>>,
) -> bool {
    if client_pid == 0 {
        return false;
    }
    if let Some(in_job) = folder_job_contains {
        return in_job(client_pid);
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
            // Notable: a PID was reused fast enough to reach the same lookup
            // window — fail-closed correctness working as designed, not
            // routine housekeeping, so this stays at WARN.
            let msg = format!(
                "stale entry pid={pid}: creation-time mismatch (PID reused) — pruning"
            );
            if jsonl_log::console_verbose() {
                eprintln!("[pipe] {msg}");
            }
            jsonl_log::log(jsonl_log::Event::launcher_diag("WARN", msg));
            prune_stale_entry(pid);
            false
        }
        None => {
            // Routine: fires on every tracked process's normal exit. Console
            // printing this unconditionally corrupted the sandboxed target's
            // own terminal rendering (REG-4) — buffered INFO only.
            let msg = format!("stale entry pid={pid}: process gone — pruning");
            if jsonl_log::console_verbose() {
                eprintln!("[pipe] {msg}");
            }
            jsonl_log::log(jsonl_log::Event::launcher_diag("INFO", msg));
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

// ─── S09: kernel-truth identity gates (inline tests) ─────────────────────────

#[cfg(test)]
mod s09_identity_tests {
    use super::*;
    use std::sync::Arc;

    /// S09 point 1: the image-path probe returns the REAL exe path of a live
    /// process — our own test binary — as a non-empty string ending in ".exe"
    /// (case-insensitively). Mirrors the live-kernel roundtrip convention of
    /// pipe_server::tests::live_kernel_roundtrip_self_pid.
    #[test]
    fn image_path_live_kernel_roundtrip_self_pid() {
        let pid = std::process::id();
        let path = query_process_image_path(pid).expect("own live process must be queryable");
        assert!(!path.is_empty());
        let lower = path.to_ascii_lowercase();
        assert!(
            lower.ends_with(".exe"),
            "kernel image path of the test binary must end in .exe, got {path}"
        );
    }

    /// S09 point 1: a PID that cannot be opened must fail closed with None —
    /// never panic, never fabricate a path.
    #[test]
    fn image_path_dead_pid_returns_none() {
        // 0x5A09_DEAD is not a multiple of 4 (Windows PIDs always are), so it
        // can never name a live process.
        assert_eq!(query_process_image_path(0x5A09_DEADu32), None);
    }

    /// S09 point 1: the Hello exe decision is made from the KERNEL path, never
    /// the guest-claimed one. Kernel says Notepad.EXE, the guest claims an
    /// unrelated fake.cmd → the returned context is the kernel path
    /// (lowercased) AND the mismatch is flagged as a spoof.
    #[test]
    fn hello_exe_context_uses_kernel_path_not_claim() {
        let pid = 0x5A09_0001u32;
        let (path, spoof) = hello_exe_context_impl(
            pid,
            "c:\\definitely\\fake.cmd",
            &|p: u32| {
                if p == pid { Some("C:\\Windows\\System32\\Notepad.EXE".to_string()) } else { None }
            },
        )
        .expect("kernel path probe must resolve");
        assert_eq!(path, "c:\\windows\\system32\\notepad.exe");
        assert!(spoof, "claimed exe differing from kernel path must flag spoof");
    }

    /// S09 point 1: a claimed exe that matches the kernel path (modulo case)
    /// is NOT a spoof — Ok((lowercased kernel path, false)).
    #[test]
    fn hello_exe_context_match_is_not_spoof() {
        let pid = 0x5A09_0002u32;
        let (path, spoof) = hello_exe_context_impl(
            pid,
            "c:\\tools\\app.exe",
            &|p: u32| if p == pid { Some("C:\\tools\\app.exe".to_string()) } else { None },
        )
        .expect("kernel path probe must resolve");
        assert_eq!(path, "c:\\tools\\app.exe");
        assert!(!spoof, "a matching claim must not be flagged as spoof");
    }

    /// #107: Git for Windows' `bin\bash.exe` relaunches through a literal
    /// `..` segment (`bin\..\usr\bin\bash.exe`) that the guest never
    /// resolves before reporting it, while the kernel reports the already-
    /// resolved path. Must NOT be flagged as a spoof.
    #[test]
    fn hello_exe_context_git_bash_dotdot_relaunch_is_not_spoof() {
        let pid = 0x5A09_0004u32;
        let (path, spoof) = hello_exe_context_impl(
            pid,
            r"c:\program files\git\bin\..\usr\bin\bash.exe",
            &|p: u32| {
                if p == pid {
                    Some(r"C:\Program Files\Git\usr\bin\bash.exe".to_string())
                } else {
                    None
                }
            },
        )
        .expect("kernel path probe must resolve");
        assert_eq!(path, r"c:\program files\git\usr\bin\bash.exe");
        assert!(!spoof, "a literal .. relaunch that resolves to the kernel path must not be a spoof");
    }

    /// `exe_paths_match`: a `.\` current-dir segment folds away and must not
    /// be flagged as a spoof.
    #[test]
    fn exe_paths_match_dot_segment_is_not_spoof() {
        let kernel = crate::fold_published(r"c:\tools\app.exe");
        assert!(exe_paths_match(r"c:\tools\.\app.exe", &kernel));
    }

    /// `exe_paths_match`: a genuine spoof via `..` — the claimed path
    /// resolves to a different file than the kernel path — must still be
    /// caught. Folding must never launder a real substitution into a match.
    #[test]
    fn exe_paths_match_real_dotdot_spoof_is_caught() {
        let kernel = crate::fold_published(r"c:\good.exe");
        assert!(!exe_paths_match(r"c:\x\..\evil.exe", &kernel));
    }

    /// `exe_paths_match`: `..` popping above the drive root clamps at the
    /// anchor (mirrors the kernel's own volume-root clamp). The folded
    /// claim only matches a kernel path that resolves to that SAME clamped
    /// location — it must not collapse into a match with an unrelated path.
    #[test]
    fn exe_paths_match_dotdot_above_root_clamps_safely() {
        let same = crate::fold_published(r"c:\evil.exe");
        assert!(
            exe_paths_match(r"c:\..\..\evil.exe", &same),
            "clamped claim resolving to the same path as the kernel must match"
        );
        let other = crate::fold_published(r"c:\good.exe");
        assert!(
            !exe_paths_match(r"c:\..\..\evil.exe", &other),
            "clamped claim must not fold into a match with an unrelated kernel path"
        );
    }

    /// `exe_paths_match`: interior `/` separators mixed with `\` fold to the
    /// same normalized form. The drive anchor itself stays `\` on both sides
    /// here — matching real kernel-reported paths, which are always
    /// backslash-anchored — since `fold_dos_dots` preserves the anchor
    /// separator verbatim by contract and only normalizes interior segments.
    #[test]
    fn exe_paths_match_mixed_separators_is_not_spoof() {
        let kernel = crate::fold_published(r"c:\program files\git\usr\bin\bash.exe");
        assert!(exe_paths_match(r"c:\program files/git/bin/../usr/bin/bash.exe", &kernel));
    }

    /// S09 point 1: when the kernel path cannot be resolved (probe returns
    /// None) the decision fails closed — Err, never a decision derived from
    /// the guest-claimed string.
    #[test]
    fn hello_exe_context_unresolved_fails_closed() {
        assert!(hello_exe_context_impl(0x5A09_0003u32, "c:\\tools\\app.exe", &|_| None).is_err());
    }

    /// S09 point 2: a child whose kernel-recorded creator is exactly the
    /// connecting client passes the kinship proof.
    #[test]
    fn spawned_child_kinship_accepts_kernel_child() {
        let child = 0x5A09_0004u32;
        let parent = 0x5A09_0005u32;
        assert!(spawned_child_kinship_impl(
            child,
            parent,
            &|p: u32| if p == child { Some(parent) } else { None },
        ));
    }

    /// S09 point 2: a hostile SpawnedChild naming a child whose kernel
    /// creator is an unrelated PID fails, and so does a child that is already
    /// gone (probe returns None) — both reject.
    #[test]
    fn spawned_child_kinship_rejects_unrelated_pid() {
        let child = 0x5A09_0006u32;
        let other = 0x5A09_0007u32;
        // Kernel records a different creator than the connecting client.
        assert!(!spawned_child_kinship_impl(
            child,
            other,
            &|p: u32| if p == child { Some(0x5A09_0008u32) } else { None },
        ));
        // Child gone before the probe: no kinship.
        assert!(!spawned_child_kinship_impl(child, other, &|_| None));
    }

    /// S09 point 2: pid 0 is never a child, and self-parentage (child ==
    /// client) is never kernel truth — even with the probe offering a
    /// grandparent, the check rejects.
    #[test]
    fn spawned_child_kinship_rejects_zero_and_self() {
        let client = 0x5A09_0009u32;
        let grandparent = 0x5A09_000Au32;
        assert!(!spawned_child_kinship_impl(0, client, &|_| Some(grandparent)));
        assert!(!spawned_child_kinship_impl(
            client,
            client,
            &|p: u32| if p == client { Some(grandparent) } else { None },
        ));
    }

    /// S09 point 3: a Decide arriving before any Hello (no connection PID)
    /// must be refused — never served with the old permissive (None, None)
    /// fall-through that skips exe-scoped rules.
    #[test]
    fn decide_context_requires_hello() {
        assert!(decide_context(None).is_err());
    }

    /// S09 point 3: a connection PID with no tracked entry (never Hello'd,
    /// pruned, or recycled) is refused — fail closed rather than deciding
    /// without an identity.
    #[test]
    fn decide_context_refuses_when_entry_missing() {
        assert!(decide_context(Some(0x5A09_0010u32)).is_err());
    }

    /// S09 point 3: a Hello'd, tracked connection returns exactly the entry's
    /// (depth, exe_lower) so Decide can apply exe-scoped rules; the entry is
    /// cleaned up so the global map stays pristine for other tests.
    #[test]
    fn decide_context_returns_entry_context() {
        let pid = 0x5A09_0011u32;
        crate::sandbox::proc_table::global_proc_info().pin().insert(
            pid,
            crate::sandbox::proc_table::ProcInfo {
                depth: 3,
                exe_lower: Arc::from("c:\\x\\y.exe"),
                create_time: 42,
            },
        );
        let (depth, exe) = decide_context(Some(pid)).expect("tracked entry must decide");
        assert_eq!(depth, 3);
        assert_eq!(&*exe, "c:\\x\\y.exe");
        crate::sandbox::proc_table::global_proc_info().pin().remove(&pid);
        assert!(crate::sandbox::proc_table::global_proc_info().pin().get(&pid).is_none());
    }
}

// ─── MP-4: folder-job admission gate (inline tests) ──────────────────────────

#[cfg(test)]
mod mp4_folder_job_tests {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::process::{Child, Command};
    use std::sync::Arc;
    use windows::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};
    use winrsbox::contain::jobctl::FolderJob;

    // Real, short-lived, suspended child process with a live HANDLE — never
    // scheduled to run (CREATE_SUSPENDED), so it stays alive exactly until
    // killed, no console window (CREATE_NO_WINDOW). Mirrors
    // `contain::jobctl::tests::spawn_sleeper`.
    fn spawn_suspended() -> Child {
        Command::new("cmd")
            .args(["/C", "ping -n 3 127.0.0.1 >nul"])
            .creation_flags(CREATE_NO_WINDOW.0 | CREATE_SUSPENDED.0)
            .spawn()
            .expect("spawn suspended ping child")
    }

    fn handle_of(child: &Child) -> HANDLE {
        HANDLE(child.as_raw_handle())
    }

    fn kill_and_reap(mut child: Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    /// A guest that IS a member of the folder job is admitted purely on that
    /// kernel fact — with ZERO tracker history (no Hello, no SpawnedChild, no
    /// root match). This is exactly the MP-4 case: a guest of ANOTHER
    /// session's launcher in the same folder, which this launcher never saw
    /// before.
    #[test]
    fn guest_in_folder_job_is_admitted_with_no_tracker_history() {
        let job = FolderJob::create().expect("create folder job");
        let guest = spawn_suspended();
        let pid = guest.id();
        job.assign_process(handle_of(&guest)).expect("assign guest to folder job");

        assert!(
            is_owned_client_pid(pid, 0, Some(&job)),
            "a process that IS in the folder job must be admitted even with \
             no tracker entry and root_target_pid=0"
        );

        kill_and_reap(guest);
    }

    /// Necessary condition (plan step 2): a process OUTSIDE the folder job is
    /// rejected even though it has a fully verified tracker entry that the
    /// pre-MP-4 path would have accepted. Job membership is not merely
    /// additional context here — its absence overrides tracker history.
    #[test]
    fn process_outside_folder_job_rejected_even_with_tracker_entry() {
        let job = FolderJob::create().expect("create folder job");
        let outsider = spawn_suspended();
        let pid = outsider.id();
        // Deliberately NOT assigned to `job`.

        let ct = process_create_time_from_handle(handle_of(&outsider));
        assert_ne!(ct, 0, "must fingerprint the live outsider process");
        crate::sandbox::proc_table::global_proc_info().pin().insert(
            pid,
            crate::sandbox::proc_table::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("c:\\outsider.exe"),
                create_time: ct,
            },
        );

        // Sanity: the pre-MP-4 (no-folder-job) path WOULD have admitted this
        // PID via its tracker entry.
        assert!(
            is_owned_client_pid(pid, 0, None),
            "sanity: tracker entry alone must admit in no-folder-job mode"
        );
        // With a folder job present, membership is required — tracker
        // history alone must NOT be enough.
        assert!(
            !is_owned_client_pid(pid, 0, Some(&job)),
            "a process outside the folder job must be rejected even with a \
             verified tracker entry"
        );

        crate::sandbox::proc_table::global_proc_info().pin().remove(&pid);
        kill_and_reap(outsider);
    }

    /// A dead/reaped PID (the PID-reuse hardening scenario applied to the
    /// job-admission path): `OpenProcess` on an already-reaped PID fails, so
    /// `folder_job_contains_pid` fails closed regardless of what the job
    /// contains for anyone else.
    #[test]
    fn dead_pid_rejected_on_folder_job_path() {
        let job = FolderJob::create().expect("create folder job");
        let child = spawn_suspended();
        let pid = child.id();
        kill_and_reap(child); // fully terminated AND reaped (wait())

        assert!(
            !is_owned_client_pid(pid, 0, Some(&job)),
            "a dead/reaped PID must be rejected on the folder-job path — \
             OpenProcess fails closed"
        );
    }

    /// PID 0 is never admitted, folder job present or not.
    #[test]
    fn zero_pid_rejected_with_folder_job_present() {
        let job = FolderJob::create().expect("create folder job");
        assert!(!is_owned_client_pid(0, 0, Some(&job)));
    }

    // ─── resolve_new_entry_depth ──────────────────────────────────────────

    /// A Hello'd PID with no tracker entry, but whose kernel-vouched parent
    /// IS tracked, resolves to parent.depth + 1 — not the naive 0 a "new
    /// process" default would give.
    #[test]
    fn resolve_new_entry_depth_finds_tracked_ancestor() {
        let child = 0x5A10_0001u32;
        let parent = 0x5A10_0002u32;
        let depth = resolve_new_entry_depth_impl(
            child,
            &|p| if p == parent { Some(2) } else { None },
            &|p| if p == child { Some(parent) } else { None },
        );
        assert_eq!(depth, 3, "must be parent.depth (2) + 1");
    }

    /// No tracked ancestor anywhere in the (bounded) parent chain — e.g. a
    /// job-admitted guest of another session's launcher, whose entire
    /// ancestry is invisible to this launcher's tracker — resolves to the
    /// conservative/fail-closed `u8::MAX`, never the permissive 0.
    #[test]
    fn resolve_new_entry_depth_conservative_when_no_ancestor_tracked() {
        let pid = 0x5A10_0003u32;
        let depth = resolve_new_entry_depth_impl(
            pid,
            &|_| None, // nothing is ever tracked
            &|p| if p == pid { Some(0x5A10_0004u32) } else { None }, // one untracked ancestor
        );
        assert_eq!(depth, u8::MAX);
    }

    /// A parent chain that terminates (PID 0 / kernel probe failure) with no
    /// tracked ancestor also fails closed to `u8::MAX`, not 0.
    #[test]
    fn resolve_new_entry_depth_conservative_when_chain_ends() {
        let pid = 0x5A10_0005u32;
        let depth = resolve_new_entry_depth_impl(pid, &|_| None, &|_| None);
        assert_eq!(depth, u8::MAX);
    }

    /// A cyclic parent chain (pathological/spoofed) terminates the walk via
    /// the cycle guard rather than looping forever, and still fails closed.
    #[test]
    fn resolve_new_entry_depth_handles_cycle() {
        let a = 0x5A10_0006u32;
        let b = 0x5A10_0007u32;
        let depth = resolve_new_entry_depth_impl(
            a,
            &|_| None,
            &|p| if p == a { Some(b) } else if p == b { Some(a) } else { None },
        );
        assert_eq!(depth, u8::MAX);
    }
}
