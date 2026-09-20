// ─── IPC pipe server ──────────────────────────────────────────────────────────

use ipc::{read_msg, write_msg, LogLevel, Req, Resp};
use policy::Policy;
use std::{
    ffi::{c_void, OsStr},
    io::Read,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use windows::{
    core::{HRESULT, PCWSTR},
    Win32::{
        Foundation::{CloseHandle, FILETIME, HLOCAL, LocalFree, ERROR_PIPE_CONNECTED, HANDLE},
        Security::{
            GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
            TokenUser, TOKEN_QUERY, TOKEN_USER,
        },
        Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX},
        System::{
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
                GetNamedPipeClientProcessId,
                PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
            },
            Threading::{
                GetCurrentProcess, GetExitCodeProcess, GetProcessTimes, OpenProcess,
                OpenProcessToken, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    },
};
use winrsbox::hot_stats::{HotStats, ThrottledFlusher};
use winrsbox::jsonl_log;

// ─── C3 Part 2: raw advapi32 bindings for SDDL/SID conversion ─────────────────
//
// The `Win32_Security_Authorization` feature of `windows-0.61` exposes these,
// but enabling it would touch Cargo.toml — out of scope per task. Declaring
// them by hand is cheap and keeps the patch isolated to pipe_server.rs.
// All three functions live in advapi32.dll and use the standard `BOOL`
// convention (nonzero = success). Signatures match MSDN verbatim.
#[link(name = "advapi32")]
unsafe extern "system" {
    /// Returns the SDDL string form of `sid` in a LocalAlloc'd buffer.
    /// Caller must `LocalFree` the returned pointer. Returns 0 on failure.
    fn ConvertSidToStringSidW(sid: PSID, stringsid: *mut *mut u16) -> i32;

    /// Parses an SDDL string and returns a LocalAlloc'd
    /// PSECURITY_DESCRIPTOR. Returns 0 on failure.
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        stringsecuritydescriptor: PCWSTR,
        stringsdrevision: u32,
        securitydescriptor: *mut PSECURITY_DESCRIPTOR,
        securitydescriptorsize: *mut u32,
    ) -> i32;
}

/// SDDL_REVISION_1 — the only revision the W variant accepts.
const SDDL_REVISION_1: u32 = 1;

// ─── Stats ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct Stats {
    pub(crate) decide: AtomicU64,
    pub(crate) redirect: AtomicU64,
    pub(crate) deny: AtomicU64,
    pub(crate) mock_: AtomicU64,
    pub(crate) cow: AtomicU64,
    pub(crate) violations: AtomicU64,
}

// ─── C3 Part 2: per-launcher security descriptor for the IPC pipe ─────────────

/// Owns the heap allocation behind the security descriptor returned by
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW`. We keep it alive
/// for the entire lifetime of the pipe accept loop because every
/// `CreateNamedPipeW` call dereferences `SECURITY_ATTRIBUTES.lpSecurityDescriptor`.
///
/// SAFETY contract: the raw pointer behind `sd` is the LocalAlloc'd buffer
/// returned by the SDDL converter. We intentionally never call `LocalFree`
/// on it — this is a one-time allocation at startup, and process exit
/// reclaims it via OS teardown. Calling `LocalFree` would risk a
/// use-after-free if the SD were referenced after the wrapper drops.
struct PipeSecurity {
    /// LocalAlloc'd security descriptor returned by SDDL conversion.
    /// Kept around purely so the field is not optimized away; the actual
    /// pointer used by Win32 is the one stored in `sa.lpSecurityDescriptor`.
    #[allow(dead_code)]
    sd: PSECURITY_DESCRIPTOR,
    /// SECURITY_ATTRIBUTES pointing into `sd`. Kept stable so the address
    /// passed to `CreateNamedPipeW` remains valid across iterations.
    sa: SECURITY_ATTRIBUTES,
}

// SAFETY: PSECURITY_DESCRIPTOR / SECURITY_ATTRIBUTES contain raw pointers to a
//         heap buffer that lives for the entire process. After construction
//         the buffer is read-only and the OS reads it from arbitrary threads
//         when servicing CreateNamedPipeW — i.e. it is already required to be
//         safe to dereference cross-thread.
unsafe impl Send for PipeSecurity {}
unsafe impl Sync for PipeSecurity {}

/// Query the current process's user SID, format it as a string SID, and
/// build a security descriptor via SDDL that grants `GENERIC_READ |
/// GENERIC_WRITE` to that SID only. Everything else (including SYSTEM, other
/// users, and remote callers) is denied because we provide an explicit DACL
/// containing exactly one ACE.
///
/// SDDL layout: `D:P(A;;GRGW;;;<user_sid>)`
///   • `D:`     — DACL section
///   • `P`      — DACL_PROTECTED (no inheritance from any container)
///   • `(A;;GRGW;;;sid)` — Allow ACE granting GENERIC_READ + GENERIC_WRITE
///                        (covers everything a pipe client and server need:
///                        read/write data, attributes, EAs, SYNCHRONIZE).
///
/// Same-user different-session caveat: the user SID is identical across
/// logon sessions of the same Windows user, so an attacker process running
/// under the same user account in a different session WILL pass this DACL.
/// The Part 3 client-PID check rejects such attackers — the SDDL is the
/// first wall, the PID validation is the second.
fn build_pipe_security() -> anyhow::Result<PipeSecurity> {
    // ── 1. Get current process user SID ────────────────────────────────────
    // SAFETY: GetCurrentProcess returns a pseudo-handle; OpenProcessToken with
    //         TOKEN_QUERY is the documented way to query our own token.
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| anyhow::anyhow!("OpenProcessToken failed: {e}"))?;
    }
    // Two-step GetTokenInformation: first call sizes the buffer.
    let mut needed: u32 = 0;
    // SAFETY: passing None for the buffer + 0 length is the documented
    //         pattern for getting the required size; we ignore the error
    //         return and read `needed` regardless.
    let _ = unsafe {
        GetTokenInformation(token, TokenUser, None, 0, &mut needed)
    };
    if needed == 0 {
        unsafe { CloseHandle(token).ok() };
        anyhow::bail!("GetTokenInformation(TokenUser) size query returned 0");
    }
    let mut buf = vec![0u8; needed as usize];
    let mut got: u32 = 0;
    // SAFETY: buf is sized to `needed`; we pass its pointer and length.
    let info_result = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            needed,
            &mut got,
        )
    };
    unsafe { CloseHandle(token).ok() };
    info_result.map_err(|e| anyhow::anyhow!("GetTokenInformation(TokenUser) failed: {e}"))?;

    // SAFETY: buf was filled by GetTokenInformation with a TOKEN_USER struct
    //         followed by the SID bytes. The buffer outlives this read.
    let token_user: &TOKEN_USER = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let user_sid = token_user.User.Sid;
    if user_sid.is_invalid() {
        anyhow::bail!("TokenUser returned an invalid SID");
    }

    // ── 2. Convert SID to string form (raw advapi32) ───────────────────────
    let mut sid_pwstr: *mut u16 = std::ptr::null_mut();
    // SAFETY: user_sid is valid for the lifetime of `buf` (still alive);
    //         ConvertSidToStringSidW LocalAlloc's into sid_pwstr on success.
    let ok = unsafe { ConvertSidToStringSidW(user_sid, &mut sid_pwstr) };
    if ok == 0 || sid_pwstr.is_null() {
        anyhow::bail!("ConvertSidToStringSidW failed");
    }
    // SAFETY: sid_pwstr is a null-terminated wide string allocated by Win32.
    let sid_str = unsafe {
        let mut len = 0usize;
        while *sid_pwstr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(sid_pwstr, len);
        String::from_utf16_lossy(slice)
    };
    // Free the SID string buffer — we copied its contents.
    // SAFETY: sid_pwstr came from LocalAlloc'd ConvertSidToStringSidW; LocalFree
    //         is the matched deallocator.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sid_pwstr as *mut c_void)));
    }

    // ── 3. Build SDDL and convert to SECURITY_DESCRIPTOR (raw advapi32) ────
    let sddl = format!("D:P(A;;GRGW;;;{sid_str})");
    let sddl_w: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut psd_ptr: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
    // SAFETY: sddl_w is null-terminated; psd_ptr is a stack out-param;
    //         the SDDL converter LocalAlloc's the descriptor and stores
    //         its pointer in `psd_ptr` on success.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &mut psd_ptr,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || psd_ptr.is_invalid() {
        anyhow::bail!(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed (sddl={sddl})",
        );
    }

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd_ptr.0,
        bInheritHandle: windows::core::BOOL(0),
    };
    Ok(PipeSecurity { sd: psd_ptr, sa })
}

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
fn is_owned_client_pid(client_pid: u32, root_target_pid: u32) -> bool {
    is_owned_client_pid_impl(
        client_pid,
        root_target_pid,
        crate::root_create_time(),
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
fn is_owned_client_pid_impl(
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
        let map = crate::global_proc_info().pin();
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
    crate::global_proc_info().pin().remove(&pid);
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

// ─── Pipe accept loop ─────────────────────────────────────────────────────────

/// Audit M-A3: cap concurrent handler tasks so a hostile sandboxed process that
/// hammers the named pipe in a loop cannot exhaust tokio's blocking pool
/// (default 512 threads) and freeze the launcher. The cap applies only to
/// per-connection handlers; the accept-side `ConnectNamedPipe` (which itself
/// uses `spawn_blocking`) is intentionally outside this budget — only one
/// accept is in flight at a time, so it never competes with handlers for
/// the cap, and leaving it uncapped guarantees the loop can always make
/// progress even when all 128 handler slots are busy.
pub(crate) const MAX_CONCURRENT_HANDLERS: usize = 128;

/// Number of parallel `ConnectNamedPipe` acceptors that share the pipe
/// namespace. Each acceptor owns its own pipe instance, so up to N clients
/// can `CreateFile`-connect simultaneously without anyone seeing
/// `ERROR_PIPE_BUSY`. Before this pool, the accept loop was single-instance:
/// MSYS2's first-run setup (which spawns ~8 helper processes in the same
/// second from a single bash invocation) raced for that one pipe, lost,
/// and burned the hook-side connect/retry budget — cascading
/// self-terminates.
///
/// 32 absorbs every burst we've measured live (MSYS2 first-run spawns 27+
/// bash helpers in 1 s, npm install, cargo build, claude-code agent fan-out)
/// with generous headroom; each instance costs only the 64 KiB in/out buffer
/// (and one tokio task while idle), so the total footprint is ~2 MiB.
pub(crate) const PIPE_ACCEPT_POOL_SIZE: usize = 32;

/// Audit (2026-09-19, Medium): message size (ipc::MAX_MSG_LEN, 16 MiB) and
/// handler concurrency (MAX_CONCURRENT_HANDLERS, 128) were each bounded,
/// but their product was not: 128 handlers each reading one maximal
/// message could hold ~2 GiB of guest-driven buffers. This budget caps the
/// TOTAL bytes of in-flight message bodies across all connections: each
/// handler reserves the guest-declared body length before the body is read
/// and holds the reservation until the message is handled. Typical
/// requests are a few hundred bytes, so normal traffic never nears the
/// cap; it only binds when many large declared sizes are in flight.
pub(crate) const MAX_INFLIGHT_MSG_BYTES: usize = 64 * 1024 * 1024;

/// How long a handler may wait for byte budget before its connection is
/// dropped. Only a pathological guest (declare a 16 MiB body, then never
/// send it, repeatedly) can exhaust the budget for long; 30 s dwarfs any
/// legitimate transfer over a local named pipe while guaranteeing the cap
/// cannot wedge the server permanently.
const BYTE_BUDGET_WAIT: Duration = Duration::from_secs(30);

/// Process-wide cap on total in-flight message-body bytes (see
/// MAX_INFLIGHT_MSG_BYTES). Blocking reservations via Mutex+Condvar are
/// fine here: handlers already run on blocking threads.
pub(crate) struct ByteBudget {
    max: usize,
    in_use: Mutex<usize>,
    cv: Condvar,
}

/// A live reservation of `n` bytes of the budget; released on drop.
struct ByteReservation<'a> {
    budget: &'a ByteBudget,
    n: usize,
}

impl ByteBudget {
    pub(crate) fn new(max: usize) -> Self {
        Self { max, in_use: Mutex::new(0), cv: Condvar::new() }
    }

    #[cfg(test)]
    fn try_reserve(&self, n: usize) -> Option<ByteReservation<'_>> {
        let mut in_use = self.in_use.lock().unwrap();
        if *in_use + n > self.max {
            return None;
        }
        *in_use += n;
        Some(ByteReservation { budget: self, n })
    }

    /// Block until `n` bytes fit under the cap, or `timeout` elapses.
    /// Single amounts above the whole budget are clamped to it (one
    /// oversized-but-legal message still goes through, bounded by the cap).
    fn reserve_timeout(&self, n: usize, timeout: Duration) -> Option<ByteReservation<'_>> {
        let n = n.min(self.max);
        let deadline = Instant::now() + timeout;
        let mut in_use = self.in_use.lock().unwrap();
        loop {
            if *in_use + n <= self.max {
                *in_use += n;
                return Some(ByteReservation { budget: self, n });
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return None;
            };
            let (guard, wait) = self.cv.wait_timeout(in_use, remaining).unwrap();
            in_use = guard;
            if wait.timed_out() {
                return None;
            }
        }
    }
}

impl Drop for ByteReservation<'_> {
    fn drop(&mut self) {
        let mut in_use = self.budget.in_use.lock().unwrap();
        *in_use -= self.n;
        drop(in_use);
        self.budget.cv.notify_all();
    }
}

/// Serves a 4-byte length prefix that was already read off the wire, then
/// delegates to the pipe. This lets `handle_connection` inspect the
/// guest-declared body length (for budget reservation) before the body is
/// read, while `ipc::read_msg` still owns the whole message parse,
/// header included.
struct PrefixedReader<'a, R: Read> {
    prefix: [u8; 4],
    pos: usize,
    inner: &'a mut R,
}

impl<R: Read> Read for PrefixedReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

/// Build one server-side instance of the launcher pipe. Pure FFI wrapper so
/// the accept loop body stays focused on the connect/validate flow. The
/// caller MUST pass `is_first = true` on exactly ONE call (the very first
/// instance created for this pipe name) to claim the kernel namespace via
/// `FILE_FLAG_FIRST_PIPE_INSTANCE`; subsequent calls MUST pass `false`
/// (the flag is illegal once an instance already exists).
///
/// Returns the handle as `isize` so it crosses tokio's `.await` / task
/// boundaries (`HANDLE`'s raw pointer is `!Send`); reconstruct with
/// `HANDLE(ph as *mut _)` on the consuming side.
fn create_pipe_instance(
    pipe_name_wide: &[u16],
    pipe_sec: &PipeSecurity,
    is_first: bool,
) -> Result<isize, String> {
    let dw_open_mode = if is_first {
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE
    } else {
        PIPE_ACCESS_DUPLEX
    };
    let dw_pipe_mode =
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
    // SAFETY: pipe_name_wide is a valid null-terminated UTF-16 string; pipe_sec
    //         contains a valid SECURITY_ATTRIBUTES that lives at least until the
    //         FFI call returns (caller owns it).
    unsafe {
        let h = CreateNamedPipeW(
            PCWSTR(pipe_name_wide.as_ptr()),
            dw_open_mode,
            dw_pipe_mode,
            255,    // max instances (kernel-imposed cap on this name)
            65536,  // out buffer size
            65536,  // in buffer size
            0,      // default timeout
            Some(&pipe_sec.sa as *const SECURITY_ATTRIBUTES),
        );
        if h.is_invalid() {
            Err(format!("{:?}", windows::core::Error::from_win32()))
        } else {
            Ok(h.0 as isize)
        }
    }
}

/// RAII teardown guard for an accepted pipe connection's server-side handle.
///
/// Audit M-A3 (robustness / resource leak): the per-connection handler runs
/// inside a `spawn_blocking` closure. If `handle_connection` panics, any
/// teardown written as plain statements *after* the call would be skipped
/// during unwind, leaking the pipe handle (and leaving the connection
/// un-disconnected) for that connection. This guard moves the teardown into
/// `Drop`, so `DisconnectNamedPipe` + `CloseHandle` run on *every* exit path —
/// normal return, `?`/early return, or panic-unwind.
///
/// Stores the `isize` repr of the handle (not a `HANDLE` / raw pointer) so the
/// value remains trivially `Send` across the `spawn_blocking` boundary, exactly
/// as the surrounding accept loop already does; the `HANDLE` is reconstructed
/// only inside `Drop`, on the worker thread that owns it.
///
/// panic=abort caveat: the workspace *release* profile uses `panic = "abort"`,
/// under which a panic terminates the process before unwinding and Drop does not
/// run. That is acceptable — an aborting process frees all its handles anyway.
/// Under `panic = "unwind"` (debug/test, and any future config change) the guard
/// is what prevents the leak. RAII is the correct pattern regardless of profile.
struct PipeConnGuard {
    /// `isize` repr of the connection's server-side pipe `HANDLE`.
    raw: isize,
}

impl Drop for PipeConnGuard {
    fn drop(&mut self) {
        // SAFETY: `raw` is the `isize` repr of the valid server-side pipe HANDLE
        //         for this connection, handed to us by the accept loop. It is not
        //         closed anywhere else on this path (`handle_connection`
        //         deliberately `mem::forget`s its `File` wrapper so teardown is
        //         the guard's sole responsibility), so this is the unique close.
        let h = HANDLE(self.raw as *mut _);
        unsafe { DisconnectNamedPipe(h).ok() };
        unsafe { CloseHandle(h).ok() };
    }
}

/// cancel-safe: NO — individual connection handlers are detached via spawn;
///              this outer loop itself is not designed for clean cancellation,
///              it runs for the lifetime of the launcher process.
pub(crate) async fn pipe_accept_loop(
    pipe_name: &str,
    policy: Arc<Policy>,
    reg_policy: Arc<policy::RegistryPolicy>,
    stats: Arc<Stats>,
    child_pids: Arc<crossbeam_queue::SegQueue<u32>>,
    violations_log: PathBuf,
    hot_stats: Arc<HotStats>,
    flusher: Arc<ThrottledFlusher>,
    // C3 Part 3: PID of the root sandboxed target. Cross-checked with
    // GetNamedPipeClientProcessId on every new connection so an unrelated
    // same-user process cannot impersonate the hooked target.
    //
    // Shared as `Arc<AtomicU32>` because the accept loop spawns BEFORE
    // `launch_suspended` produces the root PID. The launcher publishes the
    // PID via `store(.., Release)` after `CreateProcessW`, long before the
    // root child can connect (it stays suspended until `ResumeThread`). A
    // value of `0` here means "not yet known" and the validation falls
    // back to a `global_proc_info` lookup; the root insertion in main.rs
    // immediately before `ResumeThread` covers that path too.
    root_target_pid: Arc<AtomicU32>,
) -> anyhow::Result<()> {
    let pipe_name_wide: Vec<u16> = OsStr::new(pipe_name)
        .encode_wide()
        .chain(Some(0))
        .collect();

    // C3 Part 2: build the launcher-user-only DACL once at startup. The
    // descriptor is referenced by every `CreateNamedPipeW` call below, so we
    // wrap it in an Arc to keep the heap pointer stable for the loop's
    // lifetime. Failure here is fail-closed — the launcher refuses to start
    // the IPC server without a hardened SD.
    let pipe_sec = Arc::new(
        build_pipe_security()
            .map_err(|e| anyhow::anyhow!("C3: pipe SD construction failed: {e}"))?,
    );

    // Audit M-A3: bound handler-task concurrency. Each accepted connection
    // acquires one permit before `spawn_blocking`; the permit drops when the
    // handler returns, freeing the slot. `acquire_owned().await` between
    // `ConnectNamedPipe` and the handler-side `spawn_blocking` gives natural
    // backpressure on the accept loop without ever blocking the accept-side
    // `spawn_blocking` itself.
    let handler_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_HANDLERS));

    // Audit: process-wide cap on total in-flight message-body bytes,
    // bounding the product of per-message size and handler concurrency.
    let byte_budget = Arc::new(ByteBudget::new(MAX_INFLIGHT_MSG_BYTES));

    // C3 Part 1: claim the pipe namespace by creating the FIRST instance
    // synchronously, with FILE_FLAG_FIRST_PIPE_INSTANCE. This MUST succeed
    // before we expose any acceptors — a collision here means another
    // process owns the pipe name (possible attack) and we fail-closed.
    let first_ph = match create_pipe_instance(&pipe_name_wide, &pipe_sec, true) {
        Ok(ph) => ph,
        Err(err) => {
            return Err(anyhow::anyhow!(
                "CreateNamedPipeW(FIRST_PIPE_INSTANCE) failed for {pipe_name}: {err} \
                 — pipe name collision, possible attack",
            ));
        }
    };

    // Spawn the parallel accept pool. Worker 0 inherits the just-claimed
    // FIRST_PIPE_INSTANCE handle as its initial pipe; the remaining workers
    // each create their own (un-flagged) instance on entry. Each worker runs
    // its own `Create → Connect → validate → handle` loop forever, so the
    // pool can absorb up to PIPE_ACCEPT_POOL_SIZE simultaneous client
    // connects without anyone hitting ERROR_PIPE_BUSY.
    let mut workers = Vec::with_capacity(PIPE_ACCEPT_POOL_SIZE);
    for slot in 0..PIPE_ACCEPT_POOL_SIZE {
        let initial = if slot == 0 { Some(first_ph) } else { None };
        let pipe_name_wide = pipe_name_wide.clone();
        let pipe_sec = Arc::clone(&pipe_sec);
        let handler_sem = Arc::clone(&handler_sem);
        let byte_budget = Arc::clone(&byte_budget);
        let policy = Arc::clone(&policy);
        let reg_policy = Arc::clone(&reg_policy);
        let stats = Arc::clone(&stats);
        let child_pids = Arc::clone(&child_pids);
        let violations_log = violations_log.clone();
        let hot_stats = Arc::clone(&hot_stats);
        let flusher = Arc::clone(&flusher);
        let root_target_pid = Arc::clone(&root_target_pid);
        workers.push(tokio::spawn(accept_worker(
            initial,
            pipe_name_wide,
            pipe_sec,
            handler_sem,
            byte_budget,
            policy,
            reg_policy,
            stats,
            child_pids,
            violations_log,
            hot_stats,
            flusher,
            root_target_pid,
        )));
    }

    // Workers are designed to run for the launcher's lifetime; if any of them
    // returns early (Err or unexpected Ok) we surface the failure to the
    // outer launcher rather than silently shrinking the pool.
    for w in workers {
        match w.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(je) => return Err(anyhow::anyhow!("accept worker task panicked: {je}")),
        }
    }
    Ok(())
}

/// One slot of the parallel accept pool. Owns a single pipe instance at a
/// time: connects a client, validates it, hands the connection off to a
/// blocking handler task (subject to `handler_sem`), then creates a fresh
/// instance and waits for the next client.
///
/// The first worker takes the launcher-owned `FIRST_PIPE_INSTANCE` handle
/// via `initial_ph`; subsequent workers (and every subsequent iteration of
/// every worker) call `create_pipe_instance(.., false)`.
#[allow(clippy::too_many_arguments)]
async fn accept_worker(
    mut initial_ph: Option<isize>,
    pipe_name_wide: Vec<u16>,
    pipe_sec: Arc<PipeSecurity>,
    handler_sem: Arc<Semaphore>,
    byte_budget: Arc<ByteBudget>,
    policy: Arc<Policy>,
    reg_policy: Arc<policy::RegistryPolicy>,
    stats: Arc<Stats>,
    child_pids: Arc<crossbeam_queue::SegQueue<u32>>,
    violations_log: PathBuf,
    hot_stats: Arc<HotStats>,
    flusher: Arc<ThrottledFlusher>,
    root_target_pid: Arc<AtomicU32>,
) -> anyhow::Result<()> {
    loop {
        // Acquire this iteration's pipe handle: either consume the seed
        // FIRST_PIPE_INSTANCE handle (worker-0, very first iteration), or
        // create a fresh instance.
        let ph: isize = if let Some(h) = initial_ph.take() {
            h
        } else {
            match create_pipe_instance(&pipe_name_wide, &pipe_sec, false) {
                Ok(ph) => ph,
                Err(err) => {
                    eprintln!("[pipe] CreateNamedPipeW (instance) failed: {err} — retrying");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            }
        };

        // ConnectNamedPipe blocks until a client connects — run in spawn_blocking
        // to avoid blocking the async executor (§B11).
        let connect_result = tokio::task::spawn_blocking(move || {
            // SAFETY: ph is the isize repr of a valid named-pipe HANDLE; converting
            //         back is safe because the handle is valid for this thread's lifetime.
            let h = HANDLE(ph as *mut _);
            // SAFETY: h is a valid server-side pipe handle; None means synchronous wait.
            match unsafe { ConnectNamedPipe(h, None) } {
                Ok(()) => true,
                Err(e)
                    if e.code()
                        == HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) =>
                {
                    // A client connected between CreateNamedPipeW and ConnectNamedPipe —
                    // that is still a valid connection.
                    true
                }
                Err(_) => false,
            }
        })
        .await;

        let connected = connect_result.unwrap_or(false);
        if !connected {
            // SAFETY: ph is the isize repr of our pipe handle; close on error.
            unsafe { CloseHandle(HANDLE(ph as *mut _)).ok() };
            continue;
        }

        // C3 Part 3: validate the newly connected client BEFORE the handler
        // task takes the handle. GetNamedPipeClientProcessId is meaningful only
        // after the connection completes (post ConnectNamedPipe). The PID it
        // returns is the OS's record of which process called CreateFileW on
        // the server-side handle — kernel-vouched, not user-controllable.
        //
        // Failure cases handled identically: disconnect and continue the
        // accept loop, never run a handler task for an unverified client.
        let mut client_pid: u32 = 0;
        // SAFETY: pipe handle is valid (we just finished ConnectNamedPipe on it).
        let pid_ok = unsafe {
            GetNamedPipeClientProcessId(HANDLE(ph as *mut _), &mut client_pid).is_ok()
        };
        if !pid_ok {
            eprintln!(
                "[pipe] GetNamedPipeClientProcessId failed on new connection — disconnecting",
            );
            // SAFETY: ph is the isize repr of our pipe handle.
            unsafe { DisconnectNamedPipe(HANDLE(ph as *mut _)).ok() };
            unsafe { CloseHandle(HANDLE(ph as *mut _)).ok() };
            continue;
        }
        let root_pid_snapshot = root_target_pid.load(Ordering::Acquire);
        if !is_owned_client_pid(client_pid, root_pid_snapshot) {
            eprintln!(
                "[pipe] WARN: rejecting connection from non-owned pid={client_pid} \
                 (root_target_pid={root_pid_snapshot})",
            );
            stats.violations.fetch_add(1, Ordering::Relaxed);
            hot_stats
                .totals
                .violations
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            jsonl_log::log_immediate(jsonl_log::Event::violation(
                client_pid,
                "PipeClientNotOwned",
                &format!("root_target_pid={root_pid_snapshot}"),
            ));
            // SAFETY: ph is the isize repr of our pipe handle.
            unsafe { DisconnectNamedPipe(HANDLE(ph as *mut _)).ok() };
            unsafe { CloseHandle(HANDLE(ph as *mut _)).ok() };
            continue;
        }

        // Audit M-A3: bound handler concurrency. If all MAX_CONCURRENT_HANDLERS
        // slots are in use, this awaits — naturally backpressuring the accept
        // loop. `acquire_owned` returns an `OwnedSemaphorePermit` that carries
        // its own `Arc<Semaphore>` clone so it can move into the blocking task.
        let permit = match handler_sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                // Semaphore was closed — process is shutting down. Tear down
                // this connection and exit the worker instead of leaking the
                // pipe handle.
                // SAFETY: ph is the isize repr of our pipe handle.
                unsafe { DisconnectNamedPipe(HANDLE(ph as *mut _)).ok() };
                unsafe { CloseHandle(HANDLE(ph as *mut _)).ok() };
                return Ok(());
            }
        };

        // Handle this connection in a separate blocking task.
        let policy = Arc::clone(&policy);
        let reg_policy = Arc::clone(&reg_policy);
        let stats = Arc::clone(&stats);
        let child_pids = Arc::clone(&child_pids);
        let vlog = violations_log.clone();
        let hot_stats2 = Arc::clone(&hot_stats);
        let flusher2 = Arc::clone(&flusher);
        let byte_budget2 = Arc::clone(&byte_budget);

        // Intentional fire-and-forget: spawn_blocking tasks run to completion even
        // after JoinHandle is dropped — they are not cancelled.
        tokio::task::spawn_blocking(move || {
            // RAII teardown (Audit M-A3): construct the guard BEFORE running the
            // handler so `DisconnectNamedPipe` + `CloseHandle` run on every exit
            // path, including a panic in `handle_connection` (under panic=unwind).
            // Declared before `_permit` so the handle teardown spans the whole
            // closure body; both drop when the closure returns/unwinds.
            let _guard = PipeConnGuard { raw: ph };
            // The permit is dropped when this closure returns, releasing the
            // handler slot back to the semaphore for the next accepted connection.
            let _permit = permit;
            // SAFETY: ph is the isize repr of the valid pipe handle for this connection.
            let h = HANDLE(ph as *mut _);
            handle_connection(h, client_pid, &policy, &reg_policy, &stats, &child_pids, &vlog, &hot_stats2, &flusher2, &byte_budget2);
        });
    }
}

/// Registry-key substrings that always deny on write — every entry here
/// represents a well-known persistence / DLL-injection vector. Matching is
/// case-insensitive substring over the already-lowercased key path, so the
/// rules apply uniformly to HKLM\, HKCU\, HKCR\, and HKU\<SID>\ forms.
const PERSISTENCE_DENY_SUFFIXES: &[&str] = &[
    // ─── original 6 entries (kept verbatim) ─────────────────────────────────
    r"\software\microsoft\windows nt\currentversion\windows",
    r"\software\wow6432node\microsoft\windows nt\currentversion\windows",
    r"\software\microsoft\windows nt\currentversion\image file execution options",
    r"\software\microsoft\windows nt\currentversion\silentprocessexit",
    r"\system\currentcontrolset\control\session manager\appcertdlls",
    // No trailing backslash: segment-anchored matching denies both the
    // Services hive root and any subkey under it (sandbox must never write
    // a service registration anywhere).
    r"\system\currentcontrolset\services",

    // ─── H-S4 new entries ───────────────────────────────────────────────────
    // Classic autorun under HKCU and HKLM (Run / RunOnce / RunOnceEx and
    // the StartupApproved twin that controls whether disabled-via-UI entries
    // run anyway).
    r"\software\microsoft\windows\currentversion\run",
    r"\software\microsoft\windows\currentversion\runonce",
    r"\software\microsoft\windows\currentversion\runonceex",
    r"\software\microsoft\windows\currentversion\explorer\startupapproved\run",

    // Logon hooks — run as SYSTEM at every interactive logon.
    r"\software\microsoft\windows nt\currentversion\winlogon\userinit",
    r"\software\microsoft\windows nt\currentversion\winlogon\shell",
    r"\software\microsoft\windows nt\currentversion\winlogon\notify",

    // Legacy MCI drivers — Drivers32 entries are LoadLibrary'd at app startup.
    r"\software\microsoft\windows nt\currentversion\drivers32",

    // App Paths — hijacks ShellExecute("notepad.exe") and friends.
    r"\software\microsoft\windows\currentversion\app paths",

    // COM hijack — InprocServer32 / LocalServer32 under any CLSID loads
    // the attacker DLL into every COM client.
    r"\software\classes\clsid",

    // File / URL association hijack — the existing match is substring, so
    // `\shell\open\command` catches `HKCU\Software\Classes\<ext>\shell\open\command`
    // for every extension, plus the equivalent under HKLM and HKCR.
    r"\shell\open\command",
    r"\shellex\contextmenuhandlers",

    // cmd.exe autorun — runs on every cmd.exe invocation.
    r"\software\microsoft\command processor\autorun",

    // LSA package injection — adds an attacker DLL into LSASS / SAM.
    r"\system\currentcontrolset\control\lsa\notification packages",
    r"\system\currentcontrolset\control\lsa\authentication packages",
    r"\system\currentcontrolset\control\lsa\security packages",

    // Office "Trusted Locations" bypass — marks attacker paths as macro-safe.
    // Substring catches `\office\<ver>\<app>\security\trusted locations` for
    // every Office version (16.0, 15.0, ...) and every app (word, excel, ...).
    r"\security\trusted locations",

    // ─── per-user COM hijack (H2) ───────────────────────────────────────────
    // When HKCR\CLSID is opened for write, the kernel resolves to the per-user
    // classes hive: \Registry\User\<SID>_Classes\CLSID\... which nt_to_friendly
    // maps to hku\<sid>_classes\clsid\... — the \software\classes\clsid entry
    // above does not match this form. Use `_classes\clsid` to catch the
    // underscore-joined per-user hive segment.
    r"_classes\clsid",
    // ─── HKCU\Environment persistence (M6) ──────────────────────────────────
    // UserInitMprLogonScript, PATH manipulation, DLL search-order via env vars.
    r"\environment",
];

/// Value-name allowlist for persistence-denied keys. The key itself is a
/// persistence/dll-injection surface (so unknown value-names stay DENIED),
/// but a short, explicit list of benign env-var names is allowed through into
/// the CoW overlay so legitimate installers that write e.g. `HERMES_*` or
/// `PATH` don't break.
///
/// This is the PERSISTENCE-DENY exception: anything NOT in this list that
/// targets a deny-suffix key stays hard-DENIED. The dangerous names — the
/// actual logon/DLL-search-order vectors — are deliberately absent.
///
/// Naming convention:
///   - exact match (case-insensitive): `path`, `hermes_git_bash_path`
///   - `vendor_*` prefix: matches `hermes_*` (any value starting with the prefix)
#[allow(dead_code)]
const ENV_VALUE_NAME_ALLOWLIST: &[&str] = &[
    // PATH-like env vars that installers legitimately extend.
    "path",
    "pathext",
    // Toolchain homes / version env-vars written by installers. These are pure
    // data values read back by the toolchain itself — they are not consulted by
    // winlogon / the DLL loader, so they confer no persistence.
    "hermes_*",        // Hermes Agent installer (HERMES_HOME, HERMES_GIT_BASH_PATH, ...)
    "npm_config_*",    // npm global config
    "cargo_home",
    "rustup_home",
    "python*",
    "pip_*",
    "uv_*",
    "node_path",
    "node_options",
];

/// Return `true` if `fragment` occurs in `key_lower` aligned to path-segment
/// boundaries: the fragment starts with `\` (left-anchored to a segment edge)
/// and the character immediately after the match is either end-of-string or
/// `\` (right-anchored). This blocks mid-segment false positives — e.g. the
/// fragment `\run` must NOT match `...\runtime\...` or `...\brundlefly\...`,
/// only `...\run` (root) or `...\run\...` (subkey).
///
/// Note: a segment-aligned occurrence is denied wherever it appears in the
/// key, regardless of hive prefix — a sandboxed process must never write a
/// persistence key anywhere, even nested under an attacker-crafted parent.
fn segment_contains(key_lower: &str, fragment: &str) -> bool {
    let bytes = key_lower.as_bytes();
    let mut start = 0;
    while let Some(pos) = key_lower[start..].find(fragment) {
        let abs = start + pos;
        let after = abs + fragment.len();
        let right_ok = after == key_lower.len() || bytes[after] == b'\\';
        if right_ok {
            return true;
        }
        // Advance past this occurrence and keep scanning for a later,
        // properly-anchored match.
        start = abs + 1;
        if start >= key_lower.len() {
            break;
        }
    }
    false
}

/// Return `true` if `key_path` is a denied registry persistence vector.
/// Pure function — extracted from the RegDecide handler for unit testing.
/// Matching is case-insensitive (internal ASCII lowercase) and segment-anchored
/// (see `segment_contains`) so unrelated keys that merely contain a denied
/// fragment mid-segment are not over-matched.
fn is_persistence_denied(key_path: &str) -> bool {
    let lower = key_path.to_ascii_lowercase();
    PERSISTENCE_DENY_SUFFIXES
        .iter()
        .any(|s| segment_contains(&lower, s))
}

/// True if `value_name` matches the `ENV_VALUE_NAME_ALLOWLIST`. Matches are
/// case-insensitive. An entry ending in `_*` is a prefix match; otherwise an
/// exact match.
fn is_env_value_allowed(value_name: Option<&str>) -> bool {
    let Some(name) = value_name else { return false; };
    let lower = name.to_ascii_lowercase();
    ENV_VALUE_NAME_ALLOWLIST.iter().any(|pat| {
        if let Some(prefix) = pat.strip_suffix("*") {
            lower.starts_with(prefix)
        } else {
            lower == *pat
        }
    })
}

/// Audit 2026-09-19 Critical #2: record a rejected `Req::RecordOverlay` as a
/// violation — bump the launcher counters and persist an immediate JSONL
/// violation event. The guest-supplied value is included verbatim; this is an
/// escape attempt, not a mistake report.
fn log_record_overlay_violation(
    stats: &Stats,
    hot_stats: &HotStats,
    client_pid: u32,
    orig: &str,
    overlay: &str,
) {
    stats.violations.fetch_add(1, Ordering::Relaxed);
    hot_stats
        .totals
        .violations
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    jsonl_log::log_immediate(jsonl_log::Event::violation(
        client_pid,
        "RecordOverlayEscape",
        &format!("orig={orig} overlay={overlay}"),
    ));
}

/// Handle one `Req::RecordOverlay` (audit 2026-09-19 Critical #2). The wire
/// keeps carrying `overlay` (the hook legitimately sends the launcher-shaped
/// mirror), but the launcher no longer trusts it: the request is accepted only
/// when `overlay` equals `mirror(orig)` inside the published overlay roots or
/// the mock-dirs mirror (see `Policy::validate_record_overlay`). Rejections
/// are counted, logged as violations, and surfaced to the guest via `Resp::Err`
/// instead of being swallowed; DB errors are no longer swallowed either.
fn handle_record_overlay(
    policy: &Policy,
    stats: &Stats,
    hot_stats: &HotStats,
    client_pid: u32,
    orig: &str,
    overlay: &str,
) -> Resp {
    if policy.validate_record_overlay(orig, overlay) {
        match policy.record_overlay(orig, overlay) {
            Ok(()) => Resp::Ok,
            Err(e) => Resp::Err(format!("record_overlay: {e}")),
        }
    } else {
        log_record_overlay_violation(stats, hot_stats, client_pid, orig, overlay);
        Resp::Err(
            "record_overlay rejected: overlay must be mirror(orig) inside the overlay roots"
                .to_string(),
        )
    }
}

// --- NetDecide: userspace network policy (audit Medium, WFP finding) ------

/// Pure decision core for "Req::NetDecide" against the policy's net_rules.
///
/// Semantics (the contract "winrsbox netrule add --help" documents):
/// - a rule matches when its host pattern matches the host string the hook
///   reports (exact, *, *.suffix, or a v4 CIDR like 10.0.0.0/8) AND its
///   optional port matches;
/// - any matching deny rule wins over any matching allow rule (fail-closed
///   on conflict);
/// - log rules never affect the decision (observability only);
/// - no matching rule -- including no rules at all -- allows, so the default
///   policy stays open; deny-by-default is opt-in via a --host='*' deny rule.
///
/// Returns (allow, matched rule id). Hostname patterns never match an IP
/// literal unless identical: the hook reports numeric addresses (DNS is not
/// hooked), so a rule for *.github.com does NOT govern connects to GitHub's
/// IPs -- pin IPs/CIDRs for range-level control.
fn net_decide(rules: &[policy::net::NetRule], host: &str, port: u16) -> (bool, Option<String>) {
    let mut deny_rule: Option<&str> = None;
    let mut allow_rule: Option<&str> = None;
    for r in rules {
        if r.port.is_some() && r.port != Some(port) {
            continue;
        }
        if !net_host_matches(&r.host_pattern, host) {
            continue;
        }
        match r.mode {
            policy::net::NetMode::Deny => {
                if deny_rule.is_none() {
                    deny_rule = Some(&r.id);
                }
            }
            policy::net::NetMode::Allow => {
                if allow_rule.is_none() {
                    allow_rule = Some(&r.id);
                }
            }
            policy::net::NetMode::Log => {}
        }
    }
    match deny_rule {
        Some(id) => (false, Some(id.to_string())),
        None => (true, allow_rule.map(str::to_string)),
    }
}

/// Host-pattern match: exact/*/ *.suffix via policy::net::match_host, plus
/// v4 CIDR containment when the pattern is a.b.c.d/len and the host is a
/// dotted quad (the hook reports numeric addresses).
fn net_host_matches(pattern: &str, host: &str) -> bool {
    if policy::net::match_host(pattern, host) {
        return true;
    }
    match (policy::net::parse_cidr(pattern), policy::net::parse_ipv4(host)) {
        (Some((net, mask)), Some(ip)) => policy::net::ip_in_cidr(ip, net, mask),
        _ => false,
    }
}

/// NetDecide handler plumbing: read the net_rules table from the policy DB
/// and decide. Fail-closed on DB error: the hook already denies when the IPC
/// round-trip dies, and the launcher denies when it cannot read its own
/// policy, so a broken rules store can never silently reopen the network.
fn handle_net_decide(p: &Policy, host: &str, port: u16) -> (bool, Option<String>) {
    match policy::db::net_rule_list(&p.db()) {
        Ok(rules) => net_decide(&rules, host, port),
        Err(e) => {
            eprintln!("[net] net_rules read failed: {e} -- denying {host}:{port} (fail-closed)");
            (false, None)
        }
    }
}
// ──────────────────────────────────────────────────────────────────────────────
// violations.log serialization
//
// Every record appended to violations.log is produced by serde_json here.
// serde_json escapes quotes, backslashes and every control character
// (including newlines), so a guest-controlled string — exe path, escape
// detail, caller module — can never terminate its record early or forge
// additional ones: one Value serializes to exactly one log line. The
// previous hand-rolled format! + ad-hoc backslash/quote replacement left
// newlines unescaped and was forgeable (audit 2026-09-19).

/// Serialize one violation record to a single JSON line and append it to
/// violations.log. Best-effort, mirroring the previous behavior: a write
/// failure is not fatal to the sandboxed process.
pub(crate) fn append_violation_record(violations_log: &Path, record: serde_json::Value) {
    use std::io::Write;
    let mut line = match serde_json::to_string(&record) {
        Ok(l) => l,
        Err(_) => return,
    };
    line.push('\n');
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(violations_log)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

fn injection_violation_record(
    pid: u32,
    exe: &str,
    kind: ipc::InjectKind,
    target_pid: u32,
    start_address: u64,
    caller_pc: u64,
    caller_module: Option<&str>,
    stack_top: &[u64],
) -> serde_json::Value {
    serde_json::json!({
        "pid": pid,
        "exe": exe,
        "kind": kind.to_string(),
        "target_pid": target_pid,
        "start_addr": format!("0x{start_address:x}"),
        "caller_pc": format!("0x{caller_pc:x}"),
        "caller_module": caller_module,
        "stack": stack_top.iter().map(|f| format!("0x{f:x}")).collect::<Vec<_>>(),
    })
}

fn memory_violation_record(
    pid: u32,
    exe: &str,
    kind: ipc::AllocKind,
    requested_protect: u32,
    region_size: u64,
    target_address: u64,
    caller_pc: u64,
    caller_module: Option<&str>,
    stack_top: &[u64],
) -> serde_json::Value {
    serde_json::json!({
        "pid": pid,
        "exe": exe,
        "kind": kind.to_string(),
        "protect": format!("0x{requested_protect:x}"),
        "size": region_size,
        "addr": format!("0x{target_address:x}"),
        "caller_pc": format!("0x{caller_pc:x}"),
        "caller_module": caller_module,
        "stack": stack_top.iter().map(|f| format!("0x{f:x}")).collect::<Vec<_>>(),
    })
}

fn escape_violation_record(
    pid: u32,
    exe: &str,
    vector: &str,
    detail: &str,
    caller_pc: u64,
    caller_module: Option<&str>,
    stack_top: &[u64],
) -> serde_json::Value {
    serde_json::json!({
        "pid": pid,
        "exe": exe,
        "kind": "Escape",
        "vector": vector,
        "detail": detail,
        "action": "terminate",
        "caller_pc": format!("0x{caller_pc:x}"),
        "caller_module": caller_module,
        "stack": stack_top.iter().map(|f| format!("0x{f:x}")).collect::<Vec<_>>(),
    })
}


#[allow(clippy::too_many_arguments)]
fn handle_connection(
    handle: HANDLE,
    client_pid: u32,
    policy: &Policy,
    reg_policy: &policy::RegistryPolicy,
    stats: &Stats,
    child_pids: &crossbeam_queue::SegQueue<u32>,
    violations_log: &Path,
    hot_stats: &HotStats,
    flusher: &ThrottledFlusher,
    byte_budget: &ByteBudget,
) {
    use std::os::windows::io::{FromRawHandle, RawHandle};

    // Wrap the pipe HANDLE in a std::fs::File for buffered I/O.
    // We must NOT let the File's Drop close the handle — the caller (spawn_blocking)
    // closes it via CloseHandle after DisconnectNamedPipe. Therefore we call
    // std::mem::forget(file) at the end of this function.
    //
    // SAFETY: handle.0 is a valid named-pipe HANDLE for this connection; it is open
    //         for both read and write; it remains valid for the duration of this call.
    let raw: RawHandle = handle.0 as *mut _;
    let mut file = unsafe { std::fs::File::from_raw_handle(raw) };

    // Defense-in-depth: open a handle to the client process so we can
    // check liveness before each blocking read_msg. If the client died
    // between reads (pipe not yet broken by the kernel), we break early
    // instead of holding the semaphore permit indefinitely.
    // PROCESS_QUERY_LIMITED_INFORMATION (0x1000) is the minimum right
    // for GetExitCodeProcess.
    let proc_handle = unsafe {
        OpenProcess(PROCESS_ACCESS_RIGHTS(0x1000), false, client_pid).ok()
    };
    const STILL_ACTIVE: u32 = 259;

    // Track the PID associated with this pipe connection
    let mut conn_pid: Option<u32> = None;

    loop {
        if let Some(ref ph) = proc_handle {
            let mut exit_code = 0u32;
            // SAFETY: ph is a valid process handle obtained above.
            let ok = unsafe { GetExitCodeProcess(*ph, &mut exit_code).is_ok() };
            if ok && exit_code != STILL_ACTIVE {
                break;
            }
        }

        // Audit: the guest declares the body length in the 4-byte prefix,
        // and read_msg allocates exactly that much. Read the prefix here,
        // reserve the declared size against the process-wide in-flight
        // byte budget BEFORE the body is read (so declared-size x
        // concurrency is capped at MAX_INFLIGHT_MSG_BYTES), then hand the
        // prefix back to read_msg via PrefixedReader so parsing stays in
        // the ipc crate.
        let mut len_buf = [0u8; 4];
        if file.read_exact(&mut len_buf).is_err() {
            break;
        }
        let declared = u32::from_le_bytes(len_buf) as usize;
        // read_msg rejects oversized (and empty) bodies before allocating,
        // so they never need budget.
        let _budget = if declared > 0 && declared <= ipc::MAX_MSG_LEN {
            match byte_budget.reserve_timeout(declared, BYTE_BUDGET_WAIT) {
                Some(r) => Some(r),
                None => {
                    eprintln!(
                        "[pipe] pid={client_pid}: in-flight byte budget exhausted ({declared}B declared) - dropping connection"
                    );
                    break;
                }
            }
        } else {
            None
        };
        let mut prefixed = PrefixedReader { prefix: len_buf, pos: 0, inner: &mut file };
        let req: Req = match read_msg(&mut prefixed) {
            Ok(r) => r,
            Err(_) => break,
        };

        let resp = match req {
            Req::Hello { pid, exe_path } => {
                // SECURITY (audit E1): the `pid` in the Hello is attacker-controlled
                // (the hook runs inside the untrusted target). Trusting it let a
                // process claim another — or an unknown — PID, so depth-based
                // when-filters were evaluated against the wrong context (an unknown
                // PID resolves to depth=None, which policy treats as max-permissive).
                // Bind this connection to the kernel-vouched client_pid from
                // GetNamedPipeClientProcessId; the claimed pid is only logged.
                if pid != client_pid {
                    eprintln!(
                        "[pipe] WARN: Hello pid={pid} != kernel client_pid={client_pid} — \
                         using client_pid (possible spoof)",
                    );
                    stats.violations.fetch_add(1, Ordering::Relaxed);
                    hot_stats.totals.violations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    jsonl_log::log_immediate(jsonl_log::Event::violation(
                        client_pid,
                        "HelloPidSpoof",
                        &format!("claimed_pid={pid}"),
                    ));
                }
                if jsonl_log::console_verbose() {
                    println!("[sandbox] hello from pid={client_pid} exe={exe_path}");
                }
                hot_stats.totals.hellos.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                jsonl_log::log(jsonl_log::Event::hello(client_pid, &exe_path));
                let exe_lower = exe_path.to_ascii_lowercase();
                // Fingerprint the connecting process from the kernel. The client
                // is alive on this connection, so this normally succeeds; 0
                // fail-closes later connections (see tracked_entry_still_owned).
                let live_ct = query_process_create_time(client_pid).unwrap_or(0);
                if live_ct == 0 {
                    eprintln!("[pipe] hello pid={client_pid}: creation-time probe failed — \
                               entry stored with unknown fingerprint");
                }
                let map = crate::global_proc_info().pin();
                if let Some(existing) = map.get(&client_pid) {
                    // Already have entry (e.g., root target or SpawnedChild) — keep depth, update exe
                    let updated = crate::ProcInfo {
                        depth: existing.depth,
                        exe_lower: Arc::from(exe_lower.as_str()),
                        create_time: if live_ct != 0 { live_ct } else { existing.create_time },
                    };
                    map.insert(client_pid, updated);
                } else {
                    // New process — insert with depth 0 (updated by SpawnedChild if child)
                    map.insert(client_pid, crate::ProcInfo {
                        depth: 0,
                        exe_lower: Arc::from(exe_lower.as_str()),
                        create_time: live_ct,
                    });
                }
                conn_pid = Some(client_pid);
                Resp::Ok
            }
            Req::SpawnedChild { parent_pid, child_pid, child_exe } => {
                // SECURITY (audit E1 cont.): a SpawnedChild report arrives on the
                // PARENT's own authenticated connection, so the real parent is
                // this connection's kernel-vouched client_pid — not the
                // self-reported parent_pid (which a hostile hook could set to any
                // PID to make the child inherit a shallower, less-restricted
                // depth). Inherit depth from client_pid; the claimed value is
                // only logged. (child_pid is still parent-reported; it is
                // reconciled when the child itself connects with its own Hello.)
                if parent_pid != client_pid {
                    eprintln!(
                        "[pipe] WARN: SpawnedChild parent_pid={parent_pid} != client_pid={client_pid} \
                         — inheriting depth from client_pid (possible spoof)",
                    );
                    stats.violations.fetch_add(1, Ordering::Relaxed);
                    hot_stats.totals.violations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    jsonl_log::log_immediate(jsonl_log::Event::violation(
                        client_pid,
                        "SpawnedChildParentSpoof",
                        &format!("claimed_parent={parent_pid} child={child_pid}"),
                    ));
                }
                if jsonl_log::console_verbose() {
                    println!("[sandbox] child spawned: parent={client_pid} child={child_pid} exe={child_exe}");
                }
                hot_stats.totals.children.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                jsonl_log::log(jsonl_log::Event::child(client_pid, child_pid, &child_exe));
                child_pids.push(child_pid);
                // Fingerprint the freshly spawned child from the kernel so the
                // gate can pin its identity. If the probe fails (child died
                // already) the entry is stored with 0 and fail-closes; the
                // child's own Hello would refresh it if it ever connects.
                let child_ct = query_process_create_time(child_pid).unwrap_or(0);
                if child_ct == 0 {
                    eprintln!("[pipe] SpawnedChild pid={child_pid}: creation-time probe failed — \
                               entry stored with unknown fingerprint");
                }
                let map = crate::global_proc_info().pin();
                let parent_depth = map.get(&client_pid).map(|p| p.depth).unwrap_or(0);
                let exe_lower = child_exe.to_ascii_lowercase();
                map.insert(child_pid, crate::ProcInfo {
                    depth: parent_depth + 1,
                    exe_lower: Arc::from(exe_lower.as_str()),
                    create_time: child_ct,
                });
                Resp::Ok
            }
            Req::Decide { dos_path, write } => {
                stats.decide.fetch_add(1, Ordering::Relaxed);
                // Look up depth/exe for this connection's PID
                let (depth, exe_lower) = if let Some(pid) = conn_pid {
                    let map = crate::global_proc_info().pin();
                    map.get(&pid)
                        .map(|info| (Some(info.depth), Some(Arc::clone(&info.exe_lower))))
                        .unwrap_or((None, None))
                } else {
                    (None, None)
                };
                let d = policy.decide_with_context(
                    &dos_path,
                    write,
                    depth,
                    exe_lower.as_deref(),
                );
                hot_stats.totals.fs_decides.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let denied = matches!(d.mode, policy::Mode::Deny);
                match d.mode {
                    policy::Mode::Deny => {
                        stats.deny.fetch_add(1, Ordering::Relaxed);
                        hot_stats.totals.fs_denies.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        jsonl_log::log(jsonl_log::Event::deny(&dos_path, write));
                    }
                    policy::Mode::Cow => {
                        stats.cow.fetch_add(1, Ordering::Relaxed);
                        hot_stats.totals.fs_cows.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    policy::Mode::Mock => {
                        stats.mock_.fetch_add(1, Ordering::Relaxed);
                        hot_stats.totals.fs_mocks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    policy::Mode::Hidden => {
                        // Whiteout hit — path is hidden from the sandbox view.
                        // No dedicated stat counter; trace it for diagnostics.
                        hot_stats.totals.fs_decides.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    policy::Mode::Passthrough => {}
                }
                hot_stats.record_fs(&dos_path, write, denied);
                flusher.maybe_flush();
                Resp::Decision(d)
            }
            Req::RecordOverlay { orig, overlay } => {
                handle_record_overlay(policy, stats, hot_stats, client_pid, &orig, &overlay)
            }
            Req::RecordOverlayCase { path, original_basename } => {
                policy.record_overlay_case(&path, &original_basename);
                Resp::Ok
            }
            Req::ClearOverlay { path } => {
                match policy.clear_overlay(&path) {
                    Ok(()) => Resp::Ok,
                    Err(e) => Resp::Err(format!("clear_overlay: {e}")),
                }
            }
            Req::RecordWhiteout { path } => {
                match policy.record_whiteout(&path) {
                    Ok(()) => Resp::Ok,
                    Err(e) => Resp::Err(format!("record_whiteout: {e}")),
                }
            }
            Req::ClearWhiteout { path } => {
                if let Err(e) = policy.clear_whiteout(&path) {
                    Resp::Err(format!("clear_whiteout: {e}"))
                } else {
                    Resp::Ok
                }
            }
            Req::WhiteoutsUnder { dir } => {
                let names = policy.whiteouts_under(&dir);
                Resp::Whiteouts(names)
            }
            Req::OverlayChildrenWithCase { dir } => {
                let pairs = policy.overlay_children_with_case(&dir);
                Resp::OverlayChildrenWithCase(pairs)
            }
            Req::OverlayChildren { dir } => {
                let entries = policy.overlay_children(&dir);
                Resp::OverlayChildren(entries)
            }
            Req::Log { pid, level, msg } => {
                let level_str = match level {
                    LogLevel::Trace => "TRACE",
                    LogLevel::Info => "INFO ",
                    LogLevel::Warn => "WARN ",
                    LogLevel::Error => "ERROR",
                };
                // Always surface real errors; routine INFO/WARN/TRACE hook
                // diagnostics only hit the console under --trace (they always
                // persist to the JSONL below regardless).
                if matches!(level, LogLevel::Error) || jsonl_log::console_verbose() {
                    println!("[hook/{pid}] {level_str} {msg}");
                }
                // Persist to JSONL. INFO/WARN/ERROR are rare and load-bearing
                // for forensics (spawn_attempt, fs_decide on writes, denials):
                // flush them to disk immediately so a hung or idle sandbox
                // doesn't leave critical events stranded in the 5 s buffer.
                // TRACE stays on the throttled path — it can be high volume.
                let event = jsonl_log::Event::hook_log(pid, level_str.trim(), &msg);
                match level {
                    LogLevel::Trace => jsonl_log::log(event),
                    _ => jsonl_log::log_immediate(event),
                }
                Resp::Ok
            }
            Req::RegisterChild { pid } => {
                if jsonl_log::console_verbose() {
                    println!("[sandbox] child registered: pid={pid}");
                }
                child_pids.push(pid);
                Resp::Ok
            }
            Req::PreLaunchViolation { launcher_pid: _, target_exe: _, hits: _ } => {
                // Launcher emits this directly to violations.log; this variant
                // exists only for IPC schema completeness. If a hook DLL ever
                // sends one (it shouldn't), just log and ack.
                stats.violations.fetch_add(1, Ordering::Relaxed);
                hot_stats.totals.violations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Resp::Ok
            }
            Req::InjectionViolation {
                pid, exe, kind, target_pid, start_address,
                caller_pc, caller_module, stack_top,
            } => {
                stats.violations.fetch_add(1, Ordering::Relaxed);
                hot_stats.totals.violations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let caller_str = caller_module.as_deref().unwrap_or("<anonymous>");
                eprintln!(
                    "[VIOLATION] pid={pid} kind={kind} target_pid={target_pid} caller={caller_str} pc=0x{caller_pc:x}",
                );
                jsonl_log::log_immediate(jsonl_log::Event::violation(
                    pid, &format!("{kind}"),
                    &format!("target_pid={target_pid} start=0x{start_address:x} pc=0x{caller_pc:x}"),
                ));
                append_violation_record(
                    violations_log,
                    injection_violation_record(
                        pid,
                        &exe,
                        kind,
                        target_pid,
                        start_address,
                        caller_pc,
                        caller_module.as_deref(),
                        &stack_top,
                    ),
                );
                Resp::Ok
            }
            Req::MemoryViolation {
                pid, exe, kind, requested_protect, region_size,
                target_address, caller_pc, caller_module, stack_top,
            } => {
                stats.violations.fetch_add(1, Ordering::Relaxed);
                hot_stats.totals.violations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let caller_str = caller_module.as_deref().unwrap_or("<anonymous>");
                eprintln!(
                    "[VIOLATION] pid={pid} kind={kind} protect=0x{requested_protect:x} caller={caller_str} pc=0x{caller_pc:x}",
                );
                jsonl_log::log_immediate(jsonl_log::Event::violation(
                    pid, &format!("{kind}"),
                    &format!("protect=0x{requested_protect:x} addr=0x{target_address:x} pc=0x{caller_pc:x}"),
                ));
                append_violation_record(
                    violations_log,
                    memory_violation_record(
                        pid,
                        &exe,
                        kind,
                        requested_protect,
                        region_size,
                        target_address,
                        caller_pc,
                        caller_module.as_deref(),
                        &stack_top,
                    ),
                );
                Resp::Ok
            }
            Req::EscapeViolation {
                pid, exe, vector, detail, caller_pc, caller_module, stack_top,
            } => {
                stats.violations.fetch_add(1, Ordering::Relaxed);
                hot_stats.totals.violations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let caller_str = caller_module.as_deref().unwrap_or("<anonymous>");
                eprintln!(
                    "[VIOLATION] pid={pid} kind=Escape vector={vector} detail={detail} caller={caller_str} pc=0x{caller_pc:x} — process terminated",
                );
                jsonl_log::log_immediate(jsonl_log::Event::violation(
                    pid, "Escape",
                    &format!("vector={vector} detail={detail} pc=0x{caller_pc:x} action=terminate"),
                ));
                append_violation_record(
                    violations_log,
                    escape_violation_record(
                        pid,
                        &exe,
                        &vector,
                        &detail,
                        caller_pc,
                        caller_module.as_deref(),
                        &stack_top,
                    ),
                );
                Resp::Ok
            }
            Req::RegDecide { key_path, value_name, write } => {
                // Layer 1 (security, hardcoded): persistence/DLL-injection
                // deny-suffixes always deny on write, EXCEPT a benign value-name
                // in ENV_VALUE_NAME_ALLOWLIST for HKCU\Environment. This layer
                // is intentionally NOT in the DB-backed RegistryPolicy — it is a
                // non-bypassable safety floor that survives any user rule config.
                let key_lower = key_path.to_ascii_lowercase();
                let is_persistence = is_persistence_denied(&key_lower);
                let env_allowed = is_persistence
                    && key_lower.ends_with(r"\environment")
                    && is_env_value_allowed(value_name.as_deref());

                let (mode, value_json) = if write && is_persistence && !env_allowed {
                    eprintln!("[reg] DENY {key_path} value={value_name:?}");
                    (policy::Mode::Deny, None)
                } else {
                    // Layer 2 (DB-backed + overlay merge): RegistryPolicy consults
                    // REG_RULES / REG_MOCKS and returns the recorded overlay value
                    // (if any) for the read-side merge.
                    let d = reg_policy.decide(&key_path, value_name.as_deref(), write);
                    let vj = d.overlay_value.or(d.mock_value).map(|v| {
                        serde_json::to_vec(&v.to_json_value()).unwrap_or_default()
                    });
                    (d.mode, vj)
                };

                let denied = matches!(mode, policy::Mode::Deny);
                hot_stats.totals.reg_decides.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if denied { hot_stats.totals.reg_denies.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
                hot_stats.record_reg(&key_path, write, denied);
                if denied {
                    jsonl_log::log(jsonl_log::Event::reg_decide(&key_path, write, &format!("{mode:?}")));
                }
                flusher.maybe_flush();
                Resp::RegDecision { mode, value_json }
            }
            Req::RegWrite { key_path, value_name, value } => {
                // Record the value into the CoW overlay (read-back merge happens
                // via RegDecision's overlay_value). The hook builds the RegValue
                // from the raw NtSetValueKey bytes; bincode carries it here.
                let resp = match reg_policy.write_to_overlay(&key_path, &value_name, value) {
                    Ok(()) => {
                        if is_persistence_denied(&key_path.to_ascii_lowercase()) {
                            eprintln!("[reg] overlay write (persistence-allowed): {key_path}\\{value_name}");
                        }
                        Resp::Ok
                    }
                    Err(e) => {
                        eprintln!("[reg] overlay write FAILED {key_path}\\{value_name}: {e}");
                        Resp::Err(e)
                    }
                };
                resp
            }
            Req::RegDeleteValue { key_path, value_name } => {
                let resp = match reg_policy.delete_value_in_overlay(&key_path, &value_name) {
                    Ok(()) => Resp::Ok,
                    Err(e) => Resp::Err(e),
                };
                resp
            }
            Req::RegDeleteKey { key_path } => {
                let resp = match reg_policy.delete_key_in_overlay(&key_path) {
                    Ok(()) => Resp::Ok,
                    Err(e) => Resp::Err(e),
                };
                resp
            }
            Req::NetDecide { host, port } => {
                // Userspace network policy: decide against the policy's
                // net_rules (see net_decide for the match semantics). The
                // hook blocks denied connects with WSAEACCES and fails
                // closed if this pipe dies, so this answer is real
                // enforcement, not telemetry.
                //
                // The kernel-level WFP filters installed at launcher startup
                // (winrsbox::wfp) are defense-in-depth ON TOP of this, and
                // only exist when the launcher's WFP session can install
                // filters -- without them this userspace decision is the
                // only network enforcement the sandbox has.
                let (allow, rule_id) = handle_net_decide(policy, &host, port);
                hot_stats.totals.net_decides.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let host_port = format!("{host}:{port}");
                hot_stats.record_net(&host_port, !allow);
                if let Some(id) = &rule_id {
                    if jsonl_log::console_verbose() {
                        println!(
                            "[net] {host_port} -> {} (rule {id})",
                            if allow { "allow" } else { "DENY" }
                        );
                    }
                }
                jsonl_log::log(jsonl_log::Event::net_decide(&host_port, allow));
                flusher.maybe_flush();
                Resp::NetDecision { allow }
            }
            Req::MemDecide { target_pid, op } => {
                println!("[mem] decide: pid={target_pid} op={op}");
                Resp::MemDecision { allow: false }
            }
        };

        if write_msg(&mut file, &resp).is_err() {
            break;
        }
    }

    if let Some(ph) = proc_handle {
        // SAFETY: ph was opened by us above; close it now that the loop is done.
        unsafe { CloseHandle(ph).ok() };
    }

    // Do NOT let `file` run its Drop (which would call CloseHandle on the underlying HANDLE).
    // The caller in spawn_blocking closes the handle via DisconnectNamedPipe + CloseHandle.
    // Double-closing would be UB / use-after-free on the handle.
    std::mem::forget(file);
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── audit Critical #2: RecordOverlay rejection is counted + surfaced ───

    #[test]
    fn record_overlay_dispatch_rejects_escape_and_accepts_mirror() {
        let dir = tempfile::tempdir().unwrap();
        let p = policy::Policy::open_or_create(
            &dir.path().join("policy.redb"),
            dir.path().join("sb"),
            dir.path().join("md"),
            dir.path().join("proj"),
        )
        .unwrap();
        let stats = Stats::default();
        let hot = HotStats::default();
        let orig = r"d:\proj\f.txt";

        // Escape attempt: a real user-profile persistence location.
        let resp = handle_record_overlay(
            &p,
            &stats,
            &hot,
            4242,
            orig,
            r"c:\users\victim\appdata\roaming\microsoft\windows\start menu\programs\startup\pwn.bat",
        );
        assert!(matches!(resp, Resp::Err(_)), "escape attempt must be rejected, got {resp:?}");
        assert_eq!(
            stats.violations.load(Ordering::Relaxed),
            1,
            "rejection must be counted as a violation"
        );

        // Legitimate record: mirror(orig) → Ok, no violation counted.
        let mirror = policy::path::mirror_into_overlay_layout(orig, p.overlay_layout());
        let resp = handle_record_overlay(&p, &stats, &hot, 4242, orig, &mirror.to_string_lossy());
        assert!(matches!(resp, Resp::Ok), "mirror(orig) must be accepted, got {resp:?}");
        assert_eq!(stats.violations.load(Ordering::Relaxed), 1);

        // The accepted record drives later reads into the overlay.
        let d = p.decide(orig, false);
        assert_eq!(d.mode, policy::Mode::Cow);
        assert_eq!(d.overlay, Some(mirror));
    }

    // ─── original 6 patterns (kept to lock in baseline coverage) ─────────────

    #[test]
    fn persistence_appinit_dlls_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows"
        ));
    }

    #[test]
    fn persistence_appinit_wow6432_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
        ));
    }

    #[test]
    fn persistence_ifeo_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe"
        ));
    }

    #[test]
    fn persistence_silent_process_exit_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\evil.exe"
        ));
    }

    #[test]
    fn persistence_appcert_dlls_denied() {
        assert!(is_persistence_denied(
            r"HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls"
        ));
    }

    #[test]
    fn persistence_services_denied() {
        assert!(is_persistence_denied(
            r"HKLM\System\CurrentControlSet\Services\EvilSvc"
        ));
    }

    // ─── H-S4 new patterns: one test per entry ──────────────────────────────

    #[test]
    fn persistence_run_key_denied() {
        assert!(is_persistence_denied(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MyEvil"
        ));
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
        ));
    }

    #[test]
    fn persistence_runonce_key_denied() {
        assert!(is_persistence_denied(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\Stage2"
        ));
    }

    #[test]
    fn persistence_runonceex_key_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001"
        ));
    }

    #[test]
    fn persistence_startup_approved_run_denied() {
        assert!(is_persistence_denied(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
        ));
    }

    #[test]
    fn persistence_winlogon_userinit_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"
        ));
    }

    #[test]
    fn persistence_winlogon_shell_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"
        ));
    }

    #[test]
    fn persistence_winlogon_notify_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\evilpkg"
        ));
    }

    #[test]
    fn persistence_drivers32_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32"
        ));
    }

    #[test]
    fn persistence_app_paths_denied() {
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\notepad.exe"
        ));
    }

    #[test]
    fn persistence_classes_clsid_denied() {
        assert!(is_persistence_denied(
            r"HKCU\Software\Classes\CLSID\{0000000A-0000-0000-C000-000000000046}\InprocServer32"
        ));
        assert!(is_persistence_denied(
            r"HKLM\Software\Classes\CLSID\{deadbeef-1234-5678-9abc-def012345678}\LocalServer32"
        ));
    }

    #[test]
    fn persistence_shell_open_command_denied() {
        // File-association hijack — substring catches every extension and hive.
        assert!(is_persistence_denied(
            r"HKCU\Software\Classes\txtfile\shell\open\command"
        ));
        assert!(is_persistence_denied(
            r"HKLM\Software\Classes\ms-settings\shell\open\command"
        ));
    }

    #[test]
    fn persistence_context_menu_handlers_denied() {
        assert!(is_persistence_denied(
            r"HKCU\Software\Classes\*\shellex\ContextMenuHandlers\Evil"
        ));
    }

    #[test]
    fn persistence_cmd_autorun_denied() {
        assert!(is_persistence_denied(
            r"HKCU\Software\Microsoft\Command Processor\AutoRun"
        ));
    }

    #[test]
    fn persistence_lsa_notification_packages_denied() {
        assert!(is_persistence_denied(
            r"HKLM\System\CurrentControlSet\Control\Lsa\Notification Packages"
        ));
    }

    #[test]
    fn persistence_lsa_authentication_packages_denied() {
        assert!(is_persistence_denied(
            r"HKLM\System\CurrentControlSet\Control\Lsa\Authentication Packages"
        ));
    }

    #[test]
    fn persistence_lsa_security_packages_denied() {
        assert!(is_persistence_denied(
            r"HKLM\System\CurrentControlSet\Control\Lsa\Security Packages"
        ));
    }

    #[test]
    fn persistence_office_trusted_locations_denied() {
        // Any Office version / app combo matches via `\security\trusted locations`.
        assert!(is_persistence_denied(
            r"HKCU\Software\Microsoft\Office\16.0\Word\Security\Trusted Locations\Location99"
        ));
        assert!(is_persistence_denied(
            r"HKCU\Software\Microsoft\Office\15.0\Excel\Security\Trusted Locations"
        ));
    }

    // ─── negative cases — make sure we did not over-block ───────────────────

    #[test]
    fn persistence_benign_software_key_allowed() {
        // Plain HKCU\Software\MyApp\Settings is *not* in the persistence list.
        // (The handler routes it to "silent_ok" — that branch is outside this
        // pure function; is_persistence_denied must answer false here.)
        assert!(!is_persistence_denied(r"HKCU\Software\MyApp\Settings"));
    }

    #[test]
    fn persistence_empty_path_allowed() {
        assert!(!is_persistence_denied(""));
    }

    #[test]
    fn non_software_write_is_not_passthrough() {
        // H3: writes outside \software\ must NOT fall to passthrough.
        // The RegDecide handler routes them to silent_ok (absorbed).
        // This test pins the invariant at the is_persistence_denied level:
        // non-persistence keys that are also outside \software\ must still
        // be handled (the handler's else-if-write branch catches them).
        assert!(!is_persistence_denied(r"HKCU\Console\FaceName"));
        assert!(!is_persistence_denied(r"HKCU\Keyboard Layout\Preload"));
    }

    // ─── Audit C1/C4: segment-anchored matching, boundaries pinned ──────────

    #[test]
    fn persistence_run_key_root_and_value_denied() {
        // C4: the Run key root itself (a value write AT Run) must be denied,
        // not just subkeys under it.
        assert!(is_persistence_denied(
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
        ));
        assert!(is_persistence_denied(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Evil"
        ));
    }

    #[test]
    fn persistence_services_root_and_subkey_denied() {
        // C4: hive root (no trailing component) AND subkey both denied.
        assert!(is_persistence_denied(r"HKLM\System\CurrentControlSet\Services"));
        assert!(is_persistence_denied(
            r"HKLM\System\CurrentControlSet\Services\EvilSvc"
        ));
    }

    #[test]
    fn persistence_classes_clsid_root_and_subkey_denied() {
        // De-trailing-slashed entry still matches both forms.
        assert!(is_persistence_denied(r"HKCU\Software\Classes\CLSID"));
        assert!(is_persistence_denied(
            r"HKCU\Software\Classes\CLSID\{0000000A-0000-0000-C000-000000000046}\InprocServer32"
        ));
    }

    #[test]
    fn persistence_does_not_overmatch_midsegment() {
        // C1: the critical negatives. A fragment must match only at segment
        // boundaries — never mid-segment. These would all FALSE-POSITIVE under
        // the old naive `.contains()` and must now be allowed.
        assert!(!is_persistence_denied(r"HKCU\Software\MyVendor\Runtime\Settings")); // "run" inside "runtime"
        assert!(!is_persistence_denied(r"HKCU\Software\MyVendor\ServicesManager\Cfg")); // "services" inside "servicesmanager"
        assert!(!is_persistence_denied(r"HKCU\Software\Brundlefly\Data")); // "run" mid-segment
        assert!(!is_persistence_denied(r"HKCU\Software\Classes\CLSIDExtra\X")); // "clsid" inside "clsidextra"
    }

    #[test]
    fn persistence_segment_aligned_anywhere_is_denied() {
        // A segment-aligned persistence path is denied wherever it appears,
        // even nested under an attacker-crafted parent — the sandbox must never
        // write it anywhere. This is intended (documented in segment_contains).
        assert!(is_persistence_denied(
            r"HKCU\Software\X\System\CurrentControlSet\Services\Fake"
        ));
        // ...but a NON-segment-aligned lookalike must NOT match.
        assert!(!is_persistence_denied(
            r"HKCU\Software\XSystem\CurrentControlSet\ServicesY\Fake"
        ));
    }

    #[test]
    fn segment_contains_boundary_semantics() {
        // Direct unit test of the matcher's anchoring.
        assert!(segment_contains(r"a\run", r"\run")); // end-of-string
        assert!(segment_contains(r"a\run\b", r"\run")); // followed by '\'
        assert!(!segment_contains(r"a\runtime", r"\run")); // followed by other char
        assert!(!segment_contains(r"arun", r"\run")); // no left boundary
        assert!(segment_contains(r"x\run\run", r"\run")); // second occurrence anchored
    }

    // ─── ENV_VALUE_NAME_ALLOWLIST (PERSISTENCE-DENY exception) ──────────────

    #[test]
    fn env_allowlist_exact_match_path() {
        assert!(is_env_value_allowed(Some("Path")));
        assert!(is_env_value_allowed(Some("PATH")));
        assert!(is_env_value_allowed(Some("PATHEXT")));
    }

    #[test]
    fn env_allowlist_vendor_prefix_hermes() {
        assert!(is_env_value_allowed(Some("HERMES_HOME")));
        assert!(is_env_value_allowed(Some("HERMES_GIT_BASH_PATH")));
        assert!(is_env_value_allowed(Some("hermes_anything")));
    }

    #[test]
    fn env_allowlist_python_prefix() {
        assert!(is_env_value_allowed(Some("PYTHONPATH")));
        assert!(is_env_value_allowed(Some("PYTHONHOME")));
    }

    #[test]
    fn env_allowlist_none_value_name_denied() {
        // No value name → can't prove benign → fail-closed (not allowed).
        assert!(!is_env_value_allowed(None));
    }

    #[test]
    fn env_allowlist_dangerous_name_denied() {
        // The actual logon-script persistence vector must NOT match the
        // allowlist — it stays hard-DENIED even under HKCU\Environment.
        assert!(!is_env_value_allowed(Some("UserInitMprLogonScript")));
        // Unknown / arbitrary attacker value-name → denied.
        assert!(!is_env_value_allowed(Some("evil_persistence")));
        assert!(!is_env_value_allowed(Some("TEMP")));
    }

    #[test]
    fn persistence_count_pinned() {
        // Pin the list length so a silently-dropped entry fails a test.
        assert_eq!(
            PERSISTENCE_DENY_SUFFIXES.len(),
            25,
            "PERSISTENCE_DENY_SUFFIXES length drifted — update tests + threat model"
        );
    }

    // ─── Audit M-A3: handler concurrency cap ────────────────────────────────

    #[test]
    fn handler_cap_is_reasonable() {
        // Cap should be high enough to handle a normal sandbox burst (one
        // process spawning a few children + their Hello / Decide messages)
        // but low enough to bound resource use and keep room in tokio's
        // 512-thread blocking pool for the accept-side ConnectNamedPipe
        // task and any other launcher subsystems.
        assert!(MAX_CONCURRENT_HANDLERS >= 32);
        assert!(MAX_CONCURRENT_HANDLERS <= 256);
    }

    /// Pin the accept pool size. Must clear the empirically-observed
    /// MSYS2 first-run burst (~8 concurrent helper spawns) with headroom,
    /// and stay well under the kernel-imposed max-instances cap (255)
    /// that `create_pipe_instance` passes to `CreateNamedPipeW`.
    #[test]
    fn accept_pool_size_in_sane_range() {
        assert!(
            PIPE_ACCEPT_POOL_SIZE >= 16,
            "PIPE_ACCEPT_POOL_SIZE={PIPE_ACCEPT_POOL_SIZE} cannot absorb MSYS2's 27-process burst",
        );
        assert!(
            PIPE_ACCEPT_POOL_SIZE <= 64,
            "PIPE_ACCEPT_POOL_SIZE={PIPE_ACCEPT_POOL_SIZE} too high — \
             each instance costs 128 KiB pipe buffers and a tokio task",
        );
    }

    /// `create_pipe_instance` is a thin FFI wrapper; its main contract is
    /// returning a usable handle as `isize` (Send across `.await`) and
    /// honouring `is_first` for the FIRST_PIPE_INSTANCE flag. We can't
    /// CreateNamedPipeW in a unit test without a unique pipe name, so this
    /// test verifies the happy path against a one-off name and immediately
    /// closes the returned handle.
    #[test]
    fn create_pipe_instance_returns_valid_handle() {
        use windows::Win32::Foundation::HANDLE;
        let name = format!(
            r"\\.\pipe\winrsbox-unit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        );
        let wide: Vec<u16> = OsStr::new(&name)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let sec = build_pipe_security().expect("pipe SD build");
        let ph = create_pipe_instance(&wide, &sec, true)
            .expect("first instance must create on a fresh pipe name");
        assert_ne!(ph, 0, "handle must be non-null");
        unsafe { CloseHandle(HANDLE(ph as *mut _)).ok() };
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handler_semaphore_caps_in_flight_acquisitions() {
        // Mirror the runtime invariant: only MAX_CONCURRENT_HANDLERS permits
        // can be held at once. The 129th acquire must not complete while
        // 128 are still alive.
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_HANDLERS));
        let mut permits = Vec::with_capacity(MAX_CONCURRENT_HANDLERS);
        for _ in 0..MAX_CONCURRENT_HANDLERS {
            permits.push(sem.clone().acquire_owned().await.unwrap());
        }
        // A 129th acquire must time out — semaphore is full.
        let timeout = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            sem.clone().acquire_owned(),
        )
        .await;
        assert!(
            timeout.is_err(),
            "extra acquire should block while all {MAX_CONCURRENT_HANDLERS} permits are held",
        );
        // Releasing one permit must let the next acquire succeed promptly.
        drop(permits.pop());
        let after = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            sem.clone().acquire_owned(),
        )
        .await
        .expect("acquire should succeed once a permit is freed");
        assert!(after.is_ok());
    }

    // ─── C3: pipe security descriptor & PID validation ──────────────────────

    /// `build_pipe_security` should succeed on any normal user token.
    #[test]
    fn c3_pipe_security_builds_for_current_user() {
        let sec = build_pipe_security().expect("SD construction failed");
        // The SECURITY_ATTRIBUTES should reference a non-null SD pointer.
        assert!(!sec.sa.lpSecurityDescriptor.is_null());
        // SDDL string lookup pointer equality holds — sd and sa point to same buf.
        assert_eq!(sec.sd.0, sec.sa.lpSecurityDescriptor);
    }

    #[test]
    fn persistence_per_user_classes_clsid_denied() {
        // H2: per-user COM hijack via HKU\<SID>_Classes\CLSID
        assert!(is_persistence_denied(
            r"hku\s-1-5-21-123456789-123456789-123456789-1001_classes\clsid\{deadbeef}\InprocServer32"
        ));
    }

    #[test]
    fn persistence_hkcu_environment_denied() {
        // M6: HKCU\Environment for logon persistence
        assert!(is_persistence_denied(r"hkcu\environment"));
        assert!(is_persistence_denied(
            r"hkcu\environment\UserInitMprLogonScript"
        ));
    }

    /// `is_owned_client_pid` accepts the root PID via the root fast-path only
    /// when the live creation-time probe matches the pinned fingerprint
    /// (chicken-and-egg between Hello and validation). An unknown/zero
    /// fingerprint fail-closes, so a recycled root PID is rejected.
    #[test]
    fn c3_owned_pid_matches_root_target() {
        let root = 12345u32;
        // Verified identity: live probe returns the pinned fingerprint → accept.
        assert!(is_owned_client_pid_impl(
            root,
            root,
            0x01D9_0000_0000_0001,
            &|pid| if pid == 12345 { Some(0x01D9_0000_0000_0001) } else { None },
            &|_| None,
        ));
        // Unknown pinned fingerprint (0) → fail-closed even for the root PID.
        assert!(!is_owned_client_pid_impl(
            root,
            root,
            0,
            &|pid| if pid == 12345 { Some(0x01D9_0000_0000_0001) } else { None },
            &|_| None,
        ));
        // Mismatched creation time (recycled root PID) → rejected.
        assert!(!is_owned_client_pid_impl(
            root,
            root,
            0x01D9_0000_0000_0001,
            &|pid| if pid == 12345 { Some(42) } else { None },
            &|_| None,
        ));
    }

    /// `is_owned_client_pid` rejects PID 0 and any unknown PID when no map entry.
    #[test]
    fn c3_owned_pid_rejects_zero_and_unknown() {
        assert!(!is_owned_client_pid(0, 12345));
        // 99999 is neither root nor in the map.
        assert!(!is_owned_client_pid(99999, 12345));
    }

    // ─── PID-reuse hardening: map & parent-walk paths (root path covered by ──
    // ─── the two c3 tests above; every test below passes root_target_pid=0) ──

    /// A recycled PID must not inherit a dead process's trust: a stored
    /// creation-time fingerprint that no longer matches the live probe is a
    /// PID-reuse collision — reject AND prune the stale entry so the impostor
    /// can never pass a later re-check against the corpse's identity.
    #[test]
    fn reused_pid_different_create_time_rejected_and_pruned() {
        let pid = 0x5A01_0001u32;
        let t1 = 0x01D9_0000_0000_0010u64;
        crate::global_proc_info().pin().insert(
            pid,
            crate::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("c:\\victim.exe"),
                create_time: t1,
            },
        );
        // Live kernel probe would report a different creation time → the PID
        // was recycled for a foreign process.
        assert!(!is_owned_client_pid_impl(
            pid,
            0,
            0,
            &|p: u32| if p == pid { Some(t1 + 7) } else { None },
            &|_| None,
        ));
        assert!(
            crate::global_proc_info().pin().get(&pid).is_none(),
            "stale entry must be pruned on fingerprint mismatch"
        );
    }

    /// A tracked PID the kernel can no longer probe is gone (or unopenable) —
    /// reject AND prune, so the entry cannot vouch for whatever reuses the PID.
    #[test]
    fn dead_pid_rejected_and_pruned() {
        let pid = 0x5A02_0001u32;
        let t2 = 0x01D9_0000_0000_0020u64;
        crate::global_proc_info().pin().insert(
            pid,
            crate::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("c:\\victim.exe"),
                create_time: t2,
            },
        );
        assert!(!is_owned_client_pid_impl(
            pid,
            0,
            0,
            &|_| None, // kernel probe finds nothing — the process is gone
            &|_| None,
        ));
        assert!(
            crate::global_proc_info().pin().get(&pid).is_none(),
            "dead entry must be pruned"
        );
    }

    /// The happy path: a tracked entry whose live creation time matches its
    /// stored fingerprint exactly is the SAME live process — accept, and
    /// crucially do NOT prune (the entry must survive for future connections).
    #[test]
    fn genuine_owned_child_still_accepted() {
        let pid = 0x5A03_0001u32;
        let t3 = 0x01D9_0000_0000_0030u64;
        crate::global_proc_info().pin().insert(
            pid,
            crate::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("c:\\victim.exe"),
                create_time: t3,
            },
        );
        assert!(is_owned_client_pid_impl(
            pid,
            0,
            0,
            &|p: u32| if p == pid { Some(t3) } else { None },
            &|_| None,
        ));
        assert!(
            crate::global_proc_info().pin().get(&pid).is_some(),
            "a verified live entry must NOT be pruned"
        );
        crate::global_proc_info().pin().remove(&pid);
        assert!(crate::global_proc_info().pin().get(&pid).is_none());
    }

    /// `create_time == 0` is the "unknown at insert" sentinel. Fail closed
    /// regardless of what the live probe reports — an unverified entry must
    /// never grant trust.
    #[test]
    fn zero_fingerprint_entry_fail_closed() {
        let pid = 0x5A04_0001u32;
        crate::global_proc_info().pin().insert(
            pid,
            crate::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("c:\\victim.exe"),
                create_time: 0,
            },
        );
        assert!(!is_owned_client_pid_impl(
            pid,
            0,
            0,
            &|_| Some(0x1234),
            &|_| None,
        ));
        crate::global_proc_info().pin().remove(&pid);
    }

    /// A PID with no map entry is not ours — no probe result can change that.
    #[test]
    fn untracked_pid_rejected() {
        let pid = 0x5A05_0001u32;
        assert!(!is_owned_client_pid_impl(
            pid,
            0,
            0,
            &|_| Some(0x01D9_0000_0000_0099),
            &|_| None,
        ));
    }

    /// Race-resilience path: a child connecting before its SpawnedChild was
    /// processed has no map entry of its own, but its kernel-vouched parent
    /// is tracked AND creation-time verified — accept via the parent walk.
    #[test]
    fn parent_walk_accepts_verified_ancestor() {
        let child = 0x5A06_0001u32;
        let parent = 0x5A06_0002u32;
        let t6 = 0x01D9_0000_0000_0060u64;
        crate::global_proc_info().pin().insert(
            parent,
            crate::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("c:\\victim.exe"),
                create_time: t6,
            },
        );
        assert!(is_owned_client_pid_impl(
            child,
            0,
            0,
            &|p: u32| if p == parent { Some(t6) } else { None },
            &|p: u32| if p == child { Some(parent) } else { None },
        ));
        crate::global_proc_info().pin().remove(&parent);
    }

    /// A REUSED parent PID must not vouch for the client: the stored
    /// fingerprint no longer matches the live parent probe → reject, and the
    /// stale parent entry is pruned so the impostor cannot vouch next time.
    #[test]
    fn parent_walk_rejects_reused_parent_pid() {
        let child = 0x5A07_0001u32;
        let parent = 0x5A07_0002u32;
        let t7a = 0x01D9_0000_0000_0070u64;
        let t7b = 0x01D9_0000_0000_0071u64;
        crate::global_proc_info().pin().insert(
            parent,
            crate::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("c:\\victim.exe"),
                create_time: t7a,
            },
        );
        assert!(!is_owned_client_pid_impl(
            child,
            0,
            0,
            &|p: u32| if p == parent { Some(t7b) } else { None },
            &|p: u32| if p == child { Some(parent) } else { None },
        ));
        assert!(
            crate::global_proc_info().pin().get(&parent).is_none(),
            "reused parent's stale entry must be pruned"
        );
    }

    /// A parent the kernel can no longer probe is dead — it cannot vouch for
    /// the client. Reject AND prune its stale entry.
    #[test]
    fn parent_walk_rejects_dead_parent() {
        let child = 0x5A08_0001u32;
        let parent = 0x5A08_0002u32;
        let t8 = 0x01D9_0000_0000_0080u64;
        crate::global_proc_info().pin().insert(
            parent,
            crate::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("c:\\victim.exe"),
                create_time: t8,
            },
        );
        assert!(!is_owned_client_pid_impl(
            child,
            0,
            0,
            &|_| None, // parent probe finds nothing — the parent is gone
            &|p: u32| if p == child { Some(parent) } else { None },
        ));
        assert!(
            crate::global_proc_info().pin().get(&parent).is_none(),
            "dead parent's stale entry must be pruned"
        );
    }

    /// Round-trip against the REAL kernel query: our own live process verifies
    /// under its true fingerprint, and fails closed under a fingerprint that
    /// cannot match (exactly the PID-reuse condition) — with the stale entry
    /// pruned by the gate itself.
    #[test]
    fn live_kernel_roundtrip_self_pid() {
        let self_pid = std::process::id();
        // Guard against a stale entry for this PID left by any other test.
        crate::global_proc_info().pin().remove(&self_pid);
        let real_ct = query_process_create_time(self_pid)
            .expect("own live process must be queryable");
        assert_ne!(real_ct, 0);

        // True fingerprint → accepted, and the entry survives.
        crate::global_proc_info().pin().insert(
            self_pid,
            crate::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("self.exe"),
                create_time: real_ct,
            },
        );
        assert!(is_owned_client_pid_impl(
            self_pid,
            0,
            0,
            &query_process_create_time,
            &|_| None,
        ));
        crate::global_proc_info().pin().remove(&self_pid);
        assert!(crate::global_proc_info().pin().get(&self_pid).is_none());

        // A fingerprint that cannot match the live process = PID-reuse
        // condition → rejected AND the stale entry is pruned by the gate.
        crate::global_proc_info().pin().insert(
            self_pid,
            crate::ProcInfo {
                depth: 0,
                exe_lower: Arc::from("self.exe"),
                create_time: real_ct.wrapping_add(1),
            },
        );
        assert!(!is_owned_client_pid_impl(
            self_pid,
            0,
            0,
            &query_process_create_time,
            &|_| None,
        ));
        assert!(
            crate::global_proc_info().pin().get(&self_pid).is_none(),
            "mismatched self entry must be pruned by the gate"
        );
    }

    // --- audit Medium WFP: NetDecide must decide, not always-allow ----------

    fn net_rule(
        id: &str,
        host: &str,
        port: Option<u16>,
        mode: policy::net::NetMode,
    ) -> policy::net::NetRule {
        policy::net::NetRule { id: id.into(), host_pattern: host.into(), port, mode }
    }

    #[test]
    fn net_decide_no_rules_stays_open() {
        // Pins the migration contract: existing sandboxes with an empty
        // net_rules table keep the historical allow behavior; deny-by-default
        // is opt-in via a --host='*' deny rule (as the netrule help documents).
        let (allow, rule) = net_decide(&[], "8.8.8.8", 443);
        assert!(allow);
        assert_eq!(rule, None);
    }

    #[test]
    fn net_decide_star_deny_blocks_all() {
        // The documented deny-by-default configuration.
        let rules = [net_rule("d1", "*", None, policy::net::NetMode::Deny)];
        let (allow, rule) = net_decide(&rules, "8.8.8.8", 443);
        assert!(!allow);
        assert_eq!(rule.as_deref(), Some("d1"));
    }

    #[test]
    fn net_decide_exact_deny_blocks_only_target() {
        let rules = [net_rule("d1", "6.6.6.6", None, policy::net::NetMode::Deny)];
        let (allow, _) = net_decide(&rules, "6.6.6.6", 443);
        assert!(!allow);
        let (allow, _) = net_decide(&rules, "8.8.8.8", 443);
        assert!(allow);
    }

    #[test]
    fn net_decide_port_scoped_rule_matches_port_exactly() {
        let rules = [net_rule("d1", "6.6.6.6", Some(80), policy::net::NetMode::Deny)];
        let (allow, _) = net_decide(&rules, "6.6.6.6", 80);
        assert!(!allow);
        let (allow, _) = net_decide(&rules, "6.6.6.6", 443);
        assert!(allow);
    }

    #[test]
    fn net_decide_deny_wins_over_allow_on_conflict() {
        // Conflicting matching rules must fail closed.
        let rules = [
            net_rule("a1", "10.0.0.0/8", None, policy::net::NetMode::Allow),
            net_rule("d1", "10.0.0.0/8", None, policy::net::NetMode::Deny),
        ];
        let (allow, rule) = net_decide(&rules, "10.1.2.3", 443);
        assert!(!allow, "conflicting rules must fail closed");
        assert_eq!(rule.as_deref(), Some("d1"));
    }

    #[test]
    fn net_decide_cidr_deny_matches_v4_range() {
        let rules = [net_rule("d1", "10.0.0.0/8", None, policy::net::NetMode::Deny)];
        let (allow, _) = net_decide(&rules, "10.255.0.1", 443);
        assert!(!allow);
        let (allow, _) = net_decide(&rules, "11.0.0.1", 443);
        assert!(allow);
    }

    #[test]
    fn net_decide_log_mode_is_decision_neutral() {
        let rules = [net_rule("l1", "9.9.9.9", None, policy::net::NetMode::Log)];
        let (allow, rule) = net_decide(&rules, "9.9.9.9", 53);
        assert!(allow);
        assert_eq!(rule, None);
        let rules = [
            net_rule("l1", "9.9.9.9", None, policy::net::NetMode::Log),
            net_rule("d1", "9.9.9.9", None, policy::net::NetMode::Deny),
        ];
        let (allow, _) = net_decide(&rules, "9.9.9.9", 53);
        assert!(!allow);
    }

    #[test]
    fn net_decide_hostname_pattern_does_not_match_ip_literal() {
        // Documents the DNS gap honestly: the hook reports numeric
        // addresses (DNS is not hooked), so hostname rules only fire when a
        // hostname string is actually reported. IP/CIDR rules are the
        // range control -- this test must keep failing loudly if someone
        // makes hostname patterns fuzzy-match IPs without deciding to.
        let rules = [net_rule("d1", "*.github.com", None, policy::net::NetMode::Deny)];
        let (allow, _) = net_decide(&rules, "140.82.121.4", 443);
        assert!(allow, "hostname deny rule must not silently pretend to cover IP connects");
    }

    #[test]
    fn net_decide_exact_hostname_rule_matches_hostname_string() {
        let rules = [net_rule("a1", "internal.svc", None, policy::net::NetMode::Allow)];
        let (allow, rule) = net_decide(&rules, "internal.svc", 8080);
        assert!(allow);
        assert_eq!(rule.as_deref(), Some("a1"));
    }

    #[test]
    fn handle_net_decide_reads_rules_from_policy_db() {
        // Full plumbing through the real redb DB the pipe handler uses:
        // upsert via policy::db, decide via handle_net_decide.
        let dir = tempfile::tempdir().unwrap();
        let p = policy::Policy::open_or_create(
            &dir.path().join("policy.redb"),
            dir.path().join("sb"),
            dir.path().join("md"),
            dir.path().join("proj"),
        )
        .unwrap();

        // Fresh DB: no rules -> allow (same as legacy behavior).
        let (allow, _) = handle_net_decide(&p, "8.8.8.8", 443);
        assert!(allow);

        policy::db::net_rule_upsert(
            &p.db(),
            &net_rule("d1", "8.8.8.8", Some(443), policy::net::NetMode::Deny),
        )
        .unwrap();
        let (allow, rule) = handle_net_decide(&p, "8.8.8.8", 443);
        assert!(!allow);
        assert_eq!(rule.as_deref(), Some("d1"));
    }
    // --- violations.log forging: guest-controlled strings stay one record ---

    /// Hostile guest-controlled string carrying everything the old hand-built
    /// writer failed to escape: a quote, backslashes, a newline, a CR, a tab
    /// and a complete forged record with a different pid.
    fn hostile_guest_string() -> String {
        "c:\\evil\" \n {\"pid\":666,\"exe\":\"forged\",\"kind\":\"Injection\"}\r\n\t\\ more \\"
            .to_string()
    }

    #[test]
    fn violation_log_records_cannot_be_forged_by_guest_strings() {
        let dir = tempfile::tempdir().unwrap();
        let vlog = dir.path().join("violations.log");
        let hostile = hostile_guest_string();

        let injection = injection_violation_record(
            1,
            &hostile,
            ipc::InjectKind::CreateRemoteThread,
            2,
            0xdead_beef,
            0x7ff0_1234,
            Some(&hostile),
            &[0x1000, 0x2000],
        );
        let memory = memory_violation_record(
            1,
            &hostile,
            ipc::AllocKind::Allocate,
            0x40,
            4096,
            0x5000,
            0x7ff0_5678,
            None,
            &[0x3000],
        );
        let escape = escape_violation_record(
            1,
            &hostile,
            &hostile,
            &hostile,
            0x7ff0_abcd,
            Some(&hostile),
            &[0x4000],
        );
        for record in [&injection, &memory, &escape] {
            append_violation_record(&vlog, record.clone());
        }

        let raw = std::fs::read_to_string(&vlog).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 3, "3 records must stay exactly 3 lines: {raw}");
        // Every line must parse as exactly ONE record identical to the Value
        // handed to the writer: nothing split, nothing forged, no corruption.
        // The forged pid=666 object may only appear as escaped string content.
        for (line, expected) in lines.iter().zip([&injection, &memory, &escape]) {
            let parsed: serde_json::Value = serde_json::from_str(line)
                .expect("each violations.log line must be one complete JSON record");
            assert_eq!(&parsed, expected, "record must round-trip byte-exact");
        }
    }
}

#[cfg(test)]
mod inflight_budget_tests {
    use super::*;

    /// The audit invariant: per-message size x handler concurrency is no
    /// longer the memory bound. MAX_INFLIGHT_MSG_BYTES is, and it must
    /// bind strictly below the old uncapped 128 x 16 MiB = 2 GiB product.
    #[test]
    fn inflight_cap_binds_below_the_uncapped_product() {
        let old_product = MAX_CONCURRENT_HANDLERS * ipc::MAX_MSG_LEN;
        assert_eq!(old_product, 128 * 16 * 1024 * 1024);
        assert!(
            MAX_INFLIGHT_MSG_BYTES < old_product,
            "in-flight cap {MAX_INFLIGHT_MSG_BYTES} must bind below the old {old_product}-byte product"
        );
    }

    /// The budget admits 4 maximal (16 MiB) messages and nothing more; a
    /// released reservation frees exactly its bytes.
    #[test]
    fn budget_caps_total_inflight_bytes() {
        let b = ByteBudget::new(MAX_INFLIGHT_MSG_BYTES);
        let msg = ipc::MAX_MSG_LEN;
        let r1 = b.try_reserve(msg);
        let r2 = b.try_reserve(msg);
        let r3 = b.try_reserve(msg);
        let r4 = b.try_reserve(msg);
        assert!(r1.is_some() && r2.is_some() && r3.is_some() && r4.is_some());
        assert!(b.try_reserve(1).is_none(), "5th maximal message must be refused");
        drop(r4);
        assert!(b.try_reserve(1).is_some(), "released bytes must be reusable");
    }

    /// A starved reservation times out instead of blocking forever, and
    /// succeeds promptly once budget is released (no permanent wedge).
    #[test]
    fn budget_times_out_when_starved_then_recovers() {
        let b = ByteBudget::new(100);
        let r = b.try_reserve(100).unwrap();
        assert!(b.reserve_timeout(10, Duration::from_millis(50)).is_none());
        drop(r);
        let r2 = b.reserve_timeout(10, Duration::from_secs(2));
        assert!(r2.is_some(), "post-release reservation must succeed");
    }

    /// A single declared size larger than the whole budget is clamped to
    /// it (bounded), not rejected: one legal-but-huge message still flows.
    #[test]
    fn oversize_request_is_clamped_to_budget() {
        let b = ByteBudget::new(1000);
        let r = b.reserve_timeout(5000, Duration::from_millis(10));
        assert!(r.is_some(), "single oversize request is clamped, not refused");
        assert!(b.try_reserve(1).is_none(), "clamped request must consume the whole budget");
    }

    /// PrefixedReader replays the already-read length prefix, then serves
    /// the body from the pipe, so ipc::read_msg parses both untouched.
    #[test]
    fn prefixed_reader_serves_prefix_then_delegates() {
        use std::io::Cursor;
        let mut inner = Cursor::new(b"BODY".to_vec());
        let mut pr = PrefixedReader { prefix: 7u32.to_le_bytes(), pos: 0, inner: &mut inner };
        let mut out = Vec::new();
        pr.read_to_end(&mut out).unwrap();
        let mut want = 7u32.to_le_bytes().to_vec();
        want.extend_from_slice(b"BODY");
        assert_eq!(out, want);
        // inner was left untouched after its bytes were consumed
        assert_eq!(inner.position(), 4);
    }
}
