// ─── IPC pipe server ──────────────────────────────────────────────────────────

use ipc::{read_msg, write_msg, LogLevel, Req, Resp};
use policy::Policy;
use std::{
    ffi::{c_void, OsStr},
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc,
    },
};
use tokio::sync::Semaphore;
use windows::{
    core::{HRESULT, PCWSTR},
    Win32::{
        Foundation::{CloseHandle, HLOCAL, LocalFree, ERROR_PIPE_CONNECTED, HANDLE},
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
            Threading::{GetCurrentProcess, OpenProcessToken},
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
fn is_owned_client_pid(client_pid: u32, root_target_pid: u32) -> bool {
    if client_pid == 0 {
        return false;
    }
    if root_target_pid != 0 && client_pid == root_target_pid {
        return true;
    }
    // Map populated by the Hello / SpawnedChild handlers below.
    crate::global_proc_info().pin().contains_key(&client_pid)
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

/// cancel-safe: NO — individual connection handlers are detached via spawn;
///              this outer loop itself is not designed for clean cancellation,
///              it runs for the lifetime of the launcher process.
pub(crate) async fn pipe_accept_loop(
    pipe_name: &str,
    policy: Arc<Policy>,
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

    // C3 Part 1: the first iteration must request FILE_FLAG_FIRST_PIPE_INSTANCE
    // so the kernel refuses our CreateNamedPipeW if another process already
    // owns this pipe name. Subsequent iterations must NOT request that flag
    // (it is illegal once an instance exists).
    let mut first = true;

    loop {
        // Create a new pipe instance for each incoming connection.
        //
        // C3 Part 1: the first CreateNamedPipeW call carries
        //   FILE_FLAG_FIRST_PIPE_INSTANCE — fails if a competing server with
        //   the same name already exists.
        // C3 Part 1: ALL calls carry PIPE_REJECT_REMOTE_CLIENTS — refuses
        //   connections that come in over SMB (remote logon sessions).
        // C3 Part 2: ALL calls pass the launcher-user-only DACL built above
        //   via `pipe_sec.sa`.
        //
        // PIPE_ACCESS_DUPLEX                              = FILE_FLAGS_AND_ATTRIBUTES(3)
        // FILE_FLAG_FIRST_PIPE_INSTANCE                   = FILE_FLAGS_AND_ATTRIBUTES(0x00080000)
        // PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT = NAMED_PIPE_MODE(0)
        // PIPE_REJECT_REMOTE_CLIENTS                      = NAMED_PIPE_MODE(0x00000008)
        let dw_open_mode = if first {
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            PIPE_ACCESS_DUPLEX
        };
        let dw_pipe_mode =
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;

        // SAFETY: pipe_name_wide is a valid null-terminated UTF-16 string;
        //         pipe_sec.sa is a SECURITY_ATTRIBUTES with a valid SD that
        //         lives for the entire loop (owned by `pipe_sec`).
        // Convert HANDLE to isize immediately (and capture any error as a
        // formatted String) so the Result that crosses .await is Send. The
        // raw `windows::core::Error` wraps an HRESULT whose pointer fields
        // make it `!Send`.
        let create_result: Result<isize, String> = unsafe {
            let h = CreateNamedPipeW(
                PCWSTR(pipe_name_wide.as_ptr()),
                dw_open_mode,
                dw_pipe_mode,
                255,    // max instances
                65536,  // out buffer size
                65536,  // in buffer size
                0,      // default timeout
                Some(&pipe_sec.sa as *const SECURITY_ATTRIBUTES),
            );
            if h.is_invalid() {
                // CreateNamedPipeW reports failure via INVALID_HANDLE_VALUE +
                // GetLastError. windows::core::Error::from_win32() reads the
                // calling thread's last-error code captured by the API itself.
                // Format to String here so the value is Send across .await.
                Err(format!("{:?}", windows::core::Error::from_win32()))
            } else {
                Ok(h.0 as isize)
            }
        };

        let ph: isize = match create_result {
            Ok(ph) => ph,
            Err(err) => {
                if first {
                    // C3 Part 1 fail-closed: if the first instance creation
                    // fails — most commonly because another process already
                    // owns the pipe name (ERROR_ACCESS_DENIED / ERROR_PIPE_BUSY
                    // / ERROR_ALREADY_EXISTS) — abort the launcher. Continuing
                    // would silently degrade to a co-tenant on a pipe controlled
                    // by an attacker.
                    return Err(anyhow::anyhow!(
                        "CreateNamedPipeW(FIRST_PIPE_INSTANCE) failed for {pipe_name}: {err} \
                         — pipe name collision, possible attack",
                    ));
                }
                // Subsequent failures: transient kernel pressure (e.g. too many
                // instances). Log and back off briefly, then retry. The pipe
                // namespace stays owned by us because the first instance
                // succeeded.
                eprintln!(
                    "[pipe] CreateNamedPipeW (instance) failed: {err} — retrying",
                );
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        // After the first successful CreateNamedPipeW the FIRST_PIPE_INSTANCE
        // flag MUST NOT be passed again.
        first = false;

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
                // this connection and exit the loop instead of leaking the
                // pipe handle.
                // SAFETY: ph is the isize repr of our pipe handle.
                unsafe { DisconnectNamedPipe(HANDLE(ph as *mut _)).ok() };
                unsafe { CloseHandle(HANDLE(ph as *mut _)).ok() };
                break;
            }
        };

        // Handle this connection in a separate blocking task.
        let policy = Arc::clone(&policy);
        let stats = Arc::clone(&stats);
        let child_pids = Arc::clone(&child_pids);
        let vlog = violations_log.clone();
        let hot_stats2 = Arc::clone(&hot_stats);
        let flusher2 = Arc::clone(&flusher);

        // Intentional fire-and-forget: spawn_blocking tasks run to completion even
        // after JoinHandle is dropped — they are not cancelled.
        tokio::task::spawn_blocking(move || {
            // The permit is dropped when this closure returns, releasing the
            // handler slot back to the semaphore for the next accepted connection.
            let _permit = permit;
            // SAFETY: ph is the isize repr of the valid pipe handle for this connection.
            let h = HANDLE(ph as *mut _);
            handle_connection(h, &policy, &stats, &child_pids, &vlog, &hot_stats2, &flusher2);
            // SAFETY: h — disconnect and close after the connection handler finishes.
            unsafe { DisconnectNamedPipe(h).ok() };
            unsafe { CloseHandle(h).ok() };
        });
    }

    Ok(())
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
    r"\system\currentcontrolset\services\",

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
    r"\software\classes\clsid\",

    // File / URL association hijack — the existing match is substring, so
    // `\shell\open\command` catches `HKCU\Software\Classes\<ext>\shell\open\command`
    // for every extension, plus the equivalent under HKLM and HKCR.
    r"\shell\open\command",
    r"\shellex\contextmenuhandlers\",

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
];

/// Return `true` if `key_path` is a denied registry persistence vector.
/// Pure function — extracted from the RegDecide handler for unit testing.
/// Matching is case-insensitive via internal lowercase conversion.
fn is_persistence_denied(key_path: &str) -> bool {
    let lower = key_path.to_ascii_lowercase();
    PERSISTENCE_DENY_SUFFIXES
        .iter()
        .any(|s| lower.contains(s))
}

fn handle_connection(
    handle: HANDLE,
    policy: &Policy,
    stats: &Stats,
    child_pids: &crossbeam_queue::SegQueue<u32>,
    violations_log: &Path,
    hot_stats: &HotStats,
    flusher: &ThrottledFlusher,
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

    // Track the PID associated with this pipe connection
    let mut conn_pid: Option<u32> = None;

    loop {
        let req: Req = match read_msg(&mut file) {
            Ok(r) => r,
            Err(_) => break,
        };

        let resp = match req {
            Req::Hello { pid, exe_path } => {
                println!("[sandbox] hello from pid={pid} exe={exe_path}");
                hot_stats.totals.hellos.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                jsonl_log::log(jsonl_log::Event::hello(pid, &exe_path));
                let exe_lower = exe_path.to_ascii_lowercase();
                let map = crate::global_proc_info().pin();
                if let Some(existing) = map.get(&pid) {
                    // Already have entry (e.g., root target) — keep depth, update exe
                    let updated = crate::ProcInfo {
                        depth: existing.depth,
                        exe_lower: Arc::from(exe_lower.as_str()),
                    };
                    map.insert(pid, updated);
                } else {
                    // New process — insert with depth 0 (will be updated by SpawnedChild if child)
                    map.insert(pid, crate::ProcInfo {
                        depth: 0,
                        exe_lower: Arc::from(exe_lower.as_str()),
                    });
                }
                conn_pid = Some(pid);
                Resp::Ok
            }
            Req::SpawnedChild { parent_pid, child_pid, child_exe } => {
                println!("[sandbox] child spawned: parent={parent_pid} child={child_pid} exe={child_exe}");
                hot_stats.totals.children.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                jsonl_log::log(jsonl_log::Event::child(parent_pid, child_pid, &child_exe));
                child_pids.push(child_pid);
                let map = crate::global_proc_info().pin();
                let parent_depth = map.get(&parent_pid).map(|p| p.depth).unwrap_or(0);
                let exe_lower = child_exe.to_ascii_lowercase();
                map.insert(child_pid, crate::ProcInfo {
                    depth: parent_depth + 1,
                    exe_lower: Arc::from(exe_lower.as_str()),
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
                    policy::Mode::Passthrough => {}
                }
                hot_stats.record_fs(&dos_path, write, denied);
                flusher.maybe_flush();
                Resp::Decision(d)
            }
            Req::RecordOverlay { orig, overlay } => {
                let _ = policy.record_overlay(&orig, &overlay);
                Resp::Ok
            }
            Req::Log { pid, level, msg } => {
                let level_str = match level {
                    LogLevel::Trace => "TRACE",
                    LogLevel::Info => "INFO ",
                    LogLevel::Warn => "WARN ",
                    LogLevel::Error => "ERROR",
                };
                println!("[hook/{pid}] {level_str} {msg}");
                Resp::Ok
            }
            Req::RegisterChild { pid } => {
                println!("[sandbox] child registered: pid={pid}");
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
                let stack_json: Vec<String> = stack_top.iter().map(|f| format!("\"0x{f:x}\"")).collect();
                let line = format!(
                    "{{\"pid\":{pid},\"exe\":\"{}\",\"kind\":\"{kind}\",\"target_pid\":{target_pid},\"start_addr\":\"0x{start_address:x}\",\"caller_pc\":\"0x{caller_pc:x}\",\"caller_module\":{},\"stack\":[{}]}}\n",
                    exe.replace('\\', "\\\\").replace('"', "\\\""),
                    match &caller_module {
                        Some(m) => format!("\"{}\"", m.replace('\\', "\\\\").replace('"', "\\\"")),
                        None => "null".to_string(),
                    },
                    stack_json.join(","),
                );
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true).append(true).open(violations_log)
                {
                    let _ = f.write_all(line.as_bytes());
                }
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
                let stack_json: Vec<String> = stack_top.iter().map(|f| format!("\"0x{f:x}\"")).collect();
                let line = format!(
                    "{{\"pid\":{pid},\"exe\":\"{}\",\"kind\":\"{kind}\",\"protect\":\"0x{requested_protect:x}\",\"size\":{region_size},\"addr\":\"0x{target_address:x}\",\"caller_pc\":\"0x{caller_pc:x}\",\"caller_module\":{},\"stack\":[{}]}}\n",
                    exe.replace('\\', "\\\\").replace('"', "\\\""),
                    match &caller_module {
                        Some(m) => format!("\"{}\"", m.replace('\\', "\\\\").replace('"', "\\\"")),
                        None => "null".to_string(),
                    },
                    stack_json.join(","),
                );
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true).append(true).open(violations_log)
                {
                    let _ = f.write_all(line.as_bytes());
                }
                Resp::Ok
            }
            Req::RegDecide { key_path, value_name, write } => {
                // P8 default-deny: block writes to known DLL-injection persistence
                // vectors. Until full RegistryPolicy wiring, hardcode the most
                // critical paths from DEFAULT_CONFIG_KTAV.
                // Match by `contains` (substring) to cover HKU\<SID>\... per-user
                // hive paths and HKLM/HKCU/HKCR/HKU forms uniformly.
                let key_lower = key_path.to_ascii_lowercase();
                // is_persistence_denied lowercases internally, but key_lower
                // is needed for the silent-ok branch below; pass it through
                // to avoid a second allocation.
                let is_persistence = is_persistence_denied(&key_lower);
                let (mode, denied) = if write && is_persistence {
                    eprintln!("[reg] DENY {key_path} value={value_name:?}");
                    ("deny", true)
                } else if write && (key_lower.contains(r"\software\") || key_lower.ends_with(r"\software")) {
                    // Non-persistence HKCU\Software writes → silent success
                    // (program thinks it wrote, sandbox absorbs it)
                    ("silent_ok", false)
                } else {
                    ("passthrough", false)
                };
                hot_stats.totals.reg_decides.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if denied { hot_stats.totals.reg_denies.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
                hot_stats.record_reg(&key_path, write, denied);
                if denied {
                    jsonl_log::log(jsonl_log::Event::reg_decide(&key_path, write, mode));
                }
                flusher.maybe_flush();
                Resp::RegDecision { mode: mode.into(), value_json: None }
            }
            Req::RegWrite { key_path, value_name, .. } => {
                println!("[reg] write: {key_path}\\{value_name}");
                Resp::Ok
            }
            Req::RegDeleteValue { key_path, value_name } => {
                println!("[reg] delete_value: {key_path}\\{value_name}");
                Resp::Ok
            }
            Req::RegDeleteKey { key_path } => {
                println!("[reg] delete_key: {key_path}");
                Resp::Ok
            }
            Req::NetDecide { host, port } => {
                // Net enforcement happens in the WFP filter set up at
                // launcher startup (see crate::main::run + winrsbox::wfp).
                // The policy.net_rules table is informational only; we
                // always answer "allow" here and rely on the kernel-level
                // WFP rules for the actual block. Surfacing a userspace
                // deny here would just paper over a WFP gap and confuse
                // post-mortem analysis.
                let allow = true;
                hot_stats.totals.net_decides.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let host_port = format!("{host}:{port}");
                hot_stats.record_net(&host_port, false);
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

    // Do NOT let `file` run its Drop (which would call CloseHandle on the underlying HANDLE).
    // The caller in spawn_blocking closes the handle via DisconnectNamedPipe + CloseHandle.
    // Double-closing would be UB / use-after-free on the handle.
    std::mem::forget(file);
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// `is_owned_client_pid` accepts the root PID even when client is missing
    /// from `global_proc_info` (chicken-and-egg between Hello and validation).
    #[test]
    fn c3_owned_pid_matches_root_target() {
        let root = 12345u32;
        assert!(is_owned_client_pid(root, root));
    }

    /// `is_owned_client_pid` rejects PID 0 and any unknown PID when no map entry.
    #[test]
    fn c3_owned_pid_rejects_zero_and_unknown() {
        assert!(!is_owned_client_pid(0, 12345));
        // 99999 is neither root nor in the map.
        assert!(!is_owned_client_pid(99999, 12345));
    }
}
