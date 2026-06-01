// IPC client plumbing — pipe connection, send/recv, ipc_decide(), ipc_log_violation(),
// IPC_CONSECUTIVE_FAILURES counter, fail-closed self-terminate logic, TRACE_ENABLED, is_trace().
// Everything that talks to the launcher pipe.

use policy::{Decision, Mode};
use winapi::um::processthreadsapi::GetCurrentProcessId;

use crate::cache::HookCache;

// ---------------------------------------------------------------------------
// IPC / cache globals
// ---------------------------------------------------------------------------

pub(crate) static CACHE: std::sync::OnceLock<HookCache> = std::sync::OnceLock::new();

// Per-thread IPC connection. Each thread gets its own SyncClient so file-system
// calls don't serialize on a global mutex. The launcher pipe server handles
// each connection concurrently via spawn_blocking, giving real parallelism on
// multithreaded targets.
thread_local! {
    pub(crate) static IPC_CLIENT: std::cell::RefCell<Option<ipc::SyncClient>> =
        const { std::cell::RefCell::new(None) };
    pub(crate) static HELLO_SENT: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

pub(crate) static PIPE_NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
pub(crate) static DLL_PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
pub(crate) static SANDBOX_CWD: std::sync::OnceLock<String> = std::sync::OnceLock::new();

// ---------------------------------------------------------------------------
// Install-error buffer (P2-5)
//
// At install_hooks() time the IPC pipe may not yet be connected (Hello hasn't
// been sent), so ipc_log() would silently drop messages.  We buffer them here
// and flush on the first successful Hello.
// ---------------------------------------------------------------------------
static INSTALL_ERRORS: std::sync::OnceLock<std::sync::Mutex<Vec<String>>> = std::sync::OnceLock::new();

pub(crate) fn buffer_install_error(msg: String) {
    let buf = INSTALL_ERRORS.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    if let Ok(mut v) = buf.lock() {
        v.push(msg);
    }
}

pub(crate) fn flush_install_errors() {
    if let Some(buf) = INSTALL_ERRORS.get() {
        if let Ok(mut v) = buf.lock() {
            for msg in v.drain(..) {
                ipc_log(ipc::LogLevel::Warn, msg);
            }
        }
    }
}

pub(crate) static TRACE_ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Consecutive IPC failures counter for fail-closed self-termination (P1-3 audit fix).
pub(crate) static IPC_CONSECUTIVE_FAILURES: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);
/// How many ipc_decide calls must fail in a row before this process self-terminates.
///
/// 3 was too tight: under MSYS2 first-run setup the parent (bash.exe) spawns
/// ~8 helper processes inside a single second. Each helper's `DllMain` then
/// runs `install_hooks` and immediately issues its first `ipc_decide`, which
/// must `SyncClient::connect` to the launcher pipe. The single-instance
/// accept loop (one ConnectNamedPipe at a time → only one free pipe handle
/// at any moment) cannot service that burst — late processes see
/// `ERROR_PIPE_BUSY` on every retry and burn the 3-strike budget in ~1.5s,
/// then `TerminateProcess` themselves. Cascade of self-terminations corrupts
/// MSYS2 first-run state.
///
/// 8 is still fail-closed for genuine outages (a hung launcher → 8 failures
/// × multi-second connect budget = >30 s before the hook gives up), but
/// gives breathing room over a single MSYS2-style burst storm. Pair-fix:
/// `SyncClient::connect` retry budget widened from 500 ms to 3 s.
const IPC_FAIL_THRESHOLD: u32 = 8;

pub(crate) fn is_trace() -> bool {
    TRACE_ENABLED.load(std::sync::atomic::Ordering::Relaxed)
}

pub(crate) fn cache() -> &'static HookCache {
    CACHE.get_or_init(HookCache::new)
}

pub(crate) fn ensure_ipc_and<R>(f: impl FnOnce(&mut Option<ipc::SyncClient>) -> R) -> Option<R> {
    let mut sent = false;
    let result = IPC_CLIENT.with_borrow_mut(|opt| {
        if opt.is_none() {
            if let Some(name) = PIPE_NAME.get() {
                *opt = ipc::SyncClient::connect(name).ok();
                // Send Hello on first connection. If the very first send
                // already fails — pipe was accepted but the launcher's
                // handler thread died before we could write — clear the
                // client so the next ensure_ipc_and reconnects rather
                // than burning the fail-closed counter on a dead handle.
                if opt.is_some() && !HELLO_SENT.get() {
                    let pid = unsafe { GetCurrentProcessId() };
                    let exe = get_own_exe_path();
                    let send_res = opt.as_mut().unwrap().send(&ipc::Req::Hello {
                        pid,
                        exe_path: exe,
                    });
                    if send_res.is_err() {
                        *opt = None;
                    } else {
                        sent = true;
                    }
                }
            }
        }
        if opt.is_some() {
            Some(f(opt))
        } else {
            None
        }
    });
    if sent {
        HELLO_SENT.set(true);
        flush_install_errors();
        crate::inject_guard::arm();
    }
    result
}

/// Send a request through the connected client and return the response.
/// On ANY send error, the client is reset to `None` so the next call will
/// reconnect. Without this, a launcher restart (or any transient pipe
/// break) leaves every hook holding a dead client forever, every send
/// fails identically, and the fail-closed counter trips after
/// IPC_FAIL_THRESHOLD calls — terminating processes that would have
/// recovered on the next reconnect attempt.
pub(crate) fn try_send(opt: &mut Option<ipc::SyncClient>, req: &ipc::Req) -> Option<ipc::Resp> {
    let client = opt.as_mut()?;
    match client.send(req) {
        Ok(resp) => Some(resp),
        Err(_) => {
            // Mark client for reconnect on the next ensure_ipc_and call.
            *opt = None;
            None
        }
    }
}

pub(crate) fn ipc_decide(dos_lower: &str, write: bool) -> Decision {
    let result = ensure_ipc_and(|opt| {
        let req = ipc::Req::Decide {
            dos_path: dos_lower.to_owned(),
            write,
        };
        if let Some(ipc::Resp::Decision(d)) = try_send(opt, &req) {
            return Some(d);
        }
        None
    });

    match result {
        Some(Some(d)) => {
            IPC_CONSECUTIVE_FAILURES.store(0, std::sync::atomic::Ordering::Relaxed);
            d
        }
        _ => {
            // IPC failure — increment counter, possibly self-terminate (fail-closed).
            let n = IPC_CONSECUTIVE_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if n >= IPC_FAIL_THRESHOLD {
                eprintln!(
                    "[hook] CRITICAL: {} consecutive IPC failures — \
                     sandbox launcher dead/hung, self-terminating",
                    n,
                );
                unsafe {
                    winapi::um::processthreadsapi::TerminateProcess(
                        winapi::um::processthreadsapi::GetCurrentProcess(),
                        0xC0000005,
                    );
                }
                // Unreachable after TerminateProcess, but satisfies type checker.
                std::process::exit(1);
            }
            // Below threshold — return Deny (fail-closed: safer to block than to allow).
            Decision { mode: Mode::Deny, overlay: None, cow_from: None, mock_payload: None }
        }
    }
}

pub(crate) fn ipc_record_overlay(orig: &str, overlay: &str) {
    let _ = ensure_ipc_and(|opt| {
        let _ = try_send(opt, &ipc::Req::RecordOverlay {
            orig: orig.to_owned(),
            overlay: overlay.to_owned(),
        });
    });
}

pub(crate) fn ipc_register_child(pid: u32) {
    let _ = ensure_ipc_and(|opt| {
        let _ = try_send(opt, &ipc::Req::RegisterChild { pid });
    });
}

pub(crate) fn ipc_spawned_child(parent_pid: u32, child_pid: u32, child_exe: String) {
    let _ = ensure_ipc_and(|opt| {
        let _ = try_send(opt, &ipc::Req::SpawnedChild {
            parent_pid,
            child_pid,
            child_exe,
        });
    });
}

/// Send a request and return the Resp if the pipe is connected.
/// Used by reg_hooks for RegDecide, net_hooks for NetDecide, etc.
pub(crate) fn ipc_send_and_recv(req: ipc::Req) -> Option<ipc::Resp> {
    ensure_ipc_and(|opt| try_send(opt, &req)).flatten()
}

pub(crate) fn ipc_log_violation(req: ipc::Req) -> Option<()> {
    ensure_ipc_and(|opt| {
        let _ = try_send(opt, &req);
    })
}

pub(crate) fn ipc_log(level: ipc::LogLevel, msg: String) {
    let pid = unsafe { GetCurrentProcessId() };
    let _ = ensure_ipc_and(|opt| {
        let _ = try_send(opt, &ipc::Req::Log { pid, level, msg });
    });
}

/// Get the current process executable path (lowercased).
pub(crate) fn get_own_exe_path() -> String {
    let mut buf = [0u16; 512];
    // SAFETY: buf is valid, len matches. GetModuleFileNameW writes a null-terminated string.
    let len = unsafe { winapi::um::libloaderapi::GetModuleFileNameW(
        std::ptr::null_mut(),
        buf.as_mut_ptr(),
        buf.len() as u32,
    )};
    if len == 0 {
        return String::new();
    }
    let s = String::from_utf16_lossy(&buf[..len as usize]);
    s.to_ascii_lowercase()
}

#[cfg(test)]
mod ipc_threshold_tests {
    use super::*;

    #[test]
    fn fail_threshold_pinned() {
        // P1-3 fail-closed contract: the hooked process self-terminates
        // after IPC_FAIL_THRESHOLD consecutive ipc_decide failures.
        //
        // Raised from 3 → 8 to survive MSYS2 first-run-setup-style bursts
        // (8+ helper-process spawns in a single second, each racing on the
        // single-instance launcher pipe and hitting transient PIPE_BUSY).
        // Changing this value again requires updating docs/THREATMODEL.md
        // and re-validating the fail-closed posture: a 100% pipe outage
        // is still caught within IPC_FAIL_THRESHOLD × per-call connect
        // budget (~30 s with the current 3 s SyncClient retry window).
        assert_eq!(IPC_FAIL_THRESHOLD, 8, "IPC fail-closed threshold drifted");
    }

    /// The threshold MUST stay strictly greater than the largest realistic
    /// in-flight burst we tolerate (8 sibling spawns per second observed in
    /// MSYS2 first-run). If somebody lowers this back to 3, the regression
    /// is silent — the cascade-self-terminate path triggers only under
    /// burst load. Pin the lower bound separately so the intent survives
    /// a refactor of `fail_threshold_pinned`.
    #[test]
    fn fail_threshold_at_least_eight() {
        assert!(IPC_FAIL_THRESHOLD >= 8,
            "IPC_FAIL_THRESHOLD must tolerate an 8-process MSYS2 burst storm");
    }

    // -- try_send reset-on-error -----------------------------------------------
    //
    // Regression coverage for the cascade-self-terminate bug (#61): when
    // `client.send()` returned `Err`, the previous code left the dead
    // SyncClient in IPC_CLIENT, so every subsequent ipc_decide failed in the
    // exact same way and IPC_FAIL_THRESHOLD tripped. `try_send` MUST clear
    // `*opt` on Err so the next ensure_ipc_and reconnects.
    //
    // The Err-arm cannot be unit-tested here without reaching into
    // `SyncClient`'s private `pipe` field (the hook crate has no
    // `windows-rs` dep for pipe primitives). Live coverage is the
    // integration suite + manual launcher-restart smoke. The None-opt
    // path is the only purely-functional thing we CAN pin from here.

    #[test]
    fn try_send_with_none_opt_returns_none_and_leaves_opt_none() {
        let mut opt: Option<ipc::SyncClient> = None;
        let req = ipc::Req::Decide { dos_path: "c:\\x".into(), write: false };
        let resp = try_send(&mut opt, &req);
        assert!(resp.is_none(), "no client, no response");
        assert!(opt.is_none(), "try_send must not invent a client");
    }

    /// THE bug #61 covered: when `client.send()` returns `Err`, `try_send`
    /// MUST set `*opt = None` so the next `ensure_ipc_and` call reconnects.
    /// Pre-fix, the dead client stayed forever and every subsequent decide
    /// failed identically — `IPC_FAIL_THRESHOLD` tripped, the hooked
    /// process self-terminated mid-MSYS2-burst.
    ///
    /// Driver: wrap a read-only File in a SyncClient via the test-only
    /// `from_file_for_test` constructor. `write_msg` inside `send` calls
    /// `write_all` on that File and gets `PermissionDenied`, so `send`
    /// returns `Err` deterministically — the exact code path the dead
    /// pipe took live.
    #[test]
    fn try_send_clears_opt_when_underlying_send_errors() {
        // Any always-readable system file works as a write-target that
        // is guaranteed to refuse writes. notepad.exe is signed and
        // present on every Windows host CI / dev box we run on; if it
        // is absent the test should fail loudly rather than silently
        // skip (the contract under test is critical).
        let read_only = std::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(r"C:\Windows\System32\notepad.exe")
            .expect("notepad.exe must be openable read-only on a Windows host");
        let client = ipc::SyncClient::from_file_for_test(read_only);

        let mut opt = Some(client);
        let req = ipc::Req::Decide { dos_path: "c:\\x".into(), write: true };

        let resp = try_send(&mut opt, &req);

        assert!(resp.is_none(),
            "send on a read-only File MUST fail and try_send MUST return None");
        assert!(opt.is_none(),
            "try_send MUST clear opt on send Err so the next call reconnects \
             (regression #61: without this the hook accumulated 8 \
             consecutive failures and self-terminated)");
    }
}
