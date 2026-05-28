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
const IPC_FAIL_THRESHOLD: u32 = 3;

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
                // Send Hello on first connection
                if opt.is_some() && !HELLO_SENT.get() {
                    let pid = unsafe { GetCurrentProcessId() };
                    let exe = get_own_exe_path();
                    let _ = opt.as_mut().unwrap().send(&ipc::Req::Hello {
                        pid,
                        exe_path: exe,
                    });
                    sent = true;
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

pub(crate) fn ipc_decide(dos_lower: &str, write: bool) -> Decision {
    let result = ensure_ipc_and(|opt| {
        if let Some(client) = opt.as_mut() {
            let req = ipc::Req::Decide {
                dos_path: dos_lower.to_owned(),
                write,
            };
            if let Ok(ipc::Resp::Decision(d)) = client.send(&req) {
                return Some(d);
            }
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
        if let Some(client) = opt.as_mut() {
            let _ = client.send(&ipc::Req::RecordOverlay {
                orig: orig.to_owned(),
                overlay: overlay.to_owned(),
            });
        }
    });
}

pub(crate) fn ipc_register_child(pid: u32) {
    let _ = ensure_ipc_and(|opt| {
        if let Some(client) = opt.as_mut() {
            let _ = client.send(&ipc::Req::RegisterChild { pid });
        }
    });
}

pub(crate) fn ipc_spawned_child(parent_pid: u32, child_pid: u32, child_exe: String) {
    let _ = ensure_ipc_and(|opt| {
        if let Some(client) = opt.as_mut() {
            let _ = client.send(&ipc::Req::SpawnedChild {
                parent_pid,
                child_pid,
                child_exe,
            });
        }
    });
}

/// Send a request and return the Resp if the pipe is connected.
/// Used by reg_hooks for RegDecide, net_hooks for NetDecide, etc.
pub(crate) fn ipc_send_and_recv(req: ipc::Req) -> Option<ipc::Resp> {
    ensure_ipc_and(|opt| {
        if let Some(client) = opt.as_mut() {
            return client.send(&req).ok();
        }
        None
    }).flatten()
}

pub(crate) fn ipc_log_violation(req: ipc::Req) -> Option<()> {
    ensure_ipc_and(|opt| {
        if let Some(client) = opt.as_mut() {
            let _ = client.send(&req);
        }
    })
}

pub(crate) fn ipc_log(level: ipc::LogLevel, msg: String) {
    let pid = unsafe { GetCurrentProcessId() };
    let _ = ensure_ipc_and(|opt| {
        if let Some(client) = opt.as_mut() {
            let _ = client.send(&ipc::Req::Log { pid, level, msg });
        }
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
    fn fail_threshold_pinned_to_three() {
        // P1-3 fail-closed contract: after 3 consecutive IPC failures,
        // the hooked process self-terminates. Changing this requires
        // updating docs/THREATMODEL.md and the security audit posture.
        assert_eq!(IPC_FAIL_THRESHOLD, 3, "IPC fail-closed threshold drifted");
    }
}
