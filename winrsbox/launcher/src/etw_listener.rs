// ETW Kernel-Process listener — monitoring layer.
//
// Subscribes to kernel-level process events (ProcessStart, ImageLoad,
// ThreadStart) for sandboxed PIDs. Logs events for post-mortem analysis.
// Does NOT enforce (kill) — user-mode hooks handle enforcement.
//
// Why monitoring only: Kernel-Process provider gives generic events
// without enough context (image path, signing status) for reliable
// behavioral scoring. False-positive kills would break legitimate
// programs. ETW-TI Phase 2 (requires Admin) adds rich enforcement events.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

static ETW_EVENTS: AtomicU64 = AtomicU64::new(0);
static ETW_SANDBOX_EVENTS: AtomicU64 = AtomicU64::new(0);

/// Returns true if the current process is running elevated (Admin).
fn is_elevated() -> bool {
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elev = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token, TokenElevation,
            Some(&mut elev as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        let _ = windows::Win32::Foundation::CloseHandle(token);
        ok.is_ok() && elev.TokenIsElevated != 0
    }
}

pub fn start(
    sandbox_pids: Arc<dyn Fn(u32) -> bool + Send + Sync>,
) -> Result<EtwHandle, String> {
    if !is_elevated() {
        return Err("ETW Kernel-Process provider requires Admin (elevated) launcher".into());
    }
    use ferrisetw::provider::Provider;
    use ferrisetw::provider::kernel_providers;
    use ferrisetw::trace::UserTrace;

    let pids = Arc::clone(&sandbox_pids);
    let provider = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
        .add_callback(move |record, _schema_locator| {
            on_event(record, &pids);
        })
        .build();

    let session_name = "winrsbox-etw".to_string();
    // Try starting. If stale session exists, stop it via logman and retry.
    let result = UserTrace::new()
        .named(session_name.clone())
        .enable(provider)
        .start();
    let (trace, _handle) = match result {
        Ok(r) => r,
        Err(_) => {
            // Stop stale session from crashed previous run
            let _ = std::process::Command::new("logman")
                .args(["stop", &session_name, "-ets"])
                .output();
            // Re-create provider (consumed by first attempt)
            let pids2 = Arc::clone(&sandbox_pids);
            let provider2 = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
                .add_callback(move |record, _schema_locator| {
                    on_event(record, &pids2);
                })
                .build();
            UserTrace::new()
                .named(session_name)
                .enable(provider2)
                .start()
                .map_err(|e| format!("ETW start (retry) failed: {e:?}"))?
        }
    };

    Ok(EtwHandle { _trace: trace })
}

pub struct EtwHandle {
    _trace: ferrisetw::trace::UserTrace,
}

pub fn stats() -> (u64, u64) {
    (ETW_EVENTS.load(Ordering::Relaxed), ETW_SANDBOX_EVENTS.load(Ordering::Relaxed))
}

fn on_event(
    record: &ferrisetw::EventRecord,
    is_sandbox_pid: &Arc<dyn Fn(u32) -> bool + Send + Sync>,
) {
    ETW_EVENTS.fetch_add(1, Ordering::Relaxed);

    let pid = record.process_id();
    if !is_sandbox_pid(pid) {
        return;
    }

    ETW_SANDBOX_EVENTS.fetch_add(1, Ordering::Relaxed);

    let event_id = record.event_id();
    let event_name = match event_id {
        1 => "ProcessStart",
        2 => "ProcessStop",
        3 => "ThreadStart",
        4 => "ThreadStop",
        5 => "ImageLoad",
        _ => return,
    };

    crate::jsonl_log::log(crate::jsonl_log::Event::etw_event(pid, event_name));
}
