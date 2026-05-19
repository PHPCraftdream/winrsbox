// ETW Kernel-Process listener — subscribes to kernel-level process events
// and scores them via EtwScoreboard.
//
// Provider: Kernel Process (3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c)
// Events: ProcessStart, ThreadStart, ImageLoad

use crate::etw::{EtwEventKind, EtwScoreboard};
use std::sync::{Arc, Mutex};

/// `sandbox_pids` is checked to filter events: only PIDs present are scored.
pub fn start(
    scoreboard: Arc<Mutex<EtwScoreboard>>,
    sandbox_pids: Arc<dyn Fn(u32) -> bool + Send + Sync>,
) -> Result<EtwHandle, String> {
    use ferrisetw::provider::Provider;
    use ferrisetw::provider::kernel_providers;
    use ferrisetw::trace::UserTrace;

    let sb = Arc::clone(&scoreboard);
    let pids = Arc::clone(&sandbox_pids);
    let provider = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
        .add_callback(move |record, _schema_locator| {
            on_event(record, &sb, &pids);
        })
        .build();

    let (trace, _handle) = UserTrace::new()
        .named("winrsbox-etw".to_string())
        .enable(provider)
        .start()
        .map_err(|e| format!("ETW start failed: {e:?}"))?;

    Ok(EtwHandle { _trace: trace })
}

pub struct EtwHandle {
    _trace: ferrisetw::trace::UserTrace,
}

fn on_event(
    record: &ferrisetw::EventRecord,
    scoreboard: &Arc<Mutex<EtwScoreboard>>,
    is_sandbox_pid: &Arc<dyn Fn(u32) -> bool + Send + Sync>,
) {
    let pid = record.process_id();
    let event_id = record.event_id();

    if !is_sandbox_pid(pid) {
        return;
    }

    let kind = match event_id {
        1 => EtwEventKind::ProcessTrampolined,
        3 => EtwEventKind::Other,
        5 => EtwEventKind::SuspiciousImageLoad,
        _ => return,
    };

    if let Ok(mut sb) = scoreboard.lock() {
        let score = sb.record(pid, kind);
        if crate::etw::should_terminate(score) {
            eprintln!(
                "[ETW] behavioral threshold exceeded for pid={pid} score={score} — terminating"
            );
            terminate_pid(pid);
            sb.clear(pid);
        }
    }
}

fn terminate_pid(pid: u32) {
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    unsafe {
        if let Ok(h) = OpenProcess(PROCESS_TERMINATE, false, pid) {
            let _ = TerminateProcess(h, 0xC000_0005);
            let _ = windows::Win32::Foundation::CloseHandle(h);
        }
    }
}
