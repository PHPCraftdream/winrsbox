// MP-6: the part of a launcher run that is identical for both roles — from
// "session config is ready to publish" through "target exited, summary
// printed". Extracted out of `main::run()` (which used to inline this for
// the broker role only) so `main::client::run_as_client` can share it
// instead of duplicating ~400 lines. Nothing here touches `policy::Policy`
// or `policy::RegistryPolicy` — a client never opens the database (see
// `docs/multiprocess-broker-plan.md`, MP-6).

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, Mutex,
};
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::Threading::{
        GetExitCodeProcess, ResumeThread, WaitForMultipleObjects, WaitForSingleObject, INFINITE,
    },
};
use winrsbox::observe::hot_stats::ThrottledFlusher;
use winrsbox::observe::jsonl_log;

use crate::{fold_published, sandbox, Cli, GuardLevel};

/// How the shared tail waits out any remaining sandboxed children once the
/// root target has exited, and (client only) how it gets real numbers for
/// its own exit summary — a client runs no pipe server, so its own `Stats`
/// starts at all-zero and must be filled in from the broker.
pub(crate) enum ExitDrain {
    /// Broker: children were reported via `RegisterChild`/`SpawnedChild` on
    /// this process's own pipe server (existing MP-2-and-earlier path,
    /// unchanged). `stats` is already live — nothing to fetch.
    Broker(Arc<crossbeam_queue::SegQueue<u32>>),
    /// Client: no pipe server of its own, so no `child_pids` queue is ever
    /// filled — wait for the client's OWN session job to empty instead
    /// (`sandbox::child_drain::drain_own_job`, applied to the SAME session
    /// job both roles create below via `setup_job_object` — no separate
    /// handle to thread in), then fetch the folder's counters from the
    /// broker over `conn` (`ipc::Req::SessionStats`) and store them into
    /// `stats` before the summary below reads it.
    Client { conn: Arc<Mutex<ipc::SyncClient>> },
}

/// Everything the shared tail needs, gathered by the caller (`main::run()`
/// for the broker, `main::client::run_as_client` for a client) from its own
/// role-specific setup.
pub(crate) struct SessionParams<'a> {
    pub(crate) cli: &'a Cli,
    pub(crate) project_root: PathBuf,
    pub(crate) sandbox_root: PathBuf,
    pub(crate) target_args: Vec<String>,
    pub(crate) violations_log: PathBuf,
    pub(crate) pipe_name: String,
    pub(crate) overlay_layout: policy::path::OverlayLayout,
    pub(crate) folder_section_name: String,
    pub(crate) net_guarded: bool,
    pub(crate) effective_log_level: String,
    /// This launcher's own identity, published in `SessionConfig` — the
    /// hook trusts whichever launcher (broker or an attached client) started
    /// its session, verified against the folder section's trusted-launcher
    /// set (see `hook::trusted_boot`). Broker: its own pid/create_time.
    /// Client: its own pid/create_time too — NOT the broker's; a client is
    /// added to that trusted set during `Attach` (`main::broker::
    /// try_complete_attach`).
    pub(crate) launcher_pid: u32,
    pub(crate) launcher_create_time: u64,
    /// Guest admission target: the folder job to assign the guest into
    /// BEFORE the session job (MP-0 §1 nesting order) — the broker's own
    /// `FolderJob::handle()`, or a client's duplicated `folder_job_handle`
    /// from `AttachedFolder`. Either way just a HANDLE the caller owns for
    /// at least this call's duration.
    pub(crate) folder_job: HANDLE,
    /// C3 Part 3: the SAME `Arc` the broker's own pipe accept loop reads on
    /// every new connection — must be threaded through, not created fresh
    /// here, or the broker's copy would never see the real PID. Read-dead
    /// once `folder_job` admission is in play (MP-4: job membership alone
    /// decides), but still correctness-relevant defense-in-depth, so it is
    /// still populated exactly as before this function existed. A client
    /// runs no pipe server of its own — nothing ever reads its copy, so it
    /// passes a throwaway `Arc::new(AtomicU32::new(0))`.
    pub(crate) root_target_pid: Arc<AtomicU32>,
    pub(crate) stats: Arc<crate::pipe_server::Stats>,
    pub(crate) exit_drain: ExitDrain,
    /// Broker only (hot-stats.json is broker-owned, see the plan's "Логи и
    /// статистика"); `None` for a client — nothing to flush.
    pub(crate) hot_stats_flusher: Option<Arc<ThrottledFlusher>>,
}

/// Runs one sandboxed session from a ready `SessionParams` through to the
/// target's exit, returning the process exit code the caller should
/// `std::process::exit` with. Never returns `Ok` without the target having
/// actually run and exited — every early-failure path below already
/// terminates the process directly (mirrors the pre-MP-6 behaviour this was
/// extracted from).
pub(crate) async fn run_target_session(p: SessionParams<'_>) -> Result<i32> {
    let SessionParams {
        cli, project_root, sandbox_root, target_args, violations_log, pipe_name,
        overlay_layout, folder_section_name, net_guarded, effective_log_level,
        launcher_pid, launcher_create_time, folder_job, root_target_pid, stats,
        exit_drain, hot_stats_flusher,
    } = p;

    let dll_path = sandbox::find_hook_dll()?;

    // Sanitize sensitive variables and retired sandbox config before the
    // target inherits them; the trusted session section carries that config.
    let removed = winrsbox::contain::guest::env_guard::sanitize();
    if removed > 0 && jsonl_log::console_verbose() {
        println!("[sandbox] env: sanitized {removed} sensitive variables");
    }

    let cwd_str = project_root.to_string_lossy().into_owned();
    let hook_trace = cli.trace || effective_log_level.eq_ignore_ascii_case("trace");
    let disable_hooks_effective = sandbox::launch_prep::set_sandbox_environment(
        cli,
        &pipe_name,
        std::path::Path::new(&dll_path),
        &sandbox_root,
        &project_root,
        &cwd_str,
        net_guarded,
        hook_trace,
    );

    let session_cfg = ipc::SessionConfig {
        pipe_name: pipe_name.clone(),
        dll_path: dll_path.clone(),
        cwd: fold_published(&cwd_str),
        sandbox_root: fold_published(&sandbox_root.to_string_lossy()),
        overlay_roots: overlay_layout
            .all_roots()
            .map(|(_drive, root)| fold_published(&root.to_string_lossy()))
            .collect(),
        trace: hook_trace,
        guard: match cli.guard {
            GuardLevel::None => ipc::GuardLevel::None,
            GuardLevel::Scan => ipc::GuardLevel::Scan,
            GuardLevel::Full => ipc::GuardLevel::Full,
            GuardLevel::Static => ipc::GuardLevel::Static,
        },
        launcher_pid,
        launcher_create_time,
        allow_rwx: cli.allow_rwx,
        disable_hooks: disable_hooks_effective.clone(),
        folder_section_name,
    };
    let (_session_section, section_name) = winrsbox::contain::session_section::publish(&session_cfg)
        .context("publish session config section")?;
    std::env::set_var("FS_SANDBOX_SECTION", &section_name);

    let init_event = sandbox::launch_prep::create_init_event()?;
    let init_degraded_event = sandbox::launch_prep::create_degraded_event()?;
    let init_error_buffer = sandbox::launch_prep::create_init_error_buffer()?;

    let effective_guard = cli.guard;
    if effective_guard == GuardLevel::Static {
        let trust = winrsbox::contain::trust::verify_signature(std::path::Path::new(&target_args[0]));
        let mitigation_note = if trust.is_trusted() {
            ""
        } else {
            "; JIT and unsigned native extensions (.pyd/.node) will be blocked by mitigation policy"
        };
        if jsonl_log::console_verbose() {
            eprintln!(
                "[sandbox] guard: static (hard containment) — {}{mitigation_note}",
                winrsbox::contain::trust::advisory_notice(&trust)
            );
        }
    }

    sandbox::install_console_ctrl_handler();

    let proc_info = sandbox::launch_suspended(
        &project_root,
        &target_args,
        effective_guard,
        [init_event, init_degraded_event, init_error_buffer.handle()],
    )?;

    root_target_pid.store(proc_info.dwProcessId, Ordering::Release);
    sandbox::proc_table::publish_root_create_time(
        crate::pipe_server::process_create_time_from_handle(proc_info.hProcess),
    );

    if (effective_guard == GuardLevel::Full || effective_guard == GuardLevel::Static)
        && !cli.no_pre_scan
    {
        if let Err(e) = sandbox::inject::pre_launch_scan(
            proc_info.hProcess.0 as usize,
            &target_args[0],
            proc_info.dwProcessId,
            &violations_log,
        ).await {
            // SAFETY: proc_info.hProcess is valid PROCESS handle from CreateProcessW.
            unsafe {
                windows::Win32::System::Threading::TerminateProcess(proc_info.hProcess, 0xC000_0005).ok();
                CloseHandle(proc_info.hThread).ok();
                CloseHandle(proc_info.hProcess).ok();
            }
            eprintln!("pre-launch scan refused target: {e}");
            std::process::exit(0xC000_0005u32 as i32);
        }
    }

    if let Err(e) = sandbox::inject::inject_dll(proc_info.hProcess, proc_info.hThread, &dll_path) {
        // SAFETY: proc_info handles are valid PROCESS/THREAD handles from CreateProcessW.
        unsafe {
            windows::Win32::System::Threading::TerminateProcess(proc_info.hProcess, 0xC000_0005).ok();
            CloseHandle(proc_info.hThread).ok();
            CloseHandle(proc_info.hProcess).ok();
        }
        eprintln!("hook.dll injection failed: {e}");
        std::process::exit(0xC000_0005u32 as i32);
    }

    // MP-0 §1: guest joins the folder job BEFORE the session job below.
    // SAFETY: folder_job is a valid, still-open job handle for the whole
    //         call (broker's own, or a client's duplicated Attach handle).
    unsafe { winrsbox::contain::jobctl::assign_process_to_raw_job(folder_job, proc_info.hProcess) }
        .context("assign guest to folder job")?;

    let job_handle = sandbox::setup_job_object(
        proc_info.hProcess,
        cli.memory_limit,
        cli.strict_clipboard,
        cli.strict_ui,
    )?;

    let _wfp = match winrsbox::contain::wfp::install_outbound_filters(
        net_guarded,
        cli.guard != GuardLevel::None,
        cli.block_localhost,
        std::path::Path::new(&target_args[0]),
    ) {
        winrsbox::contain::wfp::WfpInstall::Installed(engine) => Some(engine),
        winrsbox::contain::wfp::WfpInstall::NotRequested => None,
        winrsbox::contain::wfp::WfpInstall::Refused(reason) => {
            // SAFETY: proc_info handles are valid PROCESS/THREAD handles from CreateProcessW.
            unsafe {
                windows::Win32::System::Threading::TerminateProcess(proc_info.hProcess, 0xC000_0005).ok();
                CloseHandle(proc_info.hThread).ok();
                CloseHandle(proc_info.hProcess).ok();
            }
            eprintln!("guarded network requested but kernel network enforcement could not be installed — refusing launch: {reason}");
            std::process::exit(0xC000_0005u32 as i32);
        }
    };

    let _etw = if cli.guard != GuardLevel::None {
        let proc_info_ref = sandbox::proc_table::global_proc_info();
        let pid_checker: Arc<dyn Fn(u32) -> bool + Send + Sync> = Arc::new(move |pid: u32| {
            proc_info_ref.pin().get(&pid).is_some()
        });
        match winrsbox::observe::etw_listener::start(pid_checker) {
            Ok(h) => {
                if jsonl_log::console_verbose() {
                    println!("[sandbox] ETW: Kernel-Process listener active");
                }
                Some(h)
            }
            Err(e) => {
                if jsonl_log::console_verbose() {
                    eprintln!("[sandbox] ETW unavailable: {e}");
                }
                None
            }
        }
    } else {
        None
    };

    let arg0_lower = target_args.first().map(|s| fold_published(s)).unwrap_or_default();
    sandbox::proc_table::global_proc_info().pin().insert(
        proc_info.dwProcessId,
        sandbox::proc_table::ProcInfo {
            depth: 0,
            exe_lower: Arc::from(arg0_lower.as_str()),
            create_time: crate::pipe_server::process_create_time_from_handle(proc_info.hProcess),
        },
    );

    // SAFETY: proc_info.hThread is valid for the lifetime of the child process;
    //         it was returned by CreateProcessW and has not yet been closed.
    unsafe { ResumeThread(proc_info.hThread) };
    // SAFETY: same — close the thread handle after use; the thread continues running.
    unsafe { CloseHandle(proc_info.hThread).ok() };

    let event_handles_raw = [init_event.0 as usize, init_degraded_event.0 as usize];
    let wait_result = match tokio::task::spawn_blocking(move || unsafe {
        let handles = event_handles_raw.map(|raw| HANDLE(raw as *mut _));
        WaitForMultipleObjects(&handles, false, 5000)
    }).await {
        Ok(wr) => wr,
        Err(e) => {
            // SAFETY: proc_info.hProcess + init_event are valid here.
            unsafe {
                windows::Win32::System::Threading::TerminateProcess(proc_info.hProcess, 0xC000_0005).ok();
                CloseHandle(proc_info.hProcess).ok();
                CloseHandle(init_event).ok();
                CloseHandle(init_degraded_event).ok();
            }
            anyhow::bail!("init-event wait task failed: {e}");
        }
    };

    if wait_result.0 == 0 {
        if jsonl_log::console_verbose() {
            println!("[sandbox] hook.dll init confirmed (pid {})", proc_info.dwProcessId);
        }
        // SAFETY: init_degraded_event is valid and not yet closed.
        let degraded = unsafe { WaitForSingleObject(HANDLE(init_degraded_event.0 as *mut _), 0) };
        if degraded.0 == 0 {
            eprintln!(
                "[sandbox] WARNING: hook.dll initialized DEGRADED (optional component install failures) — details in the sandbox log after the first hooked operation (pid {})",
                proc_info.dwProcessId
            );
        }
    } else {
        let reason = match wait_result.0 {
            1 => format!(
                "hook.dll failed during initialization: {}",
                init_error_buffer.read_message().unwrap_or_else(|| "error detail unavailable".to_string())
            ),
            258 => "hook.dll did not signal init within 5s".to_string(),
            code => format!("hook init wait failed (wait=0x{code:08x})"),
        };
        eprintln!("[sandbox] CRITICAL: {reason}, killing child pid={}", proc_info.dwProcessId);
        unsafe {
            windows::Win32::System::Threading::TerminateProcess(proc_info.hProcess, 0xC000_0005).ok();
            CloseHandle(proc_info.hProcess).ok();
        }
        unsafe { CloseHandle(init_event).ok() };
        unsafe { CloseHandle(init_degraded_event).ok() };
        anyhow::bail!("hook.dll injection failed — child terminated (pid={})", proc_info.dwProcessId);
    }
    unsafe { CloseHandle(init_event).ok() };
    unsafe { CloseHandle(init_degraded_event).ok() };

    if jsonl_log::console_verbose() {
        println!("[sandbox] target started (pid {})", proc_info.dwProcessId);
    }

    let target_isize = proc_info.hProcess.0 as isize;
    tokio::task::spawn_blocking(move || {
        // SAFETY: target_isize is the isize repr of a valid PROCESS_ALL_ACCESS
        //         handle returned by CreateProcessW; INFINITE is correct here.
        unsafe { WaitForSingleObject(HANDLE(target_isize as *mut _), INFINITE) };
    })
    .await
    .unwrap_or_else(|e| eprintln!("[sandbox] target-wait task failed: {e}"));
    let target_handle = proc_info.hProcess;

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    match exit_drain {
        ExitDrain::Broker(child_pids) => sandbox::child_drain::drain_registered_children(&child_pids).await,
        ExitDrain::Client { conn } => {
            sandbox::child_drain::drain_own_job(job_handle).await;
            fetch_session_stats(&conn, &stats).await;
        }
    }

    let mut exit_code = 0u32;
    // SAFETY: target_handle is valid; GetExitCodeProcess fills exit_code on success.
    unsafe { GetExitCodeProcess(target_handle, &mut exit_code).ok() };
    // SAFETY: target_handle — we are done with the process.
    unsafe { CloseHandle(target_handle).ok() };

    let s = &stats;
    let viol = s.violations.load(Ordering::Relaxed);
    let (etw_total, etw_sandbox) = winrsbox::observe::etw_listener::stats();
    if jsonl_log::console_verbose() {
        eprintln!(
            "\n[sandbox] exit={exit_code}  decide={} redirect={} deny={} mock={} cow={} violations={viol} etw={etw_sandbox}/{etw_total}",
            s.decide.load(Ordering::Relaxed),
            s.redirect.load(Ordering::Relaxed),
            s.deny.load(Ordering::Relaxed),
            s.mock_.load(Ordering::Relaxed),
            s.cow.load(Ordering::Relaxed),
        );
    }

    jsonl_log::log_immediate(jsonl_log::Event::exit(exit_code, s.decide.load(Ordering::Relaxed), viol));
    jsonl_log::flush();
    if let Some(f) = hot_stats_flusher {
        f.flush_now();
    }

    Ok(exit_code as i32)
}

/// MP-6: client-role stats fetch — `Req::SessionStats` on the still-open
/// Attach connection, stored into `stats`'s atomics so the exit summary
/// above reads real (folder-wide, see that request's doc) numbers instead
/// of the zeros a client's own never-incremented `Stats` starts at.
/// Best-effort: a failed fetch just leaves the summary at zero — the
/// session already ran to completion, these are diagnostics, not
/// containment, and the process is already tearing down.
async fn fetch_session_stats(conn: &Arc<Mutex<ipc::SyncClient>>, stats: &crate::pipe_server::Stats) {
    let conn = Arc::clone(conn);
    let fetched = tokio::task::spawn_blocking(move || {
        conn.lock().unwrap_or_else(|e| e.into_inner()).send(&ipc::Req::SessionStats)
    })
    .await;
    let Ok(Ok(ipc::Resp::SessionStats { decide, redirect, deny, mock, cow, violations })) = fetched else {
        return;
    };
    stats.decide.store(decide, Ordering::Relaxed);
    stats.redirect.store(redirect, Ordering::Relaxed);
    stats.deny.store(deny, Ordering::Relaxed);
    stats.mock_.store(mock, Ordering::Relaxed);
    stats.cow.store(cow, Ordering::Relaxed);
    stats.violations.store(violations, Ordering::Relaxed);
}

/// MP-6/MP-8: services a launcher's post-Attach connection for the rest of
/// its session — `Req::LauncherLog` (append one already-serialized JSONL
/// line to the broker's own `sandbox.log.jsonl`, forwarded from a client
/// that owns no such file of its own), `Req::SessionStats` (folder-wide
/// decision counters, see that request's doc), and `Req::Ping` (liveness
/// probe — see `docs/multiprocess-broker-plan.md`, "Зависание брокера").
/// Loops until the connection breaks (the launcher exited or disconnected).
/// Every other request is rejected — this is not the guest-facing protocol,
/// and a launcher has no legitimate reason to send one on this connection.
pub(crate) fn run_launcher_session_loop(file: &mut std::fs::File, ctx: &crate::broker::AttachContext) {
    let stats = &ctx.stats;
    loop {
        let req: ipc::Req = match ipc::read_msg(file) {
            Ok(r) => r,
            Err(_) => return,
        };
        let resp = match req {
            ipc::Req::LauncherLog { line } => {
                jsonl_log::append_raw_line(&line);
                ipc::Resp::Ok
            }
            ipc::Req::SessionStats => ipc::Resp::SessionStats {
                decide: stats.decide.load(Ordering::Relaxed),
                redirect: stats.redirect.load(Ordering::Relaxed),
                deny: stats.deny.load(Ordering::Relaxed),
                mock: stats.mock_.load(Ordering::Relaxed),
                cow: stats.cow.load(Ordering::Relaxed),
                violations: stats.violations.load(Ordering::Relaxed),
            },
            ipc::Req::Ping => {
                // MP-8 test seam, debug builds only (compiled out in
                // release): WINRSBOX_TEST_FREEZE_PING_MS artificially delays
                // the Pong so an integration test can exercise the client's
                // Ping-timeout warning against a real (not actually hung)
                // broker process.
                #[cfg(debug_assertions)]
                if let Some(ms) = std::env::var("WINRSBOX_TEST_FREEZE_PING_MS")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    std::thread::sleep(std::time::Duration::from_millis(ms));
                }
                let generation =
                    ctx.folder_section.view().snapshot().map(|s| s.generation).unwrap_or(0);
                ipc::Resp::Pong {
                    broker_pid: ctx.broker_pid,
                    broker_create_time: ctx.broker_create_time,
                    generation,
                }
            }
            _ => ipc::Resp::Err(
                "only LauncherLog/SessionStats/Ping are valid on an Attach connection".into(),
            ),
        };
        if ipc::write_msg(file, &resp).is_err() {
            return;
        }
    }
}
