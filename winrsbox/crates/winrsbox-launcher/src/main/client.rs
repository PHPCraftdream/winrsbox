// MP-6: the client-role launcher path — a second (or third, ...) `winrsbox`
// started in a folder whose `policy.redb` is already held by a live broker
// (`main::broker::Role::Client`). Unlike MP-2/MP-3, this process now runs a
// real session instead of a smoke test: it never opens the database, never
// runs `load_config`/the C: overlay migration, and never starts a pipe
// server — every value it needs for the shared session tail
// (`main::session::run_target_session`) comes from `Attach`'s response
// (`main::broker::AttachedFolder`) or from path-only computation the DB
// plays no part in (see `docs/multiprocess-broker-plan.md`, MP-6).

use anyhow::Result;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use winrsbox::cli;
use winrsbox::observe::jsonl_log;

use crate::{broker, failover, session, Cli};

/// MP-8: interval between steady-state `Ping`s, and the per-ping deadline —
/// see `docs/multiprocess-broker-plan.md`, "Зависание брокера". A timed-out
/// Ping is a WARNING only, never an automatic kill: the broker owns the
/// user's terminal and a "hang" may be legitimate long work; `winrsbox
/// broker restart` is the explicit remedy.
const PING_INTERVAL: Duration = Duration::from_secs(5);
const PING_TIMEOUT: Duration = Duration::from_secs(2);

/// Spawns the detached MP-8 Ping loop: pings immediately (right after
/// `Attach`), then every `PING_INTERVAL`, sharing `log_conn` with
/// `LauncherLog`/`SessionStats` — the shared `Mutex` naturally serializes
/// them onto the SAME request/response state machine on one connection
/// (see `main::session::run_launcher_session_loop`), never lets a Ping race
/// a log line. `log_conn`'s inner `SyncClient` is swapped in place on
/// failover (`main::failover::reattach_as_client`), so this loop keeps
/// pinging whichever broker is currently alive without knowing failover
/// happened. Runs for the rest of this process's life — mirrors
/// `failover::spawn_watch`.
pub(crate) fn spawn_ping_loop(log_conn: Arc<Mutex<ipc::SyncClient>>) {
    tokio::spawn(async move {
        loop {
            let conn = Arc::clone(&log_conn);
            let result = tokio::task::spawn_blocking(move || {
                conn.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .send_with_timeout(&ipc::Req::Ping, PING_TIMEOUT)
            })
            .await;
            match result {
                Ok(Ok(ipc::Resp::Pong { .. })) => {}
                Ok(Ok(other)) => {
                    let msg = format!("broker answered Ping with an unexpected response: {other:?}");
                    eprintln!("[sandbox] WARNING: {msg}");
                    jsonl_log::log(jsonl_log::Event::launcher_diag("WARN", msg));
                }
                Ok(Err(e)) => {
                    let msg = format!("broker did not answer Ping within {PING_TIMEOUT:?}: {e}");
                    eprintln!("[sandbox] WARNING: {msg}");
                    jsonl_log::log(jsonl_log::Event::launcher_diag("WARN", msg));
                }
                Err(e) => {
                    // The blocking task itself panicked — log and keep
                    // looping; a single bad ping must not stop future ones.
                    eprintln!("[sandbox] WARNING: Ping task failed: {e}");
                }
            }
            tokio::time::sleep(PING_INTERVAL).await;
        }
    });
}

/// Attempts `Attach` with a short retry budget — the same one MP-2's role
/// decision uses (`broker::CLIENT_DB_OPEN_RETRIES` × `..._RETRY_INTERVAL`,
/// 10 × 30 ms): covers the narrow window where the broker this process just
/// discovered via `broker.json` is mid-failover (its `policy.redb` lock was
/// released but the new broker hasn't republished the folder section /
/// `broker.json` yet) rather than genuinely unavailable. `EXIT_CONFLICT`
/// (unchanged exit code, `cli::EXIT_CONFLICT`) is now reserved for exactly
/// that — retries exhausted and no broker ever answered `Attach` — not for
/// "a second launcher exists", which is the whole point of this module.
pub(crate) async fn attach_with_retries(state_dir: &std::path::Path) -> Result<broker::AttachedFolder> {
    let mut last_err = None;
    for attempt in 0..broker::CLIENT_DB_OPEN_RETRIES {
        match broker::client_attach(state_dir) {
            Ok(attached) => return Ok(attached),
            Err(e) => {
                last_err = Some(e);
                if attempt + 1 < broker::CLIENT_DB_OPEN_RETRIES {
                    tokio::time::sleep(broker::CLIENT_DB_OPEN_RETRY_INTERVAL).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Attach retries exhausted")))
}

/// Runs this process as a folder client: `Attach` to the broker, build the
/// same `SessionConfig` inputs the broker would (minus anything DB-backed),
/// and hand off to the shared session tail. Never returns on the
/// `EXIT_CONFLICT` path (calls `std::process::exit` directly, matching the
/// pre-MP-6 smoke-test behaviour this replaces); returns the target's real
/// exit code on a normal session.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_as_client(
    cli_args: Cli,
    project_root: PathBuf,
    sandbox_root: PathBuf,
    cfg_path: PathBuf,
    state_dir: PathBuf,
    target_args: Vec<String>,
    overlay_layout: policy::path::OverlayLayout,
    mock_dirs_root: PathBuf,
    broker_pid: Option<u32>,
) -> Result<i32> {
    let mut attached = match attach_with_retries(&state_dir).await {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {}", broker::client_conflict_message(broker_pid));
            eprintln!("note: last Attach error: {e:#}");
            std::process::exit(cli::EXIT_CONFLICT);
        }
    };

    let own_pid = std::process::id();
    let own_create_time = crate::pipe_server::query_process_create_time(own_pid)
        .ok_or_else(|| anyhow::anyhow!("own creation time unavailable"))?;

    // Same ktav read the broker does (main/mod.rs) — file-only, no DB.
    let ktav_cfg: Option<policy::db::Config> = std::fs::read_to_string(&cfg_path)
        .ok()
        .and_then(|src| ktav::from_str::<policy::db::Config>(&src).ok());
    let ktav_log_level = ktav_cfg.as_ref().and_then(|c| c.log_level.clone());
    // MP-6 deviation (see plan doc): the broker's net_guarded ALSO checks
    // its live policy DB for configured net rules; a client has no DB
    // handle, so it uses `attached.has_net_rules` — a snapshot taken once
    // at Attach time instead of a live read. Narrower staleness window than
    // the rest of what Attach hands out (ktav/CLI flags are always live).
    let net_guarded = ktav_cfg.as_ref().map(|c| c.network_guarded()).unwrap_or(false)
        || cli_args.block_localhost
        || attached.has_net_rules;
    let effective_log_level = if cli_args.trace {
        "trace".to_string()
    } else {
        cli_args.log_level.clone().or(ktav_log_level).unwrap_or_else(|| "info".to_string())
    };

    // MP-6: this process owns no sandbox.log.jsonl — every event is
    // forwarded to the broker over the SAME connection Attach round-tripped
    // on, kept open for the rest of the session (see `AttachedFolder`'s
    // doc). `take_client` moves the connection out through `&mut self`
    // (`AttachedFolder` implements `Drop`, so its field can't be moved out
    // directly) — the two HANDLE fields `AttachedFolder::drop` touches are
    // untouched and read again below.
    let log_conn: Arc<Mutex<ipc::SyncClient>> = Arc::new(Mutex::new(attached.take_client()));
    {
        let sender_conn = Arc::clone(&log_conn);
        jsonl_log::init_remote(
            move |line| {
                let mut c = sender_conn.lock().unwrap_or_else(|e| e.into_inner());
                // Best-effort: a dead connection here means the session is
                // already ending one way or another; nothing to recover to.
                let _ = c.send(&ipc::Req::LauncherLog { line });
            },
            &effective_log_level,
        );
    }
    jsonl_log::set_console_log(cli_args.verbose || cli_args.trace);
    // Forwarded to the broker's own sandbox.log.jsonl (via init_remote
    // above) — useful for correlating a client session with the broker
    // instance/generation it actually attached to (failover diagnostics).
    jsonl_log::log(jsonl_log::Event::launcher_diag(
        "INFO",
        format!(
            "attached to broker pid={} (created {:#x}), generation={}",
            attached.broker_pid, attached.broker_create_time, attached.generation,
        ),
    ));

    let violations_log = cfg_path.parent().unwrap_or(&state_dir).join("violations.log");
    let stats = Arc::new(crate::pipe_server::Stats::default());

    // MP-7: hand the folder job/section handles off to the failover
    // watcher — it must own them for the rest of THIS PROCESS's life, not
    // just until `attached` goes out of scope at the end of this function
    // (the watcher runs independently of this function's own `.await` on
    // `run_target_session` below). `attached.folder_job_handle` stays
    // readable afterward (Copy) — SessionParams below uses it unchanged.
    let (folder_job_handle, folder_section_handle) = attached.take_folder_handles();
    failover::spawn_watch(failover::WatchParams {
        state_dir: state_dir.clone(),
        cfg_path: cfg_path.clone(),
        project_root: project_root.clone(),
        overlay_layout: overlay_layout.clone(),
        mock_dirs_root,
        folder_job_handle,
        folder_section_handle,
        folder_section_name: attached.folder_section_name.clone(),
        own_pid,
        own_create_time,
        current_broker_pid: attached.broker_pid,
        current_broker_create_time: attached.broker_create_time,
        log_conn: Arc::clone(&log_conn),
        stats: Arc::clone(&stats),
    });
    spawn_ping_loop(Arc::clone(&log_conn));

    let params = session::SessionParams {
        cli: &cli_args,
        project_root,
        sandbox_root,
        target_args,
        violations_log,
        pipe_name: attached.pipe_name.clone(),
        overlay_layout,
        folder_section_name: attached.folder_section_name.clone(),
        net_guarded,
        effective_log_level,
        launcher_pid: own_pid,
        launcher_create_time: own_create_time,
        folder_job: attached.folder_job_handle,
        // No pipe server of our own — nothing ever reads this back.
        root_target_pid: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        stats,
        exit_drain: session::ExitDrain::Client { conn: log_conn },
        hot_stats_flusher: None,
    };
    // `attached` (RAII: folder_job_handle, folder_section_handle) stays
    // alive across this whole `.await` — dropped only when this function
    // returns, well after the guest has been assigned into the folder job.
    let exit_code = session::run_target_session(params).await?;
    drop(attached);
    Ok(exit_code)
}
