// MP-7: broker failover and graceful hand-off for the "one broker per
// folder" design (`docs/multiprocess-broker-plan.md`, "Смена брокера
// (failover)"). Runs as a detached background task inside a CLIENT
// launcher process for the rest of that process's life: waits for the
// current broker to die (`WaitForSingleObject` on its process handle, no
// polling), then races every other surviving client to reopen
// `policy.redb` — the SAME election primitive MP-2 uses at startup
// (`broker::resolve_client_role`: whoever opens the db first wins). The
// winner becomes the new broker IN-PROCESS (this client's own guest and
// session keep running, untouched) and rebuilds the folder section +
// `broker.json`; every loser re-`Attach`es to the winner.

use anyhow::{Context, Result};
use policy::Policy;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicU32, Arc, Mutex};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    OpenProcess, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE,
};
use winrsbox::contain::{jobctl, session_section};
use winrsbox::observe::jsonl_log;

use crate::broker::{self, FolderSectionWriter};

/// Backoff between whole-race retries when this process neither won the db
/// lock nor found a verifiable live broker in `broker.json` (stale file, or
/// the winner hasn't published it yet). Distinct from
/// `broker::CLIENT_DB_OPEN_RETRY_INTERVAL`, which paces individual
/// `Database::create` attempts WITHIN one race.
const RACE_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(200);

/// Everything the failover watcher owns/needs for the rest of this
/// process's life. Constructed once by `main::client::run_as_client`
/// immediately after its own `Attach`, then handed to [`spawn_watch`].
pub(crate) struct WatchParams {
    pub(crate) state_dir: PathBuf,
    pub(crate) cfg_path: PathBuf,
    pub(crate) project_root: PathBuf,
    pub(crate) overlay_layout: policy::path::OverlayLayout,
    pub(crate) mock_dirs_root: PathBuf,
    /// Owned exclusively by this watcher from construction on — NOT by the
    /// `AttachedFolder` that originally produced them (see
    /// `AttachedFolder::take_folder_handles`). Reused as-is if this process
    /// stays a client (the folder job/section outlive any one broker, see
    /// the plan's "Folder section и job при смерти брокера"); replaced by a
    /// freshly re-`Attach`ed pair on every successful `reattach_as_client`.
    pub(crate) folder_job_handle: HANDLE,
    pub(crate) folder_section_handle: HANDLE,
    pub(crate) folder_section_name: String,
    pub(crate) own_pid: u32,
    pub(crate) own_create_time: u64,
    pub(crate) current_broker_pid: u32,
    pub(crate) current_broker_create_time: u64,
    /// Swapped in place on every successful re-`Attach` so
    /// `LauncherLog`/`SessionStats` (see `main::session`) keep reaching
    /// whichever broker is currently alive, without the session-tail code
    /// having to know failover happened.
    pub(crate) log_conn: Arc<Mutex<ipc::SyncClient>>,
    pub(crate) stats: Arc<crate::pipe_server::Stats>,
}

// SAFETY: every field is either owned kernel-handle data (handles carry no
//         thread affinity — safe to touch, and to hold a `&WatchParams`
//         across, from any thread) or an already-`Send`/`Sync` type
//         (`Arc<Mutex<_>>`, `PathBuf`, ...). These impls exist only because
//         raw `HANDLE` fields make the struct not auto-`Send`/`Sync`.
unsafe impl Send for WatchParams {}
unsafe impl Sync for WatchParams {}

/// Spawn the detached MP-7 failover watcher. Never joined — it runs for the
/// rest of this process's life (mirrors `broker::spawn_launcher_exit_watch`
/// and the top-level pipe-accept loop: this process's own exit path in
/// `main::session::run_target_session` does not wait on it, and normal
/// process exit tears it down along with everything else).
pub(crate) fn spawn_watch(params: WatchParams) {
    tokio::spawn(watch_loop(params));
}

async fn watch_loop(mut p: WatchParams) {
    loop {
        wait_for_process_death(p.current_broker_pid, p.current_broker_create_time).await;
        match race_for_broker_role(&p).await {
            RaceOutcome::BecameBroker(policy) => {
                become_new_broker(policy, &p).await;
                // Only returns on a fatal pipe-server failure. This
                // session's own guest keeps running regardless — it was
                // already assigned into the folder/session jobs at launch,
                // independent of this task. There's simply no more
                // failover coverage for this folder from THIS process.
                return;
            }
            RaceOutcome::Contested => {
                if !reattach_as_client(&mut p).await {
                    tokio::time::sleep(RACE_RETRY_BACKOFF).await;
                }
                // Loop back to waiting on the (possibly just-updated)
                // current broker either way.
            }
        }
    }
}

/// Block until the process identified by `(pid, create_time)` exits, or
/// return immediately if it's already gone (or was reused by another
/// process under the same pid — the create_time mismatch check, same
/// PID-reuse defence used throughout this crate). No polling: a single
/// `WaitForSingleObject`.
async fn wait_for_process_death(pid: u32, create_time: u64) {
    // SAFETY: pid identifies a process this launcher does not own; opening
    //         it with these two read-only rights is safe to attempt on any
    //         live pid and simply fails (Err) on a dead/inaccessible one.
    let Ok(h) = (unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) })
    else {
        return; // already gone
    };
    if crate::pipe_server::process_create_time_from_handle(h) != create_time {
        // SAFETY: h was just opened above and is closed exactly once here.
        unsafe { CloseHandle(h).ok() };
        return; // pid was reused — the process we cared about already died
    }
    let raw = h.0 as isize;
    let _ = tokio::task::spawn_blocking(move || unsafe {
        WaitForSingleObject(HANDLE(raw as *mut _), INFINITE)
    })
    .await;
    // SAFETY: raw is the isize repr of h, opened above and not yet closed.
    unsafe { CloseHandle(HANDLE(raw as *mut _)).ok() };
}

enum RaceOutcome {
    BecameBroker(Policy),
    /// Either another process opened the db first, or the retry budget was
    /// exhausted without ever verifying a live broker — either way, this
    /// process isn't the broker; try to re-`Attach` to whoever is.
    Contested,
}

/// The MP-7 §5 election: reuses `broker::resolve_client_role` (MP-2's exact
/// decision primitive — "whoever opens `policy.redb` first wins") against
/// the real filesystem/process world, off the async executor
/// (`Database::create` and `OpenProcess` are blocking calls).
async fn race_for_broker_role(p: &WatchParams) -> RaceOutcome {
    let db_path = p.state_dir.join("policy.redb");
    let overlay_layout = p.overlay_layout.clone();
    let mock_dirs_root = p.mock_dirs_root.clone();
    let project_root = p.project_root.clone();
    let broker_json_path = p.state_dir.join(session_section::BROKER_JSON_FILE_NAME);
    tokio::task::spawn_blocking(move || {
        match broker::resolve_client_role(
            broker::CLIENT_DB_OPEN_RETRIES,
            || {
                broker::try_open_policy(
                    &db_path,
                    overlay_layout.clone(),
                    mock_dirs_root.clone(),
                    project_root.clone(),
                )
            },
            || {
                session_section::read_broker_json(&broker_json_path)
                    .ok()
                    .map(|doc| (doc.broker_pid, doc.broker_create_time))
            },
            |pid, create_time| crate::pipe_server::query_process_create_time(pid) == Some(create_time),
            || std::thread::sleep(broker::CLIENT_DB_OPEN_RETRY_INTERVAL),
        ) {
            broker::ClientOutcome::BecameBroker(policy) => RaceOutcome::BecameBroker(policy),
            broker::ClientOutcome::ExistingBroker { .. } | broker::ClientOutcome::Unavailable => {
                RaceOutcome::Contested
            }
        }
    })
    .await
    .unwrap_or(RaceOutcome::Contested)
}

/// Re-`Attach` to whoever currently holds the broker role (via
/// `broker.json`, read fresh by `client_attach` itself) and adopt its
/// identity/handles. Returns `false` on failure (broker.json still stale,
/// new broker not ready yet, ...) — the caller backs off and retries the
/// whole race.
async fn reattach_as_client(p: &mut WatchParams) -> bool {
    let Ok(mut attached) = crate::client::attach_with_retries(&p.state_dir).await else {
        return false;
    };

    *p.log_conn.lock().unwrap_or_else(|e| e.into_inner()) = attached.take_client();

    // The folder job/section handles this task already held remain
    // perfectly valid (same kernel objects, per the plan) — closing them in
    // favour of a fresh Attach-duplicated pair is simply the least special
    // casing: Attach hands out a fresh pair every time regardless, and we'd
    // otherwise have to decide whether to keep or discard it.
    // SAFETY: both handles were exclusively owned by this task (either from
    //         construction or a previous reattach) and are closed exactly
    //         once here, immediately before being replaced below.
    unsafe {
        CloseHandle(p.folder_job_handle).ok();
        CloseHandle(p.folder_section_handle).ok();
    }
    let (job, section) = attached.take_folder_handles();
    p.folder_job_handle = job;
    p.folder_section_handle = section;
    p.current_broker_pid = attached.broker_pid;
    p.current_broker_create_time = attached.broker_create_time;

    jsonl_log::log_immediate(jsonl_log::Event::launcher_diag(
        "INFO",
        format!(
            "MP-7 failover: re-attached to broker pid={} generation={}",
            attached.broker_pid, attached.generation,
        ),
    ));
    true
}

/// Idempotent: a no-op if the legacy C: overlay was already migrated by
/// whichever process first became broker for this folder (or if this
/// project has no C: overlay at all — same conditions `main::run()` checks
/// at a fresh launcher's startup).
fn maybe_complete_c_overlay_migration(policy: &Policy, project_root: &Path) -> Result<()> {
    let Ok(local_appdata) = std::env::var("LOCALAPPDATA") else {
        return Ok(());
    };
    let project_drive = project_root.to_string_lossy().chars().next().map(|c| c.to_ascii_lowercase());
    if project_drive == Some('c') {
        return Ok(());
    }
    let (c_root, legacy) =
        crate::sandbox::prepare_c_overlay_root(Path::new(&local_appdata), project_root)?;
    crate::sandbox::complete_c_overlay_migration(policy, Path::new(&local_appdata), &legacy, &c_root)
}

/// Become the new broker in-process: open the config, run the same
/// (idempotent) C: overlay migration a fresh broker would, rebuild the
/// folder section (§2 — never `set_broker`, see
/// `ipc::FolderSectionView::rebuild`'s doc for why), publish `broker.json`,
/// and serve the folder's pipe forever. Failure anywhere here is logged and
/// swallowed — never escalated into killing this process, which still owns
/// a live sandboxed session that has nothing to do with the failover
/// subsystem failing.
async fn become_new_broker(policy: Policy, p: &WatchParams) {
    if let Err(e) = become_new_broker_inner(policy, p).await {
        jsonl_log::log_immediate(jsonl_log::Event::launcher_diag(
            "ERROR",
            format!("MP-7 failover: could not start as the new broker: {e:#}"),
        ));
    }
}

async fn become_new_broker_inner(policy: Policy, p: &WatchParams) -> Result<()> {
    let policy = Arc::new(policy);
    policy.load_config(&p.cfg_path).context("load_config after failover")?;
    maybe_complete_c_overlay_migration(&policy, &p.project_root).context("C: overlay migration after failover")?;

    let workreg_root = p.cfg_path.parent().context("cfg_path has no parent")?.join("workreg");
    std::fs::create_dir_all(&workreg_root).context("create workreg dir")?;
    let reg_policy = Arc::new(
        policy::RegistryPolicy::open(policy.db(), workreg_root).context("open RegistryPolicy")?,
    );

    // Random name (MP-10 §A), same as a fresh (non-failover) broker startup:
    // the failover winner is exactly the case the random name defends —
    // a guest could otherwise pre-create `fs-sandbox-<broker_pid>` while
    // waiting for the race to resolve and win `FILE_FLAG_FIRST_PIPE_INSTANCE`
    // ahead of the real winner.
    let new_pipe_name = session_section::random_pipe_name().context("generate broker pipe name")?;

    // SAFETY: both handles were duplicated into this process by an Attach
    //         response and handed to this watcher exclusively (see
    //         `WatchParams`'s doc) — never shared with anything else that
    //         might close or reuse them.
    let folder_job = Arc::new(unsafe { jobctl::FolderJob::from_raw_owned(p.folder_job_handle) });
    let folder_section = session_section::FolderSection::from_duplicated_handle(p.folder_section_handle)
        .context("wrap duplicated folder section handle")?;

    // §2: launcher set starts at "empty + self" — stale (pid, create_time)
    // entries inherited from the dead broker's own bookkeeping aren't
    // independently verifiable as still-live launchers by this process;
    // every surviving client re-Attaches on its own and gets re-added
    // through the normal `try_complete_attach` path, same as a first Attach.
    folder_section
        .view()
        .rebuild(p.own_pid, p.own_create_time, &new_pipe_name, &[(p.own_pid, p.own_create_time)])
        .context("rebuild folder section")?;
    let generation = folder_section.view().snapshot().map(|s| s.generation).unwrap_or(0);

    session_section::write_broker_json(
        &p.state_dir.join(session_section::BROKER_JSON_FILE_NAME),
        &session_section::BrokerJson {
            version: session_section::BROKER_JSON_VERSION,
            broker_pid: p.own_pid,
            broker_create_time: p.own_create_time,
            pipe_name: new_pipe_name.clone(),
            folder_section_name: p.folder_section_name.clone(),
            generation,
        },
    )
    .context("write broker.json")?;

    jsonl_log::log_immediate(jsonl_log::Event::launcher_diag(
        "INFO",
        format!(
            "MP-7 failover: became broker (pid={}, pipe={new_pipe_name}, generation={generation})",
            p.own_pid
        ),
    ));

    let folder_section_writer = Arc::new(FolderSectionWriter::new(folder_section));
    let attach_ctx = broker::AttachContext {
        folder_section: Arc::clone(&folder_section_writer),
        folder_section_name: p.folder_section_name.clone(),
        broker_pid: p.own_pid,
        broker_create_time: p.own_create_time,
        pipe_name: new_pipe_name.clone(),
        policy: Arc::clone(&policy),
        stats: Arc::clone(&p.stats),
    };

    let child_pids: Arc<crossbeam_queue::SegQueue<u32>> = Arc::new(crossbeam_queue::SegQueue::new());
    let cfg_dir = p.cfg_path.parent().context("cfg_path has no parent")?;
    let violations_log = cfg_dir.join("violations.log");
    let hot_stats = winrsbox::observe::hot_stats::HotStats::new();
    let flusher = Arc::new(winrsbox::observe::hot_stats::ThrottledFlusher::new(
        Arc::clone(&hot_stats),
        cfg_dir.join("hot-stats.json"),
    ));

    crate::pipe_server::pipe_accept_loop(
        &new_pipe_name,
        policy,
        reg_policy,
        Arc::clone(&p.stats),
        child_pids,
        violations_log,
        hot_stats,
        flusher,
        // folder_job admission (MP-4) decides membership; no root-pid
        // tracking is needed for a failover-started broker.
        Arc::new(AtomicU32::new(0)),
        Some(folder_job),
        Some(attach_ctx),
    )
    .await
    .context("new-broker pipe accept loop ended")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// MP-7 §5: two clients racing to become the new broker after the old
    /// one dies must never BOTH win. Uses the SAME pure decision primitive
    /// (`broker::resolve_client_role`) `race_for_broker_role` drives inside
    /// `spawn_blocking` — `db_lock` stands in for `Database::create`'s
    /// exclusive OS file lock (a real `redb::Database::create` on a live
    /// path IS mutually exclusive the same way, per MP-0 §5).
    #[test]
    fn only_one_of_two_racing_clients_becomes_broker() {
        let db_lock = AtomicBool::new(false);
        let try_open =
            || db_lock.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok().then_some(());

        let outcome_a = broker::resolve_client_role(1, try_open, || None, |_, _| false, || {});
        let outcome_b = broker::resolve_client_role(1, try_open, || None, |_, _| false, || {});

        let a_won = matches!(outcome_a, broker::ClientOutcome::BecameBroker(_));
        let b_won = matches!(outcome_b, broker::ClientOutcome::BecameBroker(_));
        assert!(a_won ^ b_won, "exactly one racer must win, got a_won={a_won} b_won={b_won}");
        assert!(db_lock.load(Ordering::SeqCst));
    }

    /// A client that verifies a live broker via `broker.json` (the "someone
    /// else already won and published" case) must recognize it on the
    /// FIRST check, without burning its retry budget.
    #[test]
    fn loser_recognizes_the_new_broker_from_broker_json_immediately() {
        let sleeps = std::cell::Cell::new(0u32);
        let outcome = broker::resolve_client_role(
            5,
            || None::<()>,
            || Some((4242, 99)),
            |pid, create_time| pid == 4242 && create_time == 99,
            || sleeps.set(sleeps.get() + 1),
        );
        assert!(matches!(outcome, broker::ClientOutcome::ExistingBroker { pid: 4242 }));
        assert_eq!(sleeps.get(), 0, "a verified live broker must stop the race on the first check");
    }

    /// Neither a winnable db lock nor a verifiable live broker: the race
    /// exhausts its budget and reports `Unavailable` — `race_for_broker_role`
    /// maps this to `RaceOutcome::Contested`, same as `ExistingBroker`, so
    /// the watcher backs off and retries the whole thing rather than
    /// spinning forever inside one race.
    #[test]
    fn race_gives_up_after_the_retry_budget_when_nothing_is_verifiable() {
        let attempts = std::cell::Cell::new(0u32);
        let outcome = broker::resolve_client_role(
            3,
            || None::<()>,
            || None,
            |_, _| false,
            || attempts.set(attempts.get() + 1),
        );
        assert!(matches!(outcome, broker::ClientOutcome::Unavailable));
        assert_eq!(attempts.get(), 2, "sleeps between attempts, none after the last one");
    }
}
