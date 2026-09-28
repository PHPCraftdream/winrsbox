// MP-2/MP-3: broker/client role selection for the "one broker per state-dir
// folder" design (`docs/multiprocess-broker-plan.md`). Whoever wins
// `Policy::open_or_create_with_layout`'s exclusive `redb::Database::create`
// lock is the broker for this folder; everyone else is a client. This
// module decides the role, owns `Attach` (client identity verification +
// handle duplication), and (MP-6) keeps the Attach connection open for the
// rest of a client's session — `main::client::run_as_client` drives the
// actual client-role session using `AttachedFolder`'s handles/connection
// from here.
//
// Also owns the broker-only folder objects: the folder Job Object
// (`contain::jobctl::FolderJob`, kernel-truth guest membership) and the
// folder section (`contain::session_section::FolderSection`, current pipe
// name shared with every launcher in this state dir) plus `broker.json`.

use anyhow::{anyhow, Context, Result};
use policy::Policy;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use windows::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_CLOSE_SOURCE, HANDLE};
use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows::Win32::System::Threading::{GetCurrentProcess, WaitForSingleObject, INFINITE};
use winrsbox::contain::{jobctl, session_section};

/// Retry budget for re-attempting `Database::create` when the DB is locked
/// but `broker.json` does not (yet, or any more) identify a live broker —
/// e.g. the previous broker just crashed. MP-0 measured redb's recovery
/// after `TerminateProcess`ing the lock owner at 7-12 ms, first attempt —
/// this budget (up to 10 * 30 ms = 300 ms) is generous relative to that.
pub(crate) const CLIENT_DB_OPEN_RETRIES: u32 = 10;
pub(crate) const CLIENT_DB_OPEN_RETRY_INTERVAL: Duration = Duration::from_millis(30);

/// This process's role for the folder, decided by [`open_policy_or_decide_role`].
pub(crate) enum Role {
    /// Opened `policy.redb` (first try or after the previous owner died
    /// mid-retry) — this process runs the existing single-process path.
    Broker(Policy),
    /// `policy.redb` is held by another, live process. `broker_pid` is
    /// `Some` when a valid, verified `broker.json` identified it, `None`
    /// when retries were exhausted without ever finding one (db still
    /// locked by *someone*, but we couldn't name them).
    Client { broker_pid: Option<u32> },
}

/// `true` iff `err` is exactly the "another process already holds this
/// database open" outcome — the MP-2 role-selection signal. Any other
/// `PolicyError` (corrupt db, io error, ...) is not a role decision and
/// must propagate as before.
pub(crate) fn is_database_already_open(err: &policy::PolicyError) -> bool {
    matches!(
        err,
        policy::PolicyError::DbOpen(redb::DatabaseError::DatabaseAlreadyOpen)
    )
}

/// Outcome of [`resolve_client_role`]'s retry loop.
pub(crate) enum ClientOutcome<T> {
    /// A `try_open` attempt succeeded — the previous broker's lock was
    /// released (crash/exit) during the retry window and this process is
    /// now the new broker.
    BecameBroker(T),
    /// `broker_alive` verified a live broker from `read_broker_json`.
    ExistingBroker { pid: u32 },
    /// Retries exhausted; no `try_open` ever succeeded and no verified live
    /// broker was ever found.
    Unavailable,
}

/// Attempt `Policy::open_or_create_with_layout` and collapse any error to
/// `None` — the shape [`resolve_client_role`]'s `try_open` closure needs.
/// Shared by the initial MP-2 role decision below and MP-7's failover race
/// (`main::failover::race_for_broker_role`), which retries this exact call
/// against the SAME db/layout/roots after the previous broker dies.
pub(crate) fn try_open_policy(
    db_path: &Path,
    overlay_layout: policy::path::OverlayLayout,
    mock_dirs_root: PathBuf,
    project_root: PathBuf,
) -> Option<Policy> {
    Policy::open_or_create_with_layout(db_path, overlay_layout, mock_dirs_root, project_root).ok()
}

/// Pure decision loop (dependency-injected — no real process/DB access),
/// unit-testable without spawning anything.
///
/// Each iteration: attempt to open the db (`try_open`); on success, this
/// process is the new broker. Otherwise read `broker.json` and, if present,
/// verify the identified process is still alive with a matching
/// `create_time` (`broker_alive` — PID-reuse safe); if verified, a live
/// broker exists and there is nothing to gain from further retries. Only
/// when neither happened does the loop sleep and retry — this covers the
/// narrow window where the previous broker crashed and the OS is still
/// releasing the file lock (MP-0: ~7-12 ms) or its `broker.json` is stale.
pub(crate) fn resolve_client_role<T>(
    max_attempts: u32,
    mut try_open: impl FnMut() -> Option<T>,
    mut read_broker_json: impl FnMut() -> Option<(u32, u64)>,
    broker_alive: impl Fn(u32, u64) -> bool,
    mut sleep: impl FnMut(),
) -> ClientOutcome<T> {
    for attempt in 0..max_attempts {
        if let Some(opened) = try_open() {
            return ClientOutcome::BecameBroker(opened);
        }
        if let Some((pid, create_time)) = read_broker_json() {
            if broker_alive(pid, create_time) {
                return ClientOutcome::ExistingBroker { pid };
            }
        }
        if attempt + 1 < max_attempts {
            sleep();
        }
    }
    ClientOutcome::Unavailable
}

/// Real (non-test) role decision: attempt to open `policy.redb`; on
/// `DatabaseAlreadyOpen`, resolve via [`resolve_client_role`] against the
/// real filesystem/process world. Any other open error propagates as
/// before MP-2 (unchanged behavior).
pub(crate) fn open_policy_or_decide_role(
    db_path: &Path,
    overlay_layout: policy::path::OverlayLayout,
    mock_dirs_root: PathBuf,
    project_root: PathBuf,
    state_dir: &Path,
) -> Result<Role> {
    match Policy::open_or_create_with_layout(
        db_path,
        overlay_layout.clone(),
        mock_dirs_root.clone(),
        project_root.clone(),
    ) {
        Ok(policy) => Ok(Role::Broker(policy)),
        Err(e) if is_database_already_open(&e) => {
            let broker_json_path = state_dir.join(session_section::BROKER_JSON_FILE_NAME);
            let outcome = resolve_client_role(
                CLIENT_DB_OPEN_RETRIES,
                || {
                    try_open_policy(
                        db_path,
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
                |pid, create_time| {
                    super::pipe_server::query_process_create_time(pid) == Some(create_time)
                },
                || std::thread::sleep(CLIENT_DB_OPEN_RETRY_INTERVAL),
            );
            Ok(match outcome {
                ClientOutcome::BecameBroker(policy) => Role::Broker(policy),
                ClientOutcome::ExistingBroker { pid } => Role::Client { broker_pid: Some(pid) },
                ClientOutcome::Unavailable => Role::Client { broker_pid: None },
            })
        }
        Err(e) => Err(e.into()),
    }
}

/// Stderr message for the client-exit path. `broker_pid` is `None` when
/// retries were exhausted without ever verifying a live broker (db still
/// locked, identity unknown).
pub(crate) fn client_conflict_message(broker_pid: Option<u32>) -> String {
    match broker_pid {
        Some(pid) => format!(
            "winrsbox is already running in this folder (broker pid {pid}); \
             connecting a second session is not implemented yet"
        ),
        None => "winrsbox is already running in this folder (policy.redb is locked, \
             broker process could not be identified); connecting a second \
             session is not implemented yet"
            .to_string(),
    }
}

// ─── Broker-only folder objects (job + section + broker.json) ─────────────

/// The folder-scoped objects a broker owns for its whole lifetime: the
/// folder Job Object (kernel-truth guest membership across every launcher
/// in this state dir) and the folder section (current pipe name, published
/// to every launcher/guest). Both handles MUST stay alive for as long as
/// this process is the broker — dropping either tears down the kernel
/// object immediately.
pub(crate) struct BrokerFolderState {
    pub(crate) folder_job: jobctl::FolderJob,
    pub(crate) folder_section: FolderSectionWriter,
    pub(crate) folder_section_name: String,
}

/// Create the folder job + folder section, initialize the section with this
/// broker's identity and pipe name, and write `broker.json` into
/// `state_dir` (atomically — see `write_broker_json`). Called once, right
/// after this process wins the broker role and before publishing the
/// per-session config section (so `SessionConfig::folder_section_name` can
/// be populated from the result).
pub(crate) fn setup_broker_folder(
    state_dir: &Path,
    pipe_name: &str,
    broker_pid: u32,
    broker_create_time: u64,
) -> Result<BrokerFolderState> {
    let folder_job = jobctl::FolderJob::create().context("create folder job")?;
    let (folder_section, folder_section_name) =
        session_section::FolderSection::create().context("create folder section")?;
    folder_section
        .view()
        .init(broker_pid, broker_create_time, pipe_name)
        .context("init folder section")?;

    let broker_json = session_section::BrokerJson {
        version: session_section::BROKER_JSON_VERSION,
        broker_pid,
        broker_create_time,
        pipe_name: pipe_name.to_string(),
        folder_section_name: folder_section_name.clone(),
        generation: 0,
    };
    session_section::write_broker_json(
        &state_dir.join(session_section::BROKER_JSON_FILE_NAME),
        &broker_json,
    )
    .context("write broker.json")?;

    Ok(BrokerFolderState {
        folder_job,
        folder_section: FolderSectionWriter::new(folder_section),
        folder_section_name,
    })
}

// ─── MP-3: Attach ───────────────────────────────────────────────────────────

/// Serializes writes to the broker's folder section (`add_launcher`/
/// `remove_launcher`) across every concurrently-handled `Attach` and
/// launcher-exit — the section's own single-writer contract
/// (`ipc::FolderSectionView`'s doc) requires exactly one writer at a time,
/// while the accept pool runs many connection handlers concurrently.
pub(crate) struct FolderSectionWriter {
    section: session_section::FolderSection,
    write_lock: Mutex<()>,
}

impl FolderSectionWriter {
    pub(crate) fn new(section: session_section::FolderSection) -> Self {
        Self { section, write_lock: Mutex::new(()) }
    }

    pub(crate) fn view(&self) -> ipc::FolderSectionView {
        self.section.view()
    }

    pub(crate) fn add_launcher(&self, pid: u32, create_time: u64) -> Result<(), ipc::FolderSectionError> {
        let _g = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.section.view().add_launcher(pid, create_time)
    }

    pub(crate) fn remove_launcher(&self, pid: u32, create_time: u64) -> bool {
        let _g = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.section.view().remove_launcher(pid, create_time)
    }

    pub(crate) fn duplicate_into(&self, target: HANDLE, access: u32) -> Result<HANDLE> {
        self.section.duplicate_into(target, access)
    }
}

/// Everything a connection handler needs to complete an `Attach`, shared
/// (cheaply cloned — one Arc, two ints, two strings) across every accept-pool
/// worker.
#[derive(Clone)]
pub(crate) struct AttachContext {
    pub(crate) folder_section: Arc<FolderSectionWriter>,
    pub(crate) folder_section_name: String,
    pub(crate) broker_pid: u32,
    pub(crate) broker_create_time: u64,
    pub(crate) pipe_name: String,
    /// MP-6: read once per Attach (cheap DB read) so the response can hand
    /// the client a `has_net_rules` snapshot — see `ipc::Resp::Attached`.
    pub(crate) policy: Arc<Policy>,
    /// MP-6: the broker's own decision counters, shared with `pipe_server`
    /// (same `Arc`) — read (never written) by `Req::SessionStats` on the
    /// post-Attach session loop. See `main::session::run_launcher_session_loop`.
    pub(crate) stats: Arc<crate::pipe_server::Stats>,
}

/// Handles exactly one connection that failed the normal job-membership
/// admission check: reads exactly one request, and — only if it is
/// `Attach` — authenticates it (kernel-truth: PID, create_time, NOT a member
/// of the folder job, matching token SID, matching image path; see
/// `pipe_server::security::authenticate_attach_client`) and, on success,
/// duplicates the folder job + folder section handles into the caller and
/// registers it as a trusted launcher. Any other message, or any failure at
/// any step (auth, duplication, `add_launcher`, the response write), is a
/// full rejection: nothing partial survives (handles already placed in the
/// client are rolled back via `DuplicateHandle(DUPLICATE_CLOSE_SOURCE)`).
/// Returns whether the client is now attached.
#[cfg(test)]
pub(crate) fn handle_attach_connection(
    conn: HANDLE,
    client_pid: u32,
    folder_job: &jobctl::FolderJob,
    ctx: &AttachContext,
) -> bool {
    crate::pipe_server::mutate::handle_preadmission_connection(
        conn, client_pid, folder_job, Some(ctx), None, None,
    )
}

/// Duplicates the folder job + folder section into `client_process`,
/// registers `(launcher_pid, launcher_create_time)` in the trusted set,
/// writes `Resp::Attached`, and — only once every step succeeded — starts the
/// background exit watch that removes the launcher when it dies. Any failure
/// rolls back everything already done to `client_process`/the folder section.
/// `client_process` stays open on both outcomes: the caller closes it on
/// `false`, the exit watch owns and closes it on `true`.
pub(crate) fn try_complete_attach(
    client_process: HANDLE,
    launcher_pid: u32,
    launcher_create_time: u64,
    folder_job: &jobctl::FolderJob,
    ctx: &AttachContext,
    file: &mut std::fs::File,
) -> bool {
    let Ok(dup_job) = folder_job.duplicate_into(client_process, jobctl::FOLDER_JOB_CLIENT_ACCESS) else {
        return false;
    };
    let Ok(dup_section) =
        ctx.folder_section.duplicate_into(client_process, session_section::FOLDER_SECTION_RW_ACCESS)
    else {
        close_remote_handle(client_process, dup_job);
        return false;
    };
    if ctx.folder_section.add_launcher(launcher_pid, launcher_create_time).is_err() {
        close_remote_handle(client_process, dup_job);
        close_remote_handle(client_process, dup_section);
        return false;
    }
    let Ok(generation) = ctx.folder_section.view().snapshot().map(|s| s.generation) else {
        ctx.folder_section.remove_launcher(launcher_pid, launcher_create_time);
        close_remote_handle(client_process, dup_job);
        close_remote_handle(client_process, dup_section);
        return false;
    };
    let has_net_rules = policy::db::net_rule_list(&ctx.policy.db())
        .map(|r| !r.is_empty())
        .unwrap_or(false);
    let resp = ipc::Resp::Attached {
        folder_job_handle: dup_job.0 as u64,
        folder_section_handle: dup_section.0 as u64,
        folder_section_name: ctx.folder_section_name.clone(),
        broker_pid: ctx.broker_pid,
        broker_create_time: ctx.broker_create_time,
        pipe_name: ctx.pipe_name.clone(),
        generation,
        has_net_rules,
    };
    if ipc::write_msg(file, &resp).is_err() {
        ctx.folder_section.remove_launcher(launcher_pid, launcher_create_time);
        close_remote_handle(client_process, dup_job);
        close_remote_handle(client_process, dup_section);
        return false;
    }
    spawn_launcher_exit_watch(client_process, launcher_pid, launcher_create_time, Arc::clone(&ctx.folder_section));
    true
}

/// Closes a handle that was ALREADY duplicated into `target`'s handle
/// table (partial success is not allowed here — if the second of two
/// duplications fails, the first must be undone in the CLIENT's own address
/// space, not just ours). Standard remote-close technique: duplicate the
/// handle-to-close FROM `target` INTO our own process with
/// `DUPLICATE_CLOSE_SOURCE` — this closes the value in `target` and hands us
/// a fresh local handle, which we close ourselves. Best-effort: failure here
/// just leaks one handle in a process whose Attach is being rejected anyway,
/// never escalated.
fn close_remote_handle(target: HANDLE, remote: HANDLE) {
    let mut local = HANDLE::default();
    // SAFETY: target is the caller's still-open, valid process handle
    //         (PROCESS_DUP_HANDLE granted via ATTACH_CLIENT_ACCESS); remote
    //         is a handle value known to be live in target's handle table
    //         (just duplicated there by us, above).
    let ok = unsafe {
        DuplicateHandle(target, remote, GetCurrentProcess(), &mut local, 0, false, DUPLICATE_CLOSE_SOURCE)
    };
    if ok.is_ok() {
        // SAFETY: local was just produced by the duplication above.
        unsafe { CloseHandle(local).ok() };
    }
}

/// Detached background task: waits for the newly attached launcher process
/// to exit, then removes it from the trusted-launcher set. Takes ownership of
/// `client_process` (opened with SYNCHRONIZE via `ATTACH_CLIENT_ACCESS`) and
/// closes it when done.
fn spawn_launcher_exit_watch(
    client_process: HANDLE,
    pid: u32,
    create_time: u64,
    folder_section: Arc<FolderSectionWriter>,
) {
    let raw = client_process.0 as isize;
    tokio::spawn(async move {
        // SAFETY: raw is the isize repr of a valid process handle with
        //         SYNCHRONIZE access, owned by this task from here on.
        let _ = tokio::task::spawn_blocking(move || unsafe {
            WaitForSingleObject(HANDLE(raw as *mut _), INFINITE)
        })
        .await;
        folder_section.remove_launcher(pid, create_time);
        // SAFETY: raw was opened by authenticate_attach_client and is
        //         closed exactly once here.
        unsafe { CloseHandle(HANDLE(raw as *mut _)).ok() };
    });
}

// ─── MP-3: launcher-side client — connect and Attach ───────────────────────

/// RAII owner of the folder job + folder section handles the broker
/// duplicated into THIS process's address space during `Attach`. Closed on
/// drop; both handles are meaningless once that happens.
pub(crate) struct AttachedFolder {
    pub(crate) folder_job_handle: HANDLE,
    pub(crate) folder_section_handle: HANDLE,
    pub(crate) folder_section_name: String,
    pub(crate) broker_pid: u32,
    pub(crate) broker_create_time: u64,
    pub(crate) pipe_name: String,
    pub(crate) generation: u64,
    pub(crate) has_net_rules: bool,
    /// MP-6: the SAME connection `Attach` round-tripped on, kept open for
    /// the client's whole session — `LauncherLog`/`SessionStats` reuse it
    /// (see `main::client`) instead of opening a second connection, which
    /// would fail the normal job-admission check just like this one did
    /// before Attach authenticated it. `Option` (not a bare `SyncClient`)
    /// solely so [`AttachedFolder::take_client`] can move it out through a
    /// `&mut self` method — `AttachedFolder` implements `Drop`, so a plain
    /// field can never be moved out of it directly (E0509).
    client: Option<ipc::SyncClient>,
    /// MP-7: set once [`take_folder_handles`](Self::take_folder_handles) has
    /// moved ownership of both folder handles out to the failover watcher
    /// (`main::failover`), which then holds them for the rest of THIS
    /// process's life — not just until `AttachedFolder` goes out of scope.
    /// `Drop` becomes a no-op for those two fields once this is set.
    folder_handles_taken: bool,
}

impl AttachedFolder {
    /// Takes ownership of the Attach connection, leaving `self.client`
    /// empty. Always `Some` immediately after a successful [`client_attach`]
    /// — the `expect` documents that invariant rather than threading an
    /// `Option` through every caller.
    pub(crate) fn take_client(&mut self) -> ipc::SyncClient {
        self.client.take().expect("AttachedFolder::client taken more than once")
    }

    /// Takes ownership of the folder job + folder section handles, leaving
    /// `Drop` with nothing left to close for them. Called at most once per
    /// `AttachedFolder` (asserted) — the caller becomes responsible for
    /// eventually `CloseHandle`ing both.
    pub(crate) fn take_folder_handles(&mut self) -> (HANDLE, HANDLE) {
        assert!(
            !self.folder_handles_taken,
            "AttachedFolder::take_folder_handles called more than once"
        );
        self.folder_handles_taken = true;
        (self.folder_job_handle, self.folder_section_handle)
    }
}

impl Drop for AttachedFolder {
    fn drop(&mut self) {
        if self.folder_handles_taken {
            return;
        }
        // SAFETY: both handles were duplicated into THIS process by the
        //         broker's Attach response and are owned exclusively by this
        //         struct; closed exactly once here.
        unsafe {
            CloseHandle(self.folder_job_handle).ok();
            CloseHandle(self.folder_section_handle).ok();
        }
    }
}

// SAFETY: HANDLE carries no thread affinity; every field is either an owned
//         kernel handle, plain data, or (MP-6) `ipc::SyncClient` (already
//         `Send` on its own — its inner File/pipe handle carries no thread
//         affinity either — this impl exists only because HANDLE is not).
unsafe impl Send for AttachedFolder {}

/// Connect to the broker named in `broker.json` under `state_dir` and send
/// `Attach`. Verifies the broker is still alive (kernel creation-time
/// fingerprint) and that the pipe's SERVER side really is that broker
/// (`GetNamedPipeServerProcessId`) before trusting anything it says — the
/// same defence `hook::trusted_boot::verify_pipe_server_identity` applies on
/// the guest side, applied here to the launcher's own client role.
pub(crate) fn client_attach(state_dir: &Path) -> Result<AttachedFolder> {
    let doc = session_section::read_broker_json(&state_dir.join(session_section::BROKER_JSON_FILE_NAME))
        .context("read broker.json")?;

    let live_ct = super::pipe_server::query_process_create_time(doc.broker_pid)
        .ok_or_else(|| anyhow!("broker pid {} is not alive", doc.broker_pid))?;
    anyhow::ensure!(
        live_ct == doc.broker_create_time,
        "broker pid {} was reused (creation time mismatch)",
        doc.broker_pid,
    );

    let mut client = ipc::SyncClient::connect(&doc.pipe_name)
        .with_context(|| format!("connect to broker pipe {}", doc.pipe_name))?;

    let mut server_pid: u32 = 0;
    // SAFETY: `pipe_raw_handle()` is the client's own live, connected pipe
    //         handle for the duration of this call; `server_pid` is a valid
    //         out-pointer. `RawHandle` and `windows::HANDLE` are both
    //         `*mut c_void` on Windows.
    unsafe { GetNamedPipeServerProcessId(HANDLE(client.pipe_raw_handle() as _), &mut server_pid) }
        .context("GetNamedPipeServerProcessId")?;
    anyhow::ensure!(
        server_pid == doc.broker_pid,
        "pipe server pid {server_pid} != broker.json broker_pid {}",
        doc.broker_pid,
    );

    let own_pid = std::process::id();
    let own_create_time = super::pipe_server::query_process_create_time(own_pid)
        .ok_or_else(|| anyhow!("own creation time unavailable"))?;
    let resp = client
        .send(&ipc::Req::Attach { launcher_pid: own_pid, launcher_create_time: own_create_time })
        .context("send Attach")?;
    match resp {
        ipc::Resp::Attached {
            folder_job_handle, folder_section_handle, folder_section_name,
            broker_pid, broker_create_time, pipe_name, generation, has_net_rules,
        } => Ok(AttachedFolder {
            folder_job_handle: HANDLE(folder_job_handle as *mut _),
            folder_section_handle: HANDLE(folder_section_handle as *mut _),
            folder_section_name,
            broker_pid,
            broker_create_time,
            pipe_name,
            generation,
            has_net_rules,
            client: Some(client),
            folder_handles_taken: false,
        }),
        ipc::Resp::Err(e) => Err(anyhow!("broker refused Attach: {e}")),
        other => Err(anyhow!("unexpected Attach response: {other:?}")),
    }
}


// Test module lives in a sibling file (layout-guard 1000-line cap):
// `attach_tests` alone (MP-3/MP-6, real named pipes + job objects) is large.
#[cfg(test)]
#[path = "broker_tests.rs"]
mod tests;
