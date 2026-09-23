// ─── IPC pipe server ──────────────────────────────────────────────────────────

mod conn;
mod ownership;
mod records;
// pub(crate): sandbox::launch_prep (R04-1b) reuses current_user_string_sid
// and the raw ConvertStringSecurityDescriptorToSecurityDescriptorW binding
// for the init-handshake events' explicit SDDL, following the same
// technique this module proved for the IPC pipe.
pub(crate) mod security;
#[cfg(test)]
mod inflight_budget_tests;
#[cfg(test)]
mod tests;

use ipc::{LogLevel, Req, Resp};
use policy::Policy;
use std::{
    ffi::OsStr,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc,
    },
};
use tokio::sync::Semaphore;
use windows::{
    core::HRESULT,
    Win32::{
        Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, HANDLE},
        System::{
            Pipes::{ConnectNamedPipe, DisconnectNamedPipe, GetNamedPipeClientProcessId},
            Threading::{GetExitCodeProcess, OpenProcess, PROCESS_ACCESS_RIGHTS},
        },
    },
};
use winrsbox::observe::hot_stats::{HotStats, ThrottledFlusher};
use winrsbox::observe::jsonl_log;

pub(crate) use conn::{
    create_pipe_instance, ByteBudget, PipeConnGuard, MAX_CONCURRENT_HANDLERS,
    MAX_INFLIGHT_MSG_BYTES, PIPE_ACCEPT_POOL_SIZE,
};
// Only the in-file tests use these via `use super::*`; the request-read path
// now lives in conn.rs (read_request_with_budget), which uses them directly.
#[cfg(test)]
pub(crate) use conn::PrefixedReader;
// The in-file test modules glob-import `super::*` and relied on the `Read`
// trait being in scope here (inflight_budget_tests calls read_to_end).
#[cfg(test)]
use std::io::Read;
pub(crate) use ownership::{
    decide_context, hello_exe_context, is_owned_client_pid, process_create_time_from_handle,
    query_process_create_time, query_process_image_path, spawned_child_kinship,
};
pub(crate) use records::{
    append_violation_record, escape_violation_record, handle_record_overlay,
    injection_violation_record, memory_violation_record,
};
pub(crate) use security::{build_pipe_security, PipeSecurity};

#[cfg(test)]
pub(crate) use ownership::is_owned_client_pid_impl;
// handle_net_decide/is_env_value_allowed/is_persistence_denied now have
// non-test callers only inside records.rs itself (resp_reg_decide/
// resp_reg_write/resp_net_decide) — this re-export exists solely so
// tests.rs's `use super::*` still sees them.
#[cfg(test)]
pub(crate) use records::{
    handle_net_decide, is_env_value_allowed, is_persistence_denied, net_decide,
    segment_contains, PERSISTENCE_DENY_SUFFIXES,
};
#[cfg(test)]
use std::time::Duration;

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
                    let msg = format!("CreateNamedPipeW (instance) failed: {err} — retrying");
                    if jsonl_log::console_verbose() {
                        eprintln!("[pipe] {msg}");
                    }
                    jsonl_log::log(jsonl_log::Event::launcher_diag("WARN", msg));
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
            if jsonl_log::console_verbose() {
                eprintln!(
                    "[pipe] GetNamedPipeClientProcessId failed on new connection — disconnecting",
                );
            }
            jsonl_log::log_immediate(jsonl_log::Event::launcher_diag(
                "WARN",
                "GetNamedPipeClientProcessId failed on new connection — disconnecting",
            ));
            // SAFETY: ph is the isize repr of our pipe handle.
            unsafe { DisconnectNamedPipe(HANDLE(ph as *mut _)).ok() };
            unsafe { CloseHandle(HANDLE(ph as *mut _)).ok() };
            continue;
        }
        let root_pid_snapshot = root_target_pid.load(Ordering::Acquire);
        if !is_owned_client_pid(client_pid, root_pid_snapshot) {
            if jsonl_log::console_verbose() {
                eprintln!(
                    "[pipe] WARN: rejecting connection from non-owned pid={client_pid} \
                     (root_target_pid={root_pid_snapshot})",
                );
            }
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

    // Connection-local reusable IPC scratch buffers — capacity persists across messages on this connection, ipc-side shrink policy caps retained capacity.
    let mut recv_buf = Vec::new();
    let mut enc_buf = Vec::new();

    loop {
        if let Some(ref ph) = proc_handle {
            let mut exit_code = 0u32;
            // SAFETY: ph is a valid process handle obtained above.
            let ok = unsafe { GetExitCodeProcess(*ph, &mut exit_code).is_ok() };
            if ok && exit_code != STILL_ACTIVE {
                break;
            }
        }

        // Read one request with the in-flight byte budget applied (prefix
        // read, budget reservation and PrefixedReader replay live in conn.rs).
        // None → drop the connection; the reservation stays bound for the rest
        // of this iteration, released at the next rebind / loop exit.
        let Some((req, _budget)) =
            conn::read_request_with_budget(&mut file, byte_budget, &mut recv_buf, client_pid)
        else {
            break;
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
                    if jsonl_log::console_verbose() {
                        eprintln!(
                            "[pipe] WARN: Hello pid={pid} != kernel client_pid={client_pid} — \
                             using client_pid (possible spoof)",
                        );
                    }
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
                // SECURITY (S09): the claimed exe_path is diagnostics-only —
                // policy context must come from the kernel's image path.
                match hello_exe_context(client_pid, &exe_path) {
                    Ok((exe_lower, claimed_mismatch)) => {
                        if claimed_mismatch {
                            if jsonl_log::console_verbose() {
                                eprintln!(
                                    "[pipe] WARN: Hello exe_path={exe_path} != kernel image path — \
                                     using kernel path (possible spoof)",
                                );
                            }
                            stats.violations.fetch_add(1, Ordering::Relaxed);
                            hot_stats.totals.violations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            jsonl_log::log_immediate(jsonl_log::Event::violation(
                                client_pid,
                                "HelloExeSpoof",
                                &format!("claimed_exe={exe_path}"),
                            ));
                        }
                        // Fingerprint the connecting process from the kernel. The client
                        // is alive on this connection, so this normally succeeds; 0
                        // fail-closes later connections (see tracked_entry_still_owned).
                        let live_ct = query_process_create_time(client_pid).unwrap_or(0);
                        if live_ct == 0 {
                            let msg = format!(
                                "hello pid={client_pid}: creation-time probe failed — \
                                 entry stored with unknown fingerprint"
                            );
                            if jsonl_log::console_verbose() {
                                eprintln!("[pipe] {msg}");
                            }
                            jsonl_log::log(jsonl_log::Event::launcher_diag("WARN", msg));
                        }
                        let map = crate::sandbox::proc_table::global_proc_info().pin();
                        if let Some(existing) = map.get(&client_pid) {
                            // Already have entry (e.g., root target or SpawnedChild) — keep depth, update exe
                            let updated = crate::sandbox::proc_table::ProcInfo {
                                depth: existing.depth,
                                exe_lower: Arc::from(exe_lower.as_str()),
                                create_time: if live_ct != 0 { live_ct } else { existing.create_time },
                            };
                            map.insert(client_pid, updated);
                        } else {
                            // New process — insert with depth 0 (updated by SpawnedChild if child)
                            map.insert(client_pid, crate::sandbox::proc_table::ProcInfo {
                                depth: 0,
                                exe_lower: Arc::from(exe_lower.as_str()),
                                create_time: live_ct,
                            });
                        }
                        conn_pid = Some(client_pid);
                        Resp::Ok
                    }
                    Err(()) => {
                        // SECURITY (S09, fail closed): kernel image query failed — leave the
                        // proc table untouched (never overwrite an existing root entry) and
                        // the connection un-Hello'd. The hook treats any non-matching
                        // response as an IPC failure and fails closed (Deny) on later
                        // decides, so an unresolved path can't purchase policy context.
                        if jsonl_log::console_verbose() {
                            eprintln!(
                                "[pipe] WARN: hello pid={client_pid}: kernel image path query \
                                 failed — refusing Hello (fail closed)",
                            );
                        }
                        stats.violations.fetch_add(1, Ordering::Relaxed);
                        hot_stats.totals.violations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        jsonl_log::log_immediate(jsonl_log::Event::violation(
                            client_pid,
                            "HelloExeUnresolved",
                            &format!("claimed_exe={exe_path}"),
                        ));
                        Resp::Err("hello: kernel image path unavailable".to_string())
                    }
                }
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
                    if jsonl_log::console_verbose() {
                        eprintln!(
                            "[pipe] WARN: SpawnedChild parent_pid={parent_pid} != client_pid={client_pid} \
                             — inheriting depth from client_pid (possible spoof)",
                        );
                    }
                    stats.violations.fetch_add(1, Ordering::Relaxed);
                    hot_stats.totals.violations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    jsonl_log::log_immediate(jsonl_log::Event::violation(
                        client_pid,
                        "SpawnedChildParentSpoof",
                        &format!("claimed_parent={parent_pid} child={child_pid}"),
                    ));
                }
                // SECURITY (S09, handshake gate): the hook always Hellos first on
                // a fresh connection (ipc_client.rs sends Hello before anything
                // else), so SpawnedChild without Hello is hostile — refuse fail closed.
                if conn_pid.is_none() {
                    if jsonl_log::console_verbose() {
                        eprintln!(
                            "[pipe] WARN: SpawnedChild before Hello from pid={client_pid} — \
                             refused (fail closed)",
                        );
                    }
                    stats.violations.fetch_add(1, Ordering::Relaxed);
                    hot_stats.totals.violations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    jsonl_log::log_immediate(jsonl_log::Event::violation(
                        client_pid,
                        "SpawnedChildBeforeHello",
                        &format!("child={child_pid}"),
                    ));
                    Resp::Err("spawned_child: handshake required".to_string())
                } else if !spawned_child_kinship(child_pid, client_pid) {
                    // SECURITY (S09, kinship proof): kernel parentage is the trust
                    // anchor — the creator PID the kernel records at CreateProcess is
                    // immutable and survives parent death, so a hostile parent naming
                    // an unrelated PID fails (the kernel records the real creator);
                    // child_pid reuse is handled by the create-time fingerprint below.
                    if jsonl_log::console_verbose() {
                        eprintln!(
                            "[pipe] WARN: SpawnedChild child={child_pid} is not a kernel child of \
                             client={client_pid} — rejected (possible spoof)",
                        );
                    }
                    stats.violations.fetch_add(1, Ordering::Relaxed);
                    hot_stats.totals.violations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    jsonl_log::log_immediate(jsonl_log::Event::violation(
                        client_pid,
                        "SpawnedChildNotKin",
                        &format!("child={child_pid}"),
                    ));
                    Resp::Err("spawned_child: kinship unverified".to_string())
                } else {
                    // Kinship proven — only now count the report as child telemetry.
                    if jsonl_log::console_verbose() {
                        println!("[sandbox] child spawned: parent={client_pid} child={child_pid} exe={child_exe}");
                    }
                    hot_stats.totals.children.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    jsonl_log::log(jsonl_log::Event::child(client_pid, child_pid, &child_exe));
                    // Bounded, validated push; throttled log — a hostile loop
                    // must not flood the immediate log path via rejections.
                    if !crate::sandbox::child_drain::queue_child_pid(child_pids, child_pid) {
                        stats.violations.fetch_add(1, Ordering::Relaxed);
                        hot_stats.totals.violations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        jsonl_log::log(jsonl_log::Event::violation(
                            client_pid,
                            "ChildPidQueueRejected",
                            &format!("child={child_pid}"),
                        ));
                    }
                    // Fingerprint the freshly spawned child from the kernel so the
                    // gate can pin its identity. If the probe fails (child died
                    // already) the entry is stored with 0 and fail-closes; the
                    // child's own Hello would refresh it if it ever connects.
                    let child_ct = query_process_create_time(child_pid).unwrap_or(0);
                    if child_ct == 0 {
                        let msg = format!(
                            "SpawnedChild pid={child_pid}: creation-time probe failed — \
                             entry stored with unknown fingerprint"
                        );
                        if jsonl_log::console_verbose() {
                            eprintln!("[pipe] {msg}");
                        }
                        jsonl_log::log(jsonl_log::Event::launcher_diag("WARN", msg));
                    }
                    let map = crate::sandbox::proc_table::global_proc_info().pin();
                    let parent_depth = map.get(&client_pid).map(|p| p.depth).unwrap_or(0);
                    // SECURITY (S09): verify the child's image path from the kernel
                    // too. On probe failure the claimed exe is stored, but is inert
                    // until the child's own Hello overwrites it with kernel truth
                    // (Decide context only ever comes from the child's own
                    // kernel-verified Hello connection).
                    let (exe_lower, claimed_mismatch) = match query_process_image_path(child_pid) {
                        Some(k) => {
                            // S11: canonical NTFS-identity fold, matching the db's when.exe key fold.
                            let kl = crate::fold_published(&k);
                            let mismatch = kl != crate::fold_published(&child_exe);
                            (kl, mismatch)
                        }
                        None => (crate::fold_published(&child_exe), false),
                    };
                    if claimed_mismatch {
                        stats.violations.fetch_add(1, Ordering::Relaxed);
                        hot_stats.totals.violations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        jsonl_log::log_immediate(jsonl_log::Event::violation(
                            client_pid,
                            "SpawnedChildExeSpoof",
                            &format!("claimed_exe={child_exe}"),
                        ));
                    }
                    map.insert(child_pid, crate::sandbox::proc_table::ProcInfo {
                        depth: crate::sandbox::proc_table::child_depth(parent_depth),
                        exe_lower: Arc::from(exe_lower.as_str()),
                        create_time: child_ct,
                    });
                    Resp::Ok
                }
            }
            Req::Decide { dos_path, write } => {
                stats.decide.fetch_add(1, Ordering::Relaxed);
                // SECURITY (S09): Hello-first state machine. The old code served
                // pre-Hello Decides with (None, None), and exe=None makes
                // exe-scoped rules be SKIPPED — a permissive fall-through. Err
                // also covers a Hello'd connection whose entry was pruned
                // (identity broke between Hello and Decide).
                match decide_context(conn_pid) {
                    Ok((depth, exe_lower)) => {
                        let d = policy.decide_with_context(
                            &dos_path,
                            write,
                            Some(depth),
                            Some(&*exe_lower),
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
                    Err(()) => {
                        if jsonl_log::console_verbose() {
                            eprintln!(
                                "[pipe] WARN: decide before hello (or identity lost) from \
                                 pid={client_pid} — refused (fail closed)",
                            );
                        }
                        stats.violations.fetch_add(1, Ordering::Relaxed);
                        hot_stats.totals.violations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        jsonl_log::log_immediate(jsonl_log::Event::violation(
                            client_pid,
                            "DecideBeforeHello",
                            &format!("path={dos_path} write={write}"),
                        ));
                        // The hook counts a non-Decision response as an IPC
                        // failure and fails closed (Deny), self-terminating at
                        // its threshold — this cannot be spammed indefinitely.
                        Resp::Err("decide: handshake required".to_string())
                    }
                }
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
            // R05: cap listings before encoding — see conn::resp_* / MAX_OVERLAY_LISTING_ENTRIES.
            Req::WhiteoutsUnder { dir } => {
                conn::resp_whiteouts(policy, &dir, client_pid, stats, hot_stats)
            }
            Req::OverlayChildrenWithCase { dir } => {
                conn::resp_overlay_children_with_case(policy, &dir, client_pid, stats, hot_stats)
            }
            Req::OverlayChildren { dir } => {
                conn::resp_overlay_children(policy, &dir, client_pid, stats, hot_stats)
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
                // Bounded, validated push (S09): the queue feeds only grace-window
                // supervision + stale-entry pruning — never trust — so this suffices.
                // Throttled log: a hostile loop must not flood the immediate path.
                if !crate::sandbox::child_drain::queue_child_pid(child_pids, pid) {
                    stats.violations.fetch_add(1, Ordering::Relaxed);
                    hot_stats.totals.violations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    jsonl_log::log(jsonl_log::Event::violation(
                        client_pid,
                        "ChildPidQueueRejected",
                        &format!("child={pid}"),
                    ));
                }
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
                records::resp_reg_decide(
                    reg_policy, hot_stats, flusher, &key_path, value_name.as_deref(), write,
                )
            }
            Req::RegWrite { key_path, value_name, value } => {
                records::resp_reg_write(reg_policy, &key_path, &value_name, value)
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
                // (winrsbox::contain::wfp) are defense-in-depth ON TOP of this, and
                // only exist when the launcher's WFP session can install
                // filters -- without them this userspace decision is the
                // only network enforcement the sandbox has.
                records::resp_net_decide(policy, hot_stats, flusher, &host, port)
            }
            Req::MemDecide { target_pid, op } => {
                if jsonl_log::console_verbose() {
                    println!("[mem] decide: pid={target_pid} op={op}");
                }
                Resp::MemDecision { allow: false }
            }
        };

        if ipc::write_msg_with_buf(&mut file, &resp, &mut enc_buf).is_err() {
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
