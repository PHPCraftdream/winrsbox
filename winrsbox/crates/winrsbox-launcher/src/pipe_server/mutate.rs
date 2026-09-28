// MP-9: pre-admission connection dispatcher (broker side).
//
// A connection that fails the normal job-membership admission check gets
// exactly one shot at ONE of two requests, per
// `docs/multiprocess-broker-plan.md` ("CLI при идущей сессии"):
//   - `Req::Attach` (MP-3): a joining launcher process.
//   - `Req::PolicyMutate` (MP-9): a CLI process (`winrsbox rule add ...`,
//     same image, never a folder-job member) applying a policy
//     mutation/read while this broker already owns policy.redb.
// Both share the same kernel-truth authentication
// (`security::authenticate_attach_client`), run BEFORE the request is read
// so an unrelated process that connects and never writes can never pin an
// accept-pool worker forever. This module is the single place that chooses
// between the two — `main::broker::handle_attach_connection` (MP-3) now
// delegates here.

use ipc::{Req, Resp};
use policy::{Policy, RegistryPolicy};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::FlushFileBuffers;
use winrsbox::contain::jobctl;

/// Reads exactly one request from a connection that failed the normal
/// job-membership admission check, after authenticating the connecting
/// process from kernel facts alone (PID, live create time, NOT a folder-job
/// member, matching token SID, matching image path — see
/// `security::authenticate_attach_client`). `attach_ctx: None` disables the
/// `Attach` branch (mirrors `folder_job: Option<...>` elsewhere in this
/// module); `policy`/`reg_policy: None` disables `PolicyMutate` (a caller
/// that never wants this path — e.g. `broker::handle_attach_connection`'s
/// own MP-3-only test suite). Returns whether a legitimate pre-admission
/// exchange happened — `false` means the caller should log/disconnect
/// exactly as it does for any other rejected connection.
pub(crate) fn handle_preadmission_connection(
    conn: HANDLE,
    client_pid: u32,
    folder_job: &jobctl::FolderJob,
    attach_ctx: Option<&crate::broker::AttachContext>,
    policy: Option<&Policy>,
    reg_policy: Option<&RegistryPolicy>,
) -> bool {
    use std::os::windows::io::FromRawHandle;
    // SAFETY: conn is the connection's valid, connected server-side pipe
    //         handle; forgotten below so the caller's `PipeConnGuard`
    //         remains the sole closer (mirrors `handle_connection`).
    let mut file = unsafe { std::fs::File::from_raw_handle(conn.0 as _) };
    let handled = (|| {
        // Authenticate from the kernel BEFORE the blocking read: an
        // unrelated process that connects and never writes must not pin a
        // worker. `client_pid` doubles as both the "claimed" and "observed"
        // identity here — every OTHER check (SID, image, job membership) is
        // independent of anything the client sends.
        let live_ct = super::query_process_create_time(client_pid)?;
        let client_process =
            super::security::authenticate_attach_client(client_pid, client_pid, live_ct, folder_job)
                .ok()?;
        let req: Option<Req> = ipc::read_msg(&mut file).ok();
        match req {
            Some(Req::Attach { launcher_pid, launcher_create_time })
                if launcher_pid == client_pid && launcher_create_time == live_ct =>
            {
                let Some(ctx) = attach_ctx else {
                    // SAFETY: opened by authenticate_attach_client above.
                    unsafe { CloseHandle(client_process).ok() };
                    return Some(false);
                };
                let ok = crate::broker::try_complete_attach(
                    client_process, launcher_pid, launcher_create_time, folder_job, ctx, &mut file,
                );
                if !ok {
                    // SAFETY: client_process is closed exactly once on every
                    //         failure path of try_complete_attach.
                    unsafe { CloseHandle(client_process).ok() };
                } else {
                    // MP-6: keep serving this connection for the launcher's
                    // whole session (LauncherLog/SessionStats).
                    crate::session::run_launcher_session_loop(&mut file, ctx);
                }
                Some(ok)
            }
            Some(Req::Ping) => {
                // One-shot exchange, same shape as PolicyMutate below — no
                // handles duplicated, the authenticated process handle is
                // done now.
                // SAFETY: opened by authenticate_attach_client above.
                unsafe { CloseHandle(client_process).ok() };
                let resp = ping_response(attach_ctx);
                let written = ipc::write_msg(&mut file, &resp).is_ok();
                // See the PolicyMutate arm below for why this flush is here.
                if written {
                    // SAFETY: conn is this connection's valid, still-open
                    //         server-side pipe handle (not yet disconnected).
                    let _ = unsafe { FlushFileBuffers(conn) };
                }
                Some(written)
            }
            Some(Req::BrokerStatus) => {
                // SAFETY: opened by authenticate_attach_client above.
                unsafe { CloseHandle(client_process).ok() };
                let resp = broker_status_response(attach_ctx, folder_job);
                let written = ipc::write_msg(&mut file, &resp).is_ok();
                if written {
                    // SAFETY: conn is this connection's valid, still-open
                    //         server-side pipe handle (not yet disconnected).
                    let _ = unsafe { FlushFileBuffers(conn) };
                }
                Some(written)
            }
            Some(Req::PolicyMutate { op }) => {
                // One-shot exchange — no handles are duplicated into the
                // caller, so the authenticated process handle is done now.
                // SAFETY: opened by authenticate_attach_client above.
                unsafe { CloseHandle(client_process).ok() };
                let resp = execute_policy_mutate(policy, reg_policy, op);
                let written = ipc::write_msg(&mut file, &resp).is_ok();
                // The caller (accept_worker) tears the connection down via
                // PipeConnGuard (DisconnectNamedPipe + CloseHandle) the
                // instant this function returns — with NO further exchange
                // on this one-shot connection to naturally pace that against
                // the client's read (unlike the admitted-connection loop,
                // which only disconnects once it next blocks reading a
                // request that never comes). Flush first: per Win32 docs,
                // FlushFileBuffers on a named pipe SERVER handle blocks
                // until the client has read everything already written,
                // so the disconnect can never race a client read still in
                // flight (this is the documented fix for exactly this
                // "write once then disconnect" shape).
                if written {
                    // SAFETY: conn is this connection's valid, still-open
                    //         server-side pipe handle (not yet disconnected).
                    let _ = unsafe { FlushFileBuffers(conn) };
                }
                Some(written)
            }
            _ => {
                // SAFETY: opened by authenticate_attach_client above.
                unsafe { CloseHandle(client_process).ok() };
                Some(false)
            }
        }
    })()
    .unwrap_or(false);
    std::mem::forget(file);
    handled
}

/// Execute a CLI-relayed `policy::db::PolicyOp` against the broker's own
/// already-open db, refreshing whichever in-memory cache the op touches
/// (`PolicyOp::touches_fs_snapshot`/`touches_reg_snapshot`) so the running
/// session observes the change on its very next decision — no restart.
/// Net rules need no refresh here: `Policy::net_rule_decide` re-checks the
/// persisted generation counter on every call and rebuilds its snapshot
/// itself when it changed. Device rules and the mem-operation policy have
/// no in-memory cache today (read fresh from the db each time), so nothing
/// to refresh for those either.
fn execute_policy_mutate(
    policy: Option<&Policy>,
    reg_policy: Option<&RegistryPolicy>,
    op: policy::db::PolicyOp,
) -> Resp {
    let Some(policy) = policy else {
        return Resp::Err("policy mutate: not supported on this connection".into());
    };
    let db = policy.db();
    match policy::db::exec(&db, &op) {
        Ok(result) => {
            if op.touches_fs_snapshot() {
                if let Err(e) = policy.invalidate_snapshot() {
                    return Resp::Err(format!("policy mutate applied but cache refresh failed: {e}"));
                }
            }
            if op.touches_reg_snapshot() {
                match reg_policy {
                    Some(reg) => {
                        if let Err(e) = reg.reload_snapshot() {
                            return Resp::Err(format!(
                                "policy mutate applied but registry cache refresh failed: {e}"
                            ));
                        }
                    }
                    None => {
                        return Resp::Err(
                            "policy mutate: registry policy unavailable on this connection".into(),
                        );
                    }
                }
            }
            Resp::PolicyMutated(result)
        }
        Err(e) => Resp::Err(format!("policy mutate: {e}")),
    }
}

/// MP-8: `Req::Ping` reply for a pre-admission (non-Attach) connection —
/// e.g. `winrsbox broker status`'s liveness check. `attach_ctx: None`
/// mirrors `execute_policy_mutate`'s "not supported on this connection"
/// shape (used by `main::broker::handle_attach_connection`'s own
/// Attach-only test double).
fn ping_response(attach_ctx: Option<&crate::broker::AttachContext>) -> Resp {
    let Some(ctx) = attach_ctx else {
        return Resp::Err("ping: not supported on this connection".into());
    };
    let generation = ctx.folder_section.view().snapshot().map(|s| s.generation).unwrap_or(0);
    Resp::Pong { broker_pid: ctx.broker_pid, broker_create_time: ctx.broker_create_time, generation }
}

/// MP-8: `Req::BrokerStatus` reply — the folder section's own snapshot
/// (broker identity, generation, pipe, trusted launchers) plus the folder
/// job's kernel-truth `ActiveProcesses` count (see
/// `jobctl::FolderJob::active_processes`), never a self-reported counter.
fn broker_status_response(
    attach_ctx: Option<&crate::broker::AttachContext>,
    folder_job: &jobctl::FolderJob,
) -> Resp {
    let Some(ctx) = attach_ctx else {
        return Resp::Err("broker status: not supported on this connection".into());
    };
    let snapshot = match ctx.folder_section.view().snapshot() {
        Ok(s) => s,
        Err(e) => return Resp::Err(format!("broker status: folder section snapshot failed: {e}")),
    };
    let active_processes = folder_job.active_processes().unwrap_or(0);
    Resp::BrokerStatus {
        broker_pid: snapshot.broker_pid,
        broker_create_time: snapshot.broker_create_time,
        generation: snapshot.generation,
        pipe_name: snapshot.pipe_name,
        trusted_launchers: snapshot.launchers,
        active_processes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::AttachContext;
    use std::os::windows::process::CommandExt;
    use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};

    fn own_create_time() -> u64 {
        crate::pipe_server::query_process_create_time(std::process::id())
            .expect("own process creation time must be queryable")
    }

    fn make_policy() -> (tempfile::TempDir, Policy) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
        (dir, p)
    }

    fn make_reg_policy(policy: &Policy) -> RegistryPolicy {
        let dir = tempfile::tempdir().unwrap();
        RegistryPolicy::open(policy.db(), dir.path().to_path_buf()).unwrap()
    }

    /// A bare, unsecured named-pipe server instance for same-process tests —
    /// production uses the hardened `pipe_server::security` machinery,
    /// irrelevant here (both ends are this test process). Mirrors
    /// `main::broker`'s own `attach_tests::test_pipe_server`.
    fn test_pipe_server(name: &str) -> HANDLE {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: wide is a NUL-terminated UTF-16 name; None = default
        //         security descriptor, fine for a same-process test pipe.
        unsafe {
            CreateNamedPipeW(
                windows::core::PCWSTR(wide.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                None,
            )
        }
    }

    fn connected_pair(tag: &str) -> (HANDLE, ipc::SyncClient) {
        let name = format!(r"\\.\pipe\winrsbox-mp9-mutate-{}-{tag}", std::process::id());
        let server = test_pipe_server(&name);
        let server_raw = server.0 as isize;
        let accept = std::thread::spawn(move || {
            let h = HANDLE(server_raw as *mut _);
            // SAFETY: h is the valid pipe handle created above.
            unsafe { ConnectNamedPipe(h, None).ok() };
            server_raw
        });
        let client = ipc::SyncClient::connect(&name).expect("client connect");
        let server_raw = accept.join().expect("accept thread must not panic");
        (HANDLE(server_raw as *mut _), client)
    }

    fn disconnect_and_close(h: HANDLE) {
        // SAFETY: h is the valid server-side pipe handle for this test's
        //         connection, not closed anywhere else on this path.
        unsafe {
            windows::Win32::System::Pipes::DisconnectNamedPipe(h).ok();
            CloseHandle(h).ok();
        }
    }

    #[test]
    fn self_applies_a_rule_upsert_and_sees_it_via_list() {
        let job = jobctl::FolderJob::create().expect("create folder job");
        let pid = std::process::id();
        let (_dir, policy) = make_policy();
        let (server, mut client) = connected_pair("rule-upsert");

        let row = policy::db::RuleRow {
            id: "r1".into(), prefix: "c:\\test".into(),
            mode_read: policy::db::RuleMode::Passthrough,
            mode_write: policy::db::RuleMode::Deny, when: None,
        };
        let op = policy::db::PolicyOp::RuleUpsert(row);
        let sent = std::thread::spawn(move || client.send(&Req::PolicyMutate { op }).map(|r| (client, r)));
        let handled = handle_preadmission_connection(server, pid, &job, None, Some(&policy), None);
        assert!(handled, "self must be able to apply a policy mutation");
        let (_client, resp) = sent.join().expect("client thread must not panic").expect("send must succeed");
        assert!(matches!(resp, Resp::PolicyMutated(policy::db::PolicyOpResult::Unit)), "got: {resp:?}");

        // The cache was invalidated — a decide made right after the mutate
        // sees the new rule without any restart.
        let d = policy.decide_with_context("c:\\test\\file.txt", true, Some(0), None);
        assert_eq!(d.mode, policy::Mode::Deny, "the mutation must be visible immediately");
    }

    #[test]
    fn decision_before_and_after_a_mutate_differs_proving_the_cache_was_reset() {
        let job = jobctl::FolderJob::create().expect("create folder job");
        let pid = std::process::id();
        let (_dir, policy) = make_policy();

        let before = policy.decide_with_context("c:\\cached\\path.txt", true, Some(0), None);
        assert_eq!(before.mode, policy::Mode::Cow, "default write mode before any rule");

        let (server, mut client) = connected_pair("cache-reset");
        let row = policy::db::RuleRow {
            id: "r2".into(), prefix: "c:\\cached".into(),
            mode_read: policy::db::RuleMode::Passthrough,
            mode_write: policy::db::RuleMode::Deny, when: None,
        };
        let op = policy::db::PolicyOp::RuleUpsert(row);
        let sent = std::thread::spawn(move || client.send(&Req::PolicyMutate { op }));
        assert!(handle_preadmission_connection(server, pid, &job, None, Some(&policy), None));
        sent.join().expect("client thread must not panic").expect("send must succeed");

        let after = policy.decide_with_context("c:\\cached\\path.txt", true, Some(0), None);
        assert_eq!(after.mode, policy::Mode::Deny, "the same path must decide differently post-mutate");
    }

    #[test]
    fn reg_rule_upsert_refreshes_the_registry_snapshot() {
        let job = jobctl::FolderJob::create().expect("create folder job");
        let pid = std::process::id();
        let (_dir, policy) = make_policy();
        let reg = make_reg_policy(&policy);
        let before = reg.decide(r"hklm\software\secret", None, false);
        assert_eq!(before.mode, policy::Mode::Passthrough);

        let (server, mut client) = connected_pair("reg-upsert");
        let row = policy::db::RuleRow {
            id: "rr1".into(), prefix: r"hklm\software\secret".into(),
            mode_read: policy::db::RuleMode::Deny,
            mode_write: policy::db::RuleMode::Deny, when: None,
        };
        let op = policy::db::PolicyOp::RegRuleUpsert(row);
        let sent = std::thread::spawn(move || client.send(&Req::PolicyMutate { op }));
        assert!(handle_preadmission_connection(server, pid, &job, None, Some(&policy), Some(&reg)));
        sent.join().expect("client thread must not panic").expect("send must succeed");

        let after = reg.decide(r"hklm\software\secret", None, false);
        assert_eq!(after.mode, policy::Mode::Deny, "registry decide must see the new rule immediately");
    }

    #[test]
    fn net_rule_upsert_needs_no_explicit_refresh_generation_counter_handles_it() {
        let job = jobctl::FolderJob::create().expect("create folder job");
        let pid = std::process::id();
        let (_dir, policy) = make_policy();

        let (server, mut client) = connected_pair("net-upsert");
        let rule = policy::net::NetRule {
            id: "n1".into(), host_pattern: "evil.example".into(), port: None,
            mode: policy::net::NetMode::Deny,
        };
        let op = policy::db::PolicyOp::NetRuleUpsert(rule);
        let sent = std::thread::spawn(move || client.send(&Req::PolicyMutate { op }));
        assert!(handle_preadmission_connection(server, pid, &job, None, Some(&policy), None));
        sent.join().expect("client thread must not panic").expect("send must succeed");

        let (allow, _) = policy.net_rule_decide("evil.example", 443).unwrap();
        assert!(!allow, "net decide must see the new rule without any explicit cache refresh call");
    }

    #[test]
    fn policy_mutate_is_rejected_when_this_connection_has_no_policy() {
        let job = jobctl::FolderJob::create().expect("create folder job");
        let pid = std::process::id();
        let (server, mut client) = connected_pair("no-policy");
        let op = policy::db::PolicyOp::RuleList;
        let sent = std::thread::spawn(move || client.send(&Req::PolicyMutate { op }));
        let handled = handle_preadmission_connection(server, pid, &job, None, None, None);
        assert!(handled, "a written Resp::Err still counts as a handled pre-admission exchange");
        let resp = sent.join().expect("client thread must not panic").expect("send must succeed");
        assert!(matches!(resp, Resp::Err(_)), "got: {resp:?}");
    }

    fn make_attach_ctx(pid: u32, ct: u64) -> AttachContext {
        let (section, name) = winrsbox::contain::session_section::FolderSection::create().unwrap();
        // Section and ctx must agree on the pipe name — production always
        // sets both together (`main::broker::setup_broker_folder`); a
        // mismatch here would only be a test-fixture bug, not something
        // `broker_status_response` (which reads the section, not `ctx`) is
        // meant to catch.
        section.view().init(pid, ct, r"\\.\pipe\winrsbox-mp8-broker").unwrap();
        AttachContext {
            folder_section: std::sync::Arc::new(crate::broker::FolderSectionWriter::new(section)),
            folder_section_name: name,
            broker_pid: pid,
            broker_create_time: ct,
            pipe_name: r"\\.\pipe\winrsbox-mp8-broker".into(),
            policy: std::sync::Arc::new({ let (d, p) = make_policy(); std::mem::forget(d); p }),
            stats: std::sync::Arc::new(crate::pipe_server::Stats::default()),
        }
    }

    #[test]
    fn ping_returns_pong_with_broker_identity_and_generation() {
        let job = jobctl::FolderJob::create().expect("create folder job");
        let pid = std::process::id();
        let ct = own_create_time();
        let ctx = make_attach_ctx(pid, ct);
        let (server, mut client) = connected_pair("ping-ok");
        let sent = std::thread::spawn(move || client.send(&Req::Ping).map(|r| (client, r)));
        let handled = handle_preadmission_connection(server, pid, &job, Some(&ctx), None, None);
        assert!(handled, "Ping must be answered on a pre-admission connection");
        let (_client, resp) = sent.join().expect("client thread must not panic").expect("send must succeed");
        match resp {
            Resp::Pong { broker_pid, broker_create_time, generation } => {
                assert_eq!(broker_pid, pid);
                assert_eq!(broker_create_time, ct);
                assert_eq!(generation, 0, "a freshly init'd section starts at generation 0");
            }
            other => panic!("expected Pong, got {other:?}"),
        }
    }

    #[test]
    fn ping_is_rejected_when_this_connection_has_no_attach_context() {
        let job = jobctl::FolderJob::create().expect("create folder job");
        let pid = std::process::id();
        let (server, mut client) = connected_pair("ping-no-ctx");
        let sent = std::thread::spawn(move || client.send(&Req::Ping));
        let handled = handle_preadmission_connection(server, pid, &job, None, None, None);
        assert!(handled, "a written Resp::Err still counts as a handled pre-admission exchange");
        let resp = sent.join().expect("client thread must not panic").expect("send must succeed");
        assert!(matches!(resp, Resp::Err(_)), "got: {resp:?}");
    }

    #[test]
    fn broker_status_reports_generation_pipe_and_active_processes() {
        let job = jobctl::FolderJob::create().expect("create folder job");
        let pid = std::process::id();
        let ct = own_create_time();
        let ctx = make_attach_ctx(pid, ct);

        // Two live processes assigned to the folder job — BrokerStatus must
        // report the kernel-truth count, not a self-reported number.
        let mut guest_a = std::process::Command::new("cmd")
            .args(["/C", "ping -n 3 127.0.0.1 >nul"])
            .creation_flags(CREATE_NO_WINDOW.0 | CREATE_SUSPENDED.0)
            .spawn()
            .expect("spawn guest_a");
        let mut guest_b = std::process::Command::new("cmd")
            .args(["/C", "ping -n 3 127.0.0.1 >nul"])
            .creation_flags(CREATE_NO_WINDOW.0 | CREATE_SUSPENDED.0)
            .spawn()
            .expect("spawn guest_b");
        job.assign_process(HANDLE(std::os::windows::io::AsRawHandle::as_raw_handle(&guest_a)))
            .expect("assign guest_a");
        job.assign_process(HANDLE(std::os::windows::io::AsRawHandle::as_raw_handle(&guest_b)))
            .expect("assign guest_b");

        let (server, mut client) = connected_pair("status-ok");
        let sent = std::thread::spawn(move || client.send(&Req::BrokerStatus).map(|r| (client, r)));
        let handled = handle_preadmission_connection(server, pid, &job, Some(&ctx), None, None);
        assert!(handled, "BrokerStatus must be answered on a pre-admission connection");
        let (_client, resp) = sent.join().expect("client thread must not panic").expect("send must succeed");
        match resp {
            Resp::BrokerStatus {
                broker_pid, broker_create_time, generation, pipe_name, trusted_launchers, active_processes,
            } => {
                assert_eq!(broker_pid, pid);
                assert_eq!(broker_create_time, ct);
                assert_eq!(generation, 0);
                assert_eq!(pipe_name, r"\\.\pipe\winrsbox-mp8-broker");
                assert!(trusted_launchers.is_empty(), "no Attach happened in this test");
                assert_eq!(active_processes, 2, "must count exactly the two assigned guests");
            }
            other => panic!("expected BrokerStatus, got {other:?}"),
        }

        let _ = guest_a.kill();
        let _ = guest_a.wait();
        let _ = guest_b.kill();
        let _ = guest_b.wait();
    }

    #[test]
    fn broker_status_is_rejected_when_this_connection_has_no_attach_context() {
        let job = jobctl::FolderJob::create().expect("create folder job");
        let pid = std::process::id();
        let (server, mut client) = connected_pair("status-no-ctx");
        let sent = std::thread::spawn(move || client.send(&Req::BrokerStatus));
        let handled = handle_preadmission_connection(server, pid, &job, None, None, None);
        assert!(handled, "a written Resp::Err still counts as a handled pre-admission exchange");
        let resp = sent.join().expect("client thread must not panic").expect("send must succeed");
        assert!(matches!(resp, Resp::Err(_)), "got: {resp:?}");
    }

    // The success path spawns a background exit-watch task via
    // `tokio::spawn` (`broker::try_complete_attach`), which panics without
    // an active Tokio runtime — `#[tokio::test]` provides one; the test
    // body itself stays synchronous (no `.await`).
    #[tokio::test]
    async fn attach_still_works_through_the_shared_dispatcher() {
        let job = jobctl::FolderJob::create().expect("create folder job");
        let pid = std::process::id();
        let ct = own_create_time();
        let (section, name) = winrsbox::contain::session_section::FolderSection::create().unwrap();
        section.view().init(pid, ct, "p").unwrap();
        let ctx = AttachContext {
            folder_section: std::sync::Arc::new(crate::broker::FolderSectionWriter::new(section)),
            folder_section_name: name,
            broker_pid: pid,
            broker_create_time: ct,
            pipe_name: r"\\.\pipe\winrsbox-mp9-broker".into(),
            policy: std::sync::Arc::new({ let (d, p) = make_policy(); std::mem::forget(d); p }),
            stats: std::sync::Arc::new(crate::pipe_server::Stats::default()),
        };
        let (server, mut client) = connected_pair("attach-ok");
        let sent = std::thread::spawn(move || {
            // Drop the client right after the reply: the broker's session loop
            // (MP-6) serves the connection until the launcher disconnects.
            client.send(&Req::Attach { launcher_pid: pid, launcher_create_time: ct })
        });
        let handled = handle_preadmission_connection(server, pid, &job, Some(&ctx), None, None);
        assert!(handled, "Attach must still succeed via the shared dispatcher");
        let resp = sent.join().expect("client thread must not panic").expect("send must succeed");
        let Resp::Attached { folder_job_handle, folder_section_handle, .. } = resp else {
            panic!("expected Attached, got {resp:?}");
        };
        // SAFETY: both handles were duplicated into this process by Attach.
        unsafe {
            CloseHandle(HANDLE(folder_job_handle as *mut _)).ok();
            CloseHandle(HANDLE(folder_section_handle as *mut _)).ok();
        }
    }

    #[test]
    fn a_guest_process_in_the_folder_job_cannot_send_policy_mutate() {
        let job = jobctl::FolderJob::create().expect("create folder job");
        let (_dir, policy) = make_policy();
        let mut guest = std::process::Command::new("cmd")
            .args(["/C", "ping -n 3 127.0.0.1 >nul"])
            .creation_flags(CREATE_NO_WINDOW.0 | CREATE_SUSPENDED.0)
            .spawn()
            .expect("spawn guest");
        job.assign_process(HANDLE(std::os::windows::io::AsRawHandle::as_raw_handle(&guest)))
            .expect("assign guest to folder job");
        let guest_pid = guest.id();

        let (server, mut client) = connected_pair("guest-rejected");
        let op = policy::db::PolicyOp::RuleList;
        let sent = std::thread::spawn(move || client.send(&Req::PolicyMutate { op }));
        let handled = handle_preadmission_connection(server, guest_pid, &job, None, Some(&policy), None);
        assert!(!handled, "a folder-job member (guest) must never reach PolicyMutate execution");
        disconnect_and_close(server);
        let _ = sent.join();
        let _ = guest.kill();
        let _ = guest.wait();
    }

    #[test]
    fn wrong_image_process_cannot_send_policy_mutate() {
        let job = jobctl::FolderJob::create().expect("create folder job");
        let (_dir, policy) = make_policy();
        let mut other = std::process::Command::new("cmd")
            .args(["/C", "ping -n 3 127.0.0.1 >nul"])
            .creation_flags(CREATE_NO_WINDOW.0 | CREATE_SUSPENDED.0)
            .spawn()
            .expect("spawn other");
        let other_pid = other.id();

        let (server, mut client) = connected_pair("wrong-image-rejected");
        let op = policy::db::PolicyOp::RuleList;
        let sent = std::thread::spawn(move || client.send(&Req::PolicyMutate { op }));
        let handled = handle_preadmission_connection(server, other_pid, &job, None, Some(&policy), None);
        assert!(!handled, "a process with a different image must never reach PolicyMutate execution");
        disconnect_and_close(server);
        let _ = sent.join();
        let _ = other.kill();
        let _ = other.wait();
    }
}
