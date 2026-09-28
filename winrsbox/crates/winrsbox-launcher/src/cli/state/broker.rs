// MP-8: `winrsbox broker status`/`winrsbox broker restart` — the CLI-facing
// counterparts to `Req::BrokerStatus`/`Req::Ping` and to killing a hung
// broker (see docs/multiprocess-broker-plan.md, "Зависание брокера").

use anyhow::{Context, Result};
use std::path::Path;
use windows::core::{HRESULT, PWSTR};
use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
    INFINITE, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE,
};

const BROKER_HELP: &str = "\
winrsbox broker — inspect or restart the folder broker

SUBCOMMANDS:
  status     Show the running broker's identity, generation, trusted
             launchers, and how many sandboxed processes are in this folder.
  restart    Terminate the running broker (refuses to touch a process whose
             image isn't this winrsbox.exe); attached clients fail over to a
             new broker automatically — no separate confirmation flag needed.

EXAMPLES:
  winrsbox broker status
  winrsbox broker restart
";

pub fn run(args: &[String], state_dir: &Path) -> Result<()> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{}", BROKER_HELP);
        return Ok(());
    }
    match args.first().map(|s| s.as_str()) {
        Some("status") => run_status(state_dir),
        Some("restart") => run_restart(state_dir),
        Some(other) => anyhow::bail!(
            "unknown 'broker' subcommand '{other}'; expected 'status' or 'restart'. \
             Run 'winrsbox broker --help' for usage."
        ),
        None => {
            print!("{}", BROKER_HELP);
            Ok(())
        }
    }
}

/// `broker.json`'s identified broker, verified still alive by kernel
/// creation-time fingerprint (PID-reuse safe) — the same check
/// `main::broker::client_attach`/`cli::connect_broker_for_mutate` apply
/// before trusting anything `broker.json` points at. `None` covers both
/// "no broker.json" and "broker.json names a dead/reused pid" — in either
/// case there is no live broker to report on or restart.
fn read_live_broker(state_dir: &Path) -> Option<crate::contain::session_section::BrokerJson> {
    let path = state_dir.join(crate::contain::session_section::BROKER_JSON_FILE_NAME);
    let doc = crate::contain::session_section::read_broker_json(&path).ok()?;
    (super::super::query_process_create_time(doc.broker_pid) == Some(doc.broker_create_time))
        .then_some(doc)
}

fn run_status(state_dir: &Path) -> Result<()> {
    if read_live_broker(state_dir).is_none() {
        println!("брокер не запущен");
        return Ok(());
    }
    // `connect_broker_for_mutate` re-verifies liveness/identity itself
    // (fresh, not the snapshot `read_live_broker` just took) and also
    // checks the pipe's SERVER side really is that broker.
    let mut client = super::super::connect_broker_for_mutate(state_dir).context("connect to broker")?;
    match client.send(&ipc::Req::BrokerStatus).context("send BrokerStatus")? {
        ipc::Resp::BrokerStatus {
            broker_pid, broker_create_time, generation, pipe_name, trusted_launchers, active_processes,
        } => {
            println!("broker: pid={broker_pid} create_time=0x{broker_create_time:x} generation={generation}");
            println!("pipe: {pipe_name}");
            println!("processes in folder job: {active_processes}");
            println!("trusted launchers: {}", trusted_launchers.len());
            for (pid, create_time) in &trusted_launchers {
                println!("  pid={pid} create_time=0x{create_time:x}");
            }
            Ok(())
        }
        ipc::Resp::Err(e) => anyhow::bail!("broker status: {e}"),
        other => anyhow::bail!("broker status: unexpected response: {other:?}"),
    }
}

fn run_restart(state_dir: &Path) -> Result<()> {
    let Some(doc) = read_live_broker(state_dir) else {
        println!("брокер не запущен");
        return Ok(());
    };
    restart_broker_process(doc.broker_pid)
}

/// Opens `pid` with `PROCESS_TERMINATE | PROCESS_SYNCHRONIZE |
/// PROCESS_QUERY_LIMITED_INFORMATION`, refuses to touch it unless its own
/// kernel-reported image path matches THIS process's `winrsbox.exe`
/// (never trust `broker.json`'s pid alone), `TerminateProcess`es it, and
/// waits for it to actually exit before returning. The handle is closed on
/// every exit path exactly once — success or any error found inside the
/// inner closure.
fn restart_broker_process(pid: u32) -> Result<()> {
    // SAFETY: pid is a plain PID value; OpenProcess simply fails (Err) when
    //         it names a dead/inaccessible process.
    let h = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    }
    .with_context(|| format!("open broker process pid={pid}"))?;

    let result = (|| -> Result<()> {
        let image = image_path_from_handle(h)
            .ok_or_else(|| anyhow::anyhow!("could not read broker's image path (pid={pid})"))?;
        let own = std::env::current_exe().context("current_exe")?;
        if !same_image(&image, &own) {
            anyhow::bail!(
                "refusing to restart pid={pid}: image path '{image}' does not match \
                 this winrsbox.exe ('{}')",
                own.display(),
            );
        }
        println!("terminating broker pid={pid} (image: {image}) ...");
        // SAFETY: h was opened above with PROCESS_TERMINATE access.
        unsafe { TerminateProcess(h, 1) }.context("TerminateProcess")?;
        // SAFETY: h was opened above with PROCESS_SYNCHRONIZE access; bounded
        //         by the OS's own teardown of the process just terminated.
        unsafe { WaitForSingleObject(h, INFINITE) };
        println!("broker terminated; attached clients will fail over to a new broker automatically");
        Ok(())
    })();

    // SAFETY: h was opened above and is closed exactly once here, on every
    //         path (success or any error surfaced by the closure).
    unsafe { CloseHandle(h).ok() };
    result
}

/// Case-insensitive path compare — Windows paths are case-insensitive, and
/// both sides here come from trusted kernel/OS sources (`current_exe()`,
/// `QueryFullProcessImageNameW`), not attacker-controlled input, so a plain
/// fold is sufficient (unlike the guest-spoof-detection fold in
/// `pipe_server::ownership::exe_paths_match`, unreachable from this lib
/// crate anyway — see `image_path_from_handle`'s doc).
fn same_image(a: &str, b: &Path) -> bool {
    a.eq_ignore_ascii_case(&b.to_string_lossy())
}

/// Kernel-truth image path of an already-open process handle
/// (`QueryFullProcessImageNameW`). Duplicate of
/// `pipe_server::ownership::image_path_from_handle` (bin-crate-only,
/// unreachable from `cli`/lib crate — same constraint as
/// `cli::query_process_create_time`'s own doc) — identical call, identical
/// growing-buffer retry.
fn image_path_from_handle(h: HANDLE) -> Option<String> {
    let mut size = 1024u32;
    loop {
        let mut buf = vec![0u16; size as usize];
        let mut len = size;
        // SAFETY: h is a valid process handle (caller's contract); buf is a
        //         fully initialized UTF-16 buffer of `size` u16s that
        //         outlives the call; QueryFullProcessImageNameW writes only
        //         into buf and `len`.
        match unsafe {
            QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len)
        } {
            Ok(()) => {
                let written = (len as usize).min(buf.len());
                let mut path = &buf[..written];
                while path.last() == Some(&0) {
                    path = &path[..path.len() - 1];
                }
                if path.is_empty() {
                    return None;
                }
                return Some(String::from_utf16_lossy(path));
            }
            Err(e) if e.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) => {
                if size >= 32768 {
                    return None;
                }
                size = size.saturating_mul(2);
            }
            Err(_) => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::process::CommandExt;

    #[test]
    fn same_image_is_case_insensitive() {
        assert!(same_image(r"C:\Prog\winrsbox.exe", Path::new(r"c:\prog\WINRSBOX.EXE")));
    }

    #[test]
    fn same_image_rejects_different_paths() {
        assert!(!same_image(r"C:\Prog\winrsbox.exe", Path::new(r"C:\Other\winrsbox.exe")));
    }

    #[test]
    fn image_path_from_handle_reads_this_own_process() {
        // SAFETY: querying our own PID with a right we already hold via
        //         GetCurrentProcess's pseudo-handle-equivalent full access.
        let h = unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, std::process::id())
        }
        .expect("open own process");
        let path = image_path_from_handle(h).expect("read own image path");
        // SAFETY: h was opened just above and is closed exactly once here.
        unsafe { CloseHandle(h).ok() };
        assert!(
            path.to_lowercase().ends_with(".exe"),
            "own image path must look like an exe path: {path}"
        );
        let own = std::env::current_exe().unwrap();
        assert!(same_image(&path, &own), "own kernel-reported path must match current_exe(): {path} vs {}", own.display());
    }

    #[test]
    fn restart_refuses_a_process_with_a_different_image() {
        // cmd.exe is never this winrsbox.exe — restart_broker_process must
        // refuse it (and must not actually terminate it).
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "ping -n 3 127.0.0.1 >nul"])
            .creation_flags(0x0800_0000 /* CREATE_NO_WINDOW */)
            .spawn()
            .expect("spawn cmd.exe");
        let pid = child.id();
        let err = restart_broker_process(pid).expect_err("must refuse a non-winrsbox image");
        assert!(
            err.to_string().contains("refusing to restart"),
            "got: {err:#}"
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "the wrong-image process must NOT have been terminated"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn read_live_broker_is_none_without_a_broker_json() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_live_broker(dir.path()).is_none());
    }
}
