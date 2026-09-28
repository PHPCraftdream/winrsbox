pub mod diag;
pub mod fs;
pub mod netdev;
pub mod reg;
pub mod state;
pub mod shell;

pub mod id {
use xxhash_rust::xxh3::Xxh3;

/// Generate a deterministic ID: `<kind>-<8hex>` from xxh3 of sorted args.
pub fn generate_id(kind: &str, args: &[&str]) -> String {
    let mut parts: Vec<&str> = args.to_vec();
    parts.sort();
    let mut hasher = Xxh3::new();
    for p in &parts {
        hasher.update(p.as_bytes());
        hasher.update(&[0]);
    }
    let hash = hasher.digest();
    format!("{}-{:08x}", kind, hash & 0xFFFFFFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_deterministic() {
        let a = generate_id("rule", &["c:\\users\\*", "deny"]);
        let b = generate_id("rule", &["c:\\users\\*", "deny"]);
        assert_eq!(a, b);
    }

    #[test]
    fn id_ignores_order() {
        let a = generate_id("rule", &["c:\\test", "cow"]);
        let b = generate_id("rule", &["cow", "c:\\test"]);
        assert_eq!(a, b);
    }

    #[test]
    fn id_kind_differs() {
        let a = generate_id("rule", &["c:\\test"]);
        let b = generate_id("mock", &["c:\\test"]);
        assert_ne!(a, b);
    }

    #[test]
    fn id_format() {
        let id = generate_id("rule", &["c:\\test"]);
        assert!(id.starts_with("rule-"));
        assert_eq!(id.len(), 13); // "rule-" + 8 hex chars
    }

    #[test]
    fn id_case_sensitive_args() {
        let a = generate_id("rule", &["c:\\test"]);
        let b = generate_id("rule", &["c:\\TEST"]);
        assert_ne!(a, b);
    }
}
}

use anyhow::{Context, Result};

/// Exit codes (structured, testable).
pub const EXIT_OK: i32 = 0;
pub const EXIT_USER_ERROR: i32 = 1;
pub const EXIT_SYSTEM_ERROR: i32 = 2;
pub const EXIT_CONFLICT: i32 = 3;

/// Known subcommands — used for back-compat dispatch.
pub const SUBCOMMANDS: &[&str] = &[
    "rule", "mock", "mockdir", "defaults", "why", "what-if", "export", "import",
    "regrule", "regmock", "regdefaults", "regwhy",
    "devrule", "netrule", "memdefaults",
    "shell",
    "doctor",
    "probe",
    "broker",
];

/// Check if args represent a CLI subcommand (vs legacy sandbox run).
pub fn is_cli_command(args: &[String]) -> bool {
    if args.is_empty() { return false; }
    let first = args[0].to_lowercase();
    SUBCOMMANDS.contains(&first.as_str())
}

pub const CLI_HELP: &str = "\
winrsbox — Windows filesystem sandbox CLI

SUBCOMMANDS:
  rule       Add, remove, list, show, or clear sandbox rules
  mock       Add, remove, list, or show file mocks
  mockdir    Add, remove, or list mocked directories
  defaults   Set or show default read/write policy modes
  why        Simulate a path lookup — show decision, target path, and rule chain
  what-if    Test a hypothetical rule change without mutating state
  export     Dump current state as JSON to stdout (filesystem + registry)
  import     Load state from JSON stdin (merge or --replace) or --ktav file

DIAGNOSTICS:
  doctor     Pre-flight system check (WFP, mitigations, Defender)
  probe      R04 Этап 0: dump own token/Job state (read-only, no mutation).
             --spawn-child also inspects a throwaway suspended cmd.exe child.
  broker     status  Show the running broker's identity/health, or
                      \"брокер не запущен\" if none is running.
             restart Terminate the running broker (refuses a process whose
                      image isn't this winrsbox.exe); attached clients fail
                      over automatically.

EXPLORER INTEGRATION:
  shell      Install/uninstall Explorer right-click context menu entries

MEMORY PROTECTION:
  memdefaults Set or show cross-process memory operation policy

NETWORK SANDBOX:
  netrule    Add, remove, list, or clear network access rules (host+port)

DEVICE SANDBOX:
  devrule    Add, remove, list, or clear device access rules (deny-by-default)

REGISTRY SANDBOX:
  regrule    Add, remove, list, or clear registry sandbox rules
  regmock    Add, remove, or list registry value mocks
  regdefaults Set or show default registry read/write policy modes
  regwhy     Simulate a registry key lookup — show decision and source

GLOBAL OPTIONS:
  --state-dir=PATH   Override state directory (default: auto-discover)
  WINRSBOX_STATE_DIR  env var — same as --state-dir

EXIT CODES:
  0  Success
  1  User error (bad args, invalid mode, unknown id)
  2  System error (IO, permissions, redb)

EXAMPLES:
  winrsbox rule add --prefix='C:\\Users\\*\\AppData' --write=deny
  winrsbox why 'C:\\Users\\alice\\doc.txt' --write --depth=1 --json
  winrsbox what-if rule add --prefix='C:\\Secret' --write=deny -- C:\\foo
  winrsbox export --json > backup.json
  winrsbox import --replace < backup.json
";

/// Dispatch CLI subcommand. `state_dir` is the `.winrsbox/<name>/` path.
pub fn run_cli(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{}", CLI_HELP);
        return Ok(());
    }
    let cmd = args[0].to_lowercase();
    let rest = &args[1..];

    match cmd.as_str() {
        "rule" => fs::rule::run(rest, state_dir),
        "mock" => fs::mock::run(rest, state_dir),
        "mockdir" => fs::mockdir::run(rest, state_dir),
        "defaults" => fs::defaults::run(rest, state_dir),
        "why" => fs::r#why::run(rest, state_dir),
        "what-if" => fs::r#why::run_what_if(rest, state_dir),
        "export" => state::export::run_export(rest, state_dir),
        "import" => state::export::run_import(rest, state_dir),
        "regrule" => reg::regrule::run(rest, state_dir),
        "regmock" => reg::regmock::run(rest, state_dir),
        "regdefaults" => reg::regdefaults::run(rest, state_dir),
        "regwhy" => reg::regwhy::run(rest, state_dir),
        "devrule" => netdev::devrule::run(rest, state_dir),
        "netrule" => netdev::netrule::run(rest, state_dir),
        "memdefaults" => netdev::memdefaults::run(rest, state_dir),
        "shell" => shell::run(rest),
        "doctor" => diag::doctor::run(),
        "probe" => diag::probe::run(rest),
        "broker" => state::broker::run(rest, state_dir),
        _ => anyhow::bail!("unknown subcommand '{}'. Run 'winrsbox --help' for usage.", cmd),
    }
}

/// Open the policy database (create if needed).
fn open_db(state_dir: &std::path::Path) -> Result<redb::Database> {
    let db_path = state_dir.join("policy.redb");
    let db = redb::Database::create(&db_path)?;
    // Ensure tables exist
    {
        let txn = db.begin_write()?;
        txn.open_table(policy::db::RULES)?;
        txn.open_table(policy::db::MOCKS)?;
        txn.open_table(policy::db::MOCK_DIRS)?;
        txn.open_table(policy::db::OVERLAY_IDX)?;
        txn.open_table(policy::db::REG_RULES)?;
        txn.open_table(policy::db::REG_MOCKS)?;
        txn.open_table(policy::db::DEV_RULES)?;
        txn.open_table(policy::db::NET_RULES)?;
        txn.commit()?;
    }
    Ok(db)
}

// ─── MP-9: policy-mutating commands while a broker session is running ─────
//
// `docs/multiprocess-broker-plan.md`, "CLI при идущей сессии". A CLI
// command that mutates/reads policy state normally opens `policy.redb`
// directly (`open_db` above). While a broker holds the file open for a live
// session, `redb::Database::create` fails with `DatabaseAlreadyOpen`
// instead — this module relays the SAME operation to the broker over IPC
// (`ipc::Req::PolicyMutate`) so `winrsbox rule add ...` (and friends) keeps
// working, and the running session sees the change immediately (the broker
// refreshes its own caches — see `policy::db::PolicyOp::touches_fs_snapshot`
// / `touches_reg_snapshot`).

/// Budget for re-attempting a DIRECT db open after the broker path itself
/// failed (broker dead / mid-failover), mirroring MP-0/MP-2's own retry
/// budget for the same recovery window (redb measured 7-12 ms first-attempt
/// recovery after `TerminateProcess`ing the previous owner —
/// `docs/investigations/mp-0-broker-primitives.md`). A short, separate
/// constant here rather than reusing `main::broker`'s: that module is
/// bin-crate-only and unreachable from `cli` (lib crate).
const CLI_DB_OPEN_RETRIES: u32 = 10;
const CLI_DB_OPEN_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(30);

/// `true` iff `err`'s root cause is exactly `redb`'s "another process
/// already holds this database open" — the MP-9 broker-relay signal. Any
/// other error (corrupt db, io error, ...) must propagate as before.
fn is_db_locked(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<redb::DatabaseError>(),
        Some(redb::DatabaseError::DatabaseAlreadyOpen)
    )
}

/// Duplicate of `pipe_server::ownership::query_process_create_time`
/// (bin-crate-only, unreachable from `cli`/lib crate) — same
/// `GetProcessTimes` call, same "0 = unqueryable/dead" contract.
fn query_process_create_time(pid: u32) -> Option<u64> {
    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    if pid == 0 {
        return None;
    }
    // SAFETY: pid is a non-zero PID; bInheritHandle=false. Failure (process
    //         gone / access denied) yields Err, mapped to None by `?`.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()? };
    let (mut create, mut exit, mut kernel, mut user) = (
        FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default(),
    );
    // SAFETY: h is the just-opened valid process handle; the four FILETIME
    //         out-params are stack-owned and outlive this call.
    let ok = unsafe { GetProcessTimes(h, &mut create, &mut exit, &mut kernel, &mut user) };
    // SAFETY: h was opened above and is closed exactly once here.
    unsafe { CloseHandle(h).ok() };
    if ok.is_err() {
        return None;
    }
    let ct = ((create.dwHighDateTime as u64) << 32) | (create.dwLowDateTime as u64);
    if ct == 0 { None } else { Some(ct) }
}

/// Connect to the broker named in `state_dir`'s `broker.json` and verify
/// its identity before trusting it: broker pid still alive with a matching
/// kernel creation time, and the pipe's SERVER side really is that broker
/// (`GetNamedPipeServerProcessId`) — the same defence
/// `main::broker::client_attach` applies for a joining launcher, applied
/// here to a CLI process instead. No job/section handles are requested —
/// a CLI command has no use for them, unlike a full `Attach`.
fn connect_broker_for_mutate(state_dir: &std::path::Path) -> Result<ipc::SyncClient> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;

    let broker_json_path = state_dir.join(crate::contain::session_section::BROKER_JSON_FILE_NAME);
    let doc = crate::contain::session_section::read_broker_json(&broker_json_path)
        .context("read broker.json")?;

    let live_ct = query_process_create_time(doc.broker_pid)
        .ok_or_else(|| anyhow::anyhow!("broker pid {} is not alive", doc.broker_pid))?;
    anyhow::ensure!(
        live_ct == doc.broker_create_time,
        "broker pid {} was reused (creation time mismatch)",
        doc.broker_pid,
    );

    let client = ipc::SyncClient::connect(&doc.pipe_name)
        .with_context(|| format!("connect to broker pipe {}", doc.pipe_name))?;

    let mut server_pid: u32 = 0;
    // SAFETY: `pipe_raw_handle()` is the client's own live, connected pipe
    //         handle for the duration of this call; `server_pid` is a valid
    //         out-pointer.
    unsafe { GetNamedPipeServerProcessId(HANDLE(client.pipe_raw_handle() as _), &mut server_pid) }
        .context("GetNamedPipeServerProcessId")?;
    anyhow::ensure!(
        server_pid == doc.broker_pid,
        "pipe server pid {server_pid} != broker.json broker_pid {}",
        doc.broker_pid,
    );

    Ok(client)
}

/// Backend for a policy command: a direct, exclusively-locked
/// `redb::Database` handle when no session is running, or a round-trip
/// through the folder broker when one is. `exec` executes the SAME
/// `policy::db::PolicyOp` either way — `policy::db::exec` is the shared
/// implementation both this (direct) and the broker
/// (`pipe_server::mutate::execute_policy_mutate`) call, so the two paths
/// cannot observably diverge.
pub(crate) enum PolicyBackend {
    Direct(redb::Database),
    Broker(ipc::SyncClient),
}

impl PolicyBackend {
    /// Open the backend for `state_dir`: direct db access when free; the
    /// broker relay when a session holds it; a short direct-open retry
    /// (`CLI_DB_OPEN_RETRIES`) when the broker itself can't be reached
    /// (dead / mid-failover) — the same recovery window MP-0/MP-2 already
    /// rely on elsewhere; a clear error only once both are exhausted.
    pub(crate) fn open(state_dir: &std::path::Path) -> Result<Self> {
        match open_db(state_dir) {
            Ok(db) => return Ok(Self::Direct(db)),
            Err(e) if !is_db_locked(&e) => return Err(e),
            Err(_) => {}
        }
        match connect_broker_for_mutate(state_dir) {
            Ok(client) => Ok(Self::Broker(client)),
            Err(broker_err) => {
                for _ in 0..CLI_DB_OPEN_RETRIES {
                    std::thread::sleep(CLI_DB_OPEN_RETRY_INTERVAL);
                    if let Ok(db) = open_db(state_dir) {
                        return Ok(Self::Direct(db));
                    }
                }
                anyhow::bail!(
                    "winrsbox: policy.redb is locked by another session and the broker \
                     could not be reached ({broker_err}); direct open retried \
                     {CLI_DB_OPEN_RETRIES} times and still failed",
                )
            }
        }
    }

    /// Execute one policy op through this backend.
    pub(crate) fn exec(&mut self, op: policy::db::PolicyOp) -> Result<policy::db::PolicyOpResult> {
        match self {
            Self::Direct(db) => policy::db::exec(db, &op).map_err(Into::into),
            Self::Broker(client) => match client.send(&ipc::Req::PolicyMutate { op })? {
                ipc::Resp::PolicyMutated(result) => Ok(result),
                ipc::Resp::Err(e) => anyhow::bail!("{e}"),
                other => anyhow::bail!("policy mutate: unexpected response: {other:?}"),
            },
        }
    }
}
