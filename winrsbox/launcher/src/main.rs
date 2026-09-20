// Assumed crate versions (pinned from Cargo.toml):
//   windows = "0.61"  (windows-0.61.3 in registry)
//   tokio   = "1"     (full features)
//   anyhow  = "1"
//   ktav    = "0.6.1"
//   serde   = "1"

mod inject;
mod pipe_server;
mod sandbox;

use anyhow::{Context, Result};
use clap::Parser;
use policy::Policy;
use rustc_hash::FxHashSet;
use winrsbox::cli;
use winrsbox::hot_stats::{HotStats, ThrottledFlusher};
use winrsbox::jsonl_log;
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

// ─── Lock-free PID → ProcInfo storage ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct ProcInfo {
    pub(crate) depth: u8,
    pub(crate) exe_lower: Arc<str>,
    /// Process creation time as a Windows FILETIME (100ns ticks since 1601)
    /// packed into a u64, captured from the kernel at insert time. The pipe
    /// gate re-queries the live PID's creation time and requires an exact
    /// match, so a recycled PID can never inherit a dead process's trust.
    /// `0` is the "unknown" sentinel — the gate fail-closes on it.
    pub(crate) create_time: u64,
}

static PROC_INFO: std::sync::OnceLock<papaya::HashMap<u32, ProcInfo>> = std::sync::OnceLock::new();

pub(crate) fn global_proc_info() -> &'static papaya::HashMap<u32, ProcInfo> {
    PROC_INFO.get_or_init(papaya::HashMap::new)
}

/// Creation-time fingerprint of the root sandboxed target, published together
/// with `root_target_pid` right after CreateProcessW (long before the resumed
/// child can connect). `0` = not yet published / unknown; the gate fail-closes.
static ROOT_CREATE_TIME: AtomicU64 = AtomicU64::new(0);

pub(crate) fn root_create_time() -> u64 {
    ROOT_CREATE_TIME.load(Ordering::Acquire)
}

/// winrsbox — runs a target process inside a CoW filesystem sandbox.
///
/// winrsbox auto-discovers a state directory next to your CWD:
/// running from `<dir>/<name>/` creates `<dir>/.winrsbox/<name>/` with
/// `workdir/` (CoW overlay) and `sandbox.ktav` (policy).
///
/// Examples:
///   winrsbox --init                      (create state dir and exit)
///   winrsbox -- node app.js              (run node inside sandbox)
///   winrsbox -d wezterm                  (show console for debugging)
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum GuardLevel {
    /// No memory protection (FS sandbox only). Same as old --weak.
    None,
    /// Content-aware scan: allow executable memory, block direct syscalls in content.
    Scan,
    /// Full protection: scan + pre-launch .text scan + JIT-safe kernel
    /// mitigations (ASLR/heap/handle/image-load/spec-exec). Deliberately does
    /// NOT prohibit dynamic code or require signed DLLs, so JIT runtimes
    /// (node/V8/.NET) and unsigned native extensions (Python .pyd, Node .node)
    /// run normally. Containment rests on the ntdll hooks + Job Object.
    Full,
    /// Hard containment (opt-in): full + ProhibitDynamicCode + signed-only DLLs.
    /// Closes the direct-syscall / fresh-ntdll hook-bypass surface that
    /// user-mode hooking cannot — at the cost of breaking JIT and unsigned
    /// native extensions. Only for pure-static targets.
    Static,
}

#[derive(Parser, Debug)]
#[command(
    name = "winrsbox",
    version,
    about = "Run a target process inside a CoW filesystem sandbox.",
    long_about = None,
)]
struct Cli {
    /// Show the console window. Without this flag the launcher hides its
    /// own console on startup so the sandbox runs invisibly.
    #[arg(short = 'd', long = "debug")]
    debug: bool,

    /// Initialise the state directory (workdir/, mock-dirs/, sandbox.ktav)
    /// and exit. No target executable is required.
    #[arg(short = 'i', long = "init")]
    init: bool,

    /// Memory protection level.
    ///   none   — no memory protection (FS sandbox only)
    ///   scan   — content-aware: scan executable bytes for direct syscalls
    ///   full   — scan + pre-launch .text scan + DLL scan + JIT-safe kernel
    ///            mitigations (default; node/python/JIT runtimes work)
    ///   static — full + ProhibitDynamicCode + signed-only DLLs (hard
    ///            containment; breaks JIT and unsigned .pyd/.node)
    #[arg(short = 'g', long = "guard", default_value = "full", value_name = "LEVEL")]
    guard: GuardLevel,

    /// Allow VirtualAlloc(PAGE_EXECUTE_READWRITE) from start.
    /// Without this, RWX-from-start is blocked (matches W^X best practice).
    /// Use for legacy packed software (old Themida 2.x).
    #[arg(long = "allow-rwx")]
    allow_rwx: bool,

    /// Skip pre-launch .text scan of the target executable.
    #[arg(long = "no-pre-scan")]
    no_pre_scan: bool,

    /// Disable specific hook categories for debugging (comma-separated).
    /// Categories: fs, memory, inject, reg, net, alpc, token, ui, proc, com,
    ///             service, shell, system, mitigations.
    /// Example: --disable-hooks inject,mitigations
    #[arg(long = "disable-hooks", value_name = "CATEGORIES")]
    disable_hooks: Option<String>,

    /// Enable trace logging from hook.dll (verbose, for debugging).
    #[arg(long = "trace")]
    trace: bool,

    /// JSONL log verbosity: error (violations only), warn (denies), info
    /// (default), trace (all decides + every hook log). Lower levels include
    /// higher ones. Precedence: this CLI flag > `log_level: ...` in the
    /// per-folder `sandbox.ktav` > built-in default "info". Set
    /// `log_level: trace` in the ktav once to make verbose logging stick
    /// across launches of that sandbox state-dir (e.g. while debugging
    /// wezterm / claude / a flaky workload) — no need to remember `--trace`
    /// or `--log-level` on every invocation. Hook diagnostics (spawn_attempt,
    /// reparse_create_blocked, winrt_activation_blocked, etc.) all flow into
    /// the JSONL too, so `trace` gives a single complete audit trail.
    #[arg(long = "log-level", value_name = "LEVEL")]
    log_level: Option<String>,

    /// Block localhost (127.0.0.0/8) connections. Prevents access to local
    /// services (databases, debug ports) but breaks MCP/LSP servers.
    #[arg(long = "block-localhost")]
    block_localhost: bool,

    /// Block clipboard access from sandboxed processes (default: allow).
    /// Without this flag, sandboxed apps can read/write clipboard normally,
    /// enabling Ctrl+C/Ctrl+V at the sandbox boundary. Set this flag when
    /// running untrusted code that could exfiltrate or pollute clipboard
    /// contents.
    #[arg(long = "strict-clipboard")]
    strict_clipboard: bool,

    /// Per-process memory limit in gigabytes (applied via Job Object).
    #[arg(long = "memory-limit", value_name = "GB")]
    memory_limit: Option<u64>,

    /// Override working directory (used by Explorer context menu integration).
    #[arg(long = "cwd", value_name = "PATH")]
    cwd: Option<String>,

    /// Target executable followed by its arguments. Everything after `--`
    /// (or after the last launcher option) is forwarded verbatim.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required_unless_present = "init",
        value_name = "TARGET [ARGS...]",
    )]
    target: Vec<String>,
}

use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0},
        Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG},
        System::Threading::{
            CreateEventW, GetExitCodeProcess, OpenProcess, ResumeThread,
            WaitForMultipleObjects, WaitForSingleObject, INFINITE,
            PROCESS_SYNCHRONIZE,
        },
    },
};

/// Build the kernel-Event name used by hook.dll to signal "initialised" to
/// the launcher (H1 fix). Format:
///     Local\fs-sandbox-init-<pid>-<32 lowercase hex chars>
///
/// The 32-char suffix is 16 bytes of cryptographically-strong entropy from
/// `BCryptGenRandom` — 128 bits, the same budget you'd spend on a UUID.
/// The launcher process keeps the only kernel handle returned by
/// `CreateEventW`; the hook.dll opens the same object by name via the
/// `FS_SANDBOX_INIT_EVENT` env var (set on this process and inherited by
/// the suspended child via CreateProcessW's environment block).
///
/// If `BCryptGenRandom` ever fails (it really shouldn't — the system RNG is
/// always available), we fall back to the predictable PID-only name so the
/// handshake still works. A panic here would brick every launch.
pub(crate) fn build_random_event_name(pid: u32) -> String {
    let mut rand_bytes = [0u8; 16];
    // SAFETY: FFI call to bcrypt!BCryptGenRandom; pbbuffer is a valid
    // mutable 16-byte slice and BCRYPT_USE_SYSTEM_PREFERRED_RNG means
    // halgorithm is unused.
    let status = unsafe {
        BCryptGenRandom(None, &mut rand_bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
    };
    if status.0 < 0 {
        // RNG unavailable — degrade to legacy predictable name rather than
        // brick the launch. The TOCTOU window is bounded by the 5-second
        // hello-handshake timeout in the launcher.
        return format!("Local\\fs-sandbox-init-{}", pid);
    }
    let mut suffix = String::with_capacity(32);
    for b in rand_bytes.iter() {
        use std::fmt::Write;
        let _ = write!(&mut suffix, "{:02x}", b);
    }
    format!("Local\\fs-sandbox-init-{}-{}", pid, suffix)
}

/// Detect whether THIS launcher was spawned inside an existing sandbox.
///
/// The outer launcher exports `FS_SANDBOX_PIPE` (its named-pipe path) into
/// the environment of every descendant — `CreateProcessW` inherits env
/// verbatim, so any nested `winrsbox.exe -- <target>` invocation inside the
/// sandbox will see the variable. Its presence is a reliable signal that we
/// are a descendant of an outer launcher, not the outer launcher itself.
///
/// Returning `true` here tells `main()` to skip the entire sandbox setup
/// (no state dir, no pipe, no overlay, no hook injection) and delegate the
/// target directly to the outer sandbox's process hook.
/// (issue C, #63)
fn is_nested_invocation() -> bool {
    std::env::var_os("FS_SANDBOX_PIPE").is_some()
}

/// Build the transparent-delegation `Command` used when this launcher is
/// itself running inside an outer sandbox (issue C, #63).
///
/// `target` is the full `cli.target` vector — `target[0]` is the executable
/// and `target[1..]` are its arguments, all forwarded verbatim. No sandbox
/// plumbing (pipe / overlay / hook / mitigations) is attached: the outer
/// sandbox's process hook in our parent observes the spawn and applies its
/// own containment, so a second nested layer would only duplicate work.
///
/// Extracted as a pure builder (no `.spawn()`/`.status()`) so a unit test can
/// assert every argument survives the handoff — a regression where only the
/// executable reached the child (e.g. dropping `target[1..]`) would otherwise
/// silently turn `cmd.exe /c "echo X"` into an interactive `cmd.exe`.
fn build_delegation_command(target: &[String]) -> std::process::Command {
    // clap's `target` field has `required_unless_present = "init"`, and we
    // only enter the nested branch when `!cli.target.is_empty()`, so
    // `target[0]` is always safe here.
    let mut cmd = std::process::Command::new(&target[0]);
    if target.len() > 1 {
        cmd.args(&target[1..]);
    }
    // stdio is inherited by default — the outer sandbox captures the spawn
    // via its NtCreateUserProcess hook, so no FS_SANDBOX_* env is needed.
    cmd
}

// ─── Child-exit drain (scales past MAXIMUM_WAIT_OBJECTS) ─────────────────────────────

/// Hard limit of WaitForMultipleObjects: a call naming more handles than
/// this fails with WAIT_FAILED instead of waiting.
const MAXIMUM_WAIT_OBJECTS: usize = 64;

/// Total grace window the launcher gives all sandboxed children to exit
/// after the root target is gone. Same budget the previous single
/// WaitForMultipleObjects call used — chunking must not extend it.
const CHILD_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// The one native call the drain loop is allowed to make. A trait so the
/// loop's >64-scaling, per-exit observation and pruning are unit-testable
/// without real process handles (see `child_drain_tests`).
trait ChildWaitSet {
    /// Block until at least one handle in `keys` signals, up to
    /// `timeout_ms`. Returns the index in `keys` of a signalled handle, or
    /// None on timeout or wait failure.
    fn wait_any(&mut self, keys: &[isize], timeout_ms: u32) -> Option<usize>;
}

struct Win32ChildWaitSet;

impl ChildWaitSet for Win32ChildWaitSet {
    fn wait_any(&mut self, keys: &[isize], timeout_ms: u32) -> Option<usize> {
        debug_assert!(!keys.is_empty(), "empty wait-set would block forever");
        debug_assert!(
            keys.len() <= MAXIMUM_WAIT_OBJECTS,
            "chunk overflow: {} > {MAXIMUM_WAIT_OBJECTS} - WaitForMultipleObjects would fail",
            keys.len()
        );
        let handles: Vec<HANDLE> = keys.iter().map(|&k| HANDLE(k as *mut _)).collect();
        // SAFETY: handles are PROCESS_SYNCHRONIZE handles opened via
        //         OpenProcess at the drain site and still open while this runs.
        let code = unsafe { WaitForMultipleObjects(&handles, false, timeout_ms) };
        // WAIT_OBJECT_0 + i names a signalled handle; anything else (timeout,
        // failure) is "no observation" — the caller's deadline and final
        // zero-timeout sweep handle the rest.
        let idx = code.0.wrapping_sub(WAIT_OBJECT_0.0);
        if (idx as usize) < keys.len() { Some(idx as usize) } else { None }
    }
}

/// Wait for every child handle to signal (process exited), observing each
/// exit the moment it happens: `on_exit` runs per child exactly once, so
/// exit-pruning is never batched behind the whole set. Handles are waited
/// on in chunks of at most MAXIMUM_WAIT_OBJECTS — a process tree wider
/// than 64 children stays fully tracked, which the previous single
/// bWaitAll=true call silently did not (it failed with WAIT_FAILED and the
/// grace window never happened). One deadline bounds the TOTAL grace across
/// all chunks, so chunking cannot extend the window. A final zero-timeout
/// sweep catches exits landing between the last wait and the deadline.
/// Handles are NOT closed here — the caller owns them.
fn wait_and_prune_children<W: ChildWaitSet>(
    waiter: &mut W,
    children: &[(u32, isize)],
    grace: Duration,
    on_exit: &mut dyn FnMut(u32),
) {
    let deadline = Instant::now() + grace;
    let mut observed = vec![false; children.len()];
    loop {
        let pending: Vec<usize> = (0..children.len()).filter(|&i| !observed[i]).collect();
        if pending.is_empty() {
            return;
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        let remaining_ms = remaining.as_millis().min(u32::MAX as u128) as u32;
        let chunk: Vec<isize> = pending
            .iter()
            .take(MAXIMUM_WAIT_OBJECTS)
            .map(|&i| children[i].1)
            .collect();
        let Some(idx) = waiter.wait_any(&chunk, remaining_ms) else {
            break;
        };
        let i = pending[idx];
        observed[i] = true;
        on_exit(children[i].0);
    }
    // Zero-timeout sweep: prune children that exited between the last wait
    // and the deadline without spending any more wall-clock time.
    for i in 0..children.len() {
        if observed[i] {
            continue;
        }
        if waiter.wait_any(&[children[i].1], 0).is_some() {
            observed[i] = true;
            on_exit(children[i].0);
        }
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

/// cancel-safe: NO — top-level main is not meant to be cancelled
///
/// Thin wrapper around `run()`: any error must exit via `std::process::exit`
/// rather than a bare `?`-propagated return, because the pipe-accept loop
/// parks a blocking-pool thread in `ConnectNamedPipe` with no timeout — if
/// `main` returns normally, `#[tokio::main]`'s generated wrapper drops the
/// `Runtime`, which blocks joining that thread. Since no client will ever
/// connect once startup has failed, a plain `return Err(..)` here hangs the
/// process indefinitely instead of reporting the error.
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let raw_args: Vec<String> = std::env::args().collect();

    // Back-compat dispatch: if first arg after binary is a known subcommand,
    // route to CLI handler. Otherwise, use legacy clap parser for sandbox run.
    // If WINRSBOX_STATE_DIR is set, always use CLI mode (agents/tests).
    let force_cli = std::env::var("WINRSBOX_STATE_DIR").is_ok();
    if raw_args.len() > 1 && (cli::is_cli_command(&raw_args[1..]) || force_cli) {
        // CLI mode: no console hiding, no tokio runtime needed
        let state_dir = if let Some(sd) = raw_args.iter().find(|a| a.starts_with("--state-dir=")) {
            PathBuf::from(&sd["--state-dir=".len()..])
        } else if let Ok(sd) = std::env::var("WINRSBOX_STATE_DIR") {
            PathBuf::from(sd)
        } else {
            let project_root: PathBuf = std::env::current_dir()
                .context("failed to get current directory")?;
            sandbox::discover_state_dir(&project_root)?
        };
        std::fs::create_dir_all(state_dir.join("workdir"))
            .with_context(|| "create state dir")?;
        std::fs::create_dir_all(state_dir.join("mock-dirs"))
            .with_context(|| "create mock-dirs")?;

        // Strip --state-dir from args before passing to CLI
        let cli_args: Vec<String> = raw_args[1..].iter()
            .filter(|a| !a.starts_with("--state-dir="))
            .cloned()
            .collect();
        match cli::run_cli(&cli_args, &state_dir) {
            Ok(()) => std::process::exit(cli::EXIT_OK),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(cli::EXIT_USER_ERROR);
            }
        }
    }

    let cli = Cli::parse();

    // Hide our console window before any println! when running headless
    // (default). With -d we keep the window visible for debugging.
    sandbox::maybe_hide_console(cli.debug);

    if let Some(ref cwd) = cli.cwd {
        std::env::set_current_dir(cwd)
            .with_context(|| format!("failed to set working directory to '{cwd}'"))?;
    }

    // ── Nested-sandbox guard (issue C, #63) ─────────────────────────────────
    // The outer (first) launcher exports FS_SANDBOX_PIPE into the environment
    // of every descendant process. If WE see it, we are already inside a
    // sandbox: spawning a second pipe + overlay here would duplicate the
    // containment and waste resources. Instead, transparently delegate the
    // target to the outer sandbox by launching it directly (no mitigations,
    // no pipe, no overlay, no hook injection) and propagating its exit code.
    // The outer sandbox's NtCreateUserProcess hook in our parent process
    // captures this target exactly like any other child, so isolation is
    // preserved without a nested layer.
    //
    // CLI subcommands (rule/why/export/...) are routed earlier in main() and
    // never reach here, so they keep working inside a sandbox for policy
    // inspection. `--init` / `--help` are also exempt.
    // Resolve the target to a full image path ONCE, before anything consumes
    // it. `CreateProcessW` only ever appends `.exe` to a bare name, so
    // `winrsbox cx` (a `cx.bat` on PATH) failed with 0x80070002; and five
    // separate consumers below — the nested-delegation command,
    // `trust::verify_signature`, `inject::pre_launch_scan`, the WFP
    // `app_id_from_path` and the root `ProcInfo` entry — each took the raw
    // string and silently degraded on it. The WFP case was the dangerous
    // one: a bare name cannot be canonicalized, so `add_filter` refused to
    // install the (correctly) app-scoped RFC1918 egress block and the
    // sandbox simply had no such filter.
    let mut cli = cli;
    if !cli.init && !cli.target.is_empty() {
        cli.target[0] = sandbox::resolve_target(&cli.target[0])?;
    }

    if !cli.init && !cli.target.is_empty() && is_nested_invocation() {
        eprintln!(
            "[sandbox] nested invocation detected — delegating <{}> to the outer sandbox",
            cli.target[0]
        );
        // stdio is inherited by default; the outer sandbox observes the spawn
        // via its own process hook, so no FS_SANDBOX_* plumbing is needed.
        let status = build_delegation_command(&cli.target)
            .status()
            .with_context(|| format!("nested delegation failed to spawn '{}'", cli.target[0]))?;
        std::process::exit(status.code().unwrap_or(1));
    }

    let project_root: PathBuf = std::env::current_dir()
        .context("failed to get current directory")?;

    let (cfg_path, sandbox_root, mock_dirs_root) = sandbox::ensure_state(&project_root)?;

    if cli.init {
        println!("[sandbox] state dir ready at {}", cfg_path.parent().unwrap().display());
        return Ok(());
    }

    let target_args = cli.target;

    // Open / create policy DB
    // Policy DB lives at the STATE-DIR level (parent of workdir), NOT inside
    // the overlay root. This is a security invariant: "under workdir = ONLY
    // agent CoW data". If policy.redb lived under workdir, the self-access
    // carve-out in the hook (which allows absolute overlay-path reopens for
    // the process's own CoW files) would expose it — an agent could read or
    // corrupt its own policy database.
    let state_dir = cfg_path.parent().unwrap_or(&sandbox_root);
    let db_path = state_dir.join("policy.redb");
    // Migration: move an existing DB from the old workdir-internal location.
    let old_db_path = sandbox_root.join("policy.redb");
    if !db_path.exists() && old_db_path.exists() {
        let _ = std::fs::rename(&old_db_path, &db_path);
    }

    // Same-volume overlay layout (fixes the drive-letter identity leak — Bug A):
    // the overlay for each virtual drive must live on THAT SAME drive, so the
    // kernel's GetFinalPathNameByHandleW reports the correct drive letter
    // (taken from the handle's physical volume). Primary root = sandbox_root
    // (project drive). Add an explicit C: root at %LOCALAPPDATA%\.winrsbox so
    // installers writing to C:\Users\…\AppData land on C:, not the project
    // drive. The session sub-dir matches the project's .winrsbox layout.
    let mut overlay_layout = policy::path::OverlayLayout::single(sandbox_root.clone());
    {
        let session_name = project_root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "session".to_string());
        if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
            let c_root = PathBuf::from(local_appdata)
                .join(".winrsbox")
                .join(&session_name)
                .join("workdir");
            // Only register a C: root if C: is NOT already the project drive
            // (avoids a redundant/duplicate root).
            let project_drive = project_root
                .to_string_lossy()
                .chars()
                .next()
                .map(|c| c.to_ascii_lowercase());
            if project_drive != Some('c') {
                std::fs::create_dir_all(&c_root).with_context(|| {
                    format!("create C: overlay root {}", c_root.display())
                })?;
                overlay_layout.set_drive_root('c', c_root);
            }
        }
    }
    let policy = Arc::new(
        Policy::open_or_create_with_layout(
            &db_path,
            overlay_layout,
            mock_dirs_root.clone(),
            project_root.clone(),
        )?,
    );
    policy.load_config(&cfg_path)?;

    // Registry policy — shares the FS policy DB; overlay store lives under
    // <state_dir>/workreg. Required for sandboxed installers that write user
    // env-vars / config to the registry (CoW-overlayed, host untouched).
    let workreg_root = cfg_path.parent().unwrap().join("workreg");
    std::fs::create_dir_all(&workreg_root)?;
    let reg_policy = Arc::new(policy::RegistryPolicy::open(policy.db(), workreg_root)?);

    // Named pipe name — use launcher PID for uniqueness
    let pipe_name = format!(r"\\.\pipe\fs-sandbox-{}", std::process::id());

    // Stats — shared between connection handlers (lock-free atomics)
    let stats = Arc::new(pipe_server::Stats::default());

    // Child PIDs registered from hook via IPC RegisterChild
    let child_pids: Arc<crossbeam_queue::SegQueue<u32>> = Arc::new(crossbeam_queue::SegQueue::new());

    // Violations log path
    let violations_log = cfg_path.parent().unwrap().join("violations.log");

    // JSONL structured log — persistent, machine-parseable.
    // Log-level precedence: CLI `--log-level` > `log_level:` in sandbox.ktav >
    // built-in default "info". Re-parsing the ktav here is cheap (small file)
    // and avoids plumbing a Config getter through Policy. ktav fields that
    // policy didn't recognise are ignored on its side; ours are ignored on
    // its side too — both views deserialize the same file independently.
    let ktav_log_level: Option<String> = std::fs::read_to_string(&cfg_path)
        .ok()
        .and_then(|src| ktav::from_str::<policy::db::Config>(&src).ok())
        .and_then(|c| c.log_level);
    // `--trace` is a blanket "show me everything" switch: it also raises the
    // JSONL/console verbosity to trace, on top of the FS_SANDBOX_TRACE gate
    // it sets for hook.dll below. Without this, `--trace` would enable
    // hook-side trace events while the console (gated on jsonl_log's level)
    // stayed silent for them.
    let effective_log_level = if cli.trace {
        "trace".to_string()
    } else {
        cli.log_level
            .clone()
            .or(ktav_log_level)
            .unwrap_or_else(|| "info".to_string())
    };
    jsonl_log::init(
        cfg_path.parent().unwrap().join("sandbox.log.jsonl"),
        &effective_log_level,
    );

    // Hot-stats: aggregates access patterns, flushed to disk at most once per 5s.
    let hot_stats = HotStats::new();
    let flusher = Arc::new(ThrottledFlusher::new(
        Arc::clone(&hot_stats),
        cfg_path.parent().unwrap().join("hot-stats.json"),
    ));

    // C3 Part 3: shared slot for the root sandboxed target's PID. The
    // accept loop reads this on every new connection to validate the
    // client's PID matches our own root or one of its tracked children.
    // It starts at 0 ("unknown") and is published below, immediately after
    // `launch_suspended`, well before the child is resumed and can connect.
    let root_target_pid: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));

    // ── Pipe server (accept loop in background task) ──────────────────────
    {
        let policy = Arc::clone(&policy);
        let reg_policy = Arc::clone(&reg_policy);
        let stats = Arc::clone(&stats);
        let child_pids = Arc::clone(&child_pids);
        let pipe_name2 = pipe_name.clone();
        let violations_log2 = violations_log.clone();
        let hot_stats2 = Arc::clone(&hot_stats);
        let flusher2 = Arc::clone(&flusher);
        let root_pid_slot = Arc::clone(&root_target_pid);

        tokio::spawn(async move {
            if let Err(e) = pipe_server::pipe_accept_loop(
                &pipe_name2,
                policy,
                reg_policy,
                stats,
                child_pids,
                violations_log2,
                hot_stats2,
                flusher2,
                root_pid_slot,
            )
            .await
            {
                // C3 Part 1: fail-closed for first-instance collision and any
                // other unrecoverable accept-loop error. Killing the launcher
                // here is the correct response — continuing without IPC
                // protection would silently degrade the sandbox to passthrough.
                eprintln!("[FATAL] pipe accept loop terminated: {e:#}");
                std::process::exit(0xC000_0142u32 as i32);
            }
        });
    }

    // Small delay so the pipe server starts accepting before the child tries to connect.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // ── Launch target process ─────────────────────────────────────────────
    let dll_path = sandbox::find_hook_dll()?;

    // Sanitize sensitive env vars BEFORE child inherits them.
    // Removes API keys, tokens, secrets, credentials from the environment.
    let removed = winrsbox::env_guard::sanitize();
    if removed > 0 && winrsbox::jsonl_log::console_verbose() {
        println!("[sandbox] env: sanitized {removed} sensitive variables");
    }

    // Set env vars for child before CreateProcessW — child inherits them.
    std::env::set_var("FS_SANDBOX_PIPE", &pipe_name);
    std::env::set_var("FS_SANDBOX_DLL", &dll_path);
    // Help GUI terminal emulators (WezTerm, Windows Terminal) that ignore the inherited
    // CWD and fall back to the home directory when spawning their shell.
    let cwd_str = project_root.to_string_lossy().into_owned();
    std::env::set_var("WEZTERM_EXECUTABLE_ARGS_CWD", &cwd_str);
    std::env::set_var("FS_SANDBOX_CWD", &cwd_str);
    // Publish the sandbox overlay storage dir so the hook can recognise
    // overlay files on delete and convert them back to virtual DOS paths.
    std::env::set_var("FS_SANDBOX_ROOT", sandbox_root.to_string_lossy().as_ref());
    // Pass guard configuration to hook DLL via env vars
    std::env::set_var("FS_SANDBOX_GUARD", match cli.guard {
        GuardLevel::None => "none",
        GuardLevel::Scan => "scan",
        GuardLevel::Full => "full",
        GuardLevel::Static => "static",
    });
    if cli.allow_rwx {
        std::env::set_var("FS_SANDBOX_ALLOW_RWX", "1");
    }
    if let Some(ref cats) = cli.disable_hooks {
        std::env::set_var("FS_SANDBOX_DISABLE_HOOKS", cats);
    }
    // Hook-side trace gate. Triggered by EITHER the explicit `--trace` CLI
    // flag, OR an `effective_log_level == "trace"` (from CLI `--log-level` or
    // `log_level: trace` in sandbox.ktav). Without this, hook-side trace logs
    // (com_blocked clsid=..., per-decide path traces, etc.) stay silent even
    // when launcher-side JSONL filter is set to trace — they're two separate
    // gates and the launcher-side one only catches what the hook actually
    // sends.
    if cli.trace || effective_log_level.eq_ignore_ascii_case("trace") {
        std::env::set_var("FS_SANDBOX_TRACE", "1");
    }
    if cli.block_localhost {
        std::env::set_var("FS_SANDBOX_BLOCK_LOCALHOST", "1");
    }
    if cli.strict_clipboard {
        std::env::set_var("FS_SANDBOX_STRICT_CLIPBOARD", "1");
    }

    // Publish a `SessionConfig` snapshot under a RANDOM per-session section
    // name so hooked descendants whose environment was scrubbed (MSYS2
    // first-run helpers in particular) can still discover the pipe name etc.
    // The name is not guessable and travels only through the injection
    // channel: it is exported as FS_SANDBOX_SECTION below (the root target
    // inherits it via CreateProcessW's environment block), and the spawn hook
    // patches it into every descendant's environment cross-process before
    // the child runs. The returned handle is held for the launcher's whole
    // lifetime — dropping it would destroy the section and break
    // late-arriving readers.
    let session_cfg = ipc::SessionConfig {
        pipe_name: pipe_name.clone(),
        dll_path: dll_path.clone(),
        cwd: cwd_str.clone(),
        sandbox_root: sandbox_root.to_string_lossy().into_owned(),
        // Publish ALL overlay roots (per-drive same-volume layout) so the hook
        // can mask paths against every root and derive the drive letter from
        // the matched one. Empty = single-root legacy fallback in the hook.
        overlay_roots: policy
            .overlay_layout()
            .all_roots()
            .map(|(_drive, root)| root.to_string_lossy().into_owned())
            .collect(),
        trace: cli.trace || effective_log_level.eq_ignore_ascii_case("trace"),
        guard: match cli.guard {
            GuardLevel::None => "none".into(),
            GuardLevel::Scan => "scan".into(),
            GuardLevel::Full => "full".into(),
            GuardLevel::Static => "static".into(),
        },
        allow_rwx: cli.allow_rwx,
        disable_hooks: cli.disable_hooks.clone().unwrap_or_default(),
    };
    let (_session_section, section_name) = winrsbox::session_section::publish(&session_cfg)
        .context("publish session config section")?;
    // The name IS the access control: the section exists under this random
    // name only, so every process that must read the config has to be told
    // the name through the injection channel. The root target receives it
    // here, via the inherited environment (authored before any guest code
    // runs, hence unforgeable at root start — same trust argument as
    // FS_SANDBOX_PIPE).
    std::env::set_var("FS_SANDBOX_SECTION", &section_name);

    // Create kernel Event for hook.dll init signaling.
    //
    // H1 fix: the event name embeds a 128-bit random suffix so a same-session
    // attacker cannot guess the name and SetEvent() it ahead of the real
    // hook.dll. The `Local\` namespace already scopes the object to this
    // logon session; the random suffix raises the bar from "any same-user
    // process can OpenEvent" to "attacker must enumerate the object-manager
    // directory or read our env vars" (the env var is propagated through
    // CreateProcessW's environment block to the target only).
    let init_event_name = build_random_event_name(std::process::id());
    let event_name_wide: Vec<u16> = init_event_name.encode_utf16().chain(Some(0)).collect();
    let init_event = unsafe {
        CreateEventW(None, false, false, PCWSTR(event_name_wide.as_ptr()))
    }?;
    std::env::set_var("FS_SANDBOX_INIT_EVENT", &init_event_name);

    // Guard level is taken verbatim — no trust-based downgrade. Full mode is
    // now JIT-safe (no ProhibitDynamicCode / signed-only), so unsigned dev
    // tools (node/python/cargo/git) run correctly under it; there is no longer
    // any reason to drop signed targets to scan. Hard containment that breaks
    // JIT is the explicit, opt-in `--guard static` tier. For `static` on an
    // unsigned target we warn that third-party DLL loads will be blocked at
    // runtime (hook.dll itself is exempt: stripped at create-time, re-applied
    // after it loads).
    let effective_guard = cli.guard;
    if effective_guard == GuardLevel::Static {
        // The trust verdict is ADVISORY — see trust.rs. It is shown so the
        // operator knows what they are about to run, and is deliberately NOT
        // enforced: unsigned OSS toolchains (cargo/node/python) are the
        // sandbox's normal workload and hook.dll itself is unsigned in dev
        // builds (its integrity is enforced by the digest manifest in
        // find_hook_dll instead). Do not turn this into a launch gate
        // without an opt-out for unsigned dev builds.
        let trust = winrsbox::trust::verify_signature(std::path::Path::new(&target_args[0]));
        let mitigation_note = if trust.is_trusted() {
            ""
        } else {
            "; JIT and unsigned native extensions (.pyd/.node) will be blocked by mitigation policy"
        };
        // stderr for the same reason as the exit summary below: launcher
        // diagnostics must not land in the target's stdout.
        eprintln!(
            "[sandbox] guard: static (hard containment) — {}{mitigation_note}",
            winrsbox::trust::advisory_notice(&trust)
        );
    }

    // Before the target exists: Ctrl+C in a shared console reaches the
    // launcher too, and the launcher dying closes a job marked
    // KILL_ON_JOB_CLOSE, which kills the whole sandboxed tree. Interactive
    // agents use Ctrl+C to interrupt a turn, so that turned the first
    // interrupt into "session destroyed".
    sandbox::install_console_ctrl_handler();

    let proc_info = sandbox::launch_suspended(&project_root, &target_args, effective_guard)?;

    // C3 Part 3: publish the root PID to the pipe accept loop so it can
    // validate `GetNamedPipeClientProcessId` against our own target on every
    // new IPC connection. This must happen BEFORE `ResumeThread` below; the
    // target stays suspended until then, so no connection can reach the
    // accept loop with this slot still set to 0.
    root_target_pid.store(proc_info.dwProcessId, Ordering::Release);
    ROOT_CREATE_TIME.store(
        pipe_server::process_create_time_from_handle(proc_info.hProcess),
        Ordering::Release,
    );

    // Pre-launch code integrity scan (full/static guard + not skipped).
    // The direct-syscall scan matters most for `full` (which allows JIT and so
    // can't rely on ProhibitDynamicCode); `static` runs it too as belt-and-suspenders.
    if (effective_guard == GuardLevel::Full || effective_guard == GuardLevel::Static)
        && !cli.no_pre_scan
    {
        if let Err(e) = inject::pre_launch_scan(
            proc_info.hProcess,
            &target_args[0],
            proc_info.dwProcessId,
            &violations_log,
        ) {
            // SAFETY: proc_info.hProcess is valid PROCESS handle from CreateProcessW.
            unsafe {
                windows::Win32::System::Threading::TerminateProcess(
                    proc_info.hProcess,
                    0xC000_0005,
                )
                .ok();
                CloseHandle(proc_info.hThread).ok();
                CloseHandle(proc_info.hProcess).ok();
            }
            eprintln!("pre-launch scan refused target: {e}");
            // Exit immediately — don't wait for tokio runtime drop (pipe accept loop blocks).
            std::process::exit(0xC000_0005u32 as i32);
        }
    }

    // Inject hook.dll into target before resuming. On failure the child already
    // exists (suspended, no user code has run) but is NOT yet in the Job Object —
    // terminate and clean up rather than leaving an orphaned, uncontained,
    // suspended process (mirrors the pre_launch_scan refusal path above).
    if let Err(e) = inject::inject_dll(proc_info.hProcess, proc_info.hThread, &dll_path) {
        // SAFETY: proc_info handles are valid PROCESS/THREAD handles from CreateProcessW.
        unsafe {
            windows::Win32::System::Threading::TerminateProcess(proc_info.hProcess, 0xC000_0005).ok();
            CloseHandle(proc_info.hThread).ok();
            CloseHandle(proc_info.hProcess).ok();
        }
        eprintln!("hook.dll injection failed: {e}");
        std::process::exit(0xC000_0005u32 as i32);
    }

    // Assign to Job Object — kernel auto-kills all children when launcher exits.
    // Job handle must outlive the target process.
    let _job_handle = sandbox::setup_job_object(
        proc_info.hProcess,
        cli.memory_limit,
        cli.strict_clipboard,
    )?;

    // WFP kernel-level network filtering (best-effort — needs fwpuclnt.dll).
    let _wfp = if cli.guard != GuardLevel::None {
        match winrsbox::wfp::WfpEngine::open() {
            Ok(mut engine) => {
                let target_path = std::path::Path::new(&target_args[0]);
                // Block lateral movement to RFC1918 private ranges
                for cidr_str in winrsbox::wfp::RFC1918 {
                    if let Some(cidr) = winrsbox::wfp::CidrV4::parse(cidr_str) {
                        match engine.block_outbound_cidr(target_path, &cidr) {
                            Ok(_) => {}
                            Err(e) => eprintln!("[sandbox] WFP filter {cidr_str} failed: {e}"),
                        }
                    }
                }
                // Block lateral movement to IPv6 private/local ranges
                for cidr_str in winrsbox::wfp::IPV6_PRIVATE {
                    if let Some(cidr) = winrsbox::wfp::CidrV6::parse(cidr_str) {
                        match engine.block_outbound_cidr_v6(&cidr) {
                            Ok(_) => {}
                            Err(e) => eprintln!("[sandbox] WFP v6 filter {cidr_str} failed: {e}"),
                        }
                    }
                }
                // Block localhost connections (opt-in — breaks MCP/LSP).
                if cli.block_localhost {
                    if let Some(lo) = winrsbox::wfp::CidrV4::parse("127.0.0.0/8") {
                        match engine.block_outbound_cidr(target_path, &lo) {
                            Ok(_) => {}
                            Err(e) => eprintln!("[sandbox] WFP localhost block failed: {e}"),
                        }
                    }
                }
                // Block SMB/NetBIOS egress (IPv4 + IPv6) — prevents DFS UNC
                // exfiltration to remote servers.
                for port in winrsbox::wfp::SMB_PORTS {
                    if let Err(e) = engine.block_outbound_port(*port) {
                        eprintln!("[sandbox] WFP SMB block port {port} (v4) failed: {e}");
                    }
                    if let Err(e) = engine.block_outbound_port_v6(*port) {
                        eprintln!("[sandbox] WFP SMB block port {port} (v6) failed: {e}");
                    }
                }
                let fc = engine.filter_count();
                if winrsbox::jsonl_log::console_verbose() {
                    println!("[sandbox] WFP: {fc} outbound filters registered");
                }
                jsonl_log::log(jsonl_log::Event::wfp(fc));
                Some(engine)
            }
            Err(e) => {
                eprintln!("[sandbox] WFP unavailable: {e}");
                None
            }
        }
    } else {
        None
    };

    // ETW Kernel-Process listener — monitoring layer (logs events, no enforcement).
    let _etw = if cli.guard != GuardLevel::None {
        let proc_info_ref = global_proc_info();
        let pid_checker: Arc<dyn Fn(u32) -> bool + Send + Sync> = Arc::new(move |pid: u32| {
            proc_info_ref.pin().get(&pid).is_some()
        });
        match winrsbox::etw_listener::start(pid_checker) {
            Ok(h) => {
                if winrsbox::jsonl_log::console_verbose() {
                    println!("[sandbox] ETW: Kernel-Process listener active");
                }
                Some(h)
            }
            Err(e) => {
                // Monitoring-only layer (etw_listener.rs) — commonly unavailable
                // simply because the launcher isn't elevated. Not a containment
                // gap, so keep it off the console unless --trace.
                if winrsbox::jsonl_log::console_verbose() {
                    eprintln!("[sandbox] ETW unavailable: {e}");
                }
                None
            }
        }
    } else {
        None
    };

    // Insert root target into PROC_INFO BEFORE resume — ensures ETW listener
    // sees this PID when kernel fires ImageLoad/ThreadStart during process startup.
    let arg0_lower = target_args.first()
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    global_proc_info().pin().insert(
        proc_info.dwProcessId,
        ProcInfo {
            depth: 0,
            exe_lower: Arc::from(arg0_lower.as_str()),
            create_time: pipe_server::process_create_time_from_handle(proc_info.hProcess),
        },
    );

    // Resume target main thread.
    // SAFETY: proc_info.hThread is valid for the lifetime of the child process;
    //         it was returned by CreateProcessW and has not yet been closed.
    unsafe { ResumeThread(proc_info.hThread) };
    // SAFETY: same — close the thread handle after use; the thread continues running.
    unsafe { CloseHandle(proc_info.hThread).ok() };

    // Wait for hook.dll to signal successful initialization via kernel Event.
    // spawn_blocking moves the blocking wait to tokio's thread pool — the async
    // runtime stays free to run pipe_accept_loop and other tasks.
    let event_handle_raw = init_event.0 as usize; // HANDLE → usize for Send
    let wait_result = match tokio::task::spawn_blocking(move || unsafe {
        WaitForSingleObject(HANDLE(event_handle_raw as *mut _), 5000)
    }).await {
        Ok(wr) => wr,
        Err(e) => {
            // The blocking wait task panicked / the runtime is shutting down. The
            // child was already resumed (line above) — terminate it and close the
            // handles instead of leaking them on a `?` early-return.
            // SAFETY: proc_info.hProcess + init_event are valid here.
            unsafe {
                windows::Win32::System::Threading::TerminateProcess(proc_info.hProcess, 0xC000_0005).ok();
                CloseHandle(proc_info.hProcess).ok();
                CloseHandle(init_event).ok();
            }
            anyhow::bail!("init-event wait task failed: {e}");
        }
    };

    if wait_result.0 == 0 { // WAIT_OBJECT_0
        if winrsbox::jsonl_log::console_verbose() {
            println!("[sandbox] hook.dll init confirmed (pid {})", proc_info.dwProcessId);
        }
    } else {
        eprintln!(
            "[sandbox] CRITICAL: hook.dll did not signal init within 5s, killing child pid={}",
            proc_info.dwProcessId
        );
        unsafe {
            windows::Win32::System::Threading::TerminateProcess(proc_info.hProcess, 0xC000_0005).ok();
            CloseHandle(proc_info.hProcess).ok();
        }
        unsafe { CloseHandle(init_event).ok() };
        anyhow::bail!("hook.dll injection failed — child terminated (pid={})", proc_info.dwProcessId);
    }
    unsafe { CloseHandle(init_event).ok() };

    if winrsbox::jsonl_log::console_verbose() {
        println!("[sandbox] target started (pid {})", proc_info.dwProcessId);
    }

    // ── Wait for target process ───────────────────────────────────────────
    // Offload the blocking wait to spawn_blocking so the tokio executor
    // stays free to service hook IPC requests while the target runs.
    // HANDLE (*mut c_void) is not Send; convert to isize to cross .await.
    let target_isize = proc_info.hProcess.0 as isize;
    tokio::task::spawn_blocking(move || {
        // SAFETY: target_isize is the isize repr of a valid PROCESS_ALL_ACCESS
        //         handle returned by CreateProcessW; INFINITE is correct here.
        unsafe { WaitForSingleObject(HANDLE(target_isize as *mut _), INFINITE) };
    })
    .await
    .unwrap_or_else(|e| eprintln!("[sandbox] target-wait task failed: {e}"));
    let target_handle = proc_info.hProcess;

    // Give any remaining child processes a brief window to finish.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Drain registered child PIDs into a deduplicated set and open handles.
    let mut seen = FxHashSet::default();
    let mut children: Vec<(u32, isize)> = Vec::new();
    while let Some(pid) = child_pids.pop() {
        if seen.insert(pid) {
            if let Ok(h) = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) } {
                children.push((pid, h.0 as isize));
            } else {
                // OpenProcess failed — the child is already gone and its PID
                // freed (or otherwise unreopenable); drop the dead child's
                // tracking entry so it can never be trusted again.
                global_proc_info().pin().remove(&pid);
            }
        }
    }

    if !children.is_empty() {
        // The list can exceed MAXIMUM_WAIT_OBJECTS (64): a process tree wider
        // than that must still be waited on and pruned. The old single
        // WaitForMultipleObjects(bWaitAll=true) failed outright past 64
        // handles (WAIT_FAILED, result discarded) and silently skipped the
        // whole grace window; the chunked drain below keeps the same 5 s
        // budget and observes every exit.
        let wait_list = children.clone();
        tokio::task::spawn_blocking(move || {
            let mut waiter = Win32ChildWaitSet;
            wait_and_prune_children(&mut waiter, &wait_list, CHILD_DRAIN_GRACE, &mut |pid| {
                global_proc_info().pin().remove(&pid);
            });
        })
        .await
        .unwrap_or_else(|e| eprintln!("[sandbox] child-wait task failed: {e}"));
        for (_, h) in &children {
            // SAFETY: h is a handle we own from OpenProcess above.
            unsafe { CloseHandle(HANDLE(*h as *mut _)).ok() };
        }
    }

    // Read exit code and print summary.
    let mut exit_code = 0u32;
    // SAFETY: target_handle is valid; GetExitCodeProcess fills exit_code on success.
    unsafe { GetExitCodeProcess(target_handle, &mut exit_code).ok() };
    // SAFETY: target_handle — we are done with the process.
    unsafe { CloseHandle(target_handle).ok() };

    let s = &stats;
    let viol = s.violations.load(Ordering::Relaxed);
    let (etw_total, etw_sandbox) = winrsbox::etw_listener::stats();
    // stderr, not stdout: this is the launcher talking about itself, and the
    // target's stdout belongs to the target. On stdout it corrupted every
    // piped or redirected run — `winrsbox cx > out.txt` ended with a sandbox
    // summary glued to the program's own output.
    eprintln!(
        "\n[sandbox] exit={exit_code}  decide={} redirect={} deny={} mock={} cow={} violations={viol} etw={etw_sandbox}/{etw_total}",
        s.decide.load(Ordering::Relaxed),
        s.redirect.load(Ordering::Relaxed),
        s.deny.load(Ordering::Relaxed),
        s.mock_.load(Ordering::Relaxed),
        s.cow.load(Ordering::Relaxed),
    );

    // Final logs and stats
    jsonl_log::log_immediate(jsonl_log::Event::exit(
        exit_code,
        s.decide.load(Ordering::Relaxed),
        viol,
    ));
    jsonl_log::flush();
    flusher.flush_now();

    // Exit immediately rather than returning through the tokio runtime drop path.
    // The pipe-accept loop keeps a spawn_blocking thread blocked on ConnectNamedPipe;
    // if we let the runtime drop normally it waits 30 s for that thread to finish.
    std::process::exit(exit_code as i32);
}

#[cfg(test)]
mod proc_info_tests {
    use super::*;

    #[test]
    fn insert_and_lookup() {
        let map: papaya::HashMap<u32, ProcInfo> = papaya::HashMap::new();
        map.pin().insert(100, ProcInfo { depth: 0, exe_lower: Arc::from("c:\\app.exe"), create_time: 0 });
        let info = map.pin().get(&100).cloned().unwrap();
        assert_eq!(info.depth, 0);
        assert_eq!(&*info.exe_lower, "c:\\app.exe");
    }

    #[test]
    fn lookup_missing_returns_none() {
        let map: papaya::HashMap<u32, ProcInfo> = papaya::HashMap::new();
        assert!(map.pin().get(&999).is_none());
    }

    #[test]
    fn remove_entry() {
        let map: papaya::HashMap<u32, ProcInfo> = papaya::HashMap::new();
        map.pin().insert(200, ProcInfo { depth: 1, exe_lower: Arc::from("child.exe"), create_time: 0 });
        assert!(map.pin().remove(&200).is_some());
        assert!(map.pin().get(&200).is_none());
    }

    #[test]
    fn concurrent_insert_and_lookup() {
        use std::sync::Arc;
        let map = Arc::new(papaya::HashMap::<u32, ProcInfo>::new());
        let mut handles = vec![];
        for i in 0..4 {
            let m = map.clone();
            handles.push(std::thread::spawn(move || {
                let pid = 1000 + i;
                m.pin().insert(pid, ProcInfo {
                    depth: i as u8,
                    exe_lower: Arc::from(format!("proc_{i}.exe").leak() as &str),
                    create_time: 0,
                });
                assert!(m.pin().get(&pid).is_some());
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // All 4 entries should be visible
        for i in 0..4u32 {
            assert!(map.pin().get(&(1000 + i)).is_some());
        }
    }

    #[test]
    fn depth_chain_root_child_grandchild() {
        let map: papaya::HashMap<u32, ProcInfo> = papaya::HashMap::new();
        // Root
        map.pin().insert(10, ProcInfo { depth: 0, exe_lower: Arc::from("root.exe"), create_time: 0 });
        // Child
        map.pin().insert(20, ProcInfo { depth: 1, exe_lower: Arc::from("child.exe"), create_time: 0 });
        // Grandchild
        map.pin().insert(30, ProcInfo { depth: 2, exe_lower: Arc::from("grandchild.exe"), create_time: 0 });

        assert_eq!(map.pin().get(&10).unwrap().depth, 0);
        assert_eq!(map.pin().get(&20).unwrap().depth, 1);
        assert_eq!(map.pin().get(&30).unwrap().depth, 2);
    }

    #[test]
    fn overwrite_updates_value() {
        let map: papaya::HashMap<u32, ProcInfo> = papaya::HashMap::new();
        map.pin().insert(50, ProcInfo { depth: 0, exe_lower: Arc::from("old.exe"), create_time: 0 });
        map.pin().insert(50, ProcInfo { depth: 1, exe_lower: Arc::from("new.exe"), create_time: 0 });
        let info = map.pin().get(&50).cloned().unwrap();
        assert_eq!(info.depth, 1);
        assert_eq!(&*info.exe_lower, "new.exe");
    }
}

#[cfg(test)]
mod cmdline_tests {
    use crate::sandbox::build_cmdline;

    #[test]
    fn simple_no_quoting() {
        assert_eq!(build_cmdline(&["foo".into(), "bar".into()]), "foo bar");
    }

    #[test]
    fn spaces_get_quoted() {
        assert_eq!(build_cmdline(&["hello world".into()]), "\"hello world\"");
    }

    #[test]
    fn backslash_in_path_not_doubled() {
        assert_eq!(
            build_cmdline(&[r"C:\Program Files\app.exe".into()]),
            r#""C:\Program Files\app.exe""#,
        );
    }

    #[test]
    fn trailing_backslash_doubled_before_close_quote() {
        // Only relevant when arg needs quoting (has spaces)
        assert_eq!(
            build_cmdline(&[r"C:\my dir\".into()]),
            r#""C:\my dir\\""#,
        );
    }

    #[test]
    fn embedded_quote() {
        assert_eq!(
            build_cmdline(&[r#"say "hi""#.into()]),
            r#""say \"hi\"""#,
        );
    }

    #[test]
    fn empty_arg() {
        assert_eq!(build_cmdline(&["".into()]), r#""""#);
    }

    #[test]
    fn cmd_c_echo() {
        let args = vec!["cmd.exe".into(), "/c".into(), "echo hello".into()];
        assert_eq!(build_cmdline(&args), r#"cmd.exe /c "echo hello""#);
    }
}

#[cfg(test)]
mod hello_event_name_tests {
    //! H1 regression tests for the randomized hello-event name.

    use super::build_random_event_name;

    /// Asserts the new format exactly:
    ///     Local\fs-sandbox-init-<pid>-<32 lowercase hex chars>
    #[test]
    fn format_includes_pid_and_32_hex_suffix() {
        let name = build_random_event_name(4242);
        let prefix = "Local\\fs-sandbox-init-4242-";
        assert!(
            name.starts_with(prefix),
            "missing pid-anchored prefix: {name}",
        );
        let suffix = &name[prefix.len()..];
        assert_eq!(suffix.len(), 32, "suffix is not 32 chars: {name}");
        assert!(
            suffix.chars().all(|c| {
                c.is_ascii_hexdigit() && (!c.is_ascii_alphabetic() || c.is_ascii_lowercase())
            }),
            "suffix has non-lowercase-hex chars: {suffix}",
        );
    }

    /// Two consecutive runs must produce different names. Collision is
    /// 2^-128 per pair — effectively never on any real test bot. If this
    /// flakes, the RNG is broken and we have bigger problems.
    #[test]
    fn two_consecutive_calls_differ() {
        let a = build_random_event_name(1);
        let b = build_random_event_name(1);
        assert_ne!(a, b, "two random names collided: {a} vs {b}");
    }

    /// Sanity: a batch of 16 names are all distinct. Catches a wedged RNG
    /// that returns zeros more reliably than the two-sample test.
    #[test]
    fn batch_of_sixteen_all_distinct() {
        use std::collections::HashSet;
        let mut seen: HashSet<String> = HashSet::new();
        for _ in 0..16 {
            let name = build_random_event_name(7);
            assert!(seen.insert(name.clone()), "duplicate random name: {name}");
        }
    }
}

#[cfg(test)]
mod nested_detection_tests {
    //! Issue C (#63): nested-sandbox detection must fire exactly when
    //! `FS_SANDBOX_PIPE` is present in the environment, and never otherwise.
    //!
    //! These tests mutate the process environment, so they must not run in
    //! parallel with anything else that reads `FS_SANDBOX_PIPE`. Each test
    //! saves and restores the variable to avoid leaking state.

    use super::is_nested_invocation;

    /// Serializes the tests in this module against each other.
    ///
    /// The doc comment above states they must not run in parallel, but stating
    /// it did not enforce it: `cargo test` runs them on separate threads of one
    /// process, and the environment is process-wide. One test would set
    /// `FS_SANDBOX_PIPE` while another removed it, and whichever asserted second
    /// failed — observed as an intermittent failure of
    /// `not_nested_when_pipe_unset` or `empty_string_still_counts_as_nested`,
    /// depending on which thread lost the race. Each test now holds this lock
    /// for its whole body, so the set/assert/restore sequence is atomic with
    /// respect to its siblings.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the lock, ignoring poisoning: a panic in one test must not cascade
    /// into spurious failures of the others, which would hide the real one.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// RAII guard that restores `FS_SANDBOX_PIPE` to its prior state on drop.
    struct PipeGuard(Option<std::ffi::OsString>);
    impl PipeGuard {
        fn capture() -> Self {
            PipeGuard(std::env::var_os("FS_SANDBOX_PIPE"))
        }
    }
    impl Drop for PipeGuard {
        fn drop(&mut self) {
            match &self.0 {
                Some(v) => std::env::set_var("FS_SANDBOX_PIPE", v),
                None => std::env::remove_var("FS_SANDBOX_PIPE"),
            }
        }
    }

    #[test]
    fn detects_nested_when_pipe_set() {
        let _lock = env_lock();
        let _g = PipeGuard::capture();
        std::env::set_var("FS_SANDBOX_PIPE", r"\\.\pipe\fs-sandbox-99999");
        assert!(is_nested_invocation(), "FS_SANDBOX_PIPE set ⇒ nested");
    }

    #[test]
    fn not_nested_when_pipe_unset() {
        let _lock = env_lock();
        let _g = PipeGuard::capture();
        std::env::remove_var("FS_SANDBOX_PIPE");
        assert!(!is_nested_invocation(), "FS_SANDBOX_PIPE unset ⇒ not nested");
    }

    /// The detector must trigger on any non-empty value — including a
    /// pathological empty string. The outer launcher always sets a
    /// well-formed pipe name, but the contract is "presence ⇒ nested",
    /// not "non-empty ⇒ nested", so an empty string still counts.
    #[test]
    fn empty_string_still_counts_as_nested() {
        let _lock = env_lock();
        let _g = PipeGuard::capture();
        std::env::set_var("FS_SANDBOX_PIPE", "");
        assert!(is_nested_invocation(), "presence (not value) ⇒ nested");
    }
}

#[cfg(test)]
mod nested_delegation_tests {
    //! Issue C (#63): the nested-delegation builder must forward EVERY
    //! target argument to the child, not just the executable. A regression
    //! that drops `target[1..]` would silently turn
    //! `cmd.exe /c "echo X"` into an interactive `cmd.exe`.
    //!
    //! These tests inspect the built `Command`'s argv directly — no process
    //! is spawned — so they are deterministic and platform-independent.

    use super::build_delegation_command;

    /// `cmd.exe /c "echo DELEGATED_ARG_OK"` (3 target elements) must reach
    /// the child with both `/c` and the quoted echo intact.
    #[test]
    fn preserves_full_target_argv() {
        let target: Vec<String> = vec![
            "cmd.exe".into(),
            "/c".into(),
            "echo DELEGATED_ARG_OK".into(),
        ];
        let cmd = build_delegation_command(&target);
        assert_eq!(cmd.get_program(), std::ffi::OsStr::new("cmd.exe"));
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(
            args,
            ["/c", "echo DELEGATED_ARG_OK"],
            "all target arguments after [0] must be forwarded verbatim",
        );
    }

    /// Pathological case: a target that is only the executable (no args).
    /// The builder must not panic on `target[1..]` and must produce zero
    /// child arguments.
    #[test]
    fn handles_executable_only_target() {
        let target: Vec<String> = vec!["cmd.exe".into()];
        let cmd = build_delegation_command(&target);
        assert_eq!(cmd.get_program(), std::ffi::OsStr::new("cmd.exe"));
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert!(args.is_empty(), "no args expected, got {args:?}");
    }

    /// Arguments that look like launcher flags (`-c`, `--flag`) must survive
    /// verbatim — clap already consumed the real launcher opts via `--`, so
    /// everything in `cli.target` is the child's argv, not ours.
    #[test]
    fn preserves_flag_like_arguments() {
        let target: Vec<String> = vec![
            "node".into(),
            "-e".into(),
            "console.log('hi')".into(),
            "--unhandled-rejections=strict".into(),
        ];
        let cmd = build_delegation_command(&target);
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(
            args,
            [
                "-e",
                "console.log('hi')",
                "--unhandled-rejections=strict",
            ],
        );
    }

    /// Empty-string arguments (rare but legal) must round-trip — they must
    /// not be silently dropped, since the child's argv indexing depends on
    /// positional presence.
    #[test]
    fn preserves_empty_string_argument() {
        let target: Vec<String> = vec!["git".into(), "commit".into(), "".into(), "-m".into()];
        let cmd = build_delegation_command(&target);
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(args, ["commit", "", "-m"], "empty-string arg preserved");
    }
}

#[cfg(test)]
mod cli_target_parsing_tests {
    //! Issue C (#63), iteration 3: regression test for the FULL argv→target
    //! chain that feeds `build_delegation_command`. The orchestrator reported
    //! that the nested launcher received only the bare executable (`cmd.exe`)
    //! without `/c "echo ..."`, which would mean clap's `trailing_var_arg`
    //! collection dropped everything after the inner `--`.
    //!
    //! These tests invoke the clap parser directly (`Cli::try_parse_from`)
    //! against the exact argv shape produced when an outer launcher spawns a
    //! nested launcher — `winrsbox.exe --cwd X -- <target...>` — and assert
    //! `cli.target` carries every trailing token verbatim. They do NOT start
    //! the sandbox, so they run anywhere without hook.dll / admin rights.

    use clap::Parser;
    use super::Cli;

    /// The exact nested-delegation shape from the acceptance test:
    ///     winrsbox.exe --cwd X -- cmd.exe /c "echo DELEGATED_ARG_OK"
    /// clap must collect THREE entries into `target`.
    #[test]
    fn nested_argv_preserves_full_target_after_inner_dashdash() {
        let argv = [
            "winrsbox.exe",
            "--cwd", r"D:\nest_sbx",
            "--",
            "cmd.exe", "/c", "echo DELEGATED_ARG_OK",
        ];
        let cli = Cli::try_parse_from(argv).expect("parse nested argv");
        assert_eq!(
            cli.target,
            vec![
                "cmd.exe".to_string(),
                "/c".to_string(),
                "echo DELEGATED_ARG_OK".to_string(),
            ],
            "clap must forward every token after `--` into cli.target",
        );
        assert!(!cli.init, "init flag must not be set by trailing tokens");
    }

    /// A nested launcher may itself be invoked with its own `--` plus a
    /// complex target (e.g. multi-word echo with spaces). The trailing
    /// collection must NOT split quoted arguments on whitespace.
    #[test]
    fn nested_argv_preserves_quoted_multiword_target() {
        let argv = [
            "winrsbox.exe",
            "--cwd", r"D:\nest_sbx",
            "--",
            "cmd.exe", "/c", "echo hello world from nested",
        ];
        let cli = Cli::try_parse_from(argv).expect("parse multiword argv");
        assert_eq!(
            cli.target,
            vec![
                "cmd.exe".to_string(),
                "/c".to_string(),
                "echo hello world from nested".to_string(),
            ],
        );
    }

    /// Hyphen-prefixed tokens after `--` (e.g. `-c`, `--flag`) must land in
    /// `target`, not be re-interpreted as launcher options. With
    /// `allow_hyphen_values=true` + `trailing_var_arg=true` on the `target`
    /// field, the first `--` terminates option parsing and everything
    /// afterwards is positional — this test pins that behaviour.
    #[test]
    fn nested_argv_treats_hyphen_tokens_as_target() {
        let argv = [
            "winrsbox.exe",
            "--",
            "node", "-e", "console.log(1)", "--unhandled-rejections=strict",
        ];
        let cli = Cli::try_parse_from(argv).expect("parse hyphen argv");
        assert_eq!(
            cli.target,
            vec![
                "node".to_string(),
                "-e".to_string(),
                "console.log(1)".to_string(),
                "--unhandled-rejections=strict".to_string(),
            ],
        );
        // sanity: launcher's own --debug was NOT set by the trailing `-e`
        assert!(!cli.debug);
    }

    /// End-to-end glue check: feed the parsed `cli.target` straight into
    /// `build_delegation_command` and confirm the `Command` argv matches the
    /// original input byte-for-byte. This catches any silent dropping or
    /// re-quoting between clap collection and the delegation builder.
    #[test]
    fn parse_then_build_command_roundtrip() {
        use super::build_delegation_command;
        let argv = [
            "winrsbox.exe",
            "--cwd", r"D:\nest_sbx",
            "--",
            "cmd.exe", "/c", "echo DELEGATED_ARG_OK",
        ];
        let cli = Cli::try_parse_from(argv).expect("parse");
        let cmd = build_delegation_command(&cli.target);
        assert_eq!(cmd.get_program(), std::ffi::OsStr::new("cmd.exe"));
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(args, ["/c", "echo DELEGATED_ARG_OK"]);
    }
}

#[cfg(test)]
mod child_drain_tests {
    use super::*;
    use std::collections::HashSet;

    /// Fake wait-set standing in for WaitForMultipleObjects: any key marked
    /// as exited signals immediately at its position; otherwise the call
    /// "times out" (None), exactly like the real API returning
    /// WAIT_TIMEOUT / WAIT_FAILED. Every call's chunk size is recorded so
    /// the tests can pin the MAXIMUM_WAIT_OBJECTS bound.
    struct FakeWaitSet {
        exited: HashSet<isize>,
        chunk_sizes: Vec<usize>,
    }

    impl FakeWaitSet {
        fn new(exited: &[isize]) -> Self {
            Self { exited: exited.iter().copied().collect(), chunk_sizes: Vec::new() }
        }
    }

    impl ChildWaitSet for FakeWaitSet {
        fn wait_any(&mut self, keys: &[isize], _timeout_ms: u32) -> Option<usize> {
            self.chunk_sizes.push(keys.len());
            keys.iter().position(|k| self.exited.contains(k))
        }
    }

    fn kids(count: u32) -> Vec<(u32, isize)> {
        (0..count).map(|i| (1000 + i, i as isize)).collect()
    }

    /// THE containment regression: a tree wider than MAXIMUM_WAIT_OBJECTS
    /// must still be waited on in full and every exit observed. The old
    /// single WaitForMultipleObjects(bWaitAll=true) call failed outright
    /// past 64 handles and observed nothing.
    #[test]
    fn more_than_64_children_all_waited_and_observed() {
        let children = kids(100); // > MAXIMUM_WAIT_OBJECTS
        let exited: Vec<isize> = children.iter().map(|(_, h)| *h).collect();
        let mut ws = FakeWaitSet::new(&exited);
        let mut pruned: Vec<u32> = Vec::new();
        wait_and_prune_children(&mut ws, &children, CHILD_DRAIN_GRACE, &mut |pid| {
            pruned.push(pid);
        });

        // every child observed exactly once
        assert_eq!(pruned.len(), children.len());
        let mut sorted = pruned.clone();
        sorted.sort_unstable();
        let mut want: Vec<u32> = children.iter().map(|(p, _)| *p).collect();
        want.sort_unstable();
        assert_eq!(sorted, want);

        // and no single native wait ever exceeded the 64-handle limit
        assert!(
            ws.chunk_sizes.iter().all(|&n| n <= MAXIMUM_WAIT_OBJECTS),
            "chunk sizes exceeded MAXIMUM_WAIT_OBJECTS: {:?}",
            ws.chunk_sizes
        );
        assert!(
            ws.chunk_sizes.iter().any(|&n| n == MAXIMUM_WAIT_OBJECTS),
            "expected at least one full chunk of {MAXIMUM_WAIT_OBJECTS}"
        );
    }

    /// Partial exits: only the exited child is observed (here via the wait
    /// loop, because it sits inside the first chunk); the rest stay
    /// unobserved and the deadline ends the drain instead of hanging.
    #[test]
    fn partial_exits_observe_only_the_exited_child() {
        let children = kids(10);
        let mut ws = FakeWaitSet::new(&[7]); // handle 7 == pid 1007 exited
        let mut pruned: Vec<u32> = Vec::new();
        wait_and_prune_children(&mut ws, &children, CHILD_DRAIN_GRACE, &mut |pid| {
            pruned.push(pid);
        });
        assert_eq!(pruned, vec![1007]);
    }

    /// Exits landing after the wait loop gave up are still caught by the
    /// final zero-timeout sweep (no extra wall-clock spent).
    #[test]
    fn sweep_catches_exit_outside_the_wait_chunk() {
        let children = kids(10);
        // handle 7 is in the first chunk, so make a later one exit instead:
        // fake that never signals inside wait_any, but does on a 0-timeout
        // call (the sweep) for handle 9.
        let mut ws = NeverSignals { sweep_exits: vec![9] };
        let mut pruned: Vec<u32> = Vec::new();
        wait_and_prune_children(&mut ws, &children, CHILD_DRAIN_GRACE, &mut |pid| {
            pruned.push(pid);
        });
        assert_eq!(pruned, vec![1009]);
    }

    /// Fake that always times out in the wait loop, but reports handle 9
    /// exited when polled with a zero timeout (the sweep's shape).
    struct NeverSignals {
        sweep_exits: Vec<isize>,
    }
    impl ChildWaitSet for NeverSignals {
        fn wait_any(&mut self, keys: &[isize], timeout_ms: u32) -> Option<usize> {
            if timeout_ms == 0 {
                return keys.iter().position(|k| self.sweep_exits.contains(k));
            }
            None
        }
    }

    /// Empty input is a no-op and never calls the native wait with an empty
    /// set (real WaitForMultipleObjects with nCount=0 is UB).
    #[test]
    fn empty_child_list_makes_no_wait_calls() {
        let mut ws = FakeWaitSet::new(&[]);
        let mut pruned: Vec<u32> = Vec::new();
        wait_and_prune_children(&mut ws, &[], CHILD_DRAIN_GRACE, &mut |pid| {
            pruned.push(pid);
        });
        assert!(pruned.is_empty());
        assert!(ws.chunk_sizes.is_empty());
    }

    /// The real Win32ChildWaitSet maps a signalled handle to the right
    /// index (here: the promptly-exiting child at index 1, while the child
    /// at index 0 is still alive) and honours the timeout on a live handle.
    #[test]
    fn win32_waitset_reports_signalled_index_and_times_out() {
        use std::os::windows::io::AsRawHandle;

        let mut fast = std::process::Command::new("cmd")
            .args(["/c", "exit 0"])
            .spawn()
            .expect("spawn cmd");
        let mut slow = std::process::Command::new("ping")
            .args(["-n", "2", "127.0.0.1"])
            .spawn()
            .expect("spawn ping");
        let fast_h = fast.as_raw_handle() as isize;
        let slow_h = slow.as_raw_handle() as isize;

        let mut ws = Win32ChildWaitSet;
        // fast is at index 1 and exits immediately; slow lives ~1s.
        let got = ws.wait_any(&[slow_h, fast_h], 10_000);
        assert_eq!(got, Some(1), "expected index 1 (the exiting child)");
        // a live process must time out, not be misreported as signalled
        let got = ws.wait_any(&[slow_h], 200);
        assert_eq!(got, None, "live child must not be reported as exited");

        fast.wait().unwrap();
        slow.wait().unwrap();
    }
}
