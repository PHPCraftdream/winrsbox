// Assumed crate versions (pinned from Cargo.toml):
//   windows = "0.61"  (windows-0.61.3 in registry)
//   tokio   = "1"     (full features)
//   anyhow  = "1"
//   ktav    = "0.3.1"
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
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

// ─── Lock-free PID → ProcInfo storage ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct ProcInfo {
    pub(crate) depth: u8,
    pub(crate) exe_lower: Arc<str>,
}

static PROC_INFO: std::sync::OnceLock<papaya::HashMap<u32, ProcInfo>> = std::sync::OnceLock::new();

pub(crate) fn global_proc_info() -> &'static papaya::HashMap<u32, ProcInfo> {
    PROC_INFO.get_or_init(papaya::HashMap::new)
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
        Foundation::{CloseHandle, HANDLE},
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

// ─── Entry point ─────────────────────────────────────────────────────────────

/// cancel-safe: NO — top-level main is not meant to be cancelled
#[tokio::main]
async fn main() -> Result<()> {
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
    let db_path = sandbox_root.join("policy.redb");
    let policy = Arc::new(
        Policy::open_or_create(
            &db_path,
            sandbox_root.clone(),
            mock_dirs_root.clone(),
            project_root.clone(),
        )?,
    );
    policy.load_config(&cfg_path)?;

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
    let effective_log_level = cli
        .log_level
        .clone()
        .or(ktav_log_level)
        .unwrap_or_else(|| "info".to_string());
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
    if removed > 0 {
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

    // Publish a `SessionConfig` snapshot via `Local\WinRsBoxSession` so
    // hooked descendants whose environment was scrubbed (MSYS2 first-run
    // helpers in particular) can still discover the pipe name etc. The
    // returned handle is held for the launcher's whole lifetime — dropping
    // it would destroy the section and break late-arriving readers.
    let session_cfg = ipc::SessionConfig {
        pipe_name: pipe_name.clone(),
        dll_path: dll_path.clone(),
        cwd: cwd_str.clone(),
        sandbox_root: sandbox_root.to_string_lossy().into_owned(),
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
    let _session_section = winrsbox::session_section::publish(&session_cfg)
        .context("publish session config to Local\\WinRsBoxSession")?;

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
        let trust = winrsbox::trust::verify_signature(std::path::Path::new(&target_args[0]));
        if trust.is_trusted() {
            println!("[sandbox] guard: static (hard containment) — target is {trust}");
        } else {
            println!("[sandbox] guard: static (hard containment) — target is unsigned; \
                      JIT and unsigned native extensions (.pyd/.node) will be blocked");
        }
    }

    let proc_info = sandbox::launch_suspended(&project_root, &target_args, effective_guard)?;

    // C3 Part 3: publish the root PID to the pipe accept loop so it can
    // validate `GetNamedPipeClientProcessId` against our own target on every
    // new IPC connection. This must happen BEFORE `ResumeThread` below; the
    // target stays suspended until then, so no connection can reach the
    // accept loop with this slot still set to 0.
    root_target_pid.store(proc_info.dwProcessId, Ordering::Release);

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
                println!("[sandbox] WFP: {fc} outbound filters registered");
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
                println!("[sandbox] ETW: Kernel-Process listener active");
                Some(h)
            }
            Err(e) => {
                eprintln!("[sandbox] ETW unavailable: {e}");
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
        ProcInfo { depth: 0, exe_lower: Arc::from(arg0_lower.as_str()) },
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
        println!("[sandbox] hook.dll init confirmed (pid {})", proc_info.dwProcessId);
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

    println!("[sandbox] target started (pid {})", proc_info.dwProcessId);

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
    let mut child_handles: Vec<HANDLE> = Vec::new();
    while let Some(pid) = child_pids.pop() {
        if seen.insert(pid) {
            if let Ok(h) = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) } {
                child_handles.push(h);
            }
        }
    }

    if !child_handles.is_empty() {
        // Convert HANDLE → isize for Send-safety across .await.
        let ihandles: Vec<isize> = child_handles.iter().map(|h| h.0 as isize).collect();
        tokio::task::spawn_blocking(move || {
            let handles: Vec<HANDLE> = ihandles.iter().map(|&i| HANDLE(i as *mut _)).collect();
            // SAFETY: handles are valid PROCESS_SYNCHRONIZE handles from OpenProcess above.
            // bWaitAll=true: wait for ALL registered children to exit (or hit the timeout).
            unsafe { WaitForMultipleObjects(&handles, true, 5000) };
        })
        .await
        .unwrap_or_else(|e| eprintln!("[sandbox] child-wait task failed: {e}"));
        for h in &child_handles {
            // SAFETY: h is a handle we own from OpenProcess above.
            unsafe { CloseHandle(*h).ok() };
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
    println!(
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
        map.pin().insert(100, ProcInfo { depth: 0, exe_lower: Arc::from("c:\\app.exe") });
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
        map.pin().insert(200, ProcInfo { depth: 1, exe_lower: Arc::from("child.exe") });
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
        map.pin().insert(10, ProcInfo { depth: 0, exe_lower: Arc::from("root.exe") });
        // Child
        map.pin().insert(20, ProcInfo { depth: 1, exe_lower: Arc::from("child.exe") });
        // Grandchild
        map.pin().insert(30, ProcInfo { depth: 2, exe_lower: Arc::from("grandchild.exe") });

        assert_eq!(map.pin().get(&10).unwrap().depth, 0);
        assert_eq!(map.pin().get(&20).unwrap().depth, 1);
        assert_eq!(map.pin().get(&30).unwrap().depth, 2);
    }

    #[test]
    fn overwrite_updates_value() {
        let map: papaya::HashMap<u32, ProcInfo> = papaya::HashMap::new();
        map.pin().insert(50, ProcInfo { depth: 0, exe_lower: Arc::from("old.exe") });
        map.pin().insert(50, ProcInfo { depth: 1, exe_lower: Arc::from("new.exe") });
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
        let _g = PipeGuard::capture();
        std::env::set_var("FS_SANDBOX_PIPE", r"\\.\pipe\fs-sandbox-99999");
        assert!(is_nested_invocation(), "FS_SANDBOX_PIPE set ⇒ nested");
    }

    #[test]
    fn not_nested_when_pipe_unset() {
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
