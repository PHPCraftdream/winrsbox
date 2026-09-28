// Assumed crate versions (pinned from Cargo.toml):
//   windows = "0.61"  (windows-0.61.3 in registry)
//   tokio   = "1"     (full features)
//   anyhow  = "1"
//   ktav    = "0.6.1"
//   serde   = "1"

#[path = "../pipe_server/mod.rs"]
mod pipe_server;
#[path = "../sandbox/mod.rs"]
mod sandbox;
mod broker;
mod client;
mod failover;
mod session;

use anyhow::{Context, Result};
use clap::Parser;
use winrsbox::cli;
use winrsbox::observe::hot_stats::{HotStats, ThrottledFlusher};
use winrsbox::observe::jsonl_log;
use std::{
    path::{Path, PathBuf},
    sync::{atomic::AtomicU32, Arc},
};
use sandbox::launch_prep::{build_delegation_command, is_nested_invocation};

/// S11 — the one fold applied to every path this launcher publishes for
/// identity decisions: `SessionConfig.cwd` / `sandbox_root` / `overlay_roots`
/// and the root target's `ProcInfo.exe_lower`. Canonical NTFS-identity fold
/// (kernel upcase/downcase tables via ntdll, `policy::path::nt_case_fold`):
/// ASCII input stays byte-identical to the historic `to_ascii_lowercase`, so
/// consumers see no change for ASCII paths, while non-ASCII paths now fold to
/// the same form the policy db and the hook compute (previously published
/// unfolded, they only matched after the hook's local re-fold). The hook
/// re-folds what it reads and fold∘fold is the identity, so publishing the
/// canonical form is a pure tightening.
pub(crate) fn fold_published(s: &str) -> String {
    policy::path::nt_case_fold(s).into_owned()
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

    /// Print sandbox diagnostics to the console.
    ///
    /// Off by default: the console belongs to the sandboxed program, and a
    /// run that emits hundreds of `[reg] DENY` lines buries its output. This
    /// changes NOTHING about what is recorded — every gated message is
    /// written to `sandbox.log.jsonl` either way, so the audit trail is the
    /// same whether or not you pass this. `--trace` implies it.
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

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

    /// Apply ALL 8 Job Object UI restriction flags (default: only the ones
    /// enabled by other flags, if any). This is a broader, explicit
    /// hardening profile than `--strict-clipboard` (which sets only
    /// READCLIPBOARD | WRITECLIPBOARD, 0x06) — `--strict-ui` also blocks
    /// foreign window handles, global atoms, desktop switching, system
    /// params/display settings, and ExitWindowsEx (0xFF total). WARNING:
    /// this is an unmeasured, opt-in hardening profile — it MAY break
    /// clipboard, browser OAuth login, and Git Credential Manager
    /// workflows inside the sandbox. Compatibility across those workflows
    /// has not been verified; use only if you accept that risk.
    #[arg(long = "strict-ui")]
    strict_ui: bool,

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
    // The outer (first) launcher exports FS_SANDBOX_SECTION into the
    // environment of every descendant process. If WE see it, we are already
    // inside a sandbox: spawning a second pipe + overlay here would duplicate
    // the containment and waste resources. Instead, transparently delegate
    // the target to the outer sandbox by launching it directly (no
    // mitigations, no pipe, no overlay, no hook injection) and propagating
    // its exit code.
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

    // `.clone()` (was a move): `cli` is still borrowed whole further below
    // (set_sandbox_environment) after `target_args` has been taken out.
    let target_args = cli.target.clone();

    // Open / create policy DB
    // Policy DB lives at the STATE-DIR level (parent of workdir), NOT inside
    // the overlay root. This is a security invariant: "under workdir = ONLY
    // agent CoW data". If policy.redb lived under workdir, the self-access
    // carve-out in the hook (which allows absolute overlay-path reopens for
    // the process's own CoW files) would expose it — an agent could read or
    // corrupt its own policy database.
    let state_dir = cfg_path.parent().unwrap_or(&sandbox_root).to_path_buf();
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
    // drive. The root is keyed by the FULL project path (same identity as the
    // per-project state dir / policy DB) — never by the basename alone
    // (review S07: same-basename projects must not share a C: overlay).
    let mut overlay_layout = policy::path::OverlayLayout::single(sandbox_root.clone());
    // (local appdata, legacy pre-S07 C: root, current C: root). Indexed data
    // is copied and rebased after the policy DB is open.
    let mut c_root_migration: Option<(PathBuf, PathBuf, PathBuf)> = None;
    {
        // Only register a C: root if C: is NOT already the project drive
        // (avoids a redundant/duplicate root).
        let project_drive = project_root
            .to_string_lossy()
            .chars()
            .next()
            .map(|c| c.to_ascii_lowercase());
        if project_drive != Some('c') {
            if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
                let (c_root, legacy) =
                    sandbox::prepare_c_overlay_root(Path::new(&local_appdata), &project_root)?;
                c_root_migration = Some((PathBuf::from(local_appdata), legacy, c_root.clone()));
                overlay_layout.set_drive_root('c', c_root);
            }
        }
    }
    // MP-2/MP-6: whoever opens policy.redb first is this folder's broker
    // for the rest of this run; DatabaseAlreadyOpen means a live broker
    // already owns it. A client never opens the DB at all — no
    // load_config, no C: overlay migration, no pipe server — everything it
    // needs comes from Attach instead (`client::run_as_client`).
    let policy = match broker::open_policy_or_decide_role(
        &db_path,
        overlay_layout.clone(),
        mock_dirs_root.clone(),
        project_root.clone(),
        &state_dir,
    )? {
        broker::Role::Broker(policy) => Arc::new(policy),
        broker::Role::Client { broker_pid } => {
            let exit_code = client::run_as_client(
                cli,
                project_root,
                sandbox_root,
                cfg_path,
                state_dir,
                target_args,
                overlay_layout,
                mock_dirs_root,
                broker_pid,
            )
            .await?;
            std::process::exit(exit_code);
        }
    };
    policy.load_config(&cfg_path)?;
    if let Some((local_appdata, legacy, c_root)) = &c_root_migration {
        sandbox::complete_c_overlay_migration(&policy, local_appdata, legacy, c_root)?;
    }

    // Registry policy — shares the FS policy DB; overlay store lives under
    // <state_dir>/workreg. Required for sandboxed installers that write user
    // env-vars / config to the registry (CoW-overlayed, host untouched).
    let workreg_root = cfg_path.parent().unwrap().join("workreg");
    std::fs::create_dir_all(&workreg_root)?;
    let reg_policy = Arc::new(policy::RegistryPolicy::open(policy.db(), workreg_root)?);

    // Named pipe name — random per MP-10 §A, not derived from the PID: a
    // predictable name lets a guest pre-create a pipe under it (e.g. while
    // waiting for failover) and win `FILE_FLAG_FIRST_PIPE_INSTANCE`, making
    // the real broker's own first-instance bind fail (fatal).
    let pipe_name = winrsbox::contain::session_section::random_pipe_name()
        .context("generate broker pipe name")?;

    // Own creation time — PID-reuse-safe self identity, shared by the
    // folder section / broker.json below AND by SessionConfig's
    // launcher_create_time further down (one query, one value).
    let own_create_time = pipe_server::query_process_create_time(std::process::id()).unwrap_or(0);

    // MP-2: broker-only folder objects — folder job (kernel-truth guest
    // membership, `contain::jobctl::FolderJob`) and folder section (current
    // pipe name published to every launcher/guest in this state dir,
    // `contain::session_section::FolderSection`), plus broker.json (the
    // entry point a joining launcher reads). Reaching this point means the
    // role decision above already resolved to Broker — every Client exits
    // earlier. Handles are held in `broker_folder`/`folder_job` for the
    // launcher's whole runtime; dropping either tears the kernel object
    // down immediately for every other reader.
    let broker::BrokerFolderState {
        folder_job,
        folder_section,
        folder_section_name,
    } = broker::setup_broker_folder(&state_dir, &pipe_name, std::process::id(), own_create_time)
        .context("set up broker folder objects")?;
    // Shared with the pipe server for kernel job-membership admission (MP-4)
    // and, via `AttachContext` below, MP-3's `Attach` handling.
    let folder_job = Arc::new(folder_job);
    let folder_section = Arc::new(folder_section);

    // Stats — shared between connection handlers (lock-free atomics)
    let stats = Arc::new(pipe_server::Stats::default());

    let attach_ctx = broker::AttachContext {
        folder_section: Arc::clone(&folder_section),
        folder_section_name: folder_section_name.clone(),
        broker_pid: std::process::id(),
        broker_create_time: own_create_time,
        pipe_name: pipe_name.clone(),
        policy: Arc::clone(&policy),
        stats: Arc::clone(&stats),
    };

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
    let ktav_cfg: Option<policy::db::Config> = std::fs::read_to_string(&cfg_path)
        .ok()
        .and_then(|src| ktav::from_str::<policy::db::Config>(&src).ok());
    let ktav_log_level: Option<String> = ktav_cfg.as_ref().and_then(|c| c.log_level.clone());

    // Network containment is OFF unless the ktav says `network: guarded`.
    // Off means the sandbox does not touch the network at all: no WFP filter
    // is registered and the `connect` hook is not installed, so a sandboxed
    // program's traffic is indistinguishable from running it directly — it
    // already connects from its own process with its own image (nothing was
    // ever proxied through the launcher), and with no filters registered the
    // sandbox leaves no trace in the system's network configuration either.
    //
    // The CLI network flags imply it rather than silently doing nothing: a
    // `--block-localhost` that quietly had no effect is the same class of
    // silent failure as the unscoped WFP filters fixed earlier today.
    let net_guarded = ktav_cfg.as_ref().map(|c| c.network_guarded()).unwrap_or(false)
        || cli.block_localhost
        // Configured network rules imply it too. Leaving them inert would be
        // the worst outcome: an operator who ran `winrsbox netrule add` sees
        // rules in `netrule list` and reasonably believes they are enforced.
        || policy::db::net_rule_list(&policy.db()).map(|r| !r.is_empty()).unwrap_or(false);
    // `--trace` is a blanket "show me everything" switch: it also raises the
    // JSONL/console verbosity to trace, on top of the hook-side trace gate it
    // publishes in the session section below. Without this, `--trace` would
    // enable hook-side trace events while the console (gated on jsonl_log's
    // level) stayed silent for them.
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
    // Console diagnostics are opt-in and deliberately independent of the FILE
    // log level: `log_level: trace` in the ktav gives a full on-disk audit
    // trail without turning the terminal into a firehose. `--trace` still
    // implies console output, since it is documented as the blanket
    // show-me-everything switch.
    jsonl_log::set_console_log(cli.verbose || cli.trace);

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
        let folder_job2 = Arc::clone(&folder_job);
        let attach_ctx2 = attach_ctx.clone();

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
                Some(folder_job2),
                Some(attach_ctx2),
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

    // ── Shared session tail (identical for broker and client) ─────────────
    let exit_code = session::run_target_session(session::SessionParams {
        cli: &cli,
        project_root,
        sandbox_root,
        target_args,
        violations_log,
        pipe_name,
        overlay_layout,
        folder_section_name,
        net_guarded,
        effective_log_level,
        launcher_pid: std::process::id(),
        launcher_create_time: own_create_time,
        folder_job: folder_job.handle(),
        root_target_pid,
        stats,
        exit_drain: session::ExitDrain::Broker(child_pids),
        hot_stats_flusher: Some(flusher),
    })
    .await?;

    // Exit immediately rather than returning through the tokio runtime drop path.
    // The pipe-accept loop keeps a spawn_blocking thread blocked on ConnectNamedPipe;
    // if we let the runtime drop normally it waits 30 s for that thread to finish.
    std::process::exit(exit_code);
}

#[cfg(test)]
mod cli_target_parsing_tests;
