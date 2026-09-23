// Assumed crate versions (pinned from Cargo.toml):
//   windows = "0.61"  (windows-0.61.3 in registry)
//   tokio   = "1"     (full features)
//   anyhow  = "1"
//   ktav    = "0.6.1"
//   serde   = "1"

mod pipe_server;
mod sandbox;

use anyhow::{Context, Result};
use clap::Parser;
use policy::Policy;
use winrsbox::cli;
use winrsbox::observe::hot_stats::{HotStats, ThrottledFlusher};
use winrsbox::observe::jsonl_log;
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::Threading::{GetExitCodeProcess, ResumeThread, WaitForSingleObject, INFINITE},
    },
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
    // drive. The root is keyed by the FULL project path (same identity as the
    // per-project state dir / policy DB) — never by the basename alone
    // (review S07: same-basename projects must not share a C: overlay).
    let mut overlay_layout = policy::path::OverlayLayout::single(sandbox_root.clone());
    // (legacy pre-S07 C: root, current C: root) — rows recorded against the
    // legacy root are rebased once the policy DB is open.
    let mut c_root_migration: Option<(PathBuf, PathBuf)> = None;
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
                c_root_migration = Some((legacy, c_root.clone()));
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
    if let Some((legacy, c_root)) = &c_root_migration {
        if let Err(e) = policy.rebase_overlay_root(legacy, c_root) {
            eprintln!("[sandbox] overlay index not rebased to {}: {e}", c_root.display());
        }
    }

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
    let removed = winrsbox::contain::guest::env_guard::sanitize();
    if removed > 0 && winrsbox::observe::jsonl_log::console_verbose() {
        println!("[sandbox] env: sanitized {removed} sensitive variables");
    }

    // Help GUI terminal emulators (WezTerm, Windows Terminal) that ignore the inherited
    // CWD and fall back to the home directory when spawning their shell.
    let cwd_str = project_root.to_string_lossy().into_owned();
    // Hook-side trace gate value — published ONLY in the session config
    // below (chunk 3, review XA 2026-09-20 S02: the FS_SANDBOX_TRACE env
    // export is retired; the trusted section is the hook's single source).
    let hook_trace = cli.trace || effective_log_level.eq_ignore_ascii_case("trace");
    let disable_hooks_effective = sandbox::launch_prep::set_sandbox_environment(
        &cli,
        &pipe_name,
        std::path::Path::new(&dll_path),
        &sandbox_root,
        &project_root,
        &cwd_str,
        net_guarded,
        hook_trace,
    );

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
        // S11: published PRE-FOLDED to the canonical NTFS-identity form (see
        // `fold_published`). `cwd_str` itself stays raw — it also feeds the
        // WEZTERM_EXECUTABLE_ARGS_CWD ergonomics env var above, which must
        // preserve the operator's spelling.
        cwd: fold_published(&cwd_str),
        sandbox_root: fold_published(&sandbox_root.to_string_lossy()),
        // Publish ALL overlay roots (per-drive same-volume layout) so the hook
        // can mask paths against every root and derive the drive letter from
        // the matched one. Empty = single-root legacy fallback in the hook.
        overlay_roots: policy
            .overlay_layout()
            .all_roots()
            .map(|(_drive, root)| fold_published(&root.to_string_lossy()))
            .collect(),
        trace: hook_trace,
        guard: match cli.guard {
            GuardLevel::None => ipc::GuardLevel::None,
            GuardLevel::Scan => ipc::GuardLevel::Scan,
            GuardLevel::Full => ipc::GuardLevel::Full,
            GuardLevel::Static => ipc::GuardLevel::Static,
        },
        // Launcher identity for the hook's pipe-server verification (S02):
        // the hook compares the pipe server's PID and its kernel creation
        // time (PID-reuse defence) against these before trusting any
        // response. The creation time goes through
        // query_process_create_time(self-pid) rather than
        // process_create_time_from_handle(GetCurrentProcess()): the helper's
        // is_invalid() check rejects the (HANDLE)-1 current-process
        // pseudo-handle (same bit pattern as INVALID_HANDLE_VALUE) and would
        // return 0, so open a real self-handle via the existing query.
        launcher_pid: std::process::id(),
        launcher_create_time: pipe_server::query_process_create_time(std::process::id())
            .unwrap_or(0),
        allow_rwx: cli.allow_rwx,
        disable_hooks: disable_hooks_effective.clone(),
    };
    let (_session_section, section_name) = winrsbox::contain::session_section::publish(&session_cfg)
        .context("publish session config section")?;
    // The name IS the access control: the section exists under this random
    // name only, so every process that must read the config has to be told
    // the name through the injection channel. The root target receives it
    // here, via the inherited environment (authored before any guest code
    // runs, hence unforgeable at root start — and every hooked descendant
    // has the same name patched in by the spawn hook).
    std::env::set_var("FS_SANDBOX_SECTION", &section_name);

    // Create kernel Event for hook.dll init signaling (H1 fix, random name).
    let init_event = sandbox::launch_prep::create_init_event(std::process::id())?;
    // S10: second event for the degraded-init acknowledgment (optional
    // component install failures buffered inside hook.dll).
    let init_degraded_event = sandbox::launch_prep::create_degraded_event(std::process::id())?;

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
        let trust = winrsbox::contain::trust::verify_signature(std::path::Path::new(&target_args[0]));
        let mitigation_note = if trust.is_trusted() {
            ""
        } else {
            "; JIT and unsigned native extensions (.pyd/.node) will be blocked by mitigation policy"
        };
        // stderr for the same reason as the exit summary below: launcher
        // diagnostics must not land in the target's stdout.
        if jsonl_log::console_verbose() {
            eprintln!(
                "[sandbox] guard: static (hard containment) — {}{mitigation_note}",
                winrsbox::contain::trust::advisory_notice(&trust)
            );
        }
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
    sandbox::proc_table::publish_root_create_time(
        pipe_server::process_create_time_from_handle(proc_info.hProcess),
    );

    // Pre-launch code integrity scan (full/static guard + not skipped).
    // The direct-syscall scan matters most for `full` (which allows JIT and so
    // can't rely on ProhibitDynamicCode); `static` runs it too as belt-and-suspenders.
    if (effective_guard == GuardLevel::Full || effective_guard == GuardLevel::Static)
        && !cli.no_pre_scan
    {
        if let Err(e) = sandbox::inject::pre_launch_scan(
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
    if let Err(e) = sandbox::inject::inject_dll(proc_info.hProcess, proc_info.hThread, &dll_path) {
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
        cli.strict_ui,
    )?;

    // WFP kernel-level network filtering. Under `network: guarded` this is a
    // hard requirement, not best-effort: if the kernel layer cannot be fully
    // installed the launch is refused (fail-closed), mirroring the
    // inject_dll refusal above — a guarded run never starts without the
    // kernel enforcement SECURITY.md promises.
    let _wfp = match winrsbox::contain::wfp::install_outbound_filters(
        net_guarded,
        cli.guard != GuardLevel::None,
        cli.block_localhost,
        std::path::Path::new(&target_args[0]),
    ) {
        winrsbox::contain::wfp::WfpInstall::Installed(engine) => Some(engine),
        winrsbox::contain::wfp::WfpInstall::NotRequested => None,
        winrsbox::contain::wfp::WfpInstall::Refused(reason) => {
            // SAFETY: proc_info handles are valid PROCESS/THREAD handles from CreateProcessW.
            unsafe {
                windows::Win32::System::Threading::TerminateProcess(proc_info.hProcess, 0xC000_0005).ok();
                CloseHandle(proc_info.hThread).ok();
                CloseHandle(proc_info.hProcess).ok();
            }
            eprintln!("guarded network requested but kernel network enforcement could not be installed — refusing launch: {reason}");
            // Exit immediately — don't wait for tokio runtime drop (pipe accept loop blocks).
            std::process::exit(0xC000_0005u32 as i32);
        }
    };

    // ETW Kernel-Process listener — monitoring layer (logs events, no enforcement).
    let _etw = if cli.guard != GuardLevel::None {
        let proc_info_ref = sandbox::proc_table::global_proc_info();
        let pid_checker: Arc<dyn Fn(u32) -> bool + Send + Sync> = Arc::new(move |pid: u32| {
            proc_info_ref.pin().get(&pid).is_some()
        });
        match winrsbox::observe::etw_listener::start(pid_checker) {
            Ok(h) => {
                if winrsbox::observe::jsonl_log::console_verbose() {
                    println!("[sandbox] ETW: Kernel-Process listener active");
                }
                Some(h)
            }
            Err(e) => {
                // Monitoring-only layer (etw_listener.rs) — commonly unavailable
                // simply because the launcher isn't elevated. Not a containment
                // gap, so keep it off the console unless --trace.
                if winrsbox::observe::jsonl_log::console_verbose() {
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
        .map(|s| fold_published(s))
        .unwrap_or_default();
    sandbox::proc_table::global_proc_info().pin().insert(
        proc_info.dwProcessId,
        sandbox::proc_table::ProcInfo {
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
                CloseHandle(init_degraded_event).ok();
            }
            anyhow::bail!("init-event wait task failed: {e}");
        }
    };

    if wait_result.0 == 0 { // WAIT_OBJECT_0
        if winrsbox::observe::jsonl_log::console_verbose() {
            println!("[sandbox] hook.dll init confirmed (pid {})", proc_info.dwProcessId);
        }
        // S10 degraded-init probe: zero-timeout poll of the second event,
        // signaled when hook.dll initialized DEGRADED (optional component
        // install failures). Unconditional stderr warning — security-relevant,
        // like the CRITICAL timeout path below, so NOT gated on verbose.
        // SAFETY: init_degraded_event is valid and not yet closed.
        let degraded = unsafe {
            WaitForSingleObject(HANDLE(init_degraded_event.0 as *mut _), 0)
        };
        if degraded.0 == 0 { // WAIT_OBJECT_0
            eprintln!(
                "[sandbox] WARNING: hook.dll initialized DEGRADED (optional component install failures) — details in the sandbox log after the first hooked operation (pid {})",
                proc_info.dwProcessId
            );
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
        unsafe { CloseHandle(init_degraded_event).ok() };
        anyhow::bail!("hook.dll injection failed — child terminated (pid={})", proc_info.dwProcessId);
    }
    unsafe { CloseHandle(init_event).ok() };
    unsafe { CloseHandle(init_degraded_event).ok() };

    if winrsbox::observe::jsonl_log::console_verbose() {
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

    sandbox::child_drain::drain_registered_children(&child_pids).await;

    // Read exit code and print summary.
    let mut exit_code = 0u32;
    // SAFETY: target_handle is valid; GetExitCodeProcess fills exit_code on success.
    unsafe { GetExitCodeProcess(target_handle, &mut exit_code).ok() };
    // SAFETY: target_handle — we are done with the process.
    unsafe { CloseHandle(target_handle).ok() };

    let s = &stats;
    let viol = s.violations.load(Ordering::Relaxed);
    let (etw_total, etw_sandbox) = winrsbox::observe::etw_listener::stats();
    // stderr, not stdout: this is the launcher talking about itself, and the
    // target's stdout belongs to the target. On stdout it corrupted every
    // piped or redirected run — `winrsbox cx > out.txt` ended with a sandbox
    // summary glued to the program's own output. Opt-in as well: the same
    // numbers are in the JSONL `exit` event written a few lines below.
    if jsonl_log::console_verbose() {
    eprintln!(
        "\n[sandbox] exit={exit_code}  decide={} redirect={} deny={} mock={} cow={} violations={viol} etw={etw_sandbox}/{etw_total}",
        s.decide.load(Ordering::Relaxed),
        s.redirect.load(Ordering::Relaxed),
        s.deny.load(Ordering::Relaxed),
        s.mock_.load(Ordering::Relaxed),
        s.cow.load(Ordering::Relaxed),
    );
    }

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
