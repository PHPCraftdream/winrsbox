// Assumed crate versions (pinned from Cargo.toml):
//   windows = "0.61"  (windows-0.61.3 in registry)
//   tokio   = "1"     (full features)
//   anyhow  = "1"
//   ktav    = "0.3.1"
//   serde   = "1"

use anyhow::{Context, Result};
use clap::Parser;
use ipc::{read_msg, write_msg, LogLevel, Req, Resp};
use policy::Policy;
use rustc_hash::FxHashSet;
use winrsbox::cli;
use winrsbox::hot_stats::{HotStats, ThrottledFlusher};
use winrsbox::jsonl_log;
use std::{
    ffi::OsStr,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

// ─── Lock-free PID → ProcInfo storage ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub depth: u8,
    pub exe_lower: Arc<str>,
}

static PROC_INFO: std::sync::OnceLock<papaya::HashMap<u32, ProcInfo>> = std::sync::OnceLock::new();

fn global_proc_info() -> &'static papaya::HashMap<u32, ProcInfo> {
    PROC_INFO.get_or_init(papaya::HashMap::new)
}

/// Default ktav policy written when auto-discovery creates a fresh state dir.
const DEFAULT_CONFIG_KTAV: &str = "\
# winrsbox policy — auto-generated on first run. Edit to customize.
#
# Reads pass through to the real filesystem; writes are Copy-on-Write
# into <state_dir>/workdir/. Add `rules` entries to deny or mock paths.

defaults: {
    read: passthrough
    write: cow
}

rules: [
    {
        prefix: C:\\Windows
        read: passthrough
        write: deny
    }
    {
        prefix: C:\\Users\\**\\.cargo
        read: passthrough
        write: passthrough
    }
    {
        prefix: C:\\Users\\**\\.rustup
        read: passthrough
        write: passthrough
    }
    {
        prefix: C:\\Users\\**\\.npm
        read: passthrough
        write: passthrough
    }
    {
        prefix: C:\\Users\\**\\AppData\\Roaming\\npm
        read: passthrough
        write: passthrough
    }
    {
        prefix: C:\\Users\\**\\AppData\\Local\\Temp
        read: passthrough
        write: passthrough
    }
    {
        prefix: C:\\Users\\**\\AppData\\Local\\pip
        read: passthrough
        write: passthrough
    }
    {
        prefix: C:\\Users\\**\\.gradle
        read: passthrough
        write: passthrough
    }
    {
        prefix: C:\\Users\\**\\.claude
        read: passthrough
        write: passthrough
    }
    {
        prefix: C:\\Users\\**\\.config
        read: passthrough
        write: passthrough
    }
    {
        prefix: C:\\Users\\**\\AppData\\Roaming\\npm
        read: passthrough
        write: passthrough
    }
    {
        prefix: C:\\Users\\**\\AppData\\Local\\node
        read: passthrough
        write: passthrough
    }
    {
        prefix: C:\\Program Files\\nodejs
        read: passthrough
        write: deny
    }
]

# mock_dirs: [
#     { prefix: C:\\Users\\Computer\\.config\\fakeapp }
# ]

# Registry persistence vectors — deny write to prevent DLL injection
# via AppInit_DLLs, Image File Execution Options, AppCertDlls.
regrules: [
    {
        prefix: HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows
        write: deny
    }
    {
        prefix: HKLM\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows
        write: deny
    }
    {
        prefix: HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows
        write: deny
    }
    {
        prefix: HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options
        write: deny
    }
    {
        prefix: HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls
        write: deny
    }
]
";

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
enum GuardLevel {
    /// No memory protection (FS sandbox only). Same as old --weak.
    None,
    /// Content-aware scan: allow executable memory, block direct syscalls in content.
    Scan,
    /// Full protection: scan + pre-launch .text scan + DLL .text scan.
    Full,
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
    ///   none  — no memory protection (FS sandbox only)
    ///   scan  — content-aware: scan executable bytes for direct syscalls
    ///   full  — scan + pre-launch .text scan + DLL scan (default)
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
    /// Categories: memory, inject, reg, net, mitigations, fs.
    /// Example: --disable-hooks inject,mitigations
    #[arg(long = "disable-hooks", value_name = "CATEGORIES")]
    disable_hooks: Option<String>,

    /// Enable trace logging from hook.dll (verbose, for debugging).
    #[arg(long = "trace")]
    trace: bool,

    /// JSONL log verbosity: error (violations only), warn (denies), info (default),
    /// trace (all decides). Lower levels include higher ones.
    #[arg(long = "log-level", default_value = "info", value_name = "LEVEL")]
    log_level: String,

    /// Block localhost (127.0.0.0/8) connections. Prevents access to local
    /// services (databases, debug ports) but breaks MCP/LSP servers.
    #[arg(long = "block-localhost")]
    block_localhost: bool,

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
    core::{HRESULT, PCWSTR},
    Win32::{
        Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, HANDLE},
        Storage::FileSystem::PIPE_ACCESS_DUPLEX,
        System::{
            Console::GetConsoleWindow,
            Diagnostics::Debug::WriteProcessMemory,
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Memory::{
                VirtualAllocEx, VirtualFreeEx,
                MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
                VIRTUAL_FREE_TYPE,
            },
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
                PIPE_TYPE_BYTE, PIPE_WAIT,
            },
            Threading::{
                CreateProcessW, GetExitCodeProcess,
                OpenProcess, ResumeThread, WaitForMultipleObjects, WaitForSingleObject,
                CREATE_SUSPENDED, INFINITE, PROCESS_INFORMATION, PROCESS_SYNCHRONIZE,
                STARTUPINFOW,
            },
        },
        UI::WindowsAndMessaging::{ShowWindow, SW_HIDE},
    },
};

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
            discover_state_dir(&project_root)?
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
    maybe_hide_console(cli.debug);

    if let Some(ref cwd) = cli.cwd {
        std::env::set_current_dir(cwd)
            .with_context(|| format!("failed to set working directory to '{cwd}'"))?;
    }

    let project_root: PathBuf = std::env::current_dir()
        .context("failed to get current directory")?;

    let (cfg_path, sandbox_root, mock_dirs_root) = ensure_state(&project_root)?;

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
    let stats = Arc::new(Stats::default());

    // Child PIDs registered from hook via IPC RegisterChild
    let child_pids: Arc<crossbeam_queue::SegQueue<u32>> = Arc::new(crossbeam_queue::SegQueue::new());

    // Violations log path
    let violations_log = cfg_path.parent().unwrap().join("violations.log");

    // JSONL structured log — persistent, machine-parseable
    jsonl_log::init(cfg_path.parent().unwrap().join("sandbox.log.jsonl"), &cli.log_level);

    // Hot-stats: aggregates access patterns, flushed to disk at most once per 5s.
    let hot_stats = HotStats::new();
    let flusher = Arc::new(ThrottledFlusher::new(
        Arc::clone(&hot_stats),
        cfg_path.parent().unwrap().join("hot-stats.json"),
    ));

    // ── Pipe server (accept loop in background task) ──────────────────────
    {
        let policy = Arc::clone(&policy);
        let stats = Arc::clone(&stats);
        let child_pids = Arc::clone(&child_pids);
        let pipe_name2 = pipe_name.clone();
        let violations_log2 = violations_log.clone();
        let hot_stats2 = Arc::clone(&hot_stats);
        let flusher2 = Arc::clone(&flusher);

        tokio::spawn(async move {
            pipe_accept_loop(&pipe_name2, policy, stats, child_pids, violations_log2, hot_stats2, flusher2).await;
        });
    }

    // Small delay so the pipe server starts accepting before the child tries to connect.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // ── Launch target process ─────────────────────────────────────────────
    let dll_path = find_hook_dll()?;

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
    // Pass guard configuration to hook DLL via env vars
    std::env::set_var("FS_SANDBOX_GUARD", match cli.guard {
        GuardLevel::None => "none",
        GuardLevel::Scan => "scan",
        GuardLevel::Full => "full",
    });
    if cli.allow_rwx {
        std::env::set_var("FS_SANDBOX_ALLOW_RWX", "1");
    }
    if let Some(ref cats) = cli.disable_hooks {
        std::env::set_var("FS_SANDBOX_DISABLE_HOOKS", cats);
    }
    if cli.trace {
        std::env::set_var("FS_SANDBOX_TRACE", "1");
    }
    if cli.block_localhost {
        std::env::set_var("FS_SANDBOX_BLOCK_LOCALHOST", "1");
    }

    // Trust-based guard level override: signed binaries get scan (JIT-friendly)
    // instead of full (kernel blocks JIT). Unsigned stays at user's chosen level.
    let effective_guard = if cli.guard == GuardLevel::Full {
        let trust = winrsbox::trust::verify_signature(std::path::Path::new(&target_args[0]));
        if trust.is_trusted() {
            println!("[sandbox] trust: {trust} → scan mode (JIT-friendly)");
            // Override FS_SANDBOX_GUARD so hook.dll uses scan too
            std::env::set_var("FS_SANDBOX_GUARD", "scan");
            GuardLevel::Scan
        } else {
            println!("[sandbox] trust: unsigned → full mode (kernel mitigations)");
            cli.guard
        }
    } else {
        cli.guard
    };

    let proc_info = launch_suspended(&project_root, &target_args, effective_guard)?;

    // Pre-launch code integrity scan (full guard + not skipped).
    if effective_guard == GuardLevel::Full && !cli.no_pre_scan {
        if let Err(e) = pre_launch_scan(
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

    // Inject hook.dll into target before resuming.
    inject_dll(proc_info.hProcess, proc_info.hThread, &dll_path)?;

    // Assign to Job Object — kernel auto-kills all children when launcher exits.
    // Job handle must outlive the target process.
    let _job_handle = {
        use windows::Win32::System::JobObjects::{
            CreateJobObjectW, SetInformationJobObject, AssignProcessToJobObject,
            JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT,
        };
        let limits = winrsbox::jobctl::JobLimits::default()
            .with_memory(cli.memory_limit.map(|gb| gb * 1024 * 1024 * 1024));
        // SAFETY: creating a new job with no name, no security attrs.
        let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .context("CreateJobObjectW")?;
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = Default::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT(
            limits.limit_flags(),
        );
        if let Some(mem) = limits.memory_bytes {
            info.ProcessMemoryLimit = mem as usize;
        }
        // SAFETY: info is a valid JOBOBJECT_EXTENDED_LIMIT_INFORMATION struct.
        unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }.context("SetInformationJobObject")?;
        // SAFETY: both job and hProcess are valid HANDLEs.
        unsafe { AssignProcessToJobObject(job, proc_info.hProcess) }
            .context("AssignProcessToJobObject")?;
        job // hold handle alive
    };

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
                    let _ = engine.block_outbound_port(*port);
                    let _ = engine.block_outbound_port_v6(*port);
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
    .ok();
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
        .ok();
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

// ─── Pipe accept loop ─────────────────────────────────────────────────────────

/// cancel-safe: NO — individual connection handlers are detached via spawn;
///              this outer loop itself is not designed for clean cancellation,
///              it runs for the lifetime of the launcher process.
async fn pipe_accept_loop(
    pipe_name: &str,
    policy: Arc<Policy>,
    stats: Arc<Stats>,
    child_pids: Arc<crossbeam_queue::SegQueue<u32>>,
    violations_log: PathBuf,
    hot_stats: Arc<HotStats>,
    flusher: Arc<ThrottledFlusher>,
) {
    let pipe_name_wide: Vec<u16> = OsStr::new(pipe_name)
        .encode_wide()
        .chain(Some(0))
        .collect();

    loop {
        // Create a new pipe instance for each incoming connection.
        // PIPE_ACCESS_DUPLEX  = FILE_FLAGS_AND_ATTRIBUTES(3)  (from Win32_Storage_FileSystem)
        // PIPE_TYPE_BYTE | PIPE_WAIT = NAMED_PIPE_MODE(0)
        // SAFETY: pipe_name_wide is a valid null-terminated UTF-16 string.
        // Convert HANDLE to isize immediately so it is Send across .await boundaries.
        // HANDLE is *mut c_void which is not Send; isize is.
        let ph: isize = unsafe {
            let h = CreateNamedPipeW(
                PCWSTR(pipe_name_wide.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_WAIT,
                255,    // max instances
                65536,  // out buffer size
                65536,  // in buffer size
                0,      // default timeout
                None,   // security attributes
            );
            if h.is_invalid() {
                // INVALID_HANDLE_VALUE sentinel
                -1isize
            } else {
                h.0 as isize
            }
        };

        if ph == -1 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            continue;
        }

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

        // Handle this connection in a separate blocking task.
        let policy = Arc::clone(&policy);
        let stats = Arc::clone(&stats);
        let child_pids = Arc::clone(&child_pids);
        let vlog = violations_log.clone();
        let hot_stats2 = Arc::clone(&hot_stats);
        let flusher2 = Arc::clone(&flusher);

        // Intentional fire-and-forget: spawn_blocking tasks run to completion even
        // after JoinHandle is dropped — they are not cancelled.
        tokio::task::spawn_blocking(move || {
            // SAFETY: ph is the isize repr of the valid pipe handle for this connection.
            let h = HANDLE(ph as *mut _);
            handle_connection(h, &policy, &stats, &child_pids, &vlog, &hot_stats2, &flusher2);
            // SAFETY: h — disconnect and close after the connection handler finishes.
            unsafe { DisconnectNamedPipe(h).ok() };
            unsafe { CloseHandle(h).ok() };
        });
    }
}

/// Check if a (host, port) connection should be denied per netrules table.
/// Minimal stub — iterates net_rules, returns true if any matching deny rule.
fn policy_net_is_denied(_policy: &Policy, _host: &str, _port: u16) -> bool {
    // TODO: query policy.net_rules table once Policy exposes net decision API.
    // For now: default-allow (no rules consulted at runtime). The CLI populates
    // the table but enforcement requires Policy::net_decide() to be added.
    false
}

fn handle_connection(
    handle: HANDLE,
    policy: &Policy,
    stats: &Stats,
    child_pids: &crossbeam_queue::SegQueue<u32>,
    violations_log: &Path,
    hot_stats: &HotStats,
    flusher: &ThrottledFlusher,
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

    // Track the PID associated with this pipe connection
    let mut conn_pid: Option<u32> = None;

    loop {
        let req: Req = match read_msg(&mut file) {
            Ok(r) => r,
            Err(_) => break,
        };

        let resp = match req {
            Req::Hello { pid, exe_path } => {
                println!("[sandbox] hello from pid={pid} exe={exe_path}");
                hot_stats.totals.hellos.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                jsonl_log::log(jsonl_log::Event::hello(pid, &exe_path));
                let exe_lower = exe_path.to_ascii_lowercase();
                let map = global_proc_info().pin();
                if let Some(existing) = map.get(&pid) {
                    // Already have entry (e.g., root target) — keep depth, update exe
                    let updated = ProcInfo {
                        depth: existing.depth,
                        exe_lower: Arc::from(exe_lower.as_str()),
                    };
                    map.insert(pid, updated);
                } else {
                    // New process — insert with depth 0 (will be updated by SpawnedChild if child)
                    map.insert(pid, ProcInfo {
                        depth: 0,
                        exe_lower: Arc::from(exe_lower.as_str()),
                    });
                }
                conn_pid = Some(pid);
                Resp::Ok
            }
            Req::SpawnedChild { parent_pid, child_pid, child_exe } => {
                println!("[sandbox] child spawned: parent={parent_pid} child={child_pid} exe={child_exe}");
                hot_stats.totals.children.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                jsonl_log::log(jsonl_log::Event::child(parent_pid, child_pid, &child_exe));
                child_pids.push(child_pid);
                let map = global_proc_info().pin();
                let parent_depth = map.get(&parent_pid).map(|p| p.depth).unwrap_or(0);
                let exe_lower = child_exe.to_ascii_lowercase();
                map.insert(child_pid, ProcInfo {
                    depth: parent_depth + 1,
                    exe_lower: Arc::from(exe_lower.as_str()),
                });
                Resp::Ok
            }
            Req::Decide { dos_path, write } => {
                stats.decide.fetch_add(1, Ordering::Relaxed);
                // Look up depth/exe for this connection's PID
                let (depth, exe_lower) = if let Some(pid) = conn_pid {
                    let map = global_proc_info().pin();
                    map.get(&pid)
                        .map(|info| (Some(info.depth), Some(Arc::clone(&info.exe_lower))))
                        .unwrap_or((None, None))
                } else {
                    (None, None)
                };
                let d = policy.decide_with_context(
                    &dos_path,
                    write,
                    depth,
                    exe_lower.as_deref(),
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
                    policy::Mode::Passthrough => {}
                }
                hot_stats.record_fs(&dos_path, write, denied);
                flusher.maybe_flush();
                Resp::Decision(d)
            }
            Req::RecordOverlay { orig, overlay } => {
                let _ = policy.record_overlay(&orig, &overlay);
                Resp::Ok
            }
            Req::Log { pid, level, msg } => {
                let level_str = match level {
                    LogLevel::Trace => "TRACE",
                    LogLevel::Info => "INFO ",
                    LogLevel::Warn => "WARN ",
                    LogLevel::Error => "ERROR",
                };
                println!("[hook/{pid}] {level_str} {msg}");
                Resp::Ok
            }
            Req::RegisterChild { pid } => {
                println!("[sandbox] child registered: pid={pid}");
                child_pids.push(pid);
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
                let stack_json: Vec<String> = stack_top.iter().map(|f| format!("\"0x{f:x}\"")).collect();
                let line = format!(
                    "{{\"pid\":{pid},\"exe\":\"{}\",\"kind\":\"{kind}\",\"target_pid\":{target_pid},\"start_addr\":\"0x{start_address:x}\",\"caller_pc\":\"0x{caller_pc:x}\",\"caller_module\":{},\"stack\":[{}]}}\n",
                    exe.replace('\\', "\\\\").replace('"', "\\\""),
                    match &caller_module {
                        Some(m) => format!("\"{}\"", m.replace('\\', "\\\\").replace('"', "\\\"")),
                        None => "null".to_string(),
                    },
                    stack_json.join(","),
                );
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true).append(true).open(violations_log)
                {
                    let _ = f.write_all(line.as_bytes());
                }
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
                let stack_json: Vec<String> = stack_top.iter().map(|f| format!("\"0x{f:x}\"")).collect();
                let line = format!(
                    "{{\"pid\":{pid},\"exe\":\"{}\",\"kind\":\"{kind}\",\"protect\":\"0x{requested_protect:x}\",\"size\":{region_size},\"addr\":\"0x{target_address:x}\",\"caller_pc\":\"0x{caller_pc:x}\",\"caller_module\":{},\"stack\":[{}]}}\n",
                    exe.replace('\\', "\\\\").replace('"', "\\\""),
                    match &caller_module {
                        Some(m) => format!("\"{}\"", m.replace('\\', "\\\\").replace('"', "\\\"")),
                        None => "null".to_string(),
                    },
                    stack_json.join(","),
                );
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true).append(true).open(violations_log)
                {
                    let _ = f.write_all(line.as_bytes());
                }
                Resp::Ok
            }
            Req::RegDecide { key_path, value_name, write } => {
                // P8 default-deny: block writes to known DLL-injection persistence
                // vectors. Until full RegistryPolicy wiring, hardcode the most
                // critical paths from DEFAULT_CONFIG_KTAV.
                // Match by suffix to cover HKU\<SID>\... (per-user hive paths)
                // as well as direct HKLM/HKCU/HKCR/HKU forms.
                const PERSISTENCE_DENY_SUFFIXES: &[&str] = &[
                    r"\software\microsoft\windows nt\currentversion\windows",
                    r"\software\wow6432node\microsoft\windows nt\currentversion\windows",
                    r"\software\microsoft\windows nt\currentversion\image file execution options",
                    r"\system\currentcontrolset\control\session manager\appcertdlls",
                ];
                let key_lower = key_path.to_ascii_lowercase();
                let is_persistence = PERSISTENCE_DENY_SUFFIXES.iter().any(|s| key_lower.contains(s));
                let (mode, denied) = if write && is_persistence {
                    eprintln!("[reg] DENY {key_path} value={value_name:?}");
                    ("deny", true)
                } else if write && (key_lower.contains(r"\software\") || key_lower.ends_with(r"\software")) {
                    // Non-persistence HKCU\Software writes → silent success
                    // (program thinks it wrote, sandbox absorbs it)
                    ("silent_ok", false)
                } else {
                    ("passthrough", false)
                };
                hot_stats.totals.reg_decides.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if denied { hot_stats.totals.reg_denies.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
                hot_stats.record_reg(&key_path, write, denied);
                if denied {
                    jsonl_log::log(jsonl_log::Event::reg_decide(&key_path, write, mode));
                }
                flusher.maybe_flush();
                Resp::RegDecision { mode: mode.into(), value_json: None }
            }
            Req::RegWrite { key_path, value_name, .. } => {
                println!("[reg] write: {key_path}\\{value_name}");
                Resp::Ok
            }
            Req::RegDeleteValue { key_path, value_name } => {
                println!("[reg] delete_value: {key_path}\\{value_name}");
                Resp::Ok
            }
            Req::RegDeleteKey { key_path } => {
                println!("[reg] delete_key: {key_path}");
                Resp::Ok
            }
            Req::NetDecide { host, port } => {
                // Minimal: check netrules table for matching deny rule.
                // Default-allow; explicit deny rule blocks.
                let allow = !policy_net_is_denied(policy, &host, port);
                if !allow {
                    eprintln!("[net] DENY {host}:{port}");
                }
                hot_stats.totals.net_decides.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if !allow { hot_stats.totals.net_denies.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
                let host_port = format!("{host}:{port}");
                hot_stats.record_net(&host_port, !allow);
                jsonl_log::log(jsonl_log::Event::net_decide(&host_port, allow));
                flusher.maybe_flush();
                Resp::NetDecision { allow }
            }
            Req::MemDecide { target_pid, op } => {
                println!("[mem] decide: pid={target_pid} op={op}");
                Resp::MemDecision { allow: false }
            }
        };

        if write_msg(&mut file, &resp).is_err() {
            break;
        }
    }

    // Do NOT let `file` run its Drop (which would call CloseHandle on the underlying HANDLE).
    // The caller in spawn_blocking closes the handle via DisconnectNamedPipe + CloseHandle.
    // Double-closing would be UB / use-after-free on the handle.
    std::mem::forget(file);
}

// ─── Process launch & injection ──────────────────────────────────────────────

fn launch_suspended(cwd: &std::path::Path, target_args: &[String], _guard: GuardLevel) -> Result<PROCESS_INFORMATION> {
    // NOTE: mitigations are applied from WITHIN hook.dll (after hooks installed)
    // via SetProcessMitigationPolicy — not from the launcher via
    // PROC_THREAD_ATTRIBUTE, because BLOCK_NON_MICROSOFT_BINARIES would
    // prevent loading our hook.dll in the first place.

    let cmdline = build_cmdline(target_args);
    let mut cmdline_wide: Vec<u16> = cmdline.encode_utf16().chain(Some(0)).collect();
    let cwd_wide: Vec<u16> = cwd.as_os_str().encode_wide().chain(Some(0)).collect();

    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();

    // SAFETY: cmdline_wide and cwd_wide are valid null-terminated UTF-16 strings.
    unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(windows::core::PWSTR(cmdline_wide.as_mut_ptr())),
            None, None, false,
            CREATE_SUSPENDED,
            None,
            PCWSTR(cwd_wide.as_ptr()),
            &si,
            &mut pi,
        )
    }
    .context("CreateProcessW failed")?;

    Ok(pi)
}

fn inject_dll(process: HANDLE, thread: HANDLE, dll_path: &str) -> Result<()> {
    let dll_wide: Vec<u16> = OsStr::new(dll_path)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let byte_len = dll_wide.len() * 2;

    // SAFETY: process is a valid HANDLE with PROCESS_ALL_ACCESS; byte_len > 0.
    let remote_buf = unsafe {
        VirtualAllocEx(process, None, byte_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };
    anyhow::ensure!(!remote_buf.is_null(), "VirtualAllocEx failed");

    let mut written = 0usize;
    // SAFETY: remote_buf just allocated in target; dll_wide valid for byte_len bytes.
    let write_ok = unsafe {
        WriteProcessMemory(process, remote_buf, dll_wide.as_ptr() as *const _, byte_len, Some(&mut written))
    };
    if write_ok.is_err() || written != byte_len {
        unsafe { VirtualFreeEx(process, remote_buf, 0, VIRTUAL_FREE_TYPE(0x8000)).ok() };
        anyhow::bail!("WriteProcessMemory failed");
    }

    let k32_wide: Vec<u16> = OsStr::new("kernel32.dll").encode_wide().chain(Some(0)).collect();
    // SAFETY: k32_wide is a valid null-terminated UTF-16 module name.
    let k32 = unsafe { GetModuleHandleW(PCWSTR(k32_wide.as_ptr()))? };
    // SAFETY: k32 is valid HMODULE; "LoadLibraryW\0" is valid PCSTR.
    let load_lib = unsafe { GetProcAddress(k32, windows::core::s!("LoadLibraryW")) }
        .context("GetProcAddress(LoadLibraryW) returned NULL")?;

    // Queue APC on the suspended main thread instead of CreateRemoteThread.
    // APC runs in the context of the main thread BEFORE the entry point,
    // avoiding CRT double-initialization that breaks cmd.exe.
    type FnNtQueueApcThread = unsafe extern "system" fn(
        HANDLE, *const core::ffi::c_void, *mut core::ffi::c_void,
        *mut core::ffi::c_void, *mut core::ffi::c_void,
    ) -> i32;
    let ntdll_w: Vec<u16> = OsStr::new("ntdll.dll").encode_wide().chain(Some(0)).collect();
    // SAFETY: ntdll is always loaded.
    let ntdll = unsafe { GetModuleHandleW(PCWSTR(ntdll_w.as_ptr()))? };
    let nt_queue = unsafe { GetProcAddress(ntdll, windows::core::s!("NtQueueApcThread")) }
        .context("NtQueueApcThread not found")?;
    // SAFETY: load_lib is LoadLibraryW address; remote_buf is the DLL path.
    let status = unsafe {
        let queue_fn: FnNtQueueApcThread = std::mem::transmute(nt_queue);
        queue_fn(
            thread,
            load_lib as *const _,
            remote_buf,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if status < 0 {
        unsafe { VirtualFreeEx(process, remote_buf, 0, VIRTUAL_FREE_TYPE(0x8000)).ok() };
        anyhow::bail!("NtQueueApcThread failed: 0x{status:08x}");
    }

    // APC will execute when thread resumes and enters alertable wait.
    // The main thread of a suspended CREATE_SUSPENDED process enters
    // alertable state during kernel32!BaseThreadInitThunk before calling
    // the entry point — our APC fires there.
    //
    // Note: we can't verify exit_code like with CreateRemoteThread.
    // If hook.dll fails to load, the process runs un-sandboxed.
    // inject_via_apc in hook.rs handles this for child processes
    // with a post-resume check.

    Ok(())
}

// ─── Pre-launch code integrity scan ──────────────────────────────────────────

/// Scan the main exe's .text section for direct syscall instructions before
/// resuming the child process. Returns Err if syscall instructions are found.
fn pre_launch_scan(
    process: HANDLE,
    target_exe: &str,
    target_pid: u32,
    violations_log: &Path,
) -> Result<()> {
    let image_base = get_image_base(process).context("get image base")?;
    if image_base == 0 {
        anyhow::bail!("image base is null");
    }

    // Read PE headers (4 KiB is enough for DOS + NT + section table)
    let mut pe_headers = vec![0u8; 4096];
    read_remote_memory(process, image_base, &mut pe_headers)
        .context("read PE headers")?;
    let text = policy::scan::pe_text_section(&pe_headers)
        .context("no .text section in PE")?;

    // Cap to a sane size to avoid pathological inputs
    let scan_size = (text.virtual_size as usize).min(64 * 1024 * 1024);
    let mut text_bytes = vec![0u8; scan_size];
    read_remote_memory(
        process,
        image_base + text.virtual_address as usize,
        &mut text_bytes,
    )
    .context("read .text section")?;

    let text_base = (image_base + text.virtual_address as usize) as u64;
    let hits = policy::scan::find_direct_syscalls(&text_bytes, text_base);
    if hits.is_empty() {
        return Ok(());
    }

    // Log violation
    log_pre_launch_violation(violations_log, target_pid, target_exe, &hits);
    eprintln!(
        "[VIOLATION] pre-launch scan: {} direct syscall(s) in {} (.text)",
        hits.len(),
        target_exe,
    );
    for h in hits.iter().take(5) {
        eprintln!("  - {} at offset 0x{:x}", h.kind, h.offset);
    }
    anyhow::bail!("direct syscall instructions found in target .text");
}

fn log_pre_launch_violation(
    log_path: &Path,
    target_pid: u32,
    target_exe: &str,
    hits: &[policy::scan::SyscallHit],
) {
    use std::io::Write;
    let hit_json: Vec<String> = hits
        .iter()
        .map(|h| format!("[\"0x{:x}\",\"{}\"]", h.offset, h.kind))
        .collect();
    let line = format!(
        "{{\"kind\":\"PreLaunchViolation\",\"target_pid\":{target_pid},\"target_exe\":\"{}\",\"hit_count\":{},\"hits\":[{}]}}\n",
        target_exe.replace('\\', "\\\\").replace('"', "\\\""),
        hits.len(),
        hit_json.join(","),
    );
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Get the image base address of the main executable in the target process.
/// Reads PEB.ImageBaseAddress (offset 0x10 on x64).
fn get_image_base(process: HANDLE) -> Result<usize> {
    // NtQueryInformationProcess(ProcessBasicInformation = 0)
    // Returns PROCESS_BASIC_INFORMATION; PebBaseAddress is at offset 0x08.
    #[repr(C)]
    #[derive(Default)]
    struct ProcessBasicInformation {
        exit_status: i32,
        _pad0: u32,
        peb_base_address: usize,
        affinity_mask: usize,
        base_priority: i32,
        _pad1: u32,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }

    // Resolve NtQueryInformationProcess from ntdll
    type FnNtQueryInformationProcess = unsafe extern "system" fn(
        HANDLE, u32, *mut core::ffi::c_void, u32, *mut u32,
    ) -> i32;

    let ntdll: Vec<u16> = OsStr::new("ntdll.dll").encode_wide().chain(Some(0)).collect();
    // SAFETY: ntdll is always loaded.
    let hmod = unsafe { GetModuleHandleW(PCWSTR(ntdll.as_ptr()))? };
    // SAFETY: hmod is valid; literal ASCII null-terminated name.
    let proc_addr = unsafe {
        GetProcAddress(hmod, windows::core::s!("NtQueryInformationProcess"))
    }
    .context("NtQueryInformationProcess not found")?;
    // SAFETY: proc_addr is the real NtQueryInformationProcess export.
    let nt_query: FnNtQueryInformationProcess =
        unsafe { std::mem::transmute(proc_addr) };

    let mut info = ProcessBasicInformation::default();
    let mut ret_len: u32 = 0;
    // SAFETY: info is valid for size_of writes; process is a valid handle.
    let status = unsafe {
        nt_query(
            process,
            0,
            &mut info as *mut _ as *mut _,
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut ret_len,
        )
    };
    if status < 0 {
        anyhow::bail!("NtQueryInformationProcess failed: 0x{status:x}");
    }
    if info.peb_base_address == 0 {
        anyhow::bail!("PEB base address is null");
    }

    // Read ImageBaseAddress at PEB + 0x10 (x64)
    let mut image_base_bytes = [0u8; 8];
    read_remote_memory(process, info.peb_base_address + 0x10, &mut image_base_bytes)
        .context("read PEB.ImageBaseAddress")?;
    Ok(usize::from_le_bytes(image_base_bytes))
}

fn read_remote_memory(process: HANDLE, addr: usize, buf: &mut [u8]) -> Result<()> {
    let mut read: usize = 0;
    // SAFETY: process is valid; buf is valid for buf.len() writes.
    let ok = unsafe {
        windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            process,
            addr as *const _,
            buf.as_mut_ptr() as *mut _,
            buf.len(),
            Some(&mut read),
        )
    };
    ok.context("ReadProcessMemory failed")?;
    if read != buf.len() {
        anyhow::bail!("short read: {read} of {}", buf.len());
    }
    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Hide the console window unconditionally unless -d is set. Called once at
/// startup before any other output. When stdio is piped (no console attached)
/// GetConsoleWindow returns NULL and this is a no-op.
fn maybe_hide_console(debug: bool) {
    if debug {
        return;
    }
    // SAFETY: GetConsoleWindow and ShowWindow have no documented preconditions
    //         and are safe to call from any thread; both handle null/invalid
    //         input by returning an error code we ignore.
    unsafe {
        let hwnd = GetConsoleWindow();
        if !hwnd.is_invalid() {
            let _ = ShowWindow(hwnd, SW_HIDE);
        }
    }
}

/// Build a Windows command line string from an argument list.
/// Follows Microsoft CommandLineToArgvW escaping rules.
fn build_cmdline(args: &[String]) -> String {
    fn quote_arg(a: &str) -> String {
        if a.is_empty() {
            return "\"\"".to_string();
        }
        if !a.contains(' ') && !a.contains('\t') && !a.contains('"') {
            return a.to_string();
        }
        let mut out = String::with_capacity(a.len() + 4);
        out.push('"');
        let bytes = a.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let ch = bytes[i];
            if ch == b'\\' {
                let start = i;
                while i < bytes.len() && bytes[i] == b'\\' { i += 1; }
                let n = i - start;
                if i == bytes.len() {
                    // Trailing backslashes → double them before closing quote
                    for _ in 0..n * 2 { out.push('\\'); }
                } else if bytes[i] == b'"' {
                    // Backslashes before quote → double them + escape the quote
                    for _ in 0..n * 2 { out.push('\\'); }
                    out.push('\\');
                    out.push('"');
                    i += 1;
                } else {
                    // Backslashes not before quote → emit literally
                    for _ in 0..n { out.push('\\'); }
                }
            } else if ch == b'"' {
                out.push('\\');
                out.push('"');
                i += 1;
            } else {
                out.push(ch as char);
                i += 1;
            }
        }
        out.push('"');
        out
    }
    args.iter().map(|a| quote_arg(a)).collect::<Vec<_>>().join(" ")
}

/// Find hook.dll alongside the launcher executable.
fn find_hook_dll() -> Result<String> {
    let exe = std::env::current_exe()?;
    let dll = exe
        .parent()
        .unwrap_or(Path::new("."))
        .join("hook.dll");
    anyhow::ensure!(
        dll.exists(),
        "hook.dll not found at {}",
        dll.display()
    );
    Ok(dll.to_string_lossy().into_owned())
}

/// Ensure the auto-discovered state directory exists and return the paths
/// `(cfg_path, sandbox_root, mock_dirs_root)`.
///
/// State dir layout: `<parent>/.winrsbox/<cwd-name>/`
///   - `workdir/`       — CoW overlay root
///   - `mock-dirs/`     — mocked directory root
///   - `sandbox.ktav`   — policy config (default-written if absent)
fn ensure_state(project_root: &Path) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let name = project_root
        .file_name()
        .context("cwd has no name (running from drive root?)")?;
    let parent = project_root
        .parent()
        .context("cwd has no parent (running from drive root?)")?;
    let state_dir = parent.join(".winrsbox").join(name);
    let workdir = state_dir.join("workdir");
    let mock_dirs = state_dir.join("mock-dirs");
    let cfg_path = state_dir.join("sandbox.ktav");

    std::fs::create_dir_all(&workdir)
        .with_context(|| format!("create state dir {}", workdir.display()))?;
    std::fs::create_dir_all(&mock_dirs)
        .with_context(|| format!("create mock-dirs {}", mock_dirs.display()))?;

    if !cfg_path.exists() {
        std::fs::write(&cfg_path, DEFAULT_CONFIG_KTAV)
            .with_context(|| format!("write default config {}", cfg_path.display()))?;
    }

    Ok((cfg_path, workdir, mock_dirs))
}

/// Discover state directory path (without creating it — CLI mode creates on demand).
fn discover_state_dir(project_root: &Path) -> Result<PathBuf> {
    let name = project_root
        .file_name()
        .context("cwd has no name (running from drive root?)")?;
    let parent = project_root
        .parent()
        .context("cwd has no parent (running from drive root?)")?;
    Ok(parent.join(".winrsbox").join(name))
}

// ─── Stats ───────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Stats {
    decide: AtomicU64,
    redirect: AtomicU64,
    deny: AtomicU64,
    mock_: AtomicU64,
    cow: AtomicU64,
    violations: AtomicU64,
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
    use super::build_cmdline;

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
