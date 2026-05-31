// ─── Sandbox orchestration helpers ───────────────────────────────────────────

use anyhow::{Context, Result};
use std::{
    os::windows::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            Console::GetConsoleWindow,
            Threading::{
                CreateProcessW, DeleteProcThreadAttributeList,
                InitializeProcThreadAttributeList, TerminateProcess,
                UpdateProcThreadAttribute, CREATE_SUSPENDED,
                EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, PROCESS_INFORMATION,
                STARTUPINFOEXW, STARTUPINFOW,
            },
        },
        UI::WindowsAndMessaging::{ShowWindow, SW_HIDE},
    },
};

use winrsbox::mitigations::{self, v1 as miti_v1};

// Raw FFI declaration for IsWow64Process2 — avoids pulling in the
// Win32_System_SystemInformation feature for one symbol. Signature per
// MSDN: BOOL IsWow64Process2(HANDLE, USHORT*, USHORT*).
//
// pProcessMachine receives IMAGE_FILE_MACHINE_UNKNOWN (0) when the target
// process is NOT WoW64 (i.e. running natively for the host arch). Any other
// value (e.g. IMAGE_FILE_MACHINE_I386 = 0x014C) means the process is a
// 32-bit binary running under the WoW64 subsystem.
#[allow(non_snake_case)]
extern "system" {
    fn IsWow64Process2(
        hProcess: HANDLE,
        pProcessMachine: *mut u16,
        pNativeMachine: *mut u16,
    ) -> i32; // BOOL
}

/// Lock-in constants used by the WoW64 refusal check below — kept here so
/// the convention is auditable in one place and unit-tested.
const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0x0000;
/// 32-bit x86. Not referenced in the runtime path (we only compare against
/// `IMAGE_FILE_MACHINE_UNKNOWN`), but kept as a named constant so the unit
/// test below documents what "non-zero process_machine" looks like in
/// practice. `#[allow(dead_code)]` because the runtime check is value-based,
/// not enum-based.
#[allow(dead_code)]
const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
const STATUS_DLL_INIT_FAILED: u32 = 0xC000_0142;

/// `FILE_ATTRIBUTE_REPARSE_POINT` (winnt.h). Set on any reparse point —
/// symlinks, directory junctions, and mount points alike. Checking this bit
/// directly (rather than only `FileType::is_symlink`) catches NTFS junctions
/// regardless of reparse tag, which is the primary TOCTOU redirection vector
/// on Windows when an attacker controls the parent directory.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Default ktav policy written when auto-discovery creates a fresh state dir.
pub(crate) const DEFAULT_CONFIG_KTAV: &str = "\
## winrsbox policy — auto-generated on first run. Edit to customize.
## (ktav 0.5.0 comments start with `##`; a single `#` is literal content.)
##
## Reads pass through to the real filesystem; writes are Copy-on-Write
## into <state_dir>/workdir/. Add `rules` entries to deny or mock paths.
##
## Verbose JSONL logging for this sandbox folder (uncomment to enable).
## Values: error / warn / info / trace. CLI `--log-level` overrides this
## if explicitly set; otherwise this value wins over the built-in `info`.
## Use `trace` while debugging a workload (every hook log + every decide
## lands in sandbox.log.jsonl) — no need to remember CLI flags each launch.
## To enable: copy the next line WITHOUT the `## ` prefix.
## log_level: trace

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

## mock_dirs: [
##     {
##         prefix: C:\\Users\\Computer\\.config\\fakeapp
##     }
## ]

## Registry persistence vectors — deny write to prevent DLL injection
## via AppInit_DLLs, Image File Execution Options, AppCertDlls.
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

/// Hide the console window unconditionally unless -d is set. Called once at
/// startup before any other output. When stdio is piped (no console attached)
/// GetConsoleWindow returns NULL and this is a no-op.
pub(crate) fn maybe_hide_console(debug: bool) {
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

/// Launch `target_args[0]` suspended under `cwd`, returning the PROCESS_INFORMATION.
///
/// Applies create-time kernel mitigations via PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY.
/// The runtime-only `BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` flag is dropped here
/// (hook.dll is unsigned — kernel would reject its load if the bit were set at
/// create time). That flag is re-applied AFTER hook.dll loads, from inside
/// hook::apply_mitigations via SetProcessMitigationPolicy. All other v1/v2 bits
/// only take effect at process create, so they MUST be passed via this path.
pub(crate) fn launch_suspended(cwd: &Path, target_args: &[String], guard: crate::GuardLevel) -> Result<PROCESS_INFORMATION> {
    let cmdline = build_cmdline(target_args);
    let mut cmdline_wide: Vec<u16> = cmdline.encode_utf16().chain(Some(0)).collect();
    let cwd_wide: Vec<u16> = cwd.as_os_str().encode_wide().chain(Some(0)).collect();

    // ─── Compute mitigation bitmask for this guard level ───────────────────
    let profile = match guard {
        crate::GuardLevel::None => mitigations::Profile::None,
        crate::GuardLevel::Scan => mitigations::Profile::Scan,
        crate::GuardLevel::Full => mitigations::Profile::Full,
        crate::GuardLevel::Static => mitigations::Profile::Static,
    };
    let (v1, v2) = mitigations::compute(profile);
    // Strip the two bits that would brick our own bootstrap if enforced BEFORE
    // hook.dll loads + installs its detours:
    //   * BLOCK_NON_MICROSOFT_BINARIES — kernel refuses the unsigned hook.dll
    //     at LoadLibrary time.
    //   * PROHIBIT_DYNAMIC_CODE — blocks detour2 from allocating/patching the
    //     executable trampolines it needs to install the ntdll hooks.
    // Both are re-applied at RUNTIME by hook::apply_mitigations, AFTER all
    // detours are in place (existing executable code keeps running; only the
    // guest's *future* dynamic code / unsigned loads are then blocked). These
    // two only appear in Profile::Static; Full carries neither (it's JIT-safe),
    // so for Full this strip is a no-op.
    let create_v1 = v1
        & !miti_v1::BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
        & !miti_v1::PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
    let has_mitigations = (create_v1 != 0) || (v2 != 0);
    // Stack-allocated 16-byte buffer; must outlive CreateProcessW (the kernel
    // reads from the pointer stored in the attribute list, not a copy).
    let bytes = mitigations::to_bytes(create_v1, v2);

    let mut pi = PROCESS_INFORMATION::default();

    // ─── Build the attribute list (only if we have any mitigation bits) ────
    //
    // SAFETY for the whole block: the buffers used by UpdateProcThreadAttribute
    // (here: `bytes` for PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY) MUST outlive
    // the CreateProcessW call AND the DeleteProcThreadAttributeList call. We
    // keep `bytes` (stack) and `attr_buf` (heap Vec) on this stack frame past
    // both. `attr_list` is a raw pointer into `attr_buf`'s backing storage.
    let mut attr_buf: Vec<u8> = Vec::new();
    let mut attr_list = LPPROC_THREAD_ATTRIBUTE_LIST::default();
    let mut creation_flags = CREATE_SUSPENDED;

    if has_mitigations {
        // First call: query required buffer size. Expected to fail with
        // ERROR_INSUFFICIENT_BUFFER and write attr_list_size. Ignore the Result.
        let mut attr_list_size: usize = 0;
        // SAFETY: passing None for lpattributelist is the documented way to query size.
        let _ = unsafe {
            InitializeProcThreadAttributeList(None, 1, None, &mut attr_list_size)
        };
        anyhow::ensure!(
            attr_list_size > 0,
            "InitializeProcThreadAttributeList returned size=0 (driver inconsistency)",
        );
        attr_buf = vec![0u8; attr_list_size];
        attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut _);

        // SAFETY: attr_buf is at least attr_list_size bytes; pointer is valid.
        unsafe {
            InitializeProcThreadAttributeList(Some(attr_list), 1, None, &mut attr_list_size)
        }
        .context("InitializeProcThreadAttributeList failed")?;

        // SAFETY: bytes is a stack 16-byte array; pointer valid for the
        // duration of the CreateProcessW call (and the subsequent
        // DeleteProcThreadAttributeList — the kernel keeps the buffer pointer
        // in the attribute list, not a copy).
        let update_result = unsafe {
            UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
                Some(bytes.as_ptr() as *const std::ffi::c_void),
                bytes.len(),
                None,
                None,
            )
        };
        if let Err(e) = update_result {
            // SAFETY: attr_list was successfully Initialize'd above.
            unsafe { DeleteProcThreadAttributeList(attr_list); }
            return Err(anyhow::Error::from(e))
                .context("UpdateProcThreadAttribute(MITIGATION_POLICY) failed");
        }
        creation_flags |= EXTENDED_STARTUPINFO_PRESENT;
    }

    // STARTUPINFOEXW is repr(C) with STARTUPINFOW as the first field, so
    // CreateProcessW (which expects *const STARTUPINFOW) can read the W part
    // from a pointer to the EXW; `cb` must equal sizeof(STARTUPINFOEXW) so
    // the kernel knows to look past the W tail at lpAttributeList. When we
    // have no mitigations, we still use STARTUPINFOEXW for code simplicity
    // but set `cb = sizeof(STARTUPINFOW)` and omit EXTENDED_STARTUPINFO_PRESENT
    // so the kernel ignores the unused tail.
    let si_ex = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: if has_mitigations {
                std::mem::size_of::<STARTUPINFOEXW>() as u32
            } else {
                std::mem::size_of::<STARTUPINFOW>() as u32
            },
            ..Default::default()
        },
        lpAttributeList: attr_list,
    };
    // *const STARTUPINFOW — same address regardless of has_mitigations: the
    // STARTUPINFOW header sits at offset 0 of STARTUPINFOEXW (repr(C)).
    let si_ptr: *const STARTUPINFOW = &si_ex.StartupInfo;

    // SAFETY: cmdline_wide and cwd_wide are valid null-terminated UTF-16 strings.
    //         attr_list (if used) is initialized and was populated above.
    //         si_ex stays alive for the duration of this call.
    let create_result = unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(windows::core::PWSTR(cmdline_wide.as_mut_ptr())),
            None, None, false,
            creation_flags,
            None,
            PCWSTR(cwd_wide.as_ptr()),
            si_ptr,
            &mut pi,
        )
    };

    // Free the attribute list — kernel has copied what it needs from it by
    // the time CreateProcessW returns (success OR failure). Per MSDN,
    // DeleteProcThreadAttributeList does NOT free the buffer pointers we
    // attached (bytes); we manage their lifetime ourselves via Rust's stack.
    if has_mitigations {
        // SAFETY: attr_list was Initialize'd; safe to Delete exactly once.
        unsafe { DeleteProcThreadAttributeList(attr_list); }
    }
    // Touch si_ex AFTER CreateProcessW to ensure the compiler doesn't move
    // the drop earlier. (Defensive — repr(C) on-stack lifetime already covers
    // the syscall, but the read is free and documents intent.)
    let _ = si_ex.StartupInfo.cb;
    // Touch attr_buf to assert it stayed alive past the syscall.
    let _ = attr_buf.len();

    create_result.context("CreateProcessW failed")?;

    // ─── Refuse 32-bit (WoW64) children ─────────────────────────────────────
    //
    // Rationale: our hook.dll patches x64 ntdll. A 32-bit process loads its
    // own 32-bit ntdll.dll inside the WoW64 subsystem; those stubs perform
    // 32→64 mode transitions (via wow64cpu!CpuSimulate, plus the well-known
    // FS:[0xC0] far-call "Heaven's Gate" path) that bypass our hooks
    // entirely. Modern AI-agent toolchains (Node, Python, Rust) all ship as
    // x64, so refusing 32-bit binaries is the right call rather than
    // attempting a separate 32-bit hook payload.
    //
    // The process is currently CREATE_SUSPENDED, so terminating it here is
    // safe: no user code has executed yet.
    if let Err(e) = enforce_native_x64(pi.hProcess, pi.dwProcessId) {
        // SAFETY: pi.hProcess / pi.hThread are valid handles from the
        // CreateProcessW that just succeeded above. Close both so we don't
        // leak; the suspended target is already terminated by enforce_*.
        unsafe {
            CloseHandle(pi.hThread).ok();
            CloseHandle(pi.hProcess).ok();
        }
        return Err(e);
    }

    Ok(pi)
}

/// Verify the child is a native x64 process (not WoW64). On any positive
/// detection of 32-bit/WoW64, the child is TerminateProcess()'d and an
/// error is returned. If IsWow64Process2 itself fails we treat that as a
/// hard error (fail-closed): we cannot prove the child is safe to inject
/// into, so we refuse to continue.
fn enforce_native_x64(child_handle: HANDLE, child_pid: u32) -> Result<()> {
    let mut process_machine: u16 = 0;
    let mut native_machine: u16 = 0;
    // SAFETY: child_handle is a valid PROCESS handle from CreateProcessW;
    //         both out pointers point to stack-allocated u16s.
    let ok = unsafe {
        IsWow64Process2(
            child_handle,
            &mut process_machine as *mut u16,
            &mut native_machine as *mut u16,
        )
    };
    if ok == 0 {
        // SAFETY: child_handle is a valid PROCESS handle.
        unsafe { let _ = TerminateProcess(child_handle, STATUS_DLL_INIT_FAILED); }
        anyhow::bail!(
            "IsWow64Process2 failed for child pid={child_pid}; refusing to inject (fail-closed)"
        );
    }
    if process_machine != IMAGE_FILE_MACHINE_UNKNOWN {
        // SAFETY: child_handle is a valid PROCESS handle; the target is
        //         CREATE_SUSPENDED so no user code has run yet.
        unsafe { let _ = TerminateProcess(child_handle, STATUS_DLL_INIT_FAILED); }
        eprintln!(
            "[sandbox] CRITICAL: 32-bit (WoW64) child not supported, terminating pid={child_pid} \
             process_machine=0x{process_machine:04X} native_machine=0x{native_machine:04X}",
        );
        anyhow::bail!(
            "32-bit child rejected — sandbox only supports x64 binaries \
             (process_machine=0x{process_machine:04X})"
        );
    }
    Ok(())
}

/// Build a Windows command line string from an argument list.
/// Follows Microsoft CommandLineToArgvW escaping rules.
pub(crate) fn build_cmdline(args: &[String]) -> String {
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
pub(crate) fn find_hook_dll() -> Result<String> {
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

/// Symlink/reparse-safe replacement for `create_dir_all` over an
/// attacker-influenced path chain.
///
/// `base` is assumed to already exist and is treated as the trust boundary
/// (we never create it). Each component of `relative` is then created one
/// segment at a time. For every segment that already exists we reject it if
/// it is a reparse point (symlink **or** NTFS junction/mount point) or not a
/// real directory; only then do we descend. This prevents an attacker who
/// controls `base` from pre-creating `.winrsbox` (or the `<name>` subdir) as
/// a junction that redirects our overlay/config writes outside the sandbox.
///
/// `symlink_metadata` is used so we inspect the link itself, never its
/// target. We check `FILE_ATTRIBUTE_REPARSE_POINT` in addition to
/// `is_symlink()` because Windows junctions are reparse points that
/// `is_symlink()` does not always report.
fn create_dir_tree_no_reparse(base: &Path, relative: &Path) -> Result<()> {
    let mut cur = base.to_path_buf();
    for comp in relative.components() {
        cur.push(comp);
        match std::fs::symlink_metadata(&cur) {
            Ok(md) => {
                let ft = md.file_type();
                if ft.is_symlink()
                    || (md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
                {
                    anyhow::bail!(
                        "refusing to use sandbox state path: component {} is a \
                         symlink/junction (reparse point) — possible TOCTOU redirection",
                        cur.display()
                    );
                }
                anyhow::ensure!(
                    ft.is_dir(),
                    "sandbox state path component {} exists but is not a directory",
                    cur.display()
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&cur)
                    .with_context(|| format!("create state dir {}", cur.display()))?;
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("stat sandbox state path component {}", cur.display())
                });
            }
        }
    }
    Ok(())
}

/// Ensure the auto-discovered state directory exists and return the paths
/// `(cfg_path, sandbox_root, mock_dirs_root)`.
///
/// State dir layout: `<parent>/.winrsbox/<cwd-name>/`
///   - `workdir/`       — CoW overlay root
///   - `mock-dirs/`     — mocked directory root
///   - `sandbox.ktav`   — policy config (default-written if absent)
pub(crate) fn ensure_state(project_root: &Path) -> Result<(PathBuf, PathBuf, PathBuf)> {
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

    // Build the tree step-by-step under `parent` (the trust boundary), rejecting
    // any existing component reached through a symlink/junction. We never blindly
    // `create_dir_all` through this attacker-influenced chain. Creating `workdir`
    // and `mock_dirs` re-walks (and thus re-validates) the shared
    // `.winrsbox/<name>` prefix, tightening the TOCTOU window.
    let state_rel = Path::new(".winrsbox").join(name);
    create_dir_tree_no_reparse(parent, &state_rel)
        .with_context(|| format!("create state dir {}", state_dir.display()))?;
    create_dir_tree_no_reparse(&state_dir, Path::new("workdir"))
        .with_context(|| format!("create state dir {}", workdir.display()))?;
    create_dir_tree_no_reparse(&state_dir, Path::new("mock-dirs"))
        .with_context(|| format!("create mock-dirs {}", mock_dirs.display()))?;

    if !cfg_path.exists() {
        std::fs::write(&cfg_path, DEFAULT_CONFIG_KTAV)
            .with_context(|| format!("write default config {}", cfg_path.display()))?;
    }

    Ok((cfg_path, workdir, mock_dirs))
}

/// Discover state directory path (without creating it — CLI mode creates on demand).
pub(crate) fn discover_state_dir(project_root: &Path) -> Result<PathBuf> {
    let name = project_root
        .file_name()
        .context("cwd has no name (running from drive root?)")?;
    let parent = project_root
        .parent()
        .context("cwd has no parent (running from drive root?)")?;
    Ok(parent.join(".winrsbox").join(name))
}

/// Assign `process` to a new Job Object with given limits; returns the Job handle.
/// The caller must keep the returned HANDLE alive for the duration of the child.
pub(crate) fn setup_job_object(
    process: HANDLE,
    memory_limit: Option<u64>,
    strict_clipboard: bool,
) -> Result<HANDLE> {
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW,
        JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_BASIC_UI_RESTRICTIONS,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT, JOB_OBJECT_UILIMIT,
    };

    // GiB → bytes, overflow-safe: a pathologically large `gb` saturates to
    // u64::MAX (effectively "unlimited") instead of wrapping to a tiny limit.
    let limits = winrsbox::jobctl::JobLimits::default()
        .with_memory(memory_limit.map(|gb| gb.saturating_mul(1024 * 1024 * 1024)));
    // SAFETY: creating a new job with no name, no security attrs.
    let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
        .context("CreateJobObjectW")?;
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = Default::default();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT(limits.limit_flags());
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
    }
    .context("SetInformationJobObject")?;

    // SAFETY: both job and process are valid HANDLEs.
    unsafe { AssignProcessToJobObject(job, process) }.context("AssignProcessToJobObject")?;

    // Apply UI restrictions to block clipboard, foreign-HWND messaging,
    // ExitWindowsEx, etc. Best-effort: not all flags are enforced on every
    // Windows build (e.g. UILIMIT_HANDLES has limited effect on Win10
    // 19045 against medium-integrity foreign windows). The user32 hooks
    // in hook::ui_guard provide a second layer.
    // Diagnostic escape hatch: set FS_SANDBOX_NO_UI_LIMITS=1 to skip Job-Object
    // UI restrictions entirely (GLOBALATOMS / SYSTEMPARAMS / DESKTOP /
    // EXITWINDOWS). Suspected to break per-process keyboard-layout switching
    // because the Win32 WM_INPUTLANGCHANGEREQUEST broadcast uses global atoms
    // via RegisterWindowMessage.
    if std::env::var("FS_SANDBOX_NO_UI_LIMITS").is_err() {
        let mut ui = winrsbox::jobctl::UiRestrictions::default();
        if strict_clipboard {
            ui = ui.with_strict_clipboard();
        }
        let ui_info = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT(ui.limit_flags()),
        };
        // SAFETY: ui_info is a valid JOBOBJECT_BASIC_UI_RESTRICTIONS struct.
        unsafe {
            SetInformationJobObject(
                job,
                JobObjectBasicUIRestrictions,
                &ui_info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            )
        }
        .context("SetInformationJobObject(UI restrictions)")?;
    }

    Ok(job)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lock-in the convention that IMAGE_FILE_MACHINE_UNKNOWN (=0) is the
    /// sentinel "process is NOT WoW64" value, and that the I386 constant
    /// (which a 32-bit Windows binary reports) is distinct from it. If the
    /// SDK ever renumbers these or someone copy-pastes the wrong constant
    /// into enforce_native_x64, this test will catch it.
    #[test]
    fn wow64_constant_is_distinct_from_native() {
        assert_eq!(IMAGE_FILE_MACHINE_UNKNOWN, 0);
        assert_ne!(IMAGE_FILE_MACHINE_I386, 0);
        assert_eq!(IMAGE_FILE_MACHINE_I386, 0x014C);
        // STATUS_DLL_INIT_FAILED is the NTSTATUS we use as the termination
        // exit code; it must remain in the "fatal error" space (top bit set).
        assert!(STATUS_DLL_INIT_FAILED & 0xC000_0000 == 0xC000_0000);
    }

    /// The auto-generated default config must be valid ktav that round-trips
    /// into a `policy::db::Config`. This pins the template against ktav format
    /// drift (e.g. an inline `{ ... }` compound or a stray quote sneaking in)
    /// and against the ktav crate's own breaking changes across versions.
    #[test]
    fn default_config_ktav_parses() {
        let cfg: policy::db::Config = ktav::from_str(DEFAULT_CONFIG_KTAV)
            .expect("DEFAULT_CONFIG_KTAV must be valid ktav");
        // Sanity: the template ships at least the C:\Windows deny rule.
        assert!(
            cfg.rules.iter().any(|r| r.prefix.eq_ignore_ascii_case(r"c:\windows")),
            "default config should contain a C:\\Windows rule",
        );
        // Backslashes must be single (ktav has no escape) — a path with `\\`
        // would mean the template was written with JSON-style escaping.
        assert!(
            !cfg.rules.iter().any(|r| r.prefix.contains(r"\\")),
            "default config rule prefixes must use single backslashes",
        );
    }
}
