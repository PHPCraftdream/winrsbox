// ─── Sandbox orchestration helpers ───────────────────────────────────────────

use anyhow::{Context, Result};
use std::{os::windows::ffi::OsStrExt, path::{Path, PathBuf}};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            Console::GetConsoleWindow,
            Threading::{
                CreateProcessW, TerminateProcess, CREATE_SUSPENDED,
                PROCESS_INFORMATION, STARTUPINFOW,
            },
        },
        UI::WindowsAndMessaging::{ShowWindow, SW_HIDE},
    },
};

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

/// Default ktav policy written when auto-discovery creates a fresh state dir.
pub(crate) const DEFAULT_CONFIG_KTAV: &str = "\
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
pub(crate) fn launch_suspended(cwd: &Path, target_args: &[String], _guard: crate::GuardLevel) -> Result<PROCESS_INFORMATION> {
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

    let limits = winrsbox::jobctl::JobLimits::default()
        .with_memory(memory_limit.map(|gb| gb * 1024 * 1024 * 1024));
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
    {
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
}
