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
## (ktav 0.6.1 comments start with `##`; a single `#` is literal content.)
##
## Reads pass through to the real filesystem; writes are Copy-on-Write
## into <state_dir>/workdir/. Add `rules` entries to deny or mock paths.
##
## Network containment — OFF by default.
##
## Unset (the default) means the sandbox does not touch the network at all:
## no WFP filter is registered and the `connect` hook is not installed, so a
## sandboxed program's traffic is indistinguishable from running it directly.
## It already connects from its own process with its own image — nothing was
## ever proxied through winrsbox — and with no filters registered the sandbox
## leaves no trace in the system's network configuration either.
##
## The trade: a sandboxed process can reach anything you can, including
## RFC1918 hosts and SMB shares. Filesystem, registry, process and memory
## containment are unaffected. Set `guarded` to turn on the RFC1918 / private
## IPv6 / SMB egress filters and the per-connection netrule checks.
## `--block-localhost` and any configured `netrule` imply `guarded`, so those
## never sit inert.
## network: guarded

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

## rules: toolchain caches stay on the real disk (shared/persistent across
## runs). NOTE: %LOCALAPPDATA%\\Temp is deliberately NOT whitelisted here —
## it falls through to the defaults (read passthrough via the overlay merge,
## write cow). Whitelisting Temp as passthrough leaked scratch files to the
## real disk AND broke network installers that download to Temp then move
## into a CoW destination (cross-layer extract fails). Keeping Temp in the
## CoW layer makes download->extract->install a single-layer operation and
## restores the out-of-project isolation invariant.
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
    ## Deny writes to winrsbox's own installed artifacts (launcher exe/DLL in
    ## the package dir, the package dir itself, npm PATH shims) so a sandboxed
    ## process cannot overwrite the code the launcher is about to inject.
    ## Rule precedence is most-literal-chars wins, so these longer carve-outs
    ## override the broader npm passthrough above; reads stay passthrough.
    {
        prefix: C:\\Users\\**\\AppData\\Roaming\\npm\\node_modules\\winrsbox
        read: passthrough
        write: deny
    }
    {
        prefix: C:\\Users\\**\\AppData\\Roaming\\npm\\winrsbox*
        read: passthrough
        write: deny
    }
    {
        prefix: C:\\Users\\**\\.npm\\node_modules\\winrsbox
        read: passthrough
        write: deny
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

/// Whether hiding the console window is ours to do, given how many processes
/// are attached to it.
///
/// `GetConsoleProcessList` counts every process attached to this console.
/// Exactly one means the console was created for us — a shortcut, an Explorer
/// double-click, `start`, `CREATE_NEW_CONSOLE` — and hiding it hides only our
/// own window. Two or more means we inherited the console of whoever launched
/// us, and hiding it would make the OPERATOR'S terminal disappear.
///
/// That is not hypothetical: the launcher is a console-subsystem binary, so
/// `winrsbox cx` from a `cmd.exe` prompt shares that prompt's console and
/// `ShowWindow(SW_HIDE)` hid the user's own window. Under Windows Terminal it
/// happens to be harmless — `GetConsoleWindow` returns a hidden pseudo-console
/// placeholder owned by the PTY host — which is exactly why the bug could sit
/// unnoticed. Visibility is therefore NOT a usable discriminator; the process
/// count is.
///
/// Zero (or a failed call) means no console at all: nothing to hide.
fn hide_console_allowed(attached_process_count: u32) -> bool {
    attached_process_count == 1
}

/// Number of processes attached to this console, or 0 when there is none.
fn console_process_count() -> u32 {
    // SAFETY: the documented two-step — call with a small buffer to learn the
    //         required count. The return value is the count, not a status; a
    //         count larger than the buffer means "buffer too small", which is
    //         still the answer we want. No console → 0.
    unsafe {
        let mut buf = [0u32; 8];
        windows::Win32::System::Console::GetConsoleProcessList(&mut buf)
    }
}

/// Hide the console window unless `-d` is set — but only when the console is
/// ours alone. Called once at startup before any other output.
pub(crate) fn maybe_hide_console(debug: bool) {
    if debug {
        return;
    }
    if !hide_console_allowed(console_process_count()) {
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

/// Console control-event handler: swallow interactive interrupts so the
/// SANDBOXED process gets to decide what they mean.
///
/// The launcher shares its console with the target and neither asks for
/// `CREATE_NEW_PROCESS_GROUP`, so conhost delivers Ctrl+C and Ctrl+Break to
/// both. Without a handler the launcher took the default action and died —
/// and because the Job Object carries `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`,
/// its dying closed the job and the kernel killed the entire sandboxed tree.
/// For an interactive agent that is fatal: in `codex` and `claude` Ctrl+C
/// means "interrupt this turn", not "quit", so the first interrupt destroyed
/// the session.
///
/// Returning TRUE says "handled" and does nothing else. The target received
/// the same event directly from conhost and reacts however it likes; if it
/// chooses to exit, the normal wait path below observes that and propagates
/// its exit code verbatim. The launcher must never substitute its own.
///
/// Close/logoff/shutdown are NOT swallowed: the operator is ending the
/// session, the target gets the event too, and the system terminates us
/// after the handler returns (a few seconds at most). Returning FALSE there
/// lets the default teardown run, which closes the job and reaps the tree —
/// the correct outcome, and the one that must not be delayed.
unsafe extern "system" fn console_ctrl_handler(ctrl_type: u32) -> windows::core::BOOL {
    use windows::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
    if ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT {
        true.into()
    } else {
        false.into()
    }
}

/// Install [`console_ctrl_handler`]. Must run before the target is launched,
/// so no interrupt window exists where the old lethal default still applies.
/// Best-effort: with no console attached there is nothing to register and
/// nothing to protect against.
pub(crate) fn install_console_ctrl_handler() {
    // SAFETY: the handler is a plain `extern "system"` fn with no state; the
    //         documented registration call, `add = TRUE`.
    unsafe {
        let _ = windows::Win32::System::Console::SetConsoleCtrlHandler(
            Some(console_ctrl_handler),
            true,
        );
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

/// Default `PATHEXT` when the variable is absent from the environment, in
/// Windows' own order. Only the four forms `CreateProcessW` can actually
/// start are listed: `.COM`/`.EXE` are images, `.BAT`/`.CMD` are rewritten to
/// `%COMSPEC% /c` by kernel32 itself. The rest of Windows' stock list
/// (`.VBS`, `.JS`, `.WSF`, `.MSC`, …) is handled by ShellExecute's
/// association lookup, not by `CreateProcessW`, and running those through a
/// script host is not something the sandbox should do implicitly.
const LAUNCHABLE_EXTS: &[&str] = &[".COM", ".EXE", ".BAT", ".CMD"];

/// Resolve `arg0` to a full image path the way a shell would.
///
/// `CreateProcessW` performs its own search, but it only ever appends `.exe`
/// to an extensionless name — it does not expand `PATHEXT`. So `winrsbox cx`,
/// where `cx` is a `cx.bat` on `PATH`, failed with
/// `The system cannot find the file specified. (0x80070002)`.
///
/// The search itself is not reimplemented here: `SearchPathW` IS the
/// primitive `CreateProcessW` uses, with the same directory order (the
/// caller's image dir, the current directory, System32, System, Windows,
/// then `PATH`). The only thing added is the loop over `PATHEXT` entries,
/// which is precisely the step `CreateProcessW` omits and `cmd.exe` performs.
///
/// Resolving up front — always, not only as a fallback after a failed launch
/// — matters beyond `cx`. `target_args[0]` is consumed raw by
/// `trust::verify_signature`, `inject::pre_launch_scan`, the WFP
/// `app_id_from_path` and the root `ProcInfo` entry. With a bare name such as
/// `winrsbox node`, `app_id_from_path` cannot canonicalize it and
/// `wfp::add_filter` correctly refuses to install an unscoped filter — so the
/// RFC1918 egress block was silently never applied. One substitution fixes
/// all of them.
///
/// A name that already carries a launchable extension, or any path
/// containing a separator, is resolved in a single call with no extension
/// appended — mirroring `CreateProcessW`'s own rule. An extensionless name is
/// never resolved with `ext = NULL`: on this machine that would find the
/// extensionless `cx` shell script sitting next to `cx.bat`, which is not a
/// Windows executable at all.
pub(crate) fn resolve_target(arg0: &str) -> Result<String> {
    let has_launchable_ext = std::path::Path::new(arg0)
        .extension()
        .map(|e| {
            let dotted = format!(".{}", e.to_string_lossy());
            LAUNCHABLE_EXTS.iter().any(|x| x.eq_ignore_ascii_case(&dotted))
        })
        .unwrap_or(false);

    if has_launchable_ext {
        if let Some(found) = search_path(arg0, None) {
            return Ok(found);
        }
    } else {
        let pathext = std::env::var("PATHEXT").unwrap_or_default();
        let exts: Vec<String> = if pathext.trim().is_empty() {
            LAUNCHABLE_EXTS.iter().map(|s| s.to_string()).collect()
        } else {
            pathext
                .split(';')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        };
        for ext in &exts {
            if let Some(found) = search_path(arg0, Some(ext)) {
                return Ok(found);
            }
        }
    }

    // An explicit path that does not resolve is a different mistake from a
    // bare name that is not on PATH; say which one happened.
    let looks_like_path = arg0.contains('\\') || arg0.contains('/') || arg0.contains(':');
    if looks_like_path {
        anyhow::bail!("target '{arg0}' does not exist");
    }
    anyhow::bail!(
        "target '{arg0}' not found on PATH (searched PATHEXT: {})",
        std::env::var("PATHEXT").unwrap_or_else(|_| LAUNCHABLE_EXTS.join(";")),
    );
}

/// One `SearchPathW` probe. `ext` is appended only when the name has no
/// extension of its own (Windows' rule, enforced by the caller).
fn search_path(name: &str, ext: Option<&str>) -> Option<String> {
    use windows::Win32::Storage::FileSystem::SearchPathW;

    let name_w: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let ext_w: Option<Vec<u16>> = ext.map(|e| e.encode_utf16().chain(Some(0)).collect());

    // Query the required length first, then fill: a path may exceed MAX_PATH.
    // SAFETY: both strings are NUL-terminated UTF-16; a zero-length buffer
    //         with a null pointer is the documented "how much do I need" form.
    let needed = unsafe {
        SearchPathW(
            PCWSTR::null(),
            PCWSTR(name_w.as_ptr()),
            ext_w.as_ref().map(|e| PCWSTR(e.as_ptr())).unwrap_or(PCWSTR::null()),
            None,
            None,
        )
    };
    if needed == 0 {
        return None;
    }
    let mut buf = vec![0u16; needed as usize + 1];
    // SAFETY: buf is `needed + 1` UTF-16 units, at least what the call above
    //         asked for; the same NUL-terminated inputs are reused.
    let written = unsafe {
        SearchPathW(
            PCWSTR::null(),
            PCWSTR(name_w.as_ptr()),
            ext_w.as_ref().map(|e| PCWSTR(e.as_ptr())).unwrap_or(PCWSTR::null()),
            Some(&mut buf),
            None,
        )
    };
    if written == 0 || written as usize > buf.len() {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..written as usize]))
}

/// Build a Windows command line string from an argument list.
/// Follows Microsoft CommandLineToArgvW escaping rules.
/// Iterates chars, not bytes: the result is encoded to UTF-16 for
/// CreateProcessW, so non-ASCII arguments must survive untouched.
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
        let chars: Vec<char> = a.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let ch = chars[i];
            if ch == '\\' {
                let start = i;
                while i < chars.len() && chars[i] == '\\' { i += 1; }
                let n = i - start;
                if i == chars.len() {
                    // Trailing backslashes → double them before closing quote
                    for _ in 0..n * 2 { out.push('\\'); }
                } else if chars[i] == '"' {
                    // Backslashes before quote → double them + escape the quote
                    for _ in 0..n * 2 { out.push('\\'); }
                    out.push('\\');
                    out.push('"');
                    i += 1;
                } else {
                    // Backslashes not before quote → emit literally
                    for _ in 0..n { out.push('\\'); }
                }
            } else if ch == '"' {
                out.push('\\');
                out.push('"');
                i += 1;
            } else {
                out.push(ch);
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
    let dll = dll.to_string_lossy().into_owned();
    // Defense-in-depth before injection: refuse self-installs inside the
    // guest's project tree (no policy rule can protect them there), then
    // verify the staged exe/DLL digests against the installer's integrity
    // manifest so a trojanized artifact becomes a loud refusal instead of a
    // silent injection of attacker-controlled code.
    verify_not_inside_guest_project_node_modules(&dll)?;
    verify_staged_artifacts(&dll)?;
    Ok(dll)
}

/// SHA-256 of a file via CNG's one-shot `BCryptHash` (no streaming state to
/// manage). Used by the staged-artifact integrity check below.
fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    use windows::Win32::Security::Cryptography::{
        BCryptCloseAlgorithmProvider, BCryptHash, BCryptOpenAlgorithmProvider,
        BCRYPT_ALG_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_SHA256_ALGORITHM,
    };

    let mut alg = BCRYPT_ALG_HANDLE::default();
    // SAFETY: alg is a valid out handle pointer; BCRYPT_SHA256_ALGORITHM is a
    //         static null-terminated wide string; no implementation pin needed.
    let status = unsafe {
        BCryptOpenAlgorithmProvider(
            &mut alg,
            BCRYPT_SHA256_ALGORITHM,
            PCWSTR::null(),
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        )
    };
    if status.0 < 0 {
        anyhow::bail!("BCryptOpenAlgorithmProvider failed: 0x{:08X}", status.0);
    }
    let data = std::fs::read(path)
        .with_context(|| format!("read {} for hashing", path.display()))?;
    let mut out = [0u8; 32];
    // SAFETY: alg was opened above; out is a valid 32-byte buffer (the
    //         SHA-256 digest size).
    let status = unsafe { BCryptHash(alg, None, &data, &mut out) };
    // SAFETY: alg was opened above and is not used after this point.
    unsafe { let _ = BCryptCloseAlgorithmProvider(alg, 0); }
    if status.0 < 0 {
        anyhow::bail!("BCryptHash failed: 0x{:08X}", status.0);
    }
    Ok(out)
}

/// Lowercase-hex encoding of a 32-byte digest (the manifest's format).
fn digest_to_hex(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Verify the launcher exe and the hook.dll it is about to inject still match
/// the digests recorded in `integrity.json` next to the exe (written by the
/// npm installer at deploy time). A MISSING manifest is fine — that is an
/// unmanaged deployment (e.g. a dev `cargo build`) with nothing to verify.
/// A present-but-mismatched manifest fails closed: a silently swapped
/// exe/DLL turns into a loud refusal instead of an injection of
/// attacker-controlled code.
fn verify_staged_artifacts_in(exe_path: &Path, dll_path: &Path) -> Result<()> {
    let manifest_path = exe_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("integrity.json");
    if !manifest_path.exists() {
        return Ok(());
    }
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("read integrity manifest {}", manifest_path.display()))?,
    )
    .with_context(|| format!("parse integrity manifest {}", manifest_path.display()))?;

    anyhow::ensure!(
        manifest.get("algorithm").and_then(|v| v.as_str()) == Some("sha256"),
        "integrity manifest {} must declare algorithm == \"sha256\"",
        manifest_path.display()
    );
    let files = manifest
        .get("files")
        .and_then(|v| v.as_object())
        .with_context(|| format!("integrity manifest {} has no `files` object", manifest_path.display()))?;
    let expected = |name: &str| -> Result<String> {
        let v = files
            .get(name)
            .and_then(|v| v.as_str())
            .with_context(|| format!("integrity manifest files[\"{name}\"] missing or not a string"))?;
        // Fail closed on anything that is not a 64-char lowercase-hex digest —
        // a manifest we cannot strictly parse is a manifest we cannot trust.
        anyhow::ensure!(
            v.len() == 64 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "integrity manifest files[\"{name}\"] is not a 64-char lowercase-hex SHA-256 digest"
        );
        Ok(v.to_ascii_lowercase())
    };
    let want_exe = expected("winrsbox.exe")?;
    let want_dll = expected("hook.dll")?;

    let actual_exe = digest_to_hex(&sha256_file(exe_path)?);
    anyhow::ensure!(
        actual_exe == want_exe,
        "integrity check FAILED for {}: expected sha256 {}…, actual {}… — \
         the launcher binary was modified after install; refusing to run",
        exe_path.display(),
        &want_exe[..16],
        &actual_exe[..16]
    );
    let actual_dll = digest_to_hex(&sha256_file(dll_path)?);
    anyhow::ensure!(
        actual_dll == want_dll,
        "integrity check FAILED for {}: expected sha256 {}…, actual {}… — \
         hook.dll was modified after install; refusing to inject it",
        dll_path.display(),
        &want_dll[..16],
        &actual_dll[..16]
    );
    Ok(())
}

/// `verify_staged_artifacts_in` bound to the real launcher exe.
fn verify_staged_artifacts(dll_path: &str) -> Result<()> {
    let exe = std::env::current_exe()?;
    verify_staged_artifacts_in(&exe, Path::new(dll_path))
}

/// Refuse to run when the launcher itself is installed inside the sandboxed
/// project's `node_modules`. There the project_root passthrough short-circuits
/// every policy rule (policy/src/decide.rs compute()), so a guest could
/// trojanize winrsbox.exe/hook.dll for the NEXT run — no deny rule can fix
/// that. The only remedy is refusing to launch from such a location.
fn verify_not_inside_guest_project_node_modules(dll_path: &str) -> Result<()> {
    // Canonical form for comparison: backslash separators, lowercased,
    // `\\?\` device prefix stripped (current_exe can return it).
    let normalize = |p: &Path| -> String {
        let s = p.to_string_lossy().replace('/', "\\").to_ascii_lowercase();
        s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
    };
    let exe = std::env::current_exe()?;
    let exe_dir = match exe.parent() {
        Some(d) => normalize(d),
        // No parent dir → cannot be inside anything.
        None => return Ok(()),
    };
    let nm_root = normalize(&std::env::current_dir()?.join("node_modules"));
    // Containment mirrors policy/src/decide.rs path_contained_in: prefix
    // match + separator boundary, so `...\node_modules` does not match a
    // sibling like `...\node_modules_bak`.
    let contained = exe_dir.starts_with(&nm_root)
        && (exe_dir.len() == nm_root.len()
            || exe_dir.as_bytes().get(nm_root.len()) == Some(&b'\\'));
    anyhow::ensure!(
        !contained,
        "refusing to launch: the winrsbox install itself ({}, containing {}) sits inside \
         the sandboxed project's node_modules, where the guest's project_root passthrough \
         makes every policy rule moot — a sandboxed process could trojanize winrsbox.exe \
         for the next run. Run the sandbox from a different directory or install winrsbox \
         globally.",
        exe_dir,
        dll_path
    );
    Ok(())
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

    // ── Finding-1 regression: guest must not overwrite the sandbox's own
    //    hook.dll / launcher artifacts ──────────────────────────────────────

    /// The npm global install drops the launcher + hook.dll into
    /// `%APPDATA%\\Roaming\\npm\\node_modules\\winrsbox\\native\\`, and the
    /// default template passes that whole tree through (writable). Without
    /// the deny carve-outs a sandboxed process can overwrite hook.dll on the
    /// real disk — the next launch would inject attacker-controlled code
    /// OUTSIDE the sandbox. This test loads DEFAULT_CONFIG_KTAV into a real
    /// Policy and pins the deny/passthrough boundary.
    #[test]
    fn install_dir_write_denied_despite_npm_passthrough() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = policy::Policy::open_or_create(
            &db_path,
            sandbox,
            mock_dirs,
            project,
        ).unwrap();

        let cfg_path = dir.path().join("cfg.ktav");
        std::fs::write(&cfg_path, DEFAULT_CONFIG_KTAV).unwrap();
        p.load_config(&cfg_path).unwrap();

        // The injection target itself: guest writes must be denied...
        let d = p.decide(r"c:\users\bob\appdata\roaming\npm\node_modules\winrsbox\native\hook.dll", true);
        assert_eq!(d.mode, policy::Mode::Deny, "guest write to hook.dll must be denied");
        // ...while reads stay passthrough (the sandbox still runs its own code).
        let d = p.decide(r"c:\users\bob\appdata\roaming\npm\node_modules\winrsbox\native\hook.dll", false);
        assert_eq!(d.mode, policy::Mode::Passthrough, "reads of hook.dll must stay passthrough");

        // The carve-out covers the whole package dir, not just native/.
        let d = p.decide(r"c:\users\bob\appdata\roaming\npm\node_modules\winrsbox\scripts\winrsbox-cli.js", true);
        assert_eq!(d.mode, policy::Mode::Deny, "guest write to the package dir must be denied");

        // PATH shims next to the package dir (npm also drops winrsbox.cmd there).
        let d = p.decide(r"c:\users\bob\appdata\roaming\npm\winrsbox.cmd", true);
        assert_eq!(d.mode, policy::Mode::Deny, "guest write to the PATH shim must be denied");

        // The carve-out is narrow: the rest of the npm tree stays writable.
        let d = p.decide(r"c:\users\bob\appdata\roaming\npm\docs\readme.md", true);
        assert_eq!(d.mode, policy::Mode::Passthrough, "unrelated npm paths must stay passthrough");

        // Prefix-variant install location (%USERPROFILE%\\.npm).
        let d = p.decide(r"c:\users\bob\.npm\node_modules\winrsbox\package.json", true);
        assert_eq!(d.mode, policy::Mode::Deny, "guest write under .npm install must be denied");

        // Toolchain prefixes stay writable by design (documented choice).
        let d = p.decide(r"c:\users\bob\.cargo\bin\cargo.exe", true);
        assert_eq!(d.mode, policy::Mode::Passthrough, ".cargo passthrough is deliberate");
    }

    // ── Change-2 integrity self-verification ─────────────────────────────────

    /// Write an integrity.json manifest next to the staged exe, using EXACTLY
    /// the shape the npm installer emits.
    fn write_integrity_manifest(dir: &Path, exe_digest: &str, dll_digest: &str) {
        let manifest = serde_json::json!({
            "version": "0.1.0",
            "algorithm": "sha256",
            "files": {
                "winrsbox.exe": exe_digest,
                "hook.dll": dll_digest,
            }
        });
        std::fs::write(
            dir.join("integrity.json"),
            serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn integrity_manifest_accepts_untampered_staged_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("winrsbox.exe");
        let dll = dir.path().join("hook.dll");
        std::fs::write(&exe, b"fake-exe-bytes").unwrap();
        std::fs::write(&dll, b"fake-dll-bytes").unwrap();

        // The oracle here is the hash function vs the comparison logic (tests
        // 3/4 below are the negative controls), so computing the digests with
        // the same sha256_file helper is fine.
        let exe_digest = digest_to_hex(&sha256_file(&exe).unwrap());
        let dll_digest = digest_to_hex(&sha256_file(&dll).unwrap());
        write_integrity_manifest(dir.path(), &exe_digest, &dll_digest);

        verify_staged_artifacts_in(&exe, &dll).unwrap();
    }

    #[test]
    fn integrity_manifest_rejects_tampered_dll() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("winrsbox.exe");
        let dll = dir.path().join("hook.dll");
        std::fs::write(&exe, b"fake-exe-bytes").unwrap();
        std::fs::write(&dll, b"fake-dll-bytes").unwrap();
        let exe_digest = digest_to_hex(&sha256_file(&exe).unwrap());
        let dll_digest = digest_to_hex(&sha256_file(&dll).unwrap());
        write_integrity_manifest(dir.path(), &exe_digest, &dll_digest);

        // Flip the dll contents AFTER the manifest was written → must refuse.
        std::fs::write(&dll, b"fake-dll-bytes-TAMPERED").unwrap();
        assert!(
            verify_staged_artifacts_in(&exe, &dll).is_err(),
            "a tampered hook.dll must fail the integrity check"
        );
    }

    #[test]
    fn integrity_manifest_rejects_tampered_exe() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("winrsbox.exe");
        let dll = dir.path().join("hook.dll");
        std::fs::write(&exe, b"fake-exe-bytes").unwrap();
        std::fs::write(&dll, b"fake-dll-bytes").unwrap();
        let exe_digest = digest_to_hex(&sha256_file(&exe).unwrap());
        let dll_digest = digest_to_hex(&sha256_file(&dll).unwrap());
        write_integrity_manifest(dir.path(), &exe_digest, &dll_digest);

        std::fs::write(&exe, b"fake-exe-bytes-TAMPERED").unwrap();
        assert!(
            verify_staged_artifacts_in(&exe, &dll).is_err(),
            "a tampered winrsbox.exe must fail the integrity check"
        );
    }

    #[test]
    fn integrity_manifest_missing_manifest_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("winrsbox.exe");
        let dll = dir.path().join("hook.dll");
        std::fs::write(&exe, b"fake-exe-bytes").unwrap();
        std::fs::write(&dll, b"fake-dll-bytes").unwrap();
        // No integrity.json → unmanaged deployment, verification is a no-op.
        assert!(!dir.path().join("integrity.json").exists());
        verify_staged_artifacts_in(&exe, &dll).unwrap();
    }

    #[test]
    fn integrity_manifest_malformed_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("winrsbox.exe");
        let dll = dir.path().join("hook.dll");
        std::fs::write(&exe, b"fake-exe-bytes").unwrap();
        std::fs::write(&dll, b"fake-dll-bytes").unwrap();
        // Malformed manifest (no `files`, no `algorithm`) → fail closed.
        std::fs::write(dir.path().join("integrity.json"), "{}").unwrap();
        assert!(
            verify_staged_artifacts_in(&exe, &dll).is_err(),
            "a malformed integrity manifest must fail closed"
        );
    }

    // --- build_cmdline: Windows command lines are UTF-16 ---

    /// Non-ASCII arguments must survive build_cmdline intact. The pre-fix
    /// writer iterated as_bytes() and pushed each byte as a char (Latin-1),
    /// so any argument that needed quoting (contains a space) and carried
    /// non-ASCII was corrupted on its way to CreateProcessW. Regression:
    /// path with spaces + Cyrillic + CJK.
    #[test]
    fn build_cmdline_preserves_non_ascii_args() {
        let arg = "D:\\проект новый\\отчёт финал.txt".to_string();
        let cmdline = build_cmdline(&[arg.clone()]);
        // Contains a space -> must be quoted...
        assert!(
            cmdline.starts_with("\"") && cmdline.ends_with("\""),
            "arg must be quoted: {cmdline}"
        );
        // ...and the quoted content must be the original, char for char.
        assert_eq!(
            &cmdline[1..cmdline.len() - 1],
            arg,
            "non-ASCII arg must survive intact"
        );

        // Multibyte chars adjacent to a backslash run (trailing-backslash case).
        let arg2 = "D:\\目录 目录\\bin\\".to_string();
        let cmdline2 = build_cmdline(&[arg2.clone()]);
        assert_eq!(
            &cmdline2[1..cmdline2.len() - 1],
            "D:\\目录 目录\\bin\\\\",
            "trailing backslash doubled, non-ASCII chars intact"
        );
    }

    /// ASCII CommandLineToArgvW escaping must be unchanged by the UTF-8 fix.
    #[test]
    fn build_cmdline_ascii_escaping_unchanged() {
        assert_eq!(build_cmdline(&[String::new()]), "\"\"");
        assert_eq!(build_cmdline(&["plain".to_string()]), "plain");
        assert_eq!(
            build_cmdline(&["a b\\".to_string()]),
            "\"a b\\\\\"",
            "trailing ASCII backslash must still be doubled"
        );
        assert_eq!(
            build_cmdline(&["say \"hi\"\\".to_string()]),
            "\"say \\\"hi\\\"\\\\\"",
            "embedded quotes + trailing backslash escaping unchanged"
        );
    }

    // --- console ownership ---

    /// Hiding the console is only ours to do when nothing else is attached.
    /// The launcher is a console-subsystem binary, so started from a `cmd.exe`
    /// prompt it shares that prompt's console — and the old unconditional
    /// `ShowWindow(SW_HIDE)` hid the OPERATOR'S window.
    #[test]
    fn console_is_hidden_only_when_we_are_the_sole_attached_process() {
        // Launched from a shell: the shell plus us. Never hide.
        assert!(!hide_console_allowed(2), "inherited console must not be hidden");
        // Deeper chains (shell -> wrapper -> launcher) are inherited too.
        assert!(!hide_console_allowed(3));
        assert!(!hide_console_allowed(17));
        // Our own console (Explorer / shortcut / CREATE_NEW_CONSOLE): hide it.
        assert!(hide_console_allowed(1));
        // No console at all — GetConsoleProcessList yields 0; nothing to hide.
        assert!(!hide_console_allowed(0));
    }

    /// Ctrl+C and Ctrl+Break are swallowed so the sandboxed program decides
    /// what they mean; the launcher staying alive is what keeps the Job
    /// Object — and therefore the whole process tree — from being torn down.
    /// Close/logoff/shutdown are NOT swallowed: the operator is ending the
    /// session and the default teardown must run.
    #[test]
    fn ctrl_handler_swallows_interrupts_but_not_session_end() {
        use windows::Win32::System::Console::{
            CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT, CTRL_LOGOFF_EVENT,
            CTRL_SHUTDOWN_EVENT,
        };
        // SAFETY: the handler is a pure function of its argument — no state,
        //         no pointers, safe to call directly.
        let handled = |e: u32| unsafe { console_ctrl_handler(e).as_bool() };
        assert!(handled(CTRL_C_EVENT), "Ctrl+C must not kill the launcher");
        assert!(handled(CTRL_BREAK_EVENT), "Ctrl+Break must not kill the launcher");
        assert!(!handled(CTRL_CLOSE_EVENT), "console close must tear the session down");
        assert!(!handled(CTRL_LOGOFF_EVENT));
        assert!(!handled(CTRL_SHUTDOWN_EVENT));
    }

    // --- resolve_target: PATHEXT expansion CreateProcessW does not do ---

    /// `PATH`/`PATHEXT` are process-wide, so these tests must not overlap —
    /// with each other or with anything else reading them. Poison-tolerant:
    /// a panic in one test must not cascade into "all the rest failed too".
    fn path_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The original report: `winrsbox cx` died with
    /// `CreateProcessW failed: The system cannot find the file specified.
    /// (0x80070002)` because `CreateProcessW` appends only `.exe` to a bare
    /// name. A `.bat` on PATH must resolve to its full path; kernel32 then
    /// rewrites it to `%COMSPEC% /c` on its own.
    #[test]
    fn resolve_target_expands_pathext_for_a_bare_batch_name() {
        let _lock = path_env_lock();
        let dir = std::env::temp_dir().join("winrsbox-resolve-bat");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bat = dir.join("wrs_probe_shim.bat");
        std::fs::write(&bat, "@echo off\r\n").unwrap();

        let saved_path = std::env::var("PATH").unwrap_or_default();
        let saved_ext = std::env::var("PATHEXT").ok();
        std::env::set_var("PATH", format!("{};{saved_path}", dir.display()));
        std::env::set_var("PATHEXT", ".COM;.EXE;.BAT;.CMD");

        let resolved = resolve_target("wrs_probe_shim");

        std::env::set_var("PATH", &saved_path);
        match saved_ext {
            Some(v) => std::env::set_var("PATHEXT", v),
            None => std::env::remove_var("PATHEXT"),
        }
        let _ = std::fs::remove_dir_all(&dir);

        let resolved = resolved.expect("bare .bat name must resolve via PATHEXT");
        assert!(
            resolved.to_ascii_lowercase().ends_with("wrs_probe_shim.bat"),
            "expected the .bat, got {resolved}",
        );
        assert!(
            std::path::Path::new(&resolved).is_absolute(),
            "resolution must yield a full path (WFP app_id / pre-scan need it), got {resolved}",
        );
    }

    /// A bare `.exe` name must resolve to a full path too. This is the case
    /// that silently cost containment: `wfp::app_id_from_path` cannot
    /// canonicalize a bare name, so `add_filter` refused to install the
    /// RFC1918 egress filters and `winrsbox node` simply ran without them.
    #[test]
    fn resolve_target_yields_full_path_for_a_bare_exe_name() {
        let _lock = path_env_lock();
        let resolved = resolve_target("cmd").expect("cmd must resolve — it is in System32");
        let lower = resolved.to_ascii_lowercase();
        assert!(lower.ends_with("cmd.exe"), "expected cmd.exe, got {resolved}");
        assert!(std::path::Path::new(&resolved).is_absolute());
        assert!(
            std::fs::canonicalize(&resolved).is_ok(),
            "the resolved path must canonicalize — that is exactly what app_id_from_path does",
        );
    }

    /// A name that already carries a launchable extension resolves without
    /// another extension being appended (CreateProcessW's own rule).
    #[test]
    fn resolve_target_keeps_an_explicit_extension() {
        let _lock = path_env_lock();
        let resolved = resolve_target("cmd.exe").expect("cmd.exe must resolve");
        let lower = resolved.to_ascii_lowercase();
        assert!(lower.ends_with("cmd.exe"), "got {resolved}");
        assert!(!lower.ends_with("cmd.exe.exe"), "extension must not be appended twice");
    }

    /// An absolute path is returned as itself, not re-searched on PATH.
    #[test]
    fn resolve_target_accepts_an_absolute_path() {
        let _lock = path_env_lock();
        let dir = std::env::temp_dir().join("winrsbox-resolve-abs");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bat = dir.join("wrs_probe_abs.cmd");
        std::fs::write(&bat, "@echo off\r\n").unwrap();

        let resolved = resolve_target(bat.to_str().unwrap());
        let _ = std::fs::remove_dir_all(&dir);

        let resolved = resolved.expect("an existing absolute path must resolve");
        assert!(resolved.to_ascii_lowercase().ends_with("wrs_probe_abs.cmd"));
    }

    /// Failure must name the target and say where it was looked for, instead
    /// of surfacing the raw `0x80070002` from deep inside CreateProcessW.
    #[test]
    fn resolve_target_reports_a_missing_target_usefully() {
        let _lock = path_env_lock();
        let err = resolve_target("winrsbox-no-such-command-xyzzy")
            .expect_err("a nonexistent bare name must not resolve")
            .to_string();
        assert!(err.contains("winrsbox-no-such-command-xyzzy"), "err: {err}");
        assert!(err.contains("PATH"), "err must say where it searched: {err}");

        let err = resolve_target(r"C:\winrsbox\no\such\path\nope.exe")
            .expect_err("a nonexistent explicit path must not resolve")
            .to_string();
        assert!(err.contains("does not exist"), "err: {err}");
    }
}
