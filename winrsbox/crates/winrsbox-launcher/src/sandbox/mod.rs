// ─── Sandbox orchestration helpers ───────────────────────────────────────────

use anyhow::{Context, Result};
use std::{
    os::windows::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, DuplicateHandle, HANDLE, DUPLICATE_SAME_ACCESS},
        System::{
            Console::GetConsoleWindow,
            Threading::{
                CreateProcessAsUserW, DeleteProcThreadAttributeList, GetCurrentProcess,
                InitializeProcThreadAttributeList, TerminateProcess,
                UpdateProcThreadAttribute, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
                EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, PROCESS_INFORMATION,
                STARTUPINFOEXW, STARTUPINFOW,
            },
        },
        UI::WindowsAndMessaging::{ShowWindow, SW_HIDE},
    },
};

use winrsbox::contain::guest::{self as guest_token, GuestToken};
use winrsbox::contain::mitigations::{self, v1 as miti_v1};

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
/// Only the two root init-event handles are inherited by the child.
/// Applies create-time kernel mitigations via PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY.
/// The runtime-only `BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` flag is dropped here
/// (hook.dll is unsigned — kernel would reject its load if the bit were set at
/// create time). That flag is re-applied AFTER hook.dll loads, from inside
/// hook::apply_mitigations via SetProcessMitigationPolicy. All other v1/v2 bits
/// only take effect at process create, so they MUST be passed via this path.
fn verify_inherited_event_handles(
    child_process: HANDLE,
    expected: [HANDLE; 2],
) -> Result<()> {
    for (name, source_handle) in ["init", "degraded"].into_iter().zip(expected) {
        let mut duplicate = HANDLE::default();
        // SAFETY: child_process is the live suspended child returned by
        // CreateProcessAsUserW; DuplicateHandle reads its handle table and
        // duplicates the entry into this process for verification.
        unsafe {
            DuplicateHandle(
                child_process,
                source_handle,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
        }
        .with_context(|| format!("root child is missing inherited {name} event handle"))?;
        // SAFETY: duplicate was returned by DuplicateHandle above and is owned here.
        unsafe { CloseHandle(duplicate) }.context("CloseHandle(inherited event probe) failed")?;
    }
    Ok(())
}

/// Launch `target_args[0]` suspended under `cwd` and pass only the root init
/// event handles alongside any create-time mitigation attributes.
pub(crate) fn launch_suspended(
    cwd: &Path,
    target_args: &[String],
    guard: crate::GuardLevel,
    inherited_event_handles: [HANDLE; 2],
) -> Result<PROCESS_INFORMATION> {
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

    // ─── R04-1c: derive the guest's privilege-reduced token ────────────────
    //
    // Root guest only (see this function's doc comment) — children spawned
    // BY the guest go through winrsbox-hook's NtCreateUserProcess hook,
    // which inherits its caller's (already-restricted) token via normal
    // Windows process-creation semantics and needs no separate handling.
    //
    // Fail closed: any error here aborts the launch. There is no fallback to
    // CreateProcessW / an unrestricted token — per the task's explicit
    // instruction, ambiguity about a Win32 error path must never silently
    // preserve the old unrestricted-token behavior.
    let own_token = launch_prep::open_own_token_for_restriction()
        .context("failed to open launcher's own primary token for guest-token derivation")?;
    // Capture the source token's admin signal BEFORE the token is derived —
    // point 6 needs this same value again after launch, to know which shape
    // (admin-restricted vs. near-no-op) the child's real token must match.
    let admin_state_result = guest_token::administrators_state(own_token);
    let build_result = guest_token::build_guest_token(own_token);
    // SAFETY: own_token was opened by us above via OpenProcessToken;
    // administrators_state/build_guest_token only borrow the handle, never
    // close it — we own its lifetime and close it here regardless of outcome.
    unsafe { CloseHandle(own_token).ok() };
    let source_admin_enabled = admin_state_result
        .context("failed to inspect launcher token's Administrators state")?
        .0;
    let guest: GuestToken = build_result.context(
        "failed to build restricted guest token (R04-1c) — aborting launch, \
         not falling back to an unrestricted token",
    )?;

    // ─── R04-1c: explicit environment block for CreateProcessAsUserW ───────
    //
    // CreateProcessAsUserW's documented lpEnvironment=NULL behavior is NOT
    // "inherit the caller's environment" the way CreateProcessW's is — MSDN
    // documents NULL there as "the new process uses an environment created
    // from the profile of the user specified by hToken", a PROFILE-derived
    // block. The launcher sets process-specific environment (e.g.
    // FS_SANDBOX_SECTION in main.rs, read by hook.dll via inheritance)
    // shortly before this call; a profile-derived block would silently drop
    // it. So this always passes an EXPLICIT block copied from this process's
    // actual current environment (correct for the guest too, since source
    // and derived token share the same TokenUser) together with
    // CREATE_UNICODE_ENVIRONMENT.
    let env_block = launch_prep::copy_caller_environment_block()
        .context("failed to capture launcher environment block for guest process")?;

    let mut pi = PROCESS_INFORMATION::default();

    // ─── Build the attribute list for exact handle inheritance ─────────────
    // Only the two root handshake events cross into the less-trusted guest.
    // The handle-list attribute prevents unrelated inheritable launcher
    // handles from leaking into it.
    let attribute_count = if has_mitigations { 2 } else { 1 };
    let mut attr_list_size: usize = 0;
    // SAFETY: passing None is the documented size-query call.
    let _ = unsafe {
        InitializeProcThreadAttributeList(None, attribute_count, None, &mut attr_list_size)
    };
    anyhow::ensure!(attr_list_size > 0, "InitializeProcThreadAttributeList returned size=0");
    let mut attr_buf = vec![0u8; attr_list_size];
    let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut _);
    // SAFETY: attr_buf is sized to the queried length and remains alive through
    // DeleteProcThreadAttributeList below.
    unsafe {
        InitializeProcThreadAttributeList(
            Some(attr_list),
            attribute_count,
            None,
            &mut attr_list_size,
        )
    }
    .context("InitializeProcThreadAttributeList failed")?;

    // SAFETY: inherited_event_handles is a live array of the only inheritable
    // handles intended for the root child; the OS reads it during process creation.
    let handle_list_result = unsafe {
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            Some(inherited_event_handles.as_ptr() as *const std::ffi::c_void),
            std::mem::size_of_val(&inherited_event_handles),
            None,
            None,
        )
    };
    if let Err(error) = handle_list_result {
        // SAFETY: attr_list was successfully initialized above.
        unsafe { DeleteProcThreadAttributeList(attr_list) };
        return Err(anyhow::Error::from(error))
            .context("UpdateProcThreadAttribute(HANDLE_LIST) failed");
    }

    if has_mitigations {
        // SAFETY: bytes lives through CreateProcessAsUserW and attribute-list
        // deletion; the API consumes this fixed mitigation bitmask.
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
        if let Err(error) = update_result {
            // SAFETY: attr_list was successfully initialized above.
            unsafe { DeleteProcThreadAttributeList(attr_list) };
            return Err(anyhow::Error::from(error))
                .context("UpdateProcThreadAttribute(MITIGATION_POLICY) failed");
        }
    }
    let creation_flags =
        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT;

    // STARTUPINFOEXW is repr(C) with STARTUPINFOW as the first field, so
    // CreateProcessW (which expects *const STARTUPINFOW) can read the W part
    // from a pointer to the EXW; `cb` must equal sizeof(STARTUPINFOEXW) so
    // the kernel knows to read lpAttributeList for the exact inherited handles.
    let si_ex = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
            ..Default::default()
        },
        lpAttributeList: attr_list,
    };
    // *const STARTUPINFOW — same address regardless of has_mitigations: the
    // STARTUPINFOW header sits at offset 0 of STARTUPINFOEXW (repr(C)).
    let si_ptr: *const STARTUPINFOW = &si_ex.StartupInfo;

    // SAFETY: cmdline_wide and cwd_wide are valid null-terminated UTF-16 strings.
    //         attr_list (if used) is initialized and was populated above.
    //         si_ex stays alive for the duration of this call. env_block is
    //         alive on this stack frame past this call. guest.handle() is a
    //         valid derived token handle owned by `guest`, alive past this
    //         call (GuestToken is not dropped until this function returns).
    let create_result = unsafe {
        CreateProcessAsUserW(
            Some(guest.handle()),
            PCWSTR::null(),
            Some(windows::core::PWSTR(cmdline_wide.as_mut_ptr())),
            None, None, true,
            creation_flags,
            Some(env_block.as_ptr() as *const std::ffi::c_void),
            PCWSTR(cwd_wide.as_ptr()),
            si_ptr,
            &mut pi,
        )
    };

    // Free the attribute list — kernel has copied what it needs from it by
    // the time CreateProcessAsUserW returns (success OR failure). Per MSDN,
    // DeleteProcThreadAttributeList does NOT free the buffer pointers we
    // attached (bytes); we manage their lifetime ourselves via Rust's stack.
    // SAFETY: attr_list was initialized above and is deleted exactly once.
    unsafe { DeleteProcThreadAttributeList(attr_list); }
    // Touch si_ex AFTER CreateProcessAsUserW to ensure the compiler doesn't
    // move the drop earlier. (Defensive — repr(C) on-stack lifetime already
    // covers the syscall, but the read is free and documents intent.)
    let _ = si_ex.StartupInfo.cb;
    // Touch attr_buf/env_block to assert both stayed alive past the syscall.
    let _ = attr_buf.len();
    let _ = inherited_event_handles.len();
    let _ = env_block.len();

    // Fail closed: any CreateProcessAsUserW error (including the documented
    // risk of ERROR_PRIVILEGE_NOT_HELD when SeIncreaseQuotaPrivilege is not
    // held by the launcher) aborts the launch here. No retry with a
    // different token or API — the guest token (and the process it would
    // have been used to create) is simply never used.
    create_result.context(
        "CreateProcessAsUserW failed — if this is ERROR_PRIVILEGE_NOT_HELD, the launcher \
         process does not hold a privilege CreateProcessAsUserW needs (commonly \
         SeIncreaseQuotaPrivilege) to create a process under the derived, privilege-reduced \
         guest token; aborting launch rather than falling back to CreateProcessW/an \
         unrestricted token",
    )?;

    if let Err(error) = verify_inherited_event_handles(pi.hProcess, inherited_event_handles) {
        // SAFETY: the process and thread handles are valid; the child is still
        // suspended, so no guest code has run and termination is safe.
        unsafe {
            TerminateProcess(pi.hProcess, STATUS_DLL_INIT_FAILED).ok();
            CloseHandle(pi.hThread).ok();
            CloseHandle(pi.hProcess).ok();
        }
        return Err(error).context("root child did not inherit its init event handles");
    }

    // ─── R04-1c point 6: verify the REAL child token, not the request ──────
    //
    // Don't trust that CreateProcessAsUserW did what was asked — open the
    // actual suspended child's primary token and check its shape matches
    // what build_guest_token derived. Any mismatch (or any error reading the
    // child's token) terminates the still-suspended child (no guest code has
    // run yet — TerminateProcess is safe) and aborts; the child is never
    // resumed with an unverified token.
    if let Err(e) = launch_prep::verify_child_token(pi.hProcess, source_admin_enabled) {
        // SAFETY: pi.hProcess/pi.hThread are valid handles from the
        // CreateProcessAsUserW that just succeeded above; the process is
        // still CREATE_SUSPENDED, so terminating it runs no guest code.
        unsafe {
            let _ = TerminateProcess(pi.hProcess, STATUS_DLL_INIT_FAILED);
            CloseHandle(pi.hThread).ok();
            CloseHandle(pi.hProcess).ok();
        }
        return Err(e);
    }

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
        // CreateProcessAsUserW that just succeeded above. Close both so we
        // don't leak; the suspended target is already terminated by enforce_*.
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

/// Find hook.dll alongside the launcher executable.
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

/// Stable per-project key component for the shared %LOCALAPPDATA%\.winrsbox\
/// overlay tree, derived from the FULL project path — the same identity the
/// per-project state dir / policy DB already use (`ensure_state` keys on
/// `<parent>/.winrsbox/<name>`: the distinguishing component is the whole
/// parent chain, not the basename). Review S07: keying the C: root by the
/// basename alone made two different projects sharing a last path component
/// (e.g. `D:\a\app` vs `D:\b\app`) read and overwrite each other's C:
/// overlay, and re-runs saw the last colliding project's stale data.
///
/// Hash: xxh3, the crate's existing identity hash (`cli::id::generate_id`).
/// generate_id truncates to 32 bits for short rule IDs; a filesystem key
/// keeps the full 64-bit digest. The basename prefix is cosmetic only.
fn c_overlay_key(project_root: &Path) -> String {
    let name = project_root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut hasher = xxhash_rust::xxh3::Xxh3::new();
    hasher.update(project_root.to_string_lossy().as_bytes());
    format!("{}-{:016x}", name, hasher.digest())
}

/// Ensure the per-project C: overlay root under `local_appdata` exists and
/// return it: `<local_appdata>/.winrsbox/<c_overlay_key>/workdir`. Created
/// with the same no-reparse contract as the state dir (review S07): a
/// pre-existing junction/symlink at any component of the chain must fail
/// loudly instead of silently redirecting where the C: overlay lands.
pub(crate) fn ensure_c_overlay_root(
    local_appdata: &Path,
    project_root: &Path,
) -> Result<PathBuf> {
    let key = c_overlay_key(project_root);
    let rel = Path::new(".winrsbox").join(&key).join("workdir");
    let c_root = local_appdata.join(&rel);
    create_dir_tree_no_reparse(local_appdata, &rel)
        .with_context(|| format!("create C: overlay root {}", c_root.display()))?;
    Ok(c_root)
}


/// Assign `process` to a new Job Object with given limits; returns the Job handle.
/// The caller must keep the returned HANDLE alive for the duration of the child.
pub(crate) fn setup_job_object(
    process: HANDLE,
    memory_limit: Option<u64>,
    strict_clipboard: bool,
    strict_ui: bool,
) -> Result<HANDLE> {
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW,
        JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_BASIC_UI_RESTRICTIONS,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT, JOB_OBJECT_UILIMIT,
    };

    // GiB → bytes, overflow-safe: a pathologically large `gb` saturates to
    // u64::MAX (effectively "unlimited") instead of wrapping to a tiny limit.
    let limits = winrsbox::contain::jobctl::JobLimits::default()
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
    // via RegisterWindowMessage. This overrides `--strict-ui` too — the env
    // var always wins, regardless of which CLI UI-restriction flag was passed.
    if std::env::var("FS_SANDBOX_NO_UI_LIMITS").is_err() {
        // `--strict-ui` (0xFF) is a strict superset of `--strict-clipboard`
        // (0x06), so when both are passed strict-ui wins outright — no need
        // to also apply with_strict_clipboard() first.
        let ui = if strict_ui {
            winrsbox::contain::jobctl::UiRestrictions::default().with_all_restrictions()
        } else if strict_clipboard {
            winrsbox::contain::jobctl::UiRestrictions::default().with_strict_clipboard()
        } else {
            winrsbox::contain::jobctl::UiRestrictions::default()
        };
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

mod target;

pub(crate) use target::{build_cmdline, resolve_target};

pub(crate) mod proc_table;
pub(crate) mod launch_prep;
pub(crate) mod child_drain;
pub(crate) mod inject;

// find_hook_dll (and the staged-artifact integrity check it runs before
// returning) moved into inject.rs (layout-guard: this file was over the
// 1000-line limit) — thematically "locate and verify hook.dll before
// injecting it" belongs with the rest of inject.rs's DLL-injection concerns.
pub(crate) use inject::{complete_c_overlay_migration, find_hook_dll, prepare_c_overlay_root};
#[cfg(test)]
pub(crate) use inject::{legacy_c_overlay_root, migrate_legacy_c_overlay};

#[cfg(test)]
mod tests;

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
