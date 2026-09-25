use crate::Cli;
use anyhow::Context;
use std::path::Path;
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        Security::{
            SECURITY_ATTRIBUTES, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID,
            TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
        },
        System::{
            Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW},
            Memory::{
                CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_READ,
                FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE,
            },
            Threading::{CreateEventW, GetCurrentProcess, OpenProcessToken},
        },
    },
};

use winrsbox::contain::guest as guest_token;

/// Environment variables carrying inherited root-event handle values.
pub(crate) const INIT_EVENT_HANDLE_ENV: &str = "FS_SANDBOX_INIT_EVENT";
pub(crate) const INIT_DEGRADED_EVENT_ENV: &str = "FS_SANDBOX_INIT_DEGRADED_EVENT";
pub(crate) const INIT_ERROR_BUFFER_HANDLE_ENV: &str = "FS_SANDBOX_INIT_ERROR_BUFFER";
const INIT_ERROR_BUFFER_SIZE: usize = 4096;

pub(crate) struct InitErrorBuffer {
    handle: HANDLE,
    view: MEMORY_MAPPED_VIEW_ADDRESS,
}

impl InitErrorBuffer {
    pub(crate) fn handle(&self) -> HANDLE {
        self.handle
    }

    pub(crate) fn read_message(&self) -> Option<String> {
        let bytes = unsafe {
            std::slice::from_raw_parts(self.view.Value.cast::<u8>(), INIT_ERROR_BUFFER_SIZE)
        };
        let length = u32::from_ne_bytes(bytes[..4].try_into().ok()?) as usize;
        if length == 0 || length > INIT_ERROR_BUFFER_SIZE - 4 {
            return None;
        }
        let message = String::from_utf8_lossy(&bytes[4..4 + length]);
        Some(
            message
                .chars()
                .map(|character| if character.is_control() { ' ' } else { character })
                .collect(),
        )
    }
}

impl Drop for InitErrorBuffer {
    fn drop(&mut self) {
        // SAFETY: the view and handle are owned by this guard and released once.
        unsafe {
            UnmapViewOfFile(self.view).ok();
            CloseHandle(self.handle).ok();
        }
    }
}

pub(crate) fn create_init_error_buffer() -> anyhow::Result<InitErrorBuffer> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: windows::core::BOOL(1),
    };
    // SAFETY: attributes is valid; the anonymous section is inherited only
    // through the launcher's explicit handle list.
    let handle = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            Some(&attributes),
            PAGE_READWRITE,
            0,
            INIT_ERROR_BUFFER_SIZE as u32,
            PCWSTR::null(),
        )
    }
    .context("CreateFileMappingW(init error buffer) failed")?;
    // SAFETY: handle names a live pagefile-backed mapping of the declared size.
    let view = unsafe {
        MapViewOfFile(
            handle,
            FILE_MAP_READ | FILE_MAP_WRITE,
            0,
            0,
            INIT_ERROR_BUFFER_SIZE,
        )
    };
    if view.Value.is_null() {
        // SAFETY: handle was created above and no view was mapped.
        unsafe { CloseHandle(handle).ok() };
        return Err(windows::core::Error::from_win32())
            .context("MapViewOfFile(init error buffer) failed");
    }
    std::env::set_var(INIT_ERROR_BUFFER_HANDLE_ENV, (handle.0 as usize).to_string());
    Ok(InitErrorBuffer { handle, view })
}

/// Detect whether THIS launcher was spawned inside an existing sandbox.
///
/// The outer launcher exports `FS_SANDBOX_SECTION` — the name of its trusted
/// session-config section — into the environment of every descendant
/// (`CreateProcessW` inherits env verbatim, and the spawn hook patches the
/// same name into every hooked child's env block). The section name is the
/// opaque identifier every sandboxed descendant legitimately inherits, so
/// its presence is a reliable signal that we are a descendant of an outer
/// launcher, not the outer launcher itself.
///
/// (Chunk 3, review XA 2026-09-20 S02: previously this keyed off
/// `FS_SANDBOX_PIPE`, which the launcher no longer exports at all — the
/// security-config variables would have made the detector permanently mute.)
///
/// Returning `true` here tells `main()` to skip the entire sandbox setup
/// (no state dir, no pipe, no overlay, no hook injection) and delegate the
/// target directly to the outer sandbox's process hook.
/// (issue C, #63)
pub(crate) fn is_nested_invocation() -> bool {
    std::env::var_os("FS_SANDBOX_SECTION").is_some()
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
/// The hook categories to disable, given the operator's `--disable-hooks` and
/// whether network containment is on.
///
/// Network off means the `connect` detour is never installed, so the guest's
/// socket path is byte-for-byte the unsandboxed one and nothing in the system
/// attributes its traffic to winrsbox. Reusing the existing disable-hooks
/// channel rather than adding a second switch keeps one mechanism to reason
/// about — and makes the composition testable, which matters because a
/// mistake here fails silently: the hook would simply install and start
/// enforcing (or not) with no error anywhere.
fn disable_hooks_categories(cli_categories: Option<&str>, net_guarded: bool) -> String {
    let mut cats: Vec<String> = cli_categories
        .unwrap_or_default()
        .split(',')
        .map(|c| c.trim().to_ascii_lowercase())
        .filter(|c| !c.is_empty())
        .collect();
    if !net_guarded && !cats.iter().any(|c| c == "net") {
        cats.push("net".to_string());
    }
    cats.join(",")
}

pub(crate) fn build_delegation_command(target: &[String]) -> std::process::Command {
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

/// Create kernel Event for hook.dll init signaling.
///
/// The root hook signals this anonymous event through a handle inherited via
/// the launcher's explicit handle list.
pub(crate) fn create_init_event() -> anyhow::Result<HANDLE> {
    let event = create_session_event()?;
    std::env::set_var(INIT_EVENT_HANDLE_ENV, (event.0 as usize).to_string());
    Ok(event)
}

/// Create the status event for degraded success or fatal hook initialization.
/// Optional install errors signal it alongside the success event; a fatal
/// install error signals it alone. Its inheritable handle value is exported
/// through `INIT_DEGRADED_EVENT_ENV`.
pub(crate) fn create_degraded_event() -> anyhow::Result<HANDLE> {
    let event = create_session_event()?;
    std::env::set_var(INIT_DEGRADED_EVENT_ENV, (event.0 as usize).to_string());
    Ok(event)
}

fn create_session_event() -> anyhow::Result<HANDLE> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: windows::core::BOOL(1),
    };
    // SAFETY: attributes is valid; the unnamed event can only be reached by
    // the exact handle inherited through the launcher's handle list.
    unsafe {
        CreateEventW(Some(&attributes), false, false, PCWSTR::null())
    }
        .context("CreateEventW for sandbox init handshake failed")
}

/// Set (non-security) env vars for child before CreateProcessW — child
/// inherits them.
///
/// Security config does NOT travel through the environment any more (review
/// XA 2026-09-20, S02): it is published ONLY through the trusted session
/// section (`session_section::publish`, embedded in `SessionConfig` by
/// main.rs). The eight retired exports (`FS_SANDBOX_PIPE/DLL/CWD/ROOT/GUARD/
/// ALLOW_RWX/DISABLE_HOOKS/TRACE`) were forgeable-by-inheritance and the
/// hook's spawn gate now DENIES any child whose environment carries one —
/// exporting them here would make every legitimate child spawn fail closed
/// at the gate. Only terminal-emulator ergonomics and the two
/// feature-adjacent switches the hook still reads stay env-borne.
///
/// Returns the effective `--disable-hooks` category list so the
/// session-section publisher can embed the same value (the env export is
/// gone; the section is the only channel).
#[allow(clippy::too_many_arguments)]
pub(crate) fn set_sandbox_environment(
    cli: &Cli,
    _pipe_name: &str,
    _dll_path: &Path,
    _sandbox_root: &Path,
    _project_root: &Path,
    cwd_str: &str,
    net_guarded: bool,
    _hook_trace: bool,
) -> String {
    // Help GUI terminal emulators (WezTerm, Windows Terminal) that ignore the inherited
    // CWD and fall back to the home directory when spawning their shell.
    std::env::set_var("WEZTERM_EXECUTABLE_ARGS_CWD", cwd_str);
    // The guard level, allow-rwx, disable-hooks and trace values reach the
    // hook exclusively through the trusted session section now — see the
    // doc comment above. Only the network/clipboard switches below remain
    // env-borne (the hook reads them as feature gates, not config).
    // Network containment off → tell the hook to skip the `net` category, so
    // `connect` is never detoured and the guest's socket path is byte-for-byte
    // the unsandboxed one. The effective category list is returned to the
    // caller, which publishes it through the trusted session section — it is
    // deliberately NOT exported as an environment variable any more.
    let disable_hooks_effective = disable_hooks_categories(cli.disable_hooks.as_deref(), net_guarded);
    // Hook-side trace gate value is published through the session section's
    // `trace` field by the caller — no `FS_SANDBOX_TRACE` export here.
    if cli.block_localhost {
        std::env::set_var("FS_SANDBOX_BLOCK_LOCALHOST", "1");
    }
    if cli.strict_clipboard {
        std::env::set_var("FS_SANDBOX_STRICT_CLIPBOARD", "1");
    }
    disable_hooks_effective
}

// ─── R04-1c: guest-launch token/environment preparation ────────────────────
// Moved here from sandbox/mod.rs (layout-guard: that file's launch_suspended
// grew past the 1000-line limit) — thematically these ARE launch-prep
// concerns: what token and environment block the guest process receives at
// creation time, same category as this file's init-event/degraded-event
// creation above.

/// Opens the launcher's own primary token with the access
/// [`guest_token::build_guest_token`] (via `CreateRestrictedToken`) and the
/// later `CreateProcessAsUserW(hToken, ...)` call need. Per `guest_token`'s
/// own doc note, `CreateRestrictedToken` carries the source handle's access
/// rights forward onto the new token — so opening with exactly the rights
/// `CreateProcessAsUserW` documents needing on ITS `hToken` argument
/// (`TOKEN_QUERY`, `TOKEN_DUPLICATE`, `TOKEN_ASSIGN_PRIMARY`, plus
/// `TOKEN_ADJUST_DEFAULT`/`TOKEN_ADJUST_SESSIONID` — needed whenever the
/// caller supplies an explicit environment block, which this module always
/// does) here means the derived guest token already carries exactly that
/// access, nothing broader.
pub(crate) fn open_own_token_for_restriction() -> anyhow::Result<HANDLE> {
    let access = TOKEN_DUPLICATE
        | TOKEN_QUERY
        | TOKEN_ASSIGN_PRIMARY
        | TOKEN_ADJUST_DEFAULT
        | TOKEN_ADJUST_SESSIONID;
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess is a pseudo-handle; access is a fixed,
    // documented-minimal TOKEN_ACCESS_MASK.
    unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) }
        .context("OpenProcessToken(own process) failed")?;
    Ok(token)
}

/// Copies the launcher's OWN environment block (as `GetEnvironmentStringsW`
/// returns it — a double-NUL-terminated sequence of NUL-terminated
/// `NAME=VALUE` wide strings) into an owned buffer, for explicit use as
/// `CreateProcessAsUserW`'s `lpEnvironment`. See the call site's comment in
/// `sandbox::launch_suspended` for why NULL is not an option there.
pub(crate) fn copy_caller_environment_block() -> anyhow::Result<Vec<u16>> {
    // SAFETY: documented zero-argument call; returns a pointer to a
    // double-NUL-terminated block owned by the OS until freed below.
    let raw = unsafe { GetEnvironmentStringsW() };
    anyhow::ensure!(!raw.is_null(), "GetEnvironmentStringsW returned NULL");
    // SAFETY: raw is non-null per the check above; the block is documented
    // to end with two consecutive NULs (an empty NAME=VALUE entry), so
    // scanning for that finds the true end.
    let len = unsafe {
        let mut i = 0usize;
        loop {
            let a = *raw.0.add(i);
            let b = *raw.0.add(i + 1);
            if a == 0 && b == 0 {
                break i + 2; // include both terminating NULs
            }
            i += 1;
        }
    };
    // SAFETY: [raw.0, raw.0 + len) was just proven valid by the scan above.
    let owned: Vec<u16> = unsafe { std::slice::from_raw_parts(raw.0, len).to_vec() };
    // SAFETY: raw came from GetEnvironmentStringsW; FreeEnvironmentStringsW
    // is its documented matching deallocator. `owned` is now a fully
    // independent copy, so freeing the OS block here is safe — nothing
    // downstream reads through `raw` again.
    unsafe { FreeEnvironmentStringsW(raw).ok() };
    Ok(owned)
}

/// R04-1c point 6: open the REAL primary token of the (still suspended)
/// child at `child_process` and verify its shape via
/// `guest_token::verify_guest_token_shape`, rather than trusting that
/// `CreateProcessAsUserW` copied the requested token verbatim.
pub(crate) fn verify_child_token(
    child_process: HANDLE,
    source_admin_enabled: bool,
) -> anyhow::Result<()> {
    let mut child_token = HANDLE::default();
    // SAFETY: child_process is the valid, just-created suspended process
    // handle from CreateProcessAsUserW above; TOKEN_QUERY is read-only.
    unsafe { OpenProcessToken(child_process, TOKEN_QUERY, &mut child_token) }
        .context("OpenProcessToken(child) failed during guest-token verification")?;
    let result = guest_token::verify_guest_token_shape(child_token, source_admin_enabled);
    // SAFETY: child_token was opened by us immediately above.
    unsafe { CloseHandle(child_token).ok() };
    result
}

#[cfg(test)]
mod init_event_security_tests {
    use super::{
        create_degraded_event, create_init_error_buffer, create_init_event,
        INIT_DEGRADED_EVENT_ENV, INIT_ERROR_BUFFER_HANDLE_ENV, INIT_EVENT_HANDLE_ENV,
    };
    use windows::Win32::Foundation::{CloseHandle, GetHandleInformation};

    fn assert_inheritable(handle: windows::Win32::Foundation::HANDLE, env: &str) {
        let value = std::env::var(env).expect("event handle env must be set");
        assert_eq!(value.parse::<usize>().unwrap(), handle.0 as usize);
        let mut flags = 0u32;
        // SAFETY: handle is live and owned by this test.
        let result = unsafe { GetHandleInformation(handle, &mut flags) };
        std::env::remove_var(env);
        // SAFETY: handle is closed exactly once after the query.
        unsafe { CloseHandle(handle).ok() };
        result.expect("GetHandleInformation failed");
        assert_ne!(flags & 1, 0, "root handshake handle must be inheritable");
    }

    #[test]
    fn root_handshake_events_export_inheritable_handle_values() {
        let init = create_init_event().expect("create init event");
        assert_inheritable(init, INIT_EVENT_HANDLE_ENV);
        let degraded = create_degraded_event().expect("create degraded event");
        assert_inheritable(degraded, INIT_DEGRADED_EVENT_ENV);
    }

    #[test]
    fn init_error_buffer_is_inheritable_and_readable() {
        let buffer = create_init_error_buffer().expect("create init error buffer");
        let mut flags = 0u32;
        // SAFETY: buffer.handle is live and owned by this test.
        unsafe { GetHandleInformation(buffer.handle, &mut flags) }
            .expect("GetHandleInformation failed");
        assert_ne!(flags & 1, 0, "error buffer handle must be inheritable");
        assert_eq!(
            std::env::var(INIT_ERROR_BUFFER_HANDLE_ENV)
                .unwrap()
                .parse::<usize>()
                .unwrap(),
            buffer.handle.0 as usize
        );

        let message = b"hook init test";
        // SAFETY: the mapping is writable for INIT_ERROR_BUFFER_SIZE bytes.
        unsafe {
            std::ptr::write(buffer.view.Value.cast::<u32>(), message.len() as u32);
            std::ptr::copy_nonoverlapping(
                message.as_ptr(),
                buffer.view.Value.cast::<u8>().add(4),
                message.len(),
            );
        }
        assert_eq!(buffer.read_message().as_deref(), Some("hook init test"));
        std::env::remove_var(INIT_ERROR_BUFFER_HANDLE_ENV);
    }
}#[cfg(test)]
mod network_opt_in_tests {
    use super::disable_hooks_categories;

    /// Network containment is off by default, and "off" has to reach the
    /// hook — otherwise the `connect` detour installs anyway and the guest's
    /// traffic is no longer indistinguishable from running it unsandboxed.
    #[test]
    fn net_hook_is_disabled_when_network_is_not_guarded() {
        assert_eq!(disable_hooks_categories(None, false), "net");
        assert_eq!(disable_hooks_categories(Some(""), false), "net");
    }

    /// With guarding on, nothing is added — the detour installs.
    #[test]
    fn net_hook_stays_enabled_when_guarded() {
        assert_eq!(disable_hooks_categories(None, true), "");
        assert_eq!(disable_hooks_categories(Some("reg"), true), "reg");
    }

    /// The operator's own `--disable-hooks` list survives, and `net` is not
    /// duplicated when they already asked for it.
    #[test]
    fn operator_categories_are_preserved_and_net_not_duplicated() {
        assert_eq!(disable_hooks_categories(Some("reg,ui"), false), "reg,ui,net");
        assert_eq!(disable_hooks_categories(Some("net"), false), "net");
        assert_eq!(disable_hooks_categories(Some("net,reg"), false), "net,reg");
        // Whitespace and case in the operator's list must not defeat the
        // duplicate check.
        assert_eq!(disable_hooks_categories(Some(" NET , reg "), false), "net,reg");
        // Empty entries from sloppy input are dropped rather than passed on.
        assert_eq!(disable_hooks_categories(Some("reg,,"), true), "reg");
    }
}

#[cfg(test)]
mod nested_detection_tests {
    //! Issue C (#63): nested-sandbox detection must fire exactly when the
    //! opaque sandbox-identifier variable is present in the environment, and
    //! never otherwise.
    //!
    //! These tests mutate the process environment, so they must not run in
    //! parallel with anything else that reads the same variable. Each test
    //! saves and restores the variable to avoid leaking state.

    use super::is_nested_invocation;

    /// Serializes the tests in this module against each other.
    ///
    /// The doc comment above states they must not run in parallel, but stating
    /// it did not enforce it: `cargo test` runs them on separate threads of one
    /// process, and the environment is process-wide. One test would set the
    /// variable while another removed it, and whichever asserted second
    /// failed — observed as an intermittent failure of
    /// `not_nested_when_section_unset` or `empty_string_still_counts_as_nested`,
    /// depending on which thread lost the race. Each test now holds this lock
    /// for its whole body, so the set/assert/restore sequence is atomic with
    /// respect to its siblings.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the lock, ignoring poisoning: a panic in one test must not cascade
    /// into spurious failures of the others, which would hide the real one.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// RAII guard that restores `FS_SANDBOX_SECTION` to its prior state on drop.
    struct SectionGuard(Option<std::ffi::OsString>);
    impl SectionGuard {
        fn capture() -> Self {
            SectionGuard(std::env::var_os("FS_SANDBOX_SECTION"))
        }
    }
    impl Drop for SectionGuard {
        fn drop(&mut self) {
            match &self.0 {
                Some(v) => std::env::set_var("FS_SANDBOX_SECTION", v),
                None => std::env::remove_var("FS_SANDBOX_SECTION"),
            }
        }
    }

    /// RED WITNESS (chunk 3, review XA 2026-09-20 S02): nesting detection must
    /// key off the session-section identifier (`FS_SANDBOX_SECTION`), not the
    /// retired `FS_SANDBOX_PIPE`. The launcher no longer exports
    /// `FS_SANDBOX_PIPE` at all (chunk 3, Part B), so a pipe-keyed detector
    /// would never fire — and every sandboxed descendant legitimately
    /// inherits the section name, which is exactly the "I live under an outer
    /// launcher" signal.
    #[test]
    fn nested_invocation_detected_via_section_env() {
        let _lock = env_lock();
        let _g = SectionGuard::capture();
        std::env::set_var("FS_SANDBOX_SECTION", r"Local\WinRsBoxSession-dummy");
        assert!(is_nested_invocation(), "FS_SANDBOX_SECTION set ⇒ nested");
        std::env::remove_var("FS_SANDBOX_SECTION");
        assert!(!is_nested_invocation(), "FS_SANDBOX_SECTION unset ⇒ not nested");
    }

    #[test]
    fn detects_nested_when_section_set() {
        let _lock = env_lock();
        let _g = SectionGuard::capture();
        std::env::set_var("FS_SANDBOX_SECTION", r"Local\WinRsBoxSession-99999");
        assert!(is_nested_invocation(), "FS_SANDBOX_SECTION set ⇒ nested");
    }

    #[test]
    fn not_nested_when_section_unset() {
        let _lock = env_lock();
        let _g = SectionGuard::capture();
        std::env::remove_var("FS_SANDBOX_SECTION");
        assert!(!is_nested_invocation(), "FS_SANDBOX_SECTION unset ⇒ not nested");
    }

    /// The detector must trigger on any value — including a pathological
    /// empty string. The outer launcher always sets a well-formed section
    /// name, but the contract is "presence ⇒ nested", not "non-empty ⇒
    /// nested", so an empty string still counts.
    #[test]
    fn empty_string_still_counts_as_nested() {
        let _lock = env_lock();
        let _g = SectionGuard::capture();
        std::env::set_var("FS_SANDBOX_SECTION", "");
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
mod env_export_redline_tests {
    //! W5 (chunk 3, review XA 2026-09-20, S02 sub-issue #1 remainder): this
    //! module must not export the eight retired security-config variables.
    //! Config travels ONLY through the trusted session section (launcher-
    //! authored, injection-channel-delivered); these env exports were
    //! forgeable-by-inheritance and the hook's spawn gate now DENIES any
    //! child whose environment carries one, so exporting them here would
    //! make every legitimate child spawn fail closed at the gate.
    //!
    //! The needles are built at runtime from plain variable names so the
    //! forbidden literals do not appear in this very file (include_str!
    //! self-match trap).

    const RETIRED: [&str; 8] = [
        "FS_SANDBOX_PIPE",
        "FS_SANDBOX_DLL",
        "FS_SANDBOX_CWD",
        "FS_SANDBOX_ROOT",
        "FS_SANDBOX_GUARD",
        "FS_SANDBOX_ALLOW_RWX",
        "FS_SANDBOX_DISABLE_HOOKS",
        "FS_SANDBOX_TRACE",
    ];

    #[test]
    fn launch_prep_never_exports_security_config_env() {
        let src = include_str!("launch_prep.rs");
        for name in RETIRED {
            let needle = format!("set_var(\"{name}\"");
            assert!(
                !src.contains(&needle),
                "launch_prep must not export {name}: security config travels \
                 only through the trusted session section, and the hook's \
                 spawn gate denies children inheriting it"
            );
        }
    }
}
