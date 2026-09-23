use crate::Cli;
use anyhow::Context;
use std::path::Path;
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree},
        Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG},
        Security::{
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_ADJUST_DEFAULT,
            TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
        },
        System::{
            Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW},
            Threading::{CreateEventW, GetCurrentProcess, OpenProcessToken},
        },
    },
};

use winrsbox::contain::guest as guest_token;

/// SYNCHRONIZE | EVENT_MODIFY_STATE — exactly the two rights this event's
/// two openers use: the launcher's `WaitForSingleObject` (main.rs) needs
/// SYNCHRONIZE, and the guest hook's `signal_one`
/// (winrsbox-hook/src/ipc/init_ack.rs) opens with `EVENT_MODIFY_STATE`
/// (0x0002) before `SetEvent`.
const INIT_EVENT_RIGHTS_MASK: &str = "0x100002";

/// Build the explicit per-object SDDL for an init-handshake event (R04-1b).
///
/// With `lpEventAttributes=None` (the previous behaviour) the DACL is
/// copied from the LAUNCHER's own `TokenDefaultDacl` at creation time.
/// R04-0's probe (docs/R04-implementation-plan-t1-light-t2.md) measured
/// that DACL to carry a `BUILTIN\Administrators` ACE alongside SYSTEM and
/// the user SID — an ACE that stops granting access once R04-1c derives the
/// guest token with Administrators deny-only. The guest (and its
/// descendants, per this file's `INIT_DEGRADED_EVENT_ENV`/`FS_SANDBOX_INIT_EVENT`
/// contract) must open these events BY NAME from `winrsbox-hook`'s
/// `signal_one`, so the grant has to name the specific user SID — not a
/// group the guest's token now denies. Same technique as
/// `pipe_server::security::current_user_string_sid` +
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW` already proved
/// for the IPC pipe (F6) — reused here via `pub(crate)`, not duplicated.
fn build_init_event_sddl() -> anyhow::Result<String> {
    let sid = crate::pipe_server::security::current_user_string_sid()?;
    Ok(format!("D:(A;;{INIT_EVENT_RIGHTS_MASK};;;{sid})"))
}

/// Convert `sddl` into a `SECURITY_ATTRIBUTES` ready for `CreateEventW`, and
/// the owning `PSECURITY_DESCRIPTOR` that must be `LocalFree`'d once the
/// kernel call has copied what it needs (the call site frees it
/// immediately after `CreateEventW` returns, on every path).
fn security_attributes_from_sddl(sddl: &str) -> anyhow::Result<(SECURITY_ATTRIBUTES, PSECURITY_DESCRIPTOR)> {
    let sddl_w: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: sddl_w is NUL-terminated; psd is a valid stack out-param; the
    // SDDL converter LocalAlloc's the descriptor and stores its pointer in
    // `psd` on success.
    let ok = unsafe {
        crate::pipe_server::security::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            1, // SDDL_REVISION_1
            &mut psd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || psd.is_invalid() {
        anyhow::bail!("ConvertStringSecurityDescriptorToSecurityDescriptorW failed (sddl={sddl})");
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd.0,
        bInheritHandle: windows::core::BOOL(0),
    };
    Ok((sa, psd))
}

/// Env var carrying the DEGRADED-init acknowledgment event name to the child
/// (S10). The hook-side counterpart literal lives in
/// winrsbox-hook/src/ipc/init_ack.rs; the two literals MUST stay identical,
/// and each side pins it in a test.
pub(crate) const INIT_DEGRADED_EVENT_ENV: &str = "FS_SANDBOX_INIT_DEGRADED_EVENT";

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
    build_session_event_name(pid, "init")
}

/// Shared builder for the hello-handshake kernel-event names (S10): draws 16
/// cryptographically-strong random bytes and formats
///     Local\fs-sandbox-<label>-<pid>-<32 lowercase hex chars>
///
/// If `BCryptGenRandom` ever fails, we fall back to the predictable
/// PID-only name so the handshake still works (see `build_random_event_name`).
fn build_session_event_name(pid: u32, label: &str) -> String {
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
        return format!("Local\\fs-sandbox-{label}-{}", pid);
    }
    let mut suffix = String::with_capacity(32);
    for b in rand_bytes.iter() {
        use std::fmt::Write;
        let _ = write!(&mut suffix, "{:02x}", b);
    }
    format!("Local\\fs-sandbox-{label}-{}-{}", pid, suffix)
}

/// Build the kernel-Event name for the S10 degraded-init acknowledgment:
///     Local\fs-sandbox-init-degraded-<pid>-<32 lowercase hex chars>
pub(crate) fn build_random_degraded_event_name(pid: u32) -> String {
    build_session_event_name(pid, "init-degraded")
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
/// H1 fix: the event name embeds a 128-bit random suffix so a same-session
/// attacker cannot guess the name and SetEvent() it ahead of the real
/// hook.dll. The `Local\` namespace already scopes the object to this
/// logon session; the random suffix raises the bar from "any same-user
/// process can OpenEvent" to "attacker must enumerate the object-manager
/// directory or read our env vars" (the env var is propagated through
/// CreateProcessW's environment block to the target only).
pub(crate) fn create_init_event(pid: u32) -> anyhow::Result<HANDLE> {
    let init_event_name = build_random_event_name(pid);
    let event_name_wide: Vec<u16> = init_event_name.encode_utf16().chain(Some(0)).collect();
    let sddl = build_init_event_sddl()?;
    let (sa, psd) = security_attributes_from_sddl(&sddl)?;
    let result = unsafe {
        CreateEventW(Some(&sa), false, false, PCWSTR(event_name_wide.as_ptr()))
    };
    // SAFETY: psd was allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW
    // above; the kernel copied it during CreateEventW, so it is freed here on
    // every path.
    unsafe { LocalFree(Some(HLOCAL(psd.0))) };
    let init_event = result?;
    std::env::set_var("FS_SANDBOX_INIT_EVENT", &init_event_name);
    Ok(init_event)
}

/// Create the second kernel Event for the S10 degraded-init acknowledgment:
/// when hook.dll finished initializing but some optional components failed to
/// install (buffered errors), it signals this event so the launcher can warn
/// the operator instead of silently running a degraded sandbox. Same
/// auto-reset, initially-unset shape as `create_init_event`; the name is
/// exported to the child via `INIT_DEGRADED_EVENT_ENV`.
pub(crate) fn create_degraded_event(pid: u32) -> anyhow::Result<HANDLE> {
    let degraded_event_name = build_random_degraded_event_name(pid);
    let event_name_wide: Vec<u16> = degraded_event_name.encode_utf16().chain(Some(0)).collect();
    let sddl = build_init_event_sddl()?;
    let (sa, psd) = security_attributes_from_sddl(&sddl)?;
    let result = unsafe {
        CreateEventW(Some(&sa), false, false, PCWSTR(event_name_wide.as_ptr()))
    };
    // SAFETY: psd was allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW
    // above; the kernel copied it during CreateEventW, so it is freed here on
    // every path.
    unsafe { LocalFree(Some(HLOCAL(psd.0))) };
    let degraded_event = result?;
    std::env::set_var(INIT_DEGRADED_EVENT_ENV, &degraded_event_name);
    Ok(degraded_event)
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
    //! R04-1b: the init-handshake events must carry an explicit DACL naming
    //! the current user SID with SYNCHRONIZE | EVENT_MODIFY_STATE — not a
    //! bare Administrators-group grant and not a default (NULL) SD. Same
    //! ACE-walk technique as `pipe_server::security::tests`.

    use super::create_init_event;
    use std::ffi::c_void;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows::Win32::Security::{
        GetAce, GetAclInformation, ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION,
        AclSizeInformation, DACL_SECURITY_INFORMATION,
    };

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;

    #[test]
    fn init_event_dacl_grants_exactly_the_current_user_sync_and_modify_state() {
        // Unique pid-like tag so parallel test runs never collide on the
        // event name.
        let pid = std::process::id().wrapping_add(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock before epoch")
                .subsec_nanos(),
        );
        let handle = create_init_event(pid).expect("create_init_event failed");
        std::env::remove_var("FS_SANDBOX_INIT_EVENT");

        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: handle is the valid event handle just created; GetSecurityInfo
        // with DACL only reads the object's security descriptor.
        let err = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                None,
            )
        };
        assert_eq!(err.0, 0, "GetSecurityInfo failed: WIN32_ERROR({})", err.0);
        assert!(!dacl.is_null(), "explicit SDDL must produce a present DACL");

        let mut info = ACL_SIZE_INFORMATION::default();
        // SAFETY: dacl is valid per the successful GetSecurityInfo call above;
        // ACL_SIZE_INFORMATION is the struct documented for AclSizeInformation.
        unsafe {
            GetAclInformation(
                dacl,
                &mut info as *mut _ as *mut c_void,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        }
        .expect("GetAclInformation failed");
        assert_eq!(
            info.AceCount, 1,
            "the SDDL grants exactly one ACE — the current user, nothing else \
             (no bare Administrators-group ACE, no default-DACL leftovers)"
        );

        let mut ace: *mut c_void = std::ptr::null_mut();
        // SAFETY: index 0 < AceCount (asserted above); dacl is valid.
        unsafe { GetAce(dacl, 0, &mut ace) }.expect("GetAce failed");
        // SAFETY: ace points into the live DACL buffer owned by the event's
        // security descriptor, valid for this scope.
        let (ace_type, mask) = unsafe {
            let a = &*(ace as *mut ACCESS_ALLOWED_ACE);
            (a.Header.AceType, a.Mask)
        };
        assert_eq!(ace_type, ACCESS_ALLOWED_ACE_TYPE, "ACE must be access-allowed");
        assert_eq!(
            mask, 0x0010_0002,
            "ACE must grant exactly SYNCHRONIZE | EVENT_MODIFY_STATE — the \
             two rights create_init_event's own WaitForSingleObject caller \
             and winrsbox-hook's signal_one (SetEvent) actually use"
        );

        // SAFETY: ace points into the live DACL; SidStart aliases the trustee SID.
        let ace_sid = unsafe {
            let a = &*(ace as *mut ACCESS_ALLOWED_ACE);
            windows::Win32::Security::PSID(&a.SidStart as *const u32 as *mut c_void)
        };
        let current_sid = crate::pipe_server::security::current_user_string_sid()
            .expect("current_user_string_sid failed");
        let mut sid_pwstr: *mut u16 = std::ptr::null_mut();
        // SAFETY: ace_sid points into the live DACL buffer; ConvertSidToStringSidW's
        // raw binding used here is the same one build_init_event_sddl relies on.
        let ok = unsafe {
            crate::pipe_server::security::ConvertSidToStringSidW(ace_sid, &mut sid_pwstr)
        };
        assert_ne!(ok, 0, "ConvertSidToStringSidW failed on ACE trustee");
        let ace_sid_str = unsafe {
            let mut len = 0usize;
            while *sid_pwstr.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(sid_pwstr, len))
        };
        // SAFETY: sid_pwstr is LocalAlloc'd by ConvertSidToStringSidW.
        unsafe {
            let _ = windows::Win32::Foundation::LocalFree(Some(
                windows::Win32::Foundation::HLOCAL(sid_pwstr as *mut c_void),
            ));
        }
        assert_eq!(
            ace_sid_str, current_sid,
            "ACE trustee must be the current user SID, not a group"
        );

        // SAFETY: handle came from CreateEventW above and is not yet closed.
        unsafe { CloseHandle(handle).ok() };
    }
}

#[cfg(test)]
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
mod hello_event_name_tests {
    //! H1 regression tests for the randomized hello-event name.

    use super::{build_random_degraded_event_name, build_random_event_name};

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

    /// S10: the degraded-ack event name follows the same pid-anchored random
    /// format under its own "init-degraded" label.
    #[test]
    fn degraded_format_includes_pid_and_32_hex_suffix() {
        let name = build_random_degraded_event_name(4242);
        let prefix = "Local\\fs-sandbox-init-degraded-4242-";
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

    /// S10: degraded and main hello names must never collide — the launcher
    /// waits on both, and a shared name would make the degraded probe fire on
    /// every successful init (or vice versa).
    #[test]
    fn degraded_name_differs_from_main_name_for_same_pid() {
        for pid in [1u32, 4242, 0xDEAD_BEEF] {
            assert_ne!(
                build_random_degraded_event_name(pid),
                build_random_event_name(pid),
                "degraded and main names collided for pid {pid}",
            );
        }
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
