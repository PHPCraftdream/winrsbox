// Init handshake + process-mitigation application (S10 fail-closed rework).
//
// Split out of core/hooks/mod.rs so the mitigation and init-event machinery
// has one testable home. `install_hooks` (hooks/mod.rs) calls
// `apply_mitigations(guard)?` and `signal_init_events()` at the same points
// as before — only the failure semantics changed:
//
//   * Every SetProcessMitigationPolicy BOOL return is now checked. The
//     static-tier DynamicCodePolicy(2)/SignaturePolicy(8) failures are FATAL
//     (Err → DllMain FALSE → the launcher kills the child): SECURITY.md's
//     threat model promises static "prohibits dynamic code and unsigned DLLs
//     to close the direct-syscall / fresh-ntdll bypass", so silently running
//     without them is a broken containment promise.
//   * ExtensionPointDisable(6)/ImageLoad(10) failures are buffered and
//     non-fatal — both have documented env escape hatches
//     (FS_SANDBOX_NO_EXTPOINT_DISABLE / FS_SANDBOX_NO_IMAGELOAD_LOCK) and no
//     hard containment promise rides on them alone.
//   * A second kernel event (INIT_DEGRADED_EVENT_ENV) tells the launcher the
//     child initialized DEGRADED (buffered install errors exist at
//     init-signal time), so the launcher can report it instead of trusting a
//     clean "initialized" handshake.

/// Environment variables carrying the two root init-event handles inherited
/// through the launcher's explicit handle list.
pub(crate) const INIT_EVENT_HANDLE_ENV: &str = "FS_SANDBOX_INIT_EVENT";
pub(crate) const INIT_DEGRADED_EVENT_ENV: &str = "FS_SANDBOX_INIT_DEGRADED_EVENT";

/// PROCESS_MITIGATION_POLICY ids (winapi types them as the
/// `PROCESS_MITIGATION_POLICY` enum; we pass these `u32`s cast with `as`).
const POLICY_DYNAMIC_CODE: u32 = 2;
const POLICY_EXTENSION_POINT_DISABLE: u32 = 6;
const POLICY_SIGNATURE: u32 = 8;
const POLICY_IMAGE_LOAD: u32 = 10;

/// Whether a SetProcessMitigationPolicy failure for `policy` must abort the
/// whole hook install (Err → DllMain FALSE → launcher kills the child).
///
/// Only the static-tier JIT/unsigned-code killers are fatal: under
/// GuardLevel::Static, SECURITY.md promises dynamic code and unsigned DLLs
/// are prohibited (the direct-syscall / fresh-ntdll bypass would otherwise
/// walk straight through every other guard). ExtensionPointDisable(6) and
/// ImageLoad(10) degrade gracefully (buffered, loud) — they carry documented
/// escape hatches and no such hard containment promise.
pub(crate) fn mitigation_failure_is_fatal(guard: ipc::GuardLevel, policy: u32) -> bool {
    guard == ipc::GuardLevel::Static
        && (policy == POLICY_DYNAMIC_CODE || policy == POLICY_SIGNATURE)
}

/// Buffer a mitigation failure and turn it into Err when the policy is one
/// the static threat model cannot run without. `err` is GetLastError()
/// captured IMMEDIATELY after the failing call (the last-error slot is
/// per-thread and clobbered by the next Win32 call).
fn buffer_mitigation_failure(
    guard: ipc::GuardLevel,
    policy: u32,
    name: &str,
    err: u32,
) -> Result<(), String> {
    let msg = format!("SetProcessMitigationPolicy({name}) failed: GetLastError={err}");
    crate::ipc_client::buffer_install_error(msg.clone());
    if mitigation_failure_is_fatal(guard, policy) {
        return Err(msg);
    }
    Ok(())
}

/// Buffer a verify-after-set mismatch and mirror the set-failure fatality
/// rule (only matters for policies 2/8, which are the only ones verified).
fn buffer_mitigation_not_enforced(
    guard: ipc::GuardLevel,
    policy: u32,
    name: &str,
    flags: u32,
) -> Result<(), String> {
    let msg = format!(
        "SetProcessMitigationPolicy({name}) accepted but mitigation not enforced \
         after set: flags=0x{flags:x}"
    );
    crate::ipc_client::buffer_install_error(msg.clone());
    if mitigation_failure_is_fatal(guard, policy) {
        return Err(msg);
    }
    Ok(())
}

/// Apply kernel-enforced process mitigations from within the sandboxed
/// process. Called after all hooks are installed so our detour patching is
/// already done. The guard level is the typed `ipc::GuardLevel` from the
/// trusted session section (review XA 2026-09-20, S02 #2) — never a string
/// compared by bytes, which used to disagree with the case-insensitive spawn
/// gate ("FULL" passed the gate, then failed the case-sensitive executor
/// compares here).
pub(crate) fn apply_mitigations(guard: ipc::GuardLevel) -> Result<(), String> {
    if guard == ipc::GuardLevel::None {
        return Ok(());
    }
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::processthreadsapi::{
        GetCurrentProcess, GetProcessMitigationPolicy, SetProcessMitigationPolicy,
    };
    use winapi::um::winnt::PROCESS_MITIGATION_POLICY;

    // ExtensionPointDisablePolicy (6): blocks AppInit_DLLs, SetWindowsHookEx, IFEO.
    // Applied in full and static — this is JIT-safe hardening (it blocks
    // injection INTO us, not our own code generation).
    // Diagnostic escape hatch: set FS_SANDBOX_NO_EXTPOINT_DISABLE=1 to skip
    // this block (suspected to also break Text Services Framework / IME
    // initialisation, including per-process keyboard layout switching).
    if matches!(guard, ipc::GuardLevel::Full | ipc::GuardLevel::Static)
        && std::env::var("FS_SANDBOX_NO_EXTPOINT_DISABLE").is_err()
    {
        let ext_disable_flags: u32 = 1;
        // SAFETY: ext_disable_flags is valid for
        // PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY — a 4-byte struct
        // whose Flags DWORD is exactly what we point at, of the documented
        // size (same calling pattern as escape_dll_sideload.rs).
        let ok = unsafe {
            SetProcessMitigationPolicy(
                POLICY_EXTENSION_POINT_DISABLE as PROCESS_MITIGATION_POLICY,
                &ext_disable_flags as *const u32 as *mut _,
                std::mem::size_of::<u32>(),
            )
        };
        if ok == 0 {
            // Capture GetLastError immediately: the last-error slot is
            // per-thread and clobbered by the next Win32 call.
            let err = unsafe { GetLastError() };
            buffer_mitigation_failure(
                guard,
                POLICY_EXTENSION_POINT_DISABLE,
                "ExtensionPointDisable",
                err,
            )?;
        }
    }

    // DynamicCode + Signature are the JIT/unsigned-code killers — they break
    // node/V8, .NET, Python .pyd, Node .node. Applied ONLY in `static` (hard
    // containment, opt-in for pure-static targets), never in `full`. This is
    // the runtime half of the M4 split; the create-time half lives in
    // launcher mitigations::Profile::Static. SignaturePolicy is applied here
    // (not at create time) precisely because hook.dll is unsigned and must
    // load first.
    if guard == ipc::GuardLevel::Static {
        // DynamicCodePolicy (2): blocks RWX/JIT.
        // winnt bit layout (PROCESS_MITIGATION_DYNAMIC_CODE_POLICY):
        //   bit 0 = ProhibitDynamicCode
        let dyn_code_flags: u32 = 1; // ProhibitDynamicCode = bit 0
        // SAFETY: dyn_code_flags is valid for
        // PROCESS_MITIGATION_DYNAMIC_CODE_POLICY — same 4-byte Flags-DWORD
        // shape as above.
        let ok = unsafe {
            SetProcessMitigationPolicy(
                POLICY_DYNAMIC_CODE as PROCESS_MITIGATION_POLICY,
                &dyn_code_flags as *const u32 as *mut _,
                std::mem::size_of::<u32>(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            buffer_mitigation_failure(guard, POLICY_DYNAMIC_CODE, "DynamicCode", err)?;
        } else {
            // Verify-after-set (S10): a lied-about success is as bad as a
            // failure. Re-query what the kernel actually holds.
            //   bit 0 = ProhibitDynamicCode must be SET.
            let mut cur: u32 = 0;
            // SAFETY: GetCurrentProcess returns the constant pseudo-handle
            // (-1), always valid; `cur` is a valid 4-byte out-buffer of the
            // documented size (escape_dll_sideload.rs precedent).
            let got = unsafe {
                GetProcessMitigationPolicy(
                    GetCurrentProcess(),
                    POLICY_DYNAMIC_CODE as PROCESS_MITIGATION_POLICY,
                    &mut cur as *mut u32 as *mut _,
                    std::mem::size_of::<u32>(),
                )
            };
            if got == 0 {
                let err = unsafe { GetLastError() };
                let msg =
                    format!("GetProcessMitigationPolicy(DynamicCode) failed: GetLastError={err}");
                crate::ipc_client::buffer_install_error(msg.clone());
                return Err(msg);
            }
            if cur & 1 == 0 {
                buffer_mitigation_not_enforced(guard, POLICY_DYNAMIC_CODE, "DynamicCode", cur)?;
            }
        }

        // SignaturePolicy (8): only Microsoft-signed DLLs (subsequent loads).
        // winnt bit layout (PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY):
        //   bit 0 = MicrosoftSignedOnly
        //   bit 1 = StoreSignedOnly
        //   bit 2 = AuditMicrosoftSignedOnly
        let sig_flags: u32 = 1; // MicrosoftSignedOnly = bit 0
        // SAFETY: sig_flags is valid for
        // PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY (4 bytes).
        let ok = unsafe {
            SetProcessMitigationPolicy(
                POLICY_SIGNATURE as PROCESS_MITIGATION_POLICY,
                &sig_flags as *const u32 as *mut _,
                std::mem::size_of::<u32>(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            buffer_mitigation_failure(guard, POLICY_SIGNATURE, "Signature", err)?;
        } else {
            // Verify-after-set: bit 0 MicrosoftSignedOnly must be SET and
            // bit 2 AuditMicrosoftSignedOnly must be CLEAR (audit mode
            // merely LOGS the violation — the load goes through — so an
            // "enforced" bit-0 with a set bit-2 is not containment).
            let mut cur: u32 = 0;
            // SAFETY: pseudo-handle + valid 4-byte out-buffer, as above.
            let got = unsafe {
                GetProcessMitigationPolicy(
                    GetCurrentProcess(),
                    POLICY_SIGNATURE as PROCESS_MITIGATION_POLICY,
                    &mut cur as *mut u32 as *mut _,
                    std::mem::size_of::<u32>(),
                )
            };
            if got == 0 {
                let err = unsafe { GetLastError() };
                let msg =
                    format!("GetProcessMitigationPolicy(Signature) failed: GetLastError={err}");
                crate::ipc_client::buffer_install_error(msg.clone());
                return Err(msg);
            }
            if cur & 1 == 0 || cur & (1 << 2) != 0 {
                buffer_mitigation_not_enforced(guard, POLICY_SIGNATURE, "Signature", cur)?;
            }
        }
    }

    // ImageLoadPolicy (10): PreferSystem32Images + NoRemoteImages.
    // Applied in all enforcing tiers (scan/full/static) — DLL sideloading via CWD/PATH hijack
    // is a critical sandbox-escape vector that affects all profiles.
    // Safe to apply after hook installation: hook.dll is already loaded,
    // and PreferSystem32Images only affects *subsequent* LoadLibrary calls.
    // Diagnostic escape hatch: set FS_SANDBOX_NO_IMAGELOAD_LOCK=1 to skip.
    if std::env::var("FS_SANDBOX_NO_IMAGELOAD_LOCK").is_err() {
        // PROCESS_MITIGATION_IMAGE_LOAD_POLICY bit layout:
        //   bit 0 = NoRemoteImages    (block UNC \\server\share\evil.dll)
        //   bit 2 = PreferSystem32Images (System32 searched before CWD/PATH)
        let image_load_flags: u32 = (1 << 0) | (1 << 2); // NoRemote | PreferSystem32
        // SAFETY: image_load_flags is valid for
        // PROCESS_MITIGATION_IMAGE_LOAD_POLICY (4 bytes).
        let ok = unsafe {
            SetProcessMitigationPolicy(
                POLICY_IMAGE_LOAD as PROCESS_MITIGATION_POLICY,
                &image_load_flags as *const u32 as *mut _,
                std::mem::size_of::<u32>(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            // ImageLoad(10) is never fatal: it has a documented env escape
            // hatch and degrades loudly-but-gracefully.
            buffer_mitigation_failure(guard, POLICY_IMAGE_LOAD, "ImageLoad", err)?;
        }
    }
    Ok(())
}

/// Open a named kernel event by name and set it (best effort).
///
/// `None` (env var absent) means this context doesn't need signaling —
/// silently skip, as the pre-S10 block did for unit tests running hook code
/// directly. An event that exists but cannot be opened/set is ignored: the
/// launcher's 5-second init timeout treats silence as failure either way.
fn signal_one(event_name: Option<&str>) {
    let Some(event_name) = event_name else { return };
    let wide: Vec<u16> = event_name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer valid for the whole
    // call; 0x0002 (EVENT_MODIFY_STATE) is the access right SetEvent needs,
    // bInheritHandle = FALSE. OpenEventW returning NULL means the event does
    // not exist (or we lack access) and nothing below runs. The handle, when
    // non-null, is closed here — SetEvent needs no lingering handle.
    unsafe {
        let h = winapi::um::synchapi::OpenEventW(
            0x0002, // EVENT_MODIFY_STATE — needed for SetEvent
            0,      // bInheritHandle = FALSE
            wide.as_ptr(),
        );
        if !h.is_null() {
            winapi::um::synchapi::SetEvent(h);
            winapi::um::handleapi::CloseHandle(h);
        }
    }
}

/// Signal and close a root handshake handle inherited explicitly at process
/// creation. Remove its variable before descendants inherit the environment.
fn consume_inherited_event(handle_env: &str, signal: bool) {
    let Ok(raw_handle) = std::env::var(handle_env) else {
        return;
    };
    std::env::remove_var(handle_env);
    let handle_value = match raw_handle.parse::<usize>() {
        Ok(value) if value != 0 => value,
        _ => {
            crate::ipc_client::buffer_install_error(format!(
                "invalid inherited event handle in {handle_env}"
            ));
            return;
        }
    };
    let handle = handle_value as winapi::shared::ntdef::HANDLE;
    // SAFETY: the launcher placed this valid event handle in the explicit
    // inherited-handle list for this process; this function consumes it once.
    let (signaled, error) = unsafe {
        let signaled = if signal {
            winapi::um::synchapi::SetEvent(handle)
        } else {
            1
        };
        let error = if signaled == 0 {
            winapi::um::errhandlingapi::GetLastError()
        } else {
            0
        };
        (signaled, error)
    };
    // SAFETY: this process owns the inherited handle and no later code uses it.
    unsafe { winapi::um::handleapi::CloseHandle(handle) };
    if signaled == 0 {
        crate::ipc_client::buffer_install_error(format!(
            "SetEvent({handle_env}) failed: GetLastError={error}"
        ));
    }
}

// ---------------------------------------------------------------------------
// Per-child bootstrap acknowledgement (review XA 2026-09-20, S02 #3)
//
// The ROOT handshake above proves only that SOME process signaled the
// launcher's inherited event — inherited by every descendant, so it proves
// nothing about which child initialized. For a spawn, the PARENT-side
// counterpart lives in core/hooks/spawn.rs: it creates an event with an
// unguessable per-child name, delivers the name through the injection env
// channel, resumes the child, and blocks until THIS process's own
// install_hooks signals it below.
// ---------------------------------------------------------------------------

/// Env var carrying the PER-CHILD bootstrap acknowledgement event name. The
/// spawn hook (parent side, core/hooks/spawn.rs) creates the event, appends
/// this NAME=VALUE pair into the child's environment block cross-process
/// before the child ever runs (same channel as FS_SANDBOX_SECTION), and waits
/// on the event after resuming the child. signal_init_events() opens and sets
/// it from this process's own install. The two sides pin the exact literal in
/// tests — do not reword.
pub(crate) const CHILD_INIT_EVENT_ENV: &str = "FS_SANDBOX_CHILD_INIT_EVENT";

/// Bounded wait for the per-child ack, mirroring the launcher's root
/// handshake budget (main.rs waits 5000 ms for the same class of signal:
/// DllMain + mitigations + hook install inside a cold child).
pub(crate) const CHILD_INIT_ACK_TIMEOUT_MS: u32 = 5000;

/// Build the per-child ack event name:
///     Local\fs-sandbox-child-init-<pid>-<32 lowercase hex chars>
///
/// The 32-char suffix is 16 bytes from `BCryptGenRandom` (system preferred
/// RNG) — 128 bits, the same budget as the launcher's root event names
/// (launch_prep::build_random_event_name, the H1 fix). A same-session
/// attacker must guess the full name to preempt-signal it.
///
/// Returns `None` when the RNG fails. Unlike the launcher's builder there is
/// deliberately NO predictable pid-only fallback: for a ROOT launch a
/// guessable name is a bounded TOCTOU window watched by an operator, but a
/// guessable PER-CHILD ack name lets any same-session process SetEvent it and
/// make the parent believe an unprotected child is protected — the exact
/// failure this fix exists to close. The caller (spawn hook) fails the spawn
/// closed instead: no unguessable name, no confirmation channel, no child.
pub(crate) fn build_child_init_event_name(pid: u32) -> Option<String> {
    let mut rand_bytes = [0u8; 16];
    // SAFETY: FFI call to bcrypt!BCryptGenRandom; pbBuffer is a valid mutable
    // 16-byte slice and BCRYPT_USE_SYSTEM_PREFERRED_RNG means hAlgorithm is
    // unused (must be null).
    let status = unsafe {
        winapi::shared::bcrypt::BCryptGenRandom(
            std::ptr::null_mut(),
            rand_bytes.as_mut_ptr(),
            rand_bytes.len() as u32,
            winapi::shared::bcrypt::BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return None;
    }
    let mut suffix = String::with_capacity(32);
    for b in rand_bytes.iter() {
        use std::fmt::Write;
        let _ = write!(&mut suffix, "{:02x}", b);
    }
    Some(format!("Local\\fs-sandbox-child-init-{}-{}", pid, suffix))
}

/// The parent-side handle for one child's bootstrap ack: an auto-reset,
/// initially-unset kernel Event (same shape as the launcher's root init
/// event) plus the unguessable name the child will find in its environment.
/// Drop closes the handle; the kernel object dies with the last handle.
pub(crate) struct ChildInitAck {
    handle: winapi::shared::ntdef::HANDLE,
    name: String,
}

impl ChildInitAck {
    /// The name to inject into the child's environment block.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Block up to `timeout_ms` for the child to signal its guard-installed
    /// ack. `true` = signaled (WAIT_OBJECT_0); `false` = timeout or wait
    /// failure, both of which the caller treats as "child never confirmed".
    pub(crate) fn wait_for_ack(&self, timeout_ms: u32) -> bool {
        // SAFETY: self.handle is the valid event handle from CreateEventW
        // below; a synchronous wait on a kernel object needs no other state.
        unsafe { winapi::um::synchapi::WaitForSingleObject(self.handle, timeout_ms) == 0 }
    }
}

impl Drop for ChildInitAck {
    fn drop(&mut self) {
        // SAFETY: self.handle is the valid event handle from CreateEventW;
        // drop runs at most once.
        unsafe {
            winapi::um::handleapi::CloseHandle(self.handle);
        }
    }
}

// ─── R04-1b: explicit per-object SDDL for the child ack event ─────────────
//
// This event is created by THIS process (the parent guest, running under
// R04-1c's restricted token once that lands: Administrators deny-only) and
// opened BY NAME by our own child (same restricted-token shape, same user
// SID — parent and child are the same Windows account). With
// `lpEventAttributes=None` the DACL is copied from the creator's
// `TokenDefaultDacl`, which R04-0's probe (docs/R04-implementation-plan-
// t1-light-t2.md) measured to carry a `BUILTIN\Administrators` ACE
// alongside SYSTEM and the user SID — an ACE that stops granting access the
// moment Administrators becomes deny-only in the token that created the
// object. The user-SID ACE and the SYSTEM ACE are unaffected by that
// change, so `TokenDefaultDacl` would likely still work here in practice —
// but "likely" is exactly the kind of default this task closes: an
// explicit SDDL naming the specific user SID makes the grant independent
// of what any particular Windows default happens to produce and testable
// without a live elevated launch.
//
// Rights granted: SYNCHRONIZE (the parent's `wait_for_ack` calls
// `WaitForSingleObject`) | EVENT_MODIFY_STATE (0x0002, the child's
// `signal_one` calls `OpenEventW(EVENT_MODIFY_STATE, ...)` then `SetEvent`).
// Parent and child share one user SID, so a single ACE covers both roles —
// mirroring the technique `winrsbox-launcher/src/pipe_server/security.rs`
// (`current_user_string_sid` + `ConvertStringSecurityDescriptorToSecurityDescriptorW`)
// already proved for the launcher's IPC pipe. That helper lives in the
// launcher's BINARY-only module tree (`mod pipe_server` in main.rs, not
// part of the `winrsbox` library crate) and this is a different crate
// entirely (`winrsbox-hook`), so it is not reachable here — the small SID
// resolver below is a deliberate duplication of the same proven technique,
// not a new one.

/// SYNCHRONIZE | EVENT_MODIFY_STATE — exactly the two rights this event's
/// two openers (parent `WaitForSingleObject`, child `SetEvent`) use.
const CHILD_ACK_EVENT_RIGHTS_SDDL: &str = "0x100002";

/// Query the current process token and return the user SID in SDDL string
/// form (e.g. `S-1-5-21-…`). Same technique as
/// `winrsbox-launcher/src/pipe_server/security.rs::current_user_string_sid`
/// (two-step `GetTokenInformation(TokenUser)` + `ConvertSidToStringSidW`),
/// duplicated here because this crate cannot reach that binary-only module.
fn current_user_string_sid() -> Result<String, String> {
    use winapi::shared::minwindef::LPVOID;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::securitybaseapi::GetTokenInformation;
    use winapi::shared::sddl::ConvertSidToStringSidW;
    use winapi::um::winbase::LocalFree;
    use winapi::um::winnt::{TokenUser, TOKEN_QUERY, TOKEN_USER};

    // SAFETY: GetCurrentProcess is a pseudo-handle; OpenProcessToken with
    // TOKEN_QUERY is the documented way to query our own token.
    let mut token: winapi::shared::ntdef::HANDLE = std::ptr::null_mut();
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(format!("OpenProcessToken failed: GetLastError={err}"));
    }

    // Two-step GetTokenInformation: first call sizes the buffer.
    let mut needed: u32 = 0;
    // SAFETY: null buffer + 0 length is the documented size-query pattern;
    // the call is expected to "fail" with ERROR_INSUFFICIENT_BUFFER while
    // still writing `needed`.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        unsafe { CloseHandle(token) };
        return Err("GetTokenInformation(TokenUser) size query returned 0".to_string());
    }
    let mut buf = vec![0u8; needed as usize];
    let mut got: u32 = 0;
    // SAFETY: buf is sized to `needed`; pointer and length match.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as LPVOID,
            needed,
            &mut got,
        )
    };
    let err = unsafe { GetLastError() };
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(format!("GetTokenInformation(TokenUser) failed: GetLastError={err}"));
    }

    // SAFETY: buf was filled by GetTokenInformation with a TOKEN_USER
    // struct followed by the SID bytes; buf outlives this read.
    let token_user: &TOKEN_USER = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let user_sid = token_user.User.Sid;
    if user_sid.is_null() {
        return Err("TokenUser returned a null SID".to_string());
    }

    let mut sid_pwstr: *mut u16 = std::ptr::null_mut();
    // SAFETY: user_sid is valid for the lifetime of `buf` (still alive);
    // ConvertSidToStringSidW LocalAlloc's into sid_pwstr on success.
    let ok = unsafe { ConvertSidToStringSidW(user_sid, &mut sid_pwstr) };
    if ok == 0 || sid_pwstr.is_null() {
        return Err("ConvertSidToStringSidW failed".to_string());
    }
    // SAFETY: sid_pwstr is a null-terminated wide string allocated by Win32.
    let sid_str = unsafe {
        let mut len = 0usize;
        while *sid_pwstr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(sid_pwstr, len);
        String::from_utf16_lossy(slice)
    };
    // SAFETY: sid_pwstr came from LocalAlloc'd ConvertSidToStringSidW;
    // LocalFree is the matched deallocator.
    unsafe {
        LocalFree(sid_pwstr as winapi::shared::minwindef::HLOCAL);
    }
    Ok(sid_str)
}

/// Build the SDDL security descriptor for the child ack event: a single ACE
/// granting the current user SID exactly SYNCHRONIZE | EVENT_MODIFY_STATE.
/// See the module-level comment above `create_child_init_ack` for why this
/// is explicit rather than `lpEventAttributes=None`.
fn build_child_ack_sddl() -> Result<String, String> {
    let sid = current_user_string_sid()?;
    Ok(format!("D:(A;;{CHILD_ACK_EVENT_RIGHTS_SDDL};;;{sid})"))
}

/// Create the per-child ack event for `pid` (auto-reset, initially unset,
/// explicit per-user SDDL — see the R04-1b comment above). Fails closed
/// when the RNG, SID resolution, SDDL conversion, or CreateEventW fails:
/// the spawn hook terminates the child rather than resume an unconfirmable
/// one.
pub(crate) fn create_child_init_ack(pid: u32) -> Result<ChildInitAck, String> {
    let name = build_child_init_event_name(pid)
        .ok_or_else(|| "BCryptGenRandom unavailable — cannot build an unguessable child ack event name".to_string())?;
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();

    let sddl = build_child_ack_sddl()?;
    let sddl_w: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut psd: winapi::um::winnt::PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: sddl_w is NUL-terminated; psd is a valid stack out-param; the
    // SDDL converter LocalAlloc's the descriptor and stores its pointer in
    // `psd` on success.
    let ok = unsafe {
        winapi::shared::sddl::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_w.as_ptr(),
            winapi::shared::sddl::SDDL_REVISION_1 as u32,
            &mut psd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || psd.is_null() {
        return Err(format!(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW(child ack) failed (sddl={sddl})"
        ));
    }
    let mut sa = winapi::um::minwinbase::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<winapi::um::minwinbase::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd,
        bInheritHandle: 0,
    };

    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer valid for the whole
    // call; `sa` points at the explicit SD built above (auto-freed via
    // LocalFree below, after CreateEventW has copied what it needs);
    // auto-reset (bManualReset=FALSE), initially unset (bInitialState=FALSE).
    let handle = unsafe { winapi::um::synchapi::CreateEventW(&mut sa, 0, 0, wide.as_ptr()) };
    let create_err = unsafe { winapi::um::errhandlingapi::GetLastError() };
    // SAFETY: psd was allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW
    // above; the kernel copied it during CreateEventW, so it is freed here on
    // every path.
    unsafe { winapi::um::winbase::LocalFree(psd as winapi::shared::minwindef::HLOCAL) };
    if handle.is_null() {
        return Err(format!("CreateEventW(child ack) failed: GetLastError={create_err}"));
    }
    Ok(ChildInitAck { handle, name })
}

/// Signal launcher that hook.dll initialized via kernel Events.
///
/// The inherited root-init handle is consumed and closed when present; absent
/// env means this context does not need the root handshake (e.g. unit tests).
/// The status handle is signaled for buffered optional errors on success and
/// alone for fatal install failures. Finally, the PER-CHILD bootstrap ack event
/// (CHILD_INIT_EVENT_ENV) is signaled when present, telling OUR spawn hook
/// (core/hooks/spawn.rs) that THIS process finished install_hooks.
pub(crate) fn signal_init_events() {
    consume_inherited_event(INIT_EVENT_HANDLE_ENV, true);
    consume_inherited_event(
        INIT_DEGRADED_EVENT_ENV,
        crate::ipc_client::install_errors_pending(),
    );
    // S02 #3: the per-child bootstrap ack. Firing here means exactly "THIS
    // process finished install_hooks": the event was created by OUR spawn
    // hook with a per-child unguessable name, so only this child can satisfy
    // the parent's wait (the inherited root event above proves nothing about
    // which child initialized).
    let child_ack = std::env::var(CHILD_INIT_EVENT_ENV).ok();
    signal_one(child_ack.as_deref());
}

pub(crate) fn signal_init_failure() {
    consume_inherited_event(INIT_DEGRADED_EVENT_ENV, true);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R04-1b: the child ack event's DACL must grant exactly the current
    /// user SID SYNCHRONIZE | EVENT_MODIFY_STATE — not a bare
    /// Administrators-group ACE, not a default-DACL leftover.
    #[test]
    fn child_ack_event_dacl_grants_exactly_the_current_user_sync_and_modify_state() {
        use winapi::ctypes::c_void;
        use winapi::um::accctrl::SE_KERNEL_OBJECT;
        use winapi::um::aclapi::GetSecurityInfo;
        use winapi::um::winnt::{
            ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
            DACL_SECURITY_INFORMATION,
        };

        let pid = std::process::id().wrapping_add(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock before epoch")
                .subsec_nanos(),
        );
        let ack = create_child_init_ack(pid).expect("create_child_init_ack failed");

        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: ack.handle is the valid event handle just created;
        // querying only the DACL leaves owner/group/sacl/psd untouched.
        let err = unsafe {
            GetSecurityInfo(
                ack.handle,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(err, 0, "GetSecurityInfo failed: GetLastError-equivalent={err}");
        assert!(!dacl.is_null(), "explicit SDDL must produce a present DACL");

        // SAFETY: ACL_SIZE_INFORMATION has no Default impl in winapi; a
        // zeroed instance is the documented pre-fill for an out-param
        // GetAclInformation fully overwrites on success.
        let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: dacl is valid per the successful GetSecurityInfo call above.
        let ok = unsafe {
            winapi::um::securitybaseapi::GetAclInformation(
                dacl,
                &mut info as *mut _ as *mut c_void,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        };
        assert_ne!(ok, 0, "GetAclInformation failed");
        assert_eq!(
            info.AceCount, 1,
            "the SDDL grants exactly one ACE — the current user, nothing else"
        );

        let mut ace: *mut c_void = std::ptr::null_mut();
        // SAFETY: index 0 < AceCount (asserted above); dacl is valid.
        let ok = unsafe { winapi::um::securitybaseapi::GetAce(dacl, 0, &mut ace) };
        assert_ne!(ok, 0, "GetAce failed");
        // SAFETY: ace points into the live DACL buffer, valid for this scope.
        let (ace_type, mask) = unsafe {
            let a = &*(ace as *mut ACCESS_ALLOWED_ACE);
            (a.Header.AceType, a.Mask)
        };
        assert_eq!(ace_type, 0x00, "ACE must be access-allowed");
        assert_eq!(
            mask, 0x0010_0002,
            "ACE must grant exactly SYNCHRONIZE | EVENT_MODIFY_STATE — the \
             two rights wait_for_ack (WaitForSingleObject) and signal_one \
             (SetEvent) actually use"
        );

        // SAFETY: ace points into the live DACL; SidStart aliases the trustee SID.
        let ace_sid = unsafe {
            let a = &*(ace as *mut ACCESS_ALLOWED_ACE);
            &a.SidStart as *const u32 as winapi::shared::minwindef::LPVOID
        };
        let current_sid = current_user_string_sid().expect("current_user_string_sid failed");
        let mut sid_pwstr: *mut u16 = std::ptr::null_mut();
        // SAFETY: ace_sid points into the live DACL buffer.
        let ok = unsafe { winapi::shared::sddl::ConvertSidToStringSidW(ace_sid, &mut sid_pwstr) };
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
            winapi::um::winbase::LocalFree(sid_pwstr as winapi::shared::minwindef::HLOCAL);
        }
        assert_eq!(
            ace_sid_str, current_sid,
            "ACE trustee must be the current user SID, not a group"
        );
    }

    /// Truth table for the S10 fatality rule: only Static × {DynamicCode(2),
    /// Signature(8)} is fatal; every other guard×policy combination degrades
    /// to a buffered, non-fatal error.
    #[test]
    fn mitigation_failure_is_fatal_truth_table() {
        for (guard, policy, fatal) in [
            (ipc::GuardLevel::None, POLICY_DYNAMIC_CODE, false),
            (ipc::GuardLevel::None, POLICY_EXTENSION_POINT_DISABLE, false),
            (ipc::GuardLevel::None, POLICY_SIGNATURE, false),
            (ipc::GuardLevel::None, POLICY_IMAGE_LOAD, false),
            (ipc::GuardLevel::Scan, POLICY_DYNAMIC_CODE, false),
            (ipc::GuardLevel::Scan, POLICY_EXTENSION_POINT_DISABLE, false),
            (ipc::GuardLevel::Scan, POLICY_SIGNATURE, false),
            (ipc::GuardLevel::Scan, POLICY_IMAGE_LOAD, false),
            (ipc::GuardLevel::Full, POLICY_DYNAMIC_CODE, false),
            (ipc::GuardLevel::Full, POLICY_EXTENSION_POINT_DISABLE, false),
            (ipc::GuardLevel::Full, POLICY_SIGNATURE, false),
            (ipc::GuardLevel::Full, POLICY_IMAGE_LOAD, false),
            (ipc::GuardLevel::Static, POLICY_DYNAMIC_CODE, true),
            (ipc::GuardLevel::Static, POLICY_EXTENSION_POINT_DISABLE, false),
            (ipc::GuardLevel::Static, POLICY_SIGNATURE, true),
            (ipc::GuardLevel::Static, POLICY_IMAGE_LOAD, false),
        ] {
            assert_eq!(
                mitigation_failure_is_fatal(guard, policy),
                fatal,
                "guard={guard} policy={policy}"
            );
        }
    }

    /// The env-var literal is a cross-crate contract with the launcher
    /// (launch_prep.rs, chunk 3); both sides pin it. Renaming it here breaks
    /// the degraded-init handshake silently — that is why the test exists.
    #[test]
    fn init_degraded_event_env_literal_is_pinned() {
        assert_eq!(INIT_DEGRADED_EVENT_ENV, "FS_SANDBOX_INIT_DEGRADED_EVENT");
    }

    #[test]
    fn root_init_event_handle_env_literal_is_pinned() {
        assert_eq!(INIT_EVENT_HANDLE_ENV, "FS_SANDBOX_INIT_EVENT");
    }

    /// The env-var literal is an in-crate contract between the spawn hook's
    /// parent side (spawn.rs env injection) and this child-side read. Both
    /// are pinned so a silent rename cannot break the handshake.
    #[test]
    fn child_init_event_env_literal_is_pinned() {
        assert_eq!(CHILD_INIT_EVENT_ENV, "FS_SANDBOX_CHILD_INIT_EVENT");
    }

    /// S02 #3: the per-child ack name must carry real entropy — two draws for
    /// the same pid must differ (a pid-derived name would let a same-session
    /// process preempt-signal the ack and fake protection), and the shape
    /// must stay Local\fs-sandbox-child-init-<pid>-<32 lowercase hex>. A
    /// short/predictable suffix would mean the RNG failed open into a
    /// fallback, which build_child_init_event_name must never do.
    #[test]
    fn child_init_event_name_is_random_per_call_and_well_formed() {
        let a = build_child_init_event_name(4242).expect("system RNG must be available");
        let b = build_child_init_event_name(4242).expect("system RNG must be available");
        assert_ne!(a, b, "two draws for the same pid must differ");
        let prefix = r"Local\fs-sandbox-child-init-4242-".to_string();
        assert!(a.starts_with(&prefix), "unexpected name shape: {a}");
        let suffix = &a[prefix.len()..];
        assert_eq!(suffix.len(), 32, "suffix must be 32 hex chars, got {suffix:?}");
        assert!(
            suffix.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "suffix must be lowercase hex: {suffix}"
        );
    }

    /// R04 F4: the seam a failed OPTIONAL-guard install reports through.
    /// Buffering a ui_guard-style install failure must flip
    /// install_errors_pending() (which signal_init_events consults to fire
    /// the launcher's FS_SANDBOX_INIT_DEGRADED_EVENT) and draining must
    /// clear it again — buffer + assert, the same seam S10 pins use.
    #[test]
    fn buffered_guard_install_failure_drives_degraded_signal_state() {
        crate::ipc_client::flush_install_errors(); // isolate from other tests
        assert!(!crate::ipc_client::install_errors_pending());
        crate::ipc_client::buffer_install_error(
            "ui_guard: detour init SendInput: simulated failure (F4 test)".into(),
        );
        assert!(
            crate::ipc_client::install_errors_pending(),
            "a buffered guard install failure must arm the degraded-init signal"
        );
        crate::ipc_client::flush_install_errors();
        assert!(!crate::ipc_client::install_errors_pending());
    }
}
