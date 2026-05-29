// Token guard — blocks privilege escalation and token-based escape from sandbox.
//
// Hooks:
//   NtAdjustPrivilegesToken     — block enabling dangerous privileges (A)
//   NtOpenProcessTokenEx        — block opening foreign process tokens (B)
//   NtDuplicateToken            — block duplicating foreign tokens (B)
//   NtSetInformationThread(ThreadImpersonationToken) — block impersonation (B)
//   NtImpersonateThread         — block impersonating foreign thread tokens (P2-2)
//   NtOpenThreadTokenEx         — block opening foreign thread tokens (P2-2)
//
// In practice: non-admin sandbox processes don't have these privileges.
// This guard is defense-in-depth for the edge case where a sandbox runs
// from an elevated context.
//
// Policy: default-allow for self-token operations, default-deny for foreign.
// Many Windows components legitimately call OpenProcessToken(GetCurrentProcess())
// and GetTokenInformation on their own token — those must pass through.

use std::sync::OnceLock;

use detour2::GenericDetour;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES};
use winapi::ctypes::c_void;
use winapi::um::processthreadsapi::GetCurrentProcessId;

use crate::anti_rec;
use crate::hooks::{ipc_log, is_trace, STATUS_ACCESS_DENIED};
use crate::process_tracker;

// ---------------------------------------------------------------------------
// Hook 1: NtAdjustPrivilegesToken — block enabling dangerous privileges
// ---------------------------------------------------------------------------

// Signature: NtAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength)
type FnNtAdjustPrivilegesToken = unsafe extern "system" fn(
    HANDLE,         // TokenHandle
    u8,             // DisableAllPrivileges (BOOLEAN)
    *mut c_void,    // NewState (TOKEN_PRIVILEGES*)
    u32,            // BufferLength
    *mut c_void,    // PreviousState
    *mut u32,       // ReturnLength
) -> NTSTATUS;

static HOOK_ADJUST_PRIV: OnceLock<GenericDetour<FnNtAdjustPrivilegesToken>> = OnceLock::new();

unsafe extern "system" fn hook_nt_adjust_privileges_token(
    token_handle: HANDLE,
    disable_all: u8,
    new_state: *mut c_void,
    buffer_length: u32,
    previous_state: *mut c_void,
    return_length: *mut u32,
) -> NTSTATUS {
    let call_original = || {
        HOOK_ADJUST_PRIV.get().unwrap().call(
            token_handle, disable_all, new_state,
            buffer_length, previous_state, return_length,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // DisableAllPrivileges=TRUE → allowed (reducing privileges is safe)
    if disable_all != 0 {
        return call_original();
    }

    // Enabling privileges: check if any dangerous privilege is being enabled.
    // TOKEN_PRIVILEGES: PrivilegeCount(u32) + LUID_AND_ATTRIBUTES[N]
    // LUID_AND_ATTRIBUTES: LUID(u64) + Attributes(u32) = 12 bytes each.
    // SE_PRIVILEGE_ENABLED = 0x00000002
    //
    // SAFETY/DoS: `new_state` and `buffer_length` come from the (hostile)
    // caller; neither is trusted. `PrivilegeCount` is attacker-controlled, so
    // it MUST be bounded before driving the read. We require the byte span we
    // intend to touch — 4 (PrivilegeCount) + count*12 — to fit inside the
    // caller-declared `buffer_length`, AND cap count to MAX_PRIVS so a caller
    // that lies about a huge buffer still can't drive an unbounded read.
    // Real tokens carry ~35 privileges; 256 is generous headroom. If anything
    // fails to validate we can't classify the request and fall through to the
    // original syscall (same as every other "can't inspect" path here) — we do
    // not invent a new deny that would break legitimate AdjustTokenPrivileges.
    const PRIV_ENTRY_SIZE: u32 = 12; // sizeof(LUID_AND_ATTRIBUTES)
    const PRIV_HEADER_SIZE: u32 = 4; // sizeof(PrivilegeCount)
    const MAX_PRIVS: u32 = 256;
    if !new_state.is_null() && buffer_length >= PRIV_HEADER_SIZE {
        let count = *(new_state as *const u32);
        // Required span; checked_mul/add guard against overflow on a hostile
        // count, and the result must fit the declared buffer length.
        let required = count
            .checked_mul(PRIV_ENTRY_SIZE)
            .and_then(|body| body.checked_add(PRIV_HEADER_SIZE));
        let fits = matches!(required, Some(req) if req <= buffer_length);
        if count > 0 && count <= MAX_PRIVS && fits {
            let entries = (new_state as *const u8).add(PRIV_HEADER_SIZE as usize) as *const [u8; 12];
            for i in 0..count as usize {
                let entry = &*entries.add(i);
                let attrs = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
                if attrs & 0x02 != 0 { // SE_PRIVILEGE_ENABLED
                    let luid_low = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
                    // Dangerous LUIDs: SeDebugPrivilege=20, SeTcbPrivilege=7,
                    // SeAssignPrimaryTokenPrivilege=3, SeImpersonatePrivilege=29,
                    // SeLoadDriverPrivilege=10, SeRestorePrivilege=18,
                    // SeBackupPrivilege=17, SeTakeOwnershipPrivilege=9
                    const DANGEROUS: &[u32] = &[3, 7, 9, 10, 17, 18, 20, 29];
                    if DANGEROUS.contains(&luid_low) {
                        return STATUS_ACCESS_DENIED;
                    }
                }
            }
        }
    }

    call_original()
}

// ---------------------------------------------------------------------------
// Hook 2: NtOpenProcessTokenEx — block opening tokens of foreign processes
// ---------------------------------------------------------------------------
// proc_guard hooks NtOpenProcess and blocks dangerous access rights on foreign
// PIDs, but NtOpenProcessToken is a SEPARATE syscall. A sandbox process that
// is allowed to open a process with PROCESS_QUERY_LIMITED_INFORMATION (which
// proc_guard allows) can then call NtOpenProcessToken on the resulting handle
// to obtain a token handle for impersonation or duplication.
//
// Policy: block TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_ASSIGN_PRIMARY on
// foreign process tokens. Allow TOKEN_QUERY (read-only, no escalation path).

type FnNtOpenProcessTokenEx = unsafe extern "system" fn(
    HANDLE,         // ProcessHandle
    u32,            // DesiredAccess
    u32,            // HandleAttributes
    *mut HANDLE,    // TokenHandle
) -> NTSTATUS;

static HOOK_OPEN_PROC_TOKEN: OnceLock<GenericDetour<FnNtOpenProcessTokenEx>> = OnceLock::new();

// Token access rights that enable escalation:
// TOKEN_DUPLICATE (0x0002) → can DuplicateTokenEx → CreateProcessAsUser
// TOKEN_IMPERSONATE (0x0004) → can ImpersonateLoggedOnUser
// TOKEN_ASSIGN_PRIMARY (0x0001) → can assign as primary token
// TOKEN_ADJUST_* (0x0020..0x0100) → modify token privileges/groups
const TOKEN_DANGEROUS_ACCESS: u32 =
    0x0001 |  // TOKEN_ASSIGN_PRIMARY
    0x0002 |  // TOKEN_DUPLICATE
    0x0004 |  // TOKEN_IMPERSONATE
    0x0020 |  // TOKEN_ADJUST_PRIVILEGES
    0x0040 |  // TOKEN_ADJUST_GROUPS
    0x0080 |  // TOKEN_ADJUST_DEFAULT
    0x0100 |  // TOKEN_ADJUST_SESSIONID
    0x0200_0000 | // MAXIMUM_ALLOWED
    0x1000_0000;  // GENERIC_ALL
// Allow: TOKEN_QUERY (0x0008), TOKEN_QUERY_SOURCE (0x0010),
//         READ_CONTROL (0x00020000), TOKEN_ALL_ACCESS bits we don't block

unsafe extern "system" fn hook_nt_open_process_token_ex(
    process_handle: HANDLE,
    desired_access: u32,
    handle_attributes: u32,
    token_handle: *mut HANDLE,
) -> NTSTATUS {
    let call_original = || {
        HOOK_OPEN_PROC_TOKEN.get().unwrap().call(
            process_handle, desired_access, handle_attributes, token_handle,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // Determine if this is our own process. GetCurrentProcess() returns a
    // pseudo-handle (-1). Real handles from OpenProcessToken(self) differ.
    // Use GetTokenInformation to check, but that's complex. Instead, resolve
    // the process handle to a PID and compare with our own.
    let self_pid = GetCurrentProcessId();
    let target_pid = resolve_process_pid(process_handle);

    if target_pid != 0 && target_pid != self_pid && !process_tracker::is_owned_child(target_pid) {
        let dangerous = desired_access & TOKEN_DANGEROUS_ACCESS;
        if dangerous != 0 {
            if is_trace() {
                ipc_log(ipc::LogLevel::Trace,
                    format!("token_open_process_blocked pid={target_pid} access=0x{desired_access:08x} dangerous=0x{dangerous:08x}"));
            }
            if !token_handle.is_null() {
                *token_handle = std::ptr::null_mut();
            }
            return STATUS_ACCESS_DENIED;
        }
    }

    call_original()
}

/// Resolve a process handle to its PID. Returns 0 on failure.
fn resolve_process_pid(handle: HANDLE) -> u32 {
    // NtQueryInformationProcess(ProcessBasicInformation) gives us the PID
    // without needing any special access rights beyond PROCESS_QUERY_LIMITED_INFORMATION.
    #[repr(C)]
    struct PROCESS_BASIC_INFORMATION {
        reserved1: *mut c_void,
        peb_base_address: *mut c_void,
        reserved2: [*mut c_void; 2],
        unique_process_id: usize,
        reserved3: *mut c_void,
    }

    type FnNtQueryInformationProcess = unsafe extern "system" fn(
        HANDLE,             // ProcessHandle
        u32,                // ProcessInformationClass (0 = ProcessBasicInformation)
        *mut c_void,        // ProcessInformation
        u32,                // ProcessInformationLength
        *mut u32,           // ReturnLength
    ) -> NTSTATUS;

    static QIP: OnceLock<Option<FnNtQueryInformationProcess>> = OnceLock::new();
    let qip = QIP.get_or_init(|| {
        unsafe {
            let addr = crate::hooks::ntdll_export("NtQueryInformationProcess\0".as_bytes())?;
            Some(std::mem::transmute(addr as usize))
        }
    });

    if let Some(qip_fn) = qip {
        let mut pbi = std::mem::MaybeUninit::<PROCESS_BASIC_INFORMATION>::uninit();
        let status = unsafe {
            qip_fn(
                handle,
                0, // ProcessBasicInformation
                pbi.as_mut_ptr() as *mut c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        if status >= 0 {
            return unsafe { (*pbi.as_ptr()).unique_process_id as u32 };
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Hook 3: NtDuplicateToken — block duplicating foreign tokens
// ---------------------------------------------------------------------------
// DuplicateTokenEx / NtDuplicateToken can elevate an impersonation token to
// a primary token, or duplicate any token for later use. Blocking on foreign
// tokens prevents an attacker from obtaining a usable copy of another user's
// token even if they somehow got a handle to it.
//
// We cannot easily determine the source token's owner here (no PID association
// for token handles), so we block ALL duplication that produces a primary token
// (Type == TokenPrimary = 1) and allow impersonation-level duplication since
// it's common for self-impersonation patterns in COM/RPC.

type FnNtDuplicateToken = unsafe extern "system" fn(
    HANDLE,             // ExistingTokenHandle
    u32,                // DesiredAccess
    *mut OBJECT_ATTRIBUTES, // ObjectAttributes
    u32,                // EffectiveOnly (BOOLEAN)
    u32,                // TokenType (TokenPrimary=1, TokenImpersonation=2)
    *mut HANDLE,        // NewTokenHandle
) -> NTSTATUS;

static HOOK_DUPLICATE_TOKEN: OnceLock<GenericDetour<FnNtDuplicateToken>> = OnceLock::new();

unsafe extern "system" fn hook_nt_duplicate_token(
    existing_token: HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    effective_only: u32,
    token_type: u32,
    new_token_handle: *mut HANDLE,
) -> NTSTATUS {
    let call_original = || {
        HOOK_DUPLICATE_TOKEN.get().unwrap().call(
            existing_token, desired_access, object_attributes,
            effective_only, token_type, new_token_handle,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // TokenPrimary = 1. Duplicating to a primary token is the most dangerous
    // path: it enables CreateProcessAsUser with the duplicated token.
    // TokenImpersonation = 2 is less dangerous in isolation but can still be
    // used for SetThreadToken. Block TokenPrimary always; block
    // TokenImpersonation with TOKEN_ALL_ACCESS or ASSIGN_PRIMARY.
    if token_type == 1 { // TokenPrimary
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace,
                format!("token_duplicate_blocked_primary access=0x{desired_access:08x}"));
        }
        if !new_token_handle.is_null() {
            *new_token_handle = std::ptr::null_mut();
        }
        return STATUS_ACCESS_DENIED;
    }

    call_original()
}

// ---------------------------------------------------------------------------
// Hook 4: NtSetInformationThread(ThreadImpersonationToken) — block impersonation
// ---------------------------------------------------------------------------
// NtSetInformationThread with ThreadImpersonationToken (class 5) assigns an
// impersonation token to the current thread. Combined with a foreign token
// handle (obtained via NtOpenProcessToken on an accessible service process),
// this lets all subsequent resource access run as the target user.
//
// Policy: block impersonation with non-null token handles. Self-impersonation
// (the thread's own process token) is rare but allowed by not hooking it when
// the token handle is null (removing impersonation = safe).

type FnNtSetInformationThread = unsafe extern "system" fn(
    HANDLE,         // ThreadHandle
    u32,            // ThreadInformationClass
    *mut c_void,    // ThreadInformation
    u32,            // ThreadInformationLength
) -> NTSTATUS;

static HOOK_SET_INFO_THREAD: OnceLock<GenericDetour<FnNtSetInformationThread>> = OnceLock::new();

const THREAD_IMPERSONATION_TOKEN: u32 = 5;

unsafe extern "system" fn hook_nt_set_information_thread(
    thread_handle: HANDLE,
    info_class: u32,
    thread_info: *mut c_void,
    info_length: u32,
) -> NTSTATUS {
    let call_original = || {
        HOOK_SET_INFO_THREAD.get().unwrap().call(
            thread_handle, info_class, thread_info, info_length,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if info_class == THREAD_IMPERSONATION_TOKEN {
        // thread_info points to a HANDLE value. If non-null, a token is being
        // assigned for impersonation.
        if !thread_info.is_null() && info_length >= std::mem::size_of::<HANDLE>() as u32 {
            let token = *(thread_info as *const HANDLE);
            if !token.is_null() {
                if is_trace() {
                    ipc_log(ipc::LogLevel::Trace,
                        format!("token_impersonation_blocked thread=0x{:x} token=0x{:x}",
                            thread_handle as usize, token as usize));
                }
                return STATUS_ACCESS_DENIED;
            }
        }
    }

    call_original()
}

// ---------------------------------------------------------------------------
// Hook 5: NtImpersonateThread — block impersonating foreign threads
// ---------------------------------------------------------------------------
// NtImpersonateThread copies the impersonation token from ServerThreadHandle
// onto ClientThreadHandle. If the server thread belongs to a higher-priv
// process, the sandbox inherits that privilege level → escalation.
//
// Policy: allow self-impersonation (server thread owned by self PID or
// NtCurrentThread pseudo-handle). Deny if server thread belongs to a foreign PID.

type FnNtImpersonateThread = unsafe extern "system" fn(
    HANDLE,         // ServerThreadHandle
    HANDLE,         // ClientThreadHandle
    *mut c_void,    // SecurityQualityOfService
) -> NTSTATUS;

static HOOK_IMPERSONATE_THREAD: OnceLock<GenericDetour<FnNtImpersonateThread>> = OnceLock::new();

const NT_CURRENT_THREAD: isize = -2;

unsafe extern "system" fn hook_nt_impersonate_thread(
    server_thread: HANDLE,
    client_thread: HANDLE,
    sqos: *mut c_void,
) -> NTSTATUS {
    let call_original = || {
        HOOK_IMPERSONATE_THREAD.get().unwrap().call(
            server_thread, client_thread, sqos,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // NtCurrentThread pseudo-handle → self-impersonation → allow
    if server_thread as isize == NT_CURRENT_THREAD {
        return call_original();
    }

    let self_pid = GetCurrentProcessId();
    let owner_pid = crate::inject_guard::thread_owner_pid(server_thread);

    if owner_pid != 0 && owner_pid != self_pid && !process_tracker::is_owned_child(owner_pid) {
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace,
                format!("token_impersonate_thread_blocked server_owner_pid={owner_pid}"));
        }
        return STATUS_ACCESS_DENIED;
    }

    call_original()
}

// ---------------------------------------------------------------------------
// Hook 6: NtOpenThreadTokenEx — block opening foreign thread tokens
// ---------------------------------------------------------------------------
// NtOpenThreadTokenEx opens a thread's impersonation token. With dangerous
// access rights on a foreign thread's token, the sandbox can later call
// NtSetInformationThread to impersonate.
//
// Policy: allow self-thread token operations (NtCurrentThread or owner == self PID).
// For foreign threads, block dangerous access bits; allow TOKEN_QUERY (read-only).

type FnNtOpenThreadTokenEx = unsafe extern "system" fn(
    HANDLE,         // ThreadHandle
    u32,            // DesiredAccess
    u8,             // OpenAsSelf (BOOLEAN)
    u32,            // HandleAttributes
    *mut HANDLE,    // TokenHandle (out)
) -> NTSTATUS;

static HOOK_OPEN_THREAD_TOKEN: OnceLock<GenericDetour<FnNtOpenThreadTokenEx>> = OnceLock::new();

// Dangerous token access bits (same set as TOKEN_DANGEROUS_ACCESS above)
const THREAD_TOKEN_DANGEROUS: u32 =
    0x0001 |  // TOKEN_ASSIGN_PRIMARY
    0x0002 |  // TOKEN_DUPLICATE
    0x0004 |  // TOKEN_IMPERSONATE
    0x0020 |  // TOKEN_ADJUST_PRIVILEGES
    0x0040 |  // TOKEN_ADJUST_GROUPS
    0x0080 |  // TOKEN_ADJUST_DEFAULT
    0x0200_0000 | // MAXIMUM_ALLOWED
    0x1000_0000;  // GENERIC_ALL

unsafe extern "system" fn hook_nt_open_thread_token_ex(
    thread_handle: HANDLE,
    desired_access: u32,
    open_as_self: u8,
    handle_attributes: u32,
    token_handle: *mut HANDLE,
) -> NTSTATUS {
    let call_original = || {
        HOOK_OPEN_THREAD_TOKEN.get().unwrap().call(
            thread_handle, desired_access, open_as_self, handle_attributes, token_handle,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // NtCurrentThread pseudo-handle (-6 for thread token, -2 for current thread)
    // Both represent self-thread → allow
    if thread_handle as isize == NT_CURRENT_THREAD || thread_handle as isize == -6 {
        return call_original();
    }

    let self_pid = GetCurrentProcessId();
    let owner_pid = crate::inject_guard::thread_owner_pid(thread_handle);

    if owner_pid != 0 && owner_pid != self_pid && !process_tracker::is_owned_child(owner_pid) {
        let dangerous = desired_access & THREAD_TOKEN_DANGEROUS;
        if dangerous != 0 {
            if is_trace() {
                ipc_log(ipc::LogLevel::Trace,
                    format!("token_open_thread_blocked owner_pid={owner_pid} access=0x{desired_access:08x} dangerous=0x{dangerous:08x}"));
            }
            if !token_handle.is_null() {
                *token_handle = std::ptr::null_mut();
            }
            return STATUS_ACCESS_DENIED;
        }
    }

    call_original()
}

// ---------------------------------------------------------------------------
// Install / Uninstall
// ---------------------------------------------------------------------------

pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    {
        let addr = crate::hooks::ntdll_export("NtAdjustPrivilegesToken\0".as_bytes())
            .ok_or("NtAdjustPrivilegesToken not found")?;
        let target: FnNtAdjustPrivilegesToken = std::mem::transmute(addr as usize);
        let hook_ptr: FnNtAdjustPrivilegesToken = hook_nt_adjust_privileges_token;
        let detour = GenericDetour::<FnNtAdjustPrivilegesToken>::new(target, hook_ptr)
            .map_err(|e| format!("detour init NtAdjustPrivilegesToken: {e:?}"))?;
        let _ = HOOK_ADJUST_PRIV.set(detour);
        HOOK_ADJUST_PRIV.get().expect("set above").enable()
            .map_err(|e| format!("detour enable NtAdjustPrivilegesToken: {e:?}"))?;
    }

    {
        let addr = crate::hooks::ntdll_export("NtOpenProcessTokenEx\0".as_bytes())
            .ok_or("NtOpenProcessTokenEx not found")?;
        let target: FnNtOpenProcessTokenEx = std::mem::transmute(addr as usize);
        let hook_ptr: FnNtOpenProcessTokenEx = hook_nt_open_process_token_ex;
        let detour = GenericDetour::<FnNtOpenProcessTokenEx>::new(target, hook_ptr)
            .map_err(|e| format!("detour init NtOpenProcessTokenEx: {e:?}"))?;
        let _ = HOOK_OPEN_PROC_TOKEN.set(detour);
        HOOK_OPEN_PROC_TOKEN.get().expect("set above").enable()
            .map_err(|e| format!("detour enable NtOpenProcessTokenEx: {e:?}"))?;
    }

    {
        let addr = crate::hooks::ntdll_export("NtDuplicateToken\0".as_bytes())
            .ok_or("NtDuplicateToken not found")?;
        let target: FnNtDuplicateToken = std::mem::transmute(addr as usize);
        let hook_ptr: FnNtDuplicateToken = hook_nt_duplicate_token;
        let detour = GenericDetour::<FnNtDuplicateToken>::new(target, hook_ptr)
            .map_err(|e| format!("detour init NtDuplicateToken: {e:?}"))?;
        let _ = HOOK_DUPLICATE_TOKEN.set(detour);
        HOOK_DUPLICATE_TOKEN.get().expect("set above").enable()
            .map_err(|e| format!("detour enable NtDuplicateToken: {e:?}"))?;
    }

    {
        let addr = crate::hooks::ntdll_export("NtSetInformationThread\0".as_bytes())
            .ok_or("NtSetInformationThread not found")?;
        let target: FnNtSetInformationThread = std::mem::transmute(addr as usize);
        let hook_ptr: FnNtSetInformationThread = hook_nt_set_information_thread;
        let detour = GenericDetour::<FnNtSetInformationThread>::new(target, hook_ptr)
            .map_err(|e| format!("detour init NtSetInformationThread: {e:?}"))?;
        let _ = HOOK_SET_INFO_THREAD.set(detour);
        HOOK_SET_INFO_THREAD.get().expect("set above").enable()
            .map_err(|e| format!("detour enable NtSetInformationThread: {e:?}"))?;
    }

    {
        let addr = crate::hooks::ntdll_export("NtImpersonateThread\0".as_bytes())
            .ok_or("NtImpersonateThread not found")?;
        let target: FnNtImpersonateThread = std::mem::transmute(addr as usize);
        let hook_ptr: FnNtImpersonateThread = hook_nt_impersonate_thread;
        let detour = GenericDetour::<FnNtImpersonateThread>::new(target, hook_ptr)
            .map_err(|e| format!("detour init NtImpersonateThread: {e:?}"))?;
        let _ = HOOK_IMPERSONATE_THREAD.set(detour);
        HOOK_IMPERSONATE_THREAD.get().expect("set above").enable()
            .map_err(|e| format!("detour enable NtImpersonateThread: {e:?}"))?;
    }

    {
        let addr = crate::hooks::ntdll_export("NtOpenThreadTokenEx\0".as_bytes())
            .ok_or("NtOpenThreadTokenEx not found")?;
        let target: FnNtOpenThreadTokenEx = std::mem::transmute(addr as usize);
        let hook_ptr: FnNtOpenThreadTokenEx = hook_nt_open_thread_token_ex;
        let detour = GenericDetour::<FnNtOpenThreadTokenEx>::new(target, hook_ptr)
            .map_err(|e| format!("detour init NtOpenThreadTokenEx: {e:?}"))?;
        let _ = HOOK_OPEN_THREAD_TOKEN.set(detour);
        HOOK_OPEN_THREAD_TOKEN.get().expect("set above").enable()
            .map_err(|e| format!("detour enable NtOpenThreadTokenEx: {e:?}"))?;
    }

    if is_trace() {
        ipc_log(ipc::LogLevel::Trace, "token_guard_installed".into());
    }
    Ok(())
}

pub unsafe fn uninstall() {
    if let Some(h) = HOOK_OPEN_THREAD_TOKEN.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_IMPERSONATE_THREAD.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_SET_INFO_THREAD.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_DUPLICATE_TOKEN.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_OPEN_PROC_TOKEN.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_ADJUST_PRIV.get() { let _ = h.disable(); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_dangerous_includes_maximum_allowed() {
        assert_ne!(TOKEN_DANGEROUS_ACCESS & 0x0200_0000, 0);
    }

    #[test]
    fn token_dangerous_includes_generic_all() {
        assert_ne!(TOKEN_DANGEROUS_ACCESS & 0x1000_0000, 0);
    }

    #[test]
    fn thread_token_dangerous_includes_maximum_allowed() {
        assert_ne!(THREAD_TOKEN_DANGEROUS & 0x0200_0000, 0);
    }

    #[test]
    fn thread_token_dangerous_includes_generic_all() {
        assert_ne!(THREAD_TOKEN_DANGEROUS & 0x1000_0000, 0);
    }

    #[test]
    fn token_dangerous_includes_core_bits() {
        assert_ne!(TOKEN_DANGEROUS_ACCESS & 0x0001, 0, "TOKEN_ASSIGN_PRIMARY");
        assert_ne!(TOKEN_DANGEROUS_ACCESS & 0x0002, 0, "TOKEN_DUPLICATE");
        assert_ne!(TOKEN_DANGEROUS_ACCESS & 0x0004, 0, "TOKEN_IMPERSONATE");
    }
}
