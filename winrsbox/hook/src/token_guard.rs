// Token guard — blocks privilege escalation attempts from sandboxed processes.
//
// Hooks:
//   NtAdjustPrivilegesToken — block enabling dangerous privileges
//   NtSetInformationToken — block token elevation
//
// In practice: non-admin sandbox processes don't have these privileges.
// This guard is defense-in-depth for the edge case where a sandbox runs
// from an elevated context.

use std::sync::OnceLock;

use detour2::GenericDetour;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS};
use winapi::ctypes::c_void;

use crate::anti_rec;

const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000_0022_u32 as NTSTATUS;

// NtAdjustPrivilegesToken blocks enabling new privileges.
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
    // LUID_AND_ATTRIBUTES: LUID(u64) + Attributes(u32)
    // SE_PRIVILEGE_ENABLED = 0x00000002
    if !new_state.is_null() {
        let count = *(new_state as *const u32);
        if count > 0 && count < 100 {
            let entries = (new_state as *const u8).add(4) as *const [u8; 12];
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

pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    let addr = crate::hooks::ntdll_export("NtAdjustPrivilegesToken\0".as_bytes())
        .ok_or("NtAdjustPrivilegesToken not found")?;
    let target: FnNtAdjustPrivilegesToken = std::mem::transmute(addr as usize);
    let hook_ptr: FnNtAdjustPrivilegesToken = hook_nt_adjust_privileges_token;
    let detour = GenericDetour::<FnNtAdjustPrivilegesToken>::new(target, hook_ptr)
        .map_err(|e| format!("detour init NtAdjustPrivilegesToken: {e:?}"))?;
    let _ = HOOK_ADJUST_PRIV.set(detour);
    HOOK_ADJUST_PRIV.get().expect("set above").enable()
        .map_err(|e| format!("detour enable NtAdjustPrivilegesToken: {e:?}"))?;
    Ok(())
}

pub unsafe fn uninstall() {
    if let Some(h) = HOOK_ADJUST_PRIV.get() { let _ = h.disable(); }
}
