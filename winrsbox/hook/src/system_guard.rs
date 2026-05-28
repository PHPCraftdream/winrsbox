// System guard — blocks NtShutdownSystem, NtSetSystemInformation,
// NtCreateDebugObject, NtRaiseHardError, NtCreateSymbolicLinkObject,
// NtLoadDriver, and NtUnloadDriver.
//
// Escape vectors:
//   * AI-agent calls NtShutdownSystem(ShutdownReboot) or
//     NtSetSystemInformation(SystemLoadGdt, ...) to modify kernel state.
//   * NtRaiseHardError(OptionShutdownSystem=6) can trigger BSOD/forced logoff.
//     Even though SeShutdownPrivilege / SeTcbPrivilege are blocked via
//     token_guard, defense-in-depth: unconditional STATUS_ACCESS_DENIED.
//   * NtCreateSymbolicLinkObject (Object Manager symlink forge, H-S1):
//     a child can create per-session object-manager symlinks (no privilege
//     required for \Sessions\<n>\BaseNamedObjects and \Sessions\<n>\
//     DosDevices\<luid>). Forging \??\C: → \??\D:\overlay\C: redirects
//     subsequent kernel path resolution, including from our own hooks.
//     Unconditional STATUS_ACCESS_DENIED.
//   * NtLoadDriver / NtUnloadDriver (BYOVD, S4): if the sandbox is launched
//     elevated and the inherited token already has SeLoadDriverPrivilege
//     enabled, token_guard's "block enable" defence is moot. A child can
//     point at an installed service key for a known-vulnerable signed driver
//     (dbutil_2_3.sys, gdrv.sys, RTCore64.sys, ...) and gain kernel code
//     execution. Unconditional STATUS_PRIVILEGE_NOT_HELD — the caller will
//     interpret it as "your token lacks the privilege" and stop retrying.
//
// Hook targets: ntdll.dll!NtShutdownSystem, ntdll.dll!NtSetSystemInformation,
//               ntdll.dll!NtCreateDebugObject, ntdll.dll!NtRaiseHardError,
//               ntdll.dll!NtCreateSymbolicLinkObject,
//               ntdll.dll!NtLoadDriver, ntdll.dll!NtUnloadDriver.

use std::sync::OnceLock;

use detour2::GenericDetour;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES, UNICODE_STRING};
use winapi::ctypes::c_void;

use crate::anti_rec;
use crate::hooks::{
    buffer_install_error, ipc_log, is_trace, ntdll_export,
    STATUS_ACCESS_DENIED, STATUS_PRIVILEGE_NOT_HELD,
};

/// Cap on WCHARs decoded from a UNICODE_STRING for diagnostic logging.
/// Sanity bound — a malicious caller could publish a UNICODE_STRING with
/// a wild `.Length`; clamp before slicing so we never deref attacker-chosen
/// gigabytes of memory just to print a trace line.
const MAX_USTR_CHARS: usize = 4096;

/// Defensive extractor for a `*PUNICODE_STRING` argument.
///
/// Returns the decoded string (lossy UTF-16 → UTF-8) or `"<null>"` /
/// `"<empty>"` placeholders. Truncates at `MAX_USTR_CHARS`.
///
/// # SAFETY
/// `p` may be null or dangling. If non-null, the caller must ensure the
/// pointer was valid at NT-API entry (which is what ntdll guarantees for
/// hook entry points). `Buffer` may itself be null.
unsafe fn extract_unicode_string(p: *const UNICODE_STRING) -> String {
    if p.is_null() {
        return "<null>".to_string();
    }
    // SAFETY: caller asserts `p` is a valid UNICODE_STRING pointer.
    let ustr = &*p;
    if ustr.Buffer.is_null() {
        return "<empty>".to_string();
    }
    let char_count = (ustr.Length as usize) / 2;
    if char_count == 0 {
        return "<empty>".to_string();
    }
    let bounded = char_count.min(MAX_USTR_CHARS);
    // SAFETY: from_raw_parts for `bounded` WCHARs from UNICODE_STRING.Buffer;
    // bounded ≤ Length/2 and ≤ MAX_USTR_CHARS, so the region is in-bounds.
    let slice = std::slice::from_raw_parts(ustr.Buffer, bounded);
    String::from_utf16_lossy(slice)
}

type FnNtShutdownSystem = unsafe extern "system" fn(u32) -> NTSTATUS;
type FnNtSetSystemInformation = unsafe extern "system" fn(u32, *mut c_void, u32) -> NTSTATUS;
type FnNtCreateDebugObject = unsafe extern "system" fn(
    *mut HANDLE,              // DebugObjectHandle (out)
    u32,                       // DesiredAccess (ACCESS_MASK)
    *const OBJECT_ATTRIBUTES,  // ObjectAttributes
    u32,                       // Flags
) -> NTSTATUS;
type FnNtRaiseHardError = unsafe extern "system" fn(
    NTSTATUS,       // ErrorStatus
    u32,            // NumberOfParameters
    u32,            // UnicodeStringParameterMask
    *mut usize,     // Parameters (PULONG_PTR)
    u32,            // ValidResponseOptions (OptionShutdownSystem=6 is dangerous)
    *mut u32,       // Response (out)
) -> NTSTATUS;
type FnNtCreateSymbolicLinkObject = unsafe extern "system" fn(
    *mut HANDLE,              // LinkHandle (out)
    u32,                       // DesiredAccess (ACCESS_MASK)
    *const OBJECT_ATTRIBUTES,  // ObjectAttributes
    *const UNICODE_STRING,     // LinkTarget
) -> NTSTATUS;
type FnNtLoadDriver = unsafe extern "system" fn(
    *const UNICODE_STRING,     // DriverServiceName
) -> NTSTATUS;
type FnNtUnloadDriver = unsafe extern "system" fn(
    *const UNICODE_STRING,     // DriverServiceName
) -> NTSTATUS;

static HOOK_SHUTDOWN: OnceLock<GenericDetour<FnNtShutdownSystem>> = OnceLock::new();
static HOOK_SET_SYS_INFO: OnceLock<GenericDetour<FnNtSetSystemInformation>> = OnceLock::new();
static HOOK_CREATE_DEBUG_OBJ: OnceLock<GenericDetour<FnNtCreateDebugObject>> = OnceLock::new();
static HOOK_RAISE_HARD_ERROR: OnceLock<GenericDetour<FnNtRaiseHardError>> = OnceLock::new();
static HOOK_CREATE_SYMLINK_OBJ: OnceLock<GenericDetour<FnNtCreateSymbolicLinkObject>> = OnceLock::new();
static HOOK_LOAD_DRIVER: OnceLock<GenericDetour<FnNtLoadDriver>> = OnceLock::new();
static HOOK_UNLOAD_DRIVER: OnceLock<GenericDetour<FnNtUnloadDriver>> = OnceLock::new();

// SAFETY: Called by detour2 dispatcher with ntdll!NtShutdownSystem ABI.
unsafe extern "system" fn hook_nt_shutdown_system(action: u32) -> NTSTATUS {
    let call_original = || {
        // SAFETY: detour2 trampoline matches FnNtShutdownSystem ABI.
        HOOK_SHUTDOWN.get().unwrap().call(action)
    };
    let Some(_g) = anti_rec::enter() else { return call_original(); };
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace,
            format!("sys_shutdown_blocked action={}", action));
    }
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with ntdll!NtSetSystemInformation ABI.
unsafe extern "system" fn hook_nt_set_system_information(
    class: u32, info: *mut c_void, len: u32,
) -> NTSTATUS {
    let call_original = || {
        // SAFETY: detour2 trampoline matches FnNtSetSystemInformation ABI.
        HOOK_SET_SYS_INFO.get().unwrap().call(class, info, len)
    };
    let Some(_g) = anti_rec::enter() else { return call_original(); };
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace,
            format!("sys_setinfo_blocked class={} len={}", class, len));
    }
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with ntdll!NtCreateDebugObject ABI.
unsafe extern "system" fn hook_nt_create_debug_object(
    handle: *mut HANDLE,
    access: u32,
    attrs: *const OBJECT_ATTRIBUTES,
    flags: u32,
) -> NTSTATUS {
    let call_original = || {
        // SAFETY: detour2 trampoline matches FnNtCreateDebugObject ABI.
        HOOK_CREATE_DEBUG_OBJ.get().unwrap().call(handle, access, attrs, flags)
    };
    let Some(_g) = anti_rec::enter() else { return call_original(); };
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace,
            format!("sys_debug_obj_blocked access=0x{:x} flags=0x{:x}", access, flags));
    }
    if !handle.is_null() {
        *handle = std::ptr::null_mut();
    }
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with ntdll!NtRaiseHardError ABI.
unsafe extern "system" fn hook_nt_raise_hard_error(
    error_status: NTSTATUS,
    num_params: u32,
    unicode_mask: u32,
    params: *mut usize,
    response_option: u32,
    response: *mut u32,
) -> NTSTATUS {
    let call_original = || {
        // SAFETY: detour2 trampoline matches FnNtRaiseHardError ABI.
        HOOK_RAISE_HARD_ERROR.get().unwrap().call(
            error_status, num_params, unicode_mask, params, response_option, response)
    };
    let Some(_g) = anti_rec::enter() else { return call_original(); };
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace,
            format!("sys_raise_hard_error_blocked status=0x{:x} option={}", error_status as u32, response_option));
    }
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with ntdll!NtCreateSymbolicLinkObject ABI.
//
// Defends against Object Manager symlink forge (H-S1). A child can create
// per-session symlinks under \Sessions\<n>\BaseNamedObjects and
// \Sessions\<n>\DosDevices\<luid> without any privilege; forging
// \??\C: → \??\D:\overlay\C: redirects subsequent kernel path resolution
// — including from our own hooks that re-resolve DOS paths to NT paths.
// AI-agent CLIs (Node/Python/Rust toolchains) never legitimately create
// object-manager symlinks, so deny unconditionally.
unsafe extern "system" fn hook_nt_create_symbolic_link_object(
    link_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    link_target: *const UNICODE_STRING,
) -> NTSTATUS {
    let call_original = || {
        // SAFETY: detour2 trampoline matches FnNtCreateSymbolicLinkObject ABI.
        HOOK_CREATE_SYMLINK_OBJ.get().unwrap().call(
            link_handle, desired_access, object_attributes, link_target)
    };
    let Some(_g) = anti_rec::enter() else { return call_original(); };
    if is_trace() {
        // SAFETY: extract_unicode_string is defensive against null / empty / bogus Length.
        let target = extract_unicode_string(link_target);
        ipc_log(ipc::LogLevel::Trace,
            format!("symlink_create_blocked: {target}"));
    }
    if !link_handle.is_null() {
        *link_handle = std::ptr::null_mut();
    }
    let _ = desired_access;
    let _ = object_attributes;
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with ntdll!NtLoadDriver ABI.
//
// Defends against BYOVD (Bring-Your-Own-Vulnerable-Driver, S4). token_guard
// blocks the AdjustTokenPrivileges path that *enables* SeLoadDriverPrivilege,
// but if the sandbox is launched from an elevated parent and the privilege
// is already enabled in the inherited token, NtLoadDriver(DriverServiceName)
// succeeds and the child gains kernel code execution via a known-vulnerable
// signed driver (dbutil_2_3.sys, gdrv.sys, RTCore64.sys, ...). Return
// STATUS_PRIVILEGE_NOT_HELD — the caller will interpret it as "your token
// lacks the privilege" and stop retrying instead of attempting workarounds.
unsafe extern "system" fn hook_nt_load_driver(
    driver_service_name: *const UNICODE_STRING,
) -> NTSTATUS {
    let call_original = || {
        // SAFETY: detour2 trampoline matches FnNtLoadDriver ABI.
        HOOK_LOAD_DRIVER.get().unwrap().call(driver_service_name)
    };
    let Some(_g) = anti_rec::enter() else { return call_original(); };
    if is_trace() {
        // SAFETY: extract_unicode_string is defensive against null / empty / bogus Length.
        let name = extract_unicode_string(driver_service_name);
        ipc_log(ipc::LogLevel::Trace,
            format!("driver_load_blocked: {name}"));
    }
    STATUS_PRIVILEGE_NOT_HELD
}

// SAFETY: Called by detour2 dispatcher with ntdll!NtUnloadDriver ABI.
//
// Hooked for symmetry with NtLoadDriver. An attacker who somehow loaded
// a "watchdog" driver (e.g. via a parallel exploit) could otherwise unload
// it from inside the sandbox; deny unconditionally for the same reason.
unsafe extern "system" fn hook_nt_unload_driver(
    driver_service_name: *const UNICODE_STRING,
) -> NTSTATUS {
    let call_original = || {
        // SAFETY: detour2 trampoline matches FnNtUnloadDriver ABI.
        HOOK_UNLOAD_DRIVER.get().unwrap().call(driver_service_name)
    };
    let Some(_g) = anti_rec::enter() else { return call_original(); };
    if is_trace() {
        // SAFETY: extract_unicode_string is defensive against null / empty / bogus Length.
        let name = extract_unicode_string(driver_service_name);
        ipc_log(ipc::LogLevel::Trace,
            format!("driver_unload_blocked: {name}"));
    }
    STATUS_PRIVILEGE_NOT_HELD
}

/// # SAFETY
/// Must be called from install_hooks() in DllMain context with anti_rec entered.
pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    // NtShutdownSystem
    if let Some(addr) = ntdll_export("NtShutdownSystem\0".as_bytes()) {
        // SAFETY: transmute of ntdll export address; ABI matches FnNtShutdownSystem.
        let target: FnNtShutdownSystem = std::mem::transmute(addr as usize);
        let hook_ptr: FnNtShutdownSystem = hook_nt_shutdown_system;
        let detour = GenericDetour::<FnNtShutdownSystem>::new(target, hook_ptr)
            .map_err(|e| format!("detour init NtShutdownSystem: {:?}", e))?;
        HOOK_SHUTDOWN.set(detour).ok();
        HOOK_SHUTDOWN.get().expect("set above").enable()
            .map_err(|e| format!("detour enable NtShutdownSystem: {:?}", e))?;
    } else {
        ipc_log(ipc::LogLevel::Warn,
            "system_guard: ntdll export NtShutdownSystem not found".into());
    }

    // NtSetSystemInformation
    if let Some(addr) = ntdll_export("NtSetSystemInformation\0".as_bytes()) {
        // SAFETY: transmute of ntdll export address; ABI matches FnNtSetSystemInformation.
        let target: FnNtSetSystemInformation = std::mem::transmute(addr as usize);
        let hook_ptr: FnNtSetSystemInformation = hook_nt_set_system_information;
        let detour = GenericDetour::<FnNtSetSystemInformation>::new(target, hook_ptr)
            .map_err(|e| format!("detour init NtSetSystemInformation: {:?}", e))?;
        HOOK_SET_SYS_INFO.set(detour).ok();
        HOOK_SET_SYS_INFO.get().expect("set above").enable()
            .map_err(|e| format!("detour enable NtSetSystemInformation: {:?}", e))?;
    } else {
        ipc_log(ipc::LogLevel::Warn,
            "system_guard: ntdll export NtSetSystemInformation not found".into());
    }

    // NtCreateDebugObject
    if let Some(addr) = ntdll_export("NtCreateDebugObject\0".as_bytes()) {
        // SAFETY: transmute of ntdll export address; ABI matches FnNtCreateDebugObject.
        let target: FnNtCreateDebugObject = std::mem::transmute(addr as usize);
        let hook_ptr: FnNtCreateDebugObject = hook_nt_create_debug_object;
        let detour = GenericDetour::<FnNtCreateDebugObject>::new(target, hook_ptr)
            .map_err(|e| format!("detour init NtCreateDebugObject: {:?}", e))?;
        HOOK_CREATE_DEBUG_OBJ.set(detour).ok();
        HOOK_CREATE_DEBUG_OBJ.get().expect("set above").enable()
            .map_err(|e| format!("detour enable NtCreateDebugObject: {:?}", e))?;
    } else {
        ipc_log(ipc::LogLevel::Warn,
            "system_guard: ntdll export NtCreateDebugObject not found".into());
    }

    // NtRaiseHardError
    if let Some(addr) = ntdll_export("NtRaiseHardError\0".as_bytes()) {
        // SAFETY: transmute of ntdll export address; ABI matches FnNtRaiseHardError.
        let target: FnNtRaiseHardError = std::mem::transmute(addr as usize);
        let hook_ptr: FnNtRaiseHardError = hook_nt_raise_hard_error;
        let detour = GenericDetour::<FnNtRaiseHardError>::new(target, hook_ptr)
            .map_err(|e| format!("detour init NtRaiseHardError: {:?}", e))?;
        HOOK_RAISE_HARD_ERROR.set(detour).ok();
        HOOK_RAISE_HARD_ERROR.get().expect("set above").enable()
            .map_err(|e| format!("detour enable NtRaiseHardError: {:?}", e))?;
    } else {
        ipc_log(ipc::LogLevel::Warn,
            "system_guard: ntdll export NtRaiseHardError not found".into());
    }

    // NtCreateSymbolicLinkObject — Object Manager symlink forge defence (H-S1).
    if let Some(addr) = ntdll_export("NtCreateSymbolicLinkObject\0".as_bytes()) {
        // SAFETY: transmute of ntdll export address; ABI matches FnNtCreateSymbolicLinkObject.
        let target: FnNtCreateSymbolicLinkObject = std::mem::transmute(addr as usize);
        let hook_ptr: FnNtCreateSymbolicLinkObject = hook_nt_create_symbolic_link_object;
        match GenericDetour::<FnNtCreateSymbolicLinkObject>::new(target, hook_ptr) {
            Ok(detour) => {
                let _ = HOOK_CREATE_SYMLINK_OBJ.set(detour);
                if let Some(h) = HOOK_CREATE_SYMLINK_OBJ.get() {
                    if let Err(e) = h.enable() {
                        buffer_install_error(
                            format!("system_guard: detour enable NtCreateSymbolicLinkObject: {:?}", e));
                    }
                }
            }
            Err(e) => buffer_install_error(
                format!("system_guard: detour init NtCreateSymbolicLinkObject: {:?}", e)),
        }
    } else {
        buffer_install_error(
            "system_guard: ntdll export NtCreateSymbolicLinkObject not found".into());
    }

    // NtLoadDriver — BYOVD defence (S4).
    if let Some(addr) = ntdll_export("NtLoadDriver\0".as_bytes()) {
        // SAFETY: transmute of ntdll export address; ABI matches FnNtLoadDriver.
        let target: FnNtLoadDriver = std::mem::transmute(addr as usize);
        let hook_ptr: FnNtLoadDriver = hook_nt_load_driver;
        match GenericDetour::<FnNtLoadDriver>::new(target, hook_ptr) {
            Ok(detour) => {
                let _ = HOOK_LOAD_DRIVER.set(detour);
                if let Some(h) = HOOK_LOAD_DRIVER.get() {
                    if let Err(e) = h.enable() {
                        buffer_install_error(
                            format!("system_guard: detour enable NtLoadDriver: {:?}", e));
                    }
                }
            }
            Err(e) => buffer_install_error(
                format!("system_guard: detour init NtLoadDriver: {:?}", e)),
        }
    } else {
        buffer_install_error(
            "system_guard: ntdll export NtLoadDriver not found".into());
    }

    // NtUnloadDriver — symmetry with NtLoadDriver.
    if let Some(addr) = ntdll_export("NtUnloadDriver\0".as_bytes()) {
        // SAFETY: transmute of ntdll export address; ABI matches FnNtUnloadDriver.
        let target: FnNtUnloadDriver = std::mem::transmute(addr as usize);
        let hook_ptr: FnNtUnloadDriver = hook_nt_unload_driver;
        match GenericDetour::<FnNtUnloadDriver>::new(target, hook_ptr) {
            Ok(detour) => {
                let _ = HOOK_UNLOAD_DRIVER.set(detour);
                if let Some(h) = HOOK_UNLOAD_DRIVER.get() {
                    if let Err(e) = h.enable() {
                        buffer_install_error(
                            format!("system_guard: detour enable NtUnloadDriver: {:?}", e));
                    }
                }
            }
            Err(e) => buffer_install_error(
                format!("system_guard: detour init NtUnloadDriver: {:?}", e)),
        }
    } else {
        buffer_install_error(
            "system_guard: ntdll export NtUnloadDriver not found".into());
    }

    if is_trace() {
        ipc_log(ipc::LogLevel::Trace, "system_guard_installed".into());
    }
    Ok(())
}

/// # SAFETY
/// Must be called from DLL_PROCESS_DETACH only.
pub unsafe fn uninstall() {
    if let Some(h) = HOOK_UNLOAD_DRIVER.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_LOAD_DRIVER.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_CREATE_SYMLINK_OBJ.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_RAISE_HARD_ERROR.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_CREATE_DEBUG_OBJ.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_SET_SYS_INFO.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_SHUTDOWN.get() { let _ = h.disable(); }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The hook functions short-circuit before dereferencing any input pointer:
    // anti_rec::enter() succeeds, then is_trace() returns false in tests (no
    // IPC client wired up), so we skip the UNICODE_STRING decode and return
    // the documented NTSTATUS directly. Calling with null inputs is therefore
    // safe and exercises the deny path.

    #[test]
    fn symlink_create_denies_with_null_inputs() {
        // SAFETY: hook returns STATUS_ACCESS_DENIED before dereffing any pointer.
        let rc = unsafe {
            hook_nt_create_symbolic_link_object(
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(rc as u32, 0xC000_0022, "expected STATUS_ACCESS_DENIED");
    }

    #[test]
    fn load_driver_denies_with_null_input() {
        // SAFETY: hook returns STATUS_PRIVILEGE_NOT_HELD before dereffing any pointer.
        let rc = unsafe { hook_nt_load_driver(std::ptr::null()) };
        assert_eq!(rc as u32, 0xC000_0061, "expected STATUS_PRIVILEGE_NOT_HELD");
    }

    #[test]
    fn unload_driver_denies_with_null_input() {
        // SAFETY: hook returns STATUS_PRIVILEGE_NOT_HELD before dereffing any pointer.
        let rc = unsafe { hook_nt_unload_driver(std::ptr::null()) };
        assert_eq!(rc as u32, 0xC000_0061, "expected STATUS_PRIVILEGE_NOT_HELD");
    }

    #[test]
    fn extract_unicode_string_handles_null() {
        // SAFETY: null pointer is the documented early-out for extract_unicode_string.
        let s = unsafe { extract_unicode_string(std::ptr::null()) };
        assert_eq!(s, "<null>");
    }

    #[test]
    fn extract_unicode_string_handles_null_buffer() {
        let ustr = UNICODE_STRING {
            Length: 10,
            MaximumLength: 10,
            Buffer: std::ptr::null_mut(),
        };
        // SAFETY: pointer is a valid stack location holding a UNICODE_STRING; Buffer is null and handled.
        let s = unsafe { extract_unicode_string(&ustr as *const UNICODE_STRING) };
        assert_eq!(s, "<empty>");
    }

    #[test]
    fn extract_unicode_string_decodes_valid() {
        let mut wide: Vec<u16> = "\\??\\C:".encode_utf16().collect();
        let ustr = UNICODE_STRING {
            Length: (wide.len() * 2) as u16,
            MaximumLength: (wide.len() * 2) as u16,
            Buffer: wide.as_mut_ptr(),
        };
        // SAFETY: backing storage (`wide`) outlives the borrow; Length matches the slice in bytes.
        let s = unsafe { extract_unicode_string(&ustr as *const UNICODE_STRING) };
        assert_eq!(s, "\\??\\C:");
    }

    #[test]
    fn status_constants_match_documented_values() {
        // Documented constants for cross-reference.
        assert_eq!(STATUS_ACCESS_DENIED as u32, 0xC000_0022);
        assert_eq!(STATUS_PRIVILEGE_NOT_HELD as u32, 0xC000_0061);
    }
}
