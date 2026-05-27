// System guard — blocks NtShutdownSystem, NtSetSystemInformation,
// NtCreateDebugObject, and NtRaiseHardError.
//
// Escape vector:
//   AI-agent calls NtShutdownSystem(ShutdownReboot) or
//   NtSetSystemInformation(SystemLoadGdt, ...) to modify kernel state.
//   NtRaiseHardError(OptionShutdownSystem=6) can trigger BSOD/forced logoff.
//   Even though SeShutdownPrivilege / SeTcbPrivilege are blocked via
//   token_guard, defense-in-depth: unconditional STATUS_ACCESS_DENIED.
//
// Hook targets: ntdll.dll!NtShutdownSystem, ntdll.dll!NtSetSystemInformation,
//               ntdll.dll!NtCreateDebugObject, ntdll.dll!NtRaiseHardError.

use std::sync::OnceLock;

use detour2::GenericDetour;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES};
use winapi::ctypes::c_void;

use crate::anti_rec;
use crate::hooks::{ipc_log, is_trace, ntdll_export};

const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000_0022_u32 as NTSTATUS;

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

static HOOK_SHUTDOWN: OnceLock<GenericDetour<FnNtShutdownSystem>> = OnceLock::new();
static HOOK_SET_SYS_INFO: OnceLock<GenericDetour<FnNtSetSystemInformation>> = OnceLock::new();
static HOOK_CREATE_DEBUG_OBJ: OnceLock<GenericDetour<FnNtCreateDebugObject>> = OnceLock::new();
static HOOK_RAISE_HARD_ERROR: OnceLock<GenericDetour<FnNtRaiseHardError>> = OnceLock::new();

unsafe extern "system" fn hook_nt_shutdown_system(action: u32) -> NTSTATUS {
    let call_original = || {
        HOOK_SHUTDOWN.get().unwrap().call(action)
    };
    let Some(_g) = anti_rec::enter() else { return call_original(); };
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace,
            format!("sys_shutdown_blocked action={}", action));
    }
    STATUS_ACCESS_DENIED
}

unsafe extern "system" fn hook_nt_set_system_information(
    class: u32, info: *mut c_void, len: u32,
) -> NTSTATUS {
    let call_original = || {
        HOOK_SET_SYS_INFO.get().unwrap().call(class, info, len)
    };
    let Some(_g) = anti_rec::enter() else { return call_original(); };
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace,
            format!("sys_setinfo_blocked class={} len={}", class, len));
    }
    STATUS_ACCESS_DENIED
}

unsafe extern "system" fn hook_nt_create_debug_object(
    handle: *mut HANDLE,
    access: u32,
    attrs: *const OBJECT_ATTRIBUTES,
    flags: u32,
) -> NTSTATUS {
    let call_original = || {
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

unsafe extern "system" fn hook_nt_raise_hard_error(
    error_status: NTSTATUS,
    num_params: u32,
    unicode_mask: u32,
    params: *mut usize,
    response_option: u32,
    response: *mut u32,
) -> NTSTATUS {
    let call_original = || {
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

pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    // NtShutdownSystem
    if let Some(addr) = ntdll_export("NtShutdownSystem\0".as_bytes()) {
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

    if is_trace() {
        ipc_log(ipc::LogLevel::Trace, "system_guard_installed".into());
    }
    Ok(())
}

pub unsafe fn uninstall() {
    if let Some(h) = HOOK_RAISE_HARD_ERROR.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_CREATE_DEBUG_OBJ.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_SET_SYS_INFO.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_SHUTDOWN.get() { let _ = h.disable(); }
}
