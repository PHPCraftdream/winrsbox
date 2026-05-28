// Service guard — blocks OpenSCManagerW / OpenServiceW for dangerous access masks.
//
// Escape vector:
//   AI-agent calls OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS), then
//   OpenServiceW(scm, L"AnyService", SERVICE_CHANGE_CONFIG), then
//   ChangeServiceConfigW to redirect bin path. services.exe runs evil.exe as SYSTEM.
//
// Also blocks CreateServiceW (via SC_MANAGER_CREATE_SERVICE) — user-installed
// services get auto-start at boot.
//
// Hook targets: advapi32.dll!OpenSCManagerW, advapi32.dll!OpenServiceW.
//
// Read-only access is allowed: CONNECT, ENUMERATE_SERVICE, QUERY_LOCK_STATUS,
// SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, READ_CONTROL.

use std::sync::OnceLock;

use detour2::GenericDetour;
use winapi::ctypes::c_void;
use winapi::um::winnt::HANDLE;

use crate::anti_rec;
use crate::hooks::{ipc_log, is_trace};

// ---------------------------------------------------------------------------
// Function types
// ---------------------------------------------------------------------------

// SC_HANDLE OpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);
type FnOpenSCManagerW = unsafe extern "system" fn(
    *const u16,  // lpMachineName
    *const u16,  // lpDatabaseName
    u32,         // dwDesiredAccess
) -> HANDLE;     // SC_HANDLE is HANDLE-alias

// SC_HANDLE OpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess);
type FnOpenServiceW = unsafe extern "system" fn(
    HANDLE,      // hSCManager
    *const u16,  // lpServiceName
    u32,         // dwDesiredAccess
) -> HANDLE;

// ---------------------------------------------------------------------------
// Dangerous access masks
// ---------------------------------------------------------------------------

const SCM_DANGEROUS: u32 =
    0x0002 |  // SC_MANAGER_CREATE_SERVICE
    0x0008 |  // SC_MANAGER_LOCK
    0x0020 |  // SC_MANAGER_MODIFY_BOOT_CONFIG
    0x0F003F| // SC_MANAGER_ALL_ACCESS
    0x040000| // WRITE_DAC
    0x080000; // WRITE_OWNER

const SERVICE_DANGEROUS: u32 =
    0x0002 |  // SERVICE_CHANGE_CONFIG
    0x0010 |  // SERVICE_START
    0x0020 |  // SERVICE_STOP
    0x0040 |  // SERVICE_PAUSE_CONTINUE
    0x10000|  // DELETE
    0x0F01FF| // SERVICE_ALL_ACCESS
    0x040000| // WRITE_DAC
    0x080000; // WRITE_OWNER

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

static HOOK_OPEN_SCM: OnceLock<GenericDetour<FnOpenSCManagerW>> = OnceLock::new();
static HOOK_OPEN_SERVICE: OnceLock<GenericDetour<FnOpenServiceW>> = OnceLock::new();

// ---------------------------------------------------------------------------
// Hook implementations
// ---------------------------------------------------------------------------

// SAFETY: Called by detour2 dispatcher with advapi32!OpenSCManagerW ABI.
unsafe extern "system" fn hook_open_sc_manager(
    machine: *const u16, database: *const u16, access: u32,
) -> HANDLE {
    let call_original = || {
        // SAFETY: detour2 trampoline matches FnOpenSCManagerW ABI.
        HOOK_OPEN_SCM.get().unwrap().call(machine, database, access)
    };
    let Some(_guard) = anti_rec::enter() else { return call_original(); };
    if access & SCM_DANGEROUS != 0 {
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace,
                format!("scm_open_blocked access=0x{:08x}", access));
        }
        winapi::um::errhandlingapi::SetLastError(5);
        return std::ptr::null_mut();
    }
    call_original()
}

// SAFETY: Called by detour2 dispatcher with advapi32!OpenServiceW ABI.
unsafe extern "system" fn hook_open_service(
    scm: HANDLE, name: *const u16, access: u32,
) -> HANDLE {
    let call_original = || {
        // SAFETY: detour2 trampoline matches FnOpenServiceW ABI.
        HOOK_OPEN_SERVICE.get().unwrap().call(scm, name, access)
    };
    let Some(_guard) = anti_rec::enter() else { return call_original(); };
    if access & SERVICE_DANGEROUS != 0 {
        let name_str = if name.is_null() { String::new() } else {
            // SAFETY: pointer arithmetic bounded by null-terminator search within 256 WCHARs.
            let len = (0..256).find(|&i| *name.add(i) == 0).unwrap_or(0);
            // SAFETY: from_raw_parts for `len` WCHARs from null-terminated `name`; len ≤ 256 by search above.
            String::from_utf16_lossy(std::slice::from_raw_parts(name, len))
        };
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace,
                format!("service_open_blocked name={} access=0x{:08x}", name_str, access));
        }
        winapi::um::errhandlingapi::SetLastError(5);
        return std::ptr::null_mut();
    }
    call_original()
}

// ---------------------------------------------------------------------------
// advapi32.dll export resolver
// ---------------------------------------------------------------------------

/// # SAFETY
/// Must be called during install (DllMain context). `name` must be a null-terminated ASCII byte string.
unsafe fn advapi32_export(name: &[u8]) -> Option<*const c_void> {
    let module_w: Vec<u16> = "advapi32.dll\0".encode_utf16().collect();
    // SAFETY: FFI call to LoadLibraryW with null-terminated wide string.
    let h = winapi::um::libloaderapi::LoadLibraryW(module_w.as_ptr());
    if h.is_null() { return None; }
    // SAFETY: FFI call to GetProcAddress with valid HMODULE and null-terminated ASCII name.
    let addr = winapi::um::libloaderapi::GetProcAddress(h, name.as_ptr() as *const i8);
    if addr.is_null() { None } else { Some(addr as *const c_void) }
}

// ---------------------------------------------------------------------------
// Install / Uninstall
// ---------------------------------------------------------------------------

/// # SAFETY
/// Must be called from install_hooks() in DllMain context with anti_rec entered.
pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    // OpenSCManagerW
    if let Some(addr) = advapi32_export(b"OpenSCManagerW\0") {
        // SAFETY: transmute of advapi32 export address; ABI matches FnOpenSCManagerW.
        let target: FnOpenSCManagerW = std::mem::transmute(addr);
        let hook_ptr: FnOpenSCManagerW = hook_open_sc_manager;
        let detour = GenericDetour::<FnOpenSCManagerW>::new(target, hook_ptr)
            .map_err(|e| format!("detour init OpenSCManagerW: {:?}", e))?;
        HOOK_OPEN_SCM.set(detour).ok();
        HOOK_OPEN_SCM.get().expect("set above").enable()
            .map_err(|e| format!("detour enable OpenSCManagerW: {:?}", e))?;
    } else {
        ipc_log(ipc::LogLevel::Warn,
            "service_guard: advapi32 export OpenSCManagerW not found — skipping".into());
    }

    // OpenServiceW
    if let Some(addr) = advapi32_export(b"OpenServiceW\0") {
        // SAFETY: transmute of advapi32 export address; ABI matches FnOpenServiceW.
        let target: FnOpenServiceW = std::mem::transmute(addr);
        let hook_ptr: FnOpenServiceW = hook_open_service;
        let detour = GenericDetour::<FnOpenServiceW>::new(target, hook_ptr)
            .map_err(|e| format!("detour init OpenServiceW: {:?}", e))?;
        HOOK_OPEN_SERVICE.set(detour).ok();
        HOOK_OPEN_SERVICE.get().expect("set above").enable()
            .map_err(|e| format!("detour enable OpenServiceW: {:?}", e))?;
    } else {
        ipc_log(ipc::LogLevel::Warn,
            "service_guard: advapi32 export OpenServiceW not found — skipping".into());
    }

    if is_trace() {
        ipc_log(ipc::LogLevel::Trace, "service_guard_installed".into());
    }
    Ok(())
}

/// # SAFETY
/// Must be called from DLL_PROCESS_DETACH only.
pub unsafe fn uninstall() {
    if let Some(h) = HOOK_OPEN_SCM.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_OPEN_SERVICE.get() { let _ = h.disable(); }
}
