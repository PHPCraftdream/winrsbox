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
// SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, READ_CONTROL. Dangerous-bit
// classification runs AFTER generic/maximum normalization — see
// is_dangerous_scm_access / is_dangerous_service_access below (R04 F5).

use std::sync::OnceLock;

use detour2::GenericDetour;
use winapi::ctypes::c_void;
use winapi::um::winnt::{
    DELETE, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, HANDLE,
    MAXIMUM_ALLOWED, STANDARD_RIGHTS_EXECUTE, STANDARD_RIGHTS_READ,
    STANDARD_RIGHTS_REQUIRED, STANDARD_RIGHTS_WRITE, WRITE_DAC, WRITE_OWNER,
};

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

// ANSI twins (R04-3, Этап 3): OpenSCManagerA / OpenServiceA are genuinely
// separate SCM RPC entry points (ROpenSCManagerA / ROpenServiceA), not thin
// wrappers over the W path — an unhooked A entry bypasses the classifier
// below entirely. dwDesiredAccess has identical bit layout in both variants
// (only the string parameters differ in encoding), so the SAME
// is_dangerous_scm_access / is_dangerous_service_access predicates apply
// unchanged; only string decoding (ANSI vs UTF-16) differs per hook body.
//
// SC_HANDLE OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess);
type FnOpenSCManagerA = unsafe extern "system" fn(
    *const u8,   // lpMachineName (LPCSTR)
    *const u8,   // lpDatabaseName
    u32,         // dwDesiredAccess
) -> HANDLE;

// SC_HANDLE OpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess);
type FnOpenServiceA = unsafe extern "system" fn(
    HANDLE,      // hSCManager
    *const u8,   // lpServiceName (LPCSTR)
    u32,         // dwDesiredAccess
) -> HANDLE;

// ---------------------------------------------------------------------------
// SCM/service access rights and dangerous-mask classification (R04 F5)
// ---------------------------------------------------------------------------
//
// winapi's `winsvc` feature is not enabled for this crate, so the SCM and
// service specific rights are pinned here with the exact values from
// winapi-0.3.9 src/um/winsvc.rs (== winsvc.h): SC_MANAGER_ALL_ACCESS = 0xF003F,
// SERVICE_ALL_ACCESS = 0xF01FF.
//
// Classification is specific-bit based (R04 F5). The old masks OR-ed in the
// *_ALL_ACCESS aggregates, so the raw intersection test denied every non-zero
// request — including the read-only rights in the header comment — and let
// GENERIC_*/MAXIMUM_ALLOWED requests bypass the check entirely (none of those
// bits intersected the specific masks). Now: (1) the denylists hold only
// individually-dangerous rights, (2) GENERIC_* bits are resolved to their
// concrete meaning per the documented "Generic Access Rights for a Service
// Control Manager" / "for a Service" tables on Service Security and Access
// Rights (learn.microsoft.com/en-us/windows/win32/services/service-security-
// and-access-rights) BEFORE the dangerous-bit test, and (3) MAXIMUM_ALLOWED is
// denied up front: it asks for everything the DACL grants — unknowable at hook
// time, and on a same-user service the DACL typically includes dangerous
// rights (same policy as is_write_access in core/hooks/mod.rs and
// TOKEN_DANGEROUS_ACCESS in proc/token_guard.rs).

const SC_MANAGER_CONNECT: u32 = 0x0001;
const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;
const SC_MANAGER_LOCK: u32 = 0x0008;
const SC_MANAGER_QUERY_LOCK_STATUS: u32 = 0x0010;
const SC_MANAGER_MODIFY_BOOT_CONFIG: u32 = 0x0020;
const SC_MANAGER_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED
    | SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_ENUMERATE_SERVICE
    | SC_MANAGER_LOCK | SC_MANAGER_QUERY_LOCK_STATUS | SC_MANAGER_MODIFY_BOOT_CONFIG;

const SERVICE_QUERY_CONFIG: u32 = 0x0001;
const SERVICE_CHANGE_CONFIG: u32 = 0x0002;
const SERVICE_QUERY_STATUS: u32 = 0x0004;
const SERVICE_ENUMERATE_DEPENDENTS: u32 = 0x0008;
const SERVICE_START: u32 = 0x0010;
const SERVICE_STOP: u32 = 0x0020;
const SERVICE_PAUSE_CONTINUE: u32 = 0x0040;
const SERVICE_INTERROGATE: u32 = 0x0080;
const SERVICE_USER_DEFINED_CONTROL: u32 = 0x0100;
const SERVICE_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED
    | SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS
    | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_START | SERVICE_STOP
    | SERVICE_PAUSE_CONTINUE | SERVICE_INTERROGATE | SERVICE_USER_DEFINED_CONTROL;

// Individually-dangerous rights only — no *_ALL_ACCESS aggregates (R04 F5).
//
// SCM: CREATE_SERVICE installs a service (persistence, service-account code
// exec); LOCK takes the exclusive LockServiceDatabase lock and blocks all
// service control; MODIFY_BOOT_CONFIG drives NotifyBootConfigStatus;
// DELETE/WRITE_DAC/WRITE_OWNER are destructive control and security-descriptor
// takeover.
const SCM_DANGEROUS: u32 = SC_MANAGER_CREATE_SERVICE | SC_MANAGER_LOCK
    | SC_MANAGER_MODIFY_BOOT_CONFIG | DELETE | WRITE_DAC | WRITE_OWNER;

// Service: CHANGE_CONFIG is the ChangeServiceConfigW BinPath redirect (the
// SYSTEM escape in the header scenario); START runs the service binary in its
// configured account; STOP / PAUSE_CONTINUE drive ControlService state
// changes (kills security/host services); USER_DEFINED_CONTROL runs
// service-defined ControlService handlers inside the (often SYSTEM) service
// process; DELETE uninstalls the service; WRITE_DAC / WRITE_OWNER retake the
// service's security descriptor.
const SERVICE_DANGEROUS: u32 = SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP
    | SERVICE_PAUSE_CONTINUE | SERVICE_USER_DEFINED_CONTROL | DELETE | WRITE_DAC
    | WRITE_OWNER;

const GENERIC_MASK_ALL: u32 = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL;

// MapGenericMask equivalent for SCM handles, per the documented table
// ("Generic Access Rights for a Service Control Manager"; GENERIC_ALL →
// SC_MANAGER_ALL_ACCESS): OR in the mapped rights, then clear the generic
// bits.
fn scm_map_generic(access: u32) -> u32 {
    let mut concrete = access;
    if concrete & GENERIC_READ != 0 {
        concrete |= STANDARD_RIGHTS_READ
            | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_QUERY_LOCK_STATUS;
    }
    if concrete & GENERIC_WRITE != 0 {
        concrete |= STANDARD_RIGHTS_WRITE
            | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_MODIFY_BOOT_CONFIG;
    }
    if concrete & GENERIC_EXECUTE != 0 {
        concrete |= STANDARD_RIGHTS_EXECUTE | SC_MANAGER_CONNECT | SC_MANAGER_LOCK;
    }
    if concrete & GENERIC_ALL != 0 {
        concrete |= SC_MANAGER_ALL_ACCESS;
    }
    concrete & !GENERIC_MASK_ALL
}

// Same for service handles, per "Generic Access Rights for a Service". The
// page prints no GENERIC_ALL row for services; GENERIC_ALL → SERVICE_ALL_ACCESS
// follows the SCM table's convention, and every candidate resolution contains
// dangerous bits, so the verdict does not depend on the exact row.
fn service_map_generic(access: u32) -> u32 {
    let mut concrete = access;
    if concrete & GENERIC_READ != 0 {
        concrete |= STANDARD_RIGHTS_READ | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS
            | SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS;
    }
    if concrete & GENERIC_WRITE != 0 {
        concrete |= STANDARD_RIGHTS_WRITE | SERVICE_CHANGE_CONFIG;
    }
    if concrete & GENERIC_EXECUTE != 0 {
        concrete |= STANDARD_RIGHTS_EXECUTE | SERVICE_START | SERVICE_STOP
            | SERVICE_PAUSE_CONTINUE | SERVICE_USER_DEFINED_CONTROL;
    }
    if concrete & GENERIC_ALL != 0 {
        concrete |= SERVICE_ALL_ACCESS;
    }
    concrete & !GENERIC_MASK_ALL
}

// Classification entry points used by the two hooks. MAXIMUM_ALLOWED is not a
// generic bit (MapGenericMask leaves it untouched): it resolves to whatever
// the DACL grants, so it cannot be proven harmless and is denied up front.
fn is_dangerous_scm_access(access: u32) -> bool {
    access & MAXIMUM_ALLOWED != 0 || scm_map_generic(access) & SCM_DANGEROUS != 0
}

fn is_dangerous_service_access(access: u32) -> bool {
    access & MAXIMUM_ALLOWED != 0 || service_map_generic(access) & SERVICE_DANGEROUS != 0
}

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

static HOOK_OPEN_SCM: OnceLock<GenericDetour<FnOpenSCManagerW>> = OnceLock::new();
static HOOK_OPEN_SERVICE: OnceLock<GenericDetour<FnOpenServiceW>> = OnceLock::new();
static HOOK_OPEN_SCM_A: OnceLock<GenericDetour<FnOpenSCManagerA>> = OnceLock::new();
static HOOK_OPEN_SERVICE_A: OnceLock<GenericDetour<FnOpenServiceA>> = OnceLock::new();

// ---------------------------------------------------------------------------
// Shared deny response (R04-3): single source of truth for the deny-decision
// side effects (trace log + Win32 failure contract) so the four hook bodies
// below — OpenSCManagerW/A, OpenServiceW/A — cannot silently drift from each
// other. Classification itself lives in is_dangerous_scm_access /
// is_dangerous_service_access (R04 F5) and is called identically by all four.
// ---------------------------------------------------------------------------

// SAFETY: must be called with anti_rec entered (matches the hook bodies below).
unsafe fn scm_deny_response(access: u32) -> HANDLE {
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace,
            format!("scm_open_blocked access=0x{:08x}", access));
    }
    winapi::um::errhandlingapi::SetLastError(5);
    std::ptr::null_mut()
}

// SAFETY: must be called with anti_rec entered (matches the hook bodies below).
unsafe fn service_deny_response(name: &str, access: u32) -> HANDLE {
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace,
            format!("service_open_blocked name={} access=0x{:08x}", name, access));
    }
    winapi::um::errhandlingapi::SetLastError(5);
    std::ptr::null_mut()
}

// Decodes a W (UTF-16) service name for the trace log only — never used for
// the access-mask decision. Bounded scan mirrors the pre-R04-3 inline code.
//
// SAFETY: `name` must be null or a valid pointer to a null-terminated wide
// string within 256 WCHARs (caller contract, matches the pre-existing hook).
unsafe fn decode_w_service_name(name: *const u16) -> String {
    if name.is_null() { return String::new(); }
    // SAFETY: pointer arithmetic bounded by null-terminator search within 256 WCHARs.
    let len = (0..256).find(|&i| *name.add(i) == 0).unwrap_or(0);
    // SAFETY: from_raw_parts for `len` WCHARs from null-terminated `name`; len ≤ 256 by search above.
    String::from_utf16_lossy(std::slice::from_raw_parts(name, len))
}

// ANSI twin of decode_w_service_name. Converts with MultiByteToWideChar
// (CP_ACP, best-fit) — the same code page OpenServiceA itself applies when it
// marshals the name into the ROpenServiceA RPC call — so the trace log shows
// the same string the real API would act on. Log-only; never drives the
// access-mask decision.
//
// SAFETY: `name` must be null or a valid pointer to a null-terminated byte
// string within 256 bytes (caller contract, matches decode_w_service_name).
unsafe fn decode_a_service_name(name: *const u8) -> String {
    if name.is_null() { return String::new(); }
    // SAFETY: pointer arithmetic bounded by null-terminator search within 256 bytes.
    let len = (0..256).find(|&i| *name.add(i) == 0).unwrap_or(0);
    if len == 0 { return String::new(); }
    let mut wide: Vec<u16> = Vec::with_capacity(len + 1);
    // SAFETY: FFI call; `name` readable for `len` bytes per the search above,
    // `wide`'s capacity (len + 1) covers the worst-case one-u16-per-byte output.
    let converted = winapi::um::stringapiset::MultiByteToWideChar(
        winapi::um::winnls::CP_ACP,
        0, // best-fit: matches OpenServiceA's own internal A->W conversion
        name as *const i8,
        len as i32,
        wide.as_mut_ptr(),
        (len + 1) as i32,
    );
    if converted <= 0 { return String::new(); }
    // SAFETY: MultiByteToWideChar wrote exactly `converted` u16s; converted ≤ wide's capacity.
    wide.set_len(converted as usize);
    String::from_utf16_lossy(&wide)
}

// ---------------------------------------------------------------------------
// Hook implementations
// ---------------------------------------------------------------------------

// SAFETY: Called by detour2 dispatcher with advapi32!OpenSCManagerW ABI.
unsafe extern "system" fn hook_open_sc_manager(
    machine: *const u16, database: *const u16, access: u32,
) -> HANDLE {
    let call_original = || {
// Detour-absent: unwrap-abort kept on purpose — SC_HANDLE family; fail-closed would be a null handle + SetLastError(ERROR_ACCESS_DENIED), exactly like this hook's own deny path above, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnOpenSCManagerW ABI.
        HOOK_OPEN_SCM.get().unwrap().call(machine, database, access)
    };
    let Some(_guard) = anti_rec::enter() else { return call_original(); };
    if is_dangerous_scm_access(access) {
        return scm_deny_response(access);
    }
    call_original()
}

// SAFETY: Called by detour2 dispatcher with advapi32!OpenSCManagerA ABI.
unsafe extern "system" fn hook_open_sc_manager_a(
    machine: *const u8, database: *const u8, access: u32,
) -> HANDLE {
    let call_original = || {
// Detour-absent: unwrap-abort kept on purpose — SC_HANDLE family; fail-closed would be a null handle + SetLastError(ERROR_ACCESS_DENIED), exactly like this hook's own deny path above, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnOpenSCManagerA ABI.
        HOOK_OPEN_SCM_A.get().unwrap().call(machine, database, access)
    };
    let Some(_guard) = anti_rec::enter() else { return call_original(); };
    if is_dangerous_scm_access(access) {
        return scm_deny_response(access);
    }
    call_original()
}

// SAFETY: Called by detour2 dispatcher with advapi32!OpenServiceW ABI.
unsafe extern "system" fn hook_open_service(
    scm: HANDLE, name: *const u16, access: u32,
) -> HANDLE {
    let call_original = || {
// Detour-absent: unwrap-abort kept on purpose — SC_HANDLE family; fail-closed would be a null handle + SetLastError(ERROR_ACCESS_DENIED), exactly like this hook's own deny path above, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnOpenServiceW ABI.
        HOOK_OPEN_SERVICE.get().unwrap().call(scm, name, access)
    };
    let Some(_guard) = anti_rec::enter() else { return call_original(); };
    if is_dangerous_service_access(access) {
        // SAFETY: `name` is the caller-supplied LPCWSTR; decode is bounded and null-safe.
        let name_str = decode_w_service_name(name);
        return service_deny_response(&name_str, access);
    }
    call_original()
}

// SAFETY: Called by detour2 dispatcher with advapi32!OpenServiceA ABI.
unsafe extern "system" fn hook_open_service_a(
    scm: HANDLE, name: *const u8, access: u32,
) -> HANDLE {
    let call_original = || {
// Detour-absent: unwrap-abort kept on purpose — SC_HANDLE family; fail-closed would be a null handle + SetLastError(ERROR_ACCESS_DENIED), exactly like this hook's own deny path above, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnOpenServiceA ABI.
        HOOK_OPEN_SERVICE_A.get().unwrap().call(scm, name, access)
    };
    let Some(_guard) = anti_rec::enter() else { return call_original(); };
    if is_dangerous_service_access(access) {
        // SAFETY: `name` is the caller-supplied LPCSTR; decode is bounded and null-safe.
        let name_str = decode_a_service_name(name);
        return service_deny_response(&name_str, access);
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
///
/// R04 F4 policy — MANDATORY category: service-SCM containment is promised by
/// SECURITY.md (an unguarded OpenSCManagerW/OpenServiceW pair is a SYSTEM
/// escape by ChangeServiceConfigW), and advapi32 has exported both since
/// NT 3.5/4.0, so a missing export must abort the install. Failing closed here
/// also removes the old inconsistency where this REQUIRED category buffered
/// and continued while every other one propagated Err out via `install()?`.
///
/// R04-3 (Этап 3): OpenSCManagerA / OpenServiceA are genuinely separate SCM
/// RPC entry points (not W-path wrappers), so they extend the SAME mandatory
/// category — a missing A export fails the install exactly like a missing W
/// export, not a buffered/optional degrade.
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
        return Err("service_guard: advapi32 export OpenSCManagerW not found".into());
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
        return Err("service_guard: advapi32 export OpenServiceW not found".into());
    }

    // OpenSCManagerA (R04-3, Этап 3)
    if let Some(addr) = advapi32_export(b"OpenSCManagerA\0") {
        // SAFETY: transmute of advapi32 export address; ABI matches FnOpenSCManagerA.
        let target: FnOpenSCManagerA = std::mem::transmute(addr);
        let hook_ptr: FnOpenSCManagerA = hook_open_sc_manager_a;
        let detour = GenericDetour::<FnOpenSCManagerA>::new(target, hook_ptr)
            .map_err(|e| format!("detour init OpenSCManagerA: {:?}", e))?;
        HOOK_OPEN_SCM_A.set(detour).ok();
        HOOK_OPEN_SCM_A.get().expect("set above").enable()
            .map_err(|e| format!("detour enable OpenSCManagerA: {:?}", e))?;
    } else {
        return Err("service_guard: advapi32 export OpenSCManagerA not found".into());
    }

    // OpenServiceA (R04-3, Этап 3)
    if let Some(addr) = advapi32_export(b"OpenServiceA\0") {
        // SAFETY: transmute of advapi32 export address; ABI matches FnOpenServiceA.
        let target: FnOpenServiceA = std::mem::transmute(addr);
        let hook_ptr: FnOpenServiceA = hook_open_service_a;
        let detour = GenericDetour::<FnOpenServiceA>::new(target, hook_ptr)
            .map_err(|e| format!("detour init OpenServiceA: {:?}", e))?;
        HOOK_OPEN_SERVICE_A.set(detour).ok();
        HOOK_OPEN_SERVICE_A.get().expect("set above").enable()
            .map_err(|e| format!("detour enable OpenServiceA: {:?}", e))?;
    } else {
        return Err("service_guard: advapi32 export OpenServiceA not found".into());
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
    if let Some(h) = HOOK_OPEN_SCM_A.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_OPEN_SERVICE_A.get() { let _ = h.disable(); }
}

#[cfg(test)]
mod install_tests {
    // Pins for R04 F4: service_guard is a REQUIRED category (install_hooks
    // propagates its Err via `install()?`), so a missing advapi32 export must
    // fail closed, not buffer-and-continue. module_source("service_guard")
    // includes THIS file, so every pin below operates on the install()/prefix
    // slices only and can never match its own text.

    fn install_source() -> (String, String) {
        let src = crate::hooks::module_source("service_guard");
        let start = src.find("pub unsafe fn install()").expect("install() must exist");
        let end =
            src.find("pub unsafe fn uninstall()").expect("uninstall() must follow install()");
        (src[..start].to_string(), src[start..end].to_string())
    }

    /// R04 F4: the two advapi32 exports must abort the install. A missing
    /// export on a REAL system means badly wrong, not ancient: advapi32 has
    /// carried both since NT 3.5/4.0, and service-SCM containment is one of
    /// SECURITY.md's in-scope promises.
    #[test]
    fn missing_advapi32_exports_fail_closed_not_buffered() {
        let (prefix, body) = install_source();
        // R04-3: OpenSCManagerA / OpenServiceA extend the SAME mandatory
        // category as the W exports — a missing A export must abort the
        // install too, not degrade to buffered/optional.
        for sym in ["OpenSCManagerW", "OpenServiceW", "OpenSCManagerA", "OpenServiceA"] {
            let needle = format!("advapi32 export {sym} not found");
            assert!(
                body.contains(&needle) && !body.contains(&format!("{needle} — skipping")),
                "service_guard missing-export arm for {sym} must return Err (fail closed), not skip"
            );
            // The Err arm, not a log arm: the needle must sit in a `return Err(` arm.
            let arm_pos = body.find(&needle).expect("arm message present");
            let before = &body[arm_pos.saturating_sub(64)..arm_pos];
            assert!(
                before.contains("return Err("),
                "missing export {sym} must abort via return Err"
            );
        }
        assert!(
            !body.contains(concat!("buffer_install", "_error")),
            "service_guard install must not buffer-and-continue on missing exports"
        );
        assert!(
            !prefix.contains(concat!("buffer_install", "_error")),
            "service_guard must no longer import buffer_install_error"
        );
    }
}

#[cfg(test)]
mod access_mask_tests {
    // R04 F5: the old aggregate masks (SC_MANAGER_ALL_ACCESS /
    // SERVICE_ALL_ACCESS OR-ed into SCM_DANGEROUS / SERVICE_DANGEROUS) denied
    // every non-zero request — including the read-only rights the file header
    // promises to allow — and let GENERIC_*/MAXIMUM_ALLOWED bypass the check.
    // These pins classify through is_dangerous_*_access, i.e. exactly what the
    // hooks evaluate.

    use super::*;
    use winapi::um::winnt::READ_CONTROL;

    #[test]
    fn harmless_scm_requests_are_allowed() {
        for mask in [
            SC_MANAGER_CONNECT,
            SC_MANAGER_ENUMERATE_SERVICE,
            SC_MANAGER_QUERY_LOCK_STATUS,
            READ_CONTROL,
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
        ] {
            assert!(!is_dangerous_scm_access(mask), "SCM mask 0x{mask:08x} must be allowed");
        }
    }

    #[test]
    fn harmless_service_requests_are_allowed() {
        for mask in [
            SERVICE_QUERY_CONFIG,
            SERVICE_QUERY_STATUS,
            SERVICE_ENUMERATE_DEPENDENTS,
            SERVICE_INTERROGATE,
            READ_CONTROL,
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
        ] {
            assert!(
                !is_dangerous_service_access(mask),
                "service mask 0x{mask:08x} must be allowed"
            );
        }
    }

    #[test]
    fn generic_read_maps_to_allowed_rights_on_both_objects() {
        assert!(!is_dangerous_scm_access(GENERIC_READ));
        assert!(!is_dangerous_service_access(GENERIC_READ));
    }

    #[test]
    fn every_specific_dangerous_scm_bit_is_denied() {
        for mask in [
            SC_MANAGER_CREATE_SERVICE,
            SC_MANAGER_LOCK,
            SC_MANAGER_MODIFY_BOOT_CONFIG,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
            SC_MANAGER_ALL_ACCESS,
        ] {
            assert!(is_dangerous_scm_access(mask), "SCM mask 0x{mask:08x} must be denied");
        }
    }

    #[test]
    fn every_specific_dangerous_service_bit_is_denied() {
        for mask in [
            SERVICE_CHANGE_CONFIG,
            SERVICE_START,
            SERVICE_STOP,
            SERVICE_PAUSE_CONTINUE,
            SERVICE_USER_DEFINED_CONTROL,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
            SERVICE_ALL_ACCESS,
        ] {
            assert!(
                is_dangerous_service_access(mask),
                "service mask 0x{mask:08x} must be denied"
            );
        }
    }

    #[test]
    fn harmless_bits_do_not_rescue_dangerous_ones() {
        assert!(is_dangerous_scm_access(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE));
        assert!(is_dangerous_service_access(SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG));
    }

    // The old bypass: generic bits did not intersect any specific mask.
    // GENERIC_WRITE resolves to CREATE_SERVICE (SCM) / CHANGE_CONFIG (service).
    #[test]
    fn generic_write_is_denied_on_both_objects() {
        assert!(is_dangerous_scm_access(GENERIC_WRITE));
        assert!(is_dangerous_service_access(GENERIC_WRITE));
    }

    // SCM: GENERIC_EXECUTE → LOCK. Service: → START|STOP|PAUSE_CONTINUE|
    // USER_DEFINED_CONTROL.
    #[test]
    fn generic_execute_is_denied_on_both_objects() {
        assert!(is_dangerous_scm_access(GENERIC_EXECUTE));
        assert!(is_dangerous_service_access(GENERIC_EXECUTE));
    }

    #[test]
    fn generic_all_is_denied_on_both_objects() {
        assert!(is_dangerous_scm_access(GENERIC_ALL));
        assert!(is_dangerous_service_access(GENERIC_ALL));
    }

    // MAXIMUM_ALLOWED resolves to whatever the DACL grants — unknowable at
    // hook time, potentially dangerous on same-user services — so it is
    // denied before any bit test (codebase precedent: is_write_access in
    // core/hooks/mod.rs, TOKEN_DANGEROUS_ACCESS in proc/token_guard.rs).
    #[test]
    fn maximum_allowed_is_denied_on_both_objects() {
        assert!(is_dangerous_scm_access(MAXIMUM_ALLOWED));
        assert!(is_dangerous_service_access(MAXIMUM_ALLOWED));
    }

    #[test]
    fn specific_masks_pass_through_mapping_unchanged() {
        assert_eq!(scm_map_generic(SC_MANAGER_CONNECT), SC_MANAGER_CONNECT);
        assert_eq!(scm_map_generic(SC_MANAGER_CREATE_SERVICE), SC_MANAGER_CREATE_SERVICE);
        assert_eq!(service_map_generic(SERVICE_QUERY_STATUS), SERVICE_QUERY_STATUS);
        assert_eq!(
            service_map_generic(SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG),
            SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG
        );
    }

    #[test]
    fn scm_generic_mapping_matches_documented_table() {
        assert_eq!(
            scm_map_generic(GENERIC_READ),
            STANDARD_RIGHTS_READ | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_QUERY_LOCK_STATUS
        );
        assert_eq!(
            scm_map_generic(GENERIC_WRITE),
            STANDARD_RIGHTS_WRITE | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_MODIFY_BOOT_CONFIG
        );
        assert_eq!(
            scm_map_generic(GENERIC_EXECUTE),
            STANDARD_RIGHTS_EXECUTE | SC_MANAGER_CONNECT | SC_MANAGER_LOCK
        );
        assert_eq!(scm_map_generic(GENERIC_ALL), SC_MANAGER_ALL_ACCESS);
    }

    #[test]
    fn service_generic_mapping_matches_documented_table() {
        assert_eq!(
            service_map_generic(GENERIC_READ),
            STANDARD_RIGHTS_READ | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS
                | SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS
        );
        assert_eq!(
            service_map_generic(GENERIC_WRITE),
            STANDARD_RIGHTS_WRITE | SERVICE_CHANGE_CONFIG
        );
        assert_eq!(
            service_map_generic(GENERIC_EXECUTE),
            STANDARD_RIGHTS_EXECUTE | SERVICE_START | SERVICE_STOP
                | SERVICE_PAUSE_CONTINUE | SERVICE_USER_DEFINED_CONTROL
        );
        assert_eq!(service_map_generic(GENERIC_ALL), SERVICE_ALL_ACCESS);
    }

    #[test]
    fn generic_bits_are_cleared_so_specific_tests_see_concrete_rights() {
        let mapped = scm_map_generic(GENERIC_READ | SC_MANAGER_CREATE_SERVICE);
        assert_eq!(mapped & GENERIC_MASK_ALL, 0);
        assert!(is_dangerous_scm_access(GENERIC_READ | SC_MANAGER_CREATE_SERVICE));
    }
}

#[cfg(test)]
mod ansi_hook_tests {
    // R04-3 (Этап 3): OpenSCManagerA / OpenServiceA are genuinely separate SCM
    // RPC entry points (ROpenSCManagerA / ROpenServiceA), not thin wrappers
    // over the W path, so an unhooked A entry bypassed F5's classifier
    // entirely. These pins prove (1) the A hook bodies route through the
    // EXACT SAME is_dangerous_scm_access / is_dangerous_service_access
    // predicates as the W hooks — zero duplicated dangerous-bit logic — and
    // (2) decode_a_service_name behaves like decode_w_service_name for the
    // log-only ANSI->wide conversion. No real detour install and no real
    // Windows service is touched by anything here.

    use super::*;

    fn hook_body(fn_name: &str, next_fn_name: &str) -> String {
        let src = crate::hooks::module_source("service_guard");
        let start = src.find(fn_name).expect("hook fn must exist");
        let end = src[start..].find(next_fn_name).expect("next fn must follow") + start;
        src[start..end].to_string()
    }

    // Same classification, denied identically through W and A: a dangerous
    // specific right (SC_MANAGER_CREATE_SERVICE) is denied on the SCM handle.
    #[test]
    fn dangerous_scm_right_denied_identically_w_and_a() {
        assert!(is_dangerous_scm_access(SC_MANAGER_CREATE_SERVICE));
        // hook_open_sc_manager and hook_open_sc_manager_a both gate on this
        // exact call — see structural pin below.
    }

    // Same classification, denied identically through W and A: a dangerous
    // specific right (SERVICE_CHANGE_CONFIG) is denied on the service handle.
    #[test]
    fn dangerous_service_right_denied_identically_w_and_a() {
        assert!(is_dangerous_service_access(SERVICE_CHANGE_CONFIG));
    }

    // Harmless specific rights are allowed identically through W and A.
    #[test]
    fn harmless_rights_allowed_identically_w_and_a() {
        assert!(!is_dangerous_scm_access(SC_MANAGER_CONNECT));
        assert!(!is_dangerous_service_access(SERVICE_QUERY_STATUS));
    }

    // GENERIC_ALL / MAXIMUM_ALLOWED are denied identically through W and A —
    // same classifier, same normalization, no A-specific carve-out exists.
    #[test]
    fn generic_all_and_maximum_allowed_denied_identically_w_and_a() {
        assert!(is_dangerous_scm_access(GENERIC_ALL));
        assert!(is_dangerous_scm_access(MAXIMUM_ALLOWED));
        assert!(is_dangerous_service_access(GENERIC_ALL));
        assert!(is_dangerous_service_access(MAXIMUM_ALLOWED));
    }

    /// Structural pin: hook_open_sc_manager_a's body must call
    /// is_dangerous_scm_access — the SAME function the W hook calls — and
    /// must not define or reference any second copy of the dangerous-bit
    /// logic (SCM_DANGEROUS/SERVICE_DANGEROUS constants only appear inside
    /// is_dangerous_*_access itself).
    #[test]
    fn hook_open_sc_manager_a_calls_shared_scm_classifier() {
        let body = hook_body("fn hook_open_sc_manager_a", "fn hook_open_service");
        assert!(
            body.contains("is_dangerous_scm_access(access)"),
            "hook_open_sc_manager_a must route through is_dangerous_scm_access, not a private copy"
        );
        assert!(
            !body.contains("SCM_DANGEROUS") && !body.contains("SERVICE_DANGEROUS"),
            "hook_open_sc_manager_a must not touch the dangerous-bit denylists directly"
        );
    }

    /// Structural pin: hook_open_service_a's body must call
    /// is_dangerous_service_access — the SAME function the W hook calls.
    #[test]
    fn hook_open_service_a_calls_shared_service_classifier() {
        let body = hook_body("fn hook_open_service_a", "advapi32.dll export resolver");
        assert!(
            body.contains("is_dangerous_service_access(access)"),
            "hook_open_service_a must route through is_dangerous_service_access, not a private copy"
        );
        assert!(
            !body.contains("SCM_DANGEROUS") && !body.contains("SERVICE_DANGEROUS"),
            "hook_open_service_a must not touch the dangerous-bit denylists directly"
        );
    }

    /// Structural pin: both A hooks must use the same shared deny-response
    /// helpers as the W hooks (scm_deny_response / service_deny_response),
    /// not a re-implemented SetLastError(5) + null-handle path.
    #[test]
    fn a_hooks_use_shared_deny_response_helpers() {
        let scm_body = hook_body("fn hook_open_sc_manager_a", "fn hook_open_service");
        assert!(scm_body.contains("scm_deny_response(access)"));
        let service_body = hook_body("fn hook_open_service_a", "advapi32.dll export resolver");
        assert!(service_body.contains("service_deny_response(&name_str, access)"));
    }

    // ANSI name decode: matches the W decode for plain ASCII input (the only
    // case where both round-trip losslessly through UTF-16), null-safe, and
    // does not touch any real service.
    #[test]
    fn decode_a_service_name_matches_w_decode_for_ascii() {
        let w: Vec<u16> = "AnyService".encode_utf16().chain(std::iter::once(0)).collect();
        let a: Vec<u8> = b"AnyService\0".to_vec();
        unsafe {
            assert_eq!(decode_w_service_name(w.as_ptr()), "AnyService");
            assert_eq!(decode_a_service_name(a.as_ptr()), "AnyService");
        }
    }

    #[test]
    fn decode_a_service_name_null_is_empty() {
        unsafe {
            assert_eq!(decode_a_service_name(std::ptr::null()), "");
        }
    }
}
