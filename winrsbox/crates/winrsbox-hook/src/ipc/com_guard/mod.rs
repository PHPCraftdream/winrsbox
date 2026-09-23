// COM guard — blocks out-of-proc COM activation (CoCreateInstance / CoCreateInstanceEx /
// CoGetClassObject) for dangerous CLSIDs that allow sandbox escape via process spawn or
// system modification. Also blocks WinRT (Windows Runtime) activation via
// RoGetActivationFactory / RoActivateInstance for dangerous runtime class prefixes
// (Windows.System.Launcher, Windows.Management.Deployment, ...).
//
// Denylisted CLSIDs: Shell.Application, WScript.Shell, FileSystemObject, WMI, Task Scheduler,
// BITS, Office automation. All are well-known escape vectors for AI agents.
//
// Hook targets: combase.dll!CoCreateInstance, combase.dll!CoCreateInstanceEx,
//               combase.dll!CoGetClassObject, combase.dll!RoGetActivationFactory,
//               combase.dll!RoActivateInstance.
//
// F4 (R04) install policy — fail-closed on the primary activations: a missing
// CoCreateInstance / CoCreateInstanceEx / CoGetClassObject export returns Err
// so install_hooks aborts rather than running without COM containment; only
// the WinRT sibling closures degrade, via the buffered install error.

use std::sync::OnceLock;

use detour2::GenericDetour;
use winapi::ctypes::c_void;
use winapi::shared::guiddef::GUID;

use crate::anti_rec;
use crate::hooks::{buffer_install_error, ipc_log, is_trace};

mod denylist;
#[cfg(test)]
mod denylist_tests;
#[cfg(test)]
mod install_tests;

use denylist::{check_denylist, is_winrt_class_denied};

// ---------------------------------------------------------------------------
// Function types
// ---------------------------------------------------------------------------

// HRESULT CoCreateInstance(
//   REFCLSID  rclsid,
//   LPUNKNOWN pUnkOuter,
//   DWORD     dwClsContext,
//   REFIID    riid,
//   LPVOID    *ppv
// );
type FnCoCreateInstance = unsafe extern "system" fn(
    *const GUID,       // rclsid
    *mut c_void,       // pUnkOuter
    u32,               // dwClsContext
    *const GUID,       // riid
    *mut *mut c_void,  // ppv
) -> i32;  // HRESULT

// HRESULT CoCreateInstanceEx(
//   REFCLSID         Clsid,
//   IUnknown         *punkOuter,
//   DWORD            dwClsCtx,
//   COSERVERINFO     *pServerInfo,
//   DWORD            dwCount,
//   MULTI_QI         *pResults
// );
type FnCoCreateInstanceEx = unsafe extern "system" fn(
    *const GUID, // Clsid
    *mut c_void, // punkOuter
    u32,         // dwClsCtx
    *mut c_void, // pServerInfo
    u32,         // dwCount
    *mut c_void, // pResults
) -> i32;

// HRESULT CoGetClassObject(
//   REFCLSID     rclsid,
//   DWORD        dwClsContext,
//   COSERVERINFO *pvReserved,
//   REFIID       riid,
//   LPVOID       *ppv
// );
type FnCoGetClassObject = unsafe extern "system" fn(
    *const GUID,       // rclsid
    u32,               // dwClsContext
    *mut c_void,       // pvReserved (COSERVERINFO*)
    *const GUID,       // riid
    *mut *mut c_void,  // ppv
) -> i32;

const E_ACCESSDENIED: i32 = 0x8007_0005_u32 as i32;

// REGDB_E_CLASSNOTREG — class not registered. Benign-looking COM error returned
// to denied WinRT activations so the caller takes a clean failure path.
const REGDB_E_CLASSNOTREG: i32 = 0x8004_0154_u32 as i32;

// ---------------------------------------------------------------------------
// WinRT function types
// ---------------------------------------------------------------------------

// HSTRING is an opaque handle to a counted, immutable UTF-16 string.
// In the Windows headers it's typedef'd as `HSTRING__*`; for FFI we treat it
// as an opaque pointer.
type HSTRING = *mut c_void;

// HRESULT RoGetActivationFactory(
//   HSTRING activatableClassId,
//   REFIID  iid,
//   void**  factory
// );
type FnRoGetActivationFactory = unsafe extern "system" fn(
    HSTRING,           // activatableClassId
    *const GUID,       // iid
    *mut *mut c_void,  // factory
) -> i32;

// HRESULT RoActivateInstance(
//   HSTRING       activatableClassId,
//   IInspectable **instance
// );
type FnRoActivateInstance = unsafe extern "system" fn(
    HSTRING,           // activatableClassId
    *mut *mut c_void,  // instance (IInspectable**)
) -> i32;

// PCWSTR WindowsGetStringRawBuffer(HSTRING string, UINT32 *length);
// Returns a pointer to the underlying UTF-16 buffer. The buffer is valid for
// the lifetime of the HSTRING and is NOT null-terminated guarantees-wise —
// caller must use the returned length. For a null HSTRING (= empty string),
// returns a pointer to a zero-length buffer and writes 0 to *length.
type FnWindowsGetStringRawBuffer = unsafe extern "system" fn(
    HSTRING,    // string
    *mut u32,   // length (out, in UTF-16 code units)
) -> *const u16;

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

static HOOK_CO_CREATE_INSTANCE: OnceLock<GenericDetour<FnCoCreateInstance>> = OnceLock::new();
static HOOK_CO_CREATE_INSTANCE_EX: OnceLock<GenericDetour<FnCoCreateInstanceEx>> = OnceLock::new();
static HOOK_CO_GET_CLASS_OBJECT: OnceLock<GenericDetour<FnCoGetClassObject>> = OnceLock::new();
static HOOK_RO_GET_ACTIVATION_FACTORY: OnceLock<GenericDetour<FnRoGetActivationFactory>> = OnceLock::new();
static HOOK_RO_ACTIVATE_INSTANCE: OnceLock<GenericDetour<FnRoActivateInstance>> = OnceLock::new();

/// Cached pointer to combase!WindowsGetStringRawBuffer. Resolved at install
/// time. Used inside both WinRT hook trampolines to decode the HSTRING.
static WINDOWS_GET_STRING_RAW_BUFFER: OnceLock<FnWindowsGetStringRawBuffer> = OnceLock::new();

// ---------------------------------------------------------------------------
// Hook implementations
// ---------------------------------------------------------------------------

/// F1 (R04) decision seam for `hook_co_create_instance`: the denylist
/// check, escape report/terminate and trace logging run under an anti_rec
/// window this function opens and closes. The real activation runs after it
/// returns, OUTSIDE any suppression: an in-proc server's DllMain /
/// DllGetClassObject / QueryInterface are guest-reachable application code,
/// and a hooked call made from inside them must get a fresh policy check
/// instead of stale suppression (anti_rec invariant 3).
///
/// Returns `true` when the activation is denied (`*ppv` already nulled).
/// `false` means the original must be invoked; this includes the
/// re-entrancy passthrough — when an outer hook window is already held on
/// this thread (`anti_rec::enter()` returns `None`) this returns `false`
/// unchecked, so the original still runs under that outer window exactly as
/// before the split.
///
/// # SAFETY
/// `rclsid` must be null or point to a readable GUID; `ppv` must be null or
/// valid for a pointer write.
unsafe fn co_create_instance_deny(
    rclsid: *const GUID,
    dw_cls_context: u32,
    ppv: *mut *mut c_void,
) -> bool {
    let Some(_guard) = anti_rec::enter() else {
        return false;
    };
    if let Some((name, terminate)) = check_denylist(rclsid) {
        if terminate {
            // Escape-class CLSID (spawn / lateral-movement / WMI): fail-stop.
            // Reports the violation over IPC and never returns.
            crate::hooks::report_and_terminate_escape("com-clsid", name);
        }
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace,
                format!("com_blocked clsid={} ctx=0x{:x}", name, dw_cls_context));
        }
        if !ppv.is_null() {
            *ppv = std::ptr::null_mut();
        }
        return true;
    }
    // Trace EVERY allowed activation too — lets us see which COM components a
    // workload actually touches (TSF/IME for keyboard, shell, MSCTF, ...) so
    // when something silently misbehaves we know what to look at. Gated on
    // is_trace() so production stays quiet.
    if is_trace() && !rclsid.is_null() {
        let g = *rclsid;
        ipc_log(ipc::LogLevel::Trace, format!(
            "com_allow clsid={{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}} ctx=0x{:x}",
            g.Data1, g.Data2, g.Data3,
            g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
            g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7],
            dw_cls_context));
    }
    false
}

// SAFETY: Called by detour2 dispatcher with combase!CoCreateInstance ABI.
unsafe extern "system" fn hook_co_create_instance(
    rclsid: *const GUID,
    p_unk_outer: *mut c_void,
    dw_cls_context: u32,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    let call_original = || {
// Detour-absent: unwrap-abort kept on purpose — HRESULT family; fail-closed would be a failing HRESULT (e.g. E_ACCESSDENIED), a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnCoCreateInstance ABI.
        HOOK_CO_CREATE_INSTANCE.get().unwrap().call(
            rclsid, p_unk_outer, dw_cls_context, riid, ppv,
        )
    };

    if co_create_instance_deny(rclsid, dw_cls_context, ppv) {
        return E_ACCESSDENIED;
    }

    // F1 (R04): the anti_rec window from the decision seam above is closed
    // here — see co_create_instance_deny.
    call_original()
}

/// F1 (R04) decision seam for `hook_co_create_instance_ex`: the denylist
/// check, escape report/terminate and trace logging run under an anti_rec
/// window this function opens and closes. The real activation runs after it
/// returns, OUTSIDE any suppression: an in-proc server's DllMain /
/// DllGetClassObject / QueryInterface are guest-reachable application code,
/// and a hooked call made from inside them must get a fresh policy check
/// instead of stale suppression (anti_rec invariant 3).
///
/// Returns `true` when the activation is denied. `false` means the original
/// must be invoked; this includes the re-entrancy passthrough — when an
/// outer hook window is already held on this thread (`anti_rec::enter()`
/// returns `None`) this returns `false` unchecked, so the original still
/// runs under that outer window exactly as before the split.
///
/// # SAFETY
/// `clsid` must be null or point to a readable GUID.
unsafe fn co_create_instance_ex_deny(
    clsid: *const GUID,
    dw_cls_ctx: u32,
) -> bool {
    let Some(_guard) = anti_rec::enter() else {
        return false;
    };
    if let Some((name, terminate)) = check_denylist(clsid) {
        if terminate {
            crate::hooks::report_and_terminate_escape("com-clsid", name);
        }
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace,
                format!("com_blocked_ex clsid={} ctx=0x{:x}", name, dw_cls_ctx));
        }
        return true;
    }
    false
}

// SAFETY: Called by detour2 dispatcher with combase!CoCreateInstanceEx ABI.
unsafe extern "system" fn hook_co_create_instance_ex(
    clsid: *const GUID,
    punk_outer: *mut c_void,
    dw_cls_ctx: u32,
    p_server_info: *mut c_void,
    dw_count: u32,
    p_results: *mut c_void,
) -> i32 {
    let call_original = || {
// Detour-absent: unwrap-abort kept on purpose — HRESULT family; fail-closed would be a failing HRESULT (e.g. E_ACCESSDENIED), a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnCoCreateInstanceEx ABI.
        HOOK_CO_CREATE_INSTANCE_EX.get().unwrap().call(
            clsid, punk_outer, dw_cls_ctx, p_server_info, dw_count, p_results,
        )
    };

    if co_create_instance_ex_deny(clsid, dw_cls_ctx) {
        return E_ACCESSDENIED;
    }

    // F1 (R04): the anti_rec window from the decision seam above is closed
    // here — see co_create_instance_ex_deny.
    call_original()
}

/// F1 (R04) decision seam for `hook_co_get_class_object`: the denylist
/// check, escape report/terminate and trace logging run under an anti_rec
/// window this function opens and closes. The real class-object retrieval
/// runs after it returns, OUTSIDE any suppression: an in-proc server's
/// DllMain / DllGetClassObject / QueryInterface are guest-reachable
/// application code, and a hooked call made from inside them must get a
/// fresh policy check instead of stale suppression (anti_rec invariant 3).
///
/// Returns `true` when the activation is denied (`*ppv` already nulled).
/// `false` means the original must be invoked; this includes the
/// re-entrancy passthrough — when an outer hook window is already held on
/// this thread (`anti_rec::enter()` returns `None`) this returns `false`
/// unchecked, so the original still runs under that outer window exactly as
/// before the split.
///
/// # SAFETY
/// `rclsid` must be null or point to a readable GUID; `ppv` must be null or
/// valid for a pointer write.
unsafe fn co_get_class_object_deny(
    rclsid: *const GUID,
    dw_cls_context: u32,
    ppv: *mut *mut c_void,
) -> bool {
    let Some(_guard) = anti_rec::enter() else {
        return false;
    };
    if let Some((name, terminate)) = check_denylist(rclsid) {
        if terminate {
            crate::hooks::report_and_terminate_escape("com-clsid", name);
        }
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace,
                format!("com_classobject_blocked clsid={} ctx=0x{:x}", name, dw_cls_context));
        }
        if !ppv.is_null() {
            *ppv = std::ptr::null_mut();
        }
        return true;
    }
    false
}

// SAFETY: Called by detour2 dispatcher with combase!CoGetClassObject ABI.
unsafe extern "system" fn hook_co_get_class_object(
    rclsid: *const GUID,
    dw_cls_context: u32,
    pv_reserved: *mut c_void,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    let call_original = || {
// Detour-absent: unwrap-abort kept on purpose — HRESULT family; fail-closed would be a failing HRESULT (e.g. E_ACCESSDENIED), a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnCoGetClassObject ABI.
        HOOK_CO_GET_CLASS_OBJECT.get().unwrap().call(
            rclsid, dw_cls_context, pv_reserved, riid, ppv,
        )
    };

    if co_get_class_object_deny(rclsid, dw_cls_context, ppv) {
        return E_ACCESSDENIED;
    }

    // F1 (R04): the anti_rec window from the decision seam above is closed
    // here — see co_get_class_object_deny.
    call_original()
}

// ---------------------------------------------------------------------------
// WinRT hook implementations
// ---------------------------------------------------------------------------

/// Decode an HSTRING to an owned `String` for matching against the denylist.
///
/// Returns `None` when:
///   - the HSTRING is null (treated as empty / not-matched),
///   - WindowsGetStringRawBuffer was not resolved (very old build), or
///   - the resolver returned a null/zero-length buffer.
///
/// # SAFETY
/// Caller must hold an anti_rec guard. `hs` is interpreted as a combase
/// HSTRING handle; if the caller passed a non-null value that is not a valid
/// HSTRING, behavior is whatever combase does in that case (typically a clean
/// error inside WindowsGetStringRawBuffer).
unsafe fn decode_hstring(hs: HSTRING) -> Option<String> {
    if hs.is_null() {
        return None;
    }
    let resolver = WINDOWS_GET_STRING_RAW_BUFFER.get().copied()?;
    let mut len: u32 = 0;
    let buf = resolver(hs, &mut len as *mut u32);
    if buf.is_null() || len == 0 {
        return None;
    }
    // SAFETY: combase guarantees `buf` points to `len` valid UTF-16 code units
    // for the lifetime of `hs`. We are still inside the hooked call, so the
    // caller's HSTRING reference keeps the buffer alive.
    let slice = std::slice::from_raw_parts(buf, len as usize);
    Some(String::from_utf16_lossy(slice))
}

/// F1 (R04) decision seam for `hook_ro_get_activation_factory`: the
/// HSTRING decode, WinRT denylist check, violation report and trace logging
/// run under an anti_rec window this function opens and closes. The real
/// factory retrieval runs after it returns, OUTSIDE any suppression: an
/// in-proc server's DllMain / DllGetClassObject / QueryInterface are
/// guest-reachable application code, and a hooked call made from inside them
/// must get a fresh policy check instead of stale suppression (anti_rec
/// invariant 3).
///
/// Returns `true` ONLY from the denied branch (`*factory` already nulled);
/// the allow/trace branch falls through to `false`. `false` means the
/// original must be invoked; this includes the re-entrancy passthrough —
/// when an outer hook window is already held on this thread
/// (`anti_rec::enter()` returns `None`) this returns `false` unchecked, so
/// the original still runs under that outer window exactly as before the
/// split.
///
/// # SAFETY
/// `activatable_class_id` must be null or a valid combase HSTRING handle —
/// this is decode_hstring's # SAFETY contract, and its caller-must-hold-an
/// anti_rec-guard requirement is satisfied by the window this seam opens.
/// `factory` must be null or valid for a pointer write.
unsafe fn ro_get_activation_factory_deny(
    activatable_class_id: HSTRING,
    factory: *mut *mut c_void,
) -> bool {
    let Some(_guard) = anti_rec::enter() else {
        return false;
    };
    // Holding `_guard` satisfies decode_hstring's caller-side SAFETY contract.
    if let Some(class_name) = decode_hstring(activatable_class_id) {
        if is_winrt_class_denied(&class_name) {
            crate::hooks::ipc_log_violation(ipc::Req::Log {
                pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                level: ipc::LogLevel::Warn,
                msg: format!("winrt_activation_blocked: {class_name}"),
            });
            if !factory.is_null() {
                *factory = std::ptr::null_mut();
            }
            return true;
        }
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace,
                format!("winrt_factory class={class_name}"));
        }
    }
    false
}

// SAFETY: Called by detour2 dispatcher with combase!RoGetActivationFactory ABI.
unsafe extern "system" fn hook_ro_get_activation_factory(
    activatable_class_id: HSTRING,
    iid: *const GUID,
    factory: *mut *mut c_void,
) -> i32 {
    let call_original = || {
// Detour-absent: unwrap-abort kept on purpose — HRESULT family; fail-closed would be a failing HRESULT (e.g. E_ACCESSDENIED), a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnRoGetActivationFactory ABI.
        HOOK_RO_GET_ACTIVATION_FACTORY.get().unwrap().call(
            activatable_class_id, iid, factory,
        )
    };

    if ro_get_activation_factory_deny(activatable_class_id, factory) {
        return REGDB_E_CLASSNOTREG;
    }

    // F1 (R04): the anti_rec window from the decision seam above is closed
    // here — see ro_get_activation_factory_deny.
    call_original()
}

/// F1 (R04) decision seam for `hook_ro_activate_instance`: the HSTRING
/// decode, WinRT denylist check, violation report and trace logging run
/// under an anti_rec window this function opens and closes. The real
/// activation runs after it returns, OUTSIDE any suppression: an in-proc
/// server's DllMain / DllGetClassObject / QueryInterface are guest-reachable
/// application code, and a hooked call made from inside them must get a
/// fresh policy check instead of stale suppression (anti_rec invariant 3).
///
/// Returns `true` ONLY from the denied branch (`*instance` already nulled);
/// the allow/trace branch falls through to `false`. `false` means the
/// original must be invoked; this includes the re-entrancy passthrough —
/// when an outer hook window is already held on this thread
/// (`anti_rec::enter()` returns `None`) this returns `false` unchecked, so
/// the original still runs under that outer window exactly as before the
/// split.
///
/// # SAFETY
/// `activatable_class_id` must be null or a valid combase HSTRING handle —
/// this is decode_hstring's # SAFETY contract, and its caller-must-hold-an
/// anti_rec-guard requirement is satisfied by the window this seam opens.
/// `instance` must be null or valid for a pointer write.
unsafe fn ro_activate_instance_deny(
    activatable_class_id: HSTRING,
    instance: *mut *mut c_void,
) -> bool {
    let Some(_guard) = anti_rec::enter() else {
        return false;
    };
    // Holding `_guard` satisfies decode_hstring's caller-side SAFETY contract.
    if let Some(class_name) = decode_hstring(activatable_class_id) {
        if is_winrt_class_denied(&class_name) {
            crate::hooks::ipc_log_violation(ipc::Req::Log {
                pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                level: ipc::LogLevel::Warn,
                msg: format!("winrt_activation_blocked: {class_name}"),
            });
            if !instance.is_null() {
                *instance = std::ptr::null_mut();
            }
            return true;
        }
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace,
                format!("winrt_activate class={class_name}"));
        }
    }
    false
}

// SAFETY: Called by detour2 dispatcher with combase!RoActivateInstance ABI.
unsafe extern "system" fn hook_ro_activate_instance(
    activatable_class_id: HSTRING,
    instance: *mut *mut c_void,
) -> i32 {
    let call_original = || {
// Detour-absent: unwrap-abort kept on purpose — HRESULT family; fail-closed would be a failing HRESULT (e.g. E_ACCESSDENIED), a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnRoActivateInstance ABI.
        HOOK_RO_ACTIVATE_INSTANCE.get().unwrap().call(
            activatable_class_id, instance,
        )
    };

    if ro_activate_instance_deny(activatable_class_id, instance) {
        return REGDB_E_CLASSNOTREG;
    }

    // F1 (R04): the anti_rec window from the decision seam above is closed
    // here — see ro_activate_instance_deny.
    call_original()
}

// ---------------------------------------------------------------------------
// combase.dll export resolver
// ---------------------------------------------------------------------------

/// # SAFETY
/// Must be called during install (DllMain context). `name` must be a null-terminated ASCII byte string.
unsafe fn combase_export(name: &[u8]) -> Option<*const c_void> {
    let module_w: Vec<u16> = "combase.dll\0".encode_utf16().collect();
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
/// R04 F4 policy — this module is MANDATORY for COM activation containment.
/// The three primary activation exports (CoCreateInstance / CoCreateInstanceEx
/// / CoGetClassObject) fail closed: a missing export returns Err, which
/// install_hooks propagates with `install()?` → DllMain FALSE → the launcher
/// kills the child. COM activation is an in-scope SECURITY.md escape path and
/// a combase bearing any of them always exports all three, so an absence
/// means the system is badly wrong rather than legitimately ancient. The
/// WinRT sibling closures below degrade instead: their failures are routed
/// through buffer_install_error, so they surface as the S10 degraded-init
/// event the launcher warns about without aborting the launch.
pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    // CoCreateInstance
    if let Some(addr1) = combase_export(b"CoCreateInstance\0") {
        // SAFETY: transmute of combase.dll export address; ABI matches FnCoCreateInstance.
        let target1: FnCoCreateInstance = std::mem::transmute(addr1);
        let hook_ptr1: FnCoCreateInstance = hook_co_create_instance;
        let detour1 = GenericDetour::<FnCoCreateInstance>::new(target1, hook_ptr1)
            .map_err(|e| format!("detour init CoCreateInstance: {:?}", e))?;
        HOOK_CO_CREATE_INSTANCE.set(detour1).ok();
        HOOK_CO_CREATE_INSTANCE.get().expect("set above").enable()
            .map_err(|e| format!("detour enable CoCreateInstance: {:?}", e))?;
    } else {
        return Err("com_guard: combase.dll export CoCreateInstance not found".into());
    }

    // CoCreateInstanceEx
    if let Some(addr2) = combase_export(b"CoCreateInstanceEx\0") {
        // SAFETY: transmute of combase.dll export address; ABI matches FnCoCreateInstanceEx.
        let target2: FnCoCreateInstanceEx = std::mem::transmute(addr2);
        let hook_ptr2: FnCoCreateInstanceEx = hook_co_create_instance_ex;
        let detour2 = GenericDetour::<FnCoCreateInstanceEx>::new(target2, hook_ptr2)
            .map_err(|e| format!("detour init CoCreateInstanceEx: {:?}", e))?;
        HOOK_CO_CREATE_INSTANCE_EX.set(detour2).ok();
        HOOK_CO_CREATE_INSTANCE_EX.get().expect("set above").enable()
            .map_err(|e| format!("detour enable CoCreateInstanceEx: {:?}", e))?;
    } else {
        return Err("com_guard: combase.dll export CoCreateInstanceEx not found".into());
    }

    // CoGetClassObject
    if let Some(addr3) = combase_export(b"CoGetClassObject\0") {
        // SAFETY: transmute of combase.dll export address; ABI matches FnCoGetClassObject.
        let target3: FnCoGetClassObject = std::mem::transmute(addr3);
        let hook_ptr3: FnCoGetClassObject = hook_co_get_class_object;
        let detour3 = GenericDetour::<FnCoGetClassObject>::new(target3, hook_ptr3)
            .map_err(|e| format!("detour init CoGetClassObject: {:?}", e))?;
        HOOK_CO_GET_CLASS_OBJECT.set(detour3).ok();
        HOOK_CO_GET_CLASS_OBJECT.get().expect("set above").enable()
            .map_err(|e| format!("detour enable CoGetClassObject: {:?}", e))?;
    } else {
        return Err("com_guard: combase.dll export CoGetClassObject not found".into());
    }

    // WindowsGetStringRawBuffer — required to decode HSTRING inside WinRT hooks.
    // If absent (very old Win build pre-RT), we skip installing the WinRT hooks
    // entirely rather than installing them in a half-functional state.
    let raw_buffer_resolved = if let Some(addr_rb) = combase_export(b"WindowsGetStringRawBuffer\0") {
        // SAFETY: transmute of combase.dll export address; ABI matches FnWindowsGetStringRawBuffer.
        let f: FnWindowsGetStringRawBuffer = std::mem::transmute(addr_rb);
        let _ = WINDOWS_GET_STRING_RAW_BUFFER.set(f);
        true
    } else {
        // OPTIONAL sibling closure (R04 F4): a pre-Win8 system has no WinRT
        // surface to guard, so a missing WindowsGetStringRawBuffer degrades
        // loudly — buffered into the install-error set so S10's
        // signal_init_events fires the launcher's degraded-init event —
        // instead of failing the whole install (mirrors reg_hooks' soft skip
        // of NtUnloadKey2 on Win7).
        buffer_install_error(
            "com_guard: combase.dll export WindowsGetStringRawBuffer not found — skipping WinRT hooks".into(),
        );
        false
    };

    // RoGetActivationFactory
    if raw_buffer_resolved {
        if let Some(addr4) = combase_export(b"RoGetActivationFactory\0") {
            // SAFETY: transmute of combase.dll export address; ABI matches FnRoGetActivationFactory.
            let target4: FnRoGetActivationFactory = std::mem::transmute(addr4);
            let hook_ptr4: FnRoGetActivationFactory = hook_ro_get_activation_factory;
            let detour4 = GenericDetour::<FnRoGetActivationFactory>::new(target4, hook_ptr4)
                .map_err(|e| format!("detour init RoGetActivationFactory: {:?}", e))?;
            HOOK_RO_GET_ACTIVATION_FACTORY.set(detour4).ok();
            HOOK_RO_GET_ACTIVATION_FACTORY.get().expect("set above").enable()
                .map_err(|e| format!("detour enable RoGetActivationFactory: {:?}", e))?;
        } else {
            // OPTIONAL sibling closure (R04 F4): RoGetActivationFactory sits
            // behind WindowsGetStringRawBuffer, so this is a WinRT-era export
            // on a WinRT-capable build — a miss means no WinRT activation
            // surface, so buffer the degradation (S10 degraded-init) rather
            // than abort the install.
            buffer_install_error(
                "com_guard: combase.dll export RoGetActivationFactory not found — skipping".into(),
            );
        }

        // RoActivateInstance
        if let Some(addr5) = combase_export(b"RoActivateInstance\0") {
            // SAFETY: transmute of combase.dll export address; ABI matches FnRoActivateInstance.
            let target5: FnRoActivateInstance = std::mem::transmute(addr5);
            let hook_ptr5: FnRoActivateInstance = hook_ro_activate_instance;
            let detour5 = GenericDetour::<FnRoActivateInstance>::new(target5, hook_ptr5)
                .map_err(|e| format!("detour init RoActivateInstance: {:?}", e))?;
            HOOK_RO_ACTIVATE_INSTANCE.set(detour5).ok();
            HOOK_RO_ACTIVATE_INSTANCE.get().expect("set above").enable()
                .map_err(|e| format!("detour enable RoActivateInstance: {:?}", e))?;
        } else {
            // OPTIONAL sibling closure (R04 F4), same posture as
            // RoGetActivationFactory above: buffered degradation, never a
            // silent skip.
            buffer_install_error(
                "com_guard: combase.dll export RoActivateInstance not found — skipping".into(),
            );
        }
    }

    if is_trace() {
        ipc_log(ipc::LogLevel::Trace, "com_guard_installed".into());
    }
    Ok(())
}

/// # SAFETY
/// Must be called from DLL_PROCESS_DETACH only.
pub unsafe fn uninstall() {
    if let Some(h) = HOOK_CO_CREATE_INSTANCE.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_CO_CREATE_INSTANCE_EX.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_CO_GET_CLASS_OBJECT.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_RO_GET_ACTIVATION_FACTORY.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_RO_ACTIVATE_INSTANCE.get() { let _ = h.disable(); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::denylist::guid;

    // ── F1 (R04): decision seams close the anti_rec window before the ──────
    // real activation trampoline runs. Application code dispatched INSIDE
    // the real CoCreateInstance (in-proc server DllMain / DllGetClassObject /
    // QueryInterface) is guest-reachable and may itself make hooked calls —
    // those must get a fresh policy check, not stale suppression.

    #[test]
    fn co_create_instance_deny_seam_closes_window_on_allow() {
        assert!(!crate::anti_rec::in_hook(), "precondition: no window held");
        // Same benign GUID `clsid_benign_not_denied` pins as allowed.
        let clsid = guid(0xDEADBEEF, 0x1234, 0x5678, [0x9A,0xBC,0xDE,0xF0,0x12,0x34,0x56,0x78]);
        let mut ppv: *mut c_void = std::ptr::null_mut();
        // SAFETY: local GUID and local out-pointer, both valid.
        let denied = unsafe { co_create_instance_deny(&clsid, 4, &mut ppv) };
        assert!(!denied, "benign CLSID must not be denied");
        assert!(ppv.is_null(), "allow path must not write *ppv");
        assert!(
            !crate::anti_rec::in_hook(),
            "F1: window must be closed at the call-original boundary"
        );
        // Decisive F1 assertion: a nested hook call — simulating code
        // dispatched inside the real CoCreateInstance — can open its own
        // window and run a full policy check. Pre-F1 this returned None.
        let nested = crate::anti_rec::enter().expect(
            "nested hook call must not be suppressed after the seam closed the window",
        );
        drop(nested);
        assert!(!crate::anti_rec::in_hook(), "window must be closed after nested drop");
    }

    #[test]
    fn co_create_instance_deny_seam_passthrough_when_window_already_held() {
        assert!(!crate::anti_rec::in_hook(), "precondition: no window held");
        // Outer hook window already held (this hook re-entered from inside
        // another hook): the seam must pass through unchecked so the original
        // still runs under the outer window — the recursion breaker preserved.
        let outer = crate::anti_rec::enter().expect("test thread must not be re-entrant");
        let clsid = guid(0xDEADBEEF, 0x1234, 0x5678, [0x9A,0xBC,0xDE,0xF0,0x12,0x34,0x56,0x78]);
        let mut ppv: *mut c_void = std::ptr::null_mut();
        // SAFETY: local GUID and local out-pointer, both valid.
        let denied = unsafe { co_create_instance_deny(&clsid, 4, &mut ppv) };
        assert!(!denied, "recursion breaker: passthrough must not deny");
        assert!(ppv.is_null(), "passthrough must not write *ppv");
        drop(outer);
        assert!(!crate::anti_rec::in_hook(), "outer window must be released");
    }

    #[test]
    fn co_create_instance_deny_seam_closes_window_on_deny() {
        assert!(!crate::anti_rec::in_hook(), "precondition: no window held");
        // Scripting.FileSystemObject is deny with terminate = false (see
        // ambiguous_clsids_deny_but_do_not_terminate) — safe to drive through
        // the seam; a terminate-class CLSID would kill the test process.
        let fso = guid(0x0D43FE01, 0xF093, 0x11CF, [0x89,0x40,0x00,0xA0,0xC9,0x05,0x42,0x28]);
        let mut ppv: *mut c_void = std::ptr::null_mut();
        // SAFETY: local GUID and local out-pointer, both valid.
        let denied = unsafe { co_create_instance_deny(&fso, 4, &mut ppv) };
        assert!(denied, "denylisted CLSID must be denied");
        assert!(ppv.is_null(), "deny path must null *ppv");
        assert!(
            !crate::anti_rec::in_hook(),
            "F1: window must be closed even on the deny path"
        );
        let nested = crate::anti_rec::enter().expect(
            "nested hook call must not be suppressed after the seam closed the window",
        );
        drop(nested);
    }
}
