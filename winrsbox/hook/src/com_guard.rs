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

use std::sync::OnceLock;

use detour2::GenericDetour;
use winapi::ctypes::c_void;
use winapi::shared::guiddef::GUID;

use crate::anti_rec;
use crate::hooks::{ipc_log, is_trace};

// ---------------------------------------------------------------------------
// CLSID denylist
// ---------------------------------------------------------------------------

#[allow(non_snake_case)]
const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> GUID {
    GUID { Data1: d1, Data2: d2, Data3: d3, Data4: d4 }
}

struct DenyEntry {
    clsid: GUID,
    name: &'static str,
}

const CLSID_DENYLIST: &[DenyEntry] = &[
    // Shell escape
    DenyEntry { clsid: guid(0x13709620, 0xC279, 0x11CE, [0xA4,0x9E,0x44,0x45,0x53,0x54,0x00,0x00]), name: "Shell.Application" },
    DenyEntry { clsid: guid(0x9BA05972, 0xF6A8, 0x11CF, [0xA4,0x42,0x00,0xA0,0xC9,0x0A,0x8F,0x39]), name: "ShellWindows" },

    // Scripting host
    DenyEntry { clsid: guid(0x72C24DD5, 0xD70A, 0x438B, [0x8A,0x42,0x98,0x42,0x4B,0x88,0xAF,0xB8]), name: "WScript.Shell" },
    DenyEntry { clsid: guid(0xF935DC22, 0x1CF0, 0x11D0, [0xAD,0xB9,0x00,0xC0,0x4F,0xD5,0x8A,0x0B]), name: "WScript.Shell.1" },
    DenyEntry { clsid: guid(0x0D43FE01, 0xF093, 0x11CF, [0x89,0x40,0x00,0xA0,0xC9,0x05,0x42,0x28]), name: "Scripting.FileSystemObject" },

    // WMI (Win32_Process.Create)
    DenyEntry { clsid: guid(0x4590F811, 0x1D3A, 0x11D0, [0x89,0x1F,0x00,0xAA,0x00,0x4B,0x2E,0x24]), name: "WbemLocator" },
    DenyEntry { clsid: guid(0x76A64158, 0xCB41, 0x11D1, [0x8B,0x02,0x00,0x60,0x08,0x06,0xD9,0xB6]), name: "WbemScripting.SWbemLocator" },

    // Task Scheduler
    DenyEntry { clsid: guid(0x0F87369F, 0xA4E5, 0x4CFC, [0xBD,0x3E,0x73,0xE6,0x15,0x45,0x72,0xDD]), name: "Schedule.Service" },
    DenyEntry { clsid: guid(0x148BD52A, 0xA2AB, 0x11CE, [0xB1,0x1F,0x00,0xAA,0x00,0x53,0x05,0x03]), name: "CTaskScheduler" },

    // BITS
    DenyEntry { clsid: guid(0x4991D34B, 0x80A1, 0x4291, [0x83,0xB6,0x33,0x28,0x36,0x6B,0x90,0x97]), name: "BackgroundCopyManager" },

    // Office (high-impact if installed)
    DenyEntry { clsid: guid(0x00024500, 0x0000, 0x0000, [0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46]), name: "Excel.Application" },
    DenyEntry { clsid: guid(0x000209FF, 0x0000, 0x0000, [0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46]), name: "Word.Application" },
    DenyEntry { clsid: guid(0x0006F03A, 0x0000, 0x0000, [0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46]), name: "Outlook.Application" },
];

fn clsid_eq(a: &GUID, b: &GUID) -> bool {
    a.Data1 == b.Data1 && a.Data2 == b.Data2 && a.Data3 == b.Data3 && a.Data4 == b.Data4
}

fn check_denylist(clsid: *const GUID) -> Option<&'static str> {
    if clsid.is_null() { return None; }
    // SAFETY: deref of non-null GUID pointer — caller must ensure it points to a valid GUID.
    let clsid = unsafe { &*clsid };
    for entry in CLSID_DENYLIST {
        if clsid_eq(clsid, &entry.clsid) {
            return Some(entry.name);
        }
    }
    None
}

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
// WinRT activation denylist (case-insensitive prefix match on runtime class name)
// ---------------------------------------------------------------------------

// NOTE on `windows.devices` umbrella entry:
//
// We deliberately deny the entire `Windows.Devices.*` namespace as a single
// policy choice rather than enumerating each leaf (`Bluetooth`, `Usb`, `Hid`,
// `SmartCards`, `PointOfService`, `Geolocation`, `Sensors`, `Radios`, ...).
// The sandbox has no legitimate need for any device-control or device-data API:
//   * Any subspace is a plausible exfil vector (Geolocation, Radios, Sensors).
//   * Any subspace is a plausible peripheral-spoofing vector (Hid, Usb, Bluetooth).
//   * New Windows.Devices.* leaves added by future Windows releases are
//     automatically covered without requiring a denylist update.
// If a sandboxed workload legitimately needs (e.g.) Geolocation, the correct
// path is a launcher-side capability grant rather than poking holes in this
// umbrella block.
const WINRT_DENY_PREFIXES: &[&str] = &[
    "windows.system.launcher",                  // LaunchUriAsync, LaunchFileAsync
    "windows.system.remotelauncher",
    "windows.system.diagnostics",               // ProcessDiagnosticInfo
    "windows.applicationmodel.appservice",
    "windows.applicationmodel.background",      // BackgroundTaskRegistration
    "windows.management.deployment",            // PackageManager
    "windows.storage.pickers",                  // FileOpenPicker
    "windows.system.remotedesktop",
    "windows.system.remotesystems",
    "windows.networking.sockets",               // socket via WinRT (defense-in-depth)
    "windows.ui.notifications",                 // toast persistence
    "windows.system.scheduler",                 // TaskScheduler equivalent
    "windows.system.power",                     // PowerManager.RequestShutdown/Restart
    "windows.system.threading",                 // ThreadPoolTimer delayed callbacks
    "windows.system.userprofile",
    "windows.system.profile",                   // hardware-id exfil
    "windows.devices",                          // umbrella: Bluetooth/USB/HID/etc — see note above
    "windows.foundation.diagnostics",           // user-mode ETW
    "windows.ui.notifications.management",      // toast exfil
    "windows.applicationmodel.core",
    "windows.applicationmodel.activation",
    "windows.applicationmodel.contacts",
    "windows.applicationmodel.appointments",
    "windows.security.credentials",             // PasswordVault credential extraction
    "windows.security.exchangeactivesyncprovisioning",
];

/// Returns true if `name` matches any denied WinRT activation class prefix
/// (case-insensitive). Extracted as a free function so it's unit-testable
/// without touching any FFI or detour state.
fn is_winrt_class_denied(name: &str) -> bool {
    // We do per-byte ASCII lowercase comparison to avoid allocating a lowercased
    // copy of every incoming class name. All denylist entries and all valid WinRT
    // runtime class names are ASCII per Windows.Foundation rules.
    let bytes = name.as_bytes();
    for prefix in WINRT_DENY_PREFIXES {
        let p = prefix.as_bytes();
        if bytes.len() < p.len() { continue; }
        let mut ok = true;
        for i in 0..p.len() {
            if bytes[i].to_ascii_lowercase() != p[i] {
                ok = false;
                break;
            }
        }
        if ok {
            // For a "prefix" match, accept either end-of-string or a separator
            // (`.`) immediately after the prefix to avoid the prefix accidentally
            // matching a longer unrelated identifier.
            if bytes.len() == p.len() {
                return true;
            }
            let next = bytes[p.len()];
            if next == b'.' {
                return true;
            }
        }
    }
    false
}

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

// SAFETY: Called by detour2 dispatcher with combase!CoCreateInstance ABI.
unsafe extern "system" fn hook_co_create_instance(
    rclsid: *const GUID,
    p_unk_outer: *mut c_void,
    dw_cls_context: u32,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    let call_original = || {
        // SAFETY: detour2 trampoline matches FnCoCreateInstance ABI.
        HOOK_CO_CREATE_INSTANCE.get().unwrap().call(
            rclsid, p_unk_outer, dw_cls_context, riid, ppv,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if let Some(name) = check_denylist(rclsid) {
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace,
                format!("com_blocked clsid={} ctx=0x{:x}", name, dw_cls_context));
        }
        if !ppv.is_null() {
            *ppv = std::ptr::null_mut();
        }
        return E_ACCESSDENIED;
    }

    call_original()
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
        // SAFETY: detour2 trampoline matches FnCoCreateInstanceEx ABI.
        HOOK_CO_CREATE_INSTANCE_EX.get().unwrap().call(
            clsid, punk_outer, dw_cls_ctx, p_server_info, dw_count, p_results,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if let Some(name) = check_denylist(clsid) {
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace,
                format!("com_blocked_ex clsid={} ctx=0x{:x}", name, dw_cls_ctx));
        }
        return E_ACCESSDENIED;
    }

    call_original()
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
        // SAFETY: detour2 trampoline matches FnCoGetClassObject ABI.
        HOOK_CO_GET_CLASS_OBJECT.get().unwrap().call(
            rclsid, dw_cls_context, pv_reserved, riid, ppv,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if let Some(name) = check_denylist(rclsid) {
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace,
                format!("com_classobject_blocked clsid={} ctx=0x{:x}", name, dw_cls_context));
        }
        if !ppv.is_null() {
            *ppv = std::ptr::null_mut();
        }
        return E_ACCESSDENIED;
    }

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

// SAFETY: Called by detour2 dispatcher with combase!RoGetActivationFactory ABI.
unsafe extern "system" fn hook_ro_get_activation_factory(
    activatable_class_id: HSTRING,
    iid: *const GUID,
    factory: *mut *mut c_void,
) -> i32 {
    let call_original = || {
        // SAFETY: detour2 trampoline matches FnRoGetActivationFactory ABI.
        HOOK_RO_GET_ACTIVATION_FACTORY.get().unwrap().call(
            activatable_class_id, iid, factory,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

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
            return REGDB_E_CLASSNOTREG;
        }
    }

    call_original()
}

// SAFETY: Called by detour2 dispatcher with combase!RoActivateInstance ABI.
unsafe extern "system" fn hook_ro_activate_instance(
    activatable_class_id: HSTRING,
    instance: *mut *mut c_void,
) -> i32 {
    let call_original = || {
        // SAFETY: detour2 trampoline matches FnRoActivateInstance ABI.
        HOOK_RO_ACTIVATE_INSTANCE.get().unwrap().call(
            activatable_class_id, instance,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

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
            return REGDB_E_CLASSNOTREG;
        }
    }

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
        ipc_log(ipc::LogLevel::Warn,
            "com_guard: combase.dll export CoCreateInstance not found — skipping".into());
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
        ipc_log(ipc::LogLevel::Warn,
            "com_guard: combase.dll export CoCreateInstanceEx not found — skipping".into());
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
        ipc_log(ipc::LogLevel::Warn,
            "com_guard: combase.dll export CoGetClassObject not found — skipping".into());
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
        ipc_log(ipc::LogLevel::Warn,
            "com_guard: combase.dll export WindowsGetStringRawBuffer not found — skipping WinRT hooks".into());
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
            ipc_log(ipc::LogLevel::Warn,
                "com_guard: combase.dll export RoGetActivationFactory not found — skipping".into());
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
            ipc_log(ipc::LogLevel::Warn,
                "com_guard: combase.dll export RoActivateInstance not found — skipping".into());
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

    #[test]
    fn winrt_deny_matches_prefix_case_insensitive() {
        // Exact match.
        assert!(is_winrt_class_denied("Windows.System.Launcher"));
        // Sub-class under denied prefix.
        assert!(is_winrt_class_denied("Windows.System.Launcher.LaunchUriParameters"));
        // Case-insensitive — uppercased prefix segment.
        assert!(is_winrt_class_denied("WINDOWS.System.Launcher"));
        // Fully uppercase.
        assert!(is_winrt_class_denied("WINDOWS.SYSTEM.LAUNCHER.LAUNCHURIPARAMETERS"));

        // Other denylist entries.
        assert!(is_winrt_class_denied("Windows.Management.Deployment.PackageManager"));
        assert!(is_winrt_class_denied("Windows.Storage.Pickers.FileOpenPicker"));
        assert!(is_winrt_class_denied("Windows.System.Diagnostics.ProcessDiagnosticInfo"));
        assert!(is_winrt_class_denied("Windows.ApplicationModel.AppService.AppServiceConnection"));

        // NOT denied — different sub-namespace under Windows.
        assert!(!is_winrt_class_denied("Windows.UI.Xaml.Controls.Button"));
        assert!(!is_winrt_class_denied("Windows.Foundation.Uri"));
        assert!(!is_winrt_class_denied("Windows.Data.Json.JsonObject"));

        // Empty string must not match.
        assert!(!is_winrt_class_denied(""));

        // Regression: prefix must be bounded on a `.` separator — a class whose
        // first segment shares a prefix-string with a denied entry but is a
        // distinct identifier must NOT match.
        assert!(!is_winrt_class_denied("Windows.System.LauncherEx"));
        assert!(!is_winrt_class_denied("Windows.System.SchedulerService"));
    }

    /// Smoke-check every entry in `WINRT_DENY_PREFIXES` so a typo or stray
    /// uppercase character in the table is caught at test time. Iterates the
    /// full list and asserts both the exact prefix and a `.<sub>` form match.
    #[test]
    fn coverage_of_every_listed_winrt_prefix() {
        for p in WINRT_DENY_PREFIXES {
            // Exact-prefix form must match.
            assert!(
                is_winrt_class_denied(p),
                "expected to be denied (exact): {p}"
            );
            // Sub-namespace form (`prefix.Child`) must also match.
            let sub = format!("{p}.Child");
            assert!(
                is_winrt_class_denied(&sub),
                "expected to be denied (sub): {sub}"
            );
            // Uppercased form must match (case-insensitive guarantee).
            let upper: String = p.to_ascii_uppercase();
            assert!(
                is_winrt_class_denied(&upper),
                "expected to be denied (uppercased): {upper}"
            );
            // Every entry must itself be stored in lowercase or the
            // case-insensitive comparison will silently miss it.
            assert_eq!(
                *p,
                p.to_ascii_lowercase(),
                "WINRT_DENY_PREFIXES entry not lowercased: {p}"
            );
        }
    }

    /// Pins the size of the WinRT denylist so silent regressions (an entry
    /// accidentally deleted during a merge) are caught at test time.
    /// Update this number deliberately when adding/removing entries.
    #[test]
    fn winrt_deny_list_count_pinned() {
        assert_eq!(WINRT_DENY_PREFIXES.len(), 25);
    }

    /// Spot-checks for the newly added entries — each one should match a
    /// realistic class name that exists in the Windows.* namespace.
    #[test]
    fn newly_added_winrt_prefixes_match_realistic_classes() {
        assert!(is_winrt_class_denied("Windows.System.Power.PowerManager"));
        assert!(is_winrt_class_denied("Windows.System.Threading.ThreadPoolTimer"));
        assert!(is_winrt_class_denied("Windows.System.UserProfile.GlobalizationPreferences"));
        assert!(is_winrt_class_denied("Windows.System.Profile.AnalyticsInfo"));
        // Devices umbrella covers every leaf.
        assert!(is_winrt_class_denied("Windows.Devices.Bluetooth.BluetoothDevice"));
        assert!(is_winrt_class_denied("Windows.Devices.Usb.UsbDevice"));
        assert!(is_winrt_class_denied("Windows.Devices.HumanInterfaceDevice.HidDevice"));
        assert!(is_winrt_class_denied("Windows.Devices.Geolocation.Geolocator"));
        assert!(is_winrt_class_denied("Windows.Devices.Radios.Radio"));
        assert!(is_winrt_class_denied("Windows.Foundation.Diagnostics.LoggingChannel"));
        assert!(is_winrt_class_denied("Windows.UI.Notifications.Management.UserNotificationListener"));
        assert!(is_winrt_class_denied("Windows.ApplicationModel.Core.CoreApplication"));
        assert!(is_winrt_class_denied("Windows.ApplicationModel.Activation.LaunchActivatedEventArgs"));
        assert!(is_winrt_class_denied("Windows.ApplicationModel.Contacts.Contact"));
        assert!(is_winrt_class_denied("Windows.ApplicationModel.Appointments.Appointment"));
        assert!(is_winrt_class_denied("Windows.Security.Credentials.PasswordVault"));
        assert!(is_winrt_class_denied(
            "Windows.Security.ExchangeActiveSyncProvisioning.EasClientDeviceInformation"
        ));
    }
}
