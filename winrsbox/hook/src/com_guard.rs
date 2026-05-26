// COM guard — blocks out-of-proc COM activation (CoCreateInstance / CoCreateInstanceEx /
// CoGetClassObject) for dangerous CLSIDs that allow sandbox escape via process spawn or
// system modification.
//
// Denylisted CLSIDs: Shell.Application, WScript.Shell, FileSystemObject, WMI, Task Scheduler,
// BITS, Office automation. All are well-known escape vectors for AI agents.
//
// Hook targets: combase.dll!CoCreateInstance, combase.dll!CoCreateInstanceEx,
//               combase.dll!CoGetClassObject.

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
type FnCoCreateInstance = unsafe extern "C" fn(
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
type FnCoCreateInstanceEx = unsafe extern "C" fn(
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
type FnCoGetClassObject = unsafe extern "C" fn(
    *const GUID,       // rclsid
    u32,               // dwClsContext
    *mut c_void,       // pvReserved (COSERVERINFO*)
    *const GUID,       // riid
    *mut *mut c_void,  // ppv
) -> i32;

const E_ACCESSDENIED: i32 = 0x8007_0005_u32 as i32;

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

static HOOK_CO_CREATE_INSTANCE: OnceLock<GenericDetour<FnCoCreateInstance>> = OnceLock::new();
static HOOK_CO_CREATE_INSTANCE_EX: OnceLock<GenericDetour<FnCoCreateInstanceEx>> = OnceLock::new();
static HOOK_CO_GET_CLASS_OBJECT: OnceLock<GenericDetour<FnCoGetClassObject>> = OnceLock::new();

// ---------------------------------------------------------------------------
// Hook implementations
// ---------------------------------------------------------------------------

unsafe extern "C" fn hook_co_create_instance(
    rclsid: *const GUID,
    p_unk_outer: *mut c_void,
    dw_cls_context: u32,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    let call_original = || {
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

unsafe extern "C" fn hook_co_create_instance_ex(
    clsid: *const GUID,
    punk_outer: *mut c_void,
    dw_cls_ctx: u32,
    p_server_info: *mut c_void,
    dw_count: u32,
    p_results: *mut c_void,
) -> i32 {
    let call_original = || {
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

unsafe extern "C" fn hook_co_get_class_object(
    rclsid: *const GUID,
    dw_cls_context: u32,
    pv_reserved: *mut c_void,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32 {
    let call_original = || {
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
// combase.dll export resolver
// ---------------------------------------------------------------------------

unsafe fn combase_export(name: &[u8]) -> Option<*const c_void> {
    let module_w: Vec<u16> = "combase.dll\0".encode_utf16().collect();
    let h = winapi::um::libloaderapi::LoadLibraryW(module_w.as_ptr());
    if h.is_null() { return None; }
    let addr = winapi::um::libloaderapi::GetProcAddress(h, name.as_ptr() as *const i8);
    if addr.is_null() { None } else { Some(addr as *const c_void) }
}

// ---------------------------------------------------------------------------
// Install / Uninstall
// ---------------------------------------------------------------------------

pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    // CoCreateInstance
    if let Some(addr1) = combase_export(b"CoCreateInstance\0") {
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

    if is_trace() {
        ipc_log(ipc::LogLevel::Trace, "com_guard_installed".into());
    }
    Ok(())
}

pub unsafe fn uninstall() {
    if let Some(h) = HOOK_CO_CREATE_INSTANCE.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_CO_CREATE_INSTANCE_EX.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_CO_GET_CLASS_OBJECT.get() { let _ = h.disable(); }
}
