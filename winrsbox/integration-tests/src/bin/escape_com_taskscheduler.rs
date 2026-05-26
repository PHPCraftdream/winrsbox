// Tries CoCreateInstance(CLSID_Schedule.Service).
// With com_guard: CoCreateInstance returns E_ACCESSDENIED → exit 5.
// Without: Task Scheduler can schedule process execution via svchost.

use winapi::shared::guiddef::GUID;

const CLSID_SCHEDULE_SERVICE: GUID = GUID {
    Data1: 0x0F87369F,
    Data2: 0xA4E5,
    Data3: 0x4CFC,
    Data4: [0xBD, 0x3E, 0x73, 0xE6, 0x15, 0x45, 0x72, 0xDD],
};

const IID_IUNKNOWN: GUID = GUID {
    Data1: 0x00000000,
    Data2: 0x0000,
    Data3: 0x0000,
    Data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

type FnCoCreateInstance = unsafe extern "system" fn(
    *const GUID, *mut winapi::ctypes::c_void, u32, *const GUID, *mut *mut winapi::ctypes::c_void,
) -> i32;

type FnCoInitializeEx = unsafe extern "system" fn(*mut winapi::ctypes::c_void, u32) -> i32;
type FnCoUninitialize = unsafe extern "system" fn();

fn main() {
    eprintln!("[escape_com_taskscheduler] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    unsafe {
        let combase: Vec<u16> = "combase.dll\0".encode_utf16().collect();
        let hmod = winapi::um::libloaderapi::LoadLibraryW(combase.as_ptr());
        if hmod.is_null() {
            eprintln!("[escape_com_taskscheduler] combase.dll not found");
            std::process::exit(3);
        }

        let init_addr = winapi::um::libloaderapi::GetProcAddress(hmod, b"CoInitializeEx\0".as_ptr() as *const i8);
        let cci_addr = winapi::um::libloaderapi::GetProcAddress(hmod, b"CoCreateInstance\0".as_ptr() as *const i8);
        let uninit_addr = winapi::um::libloaderapi::GetProcAddress(hmod, b"CoUninitialize\0".as_ptr() as *const i8);

        if init_addr.is_null() || cci_addr.is_null() || uninit_addr.is_null() {
            eprintln!("[escape_com_taskscheduler] COM exports not found");
            std::process::exit(3);
        }

        let co_init: FnCoInitializeEx = std::mem::transmute(init_addr);
        let co_create: FnCoCreateInstance = std::mem::transmute(cci_addr);
        let co_uninit: FnCoUninitialize = std::mem::transmute(uninit_addr);

        let hr = co_init(std::ptr::null_mut(), 0x2);
        if hr < 0 {
            eprintln!("[escape_com_taskscheduler] CoInitializeEx failed 0x{:x}", hr as u32);
            std::process::exit(2);
        }

        let mut p: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let hr = co_create(
            &CLSID_SCHEDULE_SERVICE,
            std::ptr::null_mut(),
            0x4 | 0x10,
            &IID_IUNKNOWN,
            &mut p,
        );
        eprintln!("[escape_com_taskscheduler] CoCreateInstance HRESULT=0x{:08x}", hr as u32);
        if hr == 0x80070005u32 as i32 {
            eprintln!("[escape_com_taskscheduler] blocked: E_ACCESSDENIED");
            co_uninit();
            std::process::exit(5);
        }
        if hr < 0 {
            eprintln!("[escape_com_taskscheduler] failed for other reason");
            co_uninit();
            std::process::exit(6);
        }
        eprintln!("[escape_com_taskscheduler] FOUND: CoCreateInstance succeeded — escape vector available!");
        co_uninit();
        std::process::exit(0);
    }
}
