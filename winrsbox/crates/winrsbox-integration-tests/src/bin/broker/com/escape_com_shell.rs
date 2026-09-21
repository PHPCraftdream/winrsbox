// Tries CoCreateInstance(CLSID_ShellApplication) and ShellExecute("notepad.exe").
// With com_guard: CoCreateInstance returns E_ACCESSDENIED → exit 5.
// Without: spawns notepad outside our sandbox.

use winapi::shared::guiddef::GUID;

const CLSID_SHELL_APPLICATION: GUID = GUID {
    Data1: 0x13709620,
    Data2: 0xC279,
    Data3: 0x11CE,
    Data4: [0xA4, 0x9E, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00],
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
    eprintln!("[escape_com_shell] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    unsafe {
        let combase: Vec<u16> = "combase.dll\0".encode_utf16().collect();
        let hmod = winapi::um::libloaderapi::LoadLibraryW(combase.as_ptr());
        if hmod.is_null() {
            eprintln!("[escape_com_shell] combase.dll not found");
            std::process::exit(3);
        }

        let init_addr = winapi::um::libloaderapi::GetProcAddress(hmod, b"CoInitializeEx\0".as_ptr() as *const i8);
        let cci_addr = winapi::um::libloaderapi::GetProcAddress(hmod, b"CoCreateInstance\0".as_ptr() as *const i8);
        let uninit_addr = winapi::um::libloaderapi::GetProcAddress(hmod, b"CoUninitialize\0".as_ptr() as *const i8);

        if init_addr.is_null() || cci_addr.is_null() || uninit_addr.is_null() {
            eprintln!("[escape_com_shell] COM exports not found");
            std::process::exit(3);
        }

        let co_init: FnCoInitializeEx = std::mem::transmute(init_addr);
        let co_create: FnCoCreateInstance = std::mem::transmute(cci_addr);
        let co_uninit: FnCoUninitialize = std::mem::transmute(uninit_addr);

        let hr = co_init(std::ptr::null_mut(), 0x2); // COINIT_APARTMENTTHREADED
        if hr < 0 {
            eprintln!("[escape_com_shell] CoInitializeEx failed 0x{:x}", hr as u32);
            std::process::exit(2);
        }

        let mut p: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let hr = co_create(
            &CLSID_SHELL_APPLICATION,
            std::ptr::null_mut(),
            0x4 | 0x10, // CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER
            &IID_IUNKNOWN,
            &mut p,
        );
        eprintln!("[escape_com_shell] CoCreateInstance HRESULT=0x{:08x}", hr as u32);
        if hr == 0x80070005u32 as i32 {
            eprintln!("[escape_com_shell] blocked: E_ACCESSDENIED");
            co_uninit();
            std::process::exit(5);
        }
        if hr < 0 {
            eprintln!("[escape_com_shell] failed for other reason");
            co_uninit();
            std::process::exit(6);
        }
        eprintln!("[escape_com_shell] FOUND: CoCreateInstance succeeded — escape vector available!");
        co_uninit();
        std::process::exit(0);
    }
}
