// Tries CoGetClassObject(CLSID_ShellApplication) — the lower-level alternative
// to CoCreateInstance. Without hook: returns IClassFactory, attacker calls
// CreateInstance on it. With hook: E_ACCESSDENIED → exit 5.

use winapi::shared::guiddef::{CLSID, IID};
use winapi::um::combaseapi::{CoInitializeEx, CoGetClassObject, CoUninitialize};

// CLSID_ShellApplication = 13709620-C279-11CE-A49E-444553540000
const CLSID_SHELL_APPLICATION: CLSID = CLSID {
    Data1: 0x13709620,
    Data2: 0xC279,
    Data3: 0x11CE,
    Data4: [0xA4,0x9E,0x44,0x45,0x53,0x54,0x00,0x00],
};

// IID_IClassFactory = 00000001-0000-0000-C000-000000000046
const IID_ICLASS_FACTORY: IID = IID {
    Data1: 0x00000001, Data2: 0x0000, Data3: 0x0000,
    Data4: [0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46],
};

fn main() {
    eprintln!("[escape_com_classobject] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    unsafe {
        let hr = CoInitializeEx(std::ptr::null_mut(), 0x2); // COINIT_APARTMENTTHREADED
        if hr < 0 { eprintln!("CoInitializeEx failed 0x{:x}", hr); std::process::exit(2); }

        let mut factory: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let hr = CoGetClassObject(
            &CLSID_SHELL_APPLICATION,
            0x4 | 0x10,  // CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER
            std::ptr::null_mut(),
            &IID_ICLASS_FACTORY,
            &mut factory,
        );
        eprintln!("[escape_com_classobject] CoGetClassObject HRESULT=0x{:08x}", hr as u32);
        if hr == 0x80070005u32 as i32 {
            eprintln!("[escape_com_classobject] blocked: E_ACCESSDENIED");
            CoUninitialize();
            std::process::exit(5);
        }
        if hr < 0 {
            eprintln!("[escape_com_classobject] unrelated failure");
            CoUninitialize();
            std::process::exit(6);
        }
        eprintln!("[escape_com_classobject] FOUND: got IClassFactory — escape vector!");
        CoUninitialize();
        std::process::exit(0);
    }
}
