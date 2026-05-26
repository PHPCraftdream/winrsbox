// Tries OpenSCManager + OpenService with SERVICE_CHANGE_CONFIG.
// Even if SCM open succeeds (limited rights), OpenService should fail at hook.

use std::ptr::null_mut;
use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;
use winapi::um::winsvc::{OpenSCManagerW, OpenServiceW, CloseServiceHandle};
use winapi::um::errhandlingapi::GetLastError;

const SC_MANAGER_CONNECT: u32 = 0x0001;
const SERVICE_CHANGE_CONFIG: u32 = 0x0002;

fn main() {
    eprintln!("[escape_service_changeconfig] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    unsafe {
        let scm = OpenSCManagerW(null_mut(), null_mut(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            eprintln!("[escape_service_changeconfig] cannot connect to SCM, err={}", GetLastError());
            std::process::exit(7);
        }

        let name: Vec<u16> = OsStr::new("Spooler").encode_wide().chain(Some(0)).collect();
        let svc = OpenServiceW(scm, name.as_ptr(), SERVICE_CHANGE_CONFIG);
        if svc.is_null() {
            eprintln!("[escape_service_changeconfig] blocked: OpenService null, err={}", GetLastError());
            CloseServiceHandle(scm);
            std::process::exit(5);
        }
        eprintln!("[escape_service_changeconfig] FOUND: OpenService(Spooler, CHANGE_CONFIG) — escape!");
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        std::process::exit(0);
    }
}
