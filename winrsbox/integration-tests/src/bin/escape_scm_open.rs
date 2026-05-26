// Tries OpenSCManagerW with SC_MANAGER_ALL_ACCESS.
// Without service_guard: succeeds (or fails with ERROR_ACCESS_DENIED from OS ACL
// if non-admin).
// With service_guard: hook returns NULL with last error = 5 → exit 5.

use std::ptr::null_mut;
use winapi::um::winsvc::OpenSCManagerW;
use winapi::um::errhandlingapi::GetLastError;

const SC_MANAGER_ALL_ACCESS: u32 = 0xF003F;

fn main() {
    eprintln!("[escape_scm_open] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    unsafe {
        let scm = OpenSCManagerW(null_mut(), null_mut(), SC_MANAGER_ALL_ACCESS);
        if scm.is_null() {
            eprintln!("[escape_scm_open] blocked: SCM null, err={}", GetLastError());
            std::process::exit(5);
        }
        eprintln!("[escape_scm_open] FOUND: SCM open with ALL_ACCESS — escape vector!");
        winapi::um::winsvc::CloseServiceHandle(scm);
        std::process::exit(0);
    }
}
