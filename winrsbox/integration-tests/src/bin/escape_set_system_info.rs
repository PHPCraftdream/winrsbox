// Tries NtSetSystemInformation with a benign class. Without hook:
// fails with ACCESS_DENIED from OS (needs SeTcbPrivilege). With hook:
// our hook returns STATUS_ACCESS_DENIED first → exit 5.

use std::ptr::null_mut;

fn main() {
    eprintln!("[escape_set_system_info] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    type FnNtSetSysInfo = unsafe extern "system" fn(u32, *mut std::ffi::c_void, u32) -> i32;
    let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    unsafe {
        let h_ntdll = winapi::um::libloaderapi::GetModuleHandleW(ntdll_w.as_ptr());
        let addr = winapi::um::libloaderapi::GetProcAddress(h_ntdll,
            b"NtSetSystemInformation\0".as_ptr() as *const i8);
        if addr.is_null() {
            eprintln!("[escape_set_system_info] NtSetSystemInformation not exported");
            std::process::exit(8);
        }
        let func: FnNtSetSysInfo = std::mem::transmute(addr);

        // Use SystemRegistryQuotaInformation (class 37) — benign-looking class
        let mut dummy: [u8; 32] = [0; 32];
        let status = func(37, dummy.as_mut_ptr() as *mut _, 32);
        eprintln!("[escape_set_system_info] NtSetSystemInformation status=0x{:x}", status as u32);

        if status == 0xC0000022u32 as i32 {
            eprintln!("[escape_set_system_info] blocked: STATUS_ACCESS_DENIED");
            std::process::exit(5);
        }
        eprintln!("[escape_set_system_info] FOUND: unexpected status — hook didn't fire?");
        std::process::exit(0);
    }
}
