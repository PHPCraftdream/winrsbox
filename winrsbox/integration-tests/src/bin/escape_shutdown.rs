// Calls NtShutdownSystem directly. Without hook: may fail with
// STATUS_PRIVILEGE_NOT_HELD. With hook: STATUS_ACCESS_DENIED → exit 5.

fn main() {
    eprintln!("[escape_shutdown] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    type FnNtShutdownSystem = unsafe extern "system" fn(u32) -> i32;
    let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    unsafe {
        let h = winapi::um::libloaderapi::GetModuleHandleW(ntdll_w.as_ptr());
        let addr = winapi::um::libloaderapi::GetProcAddress(h,
            b"NtShutdownSystem\0".as_ptr() as *const i8);
        if addr.is_null() {
            eprintln!("[escape_shutdown] NtShutdownSystem not exported");
            std::process::exit(8);
        }
        let func: FnNtShutdownSystem = std::mem::transmute(addr);
        let status = func(0); // ShutdownNoReboot
        eprintln!("[escape_shutdown] NtShutdownSystem status=0x{:x}", status as u32);
        if status == 0xC0000022u32 as i32 {
            eprintln!("[escape_shutdown] blocked: STATUS_ACCESS_DENIED");
            std::process::exit(5);
        }
        std::process::exit(0);
    }
}
