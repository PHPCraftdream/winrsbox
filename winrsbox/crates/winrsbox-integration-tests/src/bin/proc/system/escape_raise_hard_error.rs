// Tries NtRaiseHardError via GetProcAddress with OptionOk (0).
// Without hook: succeeds → attacker can escalate to BSOD/shutdown dialog.
// With hook: NtRaiseHardError returns STATUS_ACCESS_DENIED → exit 5.

fn main() {
    eprintln!("[escape_raise_hard_error] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    type FnNtRaiseHardError = unsafe extern "system" fn(
        i32,            // ErrorStatus
        u32,            // NumberOfParameters
        u32,            // UnicodeStringParameterMask
        *mut usize,     // Parameters
        u32,            // ValidResponseOptions (0 = OptionOk)
        *mut u32,       // Response (out)
    ) -> i32;

    let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    unsafe {
        let h_ntdll = winapi::um::libloaderapi::GetModuleHandleW(ntdll_w.as_ptr());
        let addr = winapi::um::libloaderapi::GetProcAddress(h_ntdll,
            b"NtRaiseHardError\0".as_ptr() as *const i8);
        if addr.is_null() {
            eprintln!("[escape_raise_hard_error] NtRaiseHardError not exported");
            std::process::exit(8);
        }
        let func: FnNtRaiseHardError = std::mem::transmute(addr);

        let mut response: u32 = 0;
        // STATUS_ASSERTION_FAILURE (0xC0000420) with OptionOk (0) — non-destructive
        // but still exercises the hook path identically to OptionShutdownSystem.
        let status = func(0xC0000420u32 as i32, 0, 0, std::ptr::null_mut(), 0, &mut response);
        eprintln!("[escape_raise_hard_error] NtRaiseHardError status=0x{:x}", status as u32);

        if status == 0xC0000022u32 as i32 {
            eprintln!("[escape_raise_hard_error] blocked: STATUS_ACCESS_DENIED");
            std::process::exit(5);
        }
        eprintln!("[escape_raise_hard_error] FOUND: hard error not blocked — escape vector!");
        std::process::exit(0);
    }
}
