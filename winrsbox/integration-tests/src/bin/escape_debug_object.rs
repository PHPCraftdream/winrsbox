// Tries NtCreateDebugObject via GetProcAddress.
// Without hook: succeeds → attacker can NtDebugActiveProcess on a target.
// With hook: NtCreateDebugObject returns STATUS_ACCESS_DENIED → exit 5.

use std::ptr::null_mut;

fn main() {
    eprintln!("[escape_debug_object] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    type FnNtCreateDebugObject = unsafe extern "system" fn(
        *mut *mut std::ffi::c_void,  // DebugObjectHandle
        u32,                          // DesiredAccess
        *mut std::ffi::c_void,        // ObjectAttributes
        u32,                          // Flags
    ) -> i32;

    let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    unsafe {
        let h_ntdll = winapi::um::libloaderapi::GetModuleHandleW(ntdll_w.as_ptr());
        let addr = winapi::um::libloaderapi::GetProcAddress(h_ntdll,
            b"NtCreateDebugObject\0".as_ptr() as *const i8);
        if addr.is_null() {
            eprintln!("[escape_debug_object] NtCreateDebugObject not exported");
            std::process::exit(8);
        }
        let func: FnNtCreateDebugObject = std::mem::transmute(addr);

        let mut dbg_obj: *mut std::ffi::c_void = null_mut();
        // DEBUG_PROCESS_ASSIGN (0x2) | DEBUG_READ_EVENT (0x1) = DEBUG_ALL_ACCESS subset
        let status = func(&mut dbg_obj, 0x1F0003, null_mut(), 0);
        eprintln!("[escape_debug_object] NtCreateDebugObject status=0x{:x}", status as u32);

        if status == 0xC0000022u32 as i32 {
            eprintln!("[escape_debug_object] blocked: STATUS_ACCESS_DENIED");
            std::process::exit(5);
        }
        if status == 0 && !dbg_obj.is_null() {
            eprintln!("[escape_debug_object] FOUND: got debug object handle — escape vector!");
            std::process::exit(0);
        }
        eprintln!("[escape_debug_object] unexpected status 0x{:x}", status as u32);
        std::process::exit(0);
    }
}
