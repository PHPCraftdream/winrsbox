// Tries NtMapViewOfSection into a foreign (non-self) process.
// Without hook: succeeds → attacker's section mapped into foreign address space.
// With hook: STATUS_ACCESS_DENIED → exit 5.

use winapi::shared::minwindef::FALSE;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::{PROCESS_VM_OPERATION, PROCESS_VM_READ, PAGE_READWRITE};
use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use winapi::um::tlhelp32::*;

fn find_pid(name: &str) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE { return None; }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut e) == 0 { CloseHandle(snap); return None; }
        loop {
            let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
            let exe = String::from_utf16_lossy(&e.szExeFile[..len]).to_lowercase();
            if exe == name.to_lowercase() { CloseHandle(snap); return Some(e.th32ProcessID); }
            if Process32NextW(snap, &mut e) == 0 { CloseHandle(snap); return None; }
        }
    }
}

fn main() {
    eprintln!("[escape_map_foreign] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    let pid = match find_pid("explorer.exe") {
        Some(p) => p,
        None => { eprintln!("explorer.exe absent, skip"); std::process::exit(7); }
    };

    unsafe {
        // Open foreign target with VM_OPERATION (proc_guard will likely deny — defense in depth)
        let h = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, pid);
        if h.is_null() {
            eprintln!("[escape_map_foreign] blocked at OpenProcess (proc_guard) — defense in depth");
            std::process::exit(5);
        }

        // Create a small RW section to map — point is foreign mapping
        // Use NtCreateSection from ntdll for raw access
        type FnNtCreateSection = unsafe extern "system" fn(
            *mut std::ffi::c_void,  // SectionHandle out
            u32,                     // DesiredAccess
            *mut std::ffi::c_void,   // ObjectAttributes
            *mut i64,                // MaximumSize
            u32,                     // SectionPageProtection
            u32,                     // AllocationAttributes
            *mut std::ffi::c_void,   // FileHandle
        ) -> i32;

        type FnNtMapViewOfSection = unsafe extern "system" fn(
            *mut std::ffi::c_void,   // SectionHandle
            *mut std::ffi::c_void,   // ProcessHandle
            *mut *mut std::ffi::c_void,  // BaseAddress
            usize,                    // ZeroBits
            usize,                    // CommitSize
            *mut i64,                 // SectionOffset
            *mut usize,               // ViewSize
            u32,                      // InheritDisposition
            u32,                      // AllocationType
            u32,                      // Win32Protect
        ) -> i32;

        let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let h_ntdll = winapi::um::libloaderapi::GetModuleHandleW(ntdll_w.as_ptr());
        let nt_create_section: FnNtCreateSection = std::mem::transmute(
            winapi::um::libloaderapi::GetProcAddress(h_ntdll, b"NtCreateSection\0".as_ptr() as *const i8));
        let nt_map: FnNtMapViewOfSection = std::mem::transmute(
            winapi::um::libloaderapi::GetProcAddress(h_ntdll, b"NtMapViewOfSection\0".as_ptr() as *const i8));

        let mut section: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut size: i64 = 4096;
        let create_status = nt_create_section(
            &mut section as *mut _ as *mut _,
            0xF001F,  // SECTION_ALL_ACCESS
            std::ptr::null_mut(),
            &mut size,
            PAGE_READWRITE,
            0x08000000,  // SEC_COMMIT
            std::ptr::null_mut(),
        );
        if create_status != 0 {
            eprintln!("[escape_map_foreign] NtCreateSection failed status=0x{:x}", create_status as u32);
            CloseHandle(h);
            std::process::exit(8);
        }

        // Map into foreign process
        let mut base: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut view_size: usize = 4096;
        let map_status = nt_map(
            section,
            h as *mut _,                 // ProcessHandle = foreign
            &mut base as *mut _,
            0,
            0,
            std::ptr::null_mut(),
            &mut view_size,
            1,                            // ViewUnmap
            0,
            PAGE_READWRITE,
        );
        eprintln!("[escape_map_foreign] NtMapViewOfSection status=0x{:x}", map_status as u32);
        let _ = CloseHandle(section as winapi::um::winnt::HANDLE);
        CloseHandle(h);

        if map_status == 0xC0000022u32 as i32 {
            eprintln!("[escape_map_foreign] blocked: STATUS_ACCESS_DENIED from our hook");
            std::process::exit(5);
        }
        eprintln!("[escape_map_foreign] FOUND: foreign mapping succeeded — escape!");
        std::process::exit(0);
    }
}
