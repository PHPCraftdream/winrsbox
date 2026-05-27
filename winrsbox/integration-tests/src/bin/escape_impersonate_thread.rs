// escape_impersonate_thread — tries NtImpersonateThread on a foreign thread.
// Opens an explorer.exe thread via CreateToolhelp32Snapshot + Thread32First/Next,
// then calls NtImpersonateThread(explorer_thread, self_thread, &sqos).
// With token_guard: returns STATUS_ACCESS_DENIED -> exit 5.
// If thread opening fails at proc_guard level -> also exit 5 (defense in depth).

use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, Thread32First, Thread32Next,
    PROCESSENTRY32W, THREADENTRY32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD,
};

fn find_pid(target: &str) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE { return None; }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut e) == 0 { CloseHandle(snap); return None; }
        loop {
            let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
            let name = String::from_utf16_lossy(&e.szExeFile[..len]).to_lowercase();
            if name == target.to_lowercase() { CloseHandle(snap); return Some(e.th32ProcessID); }
            if Process32NextW(snap, &mut e) == 0 { CloseHandle(snap); return None; }
        }
    }
}

fn find_thread_of_pid(pid: u32) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap == INVALID_HANDLE_VALUE { return None; }
        let mut te: THREADENTRY32 = std::mem::zeroed();
        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        if Thread32First(snap, &mut te) == 0 { CloseHandle(snap); return None; }
        loop {
            if te.th32OwnerProcessID == pid {
                let tid = te.th32ThreadID;
                CloseHandle(snap);
                return Some(tid);
            }
            if Thread32Next(snap, &mut te) == 0 { CloseHandle(snap); return None; }
        }
    }
}

fn main() {
    eprintln!("[escape_impersonate_thread] starting");
    // Settle
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    let explorer_pid = match find_pid("explorer.exe") {
        Some(p) => p,
        None => { eprintln!("[escape_impersonate_thread] explorer.exe not running"); std::process::exit(7); }
    };
    eprintln!("[escape_impersonate_thread] explorer pid={explorer_pid}");

    let tid = match find_thread_of_pid(explorer_pid) {
        Some(t) => t,
        None => { eprintln!("[escape_impersonate_thread] no thread found"); std::process::exit(7); }
    };
    eprintln!("[escape_impersonate_thread] explorer thread={tid}");

    unsafe {
        // Open the foreign thread with THREAD_DIRECT_IMPERSONATION (0x0200)
        let thread_handle = winapi::um::processthreadsapi::OpenThread(
            0x0200, // THREAD_DIRECT_IMPERSONATION
            0,
            tid,
        );
        if thread_handle.is_null() {
            eprintln!("[escape_impersonate_thread] OpenThread failed (defense in depth) -> exit 5");
            std::process::exit(5);
        }

        // Build SECURITY_QUALITY_OF_SERVICE
        #[repr(C)]
        struct SecurityQos {
            length: u32,
            impersonation_level: u32,
            context_tracking_mode: u8,
            effective_only: u8,
        }
        let mut sqos = SecurityQos {
            length: std::mem::size_of::<SecurityQos>() as u32,
            impersonation_level: 2, // SecurityImpersonation
            context_tracking_mode: 0, // SECURITY_STATIC_TRACKING
            effective_only: 0,
        };

        // Get NtImpersonateThread
        type FnNtImpersonateThread = unsafe extern "system" fn(
            *mut winapi::ctypes::c_void, // ServerThreadHandle
            *mut winapi::ctypes::c_void, // ClientThreadHandle
            *mut winapi::ctypes::c_void, // SecurityQualityOfService
        ) -> i32;

        let ntdll: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let hmod = winapi::um::libloaderapi::GetModuleHandleW(ntdll.as_ptr());
        let proc_addr = winapi::um::libloaderapi::GetProcAddress(
            hmod, b"NtImpersonateThread\0".as_ptr() as *const i8);
        if proc_addr.is_null() {
            eprintln!("[escape_impersonate_thread] NtImpersonateThread not found");
            CloseHandle(thread_handle);
            std::process::exit(2);
        }
        let impersonate: FnNtImpersonateThread = std::mem::transmute(proc_addr);

        let self_thread = winapi::um::processthreadsapi::GetCurrentThread();
        let status = impersonate(
            thread_handle,
            self_thread,
            &mut sqos as *mut _ as *mut winapi::ctypes::c_void,
        );
        CloseHandle(thread_handle);

        if status as u32 == 0xC0000022 {
            eprintln!("[escape_impersonate_thread] blocked: STATUS_ACCESS_DENIED");
            std::process::exit(5);
        }
        eprintln!("[escape_impersonate_thread] status=0x{:08x} (not blocked)", status as u32);
        std::process::exit(1);
    }
}
