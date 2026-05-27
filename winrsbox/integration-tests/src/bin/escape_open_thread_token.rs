// escape_open_thread_token — tries NtOpenThreadTokenEx on a foreign thread
// with TOKEN_IMPERSONATE access. Opens an explorer.exe thread, then calls
// NtOpenThreadTokenEx with dangerous access bits.
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
    eprintln!("[escape_open_thread_token] starting");
    // Settle
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    let explorer_pid = match find_pid("explorer.exe") {
        Some(p) => p,
        None => { eprintln!("[escape_open_thread_token] explorer.exe not running"); std::process::exit(7); }
    };
    eprintln!("[escape_open_thread_token] explorer pid={explorer_pid}");

    let tid = match find_thread_of_pid(explorer_pid) {
        Some(t) => t,
        None => { eprintln!("[escape_open_thread_token] no thread found"); std::process::exit(7); }
    };
    eprintln!("[escape_open_thread_token] explorer thread={tid}");

    unsafe {
        // Open thread with THREAD_QUERY_INFORMATION (0x0040) — enough to open its token
        let thread_handle = winapi::um::processthreadsapi::OpenThread(
            0x0040, // THREAD_QUERY_INFORMATION
            0,
            tid,
        );
        if thread_handle.is_null() {
            eprintln!("[escape_open_thread_token] OpenThread failed (defense in depth) -> exit 5");
            std::process::exit(5);
        }

        // Get NtOpenThreadTokenEx
        type FnNtOpenThreadTokenEx = unsafe extern "system" fn(
            *mut winapi::ctypes::c_void, // ThreadHandle
            u32,        // DesiredAccess
            u8,         // OpenAsSelf (BOOLEAN)
            u32,        // HandleAttributes
            *mut *mut winapi::ctypes::c_void, // TokenHandle (out)
        ) -> i32;

        let ntdll: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let hmod = winapi::um::libloaderapi::GetModuleHandleW(ntdll.as_ptr());
        let proc_addr = winapi::um::libloaderapi::GetProcAddress(
            hmod, b"NtOpenThreadTokenEx\0".as_ptr() as *const i8);
        if proc_addr.is_null() {
            eprintln!("[escape_open_thread_token] NtOpenThreadTokenEx not found");
            CloseHandle(thread_handle);
            std::process::exit(2);
        }
        let open_thread_token: FnNtOpenThreadTokenEx = std::mem::transmute(proc_addr);

        let mut token: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        // TOKEN_IMPERSONATE = 0x0004
        let status = open_thread_token(
            thread_handle,
            0x0004, // TOKEN_IMPERSONATE
            0,      // OpenAsSelf = FALSE
            0,      // HandleAttributes
            &mut token,
        );
        CloseHandle(thread_handle);

        if status as u32 == 0xC0000022 {
            eprintln!("[escape_open_thread_token] blocked: STATUS_ACCESS_DENIED");
            std::process::exit(5);
        }
        if !token.is_null() {
            CloseHandle(token);
        }
        // STATUS_NO_TOKEN (0xC000007C) means thread had no impersonation token —
        // this is expected for most threads. The hook didn't fire because the
        // original syscall returned an error first. But our hook checks BEFORE
        // calling original, so if we get here with NO_TOKEN, the hook allowed it
        // (which means it wasn't blocked). However, NO_TOKEN also means no actual
        // escalation occurred. For test purposes, if the hook is working it should
        // have returned ACCESS_DENIED before the kernel even checked.
        eprintln!("[escape_open_thread_token] status=0x{:08x} (not blocked)", status as u32);
        std::process::exit(1);
    }
}
