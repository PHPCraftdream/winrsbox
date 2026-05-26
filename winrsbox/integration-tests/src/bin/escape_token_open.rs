// escape_token_open — tries NtOpenProcessTokenEx on explorer.exe with TOKEN_DUPLICATE.
// proc_guard allows PROCESS_QUERY_LIMITED_INFORMATION on foreign processes, but
// NtOpenProcessToken is a separate syscall. Without token_guard, the attacker gets
// a token handle usable for duplication/impersonation.
// With token_guard: NtOpenProcessTokenEx returns STATUS_ACCESS_DENIED → exit 5.

use winapi::shared::minwindef::FALSE;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess, OpenProcessToken};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::{PROCESS_QUERY_LIMITED_INFORMATION, TOKEN_DUPLICATE, TOKEN_QUERY};

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

fn main() {
    eprintln!("[escape_token_open] starting");
    // Settle — let the sandbox hooks stabilize
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    // Self-token: MUST be allowed (critical for notepad and other programs)
    unsafe {
        let mut self_token: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let proc = GetCurrentProcess();
        let ok = OpenProcessToken(proc, TOKEN_QUERY, &mut self_token);
        if ok == 0 {
            eprintln!("[escape_token_open] OpenProcessToken(self) failed — unexpected!");
            std::process::exit(2);
        }
        CloseHandle(self_token);
        eprintln!("[escape_token_open] self-token opened OK (expected)");
    }

    // Foreign token via NtOpenProcessTokenEx: should be blocked
    let pid = match find_pid("explorer.exe") {
        Some(p) => p,
        None => { eprintln!("[escape_token_open] explorer.exe not running"); std::process::exit(7); }
    };
    eprintln!("[escape_token_open] explorer pid={}", pid);

    unsafe {
        // First get a process handle with PROCESS_QUERY_LIMITED_INFORMATION
        // (proc_guard allows this for read-only access)
        let proc_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if proc_handle.is_null() {
            eprintln!("[escape_token_open] OpenProcess failed (exit 2)");
            std::process::exit(2);
        }

        // Now try NtOpenProcessTokenEx with TOKEN_DUPLICATE — should be blocked
        type FnNtOpenProcessTokenEx = unsafe extern "system" fn(
            *mut winapi::ctypes::c_void, // ProcessHandle
            u32,        // DesiredAccess
            u32,        // HandleAttributes
            *mut *mut winapi::ctypes::c_void, // TokenHandle
        ) -> i32;

        let ntdll: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let hmod = winapi::um::libloaderapi::GetModuleHandleW(ntdll.as_ptr());
        let proc_addr = winapi::um::libloaderapi::GetProcAddress(
            hmod, b"NtOpenProcessTokenEx\0".as_ptr() as *const i8);
        if proc_addr.is_null() {
            eprintln!("[escape_token_open] NtOpenProcessTokenEx not found");
            CloseHandle(proc_handle);
            std::process::exit(2);
        }
        let open_token: FnNtOpenProcessTokenEx = std::mem::transmute(proc_addr);

        let mut token: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let status = open_token(proc_handle, TOKEN_DUPLICATE, 0, &mut token);
        CloseHandle(proc_handle);

        if status as u32 == 0xC0000022 {
            eprintln!("[escape_token_open] blocked: STATUS_ACCESS_DENIED");
            std::process::exit(5);
        }
        if !token.is_null() {
            CloseHandle(token);
        }
        eprintln!("[escape_token_open] status=0x{:08x} (not blocked by guard)", status as u32);
        std::process::exit(1);
    }
}
