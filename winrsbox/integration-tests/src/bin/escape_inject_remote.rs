// Tries OpenProcess(PROCESS_VM_WRITE | PROCESS_CREATE_THREAD) on explorer.exe.
// Without proc_guard: opens handle → injection escape available.
// With proc_guard: NtOpenProcess returns STATUS_ACCESS_DENIED → OpenProcess NULL → exit 5.

use winapi::shared::minwindef::FALSE;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::{PROCESS_CREATE_THREAD, PROCESS_VM_WRITE};

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
    eprintln!("[escape_inject_remote] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    let pid = match find_pid("explorer.exe") {
        Some(p) => p,
        None => { eprintln!("[escape_inject_remote] explorer.exe not running"); std::process::exit(7); }
    };
    eprintln!("[escape_inject_remote] explorer pid={}", pid);

    unsafe {
        let h = OpenProcess(PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, pid);
        if h.is_null() {
            eprintln!("[escape_inject_remote] blocked: OpenProcess returned NULL (proc_guard)");
            std::process::exit(5);
        }
        eprintln!("[escape_inject_remote] FOUND: OpenProcess succeeded — injection escape available!");
        CloseHandle(h);
        std::process::exit(0);
    }
}
