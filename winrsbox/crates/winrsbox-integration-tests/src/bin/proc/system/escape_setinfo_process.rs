// Tries SetProcessAffinityMask (→ NtSetInformationProcess(ProcessAffinityMask))
// on explorer.exe. Without hook: succeeds if proc handle valid → CPU affinity
// of foreign proc changed. With hook: NtSetInformationProcess returns
// ACCESS_DENIED → caller exit 5.
//
// Defense in depth: proc_guard's NtOpenProcess hook may also block the
// OpenProcess call if PROCESS_SET_INFORMATION is in DANGEROUS_ACCESS. Either
// way, the attack is stopped.

use winapi::shared::minwindef::FALSE;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use winapi::um::winbase::SetProcessAffinityMask;
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_SET_INFORMATION};

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
    eprintln!("[escape_setinfo_process] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    let pid = match find_pid("explorer.exe") {
        Some(p) => p,
        None => { eprintln!("[escape_setinfo_process] explorer.exe not running"); std::process::exit(7); }
    };
    eprintln!("[escape_setinfo_process] explorer pid={}", pid);

    unsafe {
        // Step 1: open with SET_INFORMATION — proc_guard blocks ANY foreign
        // OpenProcess with PROCESS_SET_INFORMATION (it's in DANGEROUS_ACCESS).
        // If proc_guard blocks first → also a win (defense in depth).
        let h = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if h.is_null() {
            eprintln!("[escape_setinfo_process] blocked at OpenProcess (proc_guard) — defense in depth");
            std::process::exit(5);
        }

        // Step 2: try to change affinity to single CPU (mask=1).
        // SetProcessAffinityMask calls NtSetInformationProcess(ProcessAffinityMask)
        // → our hook fires.
        let ok = SetProcessAffinityMask(h, 1);
        if ok == 0 {
            let err = winapi::um::errhandlingapi::GetLastError();
            eprintln!("[escape_setinfo_process] blocked at SetInfoProcess (our new hook) err={}", err);
            CloseHandle(h);
            std::process::exit(5);
        }
        eprintln!("[escape_setinfo_process] FOUND: changed affinity of foreign proc!");
        // Restore (best effort)
        let _ = SetProcessAffinityMask(h, !0u32);
        CloseHandle(h);
        std::process::exit(0);
    }
}
