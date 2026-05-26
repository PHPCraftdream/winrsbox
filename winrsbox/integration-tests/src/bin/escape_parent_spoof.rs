// Uses UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) to make
// the spawned cmd a child of explorer.exe. With proc_guard: denied → exit 5.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use winapi::shared::minwindef::FALSE;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::{
    CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
    OpenProcess, UpdateProcThreadAttribute, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION,
};
use winapi::um::tlhelp32::*;
use winapi::um::winbase::{EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEXW};
use winapi::um::winnt::PROCESS_CREATE_PROCESS;

const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 0x00020000;

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
    eprintln!("[escape_parent_spoof] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    let explorer = match find_pid("explorer.exe") {
        Some(p) => p,
        None => { eprintln!("[escape_parent_spoof] explorer not running"); std::process::exit(7); }
    };
    eprintln!("[escape_parent_spoof] explorer pid={}", explorer);

    unsafe {
        // Step A: open explorer with CREATE_PROCESS — this itself will be blocked
        // by NtOpenProcess hook (CREATE_PROCESS is dangerous). If it succeeds,
        // proceed with parent-spoof. If blocked, that's also a win — exit 5.
        let explorer_h = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, explorer);
        if explorer_h.is_null() {
            eprintln!("[escape_parent_spoof] step A blocked: OpenProcess(CREATE_PROCESS) on explorer denied");
            std::process::exit(5);
        }

        // Step B: build attribute list with parent override
        let mut size: usize = 0;
        InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size);
        let mut buf = vec![0u8; size];
        let attr_list = buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        if InitializeProcThreadAttributeList(attr_list, 1, 0, &mut size) == 0 {
            eprintln!("[escape_parent_spoof] InitializeProcThreadAttributeList failed");
            CloseHandle(explorer_h);
            std::process::exit(8);
        }
        if UpdateProcThreadAttribute(
            attr_list, 0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &explorer_h as *const _ as *mut _,
            std::mem::size_of::<winapi::shared::ntdef::HANDLE>(),
            null_mut(), null_mut(),
        ) == 0 {
            eprintln!("[escape_parent_spoof] UpdateProcThreadAttribute failed");
            DeleteProcThreadAttributeList(attr_list);
            CloseHandle(explorer_h);
            std::process::exit(8);
        }

        // Step C: spawn cmd.exe with spoofed parent
        let app: Vec<u16> = OsStr::new(r"C:\Windows\System32\cmd.exe").encode_wide().chain(Some(0)).collect();
        let mut cmd: Vec<u16> = OsStr::new(r"cmd.exe /c exit 0").encode_wide().chain(Some(0)).collect();

        let mut si: STARTUPINFOEXW = std::mem::zeroed();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attr_list;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let ok = CreateProcessW(
            app.as_ptr(), cmd.as_mut_ptr(),
            null_mut(), null_mut(), FALSE, EXTENDED_STARTUPINFO_PRESENT,
            null_mut(), null_mut(),
            &mut si as *mut _ as *mut _, &mut pi,
        );
        DeleteProcThreadAttributeList(attr_list);
        CloseHandle(explorer_h);

        if ok == 0 {
            let err = winapi::um::errhandlingapi::GetLastError();
            eprintln!("[escape_parent_spoof] blocked: CreateProcessW with parent spoof failed err={}", err);
            std::process::exit(5);
        }
        eprintln!("[escape_parent_spoof] FOUND: spawned cmd.exe with parent=explorer (pid={})", pi.dwProcessId);
        winapi::um::processthreadsapi::TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        std::process::exit(0);
    }
}
