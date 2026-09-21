// Tries CreateProcessW for wsl.exe. With proc_guard: denied at NtCreateUserProcess → exit 5.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use winapi::um::processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};

fn main() {
    eprintln!("[escape_spawn_wsl] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    let app: Vec<u16> = OsStr::new(r"C:\Windows\System32\wsl.exe").encode_wide().chain(Some(0)).collect();
    let mut cmd: Vec<u16> = OsStr::new(r"wsl.exe /bin/echo escape").encode_wide().chain(Some(0)).collect();

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let ok = unsafe {
        CreateProcessW(
            app.as_ptr(), cmd.as_mut_ptr(),
            null_mut(), null_mut(), 0, 0, null_mut(), null_mut(),
            &mut si, &mut pi,
        )
    };
    if ok == 0 {
        let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
        eprintln!("[escape_spawn_wsl] blocked: CreateProcessW failed err={}", err);
        std::process::exit(5);
    }
    eprintln!("[escape_spawn_wsl] FOUND: wsl.exe spawned (pid={})", pi.dwProcessId);
    unsafe {
        winapi::um::processthreadsapi::TerminateProcess(pi.hProcess, 0);
        winapi::um::handleapi::CloseHandle(pi.hProcess);
        winapi::um::handleapi::CloseHandle(pi.hThread);
    }
    std::process::exit(0);
}
