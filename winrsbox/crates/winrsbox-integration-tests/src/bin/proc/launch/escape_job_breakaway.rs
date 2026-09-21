// Tries CreateProcess with CREATE_BREAKAWAY_FROM_JOB flag.
// If parent Job has JOB_OBJECT_LIMIT_BREAKAWAY_OK=false (correct config),
// CreateProcess will fail — the flag conflicts with a non-breakable Job.
// If BREAKAWAY_OK=true (escape possible), CreateProcess succeeds → exit 0.
//
// This test verifies Job creation audit: that the launcher creates the Job
// without BREAKAWAY_OK.

use winapi::um::processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x01000000;

fn main() {
    eprintln!("[escape_job_breakaway] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    let app: Vec<u16> = OsStr::new(r"C:\Windows\System32\cmd.exe").encode_wide().chain(Some(0)).collect();
    let mut cmd: Vec<u16> = OsStr::new(r"cmd.exe /c exit 0").encode_wide().chain(Some(0)).collect();
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let ok = unsafe {
        CreateProcessW(
            app.as_ptr(), cmd.as_mut_ptr(),
            null_mut(), null_mut(), 0,
            CREATE_BREAKAWAY_FROM_JOB,
            null_mut(), null_mut(),
            &mut si, &mut pi,
        )
    };
    if ok == 0 {
        let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
        eprintln!("[escape_job_breakaway] BREAKAWAY_FROM_JOB blocked: err={}", err);
        std::process::exit(5);
    }
    eprintln!("[escape_job_breakaway] FOUND: spawned with BREAKAWAY_FROM_JOB — escape!");
    unsafe {
        winapi::um::processthreadsapi::TerminateProcess(pi.hProcess, 0);
        winapi::um::handleapi::CloseHandle(pi.hProcess);
        winapi::um::handleapi::CloseHandle(pi.hThread);
    }
    std::process::exit(0);
}
