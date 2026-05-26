// Tries to create a fresh empty Job and reassign self into it.
// Without job_guard: succeeds → process escapes parent Job UI/memory restrictions.
// With job_guard: NtAssignProcessToJobObject returns STATUS_ACCESS_DENIED →
// AssignProcessToJobObject fails → exit 5.

use winapi::um::jobapi2::{CreateJobObjectW, AssignProcessToJobObject};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::errhandlingapi::GetLastError;
use std::ptr::null_mut;

fn main() {
    eprintln!("[escape_job_reassign] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    unsafe {
        let job = CreateJobObjectW(null_mut(), null_mut());
        if job.is_null() {
            eprintln!("[escape_job_reassign] CreateJobObjectW failed err={}", GetLastError());
            std::process::exit(2);
        }
        let ok = AssignProcessToJobObject(job, GetCurrentProcess());
        if ok == 0 {
            eprintln!("[escape_job_reassign] blocked: AssignProcessToJobObject failed err={}", GetLastError());
            std::process::exit(5);
        }
        eprintln!("[escape_job_reassign] FOUND: reassigned to new empty Job — escape!");
        std::process::exit(0);
    }
}
