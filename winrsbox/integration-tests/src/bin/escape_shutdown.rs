// Tries to shut down the system via ExitWindowsEx (which forwards to NtShutdownSystem).
// Without hook: requires SeShutdownPrivilege; usually fails with ERROR_ACCESS_DENIED
// (1314) on non-admin. With hook: NtShutdownSystem returns STATUS_ACCESS_DENIED →
// ExitWindowsEx fails → exit 5.

use winapi::um::winuser::{ExitWindowsEx, EWX_LOGOFF};
use winapi::um::errhandlingapi::GetLastError;

fn main() {
    eprintln!("[escape_shutdown] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    unsafe {
        // Use EWX_LOGOFF (lowest risk action — just attempts logoff, not full shutdown)
        let ok = ExitWindowsEx(EWX_LOGOFF, 0);
        if ok == 0 {
            let err = GetLastError();
            eprintln!("[escape_shutdown] blocked: ExitWindowsEx err={}", err);
            std::process::exit(5);
        }
        eprintln!("[escape_shutdown] FOUND: shutdown action accepted!");
        std::process::exit(0);
    }
}
