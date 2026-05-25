// Tries to PostMessage WM_CLOSE to the Windows taskbar (Shell_TrayWnd).
// Without defense: closes taskbar. With Job UI HANDLES restriction:
// FindWindowW returns NULL -> escape blocked.

use winapi::um::winuser::{FindWindowW, PostMessageW, WM_CLOSE};
use std::ptr::null_mut;

fn main() {
    eprintln!("[escape_window_msg] starting");

    // Probe to force the ntdll hook path (NtCreateFile) which establishes IPC
    // and confirms hook.dll is fully initialised before our attack runs.
    let _ = std::fs::metadata("C:\\Windows\\System32\\kernel32.dll");
    for _ in 0..3 {
        unsafe { winapi::um::synchapi::SleepEx(200, 1) };
    }

    let class: Vec<u16> = "Shell_TrayWnd\0".encode_utf16().collect();
    unsafe {
        let hwnd = FindWindowW(class.as_ptr(), null_mut());
        if hwnd.is_null() {
            eprintln!("[escape_window_msg] blocked: FindWindow returned NULL (Job UILIMIT_HANDLES)");
            std::process::exit(5);
        }
        // SAFETY: never reached if Job UI restriction active. SAFE-mode does NOT
        // actually post WM_CLOSE -- too destructive. We just report we got the
        // HWND, which means defense failed.
        eprintln!("[escape_window_msg] FOUND foreign HWND: {hwnd:?} — escape!");
        // For real demonstration set FS_SANDBOX_REAL_ATTACK=1:
        if std::env::var("FS_SANDBOX_REAL_ATTACK").as_deref() == Ok("1") {
            let r = PostMessageW(hwnd, WM_CLOSE, 0, 0);
            eprintln!("[escape_window_msg] PostMessage returned {r}");
        }
        std::process::exit(0);
    }
}
