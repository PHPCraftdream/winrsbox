// Tries to read user's clipboard. Without defense: succeeds, prints first 40
// chars. With Job UILIMIT_READCLIPBOARD: OpenClipboard returns 0 -> blocked.

use winapi::um::winuser::{OpenClipboard, CloseClipboard, GetClipboardData, CF_UNICODETEXT};
use std::ptr::null_mut;

fn main() {
    eprintln!("[escape_clipboard] starting");
    // Allow APC injection of hook.dll to land before the attack.
    unsafe { winapi::um::synchapi::SleepEx(500, 1) };
    unsafe {
        if OpenClipboard(null_mut()) == 0 {
            eprintln!("[escape_clipboard] blocked: OpenClipboard returned 0");
            std::process::exit(5);
        }
        let h = GetClipboardData(CF_UNICODETEXT);
        CloseClipboard();
        if h.is_null() {
            eprintln!("[escape_clipboard] empty clipboard — but OpenClipboard succeeded, partial escape");
            std::process::exit(6);
        }
        eprintln!("[escape_clipboard] READ clipboard — escape!");
        std::process::exit(0);
    }
}
