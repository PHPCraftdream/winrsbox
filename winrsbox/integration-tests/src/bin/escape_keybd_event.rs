// Synthesizes keyboard input via user32!keybd_event (legacy API).
// SAFE-mode: presses VK_F24 (no-op key). REAL-mode: presses VK_LWIN+R.
//
// Sandbox should: ui_guard hook on keybd_event -> kill process before call lands.

use winapi::um::winuser::{keybd_event, KEYEVENTF_KEYUP, VK_F24, VK_LWIN};

const VK_R_KEY: u8 = 0x52;

fn main() {
    eprintln!("[escape_keybd_event] starting");

    let real_attack = std::env::var("FS_SANDBOX_REAL_ATTACK").as_deref() == Ok("1");
    let (vk1, vk2) = if real_attack {
        eprintln!("[escape_keybd_event] REAL attack: Win+R");
        (VK_LWIN as u8, VK_R_KEY)
    } else {
        eprintln!("[escape_keybd_event] safe mode: F24+F24");
        (VK_F24 as u8, VK_F24 as u8)
    };

    unsafe {
        // keybd_event(bVk, bScan, dwFlags, dwExtraInfo)
        keybd_event(vk1, 0, 0, 0);
        keybd_event(vk2, 0, 0, 0);
        keybd_event(vk2, 0, KEYEVENTF_KEYUP, 0);
        keybd_event(vk1, 0, KEYEVENTF_KEYUP, 0);
    }

    // If we got here, keybd_event was not blocked = escape
    eprintln!("[escape_keybd_event] keybd_event SUCCEEDED — escape!");
    std::process::exit(0);
}
