// Synthesizes keyboard input via user32!SendInput.
// SAFE-mode: presses VK_F24 (no-op key). REAL-mode: presses VK_LWIN+R.
//
// Sandbox should: ui_guard hook on SendInput -> kill process before call lands.
// Detection: if process survives the call and SendInput returns >0, it ran.

use std::mem::{size_of, zeroed};
use winapi::um::winuser::{
    SendInput, INPUT, INPUT_KEYBOARD, KEYBDINPUT,
    KEYEVENTF_KEYUP, VK_F24, VK_LWIN,
};

const VK_R_KEY: u16 = 0x52;

fn main() {
    eprintln!("[escape_sendinput] starting");

    let real_attack = std::env::var("FS_SANDBOX_REAL_ATTACK").as_deref() == Ok("1");
    let (vk1, vk2) = if real_attack {
        eprintln!("[escape_sendinput] REAL attack: Win+R");
        (VK_LWIN as u16, VK_R_KEY)
    } else {
        eprintln!("[escape_sendinput] safe mode: F24+F24");
        (VK_F24 as u16, VK_F24 as u16)
    };

    unsafe {
        let mut inputs: [INPUT; 4] = [zeroed(); 4];
        for (i, (vk, up)) in [(vk1, false), (vk2, false), (vk2, true), (vk1, true)]
            .iter()
            .enumerate()
        {
            inputs[i].type_ = INPUT_KEYBOARD;
            let ki: &mut KEYBDINPUT = inputs[i].u.ki_mut();
            ki.wVk = *vk;
            ki.dwFlags = if *up { KEYEVENTF_KEYUP } else { 0 };
        }

        let n = SendInput(4, inputs.as_mut_ptr(), size_of::<INPUT>() as i32);
        if n == 0 {
            // SendInput returned 0 = blocked (UIPI or our hook returned 0)
            eprintln!("[escape_sendinput] blocked: SendInput returned 0");
            std::process::exit(5);
        }
        eprintln!("[escape_sendinput] SendInput SUCCEEDED: n={n} — escape!");
        std::process::exit(0);
    }
}
