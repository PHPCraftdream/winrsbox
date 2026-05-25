// Full real attack: LWin+R, sleep 500ms, types "notepad\r" via unicode SendInput.
// After: FindWindowW looking for Notepad window with PID outside our process group.
// Exit=0 if escape worked, exit=5 if not.
// ALWAYS real (no safe mode). Used ONLY manually (test is #[ignore]).

use std::mem::{size_of, zeroed};
use std::ptr::null_mut;
use std::thread;
use std::time::Duration;
use winapi::shared::minwindef::DWORD;
use winapi::um::processthreadsapi::GetCurrentProcessId;
use winapi::um::winuser::{
    FindWindowW, GetWindowThreadProcessId, SendInput,
    INPUT, INPUT_KEYBOARD, KEYBDINPUT,
    KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, VK_LWIN,
};

const VK_R_KEY: u16 = 0x52;

fn main() {
    eprintln!("[escape_winr_notepad_real] starting REAL attack: Win+R -> notepad");

    unsafe {
        // Press Win+R
        let mut inputs: [INPUT; 4] = [zeroed(); 4];
        inputs[0].type_ = INPUT_KEYBOARD;
        let ki0: &mut KEYBDINPUT = inputs[0].u.ki_mut();
        ki0.wVk = VK_LWIN as u16;
        ki0.dwFlags = 0;

        inputs[1].type_ = INPUT_KEYBOARD;
        let ki1: &mut KEYBDINPUT = inputs[1].u.ki_mut();
        ki1.wVk = VK_R_KEY;
        ki1.dwFlags = 0;

        inputs[2].type_ = INPUT_KEYBOARD;
        let ki2: &mut KEYBDINPUT = inputs[2].u.ki_mut();
        ki2.wVk = VK_R_KEY;
        ki2.dwFlags = KEYEVENTF_KEYUP;

        inputs[3].type_ = INPUT_KEYBOARD;
        let ki3: &mut KEYBDINPUT = inputs[3].u.ki_mut();
        ki3.wVk = VK_LWIN as u16;
        ki3.dwFlags = KEYEVENTF_KEYUP;

        let n = SendInput(4, inputs.as_mut_ptr(), size_of::<INPUT>() as i32);
        eprintln!("[escape_winr_notepad_real] SendInput(Win+R) returned {n}");

        // Wait for Run dialog
        thread::sleep(Duration::from_millis(500));

        // Type "notepad\r" via unicode events
        let text: Vec<u16> = "notepad\r".encode_utf16().collect();
        let mut ui: Vec<INPUT> = Vec::with_capacity(text.len() * 2);
        for &ch in &text {
            let mut down: INPUT = zeroed();
            down.type_ = INPUT_KEYBOARD;
            let ki: &mut KEYBDINPUT = down.u.ki_mut();
            ki.wScan = ch;
            ki.dwFlags = KEYEVENTF_UNICODE;
            ui.push(down);

            let mut up: INPUT = zeroed();
            up.type_ = INPUT_KEYBOARD;
            let ki: &mut KEYBDINPUT = up.u.ki_mut();
            ki.wScan = ch;
            ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
            ui.push(up);
        }
        let n2 = SendInput(ui.len() as u32, ui.as_mut_ptr(), size_of::<INPUT>() as i32);
        eprintln!("[escape_winr_notepad_real] SendInput(notepad) returned {n2}");

        // Wait for notepad to start
        thread::sleep(Duration::from_secs(2));

        // Check if notepad appeared
        let notepad_class: Vec<u16> = "Notepad\0".encode_utf16().collect();
        let hwnd = FindWindowW(notepad_class.as_ptr(), null_mut());
        if !hwnd.is_null() {
            let mut pid: DWORD = 0;
            GetWindowThreadProcessId(hwnd, &mut pid);
            let own_pid = GetCurrentProcessId();
            if pid != 0 && pid != own_pid {
                eprintln!("[escape_winr_notepad_real] ESCAPE: found Notepad hwnd={hwnd:?} pid={pid}");
                std::process::exit(0);
            }
        }

        eprintln!("[escape_winr_notepad_real] no foreign Notepad found — blocked");
        std::process::exit(5);
    }
}
