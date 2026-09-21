// Escape payload: write Debugger value to IFEO path for notepad.exe.
// IFEO redirects process launch to an attacker-specified debugger binary.
// Expected: NtCreateKey or NtSetValueKey hook → RegDecide → Deny → exit 5.

fn main() {
    eprintln!("[escape_reg_ifeo] starting");
    unsafe {
        // Target: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe
        let subkey: Vec<u16> = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe\0"
            .encode_utf16().collect();
        let mut hkey: winapi::shared::minwindef::HKEY = std::ptr::null_mut();

        // Try creating/opening the key under HKLM
        let mut disp: u32 = 0;
        let create_status = winapi::um::winreg::RegCreateKeyExW(
            winapi::um::winreg::HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            std::ptr::null_mut(),
            0,
            0x20006, // KEY_WRITE
            std::ptr::null_mut(),
            &mut hkey,
            &mut disp,
        );
        if create_status != 0 {
            // No admin — key creation denied by OS ACL or our hook.
            // If hook denied it, we get ERROR_ACCESS_DENIED (5).
            eprintln!("[escape_reg_ifeo] RegCreateKeyExW failed err={create_status}");
            std::process::exit(create_status as i32);
        }

        // Try to set Debugger value
        let value_name: Vec<u16> = "Debugger\0".encode_utf16().collect();
        let data: Vec<u16> = "c:\\evil.exe\0".encode_utf16().collect();
        let set_status = winapi::um::winreg::RegSetValueExW(
            hkey,
            value_name.as_ptr(),
            0,
            1, // REG_SZ
            data.as_ptr() as *const u8,
            (data.len() * 2) as u32,
        );
        winapi::um::winreg::RegCloseKey(hkey);

        eprintln!("[escape_reg_ifeo] RegSetValueExW status={set_status}");
        if set_status == 5 {  // ERROR_ACCESS_DENIED
            std::process::exit(5);
        }
        // If write succeeded, check if it's a real escape
        eprintln!("[escape_reg_ifeo] write returned {set_status}");
    }
}
