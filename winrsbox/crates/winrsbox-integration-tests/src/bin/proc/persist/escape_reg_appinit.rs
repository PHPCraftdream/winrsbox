// Escape payload: write to HKLM\...\AppInit_DLLs (DLL injection persistence).
// Expected: NtSetValueKey hook → RegDecide → Deny → STATUS_ACCESS_DENIED → Rust error.

fn main() {
    eprintln!("[escape_reg_appinit] starting");
    unsafe {
        // RegOpenKeyExW
        let subkey: Vec<u16> = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\0"
            .encode_utf16().collect();
        let mut hkey: winapi::shared::minwindef::HKEY = std::ptr::null_mut();
        let open_status = winapi::um::winreg::RegOpenKeyExW(
            winapi::um::winreg::HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            0x20006, // KEY_WRITE
            &mut hkey,
        );
        if open_status != 0 {
            // No admin → can't open HKLM with KEY_WRITE. Try HKCU as proxy.
            eprintln!("[escape_reg_appinit] HKLM open failed err={open_status}, trying HKCU");
            let hkcu_status = winapi::um::winreg::RegOpenKeyExW(
                winapi::um::winreg::HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                0x20006,
                &mut hkey,
            );
            if hkcu_status != 0 {
                eprintln!("[escape_reg_appinit] HKCU open also failed err={hkcu_status}");
                std::process::exit(2);
            }
        }

        // Try to set AppInit_DLLs value
        let value_name: Vec<u16> = "AppInit_DLLs\0".encode_utf16().collect();
        let data: Vec<u16> = "c:\\evil.dll\0".encode_utf16().collect();
        let set_status = winapi::um::winreg::RegSetValueExW(
            hkey,
            value_name.as_ptr(),
            0,
            1, // REG_SZ
            data.as_ptr() as *const u8,
            (data.len() * 2) as u32,
        );
        winapi::um::winreg::RegCloseKey(hkey);

        eprintln!("[escape_reg_appinit] RegSetValueExW status={set_status}");
        if set_status == 5 {  // ERROR_ACCESS_DENIED
            std::process::exit(5);
        }
        eprintln!("[escape_reg_appinit] BUG: write should have been denied");
    }
}
