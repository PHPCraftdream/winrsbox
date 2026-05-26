// Escape payload: write MonitorProcess value to SilentProcessExit path.
// SilentProcessExit launches a monitor process when a target exe terminates.
// Expected: NtCreateKey or NtSetValueKey hook → RegDecide → Deny → exit 5.

fn main() {
    eprintln!("[escape_reg_silentexit] starting");
    unsafe {
        // Target: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe
        let subkey: Vec<u16> = "Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\notepad.exe\0"
            .encode_utf16().collect();
        let mut hkey: winapi::shared::minwindef::HKEY = std::ptr::null_mut();

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
            eprintln!("[escape_reg_silentexit] RegCreateKeyExW failed err={create_status}");
            std::process::exit(create_status as i32);
        }

        // Try to set MonitorProcess value
        let value_name: Vec<u16> = "MonitorProcess\0".encode_utf16().collect();
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

        eprintln!("[escape_reg_silentexit] RegSetValueExW status={set_status}");
        if set_status == 5 {  // ERROR_ACCESS_DENIED
            std::process::exit(5);
        }
        eprintln!("[escape_reg_silentexit] write returned {set_status}");
    }
}
