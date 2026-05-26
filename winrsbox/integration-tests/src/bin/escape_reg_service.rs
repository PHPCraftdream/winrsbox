// Escape payload: write ImagePath to a dummy Services key.
// Service ImagePath controls what binary SCM launches — persistence + privilege.
// Expected: NtCreateKey or NtSetValueKey hook → RegDecide → Deny → exit 5.

fn main() {
    eprintln!("[escape_reg_service] starting");
    unsafe {
        // Target: HKLM\SYSTEM\CurrentControlSet\Services\WinrsboxDummy\ImagePath
        let subkey: Vec<u16> = "SYSTEM\\CurrentControlSet\\Services\\WinrsboxDummy\0"
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
            eprintln!("[escape_reg_service] RegCreateKeyExW failed err={create_status}");
            std::process::exit(create_status as i32);
        }

        // Try to set ImagePath value
        let value_name: Vec<u16> = "ImagePath\0".encode_utf16().collect();
        let data: Vec<u16> = "c:\\evil.exe\0".encode_utf16().collect();
        let set_status = winapi::um::winreg::RegSetValueExW(
            hkey,
            value_name.as_ptr(),
            0,
            2, // REG_EXPAND_SZ
            data.as_ptr() as *const u8,
            (data.len() * 2) as u32,
        );
        winapi::um::winreg::RegCloseKey(hkey);

        eprintln!("[escape_reg_service] RegSetValueExW status={set_status}");
        if set_status == 5 {  // ERROR_ACCESS_DENIED
            std::process::exit(5);
        }
        eprintln!("[escape_reg_service] write returned {set_status}");
    }
}
