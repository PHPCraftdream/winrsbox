// escape_reg_environment — tries to write UserInitMprLogonScript to
// HKCU\Environment for logon persistence.
// Without M6 fix: RegDecide sees a non-\software\ key → passthrough → real write.
// With M6 fix: \environment in persistence denylist → deny or silent_ok.

fn main() {
    eprintln!("[escape_reg_environment] starting");
    unsafe {
        let subkey: Vec<u16> = "Environment\0".encode_utf16().collect();
        let mut hkey: winapi::shared::minwindef::HKEY = std::ptr::null_mut();
        let status = winapi::um::winreg::RegOpenKeyExW(
            winapi::um::winreg::HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            0x20006, // KEY_WRITE
            &mut hkey,
        );
        if status != 0 {
            eprintln!("[escape_reg_environment] RegOpenKeyEx failed err={status}");
            std::process::exit(2);
        }

        let value_name: Vec<u16> = "UserInitMprLogonScript\0".encode_utf16().collect();
        let data: Vec<u16> = "c:\\evil\\payload.cmd\0".encode_utf16().collect();
        let set_status = winapi::um::winreg::RegSetValueExW(
            hkey,
            value_name.as_ptr(),
            0,
            1, // REG_SZ
            data.as_ptr() as *const u8,
            (data.len() * 2) as u32,
        );
        winapi::um::winreg::RegCloseKey(hkey);

        if set_status == 5 { // ERROR_ACCESS_DENIED
            eprintln!("[escape_reg_environment] blocked: ACCESS_DENIED");
            std::process::exit(5);
        }

        // Check if sandbox silently absorbed the write (silent_ok) by reading back
        let mut hkey2: winapi::shared::minwindef::HKEY = std::ptr::null_mut();
        let open2 = winapi::um::winreg::RegOpenKeyExW(
            winapi::um::winreg::HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            0x20019, // KEY_READ
            &mut hkey2,
        );
        if open2 != 0 {
            eprintln!("[escape_reg_environment] read-back open failed, assuming blocked");
            std::process::exit(5);
        }

        let mut buf = [0u16; 512];
        let mut buf_size: u32 = 1024;
        let mut val_type: u32 = 0;
        let query = winapi::um::winreg::RegQueryValueExW(
            hkey2,
            value_name.as_ptr(),
            std::ptr::null_mut(),
            &mut val_type,
            buf.as_mut_ptr() as *mut u8,
            &mut buf_size,
        );
        winapi::um::winreg::RegCloseKey(hkey2);

        if query == 0 {
            let val = String::from_utf16_lossy(&buf[..buf_size as usize / 2]);
            if val.contains("evil") {
                eprintln!("[escape_reg_environment] ESCAPE: value persisted: {val}");
                std::process::exit(0);
            }
        }

        eprintln!("[escape_reg_environment] blocked (silent_ok or deny)");
        std::process::exit(5);
    }
}
