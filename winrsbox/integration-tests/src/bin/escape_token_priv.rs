// escape_token_priv — tries to enable SeDebugPrivilege via NtAdjustPrivilegesToken.
// Without admin we won't actually get the privilege, but our token_guard
// should deny the call regardless.

fn main() {
    eprintln!("[escape_token_priv] starting");

    unsafe {
        // OpenProcessToken
        let mut token: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let process = winapi::um::processthreadsapi::GetCurrentProcess();
        let ok = winapi::um::processthreadsapi::OpenProcessToken(
            process,
            0x0020 | 0x0008, // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
            &mut token,
        );
        if ok == 0 {
            eprintln!("[escape_token_priv] OpenProcessToken failed");
            std::process::exit(2);
        }

        // Build TOKEN_PRIVILEGES with SeDebugPrivilege (LUID = 20) enabled
        // PrivilegeCount(u32) + LUID(u64) + Attributes(u32) = 16 bytes
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&1u32.to_le_bytes()); // count
        buf[4..8].copy_from_slice(&20u32.to_le_bytes()); // LUID low = SeDebugPrivilege
        // LUID high = 0
        buf[12..16].copy_from_slice(&0x02u32.to_le_bytes()); // SE_PRIVILEGE_ENABLED

        // Call NtAdjustPrivilegesToken via ntdll
        type FnAdjust = unsafe extern "system" fn(
            *mut winapi::ctypes::c_void, u8, *mut winapi::ctypes::c_void,
            u32, *mut winapi::ctypes::c_void, *mut u32,
        ) -> i32;
        let ntdll: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let hmod = winapi::um::libloaderapi::GetModuleHandleW(ntdll.as_ptr());
        let proc_addr = winapi::um::libloaderapi::GetProcAddress(
            hmod, b"NtAdjustPrivilegesToken\0".as_ptr() as *const i8);
        if proc_addr.is_null() {
            eprintln!("[escape_token_priv] NtAdjustPrivilegesToken not found");
            winapi::um::handleapi::CloseHandle(token);
            std::process::exit(2);
        }
        let adjust: FnAdjust = std::mem::transmute(proc_addr);

        let status = adjust(
            token,
            0, // DisableAllPrivileges = FALSE
            buf.as_mut_ptr() as *mut _,
            buf.len() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        winapi::um::handleapi::CloseHandle(token);

        if status as u32 == 0xC0000022 {
            eprintln!("[escape_token_priv] blocked: STATUS_ACCESS_DENIED");
            std::process::exit(5);
        }
        // Success or other status — privilege might not be granted (non-admin),
        // but our hook should have blocked the call entirely.
        eprintln!("[escape_token_priv] status=0x{status:08x} (not blocked by guard)");
        std::process::exit(1);
    }
}
