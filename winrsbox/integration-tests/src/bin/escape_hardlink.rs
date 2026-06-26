// escape_hardlink — tries to create a hard link from CoW overlay path
// to a system file. If successful, writes through the overlay name would
// modify the real system file.

fn main() {
    eprintln!("[escape_hardlink] starting");

    // Create our own file first to ensure we have write+delete access
    let source = std::env::temp_dir().join("fs-sandbox-hardlink-source.dat");
    std::fs::write(&source, b"test").expect("create source");
    let src_wide: Vec<u16> = source.to_string_lossy().encode_utf16().chain(Some(0)).collect();

    unsafe {
        let h = winapi::um::fileapi::CreateFileW(
            src_wide.as_ptr(),
            0x10000000, // GENERIC_ALL
            0x07,
            std::ptr::null_mut(),
            3, // OPEN_EXISTING
            0,
            std::ptr::null_mut(),
        );
        if h == winapi::um::handleapi::INVALID_HANDLE_VALUE || h.is_null() {
            eprintln!("[escape_hardlink] CreateFile failed: {}",
                winapi::um::errhandlingapi::GetLastError());
            std::process::exit(2);
        }

        // Build FILE_LINK_INFORMATION
        // Layout: ReplaceIfExists(BOOLEAN, 1 byte, but aligned to 4) +
        //         RootDirectory(HANDLE, 8) + FileNameLength(u32, 4) + FileName(WCHAR[])
        // Actually proper layout is: BOOLEAN + pad(7) + HANDLE(8) + ULONG(4) + WCHAR[N]
        // Total header: 8 + 8 + 4 = 20 bytes
        let target = std::env::temp_dir().join("fs-sandbox-hardlink-test.dat");
        let target_wide: Vec<u16> = target.to_string_lossy().encode_utf16().collect();
        let name_bytes = target_wide.len() * 2;
        let total = 20 + name_bytes;
        let mut buf = vec![0u8; total];
        buf[0] = 1; // ReplaceIfExists = TRUE
        // RootDirectory = NULL (8 bytes already zero)
        // FileNameLength
        buf[16..20].copy_from_slice(&(name_bytes as u32).to_le_bytes());
        // FileName
        for (i, &w) in target_wide.iter().enumerate() {
            buf[20 + i*2..20 + i*2 + 2].copy_from_slice(&w.to_le_bytes());
        }

        // Call NtSetInformationFile(FileLinkInformation = 11) via ntdll
        type FnSetInfo = unsafe extern "system" fn(
            *mut winapi::ctypes::c_void, *mut winapi::ctypes::c_void,
            *mut winapi::ctypes::c_void, u32, u32,
        ) -> i32;

        let ntdll: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let hmod = winapi::um::libloaderapi::GetModuleHandleW(ntdll.as_ptr());
        let proc_addr = winapi::um::libloaderapi::GetProcAddress(
            hmod, b"NtSetInformationFile\0".as_ptr() as *const i8);
        if proc_addr.is_null() {
            eprintln!("[escape_hardlink] NtSetInformationFile not found");
            winapi::um::handleapi::CloseHandle(h);
            std::process::exit(2);
        }
        let nt_set_info: FnSetInfo = std::mem::transmute(proc_addr);
        let mut iosb = [0u8; 16];
        let status = nt_set_info(
            h as *mut _,
            iosb.as_mut_ptr() as *mut _,
            buf.as_mut_ptr() as *mut _,
            total as u32,
            11, // FileLinkInformation
        );
        winapi::um::handleapi::CloseHandle(h);
        // Deliberately do NOT remove source/target: those self-deletes run
        // under our own CoW hooks (overlay whiteout) and would mask a real
        // leak from the outer test process. The outer process owns the
        // real-disk leak check, so leave artifacts in place.

        if status >= 0 {
            eprintln!("[escape_hardlink] link op returned success status=0x{status:08x} (CoW-absorbed unless outer check finds a leak)");
            std::process::exit(0);
        } else if status as u32 == 0xC0000022 {
            eprintln!("[escape_hardlink] blocked: STATUS_ACCESS_DENIED");
            std::process::exit(5);
        } else {
            eprintln!("[escape_hardlink] failed: status=0x{status:08x}");
            std::process::exit(1);
        }
    }
}
