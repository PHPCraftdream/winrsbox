// escape_junction — tries to create a junction (reparse point) to escape
// CoW isolation. If successful, writes through the junction modify real
// system files while our FS hook only checks the symbolic path.

fn main() {
    eprintln!("[escape_junction] starting");

    // Try FSCTL_SET_REPARSE_POINT via DeviceIoControl / NtFsControlFile
    // We'll use the Win32 wrapper for simplicity.
    let target_dir = std::env::temp_dir().join("fs-sandbox-junction-test");
    let _ = std::fs::create_dir_all(&target_dir);

    // NtFsControlFile with FSCTL_SET_REPARSE_POINT (0x000900A4)
    // Build a minimal REPARSE_DATA_BUFFER for mount point (junction)
    let substitute = r"\??\C:\Windows\System32";
    let print_name = r"C:\Windows\System32";

    let sub_wide: Vec<u16> = substitute.encode_utf16().collect();
    let print_wide: Vec<u16> = print_name.encode_utf16().collect();
    let sub_bytes = sub_wide.len() * 2;
    let print_bytes = print_wide.len() * 2;

    // REPARSE_DATA_BUFFER for IO_REPARSE_TAG_MOUNT_POINT (0xA0000003)
    let header_size = 8; // ReparseTag(4) + ReparseDataLength(2) + Reserved(2)
    let mount_header = 8; // SubstituteNameOffset(2) + SubstituteNameLength(2) + PrintNameOffset(2) + PrintNameLength(2)
    let data_len = mount_header + sub_bytes + 2 + print_bytes + 2;
    let total = header_size + data_len;

    let mut buf = vec![0u8; total];
    // ReparseTag = IO_REPARSE_TAG_MOUNT_POINT
    buf[0..4].copy_from_slice(&0xA0000003u32.to_le_bytes());
    // ReparseDataLength
    buf[4..6].copy_from_slice(&(data_len as u16).to_le_bytes());
    // Reserved = 0
    // SubstituteNameOffset = 0
    buf[8..10].copy_from_slice(&0u16.to_le_bytes());
    // SubstituteNameLength
    buf[10..12].copy_from_slice(&(sub_bytes as u16).to_le_bytes());
    // PrintNameOffset = sub_bytes + 2
    buf[12..14].copy_from_slice(&((sub_bytes + 2) as u16).to_le_bytes());
    // PrintNameLength
    buf[14..16].copy_from_slice(&(print_bytes as u16).to_le_bytes());
    // SubstituteName
    let off = 16;
    for (i, &w) in sub_wide.iter().enumerate() {
        buf[off + i * 2..off + i * 2 + 2].copy_from_slice(&w.to_le_bytes());
    }
    // PrintName
    let off2 = off + sub_bytes + 2;
    for (i, &w) in print_wide.iter().enumerate() {
        buf[off2 + i * 2..off2 + i * 2 + 2].copy_from_slice(&w.to_le_bytes());
    }

    // Open target directory with write + reparse access
    let dir_wide: Vec<u16> = target_dir.to_string_lossy().encode_utf16().chain(Some(0)).collect();
    unsafe {
        let h = winapi::um::fileapi::CreateFileW(
            dir_wide.as_ptr(),
            0x40000000 | 0x100, // GENERIC_WRITE | FILE_WRITE_ATTRIBUTES
            0x07, // FILE_SHARE_READ|WRITE|DELETE
            std::ptr::null_mut(),
            3, // OPEN_EXISTING
            0x02000000 | 0x00200000, // FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
            std::ptr::null_mut(),
        );
        if h == winapi::um::handleapi::INVALID_HANDLE_VALUE || h.is_null() {
            eprintln!("[escape_junction] CreateFile failed");
            let _ = std::fs::remove_dir_all(&target_dir);
            std::process::exit(2);
        }

        let mut returned: u32 = 0;
        let ok = winapi::um::ioapiset::DeviceIoControl(
            h,
            0x000900A4, // FSCTL_SET_REPARSE_POINT
            buf.as_ptr() as *mut _,
            buf.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        );
        winapi::um::handleapi::CloseHandle(h);

        if ok != 0 {
            eprintln!("[escape_junction] JUNCTION CREATED — escape possible!");
            let _ = std::fs::remove_dir_all(&target_dir);
            std::process::exit(0);
        } else {
            let err = winapi::um::errhandlingapi::GetLastError();
            eprintln!("[escape_junction] DeviceIoControl failed: err={err}");
            let _ = std::fs::remove_dir_all(&target_dir);
            if err == 5 { // ERROR_ACCESS_DENIED
                std::process::exit(5); // blocked
            }
            std::process::exit(1);
        }
    }
}
