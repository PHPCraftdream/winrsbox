// escape_shadow_copy — tries to open a path that resolves through a
// volume shadow copy. Our classifier should reject these as Unknown.

fn main() {
    eprintln!("[escape_shadow_copy] starting");

    // \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM
    // This NT path lets attacker read historical SAM file from VSS.
    let path = r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32";
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let h = winapi::um::fileapi::CreateFileW(
            wide.as_ptr(),
            0x80000000, // GENERIC_READ
            0x07,
            std::ptr::null_mut(),
            3,
            0x02000000, // FILE_FLAG_BACKUP_SEMANTICS (needed for dirs)
            std::ptr::null_mut(),
        );
        if h == winapi::um::handleapi::INVALID_HANDLE_VALUE || h.is_null() {
            let err = winapi::um::errhandlingapi::GetLastError();
            eprintln!("[escape_shadow_copy] blocked: err={err}");
            std::process::exit(5);
        }
        eprintln!("[escape_shadow_copy] OPENED shadow copy — escape!");
        winapi::um::handleapi::CloseHandle(h);
        std::process::exit(0);
    }
}
