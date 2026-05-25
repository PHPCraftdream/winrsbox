// escape_raw_disk — tries to open \\.\PhysicalDrive0 for raw disk access.
// Our classifier hard-blocks any path containing "physicaldrive" as Unknown.

fn main() {
    eprintln!("[escape_raw_disk] starting");

    // \\.\PhysicalDrive0 → device\physicaldrive0 in our classifier
    let path = r"\\.\PhysicalDrive0";
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let h = winapi::um::fileapi::CreateFileW(
            wide.as_ptr(),
            0x80000000, // GENERIC_READ
            0x07,
            std::ptr::null_mut(),
            3,
            0,
            std::ptr::null_mut(),
        );
        if h == winapi::um::handleapi::INVALID_HANDLE_VALUE || h.is_null() {
            let err = winapi::um::errhandlingapi::GetLastError();
            eprintln!("[escape_raw_disk] blocked: err={err}");
            std::process::exit(5);
        }
        eprintln!("[escape_raw_disk] OPENED PhysicalDrive0 — escape!");
        winapi::um::handleapi::CloseHandle(h);
        std::process::exit(0);
    }
}
