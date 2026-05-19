// escape_pipe_scm — tries to open the Service Control Manager named pipe.
// Should be blocked by named pipe deny-list.

fn main() {
    eprintln!("[escape_pipe_scm] starting");

    // \\.\pipe\svcctl is SCM's named pipe. Opening it grants RPC channel
    // to start/stop services.
    let path = r"\\.\pipe\svcctl";
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let h = winapi::um::fileapi::CreateFileW(
            wide.as_ptr(),
            0xC0000000, // GENERIC_READ | GENERIC_WRITE
            0,
            std::ptr::null_mut(),
            3, // OPEN_EXISTING
            0,
            std::ptr::null_mut(),
        );
        if h == winapi::um::handleapi::INVALID_HANDLE_VALUE || h.is_null() {
            let err = winapi::um::errhandlingapi::GetLastError();
            eprintln!("[escape_pipe_scm] blocked: err={err}");
            // ERROR_ACCESS_DENIED (5) or ERROR_FILE_NOT_FOUND (2) — both acceptable
            std::process::exit(5);
        }
        eprintln!("[escape_pipe_scm] OPENED svcctl — escape possible!");
        winapi::um::handleapi::CloseHandle(h);
        std::process::exit(0);
    }
}
