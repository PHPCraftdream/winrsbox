// Escape payload: attempts CreateRemoteThread into a child process.
// Expected: terminated by inject_guard (NtCreateThreadEx to foreign process).

fn main() {
    eprintln!("[escape_remote_thread] starting");

    let mut child = match std::process::Command::new("cmd.exe")
        .args(["/c", "ping", "-n", "30", "127.0.0.1"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[escape_remote_thread] spawn failed: {e}");
            std::process::exit(2);
        }
    };

    let target_pid = child.id();
    eprintln!("[escape_remote_thread] child pid: {target_pid}");

    std::thread::sleep(std::time::Duration::from_millis(1000));

    unsafe {
        let handle = winapi::um::processthreadsapi::OpenProcess(
            0x001FFFFF, // PROCESS_ALL_ACCESS
            0,
            target_pid,
        );
        if handle.is_null() {
            let err = winapi::um::errhandlingapi::GetLastError();
            eprintln!("[escape_remote_thread] OpenProcess failed: err={err}");
            let _ = child.kill();
            std::process::exit(2);
        }
        eprintln!("[escape_remote_thread] OpenProcess ok: {:?}", handle);

        let k32_w: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        let k32 = winapi::um::libloaderapi::GetModuleHandleW(k32_w.as_ptr());
        if k32.is_null() {
            eprintln!("[escape_remote_thread] GetModuleHandleW(kernel32) failed");
            let _ = child.kill();
            std::process::exit(2);
        }

        let exit_thread = winapi::um::libloaderapi::GetProcAddress(
            k32,
            b"ExitThread\0".as_ptr() as *const i8,
        );
        if exit_thread.is_null() {
            eprintln!("[escape_remote_thread] GetProcAddress(ExitThread) failed");
            let _ = child.kill();
            std::process::exit(2);
        }
        eprintln!("[escape_remote_thread] ExitThread at {:?}", exit_thread);

        let mut thread_id: u32 = 0;
        eprintln!("[escape_remote_thread] calling CreateRemoteThread...");
        let thread = winapi::um::processthreadsapi::CreateRemoteThread(
            handle,
            std::ptr::null_mut(),
            0,
            Some(std::mem::transmute(exit_thread)),
            std::ptr::null_mut(),
            0x4, // CREATE_SUSPENDED
            &mut thread_id,
        );
        // If we reach here, inject_guard didn't kill us
        eprintln!("[escape_remote_thread] CreateRemoteThread returned: {:?}", thread);
        let _ = child.kill();
    }
}
