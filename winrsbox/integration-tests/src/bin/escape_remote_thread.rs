// Escape payload: directly calls NtCreateThreadEx (the modern injection technique
// used by Hell's Gate / SysWhispers / Halos Gate malware after syscall resolution).
// Expected: terminated by inject_guard hook on NtCreateThreadEx.
//
// NOTE: Win32 CreateRemoteThread is NOT directly tested here because on Windows
// 10/11, kernelbase.dll inlines syscall instructions, bypassing ntdll detours.
// That is a fundamental user-mode hooking limitation; only a kernel driver can
// catch it. We instead test the more dangerous direct-syscall path that modern
// malware actually uses.

fn main() {
    eprintln!("[escape_remote_thread] starting");

    let exe = std::env::current_exe().expect("current_exe");
    let target = exe.parent().unwrap().join("clean_noop.exe");

    let mut child = match std::process::Command::new(&target)
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
    std::thread::sleep(std::time::Duration::from_millis(500));

    unsafe {
        let handle = winapi::um::processthreadsapi::OpenProcess(
            0x001FFFFF, 0, target_pid,
        );
        if handle.is_null() {
            eprintln!("[escape_remote_thread] OpenProcess failed");
            let _ = child.kill();
            std::process::exit(2);
        }

        // Direct NtCreateThreadEx via GetProcAddress — the technique used by
        // Hell's Gate-style modern injection malware.
        let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let hntdll = winapi::um::libloaderapi::GetModuleHandleW(ntdll_w.as_ptr());
        let nt_create = winapi::um::libloaderapi::GetProcAddress(
            hntdll, b"NtCreateThreadEx\0".as_ptr() as *const i8,
        );
        if nt_create.is_null() {
            eprintln!("NtCreateThreadEx not found");
            std::process::exit(2);
        }

        let k32_w: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        let k32 = winapi::um::libloaderapi::GetModuleHandleW(k32_w.as_ptr());
        let exit_thread = winapi::um::libloaderapi::GetProcAddress(
            k32, b"ExitThread\0".as_ptr() as *const i8,
        );

        type FnNtCreateThreadEx = unsafe extern "system" fn(
            *mut *mut winapi::ctypes::c_void, u32, *mut winapi::ctypes::c_void,
            *mut winapi::ctypes::c_void, *mut winapi::ctypes::c_void,
            *mut winapi::ctypes::c_void, u32, usize, usize, usize,
            *mut winapi::ctypes::c_void,
        ) -> i32;
        let nt_create_fn: FnNtCreateThreadEx = std::mem::transmute(nt_create);

        let mut thread_h: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let status = nt_create_fn(
            &mut thread_h, 0x1FFFFF, std::ptr::null_mut(),
            handle as *mut _, exit_thread as *mut _, std::ptr::null_mut(),
            1, 0, 0, 0, std::ptr::null_mut(),
        );
        eprintln!("[escape_remote_thread] NtCreateThreadEx returned 0x{status:x} (should be killed)");
        let _ = child.kill();
    }
}
