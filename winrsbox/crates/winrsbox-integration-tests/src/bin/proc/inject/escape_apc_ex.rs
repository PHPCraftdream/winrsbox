// Escape payload: NtQueueApcThreadEx on foreign process thread.
// Tests the Windows 10+ early-bird APC injection variant.
// Expected: terminated by inject_guard (QueueApc to non-owned process).

fn main() {
    eprintln!("[escape_apc_ex] starting");
    let exe = std::env::current_exe().expect("current_exe");
    let target = exe.parent().unwrap().join("clean_sleep.exe");
    let child = std::process::Command::new(&target)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn().expect("spawn");
    let target_pid = child.id();
    std::thread::sleep(std::time::Duration::from_millis(500));

    unsafe {
        // Find child thread
        let snap = winapi::um::tlhelp32::CreateToolhelp32Snapshot(0x4, target_pid);
        let mut te = winapi::um::tlhelp32::THREADENTRY32 {
            dwSize: std::mem::size_of::<winapi::um::tlhelp32::THREADENTRY32>() as u32,
            ..std::mem::zeroed()
        };
        let mut tid = 0u32;
        if winapi::um::tlhelp32::Thread32First(snap, &mut te) != 0 {
            loop {
                if te.th32OwnerProcessID == target_pid { tid = te.th32ThreadID; break; }
                if winapi::um::tlhelp32::Thread32Next(snap, &mut te) == 0 { break; }
            }
        }
        winapi::um::handleapi::CloseHandle(snap);
        if tid == 0 { std::process::exit(2); }
        let thread_h = winapi::um::processthreadsapi::OpenThread(0x1FFFFF, 0, tid);
        if thread_h.is_null() { std::process::exit(2); }

        // Resolve NtQueueApcThreadEx — the Windows 10+ variant
        let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let hntdll = winapi::um::libloaderapi::GetModuleHandleW(ntdll_w.as_ptr());
        let queue_apc_ex = winapi::um::libloaderapi::GetProcAddress(
            hntdll, b"NtQueueApcThreadEx\0".as_ptr() as *const i8,
        );
        if queue_apc_ex.is_null() {
            // NtQueueApcThreadEx not available on this Windows version
            eprintln!("[escape_apc_ex] NtQueueApcThreadEx not found (older Windows)");
            std::process::exit(7);
        }

        type FnNtQueueApcThreadEx = unsafe extern "system" fn(
            *mut winapi::ctypes::c_void, // ThreadHandle
            *mut winapi::ctypes::c_void, // UserApcReserveHandle
            *mut winapi::ctypes::c_void, // ApcRoutine
            *mut winapi::ctypes::c_void, // ApcArgument1
            *mut winapi::ctypes::c_void, // ApcArgument2
            *mut winapi::ctypes::c_void, // ApcArgument3
        ) -> i32;
        let nt_queue_ex: FnNtQueueApcThreadEx = std::mem::transmute(queue_apc_ex);

        // Use ExitThread as APC routine (benign target — hook should kill us first)
        let k32_w: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        let k32 = winapi::um::libloaderapi::GetModuleHandleW(k32_w.as_ptr());
        let exit_thread = winapi::um::libloaderapi::GetProcAddress(
            k32, b"ExitThread\0".as_ptr() as *const i8,
        );

        // Pass NULL for UserApcReserveHandle (normal user-mode APC)
        let status = nt_queue_ex(
            thread_h as *mut _, std::ptr::null_mut(),
            exit_thread as *mut _,
            std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(),
        );
        eprintln!("[escape_apc_ex] NtQueueApcThreadEx returned 0x{status:x} (should be killed)");
    }
}
