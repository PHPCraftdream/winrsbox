// Escape payload: NtAllocateVirtualMemory(target_proc, ..., RWX) directly via
// GetProcAddress (modern Hell's-Gate-style attack — Win32 VirtualAllocEx is
// inlined in kernelbase on Win10/11 and bypasses ntdll detours).
// Expected: terminated by memory_guard foreign-process branch.

fn main() {
    eprintln!("[escape_foreign_alloc_rwx] starting");
    let exe = std::env::current_exe().expect("current_exe");
    let target = exe.parent().unwrap().join("clean_sleep.exe");
    let child = std::process::Command::new(&target)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn");
    let target_pid = child.id();
    std::thread::sleep(std::time::Duration::from_millis(500));

    unsafe {
        let handle = winapi::um::processthreadsapi::OpenProcess(0x1FFFFF, 0, target_pid);
        if handle.is_null() { std::process::exit(2); }

        // Direct ntdll!NtAllocateVirtualMemory
        let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let hntdll = winapi::um::libloaderapi::GetModuleHandleW(ntdll_w.as_ptr());
        let nt_alloc = winapi::um::libloaderapi::GetProcAddress(
            hntdll, b"NtAllocateVirtualMemory\0".as_ptr() as *const i8,
        );
        type FnNtAllocVm = unsafe extern "system" fn(
            *mut winapi::ctypes::c_void, *mut *mut winapi::ctypes::c_void,
            usize, *mut usize, u32, u32,
        ) -> i32;
        let nt_alloc_fn: FnNtAllocVm = std::mem::transmute(nt_alloc);

        let mut base: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let mut size: usize = 4096;
        let status = nt_alloc_fn(
            handle as *mut _, &mut base, 0, &mut size,
            0x1000 | 0x2000, // MEM_COMMIT | MEM_RESERVE
            0x40, // PAGE_EXECUTE_READWRITE
        );
        eprintln!("[escape_foreign_alloc_rwx] NtAllocateVirtualMemory returned 0x{status:x} (should be killed)");
    }
}
