// Escape payload: alloc + NtWriteVirtualMemory with syscall bytes (direct ntdll).
// Expected: terminated by memory_guard NtWriteVirtualMemory hook (content scan).

fn main() {
    eprintln!("[escape_foreign_write_syscall] starting");
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

        // Direct NtAllocateVirtualMemory with RW (won't fire alloc hook because RW is fine)
        let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let hntdll = winapi::um::libloaderapi::GetModuleHandleW(ntdll_w.as_ptr());

        // Hmm: foreign RW alloc — should be allowed by our hook (we block only executable on foreign).
        // Then NtWriteVirtualMemory with syscall content — should fire scan.
        let p = winapi::um::memoryapi::VirtualAllocEx(
            handle, std::ptr::null_mut(), 4096,
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            winapi::um::winnt::PAGE_READWRITE,
        );
        if p.is_null() {
            eprintln!("alloc failed");
            std::process::exit(2);
        }

        // Direct NtWriteVirtualMemory with syscall content
        let nt_write = winapi::um::libloaderapi::GetProcAddress(
            hntdll, b"NtWriteVirtualMemory\0".as_ptr() as *const i8,
        );
        type FnNtWriteVm = unsafe extern "system" fn(
            *mut winapi::ctypes::c_void, *mut winapi::ctypes::c_void,
            *const winapi::ctypes::c_void, usize, *mut usize,
        ) -> i32;
        let nt_write_fn: FnNtWriteVm = std::mem::transmute(nt_write);

        let payload: [u8; 8] = [0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3];
        let mut written = 0usize;
        let status = nt_write_fn(
            handle as *mut _, p, payload.as_ptr() as *const _,
            payload.len(), &mut written,
        );
        eprintln!("[escape_foreign_write_syscall] NtWriteVirtualMemory returned 0x{status:x} (should be killed)");
    }
}
