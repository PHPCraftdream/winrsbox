// Escape payload: sets hardware breakpoint (DR0) on foreign thread via NtSetContextThread.
// Expected: terminated by inject_guard (ContextHijack: DR7 enables DR0 outside module).

fn main() {
    eprintln!("[escape_hwbp] starting");
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
        let handle = winapi::um::processthreadsapi::OpenProcess(0x1FFFFF, 0, target_pid);
        if handle.is_null() { std::process::exit(2); }
        // Alloc anon page in child for breakpoint target
        let remote = winapi::um::memoryapi::VirtualAllocEx(
            handle, std::ptr::null_mut(), 4096,
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            winapi::um::winnt::PAGE_READWRITE,
        );
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

        // Build CONTEXT with DR0 = anon memory, DR7 = enable DR0 local
        let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let hntdll = winapi::um::libloaderapi::GetModuleHandleW(ntdll_w.as_ptr());
        let set_ctx = winapi::um::libloaderapi::GetProcAddress(
            hntdll, b"NtSetContextThread\0".as_ptr() as *const i8,
        );
        type Fn = unsafe extern "system" fn(*mut winapi::ctypes::c_void, *const winapi::ctypes::c_void) -> i32;
        let nt_set: Fn = std::mem::transmute(set_ctx);

        let mut ctx = vec![0u8; 1232];
        // ContextFlags = CONTEXT_DEBUG_REGISTERS (0x100010)
        ctx[0x30..0x34].copy_from_slice(&0x0010_0010u32.to_le_bytes());
        // Dr0 = remote anon page
        let dr0 = if remote.is_null() { 0xDEADBEEFu64 } else { remote as u64 };
        ctx[0x350..0x358].copy_from_slice(&dr0.to_le_bytes());
        // Dr7 = enable DR0 local (bit 0)
        ctx[0x370..0x378].copy_from_slice(&1u64.to_le_bytes());

        let status = nt_set(thread_h as *mut _, ctx.as_ptr() as *const _);
        eprintln!("[escape_hwbp] NtSetContextThread returned 0x{status:x} (should be killed)");
    }
}
