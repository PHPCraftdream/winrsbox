// Escape payload: thread hijack via NtSetContextThread — sets Rip to anonymous memory.
// Expected: terminated by inject_guard (ContextHijack: Rip outside any module).

fn main() {
    eprintln!("[escape_thread_hijack] starting");

    let exe = std::env::current_exe().expect("current_exe");
    let target = exe.parent().unwrap().join("clean_sleep.exe");

    let child = match std::process::Command::new(&target)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[escape_thread_hijack] spawn failed: {e}");
            std::process::exit(2);
        }
    };

    let target_pid = child.id();
    eprintln!("[escape_thread_hijack] child pid: {target_pid}");
    std::thread::sleep(std::time::Duration::from_millis(500));

    unsafe {
        // Open child process + enumerate thread
        let handle = winapi::um::processthreadsapi::OpenProcess(0x1FFFFF, 0, target_pid);
        if handle.is_null() {
            eprintln!("OpenProcess failed");
            std::process::exit(2);
        }

        // Alloc RW in child for shellcode (simulated target)
        let remote_buf = winapi::um::memoryapi::VirtualAllocEx(
            handle,
            std::ptr::null_mut(),
            4096,
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            winapi::um::winnt::PAGE_READWRITE,
        );
        if remote_buf.is_null() {
            eprintln!("VirtualAllocEx failed");
            std::process::exit(2);
        }

        // Resolve NtSetContextThread
        let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let hntdll = winapi::um::libloaderapi::GetModuleHandleW(ntdll_w.as_ptr());
        let set_ctx = winapi::um::libloaderapi::GetProcAddress(
            hntdll, b"NtSetContextThread\0".as_ptr() as *const i8,
        );
        if set_ctx.is_null() {
            eprintln!("NtSetContextThread not found");
            std::process::exit(2);
        }

        // Get child's main thread handle via ToolHelp
        let snap = winapi::um::tlhelp32::CreateToolhelp32Snapshot(0x4, target_pid); // TH32CS_SNAPTHREAD
        if snap.is_null() || snap == -1isize as *mut _ {
            eprintln!("CreateToolhelp32Snapshot failed");
            std::process::exit(2);
        }
        let mut te = winapi::um::tlhelp32::THREADENTRY32 {
            dwSize: std::mem::size_of::<winapi::um::tlhelp32::THREADENTRY32>() as u32,
            ..std::mem::zeroed()
        };
        let mut child_tid: u32 = 0;
        if winapi::um::tlhelp32::Thread32First(snap, &mut te) != 0 {
            loop {
                if te.th32OwnerProcessID == target_pid {
                    child_tid = te.th32ThreadID;
                    break;
                }
                if winapi::um::tlhelp32::Thread32Next(snap, &mut te) == 0 { break; }
            }
        }
        winapi::um::handleapi::CloseHandle(snap);
        if child_tid == 0 {
            eprintln!("no thread found for child");
            std::process::exit(2);
        }

        let thread_h = winapi::um::processthreadsapi::OpenThread(
            0x1FFFFF, 0, child_tid,
        );
        if thread_h.is_null() {
            eprintln!("OpenThread failed");
            std::process::exit(2);
        }

        // Build a CONTEXT with Rip pointing to anonymous memory (simulated hijack)
        // CONTEXT is ~1232 bytes on x64
        let mut ctx = vec![0u8; 1232];
        // ContextFlags = CONTEXT_CONTROL (0x100001)
        let flags: u32 = 0x10_0001;
        ctx[0x30..0x34].copy_from_slice(&flags.to_le_bytes());
        // Rip = remote_buf (anonymous memory in child)
        let rip = remote_buf as u64;
        ctx[0xF8..0x100].copy_from_slice(&rip.to_le_bytes());

        type FnNtSetContextThread = unsafe extern "system" fn(
            *mut winapi::ctypes::c_void, *const winapi::ctypes::c_void,
        ) -> i32;
        let nt_set_ctx: FnNtSetContextThread = std::mem::transmute(set_ctx);

        eprintln!("[escape_thread_hijack] calling NtSetContextThread with Rip=0x{rip:x}");
        let status = nt_set_ctx(thread_h as *mut _, ctx.as_ptr() as *const _);
        eprintln!("[escape_thread_hijack] NtSetContextThread returned 0x{status:x} (should be killed)");
    }
}
