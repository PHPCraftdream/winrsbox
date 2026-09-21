// Escape payload: VirtualAlloc(RWX) — under full guard mode, kernel
// ProcessDynamicCodePolicy should block this with STATUS_DYNAMIC_CODE_BLOCKED.
// Under scan mode, our user-mode hook blocks instead.

fn main() {
    unsafe {
        let p = winapi::um::memoryapi::VirtualAlloc(
            std::ptr::null_mut(),
            4096,
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            winapi::um::winnt::PAGE_EXECUTE_READWRITE,
        );
        let err = winapi::um::errhandlingapi::GetLastError();
        eprintln!("[dynamic_code] VirtualAlloc(RWX) = {:p}, GetLastError = {err}", p);
        if p.is_null() {
            // Kernel blocked — STATUS_DYNAMIC_CODE_BLOCKED typically maps to err 1260
            std::process::exit(err as i32);
        }
        // If we reach here, kernel didn't block — user-mode hook might kill us
        println!("[dynamic_code] alloc succeeded (under scan mode)");
    }
}
