// Escape payload: allocates RW memory, writes code with syscall, then VirtualProtect to RX.
// Expected: terminated by content-aware scan in NtProtectVirtualMemory hook.

fn main() {
    unsafe {
        let p = winapi::um::memoryapi::VirtualAlloc(
            std::ptr::null_mut(),
            4096,
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            winapi::um::winnt::PAGE_READWRITE,
        );
        if p.is_null() {
            eprintln!("VirtualAlloc failed");
            std::process::exit(2);
        }
        // Write code containing a direct syscall instruction
        // mov eax, 0x18; syscall; ret
        let code: [u8; 9] = [0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90];
        std::ptr::copy_nonoverlapping(code.as_ptr(), p as *mut u8, code.len());

        let mut old_protect: u32 = 0;
        let ok = winapi::um::memoryapi::VirtualProtect(
            p,
            4096,
            winapi::um::winnt::PAGE_EXECUTE_READ,
            &mut old_protect,
        );
        if ok == 0 {
            eprintln!("VirtualProtect failed");
            std::process::exit(2);
        }
        println!("should not reach this");
    }
}
