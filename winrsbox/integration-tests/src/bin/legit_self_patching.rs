// Legit self-patching: alloc RW, write clean code, flip to RX, execute.
// (Uses anonymous memory to avoid complexity of patching own .text)
// Expected: runs to completion (no syscall instructions).

fn main() {
    unsafe {
        let p = winapi::um::memoryapi::VirtualAlloc(
            std::ptr::null_mut(),
            4096,
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            winapi::um::winnt::PAGE_READWRITE,
        );
        if p.is_null() { eprintln!("VirtualAlloc failed"); std::process::exit(2); }

        // Write clean x86-64: mov eax, 7; ret
        let code: [u8; 7] = [0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3, 0x90];
        std::ptr::copy_nonoverlapping(code.as_ptr(), p as *mut u8, code.len());

        // First flip: RW→RX
        let mut old: u32 = 0;
        winapi::um::memoryapi::VirtualProtect(p, 4096, winapi::um::winnt::PAGE_EXECUTE_READ, &mut old);
        let f: extern "C" fn() -> u32 = std::mem::transmute(p);
        let r1 = f();
        assert_eq!(r1, 7);

        // Self-patch: RX→RW, modify value, RW→RX
        winapi::um::memoryapi::VirtualProtect(p, 4096, winapi::um::winnt::PAGE_READWRITE, &mut old);
        // Change immediate from 7 to 77
        *(p as *mut u8).add(1) = 77;
        winapi::um::memoryapi::VirtualProtect(p, 4096, winapi::um::winnt::PAGE_EXECUTE_READ, &mut old);

        let r2 = f();
        assert_eq!(r2, 77);
        println!("self-patched: {r1} -> {r2}");
    }
}
