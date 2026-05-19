// Clean payload: simulates legitimate JIT — alloc RW, write clean code, protect RX, call.
// Expected: runs to completion (content-aware scan finds no syscall instructions).

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
        // Write clean x86-64 code: xor eax,eax; add eax,42; ret
        let code: [u8; 8] = [0x31, 0xC0, 0x83, 0xC0, 0x2A, 0xC3, 0x90, 0x90];
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

        let f: extern "C" fn() -> u32 = std::mem::transmute(p);
        let result = f();
        assert_eq!(result, 42, "JIT function should return 42");
        println!("clean JIT returned {result}");
    }
}
