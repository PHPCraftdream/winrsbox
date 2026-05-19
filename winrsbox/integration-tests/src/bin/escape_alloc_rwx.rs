// Escape payload: allocates PAGE_EXECUTE_READWRITE memory via VirtualAlloc.
// Expected: terminated by memory guard in strict mode.

fn main() {
    unsafe {
        let p = winapi::um::memoryapi::VirtualAlloc(
            std::ptr::null_mut(),
            4096,
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            winapi::um::winnt::PAGE_EXECUTE_READWRITE,
        );
        if p.is_null() {
            eprintln!("VirtualAlloc failed");
            std::process::exit(2);
        }
        // Write a RET instruction
        *(p as *mut u8) = 0xC3;
        println!("allocated RWX at {:p}", p);
    }
}
