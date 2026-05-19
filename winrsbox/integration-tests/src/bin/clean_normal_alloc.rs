// Clean payload: allocates PAGE_READWRITE memory (non-executable).
// Expected: runs to completion, not terminated by memory guard.

fn main() {
    unsafe {
        let p = winapi::um::memoryapi::VirtualAlloc(
            std::ptr::null_mut(),
            1024 * 1024,
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            winapi::um::winnt::PAGE_READWRITE,
        );
        if p.is_null() {
            eprintln!("VirtualAlloc failed");
            std::process::exit(2);
        }
        std::ptr::write_bytes(p as *mut u8, 0xAA, 1024);
        println!("allocated 1MB RW at {:p}", p);
    }
}
