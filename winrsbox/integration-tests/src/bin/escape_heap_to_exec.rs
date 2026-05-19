// Escape payload: HeapAlloc then VirtualProtect to RX with syscall bytes.
// Expected: terminated by content-aware scan.

fn main() {
    // mov eax, 0x18; syscall; ret
    let mut buf: Vec<u8> = vec![0x90; 4096];
    buf[0] = 0xB8; buf[1] = 0x18; buf[2] = 0x00; buf[3] = 0x00; buf[4] = 0x00;
    buf[5] = 0x0F; buf[6] = 0x05; // syscall
    buf[7] = 0xC3; // ret

    let addr = buf.as_ptr() as *mut winapi::ctypes::c_void;
    unsafe {
        let mut old: u32 = 0;
        let ok = winapi::um::memoryapi::VirtualProtect(
            addr,
            4096,
            winapi::um::winnt::PAGE_EXECUTE_READ,
            &mut old,
        );
        if ok == 0 {
            eprintln!("VirtualProtect failed");
            std::process::exit(2);
        }
        println!("should not reach this");
    }
}
