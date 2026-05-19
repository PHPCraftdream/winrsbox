// Escape payload: VirtualProtect stack region to RX with syscall bytes.
// Expected: terminated by content-aware scan.

fn main() {
    // mov eax, 0x18; syscall; ret
    let mut stack_var: [u8; 4096] = [0x90; 4096];
    stack_var[0] = 0xB8; stack_var[1] = 0x18; stack_var[2] = 0x00;
    stack_var[3] = 0x00; stack_var[4] = 0x00;
    stack_var[5] = 0x0F; stack_var[6] = 0x05; // syscall
    stack_var[7] = 0xC3;

    let addr = stack_var.as_ptr() as *mut winapi::ctypes::c_void;
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
