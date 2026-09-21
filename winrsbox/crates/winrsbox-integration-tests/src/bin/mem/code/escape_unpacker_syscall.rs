// Malicious unpacker simulation: XOR-encrypted code containing syscall, unpack at runtime.
// Expected: terminated at VirtualProtect (content scan finds syscall in unpacked code).

fn main() {
    // Malicious x86-64: mov eax,0x18; syscall; ret
    let malicious_code: [u8; 8] = [0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3];
    let key: u8 = 0xBB;
    let encrypted: Vec<u8> = malicious_code.iter().map(|b| b ^ key).collect();

    // Decrypt at runtime
    let decrypted: Vec<u8> = encrypted.iter().map(|b| b ^ key).collect();

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
        std::ptr::copy_nonoverlapping(decrypted.as_ptr(), p as *mut u8, decrypted.len());

        let mut old: u32 = 0;
        // This VirtualProtect triggers content scan → finds syscall → terminate
        winapi::um::memoryapi::VirtualProtect(p, 4096, winapi::um::winnt::PAGE_EXECUTE_READ, &mut old);

        println!("should not reach this");
    }
}
