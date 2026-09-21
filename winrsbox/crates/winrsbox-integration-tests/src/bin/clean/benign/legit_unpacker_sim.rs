// Legit unpacker simulation: XOR-encrypted clean code, unpack at runtime.
// Expected: runs to completion (unpacked code has no syscall instructions).

fn main() {
    // Clean x86-64: xor eax,eax; add eax,99; ret; nop*5
    let clean_code: [u8; 8] = [0x31, 0xC0, 0x83, 0xC0, 0x63, 0xC3, 0x90, 0x90];
    let key: u8 = 0xAA;
    let encrypted: Vec<u8> = clean_code.iter().map(|b| b ^ key).collect();

    // Decrypt at runtime
    let decrypted: Vec<u8> = encrypted.iter().map(|b| b ^ key).collect();
    assert_eq!(decrypted, clean_code);

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
        winapi::um::memoryapi::VirtualProtect(p, 4096, winapi::um::winnt::PAGE_EXECUTE_READ, &mut old);

        let f: extern "C" fn() -> u32 = std::mem::transmute(p);
        let result = f();
        println!("unpacked code returned {result}");
        assert_eq!(result, 99);
    }
}
