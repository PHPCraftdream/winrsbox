// Malicious self-modifying: patches own .text with syscall instruction.
// Expected: this test is tricky — the VirtualProtect(RX) restores module memory
// which is_address_in_module=true → content scan is SKIPPED for module regions.
// This is a known design tradeoff: module .text patching is trusted because
// DLLs are scanned at load time (P3b). Self-modifying main exe would need
// separate pre-scan + hash verification (future work).
//
// For now this payload documents the limitation: self-patching .text with
// syscall is NOT caught by NtProtectVirtualMemory (module region skip).
// It IS caught by pre-launch scan if the binary originally had syscall in .text.

fn main() {
    // This buffer is in .data, not .text — so we use VirtualAlloc instead
    // to demonstrate the content scan catching it:
    unsafe {
        let p = winapi::um::memoryapi::VirtualAlloc(
            std::ptr::null_mut(),
            4096,
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            winapi::um::winnt::PAGE_READWRITE,
        );
        if p.is_null() { std::process::exit(2); }

        // Write syscall into dynamically allocated memory
        let code: [u8; 3] = [0x0F, 0x05, 0xC3]; // syscall; ret
        std::ptr::copy_nonoverlapping(code.as_ptr(), p as *mut u8, 3);

        let mut old: u32 = 0;
        winapi::um::memoryapi::VirtualProtect(
            p, 4096, winapi::um::winnt::PAGE_EXECUTE_READ, &mut old,
        );
        println!("should not reach this");
    }
}
