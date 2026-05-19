// Escape payload: emits a `syscall` instruction directly in .text.
// Expected: refused at launch by pre-launch code integrity scan.

use std::arch::asm;

fn main() {
    let result: i32;
    unsafe {
        asm!(
            "syscall",
            in("eax") 0x100u32, // bogus SSN
            in("r10") 0u64,
            in("rdx") 0u64,
            in("r8") 0u64,
            in("r9") 0u64,
            lateout("eax") result,
            clobber_abi("system"),
        );
    }
    println!("syscall returned {result}");
}
