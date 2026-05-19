// Escape payload: allocates memory until Job Object limit is hit.
// Expected: allocation fails or process killed by kernel when limit exceeded.
// Run with: winrsbox --memory-limit 1 -- escape_memory_bomb.exe

fn main() {
    eprintln!("[memory_bomb] starting allocations");
    let mut bufs: Vec<Vec<u8>> = Vec::new();
    for i in 0..100 {
        match std::panic::catch_unwind(|| vec![0u8; 128 * 1024 * 1024]) { // 128 MB chunks
            Ok(buf) => {
                bufs.push(buf);
                eprintln!("[memory_bomb] allocated {} MB", (i + 1) * 128);
            }
            Err(_) => {
                eprintln!("[memory_bomb] allocation panicked at {} MB", (i + 1) * 128);
                std::process::exit(1);
            }
        }
    }
    eprintln!("[memory_bomb] allocated 12.8 GB without being stopped (BUG)");
}
