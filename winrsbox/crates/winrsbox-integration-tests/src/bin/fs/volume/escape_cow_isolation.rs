// escape_cow_isolation — writes a file under sandbox, then checks if it
// appears on the REAL filesystem outside the CoW overlay.
// In a working sandbox: write succeeds but file is in overlay only.

use std::io::Write;

fn main() {
    eprintln!("[escape_cow_isolation] starting");
    // Write to a path NOT in passthrough rules (Desktop is under HOME but
    // not explicitly passthrough'd). Should go to CoW overlay.
    let home = std::env::var("USERPROFILE").expect("USERPROFILE");
    let target = std::path::PathBuf::from(home)
        .join("Desktop")
        .join("winrsbox-cow-canary.dat");
    let canary = b"CANARY_BYTES_E2E";

    match std::fs::write(&target, canary) {
        Ok(()) => eprintln!("[escape_cow_isolation] wrote to {}", target.display()),
        Err(e) => {
            eprintln!("[escape_cow_isolation] write failed: {e}");
            std::process::exit(2);
        }
    }

    // Print the path so the test runner can verify isolation.
    println!("PATH={}", target.display());
    let _ = std::io::stdout().flush();
    std::process::exit(0);
}
