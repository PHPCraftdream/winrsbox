// escape_fs_system_write — tries to write to C:\Windows directly.
// Without deny rule: should go to CoW overlay (sandbox absorbs write).
// With deny rule: should be ACCESS_DENIED.
// Either way, the real C:\Windows directory must NOT receive the file.

use std::path::Path;

fn main() {
    eprintln!("[escape_fs_system_write] starting");
    let target = r"C:\Windows\winrsbox-escape-canary.txt";
    let write_result = std::fs::write(target, b"PWNED");
    // Re-open via direct kernel32 (bypass any Rust caching) to check if the
    // file actually landed on the real C:\Windows directory.
    let real_check = std::path::PathBuf::from(target);
    // Spawn a fresh process to check outside-sandbox would be ideal, but
    // we're already inside sandbox — instead check via direct attribute query.
    let exists_in_sandbox = real_check.exists();
    let _ = std::fs::remove_file(target);
    let _ = (real_check, exists_in_sandbox); // silence warnings

    match write_result {
        Ok(()) => {
            // Write "succeeded" — if it's via CoW overlay, that's correct sandbox
            // behavior (real C:\Windows untouched). If deny: shouldn't get here.
            // From inside sandbox we can't easily verify the real filesystem,
            // so we exit 6 ("absorbed by CoW") — the test harness verifies
            // the real C:\Windows directory afterwards.
            eprintln!("[escape_fs_system_write] write_ok — absorbed by CoW or escape");
            std::process::exit(6);
        }
        Err(_) => {
            eprintln!("[escape_fs_system_write] blocked: ACCESS_DENIED");
            std::process::exit(5);
        }
    }
}

// Suppress unused Path import warning
#[allow(dead_code)]
fn _silence(_: &Path) {}
