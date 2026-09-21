// escape_short_name — tries to access C:\Program Files via 8.3 short name PROGRA~1.
// Without 8.3 normalization: classifier sees obscure path, CoW redirect might
// use wrong overlay path (progra~1 instead of program files), or if Deny policy
// applies to "program files" pattern, the 8.3 form bypasses the filter.
// With normalization: GetLongPathNameW resolves to canonical form, classifier works.
// Test: write via 8.3 path, then check if the real C:\Program Files was modified.

fn main() {
    eprintln!("[escape_short_name] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    // Clean up any prior test file
    let real_path = r"C:\Program Files\winrsbox_escape_test.txt";
    let _ = std::fs::remove_file(real_path);

    // Write via 8.3 path
    let path83 = r"C:\PROGRA~1\winrsbox_escape_test.txt";
    match std::fs::write(path83, b"escape") {
        Ok(()) => {
            // Check if the file leaked to real filesystem
            if std::path::Path::new(real_path).exists() {
                eprintln!("[escape_short_name] ESCAPE: file leaked to {}", real_path);
                let _ = std::fs::remove_file(real_path);
                std::process::exit(0);
            }
            // File was CoW'd — sandbox isolation held
            eprintln!("[escape_short_name] blocked (CoW absorbed)");
            std::process::exit(6);
        }
        Err(e) => {
            eprintln!("[escape_short_name] blocked: {}", e);
            std::process::exit(5);
        }
    }
}
