// escape_globalroot — tries to open a system file via GLOBALROOT alternate namespace.
// Without fs canonicalization: classifier sees unknown path → default SystemQuery → allow.
// With it: GLOBALROOT prefix matched → STATUS_ACCESS_DENIED → exit 5.

fn main() {
    eprintln!("[escape_globalroot] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    // \\?\GLOBALROOT maps to \??\GLOBALROOT in NT path form.
    // Try reading a system file through this alternate namespace.
    let path = r"\\?\GLOBALROOT\Device\HarddiskVolume3\Windows\System32\drivers\etc\hosts";
    match std::fs::read_to_string(path) {
        Ok(content) => {
            eprintln!("[escape_globalroot] FOUND: read {} bytes from GLOBALROOT", content.len());
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("[escape_globalroot] blocked: {}", e);
            std::process::exit(5);
        }
    }
}
