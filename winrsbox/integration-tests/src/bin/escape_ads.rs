// escape_ads — writes payload to ADS (Alternate Data Stream) of a file inside sandbox cwd.
// Without fs canonicalization: ADS path passes through, payload written.
// With it: colon after drive triggers STATUS_ACCESS_DENIED → exit 5.

fn main() {
    eprintln!("[escape_ads] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    let cwd = std::env::current_dir().expect("cwd");
    let main_file = cwd.join("decoy.txt");
    let _ = std::fs::write(&main_file, "decoy");
    let ads_path = format!("{}:hidden", main_file.display());
    match std::fs::write(&ads_path, b"payload") {
        Ok(()) => {
            eprintln!("[escape_ads] FOUND: wrote ADS at {}", ads_path);
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("[escape_ads] blocked: {}", e);
            std::process::exit(5);
        }
    }
}
