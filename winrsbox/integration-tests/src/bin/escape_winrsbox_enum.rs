// Lists parent directory contents looking for .winrsbox entry.
// Without enum filter: .winrsbox appears in listing -> exit 0.
// With filter: .winrsbox absent -> exit 5.

fn main() {
    eprintln!("[escape_winrsbox_enum] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    let cwd = std::env::current_dir().expect("cwd");
    let parent = cwd.parent().unwrap_or(&cwd);
    eprintln!("[escape_winrsbox_enum] enum parent: {}", parent.display());

    let mut found = false;
    if let Ok(entries) = std::fs::read_dir(parent) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy().to_lowercase();
            eprintln!("[escape_winrsbox_enum]   - {}", name_str);
            if name_str == ".winrsbox" {
                found = true;
            }
        }
    }

    if found {
        eprintln!("[escape_winrsbox_enum] FOUND: .winrsbox visible in enum");
        std::process::exit(0);
    }
    eprintln!("[escape_winrsbox_enum] hidden — defense OK");
    std::process::exit(5);
}
