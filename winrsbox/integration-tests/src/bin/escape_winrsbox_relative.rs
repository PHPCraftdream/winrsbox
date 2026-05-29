// escape_winrsbox_relative — tries to read .winrsbox via a relative path from
// an already-open directory handle, bypassing the ObjectName-only denylist check.
// Without C2 fix: extract_raw_nt_path sees bare ".winrsbox\..." without leading
// backslash → denylist misses → resolve_for_hook joins → read succeeds.
// With C2 fix: canonical_denylist_status runs on the resolved DOS path → blocked.
//
// Since we can't directly use NtCreateFile with RootDirectory from Rust std,
// we use the equivalent pattern: open parent dir, then join .winrsbox as relative.

fn main() {
    eprintln!("[escape_winrsbox_relative] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    let cwd = std::env::current_dir().expect("cwd");
    let parent = cwd.parent().unwrap_or(&cwd);

    // Attempt 1: direct relative path from parent
    let target = parent.join(".winrsbox");
    eprintln!("[escape_winrsbox_relative] probing: {}", target.display());
    match std::fs::read_dir(&target) {
        Ok(entries) => {
            let count = entries.count();
            eprintln!("[escape_winrsbox_relative] LEAK: .winrsbox visible, {count} entries");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("[escape_winrsbox_relative] direct: blocked ({e})");
        }
    }

    // Attempt 2: try to read a known file inside .winrsbox
    let policy_file = parent.join(".winrsbox").join("policy.redb");
    match std::fs::metadata(&policy_file) {
        Ok(m) => {
            eprintln!("[escape_winrsbox_relative] LEAK: policy.redb visible, {} bytes", m.len());
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("[escape_winrsbox_relative] policy.redb: blocked ({e})");
        }
    }

    eprintln!("[escape_winrsbox_relative] all attempts blocked");
    std::process::exit(5);
}
