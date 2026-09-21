// Tries to read .winrsbox/sandbox.log.jsonl from inside sandbox.
// Without isolation: read succeeds, sees host state.
// With layer 1: open fails with NOT_FOUND -> exit 5.

fn main() {
    eprintln!("[escape_winrsbox_read] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    // Probe via the sandbox-relative path. The sandbox is at <project>/tmp/
    // (parent of cwd <project>/tmp/tmp). So .winrsbox is at <project>/tmp/.winrsbox/.
    // We try cwd parent.
    let cwd = std::env::current_dir().expect("cwd");
    let parent = cwd.parent().unwrap_or(&cwd);
    let target = parent.join(".winrsbox");
    eprintln!("[escape_winrsbox_read] probing: {}", target.display());

    match std::fs::metadata(&target) {
        Ok(_) => {
            // Try to read something inside
            let log = target.join("tmp").join("sandbox.log.jsonl");
            match std::fs::read_to_string(&log) {
                Ok(content) => {
                    eprintln!("[escape_winrsbox_read] FOUND: read {} bytes from sandbox log", content.len());
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("[escape_winrsbox_read] folder exists but file read failed: {}", e);
                    std::process::exit(6);  // folder visible but log blocked — partial leak
                }
            }
        }
        Err(e) => {
            eprintln!("[escape_winrsbox_read] blocked: {}", e);
            std::process::exit(5);
        }
    }
}
