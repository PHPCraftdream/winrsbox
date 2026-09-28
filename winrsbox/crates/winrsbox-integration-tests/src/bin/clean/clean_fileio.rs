// Clean payload: file I/O (read). Tests regression with FS hooks.
// Expected: runs to completion, not terminated by memory guard.
//
// MP-9 integration test seam: when `WINRSBOX_MP9_LOOP_PATH` is set, this
// loops rereading that path every 200ms (up to `WINRSBOX_MP9_LOOP_SECS`
// seconds, default 10) instead of the single default read below, printing
// one flushed `loop-read: ...` line per attempt. This lets a test observe an
// ALREADY-RUNNING guest pick up a live policy change (a CLI mutation relayed
// through the broker, MP-9) without restarting the guest process.
fn main() {
    if let Ok(path) = std::env::var("WINRSBOX_MP9_LOOP_PATH") {
        run_reread_loop(&path);
        return;
    }
    match std::fs::read_to_string(r"C:\Windows\System32\drivers\etc\hosts") {
        Ok(content) => println!("hosts: {} bytes", content.len()),
        Err(e) => println!("read hosts: {e}"),
    }
    println!("clean_fileio ok");
}

fn run_reread_loop(path: &str) {
    use std::io::Write;
    let secs: u64 = std::env::var("WINRSBOX_MP9_LOOP_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        match std::fs::read_to_string(path) {
            Ok(content) => println!("loop-read: ok {} bytes", content.len()),
            Err(e) => println!("loop-read: err {e}"),
        }
        let _ = std::io::stdout().flush();
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    println!("clean_fileio loop done");
}
