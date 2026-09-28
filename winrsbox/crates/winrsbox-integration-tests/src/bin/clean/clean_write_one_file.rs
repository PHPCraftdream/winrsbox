// Clean payload: writes args[1] file with args[2] content. Used by the
// concurrent-children e2e test (M-T2) — two instances of this binary are
// spawned in parallel by `spawn_two_children` to exercise the launcher's
// IPC pipe server and CoW overlay under simultaneous Hello + Decide traffic.
//
// MP-10 integration test seam: when `WINRSBOX_READ_PATH` is set, this reads
// that path instead of writing anything — lets a test run a SEPARATE guest
// session that reads back a file a different session's guest wrote, proving
// cross-session CoW-overlay visibility through the one shared `policy.redb`
// the broker owns (same env-var-opt-in shape as `clean_fileio`'s MP-9 loop
// mode, `clean_sleep`'s MP-10 write-before-sleep mode).
//
// Exit codes:
//   0 = write (or read) succeeded
//   2 = missing args[1] (write mode only)
//   3 = write failed (CoW or policy denial)
//   4 = read failed (WINRSBOX_READ_PATH mode only)

fn main() -> std::process::ExitCode {
    if let Ok(path) = std::env::var("WINRSBOX_READ_PATH") {
        return match std::fs::read_to_string(&path) {
            Ok(content) => {
                println!("read: ok {content}");
                std::process::ExitCode::from(0)
            }
            Err(e) => {
                println!("read: err {e}");
                std::process::ExitCode::from(4)
            }
        };
    }
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: clean_write_one_file <path> <content>");
            return std::process::ExitCode::from(2);
        }
    };
    let content = std::env::args().nth(2).unwrap_or_default();
    match std::fs::write(&path, content.as_bytes()) {
        Ok(_) => std::process::ExitCode::from(0),
        Err(e) => {
            eprintln!("write {} failed: {e}", path);
            std::process::ExitCode::from(3)
        }
    }
}
