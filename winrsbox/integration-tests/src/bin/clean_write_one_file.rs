// Clean payload: writes args[1] file with args[2] content. Used by the
// concurrent-children e2e test (M-T2) — two instances of this binary are
// spawned in parallel by `spawn_two_children` to exercise the launcher's
// IPC pipe server and CoW overlay under simultaneous Hello + Decide traffic.
//
// Exit codes:
//   0 = write succeeded
//   2 = missing args[1]
//   3 = write failed (CoW or policy denial)

fn main() -> std::process::ExitCode {
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
