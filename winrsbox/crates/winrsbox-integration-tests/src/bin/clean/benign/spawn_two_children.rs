// Payload for M-T2: spawn two concurrent children that each write a file.
// Parent waits for both, exits 0 iff both succeeded.
//
// Exercises:
//   - launcher pipe server handling two simultaneous Hello + Decide flows
//   - process_tracker carrying multiple owned PIDs at once
//   - two independent CoW overlays for two different write targets
//
// CLI:  spawn_two_children <writer_exe> <abs_path_a> <abs_path_b>
//
// Exit codes:
//   0 = both children succeeded
//   2 = missing writer_exe arg
//   3 = spawn A failed
//   4 = spawn B failed
//   5 = A failed only (post-wait)
//   6 = B failed only (post-wait)
//   7 = both failed (post-wait)
//   8 = missing path arg

fn main() -> std::process::ExitCode {
    let writer = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: spawn_two_children <writer_exe> <path_a> <path_b>");
            return std::process::ExitCode::from(2);
        }
    };
    let path_a = match std::env::args().nth(2) {
        Some(p) => p,
        None => return std::process::ExitCode::from(8),
    };
    let path_b = match std::env::args().nth(3) {
        Some(p) => p,
        None => return std::process::ExitCode::from(8),
    };

    // Spawn both writers without waiting between them so their Hello + Decide
    // flows interleave at the launcher's pipe server.
    let mut child_a = match std::process::Command::new(&writer)
        .args([path_a.as_str(), "hello from A"])
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("spawn A failed: {e}");
            return std::process::ExitCode::from(3);
        }
    };

    let mut child_b = match std::process::Command::new(&writer)
        .args([path_b.as_str(), "hello from B"])
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("spawn B failed: {e}");
            let _ = child_a.kill();
            let _ = child_a.wait();
            return std::process::ExitCode::from(4);
        }
    };

    let result_a = child_a.wait();
    let result_b = child_b.wait();

    let a_ok = result_a.as_ref().map(|s| s.success()).unwrap_or(false);
    let b_ok = result_b.as_ref().map(|s| s.success()).unwrap_or(false);

    if !a_ok {
        eprintln!("child A result: {:?}", result_a);
    }
    if !b_ok {
        eprintln!("child B result: {:?}", result_b);
    }

    if a_ok && b_ok {
        std::process::ExitCode::from(0)
    } else if !a_ok && !b_ok {
        std::process::ExitCode::from(7)
    } else if !a_ok {
        std::process::ExitCode::from(5)
    } else {
        std::process::ExitCode::from(6)
    }
}
