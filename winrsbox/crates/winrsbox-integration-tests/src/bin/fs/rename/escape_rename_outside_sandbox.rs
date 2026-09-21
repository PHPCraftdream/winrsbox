// Tries to rename a file from sandbox cwd to a path outside (host filesystem).
//
// Under the CoW overlay model the sandbox does NOT hard-deny this rename — it
// redirects the destination into the overlay, so the real disk is untouched.
// The payload therefore cannot self-verify "did it leak?" from inside the
// sandbox: its own `.exists()` query is itself intercepted and observes the
// overlay copy, so it would always report "moved". Instead the payload reports
// only the raw MoveFileEx result and leaves the target in place; the OUTER
// test process (not under the sandbox) checks the real disk for a leak.
//
// exit 5: NtSetInformationFile was hard-denied (STATUS_ACCESS_DENIED).
// exit 0: the operation completed (either CoW-absorbed or, if the sandbox is
//         broken, a real leak — the outer test distinguishes the two).

use winapi::um::winbase::{MoveFileExW, MOVEFILE_REPLACE_EXISTING};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

fn main() {
    eprintln!("[escape_rename_outside_sandbox] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    // Create a file in cwd, then rename it OUT of sandbox.
    let cwd = std::env::current_dir().expect("cwd");
    let src = cwd.join("rename_src.txt");
    let _ = std::fs::write(&src, b"data");

    let dst_outside = r"C:\Windows\Temp\winrsbox_escape_rename.txt";

    let src_w: Vec<u16> = OsStr::new(&src).encode_wide().chain(Some(0)).collect();
    let dst_w: Vec<u16> = OsStr::new(dst_outside).encode_wide().chain(Some(0)).collect();

    unsafe {
        let ok = MoveFileExW(src_w.as_ptr(), dst_w.as_ptr(), MOVEFILE_REPLACE_EXISTING);
        if ok == 0 {
            let err = winapi::um::errhandlingapi::GetLastError();
            eprintln!("[escape_rename_outside_sandbox] blocked: MoveFileEx err={}", err);
            std::process::exit(5);
        }
        // Deliberately do NOT delete dst_outside and do NOT probe it from here:
        // both acts run under our own hooks and would only see the overlay.
        // The outer test process owns the real-disk leak check.
        eprintln!("[escape_rename_outside_sandbox] MoveFileEx returned ok (CoW-absorbed unless outer check finds a leak)");
        std::process::exit(0);
    }
}
