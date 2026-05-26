// Tries to rename a file from sandbox cwd to a path outside (host filesystem).
// Without hook: rename succeeds → file is moved into host.
// With hook: NtSetInformationFile(FileRenameInformation) returns
//            STATUS_ACCESS_DENIED → MoveFileExW returns 0 → exit 5.

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
    let _ = std::fs::remove_file(dst_outside);

    let src_w: Vec<u16> = OsStr::new(&src).encode_wide().chain(Some(0)).collect();
    let dst_w: Vec<u16> = OsStr::new(dst_outside).encode_wide().chain(Some(0)).collect();

    unsafe {
        let ok = MoveFileExW(src_w.as_ptr(), dst_w.as_ptr(), MOVEFILE_REPLACE_EXISTING);
        if ok == 0 {
            let err = winapi::um::errhandlingapi::GetLastError();
            eprintln!("[escape_rename_outside_sandbox] blocked: MoveFileEx err={}", err);
            std::process::exit(5);
        }
        // Verify it really moved
        if std::path::Path::new(dst_outside).exists() {
            eprintln!("[escape_rename_outside_sandbox] FOUND: file moved to {}", dst_outside);
            let _ = std::fs::remove_file(dst_outside);
            std::process::exit(0);
        }
        eprintln!("[escape_rename_outside_sandbox] MoveFileEx succeeded but file absent — CoW absorbed");
        std::process::exit(6);
    }
}
