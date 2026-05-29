// escape_rename_device_path — tries to rename a file to a destination expressed
// as a \Device\HarddiskVolumeN path, bypassing the DOS-path containment check.
// Without H1 fix: resolve_dest_path returns None → if-let-Some skips checks →
// call_original → rename to arbitrary real FS location.
// With H1 fix: let-else deny → STATUS_ACCESS_DENIED.
//
// Note: Win32 MoveFileExW normalizes to DOS paths, so this test uses the GLOBALROOT
// form which NtSetInformationFile sees as a non-DOS device path.

use winapi::um::winbase::{MoveFileExW, MOVEFILE_REPLACE_EXISTING};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

fn main() {
    eprintln!("[escape_rename_device_path] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    let cwd = std::env::current_dir().expect("cwd");
    let src = cwd.join("rename_device_src.txt");
    let _ = std::fs::write(&src, b"escape payload");

    // Destination outside sandbox via GLOBALROOT form
    let dst = r"\\?\GLOBALROOT\Device\HarddiskVolume3\Users\Public\winrsbox_rename_escape.txt";
    let real = r"C:\Users\Public\winrsbox_rename_escape.txt";
    let _ = std::fs::remove_file(real);

    let src_w: Vec<u16> = OsStr::new(&src).encode_wide().chain(Some(0)).collect();
    let dst_w: Vec<u16> = OsStr::new(dst).encode_wide().chain(Some(0)).collect();

    let ok = unsafe { MoveFileExW(src_w.as_ptr(), dst_w.as_ptr(), MOVEFILE_REPLACE_EXISTING) };
    if ok == 0 {
        eprintln!("[escape_rename_device_path] blocked: MoveFileEx failed");
        std::process::exit(5);
    }

    if std::path::Path::new(real).exists() {
        eprintln!("[escape_rename_device_path] ESCAPE: file renamed to real FS");
        let _ = std::fs::remove_file(real);
        std::process::exit(0);
    }

    eprintln!("[escape_rename_device_path] MoveFileEx returned Ok but file absent");
    std::process::exit(6);
}
