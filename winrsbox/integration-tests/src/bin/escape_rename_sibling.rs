// escape_rename_sibling — tries to rename a file to a sibling directory of the
// sandbox root that shares its prefix (e.g. sandbox="c:\sb" → target="c:\sb-evil").
// Without M1 fix: starts_with("c:\sb") matches "c:\sb-evil" → rename allowed.
// With M1 fix: segment-aware pattern_matches_prefix rejects sibling.

use winapi::um::winbase::{MoveFileExW, MOVEFILE_REPLACE_EXISTING};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

fn main() {
    eprintln!("[escape_rename_sibling] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    let cwd = std::env::current_dir().expect("cwd");
    let src = cwd.join("rename_sibling_src.txt");
    let _ = std::fs::write(&src, b"sibling escape payload");

    // Construct sibling path: sandbox parent + sandbox-name-with-suffix
    let sandbox_parent = cwd.parent().unwrap_or(&cwd).parent().unwrap_or(&cwd);
    let sandbox_name = cwd.parent().unwrap_or(&cwd)
        .file_name().unwrap_or_default()
        .to_string_lossy();
    let sibling_dir = sandbox_parent.join(format!("{}-evil", sandbox_name));
    let _ = std::fs::create_dir_all(&sibling_dir);
    let dst = sibling_dir.join("escaped.txt");

    eprintln!("[escape_rename_sibling] cwd={}", cwd.display());
    eprintln!("[escape_rename_sibling] dst={}", dst.display());

    let src_w: Vec<u16> = OsStr::new(&src).encode_wide().chain(Some(0)).collect();
    let dst_w: Vec<u16> = OsStr::new(&dst).encode_wide().chain(Some(0)).collect();

    let ok = unsafe { MoveFileExW(src_w.as_ptr(), dst_w.as_ptr(), MOVEFILE_REPLACE_EXISTING) };
    if ok == 0 {
        eprintln!("[escape_rename_sibling] blocked: MoveFileEx failed");
        let _ = std::fs::remove_dir_all(&sibling_dir);
        std::process::exit(5);
    }

    if dst.exists() {
        eprintln!("[escape_rename_sibling] ESCAPE: file moved to sibling dir");
        let _ = std::fs::remove_dir_all(&sibling_dir);
        std::process::exit(0);
    }

    eprintln!("[escape_rename_sibling] MoveFileEx Ok but file absent (CoW?)");
    let _ = std::fs::remove_dir_all(&sibling_dir);
    std::process::exit(6);
}
