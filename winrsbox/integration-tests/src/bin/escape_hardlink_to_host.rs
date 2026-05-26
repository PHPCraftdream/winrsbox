// Tries CreateHardLinkW(sandbox_link, host_file).
// Without hook: link created, sandbox can read/write host file via link.
// With hook: NtSetInformationFile(FileLinkInformation) denied → exit 5.

use winapi::um::winbase::CreateHardLinkW;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

fn main() {
    eprintln!("[escape_hardlink_to_host] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    let cwd = std::env::current_dir().expect("cwd");
    let link = cwd.join("evil_link.txt");
    let _ = std::fs::remove_file(&link);

    // Hard-link to an existing host file (use one we know exists).
    // hosts file is always present.
    let host = r"C:\Windows\System32\drivers\etc\hosts";
    if !std::path::Path::new(host).exists() {
        eprintln!("[escape_hardlink_to_host] hosts file absent, skipping");
        std::process::exit(7);
    }

    let link_w: Vec<u16> = OsStr::new(&link).encode_wide().chain(Some(0)).collect();
    let host_w: Vec<u16> = OsStr::new(host).encode_wide().chain(Some(0)).collect();

    unsafe {
        let ok = CreateHardLinkW(link_w.as_ptr(), host_w.as_ptr(), null_mut());
        if ok == 0 {
            let err = winapi::um::errhandlingapi::GetLastError();
            eprintln!("[escape_hardlink_to_host] blocked: CreateHardLink err={}", err);
            std::process::exit(5);
        }
        eprintln!("[escape_hardlink_to_host] FOUND: hard link created — escape vector!");
        let _ = std::fs::remove_file(&link);
        std::process::exit(0);
    }
}
