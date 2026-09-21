// escape_file_by_id — tries NtCreateFile with FILE_OPEN_BY_FILE_ID flag.
// Without check: opens file by FileID, path ignored — classifier bypassed.
// With check: flag detected before original call → STATUS_ACCESS_DENIED → exit 5.

use std::ptr::null_mut;

fn main() {
    eprintln!("[escape_file_by_id] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    // Minimal: attempt NtCreateFile with FILE_OPEN_BY_FILE_ID flag.
    // Even with empty path, our hook should deny before forwarding.
    unsafe {
        let mut handle: *mut winapi::ctypes::c_void = null_mut();
        let mut iosb = [0u64; 2]; // IO_STATUS_BLOCK is 16 bytes on x64
        let mut path_buf: [u16; 1] = [0]; // empty path
        let mut ustr = ntapi::winapi::shared::ntdef::UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: path_buf.as_mut_ptr(),
        };
        let mut oa = ntapi::winapi::shared::ntdef::OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<ntapi::winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: null_mut(),
            ObjectName: &mut ustr,
            Attributes: 0,
            SecurityDescriptor: null_mut(),
            SecurityQualityOfService: null_mut(),
        };

        const FILE_OPEN_BY_FILE_ID: u32 = 0x2000;
        const FILE_OPEN: u32 = 1;

        let status = ntapi::ntioapi::NtCreateFile(
            &mut handle,
            0x80000000u32, // GENERIC_READ
            &mut oa,
            iosb.as_mut_ptr() as *mut _,
            null_mut(),
            0,
            7, // FILE_SHARE_ALL
            FILE_OPEN,
            FILE_OPEN_BY_FILE_ID,
            null_mut(),
            0,
        );
        if status == 0xC0000022u32 as i32 {
            eprintln!("[escape_file_by_id] blocked: STATUS_ACCESS_DENIED");
            std::process::exit(5);
        }
        eprintln!("[escape_file_by_id] NtCreateFile returned 0x{:x} (not blocked)", status as u32);
        if !handle.is_null() {
            winapi::um::handleapi::CloseHandle(handle);
        }
        std::process::exit(0);
    }
}
