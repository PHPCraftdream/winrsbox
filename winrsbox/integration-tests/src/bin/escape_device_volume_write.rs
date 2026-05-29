// escape_device_volume_write — tries to write a file via \Device\HarddiskVolumeN
// form, bypassing the DOS-path policy pipeline entirely.
// Without C1 fix: resolve_for_hook returns None → call_original → real FS write.
// With C1 fix: is_fs_device_path detects HarddiskVolume → STATUS_ACCESS_DENIED.

fn main() {
    eprintln!("[escape_device_volume_write] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    // QueryDosDeviceW("C:") returns \Device\HarddiskVolumeN
    let drive: Vec<u16> = "C:\0".encode_utf16().collect();
    let mut buf = [0u16; 256];
    let len = unsafe {
        winapi::um::fileapi::QueryDosDeviceW(drive.as_ptr(), buf.as_mut_ptr(), 256)
    };
    if len == 0 {
        eprintln!("[escape_device_volume_write] QueryDosDeviceW failed");
        std::process::exit(2);
    }
    let device = String::from_utf16_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap_or(len as usize)]);
    eprintln!("[escape_device_volume_write] C: maps to {device}");

    // Try to write via device path: \??\<device>\Users\Public\winrsbox_escape_test.txt
    let target = format!(r"\\?\GLOBALROOT{}\Users\Public\winrsbox_escape_test.txt", device);
    eprintln!("[escape_device_volume_write] writing to: {target}");

    match std::fs::write(&target, b"escaped via device path") {
        Ok(()) => {
            // Verify real file exists
            let real = r"C:\Users\Public\winrsbox_escape_test.txt";
            if std::path::Path::new(real).exists() {
                eprintln!("[escape_device_volume_write] ESCAPE: file written to real FS");
                let _ = std::fs::remove_file(real);
                std::process::exit(0);
            }
            eprintln!("[escape_device_volume_write] write returned Ok but file absent (CoW?)");
            std::process::exit(6);
        }
        Err(e) => {
            eprintln!("[escape_device_volume_write] blocked: {e}");
            std::process::exit(5);
        }
    }
}
