// escape_systemquery_write — tries to open \Device\MountPointManager with
// GENERIC_WRITE. Should be blocked by is_safe_with_access(SystemQuery, write=true).

fn main() {
    eprintln!("[escape_systemquery_write] starting");

    // Open MountPointManager with write access via NtCreateFile
    let path = r"\??\MountPointManager";
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let mut ustr = ntapi::winapi::shared::ntdef::UNICODE_STRING {
            Length: ((wide.len() - 1) * 2) as u16,
            MaximumLength: (wide.len() * 2) as u16,
            Buffer: wide.as_ptr() as *mut u16,
        };
        let mut oa = ntapi::winapi::shared::ntdef::OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<ntapi::winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &mut ustr,
            Attributes: 0x40, // OBJ_CASE_INSENSITIVE
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let mut handle: ntapi::winapi::shared::ntdef::HANDLE = std::ptr::null_mut();
        let mut iosb: ntapi::ntioapi::IO_STATUS_BLOCK = std::mem::zeroed();

        // GENERIC_WRITE = 0x40000000
        let status = ntapi::ntioapi::NtCreateFile(
            &mut handle,
            0x40000000, // GENERIC_WRITE
            &mut oa,
            &mut iosb,
            std::ptr::null_mut(),
            0,
            0x07, // FILE_SHARE_READ | WRITE | DELETE
            0x01, // FILE_OPEN
            0,
            std::ptr::null_mut(),
            0,
        );

        if status >= 0 {
            eprintln!("[escape_systemquery_write] OPENED with WRITE — escape possible!");
            winapi::um::handleapi::CloseHandle(handle);
            std::process::exit(0);
        } else {
            eprintln!("[escape_systemquery_write] blocked: status=0x{status:08x}");
            std::process::exit(5);
        }
    }
}
