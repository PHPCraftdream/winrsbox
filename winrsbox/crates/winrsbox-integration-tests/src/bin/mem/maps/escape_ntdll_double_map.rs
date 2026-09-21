// Escape payload: maps a second copy of ntdll.dll (SEC_IMAGE) to get unhooked stubs.
// Expected: terminated by NtMapViewOfSection hook (critical DLL double-map).

use ntapi::winapi::shared::ntdef::{HANDLE, OBJECT_ATTRIBUTES, UNICODE_STRING, OBJ_CASE_INSENSITIVE};

fn main() {
    unsafe {
        let path = r"\??\C:\Windows\System32\ntdll.dll";
        let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        let mut ustr = UNICODE_STRING {
            Length: ((wide.len() - 1) * 2) as u16,
            MaximumLength: (wide.len() * 2) as u16,
            Buffer: wide.as_ptr() as *mut u16,
        };
        let mut oa = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &mut ustr,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };

        let mut file_handle: HANDLE = std::ptr::null_mut();
        let mut iosb: ntapi::ntioapi::IO_STATUS_BLOCK = std::mem::zeroed();
        let status = ntapi::ntioapi::NtOpenFile(
            &mut file_handle,
            0x80100000, // GENERIC_READ | SYNCHRONIZE
            &mut oa,
            &mut iosb,
            0x7, // FILE_SHARE_READ | WRITE | DELETE
            0x20, // FILE_SYNCHRONOUS_IO_NONALERT
        );
        if status < 0 {
            eprintln!("NtOpenFile failed: 0x{status:x}");
            std::process::exit(2);
        }

        let mut section_handle: HANDLE = std::ptr::null_mut();
        let status = ntapi::ntmmapi::NtCreateSection(
            &mut section_handle,
            0xF001F, // SECTION_ALL_ACCESS
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            winapi::um::winnt::PAGE_READONLY,
            0x1000000, // SEC_IMAGE
            file_handle,
        );
        if status < 0 {
            eprintln!("NtCreateSection failed: 0x{status:x}");
            std::process::exit(2);
        }

        let mut base: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let mut view_size: usize = 0;
        let status = ntapi::ntmmapi::NtMapViewOfSection(
            section_handle,
            -1isize as HANDLE,
            &mut base,
            0,
            0,
            std::ptr::null_mut(),
            &mut view_size,
            ntapi::ntmmapi::ViewShare,
            0,
            winapi::um::winnt::PAGE_READONLY,
        );
        if status < 0 {
            eprintln!("NtMapViewOfSection failed: 0x{status:x}");
            std::process::exit(2);
        }
        println!("double-mapped ntdll at {:p}", base);
    }
}
