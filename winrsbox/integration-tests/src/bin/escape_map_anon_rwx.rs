// Escape payload: creates anonymous pagefile-backed section, maps it with RWX.
// Expected: terminated by NtMapViewOfSection hook (non-image + executable).

use ntapi::winapi::shared::ntdef::HANDLE;

fn main() {
    unsafe {
        let mut section_handle: HANDLE = std::ptr::null_mut();
        let mut section_size: i64 = 4096;
        let status = ntapi::ntmmapi::NtCreateSection(
            &mut section_handle,
            0xF001F, // SECTION_ALL_ACCESS
            std::ptr::null_mut(),
            &mut section_size as *mut i64 as *mut _,
            winapi::um::winnt::PAGE_EXECUTE_READWRITE,
            0x8000000, // SEC_COMMIT
            std::ptr::null_mut(),
        );
        if status < 0 {
            eprintln!("NtCreateSection failed: 0x{status:x}");
            std::process::exit(2);
        }

        let mut base: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let mut view_size: usize = 0;
        let status = ntapi::ntmmapi::NtMapViewOfSection(
            section_handle,
            -1isize as HANDLE, // NtCurrentProcess
            &mut base,
            0,
            0,
            std::ptr::null_mut(),
            &mut view_size,
            ntapi::ntmmapi::ViewShare,
            0,
            winapi::um::winnt::PAGE_EXECUTE_READWRITE,
        );
        if status < 0 {
            eprintln!("NtMapViewOfSection failed: 0x{status:x}");
            std::process::exit(2);
        }
        println!("mapped anon RWX at {:p}", base);
    }
}
