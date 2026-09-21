// escape_alpc_com — tries to connect to a COM activation ALPC port.
// If our alpc_guard works, this should be blocked.

fn main() {
    eprintln!("[escape_alpc_com] starting");

    // Try to connect to \RPC Control\OLE<something> port.
    // We'll attempt several common COM/OLE port names.
    type FnNtAlpcConnectPort = unsafe extern "system" fn(
        *mut *mut winapi::ctypes::c_void,
        *mut ntapi::winapi::shared::ntdef::UNICODE_STRING,
        *mut ntapi::winapi::shared::ntdef::OBJECT_ATTRIBUTES,
        *mut winapi::ctypes::c_void,
        u32,
        *mut winapi::ctypes::c_void,
        *mut winapi::ctypes::c_void,
        *mut u32,
        *mut winapi::ctypes::c_void,
        *mut winapi::ctypes::c_void,
        *mut i64,
    ) -> i32;

    unsafe {
        let ntdll: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let hmod = winapi::um::libloaderapi::GetModuleHandleW(ntdll.as_ptr());
        let proc_addr = winapi::um::libloaderapi::GetProcAddress(
            hmod, b"NtAlpcConnectPort\0".as_ptr() as *const i8);
        if proc_addr.is_null() {
            eprintln!("[escape_alpc_com] NtAlpcConnectPort not found");
            std::process::exit(2);
        }
        let connect: FnNtAlpcConnectPort = std::mem::transmute(proc_addr);

        // Try common OLE port name patterns
        let port_name = r"\RPC Control\OLEf9b91d8e1234";
        let wide: Vec<u16> = port_name.encode_utf16().collect();
        let mut ustr = ntapi::winapi::shared::ntdef::UNICODE_STRING {
            Length: (wide.len() * 2) as u16,
            MaximumLength: (wide.len() * 2) as u16,
            Buffer: wide.as_ptr() as *mut u16,
        };
        let mut oa: ntapi::winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        oa.Length = std::mem::size_of::<ntapi::winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

        let mut port_handle: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let status = connect(
            &mut port_handle,
            &mut ustr,
            &mut oa,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        if status as u32 == 0xC0000022 {
            eprintln!("[escape_alpc_com] blocked: STATUS_ACCESS_DENIED");
            std::process::exit(5);
        }
        // Port may not exist (STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034) — that's also fine,
        // because the connect was attempted and would have succeeded if the port existed.
        // We only care that our hook denies BEFORE the port lookup happens.
        eprintln!("[escape_alpc_com] status=0x{status:08x} (not blocked by guard)");
        std::process::exit(1);
    }
}
