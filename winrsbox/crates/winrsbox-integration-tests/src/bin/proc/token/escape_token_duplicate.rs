// escape_token_duplicate — tries NtDuplicateToken with TokenPrimary type.
// DuplicateTokenEx / NtDuplicateToken can create a primary token from any token
// handle, enabling CreateProcessAsUser with the duplicated token context.
// Without token_guard: duplication succeeds → primary token obtained → escape.
// With token_guard: NtDuplicateToken returns STATUS_ACCESS_DENIED → exit 5.

fn main() {
    eprintln!("[escape_token_duplicate] starting");

    unsafe {
        // Open our own process token first (legitimate self-access)
        let mut token: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let process = winapi::um::processthreadsapi::GetCurrentProcess();
        let ok = winapi::um::processthreadsapi::OpenProcessToken(
            process,
            0x0008 | 0x0002, // TOKEN_QUERY | TOKEN_DUPLICATE
            &mut token,
        );
        if ok == 0 {
            eprintln!("[escape_token_duplicate] OpenProcessToken failed");
            std::process::exit(2);
        }

        // Try NtDuplicateToken with TokenPrimary = 1
        type FnNtDuplicateToken = unsafe extern "system" fn(
            *mut winapi::ctypes::c_void, // ExistingTokenHandle
            u32,        // DesiredAccess
            *mut winapi::ctypes::c_void, // ObjectAttributes
            u32,        // EffectiveOnly (BOOLEAN)
            u32,        // TokenType (TokenPrimary=1, TokenImpersonation=2)
            *mut *mut winapi::ctypes::c_void, // NewTokenHandle
        ) -> i32;

        let ntdll: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let hmod = winapi::um::libloaderapi::GetModuleHandleW(ntdll.as_ptr());
        let proc_addr = winapi::um::libloaderapi::GetProcAddress(
            hmod, b"NtDuplicateToken\0".as_ptr() as *const i8);
        if proc_addr.is_null() {
            eprintln!("[escape_token_duplicate] NtDuplicateToken not found");
            winapi::um::handleapi::CloseHandle(token);
            std::process::exit(2);
        }
        let dup_token: FnNtDuplicateToken = std::mem::transmute(proc_addr);

        let mut new_token: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let status = dup_token(
            token,
            0x000F01FF, // TOKEN_ALL_ACCESS
            std::ptr::null_mut(), // ObjectAttributes
            0,           // EffectiveOnly = FALSE
            1,           // TokenPrimary
            &mut new_token,
        );
        winapi::um::handleapi::CloseHandle(token);

        if status as u32 == 0xC0000022 {
            eprintln!("[escape_token_duplicate] blocked: STATUS_ACCESS_DENIED");
            std::process::exit(5);
        }
        if !new_token.is_null() {
            winapi::um::handleapi::CloseHandle(new_token);
        }
        eprintln!("[escape_token_duplicate] status=0x{:08x} (not blocked)", status as u32);
        std::process::exit(1);
    }
}
