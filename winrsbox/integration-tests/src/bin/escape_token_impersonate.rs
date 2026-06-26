// escape_token_impersonate — NtSetInformationThread(ThreadImpersonationToken)
// on the CURRENT thread with the process's OWN token (GetCurrentThread() +
// OpenProcessToken(GetCurrentProcess())). This is the primitive behind
// SetThreadToken / ImpersonateLoggedOnUser.
//
// token_guard policy: self-impersonation (own token on own thread) is ALLOWED
// — it confers no privilege escalation (the token is already ours) and is what
// Schannel/TLS and the .NET networking stack do during a handshake. The
// foreign-token escalation vector is blocked upstream (NtOpenProcessTokenEx,
// NtImpersonateThread). So this payload must NOT be blocked (exit != 5).

fn main() {
    eprintln!("[escape_token_impersonate] starting");

    unsafe {
        // Get our OWN process token — self-impersonation with it must be
        // allowed (no escalation; Schannel does this for TLS). The foreign-
        // token vector is tested elsewhere and blocked upstream.
        let mut token: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let process = winapi::um::processthreadsapi::GetCurrentProcess();
        let ok = winapi::um::processthreadsapi::OpenProcessToken(
            process,
            0x0008 | 0x0004, // TOKEN_QUERY | TOKEN_IMPERSONATE
            &mut token,
        );
        if ok == 0 {
            eprintln!("[escape_token_impersonate] OpenProcessToken failed");
            std::process::exit(2);
        }

        // Try NtSetInformationThread(ThreadImpersonationToken = 5)
        type FnNtSetInformationThread = unsafe extern "system" fn(
            *mut winapi::ctypes::c_void, // ThreadHandle
            u32,        // ThreadInformationClass
            *mut winapi::ctypes::c_void, // ThreadInformation
            u32,        // ThreadInformationLength
        ) -> i32;

        let ntdll: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let hmod = winapi::um::libloaderapi::GetModuleHandleW(ntdll.as_ptr());
        let proc_addr = winapi::um::libloaderapi::GetProcAddress(
            hmod, b"NtSetInformationThread\0".as_ptr() as *const i8);
        if proc_addr.is_null() {
            eprintln!("[escape_token_impersonate] NtSetInformationThread not found");
            winapi::um::handleapi::CloseHandle(token);
            std::process::exit(2);
        }
        let set_info: FnNtSetInformationThread = std::mem::transmute(proc_addr);

        let thread = winapi::um::processthreadsapi::GetCurrentThread();
        let token_handle = token;
        let status = set_info(
            thread,
            5, // ThreadImpersonationToken
            &token_handle as *const _ as *mut winapi::ctypes::c_void,
            std::mem::size_of::<*mut winapi::ctypes::c_void>() as u32,
        );
        winapi::um::handleapi::CloseHandle(token);

        if status as u32 == 0xC0000022 {
            eprintln!("[escape_token_impersonate] blocked: STATUS_ACCESS_DENIED");
            std::process::exit(5);
        }
        eprintln!("[escape_token_impersonate] status=0x{:08x} (not blocked)", status as u32);
        std::process::exit(1);
    }
}
