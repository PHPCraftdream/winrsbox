// escape_token_impersonate — NtSetInformationThread(ThreadImpersonationToken)
// on the CURRENT thread with the process's OWN token (GetCurrentThread() +
// OpenProcessToken(GetCurrentProcess())). This is the primitive behind
// SetThreadToken / ImpersonateLoggedOnUser.
//
// token_guard policy: self-impersonation (own token on own thread) is ALLOWED
// — it confers no privilege escalation (the token is already ours) and is what
// Schannel/TLS and the .NET networking stack do during a handshake. The
// foreign-token escalation vector is blocked upstream (NtOpenProcessTokenEx,
// NtImpersonateThread).
//
// Exit codes:
//   0 — self-impersonation ALLOWED (NtSetInformationThread succeeded).
//   5 — BLOCKED (STATUS_ACCESS_DENIED) — regression of the allow-self policy.
//   1 — unexpected NT status (neither success nor access-denied).
//   2 — payload setup failure (OpenProcessToken / GetProcAddress).

fn main() {
    eprintln!("[escape_token_impersonate] starting");

    unsafe {
        // OpenProcessToken yields a PRIMARY token; NtSetInformationThread
        // (ThreadImpersonationToken) requires an IMPERSONATION token. Duplicate
        // one (SecurityImpersonation level, TokenImpersonation type) — exactly
        // what Schannel/.NET do for a TLS handshake. This is our OWN process
        // token duplicated, so self-impersonation confers no escalation; the
        // foreign-token vector is tested elsewhere and blocked upstream.
        let mut primary: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let process = winapi::um::processthreadsapi::GetCurrentProcess();
        // TOKEN_DUPLICATE (0x2) is required to duplicate; TOKEN_QUERY (0x8) to
        // read. (Not to be confused with TOKEN_IMPERSONATE = 0x4.)
        let ok = winapi::um::processthreadsapi::OpenProcessToken(
            process,
            0x0002 | 0x0008, // TOKEN_DUPLICATE | TOKEN_QUERY
            &mut primary,
        );
        if ok == 0 {
            eprintln!("[escape_token_impersonate] OpenProcessToken failed");
            std::process::exit(2);
        }

        // MAXIMUM_ALLOWED (0x02000000) on the duplicate: simplest reliable
        // access for a self-impersonation token used with SetThreadToken.
        let mut token: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let ok = winapi::um::securitybaseapi::DuplicateTokenEx(
            primary,
            0x0200_0000, // MAXIMUM_ALLOWED
            std::ptr::null_mut(),
            2, // SecurityImpersonation
            2, // TokenImpersonation
            &mut token,
        );
        winapi::um::handleapi::CloseHandle(primary);
        if ok == 0 {
            let err = winapi::um::errhandlingapi::GetLastError();
            eprintln!("[escape_token_impersonate] DuplicateTokenEx failed err={err}");
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
        if status < 0 {
            eprintln!("[escape_token_impersonate] unexpected NT failure status=0x{:08x}", status as u32);
            std::process::exit(1);
        }
        eprintln!("[escape_token_impersonate] allowed: status=0x{:08x}", status as u32);
        std::process::exit(0);
    }
}
