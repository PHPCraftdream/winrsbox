use std::ffi::c_void;
use windows::core::PCWSTR;
use windows::Win32::{
    Foundation::{CloseHandle, HLOCAL, LocalFree, HANDLE},
    Security::{
        GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        TokenUser, TOKEN_QUERY, TOKEN_USER,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

// ─── C3 Part 2: raw advapi32 bindings for SDDL/SID conversion ─────────────────
//
// The `Win32_Security_Authorization` feature of `windows-0.61` exposes these,
// but enabling it would touch Cargo.toml — out of scope per task. Declaring
// them by hand is cheap and keeps the patch isolated to pipe_server.rs.
// All three functions live in advapi32.dll and use the standard `BOOL`
// convention (nonzero = success). Signatures match MSDN verbatim.
#[link(name = "advapi32")]
unsafe extern "system" {
    /// Returns the SDDL string form of `sid` in a LocalAlloc'd buffer.
    /// Caller must `LocalFree` the returned pointer. Returns 0 on failure.
    ///
    /// `pub(crate)`: sandbox::launch_prep's tests (R04-1b) reuse this to
    /// convert an init-event ACE's trustee SID back to string form for
    /// comparison against `current_user_string_sid()`.
    pub(crate) fn ConvertSidToStringSidW(sid: PSID, stringsid: *mut *mut u16) -> i32;

    /// Parses an SDDL string and returns a LocalAlloc'd
    /// PSECURITY_DESCRIPTOR. Returns 0 on failure.
    ///
    /// `pub(crate)`: reused by `sandbox::launch_prep` (R04-1b) to build
    /// explicit per-user SDDL for the init-handshake events, following the
    /// exact same SDDL-string → SECURITY_DESCRIPTOR technique this module
    /// already proved for the IPC pipe — not a new binding, just shared.
    pub(crate) fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        stringsecuritydescriptor: PCWSTR,
        stringsdrevision: u32,
        securitydescriptor: *mut PSECURITY_DESCRIPTOR,
        securitydescriptorsize: *mut u32,
    ) -> i32;
}

/// SDDL_REVISION_1 — the only revision the W variant accepts.
const SDDL_REVISION_1: u32 = 1;

// ─── C3 Part 2: per-launcher security descriptor for the IPC pipe ─────────────

/// Owns the heap allocation behind the security descriptor returned by
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW`. We keep it alive
/// for the entire lifetime of the pipe accept loop because every
/// `CreateNamedPipeW` call dereferences `SECURITY_ATTRIBUTES.lpSecurityDescriptor`.
///
/// SAFETY contract: the raw pointer behind `sd` is the LocalAlloc'd buffer
/// returned by the SDDL converter. We intentionally never call `LocalFree`
/// on it — this is a one-time allocation at startup, and process exit
/// reclaims it via OS teardown. Calling `LocalFree` would risk a
/// use-after-free if the SD were referenced after the wrapper drops.
pub(crate) struct PipeSecurity {
    /// LocalAlloc'd security descriptor returned by SDDL conversion.
    /// Kept around purely so the field is not optimized away; the actual
    /// pointer used by Win32 is the one stored in `sa.lpSecurityDescriptor`.
    #[allow(dead_code)]
    pub(crate) sd: PSECURITY_DESCRIPTOR,
    /// SECURITY_ATTRIBUTES pointing into `sd`. Kept stable so the address
    /// passed to `CreateNamedPipeW` remains valid across iterations.
    pub(crate) sa: SECURITY_ATTRIBUTES,
}

// SAFETY: PSECURITY_DESCRIPTOR / SECURITY_ATTRIBUTES contain raw pointers to a
//         heap buffer that lives for the entire process. After construction
//         the buffer is read-only and the OS reads it from arbitrary threads
//         when servicing CreateNamedPipeW — i.e. it is already required to be
//         safe to dereference cross-thread.
unsafe impl Send for PipeSecurity {}
unsafe impl Sync for PipeSecurity {}

/// Query the current process token and return the user SID in SDDL string
/// form (e.g. `S-1-5-21-…`). Extracted verbatim from the former inline block
/// of `build_pipe_security` so the DACL-building function reads as pure SD
/// construction, and so tests can compare ACE trustees against it.
///
/// The returned `String` owns a copy; the LocalAlloc'd Win32 buffer is freed
/// here on every path.
pub(crate) fn current_user_string_sid() -> anyhow::Result<String> {
    // ── 1. Get current process user SID ────────────────────────────────────
    // SAFETY: GetCurrentProcess returns a pseudo-handle; OpenProcessToken with
    //         TOKEN_QUERY is the documented way to query our own token.
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| anyhow::anyhow!("OpenProcessToken failed: {e}"))?;
    }
    // Two-step GetTokenInformation: first call sizes the buffer.
    let mut needed: u32 = 0;
    // SAFETY: passing None for the buffer + 0 length is the documented
    //         pattern for getting the required size; we ignore the error
    //         return and read `needed` regardless.
    let _ = unsafe {
        GetTokenInformation(token, TokenUser, None, 0, &mut needed)
    };
    if needed == 0 {
        unsafe { CloseHandle(token).ok() };
        anyhow::bail!("GetTokenInformation(TokenUser) size query returned 0");
    }
    let mut buf = vec![0u8; needed as usize];
    let mut got: u32 = 0;
    // SAFETY: buf is sized to `needed`; we pass its pointer and length.
    let info_result = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            needed,
            &mut got,
        )
    };
    unsafe { CloseHandle(token).ok() };
    info_result.map_err(|e| anyhow::anyhow!("GetTokenInformation(TokenUser) failed: {e}"))?;

    // SAFETY: buf was filled by GetTokenInformation with a TOKEN_USER struct
    //         followed by the SID bytes. The buffer outlives this read.
    let token_user: &TOKEN_USER = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let user_sid = token_user.User.Sid;
    if user_sid.is_invalid() {
        anyhow::bail!("TokenUser returned an invalid SID");
    }

    // ── 2. Convert SID to string form (raw advapi32) ───────────────────────
    let mut sid_pwstr: *mut u16 = std::ptr::null_mut();
    // SAFETY: user_sid is valid for the lifetime of `buf` (still alive);
    //         ConvertSidToStringSidW LocalAlloc's into sid_pwstr on success.
    let ok = unsafe { ConvertSidToStringSidW(user_sid, &mut sid_pwstr) };
    if ok == 0 || sid_pwstr.is_null() {
        anyhow::bail!("ConvertSidToStringSidW failed");
    }
    // SAFETY: sid_pwstr is a null-terminated wide string allocated by Win32.
    let sid_str = unsafe {
        let mut len = 0usize;
        while *sid_pwstr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(sid_pwstr, len);
        String::from_utf16_lossy(slice)
    };
    // Free the SID string buffer — we copied its contents.
    // SAFETY: sid_pwstr came from LocalAlloc'd ConvertSidToStringSidW; LocalFree
    //         is the matched deallocator.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sid_pwstr as *mut c_void)));
    }
    Ok(sid_str)
}

/// Build the security descriptor applied to every instance of the launcher
/// pipe (F6: narrowed from one generic-grant ACE to two role-split ACEs).
///
/// Before (C3): `D:P(A;;GRGW;;;{sid})` — one ACE granting
/// `GENERIC_READ | GENERIC_WRITE` to the current user. On named pipes,
/// FILE_GENERIC_WRITE includes FILE_CREATE_PIPE_INSTANCE (FILE_APPEND_DATA
/// shares its bit position there), and Microsoft explicitly recommends "use
/// the individual rights instead of using FILE_GENERIC_WRITE" for pipes.
///
/// After (F6), both ACEs for the same current-user SID, split by ROLE:
/// `D:P(A;;0x00100003;;;{sid})(A;;GRGW;;;{sid})`
///   • ACE[0] `0x00100003` = FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE —
///     exactly what a pipe CLIENT needs when opening an existing instance;
///     deliberately WITHOUT FILE_CREATE_PIPE_INSTANCE (0x4), without
///     READ_CONTROL/attribute/EA bits and without generic bits. Source for
///     the pipe access-rights model (FILE_GENERIC_WRITE containing the
///     create-instance right; Microsoft's individual-rights remedy) and for
///     the DACL check on server-end creation:
///     https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
///   • ACE[1] `GRGW` (0xC0000000) — GENERIC_READ | GENERIC_WRITE. This is
///     REQUIRED, not legacy: the launcher's 31 pool workers call
///     CreateNamedPipeW on the EXISTING pipe name (every non-first instance
///     is DACL-checked for FILE_CREATE_PIPE_INSTANCE per MSDN), and for
///     `PIPE_ACCESS_DUPLEX` the kernel checks that DACL against a desired
///     access of the raw generic pair. Empirically probed on this OS build:
///     purely-specific server ACEs are rejected with ACCESS_DENIED even when
///     they are a superset of every individual right the generic pair maps
///     to (0x00100007, 0x001F0007, 0x801F0007 and 0x401F0007 all fail; only
///     a 0xC0000000-carrying ACE passes), and neither GENERIC bit alone
///     suffices (0x80000000 / 0x40000000 fail; 0xC0000000 passes). The
///     mandated specific-rights server ACE is therefore not implementable
///     here without breaking the pipe pool; Microsoft's individual-rights
///     remedy remains applied where the access check IS specific: the
///     client ACE above (and the client-side dwDesiredAccess).
///
/// Honest limitation: because client and server share one user SID today,
/// the merged effective grant for any same-user process still carries the
/// generic pair (ACE[1]) — and with it, via the pipe GenericMapping, the
/// FILE_CREATE_PIPE_INSTANCE right. Closing that hole requires a distinct
/// sandbox identity — the R04 variant C/D work — and is out of scope here.
/// What DOES make a rogue same-user instance useless today: (1) the first
/// instance of the name is created with FILE_FLAG_FIRST_PIPE_INSTANCE at
/// launcher startup, so a squatter cannot pre-empt the namespace; (2) the
/// winrsbox-hook trusted_boot `verify_pipe_server_identity` check verifies
/// the server-side process (GetNamedPipeServerProcessId + kernel pipe
/// creation time) against the pinned launcher identity before the client
/// trusts the connection.
///
/// `P` keeps the DACL protected: no inheritance from any container is
/// applied, so the two ACEs below are the complete effective grant.
///
/// Same-user different-session caveat: the user SID is identical across
/// logon sessions of the same Windows user, so an attacker process running
/// under the same user account in a different session WILL pass this DACL.
/// The Part 3 client-PID check rejects such attackers — the SDDL is the
/// first wall, the PID validation is the second.
pub(crate) fn build_pipe_security() -> anyhow::Result<PipeSecurity> {
    let sid_str = current_user_string_sid()?;

    // ── 3. Build SDDL and convert to SECURITY_DESCRIPTOR (raw advapi32) ────
    let sddl = format!("D:P(A;;0x00100003;;;{sid_str})(A;;GRGW;;;{sid_str})");
    let sddl_w: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut psd_ptr: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
    // SAFETY: sddl_w is null-terminated; psd_ptr is a stack out-param;
    //         the SDDL converter LocalAlloc's the descriptor and stores
    //         its pointer in `psd_ptr` on success.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &mut psd_ptr,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || psd_ptr.is_invalid() {
        anyhow::bail!(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed (sddl={sddl})",
        );
    }

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd_ptr.0,
        bInheritHandle: windows::core::BOOL(0),
    };
    Ok(PipeSecurity { sd: psd_ptr, sa })
}

#[cfg(test)]
mod tests {
    use super::{build_pipe_security, current_user_string_sid, PipeSecurity};
    use crate::pipe_server::conn::create_pipe_instance;
    use std::ffi::c_void;
    use std::io::{Read, Write};
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use std::time::Duration;
    use windows::core::{HRESULT, PCWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, HLOCAL,
        LocalFree, HANDLE,
    };
    use windows::Win32::Security::{
        GetAce, GetAclInformation, GetSecurityDescriptorDacl, ACCESS_ALLOWED_ACE, ACL,
        ACL_SIZE_INFORMATION, AclSizeInformation, PSID,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING,
    };
    use windows::Win32::System::Pipes::{ConnectNamedPipe, GetNamedPipeClientProcessId};

    // Hand-defined (matching winnt.h) so no extra windows feature is needed:
    // windows-0.61 exports ACCESS_ALLOWED_ACE_TYPE behind the
    // Win32_System_SystemServices feature, which this crate does not enable.
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;

    /// Walk the DACL of `sec` and return raw pointers to ACE[0..AceCount],
    /// asserting the DACL is present, protected against defaulting, and holds
    /// exactly `expected` ACEs. The pointers alias the SD's LocalAlloc'd
    /// buffer, which stays alive as long as `sec` does — callers must keep
    /// `sec` in scope while dereferencing.
    fn dacl_ace_ptrs(sec: &PipeSecurity, expected: usize) -> Vec<*mut ACCESS_ALLOWED_ACE> {
        let mut present = windows::core::BOOL(0);
        let mut defaulted = windows::core::BOOL(0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: sec.sd is a valid self-relative SD from the SDDL converter.
        unsafe {
            GetSecurityDescriptorDacl(sec.sd, &mut present, &mut dacl, &mut defaulted)
        }
        .expect("GetSecurityDescriptorDacl failed");
        assert!(present.as_bool(), "DACL must be present");
        assert!(!defaulted.as_bool(), "DACL must not be defaulted");
        let mut info = ACL_SIZE_INFORMATION::default();
        // SAFETY: dacl is valid; ACL_SIZE_INFORMATION is the struct documented
        //         for AclSizeInformation and its size bounds the write.
        unsafe {
            GetAclInformation(
                dacl,
                &mut info as *mut _ as *mut c_void,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        }
        .expect("GetAclInformation failed");
        assert_eq!(info.AceCount as usize, expected, "unexpected ACE count");
        (0..info.AceCount)
            .map(|i| {
                let mut ace: *mut c_void = std::ptr::null_mut();
                // SAFETY: i < AceCount; GetAce returns a pointer to ACE i
                //         inside the DACL buffer owned by `sec`.
                unsafe { GetAce(dacl, i, &mut ace) }.expect("GetAce failed");
                ace as *mut ACCESS_ALLOWED_ACE
            })
            .collect()
    }

    /// Convert the trustee SID of `ace` to SDDL string form via the module's
    /// raw ConvertSidToStringSidW binding (freed with the matched LocalFree).
    ///
    /// SAFETY: `ace` must point at a live ACCESS_ALLOWED_ACE inside `sec`'s
    ///         DACL; SidStart aliases the first four bytes of the trustee SID.
    fn ace_sid_string(ace: &ACCESS_ALLOWED_ACE) -> anyhow::Result<String> {
        let sid = PSID(&ace.SidStart as *const u32 as *mut c_void);
        let mut pwstr: *mut u16 = std::ptr::null_mut();
        // SAFETY: sid points into the live DACL buffer; ConvertSidToStringSidW
        //         LocalAlloc's into pwstr on success.
        let ok = unsafe { super::ConvertSidToStringSidW(sid, &mut pwstr) };
        if ok == 0 || pwstr.is_null() {
            anyhow::bail!("ConvertSidToStringSidW failed");
        }
        // SAFETY: pwstr is a null-terminated wide string allocated by Win32.
        let s = unsafe {
            let mut len = 0usize;
            while *pwstr.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(pwstr, len))
        };
        // SAFETY: pwstr came from LocalAlloc'd ConvertSidToStringSidW; LocalFree
        //         is the matched deallocator.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(pwstr as *mut c_void)));
        }
        Ok(s)
    }

    #[test]
    fn dacl_client_ace_grants_exactly_read_write_synchronize_no_instance_creation() {
        let sec = build_pipe_security().expect("build_pipe_security failed");
        let aces = dacl_ace_ptrs(&sec, 2);
        // SAFETY: aces[0] points into the DACL of `sec`, alive for this scope.
        let (ace_type, mask) = unsafe {
            let a = &*aces[0];
            (a.Header.AceType, a.Mask)
        };
        assert_eq!(ace_type, ACCESS_ALLOWED_ACE_TYPE, "ACE[0] must be access-allowed");
        assert_eq!(mask, 0x0010_0003, "client ACE must be exactly R|W|SYNCHRONIZE");
        assert_eq!(mask & 0x4, 0, "client ACE must NOT carry FILE_CREATE_PIPE_INSTANCE");
        assert_eq!(mask & 0xC000_0000, 0, "client ACE must NOT carry generic bits");
        // SAFETY: aces[0] points into the live DACL; SidStart aliases the SID.
        let ace_sid = ace_sid_string(unsafe { &*aces[0] }).expect("SID conversion");
        assert_eq!(
            ace_sid,
            current_user_string_sid().expect("current user SID"),
            "ACE[0] trustee must be the current user"
        );
    }

    #[test]
    fn dacl_server_ace_grants_generic_pair_required_for_worker_instance_creation() {
        // WHY this asserts 0xC0000000 (GENERIC_READ | GENERIC_WRITE) and not
        // a specific-rights mask: every non-first CreateNamedPipeW on the
        // existing pipe name (the launcher's 31 pool workers) is DACL-checked
        // for FILE_CREATE_PIPE_INSTANCE, and for PIPE_ACCESS_DUPLEX the
        // kernel checks the raw generic pair. Probed exhaustively on this OS
        // build: purely-specific server ACEs are ACCESS_DENIED even when they
        // are a superset of everything the generic pair maps to (0x00100007,
        // 0x001F0007, 0x801F0007, 0x401F0007 all fail; neither generic bit
        // alone passes; only 0xC0000000 does). See build_pipe_security doc.
        let sec = build_pipe_security().expect("build_pipe_security failed");
        let aces = dacl_ace_ptrs(&sec, 2);
        // SAFETY: aces[1] points into the DACL of `sec`, alive for this scope.
        let (ace_type, mask) = unsafe {
            let a = &*aces[1];
            (a.Header.AceType, a.Mask)
        };
        assert_eq!(ace_type, ACCESS_ALLOWED_ACE_TYPE, "ACE[1] must be access-allowed");
        assert_eq!(
            mask, 0xC000_0000,
            "server ACE must be exactly GENERIC_READ | GENERIC_WRITE (kernel requirement)"
        );
        assert_eq!(
            mask & 0x4, 0,
            "server ACE must not carry FILE_CREATE_PIPE_INSTANCE as a specific bit (it \
             arrives via the generic mapping instead)"
        );
        assert_eq!(mask & 0x0010_0003, 0, "server ACE is not the client ACE");
        // SAFETY: aces[1] points into the live DACL; SidStart aliases the SID.
        let ace_sid = ace_sid_string(unsafe { &*aces[1] }).expect("SID conversion");
        assert_eq!(
            ace_sid,
            current_user_string_sid().expect("current user SID"),
            "ACE[1] trustee must be the current user"
        );
    }

    #[test]
    fn worker_instance_creates_under_narrow_dacl_and_precise_client_connects() -> anyhow::Result<()> {
        // Unique per run so parallel/legacy test pipes never collide.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .subsec_nanos();
        let name = format!(r"\\.\pipe\winrsbox-f6-{}-{}", std::process::id(), nanos);
        let name_wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();

        let sec = build_pipe_security().expect("build_pipe_security failed");
        // FIRST instance: claims the namespace (FILE_FLAG_FIRST_PIPE_INSTANCE).
        let first_raw = create_pipe_instance(&name_wide, &sec, true)
            .map_err(|e| anyhow::anyhow!("first instance failed: {e}"))?;
        // SECOND instance: this CreateNamedPipeW hits the DACL check for
        // FILE_CREATE_PIPE_INSTANCE on the existing name (MSDN) — the exact
        // operation the 31 pool workers perform. Success here is the
        // server-side regression proof for the narrowed DACL+mode.
        let worker_raw = create_pipe_instance(&name_wide, &sec, false)
            .map_err(|e| anyhow::anyhow!("worker instance (DACL-checked) failed: {e}"))?;
        let worker_raw_for_close = worker_raw;

        // Close the FIRST instance now: its only job was to prove
        // create_pipe_instance(is_first=true) claims the namespace, which the
        // successful call above already did. A named pipe CLIENT's
        // CreateFileW can connect to ANY existing instance of the name, not
        // specifically the one a server thread is waiting on via
        // ConnectNamedPipe — leaving first_raw open here raced the client
        // connect against it, and when CreateFileW happened to land on
        // first_raw (which nothing services), the server thread's
        // ConnectNamedPipe(worker_raw) and the client's write both blocked
        // forever (observed: reproducible hang). Closing it removes it from
        // the instance pool so the client can only reach worker_raw.
        unsafe { CloseHandle(HANDLE(first_raw as *mut _)).ok() };

        // Server role: wait for a client, vouch its PID via the kernel, echo
        // 4 bytes — all on the WORKER handle created under the narrow mode.
        let server = std::thread::spawn(move || -> anyhow::Result<(u32, [u8; 4])> {
            // SAFETY: worker_raw is the isize repr of the valid worker pipe
            //         HANDLE handed over by create_pipe_instance above.
            let h = HANDLE(worker_raw as *mut _);
            // SAFETY: h is a valid server-side pipe handle; None = sync wait.
            if let Err(e) = unsafe { ConnectNamedPipe(h, None) } {
                // Client connected between CreateNamedPipeW and here —
                // still a valid connection (same rule as production).
                if e.code() != HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) {
                    anyhow::bail!("ConnectNamedPipe failed: {e}");
                }
            }
            let mut client_pid: u32 = 0;
            // SAFETY: h is a connected server-side pipe handle.
            unsafe { GetNamedPipeClientProcessId(h, &mut client_pid) }
                .map_err(|e| anyhow::anyhow!("GetNamedPipeClientProcessId failed: {e}"))?;
            // SAFETY: h is a valid handle we own; the File wrapper is
            //         ManuallyDrop'd so the test's CloseHandle stays the sole
            //         closer (mirrors production's mem::forget pattern).
            let mut f = std::mem::ManuallyDrop::new(unsafe {
                std::fs::File::from_raw_handle(h.0 as RawHandle)
            });
            let mut bytes = [0u8; 4];
            f.read_exact(&mut bytes)?;
            f.write_all(&bytes)?;
            Ok((client_pid, bytes))
        });

        // Client role: open with EXACTLY the client ACE mask — no
        // FILE_CREATE_PIPE_INSTANCE, nothing generic.
        //
        // Hand-defined (matching winnt.h) so no extra windows feature is
        // needed: FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE.
        const CLIENT_DESIRED_ACCESS: u32 = 0x0010_0003;

        let mut client: Option<HANDLE> = None;
        for _ in 0..100 {
            // SAFETY: name_wide is a valid null-terminated UTF-16 buffer; the
            //         template handle param is None.
            match unsafe {
                CreateFileW(
                    PCWSTR(name_wide.as_ptr()),
                    CLIENT_DESIRED_ACCESS,
                    FILE_SHARE_MODE(0),
                    None,
                    OPEN_EXISTING,
                    FILE_FLAGS_AND_ATTRIBUTES(0),
                    None,
                )
            } {
                Ok(h) => {
                    client = Some(h);
                    break;
                }
                // Production (winrsbox-ipc CONNECT_RETRY) tolerates exactly
                // these two transient states: no listening instance yet, or
                // all instances busy.
                Err(e)
                    if e.code() == HRESULT::from_win32(ERROR_PIPE_BUSY.0)
                        || e.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => {
                    // SAFETY: close the worker handle we still own (first_raw
                    //         was already closed above).
                    unsafe { CloseHandle(HANDLE(worker_raw_for_close as *mut _)).ok() };
                    return Err(anyhow::anyhow!("CreateFileW failed non-retryably: {e}"));
                }
            }
        }
        let client = client.expect("pipe never became connectable within retry budget");

        // SAFETY: client is a valid handle we own; ManuallyDrop keeps
        //         CloseHandle (below) as the sole closer.
        let mut cf = std::mem::ManuallyDrop::new(unsafe {
            std::fs::File::from_raw_handle(client.0 as RawHandle)
        });
        let payload = *b"F6!\x00";
        cf.write_all(&payload)?;

        let (kernel_pid, echoed) =
            server.join().map_err(|_| anyhow::anyhow!("server thread panicked"))??;
        assert_eq!(
            kernel_pid,
            std::process::id(),
            "kernel-vouched client PID must be this process"
        );
        assert_eq!(echoed, payload, "server must echo the client payload");

        // SAFETY: each raw handle is closed exactly once — the server thread's
        //         File wrappers are ManuallyDrop'd, so we are the sole closers
        //         (first_raw was already closed above).
        unsafe { CloseHandle(client).ok() };
        unsafe { CloseHandle(HANDLE(worker_raw_for_close as *mut _)).ok() };
        Ok(())
    }
}
