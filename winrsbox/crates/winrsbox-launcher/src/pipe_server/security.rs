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
    fn ConvertSidToStringSidW(sid: PSID, stringsid: *mut *mut u16) -> i32;

    /// Parses an SDDL string and returns a LocalAlloc'd
    /// PSECURITY_DESCRIPTOR. Returns 0 on failure.
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
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

/// Query the current process's user SID, format it as a string SID, and
/// build a security descriptor via SDDL that grants `GENERIC_READ |
/// GENERIC_WRITE` to that SID only. Everything else (including SYSTEM, other
/// users, and remote callers) is denied because we provide an explicit DACL
/// containing exactly one ACE.
///
/// SDDL layout: `D:P(A;;GRGW;;;<user_sid>)`
///   • `D:`     — DACL section
///   • `P`      — DACL_PROTECTED (no inheritance from any container)
///   • `(A;;GRGW;;;sid)` — Allow ACE granting GENERIC_READ + GENERIC_WRITE
///                        (covers everything a pipe client and server need:
///                        read/write data, attributes, EAs, SYNCHRONIZE).
///
/// Same-user different-session caveat: the user SID is identical across
/// logon sessions of the same Windows user, so an attacker process running
/// under the same user account in a different session WILL pass this DACL.
/// The Part 3 client-PID check rejects such attackers — the SDDL is the
/// first wall, the PID validation is the second.
pub(crate) fn build_pipe_security() -> anyhow::Result<PipeSecurity> {
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

    // ── 3. Build SDDL and convert to SECURITY_DESCRIPTOR (raw advapi32) ────
    let sddl = format!("D:P(A;;GRGW;;;{sid_str})");
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
