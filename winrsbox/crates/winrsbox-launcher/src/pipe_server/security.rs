use std::ffi::c_void;
use windows::core::PCWSTR;
use windows::Win32::{
    Foundation::{CloseHandle, HLOCAL, LocalFree, HANDLE},
    Security::{
        GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        TokenUser, TOKEN_QUERY, TOKEN_USER,
    },
    System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_ACCESS_RIGHTS,
        PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION,
    },
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
    // SAFETY: GetCurrentProcess returns a pseudo-handle, always a valid
    //         PROCESS_QUERY_LIMITED_INFORMATION-equivalent handle for
    //         OpenProcessToken.
    token_string_sid_for_process(unsafe { GetCurrentProcess() })
}

/// [`current_user_string_sid`]'s probe, generalized to an ALREADY-OPEN
/// process handle. MP-3's Attach authentication opens the connecting
/// process exactly once (PID-reuse race avoidance) and reuses that single
/// handle for every check, including the client's token SID — see
/// `authenticate_attach_client`.
pub(crate) fn token_string_sid_for_process(process: HANDLE) -> anyhow::Result<String> {
    // SAFETY: `process` must be a valid process handle with
    //         PROCESS_QUERY_LIMITED_INFORMATION access (caller's contract);
    //         TOKEN_QUERY is read-only.
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(process, TOKEN_QUERY, &mut token)
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

// ─── MP-3: Attach authentication ────────────────────────────────────────────

/// Access rights the broker requests on the connecting process for Attach
/// authentication — opened ONCE and reused for every check (create time,
/// job membership, SID, image path) and the post-attach exit wait, so a PID
/// recycled mid-check can never inherit a partially-completed decision:
/// PROCESS_QUERY_LIMITED_INFORMATION (create time / image path / token),
/// PROCESS_DUP_HANDLE (`DuplicateHandle` source for the folder job/section
/// handles), SYNCHRONIZE (`0x0010_0000` — a generic kernel-object right, not
/// exposed on `PROCESS_ACCESS_RIGHTS` by windows-0.61; raw bit, mirroring the
/// `PROCESS_ACCESS_RIGHTS(0x1000)` raw-literal pattern `pipe_server/mod.rs`
/// already uses for PROCESS_QUERY_LIMITED_INFORMATION) for the post-attach
/// exit wait that drives `remove_launcher`.
pub(crate) const ATTACH_CLIENT_ACCESS: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(
    PROCESS_QUERY_LIMITED_INFORMATION.0 | PROCESS_DUP_HANDLE.0 | 0x0010_0000,
);

/// Why an `Attach` request was rejected. Logged by the caller; never
/// disclosed to the connection itself — every path closes the connection.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AttachRejection {
    OpenFailed,
    PidMismatch,
    CreateTimeUnavailable,
    CreateTimeMismatch,
    InFolderJob,
    SidUnavailable,
    SidMismatch,
    ImagePathUnavailable,
    ImagePathMismatch,
}

impl std::fmt::Display for AttachRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OpenFailed => "client process unopenable",
            Self::PidMismatch => "launcher_pid != kernel client pid",
            Self::CreateTimeUnavailable => "client creation time unqueryable",
            Self::CreateTimeMismatch => "launcher_create_time mismatch (PID reused or spoofed)",
            Self::InFolderJob => "client is a member of the folder job (a guest, not a launcher)",
            Self::SidUnavailable => "client token SID unqueryable",
            Self::SidMismatch => "client SID != broker SID",
            Self::ImagePathUnavailable => "client image path unqueryable",
            Self::ImagePathMismatch => "client image != broker image",
        })
    }
}

/// Pure decision core: every kernel fact is injected, so the full rejection
/// matrix is unit-testable without a live job/process pair. `own_sid` /
/// `own_image_path` are the broker's own identity to compare the client
/// against; `own_image_path` is folded the same way `image_path` values are
/// folded elsewhere for comparison (S11, `crate::fold_published`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn authenticate_attach_impl(
    client_pid: u32,
    req_launcher_pid: u32,
    req_launcher_create_time: u64,
    live_create_time: Option<u64>,
    in_folder_job: bool,
    client_sid: Option<&str>,
    own_sid: &str,
    client_image_path: Option<&str>,
    own_image_path: &str,
) -> Result<(), AttachRejection> {
    if req_launcher_pid != client_pid {
        return Err(AttachRejection::PidMismatch);
    }
    let live_ct = live_create_time.ok_or(AttachRejection::CreateTimeUnavailable)?;
    if live_ct == 0 || live_ct != req_launcher_create_time {
        return Err(AttachRejection::CreateTimeMismatch);
    }
    if in_folder_job {
        return Err(AttachRejection::InFolderJob);
    }
    let sid = client_sid.ok_or(AttachRejection::SidUnavailable)?;
    if sid != own_sid {
        return Err(AttachRejection::SidMismatch);
    }
    let image = client_image_path.ok_or(AttachRejection::ImagePathUnavailable)?;
    if crate::fold_published(image) != crate::fold_published(own_image_path) {
        return Err(AttachRejection::ImagePathMismatch);
    }
    Ok(())
}

/// Production binding: opens the client process ONCE with
/// [`ATTACH_CLIENT_ACCESS`] and runs every check against that single handle
/// (task requirement: never re-open — a PID recycled between checks must
/// never inherit a partially-completed decision). On success returns the
/// STILL-OPEN handle — the caller now owns it, and reuses it next for
/// `DuplicateHandle` and the post-attach exit wait. On rejection the handle
/// (if one was opened) is closed here; the caller never sees it.
pub(crate) fn authenticate_attach_client(
    client_pid: u32,
    req_launcher_pid: u32,
    req_launcher_create_time: u64,
    folder_job: &winrsbox::contain::jobctl::FolderJob,
) -> Result<HANDLE, AttachRejection> {
    if client_pid == 0 {
        return Err(AttachRejection::OpenFailed);
    }
    // SAFETY: client_pid is a non-zero PID from GetNamedPipeClientProcessId
    //         (kernel-vouched); bInheritHandle=false.
    let h = unsafe { OpenProcess(ATTACH_CLIENT_ACCESS, false, client_pid) }
        .map_err(|_| AttachRejection::OpenFailed)?;

    let ct = super::ownership::process_create_time_from_handle(h);
    let live_create_time = if ct == 0 { None } else { Some(ct) };
    // Fail closed on an unqueryable job-membership result: treat "unknown"
    // as "assume guest" (reject), never as "assume launcher" (admit).
    let in_folder_job = folder_job.contains(h).unwrap_or(true);
    let client_sid = token_string_sid_for_process(h).ok();
    let own_sid = current_user_string_sid().unwrap_or_default();
    let client_image_path = super::ownership::image_path_from_handle(h);
    let own_image_path = std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    match authenticate_attach_impl(
        client_pid,
        req_launcher_pid,
        req_launcher_create_time,
        live_create_time,
        in_folder_job,
        client_sid.as_deref(),
        &own_sid,
        client_image_path.as_deref(),
        &own_image_path,
    ) {
        Ok(()) => Ok(h),
        Err(e) => {
            // SAFETY: h was opened by us immediately above and is closed
            //         exactly once here — the rejection path never returns it.
            unsafe { CloseHandle(h).ok() };
            Err(e)
        }
    }
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

    // ─── MP-3: authenticate_attach_impl (pure matrix) ─────────────────────

    mod attach_impl_tests {
        use super::super::{authenticate_attach_impl, AttachRejection};

        const PID: u32 = 111;
        const CT: u64 = 999;
        const SID: &str = "S-1-5-21-1-2-3-1000";
        const IMG: &str = r"c:\bin\winrsbox.exe";

        fn accept(
            client_pid: u32, req_pid: u32, req_ct: u64, live_ct: Option<u64>,
            in_job: bool, sid: Option<&str>, img: Option<&str>,
        ) -> Result<(), AttachRejection> {
            authenticate_attach_impl(client_pid, req_pid, req_ct, live_ct, in_job, sid, SID, img, IMG)
        }

        #[test]
        fn accepts_matching_identity() {
            assert_eq!(accept(PID, PID, CT, Some(CT), false, Some(SID), Some(IMG)), Ok(()));
        }

        #[test]
        fn rejects_pid_mismatch() {
            assert_eq!(
                accept(PID, PID + 1, CT, Some(CT), false, Some(SID), Some(IMG)),
                Err(AttachRejection::PidMismatch)
            );
        }

        #[test]
        fn rejects_unqueryable_create_time() {
            assert_eq!(
                accept(PID, PID, CT, None, false, Some(SID), Some(IMG)),
                Err(AttachRejection::CreateTimeUnavailable)
            );
        }

        #[test]
        fn rejects_create_time_mismatch() {
            assert_eq!(
                accept(PID, PID, CT, Some(CT + 1), false, Some(SID), Some(IMG)),
                Err(AttachRejection::CreateTimeMismatch)
            );
        }

        #[test]
        fn rejects_zero_live_create_time_even_if_it_matches_the_claim() {
            // A live creation time of zero must never be trusted, even
            // against a request that (implausibly) also claims zero — the
            // same "no wildcard zero" discipline as folder_section_trust_check.
            assert_eq!(
                accept(PID, PID, 0, Some(0), false, Some(SID), Some(IMG)),
                Err(AttachRejection::CreateTimeMismatch)
            );
        }

        #[test]
        fn rejects_when_client_is_in_the_folder_job() {
            // The plan's core distinction: a guest is always IN the folder
            // job, a launcher never is. This is checked even when every
            // other field matches — job membership overrides the rest.
            assert_eq!(
                accept(PID, PID, CT, Some(CT), true, Some(SID), Some(IMG)),
                Err(AttachRejection::InFolderJob)
            );
        }

        #[test]
        fn rejects_unqueryable_sid() {
            assert_eq!(
                accept(PID, PID, CT, Some(CT), false, None, Some(IMG)),
                Err(AttachRejection::SidUnavailable)
            );
        }

        #[test]
        fn rejects_sid_mismatch() {
            assert_eq!(
                accept(PID, PID, CT, Some(CT), false, Some("S-1-5-21-9-9-9-9999"), Some(IMG)),
                Err(AttachRejection::SidMismatch)
            );
        }

        #[test]
        fn rejects_unqueryable_image_path() {
            assert_eq!(
                accept(PID, PID, CT, Some(CT), false, Some(SID), None),
                Err(AttachRejection::ImagePathUnavailable)
            );
        }

        #[test]
        fn rejects_image_path_mismatch() {
            assert_eq!(
                accept(PID, PID, CT, Some(CT), false, Some(SID), Some(r"c:\bin\evil.exe")),
                Err(AttachRejection::ImagePathMismatch)
            );
        }

        #[test]
        fn image_path_comparison_is_case_insensitive() {
            // S11 fold: the same binary at a different case must still match.
            assert_eq!(
                accept(PID, PID, CT, Some(CT), false, Some(SID), Some(r"C:\BIN\WinRsBox.EXE")),
                Ok(())
            );
        }
    }

    // ─── MP-3: authenticate_attach_client (live kernel) ────────────────────

    mod attach_client_tests {
        use super::super::{authenticate_attach_client, AttachRejection};
        use std::os::windows::io::AsRawHandle;
        use std::os::windows::process::CommandExt;
        use std::process::{Child, Command};
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};
        use winrsbox::contain::jobctl::FolderJob;

        fn spawn_suspended() -> Child {
            // A real, live process with a different image (cmd.exe) than the
            // test binary — mirrors ownership.rs's mp4_folder_job_tests
            // pattern. CREATE_SUSPENDED so it stays alive until killed.
            Command::new("cmd")
                .args(["/C", "ping -n 3 127.0.0.1 >nul"])
                .creation_flags(CREATE_NO_WINDOW.0 | CREATE_SUSPENDED.0)
                .spawn()
                .expect("spawn suspended cmd child")
        }

        fn handle_of(child: &Child) -> HANDLE {
            HANDLE(child.as_raw_handle())
        }

        fn kill_and_reap(mut child: Child) {
            let _ = child.kill();
            let _ = child.wait();
        }

        fn own_create_time() -> u64 {
            super::super::super::ownership::query_process_create_time(std::process::id())
                .expect("own process creation time must be queryable")
        }

        /// Happy path: the test binary itself stands in for a joining
        /// launcher — same image, same SID (same process), not in any job,
        /// correct create_time.
        #[test]
        fn accepts_self_as_a_joining_launcher() {
            let job = FolderJob::create().expect("create folder job");
            let pid = std::process::id();
            let ct = own_create_time();
            let h = authenticate_attach_client(pid, pid, ct, &job)
                .expect("self must authenticate as a joining launcher");
            // SAFETY: h was returned by authenticate_attach_client above.
            unsafe { CloseHandle(h).ok() };
        }

        #[test]
        fn rejects_launcher_pid_not_matching_kernel_client_pid() {
            let job = FolderJob::create().expect("create folder job");
            let pid = std::process::id();
            let ct = own_create_time();
            assert_eq!(
                authenticate_attach_client(pid, pid + 1, ct, &job),
                Err(AttachRejection::PidMismatch)
            );
        }

        #[test]
        fn rejects_claimed_create_time_mismatch() {
            let job = FolderJob::create().expect("create folder job");
            let pid = std::process::id();
            assert_eq!(
                authenticate_attach_client(pid, pid, 0x1234, &job),
                Err(AttachRejection::CreateTimeMismatch)
            );
        }

        /// The distinguishing MP-3 check: a process that IS a member of the
        /// folder job (a guest) must be rejected even with every other field
        /// correct — job membership overrides identity.
        #[test]
        fn rejects_a_process_that_is_in_the_folder_job() {
            let job = FolderJob::create().expect("create folder job");
            let guest = spawn_suspended();
            let pid = guest.id();
            job.assign_process(handle_of(&guest)).expect("assign guest to folder job");
            let ct = super::super::super::ownership::process_create_time_from_handle(handle_of(&guest));

            assert_eq!(
                authenticate_attach_client(pid, pid, ct, &job),
                Err(AttachRejection::InFolderJob)
            );
            kill_and_reap(guest);
        }

        /// A different image (cmd.exe, not this test binary) fails the
        /// image-path check even outside the folder job.
        #[test]
        fn rejects_a_process_with_a_different_image() {
            let job = FolderJob::create().expect("create folder job");
            let other = spawn_suspended();
            let pid = other.id();
            let ct = super::super::super::ownership::process_create_time_from_handle(handle_of(&other));

            assert_eq!(
                authenticate_attach_client(pid, pid, ct, &job),
                Err(AttachRejection::ImagePathMismatch)
            );
            kill_and_reap(other);
        }

        #[test]
        fn rejects_dead_pid() {
            let job = FolderJob::create().expect("create folder job");
            let child = spawn_suspended();
            let pid = child.id();
            kill_and_reap(child);
            // On a busy machine the PID can be recycled by an unrelated
            // process in the window between reap and OpenProcess — the
            // kernel-truth check then still rejects, just via
            // CreateTimeMismatch (create_time=1 can never match a live
            // process) instead of OpenFailed. Either is a correct rejection
            // of the dead/reused identity; only "somehow accepted" is wrong.
            let err = authenticate_attach_client(pid, pid, 1, &job).unwrap_err();
            assert!(
                matches!(err, AttachRejection::OpenFailed | AttachRejection::CreateTimeMismatch),
                "got: {err:?}"
            );
        }

        #[test]
        fn rejects_zero_pid() {
            let job = FolderJob::create().expect("create folder job");
            assert_eq!(authenticate_attach_client(0, 0, 1, &job), Err(AttachRejection::OpenFailed));
        }
    }
}
