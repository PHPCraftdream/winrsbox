// R04 Этап 0 — observation-only probe of the launcher's own token / Job
// state. This module NEVER calls AdjustTokenPrivileges, SetSecurityDescriptor*
// or any other mutating Win32 API on a real system object. Every handle it
// opens is either the caller's own token (TOKEN_QUERY only) or a throwaway
// child process it creates and tears down itself.
//
// `winrsbox probe` prints the report to stdout. `winrsbox probe --spawn-child`
// additionally spawns a suspended `cmd.exe` child, inspects ITS primary
// token (children normally inherit the parent's token unless a different
// one was supplied to CreateProcess*), and terminates it before exiting —
// nothing is left running.

use anyhow::{Context, Result};
use std::ffi::c_void;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::{
    GetAce, GetAclInformation, GetTokenInformation, LookupAccountSidW, LookupPrivilegeNameW,
    AclSizeInformation, ACL_SIZE_INFORMATION, PSID, SE_PRIVILEGE_ENABLED, SID_NAME_USE,
    TOKEN_DEFAULT_DACL, TOKEN_ELEVATION, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_OWNER,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER, TokenDefaultDacl, TokenElevation,
    TokenElevationType, TokenGroups, TokenIntegrityLevel, TokenOwner, TokenPrivileges, TokenUser,
};

// Not exported by windows-0.61's `Win32_Security` feature surface used here
// (only the privilege-attribute flags are); values match winnt.h verbatim.
const SE_GROUP_ENABLED: u32 = 0x0000_0004;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;
use windows::Win32::System::JobObjects::{
    IsProcessInJob, JobObjectBasicUIRestrictions, QueryInformationJobObject,
    JOBOBJECT_BASIC_UI_RESTRICTIONS,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetCurrentProcess, OpenProcessToken, TerminateProcess, CREATE_SUSPENDED,
    PROCESS_INFORMATION, STARTUPINFOW,
};

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertSidToStringSidW(sid: PSID, stringsid: *mut *mut u16) -> i32;
}

fn sid_to_string(sid: PSID) -> Result<String> {
    if sid.is_invalid() {
        anyhow::bail!("invalid SID");
    }
    let mut pwstr: *mut u16 = std::ptr::null_mut();
    // SAFETY: sid is a caller-provided valid SID pointer (checked above);
    // ConvertSidToStringSidW LocalAlloc's into pwstr on success.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut pwstr) };
    if ok == 0 || pwstr.is_null() {
        anyhow::bail!("ConvertSidToStringSidW failed");
    }
    // SAFETY: pwstr is a NUL-terminated wide string from LocalAlloc.
    let s = unsafe {
        let mut len = 0usize;
        while *pwstr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(pwstr, len))
    };
    // SAFETY: pwstr came from LocalAlloc; LocalFree is the matched deallocator.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(pwstr as *mut c_void)));
    }
    Ok(s)
}

/// Best-effort human-readable name for a SID via LookupAccountSidW. Returns
/// `None` (not an error) when the SID has no resolvable account name, which
/// is normal for e.g. package/capability SIDs.
fn sid_account_name(sid: PSID) -> Option<String> {
    let mut name_len: u32 = 0;
    let mut domain_len: u32 = 0;
    let mut use_: SID_NAME_USE = SID_NAME_USE(0);
    // SAFETY: sizing call — None buffers, 0 lengths is the documented pattern.
    let _ = unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR::null()),
            &mut name_len,
            Some(PWSTR::null()),
            &mut domain_len,
            &mut use_,
        )
    };
    if name_len == 0 {
        return None;
    }
    let mut name_buf = vec![0u16; name_len as usize];
    let mut domain_buf = vec![0u16; domain_len.max(1) as usize];
    // SAFETY: buffers sized from the query above.
    let ok = unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain_buf.as_mut_ptr())),
            &mut domain_len,
            &mut use_,
        )
    };
    if ok.is_err() {
        return None;
    }
    let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);
    if domain.is_empty() {
        Some(name)
    } else {
        Some(format!("{domain}\\{name}"))
    }
}

/// Two-step GetTokenInformation into an owned buffer.
fn get_token_info_buf(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<Vec<u8>> {
    let mut needed: u32 = 0;
    // SAFETY: sizing call.
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut needed) };
    if needed == 0 {
        anyhow::bail!("GetTokenInformation({class:?}) size query returned 0");
    }
    let mut buf = vec![0u8; needed as usize];
    let mut got: u32 = 0;
    // SAFETY: buf sized to `needed`.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(buf.as_mut_ptr() as *mut _),
            needed,
            &mut got,
        )
    }
    .with_context(|| format!("GetTokenInformation({class:?}) failed"))?;
    Ok(buf)
}

fn integrity_label(rid: u32) -> &'static str {
    match rid {
        0x0000 => "Untrusted",
        0x1000 => "Low",
        0x2000 => "Medium",
        0x2100 => "Medium-Plus",
        0x3000 => "High",
        0x4000 => "System",
        0x5000 => "Protected",
        _ => "Unknown",
    }
}

fn elevation_type_name(t: i32) -> &'static str {
    match t {
        1 => "Default",
        2 => "Full",
        3 => "Limited",
        _ => "Unknown",
    }
}

/// Full report on one token handle. Read-only: only TOKEN_QUERY rights used.
fn report_token(label: &str, token: HANDLE) {
    println!("--- {label} ---");

    // TokenUser
    match get_token_info_buf(token, TokenUser) {
        Ok(buf) => {
            // SAFETY: buf was filled by GetTokenInformation(TokenUser) with a
            // TOKEN_USER struct followed by SID bytes; buf outlives this read.
            let tu: &TOKEN_USER = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
            let sid = tu.User.Sid;
            match sid_to_string(sid) {
                Ok(s) => {
                    let name = sid_account_name(sid).unwrap_or_else(|| "?".into());
                    println!("TokenUser: {s} ({name})");
                }
                Err(e) => println!("TokenUser: <error: {e}>"),
            }
        }
        Err(e) => println!("TokenUser: <error: {e}>"),
    }

    // TokenOwner
    match get_token_info_buf(token, TokenOwner) {
        Ok(buf) => {
            // SAFETY: buf was filled by GetTokenInformation(TokenOwner).
            let to: &TOKEN_OWNER = unsafe { &*(buf.as_ptr() as *const TOKEN_OWNER) };
            match sid_to_string(to.Owner) {
                Ok(s) => {
                    let name = sid_account_name(to.Owner).unwrap_or_else(|| "?".into());
                    println!("TokenOwner: {s} ({name})");
                }
                Err(e) => println!("TokenOwner: <error: {e}>"),
            }
        }
        Err(e) => println!("TokenOwner: <error: {e}>"),
    }

    // TokenIntegrityLevel
    match get_token_info_buf(token, TokenIntegrityLevel) {
        Ok(buf) => {
            // SAFETY: buf was filled by GetTokenInformation(TokenIntegrityLevel)
            // with a TOKEN_MANDATORY_LABEL (SID_AND_ATTRIBUTES) struct.
            let tml: &TOKEN_MANDATORY_LABEL =
                unsafe { &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
            let sid = tml.Label.Sid;
            // SAFETY: sid is a valid SID inside `buf`; last sub-authority is
            // the mandatory-level RID per Windows SID layout for Mandatory Label.
            let rid = unsafe {
                let count = *windows::Win32::Security::GetSidSubAuthorityCount(sid);
                if count == 0 {
                    0
                } else {
                    *windows::Win32::Security::GetSidSubAuthority(sid, (count - 1) as u32)
                }
            };
            println!(
                "TokenIntegrityLevel: RID=0x{rid:04x} ({})",
                integrity_label(rid)
            );
        }
        Err(e) => println!("TokenIntegrityLevel: <error: {e}>"),
    }

    // TokenElevation
    match get_token_info_buf(token, TokenElevation) {
        Ok(buf) => {
            // SAFETY: buf was filled by GetTokenInformation(TokenElevation).
            let te: &TOKEN_ELEVATION = unsafe { &*(buf.as_ptr() as *const TOKEN_ELEVATION) };
            println!("TokenElevation (IsElevated): {}", te.TokenIsElevated != 0);
        }
        Err(e) => println!("TokenElevation: <error: {e}>"),
    }

    // TokenElevationType
    match get_token_info_buf(token, TokenElevationType) {
        Ok(buf) => {
            // SAFETY: buf was filled by GetTokenInformation(TokenElevationType)
            // with a 4-byte TOKEN_ELEVATION_TYPE enum value.
            let t: i32 = unsafe { *(buf.as_ptr() as *const i32) };
            println!(
                "TokenElevationType: {} ({}) — NOTE: Default does not imply non-admin (UAC off / built-in Administrator case); ground truth below is the Administrators group state",
                t,
                elevation_type_name(t)
            );
        }
        Err(e) => println!("TokenElevationType: <error: {e}>"),
    }

    // TokenGroups
    match get_token_info_buf(token, TokenGroups) {
        Ok(buf) => {
            // SAFETY: buf was filled by GetTokenInformation(TokenGroups) with
            // a TOKEN_GROUPS struct (GroupCount, then GroupCount
            // SID_AND_ATTRIBUTES entries); buf outlives this read.
            let tg: &TOKEN_GROUPS = unsafe { &*(buf.as_ptr() as *const TOKEN_GROUPS) };
            println!("TokenGroups ({} entries):", tg.GroupCount);
            // SAFETY: Groups is a variable-length array of GroupCount
            // SID_AND_ATTRIBUTES immediately following the header, per the
            // documented TOKEN_GROUPS layout; buf is sized to hold all of them.
            let groups = unsafe {
                std::slice::from_raw_parts(tg.Groups.as_ptr(), tg.GroupCount as usize)
            };
            let mut admins_enabled = false;
            let mut admins_deny_only = false;
            for g in groups {
                let sid_str = sid_to_string(g.Sid).unwrap_or_else(|_| "<?>".into());
                let name = sid_account_name(g.Sid).unwrap_or_else(|| "?".into());
                let enabled = g.Attributes & SE_GROUP_ENABLED != 0;
                let deny_only = g.Attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0;
                println!(
                    "  {sid_str} ({name}) enabled={enabled} deny_only={deny_only} raw_attrs=0x{:08x}",
                    g.Attributes
                );
                if sid_str == "S-1-5-32-544" {
                    admins_enabled = enabled;
                    admins_deny_only = deny_only;
                }
            }
            println!(
                "  ground-truth Administrators(S-1-5-32-544): enabled={admins_enabled} deny_only={admins_deny_only}"
            );
        }
        Err(e) => println!("TokenGroups: <error: {e}>"),
    }

    // TokenPrivileges
    match get_token_info_buf(token, TokenPrivileges) {
        Ok(buf) => {
            // SAFETY: buf was filled by GetTokenInformation(TokenPrivileges)
            // with a TOKEN_PRIVILEGES struct (PrivilegeCount, then
            // PrivilegeCount LUID_AND_ATTRIBUTES entries).
            let tp: &TOKEN_PRIVILEGES = unsafe { &*(buf.as_ptr() as *const TOKEN_PRIVILEGES) };
            println!("TokenPrivileges ({} entries):", tp.PrivilegeCount);
            // SAFETY: Privileges is a variable-length array of
            // PrivilegeCount LUID_AND_ATTRIBUTES following the header.
            let privs = unsafe {
                std::slice::from_raw_parts(tp.Privileges.as_ptr(), tp.PrivilegeCount as usize)
            };
            for p in privs {
                let mut name_len: u32 = 256;
                let mut name_buf = vec![0u16; name_len as usize];
                // SAFETY: p.Luid is a valid LUID from the token; name_buf is
                // sized to name_len.
                let ok = unsafe {
                    LookupPrivilegeNameW(
                        PCWSTR::null(),
                        &p.Luid,
                        Some(PWSTR(name_buf.as_mut_ptr())),
                        &mut name_len,
                    )
                };
                let name = if ok.is_ok() {
                    String::from_utf16_lossy(&name_buf[..name_len as usize])
                } else {
                    format!("<LUID {}:{}>", p.Luid.HighPart, p.Luid.LowPart)
                };
                let enabled = p.Attributes.0 & SE_PRIVILEGE_ENABLED.0 != 0;
                println!("  {name} enabled={enabled} raw_attrs=0x{:08x}", p.Attributes.0);
            }
        }
        Err(e) => println!("TokenPrivileges: <error: {e}>"),
    }

    // TokenDefaultDacl
    match get_token_info_buf(token, TokenDefaultDacl) {
        Ok(buf) => {
            // SAFETY: buf was filled by GetTokenInformation(TokenDefaultDacl).
            let tdd: &TOKEN_DEFAULT_DACL =
                unsafe { &*(buf.as_ptr() as *const TOKEN_DEFAULT_DACL) };
            if tdd.DefaultDacl.is_null() {
                println!("TokenDefaultDacl: <null — no default DACL>");
            } else {
                let mut info = ACL_SIZE_INFORMATION::default();
                // SAFETY: DefaultDacl points into `buf`, alive for this scope.
                let sized = unsafe {
                    GetAclInformation(
                        tdd.DefaultDacl,
                        &mut info as *mut _ as *mut c_void,
                        std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                        AclSizeInformation,
                    )
                };
                if sized.is_err() {
                    println!("TokenDefaultDacl: <GetAclInformation failed>");
                } else {
                    println!("TokenDefaultDacl ({} ACEs):", info.AceCount);
                    for i in 0..info.AceCount {
                        let mut ace_ptr: *mut c_void = std::ptr::null_mut();
                        // SAFETY: i < AceCount; DefaultDacl is valid for this scope.
                        let got = unsafe { GetAce(tdd.DefaultDacl, i, &mut ace_ptr) };
                        if got.is_err() {
                            println!("  <GetAce failed for index {i}>");
                            continue;
                        }
                        // Every ACE type we expect here (ACCESS_ALLOWED/DENIED)
                        // starts with ACE_HEADER { AceType, AceFlags, AceSize }
                        // then a Mask: u32 then the SID — identical layout for
                        // the trustee SID offset regardless of allow/deny.
                        #[repr(C)]
                        struct RawAce {
                            ace_type: u8,
                            ace_flags: u8,
                            ace_size: u16,
                            mask: u32,
                            sid_start: u32,
                        }
                        // SAFETY: ace_ptr points at a live ACE inside `buf`.
                        let raw: &RawAce = unsafe { &*(ace_ptr as *const RawAce) };
                        let sid = PSID(&raw.sid_start as *const u32 as *mut c_void);
                        let sid_str = sid_to_string(sid).unwrap_or_else(|_| "<?>".into());
                        let name = sid_account_name(sid).unwrap_or_else(|| "?".into());
                        println!(
                            "  type={} trustee={sid_str} ({name}) mask=0x{:08x}",
                            raw.ace_type, raw.mask
                        );
                    }
                }
            }
        }
        Err(e) => println!("TokenDefaultDacl: <error: {e}>"),
    }
}

/// Job membership + (if we can obtain a queryable handle) the actual UI mask.
fn report_job(process: HANDLE) {
    let mut in_job = windows::core::BOOL(0);
    // SAFETY: process is a valid process handle (current process or a child
    // we created); None job handle means "test membership in any job".
    let ok = unsafe { IsProcessInJob(process, None, &mut in_job) };
    if ok.is_err() {
        println!("IsProcessInJob: <error: {:?}>", ok.err());
        return;
    }
    println!("IsProcessInJob: {}", in_job.as_bool());
    if !in_job.as_bool() {
        return;
    }
    // QueryInformationJobObject accepts a NULL job handle meaning "the job
    // associated with the calling process" per MSDN. This only works when
    // `process` IS the calling process; for a spawned child we have no
    // queryable handle (we never assigned it to a job ourselves), so skip.
    let is_self = process == unsafe { GetCurrentProcess() };
    if !is_self {
        println!("JobObjectBasicUIRestrictions: <n/a — no job handle for child process>");
        return;
    }
    let mut restr = JOBOBJECT_BASIC_UI_RESTRICTIONS::default();
    let mut returned: u32 = 0;
    // SAFETY: None hJob = current process's job per documented behavior;
    // restr is sized correctly for JobObjectBasicUIRestrictions.
    let res = unsafe {
        QueryInformationJobObject(
            None,
            JobObjectBasicUIRestrictions,
            &mut restr as *mut _ as *mut c_void,
            std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            Some(&mut returned),
        )
    };
    match res {
        Ok(()) => {
            let mask = restr.UIRestrictionsClass.0;
            println!("JobObjectBasicUIRestrictions: mask=0x{mask:02x}");
            const FLAGS: &[(u32, &str)] = &[
                (0x01, "HANDLES"),
                (0x02, "READCLIPBOARD"),
                (0x04, "WRITECLIPBOARD"),
                (0x08, "SYSTEMPARAMS"),
                (0x10, "DISPLAYSETTINGS"),
                (0x20, "GLOBALATOMS"),
                (0x40, "DESKTOP"),
                (0x80, "EXITWINDOWS"),
            ];
            for (bit, name) in FLAGS {
                println!("    {name} (0x{bit:02x}): {}", mask & bit != 0);
            }
        }
        Err(e) => println!("JobObjectBasicUIRestrictions: <error: {e}>"),
    }
}

/// Open the current process's own primary token with TOKEN_QUERY only.
fn open_own_token() -> Result<HANDLE> {
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess is a pseudo-handle; TOKEN_QUERY is read-only.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .context("OpenProcessToken(current process) failed")?;
    Ok(token)
}

/// Spawn a throwaway suspended `cmd.exe /c exit` child (observation only),
/// inspect its primary token + job membership, then terminate and close all
/// handles. Nothing is left running.
fn probe_child() -> Result<()> {
    let cmdline = "cmd.exe /c exit";
    let mut cmdline_wide: Vec<u16> = cmdline.encode_utf16().chain(Some(0)).collect();
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: cmdline_wide is a mutable NUL-terminated buffer as required by
    // CreateProcessW; si/pi are stack out-params of the correct type.
    let create_result = unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(PWSTR(cmdline_wide.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            PCWSTR::null(),
            &si,
            &mut pi,
        )
    };
    if let Err(e) = create_result {
        println!("probe_child: CreateProcessW failed: {e}");
        return Ok(());
    }

    // SAFETY: pi.hProcess is a valid, just-created suspended process handle.
    let token_result = (|| -> Result<HANDLE> {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(pi.hProcess, TOKEN_QUERY, &mut token) }
            .context("OpenProcessToken(child) failed")?;
        Ok(token)
    })();

    match token_result {
        Ok(child_token) => {
            report_token("child (suspended cmd.exe, primary token)", child_token);
            // SAFETY: child_token was opened by us above.
            unsafe { CloseHandle(child_token).ok() };
        }
        Err(e) => println!("child token: <error: {e}>"),
    }
    println!("--- child Job membership ---");
    report_job(pi.hProcess);

    // Cleanup: never resume the child into real execution — terminate the
    // suspended process directly, then close both handles. `ResumeThread` is
    // deliberately NOT called; the process never runs a single instruction.
    // SAFETY: pi.hProcess is our own just-created handle.
    unsafe {
        let _ = TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread).ok();
        CloseHandle(pi.hProcess).ok();
    }
    Ok(())
}

pub fn run(args: &[String]) -> Result<()> {
    println!("winrsbox probe — R04 Этап 0 token/Job observation (read-only)");
    println!("================================================================");

    let token = open_own_token()?;
    report_token("current process (self)", token);
    // SAFETY: token was opened by us above via TOKEN_QUERY.
    unsafe { CloseHandle(token).ok() };

    println!("--- current process Job membership ---");
    // SAFETY: GetCurrentProcess returns a valid pseudo-handle.
    report_job(unsafe { GetCurrentProcess() });

    if args.iter().any(|a| a == "--spawn-child") {
        println!();
        probe_child()?;
    }

    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Deliverable 2: does a Win32 object created with SECURITY_ATTRIBUTES =
    //! NULL end up owned by the specific user SID, or by the Administrators
    //! GROUP? This determines whether a later stage that makes Administrators
    //! deny-only in the guest token would break the guest's ability to reopen
    //! same-name objects it needs (named events in launch_prep.rs, init_ack.rs).
    //!
    //! Observation-only: creates one throwaway named kernel event with
    //! default security, inspects it via GetSecurityInfo (read-only), closes
    //! it. Nothing else on the system is touched; the object disappears the
    //! moment the last handle (ours) closes.
    use super::*;
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION};
    use windows::Win32::System::Threading::CreateEventW;

    #[test]
    fn default_security_object_owner_and_dacl() {
        // Unique name so parallel test runs / stray leftovers never collide.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("Local\\winrsbox-r04-probe-{}-{nanos}", std::process::id());
        let name_wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();

        // SAFETY: lpEventAttributes=None means default security descriptor
        // (the exact case launch_prep.rs / init_ack.rs use for their named
        // events); name_wide is NUL-terminated.
        let event = unsafe {
            CreateEventW(None, false, false, PCWSTR(name_wide.as_ptr()))
        }
        .expect("CreateEventW(default security) failed");

        let mut owner_sid = PSID::default();
        let mut dacl_ptr: *mut ACL = std::ptr::null_mut();
        // SAFETY: event is the just-created valid handle; owner_sid/dacl_ptr
        // are stack out-params; GetSecurityInfo with no group/sacl/psd
        // out-params (None) is documented as valid — only owner+dacl queried.
        let err = unsafe {
            GetSecurityInfo(
                event,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut owner_sid),
                None,
                Some(&mut dacl_ptr),
                None,
                None,
            )
        };
        assert_eq!(err.0, 0, "GetSecurityInfo failed: WIN32_ERROR({})", err.0);

        let owner_str = sid_to_string(owner_sid).expect("owner SID -> string");
        let owner_name = sid_account_name(owner_sid).unwrap_or_else(|| "?".into());
        println!("[R04 D2] default-security event owner: {owner_str} ({owner_name})");

        // Ground truth this test exists to establish: is the owner the
        // CURRENT USER SID, or the Administrators GROUP SID (S-1-5-32-544)?
        let is_admins_group = owner_str == "S-1-5-32-544";
        println!(
            "[R04 D2] owner is BUILTIN\\Administrators group: {is_admins_group} \
             (S-1-5-21-...-1001 = the specific user SID)"
        );

        if !dacl_ptr.is_null() {
            let mut info = ACL_SIZE_INFORMATION::default();
            // SAFETY: dacl_ptr came from GetSecurityInfo above, valid for
            // the lifetime of the underlying SD buffer (freed via LocalFree
            // is NOT required here per MSDN: GetSecurityInfo's returned DACL
            // pointer is only valid while no ppSecurityDescriptor was also
            // requested to be freed — we did not request one, and per MSDN
            // "the SACL, DACL, owner, or primary group... in a single
            // allocated block" reachable via a psecuritydescriptor we did
            // NOT ask for; to avoid a leak-vs-double-free footgun we simply
            // do not free anything here — this is a one-shot diagnostic
            // test process, not long-running production code.
            let sized = unsafe {
                GetAclInformation(
                    dacl_ptr,
                    &mut info as *mut _ as *mut c_void,
                    std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            };
            if sized.is_ok() {
                println!("[R04 D2] default-security event DACL ACE count: {}", info.AceCount);
                for i in 0..info.AceCount {
                    let mut ace_ptr: *mut c_void = std::ptr::null_mut();
                    // SAFETY: i < AceCount; dacl_ptr valid for this scope.
                    if unsafe { GetAce(dacl_ptr, i, &mut ace_ptr) }.is_err() {
                        continue;
                    }
                    #[repr(C)]
                    struct RawAce {
                        ace_type: u8,
                        ace_flags: u8,
                        ace_size: u16,
                        mask: u32,
                        sid_start: u32,
                    }
                    // SAFETY: ace_ptr points at a live ACE inside the DACL.
                    let raw: &RawAce = unsafe { &*(ace_ptr as *const RawAce) };
                    let sid = PSID(&raw.sid_start as *const u32 as *mut c_void);
                    let sid_str = sid_to_string(sid).unwrap_or_else(|_| "<?>".into());
                    let name = sid_account_name(sid).unwrap_or_else(|| "?".into());
                    println!(
                        "[R04 D2]   ACE type={} trustee={sid_str} ({name}) mask=0x{:08x}",
                        raw.ace_type, raw.mask
                    );
                }
            }
        } else {
            println!("[R04 D2] default-security event has NO DACL (NULL DACL = everyone full access)");
        }

        // SAFETY: event is our own just-created handle; this both proves the
        // handle is closeable and, since we hold the only reference to this
        // uniquely-named object, causes the OS to destroy the object
        // immediately — nothing is left behind.
        unsafe { CloseHandle(event).ok() };
    }
}
