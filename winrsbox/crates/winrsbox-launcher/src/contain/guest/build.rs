//! `build_guest_token` and the helpers that construct the derived,
//! privilege-reduced token. See the module doc comment on `super` (`mod.rs`)
//! for the full privilege-removal and admin-handling rationale.

use anyhow::{Context, Result};
use std::ffi::c_void;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    AddAccessAllowedAce, CreateRestrictedToken, GetLengthSid, InitializeAcl,
    LookupPrivilegeNameW, SetTokenInformation, ACE_REVISION, ACL, CREATE_RESTRICTED_TOKEN_FLAGS,
    LUID_AND_ATTRIBUTES, PSID, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_NT_AUTHORITY, SID,
    SID_AND_ATTRIBUTES, TOKEN_DEFAULT_DACL, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_OWNER,
    TOKEN_PRIVILEGES, TOKEN_USER, TokenDefaultDacl, TokenGroups, TokenIntegrityLevel, TokenOwner,
    TokenPrivileges, TokenUser,
};

use super::{
    get_token_info_buf, sid_to_string, GuestToken, ADMINISTRATORS_SID_STR, SE_GROUP_ENABLED,
    SECURITY_MANDATORY_MEDIUM_RID,
};

const SE_GROUP_INTEGRITY_ENABLED: u32 = 0x0000_0020;
const ACL_REVISION: ACE_REVISION = ACE_REVISION(2);
/// GENERIC_ALL — matches the access mask R04-0's probe observed on every ACE
/// of the source token's `TokenDefaultDacl` (SYSTEM, user, Administrators).
const GENERIC_ALL: u32 = 0x1000_0000;

/// Copies the raw bytes of a SID (as returned by `GetTokenInformation`, i.e.
/// pointing into a short-lived buffer) into an owned, self-contained buffer.
fn copy_sid(sid: PSID) -> Result<Vec<u8>> {
    if sid.is_invalid() {
        anyhow::bail!("copy_sid: invalid SID");
    }
    // SAFETY: sid is caller-provided, checked non-null above.
    let len = unsafe { GetLengthSid(sid) };
    if len == 0 {
        anyhow::bail!("GetLengthSid returned 0");
    }
    // SAFETY: sid is valid for `len` bytes per GetLengthSid's contract.
    let bytes = unsafe { std::slice::from_raw_parts(sid.0 as *const u8, len as usize) };
    Ok(bytes.to_vec())
}

/// Every privilege currently present on `token` except `SeChangeNotifyPrivilege`,
/// as `LUID_AND_ATTRIBUTES` suitable for `CreateRestrictedToken`'s
/// `PrivilegesToDelete` list. Reads the real privilege set — does not
/// hardcode a fixed guess list, since it varies by account type.
///
/// `pub(super)` so the sibling `tests` submodule (same parent, `guest`) can
/// re-enumerate the source privileges for its acceptance assertions.
pub(super) fn privileges_to_delete_except_change_notify(
    token: HANDLE,
) -> Result<Vec<LUID_AND_ATTRIBUTES>> {
    let buf = get_token_info_buf(token, TokenPrivileges)?;
    // SAFETY: buf was filled by GetTokenInformation(TokenPrivileges).
    let tp: &TOKEN_PRIVILEGES = unsafe { &*(buf.as_ptr() as *const TOKEN_PRIVILEGES) };
    // SAFETY: Privileges is a variable-length array of PrivilegeCount
    // LUID_AND_ATTRIBUTES immediately following the header.
    let privs =
        unsafe { std::slice::from_raw_parts(tp.Privileges.as_ptr(), tp.PrivilegeCount as usize) };

    let mut to_delete = Vec::with_capacity(privs.len());
    for p in privs {
        let mut name_len: u32 = 256;
        let mut name_buf = vec![0u16; name_len as usize];
        // SAFETY: p.Luid is a valid LUID from the token; name_buf sized to name_len.
        let ok = unsafe {
            LookupPrivilegeNameW(
                PCWSTR::null(),
                &p.Luid,
                Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
                &mut name_len,
            )
        };
        let name = if ok.is_ok() {
            String::from_utf16_lossy(&name_buf[..name_len as usize])
        } else {
            String::new()
        };
        if name != "SeChangeNotifyPrivilege" {
            to_delete.push(LUID_AND_ATTRIBUTES {
                Luid: p.Luid,
                Attributes: windows::Win32::Security::TOKEN_PRIVILEGES_ATTRIBUTES(0),
            });
        }
    }
    Ok(to_delete)
}

/// Whether `BUILTIN\Administrators` (S-1-5-32-544) is present AND enabled
/// (not deny-only) in the source token's `TokenGroups` — the ground-truth
/// admin signal R04-0 established, not `TokenElevationType`. Returns the
/// SID's owned bytes when present (enabled or not) so callers can build a
/// `SidsToDisable` entry without re-querying.
///
/// `pub` (not module-private) so `sandbox::launch_suspended` (a different
/// crate target — the `winrsbox` bin, this module lives in the `winrsbox`
/// lib) can compute the same source-admin signal once, before calling
/// [`build_guest_token`], and pass it to [`super::verify_guest_token_shape`]
/// after launch without re-deriving admin state from a possibly-already-
/// restricted token.
pub fn administrators_state(token: HANDLE) -> Result<(bool, Option<Vec<u8>>)> {
    let buf = get_token_info_buf(token, TokenGroups)?;
    // SAFETY: buf was filled by GetTokenInformation(TokenGroups).
    let tg: &TOKEN_GROUPS = unsafe { &*(buf.as_ptr() as *const TOKEN_GROUPS) };
    // SAFETY: Groups is a variable-length array of GroupCount SID_AND_ATTRIBUTES.
    let groups =
        unsafe { std::slice::from_raw_parts(tg.Groups.as_ptr(), tg.GroupCount as usize) };
    for g in groups {
        let sid_str = sid_to_string(g.Sid).unwrap_or_default();
        if sid_str == ADMINISTRATORS_SID_STR {
            let enabled = g.Attributes & SE_GROUP_ENABLED != 0;
            let sid_bytes = copy_sid(g.Sid)?;
            return Ok((enabled, Some(sid_bytes)));
        }
    }
    Ok((false, None))
}

/// Owned bytes of the source token's `TokenUser` SID.
///
/// `pub(super)` so the sibling `tests` submodule can independently derive
/// the expected owner/trustee SID string for its assertions.
pub(super) fn token_user_sid_bytes(token: HANDLE) -> Result<Vec<u8>> {
    let buf = get_token_info_buf(token, TokenUser)?;
    // SAFETY: buf was filled by GetTokenInformation(TokenUser).
    let tu: &TOKEN_USER = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    copy_sid(tu.User.Sid)
}

/// Raw Medium mandatory-level SID (`S-1-16-8192`), laid out by hand: SID
/// layout with SubAuthorityCount=1 matches the `windows` crate's `SID`
/// struct exactly (its `SubAuthority` field is `[u32; 1]`), so a stack value
/// can be taken by pointer directly without an allocation.
fn medium_integrity_sid() -> SID {
    SID {
        Revision: 1,
        SubAuthorityCount: 1,
        IdentifierAuthority: SECURITY_MANDATORY_LABEL_AUTHORITY,
        SubAuthority: [SECURITY_MANDATORY_MEDIUM_RID],
    }
}

/// Raw `NT AUTHORITY\SYSTEM` SID (`S-1-5-18`), same one-subauthority layout trick.
fn system_sid() -> SID {
    SID {
        Revision: 1,
        SubAuthorityCount: 1,
        IdentifierAuthority: SECURITY_NT_AUTHORITY,
        SubAuthority: [18],
    }
}

/// Builds a raw DACL buffer granting `GENERIC_ALL` to each of `sids`, in the
/// `AddAccessAllowedAce` order given. Returns the owned buffer; the `ACL`
/// header lives at its start and remains valid as long as the buffer is
/// alive (callers must keep it alive across the `SetTokenInformation` call).
fn build_dacl(sids: &[PSID]) -> Result<Vec<u8>> {
    // Conservative fixed size: ACL header + per-ACE overhead + max SID size
    // (largest realistic SID here is well under 68 bytes) for each entry.
    let cap = 8 + sids.len() * 96;
    let mut buf = vec![0u8; cap];
    let acl_ptr = buf.as_mut_ptr() as *mut ACL;
    // SAFETY: buf is sized `cap` and appropriately aligned (Vec<u8> default
    // alignment is 1, but ACL's fields are all <=4-byte aligned integers and
    // InitializeAcl only requires the buffer to be DWORD-aligned per MSDN;
    // Vec<u8> allocations from the global allocator are at least pointer
    // (8-byte) aligned on this platform, which satisfies that).
    unsafe { InitializeAcl(acl_ptr, cap as u32, ACL_REVISION) }
        .context("InitializeAcl failed")?;
    for sid in sids {
        // SAFETY: acl_ptr initialized above; sid is a valid SID for the
        // duration of this call (owned by the caller's buffers).
        unsafe { AddAccessAllowedAce(acl_ptr, ACL_REVISION, GENERIC_ALL, *sid) }
            .context("AddAccessAllowedAce failed")?;
    }
    Ok(buf)
}

/// Builds a derived, privilege-reduced guest token from `source_token`
/// (borrowed — this function does not take ownership and does not close it).
///
/// See the module doc comment on `super` for the full privilege-removal and
/// admin-handling rationale.
pub fn build_guest_token(source_token: HANDLE) -> Result<GuestToken> {
    let privileges_to_delete = privileges_to_delete_except_change_notify(source_token)
        .context("failed to enumerate source token privileges")?;
    let (admin_enabled, admin_sid_bytes) = administrators_state(source_token)
        .context("failed to inspect source token Administrators state")?;
    let user_sid_bytes =
        token_user_sid_bytes(source_token).context("failed to read source TokenUser")?;

    // SidsToDisable must stay alive across the CreateRestrictedToken call.
    let sids_to_disable: Vec<SID_AND_ATTRIBUTES> = if admin_enabled {
        let bytes = admin_sid_bytes
            .as_ref()
            .expect("administrators_state returns Some(bytes) when enabled=true");
        vec![SID_AND_ATTRIBUTES {
            Sid: PSID(bytes.as_ptr() as *mut c_void),
            Attributes: 0,
        }]
    } else {
        Vec::new()
    };

    let mut new_token = HANDLE::default();
    // SAFETY: source_token is a valid, caller-owned token handle with at
    // least TOKEN_DUPLICATE|TOKEN_QUERY rights (contract on this function);
    // sids_to_disable/privileges_to_delete buffers are alive for this call;
    // no DISABLE_MAX_PRIVILEGE flag — deletion list is honored explicitly,
    // per this module's documented privilege-removal approach.
    unsafe {
        CreateRestrictedToken(
            source_token,
            CREATE_RESTRICTED_TOKEN_FLAGS(0),
            if sids_to_disable.is_empty() {
                None
            } else {
                Some(sids_to_disable.as_slice())
            },
            if privileges_to_delete.is_empty() {
                None
            } else {
                Some(privileges_to_delete.as_slice())
            },
            None,
            &mut new_token,
        )
    }
    .context("CreateRestrictedToken failed")?;

    let guest = GuestToken { handle: new_token };

    if admin_enabled {
        // Lower integrity to Medium explicitly (do not assume the source
        // was already Medium — a TokenElevationType=Full source would be High).
        let medium = medium_integrity_sid();
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: PSID(&medium as *const SID as *mut c_void),
                Attributes: SE_GROUP_INTEGRITY_ENABLED,
            },
        };
        // SAFETY: label is a valid, correctly sized TOKEN_MANDATORY_LABEL;
        // guest.handle has TOKEN_ADJUST_DEFAULT (implied by TOKEN_QUERY-only
        // handles from CreateRestrictedToken having all rights of source
        // minus none removed here — CreateRestrictedToken preserves the
        // access rights of the source handle).
        unsafe {
            SetTokenInformation(
                guest.handle(),
                TokenIntegrityLevel,
                &label as *const _ as *const c_void,
                std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32,
            )
        }
        .context("SetTokenInformation(TokenIntegrityLevel, Medium) failed")?;

        // TokenOwner := original TokenUser SID (preserved through
        // CreateRestrictedToken, but set explicitly per the plan).
        let owner = TOKEN_OWNER {
            Owner: PSID(user_sid_bytes.as_ptr() as *mut c_void),
        };
        // SAFETY: owner.Owner points into user_sid_bytes, alive for this call.
        unsafe {
            SetTokenInformation(
                guest.handle(),
                TokenOwner,
                &owner as *const _ as *const c_void,
                std::mem::size_of::<TOKEN_OWNER>() as u32,
            )
        }
        .context("SetTokenInformation(TokenOwner) failed")?;

        // TokenDefaultDacl := user SID + SYSTEM only (drop the
        // Administrators-group ACE the source token's default DACL carries).
        let sys = system_sid();
        let user_psid = PSID(user_sid_bytes.as_ptr() as *mut c_void);
        let sys_psid = PSID(&sys as *const SID as *mut c_void);
        let dacl_buf = build_dacl(&[user_psid, sys_psid])
            .context("failed to build restricted TokenDefaultDacl")?;
        let dacl = TOKEN_DEFAULT_DACL {
            DefaultDacl: dacl_buf.as_ptr() as *mut ACL,
        };
        // SAFETY: dacl.DefaultDacl points into dacl_buf, alive for this call.
        unsafe {
            SetTokenInformation(
                guest.handle(),
                TokenDefaultDacl,
                &dacl as *const _ as *const c_void,
                std::mem::size_of::<TOKEN_DEFAULT_DACL>() as u32,
            )
        }
        .context("SetTokenInformation(TokenDefaultDacl) failed")?;
    }

    Ok(guest)
}
