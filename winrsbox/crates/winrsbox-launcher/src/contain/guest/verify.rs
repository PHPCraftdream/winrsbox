//! Post-`CreateProcessAsUserW` verification (task R04-1c, point 6): inspects
//! the REAL primary token of an actual (suspended) child process — never
//! trusts that `CreateProcessAsUserW` copied the handed-in token verbatim.

use anyhow::{Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeNameW, SE_PRIVILEGE_ENABLED, TOKEN_GROUPS,
    TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TokenGroups, TokenIntegrityLevel, TokenPrivileges,
    LUID_AND_ATTRIBUTES,
};

use super::{
    get_token_info_buf, sid_to_string, ADMINISTRATORS_SID_STR, SE_GROUP_ENABLED,
    SECURITY_MANDATORY_MEDIUM_RID,
};

/// Names of every privilege currently ENABLED on `token` (via
/// `LookupPrivilegeNameW`, same lookup convention as
/// `build::privileges_to_delete_except_change_notify`). Lookup failures for
/// an individual LUID are skipped rather than failing the whole call — a
/// name that cannot be resolved cannot meaningfully be reported either way,
/// and this is used by fail-closed verification callers that want the
/// concrete list of enabled names on error, not a hard stop mid-enumeration.
fn enabled_privilege_names(token: HANDLE) -> Result<Vec<String>> {
    let buf = get_token_info_buf(token, TokenPrivileges)?;
    // SAFETY: buf was filled by GetTokenInformation(TokenPrivileges).
    let tp: &TOKEN_PRIVILEGES = unsafe { &*(buf.as_ptr() as *const TOKEN_PRIVILEGES) };
    // SAFETY: Privileges is a variable-length array of PrivilegeCount
    // LUID_AND_ATTRIBUTES immediately following the header.
    let privs =
        unsafe { std::slice::from_raw_parts(tp.Privileges.as_ptr(), tp.PrivilegeCount as usize) };
    let mut names = Vec::new();
    for p in privs {
        if p.Attributes.0 & SE_PRIVILEGE_ENABLED.0 == 0 {
            continue;
        }
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
        if ok.is_ok() {
            names.push(String::from_utf16_lossy(&name_buf[..name_len as usize]));
        }
    }
    Ok(names)
}

/// `BUILTIN\Administrators` group attributes on `token`, if present at all:
/// `Some((enabled, deny_only))`. `None` means the SID is absent from
/// `TokenGroups` entirely (expected for a non-admin-derived token).
fn administrators_flags(token: HANDLE) -> Result<Option<(bool, bool)>> {
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
            const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;
            let deny_only = g.Attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0;
            return Ok(Some((enabled, deny_only)));
        }
    }
    Ok(None)
}

/// `token` must be opened from the child (`OpenProcessToken`, `TOKEN_QUERY`
/// is sufficient) — this function only reads it, never mutates it, and does
/// not close it (caller owns that handle).
///
/// `source_admin_enabled` is the value `build::administrators_state`
/// returned for the *source* token used to derive the guest token (captured
/// by the caller before the derived/child token existed) — it selects which
/// shape this child token is expected to have, mirroring
/// `build::build_guest_token`'s own branch: admin source → Administrators
/// present+deny-only+Medium integrity; non-admin source → no group/integrity
/// assertion beyond privileges.
///
/// Fails closed: any verification mismatch, or any error reading the
/// child's token information, is returned as `Err` — callers must treat that
/// as "do not resume this child" per the task's explicit no-silent-fallback
/// requirement.
pub fn verify_guest_token_shape(token: HANDLE, source_admin_enabled: bool) -> Result<()> {
    let enabled = enabled_privilege_names(token)
        .context("verify_guest_token_shape: failed to read child TokenPrivileges")?;
    anyhow::ensure!(
        enabled == vec!["SeChangeNotifyPrivilege".to_string()],
        "guest token verification FAILED: child process token has enabled privileges {enabled:?}, \
         expected exactly [\"SeChangeNotifyPrivilege\"] — refusing to resume"
    );

    if source_admin_enabled {
        match administrators_flags(token)
            .context("verify_guest_token_shape: failed to read child TokenGroups")?
        {
            Some((admin_enabled, admin_deny_only)) => {
                anyhow::ensure!(
                    !admin_enabled,
                    "guest token verification FAILED: Administrators is ENABLED on child \
                     process token — refusing to resume"
                );
                anyhow::ensure!(
                    admin_deny_only,
                    "guest token verification FAILED: Administrators present on child process \
                     token but not deny-only — refusing to resume"
                );
            }
            None => anyhow::bail!(
                "guest token verification FAILED: Administrators SID is entirely ABSENT from \
                 child process token (expected present-and-deny-only) — refusing to resume"
            ),
        }

        let buf = get_token_info_buf(token, TokenIntegrityLevel)
            .context("verify_guest_token_shape: failed to read child TokenIntegrityLevel")?;
        // SAFETY: buf was filled by GetTokenInformation(TokenIntegrityLevel).
        let tml: &TOKEN_MANDATORY_LABEL = unsafe { &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
        let sid = tml.Label.Sid;
        // SAFETY: sid is valid inside `buf`; last sub-authority is the RID.
        let rid = unsafe {
            let count = *windows::Win32::Security::GetSidSubAuthorityCount(sid);
            *windows::Win32::Security::GetSidSubAuthority(sid, (count - 1) as u32)
        };
        anyhow::ensure!(
            rid == SECURITY_MANDATORY_MEDIUM_RID,
            "guest token verification FAILED: child process integrity level RID=0x{rid:04X}, \
             expected Medium (0x{SECURITY_MANDATORY_MEDIUM_RID:04X}) — refusing to resume"
        );
    }

    Ok(())
}

/// Attempts to re-enable `priv_name` on `token` via `AdjustTokenPrivileges`.
/// Per Microsoft's documented quirk, `AdjustTokenPrivileges` can report
/// success (`Ok(())`) while `GetLastError()==ERROR_NOT_ALL_ASSIGNED` — so
/// this checks BOTH signals and returns `true` only if the privilege was
/// genuinely re-enabled (call succeeded AND no partial-failure error set).
/// Exposed at crate visibility so the acceptance test in `tests` below can
/// use it; also useful for any later caller that wants the same check.
#[allow(dead_code)] // only exercised from #[cfg(test)] today; kept pub(crate) for later reuse
pub(crate) fn try_reenable_privilege(token: HANDLE, priv_name: &str) -> Result<bool> {
    use windows::Win32::Security::LookupPrivilegeValueW;
    let mut name_wide: Vec<u16> = priv_name.encode_utf16().chain(Some(0)).collect();
    let mut luid = windows::Win32::Foundation::LUID::default();
    // SAFETY: name_wide is NUL-terminated; luid is a valid out-param.
    unsafe {
        LookupPrivilegeValueW(
            PCWSTR::null(),
            windows::core::PCWSTR(name_wide.as_mut_ptr()),
            &mut luid,
        )
    }
    .with_context(|| format!("LookupPrivilegeValueW({priv_name}) failed"))?;

    let new_state = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // SAFETY: SetLastError with a plain error-code value is always safe to call.
    unsafe { windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(0)) };
    // SAFETY: new_state is a valid single-entry TOKEN_PRIVILEGES.
    let call_result = unsafe {
        AdjustTokenPrivileges(
            token,
            false,
            Some(&new_state as *const TOKEN_PRIVILEGES),
            0,
            None,
            None,
        )
    };
    let last_err = unsafe { windows::Win32::Foundation::GetLastError() };
    const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;
    Ok(call_result.is_ok() && last_err.0 != ERROR_NOT_ALL_ASSIGNED)
}
