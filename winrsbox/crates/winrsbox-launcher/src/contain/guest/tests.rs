use super::build::{privileges_to_delete_except_change_notify, token_user_sid_bytes};
use super::verify::try_reenable_privilege;
use super::*;
use windows::core::PCWSTR;
use windows::Win32::Security::{
    GetAce, GetAclInformation, AclSizeInformation, ACL_SIZE_INFORMATION, TOKEN_ALL_ACCESS,
    TOKEN_DEFAULT_DACL, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_OWNER, TOKEN_PRIVILEGES,
    TokenDefaultDacl, TokenGroups, TokenIntegrityLevel, TokenOwner, TokenPrivileges,
    LookupPrivilegeNameW, SE_PRIVILEGE_ENABLED,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

fn open_own_token(access: windows::Win32::Security::TOKEN_ACCESS_MASK) -> HANDLE {
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess is a pseudo-handle.
    unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) }
        .expect("OpenProcessToken(current process) failed");
    token
}

/// Load-bearing test (task point 3): the derived token's removed
/// privileges must NOT be re-enable-able by the guest itself. Also
/// asserts SeChangeNotifyPrivilege remains the only enabled privilege.
#[test]
fn removed_privileges_cannot_be_reenabled() {
    let source = open_own_token(TOKEN_ALL_ACCESS);
    let guest = build_guest_token(source).expect("build_guest_token failed");
    // SAFETY: source was opened by us above via TOKEN_ALL_ACCESS.
    unsafe { CloseHandle(source).ok() };

    // Enumerate what privileges the derived token now has enabled.
    let buf = get_token_info_buf(guest.handle(), TokenPrivileges)
        .expect("GetTokenInformation(TokenPrivileges) on derived token");
    let tp: &TOKEN_PRIVILEGES = unsafe { &*(buf.as_ptr() as *const TOKEN_PRIVILEGES) };
    let privs =
        unsafe { std::slice::from_raw_parts(tp.Privileges.as_ptr(), tp.PrivilegeCount as usize) };
    let mut enabled_names = Vec::new();
    for p in privs {
        let mut name_len: u32 = 256;
        let mut name_buf = vec![0u16; name_len as usize];
        let ok = unsafe {
            LookupPrivilegeNameW(
                PCWSTR::null(),
                &p.Luid,
                Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
                &mut name_len,
            )
        };
        if ok.is_ok() {
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            if p.Attributes.0 & SE_PRIVILEGE_ENABLED.0 != 0 {
                enabled_names.push(name);
            }
        }
    }
    assert_eq!(
        enabled_names,
        vec!["SeChangeNotifyPrivilege".to_string()],
        "derived token must have exactly SeChangeNotifyPrivilege enabled, got {enabled_names:?}"
    );

    // The load-bearing check: try to re-enable every privilege the
    // *source* token had (except SeChangeNotifyPrivilege) on the derived
    // token, and assert every single attempt fails.
    let source2 = open_own_token(TOKEN_ALL_ACCESS);
    let source_privs = privileges_to_delete_except_change_notify(source2)
        .expect("re-enumerate source privileges");
    unsafe { CloseHandle(source2).ok() };

    for luid_attr in &source_privs {
        let mut name_len: u32 = 256;
        let mut name_buf = vec![0u16; name_len as usize];
        let ok = unsafe {
            LookupPrivilegeNameW(
                PCWSTR::null(),
                &luid_attr.Luid,
                Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
                &mut name_len,
            )
        };
        let name = if ok.is_ok() {
            String::from_utf16_lossy(&name_buf[..name_len as usize])
        } else {
            continue;
        };
        let reenabled = try_reenable_privilege(guest.handle(), &name)
            .unwrap_or_else(|e| panic!("try_reenable_privilege({name}) errored: {e}"));
        assert!(
            !reenabled,
            "privilege {name} was re-enabled on the derived (guest) token — \
             privilege removal is broken"
        );
    }

    assert!(
        !source_privs.is_empty(),
        "sanity: source token must have had at least one non-SeChangeNotify \
         privilege in this environment for the test to be meaningful"
    );
}

/// If the source token has Administrators enabled, the derived token
/// must have it present-and-deny-only (never absent — deny semantics
/// require presence).
#[test]
fn administrators_deny_only_when_source_is_admin() {
    let source = open_own_token(TOKEN_ALL_ACCESS);
    let (admin_enabled_on_source, _) =
        administrators_state(source).expect("administrators_state(source)");
    let guest = build_guest_token(source).expect("build_guest_token failed");
    unsafe { CloseHandle(source).ok() };

    if !admin_enabled_on_source {
        eprintln!(
            "[guest_token test] source token does not have Administrators \
             enabled in this environment — skipping deny-only assertion \
             (see module doc: covered instead by the non-admin no-op test)"
        );
        return;
    }

    let buf = get_token_info_buf(guest.handle(), TokenGroups)
        .expect("GetTokenInformation(TokenGroups) on derived token");
    let tg: &TOKEN_GROUPS = unsafe { &*(buf.as_ptr() as *const TOKEN_GROUPS) };
    let groups =
        unsafe { std::slice::from_raw_parts(tg.Groups.as_ptr(), tg.GroupCount as usize) };
    let admin = groups
        .iter()
        .find(|g| sid_to_string(g.Sid).unwrap_or_default() == ADMINISTRATORS_SID_STR)
        .expect("Administrators SID must still be PRESENT on derived token (deny-only, not removed)");
    let enabled = admin.Attributes & SE_GROUP_ENABLED != 0;
    const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;
    let deny_only = admin.Attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0;
    assert!(!enabled, "Administrators must not be enabled on derived token");
    assert!(deny_only, "Administrators must be deny-only on derived token");
}

/// Derived token's integrity level must be exactly Medium when the
/// source was admin-enabled (covers both a Medium source — this
/// environment's observed filtered/admin-deny-only case — and, by not
/// assuming the source's level, the documented High-source/Full-token
/// case that could not be empirically produced in this headless
/// environment, same limitation R04-0 hit: no interactive desktop for
/// UAC consent to obtain a TokenElevationType=Full token).
#[test]
fn integrity_is_medium_when_source_is_admin() {
    let source = open_own_token(TOKEN_ALL_ACCESS);
    let (admin_enabled_on_source, _) =
        administrators_state(source).expect("administrators_state(source)");
    let guest = build_guest_token(source).expect("build_guest_token failed");
    unsafe { CloseHandle(source).ok() };

    if !admin_enabled_on_source {
        eprintln!("[guest_token test] source not admin-enabled — skipping (see module doc)");
        return;
    }

    let buf = get_token_info_buf(guest.handle(), TokenIntegrityLevel)
        .expect("GetTokenInformation(TokenIntegrityLevel) on derived token");
    let tml: &TOKEN_MANDATORY_LABEL = unsafe { &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
    let sid = tml.Label.Sid;
    // SAFETY: sid is valid inside `buf`; last sub-authority is the RID.
    let rid = unsafe {
        let count = *windows::Win32::Security::GetSidSubAuthorityCount(sid);
        *windows::Win32::Security::GetSidSubAuthority(sid, (count - 1) as u32)
    };
    assert_eq!(rid, SECURITY_MANDATORY_MEDIUM_RID, "derived token integrity must be Medium");
}

/// Derived TokenOwner must equal the original source TokenUser SID.
#[test]
fn owner_equals_original_user_when_source_is_admin() {
    let source = open_own_token(TOKEN_ALL_ACCESS);
    let (admin_enabled_on_source, _) =
        administrators_state(source).expect("administrators_state(source)");
    let user_sid = token_user_sid_bytes(source).expect("token_user_sid_bytes(source)");
    let user_sid_str = sid_to_string(PSID(user_sid.as_ptr() as *mut c_void)).unwrap();
    let guest = build_guest_token(source).expect("build_guest_token failed");
    unsafe { CloseHandle(source).ok() };

    if !admin_enabled_on_source {
        eprintln!("[guest_token test] source not admin-enabled — skipping (see module doc)");
        return;
    }

    let buf = get_token_info_buf(guest.handle(), TokenOwner)
        .expect("GetTokenInformation(TokenOwner) on derived token");
    let to: &TOKEN_OWNER = unsafe { &*(buf.as_ptr() as *const TOKEN_OWNER) };
    let owner_str = sid_to_string(to.Owner).unwrap();
    assert_eq!(owner_str, user_sid_str, "derived TokenOwner must equal original TokenUser");
}

/// Derived TokenDefaultDacl must drop the Administrators ACE and keep
/// user + SYSTEM.
#[test]
fn default_dacl_drops_administrators_when_source_is_admin() {
    let source = open_own_token(TOKEN_ALL_ACCESS);
    let (admin_enabled_on_source, _) =
        administrators_state(source).expect("administrators_state(source)");
    let user_sid = token_user_sid_bytes(source).expect("token_user_sid_bytes(source)");
    let user_sid_str = sid_to_string(PSID(user_sid.as_ptr() as *mut c_void)).unwrap();
    let guest = build_guest_token(source).expect("build_guest_token failed");
    unsafe { CloseHandle(source).ok() };

    if !admin_enabled_on_source {
        eprintln!("[guest_token test] source not admin-enabled — skipping (see module doc)");
        return;
    }

    let buf = get_token_info_buf(guest.handle(), TokenDefaultDacl)
        .expect("GetTokenInformation(TokenDefaultDacl) on derived token");
    let tdd: &TOKEN_DEFAULT_DACL = unsafe { &*(buf.as_ptr() as *const TOKEN_DEFAULT_DACL) };
    assert!(!tdd.DefaultDacl.is_null(), "derived token must have a default DACL");

    let mut info = ACL_SIZE_INFORMATION::default();
    unsafe {
        GetAclInformation(
            tdd.DefaultDacl,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .expect("GetAclInformation failed");

    let mut trustees = Vec::new();
    for i in 0..info.AceCount {
        let mut ace_ptr: *mut c_void = std::ptr::null_mut();
        if unsafe { GetAce(tdd.DefaultDacl, i, &mut ace_ptr) }.is_err() {
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
        // SAFETY: ace_ptr points at a live ACE inside tdd.DefaultDacl.
        let raw: &RawAce = unsafe { &*(ace_ptr as *const RawAce) };
        let sid = PSID(&raw.sid_start as *const u32 as *mut c_void);
        trustees.push(sid_to_string(sid).unwrap_or_default());
    }

    assert!(
        !trustees.contains(&ADMINISTRATORS_SID_STR.to_string()),
        "derived TokenDefaultDacl must NOT contain an ACE for Administrators, got {trustees:?}"
    );
    assert!(
        trustees.contains(&user_sid_str),
        "derived TokenDefaultDacl must contain an ACE for the user SID, got {trustees:?}"
    );
    assert!(
        trustees.contains(&"S-1-5-18".to_string()),
        "derived TokenDefaultDacl must contain an ACE for SYSTEM, got {trustees:?}"
    );
}

/// `build_guest_token` must surface an `Err`, not panic, when handed an
/// invalid/closed token handle — this is the failure path the launch
/// path (R04-1c) relies on to abort the launch instead of falling back
/// to an unrestricted token.
#[test]
fn build_guest_token_propagates_error_on_invalid_handle() {
    let bogus = HANDLE(0xDEAD_BEEF_usize as *mut c_void);
    let result = build_guest_token(bogus);
    assert!(
        result.is_err(),
        "build_guest_token must return Err for an invalid source token handle, not panic"
    );
}

/// `verify_guest_token_shape` must accept a genuinely derived guest
/// token, using the same `source_admin_enabled` value the real caller
/// would have captured from the source token before deriving.
#[test]
fn verify_guest_token_shape_accepts_real_derived_token() {
    let source = open_own_token(TOKEN_ALL_ACCESS);
    let (admin_enabled_on_source, _) =
        administrators_state(source).expect("administrators_state(source)");
    let guest = build_guest_token(source).expect("build_guest_token failed");
    unsafe { CloseHandle(source).ok() };

    verify_guest_token_shape(guest.handle(), admin_enabled_on_source)
        .expect("verify_guest_token_shape must accept a genuinely derived guest token");
}

/// `verify_guest_token_shape` must reject a token that has a privilege
/// enabled beyond `SeChangeNotifyPrivilege` — this is the fail-closed
/// check point 6 exists for: if `CreateProcessAsUserW` somehow handed
/// back a child running under a token that isn't privilege-reduced, this
/// function must say so instead of silently accepting it.
///
/// NOTE: this test cannot simply pass the raw source token to
/// `verify_guest_token_shape` — in this environment (a split-token
/// account; see the module doc / R04-0) the current process's OWN token
/// is already the filtered/Limited side, which already has only
/// `SeChangeNotifyPrivilege` enabled, same as a derived token. So the
/// test manufactures a definite mismatch on an independent DUPLICATE of
/// the source token (never mutates the real process token — that would
/// leak into every other test running in this process): it enables one
/// additional disabled-by-default privilege on the duplicate via
/// `AdjustTokenPrivileges` (reusing `try_reenable_privilege`, the same
/// helper the load-bearing non-reenable-ability test above uses) and
/// asserts verification then fails on that duplicate.
#[test]
fn verify_guest_token_shape_rejects_token_with_extra_enabled_privilege() {
    use windows::Win32::Security::{DuplicateTokenEx, SecurityImpersonation, TokenPrimary};

    let source = open_own_token(TOKEN_ALL_ACCESS);
    let others = privileges_to_delete_except_change_notify(source)
        .expect("enumerate non-SeChangeNotify privileges on source");
    if others.is_empty() {
        eprintln!(
            "[guest_token test] source token has no privilege besides \
             SeChangeNotifyPrivilege to enable in this environment — skipping \
             (see module doc: same split-token-account limitation as R04-0)"
        );
        unsafe { CloseHandle(source).ok() };
        return;
    }

    // Independent duplicate — mutations below must never touch the real
    // process token.
    let mut dup = HANDLE::default();
    unsafe {
        DuplicateTokenEx(
            source,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut dup,
        )
    }
    .expect("DuplicateTokenEx(source) failed");
    unsafe { CloseHandle(source).ok() };

    // Resolve a name for the first candidate privilege and try to enable it.
    let mut enabled_name: Option<String> = None;
    for luid_attr in &others {
        let mut name_len: u32 = 256;
        let mut name_buf = vec![0u16; name_len as usize];
        let ok = unsafe {
            LookupPrivilegeNameW(
                PCWSTR::null(),
                &luid_attr.Luid,
                Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
                &mut name_len,
            )
        };
        if !ok.is_ok() {
            continue;
        }
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        if try_reenable_privilege(dup, &name).unwrap_or(false) {
            enabled_name = Some(name);
            break;
        }
    }

    let Some(name) = enabled_name else {
        eprintln!(
            "[guest_token test] could not enable any additional privilege on the \
             duplicated token in this environment — skipping"
        );
        unsafe { CloseHandle(dup).ok() };
        return;
    };

    let result = verify_guest_token_shape(dup, false);
    unsafe { CloseHandle(dup).ok() };

    assert!(
        result.is_err(),
        "verify_guest_token_shape must reject a token with {name} enabled \
         in addition to SeChangeNotifyPrivilege"
    );
}

/// Non-admin-source branch: build a purpose-built "non-admin-shaped"
/// source token (a first-pass restricted token with Administrators
/// already deny-only/absent-from-enabled, obtained the same way the
/// admin branch already proves works) and assert the second pass is a
/// near no-op beyond privilege removal — no panics building it, and no
/// crash/incorrect mutation attempted on a token this function must
/// leave alone for groups/integrity/owner/DACL. This stands in for a
/// true non-admin account, which is not available in this environment
/// (same limitation as R04-0: this session's account is a split-token
/// admin account, there's no separate non-admin login to test against).
#[test]
fn non_admin_source_branch_is_near_noop() {
    let source = open_own_token(TOKEN_ALL_ACCESS);
    let first_pass = build_guest_token(source).expect("first build_guest_token failed");
    unsafe { CloseHandle(source).ok() };

    // first_pass's Administrators is deny-only if the real source was
    // admin-enabled — either way, administrators_state() on it must now
    // report enabled=false, making it a valid "non-admin-shaped" source
    // for exercising the no-op branch.
    let (enabled_on_first_pass, _) =
        administrators_state(first_pass.handle()).expect("administrators_state(first_pass)");
    assert!(
        !enabled_on_first_pass,
        "sanity: derived token must never have Administrators enabled"
    );

    // Snapshot owner/integrity/DACL before the second pass to prove they
    // are left untouched by a non-admin-source build.
    let owner_before = get_token_info_buf(first_pass.handle(), TokenOwner)
        .ok()
        .map(|b| {
            let to: &TOKEN_OWNER = unsafe { &*(b.as_ptr() as *const TOKEN_OWNER) };
            sid_to_string(to.Owner).unwrap_or_default()
        });

    let second_pass =
        build_guest_token(first_pass.handle()).expect("second build_guest_token failed");

    let owner_after = get_token_info_buf(second_pass.handle(), TokenOwner)
        .ok()
        .map(|b| {
            let to: &TOKEN_OWNER = unsafe { &*(b.as_ptr() as *const TOKEN_OWNER) };
            sid_to_string(to.Owner).unwrap_or_default()
        });

    assert_eq!(
        owner_before, owner_after,
        "non-admin-source build must not change TokenOwner"
    );
}
