use super::*;

// Note: the former `reparse_flag_constant`, `is_reparse_create_*` tests
// (5 total) used to live here. They covered a now-removed predicate; the
// real escape vector `FSCTL_SET_REPARSE_POINT[_EX]` is tested in
// fs_metadata_guard. See the comment block near the top of this file.

#[test]
fn is_ea_present_empty_cases() {
    // Null buffer with zero length: no EA.
    assert!(!is_ea_present(std::ptr::null(), 0));
    // Null buffer with non-zero length: still no EA (defensive — kernel
    // would reject this too, but we never want to dereference null).
    assert!(!is_ea_present(std::ptr::null(), 32));
    // Non-null buffer with zero length: no EA payload.
    let dummy = 0u8;
    assert!(!is_ea_present(&dummy as *const u8 as *const c_void, 0));
}

#[test]
fn is_ea_present_supplied() {
    let dummy = 0u8;
    assert!(is_ea_present(&dummy as *const u8 as *const c_void, 1));
    assert!(is_ea_present(&dummy as *const u8 as *const c_void, u32::MAX));
}

#[test]
fn is_create_disposition_classifies_revive() {
    // Dispositions that (re)create the file → revive path on whiteout.
    assert!(is_create_disposition(FILE_SUPERSEDE)); // 0
    assert!(is_create_disposition(FILE_CREATE));     // 2
    assert!(is_create_disposition(FILE_OPEN_IF));    // 3
    assert!(is_create_disposition(FILE_OVERWRITE_IF)); // 5
}

// ── Mock malformed-decision fail-closed pins (audit 2026-09-19 Low) ──
//
// The four Mode::Mock arms live inside unsafe extern "system" hook bodies
// that cannot be invoked without a live ntdll detour, so the invariant is
// pinned textually (same technique as hooks.rs::spawn_hook_body and
// inject.rs::intentional_leak_pin_tests): a Mock arm that falls through to
// the original syscall on a payload/overlay-missing Mock decision re-opens
// the fail-open hole these arms were patched to close.

fn fn_body(src: &str, fn_sig: &str) -> String {
    let start = src
        .find(fn_sig)
        .unwrap_or_else(|| panic!("fn signature missing: {fn_sig}"));
    let rest = &src[start..];
    let end = rest
        .find("
pub(crate)")
        .or_else(|| rest.find("
#[cfg(test)]"))
        .expect("next item bounds the fn body");
    rest[..end].to_string()
}

fn mock_arm(body: &str) -> String {
    let start = body
        .find("Mode::Mock => {")
        .expect("Mode::Mock arm must exist");
    let rest = &body[start..];
    let end = rest.find("Mode::Cow").unwrap_or(rest.len());
    rest[..end].to_string()
}

#[test]
fn mock_create_open_arms_fail_closed_on_malformed_decision() {
    let src = &crate::hooks::module_source("fs_hooks");
    for (sig, tag) in [
        ("fn hook_nt_create_file", "create"),
        ("fn hook_nt_open_file", "open"),
    ] {
        let arm = mock_arm(&fn_body(src, sig));
        assert!(
            !arm.contains("return call_original"),
            "{tag}: Mode::Mock arm must never fall through to the original syscall on a malformed (payload/overlay-missing) Mock decision"
        );
        assert!(
            arm.contains("mock_malformed_decision_deny"),
            "{tag}: Mode::Mock arm must log the malformed decision"
        );
        assert!(
            arm.contains("STATUS_ACCESS_DENIED"),
            "{tag}: Mode::Mock arm must fail closed (ACCESS_DENIED)"
        );
    }
}

#[test]
fn mock_query_arms_fail_closed_on_malformed_decision() {
    let src = &crate::hooks::module_source("fs_hooks");
    for (sig, tag) in [
        ("fn hook_nt_query_attributes_file", "query_attributes"),
        ("fn hook_nt_query_full_attributes_file", "query_full"),
    ] {
        let arm = mock_arm(&fn_body(src, sig));
        assert!(
            !arm.contains(".call(object_attributes, file_information)"),
            "{tag}: Mode::Mock arm must not pass the original path through on a malformed (payload/overlay-missing) Mock decision"
        );
        assert!(
            arm.contains("mock_malformed_decision_deny"),
            "{tag}: Mode::Mock arm must log the malformed decision"
        );
        assert!(
            arm.contains("STATUS_ACCESS_DENIED"),
            "{tag}: Mode::Mock arm must fail closed (ACCESS_DENIED)"
        );
    }
}

#[test]
fn is_create_disposition_rejects_pure_open() {
    // FILE_OPEN (1) and FILE_OVERWRITE (4) are NOT creates:
    // a hidden path must surface not-found for these, not revive.
    assert!(!is_create_disposition(1)); // FILE_OPEN
    assert!(!is_create_disposition(4)); // FILE_OVERWRITE
    // Unknown dispositions are also not revives.
    assert!(!is_create_disposition(99));
}

// ── P0-03: dead-end write intent + device-block deny ───────────────────

#[test]
fn dead_end_write_intent_masks() {
    // Plain data-write and generic masks.
    assert!(dead_end_write_intent(crate::hooks::GENERIC_WRITE, None, 0));
    assert!(dead_end_write_intent(crate::hooks::FILE_WRITE_DATA, None, 0));
    assert!(dead_end_write_intent(crate::hooks::FILE_APPEND_DATA, None, 0));
    // Metadata / EA / generic-all / delete / security ops — the
    // canonical mask, not a dead-end-private one.
    assert!(dead_end_write_intent(crate::hooks::GENERIC_ALL, None, 0));
    assert!(dead_end_write_intent(crate::hooks::FILE_WRITE_ATTRIBUTES, None, 0));
    assert!(dead_end_write_intent(crate::hooks::FILE_WRITE_EA, None, 0));
    assert!(dead_end_write_intent(crate::hooks::DELETE, None, 0));
    assert!(dead_end_write_intent(crate::hooks::WRITE_DAC, None, 0));
    assert!(dead_end_write_intent(crate::hooks::WRITE_OWNER, None, 0));
    // Generic READ must not count as a write.
    assert!(!dead_end_write_intent(0x8000_0000, None, 0));
    assert!(!dead_end_write_intent(0, None, 0));
}

/// The dead end must never disagree with the canonical mask: it is the
/// same definition plus the CreateOptions DELETE_ON_CLOSE bit. If this
/// table ever diverges from `is_write_access`, an open classified as a
/// read on one path and a write on the other is one edit away.
#[test]
fn dead_end_write_intent_agrees_with_is_write_access() {
    let access_cases: [u32; 10] = [
        crate::hooks::GENERIC_ALL,
        crate::hooks::GENERIC_WRITE,
        crate::hooks::FILE_WRITE_DATA,
        crate::hooks::FILE_APPEND_DATA,
        crate::hooks::FILE_WRITE_EA,
        crate::hooks::FILE_WRITE_ATTRIBUTES,
        crate::hooks::DELETE,
        crate::hooks::WRITE_DAC,
        crate::hooks::WRITE_OWNER,
        0x8000_0000, // GENERIC_READ — must stay a read on BOTH paths
    ];
    let dispositions = [0, 1, 2, 3, 4, 5]; // SUPERSEDE..OVERWRITE_IF incl. FILE_OPEN
    for &a in &access_cases {
        for &d in &dispositions {
            assert_eq!(
                dead_end_write_intent(a, Some(d), 0),
                is_write_access(a, d),
                "dead-end vs canonical disagreement for access={a:#010x} disposition={d}"
            );
        }
    }
}

#[test]
fn dead_end_write_intent_dispositions_and_options() {
    use crate::hooks::FILE_OVERWRITE;
    // Create dispositions count as writes even with no access bits.
    assert!(dead_end_write_intent(0, Some(FILE_CREATE), 0));
    assert!(dead_end_write_intent(0, Some(FILE_OPEN_IF), 0));
    assert!(dead_end_write_intent(0, Some(FILE_OVERWRITE), 0));
    assert!(dead_end_write_intent(0, Some(FILE_OVERWRITE_IF), 0));
    assert!(dead_end_write_intent(0, Some(FILE_SUPERSEDE), 0));
    // Pure open stays a read.
    assert!(!dead_end_write_intent(0, Some(1), 0)); // FILE_OPEN
    // FILE_DELETE_ON_CLOSE turns even a read-mode open into a write.
    assert!(dead_end_write_intent(0, None, FILE_DELETE_ON_CLOSE));
    assert!(!dead_end_write_intent(0, None, 0));
}

/// Calls `classify_device_open` on an NT path; returns its verdict.
fn device_block_for(path: &str, write: bool) -> DeviceVerdict {
    use ntapi::winapi::shared::ntdef::UNICODE_STRING;
    let buf: Vec<u16> = path.encode_utf16().collect();
    let len_bytes = (buf.len() * 2) as u16;
    let mut us = UNICODE_STRING {
        Length: len_bytes,
        MaximumLength: len_bytes,
        Buffer: buf.as_ptr() as *mut u16,
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: &mut us,
        Attributes: 0,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    // SAFETY: us/oa/buf are valid locals for the duration of the call.
    unsafe { crate::hooks::classify_device_open(&oa as *const OBJECT_ATTRIBUTES, write) }
}

const DENIED: DeviceVerdict = DeviceVerdict::Deny(STATUS_ACCESS_DENIED);

#[test]
fn check_device_block_denies_unc_write() {
    // P0-03: `\??\UNC\…` (the NT form of `\\localhost\c$\…`) must not
    // pass a write through — it reaches the REAL volume via the network
    // redirector, outside the CoW overlay.
    assert_eq!(
        device_block_for(r"\??\UNC\localhost\c$\Users\Public\evil.exe", true),
        DENIED
    );
    // Raw Win32 UNC spelling classifies the same.
    assert_eq!(
        device_block_for(r"\\localhost\c$\Users\Public\evil.exe", true),
        DENIED
    );
}

#[test]
fn check_device_block_allows_unc_read() {
    // Reads keep the documented pass-through behaviour. `Unhandled`, not
    // `PassThrough`: a UNC read is still a filesystem read and the
    // caller's own logic owns it.
    assert_eq!(
        device_block_for(r"\??\UNC\localhost\c$\Users\Public\evil.exe", false),
        DeviceVerdict::Unhandled
    );
}

#[test]
fn check_device_block_enforces_systemquery_write_deny() {
    // The SystemQuery contract is "read OK, write denied" — CldFlt is the
    // canonical SystemQuery member. Before the P0-03 fix this carried on
    // for writes too.
    assert_eq!(device_block_for(r"\device\cldflt", true), DENIED);
    assert_eq!(device_block_for(r"\device\cldflt", false), DeviceVerdict::Unhandled);
}

#[test]
fn check_device_block_keeps_hard_blocks_and_volume_reads() {
    // Hard blocks deny regardless of direction.
    assert_eq!(device_block_for(r"\device\physicaldrive0", false), DENIED);
    // Ordinary volume reads still pass the device gate.
    assert_eq!(
        device_block_for(r"\device\harddiskvolume2\foo", false),
        DeviceVerdict::Unhandled
    );
}

/// A volume device must NOT become `PassThrough`: the dead-end write deny
/// is exactly what stops `\Device\HarddiskVolumeN\…` writes from reaching
/// the real disk without a `decide()` call.
#[test]
fn volume_device_write_stays_subject_to_dead_end_deny() {
    assert_eq!(
        device_block_for(r"\device\harddiskvolume2\foo", true),
        DeviceVerdict::Unhandled
    );
}

/// Regression: every one of these carries write access and resolves to no
/// DOS path, so the dead-end deny used to refuse it — which took out
/// `CreatePipe`, `child_process.spawn` and every console TTY open, at
/// EVERY guard level including `none`. Observed as
/// `spawnSync ... EPERM` from node with `fs_block_unresolved_write` in the
/// trace. None of these has a filesystem behind it.
#[test]
fn non_filesystem_devices_pass_through_writes() {
    // libuv's own pipe naming, verbatim from the failing trace.
    assert_eq!(
        device_block_for(r"\??\pipe\uv\18446744073709551615-50184", true),
        DeviceVerdict::PassThrough
    );
    assert_eq!(
        device_block_for(r"\Device\NamedPipe\some-ipc-channel", true),
        DeviceVerdict::PassThrough
    );
    // Console: the TTY handles crossterm and libuv open read/write.
    assert_eq!(device_block_for(r"\??\CONOUT$", true), DeviceVerdict::PassThrough);
    assert_eq!(device_block_for(r"\??\CONIN$", true), DeviceVerdict::PassThrough);
    assert_eq!(device_block_for(r"\Device\ConDrv\Output", true), DeviceVerdict::PassThrough);
    // NUL and sockets.
    assert_eq!(device_block_for(r"\??\NUL", true), DeviceVerdict::PassThrough);
    assert_eq!(device_block_for(r"\Device\Afd\Endpoint", true), DeviceVerdict::PassThrough);
}

/// The pass-through above must not reopen the dangerous-pipe hole: those
/// classify as `Unknown` and stay denied in both directions.
#[test]
fn dangerous_pipes_stay_denied_despite_pass_through() {
    assert_eq!(device_block_for(r"\??\pipe\svcctl", true), DENIED);
    assert_eq!(device_block_for(r"\??\pipe\svcctl", false), DENIED);
    assert_eq!(device_block_for(r"\??\pipe\atsvc", true), DENIED);
}
