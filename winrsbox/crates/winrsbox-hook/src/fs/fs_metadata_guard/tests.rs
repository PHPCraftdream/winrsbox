use super::*;

// ── Relative-rename passthrough rewrite (audit 2026-09-19 Low) ────

#[test]
fn absolute_rename_buffer_nulls_root_and_keeps_flags() {
    let dest = r"c:\proj\renamed.txt";
    let nt = policy::path::dos_to_nt(dest); // \??\c:\proj\renamed.txt\0
    let name_bytes = (nt.len() - 1) * 2;

    let mut orig = vec![0u8; 0x14 + 8];
    orig[0] = 1; // ReplaceIfExists = TRUE (non-Ex) / flags word (Ex)
    orig[8] = 0xAB; // root-handle bytes — must be zeroed in the output
    orig[0x10] = 0x99; // stale FileNameLength — must be overwritten

    let (out, out_len) =
        build_absolute_rename_buffer(&orig, dest).expect("buffer must build");
    assert_eq!(out_len as usize, 0x14 + nt.len() * 2);
    assert_eq!(&out[..8], &orig[..8], "flags word copied verbatim");
    assert_eq!(&out[8..16], &0u64.to_ne_bytes(), "RootDirectory must be NULL");
    let got_len = u32::from_le_bytes([out[16], out[17], out[18], out[19]]) as usize;
    assert_eq!(
        got_len, name_bytes,
        "FileNameLength counts name bytes, not the NUL terminator"
    );
    let mut want = Vec::new();
    for w in &nt {
        want.extend_from_slice(&w.to_le_bytes());
    }
    assert_eq!(&out[0x14..], &want[..], "FileName must be the absolute NT form");
}

#[test]
fn absolute_rename_buffer_rejects_short_header() {
    let orig = [0u8; 0x13];
    assert!(build_absolute_rename_buffer(&orig, r"c:\x").is_none());
}

#[test]
fn rename_passthrough_arm_rewrites_relative_root() {
    // Textual pin (hooks.rs::spawn_hook_body precedent): the Passthrough
    // arm of the rename/link handler must rewrite a relative
    // RootDirectory buffer to the absolute NT form instead of handing
    // the caller's buffer back for a second, racy handle resolution.
    let src = crate::hooks::module_source("fs_metadata_guard.rs");
    let fn_start = src
        .find("fn hook_nt_set_information_file")
        .expect("rename hook must exist");
    let rest = &src[fn_start..];
    let body_end = rest
        .find("
#[cfg(test)]")
        .or_else(|| rest.find("
pub(crate)"))
        .expect("next item bounds the fn body");
    let body = &rest[..body_end];
    let pt_start = body
        .find("policy::Mode::Passthrough =>")
        .expect("Passthrough arm must exist");
    let pt_end = body
        .find("policy::Mode::Cow")
        .expect("Cow arm must follow Passthrough");
    let pt = &body[pt_start..pt_end];
    assert!(
        pt.contains("root.is_null()"),
        "Passthrough arm must branch on the relative-open case"
    );
    assert!(
        pt.contains("build_absolute_rename_buffer"),
        "Passthrough arm must rewrite the relative rename buffer to the absolute NT form (racy RootDirectory fix)"
    );
    assert!(
        pt.contains("fs_setinfo_passthrough_rewrite_failed"),
        "rewrite failure must be visible in trace logs and fail closed"
    );
}

// ── unaligned-read regression (alignment-UB class, mirrors 9d73d34) ──
//
// resolve_delete_target walks a caller-supplied OBJECT_ATTRIBUTES →
// UNICODE_STRING → Buffer chain: three addresses a hostile caller
// controls. The probes below force ALL THREE onto odd addresses — the
// old `&*attrs` / `&*ustr` / `from_raw_parts::<u16>(Buffer)` chain
// aborted on the first step instead of resolving the name.

/// Byte offset within `backing` whose address is ODD.
fn odd_offset(backing: &[u8]) -> usize {
    let off = 1 - (backing.as_ptr() as usize % 2);
    assert_eq!((backing.as_ptr() as usize + off) % 2, 1, "probe must sit at an odd address");
    off
}

/// Copy `value`'s bytes to `dst` — any alignment.
unsafe fn place_at<T>(dst: *mut u8, value: &T) {
    std::ptr::copy_nonoverlapping(
        value as *const T as *const u8,
        dst,
        std::mem::size_of::<T>(),
    );
}

/// Build an OBJECT_ATTRIBUTES → UNICODE_STRING → name chain with each
/// link at an ODD address. Returns the attrs pointer plus the backings
/// (which must outlive every use of the pointer).
unsafe fn odd_attrs_chain(
    name: &[u16],
) -> (*const OBJECT_ATTRIBUTES, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut name_backing = vec![0u8; name.len() * 2 + 8];
    let noff = odd_offset(&name_backing);
    // SAFETY: noff ≤ 1 and name.len()*2 fits inside the backing.
    unsafe {
        std::ptr::copy_nonoverlapping(
            name.as_ptr() as *const u8,
            name_backing.as_mut_ptr().add(noff),
            name.len() * 2,
        );
    }
    let ustr = UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2 + 2) as u16,
        // SAFETY: points at the odd window in `name_backing`, valid for
        // Length bytes; the backing outlives the returned pointer's use.
        Buffer: unsafe { name_backing.as_ptr().add(noff) } as *mut u16,
    };
    let mut ustr_backing = vec![0u8; std::mem::size_of::<UNICODE_STRING>() + 8];
    let uoff = odd_offset(&ustr_backing);
    // SAFETY: uoff ≤ 1, struct fits the backing.
    unsafe { place_at(ustr_backing.as_mut_ptr().add(uoff), &ustr) };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        // SAFETY: points at the odd window in `ustr_backing` (above).
        ObjectName: unsafe { ustr_backing.as_ptr().add(uoff) } as *mut UNICODE_STRING,
        Attributes: 0,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    let mut oa_backing = vec![0u8; std::mem::size_of::<OBJECT_ATTRIBUTES>() + 8];
    let aoff = odd_offset(&oa_backing);
    // SAFETY: aoff ≤ 1, struct fits the backing.
    unsafe { place_at(oa_backing.as_mut_ptr().add(aoff), &oa) };
    let attrs = unsafe { oa_backing.as_ptr().add(aoff) as *const OBJECT_ATTRIBUTES };
    (attrs, oa_backing, ustr_backing, name_backing)
}

#[test]
fn resolve_delete_target_resolves_misaligned_attrs_chain() {
    let name: Vec<u16> = r"\??\C:\Users\Someone\Important.TXT".encode_utf16().collect();
    // SAFETY: the chain is self-consistent and the backings outlive the
    // call below (bound in this scope).
    let (attrs, _oa, _us, _nm) = unsafe { odd_attrs_chain(&name) };
    let dest = unsafe { resolve_delete_target(attrs) };
    assert_eq!(dest.as_deref(), Some(r"c:\users\someone\important.txt"),
        "fully misaligned caller chain must resolve like an aligned one");
}

#[test]
fn resolve_delete_target_misaligned_attrs_with_null_objectname_is_none() {
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: std::ptr::null_mut(),
        Attributes: 0,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    let mut backing = vec![0u8; std::mem::size_of::<OBJECT_ATTRIBUTES>() + 8];
    let off = odd_offset(&backing);
    // SAFETY: off ≤ 1, struct fits the backing.
    unsafe { place_at(backing.as_mut_ptr().add(off), &oa) };
    // SAFETY: the odd attrs is a byte-identical, live OBJECT_ATTRIBUTES.
    let attrs = unsafe { backing.as_ptr().add(off) as *const OBJECT_ATTRIBUTES };
    assert_eq!(unsafe { resolve_delete_target(attrs) }, None);
}

/// The overlay-delete branch of apply_delete_decision reads the LIVE
/// caller OBJECT_ATTRIBUTES (Attributes/Security* fields). A hostile
/// caller can put it at an odd address — the old `let o = &*attrs;`
/// aborted there instead of redirecting the delete at the overlay copy.
#[test]
fn nt_delete_overlay_branch_reads_misaligned_caller_attrs() {
    let dir = std::env::temp_dir().join(format!("winrsbox_p002_odd_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let real = dir.join("important.txt");
    std::fs::write(&real, b"lower-file").unwrap();
    let overlay = dir.join("overlay_copy.bin");
    std::fs::write(&overlay, b"cow-copy").unwrap();

    let decision = policy::Decision {
        mode: policy::Mode::Cow,
        overlay: Some(overlay.clone()),
        cow_from: Some(real.clone()),
        mock_payload: None,
    };

    let name: Vec<u16> = r"\??\C:\Users\Someone\Important.TXT".encode_utf16().collect();
    // SAFETY: the chain is self-consistent; backings are bound below and
    // outlive the apply_delete_decision call.
    let (attrs, _oa_backing, _ustr_backing, _name_backing) =
        unsafe { odd_attrs_chain(&name) };

    let mut seen_target: Option<String> = None;
    let mut seen_root_null = false;
    let overlay_for_stub = overlay.clone();
    let result = unsafe {
        apply_delete_decision(
            attrs as *mut OBJECT_ATTRIBUTES,
            &real.to_string_lossy().to_ascii_lowercase(),
            &decision,
            |a| {
                // The stub kernel receives OUR rewritten (aligned) attrs.
                let oa = &*a;
                seen_root_null = oa.RootDirectory.is_null();
                let us = &*oa.ObjectName;
                let chars = (us.Length as usize) / 2;
                let decoded =
                    String::from_utf16_lossy(std::slice::from_raw_parts(us.Buffer, chars));
                seen_target = Some(decoded.to_ascii_lowercase());
                let _ = std::fs::remove_file(&overlay_for_stub);
                STATUS_SUCCESS
            },
        )
    };

    let expected = format!(r"\??\{}", overlay.to_string_lossy().to_ascii_lowercase());
    assert_eq!(seen_target.as_deref(), Some(expected.as_str()),
        "misaligned caller attrs must still drive the overlay redirect");
    assert!(seen_root_null, "rewritten attrs must use an absolute path");
    assert_eq!(
        result,
        DeleteResult::WhiteoutRecorded { status: STATUS_SUCCESS, overlay_removed: true },
    );
    assert!(real.exists(), "the real lower file must survive the delete");
    assert!(!overlay.exists(), "the materialised overlay copy must be gone");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `hook_nt_set_ea_file` MUST return STATUS_ACCESS_DENIED for any input,
/// including null pointers and zero length. This is the contract that
/// makes the unconditional deny safe: we never dereference Buffer and
/// we tolerate a null IoStatusBlock.
#[test]
fn nt_set_ea_file_unconditional_deny() {
    let status = unsafe {
        hook_nt_set_ea_file(
            std::ptr::null_mut(), // FileHandle
            std::ptr::null_mut(), // IoStatusBlock (null tolerated)
            std::ptr::null_mut(), // Buffer
            0,                    // Length
        )
    };
    assert_eq!(status, STATUS_ACCESS_DENIED);

    // Also with a non-zero length — must still deny without inspecting Buffer.
    let status = unsafe {
        hook_nt_set_ea_file(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            4096,
        )
    };
    assert_eq!(status, STATUS_ACCESS_DENIED);
}

/// When IoStatusBlock IS provided, the hook must populate it with the
/// deny status before returning. Callers reading the IOSB Status field
/// must observe the same value as the return.
#[test]
fn nt_set_ea_file_writes_io_status_block() {
    // IO_STATUS_BLOCK contains a winapi UNION! field with no Default impl.
    // mem::zeroed is the standard idiom for this ABI-compatible POD.
    // SAFETY: IO_STATUS_BLOCK is (union | usize)-sized POD; all-zero is
    // a valid "no status, no information" bit pattern.
    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let status = unsafe {
        hook_nt_set_ea_file(
            std::ptr::null_mut(),
            &mut iosb as *mut _,
            std::ptr::null_mut(),
            0,
        )
    };
    assert_eq!(status, STATUS_ACCESS_DENIED);
    // Status field is at offset 0 (Status/Pointer union). set_io_status
    // zeros the union slot then writes the 4-byte NTSTATUS.
    // SAFETY: reading the Status arm of the union after we wrote it
    // through set_io_status (same offset) is sound.
    let raw_status = unsafe { *(&iosb as *const _ as *const NTSTATUS) };
    assert_eq!(raw_status, STATUS_ACCESS_DENIED);
}

// -----------------------------------------------------------------------
// decide_post_delete — pure logic, no IPC, no detours
// -----------------------------------------------------------------------

/// STATUS_SUCCESS → whiteout + remove OVERLAY_IDX (file is physically gone).
#[test]
fn decide_post_delete_success_removes_idx() {
    assert_eq!(
        decide_post_delete(STATUS_SUCCESS),
        WhiteoutAction::RecordWhiteoutAndRemoveIdx,
    );
}

/// STATUS_DIRECTORY_NOT_EMPTY → whiteout but KEEP OVERLAY_IDX (physical
/// file still present due to handle contention).  This is the bug-#76
/// fix: the old code returned `Skip` here.
#[test]
fn decide_post_delete_not_empty_records_whiteout_keeps_overlay() {
    assert_eq!(
        decide_post_delete(STATUS_DIRECTORY_NOT_EMPTY),
        WhiteoutAction::RecordWhiteoutKeepOverlay,
    );
}

/// STATUS_SHARING_VIOLATION → same treatment as NOT_EMPTY.
#[test]
fn decide_post_delete_sharing_violation_records_whiteout_keeps_overlay() {
    assert_eq!(
        decide_post_delete(STATUS_SHARING_VIOLATION),
        WhiteoutAction::RecordWhiteoutKeepOverlay,
    );
}

/// STATUS_REPARSE_POINT_ENCOUNTERED (0xC0000274 / os error 4395) → whiteout
/// but KEEP OVERLAY_IDX, same as NOT_EMPTY treatment. This is bug-#79:
/// when a kernel filter driver (e.g. AnviFPFltd) intercepts the physical
/// delete and returns this status, the virtual path must still be hidden
/// so a subsequent install attempt can succeed. The old code returned
/// `Skip` here, leaving the sandbox in a broken state.
#[test]
fn decide_post_delete_reparse_point_encountered_records_whiteout_keeps_overlay() {
    assert_eq!(
        decide_post_delete(STATUS_REPARSE_POINT_ENCOUNTERED),
        WhiteoutAction::RecordWhiteoutKeepOverlay,
    );
}

/// Any other error status → Skip (do not record a spurious whiteout).
#[test]
fn decide_post_delete_other_error_skips() {
    // STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
    let other: NTSTATUS = 0xC000_0034_u32 as NTSTATUS;
    assert_eq!(decide_post_delete(other), WhiteoutAction::Skip);
}

// -----------------------------------------------------------------------
// NtDeleteFile (P0-02)
//
// These tests drive the resolve/apply seam directly and inject the
// policy Decision. They must NEVER reach hooks::decide(): with no broker
// pipe under `cargo test`, ipc_decide self-terminates the process after
// IPC_FAIL_THRESHOLD (8) consecutive failures.
// -----------------------------------------------------------------------

/// Absolute NT names (the `\??\C:\...` form Win32 hands to NtDeleteFile)
/// resolve to the lowercase DOS path the policy decides on.
#[test]
fn resolve_delete_target_maps_absolute_nt_name_to_lowercase_dos() {
    let mut name: Vec<u16> = r"\??\C:\Users\Someone\Important.TXT".encode_utf16().collect();
    let mut ustr = UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2 + 2) as u16,
        Buffer: name.as_mut_ptr(),
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: &mut ustr,
        Attributes: 0,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    let dest = unsafe { resolve_delete_target(&oa) };
    assert_eq!(dest.as_deref(), Some(r"c:\users\someone\important.txt"));
}

/// A null Buffer with a non-zero Length must NOT be dereferenced, and an
/// empty name must not resolve — both fail closed to None (the hook then
/// denies instead of forwarding anything to the kernel).
#[test]
fn resolve_delete_target_rejects_malformed_name_without_dereferencing() {
    let mut ustr = UNICODE_STRING {
        Length: 8,
        MaximumLength: 8,
        Buffer: std::ptr::null_mut(),
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: &mut ustr,
        Attributes: 0,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    assert_eq!(unsafe { resolve_delete_target(&oa) }, None);

    let mut name = [b'a' as u16; 4];
    let mut empty = UNICODE_STRING {
        Length: 0,
        MaximumLength: 8,
        Buffer: name.as_mut_ptr(),
    };
    let oa_empty = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: &mut empty,
        Attributes: 0,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    assert_eq!(unsafe { resolve_delete_target(&oa_empty) }, None);
}

/// THE regression test (P0-02): deleting a path outside project_root via
/// NtDeleteFile must record a whiteout and NEVER reach the original
/// syscall (which would unlink the real file on the real disk).
#[test]
fn nt_delete_external_path_records_whiteout_and_spares_real_file() {
    let dir = std::env::temp_dir().join(format!("winrsbox_p002_ext_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let real = dir.join("important.txt");
    std::fs::write(&real, b"lower-file-do-not-delete").unwrap();

    // Broker decision for a CoW-managed external path whose overlay copy
    // was never materialised.
    let decision = policy::Decision {
        mode: policy::Mode::Cow,
        overlay: Some(dir.join("overlay_never_created.bin")),
        cow_from: Some(real.clone()),
        mock_payload: None,
    };

    let mut original_called = false;
    let result = unsafe {
        apply_delete_decision(
            std::ptr::null_mut(), // not dereferenced on this branch
            &real.to_string_lossy().to_ascii_lowercase(),
            &decision,
            |_a| {
                original_called = true;
                0
            },
        )
    };

    assert_eq!(
        result,
        DeleteResult::WhiteoutRecorded { status: STATUS_SUCCESS, overlay_removed: false },
        "external delete must become a whiteout reported as success",
    );
    assert!(!original_called, "original NtDeleteFile must not run for an external path");
    assert!(real.exists(), "the real lower file must survive the delete");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Materialised CoW copy: the ORIGINAL syscall must be redirected at the
/// OVERLAY copy (never at the real path), the copy really disappears, the
/// real lower file survives, and the whiteout is recorded.
#[test]
fn nt_delete_materialised_overlay_copy_is_deleted_then_whiteouted() {
    let dir = std::env::temp_dir().join(format!("winrsbox_p002_mat_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let real = dir.join("important.txt");
    std::fs::write(&real, b"lower-file").unwrap();
    let overlay = dir.join("overlay_copy.bin");
    std::fs::write(&overlay, b"cow-copy").unwrap();

    let decision = policy::Decision {
        mode: policy::Mode::Cow,
        overlay: Some(overlay.clone()),
        cow_from: Some(real.clone()),
        mock_payload: None,
    };

    // Real caller attrs — the overlay branch reads them read-only.
    let mut caller_name: Vec<u16> =
        r"\??\C:\Users\Someone\Important.TXT".encode_utf16().collect();
    let mut caller_ustr = UNICODE_STRING {
        Length: (caller_name.len() * 2) as u16,
        MaximumLength: (caller_name.len() * 2 + 2) as u16,
        Buffer: caller_name.as_mut_ptr(),
    };
    let mut caller_attrs = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: &mut caller_ustr,
        Attributes: 0x40, // OBJ_CASE_INSENSITIVE
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };

    let mut seen_target: Option<String> = None;
    let mut seen_root_null = false;
    let overlay_for_stub = overlay.clone();
    let result = unsafe {
        apply_delete_decision(
            &mut caller_attrs,
            &real.to_string_lossy().to_ascii_lowercase(),
            &decision,
            |a| {
                let oa = &*a;
                seen_root_null = oa.RootDirectory.is_null();
                let us = &*oa.ObjectName;
                let chars = (us.Length as usize) / 2;
                let decoded = String::from_utf16_lossy(std::slice::from_raw_parts(us.Buffer, chars));
                seen_target = Some(decoded.to_ascii_lowercase());
                // Stand-in for the kernel: remove the copy the rewritten
                // attrs point at.
                let _ = std::fs::remove_file(&overlay_for_stub);
                STATUS_SUCCESS
            },
        )
    };

    let expected = format!(r"\??\{}", overlay.to_string_lossy().to_ascii_lowercase());
    assert_eq!(
        seen_target.as_deref(),
        Some(expected.as_str()),
        "the original syscall must be redirected at the OVERLAY copy",
    );
    assert!(seen_root_null, "rewritten attrs must use an absolute path (RootDirectory = NULL)");
    assert_eq!(
        result,
        DeleteResult::WhiteoutRecorded { status: STATUS_SUCCESS, overlay_removed: true },
    );
    assert!(real.exists(), "the real lower file must survive the delete");
    assert!(!overlay.exists(), "the materialised overlay copy must be gone");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Kernel reports the overlay copy already gone (lost race) → still
/// whiteout and report SUCCESS; the caller must not see a NOT_FOUND for
/// a status on a path the caller never named.
#[test]
fn nt_delete_overlay_copy_vanished_still_whiteouts_success() {
    let dir = std::env::temp_dir().join(format!("winrsbox_p002_race_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let real = dir.join("important.txt");
    std::fs::write(&real, b"lower-file").unwrap();
    let overlay = dir.join("overlay_copy.bin");
    std::fs::write(&overlay, b"cow-copy").unwrap();

    let decision = policy::Decision {
        mode: policy::Mode::Cow,
        overlay: Some(overlay.clone()),
        cow_from: Some(real.clone()),
        mock_payload: None,
    };

    let mut caller_name: Vec<u16> =
        r"\??\C:\Users\Someone\Important.TXT".encode_utf16().collect();
    let mut caller_ustr = UNICODE_STRING {
        Length: (caller_name.len() * 2) as u16,
        MaximumLength: (caller_name.len() * 2 + 2) as u16,
        Buffer: caller_name.as_mut_ptr(),
    };
    let mut caller_attrs = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: &mut caller_ustr,
        Attributes: 0x40,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };

    let result = unsafe {
        apply_delete_decision(
            &mut caller_attrs,
            &real.to_string_lossy().to_ascii_lowercase(),
            &decision,
            |_a| STATUS_OBJECT_NAME_NOT_FOUND, // kernel: overlay copy gone
        )
    };

    assert_eq!(
        result,
        DeleteResult::WhiteoutRecorded { status: STATUS_SUCCESS, overlay_removed: false },
    );
    assert!(real.exists(), "the real lower file must survive the delete");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Already-whiteouted path: the virtual file does not exist — the delete
/// reports NOT_FOUND (same Mode::Hidden mapping as the create/open
/// hooks) and the original is never called.
#[test]
fn nt_delete_hidden_mode_reports_not_found_without_calling_original() {
    let decision = policy::Decision {
        mode: policy::Mode::Hidden,
        overlay: None,
        cow_from: None,
        mock_payload: None,
    };
    let mut original_called = false;
    let result = unsafe {
        apply_delete_decision(
            std::ptr::null_mut(),
            r"c:\some\virtual\path.txt",
            &decision,
            |_a| {
                original_called = true;
                0
            },
        )
    };
    assert_eq!(result, DeleteResult::Status(STATUS_OBJECT_NAME_NOT_FOUND));
    assert!(!original_called);
}

/// Policy Deny: blocked, original never called.
#[test]
fn nt_delete_deny_mode_is_blocked() {
    let decision = policy::Decision {
        mode: policy::Mode::Deny,
        overlay: None,
        cow_from: None,
        mock_payload: None,
    };
    let mut original_called = false;
    let result = unsafe {
        apply_delete_decision(
            std::ptr::null_mut(),
            r"c:\some\denied\path.txt",
            &decision,
            |_a| {
                original_called = true;
                0
            },
        )
    };
    assert_eq!(result, DeleteResult::Status(STATUS_ACCESS_DENIED));
    assert!(!original_called);
}

/// Inside project_root: the caller's own OBJECT_ATTRIBUTES reach the
/// original untouched and its status is returned verbatim.
#[test]
fn nt_delete_passthrough_forwards_caller_attrs_to_original() {
    let decision = policy::Decision {
        mode: policy::Mode::Passthrough,
        overlay: None,
        cow_from: None,
        mock_payload: None,
    };
    let mut caller_name: Vec<u16> =
        r"\??\C:\project\file.txt".encode_utf16().collect();
    let mut caller_ustr = UNICODE_STRING {
        Length: (caller_name.len() * 2) as u16,
        MaximumLength: (caller_name.len() * 2 + 2) as u16,
        Buffer: caller_name.as_mut_ptr(),
    };
    let mut caller_attrs = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: &mut caller_ustr,
        Attributes: 0x40,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    let expected_ptr: *mut OBJECT_ATTRIBUTES = &mut caller_attrs;
    let mut seen_ptr: *mut OBJECT_ATTRIBUTES = std::ptr::null_mut();
    let result = unsafe {
        apply_delete_decision(
            expected_ptr,
            r"c:\project\file.txt",
            &decision,
            |a| {
                seen_ptr = a;
                0x1234
            },
        )
    };
    assert_eq!(seen_ptr, expected_ptr, "passthrough must forward the caller's attrs");
    assert_eq!(result, DeleteResult::Status(0x1234));
}

// -----------------------------------------------------------------------
// Unaligned raw-record access (alignment-UB class)
//
// The rename/disposition info buffers are caller-owned memory: the
// sandboxed process picks the address, so the NT header fields can sit
// at ANY odd address. Every field read must therefore go through
// read_unaligned. These probes force the buffer onto an odd address; a
// plain aligned dereference aborts under the debug alignment check
// (STATUS_STACK_BUFFER_OVERRUN) instead of reading the field.
// -----------------------------------------------------------------------

/// Copy `buf` into a larger backing allocation so the probe starts at an
/// ODD address regardless of the allocator's base alignment.
fn odd_window(buf: &[u8]) -> (Vec<u8>, usize) {
    let mut backing = vec![0u8; buf.len() + 512];
    let off = 1 - (backing.as_ptr() as usize % 2);
    backing[off..off + buf.len()].copy_from_slice(buf);
    (backing, off)
}

/// Build a FILE_RENAME_INFORMATION buffer (shared prefix with the Ex
/// variant): ReplaceIfExists @0x00, RootDirectory @0x08, FileNameLength
/// @0x10, FileName[] @0x14.
fn build_rename_info(root: usize, name: &str) -> Vec<u8> {
    let name_u16: Vec<u16> = name.encode_utf16().collect();
    let mut buf = vec![0u8; 0x14 + name_u16.len() * 2];
    buf[0x08..0x10].copy_from_slice(&(root as u64).to_le_bytes());
    buf[0x10..0x14].copy_from_slice(&((name_u16.len() * 2) as u32).to_le_bytes());
    for (i, u) in name_u16.iter().enumerate() {
        buf[0x14 + i * 2..0x16 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    buf
}

/// REGRESSION (alignment class): a rename-info buffer at an ODD address
/// must decode RootDirectory, FileNameLength and FileName correctly via
/// unaligned reads. The old plain dereferences (`*(ptr as *const HANDLE)`
/// at base+0x08 with an odd base) are UB and abort under the debug
/// alignment check instead of returning the field.
#[test]
fn parse_rename_info_decodes_unaligned_buffer() {
    let built = build_rename_info(0xDEADBEEF, r"\??\C:\Users\Someone\Mixed.TXT");
    let (mut backing, off) = odd_window(&built);
    assert_eq!(
        (backing.as_ptr() as usize + off) % 2,
        1,
        "probe buffer must start at an odd address",
    );
    // SAFETY: backing[off..off+built.len()] holds a full rename-info
    // buffer for exactly built.len() bytes.
    let parsed = unsafe { parse_rename_info(backing.as_ptr().add(off), built.len()) };
    let (root, name) = parsed.expect("well-formed buffer must parse");
    assert_eq!(root as usize, 0xDEADBEEF, "RootDirectory must read correctly at an odd address");
    assert_eq!(name, r"\??\C:\Users\Someone\Mixed.TXT");
}

/// The passthrough contract of parse_rename_info must survive the
/// extraction: each malformed shape maps to None (the hook then calls
/// the original instead of touching the buffer).
#[test]
fn parse_rename_info_rejects_malformed_buffers() {
    // Buffer shorter than the fixed 0x14 header.
    let short = [0u8; 0x10];
    // SAFETY: len equals the real buffer length in every call below.
    assert_eq!(unsafe { parse_rename_info(short.as_ptr(), short.len()) }, None);

    // Zero FileNameLength.
    let zero_len = vec![0u8; 0x40];
    assert_eq!(unsafe { parse_rename_info(zero_len.as_ptr(), zero_len.len()) }, None);

    // FileName runs past the declared buffer length.
    let mut over = vec![0u8; 0x40];
    over[0x10..0x14].copy_from_slice(&0x0100u32.to_le_bytes()); // 256 > 0x40 - 0x14
    assert_eq!(unsafe { parse_rename_info(over.as_ptr(), over.len()) }, None);

    // Absurd (> 0x8000) FileNameLength.
    let mut huge = vec![0u8; 0x40];
    huge[0x10..0x14].copy_from_slice(&0x8004u32.to_le_bytes());
    assert_eq!(unsafe { parse_rename_info(huge.as_ptr(), huge.len()) }, None);
}

/// REGRESSION (alignment class): FILE_DISPOSITION_INFO_EX flags at an
/// ODD address must decode via an unaligned u32 read — the old plain
/// dereference is UB there and aborts under the debug alignment check.
#[test]
fn parse_disposition_info_ex_decodes_unaligned_buffer() {
    // FILE_DISPOSITION_DELETE (0x1) | FILE_DISPOSITION_POSIX_SEMANTICS (0x8).
    let built = 0x9u32.to_le_bytes().to_vec();
    let (mut backing, off) = odd_window(&built);
    // SAFETY: backing[off..off+4] is a full FILE_DISPOSITION_INFO_EX.
    let parsed = unsafe {
        parse_disposition_info(
            backing.as_ptr().add(off),
            built.len(),
            FILE_DISPOSITION_EX_INFO_CLASS,
        )
    };
    assert_eq!(parsed, Some((true, 0x9)));
}

/// Buffers too short for their class map to None (passthrough), and the
/// non-Ex class decodes its single delete byte with no ex flags.
#[test]
fn parse_disposition_info_class_discipline() {
    let b4 = [0u8; 4];
    // SAFETY: len equals the real buffer length in every call below.
    assert_eq!(
        unsafe { parse_disposition_info(b4.as_ptr(), 3, FILE_DISPOSITION_EX_INFO_CLASS) },
        None,
        "Ex class with < 4 bytes must be a passthrough",
    );
    let b1 = [1u8];
    assert_eq!(
        unsafe { parse_disposition_info(b1.as_ptr(), 0, FILE_DISPOSITION_INFO_CLASS) },
        None,
        "non-Ex class with 0 bytes must be a passthrough",
    );
    assert_eq!(
        unsafe { parse_disposition_info(b1.as_ptr(), 1, FILE_DISPOSITION_INFO_CLASS) },
        Some((true, 0)),
        "non-Ex DeleteFile=TRUE must want a delete and carry no ex flags",
    );
    let b0 = [0u8];
    assert_eq!(
        unsafe { parse_disposition_info(b0.as_ptr(), 1, FILE_DISPOSITION_INFO_CLASS) },
        Some((false, 0)),
    );
}
