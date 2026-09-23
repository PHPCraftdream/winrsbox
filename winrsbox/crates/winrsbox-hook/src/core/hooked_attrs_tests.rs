// ---------------------------------------------------------------------------
// Review C03 regression tests (docs/review-xa-2026-09-20, P2).
//
// e491803 fixed `resolve_for_hook` to resolve an EMPTY ObjectName to the
// RootDirectory's own path — the shape Rust's `remove_dir_all` opens with
// (empty name + RootDirectory naming the directory itself). The passthrough
// CONSUMER `copy_passthrough_inner` kept refusing that shape
// (ObjectName=NULL / Buffer=NULL / Length=0) before ever looking at the
// pre-resolved path, so on the passthrough branch (directory under
// project_root — legitimately NOT redirected to the overlay) the open still
// died as STATUS_ACCESS_DENIED at the fs_hooks call site.
//
// Lives in a sibling file: hooked_attrs.rs is near the workspace's
// 1000-line file budget.
// ---------------------------------------------------------------------------
use super::*;

use crate::hooks::resolve_for_hook;

/// The full two-stage pipeline the NtCreateFile/NtOpenFile passthrough arms
/// run (fs_hooks/detours.rs): `resolve_for_hook` on a remove_dir_all-shaped
/// open (empty name + RootDirectory), then `copy_passthrough_inner` with the
/// resolver's pre-resolved absolute path. Stage 1 is e491803's fix and must
/// already pass; stage 2 is the C03 consumer fix and must yield Some with
/// the kernel opening exactly the pre-resolved path, RootDirectory nulled,
/// and every non-path field preserved — not the pre-fix None that the call
/// site turns into STATUS_ACCESS_DENIED.
#[test]
fn pre_resolved_empty_name_open_passes_through() {
    use std::os::windows::ffi::OsStrExt;

    let dir = std::env::temp_dir().join("winrsbox-c03-passthrough-probe");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create probe dir");

    // A directory handle needs FILE_FLAG_BACKUP_SEMANTICS (same probe
    // pattern as the e491803 resolver test in
    // hooks/checks/hooks_core_security_tests.rs).
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` is a NUL-terminated path; all other arguments are
    //         the documented constants for opening a directory handle.
    let handle = unsafe {
        winapi::um::fileapi::CreateFileW(
            wide.as_ptr(),
            winapi::um::winnt::GENERIC_READ,
            winapi::um::winnt::FILE_SHARE_READ
                | winapi::um::winnt::FILE_SHARE_WRITE
                | winapi::um::winnt::FILE_SHARE_DELETE,
            std::ptr::null_mut(),
            winapi::um::fileapi::OPEN_EXISTING,
            0x0200_0000, // FILE_FLAG_BACKUP_SEMANTICS — required for a directory handle
            std::ptr::null_mut(),
        )
    };
    assert!(
        handle != winapi::um::handleapi::INVALID_HANDLE_VALUE,
        "could not open a directory handle for the probe",
    );

    // remove_dir_all shape: RootDirectory = the directory handle, ObjectName
    // pointing at an EMPTY UNICODE_STRING (Length 0, Buffer null).
    let empty_ustr = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    let orig = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: handle as *mut _,
        ObjectName: &empty_ustr as *const UNICODE_STRING as *mut UNICODE_STRING,
        Attributes: 0x42,
        SecurityDescriptor: 0xAAAA_BBBB as *mut _,
        SecurityQualityOfService: 0xCCCC_DDDD as *mut _,
    };

    // ── Stage 1 — the resolver (e491803) ────────────────────────────────────
    let resolved = unsafe { resolve_for_hook(&orig) };
    let (dos, pre_resolved) = match resolved {
        Some(r) => r,
        None => {
            // SAFETY: handle came from CreateFileW above and is not used after.
            unsafe { winapi::um::handleapi::CloseHandle(handle) };
            let _ = std::fs::remove_dir_all(&dir);
            panic!("e491803 regression: empty name + RootDirectory must resolve");
        }
    };
    let pre = match pre_resolved {
        Some(p) => p,
        None => {
            // SAFETY: handle came from CreateFileW above and is not used after.
            unsafe { winapi::um::handleapi::CloseHandle(handle) };
            let _ = std::fs::remove_dir_all(&dir);
            panic!("relative open must carry a pre-resolved path for the kernel");
        }
    };
    assert_eq!(
        dos,
        dir.to_string_lossy().to_ascii_lowercase(),
        "resolved path must be the directory itself",
    );

    // ── Stage 2 — the passthrough CONSUMER under test (C03) ────────────────
    // Both empty-name shapes resolve_for_hook legalizes must be accepted:
    // a non-null ObjectName pointing at an EMPTY UNICODE_STRING, and a fully
    // NULL ObjectName.
    let object_name_variants: [(&str, *mut UNICODE_STRING); 2] = [
        ("empty UNICODE_STRING", &empty_ustr as *const UNICODE_STRING as *mut UNICODE_STRING),
        ("NULL ObjectName", std::ptr::null_mut()),
    ];
    let mut results: Vec<(&str, Option<HookedAttrs>)> = Vec::new();
    for (label, object_name) in object_name_variants {
        let orig = OBJECT_ATTRIBUTES {
            ObjectName: object_name,
            ..orig
        };
        // SAFETY: orig is a valid OBJECT_ATTRIBUTES; RootDirectory is a live
        // directory handle for the duration of this call (closed below).
        let copied = unsafe { HookedAttrs::copy_passthrough_inner(&orig, Some(pre.as_slice())) };
        results.push((label, copied));
    }
    // SAFETY: handle is the one opened above; close it before any assertion
    // can fail so we never leak it.
    unsafe { winapi::um::handleapi::CloseHandle(handle) };
    let _ = std::fs::remove_dir_all(&dir);

    for (label, copied) in results {
        let mut h = copied.unwrap_or_else(|| {
            panic!(
                "C03: pre-resolved empty-name relative open ({label}) must pass \
                 through, not fail closed into STATUS_ACCESS_DENIED"
            )
        });
        let attrs = unsafe { &*h.as_ptr_mut() };
        // The racy handle anchor must be gone (H5 contract preserved).
        assert!(
            attrs.RootDirectory.is_null(),
            "{label}: RootDirectory must be nulled once the path is absolute"
        );
        // The kernel-visible name is EXACTLY the pre-resolved path.
        let ustr = unsafe { &*attrs.ObjectName };
        let n = (ustr.Length / 2) as usize;
        assert_eq!(n, pre.len(), "{label}: Length must carry the pre-resolved path");
        // SAFETY: ustr.Buffer points into h.nt_buf (alive, self-referential
        // invariant), holding at least n u16s.
        let kernel_path = unsafe { std::slice::from_raw_parts(ustr.Buffer, n) };
        assert_eq!(
            kernel_path, &pre[..],
            "{label}: kernel must open the pre-resolved path verbatim",
        );
        assert_eq!(
            kernel_path, &h.nt_buf[..],
            "{label}: hook-owned buffer must hold the pre-resolved path",
        );
        // Non-path fields preserved verbatim (same contract as the
        // named-open H5 branch).
        assert_eq!(attrs.Attributes, 0x42, "{label}: Attributes preserved");
        assert_eq!(
            attrs.SecurityDescriptor as usize, 0xAAAA_BBBB,
            "{label}: SecurityDescriptor preserved",
        );
        assert_eq!(
            attrs.SecurityQualityOfService as usize, 0xCCCC_DDDD,
            "{label}: SecurityQualityOfService preserved",
        );
    }
}

/// The C03 carve-out must not weaken the genuine refusals. The carve-out is
/// exactly "a pre-resolved RELATIVE open" — both residual empty-name shapes
/// still fail closed (the call sites turn None into STATUS_ACCESS_DENIED).
#[test]
fn empty_name_still_refused_without_preresolved_or_relative_anchor() {
    let empty_ustr = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };

    // Shape A: empty name + non-null RootDirectory but NO pre-resolution
    // (the resolver failed / standalone callers). Fail closed, unchanged.
    // The fabricated handle value is never queried on this path: the
    // original-name refusal fires before any handle resolution.
    let orig_relative = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        // `dangling_mut()` is address 1 for a void pointer: a non-null
        // fabricated handle, exactly the `0x1 as *mut _` shape, without the
        // clippy::manual_dangling_ptr warning.
        RootDirectory: std::ptr::dangling_mut(),
        ObjectName: &empty_ustr as *const UNICODE_STRING as *mut UNICODE_STRING,
        Attributes: 0,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    assert!(
        unsafe { HookedAttrs::copy_passthrough_inner(&orig_relative, None) }.is_none(),
        "empty name with no pre-resolution must stay refused (fail closed)",
    );

    // Shape B: a pre-resolved path IS present but RootDirectory is NULL —
    // the verbatim-copy branch consumes the original name, which is empty,
    // so there is nothing to copy and the kernel would open a bare empty
    // name against the process CWD. Refusal must stay.
    let pre: Vec<u16> = "\\??\\c:\\some\\dir".encode_utf16().collect();
    let orig_absolute = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: &empty_ustr as *const UNICODE_STRING as *mut UNICODE_STRING,
        Attributes: 0,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    assert!(
        unsafe { HookedAttrs::copy_passthrough_inner(&orig_absolute, Some(pre.as_slice())) }
            .is_none(),
        "empty name with null RootDirectory must stay refused (name is consumed)",
    );
}

/// S04 (docs/review-xa-2026-09-20, P1): an ABSOLUTE open used to return
/// `pre_resolved = None`, so the policy decided on the guest's ObjectName
/// buffer while the passthrough kernel call RE-READ that same hostile buffer
/// in `copy_passthrough_inner`. A concurrent guest thread swapping the
/// buffer contents or the ObjectName POINTER between the decision and the
/// syscall could make the kernel open a path policy never approved.
/// Contract: the kernel must see exactly the decided bytes — a swap after
/// `resolve_for_hook` must be invisible to the kernel call.
#[test]
fn s04_absolute_open_decided_then_swapped_kernel_sees_decided_path() {
    // Decided request: an absolute NT open of an in-project path.
    let decided: Vec<u16> = r"\??\C:\proj\src\main.rs".encode_utf16().collect();
    let mut guest = decided.clone();
    let mut guest_ustr = UNICODE_STRING {
        Length: (guest.len() * 2) as u16,
        MaximumLength: (guest.len() * 2 + 2) as u16,
        Buffer: guest.as_mut_ptr(),
    };
    let mut orig = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: &mut guest_ustr,
        Attributes: 0x42,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };

    // Classification: reads the guest buffer once and (per S04) must hand
    // back the same bytes as the pre-resolved snapshot for the kernel call.
    let (dos, pre_resolved) = unsafe { resolve_for_hook(&orig) }.expect("absolute open must resolve");
    assert_eq!(dos, r"c:\proj\src\main.rs");
    let pre = pre_resolved.expect(
        "S04: an absolute open must carry the decided snapshot for the kernel call; \
         None lets copy_passthrough_inner re-read the hostile buffer",
    );
    assert_eq!(pre, decided, "snapshot must be exactly the decided bytes");

    // A concurrent guest thread swaps BOTH the buffer contents and the
    // ObjectName pointer after the decision, before the kernel call.
    for c in guest.iter_mut() { *c = u16::from(b'X'); }
    let mut evil: Vec<u16> = r"\??\C:\windows\system32\evil.dll".encode_utf16().collect();
    let mut evil_ustr = UNICODE_STRING {
        Length: (evil.len() * 2) as u16,
        MaximumLength: (evil.len() * 2 + 2) as u16,
        Buffer: evil.as_mut_ptr(),
    };
    orig.ObjectName = &mut evil_ustr;

    // The passthrough construction must consume the SNAPSHOT, never the
    // (now swapped) guest buffer.
    let copied =
        unsafe { HookedAttrs::copy_passthrough_inner(&orig, Some(pre.as_slice())) }
            .expect("snapshot passthrough must build");
    // SAFETY: copied is self-referential (ustr.Buffer points into the owned
    // nt_buf, alive for at least Length/2 u16s).
    let kernel = unsafe {
        std::slice::from_raw_parts(copied.ustr.Buffer, (copied.ustr.Length / 2) as usize)
    }
    .to_vec();
    assert_eq!(kernel, decided, "kernel must open exactly the decided path (S04)");
    assert!(kernel.iter().all(|&c| c != u16::from(b'X')), "swapped-in bytes must not reach the kernel");
    assert_ne!(kernel, evil, "swapped-in pointer must not reach the kernel");
    assert!(copied.attrs.RootDirectory.is_null(), "absolute snapshot open carries no handle");
    assert_eq!(copied.attrs.Attributes, 0x42, "non-path fields preserved");
}
