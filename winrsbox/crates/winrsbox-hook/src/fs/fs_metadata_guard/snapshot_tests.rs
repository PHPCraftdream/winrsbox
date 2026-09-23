// S04 snapshot regression tests (fs_metadata_guard).
//
// Lives in its own `#[cfg(test)]` module (declared in mod.rs, brief C7) to
// keep `tests.rs` under the 1000-line budget; the declaration also keeps
// this file out of `hooks::module_source` concatenations, so the textual
// pins are unaffected by anything written here.

use super::tests::{build_rename_info, odd_window};
use super::*;

/// Inside project_root the original syscall must receive an OWNED attrs built
/// from the pre-decision snapshot — same logical request (root, flags, name),
/// but no live guest pointer: a post-decision swap of the caller's buffer
/// cannot retarget the delete (S04). Before S04 this test pinned the defect
/// (pointer identity with the caller's attrs).
#[test]
fn nt_delete_passthrough_forwards_snapshot_attrs_to_original() {
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
    // Snapshot BEFORE the swap — this is the request classification read.
    // SAFETY: caller_attrs is a live OBJECT_ATTRIBUTES whose name chain is
    // valid for its Length bytes.
    let snap =
        unsafe { snapshot_delete_request(&caller_attrs) }.expect("snapshot before swap");

    // Concurrent swap after the decision: contents AND pointer.
    for c in caller_name.iter_mut() { *c = u16::from(b'X'); }
    let mut evil: Vec<u16> = r"\??\C:\windows\evil.txt".encode_utf16().collect();
    let mut evil_ustr = UNICODE_STRING {
        Length: (evil.len() * 2) as u16,
        MaximumLength: (evil.len() * 2 + 2) as u16,
        Buffer: evil.as_mut_ptr(),
    };
    caller_attrs.ObjectName = &mut evil_ustr;

    let mut seen_root_null = false;
    let mut seen_attrs: u32 = 0;
    let mut seen_name: Option<Vec<u16>> = None;
    let result = unsafe {
        apply_delete_decision(
            &snap,
            r"c:\project\file.txt",
            &decision,
            |a| {
                // SAFETY: the attrs handed to `original` are our own aligned
                // rebuild; the name chain is valid for its Length bytes.
                let oa = &*a;
                seen_root_null = oa.RootDirectory.is_null();
                seen_attrs = oa.Attributes;
                let us = &*oa.ObjectName;
                seen_name = Some(
                    std::slice::from_raw_parts(us.Buffer, (us.Length / 2) as usize).to_vec(),
                );
                0x1234
            },
        )
    };
    assert!(seen_root_null, "seen RootDirectory must be the snapshot's null root");
    assert_eq!(seen_attrs, 0x40, "seen Attributes must come from the snapshot");
    assert_eq!(
        seen_name.as_deref().map(String::from_utf16_lossy).as_deref(),
        Some(r"\??\C:\project\file.txt"),
        "the kernel must delete the DECIDED snapshot name, not swapped guest bytes",
    );
    assert_eq!(result, DeleteResult::Status(0x1234));
}

/// S04 behavioral: the kernel-bound rename buffer is decoded from the
/// SNAPSHOT bytes. Swapping the caller's buffer after the snapshot (bytes
/// and RootDirectory) must not leak into what the kernel receives.
#[test]
fn s04_rename_kernel_buffer_comes_from_snapshot_not_reread() {
    let decided = r"\??\C:\project\keep.txt";
    let built = build_rename_info(0, decided);
    let (mut backing, off) = odd_window(&built);
    // SAFETY: backing[off..off+built.len()] holds a full rename-info buffer.
    let snap = unsafe { snapshot_rename_request(backing.as_ptr().add(off), built.len()) }
        .expect("well-formed buffer must snapshot");
    // Concurrent swap: rewrite the guest window with a different root + name
    // (same length, so the whole window is overwritten).
    let evil = build_rename_info(0xBADF00, r"\??\C:\windows\keep.tx0");
    assert_eq!(built.len(), evil.len(), "swap probe must be length-identical");
    // SAFETY: evil.len() == built.len(), so the copy stays inside the window.
    unsafe {
        std::ptr::copy_nonoverlapping(evil.as_ptr(), backing.as_mut_ptr().add(off), evil.len())
    };
    let (buf, len) = build_kernel_rename_buffer(&snap, r"c:\project\keep.txt")
        .expect("approved dest must build");
    assert_eq!(len as usize, buf.len());
    assert_eq!(&buf[0x00..0x08], &snap.header8, "header word verbatim from the snapshot");
    assert_eq!(&buf[0x08..0x10], &[0u8; 8], "RootDirectory nulled");
    // FileName is the NT form of the DECIDED dest, not the swapped-in evil name.
    let name_bytes = &buf[0x14..len as usize - 2]; // exclude NUL
    let name: Vec<u16> =
        name_bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    assert_eq!(String::from_utf16_lossy(&name), r"\??\c:\project\keep.txt");
    // FileNameLength field agrees.
    let flen = u32::from_le_bytes(buf[0x10..0x14].try_into().unwrap());
    assert_eq!(flen as usize, name.len() * 2);
}
