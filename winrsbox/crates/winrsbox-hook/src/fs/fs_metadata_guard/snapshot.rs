// Owned snapshots of hooked request buffers (review S04,
// docs/review-xa-2026-09-20).
//
// REGRESSION CLASS (double fetch): the metadata hooks used to read the
// caller's buffer once for the policy DECISION and then hand the LIVE guest
// buffer back to the original syscall. A hostile (or merely unlucky)
// concurrent thread in the sandboxed process can swap the buffer bytes — or
// the UNICODE_STRING pointer itself — between the two reads, so the kernel
// acts on a path policy never approved. The fix is the same one the
// absolute-open half got (`HookedAttrs::copy_passthrough_inner` +
// `hooks::resolve_for_hook`): read the request EXACTLY ONCE into an owned
// snapshot BEFORE classification, and let both the decision and the syscall
// consume that snapshot. Nothing in here is ever read twice, and no pointer
// into guest memory survives the read.

use ntapi::winapi::shared::ntdef::HANDLE;
use ntapi::winapi::shared::ntdef::OBJECT_ATTRIBUTES;
use ntapi::winapi::shared::ntdef::UNICODE_STRING;
use winapi::ctypes::c_void;

use super::MAX_OBJECT_NAME_BYTES;

// ---------------------------------------------------------------------------
// NtDeleteFile snapshot
// ---------------------------------------------------------------------------

/// Owned copy of an `NtDeleteFile` request: every field the hook (or the
/// kernel, on passthrough) needs, copied out of the caller's
/// OBJECT_ATTRIBUTES chain in ONE pass. Holds no pointer into guest memory —
/// `security_descriptor`/`sqos` are the caller's opaque kernel-side pointers
/// passed through verbatim, never dereferenced by us.
pub(crate) struct DeleteRequest {
    pub(crate) root: HANDLE,
    pub(crate) attributes: u32,
    pub(crate) security_descriptor: *mut c_void,
    pub(crate) sqos: *mut c_void,
    pub(crate) maximum_length: u16,
    pub(crate) name_utf16: Vec<u16>,
}

impl DeleteRequest {
    /// Lossy UTF-16 decode of the snapshotted object name.
    pub(crate) fn name(&self) -> String {
        String::from_utf16_lossy(&self.name_utf16)
    }
}

/// Read the caller's OBJECT_ATTRIBUTES chain EXACTLY ONCE into a
/// [`DeleteRequest`]. Validation is fail-closed and IDENTICAL to the old
/// in-place `resolve_delete_target` walk: `None` (the hook then denies — a
/// delete whose request cannot be read is never forwarded to the kernel)
/// when attrs is null, ObjectName is null, Length is zero or odd, Length
/// exceeds MAX_OBJECT_NAME_BYTES, or Buffer is null.
///
/// No alignment is assumed anywhere: `attrs`, `ObjectName` and `Buffer` are
/// the hooked caller's addresses and a hostile caller controls all three —
/// every read is unaligned.
///
/// # SAFETY
/// `attrs` (non-null) must be readable as an OBJECT_ATTRIBUTES, its
/// `ObjectName` as a UNICODE_STRING, and that string's `Buffer` for `Length`
/// bytes — the NtDeleteFile contract at hook entry.
pub(crate) unsafe fn snapshot_delete_request(
    attrs: *const OBJECT_ATTRIBUTES,
) -> Option<DeleteRequest> {
    if attrs.is_null() {
        return None;
    }
    // SAFETY: read_unaligned of a non-null caller OBJECT_ATTRIBUTES pointer —
    // validity per the SAFETY contract; alignment never assumed.
    let obj = (attrs as *const OBJECT_ATTRIBUTES).read_unaligned();
    if obj.ObjectName.is_null() {
        return None;
    }
    // SAFETY: read_unaligned of the caller's non-null UNICODE_STRING pointer.
    let ustr = (obj.ObjectName as *const UNICODE_STRING).read_unaligned();
    let byte_len = ustr.Length as usize;
    if byte_len == 0 || byte_len % 2 != 0 || byte_len > MAX_OBJECT_NAME_BYTES || ustr.Buffer.is_null() {
        return None;
    }
    // SAFETY: Buffer is non-null and at least Length bytes long per the
    // UNICODE_STRING contract, validated above; each WCHAR is read with
    // read_unaligned, so an odd Buffer address stays well-defined.
    let name_utf16: Vec<u16> = (0..byte_len / 2)
        .map(|i| (ustr.Buffer.cast::<u8>().add(i * 2) as *const u16).read_unaligned())
        .collect();
    Some(DeleteRequest {
        root: obj.RootDirectory,
        attributes: obj.Attributes,
        security_descriptor: obj.SecurityDescriptor,
        sqos: obj.SecurityQualityOfService,
        maximum_length: ustr.MaximumLength.max(ustr.Length),
        name_utf16,
    })
}

// ---------------------------------------------------------------------------
// FILE_RENAME/LINK_INFORMATION snapshot
// ---------------------------------------------------------------------------

/// Owned copy of a FILE_RENAME_INFORMATION / FILE_LINK_INFORMATION (or Ex)
/// request: the ReplaceIfExists/Flags header word (bytes 0x00..0x08, copied
/// verbatim so the caller's replace semantics survive any rewrite), the
/// RootDirectory handle, and the FileName decoded to owned UTF-16.
pub(crate) struct RenameRequest {
    pub(crate) header8: [u8; 8],
    pub(crate) root: HANDLE,
    pub(crate) name_utf16: Vec<u16>,
}

impl RenameRequest {
    /// Lossy UTF-16 decode of the snapshotted FileName.
    pub(crate) fn name(&self) -> String {
        String::from_utf16_lossy(&self.name_utf16)
    }
}

/// Read the caller's rename/link information buffer EXACTLY ONCE into a
/// [`RenameRequest`]. Validation and offsets are byte-identical to the old
/// in-place `parse_rename_info`: `None` (the hook then passes the call
/// through to the original syscall untouched) when the buffer is shorter
/// than the fixed 0x14 header, the name length is zero or absurd
/// (> 0x8000 bytes), or the name would run past the declared buffer length.
/// No new rejections — behavior compatibility with the pre-S04 parser.
///
/// Every field read is unaligned: the buffer is caller-owned memory handed
/// to NtSetInformationFile by the sandboxed process, so neither its base
/// alignment nor any field offset within it is guaranteed. The header word
/// copy is a plain u8 slice copy (alignment 1 — always fine).
///
/// # SAFETY
/// `info` must be readable for `len` bytes (the NtSetInformationFile contract
/// at hook entry).
pub(crate) unsafe fn snapshot_rename_request(info: *const u8, len: usize) -> Option<RenameRequest> {
    // Layout for non-Ex (RENAME/LINK):
    //   0x00: ReplaceIfExists (BOOLEAN)
    //   0x08: RootDirectory (HANDLE)
    //   0x10: FileNameLength (ULONG)
    //   0x14: FileName[] (WCHAR)
    // Layout for Ex (RENAME_EX/LINK_EX):
    //   0x00: Flags (ULONG)
    //   0x08: RootDirectory (HANDLE)
    //   0x10: FileNameLength (ULONG)
    //   0x14: FileName[] (WCHAR)
    // Both variants share the header word at 0x00, RootDirectory at 0x08,
    // FileNameLength at 0x10, FileName at 0x14.
    const OFF_ROOT: usize = 0x08;
    const OFF_NAMELEN: usize = 0x10;
    const OFF_NAME: usize = 0x14;
    if len < OFF_NAME {
        return None;
    }
    // SAFETY: OFF_ROOT + size_of::<HANDLE>() == 0x10 <= len (checked above).
    let root = (info.add(OFF_ROOT) as *const HANDLE).read_unaligned();
    // SAFETY: OFF_NAMELEN + 4 == 0x14 <= len (checked above).
    let name_len = (info.add(OFF_NAMELEN) as *const u32).read_unaligned() as usize;
    if name_len == 0 || name_len > 0x8000 {
        return None;
    }
    // Bounds check: FileName buffer must fit within declared Length.
    if OFF_NAME + name_len > len {
        return None;
    }
    // SAFETY: bytes 0x00..0x08 lie within the validated buffer (len >= 0x14);
    // a u8 slice copy has alignment 1, so an odd base address stays defined.
    let mut header8 = [0u8; 8];
    header8.copy_from_slice(std::slice::from_raw_parts(info, 8));
    // SAFETY: OFF_NAME + name_len <= len was checked above, so the WCHAR
    // reads below stay inside the caller's buffer; each is unaligned, so an
    // odd buffer address stays well-defined.
    let name_ptr = info.add(OFF_NAME) as *const u16;
    let chars = name_len / 2;
    let name_utf16: Vec<u16> = (0..chars)
        .map(|i| {
            // SAFETY: i < chars and OFF_NAME + name_len <= len, so every
            // read stays inside the caller's buffer.
            unsafe { name_ptr.add(i).read_unaligned() }
        })
        .collect();
    Some(RenameRequest { header8, root, name_utf16 })
}

/// Build a caller-independent FILE_RENAME_INFORMATION-family buffer whose
/// RootDirectory is NULL and whose FileName is the ABSOLUTE NT form of the
/// resolved + policy-approved destination — decoded from the OWNED snapshot
/// (S04), never from a second read of the caller's buffer.
///
/// Layout (rename and link, non-Ex and Ex — byte-identical from 0x08 up):
///   0x00: ReplaceIfExists / Flags (8 bytes, verbatim from `snap`)
///   0x08: RootDirectory = NULL
///   0x10: FileNameLength (bytes, excluding the terminator)
///   0x14: FileName[] (UTF-16, NUL-terminated)
///
/// Returns the new buffer and its total length. `None` when the NT name of
/// `dest_dos_lower` would exceed 0x7FFF UTF-16 units (excluding the NUL) —
/// the same discipline a UNICODE_STRING Length (u16) imposes; the caller
/// must fail closed, never fall back to the caller's buffer.
pub(crate) fn build_kernel_rename_buffer(
    snap: &RenameRequest,
    dest_dos_lower: &str,
) -> Option<(Vec<u8>, u32)> {
    let nt_name = policy::path::dos_to_nt(dest_dos_lower);
    debug_assert!(nt_name.last() == Some(&0), "dos_to_nt NUL-terminates");
    // Mirrors the UNICODE_STRING u16 discipline: an NT name longer than
    // 0x7FFF units cannot be carried by the kernel's name machinery. Keep
    // this rejection so the call site's fail-closed rewrite-failed path
    // stays alive (non-dead).
    if nt_name.len() - 1 > 0x7FFF {
        return None;
    }
    let mut out = Vec::with_capacity(0x14 + nt_name.len() * 2);
    out.extend_from_slice(&snap.header8); // ReplaceIfExists / Flags verbatim
    out.extend_from_slice(&0u64.to_ne_bytes()); // RootDirectory = NULL
    // FileNameLength counts the name bytes only, not the NUL terminator.
    out.extend_from_slice(&(((nt_name.len() - 1) * 2) as u32).to_le_bytes());
    for w in &nt_name {
        out.extend_from_slice(&w.to_le_bytes());
    }
    Some((out, (0x14 + nt_name.len() * 2) as u32))
}
