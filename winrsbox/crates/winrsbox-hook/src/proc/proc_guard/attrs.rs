use super::{c_void, ipc_log, is_denylisted, is_trace};
use super::{PS_ATTRIBUTE, PS_ATTRIBUTE_LIST};
use winapi::um::memoryapi::VirtualQuery;
use winapi::um::winnt::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};

// ---------------------------------------------------------------------------
// Parent-PID spoof detection via PS_ATTRIBUTE_LIST
// ---------------------------------------------------------------------------

/// Check if the attribute list contains PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
///
/// This is a spawn VETO: it also returns true when the list's
/// `PsAttributeImageName` record (number 5) names a denylisted executable —
/// see `attr5_image_denied` for why attribute 5 is the authoritative source.
///
/// The PS_ATTRIBUTE encoding: `Attribute = (number) | (input ? 0x20000 : 0) | ...`.
/// PsAttributeParentProcess has number 0 in the NT attribute table.
/// In the PS_ATTRIBUTE_LIST passed to NtCreateUserProcess, the encoded value
/// uses 0x00020000 (PsAttributeParentProcess | PS_ATTRIBUTE_INPUT).
/// We match on the lower 16 bits == 0 (PsAttributeParentProcess number).
pub fn attribute_list_contains_parent_process(attr_list: *const c_void) -> bool {
    if attr_list.is_null() {
        return false;
    }
    let Some(count) = attr_count(attr_list) else {
        return false;
    };
    // SAFETY: attr_count validated that attr_list is readable and that
    // `count` whole records fit in the readable extent after TotalLength.
    let attrs = unsafe { (*(attr_list as *const PS_ATTRIBUTE_LIST)).Attributes.as_ptr() };
    for i in 0..count {
        // SAFETY: i < count, clamped by attr_count to the readable extent.
        let attr = unsafe { &*attrs.add(i) };
        // PsAttributeParentProcess number = 0, encoded with input flag = 0x20000.
        // Match lower 16 bits == 0 — this is the attribute number.
        if (attr.Attribute & 0xFFFF) == 0 && attr.Value != 0 {
            return true;
        }
    }
    attr5_image_denied(attr_list)
}

// ---------------------------------------------------------------------------
// Handle-list inheritance detection via PS_ATTRIBUTE_LIST
// ---------------------------------------------------------------------------

/// Check if the attribute list contains PROC_THREAD_ATTRIBUTE_HANDLE_LIST.
///
/// This is a spawn VETO: it also returns true when the list's
/// `PsAttributeImageName` record (number 5) names a denylisted executable —
/// see `attr5_image_denied` for why attribute 5 is the authoritative source.
///
/// PsAttributeHandleList has attribute number 2 in the NT attribute table.
/// The encoded value uses 0x00020002 (number=2 | PS_ATTRIBUTE_INPUT).
/// We match on the lower 16 bits == 2 (PsAttributeHandleList number).
pub fn attribute_list_contains_handle_list(attr_list: *const c_void) -> bool {
    if attr_list.is_null() {
        return false;
    }
    let Some(count) = attr_count(attr_list) else {
        return false;
    };
    // SAFETY: attr_count validated that attr_list is readable and that
    // `count` whole records fit in the readable extent after TotalLength.
    let attrs = unsafe { (*(attr_list as *const PS_ATTRIBUTE_LIST)).Attributes.as_ptr() };
    for i in 0..count {
        // SAFETY: i < count, clamped by attr_count to the readable extent.
        let attr = unsafe { &*attrs.add(i) };
        if (attr.Attribute & 0xFFFF) == 2 {
            return true;
        }
    }
    attr5_image_denied(attr_list)
}

// ---------------------------------------------------------------------------
// PS_ATTRIBUTE_LIST introspection (C0/C1: spawn-overlay-redirect support)
// ---------------------------------------------------------------------------

/// Bounds-checked walk returning a mutable pointer to the
/// `PsAttributeImageName` record (attribute number 5) in `attr_list`, or
/// `None` if the list is null/malformed or has no such record.
///
/// The record's `Value` is a raw `PWSTR` and `Size` is its byte length
/// excluding the trailing NUL — confirmed empirically by the C0 diagnostic
/// dump (`dump_attr_list_for_overlay_spawn`). Callers (C2 guard) swap Value
/// and Size to point the kernel image loader at the CoW overlay copy.
///
/// # Safety
/// `attr_list` must be a valid `PS_ATTRIBUTE_LIST` pointer for the duration of
/// the borrow (the caller owns it across the NtCreateUserProcess call). The
/// returned pointer aliases `attr_list` and must not outlive it.
pub(crate) unsafe fn image_name_attr_mut(attr_list: *mut c_void) -> Option<*mut PS_ATTRIBUTE> {
    let count = attr_count(attr_list)?;
    let list = attr_list as *mut PS_ATTRIBUTE_LIST;
    // SAFETY: attr_list is valid per caller contract; Attributes[0] begins a
    // contiguous run of `count` records after TotalLength.
    let attrs = unsafe { (*list).Attributes.as_mut_ptr() };
    for i in 0..count {
        // SAFETY: i < count, validated by attr_count against TotalLength.
        let attr = unsafe { &mut *attrs.add(i) };
        if (attr.Attribute & 0xFFFF) == 5 {
            return Some(attrs.add(i));
        }
    }
    None
}

/// Bounds-checked walk of the attribute list, returning the count of attribute
/// records (excluding the leading `TotalLength` field). Returns `None` if the
/// list is null, malformed (TotalLength too small), or not backed by readable
/// memory.
///
/// `TotalLength` is caller-controlled, so it is CLAMPED to the readable extent
/// of the buffer's memory region before it is used to derive the record count
/// (audit 2026-09-19, Medium): a hostile length must never drive the walk off
/// the mapping — an access violation inside a hook kills the process, since
/// nothing wraps hook bodies in SEH. Only whole records that fit BOTH the
/// declared length and the readable region are counted.
///
/// Pure + shared between the C0 diagnostic dump and the C1 mutator.
fn attr_count(attr_list: *const c_void) -> Option<usize> {
    if attr_list.is_null() {
        return None;
    }
    let (base, len) = readable_region(attr_list)?;
    // SAFETY: attr_list points into a committed, readable region (checked
    // just above), so reading the TotalLength header is in-bounds.
    let declared = unsafe { (*(attr_list as *const PS_ATTRIBUTE_LIST)).TotalLength };
    if declared < std::mem::size_of::<usize>() {
        return None;
    }
    let off = attr_list as usize - base as usize;
    let avail_after_header =
        len.checked_sub(off)?.checked_sub(std::mem::size_of::<usize>())?;
    let total = declared.min(avail_after_header);
    let count = total / std::mem::size_of::<PS_ATTRIBUTE>();
    if count == 0 {
        None
    } else {
        Some(count)
    }
}

/// Readable-region query for a caller-supplied pointer.
///
/// Returns `(base, len)` of the committed, currently-readable memory region
/// containing `addr`, or `None` when the address is null, unqueryable, or not
/// in a readable region. Every caller-controlled length in this module is
/// clamped through this before it is followed.
///
/// `pub(crate)` so hooks.rs can clamp the spawn-time guard-environment walk
/// (audit 2026-09-19 High) through the same vetted probe.
pub(crate) fn readable_region(addr: *const c_void) -> Option<(*const u8, usize)> {
    if addr.is_null() {
        return None;
    }
    // SAFETY: `mbi` is a plain C POD; all-bits-zero is a valid initial state
    // and VirtualQuery fully overwrites it on success.
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `mbi` is valid for writes of its size for the duration of the call.
    let got = unsafe {
        VirtualQuery(addr, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>())
    };
    if got == 0 {
        return None;
    }
    if mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) != 0 {
        return None;
    }
    const READABLE: u32 = PAGE_READONLY
        | PAGE_READWRITE
        | PAGE_WRITECOPY
        | PAGE_EXECUTE_READ
        | PAGE_EXECUTE_READWRITE
        | PAGE_EXECUTE_WRITECOPY;
    if (mbi.Protect & READABLE) == 0 {
        return None;
    }
    let base = mbi.BaseAddress as usize;
    let end = base.checked_add(mbi.RegionSize)?;
    let a = addr as usize;
    if a < base || a >= end {
        return None;
    }
    Some((base as *const u8, mbi.RegionSize))
}

/// Veto on the `PsAttributeImageName` attribute record (number 5).
///
/// The kernel image loader opens the child EXE by the path in THIS record,
/// not by `RTL_USER_PROCESS_PARAMETERS.ImagePathName` (offset 0x60, which is
/// informational PEB data a guest controls independently) — so the spawn
/// denylist must match this record, else a guest decoys ImagePathName while
/// attribute 5 names a denylisted binary (audit 2026-09-19, High). Value is a
/// raw PWSTR and Size is the byte length excluding the trailing NUL,
/// confirmed empirically by the C0 diagnostic dump.
///
/// A mismatch between the two sources needs no separate veto: both are
/// denylist-checked independently and the kernel only ever loads attribute 5,
/// so a decoy can only cause over-blocking, never a bypass.
///
/// Returns true when the record is present, readable, and denylisted.
/// Absent/unreadable records yield false: without a usable image name the
/// kernel itself cannot load an image, so the syscall fails downstream.
fn attr5_image_denied(attr_list: *const c_void) -> bool {
    let Some(name) = image_name_from_attr_list(attr_list) else {
        return false;
    };
    if !is_denylisted(&name) {
        return false;
    }
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace,
            format!("spawn_image_attr_denied: {name}"));
    }
    true
}

/// Extract the `PsAttributeImageName` (attribute number 5) value as a String.
///
/// Every length is validated against the actual buffer before it is followed:
/// the record count via `attr_count` (clamped to the readable region), and the
/// record's `Size` via a `readable_region` check of `Value` (clamped to the
/// readable extent, capped at 0x10000 bytes like the C0 dump). Null /
/// odd-sized / oversized / unreadable → None — the same defensive standard as
/// `extract_image_path`. Never dereferences outside a validated region.
pub(crate) fn image_name_from_attr_list(attr_list: *const c_void) -> Option<String> {
    let count = attr_count(attr_list)?;
    // SAFETY: attr_count validated that attr_list is readable and that
    // `count` whole records fit in the readable extent after TotalLength.
    let attrs = unsafe { (*(attr_list as *const PS_ATTRIBUTE_LIST)).Attributes.as_ptr() };
    for i in 0..count {
        // SAFETY: i < count, clamped by attr_count to the readable extent.
        let attr = unsafe { &*attrs.add(i) };
        if (attr.Attribute & 0xFFFF) != 5 {
            continue;
        }
        let ptr = attr.Value as *const u16;
        if ptr.is_null() || attr.Size == 0 || attr.Size % 2 != 0 || attr.Size > 0x1_0000 {
            return None;
        }
        let (base, len) = readable_region(ptr as *const c_void)?;
        let off = ptr as usize - base as usize;
        let avail_chars = len.checked_sub(off)? / 2;
        let chars = (attr.Size / 2).min(avail_chars);
        if chars == 0 {
            return None;
        }
        // SAFETY: ptr points to `chars` readable UTF-16 units: chars is at
        // most Size/2 (declared) and at most the region-clamped avail_chars.
        let slice = unsafe { std::slice::from_raw_parts(ptr, chars) };
        let mut name = String::from_utf16_lossy(slice);
        if name.ends_with('\0') {
            name.pop();
        }
        if name.is_empty() {
            return None;
        }
        return Some(name);
    }
    None
}

/// C0 diagnostic: dump every attribute record in `attr_list` to the trace log,
/// with extra detail for the PsAttributeImageName record (number 5). Used to
/// confirm the presence and the Value-convention (raw PWSTR + byte Size vs a
/// UNICODE_STRING pointer) BEFORE the C2 patch decides how to mutate it.
///
/// `target` is the virtual exe path (for correlation with spawn_attempt).
pub(crate) fn dump_attr_list_for_overlay_spawn(attr_list: *const c_void, target: &str) {
    let Some(count) = attr_count(attr_list) else {
        ipc_log(ipc::LogLevel::Trace,
            format!("attr_list_dump: target={target} EMPTY_OR_MALFORMED"));
        return;
    };
    // SAFETY: attr_list is valid; Attributes[0] is the first of `count` records
    // laid out contiguously after TotalLength.
    let list = attr_list as *const PS_ATTRIBUTE_LIST;
    let attrs = unsafe { (*list).Attributes.as_ptr() };
    ipc_log(ipc::LogLevel::Trace,
        format!("attr_list_dump: target={target} attr_count={count}"));
    for i in 0..count {
        // SAFETY: i < count, validated above against the declared TotalLength.
        let attr = unsafe { &*attrs.add(i) };
        let num = attr.Attribute & 0xFFFF;
        let is_image_name = num == 5; // PsAttributeImageName
        // For the image-name record, Value is a raw PWSTR (per the standard
        // CreateProcessInternalW path) and Size is the byte length excluding
        // the trailing NUL. Read it defensively to confirm.
        let value_desc = if is_image_name {
            let ptr = attr.Value as *const u16;
            if !ptr.is_null() && attr.Size > 0 && attr.Size <= 0x10000 {
                // Clamp to the readable extent of Value — Size is
                // caller-controlled (audit 2026-09-19, Medium).
                let chars = match readable_region(ptr as *const c_void) {
                    Some((base, len)) => {
                        let off = ptr as usize - base as usize;
                        (attr.Size / 2).min(len.saturating_sub(off) / 2)
                    }
                    None => 0,
                };
                if chars > 0 {
                    // SAFETY: chars <= Size/2 and clamped to the readable
                    // region by readable_region above.
                    let slice = unsafe { std::slice::from_raw_parts(ptr, chars) };
                    let s = String::from_utf16_lossy(slice);
                    format!(" value=PWSTR \"{s}\" size_bytes={} (chars={})", attr.Size, chars)
                } else {
                    format!(" value=0x{:x} size={} (unreadable)", attr.Value, attr.Size)
                }
            } else {
                format!(" value=0x{:x} size={} (unreadable)", attr.Value, attr.Size)
            }
        } else {
            String::new()
        };
        ipc_log(ipc::LogLevel::Trace,
            format!("attr_list_dump:   [{i}] num={num} encoded=0x{:x} size={} value_ptr=0x{:x}{}",
                attr.Attribute, attr.Size, attr.Value, value_desc));
    }
}
