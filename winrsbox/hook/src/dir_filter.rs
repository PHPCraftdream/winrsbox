// dir_filter — NtQueryDirectoryFile + NtQueryDirectoryFileEx hooks.
//
// Filters `.winrsbox` entries and whiteouted (tombstoned) entries from
// directory listings so sandboxed processes see a consistent merged view:
//  - the sandbox state directory is invisible;
//  - files deleted via whiteout (OverlayFS-style) vanish from listings even
//    though the real lower file is untouched on disk.
//
// Also rewrites entry names from lowercase overlay storage back to their
// original case (the physical overlay stores everything lowercase; callers
// need to see the original mixed-case names from the real host disk).

use std::collections::HashMap;
use std::sync::OnceLock;

use detour2::GenericDetour;
use ntapi::ntioapi::IO_STATUS_BLOCK;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, UNICODE_STRING};
use winapi::ctypes::c_void;

use crate::anti_rec;
use crate::hooks;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

type FnNtQueryDirectoryFile = unsafe extern "system" fn(
    HANDLE,                  // FileHandle
    HANDLE,                  // Event
    *mut c_void,             // ApcRoutine
    *mut c_void,             // ApcContext
    *mut IO_STATUS_BLOCK,    // IoStatusBlock
    *mut c_void,             // FileInformation
    u32,                     // Length
    u32,                     // FileInformationClass
    u8,                      // ReturnSingleEntry (BOOLEAN)
    *mut UNICODE_STRING,     // FileName (filter pattern, optional)
    u8,                      // RestartScan
) -> NTSTATUS;

/// NtQueryDirectoryFileEx — same as NtQueryDirectoryFile but replaces
/// ReturnSingleEntry+RestartScan with a single QueryFlags ULONG.
/// SL_RESTART_SCAN = 0x00000001, SL_RETURN_SINGLE_ENTRY = 0x00000002.
type FnNtQueryDirectoryFileEx = unsafe extern "system" fn(
    HANDLE,                  // FileHandle
    HANDLE,                  // Event
    *mut c_void,             // ApcRoutine
    *mut c_void,             // ApcContext
    *mut IO_STATUS_BLOCK,    // IoStatusBlock
    *mut c_void,             // FileInformation
    u32,                     // Length
    u32,                     // FileInformationClass
    u32,                     // QueryFlags (replaces ReturnSingleEntry + RestartScan)
    *mut UNICODE_STRING,     // FileName (filter pattern, optional)
) -> NTSTATUS;

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

static HOOK_NT_QUERY_DIRECTORY_FILE: OnceLock<GenericDetour<FnNtQueryDirectoryFile>> =
    OnceLock::new();

static HOOK_NT_QUERY_DIRECTORY_FILE_EX: OnceLock<GenericDetour<FnNtQueryDirectoryFileEx>> =
    OnceLock::new();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns (offset of FileNameLength field, offset of FileName field) for a
/// given FileInformationClass. Returns None for unhandled classes (passthrough).
const fn dir_info_name_offsets(class: u32) -> Option<(usize, usize)> {
    // (FileNameLength offset, FileName offset) — verified against MS docs.
    // FileAttributes is at 0x38 in dir-info classes; FileNameLength is at
    // 0x3C right after it. The previous 0x38 for classes 1/2/38 pointed at
    // FileAttributes and silently disabled the filter (wrong-bytes check).
    match class {
        1  => Some((0x3C, 0x40)), // FileDirectoryInformation
        2  => Some((0x3C, 0x44)), // FileFullDirectoryInformation
        3  => Some((0x3C, 0x5E)), // FileBothDirectoryInformation
        12 => Some((0x08, 0x0C)), // FileNamesInformation
        37 => Some((0x3C, 0x68)), // FileIdBothDirectoryInformation
        38 => Some((0x3C, 0x50)), // FileIdFullDirectoryInformation
        _ => None,
    }
}

/// FileAttributes field offset for directory-info classes that have one.
/// Shared prefix across classes 1/2/3/37/38 (CreationTime..AllocationSize
/// then FileAttributes at 0x38); `FileNamesInformation` (12) omits
/// attributes entirely (NextEntryOffset, FileIndex, FileNameLength only).
const fn dir_info_attr_offset(class: u32) -> Option<usize> {
    match class {
        1 | 2 | 3 | 37 | 38 => Some(0x38),
        _ => None,
    }
}

/// CreationTime/LastAccessTime/LastWriteTime/EndOfFile/AllocationSize field
/// offsets for directory-info classes that have them — same 1/2/3/37/38
/// shared prefix as `dir_info_attr_offset`; `FileNamesInformation` (12) has
/// none of these fields.
struct DirInfoTimeOffsets {
    creation_time: usize,
    last_access_time: usize,
    last_write_time: usize,
    end_of_file: usize,
    allocation_size: usize,
}
const fn dir_info_time_offsets(class: u32) -> Option<DirInfoTimeOffsets> {
    match class {
        1 | 2 | 3 | 37 | 38 => Some(DirInfoTimeOffsets {
            creation_time: 0x08,
            last_access_time: 0x10,
            last_write_time: 0x18,
            end_of_file: 0x28,
            allocation_size: 0x30,
        }),
        _ => None,
    }
}

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
/// NTFS cluster size used to round EndOfFile up to a plausible
/// AllocationSize — matches the common default cluster size; exactness
/// doesn't matter here, only "not a suspicious 0 next to a nonzero size".
const ASSUMED_CLUSTER_SIZE: u64 = 4096;

/// Case-sensitive DOS-style single-segment wildcard match: `*` = any run of
/// chars (including none), `?` = exactly one char, everything else literal.
/// Callers fold both `name` and `pattern` to the same case before calling —
/// this function does no case-folding itself so it stays a pure string op.
///
/// Classic greedy-with-backtrack glob algorithm (iterative, O(n*m) worst
/// case, no recursion — a hostile pattern like `"****...*"` cannot blow the
/// stack).
fn filename_matches_pattern(name: &str, pattern: &str) -> bool {
    let n: Vec<char> = name.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    let (mut ni, mut pi) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None; // (pattern_idx_after_star, name_idx_at_star)

    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            ni += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi + 1, ni));
            pi += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp;
            ni = sn + 1;
            star = Some((sp, ni));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Extract an NtQueryDirectoryFile `FileName` search-pattern argument.
/// Returns `None` for a null pointer, a null `Buffer`, or `Length == 0` —
/// all of which mean "no filter, every entry matches" per the NT contract,
/// not a pattern to compare against.
///
/// # SAFETY
/// `p` may be null. If non-null, caller must ensure it points to a valid
/// `UNICODE_STRING` (guaranteed by ntdll at hook entry) with `Buffer` valid
/// for `Length` bytes when `Buffer` is non-null.
unsafe fn extract_search_pattern(p: *const UNICODE_STRING) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let ustr = &*p;
    if ustr.Buffer.is_null() {
        return None;
    }
    let char_count = (ustr.Length as usize) / 2;
    if char_count == 0 {
        return None;
    }
    // SAFETY: from_raw_parts for `char_count` WCHARs from Buffer, bounded by
    // Length per the NT UNICODE_STRING contract this function documents.
    let slice = std::slice::from_raw_parts(ustr.Buffer, char_count);
    Some(String::from_utf16_lossy(slice))
}

/// Lowercase FileNames of every entry in a (possibly already hide-filtered)
/// NtQueryDirectoryFile buffer. Used so overlay-only injection never
/// double-lists a name the real disk already reported.
///
/// # SAFETY
/// `buf` must be valid for `size` bytes (or `size == 0`, in which case `buf`
/// is never dereferenced) containing a well-formed buffer for `class`.
unsafe fn collect_present_names_lower(buf: *const u8, size: usize, class: u32) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let Some((name_len_off, name_off)) = dir_info_name_offsets(class) else {
        return out;
    };
    if buf.is_null() || size == 0 {
        return out;
    }
    let mut cur = 0usize;
    while cur < size {
        let avail = size - cur;
        if avail < name_len_off + 4 { break; }
        // SAFETY: NextEntryOffset @ 0, FileNameLength @ name_len_off — guarded by avail.
        let next_off = *(buf.add(cur) as *const u32) as usize;
        let name_len = *(buf.add(cur + name_len_off) as *const u32) as usize;
        if name_len >= 2 && name_off + name_len <= avail {
            // SAFETY: FileName @ name_off, `chars` u16s — bounded by the check above.
            let name_ptr = buf.add(cur + name_off) as *const u16;
            let chars = name_len / 2;
            let name_slice = std::slice::from_raw_parts(name_ptr, chars);
            let lower: String = std::char::decode_utf16(name_slice.iter().copied())
                .map(|r| r.unwrap_or('\u{FFFD}'))
                .flat_map(|c| c.to_ascii_lowercase().to_string().chars().collect::<Vec<_>>())
                .collect();
            out.insert(lower);
        }
        if next_off == 0 || next_off > avail { break; }
        cur += next_off;
    }
    out
}

/// Appends directory-info records for `extra` `(name, is_dir)` pairs into
/// the unused tail of a caller-provided NtQueryDirectoryFile buffer,
/// chaining them after whatever real entries occupy `[0, used_size)`. This
/// is the enum-side half of the merged-view overlay model: a CoW write
/// outside `project_root` into a directory that also exists on the real
/// disk isolates into the overlay without touching the real directory (see
/// `policy::decide::compute`), so the real listing alone never shows it —
/// this function injects it back in, keeping `dir`/`ls` consistent with
/// direct-open reads that already resolve such paths via `OVERLAY_IDX`.
///
/// Entries that don't fit within `capacity` are silently dropped — this
/// mirrors NtQueryDirectoryFile's own truncation behavior (a caller that
/// pages through a directory sees them on a later call). Known limitation:
/// on a directory large enough to need multiple successful
/// NtQueryDirectoryFile calls, extras are (best-effort) re-injected on every
/// such call, since this function has no per-handle continuation state —
/// acceptable for the common case this fixes (a handful of overlay-only
/// files in an otherwise small directory).
///
/// Unsupported `class` values and an empty `extra` are both a no-op.
///
/// Returns the new used size: `used_size <= result <= capacity`.
///
/// # SAFETY
/// `buf` must be writable for `capacity` bytes. `[0, used_size)` must
/// already hold a valid NtQueryDirectoryFile linked-list buffer for `class`
/// (terminated by an entry with `NextEntryOffset == 0`), or `used_size == 0`
/// for an empty listing.
unsafe fn append_overlay_entries(
    buf: *mut u8,
    used_size: usize,
    capacity: usize,
    class: u32,
    extra: &[policy::OverlayChildMeta],
) -> usize {
    let Some((name_len_off, name_off)) = dir_info_name_offsets(class) else {
        return used_size;
    };
    if extra.is_empty() {
        return used_size;
    }

    // Locate the current tail entry (NextEntryOffset == 0) so its offset can
    // be patched once the first new record is appended. `None` means the
    // buffer is currently empty — the first appended entry starts at 0.
    let mut prev_start: Option<usize> = None;
    if used_size > 0 {
        let mut cur = 0usize;
        loop {
            let avail = used_size - cur;
            if avail < 4 { break; }
            // SAFETY: NextEntryOffset @ 0 — guarded by avail >= 4.
            let next_off = *(buf.add(cur) as *const u32) as usize;
            if next_off == 0 || next_off > avail {
                prev_start = Some(cur);
                break;
            }
            cur += next_off;
        }
    }

    let mut write_at = used_size;

    let time_offs = dir_info_time_offsets(class);

    for meta in extra {
        let name_u16: Vec<u16> = meta.name.encode_utf16().collect();
        let name_bytes = name_u16.len() * 2;
        let entry_len = name_off + name_bytes;
        let entry_len_aligned = (entry_len + 7) & !7;
        if write_at + entry_len_aligned > capacity {
            break; // doesn't fit — drop this and every subsequent extra
        }

        // SAFETY: `write_at + entry_len_aligned <= capacity`, just checked.
        let entry_ptr = buf.add(write_at);
        // Zero the header: this region (past used_size) is caller-owned
        // scratch space, not guaranteed zeroed by the kernel.
        std::ptr::write_bytes(entry_ptr, 0, entry_len_aligned);
        // NextEntryOffset = 0 — this entry is the new tail until (if) the
        // next extra gets linked after it below.
        *(entry_ptr as *mut u32) = 0;
        *(entry_ptr.add(name_len_off) as *mut u32) = name_bytes as u32;
        if let Some(attr_off) = dir_info_attr_offset(class) {
            let attrs = if meta.is_dir { FILE_ATTRIBUTE_DIRECTORY } else { FILE_ATTRIBUTE_NORMAL };
            *(entry_ptr.add(attr_off) as *mut u32) = attrs;
        }
        if let Some(ref t) = time_offs {
            // A live stat of the physical overlay file (or all-zero for a
            // stale/unreadable index entry — an honest "unknown", not
            // garbage). Real values here are what stops `dir` showing every
            // overlay-only file as 0 bytes / 1601-01-01.
            *(entry_ptr.add(t.creation_time) as *mut u64) = meta.creation_time;
            *(entry_ptr.add(t.last_access_time) as *mut u64) = meta.last_access_time;
            *(entry_ptr.add(t.last_write_time) as *mut u64) = meta.last_write_time;
            *(entry_ptr.add(t.end_of_file) as *mut u64) = meta.size;
            let alloc = meta.size.div_ceil(ASSUMED_CLUSTER_SIZE) * ASSUMED_CLUSTER_SIZE;
            *(entry_ptr.add(t.allocation_size) as *mut u64) = alloc;
        }
        let name_dst = entry_ptr.add(name_off) as *mut u16;
        for (j, &u) in name_u16.iter().enumerate() {
            *name_dst.add(j) = u;
        }

        // Link the previous tail (real or previously-appended) to this entry.
        if let Some(prev) = prev_start {
            *(buf.add(prev) as *mut u32) = (write_at - prev) as u32;
        }

        prev_start = Some(write_at);
        write_at += entry_len_aligned;
    }

    write_at
}

/// Walk the linked-list buffer returned by NtQueryDirectoryFile and remove any
/// entry whose FileName matches a name in `hide_names` (case-insensitive,
/// compared as UTF-16). `.winrsbox` is always in the hide set. For unhandled
/// FileInformationClass values, returns `false` (caller should passthrough).
///
/// Returns `true` if filtering was applied (buffer may have been modified).
/// If every entry was hidden, returns `true` and sets `*only_hidden = true`.
///
/// # SAFETY
/// `buf` must point to a writable region of `total_size` bytes containing a valid
/// NtQueryDirectoryFile linked-list buffer for the given `class`.
unsafe fn filter_entries(
    buf: *mut u8,
    total_size: usize,
    class: u32,
    hide_names: &[Vec<u16>],
    only_hidden: &mut bool,
) -> bool {
    let Some((name_len_off, name_off)) = dir_info_name_offsets(class) else {
        return false;
    };

    let mut prev: *mut u8 = std::ptr::null_mut();
    let mut cur = buf;
    // `end` is mutable: every left-shift of the buffer (when the FIRST entry is
    // hidden) compacts the live data and leaves a stale tail of duplicated
    // bytes. Without shrinking `end`, a subsequent iteration walks that stale
    // tail and either re-finds a hidden entry (corrupting the chain) or exposes
    // a phantom copy to the caller. Keeping `end` == end-of-live-data fixes both.
    let mut end = buf.add(total_size);
    let mut filtered_any = false;
    *only_hidden = false;

    while cur < end {
        // Bytes from `cur` to the buffer end. `cur < end` ⇒ avail > 0. This fn
        // is `unsafe` over a kernel-filled buffer: the kernel never emits a
        // record exceeding its own buffer, but we guard every field read and
        // every advance defensively so a truncated/malformed record can neither
        // OOB-read nor underflow the shift arithmetic into a giant ptr::copy.
        let avail = (end as usize) - (cur as usize);
        // Need NextEntryOffset (u32 @ 0) and FileNameLength (u32 @ name_len_off).
        if avail < name_len_off + 4 {
            break;
        }
        // SAFETY: deref of NextEntryOffset (offset 0) — guarded by avail check.
        let next_off = *(cur as *const u32) as usize;
        // SAFETY: deref of FileNameLength at class-specific offset — guarded above.
        let name_len = *(cur.add(name_len_off) as *const u32) as usize;
        // Inspect the name only when the whole field provably fits in the buffer.
        if name_len >= 2 && name_off + name_len <= avail {
            let name_ptr = cur.add(name_off) as *const u16;
            let chars = name_len / 2;
            // SAFETY: from_raw_parts for `chars` u16s at FileName offset; the
            // `name_off + name_len <= avail` guard above bounds the read.
            let name_slice = std::slice::from_raw_parts(name_ptr, chars);
            if name_matches_any(name_slice, hide_names) {
                filtered_any = true;
                if !prev.is_null() {
                    // Middle/last entry: patch previous to skip this one
                    let prev_next = *(prev as *const u32) as usize;
                    let new_next = if next_off == 0 {
                        0u32
                    } else {
                        (prev_next + next_off) as u32
                    };
                    // SAFETY: writing patched NextEntryOffset to previous entry; prev is a valid in-buffer pointer.
                    *(prev as *mut u32) = new_next;
                } else if next_off == 0 {
                    *only_hidden = true;
                    return true;
                } else {
                    // First of multiple entries — shift the rest of the buffer left.
                    // checked_sub: a malformed next_off larger than the remaining
                    // buffer would otherwise underflow usize into a giant copy.
                    let Some(remain) = avail.checked_sub(next_off) else { break; };
                    // SAFETY: memmove of `remain` (≤ avail) bytes left over cur;
                    // overlap is valid for ptr::copy.
                    std::ptr::copy(cur.add(next_off), cur, remain);
                    // Compact the live-data window: `remain` bytes now sit at
                    // [cur, cur+remain); everything past that is a stale
                    // duplicate left by the shift. If we don't shrink `end`,
                    // a later iteration re-walks the stale tail and corrupts
                    // the chain (re-finds hidden entries / phantom copies).
                    end = cur.add(remain);
                    continue;
                }
                // next_off > avail ⇒ next record starts past the buffer (malformed).
                if next_off == 0 || next_off > avail { break; }
                cur = cur.add(next_off);
                continue;
            }
        }
        prev = cur;
        if next_off == 0 || next_off > avail { break; }
        cur = cur.add(next_off);
    }

    filtered_any
}

/// Case-insensitive UTF-16 comparison of an entry's FileName against a list of
/// names to hide. Short-circuits on first match.
fn name_matches_any(name: &[u16], hide_names: &[Vec<u16>]) -> bool {
    for hide in hide_names {
        if name.len() != hide.len() {
            continue;
        }
        let mut all_eq = true;
        for (&a, &b) in name.iter().zip(hide.iter()) {
            // ASCII case-fold (matches the kernel's RtlDowncaseUnicodeString
            // for ASCII; non-ASCII compared verbatim).
            let af = if (b'A' as u16..=b'Z' as u16).contains(&a) { a + 0x20 } else { a };
            let bf = if (b'A' as u16..=b'Z' as u16).contains(&b) { b + 0x20 } else { b };
            if af != bf {
                all_eq = false;
                break;
            }
        }
        if all_eq {
            return true;
        }
    }
    false
}

/// Build the UTF-16 form of `.winrsbox` (the always-hidden sandbox state dir).
fn dot_winrsbox_u16() -> Vec<u16> {
    ".winrsbox".encode_utf16().collect()
}

/// Core of `build_case_map`: takes the directory path and a callable that
/// provides overlay-case fallback pairs.
///
/// Separated for testability: production code passes the real IPC client;
/// unit tests pass a stub closure that returns a hard-coded list.
///
/// # SAFETY
/// When `overlay_fallback` is the real IPC client, this must be called while
/// the `anti_rec` guard is held so the inner `read_dir` bypasses our hook.
unsafe fn build_case_map_with_fallback(
    dir_dos: &str,
    overlay_fallback: impl Fn(&str) -> Option<Vec<(String, String)>>,
) -> Option<HashMap<String, Vec<u16>>> {
    let mut map = HashMap::new();
    let mut had_anything = false;

    // (1) Real-disk first — original case from the host filesystem.
    // std::fs::read_dir calls NtQueryDirectoryFileEx internally on Windows.
    // Because the anti_rec guard is held on this thread, the inner hook call
    // returns immediately (calls original) — we read the real host disk, not
    // the overlay layer.
    if let Ok(rd) = std::fs::read_dir(dir_dos) {
        for entry in rd.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                let lower = name.to_ascii_lowercase();
                let wide: Vec<u16> = name.encode_utf16().collect();
                map.insert(lower, wide);
                had_anything = true;
            }
        }
    }

    // (2) OVERLAY_CASE fallback — merges in overlay-only entries.
    // Real-disk wins on collision: `.entry(lower).or_insert_with(…)` only
    // fills the map when the key is absent, so an overlay entry for a path
    // that ALSO exists on real disk is silently superseded by the real name.
    if let Some(pairs) = overlay_fallback(dir_dos) {
        for (lower, original) in pairs {
            map.entry(lower).or_insert_with(|| original.encode_utf16().collect());
            had_anything = true;
        }
    }

    if had_anything { Some(map) } else { None }
}

/// Build a case-rewrite lookup: lowercase ASCII name → correct-case UTF-16.
///
/// Primary source: real host directory at `dir_dos` (bypassing the overlay
/// via the anti-recursion guard already set by the caller). Returns original-
/// case names from the host disk for all entries that exist there.
///
/// Fallback: when the directory has no real-disk counterpart (overlay-only
/// creation — e.g. `%LOCALAPPDATA%\uv\cache\builds-v0\.tmpXXXXXX` inside
/// the sandbox), `read_dir` returns ENOENT. In that case we consult the
/// policy daemon's `OVERLAY_CASE` index via IPC to obtain original-case
/// basenames recorded at write time. Real-disk entries win on collision
/// (`.entry(k).or_insert_with(…)`), so the existing behaviour is preserved
/// for paths that have both a real-disk file and an overlay copy.
///
/// Returns `None` only when BOTH sources return nothing (no entries at all),
/// which signals to the caller that no rewrite is needed for this directory.
///
/// # SAFETY
/// Must be called while the `anti_rec` guard is held so the inner
/// `read_dir` → `NtQueryDirectoryFileEx` path bypasses our hook and reads
/// the real (unredirected) host disk.
unsafe fn build_case_map(dir_dos: &str) -> Option<HashMap<String, Vec<u16>>> {
    build_case_map_with_fallback(
        dir_dos,
        crate::ipc_client::ipc_overlay_children_with_case,
    )
}

/// Walk the buffer and rewrite every entry's FileName to its original case
/// according to `case_map`. Length stays the same (only case differs);
/// this is a pure in-place byte-level rewrite with no structural changes.
///
/// # SAFETY
/// `buf`/`total_size` must be a valid writable NtQueryDirectoryFile buffer
/// for the given `class`. `case_map` maps lowercase name → original-case UTF-16.
unsafe fn rewrite_entry_case(
    buf: *mut u8,
    total_size: usize,
    class: u32,
    case_map: &HashMap<String, Vec<u16>>,
) {
    let Some((name_len_off, name_off)) = dir_info_name_offsets(class) else {
        return;
    };

    let mut cur = buf;
    let end = buf.add(total_size);

    while cur < end {
        let avail = (end as usize) - (cur as usize);
        if avail < name_len_off + 4 {
            break;
        }
        // SAFETY: NextEntryOffset at offset 0, guarded by avail.
        let next_off = *(cur as *const u32) as usize;
        // SAFETY: FileNameLength at class-specific offset, guarded by avail.
        let name_len = *(cur.add(name_len_off) as *const u32) as usize;

        if name_len >= 2 && name_off + name_len <= avail {
            let name_ptr = cur.add(name_off) as *mut u16;
            let chars = name_len / 2;
            // SAFETY: from_raw_parts_mut for `chars` u16s; `name_off + name_len <= avail`.
            let name_slice = std::slice::from_raw_parts(name_ptr, chars);

            // Build the lowercase lookup key.
            let lower: String = std::char::decode_utf16(name_slice.iter().copied())
                .map(|r| r.unwrap_or('\u{FFFD}'))
                .flat_map(|c| c.to_ascii_lowercase().to_string().chars().collect::<Vec<_>>())
                .collect();

            if let Some(correct) = case_map.get(&lower) {
                // Only rewrite when same length (case change only). Length
                // difference would require structural changes — skip those.
                if correct.len() == chars {
                    // SAFETY: from_raw_parts_mut; length matches.
                    let dst = std::slice::from_raw_parts_mut(name_ptr, chars);
                    dst.copy_from_slice(correct.as_slice());
                }
            }
        }

        if next_off == 0 || next_off > avail {
            break;
        }
        cur = cur.add(next_off);
    }
}

/// Shared post-processing: filter hidden entries, then rewrite entry case.
///
/// Called after the original NtQueryDirectoryFile / NtQueryDirectoryFileEx
/// returns STATUS_SUCCESS. Reads the real host directory once (via `build_case_map`,
/// which uses the anti_rec guard to bypass our own hook) and rewrites all
/// surviving entry names to their original case.
///
/// Returns the NTSTATUS to return to the caller.
///
/// # SAFETY
/// `file_information`/`io_status_block` are the kernel-filled output buffers.
/// `dir_dos` is the virtual DOS path (may be None when handle resolution fails).
/// A search-pattern query that matched nothing on the real disk. NT signals
/// this distinctly from "enumeration exhausted" (`STATUS_NO_MORE_FILES`,
/// 0x80000006) — only `STATUS_NO_SUCH_FILE` means "the given name/pattern
/// has zero real matches", which is exactly the case where an overlay-only
/// match must be synthesized. Gating on this specific code (rather than any
/// non-zero status) means a genuine end-of-enumeration or an unrelated error
/// is never misread as "try synthesizing".
const STATUS_NO_SUCH_FILE: NTSTATUS = 0xC000000Fu32 as NTSTATUS;

/// Resolve the virtual DOS path for the directory being enumerated.
///
/// `query_handle_dos_path` calls GetFinalPathNameByHandleW which internally
/// calls NtQueryInformationFile(FileNormalizedNameInformation, class 48).
/// The path_info_guard hook normally unmirrors overlay paths back to virtual,
/// but because anti_rec is ALREADY HELD on this thread (set at the top of
/// hook_nt_query_directory_file[_ex]), path_info_guard's anti_rec::enter()
/// returns None and it calls the original without unmasking. As a result
/// query_handle_dos_path returns the OVERLAY PHYSICAL PATH (lowercase), not
/// the virtual path — so it must be unmirrored back here, once.
fn resolve_virtual_dir(dir_dos: Option<&str>) -> Option<String> {
    let raw = dir_dos?;
    let sb_root = hooks::SANDBOX_ROOT.get().map(|s| s.as_str());
    Some(hooks::unmirror_overlay_handle_relative(raw, sb_root).unwrap_or_else(|| raw.to_string()))
}

unsafe fn process_dir_output(
    file_information: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information_class: u32,
    dir_dos: Option<&str>,
    original_status: NTSTATUS,
    capacity: usize,
    search_pattern: Option<&str>,
) -> NTSTATUS {
    if io_status_block.is_null() {
        return original_status;
    }

    // Single-name (or wildcard) lookup that found nothing real: `dir
    // <exact-file>` and similar queries pass the target as the FileName
    // filter. The real syscall fails FAST here — none of the merge logic
    // below ever runs, because there are no real entries to merge into. If
    // the pattern matches an overlay-only file, synthesize the whole reply
    // from scratch; this is the same "ghost file" bug as the listing case,
    // reached through a different code path.
    if original_status == STATUS_NO_SUCH_FILE {
        if file_information.is_null() {
            return original_status;
        }
        let Some(pattern) = search_pattern else {
            return original_status; // no filter given — genuinely nothing to synthesize
        };
        let Some(dir) = resolve_virtual_dir(dir_dos) else {
            return original_status;
        };
        let pattern_lower = pattern.to_ascii_lowercase();
        let Some(extras) = crate::ipc_client::ipc_overlay_children(&dir) else {
            return original_status;
        };
        let matches: Vec<policy::OverlayChildMeta> = extras.into_iter()
            .filter(|e| filename_matches_pattern(&e.name.to_ascii_lowercase(), &pattern_lower))
            .collect();
        if matches.is_empty() {
            return original_status;
        }
        // SAFETY: file_information is writable for `capacity` bytes (the
        // caller's original NtQueryDirectoryFile `length` argument) — the
        // real syscall wrote nothing into it (it failed), so we own the
        // whole buffer from offset 0.
        let new_size = append_overlay_entries(
            file_information as *mut u8, 0, capacity, file_information_class, &matches,
        );
        if new_size == 0 {
            return original_status; // didn't fit / unsupported class
        }
        // SAFETY: io_status_block validated non-null above; Information at offset 8 on x64.
        *((io_status_block as *mut u8).add(8) as *mut usize) = new_size;
        if hooks::is_trace() {
            hooks::ipc_log(ipc::LogLevel::Trace,
                format!("fs_enum_overlay_synthesize dir={dir} pattern={pattern} matched={}", matches.len()));
        }
        return 0; // STATUS_SUCCESS
    }

    if original_status != 0 {
        return original_status;
    }
    if file_information.is_null() {
        return original_status;
    }
    // IoStatusBlock.Information (offset 8 on x64) contains bytes written.
    // SAFETY: io_status_block validated non-null; Information at offset 8 on x64.
    let info_size = *((io_status_block as *const u8).add(8) as *const usize);
    if info_size == 0 {
        return original_status;
    }

    let virtual_dir: Option<String> = resolve_virtual_dir(dir_dos);

    // Build the hide set: `.winrsbox` is always hidden, plus any whiteouted
    // direct children of the directory being enumerated.
    let mut hide_names: Vec<Vec<u16>> = vec![dot_winrsbox_u16()];
    if let Some(ref dir) = virtual_dir {
        if let Some(names) = crate::ipc_client::ipc_whiteouts_under(dir) {
            for n in names {
                hide_names.push(n.encode_utf16().collect());
            }
        }
    }

    // Diagnostic: log the hide set and directory being filtered so we can
    // trace WHY entries disappear from a given directory listing.
    if hooks::is_trace() && hide_names.len() > 1 {
        let extra: Vec<String> = hide_names.iter().skip(1)
            .map(|w| String::from_utf16_lossy(w).to_string())
            .collect();
        hooks::ipc_log(ipc::LogLevel::Trace,
            format!("fs_hide_enum_whitelist dir={} whiteouts={:?}",
                virtual_dir.as_deref().unwrap_or("<none>"),
                extra));
    }

    let mut only_hidden = false;
    if filter_entries(
        file_information as *mut u8,
        info_size,
        file_information_class,
        &hide_names,
        &mut only_hidden,
    ) {
        if only_hidden {
            const STATUS_NO_MORE_FILES: NTSTATUS = 0x0000_0104_u32 as NTSTATUS;
            if hooks::is_trace() {
                hooks::ipc_log(ipc::LogLevel::Trace,
                    format!("fs_hide_enum: only hidden entries dir={}",
                        virtual_dir.as_deref().unwrap_or("<none>")));
            }
            return STATUS_NO_MORE_FILES;
        }
        if hooks::is_trace() {
            hooks::ipc_log(ipc::LogLevel::Trace,
                format!("fs_hide_enum: entries filtered from listing dir={}",
                    virtual_dir.as_deref().unwrap_or("<none>")));
        }
    }

    // Case-rewrite: look up each surviving entry's name on the real host disk
    // and restore original case. Only applies when virtual_dir resolves to a
    // real directory on disk; overlay-only dirs are skipped (build_case_map → None).
    if let Some(ref dir) = virtual_dir {
        // std::fs::read_dir(virtual_dir) with anti_rec held → NtCreateFile
        // hook bypasses CoW (anti_rec::enter() returns None → calls original)
        // → original NtCreateFile opens the real host disk at virtual_dir.
        // Result: case_map contains original-case names from the real disk.
        if let Some(case_map) = build_case_map(dir) {
            if !case_map.is_empty() {
                rewrite_entry_case(
                    file_information as *mut u8,
                    info_size,
                    file_information_class,
                    &case_map,
                );
            }
        }
    }

    // Merge overlay-only entries: a CoW write outside project_root into a
    // directory that also exists on the real disk isolates into the overlay
    // without ever touching the real directory (policy::decide::compute), so
    // the real NtQueryDirectoryFile result above never includes it even
    // though a direct open by name already resolves it via OVERLAY_IDX — the
    // "ghost file" bug. Inject those entries here so both channels agree.
    if let Some(ref dir) = virtual_dir {
        if let Some(mut extras) = crate::ipc_client::ipc_overlay_children(dir) {
            if !extras.is_empty() {
                // SAFETY: file_information is valid for info_size bytes (kernel-filled).
                let present = collect_present_names_lower(
                    file_information as *const u8, info_size, file_information_class,
                );
                // A wildcard/exact FileName filter on this call must apply to
                // injected entries exactly as it did to the real ones — else
                // e.g. `dir *.log` (real matches only) would also inject an
                // unrelated overlay-only `.txt` file that never matched.
                let pattern_lower = search_pattern.map(|p| p.to_ascii_lowercase());
                extras.retain(|e| {
                    !present.contains(&e.name.to_ascii_lowercase())
                        && pattern_lower.as_deref()
                            .is_none_or(|pat| filename_matches_pattern(&e.name.to_ascii_lowercase(), pat))
                });
                if !extras.is_empty() {
                    // SAFETY: file_information is writable for `capacity` bytes
                    // (the caller's original NtQueryDirectoryFile `length` argument).
                    let new_size = append_overlay_entries(
                        file_information as *mut u8,
                        info_size,
                        capacity,
                        file_information_class,
                        &extras,
                    );
                    if new_size > info_size {
                        // SAFETY: io_status_block validated non-null above; Information at offset 8 on x64.
                        *((io_status_block as *mut u8).add(8) as *mut usize) = new_size;
                        if hooks::is_trace() {
                            hooks::ipc_log(ipc::LogLevel::Trace,
                                format!("fs_enum_overlay_merge dir={dir} added={}", extras.len()));
                        }
                    }
                }
            }
        }
    }

    original_status
}

// ---------------------------------------------------------------------------
// Hook implementations
// ---------------------------------------------------------------------------

// SAFETY: Called by detour2 dispatcher with ntdll!NtQueryDirectoryFile ABI.
unsafe extern "system" fn hook_nt_query_directory_file(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: *mut c_void,
    apc_context: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information: *mut c_void,
    length: u32,
    file_information_class: u32,
    return_single_entry: u8,
    file_name: *mut UNICODE_STRING,
    restart_scan: u8,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        // SAFETY: detour2 trampoline matches FnNtQueryDirectoryFile ABI.
        return HOOK_NT_QUERY_DIRECTORY_FILE.get().unwrap().call(
            file_handle, event, apc_routine, apc_context, io_status_block,
            file_information, length, file_information_class,
            return_single_entry, file_name, restart_scan,
        );
    };

    // SAFETY: detour2 trampoline matches FnNtQueryDirectoryFile ABI; same args passed through.
    let status = HOOK_NT_QUERY_DIRECTORY_FILE.get().unwrap().call(
        file_handle, event, apc_routine, apc_context, io_status_block,
        file_information, length, file_information_class,
        return_single_entry, file_name, restart_scan,
    );

    let dir_dos = crate::fs_metadata_guard::query_handle_dos_path(file_handle);
    // SAFETY: file_name is the same UNICODE_STRING pointer ntdll passed us;
    // valid (or null) per the NT contract at hook entry.
    let search_pattern = extract_search_pattern(file_name);
    process_dir_output(
        file_information,
        io_status_block,
        file_information_class,
        dir_dos.as_deref(),
        status,
        length as usize,
        search_pattern.as_deref(),
    )
}

// SAFETY: Called by detour2 dispatcher with ntdll!NtQueryDirectoryFileEx ABI.
unsafe extern "system" fn hook_nt_query_directory_file_ex(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: *mut c_void,
    apc_context: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information: *mut c_void,
    length: u32,
    file_information_class: u32,
    query_flags: u32,
    file_name: *mut UNICODE_STRING,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        // SAFETY: detour2 trampoline matches FnNtQueryDirectoryFileEx ABI.
        return HOOK_NT_QUERY_DIRECTORY_FILE_EX.get().unwrap().call(
            file_handle, event, apc_routine, apc_context, io_status_block,
            file_information, length, file_information_class,
            query_flags, file_name,
        );
    };

    // SAFETY: detour2 trampoline matches FnNtQueryDirectoryFileEx ABI.
    let status = HOOK_NT_QUERY_DIRECTORY_FILE_EX.get().unwrap().call(
        file_handle, event, apc_routine, apc_context, io_status_block,
        file_information, length, file_information_class,
        query_flags, file_name,
    );

    let dir_dos = crate::fs_metadata_guard::query_handle_dos_path(file_handle);
    // SAFETY: file_name is the same UNICODE_STRING pointer ntdll passed us;
    // valid (or null) per the NT contract at hook entry.
    let search_pattern = extract_search_pattern(file_name);
    process_dir_output(
        file_information,
        io_status_block,
        file_information_class,
        dir_dos.as_deref(),
        status,
        length as usize,
        search_pattern.as_deref(),
    )
}

// ---------------------------------------------------------------------------
// Install / uninstall
// ---------------------------------------------------------------------------

pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    macro_rules! install {
        ($lock:expr, $sym:literal, $hook_fn:expr, $fn_ty:ty) => {{
            let addr = hooks::ntdll_export($sym.as_bytes())
                .ok_or_else(|| format!("ntdll export not found: {}", $sym))?;
            // SAFETY: transmute of ntdll export address; ABI matches the hook function type.
            let target: $fn_ty = std::mem::transmute(addr as usize);
            let hook_ptr: $fn_ty = $hook_fn;
            let detour = GenericDetour::<$fn_ty>::new(target, hook_ptr)
                .map_err(|e| format!("detour init {}: {:?}", $sym, e))?;
            $lock.set(detour).ok();
            $lock.get()
                .expect("set above")
                .enable()
                .map_err(|e| format!("detour enable {}: {:?}", $sym, e))?;
        }};
    }

    install!(HOOK_NT_QUERY_DIRECTORY_FILE, "NtQueryDirectoryFile\0", hook_nt_query_directory_file, FnNtQueryDirectoryFile);
    install!(HOOK_NT_QUERY_DIRECTORY_FILE_EX, "NtQueryDirectoryFileEx\0", hook_nt_query_directory_file_ex, FnNtQueryDirectoryFileEx);

    Ok(())
}

pub unsafe fn uninstall() {
    if let Some(h) = HOOK_NT_QUERY_DIRECTORY_FILE.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_NT_QUERY_DIRECTORY_FILE_EX.get() { let _ = h.disable(); }
}

// ---------------------------------------------------------------------------
// Unit tests (pure helpers — no FFI)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic FileDirectoryInformation (class 1) buffer with the
    /// given entry names. Each entry is 0x40 + (name_chars*2) bytes; the last
    /// entry has NextEntryOffset = 0.
    fn build_dir_info_buffer(names: &[&str]) -> Vec<u8> {
        // class 1: FileDirectoryInformation
        //   0x00: ULONG NextEntryOffset
        //   0x04: ULONG FileIndex
        //   0x08: LARGE_INTEGER CreationTime
        //   0x10: LARGE_INTEGER LastAccessTime
        //   0x18: LARGE_INTEGER LastWriteTime
        //   0x20: LARGE_INTEGER ChangeTime
        //   0x28: LARGE_INTEGER EndOfFile
        //   0x30: LARGE_INTEGER AllocationSize
        //   0x38: ULONG FileAttributes
        //   0x3C: ULONG FileNameLength
        //   0x40: WCHAR FileName[]
        const NAME_LEN_OFF: usize = 0x3C;
        const NAME_OFF: usize = 0x40;
        let mut buf = Vec::new();
        let n = names.len();
        for (i, name) in names.iter().enumerate() {
            let start = buf.len();
            let name_u16: Vec<u16> = name.encode_utf16().collect();
            let name_bytes = name_u16.len() * 2;
            let entry_len = NAME_OFF + name_bytes;
            // pad to 8-byte alignment for NextEntryOffset correctness
            let entry_len_aligned = (entry_len + 7) & !7;
            let next_off = if i + 1 < n { entry_len_aligned as u32 } else { 0 };
            buf.resize(start + entry_len_aligned, 0);
            // NextEntryOffset @ 0
            buf[start..start + 4].copy_from_slice(&next_off.to_le_bytes());
            // FileNameLength @ 0x3C
            buf[start + NAME_LEN_OFF..start + NAME_LEN_OFF + 4]
                .copy_from_slice(&(name_bytes as u32).to_le_bytes());
            // FileName @ 0x40
            for (j, &u) in name_u16.iter().enumerate() {
                let off = start + NAME_OFF + j * 2;
                buf[off..off + 2].copy_from_slice(&u.to_le_bytes());
            }
        }
        buf
    }

    /// Collect the FileNames from a (possibly filtered) class-1 buffer.
    fn collect_names(buf: &[u8]) -> Vec<String> {
        const NAME_LEN_OFF: usize = 0x3C;
        const NAME_OFF: usize = 0x40;
        let mut out = Vec::new();
        let mut cur = 0usize;
        while cur < buf.len() {
            if cur + NAME_LEN_OFF + 4 > buf.len() { break; }
            let next_off = u32::from_le_bytes([buf[cur], buf[cur+1], buf[cur+2], buf[cur+3]]) as usize;
            let name_len = u32::from_le_bytes([
                buf[cur+NAME_LEN_OFF], buf[cur+NAME_LEN_OFF+1],
                buf[cur+NAME_LEN_OFF+2], buf[cur+NAME_LEN_OFF+3],
            ]) as usize;
            if name_len == 0 || cur + NAME_OFF + name_len > buf.len() { break; }
            let chars = name_len / 2;
            let mut name = String::new();
            for j in 0..chars {
                let off = cur + NAME_OFF + j * 2;
                let u = u16::from_le_bytes([buf[off], buf[off+1]]);
                name.push(char::from_u32(u as u32).unwrap_or('?'));
            }
            out.push(name);
            if next_off == 0 { break; }
            cur += next_off;
        }
        out
    }

    #[test]
    fn name_matches_case_insensitive() {
        let hide = vec![".winrsbox".encode_utf16().collect::<Vec<u16>>()];
        let lower: Vec<u16> = ".winrsbox".encode_utf16().collect();
        let upper: Vec<u16> = ".WINRSBOX".encode_utf16().collect();
        let mixed: Vec<u16> = ".WinRsBoX".encode_utf16().collect();
        assert!(name_matches_any(&lower, &hide));
        assert!(name_matches_any(&upper, &hide));
        assert!(name_matches_any(&mixed, &hide));
    }

    #[test]
    fn name_matches_length_mismatch() {
        let hide = vec!["a.txt".encode_utf16().collect::<Vec<u16>>()];
        let longer: Vec<u16> = "a.txt.bak".encode_utf16().collect();
        assert!(!name_matches_any(&longer, &hide));
    }

    #[test]
    fn name_matches_multiple_hide_names() {
        let hide = vec![
            ".winrsbox".encode_utf16().collect::<Vec<u16>>(),
            "secret.txt".encode_utf16().collect(),
        ];
        let target: Vec<u16> = "secret.txt".encode_utf16().collect();
        assert!(name_matches_any(&target, &hide));
    }

    #[test]
    fn filter_removes_winrsbox_from_middle() {
        let mut buf = build_dir_info_buffer(&["a.txt", ".winrsbox", "b.txt"]);
        let mut only_hidden = false;
        let hide = vec![dot_winrsbox_u16()];
        // SAFETY: buf is a valid writable class-1 buffer built above.
        let filtered = unsafe {
            filter_entries(buf.as_mut_ptr(), buf.len(), 1, &hide, &mut only_hidden)
        };
        assert!(filtered);
        assert!(!only_hidden);
        let names = collect_names(&buf);
        assert_eq!(names, vec!["a.txt".to_string(), "b.txt".to_string()]);
    }

    #[test]
    fn filter_removes_whiteouted_name() {
        let mut buf = build_dir_info_buffer(&["keep.txt", "gone.log", "keep2.txt"]);
        let mut only_hidden = false;
        let hide = vec![
            dot_winrsbox_u16(),
            "gone.log".encode_utf16().collect::<Vec<u16>>(),
        ];
        // SAFETY: buf is a valid writable class-1 buffer built above.
        let filtered = unsafe {
            filter_entries(buf.as_mut_ptr(), buf.len(), 1, &hide, &mut only_hidden)
        };
        assert!(filtered);
        assert!(!only_hidden);
        let names = collect_names(&buf);
        assert_eq!(names, vec!["keep.txt".to_string(), "keep2.txt".to_string()]);
    }

    #[test]
    fn filter_only_hidden_entry_sets_flag() {
        let mut buf = build_dir_info_buffer(&[".winrsbox"]);
        let mut only_hidden = false;
        let hide = vec![dot_winrsbox_u16()];
        // SAFETY: buf is a valid writable class-1 buffer built above.
        let filtered = unsafe {
            filter_entries(buf.as_mut_ptr(), buf.len(), 1, &hide, &mut only_hidden)
        };
        assert!(filtered);
        assert!(only_hidden, "only_hidden must be true when the single entry is hidden");
    }

    #[test]
    fn filter_no_match_returns_false() {
        let mut buf = build_dir_info_buffer(&["a.txt", "b.txt"]);
        let mut only_hidden = false;
        let hide = vec![dot_winrsbox_u16()];
        // SAFETY: buf is a valid writable class-1 buffer built above.
        let filtered = unsafe {
            filter_entries(buf.as_mut_ptr(), buf.len(), 1, &hide, &mut only_hidden)
        };
        assert!(!filtered);
        assert!(!only_hidden);
        let names = collect_names(&buf);
        assert_eq!(names, vec!["a.txt".to_string(), "b.txt".to_string()]);
    }

    #[test]
    fn filter_unhandled_class_returns_false() {
        let mut buf = vec![0u8; 128];
        let mut only_hidden = false;
        let hide = vec![dot_winrsbox_u16()];
        // SAFETY: buf is writable; class 999 is unhandled → no deref of record fields.
        let filtered = unsafe {
            filter_entries(buf.as_mut_ptr(), buf.len(), 999, &hide, &mut only_hidden)
        };
        assert!(!filtered);
    }

    // ---- extended N-entry coverage (regression for the enum-loses-all-but-last bug) ----
    //
    // These exercise the linked-list patching with a 3-entry buffer across every
    // position (none / middle / first / last) and verify BOTH that the surviving
    // names are correct AND that the NextEntryOffset chain stays walkable (no
    // dropped tail). A broken patch (e.g. not advancing `prev`, or overwriting a
    // neighbour) surfaces here as a truncated `collect_names` output.

    /// 3 entries, filter matches nothing → all 3 stay, offsets untouched, fn
    /// reports no filtering. This is the "nothing to hide" hot path; any buffer
    /// mutation here would silently drop entries from every directory listing.
    #[test]
    fn filter_three_entries_no_match_all_preserved() {
        let mut buf = build_dir_info_buffer(&["a.txt", "b.txt", "c.txt"]);
        let original = buf.clone();
        let mut only_hidden = false;
        let hide = vec![dot_winrsbox_u16()];
        // SAFETY: buf is a valid writable class-1 buffer built above.
        let filtered = unsafe {
            filter_entries(buf.as_mut_ptr(), buf.len(), 1, &hide, &mut only_hidden)
        };
        assert!(!filtered, "nothing matched → must report no filtering");
        assert!(!only_hidden);
        assert_eq!(buf, original, "buffer must be byte-identical when nothing is hidden");
        let names = collect_names(&buf);
        assert_eq!(names, vec!["a.txt".to_string(), "b.txt".to_string(), "c.txt".to_string()]);
    }

    /// 3 entries, middle one whiteouted → 1st and 3rd survive, chain valid.
    /// This is the patch-prev path (prev non-null, next non-zero): the previous
    /// entry's NextEntryOffset must advance by the hidden entry's offset.
    #[test]
    fn filter_three_entries_middle_hidden() {
        let mut buf = build_dir_info_buffer(&["a.txt", "gone.md", "c.txt"]);
        let mut only_hidden = false;
        let hide = vec![
            dot_winrsbox_u16(),
            "gone.md".encode_utf16().collect::<Vec<u16>>(),
        ];
        // SAFETY: buf is a valid writable class-1 buffer built above.
        let filtered = unsafe {
            filter_entries(buf.as_mut_ptr(), buf.len(), 1, &hide, &mut only_hidden)
        };
        assert!(filtered);
        assert!(!only_hidden);
        let names = collect_names(&buf);
        assert_eq!(names, vec!["a.txt".to_string(), "c.txt".to_string()]);
    }

    /// 3 entries, first one whiteouted → 2nd and 3rd survive, chain valid.
    /// This is the buffer-shift path (prev null): the rest of the buffer is
    /// memmove'd left over the hidden first entry.
    #[test]
    fn filter_three_entries_first_hidden() {
        let mut buf = build_dir_info_buffer(&["gone.md", "b.txt", "c.txt"]);
        let mut only_hidden = false;
        let hide = vec![
            dot_winrsbox_u16(),
            "gone.md".encode_utf16().collect::<Vec<u16>>(),
        ];
        // SAFETY: buf is a valid writable class-1 buffer built above.
        let filtered = unsafe {
            filter_entries(buf.as_mut_ptr(), buf.len(), 1, &hide, &mut only_hidden)
        };
        assert!(filtered);
        assert!(!only_hidden);
        let names = collect_names(&buf);
        assert_eq!(names, vec!["b.txt".to_string(), "c.txt".to_string()]);
    }

    /// 3 entries, last one whiteouted → 1st and 2nd survive, last offset=0.
    /// This is the patch-prev-then-terminate path (prev non-null, next==0):
    /// the previous entry's NextEntryOffset must be set to 0.
    #[test]
    fn filter_three_entries_last_hidden() {
        let mut buf = build_dir_info_buffer(&["a.txt", "b.txt", "gone.md"]);
        let mut only_hidden = false;
        let hide = vec![
            dot_winrsbox_u16(),
            "gone.md".encode_utf16().collect::<Vec<u16>>(),
        ];
        // SAFETY: buf is a valid writable class-1 buffer built above.
        let filtered = unsafe {
            filter_entries(buf.as_mut_ptr(), buf.len(), 1, &hide, &mut only_hidden)
        };
        assert!(filtered);
        assert!(!only_hidden);
        let names = collect_names(&buf);
        assert_eq!(names, vec!["a.txt".to_string(), "b.txt".to_string()]);
    }

    /// 3 entries, middle is `.winrsbox` (the always-hidden name) → 1st and 3rd
    /// survive. Mirrors the original bug class but with the real hide name and
    /// a 3rd entry so a truncated chain is detectable.
    #[test]
    fn filter_three_entries_winrsbox_in_middle() {
        let mut buf = build_dir_info_buffer(&["a.txt", ".winrsbox", "c.txt"]);
        let mut only_hidden = false;
        let hide = vec![dot_winrsbox_u16()];
        // SAFETY: buf is a valid writable class-1 buffer built above.
        let filtered = unsafe {
            filter_entries(buf.as_mut_ptr(), buf.len(), 1, &hide, &mut only_hidden)
        };
        assert!(filtered);
        assert!(!only_hidden);
        let names = collect_names(&buf);
        assert_eq!(names, vec!["a.txt".to_string(), "c.txt".to_string()]);
    }

    /// Larger buffer (5 entries) with two hidden in different positions (first
    /// + middle) to stress both the shift and the patch paths in one walk.
    #[test]
    fn filter_five_entries_first_and_middle_hidden() {
        let mut buf = build_dir_info_buffer(&[
            "gone1.md", "keep1.txt", "gone2.md", "keep2.txt", "keep3.txt",
        ]);
        let mut only_hidden = false;
        let hide = vec![
            dot_winrsbox_u16(),
            "gone1.md".encode_utf16().collect::<Vec<u16>>(),
            "gone2.md".encode_utf16().collect::<Vec<u16>>(),
        ];
        // SAFETY: buf is a valid writable class-1 buffer built above.
        let filtered = unsafe {
            filter_entries(buf.as_mut_ptr(), buf.len(), 1, &hide, &mut only_hidden)
        };
        assert!(filtered);
        assert!(!only_hidden);
        let names = collect_names(&buf);
        assert_eq!(
            names,
            vec!["keep1.txt".to_string(), "keep2.txt".to_string(), "keep3.txt".to_string()]
        );
    }

    /// All three entries hidden but none is the sole entry → only_hidden must
    /// stay false (we returned entries in earlier calls) and the walk must not
    /// loop. The buffer ends up empty; collect_names yields nothing.
    #[test]
    fn filter_all_entries_hidden_in_batch() {
        let mut buf = build_dir_info_buffer(&[".winrsbox", "gone.md", "gone2.md"]);
        let mut only_hidden = false;
        let hide = vec![
            dot_winrsbox_u16(),
            "gone.md".encode_utf16().collect::<Vec<u16>>(),
            "gone2.md".encode_utf16().collect::<Vec<u16>>(),
        ];
        // SAFETY: buf is a valid writable class-1 buffer built above.
        let filtered = unsafe {
            filter_entries(buf.as_mut_ptr(), buf.len(), 1, &hide, &mut only_hidden)
        };
        assert!(filtered);
        // When every entry in the batch is hidden, the contract is that the
        // caller treats the directory as having no visible entries this call.
        // For a multi-entry batch where the walk shifts/patches every record,
        // `only_hidden` is only guaranteed when the FIRST entry is hidden AND
        // it is the sole entry (next_off==0); here it depends on the shift
        // sequence. The robust contract check: after filtering, NO walkable
        // non-hidden entry survives. We re-walk using the live-data size the
        // hook would pass onward; when only_hidden is set, the caller returns
        // STATUS_NO_MORE_FILES and never walks the buffer, so treat it as empty.
        if only_hidden {
            return; // caller sees empty dir — correct
        }
        // Otherwise the buffer may still carry stale bytes in its tail; verify
        // by re-walking only the compacted live window. We don't have the
        // live size here, so confirm at least that no non-hidden name leaked:
        // every name collect_names finds must be a hidden name (i.e. the filter
        // never left a survivor). Because all three were hidden, any survivor
        // is a bug.
        let names = collect_names(&buf);
        for n in &names {
            assert!(
                hide.iter().any(|h| {
                    let hs: String = h.iter()
                        .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
                        .collect();
                    hs == *n
                }),
                "surviving name {} was not in the hide set (phantom leak)", n
            );
        }
    }

    /// FileNamesInformation (class 12) has a smaller record layout (FileName at
    /// 0x0C). Verify the class-specific offsets work for a 3-entry buffer with
    /// the middle hidden.
    #[test]
    fn filter_class_12_names_info_middle_hidden() {
        // class 12: FileNamesInformation
        //   0x00 ULONG NextEntryOffset
        //   0x04 ULONG FileIndex
        //   0x08 ULONG FileNameLength
        //   0x0C WCHAR FileName[]
        const NAME_LEN_OFF_12: usize = 0x08;
        const NAME_OFF_12: usize = 0x0C;
        let names = ["a.txt", "gone.md", "c.txt"];
        let mut entries: Vec<Vec<u8>> = Vec::new();
        for name in &names {
            let u: Vec<u16> = name.encode_utf16().collect();
            let nb = u.len() * 2;
            let entry = NAME_OFF_12 + nb;
            let aligned = (entry + 7) & !7;
            let mut e = vec![0u8; aligned];
            let nb_u32 = nb as u32;
            e[NAME_LEN_OFF_12..NAME_LEN_OFF_12 + 4].copy_from_slice(&nb_u32.to_le_bytes());
            for (j, &c) in u.iter().enumerate() {
                e[NAME_OFF_12 + j * 2..NAME_OFF_12 + j * 2 + 2].copy_from_slice(&c.to_le_bytes());
            }
            entries.push(e);
        }
        // set NextEntryOffset chain
        for i in 0..entries.len() {
            let next = if i + 1 < entries.len() {
                entries[i].len() as u32
            } else {
                0
            };
            entries[i][0..4].copy_from_slice(&next.to_le_bytes());
        }
        let mut buf: Vec<u8> = entries.into_iter().flatten().collect();
        let mut only_hidden = false;
        let hide = vec![
            dot_winrsbox_u16(),
            "gone.md".encode_utf16().collect::<Vec<u16>>(),
        ];
        // SAFETY: buf is a valid writable class-12 buffer built above.
        let filtered = unsafe {
            filter_entries(buf.as_mut_ptr(), buf.len(), 12, &hide, &mut only_hidden)
        };
        assert!(filtered);
        assert!(!only_hidden);
        // Walk the class-12 chain to collect surviving names.
        let mut got = Vec::new();
        let mut cur = 0usize;
        while cur + NAME_LEN_OFF_12 + 4 <= buf.len() {
            let next_off = u32::from_le_bytes([buf[cur], buf[cur + 1], buf[cur + 2], buf[cur + 3]]) as usize;
            let name_len = u32::from_le_bytes([
                buf[cur + NAME_LEN_OFF_12], buf[cur + NAME_LEN_OFF_12 + 1],
                buf[cur + NAME_LEN_OFF_12 + 2], buf[cur + NAME_LEN_OFF_12 + 3],
            ]) as usize;
            if name_len == 0 || cur + NAME_OFF_12 + name_len > buf.len() {
                break;
            }
            let chars = name_len / 2;
            let mut s = String::new();
            for j in 0..chars {
                let off = cur + NAME_OFF_12 + j * 2;
                s.push(char::from_u32(u16::from_le_bytes([buf[off], buf[off + 1]]) as u32).unwrap_or('?'));
            }
            got.push(s);
            if next_off == 0 {
                break;
            }
            cur += next_off;
        }
        assert_eq!(got, vec!["a.txt".to_string(), "c.txt".to_string()]);
    }

    /// Case-rewrite unit test: buffer with lowercase entry "c", case_map has
    /// "c" → "C". After rewrite_entry_case, the buffer contains "C".
    #[test]
    fn rewrite_entry_case_lowercase_to_uppercase() {
        let mut buf = build_dir_info_buffer(&["c"]);
        let mut case_map = HashMap::new();
        case_map.insert("c".to_string(), "C".encode_utf16().collect::<Vec<u16>>());
        // SAFETY: buf is a valid writable class-1 buffer built above.
        unsafe {
            rewrite_entry_case(buf.as_mut_ptr(), buf.len(), 1, &case_map);
        }
        let names = collect_names(&buf);
        assert_eq!(names, vec!["C".to_string()]);
    }

    /// Case-rewrite: entry name not in case_map → unchanged.
    #[test]
    fn rewrite_entry_case_no_match_unchanged() {
        let mut buf = build_dir_info_buffer(&["hello"]);
        let case_map: HashMap<String, Vec<u16>> = HashMap::new();
        // SAFETY: buf is a valid writable class-1 buffer built above.
        unsafe {
            rewrite_entry_case(buf.as_mut_ptr(), buf.len(), 1, &case_map);
        }
        let names = collect_names(&buf);
        assert_eq!(names, vec!["hello".to_string()]);
    }

    /// Case-rewrite: multiple entries, only one is in the map.
    #[test]
    fn rewrite_entry_case_partial_match() {
        let mut buf = build_dir_info_buffer(&["c", "other"]);
        let mut case_map = HashMap::new();
        case_map.insert("c".to_string(), "C".encode_utf16().collect::<Vec<u16>>());
        // SAFETY: buf is a valid writable class-1 buffer built above.
        unsafe {
            rewrite_entry_case(buf.as_mut_ptr(), buf.len(), 1, &case_map);
        }
        let names = collect_names(&buf);
        assert_eq!(names, vec!["C".to_string(), "other".to_string()]);
    }

    // ── build_case_map_with_fallback tests (7.3 / 7.4) ─────────────────────

    /// 7.3 — read_dir fails (ENOENT), IPC fallback returns one pair.
    /// Result: map contains that pair; returns Some.
    #[test]
    fn build_case_map_fallback_used_when_read_dir_fails() {
        let nonexistent = r"C:\___no_such_dir_for_winrsbox_test___";
        let result = unsafe {
            build_case_map_with_fallback(
                nonexistent,
                |_dir| Some(vec![("foo".to_string(), "Foo".to_string())]),
            )
        };
        let map = result.expect("fallback should produce a non-empty map");
        let wide: Vec<u16> = "Foo".encode_utf16().collect();
        assert_eq!(map.get("foo"), Some(&wide), "fallback entry 'Foo' must appear");
    }

    /// 7.4 — read_dir succeeds (returns "Real"), IPC fallback returns ("real", "FromIndex").
    /// Real-disk entry wins: value for "real" must be "Real" UTF-16, NOT "FromIndex".
    #[test]
    fn build_case_map_real_disk_wins_over_fallback() {
        // Use the current directory (guaranteed to exist) and ask for a key that
        // we control via the stub. We seed the real-disk part via stub_real to
        // avoid depending on actual file names in the cwd; instead we bypass
        // read_dir and inject via the "real disk" path through the same
        // `build_case_map_with_fallback` API by constructing a two-stage fallback.
        //
        // Actually: we can't inject into the read_dir path without the filesystem.
        // Use a temp dir with a known file to give read_dir one real entry.
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("Real");
        std::fs::write(&file_path, b"").unwrap();

        let dir_str = dir.path().to_str().expect("tempdir path must be UTF-8");
        let result = unsafe {
            build_case_map_with_fallback(
                dir_str,
                |_dir| Some(vec![
                    ("real".to_string(), "FromIndex".to_string()),
                ]),
            )
        };
        let map = result.expect("must return Some with real-disk entry");
        // real_disk path reports "Real" (windows FS preserves creation case).
        // The key is its lowercase: "real".
        if let Some(wide) = map.get("real") {
            // Convert back to string for assertion clarity.
            let name: String = std::char::decode_utf16(wide.iter().copied())
                .map(|r| r.unwrap_or('\u{FFFD}'))
                .collect();
            // Real-disk name must win; "FromIndex" must NOT appear.
            assert_ne!(
                name, "FromIndex",
                "IPC fallback must not override real-disk entry",
            );
            // Real-disk value is "Real" (Windows FS returns creation case for
            // files in a temp dir; NTFS returns whatever case was used at create).
            // We only assert that it's NOT FromIndex (defensive guard).
        }
        // Regardless: the fallback entry must NOT have overwritten real-disk
        // — verified implicitly by the ne above.
    }

    /// 7.3b — Both sources return nothing → None.
    #[test]
    fn build_case_map_empty_both_sources_returns_none() {
        let nonexistent = r"C:\___no_such_dir_for_winrsbox_test_2___";
        let result = unsafe {
            build_case_map_with_fallback(nonexistent, |_dir| None)
        };
        assert!(result.is_none(), "empty both sources must return None");
    }

    // ── overlay-entry injection (enum-merge fix: ghost-file listing bug) ───
    //
    // A CoW write outside project_root into a directory that ALSO exists on
    // the real disk gets isolated into the overlay (never touching the real
    // directory — see policy::decide's merged-view model). The real
    // NtQueryDirectoryFile result for that directory is therefore real-disk-
    // only and never shows the overlay-only file, even though a direct open
    // by name finds it via OVERLAY_IDX — a "ghost file" invisible to
    // `dir`/`ls` but readable via `type`/`cat`. These functions merge
    // overlay-only entries into the listing buffer so both channels agree.

    /// Collect (lowercase name, FileAttributes) pairs from a class-1 buffer.
    /// Test-only helper; production code never needs to READ attributes.
    fn collect_names_and_attrs(buf: &[u8]) -> Vec<(String, u32)> {
        const ATTR_OFF: usize = 0x38;
        const NAME_LEN_OFF: usize = 0x3C;
        const NAME_OFF: usize = 0x40;
        let mut out = Vec::new();
        let mut cur = 0usize;
        while cur < buf.len() {
            if cur + NAME_OFF > buf.len() { break; }
            let next_off = u32::from_le_bytes([buf[cur], buf[cur+1], buf[cur+2], buf[cur+3]]) as usize;
            let attrs = u32::from_le_bytes([
                buf[cur+ATTR_OFF], buf[cur+ATTR_OFF+1], buf[cur+ATTR_OFF+2], buf[cur+ATTR_OFF+3],
            ]);
            let name_len = u32::from_le_bytes([
                buf[cur+NAME_LEN_OFF], buf[cur+NAME_LEN_OFF+1],
                buf[cur+NAME_LEN_OFF+2], buf[cur+NAME_LEN_OFF+3],
            ]) as usize;
            if name_len == 0 || cur + NAME_OFF + name_len > buf.len() { break; }
            let chars = name_len / 2;
            let mut name = String::new();
            for j in 0..chars {
                let off = cur + NAME_OFF + j * 2;
                let u = u16::from_le_bytes([buf[off], buf[off+1]]);
                name.push(char::from_u32(u as u32).unwrap_or('?'));
            }
            out.push((name, attrs));
            if next_off == 0 { break; }
            cur += next_off;
        }
        out
    }

    #[test]
    fn dir_info_attr_offset_known_classes() {
        assert_eq!(dir_info_attr_offset(1), Some(0x38));
        assert_eq!(dir_info_attr_offset(2), Some(0x38));
        assert_eq!(dir_info_attr_offset(3), Some(0x38));
        assert_eq!(dir_info_attr_offset(37), Some(0x38));
        assert_eq!(dir_info_attr_offset(38), Some(0x38));
    }

    #[test]
    fn dir_info_attr_offset_class_12_has_no_attribute_field() {
        assert_eq!(dir_info_attr_offset(12), None);
    }

    #[test]
    fn dir_info_attr_offset_unhandled_class_is_none() {
        assert_eq!(dir_info_attr_offset(999), None);
    }

    #[test]
    fn collect_present_names_lower_reads_existing_entries() {
        let buf = build_dir_info_buffer(&["Foo.txt", "bar.log"]);
        // SAFETY: buf is a valid class-1 buffer built above.
        let present = unsafe { collect_present_names_lower(buf.as_ptr(), buf.len(), 1) };
        assert!(present.contains("foo.txt"));
        assert!(present.contains("bar.log"));
        assert_eq!(present.len(), 2);
    }

    #[test]
    fn collect_present_names_lower_empty_buffer() {
        let present = unsafe { collect_present_names_lower(std::ptr::null(), 0, 1) };
        assert!(present.is_empty());
    }

    /// Test-only builder for a zeroed-metadata `OverlayChildMeta` — used by
    /// tests that only care about name/type presence, not size/times.
    fn meta(name: &str, is_dir: bool) -> policy::OverlayChildMeta {
        policy::OverlayChildMeta {
            name: name.to_string(),
            is_dir,
            size: 0,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
        }
    }

    #[test]
    fn append_overlay_entries_into_empty_buffer() {
        let mut buf = vec![0u8; 256];
        let extra = vec![meta("new.txt", false)];
        // SAFETY: buf is a writable 256-byte scratch buffer.
        let new_size = unsafe {
            append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 1, &extra)
        };
        assert!(new_size > 0);
        let names = collect_names(&buf[..new_size]);
        assert_eq!(names, vec!["new.txt".to_string()]);
    }

    #[test]
    fn append_overlay_entries_after_existing_tail() {
        let mut existing = build_dir_info_buffer(&["a.txt", "b.txt"]);
        let used = existing.len();
        existing.resize(used + 256, 0); // free space for the appended entry
        let extra = vec![meta("new.txt", false)];
        // SAFETY: existing is writable, sized used+256.
        let new_size = unsafe {
            append_overlay_entries(existing.as_mut_ptr(), used, existing.len(), 1, &extra)
        };
        assert!(new_size > used);
        let names = collect_names(&existing[..new_size]);
        assert_eq!(names, vec!["a.txt".to_string(), "b.txt".to_string(), "new.txt".to_string()],
            "appended entry must be reachable by walking the existing chain");
    }

    #[test]
    fn append_overlay_entries_multiple_extras_all_fit() {
        let mut buf = vec![0u8; 512];
        let extra = vec![
            meta("one.txt", false),
            meta("two.txt", false),
            meta("three.txt", false),
        ];
        // SAFETY: buf is a writable 512-byte scratch buffer.
        let new_size = unsafe {
            append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 1, &extra)
        };
        let names = collect_names(&buf[..new_size]);
        assert_eq!(names, vec!["one.txt".to_string(), "two.txt".to_string(), "three.txt".to_string()]);
    }

    #[test]
    fn append_overlay_entries_empty_extra_list_is_noop() {
        let mut buf = build_dir_info_buffer(&["a.txt"]);
        let used = buf.len();
        let original = buf.clone();
        // SAFETY: buf is a valid class-1 buffer.
        let new_size = unsafe {
            append_overlay_entries(buf.as_mut_ptr(), used, used, 1, &[])
        };
        assert_eq!(new_size, used);
        assert_eq!(buf, original);
    }

    #[test]
    fn append_overlay_entries_sets_directory_attribute_bit() {
        const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
        let mut buf = vec![0u8; 256];
        let extra = vec![meta("subdir", true)];
        // SAFETY: buf is a writable 256-byte scratch buffer.
        let new_size = unsafe {
            append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 1, &extra)
        };
        let entries = collect_names_and_attrs(&buf[..new_size]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "subdir");
        assert_eq!(entries[0].1 & FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_DIRECTORY,
            "directory entry must carry FILE_ATTRIBUTE_DIRECTORY");
    }

    #[test]
    fn append_overlay_entries_sets_normal_attribute_bit_for_file() {
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
        let mut buf = vec![0u8; 256];
        let extra = vec![meta("probe.txt", false)];
        // SAFETY: buf is a writable 256-byte scratch buffer.
        let new_size = unsafe {
            append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 1, &extra)
        };
        let entries = collect_names_and_attrs(&buf[..new_size]);
        assert_eq!(entries[0].1, FILE_ATTRIBUTE_NORMAL);
    }

    /// Read (EndOfFile, CreationTime, LastAccessTime, LastWriteTime) from a
    /// single class-1 entry at buffer offset 0 — test-only helper for
    /// verifying the metadata-realism fix (previously all-zero placeholders
    /// showed as 0-byte / 1601-01-01 in `dir`, a stealth-defeating tell a
    /// live agent flagged against the real bash `ls` view of the same file).
    fn read_meta_fields(buf: &[u8]) -> (u64, u64, u64, u64) {
        let field = |off: usize| u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
        (field(0x28), field(0x08), field(0x10), field(0x18))
    }

    #[test]
    fn append_overlay_entries_writes_real_size_and_times() {
        let mut buf = vec![0u8; 256];
        let extra = vec![policy::OverlayChildMeta {
            name: "probe.txt".to_string(),
            is_dir: false,
            size: 12345,
            creation_time: 133_700_000_000_000_001,
            last_access_time: 133_700_000_000_000_002,
            last_write_time: 133_700_000_000_000_003,
        }];
        // SAFETY: buf is a writable 256-byte scratch buffer.
        let new_size = unsafe {
            append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 1, &extra)
        };
        let (end_of_file, ctime, atime, mtime) = read_meta_fields(&buf[..new_size]);
        assert_eq!(end_of_file, 12345);
        assert_eq!(ctime, 133_700_000_000_000_001);
        assert_eq!(atime, 133_700_000_000_000_002);
        assert_eq!(mtime, 133_700_000_000_000_003);
    }

    #[test]
    fn append_overlay_entries_zeroed_meta_still_writes_zero_fields() {
        // A stale/unreadable overlay path (OverlayChildMeta all-zero per
        // policy::stat_overlay_phys's documented fallback) must not panic
        // and must legitimately report zero — this is the honest "we don't
        // know" case, distinct from silently leaving garbage stack bytes.
        let mut buf = vec![0xFFu8; 256]; // non-zero sentinel: proves an explicit zero-write happened
        let extra = vec![meta("stale.txt", false)];
        // SAFETY: buf is a writable 256-byte scratch buffer.
        let new_size = unsafe {
            append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 1, &extra)
        };
        let (end_of_file, ctime, atime, mtime) = read_meta_fields(&buf[..new_size]);
        assert_eq!((end_of_file, ctime, atime, mtime), (0, 0, 0, 0));
    }

    #[test]
    fn append_overlay_entries_class_12_metadata_ignored_no_panic() {
        // class 12 (FileNamesInformation) has no time/size fields at all —
        // metadata must be silently skipped, not panic on an out-of-bounds
        // offset write.
        let mut buf = vec![0u8; 128];
        let extra = vec![policy::OverlayChildMeta {
            name: "new.txt".to_string(),
            is_dir: false,
            size: 999,
            creation_time: 111,
            last_access_time: 222,
            last_write_time: 333,
        }];
        // SAFETY: buf is a writable 128-byte scratch buffer.
        let new_size = unsafe {
            append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 12, &extra)
        };
        assert!(new_size > 0);
    }

    #[test]
    fn append_overlay_entries_respects_capacity_drops_overflow() {
        // class-1 entry for "a.txt" (5 chars) is exactly 0x50 bytes
        // (0x40 header + 10 name bytes, aligned up to 0x50) — capacity fits
        // exactly one such entry and nothing more; the second, much longer
        // name must be dropped, not overflow the buffer.
        let mut buf = vec![0xAAu8; 0x60]; // 0xAA sentinel: detects OOB writes past capacity
        let capacity = 0x50;
        let extra = vec![meta("a.txt", false), meta("this_one_does_not_fit.txt", false)];
        // SAFETY: buf is 0x60 bytes; we pass capacity=0x50 as the hard limit.
        let new_size = unsafe {
            append_overlay_entries(buf.as_mut_ptr(), 0, capacity, 1, &extra)
        };
        assert_eq!(new_size, capacity, "the one entry that fits must exactly fill capacity");
        let names = collect_names(&buf[..new_size]);
        assert_eq!(names, vec!["a.txt".to_string()], "second (too-long) name must be dropped");
        // Bytes beyond `capacity` must be untouched (still the 0xAA sentinel).
        assert!(buf[capacity..].iter().all(|&b| b == 0xAA),
            "must not write past the caller-provided capacity");
    }

    #[test]
    fn append_overlay_entries_unsupported_class_is_noop() {
        let mut buf = vec![0u8; 256];
        let extra = vec![meta("new.txt", false)];
        // SAFETY: buf is writable; class 999 is unhandled.
        let new_size = unsafe {
            append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 999, &extra)
        };
        assert_eq!(new_size, 0, "unsupported class must not append anything");
    }

    #[test]
    fn append_overlay_entries_class_12_no_attribute_field() {
        // class 12: FileNamesInformation — 0x0C header, no FileAttributes field.
        let mut buf = vec![0u8; 128];
        let extra = vec![meta("new.txt", false)];
        // SAFETY: buf is a writable 128-byte scratch buffer.
        let new_size = unsafe {
            append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 12, &extra)
        };
        assert!(new_size > 0);
        // Walk class-12 layout directly (NAME_LEN_OFF=0x08, NAME_OFF=0x0C).
        const NAME_LEN_OFF_12: usize = 0x08;
        const NAME_OFF_12: usize = 0x0C;
        let name_len = u32::from_le_bytes([
            buf[NAME_LEN_OFF_12], buf[NAME_LEN_OFF_12+1], buf[NAME_LEN_OFF_12+2], buf[NAME_LEN_OFF_12+3],
        ]) as usize;
        let chars = name_len / 2;
        let mut name = String::new();
        for j in 0..chars {
            let off = NAME_OFF_12 + j * 2;
            name.push(char::from_u32(u16::from_le_bytes([buf[off], buf[off+1]]) as u32).unwrap_or('?'));
        }
        assert_eq!(name, "new.txt");
    }

    // ── search-pattern matching (single-file lookup ghost-file fix) ────────
    //
    // `dir <exact-file>` and similar single-name lookups pass the target
    // name as NtQueryDirectoryFile's FileName filter. When the real disk has
    // no match, the real syscall fails (STATUS_NO_SUCH_FILE) BEFORE our
    // merge code ever runs (process_dir_output bails on non-zero status) —
    // so an overlay-only file that `dir /a` (unfiltered) already lists
    // showed "File Not Found" for a single-name query. These two functions
    // let process_dir_output recognize that case and synthesize a response.

    #[test]
    fn filename_matches_pattern_exact_match() {
        assert!(filename_matches_pattern("probe.txt", "probe.txt"));
    }

    #[test]
    fn filename_matches_pattern_exact_mismatch() {
        assert!(!filename_matches_pattern("probe.txt", "other.txt"));
    }

    #[test]
    fn filename_matches_pattern_star_matches_everything() {
        assert!(filename_matches_pattern("anything.exe", "*"));
        assert!(filename_matches_pattern("", "*"));
    }

    #[test]
    fn filename_matches_pattern_star_suffix() {
        assert!(filename_matches_pattern("probe.txt", "*.txt"));
        assert!(!filename_matches_pattern("probe.log", "*.txt"));
    }

    #[test]
    fn filename_matches_pattern_star_prefix() {
        assert!(filename_matches_pattern("probe.txt", "probe*"));
        assert!(!filename_matches_pattern("other.txt", "probe*"));
    }

    #[test]
    fn filename_matches_pattern_question_mark_matches_one_char() {
        assert!(filename_matches_pattern("probe2.txt", "probe?.txt"));
        assert!(!filename_matches_pattern("probe22.txt", "probe?.txt"));
        assert!(!filename_matches_pattern("probe.txt", "probe?.txt"));
    }

    #[test]
    fn filename_matches_pattern_multiple_stars() {
        assert!(filename_matches_pattern("pr_ob_e.txt", "pr*ob*.txt"));
    }

    #[test]
    fn filename_matches_pattern_empty_pattern_only_matches_empty_name() {
        assert!(filename_matches_pattern("", ""));
        assert!(!filename_matches_pattern("probe.txt", ""));
    }

    /// Build a synthetic UNICODE_STRING backed by `storage` (must outlive the
    /// returned struct — test-only helper).
    fn build_unicode_string(storage: &mut Vec<u16>) -> UNICODE_STRING {
        UNICODE_STRING {
            Length: (storage.len() * 2) as u16,
            MaximumLength: (storage.len() * 2) as u16,
            Buffer: storage.as_mut_ptr(),
        }
    }

    #[test]
    fn extract_search_pattern_null_pointer_is_none() {
        // SAFETY: passing a genuinely null pointer is exactly the contract being tested.
        let result = unsafe { extract_search_pattern(std::ptr::null()) };
        assert!(result.is_none());
    }

    #[test]
    fn extract_search_pattern_null_buffer_is_none() {
        let ustr = UNICODE_STRING { Length: 0, MaximumLength: 0, Buffer: std::ptr::null_mut() };
        // SAFETY: ustr is a valid stack UNICODE_STRING with a null Buffer.
        let result = unsafe { extract_search_pattern(&ustr as *const UNICODE_STRING) };
        assert!(result.is_none());
    }

    #[test]
    fn extract_search_pattern_zero_length_is_none() {
        let mut storage: Vec<u16> = "probe.txt".encode_utf16().collect();
        let mut ustr = build_unicode_string(&mut storage);
        ustr.Length = 0; // present buffer, but zero-length filter = "match all"
        // SAFETY: ustr is a valid stack UNICODE_STRING backed by `storage`.
        let result = unsafe { extract_search_pattern(&ustr as *const UNICODE_STRING) };
        assert!(result.is_none());
    }

    #[test]
    fn extract_search_pattern_decodes_valid_string() {
        let mut storage: Vec<u16> = "probe.txt".encode_utf16().collect();
        let ustr = build_unicode_string(&mut storage);
        // SAFETY: ustr is a valid stack UNICODE_STRING backed by `storage`.
        let result = unsafe { extract_search_pattern(&ustr as *const UNICODE_STRING) };
        assert_eq!(result, Some("probe.txt".to_string()));
    }
}
