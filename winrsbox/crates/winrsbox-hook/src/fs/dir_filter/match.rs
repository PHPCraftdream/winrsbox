use std::collections::HashMap;

use ntapi::winapi::shared::ntdef::UNICODE_STRING;

use super::{
    ASSUMED_CLUSTER_SIZE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    dir_info_attr_offset, dir_info_name_offsets, dir_info_time_offsets,
};

/// Case-sensitive DOS-style single-segment wildcard match: `*` = any run of
/// chars (including none), `?` = exactly one char, everything else literal.
/// Callers fold both `name` and `pattern` to the same case before calling —
/// this function does no case-folding itself so it stays a pure string op.
///
/// Classic greedy-with-backtrack glob algorithm (iterative, O(n*m) worst
/// case, no recursion — a hostile pattern like `"****...*"` cannot blow the
/// stack).
pub(crate) fn filename_matches_pattern(name: &str, pattern: &str) -> bool {
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
///
/// Alignment is explicitly NOT assumed: `p` and `Buffer` are the hooked
/// caller's addresses, and a hostile caller controls both. `&*p` would
/// assert UNICODE_STRING's natural pointer alignment and
/// `slice::from_raw_parts::<u16>` would assert `Buffer` evenness — so the
/// header is read field-wise with unaligned loads and each WCHAR is read
/// unaligned (byte-wise under the hood). Validity for `Length` bytes remains
/// the caller's obligation, exactly as before.
pub(crate) unsafe fn extract_search_pattern(p: *const UNICODE_STRING) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: read_unaligned of a non-null UNICODE_STRING pointer — validity
    // per the SAFETY contract above, alignment never assumed.
    let ustr = (p as *const UNICODE_STRING).read_unaligned();
    if ustr.Buffer.is_null() {
        return None;
    }
    let char_count = (ustr.Length as usize) / 2;
    if char_count == 0 {
        return None;
    }
    // SAFETY: `char_count` WCHARs read unaligned from Buffer, bounded by
    // Length per the NT UNICODE_STRING contract this function documents.
    let chars: Vec<u16> = (0..char_count)
        .map(|i| (ustr.Buffer.cast::<u8>().add(i * 2) as *const u16).read_unaligned())
        .collect();
    Some(String::from_utf16_lossy(&chars))
}

/// Lowercase FileNames of every entry in a (possibly already hide-filtered)
/// NtQueryDirectoryFile buffer. Used so overlay-only injection never
/// double-lists a name the real disk already reported.
///
/// # SAFETY
/// `buf` must be valid for `size` bytes (or `size == 0`, in which case `buf`
/// is never dereferenced) containing a well-formed buffer for `class`.
pub(crate) unsafe fn collect_present_names_lower(buf: *const u8, size: usize, class: u32) -> std::collections::HashSet<String> {
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
        // SAFETY: NextEntryOffset @ 0, FileNameLength @ name_len_off — guarded
        // by avail; read unaligned because `buf`'s base alignment is
        // caller-controlled (this buffer comes from sandboxed user code).
        let next_off = (buf.add(cur) as *const u32).read_unaligned() as usize;
        let name_len = (buf.add(cur + name_len_off) as *const u32).read_unaligned() as usize;
        if name_len >= 2 && name_off + name_len <= avail {
            // SAFETY: FileName @ name_off, `chars` u16s — bounded by the check
            // above; each WCHAR is read unaligned for the same reason.
            let name_ptr = buf.add(cur + name_off) as *const u16;
            let chars = name_len / 2;
            let lower: String = (0..chars)
                .map(|i| name_ptr.add(i).read_unaligned())
                .flat_map(|u| std::char::decode_utf16(std::iter::once(u)))
                .map(|r| r.unwrap_or('\u{FFFD}'))
                .map(|c| c.to_ascii_lowercase())
                .collect();
            out.insert(lower);
        }
        if next_off == 0 || next_off > avail { break; }
        cur += next_off;
    }
    out
}

/// Byte length of the live record chain in a NtQueryDirectoryFile buffer:
/// walks the NextEntryOffset links from offset 0 and returns the offset just
/// past the record whose NextEntryOffset == 0 — the kernel's own Information
/// convention ("last entry + that entry's ACTUAL length", no trailing
/// padding). Used to re-report Information after in-place hide-filtering
/// shrank the chain, so the IOSB never advertises removed bytes.
///
/// Defensive on malformed input (the kernel never emits it, but the buffer
/// base is caller-controlled): returns `max` for an unhandled class (the
/// caller passes the original size through unchanged), 0 for a null/empty
/// buffer, and stops at the first record whose header doesn't fit, whose
/// name field overruns the buffer, or whose link points past `max` —
/// returning the last verified-good boundary rather than panicking or
/// reading out of bounds.
///
/// # SAFETY
/// `buf` must be valid for `max` bytes (or `buf` null / `max == 0`, in which
/// case it is never dereferenced) holding a record chain laid out for
/// `class`.
pub(crate) unsafe fn buffer_live_size(buf: *const u8, max: usize, class: u32) -> usize {
    let Some((name_len_off, name_off)) = dir_info_name_offsets(class) else {
        return max;
    };
    if buf.is_null() || max == 0 {
        return 0;
    }
    let mut cur = 0usize;
    loop {
        let avail = max - cur;
        if avail < name_len_off + 4 {
            // Header doesn't fit: only [0, cur) is provably well-formed.
            return cur;
        }
        // SAFETY: NextEntryOffset (offset 0) and FileNameLength (class-
        // specific offset) are guarded by the avail check above. Both are
        // read unaligned: `buf`'s base alignment is caller-controlled
        // (this buffer comes from sandboxed user code).
        let next_off = (buf.add(cur) as *const u32).read_unaligned() as usize;
        let name_len = (buf.add(cur + name_len_off) as *const u32).read_unaligned() as usize;
        if next_off == 0 {
            // Chain terminator: report the record's ACTUAL extent.
            if name_off + name_len > avail {
                return cur; // name field overruns the buffer — don't trust it
            }
            return cur + name_off + name_len;
        }
        if next_off > avail {
            return cur; // link past the buffer — malformed
        }
        cur += next_off;
    }
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
/// pages through a directory sees them on a later call). Continuation
/// across calls is the CALLER's job: `process_dir_output` tracks a per-
/// handle overlay cursor (`DirEnumState`) and feeds this function one
/// pending entry at a time, so a filled buffer leaves the remaining extras
/// pending instead of losing them. Note the returned size when nothing was
/// written is the rounded-up append point `(used_size + 7) & !7`, which can
/// exceed `used_size` for an unaligned tail — callers must not read that as
/// "a record was appended".
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
pub(crate) unsafe fn append_overlay_entries(
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
            // SAFETY: NextEntryOffset @ 0 — guarded by avail >= 4; read
            // unaligned because `buf`'s base alignment is caller-controlled.
            let next_off = (buf.add(cur) as *const u32).read_unaligned() as usize;
            if next_off == 0 || next_off > avail {
                prev_start = Some(cur);
                break;
            }
            cur += next_off;
        }
    }

    // Round the append point up to an 8-byte boundary. The kernel reports
    // IoStatusBlock.Information as "offset of the last entry + that entry's
    // actual length" — with NO trailing alignment padding — so `used_size`
    // is routinely NOT a multiple of 8. Appending straight at `used_size`
    // would (a) start a record on a misaligned address, which is UB for the
    // field writes below AND is caught at runtime by Rust's alignment check
    // in debug builds, and (b) violate the NT contract that every
    // directory-info record sits on an 8-byte boundary (consumers read the
    // LARGE_INTEGER time/size fields as aligned u64s; on ARM64 that faults).
    // The gap bytes are never walked: the previous tail's NextEntryOffset is
    // patched to point directly at the aligned start.
    let mut write_at = (used_size + 7) & !7;

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
        // Every field write goes through `write_unaligned`: `buf` itself is
        // caller-provided memory with no alignment guarantee, so a plain
        // `*(ptr as *mut uN) = v` would be UB (and aborts under Rust's debug
        // alignment check) whenever the caller hands us an odd base address.
        // NextEntryOffset = 0 — this entry is the new tail until (if) the
        // next extra gets linked after it below.
        (entry_ptr as *mut u32).write_unaligned(0);
        (entry_ptr.add(name_len_off) as *mut u32).write_unaligned(name_bytes as u32);
        if let Some(attr_off) = dir_info_attr_offset(class) {
            let attrs = if meta.is_dir { FILE_ATTRIBUTE_DIRECTORY } else { FILE_ATTRIBUTE_NORMAL };
            (entry_ptr.add(attr_off) as *mut u32).write_unaligned(attrs);
        }
        if let Some(ref t) = time_offs {
            // A live stat of the physical overlay file (or all-zero for a
            // stale/unreadable index entry — an honest "unknown", not
            // garbage). Real values here are what stops `dir` showing every
            // overlay-only file as 0 bytes / 1601-01-01.
            (entry_ptr.add(t.creation_time) as *mut u64).write_unaligned(meta.creation_time);
            (entry_ptr.add(t.last_access_time) as *mut u64).write_unaligned(meta.last_access_time);
            (entry_ptr.add(t.last_write_time) as *mut u64).write_unaligned(meta.last_write_time);
            (entry_ptr.add(t.end_of_file) as *mut u64).write_unaligned(meta.size);
            let alloc = meta.size.div_ceil(ASSUMED_CLUSTER_SIZE) * ASSUMED_CLUSTER_SIZE;
            (entry_ptr.add(t.allocation_size) as *mut u64).write_unaligned(alloc);
        }
        let name_dst = entry_ptr.add(name_off) as *mut u16;
        for (j, &u) in name_u16.iter().enumerate() {
            *name_dst.add(j) = u;
        }

        // Link the previous tail (real or previously-appended) to this entry.
        if let Some(prev) = prev_start {
            (buf.add(prev) as *mut u32).write_unaligned((write_at - prev) as u32);
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
pub(crate) unsafe fn filter_entries(
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
        // SAFETY: NextEntryOffset (offset 0) and FileNameLength (class-
        // specific offset) are guarded by the avail check above. Both are
        // read unaligned: `buf`'s base alignment is controlled by the
        // sandboxed caller, so a record can start at an odd address.
        let next_off = (cur as *const u32).read_unaligned() as usize;
        let name_len = (cur.add(name_len_off) as *const u32).read_unaligned() as usize;
        // Inspect the name only when the whole field provably fits in the buffer.
        if name_len >= 2 && name_off + name_len <= avail {
            let name_ptr = cur.add(name_off) as *const u16;
            let chars = name_len / 2;
            // The name is read through name_matches_any_unaligned: `name_ptr`
            // is `chars` u16s into caller-owned memory (bounded by the
            // `name_off + name_len <= avail` guard above) with no alignment
            // guarantee, so slice::from_raw_parts would be UB on an odd
            // record address.
            if name_matches_any_unaligned(name_ptr, chars, hide_names) {
                filtered_any = true;
                if !prev.is_null() {
                    // Middle/last entry: patch previous to skip this one.
                    // Read/write unaligned: `prev` is a record start in the
                    // caller-aligned buffer, so it can sit at an odd address.
                    // SAFETY: prev points at a live in-buffer record whose
                    // NextEntryOffset (offset 0) is guarded by avail >= 4.
                    let prev_next = (prev as *const u32).read_unaligned() as usize;
                    let new_next = if next_off == 0 {
                        0u32
                    } else {
                        (prev_next + next_off) as u32
                    };
                    // SAFETY: same in-buffer record as above.
                    (prev as *mut u32).write_unaligned(new_next);
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

/// Raw-pointer variant of `name_matches_any`: reads the candidate name
/// through `name_ptr` with UNALIGNED accesses. Directory-info record buffers
/// come from sandboxed user code with no base-alignment guarantee, so a
/// record's FileName can start at an odd address; minting a
/// `&[u16]` there via slice::from_raw_parts would be UB.
pub(crate) fn name_matches_any_unaligned(
    name_ptr: *const u16,
    chars: usize,
    hide_names: &[Vec<u16>],
) -> bool {
    for hide in hide_names {
        if chars != hide.len() {
            continue;
        }
        let mut all_eq = true;
        for (i, &b) in hide.iter().enumerate() {
            // SAFETY: i < chars == hide.len(), and the caller guarantees
            // `chars` u16s are readable at name_ptr (bounded by the walk's
            // `name_off + name_len <= avail` check).
            let a = unsafe { name_ptr.add(i).read_unaligned() };
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
pub(crate) fn dot_winrsbox_u16() -> Vec<u16> {
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
pub(crate) unsafe fn build_case_map_with_fallback(
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
pub(crate) unsafe fn build_case_map(dir_dos: &str) -> Option<HashMap<String, Vec<u16>>> {
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
pub(crate) unsafe fn rewrite_entry_case(
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
        // SAFETY: NextEntryOffset (offset 0) and FileNameLength (class-
        // specific offset) are guarded by avail. Both are read unaligned:
        // the buffer's base alignment is controlled by the sandboxed caller,
        // so a record can start at an odd address.
        let next_off = (cur as *const u32).read_unaligned() as usize;
        let name_len = (cur.add(name_len_off) as *const u32).read_unaligned() as usize;

        if name_len >= 2 && name_off + name_len <= avail {
            let name_ptr = cur.add(name_off) as *mut u16;
            let chars = name_len / 2;

            // Build the lowercase lookup key. Each WCHAR is read unaligned:
            // `name_ptr` is `chars` u16s into caller-owned memory (bounded by
            // the `name_off + name_len <= avail` guard above) with no
            // alignment guarantee, so slice::from_raw_parts would be UB on an
            // odd record address.
            let lower: String = (0..chars)
                .map(|i| {
                    // SAFETY: i < chars, bounded by the avail check above.
                    unsafe { name_ptr.add(i).read_unaligned() }
                })
                .flat_map(|u| std::char::decode_utf16(std::iter::once(u)))
                .map(|r| r.unwrap_or('\u{FFFD}'))
                .flat_map(|c| c.to_ascii_lowercase().to_string().chars().collect::<Vec<_>>())
                .collect();

            if let Some(correct) = case_map.get(&lower) {
                // Only rewrite when same length (case change only). Length
                // difference would require structural changes — skip those.
                if correct.len() == chars {
                    // SAFETY: byte-wise copy — memcpy semantics with no
                    // alignment precondition (u8 is aligned everywhere, and
                    // ptr::copy_nonoverlapping::<u16> would demand u16
                    // alignment the odd record address cannot offer), and
                    // the map's buffer cannot overlap the record buffer.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            correct.as_ptr() as *const u8,
                            name_ptr as *mut u8,
                            chars * 2,
                        );
                    }
                }
            }
        }

        if next_off == 0 || next_off > avail {
            break;
        }
        cur = cur.add(next_off);
    }
}
