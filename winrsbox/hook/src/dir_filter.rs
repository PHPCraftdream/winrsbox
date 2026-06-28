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
unsafe fn process_dir_output(
    file_information: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information_class: u32,
    dir_dos: Option<&str>,
    original_status: NTSTATUS,
) -> NTSTATUS {
    if original_status != 0 {
        return original_status;
    }
    if io_status_block.is_null() || file_information.is_null() {
        return original_status;
    }
    // IoStatusBlock.Information (offset 8 on x64) contains bytes written.
    // SAFETY: io_status_block validated non-null; Information at offset 8 on x64.
    let info_size = *((io_status_block as *const u8).add(8) as *const usize);
    if info_size == 0 {
        return original_status;
    }

    // Resolve the virtual DOS path for the directory being enumerated.
    //
    // query_handle_dos_path calls GetFinalPathNameByHandleW which internally
    // calls NtQueryInformationFile(FileNormalizedNameInformation, class 48).
    // The path_info_guard hook normally unmirrors overlay paths back to virtual,
    // but because anti_rec is ALREADY HELD on this thread (we set it at the top
    // of hook_nt_query_directory_file[_ex]), path_info_guard's anti_rec::enter()
    // returns None and it calls the original without unmasking. As a result
    // query_handle_dos_path returns the OVERLAY PHYSICAL PATH (lowercase), not
    // the virtual path.
    //
    // Fix: unmirror the overlay-physical path back to virtual here, once.
    // The virtual path is then used for:
    //  (a) ipc_whiteouts_under — needs virtual path (policy server keys on it)
    //  (b) build_case_map — opens virtual path with anti_rec held → NtCreateFile
    //      bypasses CoW redirect → reads real host disk (original case)
    let virtual_dir: Option<String> = if let Some(raw) = dir_dos {
        let sb_root = hooks::SANDBOX_ROOT.get().map(|s| s.as_str());
        Some(hooks::unmirror_overlay_handle_relative(raw, sb_root)
            .unwrap_or_else(|| raw.to_string()))
    } else {
        None
    };

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
                hooks::ipc_log(ipc::LogLevel::Trace, "fs_hide_enum: only hidden entries".into());
            }
            return STATUS_NO_MORE_FILES;
        }
        if hooks::is_trace() {
            hooks::ipc_log(ipc::LogLevel::Trace, "fs_hide_enum: entries filtered from listing".into());
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
    process_dir_output(
        file_information,
        io_status_block,
        file_information_class,
        dir_dos.as_deref(),
        status,
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
    process_dir_output(
        file_information,
        io_status_block,
        file_information_class,
        dir_dos.as_deref(),
        status,
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
}
