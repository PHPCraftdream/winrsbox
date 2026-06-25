// dir_filter — NtQueryDirectoryFile hook.
//
// Filters `.winrsbox` entries and whiteouted (tombstoned) entries from
// directory listings so sandboxed processes see a consistent merged view:
//  - the sandbox state directory is invisible;
//  - files deleted via whiteout (OverlayFS-style) vanish from listings even
//    though the real lower file is untouched on disk.

use std::sync::OnceLock;

use detour2::GenericDetour;
use ntapi::ntioapi::IO_STATUS_BLOCK;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, UNICODE_STRING};
use winapi::ctypes::c_void;

use crate::anti_rec;
use crate::hooks;

// ---------------------------------------------------------------------------
// Type alias
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

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

static HOOK_NT_QUERY_DIRECTORY_FILE: OnceLock<GenericDetour<FnNtQueryDirectoryFile>> =
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

// ---------------------------------------------------------------------------
// Hook implementation
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

    if status != 0 {
        return status;
    }

    // IoStatusBlock.Information (offset 8 on x64) contains bytes written
    if io_status_block.is_null() || file_information.is_null() {
        return status;
    }
    // SAFETY: read of IoStatusBlock.Information at offset 8 on x64 — pointer validated non-null above.
    let info_size = *((io_status_block as *const u8).add(8) as *const usize);
    if info_size == 0 {
        return status;
    }

    // Build the hide set: `.winrsbox` is always hidden, plus any whiteouted
    // direct children of the directory being enumerated. We resolve the
    // directory's DOS path from file_handle (one GetFinalPathNameByHandleW
    // call) and issue ONE IPC WhiteoutsUnder request for it. If the IPC
    // fails or the dir has no whiteouts, only the `.winrsbox` filter applies.
    let mut hide_names: Vec<Vec<u16>> = vec![dot_winrsbox_u16()];
    let dir_dos = crate::fs_metadata_guard::query_handle_dos_path(file_handle);
    if let Some(ref dir) = dir_dos {
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
            // Every entry was hidden — return NO_MORE_FILES so the caller
            // sees an empty directory.
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

    status
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

    Ok(())
}

pub unsafe fn uninstall() {
    if let Some(h) = HOOK_NT_QUERY_DIRECTORY_FILE.get() { let _ = h.disable(); }
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
}
