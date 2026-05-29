// dir_filter — NtQueryDirectoryFile hook.
//
// Filters `.winrsbox` entries from directory listings so sandboxed processes
// cannot see the sandbox state directory.

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
/// entry whose FileName is `.winrsbox` (case-insensitive). For unhandled
/// FileInformationClass values, returns `false` (caller should passthrough).
///
/// Returns `true` if filtering was applied (buffer may have been modified).
/// If the only entry was `.winrsbox`, returns `true` and sets `*only_hidden = true`.
///
/// # SAFETY
/// `buf` must point to a writable region of `total_size` bytes containing a valid
/// NtQueryDirectoryFile linked-list buffer for the given `class`.
unsafe fn filter_dot_winrsbox(
    buf: *mut u8,
    total_size: usize,
    class: u32,
    only_hidden: &mut bool,
) -> bool {
    let Some((name_len_off, name_off)) = dir_info_name_offsets(class) else {
        return false;
    };

    let mut prev: *mut u8 = std::ptr::null_mut();
    let mut cur = buf;
    let end = buf.add(total_size);
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
        if name_len >= 2 && name_len <= 22 && name_off + name_len <= avail {
            let name_ptr = cur.add(name_off) as *const u16;
            let chars = name_len / 2;
            // SAFETY: from_raw_parts for `chars` u16s at FileName offset; the
            // `name_off + name_len <= avail` guard above bounds the read.
            let name_slice = std::slice::from_raw_parts(name_ptr, chars);
            let is_winrsbox = chars == 9
                && (name_slice[0] == '.' as u16)
                && (name_slice[1] == 'W' as u16 || name_slice[1] == 'w' as u16)
                && (name_slice[2] == 'I' as u16 || name_slice[2] == 'i' as u16)
                && (name_slice[3] == 'N' as u16 || name_slice[3] == 'n' as u16)
                && (name_slice[4] == 'R' as u16 || name_slice[4] == 'r' as u16)
                && (name_slice[5] == 'S' as u16 || name_slice[5] == 's' as u16)
                && (name_slice[6] == 'B' as u16 || name_slice[6] == 'b' as u16)
                && (name_slice[7] == 'O' as u16 || name_slice[7] == 'o' as u16)
                && (name_slice[8] == 'X' as u16 || name_slice[8] == 'x' as u16);

            if is_winrsbox {
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

    let mut only_hidden = false;
    if filter_dot_winrsbox(
        file_information as *mut u8,
        info_size,
        file_information_class,
        &mut only_hidden,
    ) {
        if only_hidden {
            // The only entry was .winrsbox — return NO_MORE_FILES
            const STATUS_NO_MORE_FILES: NTSTATUS = 0x0000_0104_u32 as NTSTATUS;
            if hooks::is_trace() {
                hooks::ipc_log(ipc::LogLevel::Trace, "fs_hide_winrsbox_enum: only entry hidden".into());
            }
            return STATUS_NO_MORE_FILES;
        }
        if hooks::is_trace() {
            hooks::ipc_log(ipc::LogLevel::Trace, "fs_hide_winrsbox_enum: entry filtered from listing".into());
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
