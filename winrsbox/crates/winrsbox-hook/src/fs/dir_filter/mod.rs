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

use std::sync::OnceLock;
// Only the test modules (split out into sibling files) reach for these.
#[cfg(test)]
use std::collections::HashMap;

use detour2::GenericDetour;
use ntapi::ntioapi::IO_STATUS_BLOCK;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, UNICODE_STRING};
#[cfg(test)]
use ntapi::winapi::shared::ntdef::OBJECT_ATTRIBUTES;
use winapi::ctypes::c_void;

use crate::anti_rec;
use crate::hooks;
use crate::hooks::nt_call_original;

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
pub(crate) const fn dir_info_name_offsets(class: u32) -> Option<(usize, usize)> {
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
pub(crate) const fn dir_info_attr_offset(class: u32) -> Option<usize> {
    match class {
        1 | 2 | 3 | 37 | 38 => Some(0x38),
        _ => None,
    }
}

/// CreationTime/LastAccessTime/LastWriteTime/EndOfFile/AllocationSize field
/// offsets for directory-info classes that have them — same 1/2/3/37/38
/// shared prefix as `dir_info_attr_offset`; `FileNamesInformation` (12) has
/// none of these fields.
pub(crate) struct DirInfoTimeOffsets {
    creation_time: usize,
    last_access_time: usize,
    last_write_time: usize,
    end_of_file: usize,
    allocation_size: usize,
}
pub(crate) const fn dir_info_time_offsets(class: u32) -> Option<DirInfoTimeOffsets> {
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

pub(crate) const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub(crate) const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
/// NTFS cluster size used to round EndOfFile up to a plausible
/// AllocationSize — matches the common default cluster size; exactness
/// doesn't matter here, only "not a suspicious 0 next to a nonzero size".
pub(crate) const ASSUMED_CLUSTER_SIZE: u64 = 4096;

mod r#match;
mod supervision;

pub(crate) use r#match::*;
pub(crate) use supervision::*;

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
pub(crate) const STATUS_NO_SUCH_FILE: NTSTATUS = 0xC000000Fu32 as NTSTATUS;

/// The real STATUS_NO_MORE_FILES — error severity (0x8…), "the enumeration is
/// exhausted". The value this used to hold (0x0000_0104) is STATUS_REPARSE:
/// success severity, so `NT_SUCCESS(0x104)` is true — callers trusted the
/// filtered buffer and FindNextFile handed the guest the very record the
/// filter had removed. STATUS_NO_MORE_ENTRIES (0x8000_001A) is a different
/// status and must never be substituted here.
pub(crate) const STATUS_NO_MORE_FILES: NTSTATUS = 0x8000_0006_u32 as NTSTATUS;

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
pub(crate) fn resolve_virtual_dir(dir_dos: Option<&str>) -> Option<String> {
    let raw = dir_dos?;
    let sb_root = hooks::SANDBOX_ROOT.get().map(|s| s.as_str());
    Some(hooks::unmirror_overlay_handle_relative(raw, sb_root).unwrap_or_else(|| raw.to_string()))
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
        return nt_call_original!(
            &HOOK_NT_QUERY_DIRECTORY_FILE,
            "NtQueryDirectoryFile",
            (file_handle, event, apc_routine, apc_context, io_status_block,
             file_information, length, file_information_class,
             return_single_entry, file_name, restart_scan)
        );
    };

    // Async-supervision gate: a query on a handle opened for asynchronous
    // I/O used to return STATUS_PENDING here, fell through
    // process_dir_output's `original_status != 0` early-return, and the
    // guest later read an unfiltered listing once the I/O completed.
    // Substitute our own event so completion cannot be observed before
    // filtering; on STATUS_PENDING block until completion and hand the
    // filter the final status.
    let Some(supervision) = DirQuerySupervision::new(event) else {
        // Fail-closed: never run a query we cannot supervise.
        if hooks::is_trace() {
            hooks::ipc_log(ipc::LogLevel::Trace,
                "fs_enum_async_unsupervised_refused: NtCreateEvent failed".to_string());
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    };

    // SAFETY: detour2 trampoline matches FnNtQueryDirectoryFile ABI; the
    // caller's Event handle is replaced by supervision.query_event() (see
    // DirQuerySupervision) — every other argument passes through unchanged.
    let status = nt_call_original!(
        &HOOK_NT_QUERY_DIRECTORY_FILE,
        "NtQueryDirectoryFile",
        (file_handle, supervision.query_event(), apc_routine, apc_context,
         io_status_block, file_information, length, file_information_class,
         return_single_entry, file_name, restart_scan)
    );

    // STATUS_PENDING → block until the kernel completes the I/O, then adopt
    // the final status so the filter below always sees a completed buffer.
    let status = supervision.wait_if_pending(status, io_status_block);

    let dir_dos = crate::fs_metadata_guard::query_handle_dos_path(file_handle);
    // SAFETY: file_name is the same UNICODE_STRING pointer ntdll passed us;
    // valid (or null) per the NT contract at hook entry.
    let search_pattern = extract_search_pattern(file_name);
    // `supervision` drops only AFTER the process_dir_output tail expression
    // below is evaluated: Drop signals the caller's event strictly after the
    // buffer has been filtered, so pre-filter data is never observable.
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
        return nt_call_original!(
            &HOOK_NT_QUERY_DIRECTORY_FILE_EX,
            "NtQueryDirectoryFileEx",
            (file_handle, event, apc_routine, apc_context, io_status_block,
             file_information, length, file_information_class,
             query_flags, file_name)
        );
    };

    // Async-supervision gate: a query on a handle opened for asynchronous
    // I/O used to return STATUS_PENDING here, fell through
    // process_dir_output's `original_status != 0` early-return, and the
    // guest later read an unfiltered listing once the I/O completed.
    // Substitute our own event so completion cannot be observed before
    // filtering; on STATUS_PENDING block until completion and hand the
    // filter the final status.
    let Some(supervision) = DirQuerySupervision::new(event) else {
        // Fail-closed: never run a query we cannot supervise.
        if hooks::is_trace() {
            hooks::ipc_log(ipc::LogLevel::Trace,
                "fs_enum_async_unsupervised_refused: NtCreateEvent failed".to_string());
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    };

    // SAFETY: detour2 trampoline matches FnNtQueryDirectoryFileEx ABI; the
    // caller's Event handle is replaced by supervision.query_event() (see
    // DirQuerySupervision) — every other argument passes through unchanged.
    let status = nt_call_original!(
        &HOOK_NT_QUERY_DIRECTORY_FILE_EX,
        "NtQueryDirectoryFileEx",
        (file_handle, supervision.query_event(), apc_routine, apc_context,
         io_status_block, file_information, length, file_information_class,
         query_flags, file_name)
    );

    // STATUS_PENDING → block until the kernel completes the I/O, then adopt
    // the final status so the filter below always sees a completed buffer.
    let status = supervision.wait_if_pending(status, io_status_block);

    let dir_dos = crate::fs_metadata_guard::query_handle_dos_path(file_handle);
    // SAFETY: file_name is the same UNICODE_STRING pointer ntdll passed us;
    // valid (or null) per the NT contract at hook entry.
    let search_pattern = extract_search_pattern(file_name);
    // `supervision` drops only AFTER the process_dir_output tail expression
    // below is evaluated: Drop signals the caller's event strictly after the
    // buffer has been filtered, so pre-filter data is never observable.
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
mod match_tests;
#[cfg(test)]
mod tests;
