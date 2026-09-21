// FS hooks: hook_nt_create_file, hook_nt_open_file, hook_nt_query_attributes_file,
// hook_nt_query_full_attributes_file, and their OnceLock statics + type aliases.

use std::sync::OnceLock;
use winapi::ctypes::c_void;

use detour2::GenericDetour;
use ntapi::ntioapi::IO_STATUS_BLOCK;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES};
use ntapi::winapi::um::winnt::ACCESS_MASK;
use policy::Mode;

use crate::anti_rec;
use crate::hooked_attrs::HookedAttrs;
use crate::hooks::{
    check_path_traversal, classify_device_open, DeviceVerdict, decide, resolve_for_hook,
    is_write_access, materialize_mock_overlay,
    prepare_overlay, set_io_status, ipc_record_overlay, ipc_record_overlay_case,
    extract_nt_basename, nt_call_original,
    FILE_CREATE, FILE_DELETE_ON_CLOSE, FILE_OPEN, FILE_OPEN_IF, FILE_OVERWRITE_IF,
    FILE_SUPERSEDE, STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_NOT_FOUND,
};
use crate::ipc_client::{
    cache, ipc_log, is_trace,
    ipc_clear_whiteout,
};

mod detours;

pub(crate) use detours::*;

// ---------------------------------------------------------------------------
// Dead-end (unresolved-path) write intent
// ---------------------------------------------------------------------------

// When resolve_for_hook returns None, the policy pipeline (decide()) was
// never consulted. The documented model lets READS outside project_root
// pass through to the real disk, so unresolved reads keep the tripwire
// passthrough. A WRITE that cannot be classified must fail CLOSED: calling
// the original NtCreateFile/NtOpenFile here would land the write on the
// real disk/volume/share outside the CoW overlay — the P0-03 UNC escape
// class.
//
// The desired-access/disposition clause IS the canonical `is_write_access`
// (unified: the dead end used to keep its own broader mask, and two
// diverging definitions of "this open intends to write" are how
// write-granting bits like GENERIC_ALL reappear as "reads" on the resolved
// path). The only dead-end extra is the FILE_DELETE_ON_CLOSE options bit,
// which rides in CreateOptions rather than DesiredAccess; an actual
// deletion also needs the DELETE access bit, which the canonical mask
// already treats as a write.
/// Write intent for the unresolved (dead-end) branch. `disposition` is
/// Some(create_disposition) for NtCreateFile and None for NtOpenFile (which
/// has no disposition parameter — FILE_OPEN keeps the disposition clause
/// of the canonical mask inert).
fn dead_end_write_intent(desired_access: u32, disposition: Option<u32>, options: u32) -> bool {
    is_write_access(desired_access, disposition.unwrap_or(FILE_OPEN))
        || options & FILE_DELETE_ON_CLOSE != 0
}

// ---------------------------------------------------------------------------
// Nt* function type aliases
// ---------------------------------------------------------------------------

pub(crate) type FnNtCreateFile = unsafe extern "system" fn(
    *mut HANDLE,            // FileHandle
    ACCESS_MASK,            // DesiredAccess
    *mut OBJECT_ATTRIBUTES, // ObjectAttributes
    *mut IO_STATUS_BLOCK,   // IoStatusBlock
    *mut i64,               // AllocationSize
    u32,                    // FileAttributes
    u32,                    // ShareAccess
    u32,                    // CreateDisposition
    u32,                    // CreateOptions
    *mut c_void,            // EaBuffer
    u32,                    // EaLength
) -> NTSTATUS;

pub(crate) type FnNtOpenFile = unsafe extern "system" fn(
    *mut HANDLE,            // FileHandle
    ACCESS_MASK,            // DesiredAccess
    *mut OBJECT_ATTRIBUTES, // ObjectAttributes
    *mut IO_STATUS_BLOCK,   // IoStatusBlock
    u32,                    // ShareAccess
    u32,                    // OpenOptions
) -> NTSTATUS;

pub(crate) type FnNtQueryAttributesFile = unsafe extern "system" fn(
    *mut OBJECT_ATTRIBUTES, // ObjectAttributes
    *mut c_void,            // FileInformation
) -> NTSTATUS;

pub(crate) type FnNtQueryFullAttributesFile = unsafe extern "system" fn(
    *mut OBJECT_ATTRIBUTES, // ObjectAttributes
    *mut c_void,            // FileInformation
) -> NTSTATUS;

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

pub(crate) static HOOK_NT_CREATE_FILE: OnceLock<GenericDetour<FnNtCreateFile>> = OnceLock::new();
pub(crate) static HOOK_NT_OPEN_FILE: OnceLock<GenericDetour<FnNtOpenFile>> = OnceLock::new();
pub(crate) static HOOK_NT_QUERY_ATTRIBUTES_FILE: OnceLock<GenericDetour<FnNtQueryAttributesFile>> =
    OnceLock::new();
pub(crate) static HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE: OnceLock<GenericDetour<FnNtQueryFullAttributesFile>> =
    OnceLock::new();

// ---------------------------------------------------------------------------
// CreateOptions flag bits + dispositions (audit H-S2 / H-S3 mitigation)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Pure classifier helpers (testable, no FFI)
// ---------------------------------------------------------------------------
//
// Note: a former `is_reparse_create` predicate + its `FILE_OPEN_REPARSE_POINT`
// / `FILE_OPEN_DISPOSITION` constants used to live here. They were removed
// after the audit found the check was overzealous (the flag controls
// traversal, not creation — only `FSCTL_SET_REPARSE_POINT[_EX]` actually
// plants a reparse point, and those are unconditionally denied in
// `fs_metadata_guard`). The dead check was false-positive'ing legitimate
// IPC primitives (wezterm's blob-lease in %TEMP%).

/// Returns true when the caller supplied an NTFS Extended Attribute buffer.
///
/// Audit H-S3 — EAs are not listed by directory enumeration, persist across
/// reboots, and recent BlackLotus-class loaders use them as covert storage.
/// No AI-agent toolchain we support sets EAs, so we treat any non-empty
/// buffer as hostile and deny defense-in-depth.
#[inline]
pub(crate) fn is_ea_present(ea_buffer: *const c_void, ea_length: u32) -> bool {
    !ea_buffer.is_null() && ea_length > 0
}

/// True iff `create_disposition` (NtCreateFile) requests that a file be
/// CREATED rather than merely opened. Such a disposition against a
/// whiteouted path is a REVIVE: the caller wants to (re)create the file, so
/// we must clear the whiteout marker and let the create proceed into the
/// overlay, rather than returning not-found.
///
/// FILE_OPEN (1) and FILE_OVERWRITE (4) are NOT creates:
///  - FILE_OPEN fails if the file does not exist — it's a pure open.
///  - FILE_OVERWRITE opens-then-truncates an EXISTING file; for a hidden
///    path it must surface not-found (the file is gone from the view).
#[inline]
pub(crate) fn is_create_disposition(create_disposition: u32) -> bool {
    matches!(
        create_disposition,
        FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE_IF | FILE_SUPERSEDE
    )
}

#[cfg(test)]
mod tests;
