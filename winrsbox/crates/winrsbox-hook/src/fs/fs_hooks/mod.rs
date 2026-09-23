// FS hooks: hook_nt_create_file, hook_nt_open_file, hook_nt_query_attributes_file,
// hook_nt_query_full_attributes_file, and their OnceLock statics + type aliases.

use std::sync::OnceLock;
use winapi::ctypes::c_void;

use detour2::GenericDetour;
use ntapi::ntioapi::IO_STATUS_BLOCK;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES};
use ntapi::winapi::um::winnt::ACCESS_MASK;
use policy::{Decision, Mode};

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

// ---------------------------------------------------------------------------
// C04 (docs/review-xa-2026-09-20): stale cached Cow + overlay-index publish
// ordering
// ---------------------------------------------------------------------------

/// Pure-FS probe: does this decision name an overlay target that is
/// physically absent right now? C04: the trigger condition for a
/// possibly-stale cached Cow.
pub(crate) fn overlay_target_missing(decision: &Decision) -> bool {
    decision
        .overlay
        .as_ref()
        .is_some_and(|p| !std::path::Path::new(p).exists())
}

/// C04: a locally cached Cow decision can outlive the overlay file — a
/// sibling process may have deleted the overlay copy and recorded a
/// whiteout after this process cached Cow. When the overlay target is
/// physically missing, drop the cached entry and re-decide fresh: the
/// server cleared its own cache on the sibling's mutation, so the fresh
/// decision is current (Hidden for a whiteout, Deny for a fresh rule,
/// Cow when the copy genuinely wasn't made yet). The caller must act on
/// the RETURNED decision, not the original.
pub(crate) fn decide_fresh_if_overlay_missing(
    decision: &Decision,
    dos: &str,
    write: bool,
) -> Decision {
    if !overlay_target_missing(decision) {
        return decision.clone();
    }
    let lower = policy::path::nt_case_fold(dos);
    // PERF-cow: the physical overlay vanished, so the index state for this
    // path is untrusted — the next materialization must re-publish.
    overlay_publish_forget(&lower);
    cache().invalidate(&lower);
    decide(dos, write)
}

/// C04 gate: NT_SUCCESS is a non-negative NTSTATUS.
pub(crate) fn cow_publish_allowed(status: NTSTATUS) -> bool {
    status >= 0
}

/// PERF-cow: process-local registry of overlay paths whose index entry this
/// process has already published successfully. Bounded like HookCache;
/// eviction is the safe direction (one redundant re-publish, never a missed
/// first publish).
fn overlay_publish_registry() -> &'static quick_cache::sync::Cache<String, ()> {
    static REG: OnceLock<quick_cache::sync::Cache<String, ()>> = OnceLock::new();
    REG.get_or_init(|| quick_cache::sync::Cache::new(8192))
}

pub(crate) fn overlay_already_published(lower: &str) -> bool {
    overlay_publish_registry().get(lower).is_some()
}

pub(crate) fn overlay_mark_published(lower: &str) {
    overlay_publish_registry().insert(lower.to_owned(), ());
}

/// Re-arm publication: any local event that can mean the overlay index and
/// the physical overlay diverged (failed redirected open, stale-cache
/// re-decide, whiteout revive) must force the next successful
/// materialization to re-publish.
pub(crate) fn overlay_publish_forget(lower: &str) {
    overlay_publish_registry().remove(lower);
}

/// C04: publish the overlay index only AFTER the redirected kernel open
/// succeeded. Records idx + original-case basename, then drops the local
/// cached decision for the path so the next decide sees the overlay.
/// PERF-cow: publication is idempotent per process — a path already marked
/// published skips BOTH IPC writes and the local invalidation; divergence
/// events call `overlay_publish_forget` to re-arm it.
pub(crate) fn publish_overlay_decision(
    lower: &str,
    overlay_dos: &str,
    original_basename: &Option<String>,
) {
    if overlay_already_published(lower) {
        return;
    }
    let idx_sent = ipc_record_overlay(lower, overlay_dos);
    let case_sent = match original_basename {
        Some(basename) => ipc_record_overlay_case(lower, basename),
        None => true,
    };
    // Mark only when both records were actually delivered; a failed send
    // leaves the path unmarked so the next successful open retries (C04:
    // the index must match the successful physical operation).
    if idx_sent && case_sent {
        overlay_mark_published(lower);
    }
    cache().invalidate(lower);
}

#[cfg(test)]
mod tests;
