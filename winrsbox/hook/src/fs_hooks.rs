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
    check_path_traversal, check_device_block, decide, resolve_for_hook,
    is_write_access, materialize_mock_overlay,
    prepare_overlay, set_io_status, ipc_record_overlay,
    STATUS_ACCESS_DENIED,
};
use crate::ipc_client::{cache, ipc_log, is_trace};

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

/// `FILE_OPEN_REPARSE_POINT` — when set, the open does NOT traverse the
/// reparse point; combined with a creating disposition it constructs a NEW
/// reparse point in place. Plain `FILE_OPEN` of an existing reparse point is
/// legitimate (git symlinks, mklink readback) and MUST stay allowed.
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// `FILE_OPEN` — open existing file only; never creates. Safe to combine with
/// `FILE_OPEN_REPARSE_POINT` because the kernel will only succeed when the
/// target reparse already exists.
const FILE_OPEN_DISPOSITION: u32 = 1;

// ---------------------------------------------------------------------------
// Pure classifier helpers (testable, no FFI)
// ---------------------------------------------------------------------------

/// Returns true when the (CreateOptions, write-access, disposition) triple
/// describes a CREATE/OVERWRITE that would plant a NEW reparse point.
///
/// Audit H-S2 — a reparse point planted inside the sandbox CWD redirects
/// subsequent path traversal *outside* the sandbox, so we deny the create
/// side. Reading an existing reparse (`FILE_OPEN` disposition) is left alone
/// because git, mklink readback, and the loader all do it legitimately.
#[inline]
pub(crate) fn is_reparse_create(create_options: u32, is_write: bool, disposition: u32) -> bool {
    (create_options & FILE_OPEN_REPARSE_POINT) != 0
        && is_write
        && disposition != FILE_OPEN_DISPOSITION
}

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

// ---------------------------------------------------------------------------
// Hook implementations
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "system" fn hook_nt_create_file(
    file_handle: *mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    io_status_block: *mut IO_STATUS_BLOCK,
    allocation_size: *mut i64,
    file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: *mut c_void,
    ea_length: u32,
) -> NTSTATUS {
    macro_rules! call_original {
        () => {
            HOOK_NT_CREATE_FILE.get().unwrap().call(
                file_handle, desired_access, object_attributes, io_status_block,
                allocation_size, file_attributes, share_access, create_disposition,
                create_options, ea_buffer, ea_length,
            )
        };
    }

    let Some(_guard) = anti_rec::enter() else {
        return call_original!();
    };

    // SAFETY: object_attributes valid per NT calling convention for the call duration.

    // Early-deny: path-traversal vectors (GLOBALROOT, FILE_OPEN_BY_FILE_ID, ADS)
    if let Some(status) = check_path_traversal(object_attributes as *const _, create_options) {
        set_io_status(io_status_block, status);
        return status;
    }

    // H5 resolve-once: resolve RootDirectory handle EXACTLY ONCE here. The
    // returned `pre_resolved` (Some for relative opens) is reused verbatim in
    // copy_passthrough_inner so the kernel opens the SAME path policy approved,
    // closing the double-resolve window.
    let Some((dos, pre_resolved)) = resolve_for_hook(object_attributes as *const _) else {
        if let Some(status) = check_device_block(object_attributes as *const _) {
            set_io_status(io_status_block, status);
            return status;
        }
        if is_write_access(desired_access, create_disposition)
            && crate::hooks::is_fs_device_path(object_attributes as *const _)
        {
            if is_trace() {
                ipc_log(ipc::LogLevel::Trace, "fs_block_device_volume_write".into());
            }
            set_io_status(io_status_block, STATUS_ACCESS_DENIED);
            return STATUS_ACCESS_DENIED;
        }
        return call_original!();
    };

    {
        let canon = crate::hooks::canonicalize_for_denylist(&dos);
        if let Some((status, reason)) = crate::hooks::canonical_denylist_status(&canon) {
            if is_trace() {
                ipc_log(ipc::LogLevel::Trace, format!("fs_block_{reason}_resolved: {dos}"));
            }
            set_io_status(io_status_block, status);
            return status;
        }
    }

    if is_ea_present(ea_buffer as *const _, ea_length) {
        crate::ipc_client::ipc_log_violation(ipc::Req::Log {
            pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
            level: ipc::LogLevel::Warn,
            msg: format!("ntfs_ea_blocked: {dos} (ea_len={ea_length})"),
        });
        if !file_handle.is_null() {
            *file_handle = std::ptr::null_mut();
        }
        set_io_status(io_status_block, STATUS_ACCESS_DENIED);
        return STATUS_ACCESS_DENIED;
    }

    let write = is_write_access(desired_access, create_disposition);
    let decision = decide(&dos, write);

    if is_reparse_create(create_options, write, create_disposition)
        && matches!(decision.mode, Mode::Passthrough | Mode::Cow)
    {
        crate::ipc_client::ipc_log_violation(ipc::Req::Log {
            pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
            level: ipc::LogLevel::Warn,
            msg: format!("reparse_create_blocked: {dos}"),
        });
        if !file_handle.is_null() {
            *file_handle = std::ptr::null_mut();
        }
        set_io_status(io_status_block, STATUS_ACCESS_DENIED);
        return STATUS_ACCESS_DENIED;
    }

    match decision.mode {
        Mode::Passthrough => {
            // H5 resolve-once passthrough: copy_passthrough_inner reuses the
            // pre-resolved absolute path (if relative open) so we never call
            // resolve_handle_path a second time.
            // SAFETY: object_attributes is non-null (checked above via resolve_for_hook).
            let mut copy = match HookedAttrs::copy_passthrough_inner(
                &*object_attributes, pre_resolved.as_deref()
            ) {
                Some(c) => c,
                None => {
                    // Oversized / unresolvable path — fail CLOSED rather than
                    // handing the attacker-owned pointer to the kernel with no
                    // TOCTOU defense (audit H5 secondary).
                    if is_trace() {
                        crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                            pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                            level: ipc::LogLevel::Warn,
                            msg: "passthrough_copy_failed_fail_closed".to_string(),
                        });
                    }
                    if !file_handle.is_null() {
                        *file_handle = std::ptr::null_mut();
                    }
                    set_io_status(io_status_block, STATUS_ACCESS_DENIED);
                    return STATUS_ACCESS_DENIED;
                }
            };
            let attrs_ptr = copy.as_ptr_mut();
            HOOK_NT_CREATE_FILE.get().unwrap().call(
                file_handle, desired_access, attrs_ptr, io_status_block,
                allocation_size, file_attributes, share_access, create_disposition,
                create_options, ea_buffer, ea_length,
            )
        }
        Mode::Deny => {
            if is_trace() {
                ipc_log(ipc::LogLevel::Trace, format!("DENY NtCreateFile: {dos} write={write}"));
            }
            if !file_handle.is_null() {
                *file_handle = std::ptr::null_mut();
            }
            // SAFETY: set_io_status writes offset 0 of IO_STATUS_BLOCK union.
            set_io_status(io_status_block, STATUS_ACCESS_DENIED);
            STATUS_ACCESS_DENIED
        }
        Mode::Cow => {
            // Fail-closed: a Cow Decision MUST carry an overlay path. If the
            // launcher (or a future bug) constructs Mode::Cow with overlay=None,
            // falling through to call_original! would route the write to the
            // real filesystem — an escape. Deny instead.
            let overlay_dos = match prepare_overlay(&decision) {
                Some(o) => o,
                None => {
                    crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                        pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                        level: ipc::LogLevel::Warn,
                        msg: format!("cow_no_overlay_path: {dos}"),
                    });
                    set_io_status(io_status_block, STATUS_ACCESS_DENIED);
                    return STATUS_ACCESS_DENIED;
                }
            };
            let lower = dos.to_lowercase();
            ipc_record_overlay(&lower, &overlay_dos);
            cache().invalidate(&lower);

            // Cow: redirect to overlay path. Keep orig's SQOS verbatim
            // (Cow is invoked from NtCreateFile/NtOpenFile where the
            // original SQOS is whatever the caller passed; the historical
            // Mock-only null-out was needed only because materialised mock
            // payloads triggered STATUS_INVALID_PARAMETER under some
            // build configs).
            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, false);
            HOOK_NT_CREATE_FILE.get().unwrap().call(
                file_handle, desired_access, h.as_ptr_mut(), io_status_block,
                allocation_size, file_attributes, share_access, create_disposition,
                create_options, ea_buffer, ea_length,
            )
        }
        Mode::Mock => {
            let Some(payload) = decision.mock_payload else {
                return call_original!();
            };
            let Some(ref overlay_path) = decision.overlay else {
                return call_original!();
            };
            // Idempotent materialization: see materialize_mock_overlay docs.
            materialize_mock_overlay(overlay_path, payload.as_slice());
            let overlay_dos = overlay_path.to_string_lossy().into_owned();

            // Mock for create/open: force SQOS = null. A non-null SQOS on a
            // file object open returns STATUS_INVALID_PARAMETER under some
            // build configurations (empirically observed by the previous
            // hand-rolled code in this same file).
            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, true);
            HOOK_NT_CREATE_FILE.get().unwrap().call(
                file_handle, desired_access, h.as_ptr_mut(), io_status_block,
                allocation_size, file_attributes, share_access,
                create_disposition, create_options, ea_buffer, ea_length,
            )
        }
    }
}

pub(crate) unsafe extern "system" fn hook_nt_open_file(
    file_handle: *mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    io_status_block: *mut IO_STATUS_BLOCK,
    share_access: u32,
    open_options: u32,
) -> NTSTATUS {
    macro_rules! call_original {
        () => {
            HOOK_NT_OPEN_FILE.get().unwrap().call(
                file_handle, desired_access, object_attributes,
                io_status_block, share_access, open_options,
            )
        };
    }

    let Some(_guard) = anti_rec::enter() else {
        return call_original!();
    };

    // SAFETY: object_attributes valid per NT calling convention.

    // Early-deny: path-traversal vectors (GLOBALROOT, FILE_OPEN_BY_FILE_ID, ADS)
    if let Some(status) = check_path_traversal(object_attributes as *const _, open_options) {
        set_io_status(io_status_block, status);
        return status;
    }

    // H5 resolve-once (same pattern as NtCreateFile above).
    let Some((dos, pre_resolved)) = resolve_for_hook(object_attributes as *const _) else {
        if let Some(status) = check_device_block(object_attributes as *const _) {
            set_io_status(io_status_block, status);
            return status;
        }
        if (desired_access & (crate::hooks::GENERIC_WRITE | crate::hooks::FILE_WRITE_DATA | crate::hooks::FILE_APPEND_DATA | crate::hooks::DELETE | crate::hooks::WRITE_DAC | crate::hooks::WRITE_OWNER)) != 0
            && crate::hooks::is_fs_device_path(object_attributes as *const _)
        {
            if is_trace() {
                ipc_log(ipc::LogLevel::Trace, "fs_block_device_volume_write".into());
            }
            set_io_status(io_status_block, STATUS_ACCESS_DENIED);
            return STATUS_ACCESS_DENIED;
        }
        return call_original!();
    };

    {
        let canon = crate::hooks::canonicalize_for_denylist(&dos);
        if let Some((status, reason)) = crate::hooks::canonical_denylist_status(&canon) {
            if is_trace() {
                ipc_log(ipc::LogLevel::Trace, format!("fs_block_{reason}_resolved: {dos}"));
            }
            set_io_status(io_status_block, status);
            return status;
        }
    }

    let write_bits =
        crate::hooks::GENERIC_WRITE | crate::hooks::FILE_WRITE_DATA | crate::hooks::FILE_APPEND_DATA
        | crate::hooks::DELETE | crate::hooks::WRITE_DAC | crate::hooks::WRITE_OWNER;
    let write = desired_access & write_bits != 0;
    let decision = decide(&dos, write);

    match decision.mode {
        Mode::Passthrough => {
            // SAFETY: object_attributes is non-null.
            let mut copy = match HookedAttrs::copy_passthrough_inner(
                &*object_attributes, pre_resolved.as_deref()
            ) {
                Some(c) => c,
                None => {
                    // Oversized / unresolvable path — fail CLOSED (audit H5).
                    if is_trace() {
                        crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                            pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                            level: ipc::LogLevel::Warn,
                            msg: "passthrough_copy_failed_fail_closed".to_string(),
                        });
                    }
                    if !file_handle.is_null() {
                        *file_handle = std::ptr::null_mut();
                    }
                    set_io_status(io_status_block, STATUS_ACCESS_DENIED);
                    return STATUS_ACCESS_DENIED;
                }
            };
            let attrs_ptr = copy.as_ptr_mut();
            HOOK_NT_OPEN_FILE.get().unwrap().call(
                file_handle, desired_access, attrs_ptr,
                io_status_block, share_access, open_options,
            )
        }
        Mode::Deny => {
            if !file_handle.is_null() {
                *file_handle = std::ptr::null_mut();
            }
            // SAFETY: set_io_status writes offset 0 of IO_STATUS_BLOCK union.
            set_io_status(io_status_block, STATUS_ACCESS_DENIED);
            STATUS_ACCESS_DENIED
        }
        Mode::Cow => {
            // Fail-closed: see hook_nt_create_file for rationale.
            let overlay_dos = match prepare_overlay(&decision) {
                Some(o) => o,
                None => {
                    crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                        pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                        level: ipc::LogLevel::Warn,
                        msg: format!("cow_no_overlay_path: {dos}"),
                    });
                    set_io_status(io_status_block, STATUS_ACCESS_DENIED);
                    return STATUS_ACCESS_DENIED;
                }
            };
            let lower = dos.to_lowercase();
            ipc_record_overlay(&lower, &overlay_dos);
            cache().invalidate(&lower);

            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, false);
            HOOK_NT_OPEN_FILE.get().unwrap().call(
                file_handle, desired_access, h.as_ptr_mut(),
                io_status_block, share_access, open_options,
            )
        }
        Mode::Mock => {
            let Some(payload) = decision.mock_payload else {
                return call_original!();
            };
            let Some(ref overlay_path) = decision.overlay else {
                return call_original!();
            };
            // Idempotent materialization (see materialize_mock_overlay docs).
            materialize_mock_overlay(overlay_path, payload.as_slice());
            let overlay_dos = overlay_path.to_string_lossy().into_owned();

            // Mock for create/open: force SQOS = null. See hook_nt_create_file
            // for the rationale on STATUS_INVALID_PARAMETER.
            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, true);
            HOOK_NT_OPEN_FILE.get().unwrap().call(
                file_handle, desired_access, h.as_ptr_mut(),
                io_status_block, share_access, open_options,
            )
        }
    }
}

pub(crate) unsafe extern "system" fn hook_nt_query_attributes_file(
    object_attributes: *mut OBJECT_ATTRIBUTES,
    file_information: *mut c_void,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return HOOK_NT_QUERY_ATTRIBUTES_FILE
            .get()
            .unwrap()
            .call(object_attributes, file_information);
    };

    // H5 resolve-once.
    let Some((dos, pre_resolved)) = resolve_for_hook(object_attributes as *const _) else {
        return HOOK_NT_QUERY_ATTRIBUTES_FILE
            .get()
            .unwrap()
            .call(object_attributes, file_information);
    };

    let decision = decide(&dos, false);
    match decision.mode {
        Mode::Passthrough => {
            // SAFETY: object_attributes is non-null.
            let mut copy = match HookedAttrs::copy_passthrough_inner(
                &*object_attributes, pre_resolved.as_deref()
            ) {
                Some(c) => c,
                None => {
                    // Oversized / unresolvable path — fail CLOSED (audit H5).
                    if is_trace() {
                        crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                            pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                            level: ipc::LogLevel::Warn,
                            msg: "passthrough_copy_failed_fail_closed".to_string(),
                        });
                    }
                    return STATUS_ACCESS_DENIED;
                }
            };
            let attrs_ptr = copy.as_ptr_mut();
            HOOK_NT_QUERY_ATTRIBUTES_FILE
                .get()
                .unwrap()
                .call(attrs_ptr, file_information)
        }
        Mode::Deny => STATUS_ACCESS_DENIED,
        Mode::Mock => {
            let Some(ref overlay_path) = decision.overlay else {
                return HOOK_NT_QUERY_ATTRIBUTES_FILE
                    .get()
                    .unwrap()
                    .call(object_attributes, file_information);
            };
            // If overlay missing, materialize mock payload first so the
            // redirected query observes the mocked file instead of ENOENT.
            if !overlay_path.exists() {
                if let Some(ref payload) = decision.mock_payload {
                    materialize_mock_overlay(overlay_path, payload);
                } else {
                    return HOOK_NT_QUERY_ATTRIBUTES_FILE
                        .get()
                        .unwrap()
                        .call(object_attributes, file_information);
                }
            }
            let overlay_dos = overlay_path.to_string_lossy().into_owned();
            // Query path: keep orig's SQOS verbatim (NtQueryAttributesFile is
            // not a create/open syscall and does not exhibit the SQOS
            // STATUS_INVALID_PARAMETER quirk).
            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, false);
            HOOK_NT_QUERY_ATTRIBUTES_FILE
                .get()
                .unwrap()
                .call(h.as_ptr_mut(), file_information)
        }
        Mode::Cow => {
            // Design choice: for read-only Query hooks we fall through to the
            // original path when overlay is missing (or the field itself is
            // None). Querying the original is benign — it merely reports
            // attributes; any actual write/open will hit hook_nt_create_file /
            // hook_nt_open_file which fail-close on Mode::Cow + overlay=None.
            // Returning STATUS_OBJECT_NAME_NOT_FOUND here would break
            // legitimate stat-then-open patterns where callers probe a file
            // first; the write-side is the actual security boundary.
            let Some(ref overlay_path) = decision.overlay else {
                return HOOK_NT_QUERY_ATTRIBUTES_FILE
                    .get()
                    .unwrap()
                    .call(object_attributes, file_information);
            };
            if !overlay_path.exists() {
                return HOOK_NT_QUERY_ATTRIBUTES_FILE
                    .get()
                    .unwrap()
                    .call(object_attributes, file_information);
            }
            let overlay_dos = overlay_path.to_string_lossy().into_owned();
            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, false);
            HOOK_NT_QUERY_ATTRIBUTES_FILE
                .get()
                .unwrap()
                .call(h.as_ptr_mut(), file_information)
        }
    }
}

pub(crate) unsafe extern "system" fn hook_nt_query_full_attributes_file(
    object_attributes: *mut OBJECT_ATTRIBUTES,
    file_information: *mut c_void,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
            .get()
            .unwrap()
            .call(object_attributes, file_information);
    };

    // H5 resolve-once.
    let Some((dos, pre_resolved)) = resolve_for_hook(object_attributes as *const _) else {
        return HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
            .get()
            .unwrap()
            .call(object_attributes, file_information);
    };

    let decision = decide(&dos, false);
    match decision.mode {
        Mode::Passthrough => {
            // SAFETY: object_attributes is non-null.
            let mut copy = match HookedAttrs::copy_passthrough_inner(
                &*object_attributes, pre_resolved.as_deref()
            ) {
                Some(c) => c,
                None => {
                    // Oversized / unresolvable path — fail CLOSED (audit H5).
                    if is_trace() {
                        crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                            pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                            level: ipc::LogLevel::Warn,
                            msg: "passthrough_copy_failed_fail_closed".to_string(),
                        });
                    }
                    return STATUS_ACCESS_DENIED;
                }
            };
            let attrs_ptr = copy.as_ptr_mut();
            HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
                .get()
                .unwrap()
                .call(attrs_ptr, file_information)
        }
        Mode::Deny => STATUS_ACCESS_DENIED,
        Mode::Mock => {
            let Some(ref overlay_path) = decision.overlay else {
                return HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
                    .get()
                    .unwrap()
                    .call(object_attributes, file_information);
            };
            // If overlay missing, materialize mock payload first so the
            // redirected query observes the mocked file instead of ENOENT.
            if !overlay_path.exists() {
                if let Some(ref payload) = decision.mock_payload {
                    materialize_mock_overlay(overlay_path, payload);
                } else {
                    return HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
                        .get()
                        .unwrap()
                        .call(object_attributes, file_information);
                }
            }
            let overlay_dos = overlay_path.to_string_lossy().into_owned();
            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, false);
            HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
                .get()
                .unwrap()
                .call(h.as_ptr_mut(), file_information)
        }
        Mode::Cow => {
            // See hook_nt_query_attributes_file for the read-only fall-through
            // rationale. Write-side fail-close lives in create/open hooks.
            let Some(ref overlay_path) = decision.overlay else {
                return HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
                    .get()
                    .unwrap()
                    .call(object_attributes, file_information);
            };
            if !overlay_path.exists() {
                return HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
                    .get()
                    .unwrap()
                    .call(object_attributes, file_information);
            }
            let overlay_dos = overlay_path.to_string_lossy().into_owned();
            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, false);
            HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
                .get()
                .unwrap()
                .call(h.as_ptr_mut(), file_information)
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests (audit H-S2 / H-S3 helpers — pure, FFI-free)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // FILE_CREATE / FILE_OPEN_IF / FILE_OVERWRITE_IF dispositions (from
    // crate::hooks). Duplicated locally so test failures point at this file.
    const FILE_OPEN: u32 = 1;
    const FILE_CREATE: u32 = 2;
    const FILE_OPEN_IF: u32 = 3;
    const FILE_OVERWRITE_IF: u32 = 5;

    /// Refactor canary: the kernel constant `FILE_OPEN_REPARSE_POINT` is
    /// `0x00200000` and bit-mistakes (e.g. typing 0x0020_000 with three
    /// zeros) silently break the deny path. Catch it at compile-time of the
    /// test suite, not at exploit time.
    #[test]
    fn reparse_flag_constant() {
        assert_eq!(FILE_OPEN_REPARSE_POINT, 0x0020_0000);
        assert_eq!(FILE_OPEN_DISPOSITION, 1);
    }

    #[test]
    fn is_reparse_create_flag_set_creating_blocks() {
        // FILE_CREATE + write + reparse flag → CREATE a reparse point → block
        assert!(is_reparse_create(FILE_OPEN_REPARSE_POINT, true, FILE_CREATE));
        // FILE_OPEN_IF and FILE_OVERWRITE_IF also create when target absent
        assert!(is_reparse_create(FILE_OPEN_REPARSE_POINT, true, FILE_OPEN_IF));
        assert!(is_reparse_create(FILE_OPEN_REPARSE_POINT, true, FILE_OVERWRITE_IF));
    }

    #[test]
    fn is_reparse_create_open_existing_allowed() {
        // FILE_OPEN of an existing reparse — git symlinks, mklink readback — OK.
        assert!(!is_reparse_create(FILE_OPEN_REPARSE_POINT, true, FILE_OPEN));
    }

    #[test]
    fn is_reparse_create_no_flag_allowed() {
        // Without the reparse flag, a normal create is none of this hook's business.
        assert!(!is_reparse_create(0, true, FILE_CREATE));
    }

    #[test]
    fn is_reparse_create_read_only_allowed() {
        // Read-only opens (write=false) never plant new reparse points,
        // even with the reparse flag and a creating disposition combo.
        assert!(!is_reparse_create(FILE_OPEN_REPARSE_POINT, false, FILE_CREATE));
    }

    /// Other arbitrary bits in create_options must not flip the result —
    /// the predicate is a flag test, not equality.
    #[test]
    fn is_reparse_create_extra_options_dont_mask() {
        const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
        const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
        let opts = FILE_OPEN_REPARSE_POINT | FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE;
        assert!(is_reparse_create(opts, true, FILE_CREATE));
    }

    #[test]
    fn is_ea_present_empty_cases() {
        // Null buffer with zero length: no EA.
        assert!(!is_ea_present(std::ptr::null(), 0));
        // Null buffer with non-zero length: still no EA (defensive — kernel
        // would reject this too, but we never want to dereference null).
        assert!(!is_ea_present(std::ptr::null(), 32));
        // Non-null buffer with zero length: no EA payload.
        let dummy = 0u8;
        assert!(!is_ea_present(&dummy as *const u8 as *const c_void, 0));
    }

    #[test]
    fn is_ea_present_supplied() {
        let dummy = 0u8;
        assert!(is_ea_present(&dummy as *const u8 as *const c_void, 1));
        assert!(is_ea_present(&dummy as *const u8 as *const c_void, u32::MAX));
    }
}
