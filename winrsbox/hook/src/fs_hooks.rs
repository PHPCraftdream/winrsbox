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
    prepare_overlay, set_io_status, ipc_record_overlay, ipc_record_overlay_case,
    extract_nt_basename,
    FILE_CREATE, FILE_OPEN_IF, FILE_OVERWRITE_IF, FILE_SUPERSEDE,
    STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_NOT_FOUND,
};
use crate::ipc_client::{
    cache, ipc_log, is_trace,
    ipc_clear_whiteout,
};

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

    // Variant B hybrid: capture original-case basename NOW, before
    // resolve_for_hook / nt_to_dos_lower lowercases the path.
    // SAFETY: object_attributes is valid per NT ABI for this call's duration.
    let original_basename: Option<String> = extract_nt_basename(object_attributes as *const _);

    // H5 resolve-once: resolve RootDirectory handle EXACTLY ONCE here. The
    // returned `pre_resolved` (Some for relative opens) is reused verbatim in
    // copy_passthrough_inner so the kernel opens the SAME path policy approved,
    // closing the double-resolve window.
    let Some((dos, pre_resolved)) = resolve_for_hook(object_attributes as *const _) else {
        // Forensic: a WRITE we couldn't resolve is exactly the class of bug
        // that the cmd.exe `>filename` escape lived in (device-namespace
        // RootDirectory + bare ObjectName). Keep this one on TRACE — it
        // produces no event under default log_level, but with `log_level:
        // trace` in sandbox.ktav an escape investigator sees every unresolved
        // write and the raw path that caused it.
        if is_trace() && is_write_access(desired_access, create_disposition) {
            let raw = crate::hooks::extract_raw_nt_path(object_attributes as *const _)
                .unwrap_or_else(|| "<unresolved>".to_string());
            ipc_log(
                ipc::LogLevel::Trace,
                format!("fs_resolve_failed: NtCreateFile raw={raw} write=true"),
            );
        }
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

    let write = is_write_access(desired_access, create_disposition);

    // ── NTFS Extended-Attributes (EA) defence-in-depth (audit H-S3) ─────────
    //
    // EA are not listed by directory enumeration, persist across reboots, and
    // recent BlackLotus-class loaders stash payloads in them. So we treat any
    // non-empty EA buffer as hostile — BUT only when it would land on the REAL
    // disk. When the destination is policy-redirected into the CoW overlay
    // (Mode::Cow/Mock), the EA is trapped inside the sandbox and can neither
    // persist on the host nor be read by an out-of-sandbox process, so it is
    // harmless. Blocking EA on a CoW path instead breaks network installers
    // (e.g. uv.exe, which carries a download-attribution EA) whose extract
    // step writes the file with its EA buffer into %TEMP% (now CoW).
    //
    // We must `decide` first to know the mode, so the unconditional block moved
    // below the decision. The EA buffer is preserved verbatim for the CoW
    // kernel open (the overlay copy legitimately keeps whatever EA the caller
    // intended).
    let ea_present = is_ea_present(ea_buffer as *const _, ea_length);
    let mut decision = decide(&dos, write);

    // ── Revive: a create/supersede/open-if against a Hidden (whiteouted) path
    // means the caller wants to (re)create the file. We clear the whiteout
    // marker and re-decide so the second decision returns Cow (overlay),
    // materialising the file in the sandbox instead of surfacing not-found.
    //
    // We do NOT recurse into hook_nt_create_file because the outer call holds
    // an anti_rec guard; the re-entry would see enter()==None and bypass the
    // decision logic entirely (calling the original on the REAL path — an
    // escape). Instead we clear + re-decide inline and fall through to the
    // normal match below.
    if decision.mode == Mode::Hidden && is_create_disposition(create_disposition) {
        let lower = dos.to_lowercase();
        ipc_clear_whiteout(&lower);
        cache().invalidate(&lower);
        if is_trace() {
            ipc_log(
                ipc::LogLevel::Trace,
                format!("fs_whiteout_revive NtCreateFile: {dos}"),
            );
        }
        decision = decide(&dos, write);
    }

    if is_trace() {
        ipc_log(
            ipc::LogLevel::Trace,
            format!("fs_decide NtCreateFile: {dos} write={write} mode={:?}", decision.mode),
        );
    }

    // Note: the former create-side `is_reparse_create` veto here was
    // overzealous and was removed. The `FILE_OPEN_REPARSE_POINT` flag on
    // NtCreateFile only controls TRAVERSAL ("open the reparse point itself,
    // don't follow") — it does NOT by itself create a reparse point. Creating
    // a reparse point requires a subsequent `FSCTL_SET_REPARSE_POINT[_EX]`,
    // and THAT is unconditionally denied in fs_metadata_guard. So this block
    // added no real defence (the actual escape vector is closed elsewhere)
    // and false-positive'd legitimate IPC primitives that pass the flag for
    // open-self semantics (e.g. wezterm's blob-lease files in %TEMP%).
    match decision.mode {
        Mode::Hidden => {
            // Pure open / read / overwrite-of-existing against a hidden path:
            // the file is gone from the sandbox view → not-found. The revive
            // case (create disposition) is handled above before this match.
            if is_trace() {
                ipc_log(
                    ipc::LogLevel::Trace,
                    format!("fs_whiteout_hidden NtCreateFile: {dos} disposition={create_disposition}"),
                );
            }
            if !file_handle.is_null() {
                *file_handle = std::ptr::null_mut();
            }
            set_io_status(io_status_block, STATUS_OBJECT_NAME_NOT_FOUND);
            STATUS_OBJECT_NAME_NOT_FOUND
        }
        Mode::Passthrough => {
            // EA-defence (audit H-S3) applies ONLY on the real-disk path. A
            // write carrying an Extended-Attribute buffer would persist on the
            // host and is the covert-storage vector BlackLotus uses. Block it
            // here (after the CoW branches were already handled above, where EA
            // are safe because they land in the overlay). See the comment near
            // `ea_present` for the full rationale.
            if write && ea_present {
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

            // CoW read-passthrough: on a READ of a file with no overlay copy,
            // open the REAL file (passthrough). CoW = copy-on-WRITE, not copy-
            // on-read. The overlay copy is only created on first WRITE. Without
            // this passthrough, reads of existing files outside project_root
            // (e.g. C:\Users\…\.gitconfig) fail with NOT_FOUND because the
            // overlay path doesn't exist yet. This broke `git config --global`
            // and many other tools that read config from the user profile.
            let overlay_exists_phys = std::path::Path::new(&overlay_dos).exists();
            if !is_write_access(desired_access, create_disposition) && !overlay_exists_phys {
                // Don't record an overlay entry — the file is still real.
                // The hook cache's Cow decision is fine: if a later WRITE
                // arrives, it will copy-on-write and record the overlay then.
                cache().invalidate(&lower);
                let mut copy = match HookedAttrs::copy_passthrough_inner(
                    &*object_attributes, pre_resolved.as_deref()
                ) {
                    Some(c) => c,
                    None => {
                        if is_trace() {
                            ipc_log(
                                ipc::LogLevel::Trace,
                                format!("cow_read_passthrough_copy_failed: {dos}"),
                            );
                        }
                        set_io_status(io_status_block, STATUS_ACCESS_DENIED);
                        return STATUS_ACCESS_DENIED;
                    }
                };
                return HOOK_NT_CREATE_FILE.get().unwrap().call(
                    file_handle, desired_access, copy.as_ptr_mut(), io_status_block,
                    allocation_size, file_attributes, share_access, create_disposition,
                    create_options, ea_buffer, ea_length,
                );
            }

            ipc_record_overlay(&lower, &overlay_dos);
            // Record original-case basename so the directory-enumeration hook
            // can restore case for overlay-only dirs (variant B hybrid).
            // Use `original_basename` captured before nt_to_dos_lower (which
            // lowercases the entire path), so the true caller-supplied case is
            // preserved. Falls back to the dos basename when the early capture
            // returned None (path already all-lowercase — nothing to preserve).
            if let Some(ref basename) = original_basename {
                ipc_record_overlay_case(&lower, basename);
            }
            cache().invalidate(&lower);

            // Cow: redirect to overlay path. Keep orig's SQOS verbatim
            // (Cow is invoked from NtCreateFile/NtOpenFile where the
            // original SQOS is whatever the caller passed; the historical
            // Mock-only null-out was needed only because materialised mock
            // payloads triggered STATUS_INVALID_PARAMETER under some
            // build configs).
            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, false);
            if is_trace() {
                let exists = std::path::Path::new(&overlay_dos).exists();
                ipc_log(
                    ipc::LogLevel::Trace,
                    format!("fs_cow_create_pre dos={dos} disp={create_disposition:#x} overlay_exists={exists} overlay={overlay_dos}"),
                );
            }
            let status = HOOK_NT_CREATE_FILE.get().unwrap().call(
                file_handle, desired_access, h.as_ptr_mut(), io_status_block,
                allocation_size, file_attributes, share_access, create_disposition,
                create_options, ea_buffer, ea_length,
            );
            // Always log STATUS_REPARSE_POINT_ENCOUNTERED (0xC0000274 / os error 4395)
            // so it appears in sandbox.log at WARN level even without trace mode.
            const STATUS_REPARSE_POINT_ENCOUNTERED: i32 = 0xC000_0274_u32 as i32;
            if status == STATUS_REPARSE_POINT_ENCOUNTERED {
                ipc_log(
                    ipc::LogLevel::Warn,
                    format!("diag_4395_cow_create dos={dos} disp={create_disposition:#x} opts={create_options:#x} access={desired_access:#x} status=0x{status:08x}"),
                );
            } else if is_trace() && (dos.contains("config.lock") || status != 0) {
                ipc_log(
                    ipc::LogLevel::Trace,
                    format!("fs_cow_create_post status=0x{status:08x} dos={dos} disp={create_disposition:#x}"),
                );
            }
            status
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

    // Variant B hybrid: capture original-case basename before nt_to_dos_lower.
    // SAFETY: object_attributes is valid per NT ABI for this call's duration.
    let original_basename: Option<String> = extract_nt_basename(object_attributes as *const _);

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

    if is_trace() {
        ipc_log(
            ipc::LogLevel::Trace,
            format!("fs_decide NtOpenFile: {dos} write={write} mode={:?}", decision.mode),
        );
    }

    match decision.mode {
        Mode::Hidden => {
            // NtOpenFile is always a pure open (CreateDisposition = FILE_OPEN
            // semantically — it cannot create). A hidden path is therefore
            // not-found. The revive path is handled by NtCreateFile, which is
            // what every "create-if-not-exists" call routes through.
            if is_trace() {
                ipc_log(
                    ipc::LogLevel::Trace,
                    format!("fs_whiteout_hidden NtOpenFile: {dos}"),
                );
            }
            if !file_handle.is_null() {
                *file_handle = std::ptr::null_mut();
            }
            set_io_status(io_status_block, STATUS_OBJECT_NAME_NOT_FOUND);
            STATUS_OBJECT_NAME_NOT_FOUND
        }
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
            // Record original-case basename (variant B hybrid — NtOpenFile path).
            // Use `original_basename` captured before nt_to_dos_lower lowercased the path.
            if let Some(ref basename) = original_basename {
                ipc_record_overlay_case(&lower, basename);
            }
            cache().invalidate(&lower);

            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, false);
            let status = HOOK_NT_OPEN_FILE.get().unwrap().call(
                file_handle, desired_access, h.as_ptr_mut(),
                io_status_block, share_access, open_options,
            );
            // Always log STATUS_REPARSE_POINT_ENCOUNTERED (0xC0000274 / os error 4395)
            // so it appears in sandbox.log at WARN level even without trace mode.
            const STATUS_REPARSE_POINT_ENCOUNTERED_OPEN: i32 = 0xC000_0274_u32 as i32;
            if status == STATUS_REPARSE_POINT_ENCOUNTERED_OPEN {
                ipc_log(
                    ipc::LogLevel::Warn,
                    format!("diag_4395_cow_open dos={dos} opts={open_options:#x} access={desired_access:#x} status=0x{status:08x} overlay={overlay_dos}"),
                );
            }
            status
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
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace, format!("fs_decide NtQueryAttributesFile: {dos} write=false mode={:?}", decision.mode));
    }
    match decision.mode {
        Mode::Hidden => STATUS_OBJECT_NAME_NOT_FOUND,
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
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace, format!("fs_decide NtQueryFullAttributesFile: {dos} write=false mode={:?}", decision.mode));
    }
    match decision.mode {
        Mode::Hidden => STATUS_OBJECT_NAME_NOT_FOUND,
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

    // Note: the former `reparse_flag_constant`, `is_reparse_create_*` tests
    // (5 total) used to live here. They covered a now-removed predicate; the
    // real escape vector `FSCTL_SET_REPARSE_POINT[_EX]` is tested in
    // fs_metadata_guard. See the comment block near the top of this file.

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

    #[test]
    fn is_create_disposition_classifies_revive() {
        // Dispositions that (re)create the file → revive path on whiteout.
        assert!(is_create_disposition(FILE_SUPERSEDE)); // 0
        assert!(is_create_disposition(FILE_CREATE));     // 2
        assert!(is_create_disposition(FILE_OPEN_IF));    // 3
        assert!(is_create_disposition(FILE_OVERWRITE_IF)); // 5
    }

    #[test]
    fn is_create_disposition_rejects_pure_open() {
        // FILE_OPEN (1) and FILE_OVERWRITE (4) are NOT creates:
        // a hidden path must surface not-found for these, not revive.
        assert!(!is_create_disposition(1)); // FILE_OPEN
        assert!(!is_create_disposition(4)); // FILE_OVERWRITE
        // Unknown dispositions are also not revives.
        assert!(!is_create_disposition(99));
    }
}
