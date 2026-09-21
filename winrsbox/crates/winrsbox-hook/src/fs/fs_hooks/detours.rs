use super::anti_rec;
use super::cache;
use super::c_void;
use super::check_path_traversal;
use super::classify_device_open;
use super::decide;
use super::dead_end_write_intent;
use super::DeviceVerdict;
use super::extract_nt_basename;
use super::HookedAttrs;
use super::ipc_clear_whiteout;
use super::ipc_log;
use super::ipc_record_overlay;
use super::ipc_record_overlay_case;
use super::is_create_disposition;
use super::is_ea_present;
use super::is_trace;
use super::is_write_access;
use super::materialize_mock_overlay;
use super::nt_call_original;
use super::prepare_overlay;
use super::resolve_for_hook;
use super::set_io_status;
use super::STATUS_ACCESS_DENIED;
use super::STATUS_OBJECT_NAME_NOT_FOUND;
use super::ACCESS_MASK;
use super::FILE_OPEN;
use super::HANDLE;
use super::IO_STATUS_BLOCK;
use super::Mode;
use super::NTSTATUS;
use super::OBJECT_ATTRIBUTES;
use super::HOOK_NT_CREATE_FILE;
use super::HOOK_NT_OPEN_FILE;
use super::HOOK_NT_QUERY_ATTRIBUTES_FILE;
use super::HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE;

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
            nt_call_original!(
                &HOOK_NT_CREATE_FILE,
                "NtCreateFile",
                (file_handle, desired_access, object_attributes, io_status_block,
                 allocation_size, file_attributes, share_access, create_disposition,
                 create_options, ea_buffer, ea_length)
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
        // Fail closed (P0-03): a write that does not resolve to a DOS path
        // must not reach the original NtCreateFile — it would bypass decide()
        // and the CoW overlay entirely (UNC shares, raw device namespaces).
        let write_intent =
            dead_end_write_intent(desired_access, Some(create_disposition), create_options);
        let device = classify_device_open(object_attributes as *const _, write_intent);
        if let DeviceVerdict::Deny(status) = device {
            set_io_status(io_status_block, status);
            return status;
        }
        // A named pipe / socket / console / NUL open has no filesystem behind
        // it, so the dead-end write deny below must not apply: denying it is
        // what broke `CreatePipe`, `child_process.spawn` and every TTY open.
        if write_intent && device != DeviceVerdict::PassThrough {
            if is_trace() {
                // Keep the sharper forensic label for raw volume-device targets.
                let kind = if crate::hooks::is_fs_device_path(object_attributes as *const _) {
                    "device_volume"
                } else {
                    "unresolved"
                };
                // Name the path. Without it this line says only "something
                // was refused", which is useless when a real program reports
                // a bare "Access is denied" and the operator has to work out
                // which of its many opens we stopped.
                let raw = crate::hooks::extract_raw_nt_path(object_attributes as *const _)
                    .unwrap_or_else(|| "<unresolved>".to_string());
                ipc_log(
                    ipc::LogLevel::Trace,
                    format!("fs_block_{kind}_write raw={raw}").into(),
                );
            }
            set_io_status(io_status_block, STATUS_ACCESS_DENIED);
            return STATUS_ACCESS_DENIED;
        }
        // Tripwire: catch 4395 from relative-opens (RootDirectory != NULL) that
        // we could not resolve. If the overlay-redirected parent handle is
        // opaque to resolve_for_hook, the kernel receives the original relative
        // request and may return STATUS_REPARSE_POINT_ENCOUNTERED.
        {
            const STATUS_REPARSE_POINT_ENCOUNTERED_RC: NTSTATUS = 0xC000_0274_u32 as NTSTATUS;
            let is_relative = !(*object_attributes).RootDirectory.is_null();
            let status = call_original!();
            if status == STATUS_REPARSE_POINT_ENCOUNTERED_RC {
                let raw = crate::hooks::extract_raw_nt_path(object_attributes as *const _)
                    .unwrap_or_else(|| "<unknown>".to_string());
                let root_val = (*object_attributes).RootDirectory as usize;
                ipc_log(
                    ipc::LogLevel::Warn,
                    format!(
                        "diag_4395_rel_create \
                         pid={pid} root_handle=0x{root_val:x} relative={is_relative} \
                         name={raw} access={desired_access:#x} share={share_access:#x} \
                         disp={create_disposition:#x} opts={create_options:#x} \
                         status=0x{status:08x}",
                        pid = winapi::um::processthreadsapi::GetCurrentProcessId(),
                    ),
                );
            }
            return status;
        }
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
            nt_call_original!(
                &HOOK_NT_CREATE_FILE,
                "NtCreateFile",
                (file_handle, desired_access, attrs_ptr, io_status_block,
                 allocation_size, file_attributes, share_access, create_disposition,
                 create_options, ea_buffer, ea_length)
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
                return nt_call_original!(
                    &HOOK_NT_CREATE_FILE,
                    "NtCreateFile",
                    (file_handle, desired_access, copy.as_ptr_mut(), io_status_block,
                     allocation_size, file_attributes, share_access, create_disposition,
                     create_options, ea_buffer, ea_length)
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
            let status = nt_call_original!(
                &HOOK_NT_CREATE_FILE,
                "NtCreateFile",
                (file_handle, desired_access, h.as_ptr_mut(), io_status_block,
                 allocation_size, file_attributes, share_access, create_disposition,
                 create_options, ea_buffer, ea_length)
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
            // A Mock decision missing its payload or overlay target is a
            // MALFORMED decision (compute always sets both), so the decision
            // channel cannot be trusted for this path — fail CLOSED. The old
            // fall-through to call_original!() opened the REAL file whenever
            // an incomplete Mock arrived (audit 2026-09-19 Low: Mock
            // fail-open on a malformed decision).
            let Some(payload) = decision.mock_payload else {
                crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                    pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                    level: ipc::LogLevel::Warn,
                    msg: format!("mock_malformed_decision_deny create no_payload: {dos}"),
                });
                set_io_status(io_status_block, STATUS_ACCESS_DENIED);
                return STATUS_ACCESS_DENIED;
            };
            let Some(ref overlay_path) = decision.overlay else {
                crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                    pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                    level: ipc::LogLevel::Warn,
                    msg: format!("mock_malformed_decision_deny create no_overlay: {dos}"),
                });
                set_io_status(io_status_block, STATUS_ACCESS_DENIED);
                return STATUS_ACCESS_DENIED;
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
            nt_call_original!(
                &HOOK_NT_CREATE_FILE,
                "NtCreateFile",
                (file_handle, desired_access, h.as_ptr_mut(), io_status_block,
                 allocation_size, file_attributes, share_access,
                 create_disposition, create_options, ea_buffer, ea_length)
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
            nt_call_original!(
                &HOOK_NT_OPEN_FILE,
                "NtOpenFile",
                (file_handle, desired_access, object_attributes,
                 io_status_block, share_access, open_options)
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
        // Fail closed (P0-03) — same contract as the NtCreateFile dead-end.
        let write_intent = dead_end_write_intent(desired_access, None, open_options);
        let device = classify_device_open(object_attributes as *const _, write_intent);
        if let DeviceVerdict::Deny(status) = device {
            set_io_status(io_status_block, status);
            return status;
        }
        // Non-filesystem devices pass through — see the NtCreateFile twin.
        if write_intent && device != DeviceVerdict::PassThrough {
            if is_trace() {
                let kind = if crate::hooks::is_fs_device_path(object_attributes as *const _) {
                    "device_volume"
                } else {
                    "unresolved"
                };
                // Name the path. Without it this line says only "something
                // was refused", which is useless when a real program reports
                // a bare "Access is denied" and the operator has to work out
                // which of its many opens we stopped.
                let raw = crate::hooks::extract_raw_nt_path(object_attributes as *const _)
                    .unwrap_or_else(|| "<unresolved>".to_string());
                ipc_log(
                    ipc::LogLevel::Trace,
                    format!("fs_block_{kind}_write raw={raw}").into(),
                );
            }
            set_io_status(io_status_block, STATUS_ACCESS_DENIED);
            return STATUS_ACCESS_DENIED;
        }
        // Tripwire: catch 4395 from relative-opens (RootDirectory != NULL) that
        // we could not resolve — same rationale as the NtCreateFile counterpart.
        {
            const STATUS_REPARSE_POINT_ENCOUNTERED_RO: NTSTATUS = 0xC000_0274_u32 as NTSTATUS;
            let is_relative = !(*object_attributes).RootDirectory.is_null();
            let status = call_original!();
            if status == STATUS_REPARSE_POINT_ENCOUNTERED_RO {
                let raw = crate::hooks::extract_raw_nt_path(object_attributes as *const _)
                    .unwrap_or_else(|| "<unknown>".to_string());
                let root_val = (*object_attributes).RootDirectory as usize;
                ipc_log(
                    ipc::LogLevel::Warn,
                    format!(
                        "diag_4395_rel_open \
                         pid={pid} root_handle=0x{root_val:x} relative={is_relative} \
                         name={raw} access={desired_access:#x} share={share_access:#x} \
                         opts={open_options:#x} status=0x{status:08x}",
                        pid = winapi::um::processthreadsapi::GetCurrentProcessId(),
                    ),
                );
            }
            return status;
        }
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

    // NtOpenFile has no create-disposition parameter; FILE_OPEN keeps the
    // disposition clause of the canonical mask inert so the single
    // is_write_access definition drives the classification here too (this
    // site used to re-inline the old narrow bit list).
    let write = is_write_access(desired_access, FILE_OPEN);
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
            nt_call_original!(
                &HOOK_NT_OPEN_FILE,
                "NtOpenFile",
                (file_handle, desired_access, attrs_ptr,
                 io_status_block, share_access, open_options)
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
            let status = nt_call_original!(
                &HOOK_NT_OPEN_FILE,
                "NtOpenFile",
                (file_handle, desired_access, h.as_ptr_mut(),
                 io_status_block, share_access, open_options)
            );
            // Always log STATUS_REPARSE_POINT_ENCOUNTERED / STATUS_NOT_A_REPARSE_POINT
            // (os error 4395) at WARN level so they appear in sandbox.log even without
            // trace mode.
            //
            // Root cause of os error 4395 from this call site: the original caller
            // (e.g. Rust's remove_dir_all) sets OBJ_DONT_REPARSE (0x1000) in
            // OBJECT_ATTRIBUTES.Attributes + FILE_OPEN_REPARSE_POINT in open_options.
            // Passing OBJ_DONT_REPARSE through to the overlay-redirected call causes
            // NtOpenFile on a non-reparse-point overlay directory to return
            // STATUS_NOT_A_REPARSE_POINT (0xC000050B → Win32 4395). The fix is in
            // HookedAttrs::redirect: it now strips OBJ_DONT_REPARSE from Attributes
            // before handing the OBJECT_ATTRIBUTES to the kernel for the overlay path.
            const STATUS_REPARSE_POINT_ENCOUNTERED_OPEN: i32 = 0xC000_0274_u32 as i32;
            const STATUS_NOT_A_REPARSE_POINT: i32 = 0xC000_050B_u32 as i32;
            if status == STATUS_REPARSE_POINT_ENCOUNTERED_OPEN
                || status == STATUS_NOT_A_REPARSE_POINT
            {
                ipc_log(
                    ipc::LogLevel::Warn,
                    format!("diag_4395_cow_open dos={dos} opts={open_options:#x} access={desired_access:#x} status=0x{status:08x} overlay={overlay_dos}"),
                );
            }
            status
        }
        Mode::Mock => {
            // Malformed Mock (payload/overlay missing) — fail CLOSED, same
            // rationale as hook_nt_create_file's Mock arm.
            let Some(payload) = decision.mock_payload else {
                crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                    pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                    level: ipc::LogLevel::Warn,
                    msg: format!("mock_malformed_decision_deny open no_payload: {dos}"),
                });
                set_io_status(io_status_block, STATUS_ACCESS_DENIED);
                return STATUS_ACCESS_DENIED;
            };
            let Some(ref overlay_path) = decision.overlay else {
                crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                    pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                    level: ipc::LogLevel::Warn,
                    msg: format!("mock_malformed_decision_deny open no_overlay: {dos}"),
                });
                set_io_status(io_status_block, STATUS_ACCESS_DENIED);
                return STATUS_ACCESS_DENIED;
            };
            // Idempotent materialization (see materialize_mock_overlay docs).
            materialize_mock_overlay(overlay_path, payload.as_slice());
            let overlay_dos = overlay_path.to_string_lossy().into_owned();

            // Mock for create/open: force SQOS = null. See hook_nt_create_file
            // for the rationale on STATUS_INVALID_PARAMETER.
            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, true);
            nt_call_original!(
                &HOOK_NT_OPEN_FILE,
                "NtOpenFile",
                (file_handle, desired_access, h.as_ptr_mut(),
                 io_status_block, share_access, open_options)
            )
        }
    }
}

pub(crate) unsafe extern "system" fn hook_nt_query_attributes_file(
    object_attributes: *mut OBJECT_ATTRIBUTES,
    file_information: *mut c_void,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return nt_call_original!(
            &HOOK_NT_QUERY_ATTRIBUTES_FILE,
            "NtQueryAttributesFile",
            (object_attributes, file_information)
        );
    };

    // H5 resolve-once.
    let Some((dos, pre_resolved)) = resolve_for_hook(object_attributes as *const _) else {
        return nt_call_original!(
            &HOOK_NT_QUERY_ATTRIBUTES_FILE,
            "NtQueryAttributesFile",
            (object_attributes, file_information)
        );
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
            nt_call_original!(
                &HOOK_NT_QUERY_ATTRIBUTES_FILE,
                "NtQueryAttributesFile",
                (attrs_ptr, file_information)
            )
        }
        Mode::Deny => STATUS_ACCESS_DENIED,
        Mode::Mock => {
            // Malformed Mock — fail CLOSED like the create/open arms. A query
            // fall-through would report the REAL file's attributes for a path
            // policy decided to mock (unlike the Cow arm below, an incomplete
            // Mock is corruption of the decision, not a pre-write state).
            let Some(ref overlay_path) = decision.overlay else {
                crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                    pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                    level: ipc::LogLevel::Warn,
                    msg: format!("mock_malformed_decision_deny query_attributes no_overlay: {dos}"),
                });
                return STATUS_ACCESS_DENIED;
            };
            // If overlay missing, materialize mock payload first so the
            // redirected query observes the mocked file instead of ENOENT.
            if !overlay_path.exists() {
                if let Some(ref payload) = decision.mock_payload {
                    materialize_mock_overlay(overlay_path, payload);
                } else {
                    crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                        pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                        level: ipc::LogLevel::Warn,
                        msg: format!("mock_malformed_decision_deny query_attributes no_payload: {dos}"),
                    });
                    return STATUS_ACCESS_DENIED;
                }
            }
            let overlay_dos = overlay_path.to_string_lossy().into_owned();
            // Query path: keep orig's SQOS verbatim (NtQueryAttributesFile is
            // not a create/open syscall and does not exhibit the SQOS
            // STATUS_INVALID_PARAMETER quirk).
            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, false);
            nt_call_original!(
                &HOOK_NT_QUERY_ATTRIBUTES_FILE,
                "NtQueryAttributesFile",
                (h.as_ptr_mut(), file_information)
            )
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
                return nt_call_original!(
                    &HOOK_NT_QUERY_ATTRIBUTES_FILE,
                    "NtQueryAttributesFile",
                    (object_attributes, file_information)
                );
            };
            if !overlay_path.exists() {
                return nt_call_original!(
                    &HOOK_NT_QUERY_ATTRIBUTES_FILE,
                    "NtQueryAttributesFile",
                    (object_attributes, file_information)
                );
            }
            let overlay_dos = overlay_path.to_string_lossy().into_owned();
            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, false);
            nt_call_original!(
                &HOOK_NT_QUERY_ATTRIBUTES_FILE,
                "NtQueryAttributesFile",
                (h.as_ptr_mut(), file_information)
            )
        }
    }
}

pub(crate) unsafe extern "system" fn hook_nt_query_full_attributes_file(
    object_attributes: *mut OBJECT_ATTRIBUTES,
    file_information: *mut c_void,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return nt_call_original!(
            &HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE,
            "NtQueryFullAttributesFile",
            (object_attributes, file_information)
        );
    };

    // H5 resolve-once.
    let Some((dos, pre_resolved)) = resolve_for_hook(object_attributes as *const _) else {
        return nt_call_original!(
            &HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE,
            "NtQueryFullAttributesFile",
            (object_attributes, file_information)
        );
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
            nt_call_original!(
                &HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE,
                "NtQueryFullAttributesFile",
                (attrs_ptr, file_information)
            )
        }
        Mode::Deny => STATUS_ACCESS_DENIED,
        Mode::Mock => {
            // Malformed Mock — fail CLOSED, same rationale as
            // hook_nt_query_attributes_file's Mock arm.
            let Some(ref overlay_path) = decision.overlay else {
                crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                    pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                    level: ipc::LogLevel::Warn,
                    msg: format!("mock_malformed_decision_deny query_full no_overlay: {dos}"),
                });
                return STATUS_ACCESS_DENIED;
            };
            // If overlay missing, materialize mock payload first so the
            // redirected query observes the mocked file instead of ENOENT.
            if !overlay_path.exists() {
                if let Some(ref payload) = decision.mock_payload {
                    materialize_mock_overlay(overlay_path, payload);
                } else {
                    crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                        pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                        level: ipc::LogLevel::Warn,
                        msg: format!("mock_malformed_decision_deny query_full no_payload: {dos}"),
                    });
                    return STATUS_ACCESS_DENIED;
                }
            }
            let overlay_dos = overlay_path.to_string_lossy().into_owned();
            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, false);
            nt_call_original!(
                &HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE,
                "NtQueryFullAttributesFile",
                (h.as_ptr_mut(), file_information)
            )
        }
        Mode::Cow => {
            // See hook_nt_query_attributes_file for the read-only fall-through
            // rationale. Write-side fail-close lives in create/open hooks.
            let Some(ref overlay_path) = decision.overlay else {
                return nt_call_original!(
                    &HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE,
                    "NtQueryFullAttributesFile",
                    (object_attributes, file_information)
                );
            };
            if !overlay_path.exists() {
                return nt_call_original!(
                    &HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE,
                    "NtQueryFullAttributesFile",
                    (object_attributes, file_information)
                );
            }
            let overlay_dos = overlay_path.to_string_lossy().into_owned();
            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, false);
            nt_call_original!(
                &HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE,
                "NtQueryFullAttributesFile",
                (h.as_ptr_mut(), file_information)
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests (audit H-S2 / H-S3 helpers — pure, FFI-free)
// ---------------------------------------------------------------------------
