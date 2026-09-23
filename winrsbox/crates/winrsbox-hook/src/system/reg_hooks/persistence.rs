// Persistence-escape hook handlers (unconditional deny)
//
// These syscalls bypass the regular Nt(Create|Set|Delete)Key path:
//   * NtRenameKey                — moves a key under a new name
//   * NtSaveKey / NtSaveKeyEx    — dumps a live hive to disk
//   * NtRestoreKey               — replaces a hive with on-disk contents
//   * NtLoadKey / NtLoadKeyEx    — mounts an arbitrary on-disk hive
//   * NtUnloadKey / 2 / Ex       — unmounts a hive (DoS / persistence)
//   * NtReplaceKey               — atomic hive replace at the next boot
//
// They aren't gated by the launcher's regrules policy and there's no
// sensible "overlay" semantics — fail-closed.

use super::*;

/// Emit a violation log if tracing is on.
fn log_persistence_blocked(syscall: &str, target: Option<String>) {
    if !crate::ipc_client::is_trace() {
        return;
    }
    // SAFETY: GetCurrentProcessId never fails / never dereferences a pointer.
    let pid = unsafe { winapi::um::processthreadsapi::GetCurrentProcessId() };
    let msg = match target {
        Some(t) if !t.is_empty() => format!(
            "reg_persistence_blocked: syscall={syscall} target={t}",
        ),
        _ => format!("reg_persistence_blocked: syscall={syscall}"),
    };
    let _ = crate::ipc_client::ipc_log_violation(ipc::Req::Log {
        pid,
        level: ipc::LogLevel::Warn,
        msg,
    });
}

// SAFETY: Called by detour2 dispatcher with the NtRenameKey ABI.
pub(super) unsafe extern "system" fn hook_nt_rename_key(
    key_handle: HANDLE,
    new_name: *mut UNICODE_STRING,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return nt_call_original!(&HOOK_RENAME_KEY, "NtRenameKey", (key_handle, new_name));
    };
    let target = if !key_handle.is_null() {
        resolve_handle_friendly(key_handle).or_else(|| ustr_to_string(new_name as *const _))
    } else {
        ustr_to_string(new_name as *const _)
    };
    log_persistence_blocked("NtRenameKey", target);
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with the NtSaveKey ABI.
pub(super) unsafe extern "system" fn hook_nt_save_key(
    key_handle: HANDLE,
    file_handle: HANDLE,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return nt_call_original!(&HOOK_SAVE_KEY, "NtSaveKey", (key_handle, file_handle));
    };
    let target = resolve_handle_friendly(key_handle);
    log_persistence_blocked("NtSaveKey", target);
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with the NtSaveKeyEx ABI.
pub(super) unsafe extern "system" fn hook_nt_save_key_ex(
    key_handle: HANDLE,
    file_handle: HANDLE,
    format: usize,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return nt_call_original!(&HOOK_SAVE_KEY_EX, "NtSaveKeyEx", (key_handle, file_handle, format));
    };
    let target = resolve_handle_friendly(key_handle);
    log_persistence_blocked("NtSaveKeyEx", target);
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with the NtRestoreKey ABI.
pub(super) unsafe extern "system" fn hook_nt_restore_key(
    key_handle: HANDLE,
    file_handle: HANDLE,
    flags: usize,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return nt_call_original!(&HOOK_RESTORE_KEY, "NtRestoreKey", (key_handle, file_handle, flags));
    };
    let target = resolve_handle_friendly(key_handle);
    log_persistence_blocked("NtRestoreKey", target);
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with the NtLoadKey ABI.
pub(super) unsafe extern "system" fn hook_nt_load_key(
    target_key: *mut OBJECT_ATTRIBUTES,
    source_file: *mut OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return nt_call_original!(&HOOK_LOAD_KEY, "NtLoadKey", (target_key, source_file));
    };
    let target = resolve_attrs_friendly(target_key as *const _);
    log_persistence_blocked("NtLoadKey", target);
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with the NtLoadKeyEx ABI.
pub(super) unsafe extern "system" fn hook_nt_load_key_ex(
    target_key: *mut OBJECT_ATTRIBUTES,
    source_file: *mut OBJECT_ATTRIBUTES,
    flags: usize,
    trust_class_key: HANDLE,
    event: HANDLE,
    desired_access: usize,
    root_handle: *mut HANDLE,
    io_status: *mut c_void,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return nt_call_original!(
            &HOOK_LOAD_KEY_EX,
            "NtLoadKeyEx",
            (target_key, source_file, flags, trust_class_key,
             event, desired_access, root_handle, io_status)
        );
    };
    let target = resolve_attrs_friendly(target_key as *const _);
    log_persistence_blocked("NtLoadKeyEx", target);
    // Defensive: caller may inspect *RootHandle on failure. Null it so they
    // can't accidentally use a stale or uninitialised HANDLE.
    if !root_handle.is_null() {
        *root_handle = std::ptr::null_mut();
    }
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with the NtUnloadKey ABI.
pub(super) unsafe extern "system" fn hook_nt_unload_key(
    target_key: *mut OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return nt_call_original!(&HOOK_UNLOAD_KEY, "NtUnloadKey", (target_key));
    };
    let target = resolve_attrs_friendly(target_key as *const _);
    log_persistence_blocked("NtUnloadKey", target);
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with the NtUnloadKey2 ABI.
pub(super) unsafe extern "system" fn hook_nt_unload_key_2(
    target_key: *mut OBJECT_ATTRIBUTES,
    flags: usize,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return nt_call_original!(&HOOK_UNLOAD_KEY_2, "NtUnloadKey2", (target_key, flags));
    };
    let target = resolve_attrs_friendly(target_key as *const _);
    log_persistence_blocked("NtUnloadKey2", target);
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with the NtUnloadKeyEx ABI.
pub(super) unsafe extern "system" fn hook_nt_unload_key_ex(
    target_key: *mut OBJECT_ATTRIBUTES,
    event: HANDLE,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return nt_call_original!(&HOOK_UNLOAD_KEY_EX, "NtUnloadKeyEx", (target_key, event));
    };
    let target = resolve_attrs_friendly(target_key as *const _);
    log_persistence_blocked("NtUnloadKeyEx", target);
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with the NtReplaceKey ABI.
pub(super) unsafe extern "system" fn hook_nt_replace_key(
    new_file: *mut OBJECT_ATTRIBUTES,
    target_handle: HANDLE,
    old_file: *mut OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return nt_call_original!(&HOOK_REPLACE_KEY, "NtReplaceKey", (new_file, target_handle, old_file));
    };
    let target = resolve_handle_friendly(target_handle)
        .or_else(|| resolve_attrs_friendly(new_file as *const _));
    log_persistence_blocked("NtReplaceKey", target);
    STATUS_ACCESS_DENIED
}
