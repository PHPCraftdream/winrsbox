// KTM transacted variants — STATUS_NOT_SUPPORTED.
//
// CLR / RegOpenKeyTransacted go through these. Returning NOT_SUPPORTED
// matches the kernel's behaviour on systems where KTM is disabled and is
// less suspicious to the caller than ACCESS_DENIED.

use super::*;

fn log_transacted_blocked(syscall: &str, target: Option<String>) {
    if !crate::ipc_client::is_trace() {
        return;
    }
    // SAFETY: GetCurrentProcessId is always safe.
    let pid = unsafe { winapi::um::processthreadsapi::GetCurrentProcessId() };
    let msg = match target {
        Some(t) if !t.is_empty() => format!(
            "reg_transacted_blocked: syscall={syscall} target={t}",
        ),
        _ => format!("reg_transacted_blocked: syscall={syscall}"),
    };
    let _ = crate::ipc_client::ipc_log_violation(ipc::Req::Log {
        pid,
        level: ipc::LogLevel::Warn,
        msg,
    });
}

// SAFETY: Called by detour2 dispatcher with the NtCreateKeyTransacted ABI.
pub(super) unsafe extern "system" fn hook_nt_create_key_transacted(
    key_handle: *mut HANDLE,
    desired_access: usize,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    title_index: usize,
    class: *mut UNICODE_STRING,
    create_options: usize,
    transaction: HANDLE,
    disposition: *mut u32,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return nt_call_original!(
            &HOOK_CREATE_KEY_TRANSACTED,
            "NtCreateKeyTransacted",
            (key_handle, desired_access, object_attributes,
             title_index, class, create_options, transaction, disposition)
        );
    };
    let target = resolve_attrs_friendly(object_attributes as *const _);
    log_transacted_blocked("NtCreateKeyTransacted", target);
    if !key_handle.is_null() {
        *key_handle = std::ptr::null_mut();
    }
    STATUS_NOT_SUPPORTED
}

// SAFETY: Called by detour2 dispatcher with the NtOpenKeyTransacted ABI.
pub(super) unsafe extern "system" fn hook_nt_open_key_transacted(
    key_handle: *mut HANDLE,
    desired_access: usize,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    transaction: HANDLE,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return nt_call_original!(
            &HOOK_OPEN_KEY_TRANSACTED,
            "NtOpenKeyTransacted",
            (key_handle, desired_access, object_attributes, transaction)
        );
    };
    let target = resolve_attrs_friendly(object_attributes as *const _);
    log_transacted_blocked("NtOpenKeyTransacted", target);
    if !key_handle.is_null() {
        *key_handle = std::ptr::null_mut();
    }
    STATUS_NOT_SUPPORTED
}

// SAFETY: Called by detour2 dispatcher with the NtOpenKeyTransactedEx ABI.
pub(super) unsafe extern "system" fn hook_nt_open_key_transacted_ex(
    key_handle: *mut HANDLE,
    desired_access: usize,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    open_options: usize,
    transaction: HANDLE,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return nt_call_original!(
            &HOOK_OPEN_KEY_TRANSACTED_EX,
            "NtOpenKeyTransactedEx",
            (key_handle, desired_access, object_attributes, open_options, transaction)
        );
    };
    let target = resolve_attrs_friendly(object_attributes as *const _);
    log_transacted_blocked("NtOpenKeyTransactedEx", target);
    if !key_handle.is_null() {
        *key_handle = std::ptr::null_mut();
    }
    STATUS_NOT_SUPPORTED
}
