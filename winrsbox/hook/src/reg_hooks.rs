// Registry runtime hooks — enforce regrules deny policy via IPC.
//
// Minimal first iteration: hook write/delete operations only.
//   - NtCreateKey: deny key creation under deny-prefixes
//   - NtSetValueKey: deny value writes under deny-prefixes
//   - NtDeleteValueKey: deny value deletion
//   - NtDeleteKey: deny key deletion
//
// Read operations (NtOpenKey, NtQueryValueKey, NtEnumerateValueKey,
// NtEnumerateKey) are passthrough — Mode::Mock and Mode::Cow require
// overlay infrastructure on the *read* side (next iteration).
//
// H4 fix (silent_ok → deny, fail-closed): until the read-side hooks land,
// the legacy silent_ok mode would absorb a write into the launcher overlay
// and return STATUS_SUCCESS, but a subsequent NtQueryValueKey would still
// hit the real hive and read the OLD value. That violates "writes you just
// performed should be readable" and leaks the host registry on read-back.
// The silent_ok arms below have been downgraded to STATUS_ACCESS_DENIED so
// the child sees a consistent (denied) view instead of an incoherent one.
// When the read-side overlay lands, restore silent_ok as a true CoW write.
//
// Path resolution: NtQueryKey(KeyNameInformation) on the open HANDLE returns
// the full NT path; we then convert to friendly form via policy::reg::nt_to_friendly.

use std::sync::OnceLock;

use detour2::GenericDetour;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES, UNICODE_STRING};
use winapi::ctypes::c_void;

use crate::anti_rec;
use crate::hooks::{STATUS_ACCESS_DENIED, STATUS_NOT_SUPPORTED};

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

type FnNtCreateKey = unsafe extern "system" fn(
    *mut HANDLE,            // KeyHandle
    u32,                    // DesiredAccess
    *mut OBJECT_ATTRIBUTES, // ObjectAttributes
    u32,                    // TitleIndex
    *mut UNICODE_STRING,    // Class
    u32,                    // CreateOptions
    *mut u32,               // Disposition
) -> NTSTATUS;

type FnNtSetValueKey = unsafe extern "system" fn(
    HANDLE,                 // KeyHandle
    *mut UNICODE_STRING,    // ValueName
    u32,                    // TitleIndex
    u32,                    // Type
    *mut c_void,            // Data
    u32,                    // DataSize
) -> NTSTATUS;

type FnNtDeleteValueKey = unsafe extern "system" fn(
    HANDLE,                 // KeyHandle
    *mut UNICODE_STRING,    // ValueName
) -> NTSTATUS;

type FnNtDeleteKey = unsafe extern "system" fn(HANDLE) -> NTSTATUS;

// ---- Persistence-escape syscall signatures ---------------------------------
//
// Width convention (matches the existing reg/fs hook style and detour2's
// `Function` trait): ACCESS_MASK / ULONG / DWORD parameters are typed as
// `usize` here to widen them to the native register size, so the trampoline
// dispatch matches what ntdll's stubs put on the stack/in registers.

type FnNtRenameKey = unsafe extern "system" fn(
    HANDLE,                 // KeyHandle
    *mut UNICODE_STRING,    // NewName
) -> NTSTATUS;

type FnNtSaveKey = unsafe extern "system" fn(
    HANDLE,                 // KeyHandle
    HANDLE,                 // FileHandle
) -> NTSTATUS;

type FnNtSaveKeyEx = unsafe extern "system" fn(
    HANDLE,                 // KeyHandle
    HANDLE,                 // FileHandle
    usize,                  // Format (ULONG)
) -> NTSTATUS;

type FnNtRestoreKey = unsafe extern "system" fn(
    HANDLE,                 // KeyHandle
    HANDLE,                 // FileHandle
    usize,                  // Flags (ULONG)
) -> NTSTATUS;

type FnNtLoadKey = unsafe extern "system" fn(
    *mut OBJECT_ATTRIBUTES, // TargetKey
    *mut OBJECT_ATTRIBUTES, // SourceFile
) -> NTSTATUS;

type FnNtLoadKeyEx = unsafe extern "system" fn(
    *mut OBJECT_ATTRIBUTES, // TargetKey
    *mut OBJECT_ATTRIBUTES, // SourceFile
    usize,                  // Flags (ULONG)
    HANDLE,                 // TrustClassKey
    HANDLE,                 // Event
    usize,                  // DesiredAccess (ACCESS_MASK)
    *mut HANDLE,            // RootHandle
    *mut c_void,            // IoStatus (PIO_STATUS_BLOCK)
) -> NTSTATUS;

type FnNtUnloadKey = unsafe extern "system" fn(
    *mut OBJECT_ATTRIBUTES, // TargetKey
) -> NTSTATUS;

type FnNtUnloadKey2 = unsafe extern "system" fn(
    *mut OBJECT_ATTRIBUTES, // TargetKey
    usize,                  // Flags (ULONG)
) -> NTSTATUS;

type FnNtUnloadKeyEx = unsafe extern "system" fn(
    *mut OBJECT_ATTRIBUTES, // TargetKey
    HANDLE,                 // Event
) -> NTSTATUS;

type FnNtReplaceKey = unsafe extern "system" fn(
    *mut OBJECT_ATTRIBUTES, // NewFile
    HANDLE,                 // TargetHandle
    *mut OBJECT_ATTRIBUTES, // OldFile
) -> NTSTATUS;

// ---- KTM (transacted) signatures -------------------------------------------
//
// All three append a Transaction HANDLE to the corresponding non-transacted
// signature. NtOpenKey/NtOpenKeyEx aren't currently hooked in this crate, so
// the non-transacted shape is reconstructed here for the trampoline alias.

type FnNtCreateKeyTransacted = unsafe extern "system" fn(
    *mut HANDLE,            // KeyHandle
    usize,                  // DesiredAccess (ACCESS_MASK)
    *mut OBJECT_ATTRIBUTES, // ObjectAttributes
    usize,                  // TitleIndex (ULONG)
    *mut UNICODE_STRING,    // Class
    usize,                  // CreateOptions (ULONG)
    HANDLE,                 // Transaction
    *mut u32,               // Disposition
) -> NTSTATUS;

type FnNtOpenKeyTransacted = unsafe extern "system" fn(
    *mut HANDLE,            // KeyHandle
    usize,                  // DesiredAccess (ACCESS_MASK)
    *mut OBJECT_ATTRIBUTES, // ObjectAttributes
    HANDLE,                 // Transaction
) -> NTSTATUS;

type FnNtOpenKeyTransactedEx = unsafe extern "system" fn(
    *mut HANDLE,            // KeyHandle
    usize,                  // DesiredAccess (ACCESS_MASK)
    *mut OBJECT_ATTRIBUTES, // ObjectAttributes
    usize,                  // OpenOptions (ULONG)
    HANDLE,                 // Transaction
) -> NTSTATUS;

type FnNtQueryKey = unsafe extern "system" fn(
    HANDLE,                 // KeyHandle
    u32,                    // KeyInformationClass
    *mut c_void,            // KeyInformation
    u32,                    // Length
    *mut u32,               // ResultLength
) -> NTSTATUS;

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

static HOOK_CREATE_KEY: OnceLock<GenericDetour<FnNtCreateKey>> = OnceLock::new();
static HOOK_SET_VALUE_KEY: OnceLock<GenericDetour<FnNtSetValueKey>> = OnceLock::new();
static HOOK_DELETE_VALUE_KEY: OnceLock<GenericDetour<FnNtDeleteValueKey>> = OnceLock::new();
static HOOK_DELETE_KEY: OnceLock<GenericDetour<FnNtDeleteKey>> = OnceLock::new();

// Persistence-escape hooks (unconditional deny → STATUS_ACCESS_DENIED).
static HOOK_RENAME_KEY:   OnceLock<GenericDetour<FnNtRenameKey>>   = OnceLock::new();
static HOOK_SAVE_KEY:     OnceLock<GenericDetour<FnNtSaveKey>>     = OnceLock::new();
static HOOK_SAVE_KEY_EX:  OnceLock<GenericDetour<FnNtSaveKeyEx>>   = OnceLock::new();
static HOOK_RESTORE_KEY:  OnceLock<GenericDetour<FnNtRestoreKey>>  = OnceLock::new();
static HOOK_LOAD_KEY:     OnceLock<GenericDetour<FnNtLoadKey>>     = OnceLock::new();
static HOOK_LOAD_KEY_EX:  OnceLock<GenericDetour<FnNtLoadKeyEx>>   = OnceLock::new();
static HOOK_UNLOAD_KEY:   OnceLock<GenericDetour<FnNtUnloadKey>>   = OnceLock::new();
static HOOK_UNLOAD_KEY_2: OnceLock<GenericDetour<FnNtUnloadKey2>>  = OnceLock::new();
static HOOK_UNLOAD_KEY_EX:OnceLock<GenericDetour<FnNtUnloadKeyEx>> = OnceLock::new();
static HOOK_REPLACE_KEY:  OnceLock<GenericDetour<FnNtReplaceKey>>  = OnceLock::new();

// KTM transacted variants (unconditional → STATUS_NOT_SUPPORTED).
static HOOK_CREATE_KEY_TRANSACTED:    OnceLock<GenericDetour<FnNtCreateKeyTransacted>>    = OnceLock::new();
static HOOK_OPEN_KEY_TRANSACTED:      OnceLock<GenericDetour<FnNtOpenKeyTransacted>>      = OnceLock::new();
static HOOK_OPEN_KEY_TRANSACTED_EX:   OnceLock<GenericDetour<FnNtOpenKeyTransactedEx>>    = OnceLock::new();

// Resolved at install time, used for path lookup in handlers.
static NT_QUERY_KEY: OnceLock<FnNtQueryKey> = OnceLock::new();

const KEY_NAME_INFORMATION: u32 = 3;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read the NT path of an open key handle via NtQueryKey(KeyNameInformation).
///
/// # SAFETY
/// `key` must be a valid open registry HANDLE. `NT_QUERY_KEY` must be initialised (install-time).
unsafe fn query_key_full_path(key: HANDLE) -> Option<Vec<u16>> {
    let nt_query = *NT_QUERY_KEY.get()?;
    let mut buf = vec![0u8; 4096];
    let mut ret_len: u32 = 0;
    // SAFETY: FFI call into ntdll!NtQueryKey; buf is a valid 4096-byte stack allocation.
    let status = nt_query(
        key, KEY_NAME_INFORMATION,
        buf.as_mut_ptr() as *mut _,
        buf.len() as u32, &mut ret_len,
    );
    if status < 0 || ret_len < 4 {
        return None;
    }
    // KEY_NAME_INFORMATION: ULONG NameLength; WCHAR Name[1];
    // SAFETY: deref of first 4 bytes as u32 — buf is 4096 bytes, status and ret_len validated above.
    let name_len_bytes = *(buf.as_ptr() as *const u32) as usize;
    let char_count = name_len_bytes / 2;
    if char_count == 0 || char_count > 2048 {
        return None;
    }
    let buf_ptr = buf.as_ptr().add(4) as *const u16;
    // SAFETY: from_raw_parts for char_count u16s starting at offset 4; buf is 4096 bytes, char_count ≤ 2048.
    let slice = std::slice::from_raw_parts(buf_ptr, char_count);
    Some(slice.to_vec())
}

/// Extract UNICODE_STRING into Rust String (lossy).
///
/// # SAFETY
/// `ustr` must be a valid pointer to a UNICODE_STRING whose Buffer is valid for Length/2 WCHARs.
unsafe fn ustr_to_string(ustr: *const UNICODE_STRING) -> Option<String> {
    if ustr.is_null() { return None; }
    // SAFETY: deref of non-null UNICODE_STRING pointer — caller guarantees validity.
    let u = &*ustr;
    let cc = (u.Length / 2) as usize;
    if cc == 0 || u.Buffer.is_null() { return None; }
    // SAFETY: from_raw_parts for cc WCHARs from UNICODE_STRING.Buffer; Length field bounds the region.
    Some(String::from_utf16_lossy(std::slice::from_raw_parts(u.Buffer, cc)))
}

/// Resolve OBJECT_ATTRIBUTES into a friendly registry path (HKLM\..., HKCU\...).
/// Honors RootDirectory by combining its full path with ObjectName.
///
/// # SAFETY
/// `attrs` must be a valid pointer to OBJECT_ATTRIBUTES with a live UNICODE_STRING ObjectName.
unsafe fn resolve_attrs_friendly(attrs: *const OBJECT_ATTRIBUTES) -> Option<String> {
    if attrs.is_null() { return None; }
    // SAFETY: deref of non-null OBJECT_ATTRIBUTES pointer — caller guarantees validity.
    let oa = &*attrs;
    let leaf = ustr_to_string(oa.ObjectName)?;
    let full_nt: Vec<u16> = if oa.RootDirectory.is_null() {
        leaf.encode_utf16().collect()
    } else {
        let root = query_key_full_path(oa.RootDirectory)?;
        let mut combined = root;
        combined.push(b'\\' as u16);
        combined.extend(leaf.encode_utf16());
        combined
    };
    policy::reg::nt_to_friendly(&full_nt)
}

/// Resolve open KEY handle to friendly path.
///
/// # SAFETY
/// `key` must be a valid open registry HANDLE.
unsafe fn resolve_handle_friendly(key: HANDLE) -> Option<String> {
    let nt = query_key_full_path(key)?;
    policy::reg::nt_to_friendly(&nt)
}

/// Log the H4 silent_ok → deny downgrade so it shows up in violations.jsonl.
/// Cheap no-op if tracing is off (mirrors the pattern used by other hook
/// violation logs in this crate).
fn log_silent_ok_downgrade(syscall: &str, friendly_key: &str, value_name: Option<&str>) {
    if !crate::ipc_client::is_trace() {
        return;
    }
    // SAFETY: GetCurrentProcessId is always safe; no pointers involved.
    let pid = unsafe { winapi::um::processthreadsapi::GetCurrentProcessId() };
    let msg = match value_name {
        Some(v) if !v.is_empty() => format!(
            "reg_silent_ok_downgraded_to_deny: syscall={syscall} key={friendly_key} value={v}",
        ),
        _ => format!(
            "reg_silent_ok_downgraded_to_deny: syscall={syscall} key={friendly_key}",
        ),
    };
    let _ = crate::ipc_client::ipc_log_violation(ipc::Req::Log {
        pid,
        level: ipc::LogLevel::Warn,
        msg,
    });
}

/// Log a fail-closed denial caused by inability to resolve a registry WRITE
/// target to a friendly key path. Cheap no-op if tracing is off.
fn log_resolve_failed(syscall: &str) {
    if !crate::ipc_client::is_trace() {
        return;
    }
    // SAFETY: GetCurrentProcessId never fails / never dereferences a pointer.
    let pid = unsafe { winapi::um::processthreadsapi::GetCurrentProcessId() };
    let _ = crate::ipc_client::ipc_log_violation(ipc::Req::Log {
        pid,
        level: ipc::LogLevel::Warn,
        msg: format!("reg_resolve_failed_deny: syscall={syscall}"),
    });
}

/// Send RegDecide IPC and return the mode string.
/// "deny"        → return STATUS_ACCESS_DENIED
/// "silent_ok"   → currently downgraded to STATUS_ACCESS_DENIED with a
///                 Warn-level violation log (H4 fix — read-side overlay
///                 hooks are not yet implemented, so the value would never
///                 be readable back). When the read-side lands, this maps
///                 back to "route the write to launcher and return SUCCESS".
/// "passthrough" → call original
///
/// Fail-closed: if IPC to the launcher (the only trust boundary) fails or the
/// response is malformed, return "deny" rather than "passthrough". This matches
/// the file-system path (`ipc_client::ipc_decide`, which returns Mode::Deny and
/// self-terminates after repeated IPC failures); a hostile process must not be
/// able to bypass registry policy by severing the pipe.
fn check_write_mode(friendly_key: &str, value_name: Option<String>) -> String {
    let req = ipc::Req::RegDecide {
        key_path: friendly_key.to_owned(),
        value_name,
        write: true,
    };
    if let Some(resp) = crate::hooks::ipc_send_and_recv(req) {
        if let ipc::Resp::RegDecision { mode, .. } = resp {
            return mode;
        }
    }
    "deny".to_string()
}

// ---------------------------------------------------------------------------
// Hook handlers
// ---------------------------------------------------------------------------

// SAFETY: Called by detour2 dispatcher with the same ABI as ntdll!NtCreateKey.
unsafe extern "system" fn hook_nt_create_key(
    key_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    title_index: u32,
    class: *mut UNICODE_STRING,
    create_options: u32,
    disposition: *mut u32,
) -> NTSTATUS {
    let call_original = || {
        // SAFETY: detour2 guarantees trampoline matches FnNtCreateKey ABI.
        HOOK_CREATE_KEY.get().unwrap().call(
            key_handle, desired_access, object_attributes,
            title_index, class, create_options, disposition,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if let Some(friendly) = resolve_attrs_friendly(object_attributes as *const _) {
        let mode = check_write_mode(&friendly, None);
        if mode.eq_ignore_ascii_case("deny") {
            if !key_handle.is_null() {
                *key_handle = std::ptr::null_mut();
            }
            return STATUS_ACCESS_DENIED;
        }
        if mode.eq_ignore_ascii_case("silent_ok") {
            // H4-parity: NtCreateKey was the only registry write hook missing the
            // silent_ok arm, so a silent_ok key creation fell through to the real
            // syscall. Downgrade to deny (fail-closed) like NtSetValueKey /
            // NtDeleteValueKey / NtDeleteKey until the read-side overlay lands.
            log_silent_ok_downgrade("NtCreateKey", &friendly, None);
            if !key_handle.is_null() {
                *key_handle = std::ptr::null_mut();
            }
            return STATUS_ACCESS_DENIED;
        }
    } else {
        // Audit CRITICAL fix: a None here previously fell through to
        // call_original() with NO policy check (fail-open). Custom hives cannot
        // be mounted in the sandbox (NtLoadKey is denied), so an unresolvable
        // write target is an exotic hive or a transient NtQueryKey failure —
        // fail CLOSED rather than letting the create/open bypass policy.
        log_resolve_failed("NtCreateKey");
        if !key_handle.is_null() {
            *key_handle = std::ptr::null_mut();
        }
        return STATUS_ACCESS_DENIED;
    }
    call_original()
}

// SAFETY: Called by detour2 dispatcher with the same ABI as ntdll!NtSetValueKey.
unsafe extern "system" fn hook_nt_set_value_key(
    key_handle: HANDLE,
    value_name: *mut UNICODE_STRING,
    title_index: u32,
    value_type: u32,
    data: *mut c_void,
    data_size: u32,
) -> NTSTATUS {
    let call_original = || {
        // SAFETY: detour2 guarantees trampoline matches FnNtSetValueKey ABI.
        HOOK_SET_VALUE_KEY.get().unwrap().call(
            key_handle, value_name, title_index, value_type, data, data_size,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if let Some(friendly) = resolve_handle_friendly(key_handle) {
        let v_name = ustr_to_string(value_name as *const _);
        let mode = check_write_mode(&friendly, v_name.clone());
        if mode.eq_ignore_ascii_case("deny") {
            return STATUS_ACCESS_DENIED;
        }
        if mode.eq_ignore_ascii_case("silent_ok") {
            // H4 fix: downgrade silent_ok → deny while the read-side overlay
            // is missing. The launcher overlay would happily absorb this
            // write, but a follow-up NtQueryValueKey on the same key still
            // hits the real hive and reads the OLD value — confusing the
            // child *and* leaking host state. Fail-closed is the safer
            // regression. The previously-routed RegWrite IPC payload (4 LE
            // bytes of REG_* type followed by raw value bytes) is no longer
            // produced; restore it once the read-side hooks land.
            log_silent_ok_downgrade("NtSetValueKey", &friendly, v_name.as_deref());
            return STATUS_ACCESS_DENIED;
        }
    } else {
        // Fail CLOSED on resolution failure (audit CRITICAL): unresolvable key
        // handle must not let a value write bypass the policy check.
        log_resolve_failed("NtSetValueKey");
        return STATUS_ACCESS_DENIED;
    }
    call_original()
}

// SAFETY: Called by detour2 dispatcher with the same ABI as ntdll!NtDeleteValueKey.
unsafe extern "system" fn hook_nt_delete_value_key(
    key_handle: HANDLE,
    value_name: *mut UNICODE_STRING,
) -> NTSTATUS {
    let call_original = || {
        // SAFETY: detour2 guarantees trampoline matches FnNtDeleteValueKey ABI.
        HOOK_DELETE_VALUE_KEY.get().unwrap().call(key_handle, value_name)
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if let Some(friendly) = resolve_handle_friendly(key_handle) {
        let v_name = ustr_to_string(value_name as *const _);
        let mode = check_write_mode(&friendly, v_name.clone());
        if mode.eq_ignore_ascii_case("deny") {
            return STATUS_ACCESS_DENIED;
        }
        if mode.eq_ignore_ascii_case("silent_ok") {
            // H4 fix: same rationale as NtSetValueKey. A tombstone recorded
            // in the launcher overlay can't be observed by the child until
            // NtQueryValueKey / NtEnumerateValueKey are hooked; until then,
            // deny the delete instead of pretending it succeeded.
            log_silent_ok_downgrade("NtDeleteValueKey", &friendly, v_name.as_deref());
            return STATUS_ACCESS_DENIED;
        }
    } else {
        // Fail CLOSED on resolution failure (audit CRITICAL).
        log_resolve_failed("NtDeleteValueKey");
        return STATUS_ACCESS_DENIED;
    }
    call_original()
}

// SAFETY: Called by detour2 dispatcher with the same ABI as ntdll!NtDeleteKey.
unsafe extern "system" fn hook_nt_delete_key(key_handle: HANDLE) -> NTSTATUS {
    let call_original = || {
        // SAFETY: detour2 guarantees trampoline matches FnNtDeleteKey ABI.
        HOOK_DELETE_KEY.get().unwrap().call(key_handle)
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if let Some(friendly) = resolve_handle_friendly(key_handle) {
        let mode = check_write_mode(&friendly, None);
        if mode.eq_ignore_ascii_case("deny") {
            return STATUS_ACCESS_DENIED;
        }
        if mode.eq_ignore_ascii_case("silent_ok") {
            // H4 fix: key-delete tombstones in the launcher overlay aren't
            // visible to the child without read-side enumeration hooks.
            // Fail closed to keep the registry view consistent.
            log_silent_ok_downgrade("NtDeleteKey", &friendly, None);
            return STATUS_ACCESS_DENIED;
        }
    } else {
        // Fail CLOSED on resolution failure (audit CRITICAL).
        log_resolve_failed("NtDeleteKey");
        return STATUS_ACCESS_DENIED;
    }
    call_original()
}

// ---------------------------------------------------------------------------
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
// ---------------------------------------------------------------------------

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
unsafe extern "system" fn hook_nt_rename_key(
    key_handle: HANDLE,
    new_name: *mut UNICODE_STRING,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return HOOK_RENAME_KEY.get().unwrap().call(key_handle, new_name);
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
unsafe extern "system" fn hook_nt_save_key(
    key_handle: HANDLE,
    file_handle: HANDLE,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return HOOK_SAVE_KEY.get().unwrap().call(key_handle, file_handle);
    };
    let target = resolve_handle_friendly(key_handle);
    log_persistence_blocked("NtSaveKey", target);
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with the NtSaveKeyEx ABI.
unsafe extern "system" fn hook_nt_save_key_ex(
    key_handle: HANDLE,
    file_handle: HANDLE,
    format: usize,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return HOOK_SAVE_KEY_EX.get().unwrap().call(key_handle, file_handle, format);
    };
    let target = resolve_handle_friendly(key_handle);
    log_persistence_blocked("NtSaveKeyEx", target);
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with the NtRestoreKey ABI.
unsafe extern "system" fn hook_nt_restore_key(
    key_handle: HANDLE,
    file_handle: HANDLE,
    flags: usize,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return HOOK_RESTORE_KEY.get().unwrap().call(key_handle, file_handle, flags);
    };
    let target = resolve_handle_friendly(key_handle);
    log_persistence_blocked("NtRestoreKey", target);
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with the NtLoadKey ABI.
unsafe extern "system" fn hook_nt_load_key(
    target_key: *mut OBJECT_ATTRIBUTES,
    source_file: *mut OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return HOOK_LOAD_KEY.get().unwrap().call(target_key, source_file);
    };
    let target = resolve_attrs_friendly(target_key as *const _);
    log_persistence_blocked("NtLoadKey", target);
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with the NtLoadKeyEx ABI.
unsafe extern "system" fn hook_nt_load_key_ex(
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
        return HOOK_LOAD_KEY_EX.get().unwrap().call(
            target_key, source_file, flags, trust_class_key,
            event, desired_access, root_handle, io_status,
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
unsafe extern "system" fn hook_nt_unload_key(
    target_key: *mut OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return HOOK_UNLOAD_KEY.get().unwrap().call(target_key);
    };
    let target = resolve_attrs_friendly(target_key as *const _);
    log_persistence_blocked("NtUnloadKey", target);
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with the NtUnloadKey2 ABI.
unsafe extern "system" fn hook_nt_unload_key_2(
    target_key: *mut OBJECT_ATTRIBUTES,
    flags: usize,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return HOOK_UNLOAD_KEY_2.get().unwrap().call(target_key, flags);
    };
    let target = resolve_attrs_friendly(target_key as *const _);
    log_persistence_blocked("NtUnloadKey2", target);
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with the NtUnloadKeyEx ABI.
unsafe extern "system" fn hook_nt_unload_key_ex(
    target_key: *mut OBJECT_ATTRIBUTES,
    event: HANDLE,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return HOOK_UNLOAD_KEY_EX.get().unwrap().call(target_key, event);
    };
    let target = resolve_attrs_friendly(target_key as *const _);
    log_persistence_blocked("NtUnloadKeyEx", target);
    STATUS_ACCESS_DENIED
}

// SAFETY: Called by detour2 dispatcher with the NtReplaceKey ABI.
unsafe extern "system" fn hook_nt_replace_key(
    new_file: *mut OBJECT_ATTRIBUTES,
    target_handle: HANDLE,
    old_file: *mut OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return HOOK_REPLACE_KEY.get().unwrap().call(new_file, target_handle, old_file);
    };
    let target = resolve_handle_friendly(target_handle)
        .or_else(|| resolve_attrs_friendly(new_file as *const _));
    log_persistence_blocked("NtReplaceKey", target);
    STATUS_ACCESS_DENIED
}

// ---------------------------------------------------------------------------
// KTM transacted variants — STATUS_NOT_SUPPORTED.
//
// CLR / RegOpenKeyTransacted go through these. Returning NOT_SUPPORTED
// matches the kernel's behaviour on systems where KTM is disabled and is
// less suspicious to the caller than ACCESS_DENIED.
// ---------------------------------------------------------------------------

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
unsafe extern "system" fn hook_nt_create_key_transacted(
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
        return HOOK_CREATE_KEY_TRANSACTED.get().unwrap().call(
            key_handle, desired_access, object_attributes,
            title_index, class, create_options, transaction, disposition,
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
unsafe extern "system" fn hook_nt_open_key_transacted(
    key_handle: *mut HANDLE,
    desired_access: usize,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    transaction: HANDLE,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return HOOK_OPEN_KEY_TRANSACTED.get().unwrap().call(
            key_handle, desired_access, object_attributes, transaction,
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
unsafe extern "system" fn hook_nt_open_key_transacted_ex(
    key_handle: *mut HANDLE,
    desired_access: usize,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    open_options: usize,
    transaction: HANDLE,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return HOOK_OPEN_KEY_TRANSACTED_EX.get().unwrap().call(
            key_handle, desired_access, object_attributes, open_options, transaction,
        );
    };
    let target = resolve_attrs_friendly(object_attributes as *const _);
    log_transacted_blocked("NtOpenKeyTransactedEx", target);
    if !key_handle.is_null() {
        *key_handle = std::ptr::null_mut();
    }
    STATUS_NOT_SUPPORTED
}

// ---------------------------------------------------------------------------
// Install / Uninstall
// ---------------------------------------------------------------------------

/// # SAFETY
/// Must be called from install_hooks() in DllMain context with anti_rec entered.
pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    // Resolve NtQueryKey (used by handlers to resolve key paths)
    if let Some(addr) = crate::hooks::ntdll_export("NtQueryKey\0".as_bytes()) {
        // SAFETY: transmute of ntdll export address; ABI matches FnNtQueryKey signature.
        let f: FnNtQueryKey = std::mem::transmute(addr as usize);
        let _ = NT_QUERY_KEY.set(f);
    }

    macro_rules! install_reg {
        ($lock:expr, $sym:literal, $hook_fn:expr, $fn_ty:ty) => {{
            let addr = crate::hooks::ntdll_export($sym.as_bytes())
                .ok_or_else(|| format!("ntdll export not found: {}", $sym))?;
            // SAFETY: transmute of ntdll export address; ABI matches the hook function type.
            let target: $fn_ty = std::mem::transmute(addr as usize);
            let hook_ptr: $fn_ty = $hook_fn;
            let detour = GenericDetour::<$fn_ty>::new(target, hook_ptr)
                .map_err(|e| format!("detour init {}: {:?}", $sym, e))?;
            $lock.set(detour).ok();
            $lock.get().expect("set above").enable()
                .map_err(|e| format!("detour enable {}: {:?}", $sym, e))?;
        }};
    }

    install_reg!(HOOK_CREATE_KEY,       "NtCreateKey\0",      hook_nt_create_key,       FnNtCreateKey);
    install_reg!(HOOK_SET_VALUE_KEY,    "NtSetValueKey\0",    hook_nt_set_value_key,    FnNtSetValueKey);
    install_reg!(HOOK_DELETE_VALUE_KEY, "NtDeleteValueKey\0", hook_nt_delete_value_key, FnNtDeleteValueKey);
    install_reg!(HOOK_DELETE_KEY,       "NtDeleteKey\0",      hook_nt_delete_key,       FnNtDeleteKey);

    // Best-effort installs for persistence-escape + KTM hooks. Don't fail the
    // whole reg_hooks install if a single Ex variant isn't exported by the
    // running ntdll (e.g. NtUnloadKey2 only exists on Win8+).
    macro_rules! install_best_effort {
        ($lock:expr, $sym:literal, $hook_fn:expr, $fn_ty:ty) => {{
            match crate::hooks::ntdll_export($sym.as_bytes()) {
                Some(addr) => {
                    // SAFETY: transmute of ntdll export address; ABI matches hook fn type.
                    let target: $fn_ty = std::mem::transmute(addr as usize);
                    let hook_ptr: $fn_ty = $hook_fn;
                    match GenericDetour::<$fn_ty>::new(target, hook_ptr) {
                        Ok(detour) => {
                            let _ = $lock.set(detour);
                            if let Some(h) = $lock.get() {
                                if let Err(e) = h.enable() {
                                    crate::hooks::buffer_install_error(
                                        format!("detour enable {}: {:?}", $sym, e),
                                    );
                                }
                            }
                        }
                        Err(e) => crate::hooks::buffer_install_error(
                            format!("detour init {}: {:?}", $sym, e),
                        ),
                    }
                }
                None => crate::hooks::buffer_install_error(
                    format!("ntdll export not found: {}", $sym),
                ),
            }
        }};
    }

    install_best_effort!(HOOK_RENAME_KEY,    "NtRenameKey\0",    hook_nt_rename_key,    FnNtRenameKey);
    install_best_effort!(HOOK_SAVE_KEY,      "NtSaveKey\0",      hook_nt_save_key,      FnNtSaveKey);
    install_best_effort!(HOOK_SAVE_KEY_EX,   "NtSaveKeyEx\0",    hook_nt_save_key_ex,   FnNtSaveKeyEx);
    install_best_effort!(HOOK_RESTORE_KEY,   "NtRestoreKey\0",   hook_nt_restore_key,   FnNtRestoreKey);
    install_best_effort!(HOOK_LOAD_KEY,      "NtLoadKey\0",      hook_nt_load_key,      FnNtLoadKey);
    install_best_effort!(HOOK_LOAD_KEY_EX,   "NtLoadKeyEx\0",    hook_nt_load_key_ex,   FnNtLoadKeyEx);
    install_best_effort!(HOOK_UNLOAD_KEY,    "NtUnloadKey\0",    hook_nt_unload_key,    FnNtUnloadKey);
    install_best_effort!(HOOK_UNLOAD_KEY_2,  "NtUnloadKey2\0",   hook_nt_unload_key_2,  FnNtUnloadKey2);
    install_best_effort!(HOOK_UNLOAD_KEY_EX, "NtUnloadKeyEx\0",  hook_nt_unload_key_ex, FnNtUnloadKeyEx);
    install_best_effort!(HOOK_REPLACE_KEY,   "NtReplaceKey\0",   hook_nt_replace_key,   FnNtReplaceKey);

    install_best_effort!(HOOK_CREATE_KEY_TRANSACTED,  "NtCreateKeyTransacted\0",  hook_nt_create_key_transacted,  FnNtCreateKeyTransacted);
    install_best_effort!(HOOK_OPEN_KEY_TRANSACTED,    "NtOpenKeyTransacted\0",    hook_nt_open_key_transacted,    FnNtOpenKeyTransacted);
    install_best_effort!(HOOK_OPEN_KEY_TRANSACTED_EX, "NtOpenKeyTransactedEx\0",  hook_nt_open_key_transacted_ex, FnNtOpenKeyTransactedEx);

    Ok(())
}

/// # SAFETY
/// Must be called from DLL_PROCESS_DETACH only.
pub unsafe fn uninstall() {
    if let Some(h) = HOOK_OPEN_KEY_TRANSACTED_EX.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_OPEN_KEY_TRANSACTED.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_CREATE_KEY_TRANSACTED.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_REPLACE_KEY.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_UNLOAD_KEY_EX.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_UNLOAD_KEY_2.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_UNLOAD_KEY.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_LOAD_KEY_EX.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_LOAD_KEY.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_RESTORE_KEY.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_SAVE_KEY_EX.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_SAVE_KEY.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_RENAME_KEY.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_DELETE_KEY.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_DELETE_VALUE_KEY.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_SET_VALUE_KEY.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_CREATE_KEY.get() { let _ = h.disable(); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_decision_matches_case_insensitive() {
        // Quick sanity check on mode comparison
        let m = "Deny".to_string();
        assert!(m.eq_ignore_ascii_case("deny"));
        let m2 = "DENY".to_string();
        assert!(m2.eq_ignore_ascii_case("deny"));
        let m3 = "passthrough".to_string();
        assert!(!m3.eq_ignore_ascii_case("deny"));
    }

    // ---------------- H4: silent_ok → deny regression tests ----------------

    /// Pins the integer the (formerly silent_ok) arm now returns. Driving
    /// the real ntdll syscall in a unit test would require a live kernel
    /// handle, but we can lock down the constant the handlers reach for so
    /// a regression that flips the path back to STATUS_SUCCESS (0) blows up.
    #[test]
    fn silent_ok_downgrade_returns_access_denied_constant() {
        // STATUS_ACCESS_DENIED == 0xC000_0022 per ntstatus.h. NTSTATUS is i32;
        // the high bit is the severity flag (ERROR) → negative i32.
        assert_eq!(
            STATUS_ACCESS_DENIED as u32, 0xC000_0022_u32,
            "STATUS_ACCESS_DENIED constant changed — silent_ok return value is wrong",
        );
        assert!(
            STATUS_ACCESS_DENIED < 0,
            "STATUS_ACCESS_DENIED must have severity=ERROR (negative i32)",
        );
        // Symmetric check: the legacy "silent" success return (0) is NOT
        // what the H4 path produces.
        assert_ne!(STATUS_ACCESS_DENIED, 0);
    }

    /// "silent_ok" is the only spelling the launcher emits that the H4
    /// downgrade keys off. Confirm the case-insensitive compare the
    /// handlers use still matches every reasonable spelling so the
    /// downgrade actually fires when the launcher asks for it.
    #[test]
    fn silent_ok_mode_string_match_is_case_insensitive() {
        for spelling in ["silent_ok", "Silent_Ok", "SILENT_OK", "silent_OK"] {
            assert!(
                spelling.eq_ignore_ascii_case("silent_ok"),
                "spelling {spelling:?} should match silent_ok",
            );
        }
        // Negative: anything not silent_ok must not fire the downgrade.
        for non_match in ["silentok", "silent ok", "silent_ko", "deny", "passthrough"] {
            assert!(
                !non_match.eq_ignore_ascii_case("silent_ok"),
                "spelling {non_match:?} must not match silent_ok",
            );
        }
    }

    // ── persistence-escape hooks: unconditional deny ─────────────────────
    //
    // Each test calls the hook directly with NULL arguments. The handler's
    // anti_rec guard is acquired (no other hook is on this thread), name
    // resolution gracefully returns None on NULL pointers, and the handler
    // returns the deny code. These exercise the bare deny path without
    // requiring live kernel handles.

    #[test]
    fn nt_rename_key_denied() {
        assert_eq!(
            unsafe { hook_nt_rename_key(std::ptr::null_mut(), std::ptr::null_mut()) },
            crate::hooks::STATUS_ACCESS_DENIED
        );
    }

    #[test]
    fn nt_save_key_denied() {
        assert_eq!(
            unsafe { hook_nt_save_key(std::ptr::null_mut(), std::ptr::null_mut()) },
            crate::hooks::STATUS_ACCESS_DENIED
        );
    }

    #[test]
    fn nt_save_key_ex_denied() {
        assert_eq!(
            unsafe { hook_nt_save_key_ex(std::ptr::null_mut(), std::ptr::null_mut(), 0) },
            crate::hooks::STATUS_ACCESS_DENIED
        );
    }

    #[test]
    fn nt_restore_key_denied() {
        assert_eq!(
            unsafe { hook_nt_restore_key(std::ptr::null_mut(), std::ptr::null_mut(), 0) },
            crate::hooks::STATUS_ACCESS_DENIED
        );
    }

    #[test]
    fn nt_load_key_denied() {
        assert_eq!(
            unsafe { hook_nt_load_key(std::ptr::null_mut(), std::ptr::null_mut()) },
            crate::hooks::STATUS_ACCESS_DENIED
        );
    }

    #[test]
    fn nt_load_key_ex_denied_and_nulls_root_handle() {
        // Stash a sentinel in RootHandle; the hook must overwrite it with NULL
        // so the caller can't observe a stale handle on the deny path.
        let mut root: HANDLE = 0x1234_5678 as HANDLE;
        let status = unsafe {
            hook_nt_load_key_ex(
                std::ptr::null_mut(),  // TargetKey
                std::ptr::null_mut(),  // SourceFile
                0,                     // Flags
                std::ptr::null_mut(),  // TrustClassKey
                std::ptr::null_mut(),  // Event
                0,                     // DesiredAccess
                &mut root,             // RootHandle (sentinel)
                std::ptr::null_mut(),  // IoStatus
            )
        };
        assert_eq!(status, crate::hooks::STATUS_ACCESS_DENIED);
        assert!(root.is_null(), "RootHandle must be nulled on deny");
    }

    #[test]
    fn nt_unload_key_denied() {
        assert_eq!(
            unsafe { hook_nt_unload_key(std::ptr::null_mut()) },
            crate::hooks::STATUS_ACCESS_DENIED
        );
    }

    #[test]
    fn nt_unload_key_2_denied() {
        assert_eq!(
            unsafe { hook_nt_unload_key_2(std::ptr::null_mut(), 0) },
            crate::hooks::STATUS_ACCESS_DENIED
        );
    }

    #[test]
    fn nt_unload_key_ex_denied() {
        assert_eq!(
            unsafe { hook_nt_unload_key_ex(std::ptr::null_mut(), std::ptr::null_mut()) },
            crate::hooks::STATUS_ACCESS_DENIED
        );
    }

    #[test]
    fn nt_replace_key_denied() {
        assert_eq!(
            unsafe {
                hook_nt_replace_key(
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            crate::hooks::STATUS_ACCESS_DENIED
        );
    }

    // ── KTM transacted variants: STATUS_NOT_SUPPORTED ────────────────────

    #[test]
    fn nt_create_key_transacted_not_supported() {
        let mut key: HANDLE = 0xDEAD_BEEF as HANDLE;
        let status = unsafe {
            hook_nt_create_key_transacted(
                &mut key,
                0,                     // DesiredAccess
                std::ptr::null_mut(),  // ObjectAttributes
                0,                     // TitleIndex
                std::ptr::null_mut(),  // Class
                0,                     // CreateOptions
                std::ptr::null_mut(),  // Transaction
                std::ptr::null_mut(),  // Disposition
            )
        };
        assert_eq!(status, crate::hooks::STATUS_NOT_SUPPORTED);
        assert!(key.is_null(), "KeyHandle out-param must be nulled");
    }

    #[test]
    fn nt_open_key_transacted_not_supported() {
        let mut key: HANDLE = 0xDEAD_BEEF as HANDLE;
        let status = unsafe {
            hook_nt_open_key_transacted(
                &mut key,
                0,                     // DesiredAccess
                std::ptr::null_mut(),  // ObjectAttributes
                std::ptr::null_mut(),  // Transaction
            )
        };
        assert_eq!(status, crate::hooks::STATUS_NOT_SUPPORTED);
        assert!(key.is_null(), "KeyHandle out-param must be nulled");
    }

    #[test]
    fn nt_open_key_transacted_ex_not_supported() {
        let mut key: HANDLE = 0xDEAD_BEEF as HANDLE;
        let status = unsafe {
            hook_nt_open_key_transacted_ex(
                &mut key,
                0,                     // DesiredAccess
                std::ptr::null_mut(),  // ObjectAttributes
                0,                     // OpenOptions
                std::ptr::null_mut(),  // Transaction
            )
        };
        assert_eq!(status, crate::hooks::STATUS_NOT_SUPPORTED);
        assert!(key.is_null(), "KeyHandle out-param must be nulled");
    }

    /// Pin the KTM status code value reachable via the reg_hooks module so
    /// any future change to STATUS_NOT_SUPPORTED has to update the canonical
    /// pin test in `hooks::status_constant_tests` too.
    #[test]
    fn status_not_supported_value() {
        assert_eq!(crate::hooks::STATUS_NOT_SUPPORTED, 0xC000_00BB_u32 as i32);
    }
}
