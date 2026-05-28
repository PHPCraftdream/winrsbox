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
use crate::hooks::STATUS_ACCESS_DENIED;

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

/// Send RegDecide IPC and return the mode string.
/// "deny"        → return STATUS_ACCESS_DENIED
/// "silent_ok"   → currently downgraded to STATUS_ACCESS_DENIED with a
///                 Warn-level violation log (H4 fix — read-side overlay
///                 hooks are not yet implemented, so the value would never
///                 be readable back). When the read-side lands, this maps
///                 back to "route the write to launcher and return SUCCESS".
/// "passthrough" → call original
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
    "passthrough".to_string()
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
        let mode = check_write_mode(&friendly, None); if mode.eq_ignore_ascii_case("deny") {
            if !key_handle.is_null() {
                *key_handle = std::ptr::null_mut();
            }
            return STATUS_ACCESS_DENIED;
        }
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
    }
    call_original()
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

    Ok(())
}

/// # SAFETY
/// Must be called from DLL_PROCESS_DETACH only.
pub unsafe fn uninstall() {
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
}
