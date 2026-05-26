// Registry runtime hooks — enforce regrules deny policy via IPC.
//
// Minimal first iteration: hook write/delete operations only.
//   - NtCreateKey: deny key creation under deny-prefixes
//   - NtSetValueKey: deny value writes under deny-prefixes
//   - NtDeleteValueKey: deny value deletion
//   - NtDeleteKey: deny key deletion
//
// Read operations (NtOpenKey, NtQueryValueKey) are passthrough — Mode::Mock
// and Mode::Cow require overlay infrastructure (next iteration).
//
// Path resolution: NtQueryKey(KeyNameInformation) on the open HANDLE returns
// the full NT path; we then convert to friendly form via policy::reg::nt_to_friendly.

use std::sync::OnceLock;

use detour2::GenericDetour;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES, UNICODE_STRING};
use winapi::ctypes::c_void;

use crate::anti_rec;

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

const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000_0022_u32 as NTSTATUS;
const KEY_NAME_INFORMATION: u32 = 3;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read the NT path of an open key handle via NtQueryKey(KeyNameInformation).
unsafe fn query_key_full_path(key: HANDLE) -> Option<Vec<u16>> {
    let nt_query = *NT_QUERY_KEY.get()?;
    let mut buf = vec![0u8; 4096];
    let mut ret_len: u32 = 0;
    let status = nt_query(
        key, KEY_NAME_INFORMATION,
        buf.as_mut_ptr() as *mut _,
        buf.len() as u32, &mut ret_len,
    );
    if status < 0 || ret_len < 4 {
        return None;
    }
    // KEY_NAME_INFORMATION: ULONG NameLength; WCHAR Name[1];
    let name_len_bytes = *(buf.as_ptr() as *const u32) as usize;
    let char_count = name_len_bytes / 2;
    if char_count == 0 || char_count > 2048 {
        return None;
    }
    let buf_ptr = buf.as_ptr().add(4) as *const u16;
    let slice = std::slice::from_raw_parts(buf_ptr, char_count);
    Some(slice.to_vec())
}

/// Extract UNICODE_STRING into Rust String (lossy).
unsafe fn ustr_to_string(ustr: *const UNICODE_STRING) -> Option<String> {
    if ustr.is_null() { return None; }
    let u = &*ustr;
    let cc = (u.Length / 2) as usize;
    if cc == 0 || u.Buffer.is_null() { return None; }
    Some(String::from_utf16_lossy(std::slice::from_raw_parts(u.Buffer, cc)))
}

/// Resolve OBJECT_ATTRIBUTES into a friendly registry path (HKLM\..., HKCU\...).
/// Honors RootDirectory by combining its full path with ObjectName.
unsafe fn resolve_attrs_friendly(attrs: *const OBJECT_ATTRIBUTES) -> Option<String> {
    if attrs.is_null() { return None; }
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
unsafe fn resolve_handle_friendly(key: HANDLE) -> Option<String> {
    let nt = query_key_full_path(key)?;
    policy::reg::nt_to_friendly(&nt)
}

/// Send RegDecide IPC and return the mode string.
/// "deny" → return STATUS_ACCESS_DENIED
/// "silent_ok" → return STATUS_SUCCESS without calling original
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

unsafe extern "system" fn hook_nt_set_value_key(
    key_handle: HANDLE,
    value_name: *mut UNICODE_STRING,
    title_index: u32,
    value_type: u32,
    data: *mut c_void,
    data_size: u32,
) -> NTSTATUS {
    let call_original = || {
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
            if !data.is_null() && data_size > 0 {
                let bytes = std::slice::from_raw_parts(data as *const u8, data_size as usize);
                if let Ok(mut ov) = crate::reg_overlay::overlay().lock() {
                    ov.set_value(&friendly, &v_name.unwrap_or_default(), value_type, bytes);
                }
            }
            return 0; // STATUS_SUCCESS — written to overlay, not real registry
        }
    }
    call_original()
}

unsafe extern "system" fn hook_nt_delete_value_key(
    key_handle: HANDLE,
    value_name: *mut UNICODE_STRING,
) -> NTSTATUS {
    let call_original = || {
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
            if let Ok(mut ov) = crate::reg_overlay::overlay().lock() {
                ov.delete_value(&friendly, &v_name.unwrap_or_default());
            }
            return 0; // STATUS_SUCCESS — tombstone in overlay
        }
    }
    call_original()
}

unsafe extern "system" fn hook_nt_delete_key(key_handle: HANDLE) -> NTSTATUS {
    let call_original = || {
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
            if let Ok(mut ov) = crate::reg_overlay::overlay().lock() {
                ov.delete_key(&friendly);
            }
            return 0;
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
        let f: FnNtQueryKey = std::mem::transmute(addr as usize);
        let _ = NT_QUERY_KEY.set(f);
    }

    macro_rules! install_reg {
        ($lock:expr, $sym:literal, $hook_fn:expr, $fn_ty:ty) => {{
            let addr = crate::hooks::ntdll_export($sym.as_bytes())
                .ok_or_else(|| format!("ntdll export not found: {}", $sym))?;
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
}
