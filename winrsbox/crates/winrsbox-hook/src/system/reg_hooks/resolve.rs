use super::HANDLE;
use super::KEY_NAME_INFORMATION;
use super::NT_QUERY_KEY;
use super::OBJECT_ATTRIBUTES;
use super::UNICODE_STRING;

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
    parse_key_name(&buf)
}

/// Parse KEY_NAME_INFORMATION bytes — ULONG NameLength followed by WCHAR
/// Name[] — into the UTF-16 key name. Every read is byte-wise: `info` has
/// alignment 1, so casting its base (or base+4) to `*const u32`/`*const u16`
/// and dereferencing would be misaligned-UB — the fields are only naturally
/// aligned when the backing allocation happens to be.
pub(super) fn parse_key_name(info: &[u8]) -> Option<Vec<u16>> {
    if info.len() < 4 {
        return None;
    }
    let name_len_bytes = u32::from_ne_bytes([info[0], info[1], info[2], info[3]]) as usize;
    let char_count = name_len_bytes / 2;
    if char_count == 0 || 4 + name_len_bytes > info.len() {
        return None;
    }
    Some(
        info[4..4 + name_len_bytes]
            .chunks_exact(2)
            .map(|c| u16::from_ne_bytes([c[0], c[1]]))
            .collect(),
    )
}

/// Extract UNICODE_STRING into Rust String (lossy).
///
/// # SAFETY
/// `ustr` must be a valid pointer to a UNICODE_STRING whose Buffer is valid
/// for Length/2 WCHARs. Validity is the caller's guarantee — alignment is
/// NOT: hooked callers (OBJECT_ATTRIBUTES chains) choose the address, so the
/// header is read field-wise with unaligned loads and the WCHARs are copied
/// byte-wise. `Buffer` itself may sit at an odd address; `&*ustr` or
/// `slice::from_raw_parts::<u16>` would assert an alignment nobody promised.
pub(super) unsafe fn ustr_to_string(ustr: *const UNICODE_STRING) -> Option<String> {
    if ustr.is_null() { return None; }
    // SAFETY: read_unaligned of a non-null UNICODE_STRING pointer — caller
    // guarantees validity, not alignment.
    let u = (ustr as *const UNICODE_STRING).read_unaligned();
    let cc = (u.Length / 2) as usize;
    if cc == 0 || u.Buffer.is_null() { return None; }
    // SAFETY: cc WCHARs read byte-wise from UNICODE_STRING.Buffer; Length
    // bounds the region and read_unaligned imposes no alignment.
    let chars: Vec<u16> = (0..cc)
        .map(|i| (u.Buffer.cast::<u8>().add(i * 2) as *const u16).read_unaligned())
        .collect();
    Some(String::from_utf16_lossy(&chars))
}

/// Resolve OBJECT_ATTRIBUTES into a friendly registry path (HKLM\..., HKCU\...).
/// Honors RootDirectory by combining its full path with ObjectName.
///
/// # SAFETY
/// `attrs` must be a valid pointer to OBJECT_ATTRIBUTES with a live UNICODE_STRING ObjectName.
pub(super) unsafe fn resolve_attrs_friendly(attrs: *const OBJECT_ATTRIBUTES) -> Option<String> {
    if attrs.is_null() { return None; }
    // SAFETY: read_unaligned of a non-null OBJECT_ATTRIBUTES pointer — the
    // (hostile) caller guarantees validity, not alignment.
    let oa = (attrs as *const OBJECT_ATTRIBUTES).read_unaligned();
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
pub(super) unsafe fn resolve_handle_friendly(key: HANDLE) -> Option<String> {
    let nt = query_key_full_path(key)?;
    policy::reg::nt_to_friendly(&nt)
}

/// Log the H4 silent_ok → deny downgrade so it shows up in violations.jsonl.
/// Cheap no-op if tracing is off (mirrors the pattern used by other hook
/// violation logs in this crate).
pub(super) fn log_silent_ok_downgrade(syscall: &str, friendly_key: &str, value_name: Option<&str>) {
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

/// Record that a deny-prefix key was opened read-only instead of refused.
///
/// The launcher already emitted a `RegDecide` deny for this key: it decides
/// on the key path alone and never sees `DesiredAccess`. Without this line an
/// investigator reading the log would conclude the call was refused, when in
/// fact the hook forwarded it to `NtOpenKey`. Trace level — this is the
/// normal, expected path for `dnsapi` and friends, not an incident.
pub(super) fn log_open_existing_only(friendly_key: &str, desired_access: u32) {
    if !crate::ipc_client::is_trace() {
        return;
    }
    // SAFETY: GetCurrentProcessId is always safe; no pointers involved.
    let pid = unsafe { winapi::um::processthreadsapi::GetCurrentProcessId() };
    let _ = crate::ipc_client::ipc_log_violation(ipc::Req::Log {
        pid,
        level: ipc::LogLevel::Trace,
        msg: format!(
            "reg_deny_prefix_opened_read_only: key={friendly_key} \
             da=0x{desired_access:x} (routed to NtOpenKey; no key created)",
        ),
    });
}

/// Log a fail-closed denial caused by inability to resolve a registry WRITE
/// target to a friendly key path. Cheap no-op if tracing is off.
pub(super) fn log_resolve_failed(syscall: &str) {
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
