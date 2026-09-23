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
use crate::hooks::{nt_call_original, STATUS_ACCESS_DENIED, STATUS_NOT_SUPPORTED};

mod resolve;
mod persistence;
mod transacted;

use resolve::{log_open_existing_only, log_resolve_failed, log_silent_ok_downgrade, resolve_attrs_friendly, resolve_handle_friendly, ustr_to_string};
use persistence::{hook_nt_rename_key, hook_nt_save_key, hook_nt_save_key_ex, hook_nt_restore_key, hook_nt_load_key, hook_nt_load_key_ex, hook_nt_unload_key, hook_nt_unload_key_2, hook_nt_unload_key_ex, hook_nt_replace_key};
use transacted::{hook_nt_create_key_transacted, hook_nt_open_key_transacted, hook_nt_open_key_transacted_ex};

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

// Test-only policy-mode override for `check_write_mode`. Unit tests run
// without the launcher pipe, so the live IPC consult fails closed to
// `Mode::Deny` and the Cow arms would be unreachable from tests. Thread
// local + `Cell` so the consult can never block: a `Mutex` would
// self-deadlock, because the forced test itself re-enters
// `check_write_mode` on the same thread. `None` keeps the production path.
#[cfg(test)]
thread_local! {
    static TEST_MODE_OVERRIDE: std::cell::Cell<Option<policy::Mode>> =
        const { std::cell::Cell::new(None) };
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
fn check_write_mode(friendly_key: &str, value_name: Option<String>) -> policy::Mode {
    #[cfg(test)]
    {
        let forced = TEST_MODE_OVERRIDE.with(|c| c.replace(None));
        if let Some(mode) = forced.clone() {
            TEST_MODE_OVERRIDE.with(|c| c.set(forced));
            return mode;
        }
    }
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
    policy::Mode::Deny
}

/// Registry access-mask bits whose presence in `DesiredAccess` means the
/// caller can mutate the key (set values, create subkeys, delete it,
/// change owner / DACL, or — via the generic / maximum aliases — the kernel
/// could grant any of the above). When NONE of these bits is set, the
/// handle can't mutate values, so only the deny-policy check applies —
/// the silent_ok downgrade is skipped, and the read-only CoW arm routes
/// to `NtOpenKey` instead of proceeding (S13: proceeding would create
/// real host keys) or denying outright (broke dnsapi; see
/// `nt_create_key_action`).
///
/// Public for tests; not exported beyond the crate.
pub(crate) const NT_CREATE_KEY_WRITE_BITS: u32 = {
    // Per Microsoft `ntddk.h` / `winnt.h` registry access rights.
    const KEY_SET_VALUE:      u32 = 0x0002;
    const KEY_CREATE_SUB_KEY: u32 = 0x0004;
    const KEY_CREATE_LINK:    u32 = 0x0020;
    const DELETE:             u32 = 0x0001_0000;
    const WRITE_DAC:          u32 = 0x0004_0000;
    const WRITE_OWNER:        u32 = 0x0008_0000;
    const GENERIC_ALL:        u32 = 0x1000_0000;
    const GENERIC_WRITE:      u32 = 0x4000_0000;
    // MAXIMUM_ALLOWED asks the kernel for "everything you'd allow me to
    // have"; on a key the sandboxed process can write to, that includes
    // write rights. Treat it as a write-intent so the Cow-downgrade still
    // fires on the dangerous case.
    const MAXIMUM_ALLOWED:    u32 = 0x0200_0000;
    KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK
        | DELETE | WRITE_DAC | WRITE_OWNER
        | GENERIC_ALL | GENERIC_WRITE | MAXIMUM_ALLOWED
};

/// `true` when `desired_access` carries any bit that could let the caller
/// mutate the key — see [`NT_CREATE_KEY_WRITE_BITS`] for the bit set.
pub(crate) fn nt_create_key_is_write_access(desired_access: u32) -> bool {
    (desired_access & NT_CREATE_KEY_WRITE_BITS) != 0
}

/// Access mask actually used for `NtCreateKey` under a Cow/Deny prefix.
///
/// `MAXIMUM_ALLOWED` means "whatever you'd grant me", not "I must write".
/// crypt32 retries a denied `KEY_ALL_ACCESS` open of the system cert stores
/// with it; denying that too left the root store unopenable (rustls/schannel:
/// `invalid peer certificate: UnknownIssuer`). Under a prefix that forbids
/// host writes the grantable set is read, so rewrite it to `KEY_READ` — the
/// open-existing-only path then serves it.
///
/// Under Cow, explicit write bits are stripped the same way: crypt32 opens
/// `HKCU\...\SystemCertificates\Root` with `KEY_ALL_ACCESS`-style masks and
/// has no read-only retry for it. Host writes are refused anyway (value
/// hooks deny Cow writes; the read-only handle can't write in the kernel),
/// so a read handle loses nothing. Deny prefixes keep refusing write masks.
pub(crate) fn nt_create_key_effective_access(desired_access: u32, mode: &policy::Mode) -> u32 {
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    const KEY_READ: u32 = 0x0002_0019;
    if matches!(mode, policy::Mode::Cow) && nt_create_key_is_write_access(desired_access) {
        return (desired_access & !NT_CREATE_KEY_WRITE_BITS) | KEY_READ;
    }
    let restricted = matches!(mode, policy::Mode::Cow | policy::Mode::Deny);
    if restricted && desired_access & MAXIMUM_ALLOWED != 0 {
        let rest = desired_access & !MAXIMUM_ALLOWED;
        if !nt_create_key_is_write_access(rest) {
            return rest | KEY_READ;
        }
    }
    desired_access
}

/// What [`hook_nt_create_key`] must do for a given access mask + policy mode.
///
/// The decision is made BEFORE the original NtCreateKey runs: NtCreateKey is
/// create-or-open, and the `Disposition` out-param only reports
/// created-vs-opened after the key already exists — too late to gate a
/// deny-listed creation. So the policy consult runs for every call and only
/// this mapping decides the outcome:
///
/// - `Mode::Deny` → deny, whatever the access mask: the syscall may CREATE
///   the key in the real hive even when called with KEY_READ, and creation
///   is the mutation that must be gated (audit 2026-09-19, Medium).
/// - `Mode::Cow` + write-intent access → deny (silent_ok downgrade, H4).
/// - `Mode::Cow` + read-only access → OpenExistingOnly (S13,
///   review-xa-2026-09-20): proceeding would reach the real create-or-open
///   and CREATE host keys under CoW prefixes; routing through `NtOpenKey`
///   keeps existing keys readable (the dnsapi compat below) without ever
///   creating.
/// - everything else → proceed (call original).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CreateKeyAction {
    Proceed,
    /// Forward to `NtOpenKey` instead of `NtCreateKey`: open the key if it
    /// already exists, never create it. Used for a read-only mask under a
    /// deny prefix — see [`nt_create_key_action`].
    OpenExistingOnly,
    Deny,
}

/// What [`hook_nt_create_key`] must do for a given access mask + policy mode.
///
/// `Mode::Deny` + read-only mask is the interesting case. Denying it outright
/// broke name resolution: `dnsapi` reads the DNS server list from
/// `HKLM\System\CurrentControlSet\Services\Tcpip\Parameters` via
/// `RegCreateKeyEx(KEY_READ)`, and that whole subtree is deny-listed because
/// `\system\currentcontrolset\services` is a service-registration
/// persistence vector. The result was `ENOTFOUND` for every lookup inside
/// the sandbox — network unusable by default.
///
/// Simply proceeding is not an option either: `NtCreateKey` is create-or-open
/// and CREATES the key whatever the mask says, which is the mutation the deny
/// list exists to stop (audit 2026-09-19, Medium).
///
/// `OpenExistingOnly` resolves the conflict instead of trading one bug for the
/// other: forward to `NtOpenKey`, which opens an existing key and returns
/// `OBJECT_NAME_NOT_FOUND` rather than creating anything. Reading a
/// persistence key is not a mutation, and a read-only handle cannot become
/// one — any later call asking for write rights consults policy again and is
/// denied.
///
/// `Mode::Cow` + read-only takes the same route (S13,
/// review-xa-2026-09-20, P1): NtCreateKey creates the key regardless of the
/// mask, and a CoW prefix is supposed to overlay writes, not mutate the
/// host hive — proceeding there created real keys (e.g. under
/// `HKCU\Software`). Open-if-present preserves what the old proceed did
/// for existing keys while refusing the create side-effect.
pub(crate) fn nt_create_key_action(desired_access: u32, mode: policy::Mode) -> CreateKeyAction {
    match mode {
        policy::Mode::Deny if nt_create_key_is_write_access(desired_access) => {
            CreateKeyAction::Deny
        }
        policy::Mode::Deny => CreateKeyAction::OpenExistingOnly,
        policy::Mode::Cow if nt_create_key_is_write_access(desired_access) => CreateKeyAction::Deny,
        // S13 (review-xa-2026-09-20, P1): NtCreateKey is create-or-open and
        // creates the key even under a read-only mask, so proceeding here
        // planted real host keys under CoW prefixes. A CoW prefix overlays
        // writes; a read-only open must never touch the host hive. Route it
        // through NtOpenKey exactly like the deny case: an existing key
        // opens (dnsapi-style RegCreateKeyEx(KEY_READ) stays compatible),
        // a missing key returns OBJECT_NAME_NOT_FOUND, nothing is created.
        policy::Mode::Cow => CreateKeyAction::OpenExistingOnly,
        _ => CreateKeyAction::Proceed,
    }
}

/// `ntdll!NtOpenKey`. This crate does not hook it, so the pointer is the real
/// syscall stub: calling it introduces no detour re-entry.
type FnNtOpenKey = unsafe extern "system" fn(
    *mut HANDLE,            // KeyHandle
    u32,                    // DesiredAccess
    *mut OBJECT_ATTRIBUTES, // ObjectAttributes
) -> NTSTATUS;

static NT_OPEN_KEY: OnceLock<Option<FnNtOpenKey>> = OnceLock::new();

fn nt_open_key() -> Option<FnNtOpenKey> {
    *NT_OPEN_KEY.get_or_init(|| {
        // SAFETY: `ntdll_export` walks the loaded ntdll export directory (the
        //         same resolution every install site here uses); the returned
        //         address is then transmuted to NtOpenKey's documented ABI
        //         (KeyHandle, DesiredAccess, ObjectAttributes).
        unsafe {
            crate::hooks::ntdll_export("NtOpenKey\0".as_bytes())
                .map(|addr| std::mem::transmute::<usize, FnNtOpenKey>(addr as usize))
        }
    })
}

/// `REG_OPENED_EXISTING_KEY` — what `NtCreateKey` reports in `Disposition`
/// when it opened rather than created. The `OpenExistingOnly` path can only
/// ever have opened, so callers that read `Disposition` see the truth.
const REG_OPENED_EXISTING_KEY: u32 = 2;

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
        nt_call_original!(
            &HOOK_CREATE_KEY,
            "NtCreateKey",
            (key_handle, desired_access, object_attributes,
             title_index, class, create_options, disposition)
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // NtCreateKey is create-or-open and CREATES the key regardless of
    // DesiredAccess, so the policy consult must run for every call — the
    // access mask only decides whether the silent_ok downgrade applies
    // (see nt_create_key_action). The previous early-bypass for read-only
    // masks let `NtCreateKey(KEY_READ)` create real keys under deny-listed
    // prefixes (audit 2026-09-19, Medium).
    if let Some(friendly) = resolve_attrs_friendly(object_attributes as *const _) {
        let mode = check_write_mode(&friendly, None);
        let desired_access = nt_create_key_effective_access(desired_access, &mode);
        // Mode is Clone, not Copy — clone so we can still inspect `mode`
        // below to tell the deny-policy deny apart from the Cow downgrade.
        match nt_create_key_action(desired_access, mode.clone()) {
            CreateKeyAction::Deny => {
                if matches!(mode, policy::Mode::Cow) {
                    // Deny came from the silent_ok downgrade (Cow + write-intent):
                    // log it so it shows up in violations.jsonl.
                    log_silent_ok_downgrade(
                        &format!("NtCreateKey(da=0x{desired_access:x})"),
                        &friendly,
                        None,
                    );
                }
                if !key_handle.is_null() {
                    *key_handle = std::ptr::null_mut();
                }
                return STATUS_ACCESS_DENIED;
            }
            CreateKeyAction::OpenExistingOnly => {
                // The launcher's decision ignored the access mask — it
                // decides on the key path alone. Record what actually
                // happened so the audit trail is not a lie.
                log_open_existing_only(&friendly, desired_access);
                // Read-only mask under a deny or CoW prefix: open if it
                // exists, never create. Without a resolvable NtOpenKey we
                // cannot honour "open but do not create", so fail closed
                // rather than fall through to the creating syscall.
                let Some(open) = nt_open_key() else {
                    if !key_handle.is_null() {
                        *key_handle = std::ptr::null_mut();
                    }
                    return STATUS_ACCESS_DENIED;
                };
                // SAFETY: same out-handle / ObjectAttributes the caller
                //         passed to NtCreateKey; NtOpenKey takes the identical
                //         first three parameters.
                let status = open(key_handle, desired_access, object_attributes);
                if status >= 0 && !disposition.is_null() {
                    *disposition = REG_OPENED_EXISTING_KEY;
                }
                return status;
            }
            CreateKeyAction::Proceed => {}
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
        nt_call_original!(
            &HOOK_SET_VALUE_KEY,
            "NtSetValueKey",
            (key_handle, value_name, title_index, value_type, data, data_size)
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if let Some(friendly) = resolve_handle_friendly(key_handle) {
        let v_name = ustr_to_string(value_name as *const _);
        let mode = check_write_mode(&friendly, v_name.clone());
        if matches!(mode, policy::Mode::Deny) {
            return STATUS_ACCESS_DENIED;
        }
        if matches!(mode, policy::Mode::Cow) {
            // CoW registry write: decode the raw value into a typed RegValue
            // and ship it to the launcher, which records it in the CoW overlay
            // (host registry untouched). The read-side merge happens via
            // RegDecision's overlay_value (NtQueryValueKey hook — see below).
            // Return STATUS_SUCCESS so the caller (RegSetValueEx /
            // SetEnvironmentVariable) sees a successful write.
            let raw = if data.is_null() || data_size == 0 {
                &[][..]
            } else {
                // SAFETY: data is valid for data_size bytes per NtSetValueKey contract.
                std::slice::from_raw_parts(data as *const u8, data_size as usize)
            };
            let value = policy::reg::reg_value_from_raw(value_type, raw);
            let req = ipc::Req::RegWrite {
                key_path: friendly.clone(),
                value_name: v_name.clone().unwrap_or_default(),
                value,
            };
            match crate::ipc_client::ipc_send_and_recv(req) {
                Some(ipc::Resp::Ok) => {
                    if crate::ipc_client::is_trace() {
                        crate::hooks::ipc_log(ipc::LogLevel::Trace,
                            format!("reg_setvalue_overlay key={friendly} value={:?}", v_name));
                    }
                    return 0; // STATUS_SUCCESS
                }
                _ => {
                    // IPC failure or launcher refused → fail-closed.
                    log_silent_ok_downgrade("NtSetValueKey", &friendly, v_name.as_deref());
                    return STATUS_ACCESS_DENIED;
                }
            }
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
        nt_call_original!(&HOOK_DELETE_VALUE_KEY, "NtDeleteValueKey", (key_handle, value_name))
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if let Some(friendly) = resolve_handle_friendly(key_handle) {
        let v_name = ustr_to_string(value_name as *const _);
        let mode = check_write_mode(&friendly, v_name.clone());
        if matches!(mode, policy::Mode::Deny) {
            return STATUS_ACCESS_DENIED;
        }
        if matches!(mode, policy::Mode::Cow) {
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
        nt_call_original!(&HOOK_DELETE_KEY, "NtDeleteKey", (key_handle))
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if let Some(friendly) = resolve_handle_friendly(key_handle) {
        let mode = check_write_mode(&friendly, None);
        if matches!(mode, policy::Mode::Deny) {
            return STATUS_ACCESS_DENIED;
        }
        if matches!(mode, policy::Mode::Cow) {
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

    // Best-effort installs for persistence-escape + KTM hooks. A MISSING
    // ntdll export stays a soft-skip (e.g. NtUnloadKey2 only exists on
    // Win8+ — there is nothing to hook if the API doesn't exist). But a
    // PRESENT export whose detour init or enable fails means active ntdll
    // interference (AV/EDR tampering/unhooking): containment can't be
    // trusted, and reg is a REQUIRED category, so the error propagates out
    // of install() → install_hooks() → DllMain FALSE → launcher kills the
    // child.
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
                                    return Err(format!("detour enable {}: {:?}", $sym, e).into());
                                }
                            }
                        }
                        Err(e) => return Err(format!("detour init {}: {:?}", $sym, e).into()),
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
mod tests;
