use super::*;
use super::resolve::parse_key_name;

// ── unaligned-read regression (alignment-UB class, mirrors 9d73d34) ──
//
// query_key_full_path parses NtQueryKey's KEY_NAME_INFORMATION out of a
// Vec<u8> (alignment 1) and ustr_to_string / resolve_attrs_friendly read
// caller-supplied OBJECT_ATTRIBUTES/UNICODE_STRING chains. None of those
// bases carries an alignment guarantee, so every multi-byte access must
// be byte-wise or read_unaligned. The probes below force ODD base
// addresses on purpose — a helper that padded every record would hand
// back an 8-aligned buffer and prove nothing.

/// Byte offset within `backing` whose address is ODD.
fn odd_offset(backing: &[u8]) -> usize {
    let off = 1 - (backing.as_ptr() as usize % 2);
    assert_eq!((backing.as_ptr() as usize + off) % 2, 1, "probe must sit at an odd address");
    off
}

/// Copy `value`'s bytes to `dst` — any alignment.
unsafe fn place_at<T>(dst: *mut u8, value: &T) {
    std::ptr::copy_nonoverlapping(
        value as *const T as *const u8,
        dst,
        std::mem::size_of::<T>(),
    );
}

/// KEY_NAME_INFORMATION at an odd address: the old
/// `*(buf.as_ptr() as *const u32)` + `from_raw_parts::<u16>(base+4)`
/// pair aborted here (misaligned dereference, 0xc0000409) instead of
/// returning the name.
#[test]
fn parse_key_name_reads_misaligned_probe() {
    let mut backing = vec![0u8; 64];
    let off = odd_offset(&backing);
    let info: [u8; 12] = [
        8, 0, 0, 0, // NameLength = 8 bytes
        b'A', 0, b'B', 0, b'C', 0, b'D', 0,
    ];
    // SAFETY: off ≤ 1 and 12 bytes fit inside the 64-byte backing.
    unsafe { std::ptr::copy_nonoverlapping(info.as_ptr(), backing.as_mut_ptr().add(off), 12) };
    // SAFETY: covers the 12 written bytes inside `backing`.
    let probe = unsafe { std::slice::from_raw_parts(backing.as_ptr().add(off), 12) };
    assert_eq!(parse_key_name(probe), Some(vec![0x0041, 0x0042, 0x0043, 0x0044]));
}

#[test]
fn parse_key_name_rejects_malformed_probes() {
    assert_eq!(parse_key_name(&[]), None);
    assert_eq!(parse_key_name(&[4, 0]), None);
    assert_eq!(parse_key_name(&[0, 0, 0, 0]), None, "zero-length name");
    assert_eq!(parse_key_name(&[8, 0, 0, 0, b'A', 0]), None, "length past buffer");
}

/// UNICODE_STRING header AND WCHAR buffer each placed at an odd address:
/// the old `&*ustr` asserted 8-byte header alignment and
/// `from_raw_parts::<u16>` asserted Buffer evenness — both abort here.
#[test]
fn ustr_to_string_reads_misaligned_header_and_buffer() {
    let pattern = "*.log";
    let wchars: Vec<u16> = pattern.encode_utf16().collect();
    let mut text_backing = vec![0u8; wchars.len() * 2 + 8];
    let toff = odd_offset(&text_backing);
    // SAFETY: u8 view of an aligned Vec<u16> payload of the same length.
    let wc_bytes = unsafe {
        std::slice::from_raw_parts(wchars.as_ptr() as *const u8, wchars.len() * 2)
    };
    text_backing[toff..toff + wc_bytes.len()].copy_from_slice(wc_bytes);

    let mut header_backing = vec![0u8; std::mem::size_of::<UNICODE_STRING>() + 8];
    let hoff = odd_offset(&header_backing);
    let header = UNICODE_STRING {
        Length: (wchars.len() * 2) as u16,
        MaximumLength: (wchars.len() * 2 + 2) as u16,
        // SAFETY: pointer into `text_backing` at the odd offset, valid
        // for Length bytes; `text_backing` outlives the call below.
        Buffer: unsafe { text_backing.as_ptr().add(toff) } as *mut u16,
    };
    // SAFETY: hoff ≤ 1, struct fits the backing allocation.
    unsafe { place_at(header_backing.as_mut_ptr().add(hoff), &header) };
    let odd_header =
        unsafe { header_backing.as_ptr().add(hoff) as *const UNICODE_STRING };
    // SAFETY: the odd header is a byte-identical, live UNICODE_STRING.
    let parsed = unsafe { ustr_to_string(odd_header) };
    assert_eq!(parsed.as_deref(), Some(pattern));
}

#[test]
fn deny_mode_enum_match() {
    let mode = policy::Mode::Deny;
    assert!(matches!(mode, policy::Mode::Deny));
    assert!(!matches!(mode, policy::Mode::Passthrough));
    assert!(!matches!(mode, policy::Mode::Cow));
}

#[test]
fn cow_mode_enum_replaces_silent_ok() {
    let mode = policy::Mode::Cow;
    assert!(matches!(mode, policy::Mode::Cow));
    assert!(!matches!(mode, policy::Mode::Deny));
    assert!(!matches!(mode, policy::Mode::Passthrough));
}

#[test]
fn mode_enum_is_exhaustive_fail_closed() {
    for mode in [
        policy::Mode::Deny,
        policy::Mode::Cow,
        policy::Mode::Mock,
        policy::Mode::Passthrough,
        policy::Mode::Hidden,
    ] {
        match mode {
            policy::Mode::Deny | policy::Mode::Cow | policy::Mode::Mock => {
                // These all deny in hook handlers (H4 downgrade)
            }
            policy::Mode::Passthrough => {
                // Only passthrough calls original
            }
            policy::Mode::Hidden => {
                // Hidden is a whiteout marker; reg hooks never see it
                // (it only applies to filesystem paths). Treating it as
                // deny is the fail-closed stance for any future use.
            }
        }
    }
}

// ---------------- H4: Cow(silent_ok) → deny regression tests ----------------

#[test]
fn silent_ok_downgrade_returns_access_denied_constant() {
    assert_eq!(
        STATUS_ACCESS_DENIED as u32, 0xC000_0022_u32,
        "STATUS_ACCESS_DENIED constant changed — Cow return value is wrong",
    );
    assert!(
        STATUS_ACCESS_DENIED < 0,
        "STATUS_ACCESS_DENIED must have severity=ERROR (negative i32)",
    );
    assert_ne!(STATUS_ACCESS_DENIED, 0);
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

// -- nt_create_key_is_write_access ----------------------------------------
//
// Regression coverage for the DNS-from-sandbox fix. NtCreateKey is the
// create-OR-open primitive, and dnsapi's `RegCreateKeyEx(KEY_READ)` on
// `HKLM\System\…` previously hit the Cow-downgrade-to-Deny path and
// cascaded into "Could not resolve host". The fix is to bypass that
// path when DesiredAccess carries no write-intent bits.

/// Microsoft `winnt.h` definitions reproduced here so the tests pin the
/// real-world access masks against our private write-bit set.
mod access_masks {
    pub const KEY_QUERY_VALUE:        u32 = 0x0001;
    pub const KEY_SET_VALUE:          u32 = 0x0002;
    pub const KEY_CREATE_SUB_KEY:     u32 = 0x0004;
    pub const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
    pub const KEY_NOTIFY:             u32 = 0x0010;
    pub const KEY_CREATE_LINK:        u32 = 0x0020;
    pub const READ_CONTROL:           u32 = 0x0002_0000;
    pub const DELETE:                 u32 = 0x0001_0000;
    pub const WRITE_DAC:              u32 = 0x0004_0000;
    pub const WRITE_OWNER:            u32 = 0x0008_0000;
    pub const MAXIMUM_ALLOWED:        u32 = 0x0200_0000;
    pub const GENERIC_ALL:            u32 = 0x1000_0000;
    pub const GENERIC_WRITE:          u32 = 0x4000_0000;
    pub const GENERIC_READ:           u32 = 0x8000_0000;

    // Compound aliases (winnt.h):
    // KEY_READ  = STANDARD_RIGHTS_READ  | QUERY_VALUE | ENUMERATE | NOTIFY
    // KEY_WRITE = STANDARD_RIGHTS_WRITE | SET_VALUE   | CREATE_SUB_KEY
    // KEY_ALL_ACCESS = STANDARD_RIGHTS_ALL | KEY_*
    pub const KEY_READ:               u32 = READ_CONTROL | KEY_QUERY_VALUE
                                          | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY;
    pub const KEY_WRITE:              u32 = READ_CONTROL | KEY_SET_VALUE
                                          | KEY_CREATE_SUB_KEY;
    pub const KEY_ALL_ACCESS:         u32 = 0x000F_003F;
}

#[test]
fn read_only_masks_are_not_writes() {
    use access_masks::*;
    // The single bit that broke DNS — KEY_READ on its own.
    assert!(!nt_create_key_is_write_access(KEY_READ),
        "KEY_READ (=0x{KEY_READ:x}) must NOT be classified as write");
    // Each individual read bit, plus all-reads combined.
    assert!(!nt_create_key_is_write_access(KEY_QUERY_VALUE));
    assert!(!nt_create_key_is_write_access(KEY_ENUMERATE_SUB_KEYS));
    assert!(!nt_create_key_is_write_access(KEY_NOTIFY));
    assert!(!nt_create_key_is_write_access(READ_CONTROL));
    assert!(!nt_create_key_is_write_access(GENERIC_READ));
    let all_reads = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS
                  | KEY_NOTIFY | READ_CONTROL | GENERIC_READ;
    assert!(!nt_create_key_is_write_access(all_reads),
        "OR of every read-only bit must still be a non-write");
}

#[test]
fn write_masks_are_writes() {
    use access_masks::*;
    assert!(nt_create_key_is_write_access(KEY_WRITE));
    assert!(nt_create_key_is_write_access(KEY_SET_VALUE));
    assert!(nt_create_key_is_write_access(KEY_CREATE_SUB_KEY));
    assert!(nt_create_key_is_write_access(KEY_CREATE_LINK));
    assert!(nt_create_key_is_write_access(DELETE));
    assert!(nt_create_key_is_write_access(WRITE_DAC));
    assert!(nt_create_key_is_write_access(WRITE_OWNER));
    assert!(nt_create_key_is_write_access(GENERIC_WRITE));
    assert!(nt_create_key_is_write_access(GENERIC_ALL));
    assert!(nt_create_key_is_write_access(KEY_ALL_ACCESS));
}

#[test]
fn read_plus_write_bit_is_still_write() {
    use access_masks::*;
    // The realistic mixed case: caller asks for read + one write bit.
    // Must still be classified as a write (the read bits don't sanitise
    // the request).
    assert!(nt_create_key_is_write_access(KEY_READ | KEY_SET_VALUE));
    assert!(nt_create_key_is_write_access(KEY_QUERY_VALUE | DELETE));
}

#[test]
fn maximum_allowed_treated_as_write() {
    use access_masks::*;
    // MAXIMUM_ALLOWED asks the kernel for "everything you'd grant me".
    // On a key the caller has write access to, that includes mutate
    // rights — we MUST route through the policy path, otherwise an
    // adversarial process could use it to bypass our Cow-downgrade
    // fail-closed on dangerous keys.
    assert!(nt_create_key_is_write_access(MAXIMUM_ALLOWED));
    assert!(nt_create_key_is_write_access(MAXIMUM_ALLOWED | KEY_READ));
}

#[test]
fn empty_access_is_not_write() {
    // Pathological caller passing 0 — kernel rejects this anyway,
    // but our classifier must not flag it as a write.
    assert!(!nt_create_key_is_write_access(0));
}

#[test]
fn write_bits_set_is_well_formed() {
    // Every bit in NT_CREATE_KEY_WRITE_BITS, taken individually, must
    // be classified as a write. This guards against a future refactor
    // accidentally clearing one of them from the constant.
    let mut bit: u32 = 1;
    while bit != 0 {
        if (NT_CREATE_KEY_WRITE_BITS & bit) != 0 {
            assert!(nt_create_key_is_write_access(bit),
                "isolated write bit 0x{bit:x} must classify as write");
        }
        // Step to next bit; explicit overflow wrap exits the loop.
        bit = bit.checked_shl(1).unwrap_or(0);
    }
}

// ── NtCreateKey gate: the creation is gated, not the access mask ─────
//
// Audit 2026-09-19 (Medium): the old code early-returned call_original()
// for any DesiredAccess without write bits, so NtCreateKey(KEY_READ)
// created real keys under deny-listed prefixes. NtCreateKey creates the
// key regardless of the requested access, and Disposition only reports
// created-vs-opened after the key already exists — the decision has to
// happen before the call.

/// A read-only mask under a deny prefix must neither create the key (the
/// audit finding) nor be refused outright (which broke DNS). It is
/// routed to `NtOpenKey`: existing key opens, missing key returns
/// OBJECT_NAME_NOT_FOUND, nothing is ever created.
#[test]
fn create_key_deny_prefix_read_only_opens_without_creating() {
    use access_masks::*;
    assert_eq!(
        nt_create_key_action(KEY_READ, policy::Mode::Deny),
        CreateKeyAction::OpenExistingOnly,
    );
    assert_eq!(
        nt_create_key_action(KEY_QUERY_VALUE, policy::Mode::Deny),
        CreateKeyAction::OpenExistingOnly,
    );
    assert_eq!(
        nt_create_key_action(0, policy::Mode::Deny),
        CreateKeyAction::OpenExistingOnly,
    );
    // The property the audit cared about is still held: whatever this
    // path does, it is never the creating syscall.
    assert_ne!(
        nt_create_key_action(KEY_READ, policy::Mode::Deny),
        CreateKeyAction::Proceed,
    );
}

/// The concrete regression: `dnsapi` reads the DNS server list from
/// `…\Services\Tcpip\Parameters` with `RegCreateKeyEx(KEY_READ)`, and
/// that subtree is deny-listed as a service-registration vector.
/// Refusing it made every lookup inside the sandbox return ENOTFOUND.
#[test]
fn dns_configuration_key_is_readable_under_the_services_deny() {
    use access_masks::*;
    // Exactly the masks RegCreateKeyEx(KEY_READ) and RegOpenKeyEx use.
    for mask in [KEY_READ, KEY_QUERY_VALUE] {
        assert_eq!(
            nt_create_key_action(mask, policy::Mode::Deny),
            CreateKeyAction::OpenExistingOnly,
            "read-only mask 0x{mask:x} must stay readable or DNS breaks",
        );
    }
    // …while registering a service under the same prefix stays denied.
    assert_eq!(
        nt_create_key_action(KEY_WRITE, policy::Mode::Deny),
        CreateKeyAction::Deny,
    );
}

#[test]
fn create_key_deny_prefix_denied_with_write_intent() {
    use access_masks::*;
    // Pre-existing deny behaviour must survive the refactor.
    assert_eq!(
        nt_create_key_action(KEY_WRITE, policy::Mode::Deny),
        CreateKeyAction::Deny,
    );
    assert_eq!(
        nt_create_key_action(KEY_ALL_ACCESS, policy::Mode::Deny),
        CreateKeyAction::Deny,
    );
}

/// S13 (review-xa-2026-09-20, P1): NtCreateKey is create-or-open and
/// CREATES the key even under a read-only mask, so the former
/// `Cow + KEY_READ -> Proceed` oracle pinned the vulnerability itself: a
/// read-only open on a CoW prefix reached the real NtCreateKey and planted
/// host keys (e.g. under `HKCU\Software`). Corrected invariant: a
/// read-only CoW request takes the same open-existing-only route as Deny —
/// the key opens if it exists, nothing is created if it does not.
#[test]
fn create_key_cow_read_only_opens_without_creating() {
    use access_masks::*;
    assert_eq!(
        nt_create_key_action(KEY_READ, policy::Mode::Cow),
        CreateKeyAction::OpenExistingOnly,
    );
    assert_eq!(
        nt_create_key_action(KEY_QUERY_VALUE, policy::Mode::Cow),
        CreateKeyAction::OpenExistingOnly,
    );
    assert_eq!(
        nt_create_key_action(0, policy::Mode::Cow),
        CreateKeyAction::OpenExistingOnly,
    );
    // The property the finding is about: never the creating syscall.
    assert_ne!(
        nt_create_key_action(KEY_READ, policy::Mode::Cow),
        CreateKeyAction::Proceed,
    );
}

#[test]
fn create_key_cow_write_intent_denied() {
    use access_masks::*;
    // H4 silent_ok downgrade: writable handle + CoW → deny.
    assert_eq!(
        nt_create_key_action(KEY_WRITE, policy::Mode::Cow),
        CreateKeyAction::Deny,
    );
    assert_eq!(
        nt_create_key_action(MAXIMUM_ALLOWED, policy::Mode::Cow),
        CreateKeyAction::Deny,
    );
}

#[test]
fn create_key_passthrough_and_mock_proceed() {
    use access_masks::*;
    assert_eq!(
        nt_create_key_action(KEY_WRITE, policy::Mode::Passthrough),
        CreateKeyAction::Proceed,
    );
    assert_eq!(
        nt_create_key_action(KEY_READ, policy::Mode::Passthrough),
        CreateKeyAction::Proceed,
    );
    assert_eq!(
        nt_create_key_action(KEY_READ, policy::Mode::Mock),
        CreateKeyAction::Proceed,
    );
}

// ── S13 behaviour: Cow + KEY_READ must not create a real host key ────
//
// The routing oracle above proves the decision; the test below proves the
// OUTCOME against the real registry: the OpenExistingOnly path a CoW
// read-only request is routed to cannot create anything. It runs the real
// handler (`hook_nt_create_key`) with the test-only Cow override against a
// unique probe key that does not exist on the host, then runs a control
// arm showing the probe WOULD have been created by a real NtCreateKey —
// so the "still absent" assertion is the exact S13 discriminator: revert
// the fix (Cow + read-only → Proceed) and this test fails at its first
// assert. Everything is resolved from ntdll via `ntdll_export` (the same
// mechanism the hooks use at install time) — no winreg dependency.

const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const REG_CREATED_NEW_KEY: u32 = 1;

type FnRtlOpenCurrentUser = unsafe extern "system" fn(u32, *mut HANDLE) -> NTSTATUS;

/// Resolve an ntdll export's address by name. Panics loudly rather than
/// testing a stub. Callers transmute to the function's documented ABI with
/// a concrete fn-pointer type (the install-site pattern in this crate).
fn ntdll_addr(name: &str) -> usize {
    let full = format!("{name}\0");
    // SAFETY: ntdll_export only walks the loaded ntdll export directory.
    let addr = unsafe { crate::hooks::ntdll_export(full.as_bytes()) }
        .unwrap_or_else(|| panic!("ntdll export {name} must resolve"));
    addr as usize
}

/// Auto-close an NT handle at scope end (best-effort; ntdll is always
/// loaded in any Windows process).
struct NtHandle(HANDLE);
impl Drop for NtHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: self.0 is either null (skipped) or a handle some
            // NtOpen/NtCreate call in this test produced.
            unsafe {
                // SAFETY: the address is ntdll!NtClose transmuted to its
                // documented ABI; self.0 is a live handle or null (skipped).
                let close: unsafe extern "system" fn(HANDLE) -> NTSTATUS =
                    std::mem::transmute(ntdll_addr("NtClose"));
                let _ = close(self.0);
            }
        }
    }
}

/// Unique probe leaf below the current user's `Software` key.
fn unique_probe_leaf() -> Vec<u16> {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(r"software\winrsbox_s13_probe_{pid}_{nanos}").encode_utf16().collect()
}

/// Restores the thread's previous test-mode override on drop (even when an
/// assert fires mid-test).
struct ModeOverrideGuard {
    prev: Option<policy::Mode>,
}
impl Drop for ModeOverrideGuard {
    fn drop(&mut self) {
        TEST_MODE_OVERRIDE.with(|c| c.set(self.prev.take()));
    }
}

/// Pin the thread's test-only policy mode for the duration of the returned
/// guard. Thread-local: the hook's own consult inside the test re-enters
/// harmlessly and no other test thread is affected.
fn force_policy_mode(m: policy::Mode) -> ModeOverrideGuard {
    TEST_MODE_OVERRIDE.with(|c| {
        let prev = c.replace(Some(m));
        assert!(prev.is_none(), "policy mode already forced on this thread");
        ModeOverrideGuard { prev }
    })
}

#[test]
fn cow_read_only_create_key_leaves_host_registry_untouched() {
    use access_masks::*;

    // -- plumbing: the same ntdll exports the hook path itself uses ------
    // SAFETY: ntdll_export walks the loaded export directory; each address
    //         is transmuted to its documented ABI (as install sites do).
    NT_QUERY_KEY.get_or_init(|| unsafe { std::mem::transmute(ntdll_addr("NtQueryKey")) });
    let nt_open: FnNtOpenKey = unsafe { std::mem::transmute(ntdll_addr("NtOpenKey")) };
    let nt_create: FnNtCreateKey = unsafe { std::mem::transmute(ntdll_addr("NtCreateKey")) };
    let nt_delete: FnNtDeleteKey = unsafe { std::mem::transmute(ntdll_addr("NtDeleteKey")) };
    let open_cu: FnRtlOpenCurrentUser = unsafe { std::mem::transmute(ntdll_addr("RtlOpenCurrentUser")) };

    // -- real current-user root handle (the HKCU equivalent) -------------
    let mut root_h: HANDLE = std::ptr::null_mut();
    // SAFETY: valid out-pointer; RtlOpenCurrentUser only writes the handle.
    let st = unsafe { open_cu(MAXIMUM_ALLOWED, &mut root_h) };
    assert!(st >= 0, "RtlOpenCurrentUser failed: 0x{:08X}", st as u32);
    let _root = NtHandle(root_h);

    // -- probe OBJECT_ATTRIBUTES: <current-user>\software\<unique> -------
    let mut leaf = unique_probe_leaf();
    let mut leaf_us = UNICODE_STRING {
        Length: (leaf.len() * 2) as u16,
        MaximumLength: (leaf.len() * 2 + 2) as u16,
        Buffer: leaf.as_mut_ptr(),
    };
    let mut oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root_h,
        ObjectName: &mut leaf_us,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };

    // -- clean slate: clear any stale probe, then verify absence ---------
    let mut probe: HANDLE = std::ptr::null_mut();
    let st_probe = unsafe { nt_open(&mut probe, KEY_READ | DELETE, &mut oa) };
    {
        let _guard = NtHandle(probe);
        if st_probe >= 0 {
            // SAFETY: probe is live and carries DELETE access.
            unsafe { let _ = nt_delete(probe); }
        }
    }
    let mut gone: HANDLE = std::ptr::null_mut();
    let st_gone = unsafe { nt_open(&mut gone, KEY_READ, &mut oa) };
    let _gone = NtHandle(gone);
    assert_eq!(
        st_gone, crate::hooks::STATUS_OBJECT_NAME_NOT_FOUND,
        "probe must not exist before the test (cleanup failed): 0x{:08X}",
        st_gone as u32,
    );

    // -- the fix under test: handler end-to-end under forced Cow ---------
    let _mode = force_policy_mode(policy::Mode::Cow);
    let mut key: HANDLE = 0xAAAA_BBBB as HANDLE; // sentinel
    let mut disp: u32 = 0xDEAD_BEEF;
    // SAFETY: out-handle/out-disposition are valid locals; oa points at
    //         the live probe attributes; this runs the exact logic the
    //         detour dispatcher would run.
    let status = unsafe {
        hook_nt_create_key(
            &mut key, KEY_READ, &mut oa, 0, std::ptr::null_mut(), 0, &mut disp,
        )
    };
    // Open-existing-only: a missing key must fail, never be created.
    assert_eq!(
        status, crate::hooks::STATUS_OBJECT_NAME_NOT_FOUND,
        "Cow + KEY_READ on a missing key must fail open-only, got 0x{:08X}",
        status as u32,
    );

    // The host hive must still not have the key — the S13 discriminator.
    // Reverting the fix routes Proceed → real NtCreateKey → this open
    // SUCCEEDS and the assert fails.
    let mut after: HANDLE = std::ptr::null_mut();
    let st_after = unsafe { nt_open(&mut after, KEY_READ, &mut oa) };
    let _after = NtHandle(after);
    assert_eq!(
        st_after, crate::hooks::STATUS_OBJECT_NAME_NOT_FOUND,
        "S13 REGRESSION: Cow + KEY_READ created a real host key",
    );

    // -- control arm: a real NtCreateKey(KEY_READ) DOES create it --------
    // Proves the detector above works and pins the exact mechanism the
    // finding describes (create-or-open ignores the read-only mask).
    let mut made: HANDLE = std::ptr::null_mut();
    let mut made_disp: u32 = 0;
    // SAFETY: valid out-params; oa/leaf live through the call.
    let st_make = unsafe {
        nt_create(&mut made, KEY_READ, &mut oa, 0, std::ptr::null_mut(), 0, &mut made_disp)
    };
    assert!(
        st_make >= 0,
        "control: real NtCreateKey(KEY_READ) must create the probe: 0x{:08X}",
        st_make as u32,
    );
    assert_eq!(made_disp, REG_CREATED_NEW_KEY, "control: expected a fresh key");
    let _made = NtHandle(made);
    let mut seen: HANDLE = std::ptr::null_mut();
    let st_seen = unsafe { nt_open(&mut seen, KEY_READ, &mut oa) };
    let _seen = NtHandle(seen);
    assert!(st_seen >= 0, "control: probe must be openable after real create");

    // -- cleanup: delete the created probe -------------------------------
    let mut dl: HANDLE = std::ptr::null_mut();
    let st_del = unsafe { nt_open(&mut dl, DELETE, &mut oa) };
    {
        let _dl = NtHandle(dl);
        if st_del >= 0 {
            // SAFETY: dl carries DELETE access.
            unsafe { let _ = nt_delete(dl); }
        }
    }
}

// ── install_best_effort failure posture (S10) ────────────────────────
//
// reg is a REQUIRED category: an ntdll export that EXISTS but whose detour
// init or enable fails means active ntdll interference (AV/EDR
// tampering/unhooking), so the macro must propagate Err out of install()
// — install_hooks() → DllMain FALSE → launcher kills the child. Only a
// genuinely absent export soft-skips via buffer_install_error (e.g.
// NtUnloadKey2 on Win7). The posture is not reachable at runtime under
// `cargo test` (no live detour failures), so it is pinned textually,
// following the structural-pin precedent.

/// Source of the `install_best_effort!` macro in mod.rs. tests.rs is
/// excluded from `module_source`, so this cannot match itself.
fn install_best_effort_macro_body() -> String {
    let src = crate::hooks::module_source("reg_hooks");
    let start = src
        .find("macro_rules! install_best_effort")
        .expect("install_best_effort macro must exist in reg_hooks");
    let rest = &src[start..];
    let end = rest.find("}};").expect("macro must be closed by }};");
    rest[..end + "}};".len()].to_string()
}

#[test]
fn install_best_effort_fails_closed_on_detour_failures() {
    let body = install_best_effort_macro_body();
    let err_arms = body.matches("return Err(").count();
    assert_eq!(
        err_arms, 2,
        "detour init AND detour enable failures must both propagate Err \
         (REQUIRED category, fail closed); found {err_arms} `return Err(`",
    );
    let buffered = body.matches("buffer_install_error").count();
    assert_eq!(
        buffered, 1,
        "ONLY a missing ntdll export may soft-skip via buffer_install_error; \
         found {buffered} occurrences",
    );
}

/// Regression (codex UnknownIssuer): crypt32 retries a denied system-store
/// open with MAXIMUM_ALLOWED; under Cow/Deny it must become a read-only
/// open-existing, not a deny. Explicit write bits still deny.
#[test]
fn maximum_allowed_under_cow_becomes_read_open() {
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    const KEY_READ: u32 = 0x0002_0019;
    for mode in [policy::Mode::Cow, policy::Mode::Deny] {
        let eff = nt_create_key_effective_access(MAXIMUM_ALLOWED, &mode);
        assert_eq!(eff, KEY_READ);
        assert!(matches!(nt_create_key_action(eff, mode.clone()), CreateKeyAction::OpenExistingOnly));
    }
    // crypt32's HKCU Root open (0x3001f): Cow → read-only open-existing.
    let eff = nt_create_key_effective_access(0x0003_001f, &policy::Mode::Cow);
    assert!(!nt_create_key_is_write_access(eff));
    assert!(matches!(nt_create_key_action(eff, policy::Mode::Cow), CreateKeyAction::OpenExistingOnly));
    // Deny prefixes keep refusing explicit write masks.
    let eff = nt_create_key_effective_access(0x0003_001f, &policy::Mode::Deny);
    assert!(matches!(nt_create_key_action(eff, policy::Mode::Deny), CreateKeyAction::Deny));
    // Unrestricted prefixes keep the caller's mask verbatim.
    assert_eq!(
        nt_create_key_effective_access(MAXIMUM_ALLOWED, &policy::Mode::Passthrough),
        MAXIMUM_ALLOWED
    );
}
