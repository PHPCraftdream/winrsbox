use super::c_void;
use super::MAX_TARGET_CHARS;

// ---------------------------------------------------------------------------
// Wide-string decoder + inspection verdict.
//
// Reads up to `MAX_TARGET_CHARS` UTF-16 code units from a null-terminated
// LPCWSTR and reports what could be fully INSPECTED as an `InspectedStr`:
// `Absent` for null pointers / unreadable memory / empty strings, `Value`
// when the NUL terminator was found within the cap (the whole string is
// decoded lossily to a Rust `String`), and `Unterminated` when the cap was
// reached without a terminator — the buffer may continue past our window,
// so it must NOT be silently decoded from the truncated 4096-unit view
// (the old behavior was evadable by pushing the payload past unit
// `MAX_TARGET_CHARS`).
//
// # SAFETY
// `p` originates from the (possibly hostile) target process and is therefore
// NOT trusted to be valid: it may be null, unmapped, or point at a buffer that
// is not null-terminated within the inspected range. This function never
// assumes validity — it null-checks, probes readability via `VirtualQuery`
// before any dereference, and bounds the terminator scan at `MAX_TARGET_CHARS`.
// A wild/unmapped pointer yields `Absent` (the caller treats it as an absent
// string). Note: `VirtualQuery` narrows but cannot fully close the TOCTOU
// window (the target could unmap the page after the probe); this is
// best-effort defense-in-depth, and a hostile process can always crash its
// own hook.
// ---------------------------------------------------------------------------

/// Inspection verdict for one attacker-supplied wide-string argument (see
/// the `read_lpcwstr` SAFETY notes above).
#[derive(Debug)]
pub(super) enum InspectedStr {
    /// Null pointer, unreadable memory, or an empty (zero-length) string:
    /// there is nothing to inspect and nothing to hide either; the original
    /// API surfaces its own error for such arguments. Same semantics the
    /// old `Option::None` return had.
    Absent,
    /// The string was fully decoded; its NUL terminator was found within
    /// `MAX_TARGET_CHARS`, so every code unit has been inspected.
    Value(String),
    /// No NUL terminator within `MAX_TARGET_CHARS`: the string may extend
    /// past our inspection window, so it cannot be fully inspected and must
    /// fail closed (see `uninspected_deny_reason`).
    Unterminated,
}

impl InspectedStr {
    /// The decoded text, or `""` when the argument is absent/unterminated.
    /// For logging and classifier input only — the fail-closed policy must
    /// match on the enum variants, never on this flattened view (which
    /// would silently turn an uninspected argument into an empty one).
    pub(super) fn as_deref(&self) -> &str {
        match self {
            InspectedStr::Value(s) => s,
            InspectedStr::Absent | InspectedStr::Unterminated => "",
        }
    }
}

pub(super) unsafe fn read_lpcwstr(p: *const u16) -> InspectedStr {
    if p.is_null() {
        return InspectedStr::Absent;
    }
    // Cheap readability pre-check: a hostile target can hand us a wild pointer.
    // Mirror the `VirtualQuery` probe used in memory_guard — confirm the first
    // code unit lives in a committed, non-NOACCESS, non-GUARD page before we
    // dereference. This avoids page-faulting on an obviously-bad pointer while
    // keeping the bounded scan below as the length guard.
    if !is_ptr_readable(p as *const c_void) {
        return InspectedStr::Absent;
    }
    // Locate the null terminator with a bounded scan.
    let mut len = 0usize;
    while len < MAX_TARGET_CHARS {
        // SAFETY: `p` is non-null (checked above) and its first page passed the
        // `VirtualQuery` readability probe. The target is untrusted, so this is
        // best-effort: the scan is capped at `MAX_TARGET_CHARS` and we bail out
        // conservatively (reporting the string as `Unterminated` so policy can
        // refuse it) if no terminator is found within the cap.
        if *p.add(len) == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        return InspectedStr::Absent;
    }
    if len == MAX_TARGET_CHARS {
        // No NUL within the cap: the string may continue past our window.
        // Decoding the truncated window here (the old behavior) would let a
        // payload beyond unit `MAX_TARGET_CHARS` evade every downstream
        // classifier, so report the truncation and let policy refuse.
        return InspectedStr::Unterminated;
    }
    // SAFETY: `len` < MAX_TARGET_CHARS and each of the first `len` code units
    // was just dereferenced (non-zero) during the scan above starting from a
    // pointer whose first page passed the readability probe.
    let slice = std::slice::from_raw_parts(p, len);
    InspectedStr::Value(String::from_utf16_lossy(slice))
}

/// ANSI twin of `read_lpcwstr` — same inspection verdicts, same fail-closed
/// contract:
///   * null / unreadable / empty -> `Absent`
///   * no NUL byte within `MAX_TARGET_CHARS` -> `Unterminated` (fail closed)
///   * otherwise the scanned bytes are converted with
///     `MultiByteToWideChar(CP_ACP, dwFlags=0)` — the same code page and
///     best-fit mapping shell32 itself applies when ShellExecuteA internally
///     dispatches to the W entry — so the classifiers judge exactly the
///     string the original API would act on (a best-fit-mapped ASCII scheme
///     like a fullwidth `runas:` cannot slip past the denylist the way it
///     would slip past a raw-byte scan).
///   * a conversion failure (return <= 0) means we could not fully inspect
///     what the caller asked us to execute -> `Unterminated` (fail closed).
///
/// # SAFETY
/// Same contract as `read_lpcwstr`: `p` is attacker-supplied and never
/// trusted; null-checked, probed with `VirtualQuery`, scan bounded at
/// `MAX_TARGET_CHARS` bytes.
pub(super) unsafe fn read_lpcstr(p: *const u8) -> InspectedStr {
    if p.is_null() {
        return InspectedStr::Absent;
    }
    if !is_ptr_readable(p as *const c_void) {
        return InspectedStr::Absent;
    }
    let mut len = 0usize;
    while len < MAX_TARGET_CHARS {
        // SAFETY: `p` passed the readability probe; the byte scan is bounded
        // at MAX_TARGET_CHARS and bails out (Unterminated) past the cap.
        if *p.add(len) == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        return InspectedStr::Absent;
    }
    if len == MAX_TARGET_CHARS {
        return InspectedStr::Unterminated;
    }
    // Worst case one UTF-16 unit per ANSI byte (SBCS); DBCS pairs only shrink.
    let mut wide: Vec<u16> = Vec::with_capacity(len + 1);
    let converted = winapi::um::stringapiset::MultiByteToWideChar(
        winapi::um::winnls::CP_ACP,
        0, // best-fit: matches shell32's own internal A->W conversion
        p as *const i8, // LPCSTR
        len as i32,
        wide.as_mut_ptr(),
        (len + 1) as i32,
    );
    if converted <= 0 {
        return InspectedStr::Unterminated;
    }
    // SAFETY: MultiByteToWideChar wrote exactly `converted` u16s into wide's
    // buffer; converted <= cchWideChar = len + 1 = wide's capacity.
    wide.set_len(converted as usize);
    InspectedStr::Value(String::from_utf16_lossy(&wide))
}

/// Best-effort readability probe for an attacker-supplied pointer. Returns
/// `true` only when `VirtualQuery` reports the address lives in a committed
/// page that is neither `PAGE_NOACCESS` nor a `PAGE_GUARD` page (a guard-page
/// touch would also fault). `VirtualQuery` is safe to call on any address and
/// returns 0 on failure. This narrows — but cannot fully eliminate — the chance
/// of faulting on a wild pointer from a hostile target (a TOCTOU unmap after
/// the probe is still possible); it is defense-in-depth, not a guarantee.
fn is_ptr_readable(addr: *const c_void) -> bool {
    if addr.is_null() {
        return false;
    }
    // PAGE_NOACCESS (0x01) and PAGE_GUARD (0x100) both make a read fault.
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_GUARD: u32 = 0x100;
    // SAFETY: VirtualQuery accepts any address and writes only into our
    // stack-local MEMORY_BASIC_INFORMATION; it returns 0 on failure.
    unsafe {
        let mut mbi: winapi::um::winnt::MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let ret = winapi::um::memoryapi::VirtualQuery(
            addr,
            &mut mbi,
            std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
        );
        if ret == 0 {
            return false;
        }
        mbi.State == winapi::um::winnt::MEM_COMMIT
            && (mbi.Protect & PAGE_NOACCESS) == 0
            && (mbi.Protect & PAGE_GUARD) == 0
    }
}

/// Policy for arguments the hook could not fully inspect: an argument that
/// is `Unterminated` (no NUL within `MAX_TARGET_CHARS`) must refuse the
/// whole call — fail closed. A partially scanned string is fail-open by
/// construction (whatever was not read was attacker-chosen), so the call is
/// denied with a distinguishing tag instead of being handed to the original
/// API with truncated input. This mirrors the existing "a malformed struct
/// must not get a free pass" precedent of the ExW `cbSize` guard.
///
/// Checked in `file`, `params`, `verb` order so the log identifies the
/// first argument that could not be fully inspected.
pub(super) fn uninspected_deny_reason(
    verb: &InspectedStr,
    file: &InspectedStr,
    params: &InspectedStr,
) -> Option<&'static str> {
    if matches!(file, InspectedStr::Unterminated) {
        Some("uninspected_file")
    } else if matches!(params, InspectedStr::Unterminated) {
        Some("uninspected_params")
    } else if matches!(verb, InspectedStr::Unterminated) {
        Some("uninspected_verb")
    } else {
        None
    }
}
