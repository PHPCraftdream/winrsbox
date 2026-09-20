// Shell guard — blocks `ShellExecuteW` / `ShellExecuteExW` calls whose target
// (`lpFile`) is a system-level URI / app-activation scheme that would spawn a
// process under a DIFFERENT parent (DcomLaunch / sihost.exe / Explorer.exe).
// Such processes escape our injection because:
//
//   * `proc_guard` only catches `NtCreateUserProcess` in the calling process —
//     the child is created by another service entirely.
//   * `inject_guard` only sees memory/thread ops inside the current process.
//
// Concrete escape primitives this module closes:
//
//   * `ms-windows-store://...`, `ms-settings:...`, and the rest of the `ms-*:`
//     URI family handled by AppX / sihost / SystemSettings.
//   * `shell:AppsFolder\<AUMID>` — direct AppX activation via Explorer.
//   * `runas:` — UAC elevation prompt host (via the URI scheme, and via the
//     `runas` `lpVerb` — both are deny-classified).
//
// Web URIs (`http:`, `https:`) are intentionally NOT blocked: the launcher's
// WFP network policy already constrains browser traffic, and the default
// browser runs under the same sandbox group, so opening it doesn't escape.
//
// Hook targets: shell32.dll!ShellExecuteW, shell32.dll!ShellExecuteExW.

use std::sync::OnceLock;

use detour2::GenericDetour;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{BOOL, FALSE, HINSTANCE};
use winapi::shared::windef::HWND;

use crate::anti_rec;
use crate::hooks::{ipc_log, is_trace};

// ---------------------------------------------------------------------------
// Danger prefix list (case-insensitive, ASCII-only).
//
// Every entry MUST be stored in lowercase — `is_shell_target_denied` lowercases
// each character of the incoming target on the fly and compares byte-for-byte
// against these entries. A non-lowercase entry would silently never match.
// ---------------------------------------------------------------------------

const SHELL_DENY_PREFIXES: &[&str] = &[
    // Microsoft Store, Settings, system-level URIs handled by sihost / AppX.
    "ms-windows-store:",
    "ms-settings:",
    "ms-search:",
    "ms-availablenetworks:",
    "ms-actioncenter:",
    "ms-cortana:",
    "ms-people:",
    "ms-clock:",
    "ms-photos:",
    "ms-calculator:",
    "ms-officeapp:",
    "ms-clipboard:",
    "ms-officeinsight:",
    "ms-screenclip:",
    "ms-screensketch:",
    "ms-yourphone:",
    "ms-paint:",
    // Edge browser activation — spawned by sihost / AppX outside our injection.
    "microsoft-edge:",
    "microsoft-edge-holographic:",
    // Phone / SMS / mail / calendar / news handlers — all dispatched to the
    // shell-registered default app outside our process tree.
    "tel:",
    "sms:",
    "webcal:",
    "mailto:",
    "feed:",
    "news:",
    "nntp:",
    // Windows Search activation.
    "search-ms:",
    // Third-party AppX-style URI handlers (common LOLBin escape targets).
    "steam:",
    "epicgames:",
    "spotify:",
    "discord:",
    "slack:",
    "zoommtg:",
    "msteams:",
    // AppX activation via Explorer — `shell:AppsFolder\<AUMID>`.
    "shell:appsfolder\\",
    "shell:appsfolder/",
    // Run-as / elevation prompts.
    "runas:",
];

/// Maximum number of UTF-16 code units we will inspect from `lpFile`. The
/// danger prefixes are short (≤ 32 ASCII chars); 32 is plenty to distinguish
/// them, and capping avoids the rare case of a multi-MB string crashing us.
const PREFIX_INSPECT_CHARS: usize = 32;

/// Safety cap on `lpFile` length when scanning for the NUL terminator. Real
/// shell-execute targets are bounded by `MAX_PATH` or URI scheme limits; 4096
/// is generous and prevents a malicious caller from forcing an infinite loop.
const MAX_TARGET_CHARS: usize = 4096;

/// SE_ERR_ACCESSDENIED — documented Shell error code returned by Shell APIs
/// when a target is blocked by policy. `ShellExecuteW` returns this value cast
/// to `HINSTANCE`; `ShellExecuteExW` reports it via the `hInstApp` field.
const SE_ERR_ACCESSDENIED: usize = 5;

// ---------------------------------------------------------------------------
// Classifier (free function — unit-testable without FFI / detour state).
// ---------------------------------------------------------------------------

/// Returns `true` if `file` starts with any of `SHELL_DENY_PREFIXES`, using
/// ASCII case-insensitive comparison on the first `PREFIX_INSPECT_CHARS`
/// bytes. Allocates nothing — compares byte-by-byte.
///
/// Empty / extremely short strings always return `false` (the original API
/// will reject them on its own).
pub(crate) fn is_shell_target_denied(file: &str) -> bool {
    let bytes = file.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let scan = bytes.len().min(PREFIX_INSPECT_CHARS);
    for prefix in SHELL_DENY_PREFIXES {
        let p = prefix.as_bytes();
        if p.len() > scan {
            continue;
        }
        let mut matches = true;
        for i in 0..p.len() {
            // `p` is already lowercase by construction; lowercase the input
            // byte to obtain a case-insensitive match without allocating.
            if bytes[i].to_ascii_lowercase() != p[i] {
                matches = false;
                break;
            }
        }
        if matches {
            return true;
        }
    }
    false
}

/// Number of leading characters of `lpFile` inspected when deciding whether a
/// target is a "Unicode scheme attempt". A URI scheme per RFC 3986 is short and
/// ASCII; 64 chars comfortably covers any legitimate scheme plus a margin while
/// bounding the scan.
const UNICODE_SCHEME_INSPECT_CHARS: usize = 64;

/// Returns `true` when `file` looks like a URI scheme attempt whose scheme
/// portion contains a non-ASCII character.
///
/// Motivation (M6): the denylist (`is_shell_target_denied`) lowercases ASCII
/// per byte. An attacker can pass a scheme containing a non-ASCII homoglyph or
/// case-fold that Explorer's URI canonicalizer folds DOWN to an ASCII scheme
/// (e.g. `R\u{1E9E}NAS:notepad.exe`, where U+1E9E LATIN CAPITAL SHARP S may
/// fold toward `ss`/`s` and reconstruct `runas:`), while our ASCII-only
/// lowercasing leaves the non-ASCII byte untouched so the prefix never matches.
///
/// An AI-agent sandbox never legitimately passes a non-ASCII URI scheme — the
/// scheme portion of any RFC-3986 URI is ASCII. So a scheme-like string with a
/// non-ASCII scheme is treated as an attack and denied.
///
/// We must NOT blanket-reject non-ASCII in `lpFile`: `ShellExecute` `lpFile`
/// can be a plain filesystem path with a Unicode name (e.g. `документ.txt` or
/// `C:\Users\документ.txt`). The discriminator is the position of the first
/// `:`:
///
/// 1. Inspect only the first `UNICODE_SCHEME_INSPECT_CHARS` chars.
/// 2. Find the first `:`. None → not a scheme (a plain path), return `false`.
/// 3. If that `:` is at char index 1 and char 0 is ASCII alphabetic, it's a
///    drive letter (`C:\...`), not a scheme → return `false` (a Unicode
///    filename after the drive letter is fine).
/// 4. If the substring BEFORE the first `:` contains any non-ASCII char, the
///    scheme is non-ASCII → return `true` (suspicious — deny).
/// 5. Otherwise the scheme is ASCII; the normal `SHELL_DENY_PREFIXES` check
///    handles it → return `false`.
pub(crate) fn is_suspicious_unicode_scheme(file: &str) -> bool {
    // Step 1: bound inspection to the first N chars (by char, not byte, so the
    // index math below operates on whole code points).
    let mut prefix_end = file.len();
    for (count, (idx, _)) in file.char_indices().enumerate() {
        if count == UNICODE_SCHEME_INSPECT_CHARS {
            prefix_end = idx;
            break;
        }
    }
    let head = &file[..prefix_end];

    // Step 2: locate the first ':' within the inspected head.
    let Some(colon) = head.find(':') else {
        // No early colon → not a scheme (plain path). Unicode filename allowed.
        return false;
    };

    // Step 3: drive-letter case `X:` — colon at byte index 1, single ASCII
    // alphabetic char before it. (For an ASCII drive letter the char index and
    // byte index coincide, so `colon == 1` is exact here.)
    let before = &head[..colon];
    if colon == 1 {
        let c0 = before.as_bytes()[0];
        if c0.is_ascii_alphabetic() {
            return false;
        }
    }

    // Step 4: a non-ASCII char anywhere in the scheme portion is the attack.
    if !before.is_ascii() {
        return true;
    }

    // Step 5: ASCII scheme — leave it to the denylist check.
    false
}

/// Scans `params` for any embedded denied URI. ShellExecute callers can pass
/// the dangerous scheme via `lpParameters` instead of `lpFile` — e.g.
/// `lpFile = "cmd.exe", lpParameters = "/c start ms-windows-store://..."`.
/// The ENTIRE parameter string is lowercased and scanned for any denylist
/// entry occurring as a substring. Returns `true` on the first match.
///
/// Substring (not prefix) scan is intentional because the dangerous scheme
/// may appear after a `start`, `/c`, redirection metacharacters, or quoting.
///
/// No downstream length cap is added here on purpose: the only genuine bound
/// on argument length lives upstream in `read_lpcwstr` (at most
/// `MAX_TARGET_CHARS` = 4096 UTF-16 code units ≈ ≤ 12 KB of UTF-8), so the
/// full string we can ever receive is fully inspected. The previous
/// 1024-byte scan cutoff was evadable — a payload pushed past byte 1024
/// (e.g. behind whitespace padding) was never seen. A partial scan is
/// fail-open by construction: whatever we do not look at, the attacker
/// controls, so we look at all of it instead.
pub(crate) fn is_shell_params_denied(params: &str) -> bool {
    if params.is_empty() {
        return false;
    }
    let scan = params.to_ascii_lowercase();
    SHELL_DENY_PREFIXES.iter().any(|p| scan.contains(p))
}

/// ASCII case-insensitive equality over raw bytes, without allocating. `b`
/// must already be lowercase by construction (every verb literal below is).
fn eq_ascii_ci(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b.iter()).all(|(x, y)| x.to_ascii_lowercase() == *y)
}

/// Classifies `lpVerb` against an explicit allowlist and returns the deny
/// reason, or `None` when the verb is allowed. The comparison is an EXACT,
/// ASCII case-insensitive match — no prefix matching, no substring search
/// — so a verb that merely shares characters with an allowed entry can
/// never inherit its verdict.
///
/// Decisions (fail-closed allowlist):
///
/// * `""` (the empty verb — which is also what a NULL `lpVerb` decodes to
///   via `InspectedStr::as_deref`) → `None`. The empty verb asks the shell
///   to use its default verb and is the sandbox's normal launch path; the
///   existing target/params checks still apply.
/// * `open` / `edit` / `print` → `None` (allowed). Ordinary file-association
///   dispatch inside the normal execution path: no elevation and no
///   different-parent spawn primitive beyond what `open` already does; the
///   target/params checks still apply.
/// * `runas` → `Some("verb_escalation")`. Triggers the UAC elevation prompt
///   — the same decision class as the spawn denylist, which already
///   denylists the `runas:` URI scheme for exactly this reason.
/// * `explore` / `find` → `Some("verb_explorer")`. Both exist solely to
///   launch Explorer-hosted shell UI — the module header lists Explorer as
///   a different-parent escape surface, and there is no legitimate
///   headless-agent use.
/// * anything else → `Some("verb_unknown")`. Fail-closed allowlist: a
///   future elevation-class verb, or a homoglyph lookalike (e.g. Cyrillic
///   `а` U+0430 in "runаs"), can never silently pass.
pub(crate) fn shell_verb_deny_reason(verb: &str) -> Option<&'static str> {
    let v = verb.as_bytes();
    if v.is_empty() {
        return None;
    }
    if eq_ascii_ci(v, b"open") || eq_ascii_ci(v, b"edit") || eq_ascii_ci(v, b"print") {
        return None;
    }
    if eq_ascii_ci(v, b"runas") {
        return Some("verb_escalation");
    }
    if eq_ascii_ci(v, b"explore") || eq_ascii_ci(v, b"find") {
        return Some("verb_explorer");
    }
    Some("verb_unknown")
}

/// Combined check used by both ShellExecute hook entry points. Returns a
/// short tag identifying which input matched so the violation log can
/// distinguish `reason=verb_escalation`, `reason=verb_explorer`,
/// `reason=verb_unknown`, `reason=file`, `reason=unicode_scheme`, and
/// `reason=params`. Returns `None` when no input matches.
///
/// The verb is checked FIRST: an escalation- or Explorer-class verb denies
/// the call no matter how benign the target looks. An empty/allowed verb
/// falls through, so the pre-existing file / unicode_scheme / params
/// precedence below is unchanged.
///
/// `unicode_scheme` (M6) is checked on `file` before the ASCII denylist so a
/// homoglyph/fold scheme that would slip past the byte-wise denylist is still
/// denied. See `is_suspicious_unicode_scheme`.
pub(crate) fn shell_deny_reason(verb: &str, file: &str, params: &str) -> Option<&'static str> {
    // An allowed verb (None) must FALL THROUGH to the file / params checks;
    // only a denied verb short-circuits with its own reason.
    if let Some(reason) = shell_verb_deny_reason(verb) {
        return Some(reason);
    }
    if is_shell_target_denied(file) {
        Some("file")
    } else if is_suspicious_unicode_scheme(file) {
        Some("unicode_scheme")
    } else if is_shell_params_denied(params) {
        Some("params")
    } else {
        None
    }
}

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
enum InspectedStr {
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
    fn as_deref(&self) -> &str {
        match self {
            InspectedStr::Value(s) => s,
            InspectedStr::Absent | InspectedStr::Unterminated => "",
        }
    }
}

unsafe fn read_lpcwstr(p: *const u16) -> InspectedStr {
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
unsafe fn read_lpcstr(p: *const u8) -> InspectedStr {
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
fn uninspected_deny_reason(
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

// ---------------------------------------------------------------------------
// Win32 SHELLEXECUTEINFOW layout.
//
// We only need fields up to `hInstApp` because:
//   * `lpFile` is the target we inspect (offset 0x18 on x64).
//   * `hInstApp` is where we report the access-denied error code on deny.
//
// `winapi 0.3` does not expose `SHELLEXECUTEINFOW` with the
// `winuser`/`shellapi` features enabled in our Cargo.toml. Rather than
// expanding the dependency feature surface (which can ripple into unrelated
// build issues), we declare a minimal `#[repr(C)]` mirror covering only the
// prefix of the struct that we read or write. Reading additional trailing
// fields would be UB if the caller passed a smaller `cbSize`, but we don't.
// ---------------------------------------------------------------------------

#[repr(C)]
#[allow(non_snake_case)]
struct SHELLEXECUTEINFOW {
    cbSize: u32,
    fMask: u32,
    hwnd: HWND,
    lpVerb: *const u16,
    lpFile: *const u16,
    lpParameters: *const u16,
    lpDirectory: *const u16,
    nShow: i32,
    hInstApp: HINSTANCE,
    // Trailing fields (lpIDList, lpClass, hkeyClass, dwHotKey, hMonitor/hIcon, hProcess)
    // intentionally omitted: we never read them and Rust permits a shorter
    // prefix-mirror over a pointed-to C struct as long as we don't read past
    // the declared end.
}

/// ANSI twin of the `SHELLEXECUTEINFOW` prefix-mirror — same field layout,
/// string fields are LPCSTR. See the W struct notes above for why only the
/// inspected prefix is declared.
#[repr(C)]
#[allow(non_snake_case)]
struct SHELLEXECUTEINFOA {
    cbSize: u32,
    fMask: u32,
    hwnd: HWND,
    lpVerb: *const u8,
    lpFile: *const u8,
    lpParameters: *const u8,
    lpDirectory: *const u8,
    nShow: i32,
    hInstApp: HINSTANCE,
}

// ---------------------------------------------------------------------------
// Function types.
// ---------------------------------------------------------------------------

// HINSTANCE ShellExecuteW(
//   HWND    hwnd,
//   LPCWSTR lpOperation,
//   LPCWSTR lpFile,
//   LPCWSTR lpParameters,
//   LPCWSTR lpDirectory,
//   INT     nShowCmd
// );
type FnShellExecuteW = unsafe extern "system" fn(
    HWND,          // hwnd
    *const u16,    // lpOperation
    *const u16,    // lpFile
    *const u16,    // lpParameters
    *const u16,    // lpDirectory
    i32,           // nShowCmd
) -> HINSTANCE;

// BOOL ShellExecuteExW(SHELLEXECUTEINFOW *pExecInfo);
type FnShellExecuteExW = unsafe extern "system" fn(
    *mut SHELLEXECUTEINFOW,
) -> BOOL;

// ---------------------------------------------------------------------------
// Detour storage.
// ---------------------------------------------------------------------------

static HOOK_SHELL_EXECUTE_W: OnceLock<GenericDetour<FnShellExecuteW>> = OnceLock::new();
static HOOK_SHELL_EXECUTE_EX_W: OnceLock<GenericDetour<FnShellExecuteExW>> = OnceLock::new();

// ANSI twins (audit 2026-09-19 High, "sibling API"): ShellExecuteA /
// ShellExecuteExA share the exact shell32 dispatch path of the W variants
// after an internal CP_ACP -> UTF-16 conversion, so an unhooked A entry is a
// full bypass of every W-side check. The A hooks decode with the SAME code
// page and best-fit semantics the original uses (MultiByteToWideChar with
// dwFlags=0), then run the identical classifier chain.
//
// HINSTANCE ShellExecuteA(
//   HWND    hwnd,
//   LPCSTR  lpOperation,
//   LPCSTR  lpFile,
//   LPCSTR  lpParameters,
//   LPCSTR  lpDirectory,
//   INT     nShowCmd
// );
type FnShellExecuteA = unsafe extern "system" fn(
    HWND,          // hwnd
    *const u8,     // lpOperation (LPCSTR)
    *const u8,     // lpFile
    *const u8,     // lpParameters
    *const u8,     // lpDirectory
    i32,           // nShowCmd
) -> HINSTANCE;

// BOOL ShellExecuteExA(SHELLEXECUTEINFOA *pExecInfo);
type FnShellExecuteExA = unsafe extern "system" fn(
    *mut SHELLEXECUTEINFOA,
) -> BOOL;

static HOOK_SHELL_EXECUTE_A: OnceLock<GenericDetour<FnShellExecuteA>> = OnceLock::new();
static HOOK_SHELL_EXECUTE_EX_A: OnceLock<GenericDetour<FnShellExecuteExA>> = OnceLock::new();

// ---------------------------------------------------------------------------
// Hook implementations.
// ---------------------------------------------------------------------------

// SAFETY: Called by detour2 dispatcher with shell32!ShellExecuteW ABI.
unsafe extern "system" fn hook_shell_execute_w(
    hwnd: HWND,
    lp_operation: *const u16,
    lp_file: *const u16,
    lp_parameters: *const u16,
    lp_directory: *const u16,
    n_show_cmd: i32,
) -> HINSTANCE {
    let call_original = || {
// Detour-absent: unwrap-abort kept on purpose — HINSTANCE family; fail-closed would be an SE_ERR_* failure code (ShellExecute: <= 32 means failure), a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnShellExecuteW ABI.
        HOOK_SHELL_EXECUTE_W.get().unwrap().call(
            hwnd, lp_operation, lp_file, lp_parameters, lp_directory, n_show_cmd,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // Read all three attacker-supplied strings as `InspectedStr` — including
    // `lp_operation` (the verb), which the old hook never read at all, so a
    // `runas` verb bypassed every check. An argument with no NUL within
    // `MAX_TARGET_CHARS` comes back as `Unterminated` instead of a silently
    // truncated string.
    let verb = read_lpcwstr(lp_operation);
    let file = read_lpcwstr(lp_file);
    let params = read_lpcwstr(lp_parameters);

    // Fail closed FIRST: an argument the hook could not fully inspect must
    // refuse the whole call — a truncated view would let anything past the
    // cutoff evade every classifier below. Only when all three arguments
    // are fully inspected are they flattened via `as_deref()` and handed
    // to the classifier chain.
    let deny_reason = match uninspected_deny_reason(&verb, &file, &params) {
        Some(reason) => Some(reason),
        None => shell_deny_reason(verb.as_deref(), file.as_deref(), params.as_deref()),
    };
    if let Some(reason) = deny_reason {
        if is_trace() {
            let (verb_str, file_str, params_str) =
                (verb.as_deref(), file.as_deref(), params.as_deref());
            crate::hooks::ipc_log_violation(ipc::Req::Log {
                pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                level: ipc::LogLevel::Warn,
                msg: format!(
                    "shell_execute_blocked reason={reason} verb={verb_str} file={file_str} params={params_str}"
                ),
            });
        }
        // ShellExecuteW returns HINSTANCE; values <= 32 indicate error.
        // 5 == SE_ERR_ACCESSDENIED.
        return SE_ERR_ACCESSDENIED as *mut c_void as HINSTANCE;
    }

    call_original()
}

// SAFETY: Called by detour2 dispatcher with shell32!ShellExecuteExW ABI.
unsafe extern "system" fn hook_shell_execute_ex_w(
    p_exec_info: *mut SHELLEXECUTEINFOW,
) -> BOOL {
    let call_original = || {
// Detour-absent: unwrap-abort kept on purpose — BOOL family; fail-closed would be FALSE, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnShellExecuteExW ABI.
        HOOK_SHELL_EXECUTE_EX_W.get().unwrap().call(p_exec_info)
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if !p_exec_info.is_null() {
        // Validate the caller-declared `cbSize` BEFORE we read past the
        // beginning of the struct or (on deny) write `hInstApp`. A caller that
        // passes a struct smaller than our mirror (e.g. an older/truncated
        // SHELLEXECUTEINFO) must not have `hInstApp` written into it — that
        // field sits near the end of the struct and writing it could clobber
        // memory past the caller's allocation.
        //
        // We compute the offset of `hInstApp` via `core::mem::offset_of!`
        // (stable since Rust 1.77) so this stays correct if the mirror layout
        // changes. A struct large enough to contain the whole `hInstApp` field
        // can be safely written; a smaller one is still DENIED (a malformed
        // struct must not get a free pass) but WITHOUT writing `hInstApp` — we
        // return FALSE only, which the caller can always observe.
        //
        // SAFETY: `p_exec_info` is non-null (checked above). Reading `cbSize`
        // (the first field, offset 0) is valid for any allocation a caller
        // could legitimately pass to ShellExecuteExW, which must contain at
        // least the `cbSize` field it is required to initialize.
        let cb_size = (*p_exec_info).cbSize as usize;
        const HINSTAPP_OFFSET: usize = core::mem::offset_of!(SHELLEXECUTEINFOW, hInstApp);
        // Bytes the caller must have allocated for a write of `hInstApp` to be
        // in-bounds: through the end of the field.
        let hinstapp_end = HINSTAPP_OFFSET + core::mem::size_of::<HINSTANCE>();
        // Bytes that must be present before we may read the prefix fields we
        // inspect. `lpParameters` is the last field we read, so its end is the
        // minimum struct size required for our reads to be in-bounds.
        const LPPARAMETERS_OFFSET: usize = core::mem::offset_of!(SHELLEXECUTEINFOW, lpParameters);
        let lpparameters_end = LPPARAMETERS_OFFSET + core::mem::size_of::<*const u16>();
        let cbsize_ok_for_full_struct = cb_size >= core::mem::size_of::<SHELLEXECUTEINFOW>();
        let cbsize_ok_for_hinstapp_write = cb_size >= hinstapp_end;

        // The target controls `cbSize`. If it declares a struct too small to
        // even contain the fields we inspect (`lpVerb`/`lpFile`/`lpParameters`),
        // reading those fields would touch memory past the caller's allocation. We
        // cannot inspect such a call, so fall through to the original — the
        // documented "can't inspect → call original" path. (We never deny on a
        // pointer we couldn't safely read; the real ShellExecuteExW will reject
        // a malformed `cbSize` itself.)
        if cb_size < lpparameters_end {
            return call_original();
        }

        // SAFETY: `p_exec_info` is non-null (checked above) and `cb_size` is at
        // least `lpparameters_end`, so the prefix fields up to and including
        // `lpParameters` lie within the caller-declared (and per the ABI
        // contract, initialized) allocation. We only read those prefix fields;
        // the denylist/Unicode/params decision itself never writes the struct.
        let info_ref = &*p_exec_info;
        // Reading `lpVerb` is safe under the EXISTING `cb_size >=
        // lpparameters_end` guard: `offset_of!(lpVerb)` < `offset_of!(lpParameters)`,
        // so `lpVerb` lies within the same caller-declared allocation that
        // guard already proves covers every field up to and including
        // `lpParameters`. The old hook never read it, so a `runas` verb
        // bypassed every check.
        let verb = read_lpcwstr(info_ref.lpVerb);
        let file = read_lpcwstr(info_ref.lpFile);
        let params = read_lpcwstr(info_ref.lpParameters);

        // Fail closed FIRST: an argument the hook could not fully inspect
        // (no NUL within `MAX_TARGET_CHARS`) must refuse the whole call —
        // a truncated view would let anything past the cutoff evade every
        // classifier. Only when all three arguments are fully inspected are
        // they flattened via `as_deref()` and handed to the classifier chain.
        let deny_reason = match uninspected_deny_reason(&verb, &file, &params) {
            Some(reason) => Some(reason),
            None => shell_deny_reason(verb.as_deref(), file.as_deref(), params.as_deref()),
        };
        if let Some(reason) = deny_reason {
            // Note when the struct is too small to hold a full SHELLEXECUTEINFOW
            // so the log records why we may have skipped the hInstApp write.
            let truncated = !cbsize_ok_for_full_struct;
            if is_trace() {
                let (verb_str, file_str, params_str) =
                    (verb.as_deref(), file.as_deref(), params.as_deref());
                crate::hooks::ipc_log_violation(ipc::Req::Log {
                    pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                    level: ipc::LogLevel::Warn,
                    msg: format!(
                        "shell_execute_ex_blocked reason={reason} cbSize={cb_size} truncated={truncated} verb={verb_str} file={file_str} params={params_str}"
                    ),
                });
            }
            if cbsize_ok_for_hinstapp_write {
                // Report SE_ERR_ACCESSDENIED via hInstApp per shellapi.h
                // contract and return FALSE.
                // SAFETY: p_exec_info is non-null and the caller declared a
                // `cbSize` (>= hinstapp_end) large enough to contain the whole
                // `hInstApp` field, so this write is in-bounds.
                (*p_exec_info).hInstApp = SE_ERR_ACCESSDENIED as *mut c_void as HINSTANCE;
            }
            // Deny regardless: a struct too small to hold `hInstApp` is still
            // refused (return FALSE) without the write.
            return FALSE;
        }
    }

    call_original()
}

/// Full deny decision for one ShellExecuteA / ShellExecuteExA call, from raw
/// ANSI pointers to the classifier-chain verdict. Identical to the W path:
/// read + inspect all three attacker strings via `read_lpcstr`, fail closed
/// on any uninspected argument, then run the shared `shell_deny_reason`
/// chain (verb allowlist -> file denylist -> unicode-scheme -> params scan).
/// Returns the reason tag, or `None` when the call may proceed.
///
/// Pure over its inputs (reads are bounded and probe-guarded); tests
/// fabricate ANSI buffers and drive exactly the decision the hooks apply —
/// no shell32 involvement.
///
/// # SAFETY
/// Each pointer must be null or readable memory (wild pointers are
/// probe-guarded and yield `Absent`, never a fault we propagate).
unsafe fn shell_execute_a_deny_reason(
    lp_operation: *const u8,
    lp_file: *const u8,
    lp_parameters: *const u8,
) -> Option<&'static str> {
    let verb = read_lpcstr(lp_operation);
    let file = read_lpcstr(lp_file);
    let params = read_lpcstr(lp_parameters);
    match uninspected_deny_reason(&verb, &file, &params) {
        Some(reason) => Some(reason),
        None => shell_deny_reason(verb.as_deref(), file.as_deref(), params.as_deref()),
    }
}

// SAFETY: Called by detour2 dispatcher with shell32!ShellExecuteA ABI.
unsafe extern "system" fn hook_shell_execute_a(
    hwnd: HWND,
    lp_operation: *const u8,
    lp_file: *const u8,
    lp_parameters: *const u8,
    lp_directory: *const u8,
    n_show_cmd: i32,
) -> HINSTANCE {
    let call_original = || {
// Detour-absent: unwrap-abort kept on purpose — HINSTANCE family; fail-closed would be an SE_ERR_* failure code (ShellExecute: <= 32 means failure), a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnShellExecuteA ABI.
        HOOK_SHELL_EXECUTE_A.get().unwrap().call(
            hwnd, lp_operation, lp_file, lp_parameters, lp_directory, n_show_cmd,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if let Some(reason) =
        shell_execute_a_deny_reason(lp_operation, lp_file, lp_parameters)
    {
        if is_trace() {
            crate::hooks::ipc_log_violation(ipc::Req::Log {
                pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                level: ipc::LogLevel::Warn,
                msg: format!("shell_execute_a_blocked reason={reason}"),
            });
        }
        // ShellExecuteA returns HINSTANCE; values <= 32 indicate error.
        // 5 == SE_ERR_ACCESSDENIED.
        return SE_ERR_ACCESSDENIED as *mut c_void as HINSTANCE;
    }

    call_original()
}

// SAFETY: Called by detour2 dispatcher with shell32!ShellExecuteExA ABI.
unsafe extern "system" fn hook_shell_execute_ex_a(
    p_exec_info: *mut SHELLEXECUTEINFOA,
) -> BOOL {
    let call_original = || {
// Detour-absent: unwrap-abort kept on purpose — BOOL family; fail-closed would be FALSE, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnShellExecuteExA ABI.
        HOOK_SHELL_EXECUTE_EX_A.get().unwrap().call(p_exec_info)
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if !p_exec_info.is_null() {
        // cbSize validation identical to the W hook: a struct too small to
        // contain the inspected prefix falls through to the original (the
        // real API rejects it), and hInstApp is only written when the
        // caller's declared size proves the field exists.
        // SAFETY: p_exec_info is non-null (checked above); reading cbSize
        // (offset 0) is valid for any allocation a caller could legitimately
        // pass, since cbSize is the field it is required to initialize.
        let cb_size = (*p_exec_info).cbSize as usize;
        const HINSTAPP_OFFSET_A: usize = core::mem::offset_of!(SHELLEXECUTEINFOA, hInstApp);
        let hinstapp_end = HINSTAPP_OFFSET_A + core::mem::size_of::<HINSTANCE>();
        const LPPARAMETERS_OFFSET_A: usize = core::mem::offset_of!(SHELLEXECUTEINFOA, lpParameters);
        let lpparameters_end = LPPARAMETERS_OFFSET_A + core::mem::size_of::<*const u8>();
        let cbsize_ok_for_full_struct = cb_size >= core::mem::size_of::<SHELLEXECUTEINFOA>();
        let cbsize_ok_for_hinstapp_write = cb_size >= hinstapp_end;

        if cb_size < lpparameters_end {
            return call_original();
        }

        // SAFETY: cb_size >= lpparameters_end proves the prefix fields up to
        // and including lpParameters lie within the caller's allocation.
        let info_ref = &*p_exec_info;
        let deny_reason = shell_execute_a_deny_reason(
            info_ref.lpVerb, info_ref.lpFile, info_ref.lpParameters,
        );
        if let Some(reason) = deny_reason {
            let truncated = !cbsize_ok_for_full_struct;
            if is_trace() {
                crate::hooks::ipc_log_violation(ipc::Req::Log {
                    pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                    level: ipc::LogLevel::Warn,
                    msg: format!(
                        "shell_execute_ex_a_blocked reason={reason} cbSize={cb_size} truncated={truncated}"
                    ),
                });
            }
            if cbsize_ok_for_hinstapp_write {
                // Report SE_ERR_ACCESSDENIED via hInstApp and return FALSE.
                // SAFETY: p_exec_info is non-null and the caller declared a
                // cbSize (>= hinstapp_end) covering the whole hInstApp field.
                (*p_exec_info).hInstApp = SE_ERR_ACCESSDENIED as *mut c_void as HINSTANCE;
            }
            // Denied regardless: a struct too small for hInstApp is refused
            // (FALSE) without the write.
            return FALSE;
        }
    }

    call_original()
}

// ---------------------------------------------------------------------------
// shell32.dll export resolver — mirrors `combase_export` in com_guard.rs.
// ---------------------------------------------------------------------------

/// # SAFETY
/// Must be called during install (DllMain context). `name` must be a
/// null-terminated ASCII byte string.
unsafe fn shell32_export(name: &[u8]) -> Option<*const c_void> {
    let module_w: Vec<u16> = "shell32.dll\0".encode_utf16().collect();
    // SAFETY: FFI call to LoadLibraryW with null-terminated wide string.
    let h = winapi::um::libloaderapi::LoadLibraryW(module_w.as_ptr());
    if h.is_null() {
        return None;
    }
    // SAFETY: FFI call to GetProcAddress with valid HMODULE and
    // null-terminated ASCII name.
    let addr = winapi::um::libloaderapi::GetProcAddress(h, name.as_ptr() as *const i8);
    if addr.is_null() { None } else { Some(addr as *const c_void) }
}

// ---------------------------------------------------------------------------
// Install / Uninstall.
// ---------------------------------------------------------------------------

/// # SAFETY
/// Must be called from `install_hooks()` in DllMain context with `anti_rec`
/// entered.
pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    // ShellExecuteW
    if let Some(addr) = shell32_export(b"ShellExecuteW\0") {
        // SAFETY: transmute of shell32 export address; ABI matches
        // FnShellExecuteW.
        let target: FnShellExecuteW = std::mem::transmute(addr);
        let hook_ptr: FnShellExecuteW = hook_shell_execute_w;
        let detour = GenericDetour::<FnShellExecuteW>::new(target, hook_ptr)
            .map_err(|e| format!("detour init ShellExecuteW: {:?}", e))?;
        HOOK_SHELL_EXECUTE_W.set(detour).ok();
        HOOK_SHELL_EXECUTE_W
            .get()
            .expect("set above")
            .enable()
            .map_err(|e| format!("detour enable ShellExecuteW: {:?}", e))?;
    } else {
        ipc_log(
            ipc::LogLevel::Warn,
            "shell_guard: shell32 export ShellExecuteW not found — skipping".into(),
        );
    }

    // ShellExecuteExW
    if let Some(addr) = shell32_export(b"ShellExecuteExW\0") {
        // SAFETY: transmute of shell32 export address; ABI matches
        // FnShellExecuteExW.
        let target: FnShellExecuteExW = std::mem::transmute(addr);
        let hook_ptr: FnShellExecuteExW = hook_shell_execute_ex_w;
        let detour = GenericDetour::<FnShellExecuteExW>::new(target, hook_ptr)
            .map_err(|e| format!("detour init ShellExecuteExW: {:?}", e))?;
        HOOK_SHELL_EXECUTE_EX_W.set(detour).ok();
        HOOK_SHELL_EXECUTE_EX_W
            .get()
            .expect("set above")
            .enable()
            .map_err(|e| format!("detour enable ShellExecuteExW: {:?}", e))?;
    } else {
        ipc_log(
            ipc::LogLevel::Warn,
            "shell_guard: shell32 export ShellExecuteExW not found — skipping".into(),
        );
    }

    // ShellExecuteA (audit High sibling closure)
    if let Some(addr) = shell32_export(b"ShellExecuteA\0") {
        // SAFETY: transmute of shell32 export address; ABI matches
        // FnShellExecuteA.
        let target: FnShellExecuteA = std::mem::transmute(addr);
        let hook_ptr: FnShellExecuteA = hook_shell_execute_a;
        let detour = GenericDetour::<FnShellExecuteA>::new(target, hook_ptr)
            .map_err(|e| format!("detour init ShellExecuteA: {:?}", e))?;
        HOOK_SHELL_EXECUTE_A.set(detour).ok();
        HOOK_SHELL_EXECUTE_A
            .get()
            .expect("set above")
            .enable()
            .map_err(|e| format!("detour enable ShellExecuteA: {:?}", e))?;
    } else {
        ipc_log(
            ipc::LogLevel::Warn,
            "shell_guard: shell32 export ShellExecuteA not found — skipping".into(),
        );
    }

    // ShellExecuteExA (audit High sibling closure)
    if let Some(addr) = shell32_export(b"ShellExecuteExA\0") {
        // SAFETY: transmute of shell32 export address; ABI matches
        // FnShellExecuteExA.
        let target: FnShellExecuteExA = std::mem::transmute(addr);
        let hook_ptr: FnShellExecuteExA = hook_shell_execute_ex_a;
        let detour = GenericDetour::<FnShellExecuteExA>::new(target, hook_ptr)
            .map_err(|e| format!("detour init ShellExecuteExA: {:?}", e))?;
        HOOK_SHELL_EXECUTE_EX_A.set(detour).ok();
        HOOK_SHELL_EXECUTE_EX_A
            .get()
            .expect("set above")
            .enable()
            .map_err(|e| format!("detour enable ShellExecuteExA: {:?}", e))?;
    } else {
        ipc_log(
            ipc::LogLevel::Warn,
            "shell_guard: shell32 export ShellExecuteExA not found — skipping".into(),
        );
    }

    if is_trace() {
        ipc_log(ipc::LogLevel::Trace, "shell_guard_installed".into());
    }
    Ok(())
}

/// # SAFETY
/// Must be called from DLL_PROCESS_DETACH only.
pub unsafe fn uninstall() {
    if let Some(h) = HOOK_SHELL_EXECUTE_W.get() {
        let _ = h.disable();
    }
    if let Some(h) = HOOK_SHELL_EXECUTE_EX_W.get() {
        let _ = h.disable();
    }
    if let Some(h) = HOOK_SHELL_EXECUTE_A.get() {
        let _ = h.disable();
    }
    if let Some(h) = HOOK_SHELL_EXECUTE_EX_A.get() {
        let _ = h.disable();
    }
}

/// Exports this module installs detours on. Kept in lockstep with install()
/// — the sibling-drift check in hooks.rs verifies every name here still
/// appears as an install literal in this file, and that guarded families
/// have no unhooked siblings.
pub(crate) const HOOKED_EXPORTS: &[&str] = &[
    "ShellExecuteW",
    "ShellExecuteExW",
    "ShellExecuteA",
    "ShellExecuteExA",
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ms_windows_store_uri_denied() {
        assert!(is_shell_target_denied(
            "ms-windows-store://app/0123"
        ));
    }

    #[test]
    fn ms_settings_uri_denied_case_insensitive() {
        assert!(is_shell_target_denied("MS-Settings:network"));
        assert!(is_shell_target_denied("ms-SETTINGS:privacy"));
        assert!(is_shell_target_denied("Ms-Settings:"));
    }

    #[test]
    fn shell_appsfolder_aumid_denied() {
        assert!(is_shell_target_denied(
            "shell:AppsFolder\\Microsoft.WindowsCalculator_8wekyb3d8bbwe!App"
        ));
        // Forward-slash variant — some callers normalize the separator.
        assert!(is_shell_target_denied(
            "shell:appsfolder/Microsoft.WindowsCalculator_8wekyb3d8bbwe!App"
        ));
        // Case-insensitive on the scheme/folder name.
        assert!(is_shell_target_denied(
            "SHELL:APPSFOLDER\\Microsoft.WindowsCalculator_8wekyb3d8bbwe!App"
        ));
    }

    #[test]
    fn runas_scheme_denied() {
        assert!(is_shell_target_denied("runas:c:\\windows\\notepad.exe"));
        assert!(is_shell_target_denied("RunAs:something"));
    }

    #[test]
    fn benign_targets_not_denied() {
        // Plain filesystem path.
        assert!(!is_shell_target_denied("C:\\Windows\\notepad.exe"));
        // Web URI — intentionally allowed (see module docs).
        assert!(!is_shell_target_denied("https://example.com"));
        assert!(!is_shell_target_denied("http://example.com/page"));
        // Empty string.
        assert!(!is_shell_target_denied(""));
        // Non-shell-app prefix that just happens to start with "shell:".
        assert!(!is_shell_target_denied("shell:Downloads"));
        // A scheme that shares a prefix with a denied scheme but is distinct.
        assert!(!is_shell_target_denied("ms-mybrand:foo"));
        // A short non-matching token.
        assert!(!is_shell_target_denied("a"));
    }

    #[test]
    fn coverage_of_every_listed_prefix() {
        // Smoke-check every entry in SHELL_DENY_PREFIXES so a typo in the
        // table is caught at test time. We append a trivial "x" suffix so
        // each test target actually has the prefix plus something.
        for p in SHELL_DENY_PREFIXES {
            let mut t = String::from(*p);
            t.push('x');
            assert!(
                is_shell_target_denied(&t),
                "expected to be denied: {}",
                t
            );
            // Uppercased variant must also match.
            let t_upper: String = t.to_ascii_uppercase();
            assert!(
                is_shell_target_denied(&t_upper),
                "expected to be denied (uppercased): {}",
                t_upper
            );
        }
    }

    /// Hook smoke: a null `lp_file` for ShellExecuteW must NOT be denied —
    /// the classifier returns false for null / empty strings, leaving the
    /// original API to handle the malformed call. This locks in the
    /// "let original surface its own error" behavior.
    #[test]
    fn null_target_not_denied_by_classifier() {
        // Direct classifier check — no FFI needed.
        assert!(!is_shell_target_denied(""));
    }

    /// `read_lpcwstr` must report `Absent` for a null pointer (no UB, no
    /// panic) — same semantics the old `Option::None` return had.
    #[test]
    fn read_lpcwstr_handles_null() {
        // SAFETY: explicitly passing a null pointer to test the null-path.
        let result = unsafe { read_lpcwstr(std::ptr::null()) };
        assert!(matches!(result, InspectedStr::Absent));
    }

    /// `read_lpcwstr` must correctly decode a normal null-terminated UTF-16
    /// buffer constructed in Rust, reporting it as a fully inspected `Value`.
    #[test]
    fn read_lpcwstr_decodes_terminated_buffer() {
        let s: Vec<u16> = "ms-settings:network\0".encode_utf16().collect();
        // SAFETY: `s` is a properly null-terminated UTF-16 buffer that lives
        // for the duration of this call.
        let decoded = unsafe { read_lpcwstr(s.as_ptr()) };
        match decoded {
            InspectedStr::Value(v) => assert_eq!(v, "ms-settings:network"),
            other => panic!("expected InspectedStr::Value, got {other:?}"),
        }
    }

    /// Pin the size of `SHELL_DENY_PREFIXES`. Update this number deliberately
    /// when adding or removing entries.
    #[test]
    fn shell_deny_list_count_pinned() {
        assert_eq!(SHELL_DENY_PREFIXES.len(), 37);
    }

    /// Sanity check: `PREFIX_INSPECT_CHARS` must be large enough to cover the
    /// longest denylist entry. `microsoft-edge-holographic:` is 27 chars.
    #[test]
    fn prefix_inspect_chars_accommodates_longest_entry() {
        let longest = SHELL_DENY_PREFIXES
            .iter()
            .map(|s| s.len())
            .max()
            .unwrap_or(0);
        assert!(
            longest <= PREFIX_INSPECT_CHARS,
            "longest denylist entry ({longest}) exceeds PREFIX_INSPECT_CHARS ({PREFIX_INSPECT_CHARS})"
        );
    }

    /// New schemes added in H2/H3: Microsoft Edge variants.
    #[test]
    fn microsoft_edge_uri_denied() {
        assert!(is_shell_target_denied("microsoft-edge:https://evil.example/"));
        assert!(is_shell_target_denied("MICROSOFT-EDGE:about:blank"));
        assert!(is_shell_target_denied("microsoft-edge-holographic:foo"));
    }

    /// New schemes: tel / sms / webcal / mailto handlers.
    #[test]
    fn telephony_and_calendar_schemes_denied() {
        assert!(is_shell_target_denied("tel:+15555550100"));
        assert!(is_shell_target_denied("sms:+15555550100?body=hi"));
        assert!(is_shell_target_denied("webcal://example.com/cal.ics"));
        assert!(is_shell_target_denied("mailto:alice@example.com"));
    }

    /// New schemes: news / feed / nntp / search-ms.
    #[test]
    fn news_feed_search_schemes_denied() {
        assert!(is_shell_target_denied("feed://example.com/rss"));
        assert!(is_shell_target_denied("news:alt.test"));
        assert!(is_shell_target_denied("nntp://news.example.com/group"));
        assert!(is_shell_target_denied("search-ms:query=test"));
    }

    /// New schemes: third-party app activations.
    #[test]
    fn third_party_app_schemes_denied() {
        assert!(is_shell_target_denied("steam://run/12345"));
        assert!(is_shell_target_denied("epicgames://launch"));
        assert!(is_shell_target_denied("spotify:track:abc"));
        assert!(is_shell_target_denied("discord://invite/foo"));
        assert!(is_shell_target_denied("slack://open"));
        assert!(is_shell_target_denied("zoommtg://zoom.us/join?confno=123"));
        assert!(is_shell_target_denied("msteams://teams.microsoft.com/l/team/..."));
    }

    /// `lpParameters` substring scan: explorer.exe + shell:AppsFolder\... and
    /// cmd.exe + /c start ms-windows-store://... must both deny via the
    /// params channel.
    #[test]
    fn lp_parameters_uri_denied() {
        // Classic escape: launcher target is benign, payload hides in args.
        assert!(is_shell_params_denied("shell:AppsFolder\\evil"));
        assert!(is_shell_params_denied("/c start ms-windows-store://app/0"));
        // shell_deny_reason should report `params` (not `file`) for these;
        // an empty verb is the default-verb launch path and stays allowed.
        assert_eq!(
            shell_deny_reason("", "explorer.exe", "shell:AppsFolder\\evil"),
            Some("params")
        );
        assert_eq!(
            shell_deny_reason("", "cmd.exe", "/c start ms-windows-store://app/0"),
            Some("params")
        );
        // Confirms case-insensitive substring scan picks up an embedded URI.
        assert!(is_shell_params_denied(
            "/c \"start MICROSOFT-EDGE:https://evil/\""
        ));
    }

    /// Benign parameters must not be denied — guards against regressions
    /// where the params substring scan would flag harmless text.
    #[test]
    fn lp_parameters_benign_not_denied() {
        assert!(!is_shell_params_denied("/c echo hello"));
        assert!(!is_shell_params_denied("--flag value"));
        assert!(!is_shell_params_denied(""));
        // File-only deny still works through the combined helper (empty verb
        // is allowed, so the file verdict surfaces unchanged).
        assert_eq!(
            shell_deny_reason("", "ms-settings:network", "/c echo hi"),
            Some("file")
        );
        assert_eq!(shell_deny_reason("", "notepad.exe", "/c echo hi"), None);
    }

    /// Coverage mirror for the WinRT side (lives in com_guard) — verifies
    /// every shell deny prefix matches via the params substring scan as well.
    /// Renamed to match the requested test name.
    #[test]
    fn coverage_of_every_listed_winrt_prefix_via_params() {
        for p in SHELL_DENY_PREFIXES {
            // Embed the prefix inside a benign-looking parameter string.
            let wrapped = format!("/c start {p}target");
            assert!(
                is_shell_params_denied(&wrapped),
                "expected params to be denied: {wrapped}"
            );
        }
    }

    // -----------------------------------------------------------------
    // M6 — Unicode-scheme detection.
    // -----------------------------------------------------------------

    /// A scheme whose name contains a non-ASCII homoglyph/fold (here U+1E9E
    /// LATIN CAPITAL SHARP S inside `R...NAS:`) is flagged as suspicious so it
    /// cannot slip past the ASCII byte-wise denylist.
    #[test]
    fn unicode_scheme_runas_denied() {
        assert!(is_suspicious_unicode_scheme("R\u{1E9E}NAS:x"));
    }

    /// A plain ASCII scheme is NOT flagged by the Unicode check — it is the
    /// `SHELL_DENY_PREFIXES` denylist's job to match `runas:` and friends.
    #[test]
    fn ascii_scheme_not_flagged_by_unicode_check() {
        assert!(!is_suspicious_unicode_scheme("runas:x"));
        // And the denylist does catch it, confirming separation of concerns.
        assert!(is_shell_target_denied("runas:x"));
    }

    /// A drive-letter path with a Unicode filename must NOT be flagged: the
    /// only early colon is the `C:` drive letter, which is explicitly exempt.
    #[test]
    fn drive_letter_path_not_flagged() {
        assert!(!is_suspicious_unicode_scheme("C:\\Users\\документ.txt"));
        // Lowercase drive letter too.
        assert!(!is_suspicious_unicode_scheme("d:\\папка\\файл.txt"));
    }

    /// A UNC path with a Unicode filename and no early colon must NOT be
    /// flagged (step 2 returns false when no `:` precedes path separators).
    #[test]
    fn unicode_filename_no_scheme_not_flagged() {
        assert!(!is_suspicious_unicode_scheme("\\\\server\\share\\документ.txt"));
    }

    /// A plain relative path with no colon at all is not a scheme.
    #[test]
    fn plain_relative_path_not_flagged() {
        assert!(!is_suspicious_unicode_scheme("notepad.exe"));
    }

    /// Extra coverage: an all-ASCII relative path that contains a colon only
    /// AFTER a separator (so the first colon is not in a scheme position) is
    /// not treated as a Unicode scheme. The first `:` is found before the
    /// backslash here, but the scheme portion is ASCII, so step 5 applies.
    #[test]
    fn ascii_scheme_with_unicode_after_colon_not_flagged() {
        // ASCII scheme, Unicode only in the opaque part → handled by denylist,
        // not by the Unicode-scheme check.
        assert!(!is_suspicious_unicode_scheme("mailto:документ@пример.рф"));
    }

    /// Empty input is never a scheme.
    #[test]
    fn empty_not_flagged_as_unicode_scheme() {
        assert!(!is_suspicious_unicode_scheme(""));
    }

    /// The combined `shell_deny_reason` reports `unicode_scheme` for a
    /// homoglyph scheme passed via `lpFile`, and still reports `file` /
    /// `params` for ASCII denylist hits.
    #[test]
    fn shell_deny_reason_reports_unicode_scheme() {
        assert_eq!(
            shell_deny_reason("", "R\u{1E9E}NAS:notepad.exe", ""),
            Some("unicode_scheme")
        );
        // ASCII denylist hit still wins as `file`.
        assert_eq!(shell_deny_reason("", "runas:x", ""), Some("file"));
        // Benign drive-letter path with Unicode filename → not denied.
        assert_eq!(
            shell_deny_reason("", "C:\\Users\\документ.txt", "/c echo hi"),
            None
        );
    }

    // -----------------------------------------------------------------
    // code-quality #1 — SHELLEXECUTEINFOW cbSize validation.
    // -----------------------------------------------------------------

    /// Documents the layout invariant the `hook_shell_execute_ex_w` cbSize
    /// guard relies on: a write of `hInstApp` is in-bounds only when the
    /// caller's `cbSize` is at least `offset_of!(hInstApp) + size_of::<HINSTANCE>()`.
    /// If a fabricated struct's `cbSize` is smaller than that, the hook must
    /// deny WITHOUT writing `hInstApp` (return FALSE only). We cannot easily
    /// exercise the detoured FFI path in a `--lib` unit test (the detour is
    /// not installed), so we lock the offset arithmetic that drives that
    /// decision here.
    #[test]
    fn cbsize_too_small_does_not_write_past_struct() {
        let full = core::mem::size_of::<SHELLEXECUTEINFOW>();
        let hinstapp_off = core::mem::offset_of!(SHELLEXECUTEINFOW, hInstApp);
        let hinstapp_end = hinstapp_off + core::mem::size_of::<HINSTANCE>();

        // hInstApp must lie fully inside the struct.
        assert!(hinstapp_end <= full, "hInstApp field extends past struct end");
        // The field has non-zero size and a non-zero offset (it is not the
        // first field), so a too-small struct really can omit it.
        assert!(hinstapp_off > 0);

        // Mirror the runtime decision for a few representative cbSize values.
        let writes_hinstapp = |cb: usize| cb >= hinstapp_end;
        // A struct truncated before hInstApp must NOT be written.
        assert!(!writes_hinstapp(hinstapp_off));
        assert!(!writes_hinstapp(hinstapp_end - 1));
        assert!(!writes_hinstapp(0));
        // A full / oversized struct may be written.
        assert!(writes_hinstapp(hinstapp_end));
        assert!(writes_hinstapp(full));
        assert!(writes_hinstapp(full + 16));
    }

    /// `is_shell_params_denied` must not panic on multi-byte UTF-8 input that
    /// crosses the 1024-byte scan cap.
    #[test]
    fn params_scan_handles_multibyte_boundary() {
        // Build a >1024-byte string whose 1024th byte falls inside a
        // multi-byte character. Each '€' is 3 UTF-8 bytes.
        let mut s = String::new();
        while s.len() < 1100 {
            s.push('€');
        }
        // Must not panic; benign content should not match.
        assert!(!is_shell_params_denied(&s));
    }

    // -----------------------------------------------------------------
    // FIX 2 — lpVerb allowlist classification.
    // -----------------------------------------------------------------

    /// `runas` (any ASCII casing) must classify as an escalation verb —
    /// the UAC-elevation twin of the already-denied `runas:` URI scheme.
    #[test]
    fn runas_verb_classified_as_escalation() {
        assert_eq!(shell_verb_deny_reason("runas"), Some("verb_escalation"));
        assert_eq!(shell_verb_deny_reason("RunAs"), Some("verb_escalation"));
        assert_eq!(shell_verb_deny_reason("RUNAS"), Some("verb_escalation"));
    }

    /// Locks in every allowlist decision. `runasadmin` proves the match is
    /// EXACT (a prefix match would wrongly inherit `runas`'s verdict), and
    /// the Cyrillic-а homoglyph proves non-ASCII lookalikes fail closed.
    #[test]
    fn shell_verbs_allowlist_decisions() {
        // Allowed: the default verb (also what a NULL lpVerb decodes to via
        // `InspectedStr::as_deref` of `Absent`) and ordinary association
        // dispatch — ASCII case-insensitive in every casing.
        assert_eq!(shell_verb_deny_reason(""), None);
        assert_eq!(shell_verb_deny_reason("open"), None);
        assert_eq!(shell_verb_deny_reason("OPEN"), None);
        assert_eq!(shell_verb_deny_reason("Open"), None);
        assert_eq!(shell_verb_deny_reason("edit"), None);
        assert_eq!(shell_verb_deny_reason("print"), None);
        // Explorer-hosted shell UI — different-parent escape surface.
        assert_eq!(shell_verb_deny_reason("explore"), Some("verb_explorer"));
        assert_eq!(shell_verb_deny_reason("EXPLORE"), Some("verb_explorer"));
        assert_eq!(shell_verb_deny_reason("find"), Some("verb_explorer"));
        // Exact-match proof: NOT prefix-matched against `runas`.
        assert_eq!(shell_verb_deny_reason("runasadmin"), Some("verb_unknown"));
        // Not a verb at all.
        assert_eq!(shell_verb_deny_reason("frobnicate"), Some("verb_unknown"));
        // Homoglyph lookalike (Cyrillic а U+0430) must not pass as `runas`.
        assert_eq!(shell_verb_deny_reason("run\u{430}s"), Some("verb_unknown"));
    }

    /// The combined gate must consult the verb FIRST: `runas` denies even
    /// with a benign target, while an allowed verb leaves the pre-existing
    /// file / params verdicts untouched.
    #[test]
    fn shell_deny_reason_reports_runas_escalation() {
        assert_eq!(
            shell_deny_reason("runas", "notepad.exe", ""),
            Some("verb_escalation")
        );
        assert_eq!(shell_deny_reason("open", "notepad.exe", "/c echo hi"), None);
    }

    // -----------------------------------------------------------------
    // FIX 1 — full-params scan + fail-closed inspection verdict.
    // -----------------------------------------------------------------

    /// Regression for the old 1024-byte scan cutoff: a payload pushed past
    /// byte 1024 (behind whitespace padding) was never seen and sailed
    /// through. The full-string scan must deny it both via the direct
    /// params classifier and through the combined gate.
    #[test]
    fn padded_params_beyond_old_1024_cutoff_denied() {
        // The dangerous URI starts past byte 1024.
        let padded = format!("{}{}", " ".repeat(1100), "/c start ms-windows-store://app/0");
        assert!(is_shell_params_denied(&padded));
        assert_eq!(shell_deny_reason("", "cmd.exe", &padded), Some("params"));
    }

    /// The reader must refuse to hand back a truncated view: with no NUL in
    /// range the result is `Unterminated` (fail-closed input for
    /// `uninspected_deny_reason`), never a silently cut 4096-unit string.
    /// Boundary cases: NUL at index 4095 → `Value` of 4095 chars; NUL at
    /// index 4096 (cap reached first) → `Unterminated`.
    #[test]
    fn unterminated_lpcwstr_is_refused() {
        // 5000 non-zero units, no terminator anywhere within the cap.
        let no_nul: Vec<u16> = vec![0x41u16; 5000];
        // SAFETY: `no_nul` outlives the call; the reader's scan is bounded
        // by `MAX_TARGET_CHARS`, well inside this allocation.
        let r = unsafe { read_lpcwstr(no_nul.as_ptr()) };
        assert!(matches!(r, InspectedStr::Unterminated));

        // Just under the cap: 4095 'A' units + NUL at index 4095 → Value.
        let under: Vec<u16> = {
            let mut v = vec![0x41u16; MAX_TARGET_CHARS - 1];
            v.push(0);
            v
        };
        // SAFETY: NUL-terminated buffer that outlives the call.
        let r = unsafe { read_lpcwstr(under.as_ptr()) };
        match r {
            InspectedStr::Value(s) => assert_eq!(s.chars().count(), MAX_TARGET_CHARS - 1),
            other => panic!("expected InspectedStr::Value, got {other:?}"),
        }

        // Exactly at the cap: 4096 'A' units + NUL at index 4096 — the scan
        // hits MAX_TARGET_CHARS before seeing the terminator → Unterminated.
        let at_cap: Vec<u16> = {
            let mut v = vec![0x41u16; MAX_TARGET_CHARS];
            v.push(0);
            v
        };
        // SAFETY: buffer outlives the call; the bounded scan stops at the cap.
        let r = unsafe { read_lpcwstr(at_cap.as_ptr()) };
        assert!(matches!(r, InspectedStr::Unterminated));
    }

    /// `uninspected_deny_reason` must refuse the whole call when ANY argument
    /// is `Unterminated` (checked file → params → verb, so the log names the
    /// first such argument), and let an all-inspected call through to the
    /// classifier chain.
    #[test]
    fn uninspected_argument_denies_call() {
        let verb = InspectedStr::Value("open".into());
        let file = InspectedStr::Value("notepad.exe".into());
        let params = InspectedStr::Value("/c echo hi".into());
        // All fully inspected → no refusal here.
        assert_eq!(uninspected_deny_reason(&verb, &file, &params), None);
        // Each position in isolation, in file → params → verb precedence.
        assert_eq!(
            uninspected_deny_reason(&verb, &InspectedStr::Unterminated, &params),
            Some("uninspected_file")
        );
        assert_eq!(
            uninspected_deny_reason(&verb, &file, &InspectedStr::Unterminated),
            Some("uninspected_params")
        );
        assert_eq!(
            uninspected_deny_reason(&InspectedStr::Unterminated, &file, &params),
            Some("uninspected_verb")
        );
        // Multiple Unterminated args still report the highest-precedence tag.
        assert_eq!(
            uninspected_deny_reason(
                &InspectedStr::Unterminated,
                &InspectedStr::Unterminated,
                &params
            ),
            Some("uninspected_file")
        );
    }

    // -----------------------------------------------------------------
    // Sibling-entry closure (audit High): ShellExecuteA / ShellExecuteExA
    // must reach the same classifier chain as the W hooks. The direct
    // hook-body calls below take the DENY path, which returns before the
    // trampoline is ever touched (the detour is not installed under --lib
    // tests), so they are safe to drive here. Benign calls are asserted
    // only through the seam fn — a None verdict through the hook body
    // would call the (uninstalled) trampoline.
    // -----------------------------------------------------------------

    /// NUL-terminated ANSI buffer for fabricating LPCSTR arguments.
    fn ansi_buf(s: &str) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        v
    }

    #[test]
    fn read_lpcstr_decodes_terminated_buffer() {
        let s = ansi_buf("ms-settings:network");
        // SAFETY: `s` is a NUL-terminated ANSI buffer outliving the call.
        let decoded = unsafe { read_lpcstr(s.as_ptr()) };
        match decoded {
            InspectedStr::Value(v) => assert_eq!(v, "ms-settings:network"),
            other => panic!("expected InspectedStr::Value, got {other:?}"),
        }
    }

    #[test]
    fn read_lpcstr_absent_for_null_and_empty() {
        // SAFETY: explicit null-pointer path.
        let r = unsafe { read_lpcstr(std::ptr::null()) };
        assert!(matches!(r, InspectedStr::Absent));
        let empty = b"\0".to_vec();
        // SAFETY: zero-length terminated buffer outlives the call.
        let r = unsafe { read_lpcstr(empty.as_ptr()) };
        assert!(matches!(r, InspectedStr::Absent));
    }

    #[test]
    fn read_lpcstr_unterminated_beyond_cap() {
        let no_nul = vec![0x41u8; MAX_TARGET_CHARS + 8];
        // SAFETY: buffer outlives the call; the scan is bounded by the cap.
        let r = unsafe { read_lpcstr(no_nul.as_ptr()) };
        assert!(matches!(r, InspectedStr::Unterminated));
    }

    #[test]
    fn shell_execute_a_seam_classifies_like_the_w_chain() {
        let verb_none = std::ptr::null();
        let file_settings = ansi_buf("ms-settings:network");
        let file_benign = ansi_buf(r"C:\Windows\notepad.exe");
        let params_store = ansi_buf("/c start ms-windows-store://app/0");
        let verb_runas = ansi_buf("runas");

        // SAFETY: all pointers are valid NUL-terminated buffers or null.
        unsafe {
            assert_eq!(
                shell_execute_a_deny_reason(verb_none, file_settings.as_ptr(), std::ptr::null()),
                Some("file")
            );
            assert_eq!(
                shell_execute_a_deny_reason(verb_runas.as_ptr(), file_benign.as_ptr(), std::ptr::null()),
                Some("verb_escalation")
            );
            assert_eq!(
                shell_execute_a_deny_reason(verb_none, file_benign.as_ptr(), params_store.as_ptr()),
                Some("params")
            );
            // Benign call: every classifier declines — the A hook would let
            // the original run (asserted via the seam, not the hook body).
            assert_eq!(
                shell_execute_a_deny_reason(verb_none, file_benign.as_ptr(), std::ptr::null()),
                None
            );
        }
    }

    #[test]
    fn shell_execute_a_hook_denies_dangerous_target() {
        let file = ansi_buf("MS-Settings:network");
        // SAFETY: deny path returns SE_ERR_ACCESSDENIED without touching the
        // (uninstalled) trampoline.
        let got = unsafe {
            hook_shell_execute_a(
                std::ptr::null_mut(), // hwnd
                std::ptr::null(),     // lpOperation (default verb)
                file.as_ptr(),        // lpFile
                std::ptr::null(),     // lpParameters
                std::ptr::null(),     // lpDirectory
                0,                    // nShowCmd
            )
        };
        assert_eq!(got as usize, SE_ERR_ACCESSDENIED, "A hook must deny via lpFile");
    }

    #[test]
    fn shell_execute_a_hook_denies_unterminated_argument() {
        // Fail-closed parity with the W hook: an lpFile with no NUL within
        // the inspection cap must refuse the whole call.
        let file = vec![0x41u8; MAX_TARGET_CHARS + 8];
        // SAFETY: deny path returns before call_original.
        let got = unsafe {
            hook_shell_execute_a(
                std::ptr::null_mut(),
                std::ptr::null(),
                file.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
            )
        };
        assert_eq!(got as usize, SE_ERR_ACCESSDENIED, "uninspected lpFile must deny");
    }

    #[test]
    fn shell_execute_ex_a_hook_denies_and_sets_hinstapp() {
        let verb = ansi_buf("open");
        let file = ansi_buf(r"runas:c:\x");
        let mut info = SHELLEXECUTEINFOA {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOA>() as u32,
            fMask: 0,
            hwnd: std::ptr::null_mut(),
            lpVerb: verb.as_ptr(),
            lpFile: file.as_ptr(),
            lpParameters: std::ptr::null(),
            lpDirectory: std::ptr::null(),
            nShow: 0,
            hInstApp: std::ptr::null_mut(),
        };
        // SAFETY: deny path writes only our own fabricated struct's hInstApp
        // and returns FALSE without touching the trampoline.
        let got = unsafe { hook_shell_execute_ex_a(&mut info) };
        assert_eq!(got, FALSE, "ExA hook must deny the runas target");
        assert_eq!(
            info.hInstApp as usize, SE_ERR_ACCESSDENIED,
            "denial must be reported via hInstApp per the shellapi contract"
        );
    }

    #[test]
    fn shell_execute_ex_a_too_small_cbsize_denies_without_hinstapp_write() {
        let file = ansi_buf("ms-settings:network");
        // cbSize covers up to lpParameters but NOT hInstApp.
        let lpparameters_end =
            (core::mem::offset_of!(SHELLEXECUTEINFOA, lpParameters)
                + core::mem::size_of::<*const u8>()) as u32;
        let mut info = SHELLEXECUTEINFOA {
            cbSize: lpparameters_end,
            fMask: 0,
            hwnd: std::ptr::null_mut(),
            lpVerb: std::ptr::null(),
            lpFile: file.as_ptr(),
            lpParameters: std::ptr::null(),
            lpDirectory: std::ptr::null(),
            nShow: 0,
            hInstApp: std::ptr::null_mut(),
        };
        // SAFETY: deny path; the struct is our own stack allocation and the
        // hook must NOT write hInstApp past the declared cbSize.
        let got = unsafe { hook_shell_execute_ex_a(&mut info) };
        assert_eq!(got, FALSE, "truncated struct must still be denied");
        assert!(
            info.hInstApp.is_null(),
            "hInstApp must NOT be written when cbSize cannot hold it"
        );
    }

    /// Export-name tripwire: a typo'd / renamed shell32 export silently
    /// skips its detour (all installers log-and-skip). Pin resolution.
    #[test]
    fn shell_a_exports_resolve_in_shell32() {
        // SAFETY: GetProcAddress wrapper over LoadLibraryW("shell32.dll");
        // safe outside DllMain constraints in tests.
        unsafe {
            for name in [
                b"ShellExecuteW\0".as_slice(),
                b"ShellExecuteExW\0".as_slice(),
                b"ShellExecuteA\0".as_slice(),
                b"ShellExecuteExA\0".as_slice(),
            ] {
                let addr = shell32_export(name);
                let name_str = String::from_utf8_lossy(name);
                assert!(addr.is_some(), "shell32 export must resolve: {name_str}");
            }
        }
    }
}
