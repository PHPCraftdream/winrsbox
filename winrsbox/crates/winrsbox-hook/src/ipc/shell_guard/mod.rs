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
// F2 (R04): the Ex entry points also deny fMask-driven alternate target
// resolution (IDList / shell class / env-subst) outright.
//
// Hook targets: shell32.dll!ShellExecuteW, shell32.dll!ShellExecuteExW.

use std::sync::OnceLock;

use detour2::GenericDetour;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{BOOL, FALSE, HINSTANCE};
use winapi::shared::windef::HWND;

use crate::hooks::{ipc_log, is_trace};
mod inspect;
mod decide;

use decide::{
    shell_execute_a_deny, shell_execute_ex_a_deny, shell_execute_ex_w_deny,
    shell_execute_w_deny,
};
#[cfg(test)]
use decide::shell_execute_a_deny_reason;
#[cfg(test)]
use inspect::{read_lpcstr, read_lpcwstr, uninspected_deny_reason};

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

// ---------------------------------------------------------------------------
// F2 (R04) — fMask classification for the ShellExecuteEx* entry points.
//
// winapi 0.3 does not expose these constants with the features enabled in
// our Cargo.toml; values per the SHELLEXECUTEINFOW docs
// (learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfow).
// ---------------------------------------------------------------------------

pub(crate) const SEE_MASK_CLASSNAME: u32 = 0x0000_0001;
pub(crate) const SEE_MASK_CLASSKEY: u32 = 0x0000_0003;
pub(crate) const SEE_MASK_IDLIST: u32 = 0x0000_0004;
pub(crate) const SEE_MASK_INVOKEIDLIST: u32 = 0x0000_000C;
pub(crate) const SEE_MASK_DOENVSUBST: u32 = 0x0000_0200;

/// Classifies `fMask` (the `SHELLEXECUTEINFOW.fMask` field, both the W and
/// the A Ex entry) and returns the deny reason, or `None` when the mask
/// keeps target resolution on the plain `lpFile` + `lpParameters` strings
/// the string chain inspects.
///
/// Decisions (most-specific tag first, because `CLASSKEY` sets the
/// `CLASSNAME` bit and `INVOKEIDLIST` sets the `IDLIST` bit):
///
/// * `SEE_MASK_CLASSKEY` (0x3) → `Some("mask_classkey")`. `hkeyClass`
///   selects a registry-class handler we do not classify.
/// * `SEE_MASK_CLASSNAME` (0x1) → `Some("mask_classname")`. `lpClass`
///   selects a shell-class handler we do not classify.
/// * `SEE_MASK_INVOKEIDLIST` (0xC) → `Some("mask_invokeidlist")`. The item
///   is identified by `lpIDList` or dispatched to `lpFile`'s context-menu
///   handler — either way execution leaves the plain string
///   interpretation we inspect.
/// * `SEE_MASK_IDLIST` (0x4) → `Some("mask_idlist")`. The target resolves
///   from the `lpIDList` PIDL — a binary shell format we deliberately do
///   not parse; the fail-closed refusal follows the
///   `uninspected_deny_reason` precedent (an input we cannot classify must
///   refuse the call).
/// * `SEE_MASK_DOENVSUBST` (0x200) → `Some("mask_doenvsubst")`. The shell
///   expands environment variables in `lpFile`/`lpDirectory` before
///   execution, so the string we inspected is not the string executed.
/// * anything else → `None`. The remaining documented bits (ICON 0x10,
///   HOTKEY 0x20, NOCLOSEPROCESS 0x40, CONNECTNETDRV 0x80, NOASYNC/
///   FLAG_DDEWAIT 0x100, FLAG_NO_UI 0x400, UNICODE 0x4000, NO_CONSOLE
///   0x8000, ASYNCOK 0x100000, HMONITOR 0x200000, NOZONECHECKS 0x800000,
///   WAITFORINPUTIDLE 0x2000000, FLAG_LOG_USAGE 0x4000000,
///   FLAG_HINST_IS_SITE 0x8000000, NOQUERYCLASSSTORE 0x1000000) do not
///   change which struct member the target is resolved from. Lone
///   undefined values (0x2, 0x8 without their partner bits) are ignored by
///   the shell.
pub(crate) fn shell_fmask_deny_reason(f_mask: u32) -> Option<&'static str> {
    if (f_mask & SEE_MASK_CLASSKEY) == SEE_MASK_CLASSKEY {
        return Some("mask_classkey");
    }
    if (f_mask & SEE_MASK_CLASSNAME) != 0 {
        return Some("mask_classname");
    }
    if (f_mask & SEE_MASK_INVOKEIDLIST) == SEE_MASK_INVOKEIDLIST {
        return Some("mask_invokeidlist");
    }
    if (f_mask & SEE_MASK_IDLIST) != 0 {
        return Some("mask_idlist");
    }
    if (f_mask & SEE_MASK_DOENVSUBST) != 0 {
        return Some("mask_doenvsubst");
    }
    None
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
    // the declared end. After F2 this stays sound for lpIDList/lpClass/
    // hkeyClass under every ALLOWED call: any fMask bit that would make the
    // shell resolve the target through them is denied
    // (`shell_fmask_deny_reason`), so under every allowed call those members
    // are ignored-by-contract per the OS docs.
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

    if shell_execute_w_deny(lp_operation, lp_file, lp_parameters) {
        // ShellExecuteW returns HINSTANCE; values <= 32 indicate error.
        // 5 == SE_ERR_ACCESSDENIED.
        return SE_ERR_ACCESSDENIED as *mut c_void as HINSTANCE;
    }

    // F1 (R04): the anti_rec window from the decision seam above is closed
    // here. ShellExecuteW can dispatch shell verb handlers (guest-reachable
    // application code); a hooked call made from inside them must run a
    // fresh policy check, not see stale suppression.
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

    if shell_execute_ex_w_deny(p_exec_info) {
        return FALSE;
    }

    // F1 (R04): the anti_rec window from the decision seam above is closed
    // here. ShellExecuteExW can dispatch shell verb handlers (guest-reachable
    // application code); a hooked call made from inside them must run a
    // fresh policy check, not see stale suppression.
    call_original()
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

    if shell_execute_a_deny(lp_operation, lp_file, lp_parameters) {
        // ShellExecuteA returns HINSTANCE; values <= 32 indicate error.
        // 5 == SE_ERR_ACCESSDENIED.
        return SE_ERR_ACCESSDENIED as *mut c_void as HINSTANCE;
    }

    // F1 (R04): the anti_rec window from the decision seam above is closed
    // here. ShellExecuteA can dispatch shell verb handlers (guest-reachable
    // application code); a hooked call made from inside them must run a
    // fresh policy check, not see stale suppression.
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

    if shell_execute_ex_a_deny(p_exec_info) {
        return FALSE;
    }

    // F1 (R04): the anti_rec window from the decision seam above is closed
    // here. ShellExecuteExA can dispatch shell verb handlers (guest-reachable
    // application code); a hooked call made from inside them must run a
    // fresh policy check, not see stale suppression.
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
///
/// R04 F4 policy — MANDATORY category: all four ShellExecute* exports fail
/// closed. shell32 has exported them since Win95 and the ShellExecute verb
/// allow-list is documented SECURITY.md behavior, so a missing export must
/// abort the install (Err propagates out through install_hooks) rather than
/// degrade silently with the shell escape path left unguarded.
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
        // Fail-closed per the mandatory-category policy (R04 F4): shell32
        // exports are universal and the ShellExecute verb allow-list is
        // documented SECURITY.md containment behavior, so a missing export
        // must abort the install rather than degrade silently.
        return Err("shell_guard: shell32 export ShellExecuteW not found".into());
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
        return Err("shell_guard: shell32 export ShellExecuteExW not found".into());
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
        return Err("shell_guard: shell32 export ShellExecuteA not found".into());
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
        return Err("shell_guard: shell32 export ShellExecuteExA not found".into());
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

#[cfg(test)]
mod tests;
#[cfg(test)]
mod install_tests;
