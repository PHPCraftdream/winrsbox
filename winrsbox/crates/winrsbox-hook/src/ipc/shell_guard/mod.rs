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
mod inspect;

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

#[cfg(test)]
mod tests;
