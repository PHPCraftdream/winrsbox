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
//   * `runas:` — UAC elevation prompt host.
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

/// Scans `params` for any embedded denied URI. ShellExecute callers can pass
/// the dangerous scheme via `lpParameters` instead of `lpFile` — e.g.
/// `lpFile = "cmd.exe", lpParameters = "/c start ms-windows-store://..."`.
/// We scan up to the first 1024 bytes of the lowercased parameter string for
/// any denylist entry occurring as a substring. Returns `true` on the first
/// match.
///
/// Substring (not prefix) scan is intentional because the dangerous scheme
/// may appear after a `start`, `/c`, redirection metacharacters, or quoting.
pub(crate) fn is_shell_params_denied(params: &str) -> bool {
    if params.is_empty() {
        return false;
    }
    // Find a UTF-8-safe byte index at or below the scan cap. Because Windows
    // shell parameters are overwhelmingly ASCII and the indexing happens at
    // the boundary of the byte cap, we step back to the previous char
    // boundary to avoid panicking on a multibyte split.
    let cap = params.len().min(1024);
    let mut idx = cap;
    while idx > 0 && !params.is_char_boundary(idx) {
        idx -= 1;
    }
    let scan = params[..idx].to_ascii_lowercase();
    SHELL_DENY_PREFIXES.iter().any(|p| scan.contains(p))
}

/// Combined check used by both ShellExecute hook entry points. Returns a
/// short tag identifying which input matched so the violation log can
/// distinguish `reason=file` from `reason=params`. Returns `None` when
/// neither input matches.
pub(crate) fn shell_deny_reason(file: &str, params: &str) -> Option<&'static str> {
    if is_shell_target_denied(file) {
        Some("file")
    } else if is_shell_params_denied(params) {
        Some("params")
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Wide-string decoder.
//
// Reads up to `MAX_TARGET_CHARS` UTF-16 code units from a null-terminated
// LPCWSTR, decodes lossily to a Rust `String`, and returns it. Returns `None`
// for null pointers, empty strings, and (defensively) for an unterminated
// buffer that hits the cap.
//
// # SAFETY
// `p` must either be null OR point to a valid null-terminated UTF-16 buffer
// (the standard Win32 LPCWSTR contract). Caller is responsible for ensuring
// the pointer is valid for at least until the null terminator or until
// `MAX_TARGET_CHARS` code units have been read.
// ---------------------------------------------------------------------------

unsafe fn read_lpcwstr(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // Locate the null terminator with a bounded scan.
    let mut len = 0usize;
    while len < MAX_TARGET_CHARS {
        // SAFETY: `p` is non-null per check above; caller contract guarantees
        // readability up to and including the null terminator (or, if the
        // buffer is improperly terminated, up to the cap — at which point we
        // bail out conservatively).
        if *p.add(len) == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        return None;
    }
    // SAFETY: We have just verified `len` < MAX_TARGET_CHARS and that each of
    // the first `len` code units is non-zero and within the readable range.
    let slice = std::slice::from_raw_parts(p, len);
    Some(String::from_utf16_lossy(slice))
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
        // SAFETY: detour2 trampoline matches FnShellExecuteW ABI.
        HOOK_SHELL_EXECUTE_W.get().unwrap().call(
            hwnd, lp_operation, lp_file, lp_parameters, lp_directory, n_show_cmd,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    let file_str = read_lpcwstr(lp_file).unwrap_or_default();
    let params_str = read_lpcwstr(lp_parameters).unwrap_or_default();
    if let Some(reason) = shell_deny_reason(&file_str, &params_str) {
        if is_trace() {
            crate::hooks::ipc_log_violation(ipc::Req::Log {
                pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                level: ipc::LogLevel::Warn,
                msg: format!(
                    "shell_execute_blocked reason={reason} file={file_str} params={params_str}"
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
        // SAFETY: detour2 trampoline matches FnShellExecuteExW ABI.
        HOOK_SHELL_EXECUTE_EX_W.get().unwrap().call(p_exec_info)
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if !p_exec_info.is_null() {
        // SAFETY: Caller of ShellExecuteExW is contractually obliged to pass
        // a valid pointer to an initialized SHELLEXECUTEINFOW; we only read
        // the prefix fields up to lpParameters.
        let info_ref = &*p_exec_info;
        let file_str = read_lpcwstr(info_ref.lpFile).unwrap_or_default();
        let params_str = read_lpcwstr(info_ref.lpParameters).unwrap_or_default();
        if let Some(reason) = shell_deny_reason(&file_str, &params_str) {
            if is_trace() {
                crate::hooks::ipc_log_violation(ipc::Req::Log {
                    pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                    level: ipc::LogLevel::Warn,
                    msg: format!(
                        "shell_execute_ex_blocked reason={reason} file={file_str} params={params_str}"
                    ),
                });
            }
            // Report SE_ERR_ACCESSDENIED via hInstApp per shellapi.h
            // contract and return FALSE.
            // SAFETY: p_exec_info is non-null and points to a writable
            // struct allocated by the caller; hInstApp is part of the
            // documented struct prefix.
            (*p_exec_info).hInstApp = SE_ERR_ACCESSDENIED as *mut c_void as HINSTANCE;
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
}

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

    /// `read_lpcwstr` must return `None` for a null pointer (no UB, no panic).
    #[test]
    fn read_lpcwstr_handles_null() {
        // SAFETY: explicitly passing a null pointer to test the null-path.
        let result = unsafe { read_lpcwstr(std::ptr::null()) };
        assert!(result.is_none());
    }

    /// `read_lpcwstr` must correctly decode a normal null-terminated UTF-16
    /// buffer constructed in Rust.
    #[test]
    fn read_lpcwstr_decodes_terminated_buffer() {
        let s: Vec<u16> = "ms-settings:network\0".encode_utf16().collect();
        // SAFETY: `s` is a properly null-terminated UTF-16 buffer that lives
        // for the duration of this call.
        let decoded = unsafe { read_lpcwstr(s.as_ptr()) };
        assert_eq!(decoded.as_deref(), Some("ms-settings:network"));
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
        // shell_deny_reason should report `params` (not `file`) for these.
        assert_eq!(
            shell_deny_reason("explorer.exe", "shell:AppsFolder\\evil"),
            Some("params")
        );
        assert_eq!(
            shell_deny_reason("cmd.exe", "/c start ms-windows-store://app/0"),
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
        // File-only deny still works through the combined helper.
        assert_eq!(
            shell_deny_reason("ms-settings:network", "/c echo hi"),
            Some("file")
        );
        assert_eq!(shell_deny_reason("notepad.exe", "/c echo hi"), None);
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
}
