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
/// distinguish `reason=file`, `reason=unicode_scheme`, and `reason=params`.
/// Returns `None` when no input matches.
///
/// `unicode_scheme` (M6) is checked on `file` before the ASCII denylist so a
/// homoglyph/fold scheme that would slip past the byte-wise denylist is still
/// denied. See `is_suspicious_unicode_scheme`.
pub(crate) fn shell_deny_reason(file: &str, params: &str) -> Option<&'static str> {
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
        let cbsize_ok_for_full_struct = cb_size >= core::mem::size_of::<SHELLEXECUTEINFOW>();
        let cbsize_ok_for_hinstapp_write = cb_size >= hinstapp_end;

        // SAFETY: `p_exec_info` is non-null and the caller contract guarantees
        // the declared `cbSize` bytes are initialized & readable. We only read
        // the prefix fields up to `lpParameters`; if `cbSize` is too small to
        // even contain those, the reads below could touch uninitialized/OOB
        // memory — but `lpParameters` lives well before `hInstApp`, so any
        // struct large enough to be a valid ShellExecuteExW call covers them.
        // The denylist/Unicode/params decision itself never writes the struct.
        let info_ref = &*p_exec_info;
        let file_str = read_lpcwstr(info_ref.lpFile).unwrap_or_default();
        let params_str = read_lpcwstr(info_ref.lpParameters).unwrap_or_default();
        if let Some(reason) = shell_deny_reason(&file_str, &params_str) {
            // Note when the struct is too small to hold a full SHELLEXECUTEINFOW
            // so the log records why we may have skipped the hInstApp write.
            let truncated = !cbsize_ok_for_full_struct;
            if is_trace() {
                crate::hooks::ipc_log_violation(ipc::Req::Log {
                    pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                    level: ipc::LogLevel::Warn,
                    msg: format!(
                        "shell_execute_ex_blocked reason={reason} cbSize={cb_size} truncated={truncated} file={file_str} params={params_str}"
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
            shell_deny_reason("R\u{1E9E}NAS:notepad.exe", ""),
            Some("unicode_scheme")
        );
        // ASCII denylist hit still wins as `file`.
        assert_eq!(shell_deny_reason("runas:x", ""), Some("file"));
        // Benign drive-letter path with Unicode filename → not denied.
        assert_eq!(
            shell_deny_reason("C:\\Users\\документ.txt", "/c echo hi"),
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
}
