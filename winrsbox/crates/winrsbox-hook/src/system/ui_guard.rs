// UI guard — protects against two classes of escape:
//
// 1. Input injection (kill-on-call): SendInput, keybd_event, mouse_event,
//    BlockInput, SetCursorPos. AI agents and dev-tools never legitimately
//    synthesize input; these are pure Win+R-style hijack primitives.
//
// 2. Cross-window messaging and clipboard (soft deny): FindWindow*,
//    OpenClipboard, GetClipboardData, SendMessage*, PostMessage*. Job
//    JOB_OBJECT_UILIMIT_HANDLES/READCLIPBOARD does not enforce these
//    reliably on Win10 19045 in practice — user-mode hooks fill the gap.
//    Behaviour: return NULL/FALSE rather than kill, so apps that probe
//    for siblings (legitimate own-process queries) keep working.

use std::sync::OnceLock;

use detour2::GenericDetour;
use winapi::shared::minwindef::{BOOL, DWORD, LPARAM, UINT, WPARAM};
use winapi::shared::ntdef::{HANDLE, LPCSTR};
use winapi::shared::windef::HWND;
use winapi::um::winnt::LPCWSTR;
use winapi::um::winuser::INPUT;

use crate::anti_rec;
use crate::hooks::{buffer_install_error, ipc_log, is_trace};

type FnSendInput    = unsafe extern "system" fn(UINT, *mut INPUT, i32) -> UINT;
type FnKeybdEvent   = unsafe extern "system" fn(u8, u8, DWORD, usize);
type FnMouseEvent   = unsafe extern "system" fn(DWORD, DWORD, DWORD, DWORD, usize);
type FnBlockInput   = unsafe extern "system" fn(BOOL) -> BOOL;
type FnSetCursorPos = unsafe extern "system" fn(i32, i32) -> BOOL;

type FnFindWindowW    = unsafe extern "system" fn(LPCWSTR, LPCWSTR) -> HWND;
type FnFindWindowA    = unsafe extern "system" fn(LPCSTR, LPCSTR) -> HWND;
type FnFindWindowExW  = unsafe extern "system" fn(HWND, HWND, LPCWSTR, LPCWSTR) -> HWND;
type FnFindWindowExA  = unsafe extern "system" fn(HWND, HWND, LPCSTR, LPCSTR) -> HWND;
type FnOpenClipboard  = unsafe extern "system" fn(HWND) -> BOOL;
type FnGetClipboardData = unsafe extern "system" fn(UINT) -> HANDLE;
type FnPostMessageW   = unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> BOOL;
type FnPostMessageA   = unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> BOOL;
type FnSendMessageW   = unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> isize;
type FnSendMessageA   = unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> isize;
type FnExitWindowsEx  = unsafe extern "system" fn(UINT, DWORD) -> BOOL;

static HOOK_SEND_INPUT:     OnceLock<GenericDetour<FnSendInput>>    = OnceLock::new();
static HOOK_KEYBD_EVENT:    OnceLock<GenericDetour<FnKeybdEvent>>   = OnceLock::new();
static HOOK_MOUSE_EVENT:    OnceLock<GenericDetour<FnMouseEvent>>   = OnceLock::new();
static HOOK_BLOCK_INPUT:    OnceLock<GenericDetour<FnBlockInput>>   = OnceLock::new();
static HOOK_SET_CURSOR_POS: OnceLock<GenericDetour<FnSetCursorPos>> = OnceLock::new();

static HOOK_FIND_WINDOW_W:     OnceLock<GenericDetour<FnFindWindowW>>     = OnceLock::new();
static HOOK_FIND_WINDOW_A:     OnceLock<GenericDetour<FnFindWindowA>>     = OnceLock::new();
static HOOK_FIND_WINDOW_EX_W:  OnceLock<GenericDetour<FnFindWindowExW>>   = OnceLock::new();
static HOOK_FIND_WINDOW_EX_A:  OnceLock<GenericDetour<FnFindWindowExA>>   = OnceLock::new();
static HOOK_OPEN_CLIPBOARD:    OnceLock<GenericDetour<FnOpenClipboard>>   = OnceLock::new();
static HOOK_GET_CLIPBOARD:     OnceLock<GenericDetour<FnGetClipboardData>> = OnceLock::new();
static STRICT_CLIPBOARD: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static HOOK_POST_MESSAGE_W:    OnceLock<GenericDetour<FnPostMessageW>>    = OnceLock::new();
static HOOK_POST_MESSAGE_A:    OnceLock<GenericDetour<FnPostMessageA>>    = OnceLock::new();
static HOOK_SEND_MESSAGE_W:    OnceLock<GenericDetour<FnSendMessageW>>    = OnceLock::new();
static HOOK_SEND_MESSAGE_A:    OnceLock<GenericDetour<FnSendMessageA>>    = OnceLock::new();
static HOOK_EXIT_WINDOWS_EX:   OnceLock<GenericDetour<FnExitWindowsEx>>   = OnceLock::new();

// win32u!NtUserSendInput — the syscall-stub sibling of user32!SendInput
// (audit 2026-09-19 High). Since Win10 1809 user32!SendInput forwards to
// win32u, and win32u.dll EXPORTS NtUserSendInput, so a caller can reach the
// same input-synthesis syscall without touching our user32 patch. The
// win32u module is NOT ntdll — resolution goes through LoadLibraryW like
// the user32 installs below. Same kill-on-call policy as SendInput.
type FnNtUserSendInput = unsafe extern "system" fn(UINT, *mut INPUT, i32) -> UINT;
static HOOK_NT_USER_SEND_INPUT: OnceLock<GenericDetour<FnNtUserSendInput>> = OnceLock::new();

/// F3 (R04) classification of an HWND seen by a UI hook. Replaces the old
/// boolean `is_foreign_hwnd`, which collapsed NULL and failed
/// GetWindowThreadProcessId lookups into the same "allowed" outcome,
/// conflating special destinations and unresolvable handles with genuinely
/// safe own-process targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HwndClass {
    /// NULL — no concrete destination. PostMessage(NULL) posts to the
    /// calling thread's own queue; SendMessage(NULL) is a documented no-op
    /// returning 0; FindWindow returning NULL means "not found".
    NoTarget,
    /// Documented pseudo-destinations: HWND_BROADCAST (0xffff), HWND_TOPMOST
    /// (-1), HWND_NOTOPMOST (-2), HWND_MESSAGE (-3). Not real windows;
    /// HWND_BROADCAST fans a message out to every top-level window on the
    /// desktop — a cross-process dispatch by definition.
    SpecialDest,
    /// GetWindowThreadProcessId resolved no owning PID for a value that is
    /// NOT one of the recognized special constants: stale/destroyed HWND,
    /// cross-desktop or otherwise unresolvable destination. Unknown identity
    /// for a message dispatch is not evidence of safety (F3).
    Unknown,
    /// Resolves to this process's own PID (the sandbox-tree root) or to a
    /// PID that `crate::process_tracker` currently tracks as our own spawned
    /// child (creation-time fingerprint verified against PID reuse).
    OwnSandbox,
    /// Resolves to a live PID that is neither us nor a tracked sandbox child.
    Foreign,
}

/// Classify documented special HWND constants before any OS query. These
/// pseudo-values must never be resolved via GetWindowThreadProcessId —
/// HWND_BROADCAST fails there and was previously misclassified as "allowed"
/// through the pid==0 hole. HWND_BOTTOM (1) is deliberately absent: it is a
/// SetWindowPos z-order constant, not a message destination, so an
/// unresolvable value like it classifies as `Unknown`.
fn classify_special(hwnd: HWND) -> Option<HwndClass> {
    match hwnd as usize {
        0 => Some(HwndClass::NoTarget), // NULL == HWND_DESKTOP == HWND_TOP
        0xFFFF => Some(HwndClass::SpecialDest),         // HWND_BROADCAST
        usize::MAX => Some(HwndClass::SpecialDest),     // HWND_TOPMOST (-1)
        // usize::MAX - 1 / - 2 are not valid match patterns; literal spellings:
        0xFFFF_FFFF_FFFF_FFFE => Some(HwndClass::SpecialDest), // HWND_NOTOPMOST (-2)
        0xFFFF_FFFF_FFFF_FFFD => Some(HwndClass::SpecialDest), // HWND_MESSAGE (-3)
        _ => None,
    }
}

/// Pure decision core over the PID the OS reported for the HWND. `pid == 0`
/// (lookup failed) is `Unknown`, NOT `NoTarget` — the two must stay distinct
/// because NULL has documented own-scope semantics and a failed lookup does
/// not.
fn classify_pid(pid: DWORD) -> HwndClass {
    if pid == 0 {
        return HwndClass::Unknown;
    }
    // SAFETY: GetCurrentProcessId is a constant-cost TEB read.
    if pid == unsafe { winapi::um::processthreadsapi::GetCurrentProcessId() } {
        return HwndClass::OwnSandbox;
    }
    if crate::process_tracker::is_owned_child(pid) {
        return HwndClass::OwnSandbox;
    }
    HwndClass::Foreign
}

/// F3 (R04) classifier: map an HWND to its `HwndClass`. See `f3_denied` for
/// the per-family policy each class feeds.
///
/// # SAFETY
/// `hwnd` may be any HWND value, including null and the special
/// pseudo-constants (all handled in `classify_special`). The
/// `process_tracker` membership check is bounded (one map probe; only
/// tracked PIDs trigger one PROCESS_QUERY_LIMITED_INFORMATION open). Every
/// caller runs inside an `anti_rec` window, so a nested OpenProcess that
/// re-enters proc_guard's NtOpenProcess hook forwards straight to the
/// original — see process_tracker's own anti-recursion analysis (M2).
unsafe fn classify_hwnd(hwnd: HWND) -> HwndClass {
    if let Some(class) = classify_special(hwnd) {
        return class;
    }
    let mut pid: DWORD = 0;
    // SAFETY: hwnd is opaque; GetWindowThreadProcessId only reads it.
    let _ = winapi::um::winuser::GetWindowThreadProcessId(hwnd, &mut pid);
    classify_pid(pid)
}

/// F3 (R04) policy: map an `HwndClass` to the soft-deny decision for every
/// family this file hooks. `true` = hook soft-denies (already logged),
/// `false` = forward to the original.
///
/// Dispatch family — SendMessageW/A, PostMessageW/A:
///   - `NoTarget` (NULL): allowed. PostMessage(NULL) posts to the calling
///     thread's own queue and SendMessage(NULL) is a documented no-op
///     returning 0 — neither crosses a process boundary. Keeps F1's
///     null-HWND seam tests meaningful.
///   - `OwnSandbox`: allowed — compatibility posture (interactive
///     terminal/IDE sessions): own windows and fingerprint-verified sandbox
///     children keep messaging. NOT a trust claim under the R04 model
///     (children are on the untrusted side there); this keeps intra-sandbox
///     plumbing working until the headless profile — separate R04
///     architectural work per the finding — can deny it explicitly. The
///     class is distinct from `Foreign` precisely so that switch is a
///     policy change at this one match, not a classifier change.
///   - `SpecialDest`: denied. HWND_BROADCAST reaches every top-level window
///     on the desktop — cross-process by definition, previously smuggled
///     through the pid==0 hole. The other pseudo-handles are invalid
///     message targets the real APIs fail on anyway, so denying them is
///     behavior-preserving.
///   - `Unknown`: denied. "Lookup resolved nothing" used to be an allow
///     through the same pid==0 hole; an unresolvable identity for a
///     side-effectful dispatch is not evidence of safety. A genuinely stale
///     HWND would have failed the real call anyway, and callers already
///     handle FALSE/0 returns.
///   - `Foreign`: denied (unchanged).
///
/// Probe family — FindWindowW/A/ExW/ExA (result filter): same partition;
/// deny means return NULL ("not found"). A SpecialDest or Unknown result is
/// not vouchable as own-process and is hidden like a foreign one. FindWindow
/// never legitimately returns the pseudo-constants, so those arms are pure
/// fail-closed.
fn f3_denied(class: HwndClass, api: &str) -> bool {
    match class {
        HwndClass::NoTarget | HwndClass::OwnSandbox => false,
        HwndClass::SpecialDest => {
            log_soft_deny(api, "special destination HWND");
            true
        }
        HwndClass::Unknown => {
            log_soft_deny(api, "unknown HWND");
            true
        }
        HwndClass::Foreign => {
            log_soft_deny(api, "foreign HWND");
            true
        }
    }
}

fn log_soft_deny(api: &str, detail: &str) {
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace,
            format!("UI soft-deny: {api} {detail}"));
    }
}

fn report_and_kill(api: &str) -> ! {
    if is_trace() {
        ipc_log(ipc::LogLevel::Warn,
            format!("INPUT-INJECT DENY: {api} — terminating process"));
    }
    // SAFETY: TerminateProcess on own handle is always valid; intentional self-termination.
    unsafe {
        winapi::um::processthreadsapi::TerminateProcess(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            0xC000_0005,
        );
    }
    // SAFETY: Sleep(INFINITE-like) after TerminateProcess — defensive loop in case terminate is async.
    loop {
        unsafe { winapi::um::synchapi::Sleep(1000) };
    }
}

// SAFETY: Called by detour2 dispatcher with user32!SendInput ABI.
unsafe extern "system" fn hook_send_input(n: UINT, inputs: *mut INPUT, sz: i32) -> UINT {
    let Some(_g) = anti_rec::enter() else {
// Detour-absent: unwrap-abort kept on purpose — UINT family; fail-closed would be 0 ("no events inserted"), a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnSendInput ABI.
        return HOOK_SEND_INPUT.get().unwrap().call(n, inputs, sz);
    };
    let _ = _g; // guard held until report_and_kill diverges
    report_and_kill("SendInput")
}

// SAFETY: Called by detour2 dispatcher with user32!keybd_event ABI.
unsafe extern "system" fn hook_keybd_event(b: u8, s: u8, f: DWORD, ex: usize) {
    let Some(_g) = anti_rec::enter() else {
// Detour-absent: unwrap-abort kept on purpose — void family; fail-closed would be an early `return`, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnKeybdEvent ABI.
        HOOK_KEYBD_EVENT.get().unwrap().call(b, s, f, ex);
        return;
    };
    let _ = _g;
    report_and_kill("keybd_event")
}

// SAFETY: Called by detour2 dispatcher with user32!mouse_event ABI.
unsafe extern "system" fn hook_mouse_event(f: DWORD, x: DWORD, y: DWORD, d: DWORD, ex: usize) {
    let Some(_g) = anti_rec::enter() else {
// Detour-absent: unwrap-abort kept on purpose — void family; fail-closed would be an early `return`, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnMouseEvent ABI.
        HOOK_MOUSE_EVENT.get().unwrap().call(f, x, y, d, ex);
        return;
    };
    let _ = _g;
    report_and_kill("mouse_event")
}

// SAFETY: Called by detour2 dispatcher with user32!BlockInput ABI.
unsafe extern "system" fn hook_block_input(fblock: BOOL) -> BOOL {
    let Some(_g) = anti_rec::enter() else {
// Detour-absent: unwrap-abort kept on purpose — BOOL family; fail-closed would be FALSE, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnBlockInput ABI.
        return HOOK_BLOCK_INPUT.get().unwrap().call(fblock);
    };
    let _ = _g;
    report_and_kill("BlockInput")
}

// SAFETY: Called by detour2 dispatcher with user32!SetCursorPos ABI.
unsafe extern "system" fn hook_set_cursor_pos(x: i32, y: i32) -> BOOL {
    let Some(_g) = anti_rec::enter() else {
// Detour-absent: unwrap-abort kept on purpose — BOOL family; fail-closed would be FALSE, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnSetCursorPos ABI.
        return HOOK_SET_CURSOR_POS.get().unwrap().call(x, y);
    };
    let _ = _g;
    report_and_kill("SetCursorPos")
}

// SAFETY: Called by detour2 dispatcher with win32u!NtUserSendInput ABI.
// Same signature as user32!SendInput (UINT, PINPUT, int) — identical
// input-synthesis primitive one stub lower.
unsafe extern "system" fn hook_nt_user_send_input(n: UINT, inputs: *mut INPUT, sz: i32) -> UINT {
    let Some(_g) = anti_rec::enter() else {
// Detour-absent: unwrap-abort kept on purpose — UINT family; fail-closed would be 0 ("no events inserted"), a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnNtUserSendInput ABI.
        return HOOK_NT_USER_SEND_INPUT.get().unwrap().call(n, inputs, sz);
    };
    let _ = _g;
    report_and_kill("NtUserSendInput")
}

// ── Cross-window / clipboard soft-deny ─────────────────────────────────────

// NOTE: FindWindow*/PostMessage*/SendMessage* hooks are best-effort. On
// Win10 19045 the kernel routes some user32 entries through win32u.dll
// bypassing our user-mode patch. SendInput-class hooks (the actual Win+R
// vector) work reliably. Job UI restrictions cover the rest in principle.

// SAFETY: Called by detour2 dispatcher with user32!FindWindowW ABI.
unsafe extern "system" fn hook_find_window_w(class: LPCWSTR, name: LPCWSTR) -> HWND {
    let Some(_g) = anti_rec::enter() else {
// Detour-absent: unwrap-abort kept on purpose — HWND family; fail-closed would be NULL, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnFindWindowW ABI.
        return HOOK_FIND_WINDOW_W.get().unwrap().call(class, name);
    };
// Detour-absent: unwrap-abort kept on purpose — HWND family; fail-closed would be NULL, a per-API decision (see nt_call_original in hooks.rs).
    // SAFETY: detour2 trampoline matches FnFindWindowW ABI; same args passed through.
    let hwnd = HOOK_FIND_WINDOW_W.get().unwrap().call(class, name);
    if f3_denied(unsafe { classify_hwnd(hwnd) }, "FindWindowW") {
        return std::ptr::null_mut();
    }
    hwnd
}

// SAFETY: Called by detour2 dispatcher with user32!FindWindowA ABI.
unsafe extern "system" fn hook_find_window_a(class: LPCSTR, name: LPCSTR) -> HWND {
    let Some(_g) = anti_rec::enter() else {
// Detour-absent: unwrap-abort kept on purpose — HWND family; fail-closed would be NULL, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnFindWindowA ABI.
        return HOOK_FIND_WINDOW_A.get().unwrap().call(class, name);
    };
// Detour-absent: unwrap-abort kept on purpose — HWND family; fail-closed would be NULL, a per-API decision (see nt_call_original in hooks.rs).
    // SAFETY: detour2 trampoline matches FnFindWindowA ABI; same args passed through.
    let hwnd = HOOK_FIND_WINDOW_A.get().unwrap().call(class, name);
    if f3_denied(unsafe { classify_hwnd(hwnd) }, "FindWindowA") {
        return std::ptr::null_mut();
    }
    hwnd
}

// SAFETY: Called by detour2 dispatcher with user32!FindWindowExW ABI.
unsafe extern "system" fn hook_find_window_ex_w(
    parent: HWND, child: HWND, class: LPCWSTR, name: LPCWSTR,
) -> HWND {
    let Some(_g) = anti_rec::enter() else {
// Detour-absent: unwrap-abort kept on purpose — HWND family; fail-closed would be NULL, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnFindWindowExW ABI.
        return HOOK_FIND_WINDOW_EX_W.get().unwrap().call(parent, child, class, name);
    };
// Detour-absent: unwrap-abort kept on purpose — HWND family; fail-closed would be NULL, a per-API decision (see nt_call_original in hooks.rs).
    // SAFETY: detour2 trampoline matches FnFindWindowExW ABI; same args passed through.
    let hwnd = HOOK_FIND_WINDOW_EX_W.get().unwrap().call(parent, child, class, name);
    if f3_denied(unsafe { classify_hwnd(hwnd) }, "FindWindowExW") {
        return std::ptr::null_mut();
    }
    hwnd
}

// SAFETY: Called by detour2 dispatcher with user32!FindWindowExA ABI.
unsafe extern "system" fn hook_find_window_ex_a(
    parent: HWND, child: HWND, class: LPCSTR, name: LPCSTR,
) -> HWND {
    let Some(_g) = anti_rec::enter() else {
// Detour-absent: unwrap-abort kept on purpose — HWND family; fail-closed would be NULL, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnFindWindowExA ABI.
        return HOOK_FIND_WINDOW_EX_A.get().unwrap().call(parent, child, class, name);
    };
// Detour-absent: unwrap-abort kept on purpose — HWND family; fail-closed would be NULL, a per-API decision (see nt_call_original in hooks.rs).
    // SAFETY: detour2 trampoline matches FnFindWindowExA ABI; same args passed through.
    let hwnd = HOOK_FIND_WINDOW_EX_A.get().unwrap().call(parent, child, class, name);
    if f3_denied(unsafe { classify_hwnd(hwnd) }, "FindWindowExA") {
        return std::ptr::null_mut();
    }
    hwnd
}

// SAFETY: Called by detour2 dispatcher with user32!OpenClipboard ABI.
// Two modes:
//   - FS_SANDBOX_STRICT_CLIPBOARD=1: deny (return 0). Used by `--strict-clipboard`.
//   - otherwise: trace-log args + return value, then forward. Lets escape
//     forensics see clipboard activity (and clipboard-FAILURE codepaths)
//     without altering behaviour.
unsafe extern "system" fn hook_open_clipboard(hwnd: HWND) -> BOOL {
    let Some(_g) = anti_rec::enter() else {
// Detour-absent: unwrap-abort kept on purpose — BOOL family; fail-closed would be FALSE, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnOpenClipboard ABI.
        return HOOK_OPEN_CLIPBOARD.get().unwrap().call(hwnd);
    };
    if STRICT_CLIPBOARD.load(std::sync::atomic::Ordering::Relaxed) {
        log_soft_deny("OpenClipboard", "denied");
        return 0;
    }
// Detour-absent: unwrap-abort kept on purpose — BOOL family; fail-closed would be FALSE, a per-API decision (see nt_call_original in hooks.rs).
    // SAFETY: detour2 trampoline matches FnOpenClipboard ABI.
    let ret = HOOK_OPEN_CLIPBOARD.get().unwrap().call(hwnd);
    if is_trace() {
        let err = if ret == 0 {
            winapi::um::errhandlingapi::GetLastError()
        } else {
            0
        };
        ipc_log(ipc::LogLevel::Trace,
            format!("OpenClipboard(hwnd={hwnd:p}) -> {ret} last_err={err}"));
    }
    ret
}

// SAFETY: Called by detour2 dispatcher with user32!GetClipboardData ABI.
unsafe extern "system" fn hook_get_clipboard_data(format: UINT) -> HANDLE {
    let Some(_g) = anti_rec::enter() else {
// Detour-absent: unwrap-abort kept on purpose — HANDLE family; fail-closed would be NULL, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnGetClipboardData ABI.
        return HOOK_GET_CLIPBOARD.get().unwrap().call(format);
    };
    if STRICT_CLIPBOARD.load(std::sync::atomic::Ordering::Relaxed) {
        log_soft_deny("GetClipboardData", "denied");
        return std::ptr::null_mut();
    }
// Detour-absent: unwrap-abort kept on purpose — HANDLE family; fail-closed would be NULL, a per-API decision (see nt_call_original in hooks.rs).
    // SAFETY: detour2 trampoline matches FnGetClipboardData ABI.
    let ret = HOOK_GET_CLIPBOARD.get().unwrap().call(format);
    if is_trace() {
        let err = if ret.is_null() {
            winapi::um::errhandlingapi::GetLastError()
        } else {
            0
        };
        if ret.is_null() {
            // On failure, enumerate every format currently on the clipboard.
            // ERROR_INVALID_HANDLE on GetClipboardData usually means the
            // requested format isn't published — knowing what IS there tells
            // us whether the source app uses a different format vs. nothing
            // landing on the clipboard at all (cross-process / cross-job
            // visibility problem).
            let mut fmts: Vec<u32> = Vec::with_capacity(16);
            let mut f: u32 = 0;
            loop {
                // SAFETY: FFI; EnumClipboardFormats with the previous format
                // returns the next one, or 0 at end.
                f = winapi::um::winuser::EnumClipboardFormats(f);
                if f == 0 { break; }
                fmts.push(f);
                if fmts.len() >= 32 { break; }
            }
            ipc_log(ipc::LogLevel::Trace,
                format!("GetClipboardData(format={format}) -> NULL last_err={err} available_formats={fmts:?}"));
        } else {
            ipc_log(ipc::LogLevel::Trace,
                format!("GetClipboardData(format={format}) -> {ret:p} last_err={err}"));
        }
    }
    ret
}

// SAFETY: Called by detour2 dispatcher with user32!PostMessageW ABI.
unsafe extern "system" fn hook_post_message_w(
    hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM,
) -> BOOL {
    let Some(_g) = anti_rec::enter() else {
// Detour-absent: unwrap-abort kept on purpose — BOOL family; fail-closed would be FALSE, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnPostMessageW ABI.
        return HOOK_POST_MESSAGE_W.get().unwrap().call(hwnd, msg, wparam, lparam);
    };
    if f3_denied(unsafe { classify_hwnd(hwnd) }, "PostMessageW") {
        return 0;
    }
// Detour-absent: unwrap-abort kept on purpose — BOOL family; fail-closed would be FALSE, a per-API decision (see nt_call_original in hooks.rs).
    HOOK_POST_MESSAGE_W.get().unwrap().call(hwnd, msg, wparam, lparam)
}

// SAFETY: Called by detour2 dispatcher with user32!PostMessageA ABI.
unsafe extern "system" fn hook_post_message_a(
    hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM,
) -> BOOL {
    let Some(_g) = anti_rec::enter() else {
// Detour-absent: unwrap-abort kept on purpose — BOOL family; fail-closed would be FALSE, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnPostMessageA ABI.
        return HOOK_POST_MESSAGE_A.get().unwrap().call(hwnd, msg, wparam, lparam);
    };
    if f3_denied(unsafe { classify_hwnd(hwnd) }, "PostMessageA") {
        return 0;
    }
// Detour-absent: unwrap-abort kept on purpose — BOOL family; fail-closed would be FALSE, a per-API decision (see nt_call_original in hooks.rs).
    HOOK_POST_MESSAGE_A.get().unwrap().call(hwnd, msg, wparam, lparam)
}

/// F1 (R04) decision seam for `hook_send_message_w`: the F3
/// HWND-classification decision and its soft-deny log run under an anti_rec
/// window this
/// function opens and closes. The real SendMessageW runs the target window
/// procedure synchronously on this thread — guest-reachable application
/// code — so the hook must invoke it only AFTER this returns, with the
/// window closed: a hooked call made from inside that wndproc gets a fresh
/// policy check instead of stale suppression (anti_rec invariant 3).
///
/// Returns `true` when the message must be soft-denied (already logged
/// in-window). `false` means the original must be invoked; this includes
/// the re-entrancy passthrough — when an outer hook window is already held
/// on this thread (`anti_rec::enter()` returns `None`) this returns `false`
/// unchecked, so the original still runs under that outer window exactly as
/// before the split.
///
/// # SAFETY
/// `hwnd` may be any HWND value; `classify_hwnd` handles null (as
/// `HwndClass::NoTarget`) and the special pseudo-constants (as
/// `HwndClass::SpecialDest`) internally.
unsafe fn send_message_w_deny(hwnd: HWND) -> bool {
    let Some(_g) = anti_rec::enter() else {
        return false;
    };
    f3_denied(unsafe { classify_hwnd(hwnd) }, "SendMessageW")
}

// SAFETY: Called by detour2 dispatcher with user32!SendMessageW ABI.
unsafe extern "system" fn hook_send_message_w(
    hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM,
) -> isize {
    if send_message_w_deny(hwnd) {
        return 0;
    }
// Detour-absent: unwrap-abort kept on purpose — LRESULT family; fail-closed would be 0, a per-API decision (see nt_call_original in hooks.rs).
    // SAFETY: detour2 trampoline matches FnSendMessageW ABI.
    // F1 (R04): no anti_rec window is held here — send_message_w_deny closed
    // it. SendMessageW runs the target window procedure synchronously in
    // this thread's frame; a hooked call from that code must run a fresh
    // policy check.
    HOOK_SEND_MESSAGE_W.get().unwrap().call(hwnd, msg, wparam, lparam)
}

/// F1 (R04) decision seam for `hook_send_message_a`: the F3
/// HWND-classification decision and its soft-deny log run under an anti_rec
/// window this
/// function opens and closes. The real SendMessageA runs the target window
/// procedure synchronously on this thread — guest-reachable application
/// code — so the hook must invoke it only AFTER this returns, with the
/// window closed: a hooked call made from inside that wndproc gets a fresh
/// policy check instead of stale suppression (anti_rec invariant 3).
///
/// Returns `true` when the message must be soft-denied (already logged
/// in-window). `false` means the original must be invoked; this includes
/// the re-entrancy passthrough — when an outer hook window is already held
/// on this thread (`anti_rec::enter()` returns `None`) this returns `false`
/// unchecked, so the original still runs under that outer window exactly as
/// before the split.
///
/// # SAFETY
/// `hwnd` may be any HWND value; `classify_hwnd` handles null (as
/// `HwndClass::NoTarget`) and the special pseudo-constants (as
/// `HwndClass::SpecialDest`) internally.
unsafe fn send_message_a_deny(hwnd: HWND) -> bool {
    let Some(_g) = anti_rec::enter() else {
        return false;
    };
    f3_denied(unsafe { classify_hwnd(hwnd) }, "SendMessageA")
}

// SAFETY: Called by detour2 dispatcher with user32!SendMessageA ABI.
unsafe extern "system" fn hook_send_message_a(
    hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM,
) -> isize {
    if send_message_a_deny(hwnd) {
        return 0;
    }
// Detour-absent: unwrap-abort kept on purpose — LRESULT family; fail-closed would be 0, a per-API decision (see nt_call_original in hooks.rs).
    // SAFETY: detour2 trampoline matches FnSendMessageA ABI.
    // F1 (R04): no anti_rec window is held here — send_message_a_deny closed
    // it. SendMessageA runs the target window procedure synchronously in
    // this thread's frame; a hooked call from that code must run a fresh
    // policy check.
    HOOK_SEND_MESSAGE_A.get().unwrap().call(hwnd, msg, wparam, lparam)
}

// SAFETY: Called by detour2 dispatcher with user32!ExitWindowsEx ABI.
//
// Hard-deny logoff/shutdown from a sandboxed process. The Job-Object
// `JOB_OBJECT_UILIMIT_EXITWINDOWS` bit, which used to enforce this at the
// kernel level, was dropped from the default set because it empirically
// blocks cross-process clipboard PASTE (GetClipboardData returns NULL
// with ERROR_INVALID_HANDLE on data published by a non-sandboxed source).
// This user-mode hook restores the protection: a sandboxed AI agent
// cannot ExitWindowsEx the user's session. SetLastError(ERROR_ACCESS_DENIED)
// makes the failure observable to callers that inspect GetLastError.
unsafe extern "system" fn hook_exit_windows_ex(flags: UINT, reason: DWORD) -> BOOL {
    let Some(_g) = anti_rec::enter() else {
// Detour-absent: unwrap-abort kept on purpose — BOOL family; fail-closed would be FALSE, a per-API decision (see nt_call_original in hooks.rs).
        // SAFETY: detour2 trampoline matches FnExitWindowsEx ABI.
        return HOOK_EXIT_WINDOWS_EX.get().unwrap().call(flags, reason);
    };
    if is_trace() {
        ipc_log(ipc::LogLevel::Warn,
            format!("ExitWindowsEx denied: flags=0x{flags:x} reason=0x{reason:x}"));
    }
    winapi::um::errhandlingapi::SetLastError(5); // ERROR_ACCESS_DENIED
    0
}

/// # SAFETY
/// Must be called from install_hooks() in DllMain context with anti_rec entered.
pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    // Resolve user32 module — load if not already loaded.
    let user32_w: Vec<u16> = "user32.dll\0".encode_utf16().collect();
    // SAFETY: FFI call to LoadLibraryW with null-terminated wide string; no outstanding borrows.
    let user32 = winapi::um::libloaderapi::LoadLibraryW(user32_w.as_ptr());
    if user32.is_null() {
        return Err("LoadLibraryW(user32.dll) failed".into());
    }

    // ui is the one OPTIONAL hook category: a failed install never aborts
    // startup, but every failure mode is buffered so the degradation is
    // observable (S10 degraded-init event + first-Hello flush) instead of
    // being silently swallowed.
    macro_rules! install {
        ($lock:expr, $sym:literal, $hook:ident, $ty:ty) => {{
            let addr = winapi::um::libloaderapi::GetProcAddress(
                user32, concat!($sym, "\0").as_ptr() as *const _);
            if !addr.is_null() {
                // SAFETY: transmute of GetProcAddress result; ABI matches the hook function type $ty.
                let target: $ty = std::mem::transmute(addr as usize);
                let hook_ptr: $ty = $hook;
                match GenericDetour::<$ty>::new(target, hook_ptr) {
                    Ok(detour) => {
                        $lock.set(detour).ok();
                        if let Some(d) = $lock.get() {
                            if let Err(e) = d.enable() {
                                buffer_install_error(
                                    format!("ui_guard: detour enable {}: {:?}", $sym, e));
                            }
                        }
                    }
                    Err(e) => buffer_install_error(
                        format!("ui_guard: detour init {}: {:?}", $sym, e)),
                }
            } else {
                buffer_install_error(format!("ui_guard: export not found: {}", $sym));
            }
        }};
    }

    // Same as `install!` but for a module handle resolved elsewhere
    // (win32u.dll is not ntdll and not the user32 handle above).
    macro_rules! install_from {
        ($mod_:expr, $lock:expr, $sym:literal, $hook:ident, $ty:ty) => {{
            let addr = winapi::um::libloaderapi::GetProcAddress(
                $mod_, concat!($sym, "\0").as_ptr() as *const _);
            if !addr.is_null() {
                // SAFETY: transmute of GetProcAddress result; ABI matches the hook function type $ty.
                let target: $ty = std::mem::transmute(addr as usize);
                let hook_ptr: $ty = $hook;
                match GenericDetour::<$ty>::new(target, hook_ptr) {
                    Ok(detour) => {
                        $lock.set(detour).ok();
                        if let Some(d) = $lock.get() {
                            if let Err(e) = d.enable() {
                                buffer_install_error(
                                    format!("ui_guard: detour enable {}: {:?}", $sym, e));
                            }
                        }
                    }
                    Err(e) => buffer_install_error(
                        format!("ui_guard: detour init {}: {:?}", $sym, e)),
                }
            } else {
                buffer_install_error(format!("ui_guard: export not found: {}", $sym));
            }
        }};
    }

    install!(HOOK_SEND_INPUT,     "SendInput",     hook_send_input,     FnSendInput);
    install!(HOOK_KEYBD_EVENT,    "keybd_event",   hook_keybd_event,    FnKeybdEvent);
    install!(HOOK_MOUSE_EVENT,    "mouse_event",   hook_mouse_event,    FnMouseEvent);
    install!(HOOK_BLOCK_INPUT,    "BlockInput",    hook_block_input,    FnBlockInput);
    install!(HOOK_SET_CURSOR_POS, "SetCursorPos",  hook_set_cursor_pos, FnSetCursorPos);

    install!(HOOK_FIND_WINDOW_W,    "FindWindowW",      hook_find_window_w,      FnFindWindowW);
    install!(HOOK_FIND_WINDOW_A,    "FindWindowA",      hook_find_window_a,      FnFindWindowA);
    install!(HOOK_FIND_WINDOW_EX_W, "FindWindowExW",    hook_find_window_ex_w,   FnFindWindowExW);
    install!(HOOK_FIND_WINDOW_EX_A, "FindWindowExA",    hook_find_window_ex_a,   FnFindWindowExA);

    // Clipboard hooks are installed ONLY under FS_SANDBOX_STRICT_CLIPBOARD.
    // In the default mode the system clipboard path is left fully untouched
    // — a previous always-on-trace variant turned out to interfere with
    // cross-process clipboard reads (LastError trampling / anti_rec
    // contention in the hot path corrupted the caller's view of
    // GetClipboardData's outcome), reproducibly breaking PASTE from
    // non-sandboxed apps into sandboxed wezterm. Forensic tracing is
    // available by setting FS_SANDBOX_STRICT_CLIPBOARD=1 (which also
    // hard-denies) for cases that genuinely need it.
    let strict_clipboard = std::env::var("FS_SANDBOX_STRICT_CLIPBOARD")
        .as_deref() == Ok("1");
    STRICT_CLIPBOARD.store(strict_clipboard, std::sync::atomic::Ordering::Relaxed);
    if strict_clipboard {
        install!(HOOK_OPEN_CLIPBOARD,   "OpenClipboard",    hook_open_clipboard,     FnOpenClipboard);
        install!(HOOK_GET_CLIPBOARD,    "GetClipboardData", hook_get_clipboard_data, FnGetClipboardData);
    }

    install!(HOOK_POST_MESSAGE_W,   "PostMessageW",     hook_post_message_w,     FnPostMessageW);
    install!(HOOK_POST_MESSAGE_A,   "PostMessageA",     hook_post_message_a,     FnPostMessageA);
    install!(HOOK_SEND_MESSAGE_W,   "SendMessageW",     hook_send_message_w,     FnSendMessageW);
    install!(HOOK_SEND_MESSAGE_A,   "SendMessageA",     hook_send_message_a,     FnSendMessageA);
    install!(HOOK_EXIT_WINDOWS_EX,  "ExitWindowsEx",    hook_exit_windows_ex,    FnExitWindowsEx);

    // win32u.dll — audit High sibling closure for SendInput. Present since
    // Win10 1809; on older builds there is no win32u path to guard, so a
    // missing module/export is buffered (consistent with the install!
    // macro) — an unguarded NtUserSendInput is a real coverage gap.
    let win32u_w: Vec<u16> = "win32u.dll\0".encode_utf16().collect();
    // SAFETY: LoadLibraryW with a null-terminated wide name; win32u is a
    // KnownDLL on Win10 1809+ and always loadable.
    let win32u = winapi::um::libloaderapi::LoadLibraryW(win32u_w.as_ptr());
    if !win32u.is_null() {
        install_from!(win32u, HOOK_NT_USER_SEND_INPUT, "NtUserSendInput",
                      hook_nt_user_send_input, FnNtUserSendInput);
    } else {
        buffer_install_error(
            "ui_guard: win32u.dll not loaded — NtUserSendInput unguarded".into(),
        );
    }
    Ok(())
}

/// # SAFETY
/// Must be called from DLL_PROCESS_DETACH only.
pub unsafe fn uninstall() {
    if let Some(h) = HOOK_SEND_INPUT.get()     { let _ = h.disable(); }
    if let Some(h) = HOOK_KEYBD_EVENT.get()    { let _ = h.disable(); }
    if let Some(h) = HOOK_MOUSE_EVENT.get()    { let _ = h.disable(); }
    if let Some(h) = HOOK_BLOCK_INPUT.get()    { let _ = h.disable(); }
    if let Some(h) = HOOK_SET_CURSOR_POS.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_FIND_WINDOW_W.get()    { let _ = h.disable(); }
    if let Some(h) = HOOK_FIND_WINDOW_A.get()    { let _ = h.disable(); }
    if let Some(h) = HOOK_FIND_WINDOW_EX_W.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_FIND_WINDOW_EX_A.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_OPEN_CLIPBOARD.get()   { let _ = h.disable(); }
    if let Some(h) = HOOK_GET_CLIPBOARD.get()    { let _ = h.disable(); }
    if let Some(h) = HOOK_POST_MESSAGE_W.get()   { let _ = h.disable(); }
    if let Some(h) = HOOK_POST_MESSAGE_A.get()   { let _ = h.disable(); }
    if let Some(h) = HOOK_SEND_MESSAGE_W.get()   { let _ = h.disable(); }
    if let Some(h) = HOOK_SEND_MESSAGE_A.get()   { let _ = h.disable(); }
    if let Some(h) = HOOK_EXIT_WINDOWS_EX.get()  { let _ = h.disable(); }
    if let Some(h) = HOOK_NT_USER_SEND_INPUT.get() { let _ = h.disable(); }
}

/// Exports this module installs detours on. Kept in lockstep with install()
/// — the sibling-drift check in hooks.rs verifies every name here still
/// appears as an install literal in this file, and that guarded families
/// have no unhooked siblings.
pub(crate) const HOOKED_EXPORTS: &[&str] = &[
    "SendInput",
    "keybd_event",
    "mouse_event",
    "BlockInput",
    "SetCursorPos",
    "FindWindowW",
    "FindWindowA",
    "FindWindowExW",
    "FindWindowExA",
    "OpenClipboard",
    "GetClipboardData",
    "PostMessageW",
    "PostMessageA",
    "SendMessageW",
    "SendMessageA",
    "ExitWindowsEx",
    "NtUserSendInput",
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Export-name tripwire for the win32u sibling: win32u!NtUserSendInput
    /// must resolve on supported hosts (Win10 1809+). A typo in the install
    /// literal would silently skip the detour (the install macros log-and-
    /// skip), which is exactly the sibling-drift this module existed to
    /// close — so the resolution is pinned in CI.
    #[test]
    fn win32u_send_input_export_resolves() {
        let win32u_w: Vec<u16> = "win32u.dll\0".encode_utf16().collect();
        // SAFETY: LoadLibraryW / GetProcAddress pair over a system DLL.
        unsafe {
            let h = winapi::um::libloaderapi::LoadLibraryW(win32u_w.as_ptr());
            assert!(!h.is_null(), "win32u.dll must load on Win10 1809+");
            let addr = winapi::um::libloaderapi::GetProcAddress(
                h, b"NtUserSendInput\0".as_ptr() as *const _,
            );
            assert!(!addr.is_null(), "win32u!NtUserSendInput must resolve");
        }
    }

    /// Same tripwire for the guarded user32 base of the family.
    #[test]
    fn user32_send_input_export_resolves() {
        let user32_w: Vec<u16> = "user32.dll\0".encode_utf16().collect();
        // SAFETY: LoadLibraryW / GetProcAddress pair over a system DLL.
        unsafe {
            let h = winapi::um::libloaderapi::LoadLibraryW(user32_w.as_ptr());
            assert!(!h.is_null(), "user32.dll must load");
            let addr = winapi::um::libloaderapi::GetProcAddress(
                h, b"SendInput\0".as_ptr() as *const _,
            );
            assert!(!addr.is_null(), "user32!SendInput must resolve");
        }
    }

    /// The SendInput family policy: both entry points route to the same
    /// kill path (`report_and_kill`), which must never be driven from a
    /// unit test (it terminates the process). The kill decision for this
    /// family is unconditional — AI agents never legitimately synthesize
    /// input — so the falsifiable assertions here are (a) the win32u
    /// entry resolves and (b) the hook storage exists and is wired in
    /// install()/uninstall(), which the sibling-drift check pins.
    #[test]
    fn nt_user_send_input_hook_storage_declared() {
        // Not installed under tests: the OnceLock must be EMPTY here. If
        // someone ever auto-installs hooks at test time, this flags it —
        // a populated slot would make the direct-call kill path reachable
        // from tests.
        assert!(
            HOOK_NT_USER_SEND_INPUT.get().is_none(),
            "win32u hook must not be installed under unit tests"
        );
    }

    /// F1 (R04): the W decision seam must close its anti_rec window before
    /// returning on the allow path, so the trampoline runs with no window
    /// held. The decisive assertion is the nested `enter()` below: it
    /// simulates a hooked call made from inside the target window procedure
    /// (dispatched synchronously by the real SendMessageW) and must be able
    /// to open its own window for a fresh policy check — pre-F1 it returned
    /// `None` (stale suppression). Null HWND classifies as `HwndClass::NoTarget`
    /// and stays allowed by design, so this exercises the allow path only;
    /// the deny path needs a real foreign window handle and is not unit-testable.
    #[test]
    fn send_message_w_deny_seam_closes_window_on_allow() {
        assert!(!crate::anti_rec::in_hook(), "precondition: no window held");
        let null_hwnd: HWND = std::ptr::null_mut();
        let denied = unsafe { send_message_w_deny(null_hwnd) };
        assert!(!denied);
        assert!(
            !crate::anti_rec::in_hook(),
            "window must be closed at the call-original boundary"
        );
        let nested = crate::anti_rec::enter().expect(
            "nested hook call must not be suppressed after the seam closed the window",
        );
        drop(nested);
        assert!(!crate::anti_rec::in_hook());
    }

    /// Same F1 (R04) contract for the A twin of the decision seam.
    #[test]
    fn send_message_a_deny_seam_closes_window_on_allow() {
        assert!(!crate::anti_rec::in_hook(), "precondition: no window held");
        let null_hwnd: HWND = std::ptr::null_mut();
        let denied = unsafe { send_message_a_deny(null_hwnd) };
        assert!(!denied);
        assert!(
            !crate::anti_rec::in_hook(),
            "window must be closed at the call-original boundary"
        );
        let nested = crate::anti_rec::enter().expect(
            "nested hook call must not be suppressed after the seam closed the window",
        );
        drop(nested);
        assert!(!crate::anti_rec::in_hook());
    }

    /// F1 (R04): the recursion breaker is preserved — under an outer hook
    /// window the seam returns `false` unchecked (passthrough), so the
    /// original still runs under that outer window exactly as pre-F1.
    #[test]
    fn send_message_w_deny_seam_passthrough_when_window_already_held() {
        assert!(!crate::anti_rec::in_hook(), "precondition: no window held");
        let outer =
            crate::anti_rec::enter().expect("test thread must not be re-entrant");
        let null_hwnd: HWND = std::ptr::null_mut();
        let denied = unsafe { send_message_w_deny(null_hwnd) };
        assert!(!denied);
        drop(outer);
        assert!(!crate::anti_rec::in_hook());
    }

    /// Same passthrough contract for the A twin of the decision seam.
    #[test]
    fn send_message_a_deny_seam_passthrough_when_window_already_held() {
        assert!(!crate::anti_rec::in_hook(), "precondition: no window held");
        let outer =
            crate::anti_rec::enter().expect("test thread must not be re-entrant");
        let null_hwnd: HWND = std::ptr::null_mut();
        let denied = unsafe { send_message_a_deny(null_hwnd) };
        assert!(!denied);
        drop(outer);
        assert!(!crate::anti_rec::in_hook());
    }

    /// F3 test fixtures — PIDs disjoint from every other tracker fixture.
    const F3_TEST_CHILD_PID: u32 = 0x5EED_5F30;
    const F3_TEST_FOREIGN_PID: u32 = 0x5EED_5F31;

    /// F3: the documented pseudo-destinations must classify as their own
    /// `SpecialDest` case (and NULL as `NoTarget`) — not silently merged into
    /// "allowed" or "foreign". classify_special answers before any OS query, so
    /// this is fully deterministic.
    #[test]
    fn f3_special_destinations_classify_distinctly() {
        let null_hwnd: HWND = std::ptr::null_mut();
        let broadcast = 0xFFFFusize as HWND;  // winuser!HWND_BROADCAST
        let topmost   = (-1isize) as HWND;    // winuser!HWND_TOPMOST
        let notopmost = (-2isize) as HWND;    // winuser!HWND_NOTOPMOST
        let message   = (-3isize) as HWND;    // winuser!HWND_MESSAGE
        assert_eq!(unsafe { classify_hwnd(null_hwnd) }, HwndClass::NoTarget);
        assert_eq!(unsafe { classify_hwnd(broadcast) }, HwndClass::SpecialDest);
        assert_eq!(unsafe { classify_hwnd(topmost) }, HwndClass::SpecialDest);
        assert_eq!(unsafe { classify_hwnd(notopmost) }, HwndClass::SpecialDest);
        assert_eq!(unsafe { classify_hwnd(message) }, HwndClass::SpecialDest);
    }

    /// F3: an own-sandbox child PID (tracked via process_tracker, the same
    /// membership-only fixture convention every tracker test uses) classifies
    /// as `OwnSandbox` — distinctly from an untracked foreign PID — and falls
    /// back to `Foreign` once untracked. Drives `classify_pid`, the pure
    /// decision core, so no foreign window needs to exist.
    #[test]
    fn f3_sandbox_child_classifies_distinctly_from_foreign() {
        let own = unsafe { winapi::um::processthreadsapi::GetCurrentProcessId() };
        assert_eq!(classify_pid(own), HwndClass::OwnSandbox, "own PID is the sandbox root");
        crate::process_tracker::mark_spawned(F3_TEST_CHILD_PID, 1, "f3_test_child.exe".into(), 0);
        assert_eq!(
            classify_pid(F3_TEST_CHILD_PID),
            HwndClass::OwnSandbox,
            "tracked sandbox child must be its own class, not Foreign"
        );
        assert_eq!(classify_pid(F3_TEST_FOREIGN_PID), HwndClass::Foreign);
        crate::process_tracker::untrack(F3_TEST_CHILD_PID);
        assert_eq!(
            classify_pid(F3_TEST_CHILD_PID),
            HwndClass::Foreign,
            "after untrack the PID must fall back to Foreign"
        );
        assert_eq!(classify_pid(0), HwndClass::Unknown, "failed lookup is Unknown");
    }

    /// F3: "unknown identity для опасного действия не должна считаться safe".
    /// NULL keeps its narrow allow (own-thread queue / documented no-op —
    /// required so F1's null-HWND seam tests stay valid); a genuinely
    /// unresolvable non-special HWND must NOT get that outcome, nor may a
    /// special destination or a foreign one.
    #[test]
    fn f3_unknown_is_denied_not_null_allow() {
        assert!(!f3_denied(HwndClass::NoTarget, "SendMessageW"));
        assert!(f3_denied(HwndClass::Unknown, "SendMessageW"));
        assert!(f3_denied(HwndClass::SpecialDest, "PostMessageW"));
        assert!(f3_denied(HwndClass::Foreign, "FindWindowW"));
    }

    /// F3: the real FFI path — GetWindowThreadProcessId on a live own-process
    /// window — must classify as `OwnSandbox`. A message-only window (parent
    /// HWND_MESSAGE) is used: never visible, no pump needed for classification.
    #[test]
    fn f3_real_own_window_classifies_own_sandbox() {
        let class_name: Vec<u16> = "winrsbox_ui_guard_f3_test\0".encode_utf16().collect();
        // SAFETY: WNDCLASSW is plain-data FFI input; all-zero is a valid value.
        let mut wc: winapi::um::winuser::WNDCLASSW = unsafe { std::mem::zeroed() };
        wc.lpfnWndProc = Some(winapi::um::winuser::DefWindowProcW);
        wc.lpszClassName = class_name.as_ptr();
        // SAFETY: wc points to a fully initialized WNDCLASSW whose strings
        // outlive the RegisterClassW call.
        let atom = unsafe { winapi::um::winuser::RegisterClassW(&wc) };
        assert_ne!(atom, 0, "RegisterClassW must succeed");
        // SAFETY: FFI window creation with a registered class; result checked.
        let hwnd = unsafe {
            winapi::um::winuser::CreateWindowExW(
                0,
                class_name.as_ptr(),
                std::ptr::null(),
                0,
                0, 0, 0, 0,
                winapi::um::winuser::HWND_MESSAGE,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert!(!hwnd.is_null(), "message-only window must be created");
        assert_eq!(unsafe { classify_hwnd(hwnd) }, HwndClass::OwnSandbox);
        // SAFETY: destroying a window this thread just created.
        unsafe { winapi::um::winuser::DestroyWindow(hwnd) };
    }
}
