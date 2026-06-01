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
use crate::hooks::{ipc_log, is_trace};

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

/// Returns true when `hwnd` is a window owned by a process **other** than us.
/// For cross-process HWNDs we deny PostMessage/SendMessage. Own-process
/// windows still work normally.
///
/// # SAFETY
/// `hwnd` may be any HWND value; null is handled internally.
unsafe fn is_foreign_hwnd(hwnd: HWND) -> bool {
    if hwnd.is_null() { return false; }
    let mut pid: DWORD = 0;
    let _ = winapi::um::winuser::GetWindowThreadProcessId(hwnd, &mut pid);
    if pid == 0 { return false; }
    pid != winapi::um::processthreadsapi::GetCurrentProcessId()
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
        // SAFETY: detour2 trampoline matches FnSendInput ABI.
        return HOOK_SEND_INPUT.get().unwrap().call(n, inputs, sz);
    };
    let _ = _g; // guard held until report_and_kill diverges
    report_and_kill("SendInput")
}

// SAFETY: Called by detour2 dispatcher with user32!keybd_event ABI.
unsafe extern "system" fn hook_keybd_event(b: u8, s: u8, f: DWORD, ex: usize) {
    let Some(_g) = anti_rec::enter() else {
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
        // SAFETY: detour2 trampoline matches FnBlockInput ABI.
        return HOOK_BLOCK_INPUT.get().unwrap().call(fblock);
    };
    let _ = _g;
    report_and_kill("BlockInput")
}

// SAFETY: Called by detour2 dispatcher with user32!SetCursorPos ABI.
unsafe extern "system" fn hook_set_cursor_pos(x: i32, y: i32) -> BOOL {
    let Some(_g) = anti_rec::enter() else {
        // SAFETY: detour2 trampoline matches FnSetCursorPos ABI.
        return HOOK_SET_CURSOR_POS.get().unwrap().call(x, y);
    };
    let _ = _g;
    report_and_kill("SetCursorPos")
}

// ── Cross-window / clipboard soft-deny ─────────────────────────────────────

// NOTE: FindWindow*/PostMessage*/SendMessage* hooks are best-effort. On
// Win10 19045 the kernel routes some user32 entries through win32u.dll
// bypassing our user-mode patch. SendInput-class hooks (the actual Win+R
// vector) work reliably. Job UI restrictions cover the rest in principle.

// SAFETY: Called by detour2 dispatcher with user32!FindWindowW ABI.
unsafe extern "system" fn hook_find_window_w(class: LPCWSTR, name: LPCWSTR) -> HWND {
    let Some(_g) = anti_rec::enter() else {
        // SAFETY: detour2 trampoline matches FnFindWindowW ABI.
        return HOOK_FIND_WINDOW_W.get().unwrap().call(class, name);
    };
    // SAFETY: detour2 trampoline matches FnFindWindowW ABI; same args passed through.
    let hwnd = HOOK_FIND_WINDOW_W.get().unwrap().call(class, name);
    if is_foreign_hwnd(hwnd) {
        log_soft_deny("FindWindowW", "foreign HWND");
        return std::ptr::null_mut();
    }
    hwnd
}

// SAFETY: Called by detour2 dispatcher with user32!FindWindowA ABI.
unsafe extern "system" fn hook_find_window_a(class: LPCSTR, name: LPCSTR) -> HWND {
    let Some(_g) = anti_rec::enter() else {
        // SAFETY: detour2 trampoline matches FnFindWindowA ABI.
        return HOOK_FIND_WINDOW_A.get().unwrap().call(class, name);
    };
    // SAFETY: detour2 trampoline matches FnFindWindowA ABI; same args passed through.
    let hwnd = HOOK_FIND_WINDOW_A.get().unwrap().call(class, name);
    if is_foreign_hwnd(hwnd) {
        log_soft_deny("FindWindowA", "foreign HWND");
        return std::ptr::null_mut();
    }
    hwnd
}

// SAFETY: Called by detour2 dispatcher with user32!FindWindowExW ABI.
unsafe extern "system" fn hook_find_window_ex_w(
    parent: HWND, child: HWND, class: LPCWSTR, name: LPCWSTR,
) -> HWND {
    let Some(_g) = anti_rec::enter() else {
        // SAFETY: detour2 trampoline matches FnFindWindowExW ABI.
        return HOOK_FIND_WINDOW_EX_W.get().unwrap().call(parent, child, class, name);
    };
    // SAFETY: detour2 trampoline matches FnFindWindowExW ABI; same args passed through.
    let hwnd = HOOK_FIND_WINDOW_EX_W.get().unwrap().call(parent, child, class, name);
    if is_foreign_hwnd(hwnd) {
        log_soft_deny("FindWindowExW", "foreign HWND");
        return std::ptr::null_mut();
    }
    hwnd
}

// SAFETY: Called by detour2 dispatcher with user32!FindWindowExA ABI.
unsafe extern "system" fn hook_find_window_ex_a(
    parent: HWND, child: HWND, class: LPCSTR, name: LPCSTR,
) -> HWND {
    let Some(_g) = anti_rec::enter() else {
        // SAFETY: detour2 trampoline matches FnFindWindowExA ABI.
        return HOOK_FIND_WINDOW_EX_A.get().unwrap().call(parent, child, class, name);
    };
    // SAFETY: detour2 trampoline matches FnFindWindowExA ABI; same args passed through.
    let hwnd = HOOK_FIND_WINDOW_EX_A.get().unwrap().call(parent, child, class, name);
    if is_foreign_hwnd(hwnd) {
        log_soft_deny("FindWindowExA", "foreign HWND");
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
        // SAFETY: detour2 trampoline matches FnOpenClipboard ABI.
        return HOOK_OPEN_CLIPBOARD.get().unwrap().call(hwnd);
    };
    if STRICT_CLIPBOARD.load(std::sync::atomic::Ordering::Relaxed) {
        log_soft_deny("OpenClipboard", "denied");
        return 0;
    }
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
        // SAFETY: detour2 trampoline matches FnGetClipboardData ABI.
        return HOOK_GET_CLIPBOARD.get().unwrap().call(format);
    };
    if STRICT_CLIPBOARD.load(std::sync::atomic::Ordering::Relaxed) {
        log_soft_deny("GetClipboardData", "denied");
        return std::ptr::null_mut();
    }
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
        // SAFETY: detour2 trampoline matches FnPostMessageW ABI.
        return HOOK_POST_MESSAGE_W.get().unwrap().call(hwnd, msg, wparam, lparam);
    };
    if is_foreign_hwnd(hwnd) {
        log_soft_deny("PostMessageW", "foreign HWND");
        return 0;
    }
    HOOK_POST_MESSAGE_W.get().unwrap().call(hwnd, msg, wparam, lparam)
}

// SAFETY: Called by detour2 dispatcher with user32!PostMessageA ABI.
unsafe extern "system" fn hook_post_message_a(
    hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM,
) -> BOOL {
    let Some(_g) = anti_rec::enter() else {
        // SAFETY: detour2 trampoline matches FnPostMessageA ABI.
        return HOOK_POST_MESSAGE_A.get().unwrap().call(hwnd, msg, wparam, lparam);
    };
    if is_foreign_hwnd(hwnd) {
        log_soft_deny("PostMessageA", "foreign HWND");
        return 0;
    }
    HOOK_POST_MESSAGE_A.get().unwrap().call(hwnd, msg, wparam, lparam)
}

// SAFETY: Called by detour2 dispatcher with user32!SendMessageW ABI.
unsafe extern "system" fn hook_send_message_w(
    hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM,
) -> isize {
    let Some(_g) = anti_rec::enter() else {
        // SAFETY: detour2 trampoline matches FnSendMessageW ABI.
        return HOOK_SEND_MESSAGE_W.get().unwrap().call(hwnd, msg, wparam, lparam);
    };
    if is_foreign_hwnd(hwnd) {
        log_soft_deny("SendMessageW", "foreign HWND");
        return 0;
    }
    HOOK_SEND_MESSAGE_W.get().unwrap().call(hwnd, msg, wparam, lparam)
}

// SAFETY: Called by detour2 dispatcher with user32!SendMessageA ABI.
unsafe extern "system" fn hook_send_message_a(
    hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM,
) -> isize {
    let Some(_g) = anti_rec::enter() else {
        // SAFETY: detour2 trampoline matches FnSendMessageA ABI.
        return HOOK_SEND_MESSAGE_A.get().unwrap().call(hwnd, msg, wparam, lparam);
    };
    if is_foreign_hwnd(hwnd) {
        log_soft_deny("SendMessageA", "foreign HWND");
        return 0;
    }
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

    macro_rules! install {
        ($lock:expr, $sym:literal, $hook:ident, $ty:ty) => {{
            let addr = winapi::um::libloaderapi::GetProcAddress(
                user32, concat!($sym, "\0").as_ptr() as *const _);
            if !addr.is_null() {
                // SAFETY: transmute of GetProcAddress result; ABI matches the hook function type $ty.
                let target: $ty = std::mem::transmute(addr as usize);
                let hook_ptr: $ty = $hook;
                if let Ok(detour) = GenericDetour::<$ty>::new(target, hook_ptr) {
                    $lock.set(detour).ok();
                    if let Some(d) = $lock.get() {
                        let _ = d.enable();
                    }
                }
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
}
