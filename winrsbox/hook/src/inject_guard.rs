// Inject guard — blocks cross-process injection from sandboxed processes.
//
// Hooks NtCreateThreadEx and NtQueueApcThread. Three-layer filtering:
//   1. Caller-aware: system DLLs (ntdll/kernelbase/kernel32) → allow
//   2. Deferred install: hooks activate after ARMED flag is set (post-init)
//   3. System PID whitelist: target PID < SYSTEM_PID_THRESHOLD → allow
//
// Crate versions assumed (from Cargo.toml):
//   detour  = "0.8"
//   ntapi   = "0.4"
//   winapi  = "0.3"

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use detour::GenericDetour;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES};
use winapi::ctypes::c_void;
use winapi::um::processthreadsapi::GetCurrentProcessId;

use crate::anti_rec;

// ---------------------------------------------------------------------------
// Nt* function type aliases
// ---------------------------------------------------------------------------

type FnNtCreateThreadEx = unsafe extern "system" fn(
    *mut HANDLE, u32, *mut OBJECT_ATTRIBUTES, HANDLE,
    *mut c_void, *mut c_void, u32, usize, usize, usize, *mut c_void,
) -> NTSTATUS;

type FnNtQueueApcThread = unsafe extern "system" fn(
    HANDLE, *mut c_void, *mut c_void, *mut c_void, *mut c_void,
) -> NTSTATUS;

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

static HOOK_CREATE_THREAD: OnceLock<GenericDetour<FnNtCreateThreadEx>> = OnceLock::new();
static HOOK_QUEUE_APC: OnceLock<GenericDetour<FnNtQueueApcThread>> = OnceLock::new();

// ---------------------------------------------------------------------------
// Filter 2: Deferred arming
// ---------------------------------------------------------------------------

static ARMED: AtomicBool = AtomicBool::new(false);

/// Arm inject_guard after process initialization completes.
/// Called from hooks.rs after the first IPC Hello is sent (meaning the
/// process has finished loading, CRT init, etc. and user code is running).
pub fn arm() {
    ARMED.store(true, Ordering::Release);
}

pub fn is_armed() -> bool {
    ARMED.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Filter 3: System PID whitelist
// ---------------------------------------------------------------------------

const SYSTEM_PID_THRESHOLD: u32 = 200;

pub fn is_system_pid(pid: u32) -> bool {
    pid < SYSTEM_PID_THRESHOLD
}

// ---------------------------------------------------------------------------
// Filter 1: Caller-aware — is the caller a system DLL?
// ---------------------------------------------------------------------------

const SYSTEM_DLLS: &[&str] = &[
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "ucrtbase.dll",
    "ucrtbased.dll", "msvcrt.dll", "apphelp.dll", "rpcrt4.dll",
    "hook.dll", // our own DLL — sandbox injection mechanism uses NtQueueApcThread
];

pub fn is_system_caller() -> bool {
    let stack = crate::memory_guard::capture_stack_pub(2, 16);
    if stack.is_empty() {
        return true; // can't determine → assume system
    }
    // Walk ALL stack frames. If any frame is in a non-system, non-hook module
    // (i.e., user code), this is a user-initiated call.
    for &pc in &stack {
        let path = match crate::memory_guard::module_path_for_address(pc as *const c_void) {
            Some(p) => p,
            None => return false, // anonymous frame → NOT system
        };
        let lower = path.to_ascii_lowercase();
        let basename = lower.rsplit_once('\\').map(|(_, b)| b).unwrap_or(&lower);
        if basename == "hook.dll" {
            continue;
        }
        if SYSTEM_DLLS.iter().any(|&s| s == basename) {
            continue;
        }
        // Non-system, non-hook module found → user-initiated
        return false;
    }
    true // all frames are system DLLs or hook.dll
}

// ---------------------------------------------------------------------------
// Process identity check
// ---------------------------------------------------------------------------

const NT_CURRENT_PROCESS: isize = -1;

pub fn is_self_process(handle: HANDLE) -> bool {
    if handle as isize == NT_CURRENT_PROCESS {
        return true;
    }
    if handle.is_null() {
        return false;
    }
    // SAFETY: GetProcessId is safe on any HANDLE; returns 0 on invalid handle.
    let target_pid = unsafe { winapi::um::processthreadsapi::GetProcessId(handle) };
    target_pid != 0 && target_pid == unsafe { GetCurrentProcessId() }
}

pub fn thread_owner_pid(thread_handle: HANDLE) -> u32 {
    if thread_handle.is_null() {
        return 0;
    }
    #[repr(C)]
    struct ThreadBasicInfo {
        exit_status: i32,
        _pad0: u32,
        teb_base: usize,
        client_id_process: usize,
        client_id_thread: usize,
        affinity_mask: usize,
        priority: i32,
        base_priority: i32,
    }
    let mut info: ThreadBasicInfo = unsafe { std::mem::zeroed() };
    let mut ret_len: u32 = 0;
    // SAFETY: NtQueryInformationThread returns STATUS_INVALID_HANDLE on bad handles.
    let status = unsafe {
        ntapi::ntpsapi::NtQueryInformationThread(
            thread_handle,
            0, // ThreadBasicInformation
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<ThreadBasicInfo>() as u32,
            &mut ret_len,
        )
    };
    if status >= 0 { info.client_id_process as u32 } else { 0 }
}

// ---------------------------------------------------------------------------
// Combined filter: should we block this cross-process operation?
// ---------------------------------------------------------------------------

fn should_block(target_pid: u32) -> bool {
    // Filter 2: not yet armed → allow (process still initializing)
    if !is_armed() {
        return false;
    }
    // Filter 3: system process → allow
    if is_system_pid(target_pid) {
        return false;
    }
    // Filter 1: system DLL caller → allow
    if is_system_caller() {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Report + terminate
// ---------------------------------------------------------------------------

fn report_and_terminate(kind: ipc::InjectKind, target_pid: u32, start_addr: u64) -> ! {
    let pid = unsafe { GetCurrentProcessId() };
    let stack = crate::memory_guard::capture_stack_pub(3, 16);
    let caller_pc = stack.first().copied().unwrap_or(0);
    let caller_module = crate::memory_guard::module_path_for_address(caller_pc as *const c_void);
    let exe = crate::memory_guard::get_own_exe_path_pub();

    let _ = crate::hooks::ipc_log_violation(ipc::Req::InjectionViolation {
        pid,
        exe: exe.clone(),
        kind,
        target_pid,
        start_address: start_addr,
        caller_pc,
        caller_module: caller_module.clone(),
        stack_top: stack.clone(),
    });

    let tmp = std::env::temp_dir();
    let path = tmp.join(format!("fs-sandbox-violation-{pid}.log"));
    let line = format!(
        "{{\"pid\":{pid},\"exe\":\"{}\",\"kind\":\"{kind}\",\"target_pid\":{target_pid},\"start_addr\":\"0x{start_addr:x}\",\"caller_pc\":\"0x{caller_pc:x}\"}}\n",
        exe.replace('\\', "\\\\").replace('"', "\\\""),
    );
    let _ = std::fs::write(&path, line.as_bytes());

    let msg = format!(
        "[VIOLATION] pid={pid} kind={kind} target_pid={target_pid} pc=0x{caller_pc:x}\0",
    );
    let wide: Vec<u16> = msg.encode_utf16().collect();
    // SAFETY: wide is a valid null-terminated UTF-16 string.
    unsafe { winapi::um::debugapi::OutputDebugStringW(wide.as_ptr()) };

    // SAFETY: GetCurrentProcess() always returns a valid pseudo-handle.
    unsafe {
        winapi::um::processthreadsapi::TerminateProcess(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            0xC000_0005,
        );
    }
    loop { unsafe { winapi::um::synchapi::Sleep(1000) }; }
}

// ---------------------------------------------------------------------------
// Hook implementations
// ---------------------------------------------------------------------------

unsafe extern "system" fn hook_nt_create_thread_ex(
    thread_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    process_handle: HANDLE,
    start_routine: *mut c_void,
    argument: *mut c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_size: usize,
    maximum_stack_size: usize,
    attribute_list: *mut c_void,
) -> NTSTATUS {
    let call_original = || {
        HOOK_CREATE_THREAD.get().unwrap().call(
            thread_handle, desired_access, object_attributes,
            process_handle, start_routine, argument,
            create_flags, zero_bits, stack_size, maximum_stack_size,
            attribute_list,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if !is_self_process(process_handle) {
        let target_pid = winapi::um::processthreadsapi::GetProcessId(process_handle);
        if should_block(target_pid) {
            report_and_terminate(
                ipc::InjectKind::CreateRemoteThread,
                target_pid,
                start_routine as u64,
            );
        }
    }

    call_original()
}

unsafe extern "system" fn hook_nt_queue_apc_thread(
    thread_handle: HANDLE,
    apc_routine: *mut c_void,
    apc_arg1: *mut c_void,
    apc_arg2: *mut c_void,
    apc_arg3: *mut c_void,
) -> NTSTATUS {
    let call_original = || {
        HOOK_QUEUE_APC.get().unwrap().call(
            thread_handle, apc_routine, apc_arg1, apc_arg2, apc_arg3,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    let owner_pid = thread_owner_pid(thread_handle);
    let self_pid = GetCurrentProcessId();
    if owner_pid != 0 && owner_pid != self_pid {
        if should_block(owner_pid) {
            report_and_terminate(
                ipc::InjectKind::QueueApc,
                owner_pid,
                apc_routine as u64,
            );
        }
    }

    call_original()
}

// ---------------------------------------------------------------------------
// Install / Uninstall
// ---------------------------------------------------------------------------

/// # SAFETY
/// Same constraints as memory_guard::install().
pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    macro_rules! install_guard {
        ($lock:expr, $sym:literal, $hook_fn:expr, $fn_ty:ty) => {{
            let addr = crate::hooks::ntdll_export($sym.as_bytes())
                .ok_or_else(|| format!("ntdll export not found: {}", $sym))?;
            // SAFETY: addr is the real ntdll export matching the type alias.
            let target: $fn_ty = std::mem::transmute(addr as usize);
            let hook_ptr: $fn_ty = $hook_fn;
            let detour = GenericDetour::<$fn_ty>::new(target, hook_ptr)
                .map_err(|e| format!("detour init {}: {:?}", $sym, e))?;
            $lock.set(detour).ok();
            $lock.get()
                .expect("set above")
                .enable()
                .map_err(|e| format!("detour enable {}: {:?}", $sym, e))?;
        }};
    }

    install_guard!(HOOK_CREATE_THREAD, "NtCreateThreadEx\0",  hook_nt_create_thread_ex, FnNtCreateThreadEx);
    install_guard!(HOOK_QUEUE_APC,     "NtQueueApcThread\0",  hook_nt_queue_apc_thread, FnNtQueueApcThread);

    // Hooks installed but NOT armed — will arm after first IPC Hello
    Ok(())
}

/// # SAFETY
/// Must be called from DLL_PROCESS_DETACH only.
pub unsafe fn uninstall() {
    if let Some(h) = HOOK_CREATE_THREAD.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_QUEUE_APC.get() { let _ = h.disable(); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_self_process_pseudo_handle() {
        assert!(is_self_process(-1isize as HANDLE));
    }

    #[test]
    fn is_self_process_null_is_false() {
        assert!(!is_self_process(std::ptr::null_mut()));
    }

    #[test]
    fn thread_owner_pid_null_is_zero() {
        assert_eq!(thread_owner_pid(std::ptr::null_mut()), 0);
    }

    #[test]
    fn thread_owner_pid_current_thread() {
        let owner = thread_owner_pid(-2isize as HANDLE);
        let self_pid = unsafe { GetCurrentProcessId() };
        assert_eq!(owner, self_pid);
    }

    #[test]
    fn system_pid_threshold() {
        assert!(is_system_pid(4));   // System
        assert!(is_system_pid(64));  // csrss
        assert!(is_system_pid(0));
        assert!(is_system_pid(199));
        assert!(!is_system_pid(200));
        assert!(!is_system_pid(12345));
    }

    #[test]
    fn not_armed_by_default() {
        // ARMED starts false; reset for safety
        ARMED.store(false, Ordering::Release);
        assert!(!is_armed());
        assert!(!should_block(12345));
    }

    #[test]
    fn should_block_system_pid_even_when_armed() {
        ARMED.store(true, Ordering::Release);
        assert!(!should_block(64)); // csrss
        ARMED.store(false, Ordering::Release);
    }
}
