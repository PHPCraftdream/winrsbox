// Inject guard — blocks cross-process injection from sandboxed processes.
//
// Hooks NtCreateThreadEx, NtQueueApcThread, and NtQueueApcThreadEx.
// Three-layer filtering:
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

use detour2::GenericDetour;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES};
use winapi::ctypes::c_void;
use winapi::um::libloaderapi::{GetModuleFileNameW, GetModuleHandleExW};
use winapi::um::processthreadsapi::GetCurrentProcessId;

use crate::anti_rec;
use crate::hooks::nt_call_original;

// ---------------------------------------------------------------------------
// Nt* function type aliases
// ---------------------------------------------------------------------------

type FnNtCreateThreadEx = unsafe extern "system" fn(
    *mut HANDLE, u32, *mut OBJECT_ATTRIBUTES, HANDLE,
    *mut c_void, *mut c_void, u32, usize, usize, usize, *mut c_void,
) -> NTSTATUS;

// Legacy NtCreateThread signature (still used by some Win32 wrappers).
// All scalar params widened to usize for detour Function trait compat.
type FnNtCreateThread = unsafe extern "system" fn(
    *mut HANDLE,            // ThreadHandle
    usize,                  // DesiredAccess (ACCESS_MASK widened)
    *mut OBJECT_ATTRIBUTES, // ObjectAttributes
    HANDLE,                 // ProcessHandle
    *mut c_void,            // ClientId
    *mut c_void,            // ThreadContext (CONTEXT*)
    *mut c_void,            // InitialTeb (USER_STACK*)
    usize,                  // CreateSuspended (BOOLEAN widened)
) -> NTSTATUS;

type FnNtQueueApcThread = unsafe extern "system" fn(
    HANDLE, *mut c_void, *mut c_void, *mut c_void, *mut c_void,
) -> NTSTATUS;

// NtQueueApcThreadEx — Windows 10+ variant with UserApcReserveHandle.
// Signature from ntapi 0.4 ntpsapi.rs:
//   NtQueueApcThreadEx(ThreadHandle, UserApcReserveHandle, ApcRoutine,
//                     ApcArgument1, ApcArgument2, ApcArgument3) -> NTSTATUS
type FnNtQueueApcThreadEx = unsafe extern "system" fn(
    HANDLE, // ThreadHandle
    HANDLE, // UserApcReserveHandle
    *mut c_void, // ApcRoutine
    *mut c_void, // ApcArgument1
    *mut c_void, // ApcArgument2
    *mut c_void, // ApcArgument3
) -> NTSTATUS;

type FnNtSetContextThread = unsafe extern "system" fn(
    HANDLE,         // ThreadHandle
    *const c_void,  // Context (CONTEXT*)
) -> NTSTATUS;

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

static HOOK_CREATE_THREAD_EX: OnceLock<GenericDetour<FnNtCreateThreadEx>> = OnceLock::new();
static HOOK_CREATE_THREAD: OnceLock<GenericDetour<FnNtCreateThread>> = OnceLock::new();
static HOOK_QUEUE_APC: OnceLock<GenericDetour<FnNtQueueApcThread>> = OnceLock::new();
static HOOK_QUEUE_APC_EX: OnceLock<GenericDetour<FnNtQueueApcThreadEx>> = OnceLock::new();
static HOOK_SET_CONTEXT: OnceLock<GenericDetour<FnNtSetContextThread>> = OnceLock::new();

// ---------------------------------------------------------------------------
// Filter 2: Deferred arming
// ---------------------------------------------------------------------------

static ARMED: AtomicBool = AtomicBool::new(false);

/// Arm inject_guard. Idempotent: a single `AtomicBool` store, safe to call any
/// number of times and from any context (no allocation, no LoadLibrary, no
/// syscall — safe under loader lock / DllMain).
///
/// Called from two sites (M1 fix):
///   1. hooks.rs `install_hooks`, right after every detour is installed — this
///      is the deterministic, primary trigger ("hooks are live → arm").
///   2. ipc_client.rs `ensure_ipc_and`, on the first successful IPC round-trip —
///      kept as belt-and-suspenders. Harmless because the store is idempotent.
///
/// Before the fix, only site (2) existed, so a process that injected before its
/// first FS/registry op was still un-armed and `should_block` returned false.
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

// System DLLs recognized by basename AND verified system-directory location.
// `hook.dll` is deliberately absent: our own image is matched by full-path
// identity (`verified_hook_image_path`), because a basename match would let
// the guest get its own DLL trusted by naming it `hook.dll`.
const SYSTEM_DLLS: &[&str] = &[
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "ucrtbase.dll",
    "ucrtbased.dll", "msvcrt.dll", "apphelp.dll", "rpcrt4.dll",
];

/// Full lowercased path of the image that contains this hook's code — i.e.
/// the module the launcher actually injected. Resolved from an in-image
/// address (`ARMED` lives in this file), NOT from the session config: the
/// session section is guest-writable on current builds (audit 2026-09-19,
/// Critical 3), so the configured `dll_path` is not a trust anchor.
/// `None` (resolution failed) → hook frames are not trusted; fail closed.
fn verified_hook_image_path() -> Option<&'static str> {
    static HOOK_IMAGE: OnceLock<Option<String>> = OnceLock::new();
    HOOK_IMAGE
        .get_or_init(|| {
            // SAFETY: FROM_ADDRESS probes the address via loader structures
            // without dereferencing it (mirrors memory_guard's usage);
            // UNCHANGED_REFCOUNT does not bump the load count, so no
            // FreeLibrary pairing is needed. `ARMED` is a static of this
            // module, so its address is inside our own image.
            let hmod = unsafe {
                let mut hmod: *mut c_void = std::ptr::null_mut();
                let ok = GetModuleHandleExW(
                    0x0000_0004 /* FROM_ADDRESS */ | 0x0000_0002 /* UNCHANGED_REFCOUNT */,
                    &ARMED as *const AtomicBool as *const u16,
                    &mut hmod as *mut *mut c_void as *mut _,
                );
                if ok == 0 { None } else { Some(hmod) }
            }?;
            // SAFETY: hmod is a valid module handle from GetModuleHandleExW.
            unsafe {
                let mut buf = [0u16; 512];
                let len = GetModuleFileNameW(hmod as _, buf.as_mut_ptr(), buf.len() as u32);
                if len == 0 || len as usize >= buf.len() {
                    return None; // failed or truncated path → fail closed
                }
                Some(String::from_utf16_lossy(&buf[..len as usize]).to_ascii_lowercase())
            }
        })
        .as_deref()
}

/// Lowercased system-directory prefix (trailing `\` included), anchored on
/// the directory of the actually-loaded ntdll image — every DLL in
/// `SYSTEM_DLLS` loads from that directory for this process bitness.
/// Anchoring on a real loaded image (not a `GetSystemDirectoryW` call)
/// keeps the check valid under all Windows layouts. `None` on anchor
/// failure → the caller fails closed (no frame trusted by basename).
fn verified_system_dir_prefix() -> Option<&'static str> {
    static SYSTEM_DIR: OnceLock<Option<String>> = OnceLock::new();
    SYSTEM_DIR
        .get_or_init(|| {
            // SAFETY: ntdll_export only reads the loaded module's export table.
            let addr = unsafe { crate::hooks::ntdll_export(b"NtCreateThreadEx\0") }?;
            let path = crate::memory_guard::module_path_for_address(addr as *const c_void)?;
            let lower = path.to_ascii_lowercase();
            let sep = lower.rfind('\\')?;
            Some(format!("{}\\", &lower[..=sep]))
        })
        .as_deref()
}

/// Decide whether ONE stack frame's module (path already lowercased) may be
/// treated as system/sandbox code. `hook_image` is the verified full path
/// of our own image, `system_dir` the verified system-directory prefix;
/// either being `None` fails closed for the respective check.
fn frame_is_trusted(
    path_lower: &str,
    hook_image: Option<&str>,
    system_dir: Option<&str>,
) -> bool {
    if let Some(hook) = hook_image {
        if path_lower == hook {
            return true; // our own image, verified by full path
        }
    }
    let basename = path_lower.rsplit_once('\\').map(|(_, b)| b).unwrap_or(path_lower);
    if SYSTEM_DLLS.iter().any(|&s| s == basename) {
        // Basename alone is spoofable — the guest can ship its own
        // `ntdll.dll`; require the verified system directory as well.
        return system_dir.map_or(false, |dir| path_lower.starts_with(dir));
    }
    false
}

/// Walk every frame. An empty/unresolvable stack, an anonymous frame, or
/// any non-system frame means the caller is NOT system: "cannot determine"
/// must deny, never allow (audit 2026-09-19, systemic pattern).
fn stack_is_system(stack: &[u64]) -> bool {
    if stack.is_empty() {
        return false; // unresolvable stack → untrusted (was: treated as system)
    }
    let hook_image = verified_hook_image_path();
    let system_dir = verified_system_dir_prefix();
    for &pc in stack {
        let path = match crate::memory_guard::module_path_for_address(pc as *const c_void) {
            Some(p) => p,
            None => return false, // anonymous frame → NOT system
        };
        if !frame_is_trusted(&path.to_ascii_lowercase(), hook_image, system_dir) {
            return false;
        }
    }
    true
}

pub fn is_system_caller() -> bool {
    let stack = crate::memory_guard::capture_stack_pub(2, 16);
    stack_is_system(&stack)
}

// ---------------------------------------------------------------------------
// Process identity check
// ---------------------------------------------------------------------------

const NT_CURRENT_PROCESS: isize = -1;

pub unsafe fn is_self_process(handle: HANDLE) -> bool {
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

pub unsafe fn thread_owner_pid(thread_handle: HANDLE) -> u32 {
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
        nt_call_original!(
            &HOOK_CREATE_THREAD_EX,
            "NtCreateThreadEx",
            (thread_handle, desired_access, object_attributes,
             process_handle, start_routine, argument,
             create_flags, zero_bits, stack_size, maximum_stack_size,
             attribute_list)
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

unsafe extern "system" fn hook_nt_create_thread(
    thread_handle: *mut HANDLE,
    desired_access: usize,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    process_handle: HANDLE,
    client_id: *mut c_void,
    thread_context: *mut c_void,
    initial_teb: *mut c_void,
    create_suspended: usize,
) -> NTSTATUS {
    let call_original = || {
        nt_call_original!(
            &HOOK_CREATE_THREAD,
            "NtCreateThread",
            (thread_handle, desired_access, object_attributes, process_handle,
             client_id, thread_context, initial_teb, create_suspended)
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
                thread_context as u64,
            );
        }
    }

    call_original()
}

// ---------------------------------------------------------------------------
// CONTEXT offsets (x64 Windows)
// ---------------------------------------------------------------------------

const CONTEXT_CONTROL: u32 = 0x10_0001;
const CONTEXT_DEBUG_REGISTERS: u32 = 0x10_0010;
const CTX_FLAGS_OFFSET: usize = 0x30;
const CTX_RIP_OFFSET: usize = 0xF8;
const CTX_DR0_OFFSET: usize = 0x350;
const CTX_DR7_OFFSET: usize = 0x370;

// The fixed offsets above are naturally aligned, but the CONTEXT base is the
// hooked caller's pointer — NtSetContextThread callers choose the address, and
// nothing forces it onto CONTEXT's 16-byte boundary. A plain
// `*(ctx.add(offset) as *const u64)` aborts on an odd probe (misaligned
// dereference), so both readers are unaligned by design.

/// Read a u32 at `offset` inside a caller-supplied CONTEXT.
///
/// # SAFETY
/// `ctx.add(offset)` must be readable for 4 bytes.
pub unsafe fn read_ctx_u32(ctx: *const c_void, offset: usize) -> u32 {
    (ctx.cast::<u8>().add(offset) as *const u32).read_unaligned()
}

/// Read a u64 at `offset` inside a caller-supplied CONTEXT.
///
/// # SAFETY
/// `ctx.add(offset)` must be readable for 8 bytes.
pub unsafe fn read_ctx_u64(ctx: *const c_void, offset: usize) -> u64 {
    (ctx.cast::<u8>().add(offset) as *const u64).read_unaligned()
}

unsafe extern "system" fn hook_nt_set_context_thread(
    thread_handle: HANDLE,
    context: *const c_void,
) -> NTSTATUS {
    let call_original =
        || nt_call_original!(&HOOK_SET_CONTEXT, "NtSetContextThread", (thread_handle, context));

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    let owner_pid = thread_owner_pid(thread_handle);
    let self_pid = GetCurrentProcessId();
    if owner_pid != 0 && owner_pid != self_pid && should_block(owner_pid) {
        if !context.is_null() {
            let flags = read_ctx_u32(context, CTX_FLAGS_OFFSET);

            // Check 1: Rip hijack — setting instruction pointer to outside any module
            if flags & CONTEXT_CONTROL != 0 {
                let rip = read_ctx_u64(context, CTX_RIP_OFFSET);
                if rip != 0 && !crate::memory_guard::is_address_in_module(rip as *const c_void) {
                    report_and_terminate(
                        ipc::InjectKind::ContextHijack,
                        owner_pid,
                        rip,
                    );
                }
            }

            // Check 2: Hardware breakpoint injection — setting DR0-DR3 via DR7
            if flags & CONTEXT_DEBUG_REGISTERS != 0 {
                let dr7 = read_ctx_u64(context, CTX_DR7_OFFSET);
                // DR7 bits 0,2,4,6 = local enable for DR0-DR3
                let any_enabled = dr7 & 0x55 != 0;
                if any_enabled {
                    let dr0 = read_ctx_u64(context, CTX_DR0_OFFSET);
                    if dr0 != 0 && !crate::memory_guard::is_address_in_module(dr0 as *const c_void) {
                        report_and_terminate(
                            ipc::InjectKind::ContextHijack,
                            owner_pid,
                            dr0,
                        );
                    }
                }
            }
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
        nt_call_original!(
            &HOOK_QUEUE_APC,
            "NtQueueApcThread",
            (thread_handle, apc_routine, apc_arg1, apc_arg2, apc_arg3)
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

unsafe extern "system" fn hook_nt_queue_apc_thread_ex(
    thread_handle: HANDLE,
    user_apc_reserve_handle: HANDLE,
    apc_routine: *mut c_void,
    apc_arg1: *mut c_void,
    apc_arg2: *mut c_void,
    apc_arg3: *mut c_void,
) -> NTSTATUS {
    let call_original = || {
        nt_call_original!(
            &HOOK_QUEUE_APC_EX,
            "NtQueueApcThreadEx",
            (thread_handle, user_apc_reserve_handle,
             apc_routine, apc_arg1, apc_arg2, apc_arg3)
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

    install_guard!(HOOK_CREATE_THREAD_EX, "NtCreateThreadEx\0", hook_nt_create_thread_ex, FnNtCreateThreadEx);
    // Legacy NtCreateThread is still used by some Win32 CreateRemoteThread paths
    // on certain Windows builds. Best-effort install: don't fail if not found.
    if let Some(addr) = crate::hooks::ntdll_export("NtCreateThread\0".as_bytes()) {
        let target: FnNtCreateThread = std::mem::transmute(addr as usize);
        let hook_ptr: FnNtCreateThread = hook_nt_create_thread;
        if let Ok(detour) = GenericDetour::<FnNtCreateThread>::new(target, hook_ptr) {
            let _ = HOOK_CREATE_THREAD.set(detour);
            if let Some(h) = HOOK_CREATE_THREAD.get() { let _ = h.enable(); }
        }
    }
    install_guard!(HOOK_QUEUE_APC,     "NtQueueApcThread\0",  hook_nt_queue_apc_thread, FnNtQueueApcThread);
    // NtQueueApcThreadEx — Windows 10+ variant (early-bird APC). Best-effort
    // install: not present on older Windows, so don't fail if export missing.
    if let Some(addr) = crate::hooks::ntdll_export("NtQueueApcThreadEx\0".as_bytes()) {
        let target: FnNtQueueApcThreadEx = std::mem::transmute(addr as usize);
        let hook_ptr: FnNtQueueApcThreadEx = hook_nt_queue_apc_thread_ex;
        if let Ok(detour) = GenericDetour::<FnNtQueueApcThreadEx>::new(target, hook_ptr) {
            let _ = HOOK_QUEUE_APC_EX.set(detour);
            if let Some(h) = HOOK_QUEUE_APC_EX.get() { let _ = h.enable(); }
        }
    }
    install_guard!(HOOK_SET_CONTEXT,   "NtSetContextThread\0", hook_nt_set_context_thread, FnNtSetContextThread);

    // Hooks installed but NOT armed — will arm after first IPC Hello
    Ok(())
}

/// # SAFETY
/// Must be called from DLL_PROCESS_DETACH only.
pub unsafe fn uninstall() {
    if let Some(h) = HOOK_SET_CONTEXT.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_CREATE_THREAD_EX.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_CREATE_THREAD.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_QUEUE_APC_EX.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_QUEUE_APC.get() { let _ = h.disable(); }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── unaligned-read regression (alignment-UB class, mirrors 9d73d34) ──
    //
    // The CONTEXT pointer is the hooked NtSetContextThread caller's: the
    // fixed offsets above are naturally aligned, but the BASE can be any
    // address the caller chose. This probe forces an odd base — the old
    // plain `*(... as *const u32/u64)` dereferences aborted there
    // (misaligned dereference, 0xc0000409) instead of reading the fields.

    #[test]
    fn read_ctx_reads_misaligned_context_probe() {
        let mut backing = vec![0u8; 0x380 + 8];
        let off = 1 - (backing.as_ptr() as usize % 2);
        assert_eq!((backing.as_ptr() as usize + off) % 2, 1,
            "probe CONTEXT must sit at an odd address");
        let flags: u32 = 0x0010_0015;
        let rip: u64 = 0x0000_7FF6_0000_1234;
        let dr0: u64 = 0x0000_DEAD_BEEF_0001;
        let dr7: u64 = 0x0000_0000_0004_0DE7;
        // Byte-wise stores: aligned u32/u64 stores would trip the same
        // precondition the readers are being tested against.
        backing[off + 0x30..off + 0x34].copy_from_slice(&flags.to_le_bytes());
        backing[off + 0xF8..off + 0x100].copy_from_slice(&rip.to_le_bytes());
        backing[off + 0x350..off + 0x358].copy_from_slice(&dr0.to_le_bytes());
        backing[off + 0x370..off + 0x378].copy_from_slice(&dr7.to_le_bytes());
        // SAFETY: base+offset stays inside `backing` for every read below.
        let ctx = unsafe { backing.as_ptr().add(off) as *const c_void };
        // SAFETY: each read is within the written probe region.
        unsafe {
            assert_eq!(read_ctx_u32(ctx, CTX_FLAGS_OFFSET), flags);
            assert_eq!(read_ctx_u64(ctx, CTX_RIP_OFFSET), rip);
            assert_eq!(read_ctx_u64(ctx, CTX_DR0_OFFSET), dr0);
            assert_eq!(read_ctx_u64(ctx, CTX_DR7_OFFSET), dr7);
        }
    }

    // ARMED is a process-global AtomicBool, and cargo runs these tests on
    // parallel threads in one binary. Tests that mutate ARMED must not race each
    // other (a stray arm() from one test would flip the gate another test is
    // asserting on). Serialize them through this lock. Poison is recovered with
    // into_inner() so an assertion failure in one test does not cascade into
    // spurious .lock() panics in the others (§B2 Mutex-poisoning discipline).
    static ARMED_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn armed_test_guard() -> std::sync::MutexGuard<'static, ()> {
        ARMED_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    #[test]
    fn is_self_process_pseudo_handle() {
        assert!(unsafe { is_self_process(-1isize as HANDLE) });
    }

    #[test]
    fn is_self_process_null_is_false() {
        assert!(unsafe { !is_self_process(std::ptr::null_mut()) });
    }

    #[test]
    fn thread_owner_pid_null_is_zero() {
        assert_eq!(unsafe { thread_owner_pid(std::ptr::null_mut()) }, 0);
    }

    #[test]
    fn thread_owner_pid_current_thread() {
        let owner = unsafe { thread_owner_pid(-2isize as HANDLE) };
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
        let _g = armed_test_guard();
        // ARMED starts false; reset for safety
        ARMED.store(false, Ordering::Release);
        assert!(!is_armed());
        assert!(!should_block(12345));
    }

    #[test]
    fn should_block_system_pid_even_when_armed() {
        let _g = armed_test_guard();
        ARMED.store(true, Ordering::Release);
        assert!(!should_block(64)); // csrss
        ARMED.store(false, Ordering::Release);
    }

    /// M1: arm() is a single atomic store, hence idempotent — calling it
    /// repeatedly is harmless and leaves the guard armed. This is the property
    /// that lets install_hooks() AND ensure_ipc_and() both call it.
    #[test]
    fn arm_is_idempotent() {
        let _g = armed_test_guard();
        ARMED.store(false, Ordering::Release);
        arm();
        assert!(is_armed());
        arm();
        arm();
        assert!(is_armed(), "repeated arm() must remain armed");
        ARMED.store(false, Ordering::Release);
    }

    /// M1: after arm(), a cross-process op targeting a non-system PID from a
    /// non-system caller is blocked. The arming gate (Filter 2) is the thing
    /// install_hooks() now flips deterministically; this test pins that flipping
    /// it changes the should_block() outcome for the foreign-PID case.
    ///
    /// `is_system_caller()` walks the *live* test-harness stack, so we branch on
    /// it to stay deterministic across environments: the load-bearing assertion
    /// is that when the caller is non-system (the normal case in the test
    /// binary), arming turns should_block(foreign) from false into true.
    #[test]
    fn should_block_after_arm_blocks_foreign_pid() {
        const FOREIGN_PID: u32 = 999_999; // well above SYSTEM_PID_THRESHOLD

        let _g = armed_test_guard();
        ARMED.store(false, Ordering::Release);
        // Un-armed: never blocks, regardless of caller/pid (Filter 2 short-circuit).
        assert!(!should_block(FOREIGN_PID), "un-armed guard must not block");

        arm();
        if is_system_caller() {
            // Degenerate environment (entire stack classified system): Filter 1
            // still allows. We can't force a non-system frame here, so just
            // assert the gate is armed.
            assert!(is_armed());
        } else {
            assert!(
                should_block(FOREIGN_PID),
                "armed + non-system caller + foreign pid must block",
            );
        }
        ARMED.store(false, Ordering::Release);
    }

    /// M1 deterministic-arm contract pin: arm() must leave is_armed() true.
    /// install_hooks() relies on this so the inject hooks become active the
    /// moment all detours are installed, not on the first IPC round-trip.
    #[test]
    fn arm_sets_is_armed_contract() {
        let _g = armed_test_guard();
        ARMED.store(false, Ordering::Release);
        assert!(!is_armed());
        arm();
        assert!(is_armed(), "arm() must set the ARMED gate");
        ARMED.store(false, Ordering::Release);
    }

    #[test]
    fn context_flags_constants() {
        assert_eq!(CONTEXT_CONTROL, 0x10_0001);
        assert_eq!(CONTEXT_DEBUG_REGISTERS, 0x10_0010);
    }

    #[test]
    fn read_ctx_from_mock_buffer() {
        let mut buf = vec![0u8; 1024];
        let flags: u32 = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
        buf[CTX_FLAGS_OFFSET..CTX_FLAGS_OFFSET + 4].copy_from_slice(&flags.to_le_bytes());
        let rip: u64 = 0x7FF8A1234567;
        buf[CTX_RIP_OFFSET..CTX_RIP_OFFSET + 8].copy_from_slice(&rip.to_le_bytes());
        let dr0: u64 = 0xDEADBEEF;
        buf[CTX_DR0_OFFSET..CTX_DR0_OFFSET + 8].copy_from_slice(&dr0.to_le_bytes());
        let dr7: u64 = 0x01;
        buf[CTX_DR7_OFFSET..CTX_DR7_OFFSET + 8].copy_from_slice(&dr7.to_le_bytes());

        unsafe {
            let ctx = buf.as_ptr() as *const c_void;
            assert_eq!(read_ctx_u32(ctx, CTX_FLAGS_OFFSET), flags);
            assert_eq!(read_ctx_u64(ctx, CTX_RIP_OFFSET), rip);
            assert_eq!(read_ctx_u64(ctx, CTX_DR0_OFFSET), dr0);
            assert_eq!(read_ctx_u64(ctx, CTX_DR7_OFFSET), dr7);
        }
    }

    // --- Regression tests: audit 2026-09-19 Medium (inject_guard) ---
    // These pin the deny-by-default classification: a spoofed `hook.dll`
    // basename is not trusted, and an unresolvable stack is not "system".

    #[test]
    fn spoofed_hook_basename_is_not_trusted() {
        let trusted = frame_is_trusted(
            r"c:\guest\evil\hook.dll",
            Some(r"c:\tools\winrsbox\hook.dll"),
            Some(r"c:\windows\system32\"),
        );
        assert!(!trusted, "basename-only hook.dll match trusts a spoofed path");
    }

    #[test]
    fn verified_hook_image_exact_path_is_trusted() {
        let trusted = frame_is_trusted(
            r"c:\tools\winrsbox\hook.dll",
            Some(r"c:\tools\winrsbox\hook.dll"),
            None,
        );
        assert!(trusted, "the verified injected image must stay trusted");
    }

    #[test]
    fn unresolvable_stack_is_not_system() {
        assert!(!stack_is_system(&[]), "empty stack must deny, not assume system");
    }

    #[test]
    fn system_dll_basename_outside_system_dir_is_not_trusted() {
        let trusted = frame_is_trusted(
            r"d:\app\ntdll.dll",
            None,
            Some(r"c:\windows\system32\"),
        );
        assert!(!trusted, "guest-shipped system DLL name must not be trusted");
    }

    #[test]
    fn system_dll_inside_verified_system_dir_is_trusted() {
        let trusted = frame_is_trusted(
            r"c:\windows\system32\kernelbase.dll",
            None,
            Some(r"c:\windows\system32\"),
        );
        assert!(trusted, "legit system frames must stay allow-listed (no over-blocking)");
    }
}
