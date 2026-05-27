// Process guard — blocks cross-process code injection, dangerous process spawns,
// parent-PID spoofing, and Job Object breakaway.
//
// Hook 1: NtOpenProcess — denies PROCESS_TERMINATE | CREATE_THREAD | VM_OPERATION |
//         VM_WRITE | DUP_HANDLE | CREATE_PROCESS | SET_QUOTA | SET_INFORMATION |
//         SUSPEND_RESUME on non-owned PIDs. Allows VM_READ, QUERY_INFO (info-leak
//         is out of scope).
// Hook 2: Integrated into hooks.rs hook_nt_create_user_process — blocks denylisted
//         executables (wsl, wmic, LOLBins) and parent-PID spoofing via
//         PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
// Hook 3: NtAssignProcessToJobObject — unconditionally denies Job reassignment
//         from within the sandbox, preventing nested-Job escape on Win10+.
// Hook 4: NtSetInformationProcess — blocks dangerous ProcessInformationClass
//         mutations on foreign (non-owned) processes. Self-process is always
//         allowed for legitimate JIT/runtime usage.
// Hook 5: NtTerminateProcess — untracks child PIDs from process_tracker on
//         exit, preventing unbounded growth and PID-reuse poisoning (P1-2).

use std::sync::OnceLock;

use detour2::GenericDetour;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES};
use winapi::ctypes::c_void;
use winapi::um::processthreadsapi::GetCurrentProcessId;
use winapi::shared::ntdef::ULONG;

use crate::anti_rec;
use crate::hooks::{ipc_log, is_trace};
use crate::process_tracker;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

#[repr(C)]
struct CLIENT_ID {
    UniqueProcess: HANDLE,
    UniqueThread: HANDLE,
}

type FnNtOpenProcess = unsafe extern "system" fn(
    *mut HANDLE,          // ProcessHandle
    u32,                  // DesiredAccess
    *const OBJECT_ATTRIBUTES,
    *const CLIENT_ID,
) -> NTSTATUS;

type FnNtAssignProcessToJobObject = unsafe extern "system" fn(
    *mut c_void,  // JobHandle
    *mut c_void,  // ProcessHandle
) -> NTSTATUS;

type FnNtSetInformationProcess = unsafe extern "system" fn(
    HANDLE,          // ProcessHandle
    ULONG,           // ProcessInformationClass
    *mut c_void,     // ProcessInformation
    ULONG,           // ProcessInformationLength
) -> NTSTATUS;

type FnNtTerminateProcess = unsafe extern "system" fn(
    HANDLE,    // ProcessHandle
    NTSTATUS,  // ExitStatus
) -> NTSTATUS;

// PS_ATTRIBUTE for parent-spoof detection in NtCreateUserProcess attribute list.
#[repr(C)]
struct PS_ATTRIBUTE {
    Attribute: usize,
    Size: usize,
    Value: usize,
    ReturnLength: *mut usize,
}

#[repr(C)]
struct PS_ATTRIBUTE_LIST {
    TotalLength: usize,
    Attributes: [PS_ATTRIBUTE; 1],
}

// ---------------------------------------------------------------------------
// Owned-PID check — delegates to process_tracker (single source of truth).
// Self PID is always allowed; children we spawned are tracked via
// process_tracker::mark_spawned in hooks.rs hook_nt_create_user_process.
// ---------------------------------------------------------------------------

fn pid_owned(pid: u32) -> bool {
    pid == unsafe { GetCurrentProcessId() } || process_tracker::is_owned_child(pid)
}

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

static HOOK_NT_OPEN_PROCESS: OnceLock<GenericDetour<FnNtOpenProcess>> = OnceLock::new();
static HOOK_NT_ASSIGN_JOB: OnceLock<GenericDetour<FnNtAssignProcessToJobObject>> = OnceLock::new();
static HOOK_NT_SET_INFO_PROCESS: OnceLock<GenericDetour<FnNtSetInformationProcess>> = OnceLock::new();
static HOOK_NT_TERMINATE_PROCESS: OnceLock<GenericDetour<FnNtTerminateProcess>> = OnceLock::new();

// ---------------------------------------------------------------------------
// NtOpenProcess hook
// ---------------------------------------------------------------------------

const DANGEROUS_ACCESS: u32 =
    0x0001 |  // PROCESS_TERMINATE
    0x0002 |  // PROCESS_CREATE_THREAD
    0x0008 |  // PROCESS_VM_OPERATION
    0x0020 |  // PROCESS_VM_WRITE
    0x0040 |  // PROCESS_DUP_HANDLE
    0x0080 |  // PROCESS_CREATE_PROCESS
    0x0100 |  // PROCESS_SET_QUOTA
    0x0200 |  // PROCESS_SET_INFORMATION
    0x0800;   // PROCESS_SUSPEND_RESUME
// NOT blocked: VM_READ (0x0010), QUERY_INFO (0x0400), QUERY_LIMITED (0x1000)

const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000_0022_u32 as NTSTATUS;

unsafe extern "system" fn hook_nt_open_process(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    client_id: *const CLIENT_ID,
) -> NTSTATUS {
    let call_original = || {
        HOOK_NT_OPEN_PROCESS.get().unwrap().call(
            process_handle, desired_access, object_attributes, client_id,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if client_id.is_null() {
        return call_original();
    }

    let pid = (*client_id).UniqueProcess as usize as u32;
    let dangerous = desired_access & DANGEROUS_ACCESS;

    if dangerous != 0 && !pid_owned(pid) {
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace,
                format!("proc_open_blocked pid={pid} access=0x{desired_access:08x} dangerous=0x{dangerous:08x}"));
        }
        if !process_handle.is_null() {
            *process_handle = std::ptr::null_mut();
        }
        return STATUS_ACCESS_DENIED;
    }

    call_original()
}

// ---------------------------------------------------------------------------
// NtAssignProcessToJobObject hook — blocks Job reassignment escape
// ---------------------------------------------------------------------------

unsafe extern "system" fn hook_nt_assign_process_to_job_object(
    job: *mut c_void,
    process: *mut c_void,
) -> NTSTATUS {
    let call_original = || {
        HOOK_NT_ASSIGN_JOB.get().unwrap().call(job, process)
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // Any hooked process is already inside our sandbox Job. An explicit
    // NtAssignProcessToJobObject call from within the sandbox is an escape
    // attempt — the attacker creates an empty Job (no limits) and reassigns
    // themselves into it. On Win10+ nested Jobs allow this, so the process
    // would be in both Jobs but could use the empty one to dodge restrictions.
    // Deny unconditionally.
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace,
            format!("job_assign_blocked job=0x{:x} proc=0x{:x}",
                job as usize, process as usize));
    }
    STATUS_ACCESS_DENIED
}

// ---------------------------------------------------------------------------
// NtSetInformationProcess hook — block dangerous foreign-process mutations
// ---------------------------------------------------------------------------
//
// Classes treated as dangerous on FOREIGN PIDs (self-process is always allowed
// for legitimate JIT/runtime usage):
//   1  ProcessQuotaLimits        — change quotas of another process
//   3  ProcessBasePriority       — set base priority foreign
//   8  ProcessIoPortHandlers     — set IO completion port handlers
//   9  ProcessAccessToken        — assign primary token to foreign process (escape!)
//   20 ProcessPriorityBoost      — boost priority foreign
//   21 ProcessAffinityMask       — change CPU affinity foreign
//   25 ProcessForegroundInformation — set foreground on foreign
//   32 ProcessHandleTracing      — enable handle tracing foreign

const PROCESS_QUOTA_LIMITS: ULONG = 1;
const PROCESS_BASE_PRIORITY: ULONG = 3;
const PROCESS_IO_PORT_HANDLERS: ULONG = 8;
const PROCESS_ACCESS_TOKEN: ULONG = 9;
const PROCESS_PRIORITY_BOOST: ULONG = 20;
const PROCESS_AFFINITY_MASK: ULONG = 21;
const PROCESS_FOREGROUND_INFORMATION: ULONG = 25;
const PROCESS_HANDLE_TRACING: ULONG = 32;

const DANGEROUS_PROC_CLASSES: &[ULONG] = &[
    PROCESS_QUOTA_LIMITS,
    PROCESS_BASE_PRIORITY,
    PROCESS_IO_PORT_HANDLERS,
    PROCESS_ACCESS_TOKEN,
    PROCESS_PRIORITY_BOOST,
    PROCESS_AFFINITY_MASK,
    PROCESS_FOREGROUND_INFORMATION,
    PROCESS_HANDLE_TRACING,
];

unsafe extern "system" fn hook_nt_set_information_process(
    process_handle: HANDLE,
    class: ULONG,
    info: *mut c_void,
    len: ULONG,
) -> NTSTATUS {
    let call_original = || {
        HOOK_NT_SET_INFO_PROCESS.get().unwrap().call(process_handle, class, info, len)
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if !DANGEROUS_PROC_CLASSES.contains(&class) {
        return call_original();
    }

    // Resolve handle → PID. If self or owned child → allow.
    let target_pid = resolve_process_pid(process_handle);
    if target_pid == 0 || pid_owned(target_pid) {
        return call_original();
    }

    if is_trace() {
        ipc_log(ipc::LogLevel::Trace,
            format!("proc_setinfo_blocked pid={target_pid} class={class}"));
    }
    STATUS_ACCESS_DENIED
}

// ---------------------------------------------------------------------------
// NtTerminateProcess hook — untrack child PIDs on exit (P1-2 fix)
// ---------------------------------------------------------------------------
//
// This is a tracker-cleanup hook, NOT a security hook. Always passes through
// to the original. Prevents unbounded growth of process_tracker and PID-reuse
// poisoning (recycled PID treated as owned child → escape vector).

unsafe extern "system" fn hook_nt_terminate_process(
    process_handle: HANDLE,
    exit_status: NTSTATUS,
) -> NTSTATUS {
    let call_original = || {
        HOOK_NT_TERMINATE_PROCESS.get().unwrap().call(process_handle, exit_status)
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // Resolve handle → PID. GetProcessId returns 0 on failure or pseudo-handle
    // for current process (NtCurrentProcess = -1).
    let target_pid = winapi::um::processthreadsapi::GetProcessId(process_handle);
    let self_pid = GetCurrentProcessId();

    // Untrack if it's one of our owned children. Skip self (never tracked)
    // and skip 0 (resolution failure / NtCurrentProcess pseudo-handle).
    if target_pid != 0 && target_pid != self_pid {
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace,
                format!("proc_terminate_untrack pid={target_pid}"));
        }
        process_tracker::untrack(target_pid);
    }

    call_original()
}

// ---------------------------------------------------------------------------
// Resolve process handle → PID via NtQueryInformationProcess
// ---------------------------------------------------------------------------

fn resolve_process_pid(handle: HANDLE) -> u32 {
    #[repr(C)]
    struct PROCESS_BASIC_INFORMATION {
        reserved1: *mut c_void,
        peb_base_address: *mut c_void,
        reserved2: [*mut c_void; 2],
        unique_process_id: usize,
        reserved3: *mut c_void,
    }

    type FnNtQueryInformationProcess = unsafe extern "system" fn(
        HANDLE,
        ULONG,       // ProcessInformationClass (0 = ProcessBasicInformation)
        *mut c_void, // ProcessInformation
        ULONG,       // ProcessInformationLength
        *mut ULONG,  // ReturnLength
    ) -> NTSTATUS;

    static QIP: OnceLock<Option<FnNtQueryInformationProcess>> = OnceLock::new();
    let qip = QIP.get_or_init(|| {
        unsafe {
            let addr = crate::hooks::ntdll_export("NtQueryInformationProcess\0".as_bytes())?;
            Some(std::mem::transmute(addr as usize))
        }
    });

    if let Some(qip_fn) = qip {
        let mut pbi = std::mem::MaybeUninit::<PROCESS_BASIC_INFORMATION>::uninit();
        let status = unsafe {
            qip_fn(
                handle,
                0, // ProcessBasicInformation
                pbi.as_mut_ptr() as *mut c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
                std::ptr::null_mut(),
            )
        };
        if status >= 0 {
            return unsafe { (*pbi.as_ptr()).unique_process_id as u32 };
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Spawn denylist (checked in hooks.rs hook_nt_create_user_process)
// ---------------------------------------------------------------------------

const SPAWN_DENYLIST: &[&str] = &[
    "wsl.exe", "wslhost.exe", "bash.exe",
    "wmic.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "bitsadmin.exe", "certutil.exe",
    "installutil.exe", "msbuild.exe",
    "regasm.exe", "regsvcs.exe",
];

/// Check if an image path matches the spawn denylist. Returns true if blocked.
pub fn is_denylisted(image_path: &str) -> bool {
    let lower = image_path.to_lowercase().replace('/', "\\");
    let filename = lower.rsplit('\\').next().unwrap_or(&lower);
    SPAWN_DENYLIST.iter().any(|entry| filename == *entry)
}

// ---------------------------------------------------------------------------
// Parent-PID spoof detection via PS_ATTRIBUTE_LIST
// ---------------------------------------------------------------------------

/// Check if the attribute list contains PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
///
/// The PS_ATTRIBUTE encoding: `Attribute = (number) | (input ? 0x20000 : 0) | ...`.
/// PsAttributeParentProcess has number 0 in the NT attribute table.
/// In the PS_ATTRIBUTE_LIST passed to NtCreateUserProcess, the encoded value
/// uses 0x00020000 (PsAttributeParentProcess | PS_ATTRIBUTE_INPUT).
/// We match on the lower 16 bits == 0 (PsAttributeParentProcess number).
pub fn attribute_list_contains_parent_process(attr_list: *const c_void) -> bool {
    if attr_list.is_null() {
        return false;
    }
    let list = attr_list as *const PS_ATTRIBUTE_LIST;
    let total = unsafe { (*list).TotalLength };
    if total < std::mem::size_of::<usize>() {
        return false;
    }
    let attr_count = (total - std::mem::size_of::<usize>()) / std::mem::size_of::<PS_ATTRIBUTE>();
    if attr_count == 0 {
        return false;
    }
    let attrs = unsafe { (*list).Attributes.as_ptr() };
    for i in 0..attr_count {
        let attr = unsafe { &*attrs.add(i) };
        // PsAttributeParentProcess number = 0, encoded with input flag = 0x20000.
        // Match lower 16 bits == 0 — this is the attribute number.
        if (attr.Attribute & 0xFFFF) == 0 && attr.Value != 0 {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Extract image path from RTL_USER_PROCESS_PARAMETERS
// ---------------------------------------------------------------------------

/// Extract the image path from process parameters.
/// Reuses the same offset logic as hooks.rs extract_child_exe (offset 0x60 on x64).
pub unsafe fn extract_image_path(params: *const c_void) -> Option<String> {
    if params.is_null() {
        return None;
    }
    // RTL_USER_PROCESS_PARAMETERS layout on x64:
    //   0x60: ImagePathName (UNICODE_STRING)
    let params_ptr = params as *const u8;
    let image_path_offset = 0x60usize;
    let ustr_ptr = params_ptr.add(image_path_offset) as *const ntapi::winapi::shared::ntdef::UNICODE_STRING;
    let ustr = &*ustr_ptr;
    let char_count = (ustr.Length / 2) as usize;
    if char_count == 0 || ustr.Buffer.is_null() {
        return None;
    }
    let name_slice = std::slice::from_raw_parts(ustr.Buffer, char_count);
    Some(String::from_utf16_lossy(name_slice))
}

// ---------------------------------------------------------------------------
// Install / Uninstall
// ---------------------------------------------------------------------------

pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    let addr = crate::hooks::ntdll_export("NtOpenProcess\0".as_bytes())
        .ok_or("ntdll export not found: NtOpenProcess")?;
    let target: FnNtOpenProcess = std::mem::transmute(addr as usize);
    let hook_ptr: FnNtOpenProcess = hook_nt_open_process;
    let detour = GenericDetour::<FnNtOpenProcess>::new(target, hook_ptr)
        .map_err(|e| format!("detour init NtOpenProcess: {:?}", e))?;
    HOOK_NT_OPEN_PROCESS.set(detour).ok();
    HOOK_NT_OPEN_PROCESS.get()
        .expect("set above")
        .enable()
        .map_err(|e| format!("detour enable NtOpenProcess: {:?}", e))?;

    let addr2 = crate::hooks::ntdll_export("NtAssignProcessToJobObject\0".as_bytes())
        .ok_or("ntdll export not found: NtAssignProcessToJobObject")?;
    let target2: FnNtAssignProcessToJobObject = std::mem::transmute(addr2 as usize);
    let hook_ptr2: FnNtAssignProcessToJobObject = hook_nt_assign_process_to_job_object;
    let detour2 = GenericDetour::<FnNtAssignProcessToJobObject>::new(target2, hook_ptr2)
        .map_err(|e| format!("detour init NtAssignProcessToJobObject: {:?}", e))?;
    HOOK_NT_ASSIGN_JOB.set(detour2).ok();
    HOOK_NT_ASSIGN_JOB.get()
        .expect("set above")
        .enable()
        .map_err(|e| format!("detour enable NtAssignProcessToJobObject: {:?}", e))?;

    // Hook 4: NtSetInformationProcess — block dangerous foreign-process mutations
    let addr3 = crate::hooks::ntdll_export("NtSetInformationProcess\0".as_bytes())
        .ok_or("ntdll export not found: NtSetInformationProcess")?;
    let target3: FnNtSetInformationProcess = std::mem::transmute(addr3 as usize);
    let hook_ptr3: FnNtSetInformationProcess = hook_nt_set_information_process;
    let detour3 = GenericDetour::<FnNtSetInformationProcess>::new(target3, hook_ptr3)
        .map_err(|e| format!("detour init NtSetInformationProcess: {:?}", e))?;
    HOOK_NT_SET_INFO_PROCESS.set(detour3).ok();
    HOOK_NT_SET_INFO_PROCESS.get()
        .expect("set above")
        .enable()
        .map_err(|e| format!("detour enable NtSetInformationProcess: {:?}", e))?;

    // Hook 5: NtTerminateProcess — untrack child PIDs on exit (P1-2 fix)
    let addr4 = crate::hooks::ntdll_export("NtTerminateProcess\0".as_bytes())
        .ok_or("ntdll export not found: NtTerminateProcess")?;
    let target4: FnNtTerminateProcess = std::mem::transmute(addr4 as usize);
    let hook_ptr4: FnNtTerminateProcess = hook_nt_terminate_process;
    let detour4 = GenericDetour::<FnNtTerminateProcess>::new(target4, hook_ptr4)
        .map_err(|e| format!("detour init NtTerminateProcess: {:?}", e))?;
    HOOK_NT_TERMINATE_PROCESS.set(detour4).ok();
    HOOK_NT_TERMINATE_PROCESS.get()
        .expect("set above")
        .enable()
        .map_err(|e| format!("detour enable NtTerminateProcess: {:?}", e))?;

    if is_trace() {
        ipc_log(ipc::LogLevel::Trace, "proc_guard_installed".into());
    }
    Ok(())
}

pub unsafe fn uninstall() {
    if let Some(h) = HOOK_NT_TERMINATE_PROCESS.get() {
        let _ = h.disable();
    }
    if let Some(h) = HOOK_NT_SET_INFO_PROCESS.get() {
        let _ = h.disable();
    }
    if let Some(h) = HOOK_NT_ASSIGN_JOB.get() {
        let _ = h.disable();
    }
    if let Some(h) = HOOK_NT_OPEN_PROCESS.get() {
        let _ = h.disable();
    }
}
