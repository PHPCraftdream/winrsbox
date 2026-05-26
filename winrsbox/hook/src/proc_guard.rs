// Process guard — blocks cross-process code injection, dangerous process spawns,
// and parent-PID spoofing.
//
// Hook 1: NtOpenProcess — denies PROCESS_TERMINATE | CREATE_THREAD | VM_OPERATION |
//         VM_WRITE | DUP_HANDLE | CREATE_PROCESS | SET_QUOTA | SET_INFORMATION |
//         SUSPEND_RESUME on non-owned PIDs. Allows VM_READ, QUERY_INFO (info-leak
//         is out of scope).
// Hook 2: Integrated into hooks.rs hook_nt_create_user_process — blocks denylisted
//         executables (wsl, wmic, LOLBins) and parent-PID spoofing via
//         PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.

use std::sync::OnceLock;

use detour2::GenericDetour;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES};
use winapi::ctypes::c_void;
use winapi::um::processthreadsapi::GetCurrentProcessId;

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

    if is_trace() {
        ipc_log(ipc::LogLevel::Trace, "proc_guard_installed".into());
    }
    Ok(())
}

pub unsafe fn uninstall() {
    if let Some(h) = HOOK_NT_OPEN_PROCESS.get() {
        let _ = h.disable();
    }
}
