// Link guard — blocks creation of hard links, junctions, and symlinks
// from sandboxed processes. These would bypass CoW isolation:
//
// Junction attack: mklink /J <CoW_path> C:\Windows\System32
//   → writes through junction modify real system files while our
//     FS hook only checks the symbolic (pre-resolution) path.
//
// Hard link attack: NtSetInformationFile(FileLinkInformation)
//   → creates a second name for a file, writes through either name
//     modify the same data.
//
// Defense: block NtFsControlFile(FSCTL_SET_REPARSE_POINT) and
// NtSetInformationFile(FileLinkInformation) entirely. AI agents
// and compilers never need these operations.

use std::sync::OnceLock;

use detour2::GenericDetour;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS};
use winapi::ctypes::c_void;

use crate::anti_rec;

const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000_0022_u32 as NTSTATUS;
const FSCTL_SET_REPARSE_POINT: u32 = 0x000900A4;
const FILE_LINK_INFORMATION: u32 = 11;
const FILE_LINK_INFORMATION_EX: u32 = 72;

type FnNtFsControlFile = unsafe extern "system" fn(
    HANDLE,         // FileHandle
    HANDLE,         // Event
    *mut c_void,    // ApcRoutine
    *mut c_void,    // ApcContext
    *mut c_void,    // IoStatusBlock
    u32,            // FsControlCode
    *mut c_void,    // InputBuffer
    u32,            // InputBufferLength
    *mut c_void,    // OutputBuffer
    u32,            // OutputBufferLength
) -> NTSTATUS;

type FnNtSetInformationFile = unsafe extern "system" fn(
    HANDLE,         // FileHandle
    *mut c_void,    // IoStatusBlock
    *mut c_void,    // FileInformation
    u32,            // Length
    u32,            // FileInformationClass
) -> NTSTATUS;

static HOOK_FS_CONTROL: OnceLock<GenericDetour<FnNtFsControlFile>> = OnceLock::new();
static HOOK_SET_INFO: OnceLock<GenericDetour<FnNtSetInformationFile>> = OnceLock::new();

unsafe extern "system" fn hook_nt_fs_control_file(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: *mut c_void,
    apc_context: *mut c_void,
    io_status_block: *mut c_void,
    fs_control_code: u32,
    input_buffer: *mut c_void,
    input_buffer_length: u32,
    output_buffer: *mut c_void,
    output_buffer_length: u32,
) -> NTSTATUS {
    let call_original = || {
        HOOK_FS_CONTROL.get().unwrap().call(
            file_handle, event, apc_routine, apc_context,
            io_status_block, fs_control_code,
            input_buffer, input_buffer_length,
            output_buffer, output_buffer_length,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if fs_control_code == FSCTL_SET_REPARSE_POINT {
        return STATUS_ACCESS_DENIED;
    }

    call_original()
}

unsafe extern "system" fn hook_nt_set_information_file(
    file_handle: HANDLE,
    io_status_block: *mut c_void,
    file_information: *mut c_void,
    length: u32,
    file_information_class: u32,
) -> NTSTATUS {
    let call_original = || {
        HOOK_SET_INFO.get().unwrap().call(
            file_handle, io_status_block,
            file_information, length,
            file_information_class,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if file_information_class == FILE_LINK_INFORMATION
        || file_information_class == FILE_LINK_INFORMATION_EX
    {
        return STATUS_ACCESS_DENIED;
    }

    call_original()
}

pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    macro_rules! install_guard {
        ($lock:expr, $sym:literal, $hook_fn:expr, $fn_ty:ty) => {{
            let addr = crate::hooks::ntdll_export($sym.as_bytes())
                .ok_or_else(|| format!("ntdll export not found: {}", $sym))?;
            let target: $fn_ty = std::mem::transmute(addr as usize);
            let hook_ptr: $fn_ty = $hook_fn;
            let detour = GenericDetour::<$fn_ty>::new(target, hook_ptr)
                .map_err(|e| format!("detour init {}: {:?}", $sym, e))?;
            $lock.set(detour).ok();
            $lock.get().expect("set above").enable()
                .map_err(|e| format!("detour enable {}: {:?}", $sym, e))?;
        }};
    }

    install_guard!(HOOK_FS_CONTROL, "NtFsControlFile\0", hook_nt_fs_control_file, FnNtFsControlFile);
    install_guard!(HOOK_SET_INFO, "NtSetInformationFile\0", hook_nt_set_information_file, FnNtSetInformationFile);

    Ok(())
}

pub unsafe fn uninstall() {
    if let Some(h) = HOOK_SET_INFO.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_FS_CONTROL.get() { let _ = h.disable(); }
}
