// fs_metadata_guard — NtSetInformationFile + NtFsControlFile hooks.
//
// Blocks rename/hardlink/disposition escaping sandbox boundaries and
// reparse-point creation/deletion.

use std::sync::OnceLock;

use detour2::GenericDetour;
use ntapi::ntioapi::IO_STATUS_BLOCK;
use ntapi::winapi::shared::ntdef::HANDLE;
use ntapi::winapi::shared::ntdef::NTSTATUS;
use winapi::ctypes::c_void;

use crate::anti_rec;
use crate::hooks;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

type FnNtSetInformationFile = unsafe extern "system" fn(
    HANDLE,                  // FileHandle
    *mut IO_STATUS_BLOCK,    // IoStatusBlock
    *mut c_void,             // FileInformation
    u32,                     // Length
    u32,                     // FileInformationClass
) -> NTSTATUS;

type FnNtFsControlFile = unsafe extern "system" fn(
    HANDLE,                  // FileHandle
    HANDLE,                  // Event
    *mut c_void,             // ApcRoutine
    *mut c_void,             // ApcContext
    *mut IO_STATUS_BLOCK,    // IoStatusBlock
    u32,                     // FsControlCode
    *mut c_void,             // InputBuffer
    u32,                     // InputBufferLength
    *mut c_void,             // OutputBuffer
    u32,                     // OutputBufferLength
) -> NTSTATUS;

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

static HOOK_NT_SET_INFO_FILE: OnceLock<GenericDetour<FnNtSetInformationFile>> = OnceLock::new();
static HOOK_NT_FS_CONTROL_FILE: OnceLock<GenericDetour<FnNtFsControlFile>> = OnceLock::new();

// ---------------------------------------------------------------------------
// STATUS codes
// ---------------------------------------------------------------------------

const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000_0022_u32 as NTSTATUS;

// ---------------------------------------------------------------------------
// FileInformationClass constants
// ---------------------------------------------------------------------------

const FILE_RENAME_INFO_CLASS: u32 = 10;
const FILE_RENAME_EX_INFO_CLASS: u32 = 65;
const FILE_LINK_INFO_CLASS: u32 = 11;
const FILE_LINK_EX_INFO_CLASS: u32 = 72;
const FILE_DISPOSITION_INFO_CLASS: u32 = 13;
const FILE_DISPOSITION_EX_INFO_CLASS: u32 = 64;

// ---------------------------------------------------------------------------
// FSCTL constants
// ---------------------------------------------------------------------------

const FSCTL_SET_REPARSE_POINT: u32    = 0x900A4;
const FSCTL_SET_REPARSE_POINT_EX: u32 = 0x900E4;
const FSCTL_DELETE_REPARSE_POINT: u32 = 0x900AC;
const FSCTL_PIPE_IMPERSONATE: u32     = 0x11003C;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the DOS path of an open file handle via GetFinalPathNameByHandleW.
/// Returns lowercase DOS path without `\\?\` prefix, or None on failure.
pub(crate) unsafe fn query_handle_dos_path(handle: HANDLE) -> Option<String> {
    use winapi::um::fileapi::GetFinalPathNameByHandleW;
    const VOLUME_NAME_DOS: u32 = 0;
    let mut buf: Vec<u16> = vec![0; 4096];
    let len = GetFinalPathNameByHandleW(
        handle, buf.as_mut_ptr(), buf.len() as u32, VOLUME_NAME_DOS,
    );
    if len == 0 || len as usize >= buf.len() {
        return None;
    }
    let s = String::from_utf16_lossy(&buf[..len as usize]);
    let lower = s.to_ascii_lowercase();
    let stripped = lower.strip_prefix(r"\\?\").unwrap_or(&lower).to_string();
    Some(stripped)
}

/// Given a RootDirectory handle and a filename from FILE_RENAME/LINK_INFORMATION,
/// resolve to an absolute lowercase DOS path. Returns None on failure.
unsafe fn resolve_dest_path(root: HANDLE, name: &str) -> Option<String> {
    if root.is_null() {
        // name is absolute (NT path like \??\C:\... or DOS like C:\...)
        let name_u16: Vec<u16> = name.encode_utf16().collect();
        policy::path::nt_to_dos_lower(&name_u16)
    } else {
        // Relative: resolve root handle path, then append name
        let base = query_handle_dos_path(root)?;
        let full = if name.starts_with('\\') {
            format!("{}{}", base, name)
        } else {
            format!("{}\\{}", base, name)
        };
        Some(full.to_ascii_lowercase())
    }
}

// ---------------------------------------------------------------------------
// Hook implementations
// ---------------------------------------------------------------------------

unsafe extern "system" fn hook_nt_set_information_file(
    handle: HANDLE,
    iosb: *mut IO_STATUS_BLOCK,
    info: *mut c_void,
    len: u32,
    class: u32,
) -> NTSTATUS {
    let call_original = || {
        HOOK_NT_SET_INFO_FILE.get().unwrap().call(handle, iosb, info, len, class)
    };
    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    match class {
        FILE_RENAME_INFO_CLASS | FILE_RENAME_EX_INFO_CLASS
        | FILE_LINK_INFO_CLASS | FILE_LINK_EX_INFO_CLASS => {
            // Layout for non-Ex (RENAME/LINK):
            //   0x00: ReplaceIfExists (BOOLEAN)
            //   0x08: RootDirectory (HANDLE)
            //   0x10: FileNameLength (ULONG)
            //   0x14: FileName[] (WCHAR)
            // Layout for Ex (RENAME_EX/LINK_EX):
            //   0x00: Flags (ULONG)
            //   0x08: RootDirectory (HANDLE)
            //   0x10: FileNameLength (ULONG)
            //   0x14: FileName[] (WCHAR)
            // Both variants share RootDirectory at 0x08, FileNameLength at 0x10, FileName at 0x14.
            let off_root = 0x08usize;
            let off_namelen = 0x10usize;
            let off_name = 0x14usize;
            if (len as usize) < off_name {
                return call_original();
            }

            let info_bytes = info as *mut u8;
            let root = *(info_bytes.add(off_root) as *const HANDLE);
            let name_len = *(info_bytes.add(off_namelen) as *const u32) as usize;
            if name_len == 0 || name_len > 0x8000 {
                return call_original();
            }
            // Bounds check: FileName buffer must fit within declared Length
            if off_name + name_len > len as usize {
                return call_original();
            }
            let name_ptr = info_bytes.add(off_name) as *const u16;
            let chars = name_len / 2;
            let name_slice = std::slice::from_raw_parts(name_ptr, chars);
            let dest_name = String::from_utf16_lossy(name_slice);

            if let Some(dest) = resolve_dest_path(root, &dest_name) {
                // Check if destination is outside sandbox root
                if let Some(sandbox_root) = hooks::SANDBOX_CWD.get() {
                    if !dest.starts_with(&sandbox_root.to_lowercase()) {
                        if hooks::is_trace() {
                            hooks::ipc_log(ipc::LogLevel::Trace,
                                format!("fs_setinfo_block_outside class={} dest={}", class, dest));
                        }
                        if !iosb.is_null() {
                            hooks::set_io_status(iosb, STATUS_ACCESS_DENIED);
                        }
                        return STATUS_ACCESS_DENIED;
                    }
                }
            }
        }
        FILE_DISPOSITION_INFO_CLASS | FILE_DISPOSITION_EX_INFO_CLASS => {
            let wants_delete = if class == FILE_DISPOSITION_EX_INFO_CLASS {
                if (len as usize) < 4 { return call_original(); }
                let flags = *(info as *const u32);
                (flags & 1) != 0 // FILE_DISPOSITION_DELETE
            } else {
                if (len as usize) < 1 { return call_original(); }
                *(info as *const u8) != 0 // DeleteFile = TRUE
            };
            if wants_delete {
                if let Some(path) = query_handle_dos_path(handle) {
                    if let Some(sandbox_root) = hooks::SANDBOX_CWD.get() {
                        if !path.starts_with(&sandbox_root.to_lowercase()) {
                            if hooks::is_trace() {
                                hooks::ipc_log(ipc::LogLevel::Trace,
                                    format!("fs_setinfo_delete_block path={}", path));
                            }
                            if !iosb.is_null() {
                                hooks::set_io_status(iosb, STATUS_ACCESS_DENIED);
                            }
                            return STATUS_ACCESS_DENIED;
                        }
                    }
                }
            }
        }
        _ => {}
    }

    call_original()
}

unsafe extern "system" fn hook_nt_fs_control_file(
    handle: HANDLE,
    event: HANDLE,
    apc_routine: *mut c_void,
    apc_context: *mut c_void,
    iosb: *mut IO_STATUS_BLOCK,
    fs_control_code: u32,
    input: *mut c_void, input_len: u32,
    output: *mut c_void, output_len: u32,
) -> NTSTATUS {
    let call_original = || {
        HOOK_NT_FS_CONTROL_FILE.get().unwrap().call(
            handle, event, apc_routine, apc_context, iosb,
            fs_control_code, input, input_len, output, output_len,
        )
    };
    let Some(_g) = anti_rec::enter() else { return call_original(); };

    match fs_control_code {
        FSCTL_SET_REPARSE_POINT
        | FSCTL_SET_REPARSE_POINT_EX
        | FSCTL_DELETE_REPARSE_POINT
        | FSCTL_PIPE_IMPERSONATE => {
            if hooks::is_trace() {
                let src = query_handle_dos_path(handle).unwrap_or_default();
                hooks::ipc_log(ipc::LogLevel::Trace,
                    format!("fs_fsctl_block code=0x{:x} src={}", fs_control_code, src));
            }
            if !iosb.is_null() {
                hooks::set_io_status(iosb, STATUS_ACCESS_DENIED);
            }
            return STATUS_ACCESS_DENIED;
        }
        _ => {}
    }

    call_original()
}

// ---------------------------------------------------------------------------
// Install / uninstall
// ---------------------------------------------------------------------------

pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    macro_rules! install {
        ($lock:expr, $sym:literal, $hook_fn:expr, $fn_ty:ty) => {{
            let addr = hooks::ntdll_export($sym.as_bytes())
                .ok_or_else(|| format!("ntdll export not found: {}", $sym))?;
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

    install!(HOOK_NT_SET_INFO_FILE,   "NtSetInformationFile\0", hook_nt_set_information_file, FnNtSetInformationFile);
    install!(HOOK_NT_FS_CONTROL_FILE, "NtFsControlFile\0",      hook_nt_fs_control_file,      FnNtFsControlFile);

    Ok(())
}

pub unsafe fn uninstall() {
    if let Some(h) = HOOK_NT_FS_CONTROL_FILE.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_NT_SET_INFO_FILE.get() { let _ = h.disable(); }
}
