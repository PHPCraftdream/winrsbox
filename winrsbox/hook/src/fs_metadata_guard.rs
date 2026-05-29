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
use crate::hooks::STATUS_ACCESS_DENIED;

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

/// `NtSetEaFile` — writes NTFS Extended Attributes to an already-open handle.
///
/// Signature (per ntdll!NtSetEaFile, Windows 10/11 x64):
/// ```c
/// NTSTATUS NtSetEaFile(
///     HANDLE FileHandle,
///     PIO_STATUS_BLOCK IoStatusBlock,
///     PVOID Buffer,
///     ULONG Length
/// );
/// ```
///
/// EAs are off-band, do not appear in directory listings, persist across
/// reboots, and have been documented as covert payload storage by
/// BlackLotus-class loaders. No expected sandboxed workload writes EAs.
type FnNtSetEaFile = unsafe extern "system" fn(
    HANDLE,                  // FileHandle
    *mut IO_STATUS_BLOCK,    // IoStatusBlock
    *mut c_void,             // Buffer
    u32,                     // Length
) -> NTSTATUS;

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

static HOOK_NT_SET_INFO_FILE: OnceLock<GenericDetour<FnNtSetInformationFile>> = OnceLock::new();
static HOOK_NT_FS_CONTROL_FILE: OnceLock<GenericDetour<FnNtFsControlFile>> = OnceLock::new();
static HOOK_NT_SET_EA_FILE: OnceLock<GenericDetour<FnNtSetEaFile>> = OnceLock::new();

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

/// Returns true if a rename/hardlink destination is an escape vector and must
/// be denied. The previous code only checked `starts_with(sandbox_root)`, which
/// a `..` segment defeats: the literal string `c:\sandbox\..\..\windows\x`
/// passes the prefix test, then the kernel collapses `..` and writes outside
/// the sandbox. This mirrors the create-side denylist in
/// `hooks::check_path_traversal` (parent-dir traversal, `.winrsbox` state dir,
/// GLOBALROOT, 8.3 short-names), applied to the resolved lowercase DOS path.
fn dest_is_escape(dest_lower: &str) -> bool {
    // Fold `/`→`\` first so separators match the kernel's view (and so a
    // `/`-separated `..` is caught below). `dest_lower` is already lowercased.
    let folded = dest_lower.replace('/', "\\");
    // Parent/self traversal — a segment consisting only of dots/spaces (`.`,
    // `..`, `...`, `. `) is either traversal or an NTFS trailing-dot trick. Must
    // run BEFORE strip_trailing_dot_space, which would collapse `..` into an
    // empty segment and hide it. (This `..` rejection is rename-specific: it
    // protects the starts_with(sandbox_root) containment below.)
    if folded
        .split('\\')
        .any(|seg| !seg.is_empty() && seg.bytes().all(|b| b == b'.' || b == b' '))
    {
        return true;
    }
    // Shared escape denylist (GLOBALROOT / ADS / 8.3 short-name / .winrsbox) —
    // single source of truth with the create-side hooks::check_path_traversal,
    // so the two guards cannot drift. Mirror NTFS per-segment trailing dot/space
    // stripping first.
    let canon = hooks::strip_trailing_dot_space(&folded);
    hooks::canonical_denylist_status(canon.as_ref()).is_some()
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

            let Some(dest) = resolve_dest_path(root, &dest_name) else {
                if hooks::is_trace() {
                    hooks::ipc_log(ipc::LogLevel::Trace,
                        format!("fs_setinfo_unresolvable_dest class={class} raw={dest_name}"));
                }
                if !iosb.is_null() {
                    hooks::set_io_status(iosb, STATUS_ACCESS_DENIED);
                }
                return STATUS_ACCESS_DENIED;
            };
            // Escape-vector denylist (traversal, .winrsbox, GLOBALROOT,
            // 8.3 short-name) — mirrors create-side check_path_traversal.
            // Runs regardless of SANDBOX_CWD: it rejects on path SHAPE, so a
            // `..` traversal can't defeat the containment check below.
            if dest_is_escape(&dest) {
                if hooks::is_trace() {
                    hooks::ipc_log(ipc::LogLevel::Trace,
                        format!("fs_setinfo_block_escape class={} dest={}", class, dest));
                }
                if !iosb.is_null() {
                    hooks::set_io_status(iosb, STATUS_ACCESS_DENIED);
                }
                return STATUS_ACCESS_DENIED;
            }
            // Check if destination is outside sandbox root
            if let Some(sandbox_root) = hooks::SANDBOX_CWD.get() {
                if !policy::path::pattern_matches_prefix(&sandbox_root.to_lowercase(), &dest) {
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
                        if !policy::path::pattern_matches_prefix(&sandbox_root.to_lowercase(), &path) {
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

/// Unconditionally deny `NtSetEaFile`. Symmetric to the EA-buffer block in
/// `hook_nt_create_file`: closes the post-open vector where a child writes
/// EAs to a handle the sandbox already opened. NtQueryEaFile is read-only
/// and intentionally left alone — info-leak is out of scope for this fix.
///
/// # Safety
/// Called by the kernel via the installed detour with NT-ABI-conformant
/// arguments. We do not dereference Buffer; we only write to IoStatusBlock
/// if non-null. iosb is the only pointer touched and the standard NT
/// convention guarantees it points at writable memory or is null.
unsafe extern "system" fn hook_nt_set_ea_file(
    _handle: HANDLE,
    iosb: *mut IO_STATUS_BLOCK,
    _buffer: *mut c_void,
    length: u32,
) -> NTSTATUS {
    // No need to call original — unconditional deny.
    // Skip anti_rec: this hook is a leaf (no NT re-entry), and even if our
    // own code somehow set EAs we'd want to know about it.
    if hooks::is_trace() {
        hooks::ipc_log(ipc::LogLevel::Trace,
            format!("nt_set_ea_file_blocked length={}", length));
    }
    crate::ipc_client::ipc_log_violation(ipc::Req::Log {
        pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
        level: ipc::LogLevel::Warn,
        msg: format!("nt_set_ea_file_blocked length={}", length),
    });
    if !iosb.is_null() {
        hooks::set_io_status(iosb, STATUS_ACCESS_DENIED);
    }
    STATUS_ACCESS_DENIED
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

    // NtSetEaFile — closes the post-open NTFS EA-write vector (audit H-S3).
    // Best-effort: if this fails the rest of fs_metadata_guard is still
    // useful, and the create-time EA block in fs_hooks.rs still catches
    // EA-setting via NtCreateFile. Surface the failure via buffer_install_error.
    match hooks::ntdll_export(b"NtSetEaFile\0") {
        Some(addr) => {
            let target: FnNtSetEaFile = std::mem::transmute(addr as usize);
            let hook_ptr: FnNtSetEaFile = hook_nt_set_ea_file;
            match GenericDetour::<FnNtSetEaFile>::new(target, hook_ptr) {
                Ok(detour) => {
                    let _ = HOOK_NT_SET_EA_FILE.set(detour);
                    if let Some(d) = HOOK_NT_SET_EA_FILE.get() {
                        if let Err(e) = d.enable() {
                            crate::hooks::buffer_install_error(
                                format!("NtSetEaFile enable failed: {:?}", e));
                        }
                    }
                }
                Err(e) => crate::hooks::buffer_install_error(
                    format!("NtSetEaFile detour init failed: {:?}", e)),
            }
        }
        None => crate::hooks::buffer_install_error(
            "NtSetEaFile export not found in ntdll".into()),
    }

    Ok(())
}

pub unsafe fn uninstall() {
    if let Some(h) = HOOK_NT_SET_EA_FILE.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_NT_FS_CONTROL_FILE.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_NT_SET_INFO_FILE.get() { let _ = h.disable(); }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// `hook_nt_set_ea_file` MUST return STATUS_ACCESS_DENIED for any input,
    /// including null pointers and zero length. This is the contract that
    /// makes the unconditional deny safe: we never dereference Buffer and
    /// we tolerate a null IoStatusBlock.
    #[test]
    fn nt_set_ea_file_unconditional_deny() {
        let status = unsafe {
            hook_nt_set_ea_file(
                std::ptr::null_mut(), // FileHandle
                std::ptr::null_mut(), // IoStatusBlock (null tolerated)
                std::ptr::null_mut(), // Buffer
                0,                    // Length
            )
        };
        assert_eq!(status, STATUS_ACCESS_DENIED);

        // Also with a non-zero length — must still deny without inspecting Buffer.
        let status = unsafe {
            hook_nt_set_ea_file(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                4096,
            )
        };
        assert_eq!(status, STATUS_ACCESS_DENIED);
    }

    /// When IoStatusBlock IS provided, the hook must populate it with the
    /// deny status before returning. Callers reading the IOSB Status field
    /// must observe the same value as the return.
    #[test]
    fn nt_set_ea_file_writes_io_status_block() {
        // IO_STATUS_BLOCK contains a winapi UNION! field with no Default impl.
        // mem::zeroed is the standard idiom for this ABI-compatible POD.
        // SAFETY: IO_STATUS_BLOCK is (union | usize)-sized POD; all-zero is
        // a valid "no status, no information" bit pattern.
        let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        let status = unsafe {
            hook_nt_set_ea_file(
                std::ptr::null_mut(),
                &mut iosb as *mut _,
                std::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(status, STATUS_ACCESS_DENIED);
        // Status field is at offset 0 (Status/Pointer union). set_io_status
        // zeros the union slot then writes the 4-byte NTSTATUS.
        // SAFETY: reading the Status arm of the union after we wrote it
        // through set_io_status (same offset) is sound.
        let raw_status = unsafe { *(&iosb as *const _ as *const NTSTATUS) };
        assert_eq!(raw_status, STATUS_ACCESS_DENIED);
    }
}
