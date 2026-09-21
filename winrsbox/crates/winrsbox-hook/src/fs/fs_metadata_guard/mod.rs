// fs_metadata_guard — NtSetInformationFile + NtFsControlFile hooks.
//
// Blocks rename/hardlink/disposition escaping sandbox boundaries and
// reparse-point creation/deletion.

use std::sync::OnceLock;

use detour2::GenericDetour;
use ntapi::ntioapi::IO_STATUS_BLOCK;
use ntapi::winapi::shared::ntdef::HANDLE;
use ntapi::winapi::shared::ntdef::NTSTATUS;
use ntapi::winapi::shared::ntdef::OBJECT_ATTRIBUTES;
use ntapi::winapi::shared::ntdef::UNICODE_STRING;
use winapi::ctypes::c_void;

use crate::anti_rec;
use crate::hooks;
use crate::hooks::{nt_call_original, STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_NOT_FOUND};

mod setinfo;
pub(crate) use setinfo::*;

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

/// `NtDeleteFile` — deletes a file BY PATH, without opening a handle (P0-02).
///
/// Signature (per ntdll!NtDeleteFile, Windows 10/11 x64):
/// ```c
/// NTSTATUS NtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes);
/// ```
///
/// `DeleteFileW`/`std::fs::remove_file` delete through the disposition
/// classes of `NtSetInformationFile` (covered by
/// `hook_nt_set_information_file`); `NtDeleteFile` is a separate ntdll
/// export that resolves and deletes the object in one step, so it carries
/// its own policy check below.
pub(crate) type FnNtDeleteFile = unsafe extern "system" fn(*mut OBJECT_ATTRIBUTES) -> NTSTATUS;

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

static HOOK_NT_SET_INFO_FILE: OnceLock<GenericDetour<FnNtSetInformationFile>> = OnceLock::new();
static HOOK_NT_FS_CONTROL_FILE: OnceLock<GenericDetour<FnNtFsControlFile>> = OnceLock::new();
static HOOK_NT_SET_EA_FILE: OnceLock<GenericDetour<FnNtSetEaFile>> = OnceLock::new();
pub(crate) static HOOK_NT_DELETE_FILE: OnceLock<GenericDetour<FnNtDeleteFile>> = OnceLock::new();

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
// NTSTATUS constants used by the disposition handler
// ---------------------------------------------------------------------------

const STATUS_SUCCESS: NTSTATUS = 0;
/// Directory still has open handles or children (handle-contention / race).
const STATUS_DIRECTORY_NOT_EMPTY: NTSTATUS = 0xC000_0101_u32 as NTSTATUS;
/// Another process has the file open in an incompatible share mode.
const STATUS_SHARING_VIOLATION: NTSTATUS   = 0xC000_0043_u32 as NTSTATUS;
/// The object manager encountered a reparse point while retrieving an object.
/// Returned by some kernel filter drivers (e.g. AnviFPFltd) or when a path
/// component inside the overlay is unexpectedly tagged as a reparse point.
/// Treat the same as NOT_EMPTY: the physical delete did not complete but we
/// still need to hide the virtual path so a subsequent install succeeds.
const STATUS_REPARSE_POINT_ENCOUNTERED: NTSTATUS = 0xC000_0274_u32 as NTSTATUS;

/// Sanity cap for the `NtDeleteFile` ObjectName buffer, in BYTES — the same
/// 0x8000 bound the FILE_RENAME_INFORMATION path applies to its FileName.
const MAX_OBJECT_NAME_BYTES: usize = 0x8000;

// ---------------------------------------------------------------------------
// Post-delete whiteout decision
// ---------------------------------------------------------------------------

/// What the overlay-delete handler should do after `call_original()` returns.
#[derive(Debug, PartialEq)]
enum WhiteoutAction {
    /// Status is a hard error — do not record any whiteout.
    Skip,
    /// Record the whiteout but keep the OVERLAY_IDX entry (physical overlay
    /// file may still exist due to handle contention / non-emptiness).
    RecordWhiteoutKeepOverlay,
    /// Record the whiteout AND remove the OVERLAY_IDX entry (file is physically
    /// gone, overlay storage is clean).
    RecordWhiteoutAndRemoveIdx,
}

/// Pure decision function: given the NTSTATUS returned by the kernel for a
/// `NtSetInformationFile(FileDispositionInfo, delete=true)` call on an
/// overlay-resident path, decide what the hook should do next.
///
/// Returning `RecordWhiteout*` for `STATUS_DIRECTORY_NOT_EMPTY`,
/// `STATUS_SHARING_VIOLATION`, and `STATUS_REPARSE_POINT_ENCOUNTERED` fixes
/// bug #76/#79: when the physical delete is blocked by handle contention, a
/// non-empty directory, or a reparse-point interception by a kernel filter
/// driver (e.g. AnviFPFltd), we still need to hide the virtual path so a
/// subsequent install/clone into the same location succeeds.
fn decide_post_delete(status: NTSTATUS) -> WhiteoutAction {
    match status {
        STATUS_SUCCESS => WhiteoutAction::RecordWhiteoutAndRemoveIdx,
        STATUS_DIRECTORY_NOT_EMPTY
        | STATUS_SHARING_VIOLATION
        | STATUS_REPARSE_POINT_ENCOUNTERED => {
            WhiteoutAction::RecordWhiteoutKeepOverlay
        }
        _ => WhiteoutAction::Skip,
    }
}

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
///
/// If the resolved path lands inside the overlay storage (because the root
/// handle was itself CoW-redirected), it is unmirrored back to its virtual
/// form — WITHOUT this, `decide` would mirror the overlay path AGAIN,
/// producing a double-nested overlay location and breaking rename operations.
unsafe fn resolve_dest_path(root: HANDLE, name: &str) -> Option<String> {
    let raw = if root.is_null() {
        // name is absolute (NT path like \??\C:\... or DOS like C:\...)
        let name_u16: Vec<u16> = name.encode_utf16().collect();
        policy::path::nt_to_dos_lower(&name_u16)?
    } else {
        // Relative: resolve root handle path, then append name
        let base = query_handle_dos_path(root)?;
        let full = if name.starts_with('\\') {
            format!("{}{}", base, name)
        } else {
            format!("{}\\{}", base, name)
        };
        full.to_ascii_lowercase()
    };
    // Unmirror: if the resolved path is under an overlay root (because the
    // root handle lives in the overlay), convert it back to its virtual form
    // so decide/mirror operates on the correct path. Without this the rename
    // dest is double-mirrored into a nested overlay location.
    let sb_root = hooks::SANDBOX_ROOT.get().map(|s| s.as_str());
    let unmirrored = hooks::unmirror_overlay_handle_relative(&raw, sb_root);
    Some(unmirrored.unwrap_or(raw))
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
    if let Some(h) = HOOK_NT_DELETE_FILE.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_NT_SET_EA_FILE.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_NT_FS_CONTROL_FILE.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_NT_SET_INFO_FILE.get() { let _ = h.disable(); }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests;
