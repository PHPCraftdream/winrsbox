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

/// Parsed header of a FILE_RENAME_INFORMATION / FILE_LINK_INFORMATION buffer
/// (or their Ex variants): the RootDirectory handle and the decoded FileName.
///
/// Every field read is unaligned: the buffer is caller-owned memory handed to
/// NtSetInformationFile by the sandboxed process, so neither its base
/// alignment nor any field offset within it is guaranteed — a caller can pass
/// a buffer at an odd address, leaving RootDirectory (0x08), FileNameLength
/// (0x10) and FileName[] (0x14) misaligned. Plain dereferences there are UB
/// (and abort under the debug alignment check).
///
/// Returns `None` — the hook must then pass the call through to the original
/// syscall untouched — when the buffer is shorter than the fixed header, the
/// name length is zero or absurd (> 0x8000 bytes, the same sanity cap the
/// NtDeleteFile path applies), or the name would run past the declared
/// buffer length.
///
/// # SAFETY
/// `info` must be readable for `len` bytes (the NtSetInformationFile contract
/// at hook entry).
unsafe fn parse_rename_info(info: *const u8, len: usize) -> Option<(HANDLE, String)> {
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
    const OFF_ROOT: usize = 0x08;
    const OFF_NAMELEN: usize = 0x10;
    const OFF_NAME: usize = 0x14;
    if len < OFF_NAME {
        return None;
    }

    let root = (info.add(OFF_ROOT) as *const HANDLE).read_unaligned();
    let name_len = (info.add(OFF_NAMELEN) as *const u32).read_unaligned() as usize;
    if name_len == 0 || name_len > 0x8000 {
        return None;
    }
    // Bounds check: FileName buffer must fit within declared Length
    if OFF_NAME + name_len > len {
        return None;
    }
    let name_ptr = info.add(OFF_NAME) as *const u16;
    let chars = name_len / 2;
    let name: Vec<u16> = (0..chars)
        .map(|i| {
            // SAFETY: i < chars and OFF_NAME + name_len <= len, so every
            // read stays inside the caller's buffer.
            unsafe { name_ptr.add(i).read_unaligned() }
        })
        .collect();
    Some((root, String::from_utf16_lossy(&name)))
}

/// Build a caller-independent FILE_RENAME_INFORMATION-family buffer whose
/// RootDirectory is NULL and whose FileName is the ABSOLUTE NT form of the
/// resolved + policy-approved destination.
///
/// Layout (rename and link, non-Ex and Ex — byte-identical from 0x08 up):
///   0x00: ReplaceIfExists / Flags (8 bytes, copied verbatim from `orig`)
///   0x08: RootDirectory = NULL
///   0x10: FileNameLength (bytes, excluding the terminator)
///   0x14: FileName[] (UTF-16, NUL-terminated)
///
/// Returns the new buffer and its total length. `None` when `orig` is
/// shorter than the fixed header — the caller must fail closed, never
/// fall back to the caller's relative buffer.
fn build_absolute_rename_buffer(orig: &[u8], dest_dos_lower: &str) -> Option<(Vec<u8>, u32)> {
    if orig.len() < 0x14 {
        return None;
    }
    let nt_name = policy::path::dos_to_nt(dest_dos_lower);
    debug_assert!(nt_name.last() == Some(&0), "dos_to_nt NUL-terminates");
    let mut out = Vec::with_capacity(0x14 + nt_name.len() * 2);
    out.extend_from_slice(&orig[..8]); // ReplaceIfExists / Flags verbatim
    out.extend_from_slice(&0u64.to_ne_bytes()); // RootDirectory = NULL
    // FileNameLength counts the name bytes only, not the NUL terminator.
    out.extend_from_slice(&(((nt_name.len() - 1) * 2) as u32).to_le_bytes());
    for w in &nt_name {
        out.extend_from_slice(&w.to_le_bytes());
    }
    Some((out, (0x14 + nt_name.len() * 2) as u32))
}

/// Decode a FILE_DISPOSITION_INFORMATION (non-Ex) or
/// FILE_DISPOSITION_INFO_EX buffer into (wants_delete, ex_flags). `ex_flags`
/// carries the raw Ex flags word (the diagnostics path reads the
/// POSIX-semantics bit out of it) and is 0 for the non-Ex class.
///
/// The Ex flags field is read unaligned: the buffer is caller-owned memory
/// with no base-alignment guarantee, and the kernel does not force
/// FILE_DISPOSITION_INFO_EX buffers onto a 4-byte boundary. The non-Ex class
/// reads a single BYTE at offset 0, which is aligned by definition.
///
/// Returns `None` when the buffer is too short for the class — the hook then
/// passes the call through to the original syscall.
///
/// # SAFETY
/// `info` must be readable for `len` bytes (the NtSetInformationFile contract
/// at hook entry).
unsafe fn parse_disposition_info(info: *const u8, len: usize, class: u32) -> Option<(bool, u32)> {
    if class == FILE_DISPOSITION_EX_INFO_CLASS {
        if len < 4 {
            return None;
        }
        let flags = (info as *const u32).read_unaligned();
        Some(((flags & 1) != 0, flags)) // FILE_DISPOSITION_DELETE
    } else {
        if len < 1 {
            return None;
        }
        // SAFETY: single-byte read; len >= 1 guarantees its validity.
        Some((*info != 0, 0)) // DeleteFile = TRUE
    }
}

unsafe extern "system" fn hook_nt_set_information_file(
    handle: HANDLE,
    iosb: *mut IO_STATUS_BLOCK,
    info: *mut c_void,
    len: u32,
    class: u32,
) -> NTSTATUS {
    let call_original = || {
        nt_call_original!(&HOOK_NT_SET_INFO_FILE, "NtSetInformationFile",
            (handle, iosb, info, len, class))
    };
    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    match class {
        FILE_RENAME_INFO_CLASS | FILE_RENAME_EX_INFO_CLASS
        | FILE_LINK_INFO_CLASS | FILE_LINK_EX_INFO_CLASS => {
            // Buffer parsing (RootDirectory, FileNameLength, FileName) lives
            // in parse_rename_info — every field is read UNALIGNED there,
            // because the caller-owned buffer has no base-alignment
            // guarantee. `None` means "malformed / too short" and passes the
            // call through to the original syscall.
            let Some((root, dest_name)) = parse_rename_info(info as *const u8, len as usize)
            else {
                return call_original();
            };

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
            // Allow the rename/hardlink destination if policy would allow a
            // write there. This mirrors the create-side decision so an external
            // path that policy isolates via CoW (e.g. d:\e2e_external — outside
            // project_root but recorded as Cow) stays writable. Without this,
            // git's atomic `create config.lock` → `rename → config` workflow
            // fails inside a CoW-managed external dir: the .lock write is
            // allowed (Cow) but the rename to the bare name is denied because
            // the destination isn't under SANDBOX_CWD, leaving the repo half-
            // initialized (no HEAD/config/objects).
            //
            // Passthrough → inside project_root (real write) — call original.
            // Cow/Mock    → external path CoW-managed into the overlay. The
            //               caller's source handle points at the overlay copy
            //               (create/open redirected it there), but the rename
            //               buffer still names the VIRTUAL destination, so we
            //               must rewrite the FileName to the overlay path and
            //               null RootDirectory so the kernel targets the same
            //               layer the source handle lives on.
            // Deny       → block.
            // Hidden     → revive (same as NtCreateFile's revive path in
            //              fs_hooks.rs): a rename/hardlink onto a whiteouted
            //              path is a re-creation of that path. The source will
            //              be moved/linked into the overlay, superseding the
            //              tombstone, so we clear the whiteout and re-decide.
            //              Without this, `git config` (which on a fresh repo
            //              renames `config.lock` over a `.git/config` path that
            //              `git init` never populated because it too was
            //              whiteouted by a prior `rm -rf .git`) is denied, every
            //              subsequent git command fails to read config, and the
            //              repo is unusable.
            let mut decision = hooks::decide(&dest, true);
            if decision.mode == policy::Mode::Hidden {
                let lower = dest.to_ascii_lowercase();
                hooks::ipc_clear_whiteout(&lower);
                hooks::cache().invalidate(&lower);
                if hooks::is_trace() {
                    hooks::ipc_log(ipc::LogLevel::Trace,
                        format!("fs_whiteout_revive setinfo_rename: {dest}"));
                }
                decision = hooks::decide(&dest, true);
            }
            match decision.mode {
                policy::Mode::Passthrough => {
                    if root.is_null() {
                        return call_original();
                    }
                    // Relative rename (RootDirectory != NULL): `dest` was
                    // resolved from ONE query of the root handle, and the
                    // decision above approved exactly that path. Handing the
                    // caller's buffer back to the original syscall makes the
                    // kernel re-resolve the same handle VALUE at call time —
                    // a concurrent NtClose + handle-recycle between the two
                    // resolutions retargets the rename at a directory we
                    // never approved (the H5 double-resolve class fixed in
                    // hooks::resolve_for_hook; audit 2026-09-19 Low:
                    // rename-Passthrough keeps a racy RootDirectory).
                    // Rewrite the buffer to the absolute NT form with
                    // RootDirectory = NULL so the kernel acts on exactly the
                    // approved path; fail closed if it cannot be rebuilt.
                    // SAFETY: `info` is readable for `len` bytes per the
                    // NtSetInformationFile contract at hook entry (the same
                    // guarantee parse_rename_info relies on).
                    let orig_bytes =
                        std::slice::from_raw_parts(info as *const u8, len as usize);
                    let Some((rewritten, rewritten_len)) =
                        build_absolute_rename_buffer(orig_bytes, &dest)
                    else {
                        if hooks::is_trace() {
                            hooks::ipc_log(
                                ipc::LogLevel::Trace,
                                format!("fs_setinfo_passthrough_rewrite_failed class={class} dest={dest}"),
                            );
                        }
                        if !iosb.is_null() {
                            hooks::set_io_status(iosb, STATUS_ACCESS_DENIED);
                        }
                        return STATUS_ACCESS_DENIED;
                    };
                    return nt_call_original!(
                        &HOOK_NT_SET_INFO_FILE,
                        "NtSetInformationFile",
                        (handle, iosb, rewritten.as_ptr() as *mut c_void, rewritten_len, class)
                    );
                }
                policy::Mode::Cow | policy::Mode::Mock => {
                    if decision.overlay.is_none() {
                        if !iosb.is_null() {
                            hooks::set_io_status(iosb, STATUS_ACCESS_DENIED);
                        }
                        return STATUS_ACCESS_DENIED;
                    }
                    // Mirror into overlay (records the index entry and creates
                    // parent dirs) so subsequent opens at the virtual path
                    // resolve here. prepare_overlay also returns the canonical
                    // overlay DOS path to splice into the rename buffer.
                    let overlay_dos = match hooks::prepare_overlay(&decision) {
                        Some(p) => p,
                        None => {
                            if !iosb.is_null() {
                                hooks::set_io_status(iosb, STATUS_ACCESS_DENIED);
                            }
                            return STATUS_ACCESS_DENIED;
                        }
                    };
                    let dest_lower = dest.to_ascii_lowercase();
                    let is_link = class == FILE_LINK_INFO_CLASS
                        || class == FILE_LINK_EX_INFO_CLASS;
                    // Source-side bookkeeping. For a *rename* (not hardlink),
                    let src_raw_for_check: String = if !is_link {
                        query_handle_dos_path(handle).unwrap_or_default()
                    } else {
                        String::new()
                    };
                    if !is_link && !src_raw_for_check.is_empty() {
                        // Unmirror the source path: the handle lives in the
                        // overlay (CoW-redirected), so query_handle_dos_path
                        // returns the OVERLAY path, not the virtual path.
                        let sb_root = hooks::SANDBOX_ROOT.get().map(|s| s.as_str());
                        let src = hooks::unmirror_overlay_handle_relative(&src_raw_for_check, sb_root)
                            .unwrap_or_else(|| src_raw_for_check.clone());
                        let src_lower = src.to_ascii_lowercase();
                        if hooks::is_trace() {
                            let fsize = std::fs::metadata(&src_raw_for_check).map(|m| m.len()).unwrap_or(u64::MAX);
                            hooks::ipc_log(ipc::LogLevel::Trace,
                                format!("fs_setinfo_rename_src src_virtual={src_lower} src_overlay={src_raw_for_check} size={fsize}"));
                        }
                        hooks::ipc_clear_overlay(&src_lower);
                        hooks::ipc_record_whiteout(&src_lower);
                        hooks::cache().invalidate(&src_lower);
                    }
                    hooks::ipc_record_overlay(&dest_lower, &overlay_dos);
                    // Record original-case basename (variant B hybrid — rename path).
                    // `dest_name` is the raw rename-information buffer decoded from
                    // UTF-16 before resolve_dest_path lowercased it; its last component
                    // preserves the caller's original case (e.g. "Mixed_Case_Dir").
                    // This is the same fix as the NtCreateFile / NtOpenFile paths:
                    // resolve_dest_path calls nt_to_dos_lower, so `dest` is lowercase.
                    {
                        let trimmed = dest_name.trim_end_matches(|c| c == '\\' || c == '/');
                        if let Some(basename) = trimmed.rsplit(|c| c == '\\' || c == '/').next() {
                            if !basename.is_empty() && basename.bytes().any(|b: u8| b.is_ascii_uppercase()) {
                                hooks::ipc_record_overlay_case(&dest_lower, basename);
                            }
                        }
                    }
                    hooks::cache().invalidate(&dest_lower);

                    let status = setinfo_rename_to_overlay(
                        handle, iosb, info, len, class, &overlay_dos,
                    );
                    if hooks::is_trace() {
                        // Post-rename: check if SOURCE file (config.lock) was actually
                        // moved away. NtSetInformationFile(FileRenameInfo) is a MOVE,
                        // so the source should NOT exist after.
                        let src_still_exists = if !src_raw_for_check.is_empty() {
                            std::fs::metadata(&src_raw_for_check).is_ok()
                        } else {
                            false
                        };
                        hooks::ipc_log(ipc::LogLevel::Trace,
                            format!("fs_setinfo_rename_result class={class} status=0x{status:08x} dest={dest_lower} src_gone={} src_overlay={src_raw_for_check}",
                                !src_still_exists));
                    }
                    return status;
                }
                policy::Mode::Deny | policy::Mode::Hidden => {
                    if hooks::is_trace() {
                        hooks::ipc_log(ipc::LogLevel::Trace,
                            format!("fs_setinfo_block_outside class={} dest={} mode={:?}",
                                class, dest, decision.mode));
                    }
                    if !iosb.is_null() {
                        hooks::set_io_status(iosb, STATUS_ACCESS_DENIED);
                    }
                    return STATUS_ACCESS_DENIED;
                }
            }
        }
        FILE_DISPOSITION_INFO_CLASS | FILE_DISPOSITION_EX_INFO_CLASS => {
            // Buffer parsing lives in parse_disposition_info — the Ex flags
            // word is read UNALIGNED there (caller-owned buffer, no
            // base-alignment guarantee); `None` means "too short for the
            // class" and passes the call through to the original syscall.
            let Some((wants_delete, disp_ex_flags)) =
                parse_disposition_info(info as *const u8, len as usize, class)
            else {
                return call_original();
            };
            if wants_delete {
                // Tripwire for diag_4395_posix_disp: disp_ex_flags is the
                // FileDispositionExInfo flags word from the same unaligned
                // read that decided wants_delete, so the failure log needs no
                // second pointer dereference.
                if let Some(path) = query_handle_dos_path(handle) {
                    let in_project = hooks::SANDBOX_CWD.get().map_or(false, |cwd| {
                        policy::path::pattern_matches_prefix(&cwd.to_lowercase(), &path)
                    });
                    if in_project {
                        // Inside the agent's own project_root: real delete as
                        // usual (passthrough). project_root is the only place
                        // the agent may mutate the real disk.
                        return call_original();
                    }

                    // Outside project_root: whiteout. The real lower file is
                    // NEVER touched (invariant #1). Two sub-cases:
                    //
                    // (a) The handle resolves INTO the sandbox overlay storage
                    //     (path is under ANY overlay root — primary or per-drive).
                    //     This is a CoW'd copy the agent previously created; it
                    //     lives inside the sandbox so we may really delete it,
                    //     then record a whiteout for the VIRTUAL path.
                    //
                    // (b) The handle resolves to a real external file. We must
                    //     NOT call the original (that would delete the real file).
                    //     Record a whiteout for the path and return SUCCESS.
                    //
                    // The overlay-root check iterates ALL roots (multi-root Path
                    // 1 layout), not just the primary SANDBOX_ROOT. Without this,
                    // C: overlay files (config.lock, etc.) fall through to case
                    // (b) — whiteout without physical deletion — leaving the
                    // overlay file in place. A subsequent FILE_CREATE then hits
                    // STATUS_OBJECT_NAME_COLLISION on the leftover file, breaking
                    // git's atomic config-lock workflow.
                    let overlay_roots: Vec<&str> = match crate::ipc_client::OVERLAY_ROOTS.get() {
                        Some(list) if !list.is_empty() => list.iter().map(|s| s.as_str()).collect(),
                        _ => hooks::SANDBOX_ROOT.get().map(|s| vec![s.as_str()]).unwrap_or_default(),
                    };
                    let mut matched_overlay = false;
                    for sb in &overlay_roots {
                        let sb_lower = sb.to_lowercase();
                        let sb_trimmed = sb_lower.trim_end_matches('\\');
                        if sb_trimmed.is_empty() { continue; }
                        if !policy::path::pattern_matches_prefix(sb_trimmed, &path) { continue; }
                        matched_overlay = true;
                        // (a) overlay copy: really delete it (the path is
                        // inside the sandbox, safe to mutate), then whiteout
                        // the virtual path so the lower layer stays hidden.
                        // Use multi-root unmirror (OVERLAY_ROOTS-aware).
                        let sb_root_opt = hooks::SANDBOX_ROOT.get().map(|s| s.as_str());
                        let virtual_dos = hooks::unmirror_overlay_handle_relative(&path, sb_root_opt)
                            .unwrap_or_else(|| path.clone());
                        let status = call_original();
                        let lower = virtual_dos.to_lowercase();
                        // Diagnostic: always log STATUS_REPARSE_POINT_ENCOUNTERED
                        // (os error 4395) regardless of trace level so it
                        // appears in sandbox.log and is easy to find when
                        // investigating the pywin32 / uv install failure.
                        if status == STATUS_REPARSE_POINT_ENCOUNTERED {
                            let posix = (disp_ex_flags & 0x8) != 0;
                            hooks::ipc_log(ipc::LogLevel::Warn,
                                format!("diag_4395_posix_disp \
                                         handle=0x{handle_val:x} \
                                         class={class} disp_flags=0x{disp_ex_flags:08x} \
                                         posix={posix} status=0x{status:08X} \
                                         virtual={virtual_dos} overlay={path}",
                                        handle_val = handle as usize));
                        }
                        match decide_post_delete(status) {
                            WhiteoutAction::RecordWhiteoutAndRemoveIdx => {
                                hooks::ipc_clear_overlay(&lower);
                                hooks::ipc_record_whiteout(&lower);
                                hooks::cache().invalidate(&lower);
                                if hooks::is_trace() {
                                    hooks::ipc_log(ipc::LogLevel::Trace,
                                        format!("fs_whiteout_overlay_delete virtual={virtual_dos} overlay={path}"));
                                }
                            }
                            WhiteoutAction::RecordWhiteoutKeepOverlay => {
                                // Physical delete failed (handle contention /
                                // NOT_EMPTY / reparse-point filter) but the
                                // virtual path must be hidden so a subsequent
                                // create in the same location succeeds. Do NOT
                                // remove OVERLAY_IDX — the physical file may
                                // still be present.
                                hooks::ipc_record_whiteout(&lower);
                                hooks::cache().invalidate(&lower);
                                if hooks::is_trace() {
                                    hooks::ipc_log(ipc::LogLevel::Trace,
                                        format!("whiteout_recorded_on_partial_delete \
                                                 status=0x{:08X} virtual={virtual_dos} overlay={path}",
                                                status as u32));
                                }
                            }
                            WhiteoutAction::Skip => {}
                        }
                        return status;
                    }
                    if matched_overlay { unreachable!(); }

                    // (b) real external file: do NOT delete it. Record the
                    // whiteout and return SUCCESS so the caller sees a
                    // successful virtual delete. The real disk is untouched.
                    let lower = path.to_lowercase();
                    hooks::ipc_record_whiteout(&lower);
                    hooks::cache().invalidate(&lower);
                    if hooks::is_trace() {
                        hooks::ipc_log(ipc::LogLevel::Trace,
                            format!("fs_whiteout_external_delete path={path}"));
                    }
                    // STATUS_SUCCESS with a clean iosb.Status. The caller may
                    // then NtClose the handle; that is fine (the real file is
                    // still on disk, NtClose just drops the handle).
                    if !iosb.is_null() {
                        hooks::set_io_status(iosb, 0); // STATUS_SUCCESS
                    }
                    return 0; // STATUS_SUCCESS
                } else {
                    // query_handle_dos_path returned None — the handle is
                    // opaque to GetFinalPathNameByHandleW. Pass through to the
                    // kernel and catch any 4395 so the tripwire fires.
                    //
                    // FILE_DISPOSITION_POSIX_SEMANTICS flag = bit 3 (0x8).
                    // When set, POSIX-delete semantics are requested: the file
                    // is unlinked even if other handles are open (like unlink(2)).
                    let posix = (disp_ex_flags & 0x8) != 0;
                    let status = call_original();
                    if status == STATUS_REPARSE_POINT_ENCOUNTERED {
                        hooks::ipc_log(
                            ipc::LogLevel::Warn,
                            format!(
                                "diag_4395_posix_disp \
                                 handle=0x{handle_val:x} \
                                 class={class} disp_flags=0x{disp_ex_flags:08x} \
                                 posix={posix} status=0x{status:08x} \
                                 note=handle_unresolvable",
                                handle_val = handle as usize,
                            ),
                        );
                    }
                    return status;
                }
            }
        }
        _ => {}
    }

    call_original()
}

/// Rewrite a FileRenameInfo(Ex)/FileLinkInfo(Ex) buffer to name the overlay
/// path instead of the caller's virtual destination, then call the original
/// `NtSetInformationFile` with RootDirectory=NULL (absolute overlay path).
///
/// Both the non-Ex (ReplaceIfExists at 0x00, BOOLEAN) and Ex (Flags at 0x00,
/// ULONG) variants keep RootDirectory at 0x08, FileNameLength at 0x10, and the
/// WCHAR FileName[] at 0x14. We preserve the leading header word so
/// ReplaceIfExists / Flags semantics are unchanged, set RootDirectory=NULL,
/// and append the UTF-16 overlay path.
///
/// # SAFETY
/// `info`/`len` are the original NtSetInformationFile buffer; `iosb` may be
/// null. Caller holds the anti_rec guard (we are mid-hook).
unsafe fn setinfo_rename_to_overlay(
    handle: HANDLE,
    iosb: *mut IO_STATUS_BLOCK,
    info: *const c_void,
    len: u32,
    class: u32,
    overlay_dos: &str,
) -> NTSTATUS {
    let off_root = 0x08usize;
    let off_name = 0x14usize;

    // Build a replacement info buffer. The first 0x08 bytes carry either
    // ReplaceIfExists (non-Ex) or Flags (Ex); copy verbatim so the caller's
    // replace/replace-if-exists behavior is preserved. Zero RootDirectory,
    // set FileNameLength, and write the UTF-16 NT-form overlay path
    // (`\??\<overlay_dos>`). The kernel's FileRenameInfo FileName expects an
    // NT object name, not a bare DOS path; passing the DOS form yields
    // STATUS_INVALID_PARAMETER.
    let overlay_nt = hooks::make_overlay_nt_buf(overlay_dos);
    // make_overlay_nt_buf returns `\??\<path>\0` (WITH trailing NUL).
    // FileNameLength counts bytes EXCLUDING the trailing NUL (matches the
    // UNICODE_STRING.Length discipline used by HookedAttrs::redirect).
    let chars_excluding_nul = overlay_nt.len().saturating_sub(1);
    let file_name_bytes = chars_excluding_nul * 2;
    let new_len = off_name + file_name_bytes;
    let mut buf: Vec<u8> = Vec::with_capacity(new_len);
    // Header [0x00, 0x08): preserve ReplaceIfExists/Flags verbatim.
    let header = if (len as usize) >= off_root {
        std::slice::from_raw_parts(info as *const u8, off_root)
    } else {
        // Defensive: caller already validated len >= off_name (0x14) before
        // invoking us, but do not assume a malformed buffer.
        if !iosb.is_null() {
            hooks::set_io_status(iosb, STATUS_ACCESS_DENIED);
        }
        return STATUS_ACCESS_DENIED;
    };
    buf.extend_from_slice(header);
    // RootDirectory (HANDLE, 8 bytes) = NULL — we pass an absolute overlay path.
    buf.extend_from_slice(&[0u8; 8]);
    // FileNameLength (ULONG, 4 bytes, little-endian).
    buf.extend_from_slice(&(file_name_bytes as u32).to_le_bytes());
    // FileName[] (WCHAR) — the NT path bytes (excluding the trailing NUL).
    for w in overlay_nt.iter().take(chars_excluding_nul) {
        buf.extend_from_slice(&w.to_le_bytes());
    }

    let new_info = buf.as_mut_ptr() as *mut c_void;
    if hooks::is_trace() {
        hooks::ipc_log(ipc::LogLevel::Trace,
            format!("fs_setinfo_rename_overlay class={class} overlay={overlay_dos}"));
    }
    let status = nt_call_original!(&HOOK_NT_SET_INFO_FILE, "NtSetInformationFile",
        (handle, iosb, new_info, new_len as u32, class));
    // Diagnostic: check whether the source file was actually moved (rename =
    // move, not copy). A lingering source file causes "File exists" on the next
    // config.lock create cycle, breaking git's atomic config commit.
    if hooks::is_trace() && status == 0 {
        let src_still_exists = std::fs::metadata(overlay_dos).is_ok();
        hooks::ipc_log(ipc::LogLevel::Trace,
            format!("fs_setinfo_rename_postcheck status=0x{status:08x} src_gone={} overlay={overlay_dos}",
                !src_still_exists));
    }
    status
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
        nt_call_original!(
            &HOOK_NT_FS_CONTROL_FILE,
            "NtFsControlFile",
            (handle, event, apc_routine, apc_context, iosb,
             fs_control_code, input, input_len, output, output_len)
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
// NtDeleteFile (P0-02) — delete-by-path had no detour at all
// ---------------------------------------------------------------------------

/// Outcome of applying the policy decision for an `NtDeleteFile` call.
/// Exists so unit tests can observe the whiteout decision without a live
/// IPC broker (`ipc_record_whiteout` is fire-and-forget over the pipe).
#[derive(Debug, PartialEq)]
enum DeleteResult {
    /// Kernel/policy status returned as-is (passthrough, deny, hidden, or a
    /// failed overlay-copy delete).
    Status(NTSTATUS),
    /// A whiteout was recorded for the virtual path; the real lower file was
    /// never touched. `overlay_removed`: a materialised overlay copy was
    /// additionally deleted through the original syscall.
    WhiteoutRecorded {
        status: NTSTATUS,
        overlay_removed: bool,
    },
}

/// Resolve the delete target of an `NtDeleteFile` OBJECT_ATTRIBUTES into the
/// lowercase DOS path used for the policy decision. Reuses the same
/// resolution helper as the rename/link path (`resolve_dest_path`: absolute
/// NT names, RootDirectory-relative joins, overlay unmirroring).
///
/// Returns `None` when the name is malformed (null `ObjectName`/`Buffer`,
/// zero/odd/oversized `Length`) or cannot be mapped to a DOS path (device
/// namespace, UNC, ...). Callers MUST fail closed on `None`: a delete whose
/// containment cannot be proven must never reach the kernel. The
/// UNICODE_STRING parsing here is local to this hook and validates every
/// field before dereference.
///
/// No alignment is assumed anywhere: `attrs`, `ObjectName` and `Buffer` are
/// the hooked caller's addresses and a hostile caller controls all three.
/// `&*attrs` would assert OBJECT_ATTRIBUTES' pointer alignment, `&*ustr` /
/// `slice::from_raw_parts::<u16>` would assert UNICODE_STRING/u16 alignment —
/// so both headers are read field-wise with unaligned loads and the name
/// bytes are read unaligned too. Validity (non-null, Length bytes readable)
/// remains the caller's obligation, exactly as before.
unsafe fn resolve_delete_target(attrs: *const OBJECT_ATTRIBUTES) -> Option<String> {
    if attrs.is_null() {
        return None;
    }
    // SAFETY: read_unaligned of a non-null OBJECT_ATTRIBUTES pointer —
    // validity per the SAFETY contract, alignment never assumed.
    let obj = (attrs as *const OBJECT_ATTRIBUTES).read_unaligned();
    if obj.ObjectName.is_null() {
        return None;
    }
    // SAFETY: read_unaligned of the caller's non-null UNICODE_STRING pointer.
    let ustr = (obj.ObjectName as *const UNICODE_STRING).read_unaligned();
    let byte_len = ustr.Length as usize;
    if byte_len == 0 || byte_len % 2 != 0 || byte_len > MAX_OBJECT_NAME_BYTES || ustr.Buffer.is_null() {
        return None;
    }
    // SAFETY: Buffer is non-null and at least Length bytes long per the
    // UNICODE_STRING contract, validated above; each WCHAR is read with
    // read_unaligned, so an odd Buffer address stays well-defined.
    let chars: Vec<u16> = (0..byte_len / 2)
        .map(|i| (ustr.Buffer.cast::<u8>().add(i * 2) as *const u16).read_unaligned())
        .collect();
    let name = String::from_utf16_lossy(&chars);
    resolve_dest_path(obj.RootDirectory, &name)
}

/// Apply the policy decision for a delete of `dest_lower` (the lowercase
/// virtual DOS path). Mirrors the FILE_DISPOSITION_INFO handling in
/// `hook_nt_set_information_file`:
///
/// - Passthrough → inside project_root, the one place a real delete may
///   happen: forward the caller's attrs to the original.
/// - Deny        → block.
/// - Hidden      → the path is already whiteouted; report NOT_FOUND (same
///   Mode::Hidden mapping as the create/open hooks in fs_hooks.rs).
/// - Cow / Mock  → outside project_root: record a whiteout instead of
///   touching the real disk (invariant #1). If a CoW copy was already
///   materialised in the overlay, first delete THAT copy through the
///   original syscall with ObjectName rewritten to the overlay NT path,
///   then do the same post-delete bookkeeping as the disposition path
///   (`decide_post_delete`).
///
/// `original` is the real `NtDeleteFile`: it receives the caller's attrs on
/// Passthrough and the rewritten attrs for the overlay-copy delete.
///
/// # SAFETY
/// `attrs` (non-null) must be the live caller OBJECT_ATTRIBUTES; it is
/// dereferenced read-only on the overlay-delete branch. `original` must be
/// the installed detour's original target. Caller holds the anti_rec guard.
unsafe fn apply_delete_decision(
    attrs: *mut OBJECT_ATTRIBUTES,
    dest_lower: &str,
    decision: &policy::Decision,
    original: impl FnOnce(*mut OBJECT_ATTRIBUTES) -> NTSTATUS,
) -> DeleteResult {
    match decision.mode {
        policy::Mode::Passthrough => DeleteResult::Status(original(attrs)),
        policy::Mode::Deny => DeleteResult::Status(STATUS_ACCESS_DENIED),
        policy::Mode::Hidden => DeleteResult::Status(STATUS_OBJECT_NAME_NOT_FOUND),
        policy::Mode::Cow | policy::Mode::Mock => {
            let record = |status: NTSTATUS, overlay_removed: bool| {
                hooks::ipc_record_whiteout(dest_lower);
                hooks::cache().invalidate(dest_lower);
                DeleteResult::WhiteoutRecorded { status, overlay_removed }
            };
            let Some(overlay) = decision.overlay.as_ref() else {
                // CoW decision without a projected overlay path: nothing was
                // ever materialised, so hiding the lower file is the whole job.
                return record(STATUS_SUCCESS, false);
            };
            let overlay_dos = overlay.to_string_lossy().into_owned();
            if !std::path::Path::new(&overlay_dos).exists() {
                // CoW path never materialised: the caller sees the real lower
                // file; a whiteout hides it. The kernel stays out of it and
                // the caller gets the success a real delete would report.
                return record(STATUS_SUCCESS, false);
            }
            // Materialised CoW copy: physically delete the OVERLAY file (the
            // lower file is NEVER touched) through the original syscall with
            // the ObjectName rewritten to the overlay NT path — same trick as
            // `setinfo_rename_to_overlay`.
            let mut nt = hooks::make_overlay_nt_buf(&overlay_dos); // `\??\<path>\0`
            let chars_excl_nul = nt.len().saturating_sub(1);
            let mut ustr = UNICODE_STRING {
                // Length excludes the trailing NUL; MaximumLength includes it
                // (same discipline as setinfo_rename_to_overlay).
                Length: (chars_excl_nul * 2) as u16,
                MaximumLength: (nt.len() * 2) as u16,
                Buffer: nt.as_mut_ptr(),
            };
            // SAFETY: read_unaligned — `attrs` is the live caller OBJECT_
            // ATTRIBUTES (validity contract above); the caller chose its
            // address, so read_unaligned is the only well-defined access.
            let o = (attrs as *const OBJECT_ATTRIBUTES).read_unaligned();
            let mut oa = OBJECT_ATTRIBUTES {
                Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                RootDirectory: std::ptr::null_mut(),
                ObjectName: &mut ustr,
                // Keep the caller's flags (OBJ_CASE_INSENSITIVE governs name
                // resolution) and security pointers verbatim; only the root
                // and name are rewritten.
                Attributes: o.Attributes,
                SecurityDescriptor: o.SecurityDescriptor,
                SecurityQualityOfService: o.SecurityQualityOfService,
            };
            let status = original(&mut oa);
            match decide_post_delete(status) {
                WhiteoutAction::RecordWhiteoutAndRemoveIdx => {
                    hooks::ipc_clear_overlay(dest_lower);
                    record(status, true)
                }
                WhiteoutAction::RecordWhiteoutKeepOverlay => record(status, false),
                WhiteoutAction::Skip if status == STATUS_OBJECT_NAME_NOT_FOUND => {
                    // The overlay copy vanished between the decision and the
                    // delete (or was never really there): the lower file still
                    // backs the virtual path, so hide it and report success.
                    record(STATUS_SUCCESS, false)
                }
                WhiteoutAction::Skip => DeleteResult::Status(status),
            }
        }
    }
}

/// `NtDeleteFile` — deletes by path WITHOUT ever opening a handle (P0-02).
///
/// `DeleteFileW`/`std::fs::remove_file` open a handle first and delete via
/// `NtSetInformationFile(FILE_DISPOSITION_INFO*)`, which
/// `hook_nt_set_information_file` covers. A sandboxed process calling
/// `ntdll!NtDeleteFile` directly (GetProcAddress + OBJECT_ATTRIBUTES naming
/// an arbitrary path) previously bypassed decide(), the overlay and the
/// whiteout machinery entirely and removed the REAL file. This detour gives
/// that call exactly the disposition-path semantics.
///
/// # SAFETY
/// Called by the kernel via the installed detour with NT-ABI-conformant
/// arguments; `attrs` may be null (the object manager rejects that itself).
pub(crate) unsafe extern "system" fn hook_nt_delete_file(
    attrs: *mut OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let call_original = || nt_call_original!(&HOOK_NT_DELETE_FILE, "NtDeleteFile", (attrs));
    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // Degenerate call with no OBJECT_ATTRIBUTES: the object manager rejects
    // it and nothing can be deleted — pass the kernel's own answer through.
    if attrs.is_null() {
        return call_original();
    }

    let Some(dest) = resolve_delete_target(attrs) else {
        // Fail closed (same convention as unresolvable rename destinations):
        // a delete whose containment cannot be proven is never forwarded to
        // the kernel. Covers malformed UNICODE_STRINGs, device-namespace
        // names and UNC paths.
        if hooks::is_trace() {
            hooks::ipc_log(ipc::LogLevel::Trace,
                format!("fs_delete_unresolvable_target attrs={:?}", attrs));
        }
        return STATUS_ACCESS_DENIED;
    };
    // Shared escape denylist (traversal, .winrsbox, GLOBALROOT, 8.3
    // short-name) — mirrors the rename/hardlink destination check.
    if dest_is_escape(&dest) {
        if hooks::is_trace() {
            hooks::ipc_log(ipc::LogLevel::Trace,
                format!("fs_delete_block_escape dest={dest}"));
        }
        return STATUS_ACCESS_DENIED;
    }

    let dest_lower = dest.to_ascii_lowercase();
    let decision = hooks::decide(&dest, true);
    let result = apply_delete_decision(
        attrs,
        &dest_lower,
        &decision,
        |a| nt_call_original!(&HOOK_NT_DELETE_FILE, "NtDeleteFile", (a)),
    );
    if hooks::is_trace() {
        hooks::ipc_log(ipc::LogLevel::Trace,
            format!("fs_delete_result dest={dest_lower} result={result:?}"));
    }
    match result {
        DeleteResult::Status(status) => status,
        DeleteResult::WhiteoutRecorded { status, .. } => status,
    }
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
mod tests {
    use super::*;

    // ── Relative-rename passthrough rewrite (audit 2026-09-19 Low) ────

    #[test]
    fn absolute_rename_buffer_nulls_root_and_keeps_flags() {
        let dest = r"c:\proj\renamed.txt";
        let nt = policy::path::dos_to_nt(dest); // \??\c:\proj\renamed.txt\0
        let name_bytes = (nt.len() - 1) * 2;

        let mut orig = vec![0u8; 0x14 + 8];
        orig[0] = 1; // ReplaceIfExists = TRUE (non-Ex) / flags word (Ex)
        orig[8] = 0xAB; // root-handle bytes — must be zeroed in the output
        orig[0x10] = 0x99; // stale FileNameLength — must be overwritten

        let (out, out_len) =
            build_absolute_rename_buffer(&orig, dest).expect("buffer must build");
        assert_eq!(out_len as usize, 0x14 + nt.len() * 2);
        assert_eq!(&out[..8], &orig[..8], "flags word copied verbatim");
        assert_eq!(&out[8..16], &0u64.to_ne_bytes(), "RootDirectory must be NULL");
        let got_len = u32::from_le_bytes([out[16], out[17], out[18], out[19]]) as usize;
        assert_eq!(
            got_len, name_bytes,
            "FileNameLength counts name bytes, not the NUL terminator"
        );
        let mut want = Vec::new();
        for w in &nt {
            want.extend_from_slice(&w.to_le_bytes());
        }
        assert_eq!(&out[0x14..], &want[..], "FileName must be the absolute NT form");
    }

    #[test]
    fn absolute_rename_buffer_rejects_short_header() {
        let orig = [0u8; 0x13];
        assert!(build_absolute_rename_buffer(&orig, r"c:\x").is_none());
    }

    #[test]
    fn rename_passthrough_arm_rewrites_relative_root() {
        // Textual pin (hooks.rs::spawn_hook_body precedent): the Passthrough
        // arm of the rename/link handler must rewrite a relative
        // RootDirectory buffer to the absolute NT form instead of handing
        // the caller's buffer back for a second, racy handle resolution.
        let src = include_str!("fs_metadata_guard.rs");
        let fn_start = src
            .find("fn hook_nt_set_information_file")
            .expect("rename hook must exist");
        let rest = &src[fn_start..];
        let body_end = rest
            .find("
#[cfg(test)]")
            .or_else(|| rest.find("
pub(crate)"))
            .expect("next item bounds the fn body");
        let body = &rest[..body_end];
        let pt_start = body
            .find("policy::Mode::Passthrough =>")
            .expect("Passthrough arm must exist");
        let pt_end = body
            .find("policy::Mode::Cow")
            .expect("Cow arm must follow Passthrough");
        let pt = &body[pt_start..pt_end];
        assert!(
            pt.contains("root.is_null()"),
            "Passthrough arm must branch on the relative-open case"
        );
        assert!(
            pt.contains("build_absolute_rename_buffer"),
            "Passthrough arm must rewrite the relative rename buffer to the absolute NT form (racy RootDirectory fix)"
        );
        assert!(
            pt.contains("fs_setinfo_passthrough_rewrite_failed"),
            "rewrite failure must be visible in trace logs and fail closed"
        );
    }

    // ── unaligned-read regression (alignment-UB class, mirrors 9d73d34) ──
    //
    // resolve_delete_target walks a caller-supplied OBJECT_ATTRIBUTES →
    // UNICODE_STRING → Buffer chain: three addresses a hostile caller
    // controls. The probes below force ALL THREE onto odd addresses — the
    // old `&*attrs` / `&*ustr` / `from_raw_parts::<u16>(Buffer)` chain
    // aborted on the first step instead of resolving the name.

    /// Byte offset within `backing` whose address is ODD.
    fn odd_offset(backing: &[u8]) -> usize {
        let off = 1 - (backing.as_ptr() as usize % 2);
        assert_eq!((backing.as_ptr() as usize + off) % 2, 1, "probe must sit at an odd address");
        off
    }

    /// Copy `value`'s bytes to `dst` — any alignment.
    unsafe fn place_at<T>(dst: *mut u8, value: &T) {
        std::ptr::copy_nonoverlapping(
            value as *const T as *const u8,
            dst,
            std::mem::size_of::<T>(),
        );
    }

    /// Build an OBJECT_ATTRIBUTES → UNICODE_STRING → name chain with each
    /// link at an ODD address. Returns the attrs pointer plus the backings
    /// (which must outlive every use of the pointer).
    unsafe fn odd_attrs_chain(
        name: &[u16],
    ) -> (*const OBJECT_ATTRIBUTES, Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut name_backing = vec![0u8; name.len() * 2 + 8];
        let noff = odd_offset(&name_backing);
        // SAFETY: noff ≤ 1 and name.len()*2 fits inside the backing.
        unsafe {
            std::ptr::copy_nonoverlapping(
                name.as_ptr() as *const u8,
                name_backing.as_mut_ptr().add(noff),
                name.len() * 2,
            );
        }
        let ustr = UNICODE_STRING {
            Length: (name.len() * 2) as u16,
            MaximumLength: (name.len() * 2 + 2) as u16,
            // SAFETY: points at the odd window in `name_backing`, valid for
            // Length bytes; the backing outlives the returned pointer's use.
            Buffer: unsafe { name_backing.as_ptr().add(noff) } as *mut u16,
        };
        let mut ustr_backing = vec![0u8; std::mem::size_of::<UNICODE_STRING>() + 8];
        let uoff = odd_offset(&ustr_backing);
        // SAFETY: uoff ≤ 1, struct fits the backing.
        unsafe { place_at(ustr_backing.as_mut_ptr().add(uoff), &ustr) };
        let oa = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            // SAFETY: points at the odd window in `ustr_backing` (above).
            ObjectName: unsafe { ustr_backing.as_ptr().add(uoff) } as *mut UNICODE_STRING,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let mut oa_backing = vec![0u8; std::mem::size_of::<OBJECT_ATTRIBUTES>() + 8];
        let aoff = odd_offset(&oa_backing);
        // SAFETY: aoff ≤ 1, struct fits the backing.
        unsafe { place_at(oa_backing.as_mut_ptr().add(aoff), &oa) };
        let attrs = unsafe { oa_backing.as_ptr().add(aoff) as *const OBJECT_ATTRIBUTES };
        (attrs, oa_backing, ustr_backing, name_backing)
    }

    #[test]
    fn resolve_delete_target_resolves_misaligned_attrs_chain() {
        let name: Vec<u16> = r"\??\C:\Users\Someone\Important.TXT".encode_utf16().collect();
        // SAFETY: the chain is self-consistent and the backings outlive the
        // call below (bound in this scope).
        let (attrs, _oa, _us, _nm) = unsafe { odd_attrs_chain(&name) };
        let dest = unsafe { resolve_delete_target(attrs) };
        assert_eq!(dest.as_deref(), Some(r"c:\users\someone\important.txt"),
            "fully misaligned caller chain must resolve like an aligned one");
    }

    #[test]
    fn resolve_delete_target_misaligned_attrs_with_null_objectname_is_none() {
        let oa = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: std::ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let mut backing = vec![0u8; std::mem::size_of::<OBJECT_ATTRIBUTES>() + 8];
        let off = odd_offset(&backing);
        // SAFETY: off ≤ 1, struct fits the backing.
        unsafe { place_at(backing.as_mut_ptr().add(off), &oa) };
        // SAFETY: the odd attrs is a byte-identical, live OBJECT_ATTRIBUTES.
        let attrs = unsafe { backing.as_ptr().add(off) as *const OBJECT_ATTRIBUTES };
        assert_eq!(unsafe { resolve_delete_target(attrs) }, None);
    }

    /// The overlay-delete branch of apply_delete_decision reads the LIVE
    /// caller OBJECT_ATTRIBUTES (Attributes/Security* fields). A hostile
    /// caller can put it at an odd address — the old `let o = &*attrs;`
    /// aborted there instead of redirecting the delete at the overlay copy.
    #[test]
    fn nt_delete_overlay_branch_reads_misaligned_caller_attrs() {
        let dir = std::env::temp_dir().join(format!("winrsbox_p002_odd_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("important.txt");
        std::fs::write(&real, b"lower-file").unwrap();
        let overlay = dir.join("overlay_copy.bin");
        std::fs::write(&overlay, b"cow-copy").unwrap();

        let decision = policy::Decision {
            mode: policy::Mode::Cow,
            overlay: Some(overlay.clone()),
            cow_from: Some(real.clone()),
            mock_payload: None,
        };

        let name: Vec<u16> = r"\??\C:\Users\Someone\Important.TXT".encode_utf16().collect();
        // SAFETY: the chain is self-consistent; backings are bound below and
        // outlive the apply_delete_decision call.
        let (attrs, _oa_backing, _ustr_backing, _name_backing) =
            unsafe { odd_attrs_chain(&name) };

        let mut seen_target: Option<String> = None;
        let mut seen_root_null = false;
        let overlay_for_stub = overlay.clone();
        let result = unsafe {
            apply_delete_decision(
                attrs as *mut OBJECT_ATTRIBUTES,
                &real.to_string_lossy().to_ascii_lowercase(),
                &decision,
                |a| {
                    // The stub kernel receives OUR rewritten (aligned) attrs.
                    let oa = &*a;
                    seen_root_null = oa.RootDirectory.is_null();
                    let us = &*oa.ObjectName;
                    let chars = (us.Length as usize) / 2;
                    let decoded =
                        String::from_utf16_lossy(std::slice::from_raw_parts(us.Buffer, chars));
                    seen_target = Some(decoded.to_ascii_lowercase());
                    let _ = std::fs::remove_file(&overlay_for_stub);
                    STATUS_SUCCESS
                },
            )
        };

        let expected = format!(r"\??\{}", overlay.to_string_lossy().to_ascii_lowercase());
        assert_eq!(seen_target.as_deref(), Some(expected.as_str()),
            "misaligned caller attrs must still drive the overlay redirect");
        assert!(seen_root_null, "rewritten attrs must use an absolute path");
        assert_eq!(
            result,
            DeleteResult::WhiteoutRecorded { status: STATUS_SUCCESS, overlay_removed: true },
        );
        assert!(real.exists(), "the real lower file must survive the delete");
        assert!(!overlay.exists(), "the materialised overlay copy must be gone");
        let _ = std::fs::remove_dir_all(&dir);
    }

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

    // -----------------------------------------------------------------------
    // decide_post_delete — pure logic, no IPC, no detours
    // -----------------------------------------------------------------------

    /// STATUS_SUCCESS → whiteout + remove OVERLAY_IDX (file is physically gone).
    #[test]
    fn decide_post_delete_success_removes_idx() {
        assert_eq!(
            decide_post_delete(STATUS_SUCCESS),
            WhiteoutAction::RecordWhiteoutAndRemoveIdx,
        );
    }

    /// STATUS_DIRECTORY_NOT_EMPTY → whiteout but KEEP OVERLAY_IDX (physical
    /// file still present due to handle contention).  This is the bug-#76
    /// fix: the old code returned `Skip` here.
    #[test]
    fn decide_post_delete_not_empty_records_whiteout_keeps_overlay() {
        assert_eq!(
            decide_post_delete(STATUS_DIRECTORY_NOT_EMPTY),
            WhiteoutAction::RecordWhiteoutKeepOverlay,
        );
    }

    /// STATUS_SHARING_VIOLATION → same treatment as NOT_EMPTY.
    #[test]
    fn decide_post_delete_sharing_violation_records_whiteout_keeps_overlay() {
        assert_eq!(
            decide_post_delete(STATUS_SHARING_VIOLATION),
            WhiteoutAction::RecordWhiteoutKeepOverlay,
        );
    }

    /// STATUS_REPARSE_POINT_ENCOUNTERED (0xC0000274 / os error 4395) → whiteout
    /// but KEEP OVERLAY_IDX, same as NOT_EMPTY treatment. This is bug-#79:
    /// when a kernel filter driver (e.g. AnviFPFltd) intercepts the physical
    /// delete and returns this status, the virtual path must still be hidden
    /// so a subsequent install attempt can succeed. The old code returned
    /// `Skip` here, leaving the sandbox in a broken state.
    #[test]
    fn decide_post_delete_reparse_point_encountered_records_whiteout_keeps_overlay() {
        assert_eq!(
            decide_post_delete(STATUS_REPARSE_POINT_ENCOUNTERED),
            WhiteoutAction::RecordWhiteoutKeepOverlay,
        );
    }

    /// Any other error status → Skip (do not record a spurious whiteout).
    #[test]
    fn decide_post_delete_other_error_skips() {
        // STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
        let other: NTSTATUS = 0xC000_0034_u32 as NTSTATUS;
        assert_eq!(decide_post_delete(other), WhiteoutAction::Skip);
    }

    // -----------------------------------------------------------------------
    // NtDeleteFile (P0-02)
    //
    // These tests drive the resolve/apply seam directly and inject the
    // policy Decision. They must NEVER reach hooks::decide(): with no broker
    // pipe under `cargo test`, ipc_decide self-terminates the process after
    // IPC_FAIL_THRESHOLD (8) consecutive failures.
    // -----------------------------------------------------------------------

    /// Absolute NT names (the `\??\C:\...` form Win32 hands to NtDeleteFile)
    /// resolve to the lowercase DOS path the policy decides on.
    #[test]
    fn resolve_delete_target_maps_absolute_nt_name_to_lowercase_dos() {
        let mut name: Vec<u16> = r"\??\C:\Users\Someone\Important.TXT".encode_utf16().collect();
        let mut ustr = UNICODE_STRING {
            Length: (name.len() * 2) as u16,
            MaximumLength: (name.len() * 2 + 2) as u16,
            Buffer: name.as_mut_ptr(),
        };
        let oa = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &mut ustr,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let dest = unsafe { resolve_delete_target(&oa) };
        assert_eq!(dest.as_deref(), Some(r"c:\users\someone\important.txt"));
    }

    /// A null Buffer with a non-zero Length must NOT be dereferenced, and an
    /// empty name must not resolve — both fail closed to None (the hook then
    /// denies instead of forwarding anything to the kernel).
    #[test]
    fn resolve_delete_target_rejects_malformed_name_without_dereferencing() {
        let mut ustr = UNICODE_STRING {
            Length: 8,
            MaximumLength: 8,
            Buffer: std::ptr::null_mut(),
        };
        let oa = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &mut ustr,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        assert_eq!(unsafe { resolve_delete_target(&oa) }, None);

        let mut name = [b'a' as u16; 4];
        let mut empty = UNICODE_STRING {
            Length: 0,
            MaximumLength: 8,
            Buffer: name.as_mut_ptr(),
        };
        let oa_empty = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &mut empty,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        assert_eq!(unsafe { resolve_delete_target(&oa_empty) }, None);
    }

    /// THE regression test (P0-02): deleting a path outside project_root via
    /// NtDeleteFile must record a whiteout and NEVER reach the original
    /// syscall (which would unlink the real file on the real disk).
    #[test]
    fn nt_delete_external_path_records_whiteout_and_spares_real_file() {
        let dir = std::env::temp_dir().join(format!("winrsbox_p002_ext_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("important.txt");
        std::fs::write(&real, b"lower-file-do-not-delete").unwrap();

        // Broker decision for a CoW-managed external path whose overlay copy
        // was never materialised.
        let decision = policy::Decision {
            mode: policy::Mode::Cow,
            overlay: Some(dir.join("overlay_never_created.bin")),
            cow_from: Some(real.clone()),
            mock_payload: None,
        };

        let mut original_called = false;
        let result = unsafe {
            apply_delete_decision(
                std::ptr::null_mut(), // not dereferenced on this branch
                &real.to_string_lossy().to_ascii_lowercase(),
                &decision,
                |_a| {
                    original_called = true;
                    0
                },
            )
        };

        assert_eq!(
            result,
            DeleteResult::WhiteoutRecorded { status: STATUS_SUCCESS, overlay_removed: false },
            "external delete must become a whiteout reported as success",
        );
        assert!(!original_called, "original NtDeleteFile must not run for an external path");
        assert!(real.exists(), "the real lower file must survive the delete");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Materialised CoW copy: the ORIGINAL syscall must be redirected at the
    /// OVERLAY copy (never at the real path), the copy really disappears, the
    /// real lower file survives, and the whiteout is recorded.
    #[test]
    fn nt_delete_materialised_overlay_copy_is_deleted_then_whiteouted() {
        let dir = std::env::temp_dir().join(format!("winrsbox_p002_mat_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("important.txt");
        std::fs::write(&real, b"lower-file").unwrap();
        let overlay = dir.join("overlay_copy.bin");
        std::fs::write(&overlay, b"cow-copy").unwrap();

        let decision = policy::Decision {
            mode: policy::Mode::Cow,
            overlay: Some(overlay.clone()),
            cow_from: Some(real.clone()),
            mock_payload: None,
        };

        // Real caller attrs — the overlay branch reads them read-only.
        let mut caller_name: Vec<u16> =
            r"\??\C:\Users\Someone\Important.TXT".encode_utf16().collect();
        let mut caller_ustr = UNICODE_STRING {
            Length: (caller_name.len() * 2) as u16,
            MaximumLength: (caller_name.len() * 2 + 2) as u16,
            Buffer: caller_name.as_mut_ptr(),
        };
        let mut caller_attrs = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &mut caller_ustr,
            Attributes: 0x40, // OBJ_CASE_INSENSITIVE
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };

        let mut seen_target: Option<String> = None;
        let mut seen_root_null = false;
        let overlay_for_stub = overlay.clone();
        let result = unsafe {
            apply_delete_decision(
                &mut caller_attrs,
                &real.to_string_lossy().to_ascii_lowercase(),
                &decision,
                |a| {
                    let oa = &*a;
                    seen_root_null = oa.RootDirectory.is_null();
                    let us = &*oa.ObjectName;
                    let chars = (us.Length as usize) / 2;
                    let decoded = String::from_utf16_lossy(std::slice::from_raw_parts(us.Buffer, chars));
                    seen_target = Some(decoded.to_ascii_lowercase());
                    // Stand-in for the kernel: remove the copy the rewritten
                    // attrs point at.
                    let _ = std::fs::remove_file(&overlay_for_stub);
                    STATUS_SUCCESS
                },
            )
        };

        let expected = format!(r"\??\{}", overlay.to_string_lossy().to_ascii_lowercase());
        assert_eq!(
            seen_target.as_deref(),
            Some(expected.as_str()),
            "the original syscall must be redirected at the OVERLAY copy",
        );
        assert!(seen_root_null, "rewritten attrs must use an absolute path (RootDirectory = NULL)");
        assert_eq!(
            result,
            DeleteResult::WhiteoutRecorded { status: STATUS_SUCCESS, overlay_removed: true },
        );
        assert!(real.exists(), "the real lower file must survive the delete");
        assert!(!overlay.exists(), "the materialised overlay copy must be gone");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Kernel reports the overlay copy already gone (lost race) → still
    /// whiteout and report SUCCESS; the caller must not see a NOT_FOUND for
    /// a status on a path the caller never named.
    #[test]
    fn nt_delete_overlay_copy_vanished_still_whiteouts_success() {
        let dir = std::env::temp_dir().join(format!("winrsbox_p002_race_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("important.txt");
        std::fs::write(&real, b"lower-file").unwrap();
        let overlay = dir.join("overlay_copy.bin");
        std::fs::write(&overlay, b"cow-copy").unwrap();

        let decision = policy::Decision {
            mode: policy::Mode::Cow,
            overlay: Some(overlay.clone()),
            cow_from: Some(real.clone()),
            mock_payload: None,
        };

        let mut caller_name: Vec<u16> =
            r"\??\C:\Users\Someone\Important.TXT".encode_utf16().collect();
        let mut caller_ustr = UNICODE_STRING {
            Length: (caller_name.len() * 2) as u16,
            MaximumLength: (caller_name.len() * 2 + 2) as u16,
            Buffer: caller_name.as_mut_ptr(),
        };
        let mut caller_attrs = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &mut caller_ustr,
            Attributes: 0x40,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };

        let result = unsafe {
            apply_delete_decision(
                &mut caller_attrs,
                &real.to_string_lossy().to_ascii_lowercase(),
                &decision,
                |_a| STATUS_OBJECT_NAME_NOT_FOUND, // kernel: overlay copy gone
            )
        };

        assert_eq!(
            result,
            DeleteResult::WhiteoutRecorded { status: STATUS_SUCCESS, overlay_removed: false },
        );
        assert!(real.exists(), "the real lower file must survive the delete");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Already-whiteouted path: the virtual file does not exist — the delete
    /// reports NOT_FOUND (same Mode::Hidden mapping as the create/open
    /// hooks) and the original is never called.
    #[test]
    fn nt_delete_hidden_mode_reports_not_found_without_calling_original() {
        let decision = policy::Decision {
            mode: policy::Mode::Hidden,
            overlay: None,
            cow_from: None,
            mock_payload: None,
        };
        let mut original_called = false;
        let result = unsafe {
            apply_delete_decision(
                std::ptr::null_mut(),
                r"c:\some\virtual\path.txt",
                &decision,
                |_a| {
                    original_called = true;
                    0
                },
            )
        };
        assert_eq!(result, DeleteResult::Status(STATUS_OBJECT_NAME_NOT_FOUND));
        assert!(!original_called);
    }

    /// Policy Deny: blocked, original never called.
    #[test]
    fn nt_delete_deny_mode_is_blocked() {
        let decision = policy::Decision {
            mode: policy::Mode::Deny,
            overlay: None,
            cow_from: None,
            mock_payload: None,
        };
        let mut original_called = false;
        let result = unsafe {
            apply_delete_decision(
                std::ptr::null_mut(),
                r"c:\some\denied\path.txt",
                &decision,
                |_a| {
                    original_called = true;
                    0
                },
            )
        };
        assert_eq!(result, DeleteResult::Status(STATUS_ACCESS_DENIED));
        assert!(!original_called);
    }

    /// Inside project_root: the caller's own OBJECT_ATTRIBUTES reach the
    /// original untouched and its status is returned verbatim.
    #[test]
    fn nt_delete_passthrough_forwards_caller_attrs_to_original() {
        let decision = policy::Decision {
            mode: policy::Mode::Passthrough,
            overlay: None,
            cow_from: None,
            mock_payload: None,
        };
        let mut caller_name: Vec<u16> =
            r"\??\C:\project\file.txt".encode_utf16().collect();
        let mut caller_ustr = UNICODE_STRING {
            Length: (caller_name.len() * 2) as u16,
            MaximumLength: (caller_name.len() * 2 + 2) as u16,
            Buffer: caller_name.as_mut_ptr(),
        };
        let mut caller_attrs = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &mut caller_ustr,
            Attributes: 0x40,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let expected_ptr: *mut OBJECT_ATTRIBUTES = &mut caller_attrs;
        let mut seen_ptr: *mut OBJECT_ATTRIBUTES = std::ptr::null_mut();
        let result = unsafe {
            apply_delete_decision(
                expected_ptr,
                r"c:\project\file.txt",
                &decision,
                |a| {
                    seen_ptr = a;
                    0x1234
                },
            )
        };
        assert_eq!(seen_ptr, expected_ptr, "passthrough must forward the caller's attrs");
        assert_eq!(result, DeleteResult::Status(0x1234));
    }

    // -----------------------------------------------------------------------
    // Unaligned raw-record access (alignment-UB class)
    //
    // The rename/disposition info buffers are caller-owned memory: the
    // sandboxed process picks the address, so the NT header fields can sit
    // at ANY odd address. Every field read must therefore go through
    // read_unaligned. These probes force the buffer onto an odd address; a
    // plain aligned dereference aborts under the debug alignment check
    // (STATUS_STACK_BUFFER_OVERRUN) instead of reading the field.
    // -----------------------------------------------------------------------

    /// Copy `buf` into a larger backing allocation so the probe starts at an
    /// ODD address regardless of the allocator's base alignment.
    fn odd_window(buf: &[u8]) -> (Vec<u8>, usize) {
        let mut backing = vec![0u8; buf.len() + 512];
        let off = 1 - (backing.as_ptr() as usize % 2);
        backing[off..off + buf.len()].copy_from_slice(buf);
        (backing, off)
    }

    /// Build a FILE_RENAME_INFORMATION buffer (shared prefix with the Ex
    /// variant): ReplaceIfExists @0x00, RootDirectory @0x08, FileNameLength
    /// @0x10, FileName[] @0x14.
    fn build_rename_info(root: usize, name: &str) -> Vec<u8> {
        let name_u16: Vec<u16> = name.encode_utf16().collect();
        let mut buf = vec![0u8; 0x14 + name_u16.len() * 2];
        buf[0x08..0x10].copy_from_slice(&(root as u64).to_le_bytes());
        buf[0x10..0x14].copy_from_slice(&((name_u16.len() * 2) as u32).to_le_bytes());
        for (i, u) in name_u16.iter().enumerate() {
            buf[0x14 + i * 2..0x16 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        buf
    }

    /// REGRESSION (alignment class): a rename-info buffer at an ODD address
    /// must decode RootDirectory, FileNameLength and FileName correctly via
    /// unaligned reads. The old plain dereferences (`*(ptr as *const HANDLE)`
    /// at base+0x08 with an odd base) are UB and abort under the debug
    /// alignment check instead of returning the field.
    #[test]
    fn parse_rename_info_decodes_unaligned_buffer() {
        let built = build_rename_info(0xDEADBEEF, r"\??\C:\Users\Someone\Mixed.TXT");
        let (mut backing, off) = odd_window(&built);
        assert_eq!(
            (backing.as_ptr() as usize + off) % 2,
            1,
            "probe buffer must start at an odd address",
        );
        // SAFETY: backing[off..off+built.len()] holds a full rename-info
        // buffer for exactly built.len() bytes.
        let parsed = unsafe { parse_rename_info(backing.as_ptr().add(off), built.len()) };
        let (root, name) = parsed.expect("well-formed buffer must parse");
        assert_eq!(root as usize, 0xDEADBEEF, "RootDirectory must read correctly at an odd address");
        assert_eq!(name, r"\??\C:\Users\Someone\Mixed.TXT");
    }

    /// The passthrough contract of parse_rename_info must survive the
    /// extraction: each malformed shape maps to None (the hook then calls
    /// the original instead of touching the buffer).
    #[test]
    fn parse_rename_info_rejects_malformed_buffers() {
        // Buffer shorter than the fixed 0x14 header.
        let short = [0u8; 0x10];
        // SAFETY: len equals the real buffer length in every call below.
        assert_eq!(unsafe { parse_rename_info(short.as_ptr(), short.len()) }, None);

        // Zero FileNameLength.
        let zero_len = vec![0u8; 0x40];
        assert_eq!(unsafe { parse_rename_info(zero_len.as_ptr(), zero_len.len()) }, None);

        // FileName runs past the declared buffer length.
        let mut over = vec![0u8; 0x40];
        over[0x10..0x14].copy_from_slice(&0x0100u32.to_le_bytes()); // 256 > 0x40 - 0x14
        assert_eq!(unsafe { parse_rename_info(over.as_ptr(), over.len()) }, None);

        // Absurd (> 0x8000) FileNameLength.
        let mut huge = vec![0u8; 0x40];
        huge[0x10..0x14].copy_from_slice(&0x8004u32.to_le_bytes());
        assert_eq!(unsafe { parse_rename_info(huge.as_ptr(), huge.len()) }, None);
    }

    /// REGRESSION (alignment class): FILE_DISPOSITION_INFO_EX flags at an
    /// ODD address must decode via an unaligned u32 read — the old plain
    /// dereference is UB there and aborts under the debug alignment check.
    #[test]
    fn parse_disposition_info_ex_decodes_unaligned_buffer() {
        // FILE_DISPOSITION_DELETE (0x1) | FILE_DISPOSITION_POSIX_SEMANTICS (0x8).
        let built = 0x9u32.to_le_bytes().to_vec();
        let (mut backing, off) = odd_window(&built);
        // SAFETY: backing[off..off+4] is a full FILE_DISPOSITION_INFO_EX.
        let parsed = unsafe {
            parse_disposition_info(
                backing.as_ptr().add(off),
                built.len(),
                FILE_DISPOSITION_EX_INFO_CLASS,
            )
        };
        assert_eq!(parsed, Some((true, 0x9)));
    }

    /// Buffers too short for their class map to None (passthrough), and the
    /// non-Ex class decodes its single delete byte with no ex flags.
    #[test]
    fn parse_disposition_info_class_discipline() {
        let b4 = [0u8; 4];
        // SAFETY: len equals the real buffer length in every call below.
        assert_eq!(
            unsafe { parse_disposition_info(b4.as_ptr(), 3, FILE_DISPOSITION_EX_INFO_CLASS) },
            None,
            "Ex class with < 4 bytes must be a passthrough",
        );
        let b1 = [1u8];
        assert_eq!(
            unsafe { parse_disposition_info(b1.as_ptr(), 0, FILE_DISPOSITION_INFO_CLASS) },
            None,
            "non-Ex class with 0 bytes must be a passthrough",
        );
        assert_eq!(
            unsafe { parse_disposition_info(b1.as_ptr(), 1, FILE_DISPOSITION_INFO_CLASS) },
            Some((true, 0)),
            "non-Ex DeleteFile=TRUE must want a delete and carry no ex flags",
        );
        let b0 = [0u8];
        assert_eq!(
            unsafe { parse_disposition_info(b0.as_ptr(), 1, FILE_DISPOSITION_INFO_CLASS) },
            Some((false, 0)),
        );
    }
}
