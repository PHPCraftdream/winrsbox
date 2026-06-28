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
// NTSTATUS constants used by the disposition handler
// ---------------------------------------------------------------------------

const STATUS_SUCCESS: NTSTATUS = 0;
/// Directory still has open handles or children (handle-contention / race).
const STATUS_DIRECTORY_NOT_EMPTY: NTSTATUS = 0xC000_0101_u32 as NTSTATUS;
/// Another process has the file open in an incompatible share mode.
const STATUS_SHARING_VIOLATION: NTSTATUS   = 0xC000_0043_u32 as NTSTATUS;

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
/// Returning `RecordWhiteout*` for `STATUS_DIRECTORY_NOT_EMPTY` and
/// `STATUS_SHARING_VIOLATION` fixes bug #76: when handle contention prevents
/// the kernel from completing the physical delete, we still need to hide the
/// path from the sandbox view so a subsequent clone into the same location
/// succeeds.
fn decide_post_delete(status: NTSTATUS) -> WhiteoutAction {
    match status {
        STATUS_SUCCESS => WhiteoutAction::RecordWhiteoutAndRemoveIdx,
        STATUS_DIRECTORY_NOT_EMPTY | STATUS_SHARING_VIOLATION => {
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
                    return call_original();
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
                                // NOT_EMPTY) but the virtual path must be hidden
                                // so a subsequent create in the same location
                                // succeeds.  Do NOT remove OVERLAY_IDX — the
                                // physical file may still be present.
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
    let status = HOOK_NT_SET_INFO_FILE.get().unwrap().call(
        handle, iosb, new_info, new_len as u32, class,
    );
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

    /// Any other error status → Skip (do not record a spurious whiteout).
    #[test]
    fn decide_post_delete_other_error_skips() {
        // STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
        let other: NTSTATUS = 0xC000_0034_u32 as NTSTATUS;
        assert_eq!(decide_post_delete(other), WhiteoutAction::Skip);
    }
}
