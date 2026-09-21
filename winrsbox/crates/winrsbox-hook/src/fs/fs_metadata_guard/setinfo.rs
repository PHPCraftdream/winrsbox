use ntapi::ntioapi::IO_STATUS_BLOCK;
use ntapi::winapi::shared::ntdef::HANDLE;
use ntapi::winapi::shared::ntdef::NTSTATUS;
use ntapi::winapi::shared::ntdef::OBJECT_ATTRIBUTES;
use winapi::ctypes::c_void;

use super::{
    anti_rec, decide_post_delete, hooks, nt_call_original, query_handle_dos_path,
    resolve_dest_path, UNICODE_STRING, WhiteoutAction,
    FILE_DISPOSITION_EX_INFO_CLASS, FILE_DISPOSITION_INFO_CLASS, FILE_LINK_EX_INFO_CLASS,
    FILE_LINK_INFO_CLASS, FILE_RENAME_EX_INFO_CLASS, FILE_RENAME_INFO_CLASS,
    FSCTL_DELETE_REPARSE_POINT, FSCTL_PIPE_IMPERSONATE, FSCTL_SET_REPARSE_POINT,
    FSCTL_SET_REPARSE_POINT_EX, HOOK_NT_DELETE_FILE, HOOK_NT_FS_CONTROL_FILE,
    HOOK_NT_SET_INFO_FILE, MAX_OBJECT_NAME_BYTES, STATUS_ACCESS_DENIED,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_REPARSE_POINT_ENCOUNTERED, STATUS_SUCCESS,
};

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
pub(crate) unsafe fn parse_rename_info(info: *const u8, len: usize) -> Option<(HANDLE, String)> {
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
pub(crate) fn build_absolute_rename_buffer(orig: &[u8], dest_dos_lower: &str) -> Option<(Vec<u8>, u32)> {
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
pub(crate) unsafe fn parse_disposition_info(info: *const u8, len: usize, class: u32) -> Option<(bool, u32)> {
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

pub(crate) unsafe extern "system" fn hook_nt_set_information_file(
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

pub(crate) unsafe extern "system" fn hook_nt_fs_control_file(
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
pub(crate) unsafe extern "system" fn hook_nt_set_ea_file(
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
pub(crate) enum DeleteResult {
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
pub(crate) unsafe fn resolve_delete_target(attrs: *const OBJECT_ATTRIBUTES) -> Option<String> {
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
pub(crate) unsafe fn apply_delete_decision(
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
