// CoW overlay destination preparation and mock-overlay materialization.

use super::*;

// ---------------------------------------------------------------------------
// CoW helper
// ---------------------------------------------------------------------------

/// Segment-aware check that an ASCII-lowercased overlay destination lives in
/// launcher-owned territory: inside one of `roots_lower` (the published
/// overlay roots, lowercased) or inside the launcher `mock-dirs` directory —
/// mock-dir Cow decisions legitimately mirror into the `mock-dirs` sibling of
/// the workdir root, which the session config does not publish separately.
/// The rest of the launcher state dir grants nothing (a `<state>\workdirevil`
/// sibling lookalike is refused) and a volume-root parent (`c:\`) grants
/// nothing.
///
/// Refuses: empty destinations, empty roots, sibling-prefix lookalikes
/// (`<root>evil\...` — segment-anchored matching) and any `.`/`..` segment
/// in the destination (never folded here — refuse rather than guess what the
/// kernel would resolve; mirrors the `path_contained_in` backstop on the
/// policy side).
pub(crate) fn overlay_dest_in_roots(dest_lower: &str, roots_lower: &[&str]) -> bool {
    let dest_trim = dest_lower.trim_end_matches(|c| c == '\\' || c == '/');
    if dest_trim.is_empty() {
        return false;
    }
    if dest_trim.split(|c| c == '\\' || c == '/').any(|seg| seg == "." || seg == "..") {
        return false;
    }
    roots_lower.iter().any(|root| {
        let root_trim = root.trim_end_matches('\\');
        if root_trim.is_empty() {
            return false;
        }
        // Direct: destination under the root itself (workdir CoW mirror).
        if policy::path::pattern_matches_prefix(root_trim, dest_trim) {
            return true;
        }
        // Launcher state dir carve-out — mock-dirs sibling ONLY: mock-dir
        // Cow decisions mirror into `<state>\mock-dirs\...`, which the session
        // config does not publish separately. The parent of `c:\workdir` is
        // `c:\state`; a volume-root parent (`c:\`, no parent of its own)
        // grants nothing. Allowing the whole state dir would admit sibling
        // lookalikes (`<state>\workdirevil\...`) — only the mock-dirs
        // subtree is allowed.
        let state_path = std::path::Path::new(root_trim)
            .parent()
            .map(|p| p.to_path_buf());
        if let Some(state) = state_path {
            let state_lossy = state.to_string_lossy();
            let state_trim = state_lossy.trim_end_matches('\\');
            if !state_trim.is_empty() && state.parent().is_some() {
                let mock_root = format!("{state_trim}\\mock-dirs");
                if policy::path::pattern_matches_prefix(&mock_root, dest_trim) {
                    return true;
                }
            }
        }
        false
    })
}

pub(crate) fn prepare_overlay(decision: &Decision) -> Option<String> {
    // Launcher-published roots: per-drive list first, legacy single root as
    // fallback (same resolution as every other overlay-root consumer in this
    // crate). Both are launcher-authored. Empty → fail closed below.
    let roots_lower = overlay_roots_lower(
        crate::ipc_client::OVERLAY_ROOTS.get(),
        SANDBOX_ROOT.get().map(|s| s.as_str()),
    );
    let roots: Vec<&str> = roots_lower.iter().map(|s| s.as_str()).collect();
    prepare_overlay_in_roots(decision, &roots)
}

/// Resolve the allowed overlay roots and ASCII-fold them.
///
/// The fold is not cosmetic. The launcher publishes each root with its
/// on-disk case (`D:\dev\…`), while `prepare_overlay_in_roots` compares a
/// destination that has already been lowercased. Without folding the root,
/// `d:\…` never prefix-matched `D:\…`, so EVERY copy-on-write write outside
/// `project_root` was refused with STATUS_ACCESS_DENIED — on any volume whose
/// path is not already lowercase, which is the normal case. The sandbox's
/// core feature was inoperative and the failure was silent apart from a
/// `prepare_overlay_reject` line.
///
/// Every other consumer of `OVERLAY_ROOTS` in this crate already folds the
/// root locally for the same reason (`is_overlay_root_ancestor`,
/// `is_self_overlay_workdir_access`, the unmirror helper in
/// `overlay_to_virtual_dos`). Split out as a pure function so the fold is
/// testable without the OnceLock globals.
pub(super) fn overlay_roots_lower(published: Option<&Vec<String>>, sandbox_root: Option<&str>) -> Vec<String> {
    match published {
        Some(list) if !list.is_empty() => list.iter().map(|s| s.to_ascii_lowercase()).collect(),
        // Legacy single-root fallback.
        _ => sandbox_root
            .map(|s| vec![s.to_ascii_lowercase()])
            .unwrap_or_default(),
    }
}

/// Core of `prepare_overlay` with the allowed roots injected (test seam — the
/// OnceLock globals cannot be set per-test). `roots` are the lowercased
/// published overlay roots; an empty slice fail-closes every destination.
pub(super) fn prepare_overlay_in_roots(decision: &Decision, roots: &[&str]) -> Option<String> {
    let overlay_path = decision.overlay.as_ref()?;
    let overlay_dos = overlay_path.to_string_lossy().into_owned();

    // Defence in depth (audit 2026-09-19 Critical #2): the launcher validates
    // RecordOverlay wire requests, but this DLL runs inside the hostile
    // target — re-check every destination against launcher-owned territory
    // BEFORE create_dir_all / fs::copy touch the disk. A destination outside
    // the overlay roots must never be created or written to, whatever
    // produced it. Fail-closed: callers turn None into STATUS_ACCESS_DENIED.
    let dest_lower = overlay_dos.to_ascii_lowercase();
    if !overlay_dest_in_roots(&dest_lower, roots) {
        ipc_log_violation(ipc::Req::Log {
            // SAFETY: GetCurrentProcessId is a non-failing Win32 query with no
            // preconditions (constant pseudo-handle semantics, no pointers).
            pid: unsafe { GetCurrentProcessId() },
            level: ipc::LogLevel::Error,
            msg: format!(
                "prepare_overlay_reject: overlay destination outside overlay roots: {overlay_dos}"
            ),
        });
        return None;
    }

    if let Some(parent) = overlay_path.parent() {
        // S05 (docs/review-xa-2026-09-20): a pre-existing junction/symlink
        // INSIDE the overlay tree silently redirects create_dir_all — and the
        // CoW copy that follows — onto real disk. The destination string
        // alone cannot see that; verified_create_dir_all resolves the parent
        // (and, for a create-new, its deepest existing ancestor) against the
        // roots, before AND after touching the disk.
        //
        // IN_HOOK is true on this thread; filesystem calls here will see IN_HOOK=true
        // in the hook and call the original immediately — no recursion.
        let parent_lower = parent.to_string_lossy().to_ascii_lowercase();
        let parent_ok = if overlay_dest_in_roots(&parent_lower, roots) {
            verified_create_dir_all(parent, roots)
        } else {
            // The destination itself may be the published workdir root.
            std::fs::symlink_metadata(overlay_path).is_ok()
                && resolved_parent_in_roots(overlay_path, roots)
        };
        if !parent_ok {
            ipc_log_violation(ipc::Req::Log {
                // SAFETY: GetCurrentProcessId is a non-failing Win32 query with no
                // preconditions (constant pseudo-handle semantics, no pointers).
                pid: unsafe { GetCurrentProcessId() },
                level: ipc::LogLevel::Error,
                msg: format!(
                    "prepare_overlay_reject: destination parent resolves outside overlay roots: {overlay_dos}"
                ),
            });
            return None;
        }
    }

    if let Some(ref src) = decision.cow_from {
        if !overlay_path.exists() {
            // PERFORMANCE FAST-PATH ONLY: this exists() check skips
            // re-opening (and re-verifying) the CoW source after the
            // overlay has already been materialized. It decides nothing
            // about correctness — the materialization race is decided
            // solely by cow_copy_verified's atomic create_new(true): a
            // racer that loses (AlreadyExists) never opens or writes the
            // destination, so content can never be clobbered or
            // interleaved.
            //
            // S05 (docs/review-xa-2026-09-20): the launcher recorded `cow_from`
            // after an existence check in the *trusted* policy process, but
            // this copy runs *inside the hostile target*. The old
            // src_is_reparse_point() guard closed only the FINAL-component
            // case, and only at metadata time: repeated symlink_metadata
            // before std::fs::copy is not an atomic TOCTOU fix (query and
            // copy re-resolve the path independently) and never checked
            // INTERMEDIATE components — a symlink/junction on any component
            // still pointed the copy at an attacker-chosen external file
            // (information escape / overlay seeded from outside the
            // boundary). cow_copy_verified opens the source ONCE, verifies
            // that the handle's resolved final path equals the named source,
            // and streams the bytes from that SAME handle — no path is
            // re-resolved between the check and the copy.
            //
            // Copy failures are still ignored here (same as the old
            // `let _ = std::fs::copy`): a skipped copy is never a hard
            // failure, and the hook's redirected open surfaces real problems
            // through NTSTATUS.
            let _ = cow_copy_verified(src, overlay_path);
        }
    }

    Some(overlay_dos)
}

/// True final path of an OPEN handle, in the device-prefixed DOS form that
/// GetFinalPathNameByHandleW returns with flags 0 (VOLUME_NAME_DOS):
/// `\\?\D:\…`, or `\\?\UNC\server\share\…` for UNC.
///
/// S05 (docs/review-xa-2026-09-20): this is the oracle a string-level check
/// cannot be — it reports where the kernel ACTUALLY opened, after every
/// reparse point on every path component has been traversed.
///
/// None → the query failed (invalid handle, vanished object, pathologically
/// long path); callers fail closed on None.
fn final_handle_path(file: &std::fs::File) -> Option<String> {
    use std::os::windows::io::AsRawHandle;
    // Fast path: a stack buffer covers every sane path. A successful call
    // returns the chars copied (NUL excluded); a too-small buffer returns the
    // required size (NUL included).
    let mut buf = [0u16; 512];
    // SAFETY: `file` owns a valid open file handle for the duration of the
    // call, and `buf` is a valid writeable u16 buffer of buf.len() elements
    // for the same duration — exactly GetFinalPathNameByHandleW's contract.
    // (as_raw_handle is std's *mut c_void; the cast retypes it to winapi's
    // HANDLE — the same raw pointer under a different c_void definition.)
    let n = unsafe {
        winapi::um::fileapi::GetFinalPathNameByHandleW(
            file.as_raw_handle() as *mut winapi::ctypes::c_void,
            buf.as_mut_ptr(),
            buf.len() as u32,
            0,
        )
    };
    if n == 0 {
        return None;
    }
    if (n as usize) < buf.len() {
        return Some(String::from_utf16_lossy(&buf[..n as usize]));
    }
    // Too small: the return IS the required size including the NUL. Retry
    // once with a heap buffer of exactly that size; give up above 32 Ki
    // chars (64 KiB of path is not a file, it is an attack).
    let need = n as usize;
    if need > 32 * 1024 {
        return None;
    }
    let mut big = vec![0u16; need];
    // SAFETY: `file` owns a valid open file handle, and `big` is a valid
    // writeable u16 buffer of the API-reported required size for the call.
    let n2 = unsafe {
        winapi::um::fileapi::GetFinalPathNameByHandleW(
            file.as_raw_handle() as *mut winapi::ctypes::c_void,
            big.as_mut_ptr(),
            big.len() as u32,
            0,
        )
    };
    if n2 == 0 || n2 as usize >= big.len() {
        return None;
    }
    Some(String::from_utf16_lossy(&big[..n2 as usize]))
}

/// Convert GetFinalPathNameByHandleW output into the plain DOS form the rest
/// of this crate compares against, then ASCII-lowercase:
/// `\\?\D:\x\y` → `d:\x\y`; a UNC final path keeps its leading `\\`
/// (`\\?\UNC\server\share\x` → `\\server\share\x`).
fn normalize_resolved_dos(p: &str) -> String {
    let stripped = if let Some(rest) = p.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = p.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        // Not device-prefixed (should not happen for this API) — pass
        // through rather than guess.
        p.to_string()
    };
    stripped.to_ascii_lowercase()
}

/// Handle-based containment check: `p` must canonicalize (which resolves
/// every reparse point on every component) to a path inside `roots`.
/// Errors fail closed.
fn resolved_parent_in_roots(p: &std::path::Path, roots: &[&str]) -> bool {
    match std::fs::canonicalize(p) {
        // canonicalize is GetFinalPathNameByHandleW underneath: its output is
        // the device-prefixed verbatim form (`\\?\D:\…`), so de-prefix + fold
        // exactly like final_handle_path output before the string check.
        Ok(c) => overlay_dest_in_roots(&normalize_resolved_dos(&c.to_string_lossy()), roots),
        // Fail closed: an unresolvable parent is not proven in-root.
        Err(_) => false,
    }
}

/// Create `parent` (like `std::fs::create_dir_all`) but refuse to let a
/// pre-existing junction/symlink/hardlink anywhere in the parent chain
/// redirect the creation — or the writes that follow it — outside `roots`.
///
/// S05 (docs/review-xa-2026-09-20): a string-level containment check of the
/// destination is blind to reparse points ON the path. A junction planted at
/// `<root>\link` → `d:\real` makes the string `<root>\link\evil.txt` look
/// in-root while create_dir_all happily creates `d:\real\evil.txt`. This
/// helper therefore:
///   1. an EXISTING parent is allowed iff it canonicalizes INSIDE `roots`
///      (a junction parent is allowed iff it resolves in-root — same
///      tolerance as the merged policy-side gap 1,
///      `path_aliases_outside_root` in crates/winrsbox-policy/src/decide/mod.rs;
///      reference only — this crate cannot reuse it — one pointing outside
///      is refused);
///   2. a MISSING parent is resolved through its deepest EXISTING ancestor
///      (canonicalize cannot walk missing components; the walk mirrors the
///      same policy-side helper) and the re-appended missing tail must still
///      string-match inside `roots`;
///   3. after create_dir_all succeeds, the parent is re-canonicalized — what
///      was actually created on disk must be where we think it is.
///
/// False on a refused/failed creation is fail-closed for the caller. Only
/// the containment refusals log violations; a plain create_dir_all error is
/// a functional failure, not a violation.
fn verified_create_dir_all(parent: &std::path::Path, roots: &[&str]) -> bool {
    if std::fs::symlink_metadata(parent).is_ok() {
        // Exists right now — nothing to create; its resolution must be
        // in-root (no-follow metadata open + handle-based canonicalize, so
        // a junction parent is judged by where it POINTS).
        return resolved_parent_in_roots(parent, roots);
    }

    // Missing: walk up to the deepest EXISTING ancestor, collecting the
    // missing tail on the way down. The ANCESTOR itself may legitimately
    // sit outside the roots (e.g. `<state>\workdir`'s parent is the state
    // dir) — containment is judged on the JOINED result only.
    let mut cur = parent;
    let mut missing_tail: Vec<std::ffi::OsString> = Vec::new();
    while std::fs::symlink_metadata(cur).is_err() {
        match (cur.file_name(), cur.parent()) {
            (Some(name), Some(up)) => {
                missing_tail.push(name.to_os_string());
                cur = up;
            }
            // Popped past the drive root without finding anything existing —
            // nothing resolvable to anchor on; fail closed.
            _ => return false,
        }
    }
    // Resolve the ancestor by handle (canonicalize traverses every reparse
    // point on the existing chain); an unresolvable anchor fails closed.
    // De-prefix the verbatim `\\?\` form so the joined string is plain DOS
    // like the roots.
    let anchor = match std::fs::canonicalize(cur) {
        Ok(a) => normalize_resolved_dos(&a.to_string_lossy()),
        Err(_) => return false,
    };
    let mut joined = anchor;
    for seg in missing_tail.iter().rev() {
        joined.push('\\');
        joined.push_str(&seg.to_string_lossy());
    }
    if !overlay_dest_in_roots(&joined.to_ascii_lowercase(), roots) {
        ipc_log_violation(ipc::Req::Log {
            // SAFETY: GetCurrentProcessId is a non-failing Win32 query with no
            // preconditions (constant pseudo-handle semantics, no pointers).
            pid: unsafe { GetCurrentProcessId() },
            level: ipc::LogLevel::Error,
            msg: format!(
                "verified_create_reject: destination parent's deepest existing ancestor resolves outside overlay roots: {joined}"
            ),
        });
        return false;
    }

    // The joined (anchor + missing tail) string passed — create.
    if std::fs::create_dir_all(parent).is_err() {
        return false;
    }

    // POST-create re-check: confirms what was actually created on disk is
    // where we think it is (a reparse point planted mid-walk cannot redirect
    // the creation unnoticed).
    if !resolved_parent_in_roots(parent, roots) {
        ipc_log_violation(ipc::Req::Log {
            // SAFETY: GetCurrentProcessId is a non-failing Win32 query with no
            // preconditions (constant pseudo-handle semantics, no pointers).
            pid: unsafe { GetCurrentProcessId() },
            level: ipc::LogLevel::Error,
            msg: format!(
                "verified_create_reject: created parent resolves outside overlay roots: {}",
                parent.display()
            ),
        });
        return false;
    }
    true
}

/// Verified open-then-copy for CoW: opens the source ONCE, proves the
/// handle's resolved final path equals the named source, then streams the
/// bytes from that SAME handle into a no-follow destination create.
///
/// S05 (docs/review-xa-2026-09-20): replaces the old symlink_metadata-then-
/// fs::copy guard, because repeated symlink_metadata before copy is not an
/// atomic TOCTOU fix and does not check intermediate path components.
///
///  1. The source is opened and queried by HANDLE (final_handle_path), so
///     this compares the handle's true final path to the NAMED path: any
///     reparse point on ANY component — final or intermediate — makes the two
///     diverge (canonicalize_for_denylist is string-level only: it
///     ASCII-lowercases, folds `/`→`\`, strips per-segment trailing
///     dot/space; it does not resolve anything). A divergence means the open
///     silently followed an alias → refuse. A hardlinked source intentionally
///     still passes: a hardlink name IS the same object the policy approved
///     copying FROM, and the copy produces a fresh, separate overlay object.
///     Known accepted limitation (same class as policy gap 1): an 8.3
///     short-name spelling in `src` compares unequal to its long name and is
///     refused fail-closed.
///  2. The destination is created with create_new +
///     FILE_FLAG_OPEN_REPARSE_POINT (no-follow): a name occupied by ANY
///     reparse point — including a dangling symlink — FAILS the create
///     instead of being redirected. AlreadyExists is success (the overlay
///     copy was materialized concurrently or earlier — the old
///     `!overlay_path.exists()` skip semantics).
///  3. The bytes stream source→destination through the two open handles; no
///     path is re-resolved, so nothing can swap underneath the copy. C04
///     (docs/review-xa-2026-09-20): if that stream fails midway, the torn
///     destination is removed (discard_torn_materialization) so a short
///     file is never mistaken for a completed copy later.
///
/// Every false return means "copy skipped": the caller treats this exactly
/// like the old ignored-copy-error behavior (CoW is best-effort; the
/// redirected open surfaces real problems through NTSTATUS).
pub(super) fn cow_copy_verified(src: &std::path::Path, overlay_path: &std::path::Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    // Fail closed: an unopenable source skips the copy (the old code also
    // skipped on uncertainty).
    let mut f_src = match std::fs::File::open(src) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let resolved = match final_handle_path(&f_src) {
        Some(r) => normalize_resolved_dos(&r),
        None => return false,
    };
    if super::canonicalize_for_denylist(&resolved)
        != super::canonicalize_for_denylist(&src.to_string_lossy())
    {
        // Some component (or the final one) silently redirected the open.
        ipc_log_violation(ipc::Req::Log {
            // SAFETY: GetCurrentProcessId is a non-failing Win32 query with no
            // preconditions (constant pseudo-handle semantics, no pointers).
            pid: unsafe { GetCurrentProcessId() },
            level: ipc::LogLevel::Error,
            msg: format!(
                "cow_copy_reject: CoW source resolves elsewhere than named: {} -> {resolved}",
                src.display()
            ),
        });
        return false;
    }

    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        // FILE_FLAG_OPEN_REPARSE_POINT: open the final component itself, not
        // whatever its reparse point targets — create_new then fails on an
        // occupied name instead of following it.
        .custom_flags(0x0020_0000)
        .open(overlay_path)
    {
        // Materialized concurrently or earlier — same as the old
        // `!overlay_path.exists()` skip.
        Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => true,
        Err(_) => false,
        Ok(mut f_dst) => {
            // Stream from the SAME verified source handle — no path
            // re-resolution between check and copy. C04
            // (docs/review-xa-2026-09-20): a stream that fails midway must
            // not leave a short/torn file at the FINAL name — every later
            // exists()/create_new call would treat it as fully
            // materialized, forever. Best-effort removal re-opens the race
            // window so the next open retries materialization cleanly; the
            // failure itself stays a skip (false), never a hard error.
            match std::io::copy(&mut f_src, &mut f_dst) {
                Ok(_) => true,
                Err(_) => {
                    discard_torn_materialization(overlay_path);
                    false
                }
            }
        }
    }
}

/// C04 (docs/review-xa-2026-09-20): a failed copy/write after the
/// exclusive create must not leave a short file behind — every later
/// exists()/create_new call would treat the torn file as fully
/// materialized forever. Best-effort removal re-opens the race window
/// so the next open retries the materialization cleanly.
pub(super) fn discard_torn_materialization(overlay_path: &std::path::Path) {
    let _ = std::fs::remove_file(overlay_path);
}

/// Materialize a Mock-mode overlay file exactly once.
///
/// On the first call for a given `overlay_path`, the parent directory is
/// created (idempotent) and `payload` is written. On subsequent calls — when
/// `overlay_path` already exists — this is a no-op. Errors from the underlying
/// filesystem operations are swallowed: the hook's redirected open will
/// surface any real problem through normal NTSTATUS channels.
///
/// Idempotency is load-bearing for two reasons:
///   1. Performance: Mock-targeted paths can be opened thousands of times
///      (config files, registry-like polls). Rewriting on every open is a
///      pointless storm.
///   2. Correctness: concurrent threads opening the same path used to race
///      `std::fs::write`, producing torn writes or transient empty files.
///
/// S05 (docs/review-xa-2026-09-20): materialization now refuses destinations
/// (or destination parents) that resolve outside launcher-owned roots, and
/// the create is no-follow (create_new + FILE_FLAG_OPEN_REPARSE_POINT), so a
/// name occupied by ANY reparse point — including a dangling symlink — fails
/// the create instead of redirecting the write outside the sandbox.
pub(crate) fn materialize_mock_overlay(overlay_path: &std::path::Path, payload: &[u8]) {
    // Same root resolution as `prepare_overlay`: launcher-published per-drive
    // list first, legacy single root as fallback. Both are launcher-authored;
    // empty → fail closed in the seam below.
    let roots_lower = overlay_roots_lower(
        crate::ipc_client::OVERLAY_ROOTS.get(),
        SANDBOX_ROOT.get().map(|s| s.as_str()),
    );
    let roots: Vec<&str> = roots_lower.iter().map(|s| s.as_str()).collect();
    materialize_mock_overlay_in_roots(overlay_path, payload, &roots);
}

/// Core of `materialize_mock_overlay` with the allowed roots injected (test
/// seam — the OnceLock globals cannot be set per-test). `roots` are the
/// lowercased published overlay roots; an empty slice fail-closes every
/// destination.
pub(crate) fn materialize_mock_overlay_in_roots(
    overlay_path: &std::path::Path,
    payload: &[u8],
    roots: &[&str],
) {
    use std::os::windows::fs::OpenOptionsExt;
    // Idempotency fast path — load-bearing, see the wrapper's doc comment:
    // rewriting on every open is a pointless storm AND a torn-write race.
    // Performance fast-path only: the materialization race itself is
    // decided solely by the atomic create_new(true) gate below.
    if overlay_path.exists() {
        return;
    }
    // S05 (docs/review-xa-2026-09-20): string-level containment of the
    // destination first.
    let dest_lower = overlay_path.to_string_lossy().to_ascii_lowercase();
    if !overlay_dest_in_roots(&dest_lower, roots) {
        ipc_log_violation(ipc::Req::Log {
            // SAFETY: GetCurrentProcessId is a non-failing Win32 query with no
            // preconditions (constant pseudo-handle semantics, no pointers).
            pid: unsafe { GetCurrentProcessId() },
            level: ipc::LogLevel::Error,
            msg: format!(
                "materialize_mock_reject: overlay destination outside overlay roots: {}",
                overlay_path.display()
            ),
        });
        return;
    }
    let Some(parent) = overlay_path.parent() else {
        return;
    };
    // The parent chain is created only where VERIFIED in-root (junctions on
    // the chain would otherwise redirect the write below).
    if !verified_create_dir_all(parent, roots) {
        ipc_log_violation(ipc::Req::Log {
            // SAFETY: GetCurrentProcessId is a non-failing Win32 query with no
            // preconditions (constant pseudo-handle semantics, no pointers).
            pid: unsafe { GetCurrentProcessId() },
            level: ipc::LogLevel::Error,
            msg: format!(
                "materialize_mock_reject: destination parent resolves outside overlay roots: {}",
                overlay_path.display()
            ),
        });
        return;
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        // FILE_FLAG_OPEN_REPARSE_POINT (no-follow): a name occupied by ANY
        // reparse point — including a dangling symlink — fails the create
        // instead of redirecting the write outside the sandbox.
        .custom_flags(0x0020_0000)
        .open(overlay_path)
    {
        Ok(mut f) => {
            use std::io::Write;
            // Swallowed exactly like the old `std::fs::write`: the hook's
            // redirected open surfaces real problems through NTSTATUS.
            // C04 (docs/review-xa-2026-09-20): but a FAILED write must not
            // leave a torn (short) file behind — every later
            // exists()/create_new call would treat it as fully
            // materialized forever — so the partial file is removed
            // best-effort, re-opening the race window for a clean retry.
            if f.write_all(payload).is_err() {
                discard_torn_materialization(overlay_path);
            }
        }
        // Concurrent materialization won the race — idempotent no-op.
        Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        // Swallowed exactly like the old `std::fs::write`.
        Err(_) => {}
    }
}
