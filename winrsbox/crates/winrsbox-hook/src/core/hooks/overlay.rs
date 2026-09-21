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
        // IN_HOOK is true on this thread; filesystem calls here will see IN_HOOK=true
        // in the hook and call the original immediately — no recursion.
        let _ = std::fs::create_dir_all(parent);
    }

    if let Some(ref src) = decision.cow_from {
        if !overlay_path.exists() && !src_is_reparse_point(src) {
            // src_is_reparse_point() guard above closes a TOCTOU: the launcher
            // recorded `cow_from` after an existence check in the *trusted*
            // policy process, but this copy runs *inside the hostile target*.
            // Between decision and copy, the adversary can swap the source for
            // a symlink/junction pointing OUTSIDE the sandbox. std::fs::copy
            // follows reparse points, so without this check it would copy an
            // attacker-chosen external file into the overlay (information
            // escape / overlay seeded from outside the boundary). We re-check
            // immediately before the copy and refuse if the source is now a
            // reparse point — a normal file is copied as before.
            let _ = std::fs::copy(src, overlay_path);
        }
    }

    Some(overlay_dos)
}

/// True if `src` is a reparse point (symlink, junction/mount point, or any
/// other reparse tag) *right now*.
///
/// Uses `symlink_metadata`, which on Windows opens with no-follow semantics
/// (it does NOT traverse the final reparse point), and tests the
/// `FILE_ATTRIBUTE_REPARSE_POINT` (0x400) bit directly. Checking the attribute
/// bit — rather than `FileType::is_symlink()` — is deliberate: `is_symlink()`
/// returns false for NTFS junctions/mount points, which are exactly the
/// reparse type an attacker can create without privilege. We must reject ALL
/// reparse points, not just name-surrogate symlinks.
///
/// Fails closed: if the metadata query itself errors (e.g. the source vanished
/// in the race), we treat the source as untrusted and skip the CoW copy.
fn src_is_reparse_point(src: &std::path::Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    match std::fs::symlink_metadata(src) {
        Ok(md) => md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0,
        Err(_) => true,
    }
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
pub(crate) fn materialize_mock_overlay(overlay_path: &std::path::Path, payload: &[u8]) {
    if overlay_path.exists() {
        return;
    }
    if let Some(parent) = overlay_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(overlay_path, payload);
}