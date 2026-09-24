// Escape-vector denylist: NTFS-style canonicalization and status classification of paths that bypass policy.

use super::*;

/// Mirror NTFS canonicalization: NTFS strips trailing dots and spaces from
/// each path segment when resolving file names. Our denylist comparisons must
/// do the same; otherwise paths like `C:\.winrsbox.  ` bypass the
/// `.ends_with(r"\.winrsbox")` check while the kernel still opens the real
/// `.winrsbox` directory.
///
/// Borrowed-fast-path: when no segment ends with `.` or ` `, returns the input
/// untouched. Hot path for typical paths (Windows path roots, drive letters,
/// well-formed file names) allocates nothing.
///
/// Drive-letter handling: `C:` ends in `:` so it's untouched. `C:.` becomes
/// `C:` (trailing dot stripped). The `\\?\` long-path prefix splits to
/// `["", "", "?", "C:", ...]` and each non-trailing-dot/space segment passes
/// through unchanged.
pub(crate) fn strip_trailing_dot_space(s: &str) -> Cow<'_, str> {
    let needs_strip = s.split('\\').any(|seg| seg.ends_with('.') || seg.ends_with(' '));
    if !needs_strip {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut first = true;
    for seg in s.split('\\') {
        if !first { out.push('\\'); } else { first = false; }
        let trimmed = seg.trim_end_matches(|c: char| c == '.' || c == ' ');
        out.push_str(trimmed);
    }
    Cow::Owned(out)
}

/// Shared escape-vector denylist over an already-canonical lowercase path:
/// ASCII-lowercased, `/` folded to `\`, per-segment trailing dot/space stripped
/// (use `canonicalize_for_denylist`). Single source of truth so the create-side
/// (`check_path_traversal`) and the rename/hardlink-side (`dest_is_escape`)
/// can never drift apart on what counts as an escape.
///
/// Returns `(status, reason)` to deny with, or None to continue. The reason is
/// a stable label for trace logging. NOTE: parent-dir (`..`) handling is
/// intentionally NOT here — it is caller-specific: the create path folds
/// `..`/`.` lexically in `resolve_for_hook` (via
/// `policy::path::fold_nt_dots`) BEFORE the denylist and the policy
/// decision, so the create side always feeds this denylist an already-
/// folded path; the rename/hardlink guard rejects dots-only segments up
/// front (`fs_metadata_guard::dest_is_escape`). Keep the two callers'
/// treatment aligned when touching either.
pub(crate) fn canonical_denylist_status(canon: &str) -> Option<(NTSTATUS, &'static str)> {
    // GLOBALROOT alternate namespace bypasses the DOS-form classifier.
    if canon.contains(r"\??\globalroot") || canon.contains(r"\globalroot\") {
        return Some((STATUS_ACCESS_DENIED, "globalroot"));
    }
    // ADS — a second colon after the drive-letter colon. Works on both NT
    // (`\??\c:\..`) and bare DOS (`c:\..`) forms.
    let after = strip_nt_dos_prefix(canon).unwrap_or(canon);
    let bytes = after.as_bytes();
    if bytes.len() >= 3 && bytes[1] == b':' {
        if let Some(extra_colon) = after[2..].find(':') {
            let stream = &after[2 + extra_colon + 1..];
            let allowed = ["$data", "$index_allocation", "zone.identifier"];
            if !allowed.iter().any(|a| stream == *a || stream.starts_with(&format!("{}:", a))) {
                return Some((STATUS_ACCESS_DENIED, "ads"));
            }
        }
    }
    // A literal `~0` filename is valid; only a spelling that expands is an alias.
    if needs_short_name_resolve(canon) && short_name_alias_or_unknown(after) {
        return Some((STATUS_ACCESS_DENIED, "short_name"));
    }
    // Sandbox state directory — masked as non-existent (NAME_NOT_FOUND) so the
    // process treats `.winrsbox` as absent rather than forbidden.
    if canon.contains(r"\.winrsbox\") || canon.ends_with(r"\.winrsbox") {
        // Self-access carve-out (symmetric with unmirror_overlay_handle_relative
        // for relative opens): a sandboxed process that learned its own overlay
        // path via a passthrough query channel (class-9 FileNameInformation or
        // NtQueryObject — neither masked by design) will re-open its OWN CoW
        // files ABSOLUTELY. Without this carve-out, the absolute overlay path
        // (e.g. `c:\users\…\.winrsbox\<session>\workdir\…\.git`) is blocked by
        // the `\.winrsbox\` rule → NAME_NOT_FOUND → the process's own files
        // become inaccessible. This is a self-DoS, not a probing attack.
        //
        // Only carve out paths UNDER a known overlay workdir root — control
        // files (policy.redb, session-config, violations.log) live inside
        // `.winrsbox` but NOT under `workdir\`, so they stay denied. The match
        // is case-insensitive (canon is already lowercased) and segment-
        // anchored via `pattern_matches_prefix`.
        if is_self_overlay_workdir_access(&canon) {
            return None;
        }
        // Ancestor carve-out: when the process resolved its gitdir to the
        // overlay path (via GetFinalPathNameByHandle / class-9 leak), git's
        // canonical-path resolution walks UP the path chain, checking each
        // parent directory via stat()/GetFileAttributes. If `.winrsbox` or
        // `.winrsbox\hermes` is masked as NOT_FOUND, the chain breaks and
        // git aborts ("unable to create directory for ..."). If the path is
        // an ANCESTOR of a known overlay root, don't block — the process is
        // walking its own legitimate path chain, not probing for sandbox
        // internals. Control files (siblings of `workdir\`, like `policy.redb`)
        // are NOT ancestors → stay blocked.
        if is_overlay_root_ancestor(&canon) {
            return None;
        }
        return Some((STATUS_OBJECT_NAME_NOT_FOUND, "winrsbox"));
    }
    None
}

/// Canonical lowercase form for denylist comparison: ASCII-lowercase, `/`
/// folded to `\` (the object manager accepts `/` as a separator), per-segment
/// trailing dot/space stripped (mirrors NTFS). Borrows-through when nothing
/// needs changing on the hot path.
pub(crate) fn canonicalize_for_denylist(s: &str) -> Cow<'_, str> {
    let needs_case = s.bytes().any(|b| b.is_ascii_uppercase());
    let needs_slash = s.contains('/');
    let needs_strip = s.split('\\').any(|seg| seg.ends_with('.') || seg.ends_with(' '));

    if !needs_case && !needs_slash && !needs_strip {
        return Cow::Borrowed(s);
    }

    // Single-pass: ASCII-lowercase + fold '/' → '\'. Iterate over CHARS (not
    // bytes) so multibyte non-ASCII sequences are preserved verbatim, exactly
    // as the original `s.to_ascii_lowercase()` did — `char::to_ascii_lowercase`
    // maps only A–Z and leaves every non-ASCII char untouched. (A per-byte
    // `b as char` fold would mojibake bytes >= 0x80 into U+0080..U+00FF and
    // diverge from the old output for non-ASCII paths.)
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch == '/' {
            out.push('\\');
        } else {
            out.push(ch.to_ascii_lowercase());
        }
    }

    // Apply per-segment trailing-dot/space strip (reuse existing helper).
    match strip_trailing_dot_space(&out) {
        Cow::Borrowed(_) => Cow::Owned(out),
        Cow::Owned(stripped) => Cow::Owned(stripped),
    }
}

/// Returns Some(STATUS_ACCESS_DENIED) if the raw NT path or create options
/// indicate a path-traversal / escape vector. None → caller should continue.
///
/// Checks:
///   1. FILE_OPEN_BY_FILE_ID — opens by FileID, path ignored by kernel
///   2. GLOBALROOT alternate namespace — bypasses DOS-form classifier
///   3. ADS (Alternate Data Streams) — colon after drive letter (non-standard)
///   4. 8.3 short names (e.g. `PROGRA~1`) — bypass classifier + CoW pipeline
///   5. Sandbox state hide (`.winrsbox`) — masked with NAME_NOT_FOUND
///
/// All path comparisons use a single canonical form: ASCII-lowercased AND
/// per-segment trailing dot/space stripped, mirroring how the NT kernel +
/// NTFS will canonicalize the path before opening it. ASCII-only lowercase
/// is intentional: every denylist substring (`\.winrsbox`, `globalroot`,
/// etc.) is ASCII; non-ASCII bytes pass through untouched and therefore
/// cannot collapse into an ASCII denylist match (or escape one) via
/// Unicode case-fold mismatches with the kernel's `RtlDowncaseUnicodeString`.
///
/// Parent-dir (`..`) handling is deliberately NOT part of this raw-path
/// check: `resolve_for_hook` folds `..`/`.` lexically before the policy
/// decision (audit Critical #1), and the create/open hooks re-run
/// `canonical_denylist_status` on the resolved FOLDED DOS path afterwards,
/// so folding cannot hide a denylist hit that the raw string would have
/// missed in the other direction.
///
/// SAFETY: `attrs` must be valid per NT calling convention.
pub(crate) unsafe fn check_path_traversal(attrs: *const OBJECT_ATTRIBUTES, create_options: u32) -> Option<NTSTATUS> {
    // 1. FILE_OPEN_BY_FILE_ID — path ignored, opens by FileID instead
    const FILE_OPEN_BY_FILE_ID: u32 = 0x00002000;
    if create_options & FILE_OPEN_BY_FILE_ID != 0 {
        if is_trace() { ipc_log(ipc::LogLevel::Trace, "fs_block_open_by_file_id".into()); }
        return Some(STATUS_ACCESS_DENIED);
    }

    // 2-5. Canonicalize ONCE (ASCII-lowercase, `/`→`\`, per-segment trailing
    //      dot/space strip — the kernel + NTFS apply these before resolving the
    //      path), then run the shared denylist (GLOBALROOT / ADS / 8.3
    //      short-name / .winrsbox). ASCII-only lowercase keeps non-ASCII bytes
    //      (e.g. U+0130) from folding into or out of an ASCII denylist match.
    //      This is the single source of truth shared with the rename/hardlink
    //      guard (fs_metadata_guard::dest_is_escape) so the two cannot drift.
    let raw_nt = extract_raw_nt_path(attrs)?;
    let canon = canonicalize_for_denylist(&raw_nt);
    if let Some((status, reason)) = canonical_denylist_status(&canon) {
        // Pragmatic mkdir handling: when the process resolved its gitdir to
        // the overlay path (via GetFinalPathNameByHandle / class-9 leak),
        // git's safe_create_leading_directories walks the full path from
        // root, calling mkdir for each component. When it reaches `.winrsbox`
        // (the ancestor of the overlay root), our denylist masks it as
        // NAME_NOT_FOUND. Git interprets this as ENOENT from mkdir →
        // "unable to create directory" → clone aborts.
        //
        // Fix: for directory creation (mkdir = FILE_DIRECTORY_FILE), return
        // STATUS_OBJECT_NAME_COLLISION (EEXIST) instead of NOT_FOUND. Git's
        // mkdir sees "already exists" → skips → continues to the next dir.
        // This is safe: the directory physically exists, and we're just
        // letting the caller's mkdir-then-check-EEXIST logic proceed.
        const FILE_DIRECTORY_FILE: u32 = 0x00000001;
        if reason == "winrsbox"
            && status == STATUS_OBJECT_NAME_NOT_FOUND
            && create_options & FILE_DIRECTORY_FILE != 0
        {
            return Some(STATUS_OBJECT_NAME_COLLISION);
        }
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace, format!("fs_block_{reason}: {}", raw_nt));
        }
        return Some(status);
    }

    None
}

/// Return true iff `canon` is a strict ANCESTOR of a known overlay root
/// (i.e., the root starts with `canon\`). Used to carve out `.winrsbox`
/// and `.winrsbox\hermes` from the denylist so the process's canonical-
/// path resolution (walking up the chain) doesn't break when it resolved
/// its gitdir to the overlay path. Control files (siblings of `workdir\`)
/// are NOT ancestors → stay denied.
fn is_overlay_root_ancestor(canon: &str) -> bool {
    let canon_dos = strip_nt_dos_prefix(canon).unwrap_or(canon);
    let canon_trimmed = canon_dos.trim_end_matches('\\');
    if canon_trimmed.is_empty() { return false; }
    let roots: Vec<&str> = match crate::ipc_client::OVERLAY_ROOTS.get() {
        Some(list) if !list.is_empty() => list.iter().map(|s| s.as_str()).collect(),
        _ => match SANDBOX_ROOT.get() {
            Some(s) => vec![s.as_str()],
            None => return false,
        },
    };
    for root in &roots {
        let root_lower = root.to_ascii_lowercase();
        let root_trimmed = root_lower.trim_end_matches('\\');
        // canon is an ancestor of root if root starts with `canon\`.
        if root_trimmed.starts_with(&format!("{}\\", canon_trimmed)) {
            return true;
        }
    }
    false
}

/// Return true iff a canonicalized lowercased DOS path is under one of the
/// known overlay WORKDIR roots (i.e. it is the sandboxed process's own CoW
/// data, re-opened absolutely after a passthrough query leaked the overlay
/// location). This is the self-access carve-out for the `\.winrsbox\` deny
/// rule: control files (policy.redb, session-config) live under `.winrsbox`
/// but NOT under `workdir\`, so they remain denied.
///
/// `canon` is already ASCII-lowercased + canonicalized (per-segment trailing
/// dot/space stripped) by `canonicalize_for_denylist`. Matching is segment-
/// anchored via `pattern_matches_prefix` to avoid sibling-prefix false hits.
pub(super) fn is_self_overlay_workdir_access(canon: &str) -> bool {
    // Try the multi-root layout first (Path 1), then the legacy single root.
    let roots: Vec<&str> = match crate::ipc_client::OVERLAY_ROOTS.get() {
        Some(list) if !list.is_empty() => list.iter().map(|s| s.as_str()).collect(),
        _ => match SANDBOX_ROOT.get() {
            Some(s) => vec![s.as_str()],
            None => return false,
        },
    };
    // `canon` may carry the `\??\` NT prefix; strip it for the DOS comparison.
    let canon_dos = strip_nt_dos_prefix(canon).unwrap_or(canon);
    // Defense-in-depth: even after the structural fix (policy.redb moved out
    // of workdir), explicitly deny control files that might end up under an
    // overlay root. These are NOT agent data — they are sandbox internals.
    // The last segment is checked against a denylist of known control
    // filenames + the *.redb extension.
    if is_control_file(canon_dos) {
        return false;
    }
    for root in &roots {
        let root_lower = root.to_ascii_lowercase();
        let root_trimmed = root_lower.trim_end_matches('\\');
        if root_trimmed.is_empty() {
            continue;
        }
        if policy::path::pattern_matches_prefix(root_trimmed, canon_dos) {
            return true;
        }
    }
    // Diagnostic: log why the carve-out didn't match.
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace,
            format!("carveout_miss: canon_dos={canon_dos} roots_count={} first_root={:?}",
                roots.len(), roots.first()));
    }
    false
}

/// Return true if the last path segment of `canon_dos` (a canonicalized
/// lowercased DOS path) is a known sandbox control file or has a `.redb`
/// extension. These are NEVER agent data and must not be carved out by the
/// self-access exception — even if they somehow end up under an overlay root.
pub(super) fn is_control_file(canon_dos: &str) -> bool {
    const CONTROL_NAMES: &[&str] = &[
        "policy.redb",
        "sandbox.ktav",
        "sandbox.log.jsonl",
        "violations.log",
        "hot-stats.json",
    ];
    let last_seg = canon_dos.rsplit('\\').next().unwrap_or(canon_dos);
    if CONTROL_NAMES.iter().any(|&n| last_seg == n) {
        return true;
    }
    // Any *.redb file — future-proof against renamed DB files.
    last_seg.ends_with(".redb")
}

/// Strip the `\??\` (or `\\?\`) prefix from an NT DOS-form path string.
/// Returns the remainder (e.g. `c:\path`) or None if the path doesn't start
/// with a known prefix.
fn strip_nt_dos_prefix(lower: &str) -> Option<&str> {
    if let Some(rest) = lower.strip_prefix(r"\??\") {
        return Some(rest);
    }
    if let Some(rest) = lower.strip_prefix(r"\\?\") {
        return Some(rest);
    }
    None
}
