use super::*;

// ---------------------------------------------------------------------------
// S05 (docs/review-xa-2026-09-20) — passthrough pre-open alias probe
//
// The finding (P1): the hook and the policy approve the STRING path, then
// the original NtCreateFile/NtOpenFile lets the KERNEL resolve it —
// silently following a junction/symlink on ANY component to a real object
// outside the root. A post-open check is too late for OVERWRITE/truncate
// dispositions (the real object is already truncated by the time the
// handle exists), so the probe below walks the REAL filesystem ahead of
// the open.
// ---------------------------------------------------------------------------

/// S05 (docs/review-xa-2026-09-20): what the pre-open component walk found
/// about the REAL filesystem behind a passthrough write-open path.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PassthroughProbe {
    /// Every existing component is reparse-free and the final component is
    /// either missing, a directory, or a single-link file — the kernel open
    /// will land exactly on the decided path.
    Clean,
    /// A reparse point sits on some component (final or intermediate): the
    /// kernel would silently traverse it. `resolved` is that component's
    /// handle-resolved final location with the not-yet-existing tail
    /// re-appended — the path the kernel would ACTUALLY touch.
    Aliased { resolved: String },
    /// The final component is an existing multi-link FILE: one underlying
    /// file object answers to names we cannot see, so writing this name
    /// mutates an object reachable outside the sandbox (path stays in-tree,
    /// object does not).
    MultiLink,
    /// The filesystem state could not be proven (metadata query error other
    /// than not-found, unresolvable alias, undeterminable link count on a
    /// file) — fail closed.
    Unverifiable,
}

/// Link count of the file object named by `p`, or `None` when it cannot be
/// determined (open failed — sharing violation, permissions, … — or the
/// API call failed). S05 (docs/review-xa-2026-09-20): mirrors the shape of
/// policy decide/mod.rs's `number_of_links` (policy internals are
/// pub(crate) — not importable from the hook), but goes through winapi's
/// `fileapi` bindings (already enabled in this crate) instead of the
/// policy crate's hand-rolled FFI struct. Every `None` fails closed
/// upstream.
fn file_link_count(p: &std::path::Path) -> Option<u32> {
    use std::os::windows::io::AsRawHandle;
    // Plain read open. A handle held with an exclusive share mode makes
    // THIS open fail — that unprovability is exactly what the caller's
    // Unverifiable verdict encodes, not a bypass.
    let f = std::fs::File::open(p).ok()?;
    // SAFETY: `BY_HANDLE_FILE_INFORMATION` is a plain-old-data winapi struct
    // (DWORD and FILETIME fields only), so a fully zeroed value is a valid
    // bit pattern; on failure the zeroed value is never read (we return
    // None).
    let mut info: winapi::um::fileapi::BY_HANDLE_FILE_INFORMATION =
        unsafe { std::mem::zeroed() };
    // SAFETY: `f.as_raw_handle()` is a live handle for the duration of the
    // call (owned by `f`, dropped only after this scope) and `info` is a
    // writable, correctly sized instance of the struct the API fills in.
    // (The cast bridges std's RawHandle and winapi's distinct c_void.)
    let ok = unsafe {
        winapi::um::fileapi::GetFileInformationByHandle(
            f.as_raw_handle() as *mut winapi::ctypes::c_void,
            &mut info,
        )
    };
    if ok == 0 {
        None
    } else {
        Some(info.nNumberOfLinks)
    }
}

/// Canonical NT-kernel-fold final DOS path of `p` via handle-based resolution
/// (std::fs::canonicalize opens the object and asks the kernel for its
/// final path, so junctions/symlinks in EVERY component are resolved).
/// Strips the `\\?\` verbatim prefix the way GetFinalPathNameByHandleW
/// prints it: `\\?\UNC\…` → `\\…`, else a leading `\\?\` is removed.
/// Err → None (callers fail closed). Same normalization as policy
/// decide/mod.rs's private helper of the same name (the S11 kernel fold,
/// not ASCII-only lowercase).
fn canonical_dos_lower(p: &std::path::Path) -> Option<String> {
    let canon = std::fs::canonicalize(p).ok()?;
    let mut s = canon.to_string_lossy().into_owned();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        s = format!(r"\\{rest}");
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        s = rest.to_owned();
    }
    Some(policy::path::nt_case_fold(&s).into_owned())
}

/// S05 (docs/review-xa-2026-09-20) backstop probe for a passthrough open,
/// run at the moment of the syscall — BEFORE the original
/// NtCreateFile/NtOpenFile is invoked. This is the enforcement twin of the
/// policy-side gap-1 fix (decide/mod.rs `path_aliases_outside_root`): the
/// policy consults the filesystem when DECIDING, but an alias planted (or
/// a decision arriving stale) between that consult and this open is
/// exactly the TOCTOU window this probe narrows.
///
/// Called ONLY for WRITE passthrough opens. Read authority stays global by
/// design: a read through an alias reveals nothing a direct read of the
/// target would not, so probing reads would only add cost, not security.
///
/// The finding's core demand is honored structurally: the refusal (or
/// re-authorization) happens BEFORE the open completes, because a
/// post-open check is too late for OVERWRITE/truncate dispositions — the
/// real object is already damaged when the handle exists.
///
/// Invariant enforced (self-contained — the hook process does not know
/// project_root; only the policy process does): a passthrough WRITE open
/// must traverse NO reparse point on ANY component and must not mutate a
/// multi-link file object under another name. An Aliased result is NOT
/// refused outright: the RESOLVED destination is handed back through the
/// same policy (see `passthrough_alias_decision`), so a junction between
/// two in-project directories — or a project root itself reached through a
/// pre-existing alias, the tolerance policy-side gap 1 codifies — can
/// still be Passthrough-authorized for writes. Hardlinks do not change the
/// resolved path (a hardlink name canonicalizes to itself), so a
/// multi-link file is its own case (`MultiLink`): the passthrough write is
/// refused — gap 1 policy would have CoW'd it, so a Passthrough decision
/// that reaches this arm is stale, and fail-closed Deny is the correct
/// backstop posture.
///
/// Cost: O(components) `symlink_metadata` queries per passthrough WRITE
/// open — cheap next to the uncached IPC `decide()` immediately preceding
/// it in the Passthrough arms (Passthrough decisions are deliberately
/// never cached — hooks/mod.rs Bug #75).
///
/// Honesty note: this walk cannot race-proof against a component swapped
/// AFTER the walk but BEFORE the kernel open. No userspace primitive on
/// Windows closes that window without OBJ_DONT_REPARSE, which std does not
/// expose; the decide→open window is narrowed to the walk itself, which is
/// the same accepted TOCTOU class as the policy-side gap-1 fix.
pub(crate) fn probe_passthrough(dos: &str) -> PassthroughProbe {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    let p = std::path::Path::new(dos);
    // `ancestors()` yields deep→shallow; reverse so the walk runs
    // shallow→deep (drive root … final component) and stops at the
    // SHALLOWEST reparse point — the component the kernel would start
    // traversing through.
    let mut comps: Vec<&std::path::Path> = p.ancestors().collect();
    comps.reverse();

    let mut final_md: Option<std::fs::Metadata> = None;
    for (i, comp) in comps.iter().enumerate() {
        // symlink_metadata does NOT follow the final component, so a
        // reparse point ON the component is seen as itself, not resolved.
        match std::fs::symlink_metadata(comp) {
            Ok(md) => {
                if md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return aliased_from(&comps, i);
                }
                final_md = Some(md);
            }
            // Everything deeper is also missing; the kernel create resolves
            // through the prefix we just proved reparse-free. This is the
            // create-new fast path.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return PassthroughProbe::Clean;
            }
            // Not provable → fail closed.
            Err(_) => return PassthroughProbe::Unverifiable,
        }
    }

    // Loop completed: every component exists and none is a reparse point.
    // Final-component file-object accounting (mirror of policy-side gap 1):
    // directories are exempt (NTFS cannot hardlink dirs, and a dir's link
    // count legitimately exceeds 1 via its children's `..` entries); a FILE
    // must be single-link, else one underlying object answers to names we
    // cannot see; an undeterminable link count fails closed.
    let md = final_md.expect("ancestors() is never empty, so the loop assigned at least once");
    if md.is_dir() {
        return PassthroughProbe::Clean;
    }
    match file_link_count(p) {
        Some(1) => PassthroughProbe::Clean,
        Some(_) => PassthroughProbe::MultiLink,
        None => PassthroughProbe::Unverifiable,
    }
}

/// Resolve the FIRST reparse-bearing component (index `i` in the
/// shallow→deep `comps` walk) THROUGH its reparse point by handle, and
/// re-append the not-yet-verified deeper components (which may not exist) —
/// the path the kernel would actually touch beyond the alias. An
/// unresolvable alias cannot be proven benign → `Unverifiable`.
fn aliased_from(comps: &[&std::path::Path], i: usize) -> PassthroughProbe {
    let Some(anchor) = canonical_dos_lower(comps[i]) else {
        return PassthroughProbe::Unverifiable;
    };
    // `comps` are cumulative ancestors (each entry is a full path prefix, not
    // a bare component name), and `comps[comps.len() - 1]` is the original
    // full path. The not-yet-verified tail beyond the alias is the relative
    // remainder of that full path past `comps[i]` — appending each
    // subsequent `comps` entry's full string (as opposed to just its own
    // trailing component) would re-nest the whole original path onto the
    // anchor once per remaining component.
    let full = comps[comps.len() - 1];
    let mut resolved = anchor;
    if let Ok(tail) = full.strip_prefix(comps[i]) {
        for part in tail.components() {
            resolved.push('\\');
            resolved.push_str(&part.as_os_str().to_string_lossy());
        }
    }
    PassthroughProbe::Aliased { resolved }
}

/// Whether an alias-detected passthrough write may proceed given the policy
/// verdict on the RESOLVED destination. Only a fresh Passthrough for the
/// resolved path authorizes the traversal (in-project junctions, a project
/// root itself behind a pre-existing alias — the tolerance policy-side gap 1
/// codifies). Cow/Deny/Mock/Hidden for the resolved destination mean the
/// write would land somewhere policy does not passthrough-authorize → refuse.
pub(crate) fn aliased_resolution_permits(resolved_mode: Mode) -> bool {
    matches!(resolved_mode, Mode::Passthrough)
}

/// S05 (docs/review-xa-2026-09-20): pre-open verdict for a passthrough
/// open. `None` = the open may proceed (a read open, a Clean probe, or an
/// Aliased probe whose RESOLVED destination the policy itself
/// re-authorizes for writes). `Some(Deny)` = the hook must fail closed
/// (MultiLink / Unverifiable, or an Aliased resolution policy does not
/// passthrough-authorize).
///
/// UNIT-TEST HAZARD: the Aliased arm calls decide(), which is the IPC
/// client. The unit-test process has no pipe server, and the hook's IPC
/// client TERMINATES THE TEST PROCESS once consecutive decide failures
/// cross the fail-stop threshold. Tests must never call this function;
/// they cover probe_passthrough and aliased_resolution_permits, and the
/// wiring into the hook bodies is pinned textually (see fs_hooks/tests.rs).
pub(crate) fn passthrough_alias_decision(dos: &str, write: bool) -> Option<Decision> {
    if !write {
        return None;
    }
    match probe_passthrough(dos) {
        PassthroughProbe::Clean => None,
        PassthroughProbe::Aliased { resolved } => {
            if aliased_resolution_permits(decide(&resolved, true).mode) {
                None
            } else {
                Some(deny_decision())
            }
        }
        PassthroughProbe::MultiLink | PassthroughProbe::Unverifiable => Some(deny_decision()),
    }
}

/// The synthetic fail-closed Decision for probe verdicts. Kept next to the
/// probe so a Deny cannot drift into carrying overlay/payload semantics (a
/// Deny with an overlay path would be a contradiction).
fn deny_decision() -> Decision {
    Decision { mode: Mode::Deny, overlay: None, cow_from: None, mock_payload: None }
}
