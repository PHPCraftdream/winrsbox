// Path resolution: OBJECT_ATTRIBUTES -> DOS/NT paths (device-drive mapping, dot-folding, overlay unmirror).

use super::*;

// ---------------------------------------------------------------------------
// Device-namespace -> DOS drive mapping
//
// `NtQueryObject(ObjectNameInformation)` on a directory handle returns the
// canonical kernel-namespace name — typically `\Device\HarddiskVolumeN\rest`.
// `policy::path::nt_to_dos_lower` only accepts paths in the DOS-device form
// (`\??\C:\rest`, `\\?\C:\rest`), so a RootDirectory-relative open whose base
// is a device path falls through to silent passthrough — that is the
// escape cmd.exe's `>filename` redirection uses.
//
// Build the inverse of QueryDosDeviceW once (drive A..Z -> device path),
// then prefix-match each resolved base against it to rewrite the device
// prefix back into `\??\<letter>:`. Non-volume devices (`\Device\ConDrv\…`,
// `\Device\Afd\…`, …) don't appear in the map and fall through unchanged.
// ---------------------------------------------------------------------------

pub(super) fn ascii_to_lower_u16(c: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&c) { c + 32 } else { c }
}

pub(super) fn device_drive_map() -> &'static Vec<(Vec<u16>, u16)> {
    static MAP: OnceLock<Vec<(Vec<u16>, u16)>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut v: Vec<(Vec<u16>, u16)> = Vec::with_capacity(26);
        let mut buf = [0u16; 1024];
        for letter in b'A'..=b'Z' {
            let drive: [u16; 3] = [letter as u16, b':' as u16, 0];
            // SAFETY: drive is null-terminated UTF-16, buf is valid for buf.len() u16s.
            let len = unsafe {
                winapi::um::fileapi::QueryDosDeviceW(
                    drive.as_ptr(), buf.as_mut_ptr(), buf.len() as u32,
                )
            };
            if len == 0 {
                continue;
            }
            let len = len as usize;
            let end = buf[..len].iter().position(|&c| c == 0).unwrap_or(len);
            if end == 0 {
                continue;
            }
            let device_lower: Vec<u16> = buf[..end].iter().copied().map(ascii_to_lower_u16).collect();
            v.push((device_lower, ascii_to_lower_u16(letter as u16)));
        }
        v
    })
}

/// If `path` (UTF-16) begins with a known `\Device\<volume>` prefix, return a
/// freshly-built `\??\<letter>:<rest>` vector. Returns `None` when no mapping
/// applies (non-volume devices, paths already in DOS form, etc.).
pub(crate) fn device_path_to_dos_nt(path: &[u16]) -> Option<Vec<u16>> {
    let path_lower: Vec<u16> = path.iter().copied().map(ascii_to_lower_u16).collect();
    let map = device_drive_map();
    for (device, letter) in map.iter() {
        if !path_lower.starts_with(device) {
            continue;
        }
        // The prefix must align on a path component boundary, otherwise
        // `\Device\HarddiskVolume3` would spuriously match a real path like
        // `\Device\HarddiskVolume30\…` belonging to a different drive.
        let tail = &path[device.len()..];
        match tail.first().copied() {
            None => {} // bare base, no tail
            Some(c) if c == b'\\' as u16 => {} // proper boundary
            _ => continue,
        }
        let mut out: Vec<u16> = Vec::with_capacity(4 + 2 + tail.len());
        out.extend_from_slice(&[b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16]);
        out.push(*letter);
        out.push(b':' as u16);
        out.extend_from_slice(tail);
        return Some(out);
    }
    None
}

// ---------------------------------------------------------------------------
// NT path buffer builder
//
// Returns a Vec<u16> for `\??\<overlay_dos_path>\0`.
// The Vec MUST outlive any UNICODE_STRING / OBJECT_ATTRIBUTES that borrows
// its data pointer.
// ---------------------------------------------------------------------------
pub(crate) fn make_overlay_nt_buf(overlay_dos: &str) -> Vec<u16> {
    policy::path::dos_to_nt(overlay_dos)
}

// ---------------------------------------------------------------------------
// Path extraction
// ---------------------------------------------------------------------------

/// Extract a DOS path string from an OBJECT_ATTRIBUTES.
///
/// # SAFETY
/// `attrs` and its ObjectName must be valid for reads for the duration of the
/// call (guaranteed by NT calling convention for hook parameters).
/// Resolve OBJECT_ATTRIBUTES for an FS hook in ONE pass, reading any
/// `RootDirectory` directory handle **exactly once**. Returns:
///   - the DOS path (lowercased) used for the policy decision, AND
///   - `Some(absolute_nt_path)` — the single resolution, owned by us, to be
///     reused verbatim for the kernel passthrough
///     (`HookedAttrs::copy_passthrough_inner`). Returned for BOTH the
///     RootDirectory-RELATIVE case (H5) and the ABSOLUTE-path case (S04):
///     policy decides on the DOS view, the kernel passthrough opens the
///     snapshot verbatim. For relative opens this closes the H5
///     double-resolve window: a concurrent `NtClose`+reopen of the directory
///     handle between the decision and the kernel call can no longer make the
///     path policy approved differ from the path the kernel opens. (The
///     bare-relative-CWD branch below already returned this snapshot.)
///
/// Returns `None` overall when no DOS path can be derived (caller then passes
/// through / device-blocks). This is the single path-resolution entry point for
/// the FS hooks; `extract_raw_nt_path` (pre-canonicalization, no handle join)
/// remains separate for `check_path_traversal`.
pub(crate) unsafe fn resolve_for_hook(
    attrs: *const OBJECT_ATTRIBUTES,
) -> Option<(String, Option<Vec<u16>>)> {
    if attrs.is_null() {
        return None;
    }
    let obj = &*attrs;
    // An absent or empty ObjectName is not automatically unresolvable: paired
    // with a RootDirectory it names the directory that handle already points
    // at. That is the shape Rust's `remove_dir_all` uses — it reopens the
    // directory relative to its parent with FILE_DELETE_ON_CLOSE and an empty
    // name — so treating it as unresolvable sent every such delete into the
    // fail-closed dead end and returned ACCESS_DENIED. Observed as
    // `WARNING: failed to clean up stale arg0 temp dirs: Access is denied`
    // from a sandboxed codex, with `fs_block_unresolved_write` in the trace.
    let name_slice: &[u16] = if obj.ObjectName.is_null() {
        &[]
    } else {
        let ustr = &*obj.ObjectName;
        let char_count = (ustr.Length / 2) as usize;
        if char_count == 0 {
            &[]
        } else if ustr.Buffer.is_null() {
            // P2-01: `Length > 0` with a NULL Buffer is trivially constructible
            // by the (untrusted) caller of NtCreateFile/NtOpenFile.
            // `from_raw_parts` with a null pointer and a non-zero length is UB;
            // bare NT would return STATUS_INVALID_PARAMETER. Fail closed: no
            // DOS path can be derived, the caller passes through /
            // device-blocks as for any other unresolvable path.
            return None;
        } else {
            // SAFETY: Buffer is non-null (checked above) and valid for at least
            // Length bytes per the NT UNICODE_STRING contract.
            std::slice::from_raw_parts(ustr.Buffer, char_count)
        }
    };
    // With no name AND no directory handle there is nothing to resolve.
    if name_slice.is_empty() && obj.RootDirectory.is_null() {
        return None;
    }

    if !obj.RootDirectory.is_null() {
        // Resolve the directory handle ONCE; the resulting absolute NT path is
        // reused for both the policy decision and the kernel passthrough.
        let base = match inject::resolve_handle_path(obj.RootDirectory) {
            Some(b) => b,
            None => return None,
        };
        // Map `\Device\HarddiskVolumeN\…` -> `\??\C:\…`. NtQueryObject on a
        // directory handle returns the canonical device-namespace name;
        // policy::path::nt_to_dos_lower only understands the DOS-device form.
        // Without this conversion, cmd.exe's `>filename` redirection (which
        // opens the file with RootDirectory = handle to CWD and ObjectName =
        // bare basename) silently falls through to call_original and writes
        // land on the real filesystem instead of the overlay.
        let base_device = base.clone();
        let base = device_path_to_dos_nt(&base).unwrap_or(base);
        let mut full: Vec<u16> = base;
        // Empty name → the target IS the handle's own directory; appending a
        // separator would produce a trailing-backslash path that resolves
        // differently.
        if !name_slice.is_empty() {
            full.push(b'\\' as u16);
            full.extend_from_slice(name_slice);
        }
        // Fold `.`/`..` lexically BEFORE the policy decision AND before the
        // kernel passthrough (audit Critical #1): `full` is handed to
        // copy_passthrough_inner verbatim (pre_resolved), so folding here
        // keeps the decided path and the kernel-acted-on path byte-identical
        // for relative opens. A relative `..\..\payload.exe` used to decide
        // on the unfolded string (which prefix-matched project_root) while
        // the kernel resolved the `..` segments outside the sandbox.
        let full = policy::path::fold_nt_dots(&full);
        let physical_dos = policy::path::nt_to_dos_lower(&full)?;
        // Relative-open whose directory handle was itself a CoW'd overlay file:
        // see `unmirror_overlay_handle_relative` for the rationale. Returns the
        // original `dos` unchanged when the handle does not resolve into the
        // overlay storage (the common non-sandbox case, zero overhead).
        let sb_root = SANDBOX_ROOT.get().map(|s| s.as_str());
        let virtual_dos = unmirror_overlay_handle_relative(&physical_dos, sb_root);
        let kernel_nt = virtual_dos
            .as_deref()
            .and_then(|virtual_path| read_through_missing_overlay(&physical_dos, virtual_path))
            .unwrap_or_else(|| full.into_owned());
        let dos = virtual_dos.unwrap_or(physical_dos);
        // OBJ_DONT_REPARSE would reject the DOS drive-name symlink (`\??\D:`).
        let kernel_path = if obj.Attributes & 0x1000 != 0 {
            super::device::device_nt_for_folded_dos(&base_device, &kernel_nt)
                .unwrap_or(kernel_nt)
        } else {
            kernel_nt
        };
        return Some((dos, Some(kernel_path)));
    }

    // Fast path: ObjectName already in absolute NT form (`\??\C:\…`).
    // Fold `.`/`..` lexically before deriving the DOS path so the policy
    // decides on the path the kernel will resolve (audit Critical #1:
    // `\??\d:\<root>\..\..\payload.exe` used to prefix-match the
    // root while the kernel created the file outside the sandbox).
    // Review S04 (docs/review-xa-2026-09-20): the kernel passthrough
    // consumes the snapshot too. The decision (via `dos`) and the kernel
    // open (via the returned snapshot) read the guest ObjectName buffer
    // exactly once, here; a concurrent swap of the buffer bytes or the
    // ObjectName pointer between classification and syscall cannot
    // retarget the open.
    // Self-overlay unmirror carve-out PRESERVED: `dos` (policy) may be the
    // VIRTUAL overlay path while the returned snapshot stays the PHYSICAL
    // overlay path the caller named — the virtual/physical distinction now
    // lives between the two return values instead of in a second read of
    // guest memory. Without reparse points the folded path resolves to
    // exactly the target the original buffer named (the kernel folds
    // `.`/`..` itself).
    let folded = policy::path::fold_nt_dots(name_slice);
    if let Some(dos) = policy::path::nt_to_dos_lower(&folded) {
        // Self-block guard (class #64 for ABSOLUTE paths, symmetric with the
        // relative-open case at line 321). A sandboxed process that learned
        // its own overlay path via a passthrough query channel (class-9
        // FileNameInformation or NtQueryObject — neither masked, by design)
        // will re-open it ABSOLUTELY. Without this unmirror, the absolute
        // overlay path (e.g. `c:\users\…\.winrsbox\<session>\workdir\…
        // \clone\.git`) hits `canonical_denylist_status`'s `\.winrsbox\`
        // rule and returns NAME_NOT_FOUND — a self-DoS that breaks the
        // sandboxed process's own CoW files. Unmirror the overlay path back
        // to its virtual form for the POLICY decision; the kernel-open path
        // (`pre_resolved`) stays on the absolute overlay path so the
        // real file under the overlay is opened. Control files (policy.redb,
        // session-config inside .winrsbox but NOT under workdir\) remain
        // denied — unmirror only succeeds for paths under a known overlay
        // workdir root.
        let sb_root = SANDBOX_ROOT.get().map(|s| s.as_str());
        let dos = unmirror_overlay_handle_relative(&dos, sb_root).unwrap_or(dos);
        return Some((dos, Some(folded.into_owned())));
    }

    // Bare relative path (no NT prefix, no RootDirectory). cmd.exe's
    // `>filename` redirection takes exactly this shape: ObjectName.Buffer
    // literally contains `qwe.txt`, RootDirectory is NULL, and the kernel
    // resolves the open against ProcessParameters.CurrentDirectory. Mirror
    // that here so the policy decision sees the SAME absolute path the
    // kernel will open — otherwise every cmd-redirected write escapes Cow
    // because the hook falls through to call_original on resolve failure.
    //
    // Skip NT object names (anything starting with `\`): `\Device\Afd\…`,
    // `\??\Unresolved`, UNC `\\srv\share`, etc. — those are not relative
    // file paths and the caller's existing passthrough path handles them.
    if name_slice.is_empty() || name_slice[0] == b'\\' as u16 {
        return None;
    }

    let mut cwd_buf = [0u16; 1024];
    let cwd_len = winapi::um::processenv::GetCurrentDirectoryW(
        cwd_buf.len() as u32,
        cwd_buf.as_mut_ptr(),
    ) as usize;
    if cwd_len == 0 || cwd_len >= cwd_buf.len() {
        return None;
    }
    let cwd = &cwd_buf[..cwd_len];

    let abs = join_bare_relative_to_nt(cwd, name_slice);
    // Fold `.`/`..` lexically: `abs` is also the kernel passthrough path
    // (pre_resolved = Some), so decision and kernel action stay identical.
    let abs = policy::path::fold_nt_dots(&abs);
    let sb_root = SANDBOX_ROOT.get().map(|s| s.as_str());
    let dos = bare_relative_dos(&abs, sb_root)?;
    Some((dos, Some(abs.into_owned())))
}

fn read_through_missing_overlay(physical: &str, virtual_path: &str) -> Option<Vec<u16>> {
    let missing = std::fs::symlink_metadata(physical)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
    if !missing {
        return None;
    }
    let mut nt = policy::path::dos_to_nt(virtual_path);
    nt.pop(); // UNICODE_STRING.Length excludes the terminator.
    Some(nt)
}

#[cfg(test)]
mod read_through_tests {
    use super::*;

    #[test]
    fn missing_overlay_leaf_reads_host_but_existing_leaf_stays_overlayed() {
        let dir = tempfile::tempdir().unwrap();
        let physical = dir.path().join("overlay").join("config.json");
        let host = dir.path().join("host").join("config.json");
        std::fs::create_dir_all(physical.parent().unwrap()).unwrap();
        std::fs::create_dir_all(host.parent().unwrap()).unwrap();
        std::fs::write(&host, b"host").unwrap();
        let snapshot = read_through_missing_overlay(&physical.to_string_lossy(), &host.to_string_lossy())
            .expect("missing overlay leaf must read through");
        assert_eq!(String::from_utf16_lossy(&snapshot), format!(r"\??\{}", host.display()));
        std::fs::write(&physical, b"overlay").unwrap();
        assert!(read_through_missing_overlay(&physical.to_string_lossy(), &host.to_string_lossy()).is_none());
    }
}

/// Lowercase-DOS form of a folded absolute NT path for the bare-relative
/// CWD branch, WITH the overlay-storage unmirror its two sibling branches
/// (RootDirectory-relative and absolute-path) already apply.
///
/// When the process CWD lives inside the overlay storage (the guest cd'd
/// into an external directory whose CoW copy was materialized there),
/// `nt_to_dos_lower` yields the REAL overlay path, and the `.winrsbox`
/// segment of the denylist would self-block every bare-relative open in
/// that directory — `cmd.exe`'s `>file` redirection resolves against the
/// kernel CWD with no RootDirectory handle, so exactly this branch handles
/// it (audit 2026-09-19 Low: bare-relative CWD branch lacks unmirror).
/// The POLICY decision must see the virtual path; the kernel passthrough
/// keeps the real overlay path (`pre_resolved`), so the file actually
/// touched is unchanged.
/// Pure over its inputs so the unmirror discipline is unit-testable
/// without touching the process-global `SANDBOX_ROOT`.
pub(crate) fn bare_relative_dos(abs_nt: &[u16], sb_root: Option<&str>) -> Option<String> {
    let dos = policy::path::nt_to_dos_lower(abs_nt)?;
    Some(unmirror_overlay_handle_relative(&dos, sb_root).unwrap_or(dos))
}

/// Build the absolute NT-form path `\??\<cwd>\<relative>` for a bare-relative
/// `name` given the process's current working directory `cwd`. Pure over its
/// inputs so the join discipline can be unit-tested without a real
/// `GetCurrentDirectoryW`.
///
/// Inputs are UTF-16 slices (the form the kernel ABI hands us):
///   - `cwd`     must be the lowercased absolute DOS path of the process CWD
///               (e.g. `c:\users\alice\desktop`). NUL terminator NOT included.
///   - `name`    is the bare relative ObjectName from `OBJECT_ATTRIBUTES`
///               (e.g. `qwe.txt`). NUL terminator NOT included.
///
/// Returns a freshly-built UTF-16 vector `\??\<cwd>[\]<name>` (no NUL).
/// A trailing path separator on `cwd` is honoured (no double `\\`);
/// otherwise one is inserted.
pub(crate) fn join_bare_relative_to_nt(cwd: &[u16], name: &[u16]) -> Vec<u16> {
    let need_sep = !cwd.is_empty() && cwd[cwd.len() - 1] != b'\\' as u16;
    let mut out: Vec<u16> = Vec::with_capacity(4 + cwd.len() + 1 + name.len());
    out.extend_from_slice(&[b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16]);
    out.extend_from_slice(cwd);
    if need_sep {
        out.push(b'\\' as u16);
    }
    out.extend_from_slice(name);
    out
}

/// Translate a policy path that resolved INTO the sandbox overlay storage back
/// to the virtual DOS path the sandboxed process believes it owns.
///
/// When a relative-open's `RootDirectory` handle points to a CoW'd overlay file
/// (e.g. `.git` opened by git.exe → CoW'd into `<sandbox_root>\d\…\.git`),
/// `inject::resolve_handle_path` returns the REAL kernel-namespace path of that
/// handle, which lives under `SANDBOX_ROOT`. Glueing the relative `ObjectName`
/// onto it yields an overlay path like
/// `d:\…\.winrsbox\<name>\workdir\d\…\.git\config`. Feeding that to
/// `decide`/`canonical_denylist` verbatim would trip our own sandbox-internals
/// denylist (the `.winrsbox` segment → `STATUS_OBJECT_NAME_NOT_FOUND`) and
/// silently break legitimate relative opens against the process's OWN CoW
/// copies. That self-block is what makes `git add`/`git commit` fail with
/// "unknown error reading configuration files".
///
/// Such a handle-relative open is a legitimate self-access, NOT an attempt by
/// the agent to poke sandbox internals by virtual path. This fn translates the
/// overlay path back to the virtual DOS path; subsequent `decide` re-mirrors it
/// into the overlay (Cow). A missing overlay leaf reads through to the virtual
/// host path; an existing overlay leaf keeps the physical snapshot. The denylist
/// then sees the VIRTUAL path, so a genuine `D:\…\.winrsbox` attack by virtual
/// path stays blocked.
///
/// Returns `None` (no rewrite) when `SANDBOX_ROOT` is unset, when the path is
/// not under it, or when `unmirror_from_overlay` cannot recover a virtual path.
/// Pure over its inputs — callers pass `Some(sb_root)` from `SANDBOX_ROOT.get()`
/// in production and a literal string in tests (avoids contending with the
/// process-global `OnceLock`).
pub(crate) fn unmirror_overlay_handle_relative(
    overlay_dos: &str,
    sandbox_root: Option<&str>,
) -> Option<String> {
    // Candidate overlay-roots: all per-drive same-volume roots if published,
    // else the legacy single sandbox_root. A relative-open handle may point
    // into ANY of them (e.g. a C:-root overlay for a C: virtual path), so try
    // each until one prefix-matches and unmirrors cleanly.
    let roots: Vec<&str> = match crate::ipc_client::OVERLAY_ROOTS.get() {
        Some(list) if !list.is_empty() => list.iter().map(|s| s.as_str()).collect(),
        _ => sandbox_root.into_iter().collect(),
    };
    for sb in roots {
        // S11: canonical NTFS-identity fold (overlay roots are matched against
        // kernel-folded paths), not Unicode to_lowercase.
        let sb_lower = policy::path::nt_case_fold(sb);
        let sb_trimmed = sb_lower.trim_end_matches('\\');
        if sb_trimmed.is_empty() {
            continue;
        }
        if !policy::path::pattern_matches_prefix(sb_trimmed, overlay_dos) {
            continue;
        }
        let overlay_pbuf = std::path::PathBuf::from(overlay_dos);
        // Try BOTH layouts: the Path-1 same-volume layout (no <drive>\
        // component — the drive is implicit in the chosen root) AND the legacy
        // layout (<root>\<drive>\<rest>). The same-volume layout is the
        // primary; the legacy fallback covers old overlay paths that still
        // carry the drive component.
        // Try BOTH layouts: the Path-1 same-volume layout (no <drive>\
        // component — the drive is implicit in the chosen root) AND the legacy
        // layout (<root>\<drive>\<rest>). The same-volume layout is the
        // primary; the legacy fallback covers old overlay paths that still
        // carry the drive component.
        //
        // Discriminator: in the legacy layout, the first component after root
        // IS the drive letter, and it MATCHES the root's own drive (legacy
        // mirrors D: paths into a D: root). In Path 1, the first component is
        // a directory name that only coincidentally might be a single letter —
        // but it will NOT match the root's drive (e.g. `C:\a\file` → overlay
        // `<C-root>\a\file`, first comp `a` ≠ root drive `c`). This makes
        // "first comp == root drive" a reliable discriminator that avoids the
        // false-positive on single-letter top-level directories like `C:\a`.
        if let Ok(rest) = overlay_pbuf.strip_prefix(sb_trimmed) {
            let root_drive = sb_trimmed.chars().next().filter(|c| c.is_ascii_alphabetic());
            let mut comps = rest.components();
            let first = comps.next();
            // Legacy layout: first comp is a single ASCII letter matching root's drive.
            let (drive, remaining) = match first {
                Some(std::path::Component::Normal(s))
                    if s.len() == 1
                        && s.to_str()
                            .map(|c| {
                                let ch = c.chars().next().unwrap_or('\0');
                                ch.is_ascii_alphabetic()
                                    && ch.to_ascii_lowercase() == root_drive.unwrap_or('\0').to_ascii_lowercase()
                            })
                            .unwrap_or(false) =>
                {
                    // Old layout: <root>\<drive>\<rest> — drive from first comp.
                    (s.to_str().unwrap().chars().next(), comps)
                }
                _ => {
                    // Path 1 layout: <root>\<rest> — drive from root, all comps are dirs.
                    (root_drive, rest.components())
                }
            };
            if let Some(d) = drive {
                let mut virtual_dos = format!("{}:", d.to_ascii_lowercase());
                for c in remaining {
                    match c {
                        std::path::Component::Normal(s) => {
                            virtual_dos.push('\\');
                            virtual_dos.push_str(s.to_str()?);
                        }
                        _ => {}
                    }
                }
                return Some(virtual_dos);
            }
        }
        // Legacy layout fallback (for roots not in OVERLAY_ROOTS — e.g. during
        // very early init before session section is loaded).
        if let Some(virtual_dos) = policy::path::unmirror_from_overlay(
            &overlay_pbuf,
            std::path::Path::new(sb_trimmed),
        ) {
            return Some(policy::path::nt_case_fold(&virtual_dos).into_owned());
        }
    }
    None
}

pub(crate) unsafe fn extract_raw_nt_path(attrs: *const OBJECT_ATTRIBUTES) -> Option<String> {
    if attrs.is_null() { return None; }
    let obj = &*attrs;
    if obj.ObjectName.is_null() { return None; }
    let ustr = &*obj.ObjectName;
    let char_count = (ustr.Length / 2) as usize;
    if char_count == 0 { return None; }
    if ustr.Buffer.is_null() {
        // P2-01: NULL Buffer with non-zero Length is caller-constructible UB
        // in from_raw_parts; fail closed (mirrors alpc_guard::classify_port_name).
        return None;
    }
    // SAFETY: Buffer is non-null (checked above) and valid for at least
    // Length bytes per the NT UNICODE_STRING contract.
    let name_slice = std::slice::from_raw_parts(ustr.Buffer, char_count);
    Some(String::from_utf16_lossy(name_slice))
}

/// Extract the basename (last path component) from an NT OBJECT_ATTRIBUTES
/// path, preserving original case from the UNICODE_STRING buffer.
///
/// Used by variant B hybrid case-rewrite: `nt_to_dos_lower` (called by
/// `resolve_for_hook`) lowercases the entire path, so by the time we have
/// `dos`, the original case information is gone. This function reads the
/// UNICODE_STRING buffer BEFORE lowercasing and returns only the last
/// component so the original-case basename can be stored in OVERLAY_CASE.
///
/// Returns `None` when:
///  - `attrs` is null or has no ObjectName
///  - The path is empty or ends with a separator (directory-open trailing `\`)
///  - The basename is already in its canonical (kernel-folded) form — no case
///    to preserve (S11: fold-relative, so non-ASCII case pairs like `Секрет`
///    are returned too)
///
/// # SAFETY
/// `attrs` must be valid for reads for the duration of this call (same
/// lifetime guarantee as `extract_raw_nt_path` and `resolve_for_hook`).
pub(crate) unsafe fn extract_nt_basename(attrs: *const OBJECT_ATTRIBUTES) -> Option<String> {
    let raw = extract_raw_nt_path(attrs)?;
    // Strip optional trailing separator (directory opens end with `\`).
    let trimmed = raw.trim_end_matches(|c| c == '\\' || c == '/');
    let basename = trimmed.rsplit(|c| c == '\\' || c == '/').next()?;
    if basename.is_empty() { return None; }
    // Only return when the kernel fold would CHANGE the basename — if it is
    // already in canonical folded form, ipc_record_overlay_case would skip it
    // anyway (its own fold-relative guard), so avoid the IPC round-trip
    // entirely. S11: fold-relative instead of ASCII-only, so non-ASCII case
    // pairs (Секрет) keep their case records.
    if policy::path::nt_case_fold(basename) != basename {
        Some(basename.to_owned())
    } else {
        None
    }
}
