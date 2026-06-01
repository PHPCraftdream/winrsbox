// Detour implementations for Nt* functions.
//
// Uses detour::GenericDetour (stable, no nightly) stored in OnceLock.
//
// Mode::Cow semantic (unified, no Redirect variant):
//   cow_from = None  → pure redirect (overlay already exists or read path)
//   cow_from = Some  → real CoW (copy original file before redirecting)
//
// This file is the "shared infra + orchestration" module.
// IPC client plumbing lives in ipc_client.rs.
// FS hook implementations live in fs_hooks.rs.

use std::borrow::Cow;
use std::sync::OnceLock;
// Use winapi's c_void to match signatures expected by winapi/ntapi functions.
use winapi::ctypes::c_void;

use detour2::GenericDetour;
use ntapi::ntioapi::IO_STATUS_BLOCK;
use ntapi::winapi::shared::ntdef::{
    HANDLE, NTSTATUS, OBJECT_ATTRIBUTES, UNICODE_STRING,
};
use ntapi::winapi::um::winnt::ACCESS_MASK;
use policy::Decision;
use winapi::um::processthreadsapi::{GetCurrentProcessId, GetProcessId};

use crate::anti_rec;
use crate::inject;

// ---------------------------------------------------------------------------
// Re-exports from ipc_client — keep existing call sites working.
// (crate::hooks::ipc_log, is_trace, ipc_log_violation, ipc_send_and_recv,
//  ntdll_export, flush_install_errors, SANDBOX_CWD, etc.)
// ---------------------------------------------------------------------------
pub(crate) use crate::ipc_client::{
    buffer_install_error,
    cache,
    ipc_decide,
    ipc_log,
    ipc_log_violation,
    ipc_record_overlay,
    ipc_register_child,
    ipc_send_and_recv,
    ipc_spawned_child,
    is_trace,
    DLL_PATH,
    PIPE_NAME,
    SANDBOX_CWD,
    TRACE_ENABLED,
};

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

fn ascii_to_lower_u16(c: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&c) { c + 32 } else { c }
}

fn device_drive_map() -> &'static Vec<(Vec<u16>, u16)> {
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
// NtCreateUserProcess type alias + OnceLock (stays here; install_hooks uses it)
// ---------------------------------------------------------------------------

type FnNtCreateUserProcess = unsafe extern "system" fn(
    *mut HANDLE,            // ProcessHandle
    *mut HANDLE,            // ThreadHandle
    ACCESS_MASK,            // ProcessDesiredAccess
    ACCESS_MASK,            // ThreadDesiredAccess
    *mut OBJECT_ATTRIBUTES, // ProcessObjectAttributes
    *mut OBJECT_ATTRIBUTES, // ThreadObjectAttributes
    u32,                    // ProcessFlags
    u32,                    // ThreadFlags
    *mut c_void,            // ProcessParameters
    *mut c_void,            // CreateInfo
    *mut c_void,            // AttributeList
) -> NTSTATUS;

static HOOK_NT_CREATE_USER_PROCESS: OnceLock<GenericDetour<FnNtCreateUserProcess>> =
    OnceLock::new();

// FnNtQueryDirectoryFile, FnNtSetInformationFile, FnNtFsControlFile
// moved to dir_filter.rs and fs_metadata_guard.rs respectively.

// ---------------------------------------------------------------------------
// Write-access detection
// ---------------------------------------------------------------------------

pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const DELETE: u32 = 0x0001_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;

pub const FILE_CREATE: u32 = 0x0000_0002;
pub const FILE_OPEN_IF: u32 = 0x0000_0003;
pub const FILE_OVERWRITE: u32 = 0x0000_0004;
pub const FILE_OVERWRITE_IF: u32 = 0x0000_0005;
pub const FILE_SUPERSEDE: u32 = 0x0000_0000;

pub fn is_write_access(desired: ACCESS_MASK, disposition: u32) -> bool {
    let write_bits =
        GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER;
    desired & write_bits != 0
        || matches!(disposition, FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE | FILE_OVERWRITE_IF | FILE_SUPERSEDE)
}

// ---------------------------------------------------------------------------
// STATUS codes
// ---------------------------------------------------------------------------

pub(crate) const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000_0022_u32 as NTSTATUS;
pub(crate) const STATUS_OBJECT_NAME_NOT_FOUND: NTSTATUS = 0xC000_0034_u32 as NTSTATUS;
pub(crate) const STATUS_PRIVILEGE_NOT_HELD: NTSTATUS = 0xC000_0061_u32 as NTSTATUS;
/// Returned by the KTM (transacted-registry) hook handlers — these syscalls
/// give callers a CLR/RegOpenKeyTransacted-style escape vector around the
/// regular registry write hooks. We refuse the transaction outright rather
/// than try to overlay it.
pub(crate) const STATUS_NOT_SUPPORTED: NTSTATUS = 0xC000_00BB_u32 as NTSTATUS;

// ---------------------------------------------------------------------------
// decide() — consults cache then IPC
// ---------------------------------------------------------------------------

pub(crate) fn decide(dos_path: &str, write: bool) -> Decision {
    // dos_path is already lowercase from nt_to_dos_lower in extract_dos_path
    //
    // M5 (non-issue): the cache key is intentionally just (dos_path, write) —
    // process depth and exe are NOT part of the key, and that is correct here.
    // This HookCache is a per-process `static OnceLock<HookCache>` (one instance
    // per loaded hook.dll). Depth is a property of the *process*, assigned once
    // by the launcher (root = 0; child = parent_depth + 1 on SpawnedChild) and
    // never mutated for a live PID. Every Req::Decide this process sends resolves
    // server-side to this one constant depth (the launcher keys depth/exe off the
    // connection's Hello pid). So within a single process the depth context is
    // invariant, every cached entry is consistent with it, and the cross-process
    // "depth-0 caches Passthrough, depth-3 reads it" poisoning is impossible:
    // those are different processes with separate in-heap caches.
    if let Some(d) = cache().get_caseless(dos_path, write) {
        return d;
    }
    let d = ipc_decide(dos_path, write);
    cache().insert(dos_path, write, d.clone());
    d
}

// ---------------------------------------------------------------------------
// IO_STATUS_BLOCK helper
// ---------------------------------------------------------------------------

/// Write the Status field (at offset 0) of an IO_STATUS_BLOCK.
///
/// # SAFETY
/// IO_STATUS_BLOCK.Status/Pointer union begins at offset 0 on all Windows
/// x64 ABIs. The union is `{ Status: i32 | Pointer: *mut c_void }` (8 bytes
/// on x64). We zero the full 8-byte slot first, then write the 4-byte
/// NTSTATUS, so callers reading the Pointer member see a clean value.
/// The Information field (next 8 bytes) is intentionally NOT touched.
pub(crate) unsafe fn set_io_status(block: *mut IO_STATUS_BLOCK, status: NTSTATUS) {
    if !block.is_null() {
        // Zero the full 8-byte union slot, then write the 4-byte status.
        let slot = block as *mut usize;
        *slot = 0;
        *(block as *mut NTSTATUS) = status;
    }
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
///   - `Some(absolute_nt_path)` when the open was RootDirectory-RELATIVE — the
///     single resolution, owned by us, to be reused verbatim for the kernel
///     passthrough (`HookedAttrs::copy_passthrough_inner`). Reusing it instead
///     of re-resolving the handle in `copy_passthrough` closes the H5
///     double-resolve window: a concurrent `NtClose`+reopen of the directory
///     handle between the decision and the kernel call can no longer make the
///     path policy approved differ from the path the kernel opens.
///   - `None` for the absolute-path case (no `RootDirectory` handle, hence no
///     race) — the caller keeps the existing verbatim-copy passthrough.
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
    if obj.ObjectName.is_null() {
        return None;
    }
    let ustr = &*obj.ObjectName;
    let char_count = (ustr.Length / 2) as usize;
    if char_count == 0 {
        return None;
    }
    // SAFETY: Buffer is valid for at least Length bytes per NT UNICODE_STRING contract.
    let name_slice = std::slice::from_raw_parts(ustr.Buffer, char_count);

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
        let base = device_path_to_dos_nt(&base).unwrap_or(base);
        let mut full: Vec<u16> = base;
        full.push(b'\\' as u16);
        full.extend_from_slice(name_slice);
        let dos = policy::path::nt_to_dos_lower(&full)?;
        return Some((dos, Some(full)));
    }

    // Fast path: ObjectName already in absolute NT form (`\??\C:\…`).
    if let Some(dos) = policy::path::nt_to_dos_lower(name_slice) {
        return Some((dos, None));
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
    let dos = policy::path::nt_to_dos_lower(&abs)?;
    Some((dos, Some(abs)))
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

pub(crate) unsafe fn extract_raw_nt_path(attrs: *const OBJECT_ATTRIBUTES) -> Option<String> {
    if attrs.is_null() { return None; }
    let obj = &*attrs;
    if obj.ObjectName.is_null() { return None; }
    let ustr = &*obj.ObjectName;
    let char_count = (ustr.Length / 2) as usize;
    if char_count == 0 { return None; }
    let name_slice = std::slice::from_raw_parts(ustr.Buffer, char_count);
    Some(String::from_utf16_lossy(name_slice))
}

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
/// intentionally NOT here — it is caller-specific (the create path lets the
/// kernel/NTFS resolve it; the rename guard rejects it for its `starts_with`
/// containment).
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
    // 8.3 short-name (e.g. PROGRA~1) — kernel resolves to a full path, bypassing
    // the classifier and the CoW overlay.
    if needs_short_name_resolve(canon) {
        return Some((STATUS_ACCESS_DENIED, "short_name"));
    }
    // Sandbox state directory — masked as non-existent (NAME_NOT_FOUND) so the
    // process treats `.winrsbox` as absent rather than forbidden.
    if canon.contains(r"\.winrsbox\") || canon.ends_with(r"\.winrsbox") {
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
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace, format!("fs_block_{reason}: {}", raw_nt));
        }
        return Some(status);
    }

    None
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

/// Returns Some(STATUS_ACCESS_DENIED) if the raw NT path in `attrs` is a
/// hard-blocked device (shadowcopy, physicaldrive, raw harddisk, dangerous
/// pipe). None otherwise → caller should call the original Nt* function.
///
/// SAFETY: `attrs` must be valid per NT calling convention.
pub(crate) unsafe fn check_device_block(attrs: *const OBJECT_ATTRIBUTES) -> Option<NTSTATUS> {
    let dev_path = extract_raw_nt_path(attrs)?;
    let utf16: Vec<u16> = dev_path.encode_utf16().collect();
    let device = policy::dev::nt_to_device_path(&utf16)?;
    let kind = policy::dev::classify_device(&device);
    if matches!(kind, policy::dev::DeviceKind::Unknown) {
        if is_trace() {
            ipc_log(
                ipc::LogLevel::Trace,
                format!("DENY device: {dev_path} kind={kind:?}"),
            );
        }
        Some(STATUS_ACCESS_DENIED)
    } else {
        None
    }
}

/// Returns true if the path in `attrs` refers to a filesystem volume device
/// (`\Device\HarddiskVolumeN\...`). Used to deny writes through device-path
/// forms that bypass the DOS-path policy pipeline.
///
/// # Safety
/// `attrs` must be valid per NT calling convention.
pub(crate) unsafe fn is_fs_device_path(attrs: *const OBJECT_ATTRIBUTES) -> bool {
    let Some(raw) = extract_raw_nt_path(attrs) else { return false };
    let utf16: Vec<u16> = raw.encode_utf16().collect();
    let Some(device) = policy::dev::nt_to_device_path(&utf16) else { return false };
    matches!(policy::dev::classify_device(&device), policy::dev::DeviceKind::HarddiskVolume)
}

// ---------------------------------------------------------------------------
// Post-open reparse verification + 8.3 short-name resolution
// ---------------------------------------------------------------------------

// NOTE: post-open junction/symlink verification removed — false positives on
// legitimate DLL/path-canonicalization differences. Junctions can still be
// closed by hooking NtCreateFile with FILE_FLAG_OPEN_REPARSE_POINT and
// blocking the create-side (separate task).

/// Check if a path contains an 8.3 short-name pattern (tilde followed by digit).
pub(crate) fn needs_short_name_resolve(path: &str) -> bool {
    let bytes = path.as_bytes();
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == b'~' && bytes[i + 1].is_ascii_digit() {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// CoW helper
// ---------------------------------------------------------------------------

pub(crate) fn prepare_overlay(decision: &Decision) -> Option<String> {
    let overlay_path = decision.overlay.as_ref()?;
    let overlay_dos = overlay_path.to_string_lossy().into_owned();

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

// ---------------------------------------------------------------------------
// Extract child exe from RTL_USER_PROCESS_PARAMETERS
// ---------------------------------------------------------------------------

/// Maximum number of UTF-16 code units in a Windows path. NT object names
/// (incl. UNC + \\?\ paths) cap at 32768 chars. Anything longer is malformed
/// or hostile (kernel returned garbage from a wrong offset).
const MAX_PATH_CHARS: usize = 32768;

/// Extract the executable path from RTL_USER_PROCESS_PARAMETERS.
/// Returns empty string if extraction fails.
//
// SAFETY:
// - `params` must point to a kernel-allocated `RTL_USER_PROCESS_PARAMETERS`
//   structure as populated by `NtCreateUserProcess` /
//   `RtlCreateProcessParametersEx`.
// - The struct layout is undocumented but stable on Windows 10/11 x64:
//   `ImagePathName` (UNICODE_STRING) lives at offset 0x60 (verified
//   empirically; matches the layout reported by reactos/wine and confirmed
//   against ntdll!_RTL_USER_PROCESS_PARAMETERS in WinDbg).
// - The struct's total size is always >= 0x500 in practice (the standard
//   layout is ~0x4F0 + variable-length env block), so reading the 16-byte
//   `UNICODE_STRING` header at offset 0x60 is safe even without explicit
//   length validation.
// - The `UNICODE_STRING.Buffer` pointer is kernel-allocated and valid for
//   the lifetime of the process-params structure (i.e., across this call).
// - If `params.is_null()` we early-return without dereferencing.
//
// Validity guards:
// - We bound the `.Length` field to MAX_PATH_CHARS (32768 UTF-16 units)
//   before slicing.
// - We treat `.Buffer == null` or `.Length == 0` as "no image path",
//   returning an empty string.
//
// Failure mode: if Microsoft ever shifts the offset (e.g., Windows 12),
// we'll read garbage and return a non-existent path — the comparison
// against the launcher's `allowed_image` list / denylist will fail
// closed (deny).
unsafe fn extract_child_exe(params: *mut c_void) -> String {
    if params.is_null() {
        return String::new();
    }
    // RTL_USER_PROCESS_PARAMETERS layout on x64 Windows 10/11:
    //   0x60: ImagePathName (UNICODE_STRING — 0x10 bytes)
    let params_ptr = params as *const u8;
    let image_path_offset = 0x60usize;
    let ustr_ptr = params_ptr.add(image_path_offset) as *const UNICODE_STRING;
    let ustr = &*ustr_ptr;
    if ustr.Buffer.is_null() || ustr.Length == 0 {
        return String::new();
    }
    let char_count = (ustr.Length / 2) as usize;
    // Sanity bound: a real ImagePathName never approaches 32K UTF-16 chars.
    // If we read garbage from a shifted offset, this catches the obviously
    // bogus case and fails closed.
    if char_count > MAX_PATH_CHARS {
        return String::new();
    }
    let name_slice = std::slice::from_raw_parts(ustr.Buffer, char_count);
    policy::path::nt_to_dos_lower(name_slice).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// NtCreateUserProcess hook
// ---------------------------------------------------------------------------

const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x0000_0001;

unsafe extern "system" fn hook_nt_create_user_process(
    process_handle: *mut HANDLE,
    thread_handle: *mut HANDLE,
    process_desired_access: ACCESS_MASK,
    thread_desired_access: ACCESS_MASK,
    process_object_attributes: *mut OBJECT_ATTRIBUTES,
    thread_object_attributes: *mut OBJECT_ATTRIBUTES,
    process_flags: u32,
    thread_flags: u32,
    process_parameters: *mut c_void,
    create_info: *mut c_void,
    attribute_list: *mut c_void,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return HOOK_NT_CREATE_USER_PROCESS.get().unwrap().call(
            process_handle, thread_handle,
            process_desired_access, thread_desired_access,
            process_object_attributes, thread_object_attributes,
            process_flags, thread_flags,
            process_parameters, create_info, attribute_list,
        );
    };

    // --- proc_guard: denylisted executables ---
    if let Some(img) = crate::proc_guard::extract_image_path(process_parameters) {
        if crate::proc_guard::is_denylisted(&img) {
            if is_trace() {
                ipc_log(ipc::LogLevel::Trace,
                    format!("proc_spawn_blocked: {img}"));
            }
            return STATUS_ACCESS_DENIED;
        }
    }

    // --- proc_guard: parent-PID spoofing ---
    if !attribute_list.is_null() {
        if crate::proc_guard::attribute_list_contains_parent_process(attribute_list) {
            let img = crate::proc_guard::extract_image_path(process_parameters)
                .unwrap_or_else(|| "(unknown)".into());
            if is_trace() {
                ipc_log(ipc::LogLevel::Trace,
                    format!("proc_parent_spoof_blocked: {img}"));
            }
            return STATUS_ACCESS_DENIED;
        }
    }

    // --- proc_guard: explicit handle-list inheritance ---
    if !attribute_list.is_null() {
        if crate::proc_guard::attribute_list_contains_handle_list(attribute_list) {
            if is_trace() {
                ipc_log(ipc::LogLevel::Trace,
                    "proc_handle_list_blocked".into());
            }
            return STATUS_ACCESS_DENIED;
        }
    }

    // Force the child to start suspended so we can inject before it runs.
    let forced_flags = thread_flags | THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
    let originally_suspended = (thread_flags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED) != 0;

    // Log EVERY spawn attempt with the target exe, before the syscall. Critical
    // diagnostic: a spawn_attempt without a matching `hello` event later means
    // the child was created but hook.dll injection did not initialise it (e.g.
    // cmd.exe's DllMain interferes — known limitation). Without this entry the
    // log shows children=0 and the cause is invisible.
    let spawn_target = extract_child_exe(process_parameters);
    let parent_pid = GetCurrentProcessId();
    ipc_log(ipc::LogLevel::Info,
        format!("spawn_attempt: parent={parent_pid} target={spawn_target}"));

    let status = HOOK_NT_CREATE_USER_PROCESS.get().unwrap().call(
        process_handle, thread_handle,
        process_desired_access, thread_desired_access,
        process_object_attributes, thread_object_attributes,
        process_flags, forced_flags,
        process_parameters, create_info, attribute_list,
    );

    if status < 0 {
        ipc_log(ipc::LogLevel::Warn,
            format!("spawn_failed: parent={parent_pid} target={spawn_target} status=0x{:08x}", status as u32));
        return status;
    }

    let proc_h = if process_handle.is_null() { return status; } else { *process_handle };
    let thr_h = if thread_handle.is_null() { return status; } else { *thread_handle };

    if proc_h.is_null() || thr_h.is_null() {
        return status;
    }

    // Register with launcher for process-tree tracking.
    // SAFETY: proc_h is a valid process handle returned by NtCreateUserProcess.
    let child_pid = GetProcessId(proc_h);
    if child_pid != 0 {
        let parent_pid = unsafe { GetCurrentProcessId() };
        ipc_register_child(child_pid);
        // Send SpawnedChild with child exe path extracted from process parameters.
        let child_exe = extract_child_exe(process_parameters);
        // Track this PID as our spawned child so memory_guard/reg_hooks can
        // distinguish legitimate injection-target operations from external attacks.
        // Capture the creation-time fingerprint from the live handle we already
        // hold (M2: source-capture makes the PID-reuse defense always engage).
        // SAFETY: proc_h is the valid process handle returned by NtCreateUserProcess.
        let create_time = unsafe { crate::process_tracker::create_time_from_handle(proc_h) };
        crate::process_tracker::mark_spawned(child_pid, parent_pid, child_exe.clone(), create_time);
        ipc_spawned_child(parent_pid, child_pid, child_exe);
    }

    // Inject hook.dll via APC. If injection fails the child process ALREADY
    // exists (suspended, no user code executed yet) and would escape the
    // sandbox once resumed. Terminate it before resume — fail closed.
    let mut inject_failed = false;
    if let Some(dll_path) = DLL_PATH.get() {
        if let Err(e) = inject::inject_via_apc(proc_h, thr_h, dll_path) {
            ipc_log(
                ipc::LogLevel::Error,
                format!("APC inject failed pid={child_pid}: {e}; terminating sandbox-escape candidate"),
            );
            // SAFETY: proc_h is the valid PROCESS handle returned moments ago
            // by NtCreateUserProcess; TerminateProcess never blocks. Exit code 1
            // signals "killed by sandbox" to anyone waiting on the process.
            unsafe { winapi::um::processthreadsapi::TerminateProcess(proc_h, 1) };
            inject_failed = true;
        }
    }

    // Resume if the caller did not want a suspended thread — but skip if we
    // just killed the child; there is nothing to resume in a dead process and
    // ResumeThread would only return an error.
    if !originally_suspended && !inject_failed {
        let mut suspend_count: u32 = 0;
        // SAFETY: thr_h is a valid thread handle; NtResumeThread is always present.
        ntapi::ntpsapi::NtResumeThread(thr_h, &mut suspend_count);
    }

    status
}

// ---------------------------------------------------------------------------
// Resolve an export from ntdll.dll by name.
// ---------------------------------------------------------------------------

pub(crate) unsafe fn ntdll_export(name: &[u8]) -> Option<*const ()> {
    use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};
    let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    // SAFETY: ntdll_w is null-terminated UTF-16 name of a module always present.
    let hmod = GetModuleHandleW(ntdll_w.as_ptr());
    if hmod.is_null() {
        return None;
    }
    // SAFETY: name is a valid null-terminated ASCII byte slice.
    let p = GetProcAddress(hmod, name.as_ptr() as *const i8);
    if p.is_null() { None } else { Some(p as *const ()) }
}

// ---------------------------------------------------------------------------
// Public install / uninstall
// ---------------------------------------------------------------------------

/// Install all Nt* detours.
///
/// # SAFETY
/// Must be called at most once, from DllMain(DLL_PROCESS_ATTACH), with the
/// loader lock held. Only Win32 APIs safe in DllMain are used here
/// (GetModuleHandleW, GetProcAddress, VirtualAlloc via detour internals).
pub unsafe fn install_hooks() -> Result<(), Box<dyn std::error::Error>> {
    use crate::fs_hooks::{
        HOOK_NT_CREATE_FILE, HOOK_NT_OPEN_FILE,
        HOOK_NT_QUERY_ATTRIBUTES_FILE, HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE,
        FnNtCreateFile, FnNtOpenFile, FnNtQueryAttributesFile, FnNtQueryFullAttributesFile,
        hook_nt_create_file, hook_nt_open_file,
        hook_nt_query_attributes_file, hook_nt_query_full_attributes_file,
    };

    if let Ok(pipe) = std::env::var("FS_SANDBOX_PIPE") {
        let _ = PIPE_NAME.set(pipe);
    }
    if let Ok(dll) = std::env::var("FS_SANDBOX_DLL") {
        let _ = DLL_PATH.set(dll);
    }
    if std::env::var("FS_SANDBOX_TRACE").is_ok() {
        TRACE_ENABLED.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    if let Ok(cwd) = std::env::var("FS_SANDBOX_CWD") {
        let _ = SANDBOX_CWD.set(cwd.clone());
        // Override the process CWD to the sandbox root. This runs before any
        // user-mode entry point code, so the process sees the right directory
        // from the first os.Getwd() / GetCurrentDirectory call.
        // SetCurrentDirectoryW is safe to call from DllMain (pure RtlSetCurrentDirectory_U).
        let wide: Vec<u16> = cwd.encode_utf16().chain(Some(0)).collect();
        // SAFETY: wide is a valid null-terminated UTF-16 path string.
        unsafe { winapi::um::processenv::SetCurrentDirectoryW(wide.as_ptr()) };
    }

    macro_rules! install {
        ($lock:expr, $sym:literal, $hook_fn:expr, $fn_ty:ty) => {{
            let addr = ntdll_export($sym.as_bytes())
                .ok_or_else(|| format!("ntdll export not found: {}", $sym))?;
            // SAFETY: addr is the real ntdll export matching the FnNt* type alias.
            let target: $fn_ty = std::mem::transmute(addr as usize);
            let hook_ptr: $fn_ty = $hook_fn;
            let detour = GenericDetour::<$fn_ty>::new(target, hook_ptr)
                .map_err(|e| format!("detour init {}: {:?}", $sym, e))?;
            // Populate OnceLock BEFORE enabling so the hook never observes an
            // empty OnceLock: hook_* calls $lock.get().unwrap(), which would
            // panic if the hook fired in the window between enable and set.
            $lock.set(detour).ok();
            $lock.get()
                .expect("set above")
                .enable()
                .map_err(|e| format!("detour enable {}: {:?}", $sym, e))?;
        }};
    }

    let guard = std::env::var("FS_SANDBOX_GUARD").unwrap_or_else(|_| "full".into());
    let disabled = std::env::var("FS_SANDBOX_DISABLE_HOOKS").unwrap_or_default();
    let disabled_cats: Vec<String> = disabled.split(',').map(|s| s.trim().to_ascii_lowercase()).collect();
    let skip = |cat: &str| disabled_cats.iter().any(|d| d == cat);

    if !skip("fs") {
        install!(HOOK_NT_CREATE_FILE,              "NtCreateFile\0",              hook_nt_create_file,              FnNtCreateFile);
        install!(HOOK_NT_OPEN_FILE,                "NtOpenFile\0",                hook_nt_open_file,                FnNtOpenFile);
        install!(HOOK_NT_QUERY_ATTRIBUTES_FILE,    "NtQueryAttributesFile\0",     hook_nt_query_attributes_file,    FnNtQueryAttributesFile);
        install!(HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE, "NtQueryFullAttributesFile\0", hook_nt_query_full_attributes_file, FnNtQueryFullAttributesFile);
        install!(HOOK_NT_CREATE_USER_PROCESS,      "NtCreateUserProcess\0",       hook_nt_create_user_process,      FnNtCreateUserProcess);
        crate::dir_filter::install()?;
        crate::fs_metadata_guard::install()?;
    }

    if guard != "none" {
        // Hold anti_rec during guard installation so detour's internal
        // VirtualProtect calls (to patch ntdll stubs) pass through the
        // NtProtectVirtualMemory hook without triggering content scans
        // on ntdll's legitimate syscall instructions.
        let _install_guard = anti_rec::enter();
        if !skip("memory") {
            crate::memory_guard::install(&guard)?;
        }
        if !skip("inject") {
            crate::inject_guard::install()?;
        }
        if !skip("reg") {
            if let Err(e) = crate::reg_hooks::install() {
                buffer_install_error(format!("reg_hooks install failed: {:?}", e));
            }
        }
        if !skip("net") {
            if let Err(e) = crate::net_hooks::install() {
                buffer_install_error(format!("net_hooks install failed: {:?}", e));
            }
        }
        if !skip("alpc") {
            if let Err(e) = crate::alpc_guard::install() {
                buffer_install_error(format!("alpc_guard install failed: {:?}", e));
            }
        }
        if !skip("token") {
            crate::token_guard::install()?;
        }
        if !skip("ui") {
            if let Err(e) = crate::ui_guard::install() {
                buffer_install_error(format!("ui_guard install failed: {:?}", e));
            }
        }
        if !skip("proc") {
            crate::proc_guard::install()?;
        }
        if !skip("com") {
            crate::com_guard::install()?;
        }
        if !skip("service") {
            if let Err(e) = crate::service_guard::install() {
                buffer_install_error(format!("service_guard install failed: {:?}", e));
            }
        }
        if !skip("shell") {
            if let Err(e) = crate::shell_guard::install() {
                buffer_install_error(format!("shell_guard install failed: {:?}", e));
            }
        }
        if !skip("system") {
            if let Err(e) = crate::system_guard::install() {
                buffer_install_error(format!("system_guard install failed: {:?}", e));
            }
        }

        if !skip("mitigations") {
            apply_mitigations(&guard);
        }

        // Arm the inject_guard deterministically now that every hook (incl.
        // inject_guard's NtCreateThreadEx/NtQueueApcThread detours) is installed.
        //
        // M1 fix: previously arming happened lazily on the first successful IPC
        // round-trip (ensure_ipc_and -> inject_guard::arm()), which only occurs
        // on a process's first file/registry op. A process that issued a
        // cross-process injection before any FS/reg op was still ARMED=false, so
        // should_block() returned false and the injection sailed through. Tying
        // arming to "hooks installed" closes that init-order window.
        //
        // arm() is a single `AtomicBool::store(true, Release)` — no allocation,
        // no LoadLibrary, no syscall — so it is safe in this DllMain/loader-lock-
        // adjacent context and idempotent. The ensure_ipc_and() call is kept as
        // belt-and-suspenders for the `guard == "none"` path (where inject_guard
        // is not installed, arming is a harmless no-op flag flip).
        if !skip("inject") {
            crate::inject_guard::arm();
        }
    }

    // Signal launcher that hook.dll initialized successfully via kernel Event.
    // If this env var is absent, we're in a context that doesn't need signaling
    // (e.g. unit tests running hook code directly).
    if let Ok(event_name) = std::env::var("FS_SANDBOX_INIT_EVENT") {
        let wide: Vec<u16> = event_name.encode_utf16().chain(Some(0)).collect();
        unsafe {
            let h = winapi::um::synchapi::OpenEventW(
                0x0002, // EVENT_MODIFY_STATE — needed for SetEvent
                0,      // bInheritHandle = FALSE
                wide.as_ptr(),
            );
            if !h.is_null() {
                winapi::um::synchapi::SetEvent(h);
                winapi::um::handleapi::CloseHandle(h);
            }
        }
    }

    Ok(())
}

/// Apply kernel-enforced process mitigations from within the sandboxed process.
/// Called after all hooks are installed so our detour patching is already done.
fn apply_mitigations(guard: &str) {
    if guard == "none" {
        return;
    }
    use winapi::um::processthreadsapi::SetProcessMitigationPolicy;
    use winapi::um::winnt::PROCESS_MITIGATION_POLICY;

    // ExtensionPointDisablePolicy (6): blocks AppInit_DLLs, SetWindowsHookEx, IFEO.
    // Applied in full and static — this is JIT-safe hardening (it blocks
    // injection INTO us, not our own code generation).
    // Diagnostic escape hatch: set FS_SANDBOX_NO_EXTPOINT_DISABLE=1 to skip
    // this block (suspected to also break Text Services Framework / IME
    // initialisation, including per-process keyboard layout switching).
    if (guard == "full" || guard == "static")
        && std::env::var("FS_SANDBOX_NO_EXTPOINT_DISABLE").is_err()
    {
        let ext_disable_flags: u32 = 1;
        // SAFETY: ext_disable_flags is valid for PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY.
        unsafe {
            SetProcessMitigationPolicy(
                6i32 as PROCESS_MITIGATION_POLICY,
                &ext_disable_flags as *const u32 as *mut _,
                std::mem::size_of::<u32>(),
            );
        }
    }

    // DynamicCode + Signature are the JIT/unsigned-code killers — they break
    // node/V8, .NET, Python .pyd, Node .node. Applied ONLY in `static` (hard
    // containment, opt-in for pure-static targets), never in `full`. This is
    // the runtime half of the M4 split; the create-time half lives in
    // launcher mitigations::Profile::Static. SignaturePolicy is applied here
    // (not at create time) precisely because hook.dll is unsigned and must
    // load first.
    if guard == "static" {
        // DynamicCodePolicy (2): blocks RWX/JIT
        let dyn_code_flags: u32 = 1; // ProhibitDynamicCode = bit 0
        // SAFETY: same — 4-byte struct with Flags DWORD.
        unsafe {
            SetProcessMitigationPolicy(
                2i32 as PROCESS_MITIGATION_POLICY, // ProcessDynamicCodePolicy
                &dyn_code_flags as *const u32 as *mut _,
                std::mem::size_of::<u32>(),
            );
        }

        // SignaturePolicy (8): only Microsoft-signed DLLs (subsequent loads)
        let sig_flags: u32 = 1; // MicrosoftSignedOnly = bit 0
        // SAFETY: same — PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY (4 bytes).
        unsafe {
            SetProcessMitigationPolicy(
                8i32 as PROCESS_MITIGATION_POLICY, // ProcessSignaturePolicy
                &sig_flags as *const u32 as *mut _,
                std::mem::size_of::<u32>(),
            );
        }
    }

    // ImageLoadPolicy (10): PreferSystem32Images + NoRemoteImages.
    // Applied in all enforcing tiers (scan/full/static) — DLL sideloading via CWD/PATH hijack
    // is a critical sandbox-escape vector that affects all profiles.
    // Safe to apply after hook installation: hook.dll is already loaded,
    // and PreferSystem32Images only affects *subsequent* LoadLibrary calls.
    // Diagnostic escape hatch: set FS_SANDBOX_NO_IMAGELOAD_LOCK=1 to skip.
    if std::env::var("FS_SANDBOX_NO_IMAGELOAD_LOCK").is_err() {
        // PROCESS_MITIGATION_IMAGE_LOAD_POLICY bit layout:
        //   bit 0 = NoRemoteImages    (block UNC \\server\share\evil.dll)
        //   bit 2 = PreferSystem32Images (System32 searched before CWD/PATH)
        let image_load_flags: u32 = (1 << 0) | (1 << 2); // NoRemote | PreferSystem32
        // SAFETY: image_load_flags is valid for PROCESS_MITIGATION_IMAGE_LOAD_POLICY (4 bytes).
        unsafe {
            SetProcessMitigationPolicy(
                10i32 as PROCESS_MITIGATION_POLICY, // ProcessImageLoadPolicy
                &image_load_flags as *const u32 as *mut _,
                std::mem::size_of::<u32>(),
            );
        }
    }
}

/// Disable all detours. Called from DllMain(DLL_PROCESS_DETACH).
///
/// # SAFETY
/// Must be called on DLL_PROCESS_DETACH only. Errors are ignored because
/// the process is tearing down.
pub unsafe fn uninstall_hooks() {
    crate::system_guard::uninstall();
    crate::shell_guard::uninstall();
    crate::service_guard::uninstall();
    crate::com_guard::uninstall();
    crate::proc_guard::uninstall();
    crate::ui_guard::uninstall();
    crate::token_guard::uninstall();
    crate::alpc_guard::uninstall();
    crate::net_hooks::uninstall();
    crate::reg_hooks::uninstall();
    crate::inject_guard::uninstall();
    crate::memory_guard::uninstall();
    if let Some(h) = crate::fs_hooks::HOOK_NT_CREATE_FILE.get() { let _ = h.disable(); }
    if let Some(h) = crate::fs_hooks::HOOK_NT_OPEN_FILE.get() { let _ = h.disable(); }
    if let Some(h) = crate::fs_hooks::HOOK_NT_QUERY_ATTRIBUTES_FILE.get() { let _ = h.disable(); }
    if let Some(h) = crate::fs_hooks::HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_NT_CREATE_USER_PROCESS.get() { let _ = h.disable(); }
    crate::fs_metadata_guard::uninstall();
    crate::dir_filter::uninstall();
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy::{Decision, Mode};
    use std::path::PathBuf;

    #[test]
    fn write_access_flags() {
        assert!(is_write_access(GENERIC_WRITE, 0));
        assert!(is_write_access(FILE_APPEND_DATA, 0));
        assert!(is_write_access(DELETE, 0));
        assert!(is_write_access(0, FILE_CREATE));
        assert!(is_write_access(0, FILE_OVERWRITE_IF));
        assert!(is_write_access(0, FILE_SUPERSEDE));
        assert!(!is_write_access(0, 1)); // FILE_OPEN
    }

    /// Build a path inside the OS temp dir that is unique per test invocation,
    /// without pulling in the `tempfile` crate (forbidden by scope rules).
    fn unique_temp_path(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "winrsbox-hook-test-{tag}-{pid}-{nanos}-{seq}",
        ));
        p
    }

    /// Mock-overlay materialization MUST be a no-op once the overlay file
    /// already exists. Regression test for the per-open `fs::write` storm:
    /// the second call with a different payload must NOT overwrite the
    /// file content produced by the first call.
    #[test]
    fn mock_write_idempotent_when_exists() {
        let dir = unique_temp_path("mock-idem");
        let overlay = dir.join("payload.bin");
        let first: &[u8] = b"first-write";
        let second: &[u8] = b"SECOND-WRITE-MUST-NOT-LAND";

        // First call materializes the file.
        materialize_mock_overlay(&overlay, first);
        assert!(overlay.exists(), "first materialize should create the file");
        let after_first = std::fs::read(&overlay).expect("read after first");
        assert_eq!(after_first, first);

        // Second call must be a no-op: content unchanged.
        materialize_mock_overlay(&overlay, second);
        let after_second = std::fs::read(&overlay).expect("read after second");
        assert_eq!(
            after_second, first,
            "second materialize must NOT overwrite existing overlay"
        );

        // Cleanup — best-effort, ignore failures.
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `prepare_overlay` must return `None` when the Decision claims Mode::Cow
    /// but carries no overlay path. The caller relies on this signal to fail
    /// closed (return STATUS_ACCESS_DENIED) instead of leaking the write to
    /// the real filesystem.
    #[test]
    fn prepare_overlay_none_when_overlay_field_missing() {
        let d = Decision {
            mode: Mode::Cow,
            overlay: None,
            cow_from: None,
            mock_payload: None,
        };
        assert!(prepare_overlay(&d).is_none());
    }

    /// `prepare_overlay` returns `Some(<dos string>)` when an overlay path is
    /// present, matching the lossy stringification of the supplied PathBuf.
    #[test]
    fn prepare_overlay_some_when_overlay_field_present() {
        // Use a unique temp dir so create_dir_all (called inside prepare_overlay)
        // succeeds without polluting an arbitrary location like c:\overlay.
        let dir = unique_temp_path("prep-some");
        let overlay = dir.join("redirect.bin");
        let expected = overlay.to_string_lossy().into_owned();

        let d = Decision {
            mode: Mode::Cow,
            overlay: Some(overlay.clone()),
            cow_from: None,
            mock_payload: None,
        };
        let got = prepare_overlay(&d).expect("Some when overlay field is set");
        assert_eq!(got, expected);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── path-normalization tests ────────────────────────────────────────────
    // M-S3: NTFS strips trailing dot/space from each path segment; the kernel
    // resolves "C:\.winrsbox." to "C:\.winrsbox". Our denylist check must do
    // the same, otherwise it slips through ends_with(r"\.winrsbox").

    #[test]
    fn trailing_dot_in_winrsbox_segment_caught() {
        let path = r"C:\sandbox\.winrsbox.";
        let normalized = strip_trailing_dot_space(path);
        assert_eq!(normalized.as_ref(), r"C:\sandbox\.winrsbox");
    }

    #[test]
    fn trailing_space_in_winrsbox_segment_caught() {
        let path = "C:\\sandbox\\.winrsbox  ";
        let normalized = strip_trailing_dot_space(path);
        assert_eq!(normalized.as_ref(), r"C:\sandbox\.winrsbox");
    }

    #[test]
    fn trailing_mix_dot_space_segments_caught() {
        let path = "C:\\sand box. \\.winrsbox.";
        let normalized = strip_trailing_dot_space(path);
        assert_eq!(normalized.as_ref(), r"C:\sand box\.winrsbox");
    }

    #[test]
    fn normal_path_no_allocation() {
        let path = r"C:\Users\test\file.txt";
        let normalized = strip_trailing_dot_space(path);
        assert!(matches!(normalized, Cow::Borrowed(_)),
            "well-formed path must not allocate");
    }

    #[test]
    fn unc_prefix_passes_through() {
        // \\?\ split-by-\: ["", "", "?", "C:", "folder.", "file.txt"]
        // After per-segment strip: ["", "", "?", "C:", "folder", "file.txt"]
        // Rejoined: \\?\C:\folder\file.txt
        let path = r"\\?\C:\folder.\file.txt";
        let normalized = strip_trailing_dot_space(path);
        assert_eq!(normalized.as_ref(), r"\\?\C:\folder\file.txt");
    }

    #[test]
    fn nt_prefix_question_mark_passes_through() {
        // \??\ NT-form prefix: same per-segment treatment.
        let path = r"\??\C:\folder.\file.txt";
        let normalized = strip_trailing_dot_space(path);
        assert_eq!(normalized.as_ref(), r"\??\C:\folder\file.txt");
    }

    #[test]
    fn drive_letter_only_unchanged() {
        // C: has no trailing dot or space; must round-trip exactly.
        let path = "C:";
        let normalized = strip_trailing_dot_space(path);
        assert_eq!(normalized.as_ref(), "C:");
        assert!(matches!(normalized, Cow::Borrowed(_)));
    }

    #[test]
    fn drive_letter_with_trailing_dot_normalized() {
        // C:. → C:  (NTFS strips the trailing dot)
        let path = r"C:.";
        let normalized = strip_trailing_dot_space(path);
        assert_eq!(normalized.as_ref(), r"C:");
    }

    #[test]
    fn drive_letter_root_path_unchanged() {
        let path = r"C:\\foo\\bar";
        let normalized = strip_trailing_dot_space(path);
        assert_eq!(normalized.as_ref(), r"C:\\foo\\bar");
    }

    #[test]
    fn ascii_lowercase_preserves_non_ascii() {
        // U+0130 (LATIN CAPITAL LETTER I WITH DOT ABOVE) must NOT collapse
        // into "i" or "i\u{307}". Rust's to_lowercase() folds it to a two-char
        // sequence; the NT kernel folds it to "i". Either fold can split-brain
        // a denylist check. ASCII-only lowercase leaves it as U+0130, which
        // is what every comparison site must see.
        let path = "C:\\WINRSBOX\u{0130}MARKER";
        let lower = path.to_ascii_lowercase();
        assert_eq!(lower, "c:\\winrsbox\u{0130}marker",
            "U+0130 must pass through untouched");
    }

    #[test]
    fn winrsbox_with_unicode_suffix_does_not_match_denylist() {
        // Adversarial: attacker can't bypass the .winrsbox hide check by
        // appending U+0130 (which kernel folds to ASCII 'i', producing a
        // different on-disk path). ASCII-only lowercase leaves U+0130 alone,
        // so ends_with(r"\.winrsbox") cannot match. Kernel resolves to
        // "C:\.winrsboxi" — a different path that does not contain our
        // sandbox state.
        let path = "C:\\.WINRSBOX\u{0130}";
        let lower = path.to_ascii_lowercase();
        let canon = strip_trailing_dot_space(&lower);
        assert!(!canon.ends_with(r"\.winrsbox"));
        assert!(!canon.contains(r"\.winrsbox\"));
    }

    /// Adversarial: full canonicalization pipeline (as used in
    /// `check_path_traversal`) must catch a trailing-dot `.winrsbox` segment.
    /// Before the fix this slipped past ends_with(r"\.winrsbox"); after the
    /// fix it's caught and the sandbox state stays hidden.
    #[test]
    fn winrsbox_hide_catches_trailing_dot() {
        let raw = r"\??\C:\sandbox\.WINRSBOX.";
        let lower = raw.to_ascii_lowercase();
        let canon = strip_trailing_dot_space(&lower);
        assert!(canon.contains(r"\.winrsbox\") || canon.ends_with(r"\.winrsbox"),
            "trailing dot must be stripped before .winrsbox denylist check (got: {})",
            canon.as_ref());
    }

    /// Adversarial: trailing space variant.
    #[test]
    fn winrsbox_hide_catches_trailing_space() {
        let raw = "\\??\\C:\\sandbox\\.WINRSBOX ";
        let lower = raw.to_ascii_lowercase();
        let canon = strip_trailing_dot_space(&lower);
        assert!(canon.ends_with(r"\.winrsbox"),
            "trailing space must be stripped (got: {})", canon.as_ref());
    }

    /// Adversarial: trailing-dot inside an intermediate `.winrsbox.` segment
    /// (not the final segment of the path) still matches the
    /// `lower.contains(r"\.winrsbox\")` form.
    #[test]
    fn winrsbox_hide_catches_intermediate_segment_trailing_dot() {
        // After NTFS canonicalization the kernel opens \.winrsbox\sub\file
        let raw = r"\??\C:\sandbox\.winrsbox.\sub\file";
        let lower = raw.to_ascii_lowercase();
        let canon = strip_trailing_dot_space(&lower);
        assert!(canon.contains(r"\.winrsbox\"),
            "intermediate trailing dot must be stripped (got: {})", canon.as_ref());
    }

    // -- device_path_to_dos_nt --------------------------------------------------
    //
    // Regression coverage for the cmd.exe `>filename` escape: NtQueryObject on
    // a directory handle returns a `\Device\HarddiskVolumeN\…` kernel path.
    // Without remapping it back into `\??\<letter>:\…`, `nt_to_dos_lower`
    // rejects the joined path and the hook silently passes through.
    //
    // These tests are purely structural — they construct paths against an
    // ad-hoc volume map and verify the prefix-match + boundary logic. They do
    // NOT exercise the OS-backed `device_drive_map()` cache (which requires a
    // real QueryDosDeviceW call); a follow-up integration test should pick a
    // mounted drive, look up its device path via QueryDosDeviceW, and check
    // round-trip.

    fn u16s(s: &str) -> Vec<u16> { s.encode_utf16().collect() }

    fn dos_string(v: Option<Vec<u16>>) -> Option<String> {
        v.map(|w| String::from_utf16_lossy(&w))
    }

    #[test]
    fn device_unknown_volume_returns_none() {
        // No QueryDosDeviceW entry maps to HarddiskVolume999 → unchanged.
        let out = device_path_to_dos_nt(&u16s(r"\Device\HarddiskVolume999\foo"));
        assert!(out.is_none(),
            "unknown device prefix must NOT be rewritten (got {:?})", dos_string(out));
    }

    #[test]
    fn device_condrv_returns_none() {
        // Console driver is not a volume; must not be remapped.
        let out = device_path_to_dos_nt(&u16s(r"\Device\ConDrv\Reference"));
        assert!(out.is_none(),
            "non-volume device must NOT be rewritten (got {:?})", dos_string(out));
    }

    #[test]
    fn device_path_already_dos_returns_none() {
        // `\??\C:\…` is already in DOS form; no rewrite expected.
        let out = device_path_to_dos_nt(&u16s(r"\??\C:\foo"));
        assert!(out.is_none(),
            "DOS-prefixed path must NOT be rewritten (got {:?})", dos_string(out));
    }

    #[test]
    fn ascii_to_lower_u16_only_touches_ascii_upper() {
        assert_eq!(ascii_to_lower_u16(b'A' as u16), b'a' as u16);
        assert_eq!(ascii_to_lower_u16(b'Z' as u16), b'z' as u16);
        assert_eq!(ascii_to_lower_u16(b'a' as u16), b'a' as u16);
        assert_eq!(ascii_to_lower_u16(b'0' as u16), b'0' as u16);
        assert_eq!(ascii_to_lower_u16(b'\\' as u16), b'\\' as u16);
        // U+0080+ pass through unchanged.
        assert_eq!(ascii_to_lower_u16(0x00E9), 0x00E9); // é
        assert_eq!(ascii_to_lower_u16(0x0410), 0x0410); // Cyrillic А
    }

    /// Boundary discipline: `\Device\HarddiskVolume3` MUST NOT prefix-match
    /// against `\Device\HarddiskVolume30\…`. The check is a follow-byte
    /// inspection; if a candidate device entry happens to match, the next
    /// u16 must be `\` (or end-of-string), not a digit.
    ///
    /// Exercised via the boundary logic inside device_path_to_dos_nt: we
    /// hand-craft a tail starting with a digit and assert the function
    /// rejects it. Since we cannot inject a fake volume into the static map,
    /// this test piggy-backs on the unknown-volume case — any present
    /// volume's path is system-dependent; the *negative* assertion that
    /// non-volume devices and prefix-aliased paths bail out is what survives
    /// the OS-dependence.
    #[test]
    fn device_path_boundary_logic_compiles() {
        // Smoke: function is reachable and returns Option<Vec<u16>>.
        let _ = device_path_to_dos_nt(&u16s(""));
        let _ = device_path_to_dos_nt(&u16s(r"\Device"));
    }

    /// OS-backed sanity: at least ONE drive letter on the test host must map
    /// (the system drive). If the static map is empty, the `device_drive_map`
    /// bootstrap has a bug (e.g. wrong buf size, missed null-termination).
    #[test]
    fn device_drive_map_is_nonempty_on_windows() {
        let map = device_drive_map();
        assert!(!map.is_empty(),
            "device_drive_map() returned no entries — QueryDosDeviceW path is broken");
    }

    /// OS-backed round-trip: the system drive's letter MUST resolve to a
    /// `\Device\…` path, and feeding `<that>\probe` back through
    /// device_path_to_dos_nt must give `\??\<letter>:\probe`.
    #[test]
    fn device_path_roundtrip_via_real_qdd() {
        use winapi::um::fileapi::QueryDosDeviceW;
        let drive = [b'C' as u16, b':' as u16, 0u16];
        let mut buf = [0u16; 512];
        // SAFETY: drive is null-terminated, buf is valid for buf.len() u16s.
        let len = unsafe {
            QueryDosDeviceW(drive.as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
        };
        if len == 0 {
            // Test host lacks a C: drive — skip. (Unusual but not impossible
            // in some CI sandboxes; the previous test already proved the
            // bootstrap works, so we don't fail the suite over it.)
            return;
        }
        let end = buf[..len as usize].iter().position(|&c| c == 0).unwrap_or(len as usize);
        let mut device_plus_tail: Vec<u16> = buf[..end].to_vec();
        device_plus_tail.extend_from_slice(&u16s(r"\probe"));

        let rewritten = device_path_to_dos_nt(&device_plus_tail)
            .expect("system drive's device path must remap");
        let s = String::from_utf16_lossy(&rewritten).to_ascii_lowercase();
        assert!(s.starts_with(r"\??\c:\"),
            "expected `\\??\\c:\\…`, got {s}");
        assert!(s.ends_with(r"\probe"), "tail lost in rewrite: {s}");
    }

    // -- join_bare_relative_to_nt ----------------------------------------------
    //
    // Regression coverage for the cmd.exe `>filename` escape's bare-relative
    // branch in resolve_for_hook. The OS-backed half of that fix
    // (GetCurrentDirectoryW) can't be unit-tested without launching a child
    // process, so the join discipline is split into this pure helper that
    // takes CWD as an input slice.

    fn u(s: &str) -> Vec<u16> { s.encode_utf16().collect() }
    fn s_of(v: &[u16]) -> String { String::from_utf16_lossy(v) }

    #[test]
    fn join_typical_cwd_and_bare_name() {
        let abs = join_bare_relative_to_nt(&u(r"C:\Users\alice\Desktop"), &u("qwe.txt"));
        assert_eq!(s_of(&abs), r"\??\C:\Users\alice\Desktop\qwe.txt");
    }

    #[test]
    fn join_inserts_separator_when_cwd_missing_trailing_slash() {
        // The realistic case — GetCurrentDirectoryW typically returns
        // `C:\some\path` without a trailing slash.
        let abs = join_bare_relative_to_nt(&u(r"C:\some\path"), &u("file"));
        assert_eq!(s_of(&abs), r"\??\C:\some\path\file");
    }

    #[test]
    fn join_no_double_slash_when_cwd_has_trailing_slash() {
        // Drive root case (`C:\`) — CWD already ends with `\`. We must NOT
        // insert a second one, or the kernel parses `\\file` as a UNC root.
        let abs = join_bare_relative_to_nt(&u(r"C:\"), &u("file.txt"));
        assert_eq!(s_of(&abs), r"\??\C:\file.txt");
    }

    #[test]
    fn join_prefix_is_dos_device_form() {
        // The first four code units MUST be `\??\` (the DOS-device prefix
        // policy::path::nt_to_dos_lower recognises). A `\\?\` variant would
        // also be accepted by the path normalizer, but mixing the two would
        // fail the join contract test below.
        let abs = join_bare_relative_to_nt(&u(r"C:\x"), &u("y"));
        assert_eq!(&abs[..4], &[
            b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16,
        ]);
    }

    #[test]
    fn join_passes_through_nt_to_dos_lower() {
        // The combined contract: anything the join produces from a valid
        // DOS CWD + a bare relative name must be classifiable by
        // `policy::path::nt_to_dos_lower` — that's the gate that turns
        // the kernel-form path back into our policy-form DOS path. If this
        // ever breaks, the cmd.exe escape returns.
        let abs = join_bare_relative_to_nt(
            &u(r"C:\Users\Computer\Desktop"),
            &u("qwe.txt"),
        );
        let dos = policy::path::nt_to_dos_lower(&abs)
            .expect("synthesized \\??\\<cwd>\\<name> must be DOS-classifiable");
        assert_eq!(dos, r"c:\users\computer\desktop\qwe.txt");
    }

    #[test]
    fn join_preserves_subdirectory_in_name() {
        // Caller can pass a multi-component bare relative path (e.g.
        // `subdir\file.txt`). The join logic must not flatten or split it.
        let abs = join_bare_relative_to_nt(
            &u(r"C:\base"),
            &u(r"sub\file.txt"),
        );
        assert_eq!(s_of(&abs), r"\??\C:\base\sub\file.txt");
    }
}

// ---------------------------------------------------------------------------
// C1/C2 regression — resolved-path denylist catches .winrsbox in joined paths
// ---------------------------------------------------------------------------
#[cfg(test)]
mod resolved_path_denylist_tests {
    use super::*;

    #[test]
    fn resolved_winrsbox_relative_caught() {
        let joined = r"c:\sandbox\.winrsbox\policy.json";
        let canon = canonicalize_for_denylist(joined);
        assert!(
            canonical_denylist_status(&canon).is_some(),
            ".winrsbox in resolved DOS path must be denied"
        );
    }

    #[test]
    fn resolved_winrsbox_bare_segment_caught() {
        let joined = r"c:\sandbox\.winrsbox";
        let canon = canonicalize_for_denylist(joined);
        assert!(canonical_denylist_status(&canon).is_some());
    }

    #[test]
    fn resolved_normal_path_not_blocked() {
        let joined = r"c:\sandbox\src\main.rs";
        let canon = canonicalize_for_denylist(joined);
        assert!(canonical_denylist_status(&canon).is_none());
    }

    #[test]
    fn canonicalize_already_canonical_borrows() {
        let p = r"c:\sandbox\src\main.rs";
        assert!(
            matches!(canonicalize_for_denylist(p), Cow::Borrowed(_)),
            "already-canonical path must return Cow::Borrowed (zero alloc)"
        );
    }

    #[test]
    fn canonicalize_folds_forward_slash() {
        let p = r"c:/sandbox/src/main.rs";
        let canon = canonicalize_for_denylist(p);
        assert!(matches!(canon, Cow::Owned(_)));
        assert_eq!(&*canon, r"c:\sandbox\src\main.rs");
    }

    #[test]
    fn canonicalize_lowercases_uppercase() {
        let p = r"C:\Sandbox\SRC\Main.RS";
        let canon = canonicalize_for_denylist(p);
        assert!(matches!(canon, Cow::Owned(_)));
        assert_eq!(&*canon, r"c:\sandbox\src\main.rs");
    }

    #[test]
    fn canonicalize_strips_trailing_dot() {
        let p = r"c:\sandbox\src.\main.rs";
        let canon = canonicalize_for_denylist(p);
        assert!(matches!(canon, Cow::Owned(_)));
        // Reference: old algorithm
        let lowered = p.to_ascii_lowercase().replace('/', "\\");
        let reference = strip_trailing_dot_space(&lowered);
        assert_eq!(&*canon, &*reference);
    }

    /// The Owned (needs-change) branch MUST produce byte-for-byte the same
    /// output as the original `s.to_ascii_lowercase().replace('/', "\\")`
    /// then `strip_trailing_dot_space`. Non-ASCII chars must be preserved
    /// verbatim (NOT per-byte mojibake'd into U+0080..U+00FF). This path has
    /// an uppercase ASCII letter (forcing the Owned branch) AND a non-ASCII
    /// segment, which is exactly where a per-byte fold would diverge.
    #[test]
    fn canonicalize_preserves_non_ascii_on_owned_branch() {
        let p = "C:\\Users\\Ω\\Naïve/Файл.TXT";
        let canon = canonicalize_for_denylist(p);
        assert!(matches!(canon, Cow::Owned(_)));
        // Reference: exactly the pre-optimization algorithm.
        let lowered = p.to_ascii_lowercase().replace('/', "\\");
        let reference = strip_trailing_dot_space(&lowered).into_owned();
        assert_eq!(&*canon, reference,
            "Owned branch must match the original transform byte-for-byte, \
             preserving non-ASCII UTF-8");
        // And the non-ASCII chars survive as real chars (not mojibake).
        assert!(canon.contains('ω') || canon.contains('Ω'),
            "Greek omega must survive the fold as a real char");
        assert!(canon.contains('ф') || canon.contains('Ф'),
            "Cyrillic char must survive the fold");
    }

    /// A path that is already canonical EXCEPT it contains a non-ASCII char
    /// must still borrow (the non-ASCII char itself triggers no transform).
    #[test]
    fn canonicalize_non_ascii_already_canonical_borrows() {
        let p = "c:\\users\\наvöl\\file.txt"; // lowercase, no slash, no trailing dot/space
        assert!(
            matches!(canonicalize_for_denylist(p), Cow::Borrowed(_)),
            "lowercase non-ASCII path with no '/' or trailing dot/space must borrow"
        );
    }

    #[test]
    fn device_volume_classified_as_harddisk() {
        let path = r"\device\harddiskvolume3\windows\system32";
        assert_eq!(
            policy::dev::classify_device(path),
            policy::dev::DeviceKind::HarddiskVolume,
        );
    }

    #[test]
    fn device_volume_not_unknown() {
        let path = r"device\harddiskvolume1\users\test\file.txt";
        assert!(
            !matches!(
                policy::dev::classify_device(path),
                policy::dev::DeviceKind::Unknown
            ),
            "HarddiskVolume must not be Unknown (would be blocked by check_device_block already)"
        );
    }
}

// ---------------------------------------------------------------------------
// status_constant_tests — pin canonical NT status codes.
//
// These tests catch anyone who accidentally changes the canonical value of a
// status code constant. Sibling guard modules import these from here; a typo
// or unit-mismatch would split-brain the sandbox (some guards return
// ACCESS_DENIED, others return some random garbage from the typo).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod status_constant_tests {
    use super::*;

    #[test]
    fn status_access_denied_is_canonical() {
        assert_eq!(STATUS_ACCESS_DENIED, 0xC000_0022_u32 as i32);
    }

    #[test]
    fn status_object_name_not_found_is_canonical() {
        assert_eq!(STATUS_OBJECT_NAME_NOT_FOUND, 0xC000_0034_u32 as i32);
    }

    #[test]
    fn status_privilege_not_held_is_canonical() {
        assert_eq!(STATUS_PRIVILEGE_NOT_HELD, 0xC000_0061_u32 as i32);
    }

    #[test]
    fn status_not_supported_is_canonical() {
        assert_eq!(STATUS_NOT_SUPPORTED, 0xC000_00BB_u32 as i32);
    }
}
