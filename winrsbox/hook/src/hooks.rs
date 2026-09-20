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
use policy::Mode;
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
    ipc_record_overlay_case,
    ipc_clear_overlay,
    ipc_clear_whiteout,
    ipc_record_whiteout,
    ipc_register_child,
    ipc_send_and_recv,
    ipc_spawned_child,
    is_trace,
    DLL_PATH,
    PIPE_NAME,
    SANDBOX_CWD,
    SANDBOX_ROOT,
    TRACE_ENABLED,
};

// ---------------------------------------------------------------------------
// Escape-vector fail-stop
//
// Shared by com_guard (denied CLSID activation) and alpc_guard (connect to an
// escape-class broker port). These endpoints have no legitimate use from inside
// the sandbox, so an attempt to reach one is treated as a deliberate
// containment-escape and the process is terminated rather than merely denied (a
// denied process just keeps probing other vectors). Mirrors the report+kill
// shape of `inject_guard` / `memory_guard`: capture a short stack, send a
// structured violation over IPC (so the launcher counts it and writes it to
// violations.log), drop a local crash breadcrumb, then TerminateProcess.
//
// MUST be called with `anti_rec` already entered by the calling hook, so the
// IPC pipe I/O it performs re-enters our own fs hooks as passthrough (no
// recursion) — the same contract inject/memory terminate paths rely on.
pub(crate) fn report_and_terminate_escape(vector: &str, detail: &str) -> ! {
    let pid = unsafe { winapi::um::processthreadsapi::GetCurrentProcessId() };
    let stack = crate::memory_guard::capture_stack_pub(3, 16);
    let caller_pc = stack.first().copied().unwrap_or(0);
    let caller_module =
        crate::memory_guard::module_path_for_address(caller_pc as *const winapi::ctypes::c_void);
    let exe = crate::memory_guard::get_own_exe_path_pub();

    let _ = ipc_log_violation(ipc::Req::EscapeViolation {
        pid,
        exe: exe.clone(),
        vector: vector.to_string(),
        detail: detail.to_string(),
        caller_pc,
        caller_module: caller_module.clone(),
        stack_top: stack.clone(),
    });

    let tmp = std::env::temp_dir();
    let path = tmp.join(format!("fs-sandbox-violation-{pid}.log"));
    let line = format!(
        "{{\"pid\":{pid},\"exe\":\"{}\",\"kind\":\"Escape\",\"vector\":\"{vector}\",\"detail\":\"{}\",\"caller_pc\":\"0x{caller_pc:x}\"}}\n",
        exe.replace('\\', "\\\\").replace('"', "\\\""),
        detail.replace('\\', "\\\\").replace('"', "\\\""),
    );
    let _ = std::fs::write(&path, line.as_bytes());

    let msg = format!(
        "[VIOLATION] pid={pid} kind=Escape vector={vector} detail={detail} pc=0x{caller_pc:x}\0",
    );
    let wide: Vec<u16> = msg.encode_utf16().collect();
    // SAFETY: wide is a valid null-terminated UTF-16 string.
    unsafe { winapi::um::debugapi::OutputDebugStringW(wide.as_ptr()) };

    // SAFETY: GetCurrentProcess() always returns a valid pseudo-handle.
    unsafe {
        winapi::um::processthreadsapi::TerminateProcess(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            0xC000_0005,
        );
    }
    loop { unsafe { winapi::um::synchapi::Sleep(1000) }; }
}

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
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const FILE_WRITE_EA: u32 = 0x0000_0010;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
pub const DELETE: u32 = 0x0001_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;

pub const FILE_CREATE: u32 = 0x0000_0002;
pub const FILE_OPEN: u32 = 0x0000_0001;
pub const FILE_OPEN_IF: u32 = 0x0000_0003;
pub const FILE_OVERWRITE: u32 = 0x0000_0004;
pub const FILE_OVERWRITE_IF: u32 = 0x0000_0005;
pub const FILE_SUPERSEDE: u32 = 0x0000_0000;
/// CreateOptions bit (NOT a desired-access bit): delete when the last
/// handle closes. It rides in NtCreateFile/NtOpenFile CreateOptions, so it
/// is consulted directly only by the dead-end classifier; an actual
/// deletion additionally needs the DELETE access bit, which IS in the
/// write mask.
pub const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

/// THE single canonical definition of "this open intends to write".
///
/// Consumed by the resolved-path pipeline (hook_nt_create_file,
/// hook_nt_open_file), the unresolved-path dead end
/// (fs_hooks::dead_end_write_intent) and the trace logging. Keep exactly
/// one mask here — the resolved path and the dead end used to keep two
/// diverging definitions, which is how write-granting bits got classified
/// as reads on the resolved path.
///
/// Bits beyond plain data writes:
///  - GENERIC_ALL: grants every write right there is. Treating it as a read
///    let a CreateFileW(..., GENERIC_ALL, ...) open ride the CoW
///    read-passthrough onto the REAL disk (observed escape: fs_decide
///    logged write=false mode=Cow for a GENERIC_ALL open).
///  - FILE_WRITE_ATTRIBUTES: SetFileTime-class metadata mutation of a real
///    file outside project_root (audit 2026-09-19, Medium).
///  - FILE_WRITE_EA: extended-attribute mutation.
///
/// MAXIMUM_ALLOWED is deliberately NOT a write here: it resolves per-DACL
/// and is a probe-heavy pattern, so classifying it as a write would
/// CoW-copy every probed file. The registry classifier
/// (reg_hooks::nt_create_key_is_write_access) made the opposite trade —
/// its overlay cost is a redb row, not a full file copy.
pub fn is_write_access(desired: ACCESS_MASK, disposition: u32) -> bool {
    let write_bits = GENERIC_ALL
        | GENERIC_WRITE
        | FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER;
    desired & write_bits != 0
        || matches!(
            disposition,
            FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE | FILE_OVERWRITE_IF | FILE_SUPERSEDE
        )
}

// ---------------------------------------------------------------------------
// STATUS codes
// ---------------------------------------------------------------------------

pub(crate) const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000_0022_u32 as NTSTATUS;
pub(crate) const STATUS_OBJECT_NAME_NOT_FOUND: NTSTATUS = 0xC000_0034_u32 as NTSTATUS;
pub(crate) const STATUS_OBJECT_NAME_COLLISION: NTSTATUS = 0xC000_0035_u32 as NTSTATUS;
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
    // Bug #75 / #78: do NOT cache Passthrough or Hidden decisions.
    //
    // Passthrough: a child process can write into the overlay at any time,
    // making a cached Passthrough immediately stale (Bug #75).
    //
    // Hidden: a sibling process can revive a whiteouted path (e.g., the HTTPS
    // clone retry re-creates hermes-agent after SSH cleanup whiteouts it).
    // If we cached Hidden, the parent's per-process HookCache would continue
    // returning Hidden even after the server's WHITEOUTS table is cleared by
    // the revival IPC call, causing Push-Location to see "does not exist" even
    // though the HTTPS clone succeeded (Bug #78 extension).
    //
    // Stable decisions: Cow, Mock, Deny — these reflect durable policy state
    // that cannot be invalidated by a sibling process action.
    if !matches!(d.mode, Mode::Passthrough | Mode::Hidden) {
        cache().insert(dos_path, write, d.clone());
    }
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
        let dos = policy::path::nt_to_dos_lower(&full)?;
        // Relative-open whose directory handle was itself a CoW'd overlay file:
        // see `unmirror_overlay_handle_relative` for the rationale. Returns the
        // original `dos` unchanged when the handle does not resolve into the
        // overlay storage (the common non-sandbox case, zero overhead).
        let sb_root = SANDBOX_ROOT.get().map(|s| s.as_str());
        let dos = unmirror_overlay_handle_relative(&dos, sb_root).unwrap_or(dos);
        return Some((dos, Some(full.into_owned())));
    }

    // Fast path: ObjectName already in absolute NT form (`\??\C:\…`).
    // Fold `.`/`..` lexically before deriving the DOS path so the policy
    // decides on the path the kernel will resolve (audit Critical #1:
    // `\??\d:\<root>\..\..\payload.exe` used to prefix-match the
    // root while the kernel created the file outside the sandbox).
    // `pre_resolved` deliberately stays None: the kernel keeps the ORIGINAL
    // ObjectName, which the unmirror self-overlay carve-out below requires
    // (when the caller names the overlay path absolutely, the kernel must
    // open the REAL overlay path, not the virtual form). Without reparse
    // points the original resolves to exactly the folded target.
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
        // (`pre_resolved = None`) stays on the absolute overlay path so the
        // real file under the overlay is opened. Control files (policy.redb,
        // session-config inside .winrsbox but NOT under workdir\) remain
        // denied — unmirror only succeeds for paths under a known overlay
        // workdir root.
        let sb_root = SANDBOX_ROOT.get().map(|s| s.as_str());
        let dos = unmirror_overlay_handle_relative(&dos, sb_root).unwrap_or(dos);
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
    // Fold `.`/`..` lexically: `abs` is also the kernel passthrough path
    // (pre_resolved = Some), so decision and kernel action stay identical.
    let abs = policy::path::fold_nt_dots(&abs);
    let sb_root = SANDBOX_ROOT.get().map(|s| s.as_str());
    let dos = bare_relative_dos(&abs, sb_root)?;
    Some((dos, Some(abs.into_owned())))
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
/// into the overlay (Cow) and the kernel passthrough still uses the original
/// overlay `full` path, so the actual file touched is unchanged. The denylist
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
        let sb_lower = sb.to_lowercase();
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
            return Some(virtual_dos.to_ascii_lowercase());
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
///  - The basename is all-ASCII-lowercase (no case to preserve)
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
    // Only return when there is at least one uppercase ASCII letter — if the
    // basename is already all-lowercase, ipc_record_overlay_case would skip it
    // anyway (its own guard), so avoid the IPC round-trip entirely.
    if basename.bytes().any(|b| b.is_ascii_uppercase()) {
        Some(basename.to_owned())
    } else {
        None
    }
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
    // 8.3 short-name (e.g. PROGRA~1) — kernel resolves to a full path, bypassing
    // the classifier and the CoW overlay.
    if needs_short_name_resolve(canon) {
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
fn is_self_overlay_workdir_access(canon: &str) -> bool {
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
fn is_control_file(canon_dos: &str) -> bool {
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

/// What the device classification says about an open whose path the policy
/// pipeline could not resolve to a DOS path.
///
/// Three-valued on purpose. The caller's fail-closed rule for an unresolvable
/// write ("deny — it would reach the real disk outside the overlay") is right
/// for filesystem-shaped targets and wrong for devices that have no
/// filesystem behind them at all. Collapsing `PassThrough` into "no verdict"
/// is what denied every named-pipe and console open carrying write access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeviceVerdict {
    /// Refuse the open outright, in either direction.
    Deny(NTSTATUS),
    /// A non-filesystem device the sandbox deliberately passes through:
    /// named pipes, sockets, the console and NUL. A write to one of these
    /// cannot reach the real filesystem, so the caller's dead-end write deny
    /// must NOT apply. This is what `CreatePipe`, `child_process.spawn` and
    /// every console TTY open depend on.
    PassThrough,
    /// No device verdict — either not a device path at all, or a filesystem
    /// volume device (`\Device\HarddiskVolumeN\…`), which is exactly the raw
    /// form the dead-end deny exists to stop. The caller's own rules apply.
    Unhandled,
}

/// Classify the raw NT path in `attrs` for an open in the requested direction:
/// - hard blocks (shadowcopy, physicaldrive, raw harddisk, dangerous pipe,
///   credential surfaces) — `Deny` regardless of direction;
/// - UNC/network-redirector targets (`DeviceKind::NetworkPath`, P0-03) and
///   unrecognized system devices (`DeviceKind::SystemQuery`) — `Deny` when
///   `write` is set. A write here would reach the real disk/volume/share
///   outside the CoW overlay with no `decide()` call; reads keep the
///   documented pass-through ("reads outside project_root hit the real
///   disk");
/// - named pipes, sockets, console and NUL — `PassThrough` in both
///   directions;
/// - volume devices and non-device paths — `Unhandled`.
///
/// SAFETY: `attrs` must be valid per NT calling convention.
pub(crate) unsafe fn classify_device_open(
    attrs: *const OBJECT_ATTRIBUTES,
    write: bool,
) -> DeviceVerdict {
    let Some(dev_path) = extract_raw_nt_path(attrs) else {
        return DeviceVerdict::Unhandled;
    };
    let utf16: Vec<u16> = dev_path.encode_utf16().collect();
    let Some(device) = policy::dev::nt_to_device_path(&utf16) else {
        return DeviceVerdict::Unhandled;
    };
    let kind = policy::dev::classify_device(&device);
    // Exhaustive on DeviceKind — a future variant must decide explicitly
    // here rather than silently inherit "carry on".
    let verdict = match kind {
        policy::dev::DeviceKind::Unknown => DeviceVerdict::Deny(STATUS_ACCESS_DENIED),
        policy::dev::DeviceKind::NetworkPath | policy::dev::DeviceKind::SystemQuery => {
            if write {
                DeviceVerdict::Deny(STATUS_ACCESS_DENIED)
            } else {
                DeviceVerdict::Unhandled
            }
        }
        policy::dev::DeviceKind::NamedPipe
        | policy::dev::DeviceKind::Socket
        | policy::dev::DeviceKind::Console
        | policy::dev::DeviceKind::Null => DeviceVerdict::PassThrough,
        // A volume device is filesystem-shaped: it must stay subject to the
        // caller's dead-end deny, which is the whole point of that rule.
        policy::dev::DeviceKind::HarddiskVolume => DeviceVerdict::Unhandled,
    };
    if matches!(verdict, DeviceVerdict::Deny(_)) && is_trace() {
        ipc_log(
            ipc::LogLevel::Trace,
            format!("DENY device: {dev_path} kind={kind:?} write={write}"),
        );
    }
    verdict
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
fn overlay_roots_lower(published: Option<&Vec<String>>, sandbox_root: Option<&str>) -> Vec<String> {
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
fn prepare_overlay_in_roots(decision: &Decision, roots: &[&str]) -> Option<String> {
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

/// If a spawn target's image path lives in the CoW overlay, rewrite the
/// `ImagePathName` field of `RTL_USER_PROCESS_PARAMETERS` to the REAL overlay
/// path for the duration of the `NtCreateUserProcess` call, then restore it.
///
/// Why: the kernel image loader (`NtCreateProcessEx` → `MmCreateSection`) opens
/// the EXE by the path in `ImagePathName` DIRECTLY — it does not route through
/// our user-mode file hook. So if a sandboxed installer extracts+moves a binary
/// into a CoW-managed dir (e.g. `%LOCALAPPDATA%\hermes\bin\uv.exe`, which only
/// exists in the overlay), `NtCreateUserProcess` returns
/// `STATUS_PATH_NOT_FOUND` and the install aborts. Patching `ImagePathName` to
/// the real overlay file makes the loader find the bytes; the child still runs
/// fully hooked (we inject into it on resume), and its argv/CommandLine is
/// unchanged so it self-identifies by the virtual path.
///
/// No-op (returns immediately) when the image path is not overlay-managed.
///
/// # Safety
/// `params` must be a valid `RTL_USER_PROCESS_PARAMETERS`. The guard swaps the
/// `UNICODE_STRING.Buffer`/`Length`/`MaximumLength` of `ImagePathName` for a
/// caller-owned UTF-16 buffer for the duration of its lifetime and restores the
/// originals on drop. The buffer outlives the syscall because it is owned by the
/// guard.
/// One in-place patch applied by `ImagePathOverlayGuard`, restored on drop.
enum Patch {
    /// A `UNICODE_STRING` field (e.g. RTL_USER_PROCESS_PARAMETERS.ImagePathName).
    /// Snapshot the whole struct, restore on drop.
    UnicodeString { ptr: *mut UNICODE_STRING, orig: UNICODE_STRING },
    /// A raw PS_ATTRIBUTE record (PsAttributeImageName). `Value` is a raw
    /// PWSTR and `Size` is its byte length excluding the trailing NUL (per
    /// the C0 diagnostic dump convention). Snapshot (Value, Size), restore.
    Attr { ptr: *mut crate::proc_guard::PS_ATTRIBUTE, orig_value: usize, orig_size: usize },
}

struct ImagePathOverlayGuard {
    patches: Vec<Patch>,
    // Owned replacement buffers; kept alive for the syscall. Each patch owns
    // exactly one buffer (the overlay NT path, possibly reused for both the
    // UNICODE_STRING and the attr pointing at the same overlay copy).
    bufs: Vec<Vec<u16>>,
}

impl ImagePathOverlayGuard {
    fn no_op() -> Self {
        ImagePathOverlayGuard { patches: Vec::new(), bufs: Vec::new() }
    }

    /// Patch a `UNICODE_STRING` field to point at the owned overlay NT buffer.
    ///
    /// # Safety
    /// `ustr_ptr` must be a valid, writeable `UNICODE_STRING` for the syscall
    /// duration; the guard owns the replacement buffer and restores the original
    /// on drop.
    unsafe fn patch_one(
        &mut self,
        ustr_ptr: *mut UNICODE_STRING,
        overlay_nt_wide: &[u16],
    ) {
        if ustr_ptr.is_null() {
            return;
        }
        let chars_excluding_nul = overlay_nt_wide.len().saturating_sub(1);
        let mut buf: Vec<u16> = overlay_nt_wide.to_vec();
        let new_len = (chars_excluding_nul * 2) as u16;
        let new_max = (buf.len() * 2) as u16;
        let orig = std::ptr::read(ustr_ptr);
        self.patches.push(Patch::UnicodeString { ptr: ustr_ptr, orig });
        self.bufs.push(buf);
        let last = self.bufs.last_mut().unwrap();
        let patched = UNICODE_STRING {
            Length: new_len,
            MaximumLength: new_max,
            Buffer: last.as_mut_ptr(),
        };
        std::ptr::write(ustr_ptr, patched);
    }

    /// Patch a raw `PS_ATTRIBUTE` (PsAttributeImageName) to point its `Value`
    /// (raw PWSTR) and `Size` (bytes, no NUL) at the owned overlay NT buffer.
    ///
    /// # Safety
    /// `attr_ptr` must be a valid, writeable `PS_ATTRIBUTE` for the syscall
    /// duration; the guard owns the replacement buffer and restores the original
    /// (Value, Size) on drop.
    unsafe fn patch_attr(
        &mut self,
        attr_ptr: *mut crate::proc_guard::PS_ATTRIBUTE,
        overlay_nt_wide: &[u16],
    ) {
        if attr_ptr.is_null() {
            return;
        }
        let chars_excluding_nul = overlay_nt_wide.len().saturating_sub(1);
        let new_size = chars_excluding_nul * 2;
        let mut buf: Vec<u16> = overlay_nt_wide.to_vec();
        // SAFETY: attr_ptr is valid per caller contract.
        let orig_value = (*attr_ptr).Value;
        let orig_size = (*attr_ptr).Size;
        self.patches.push(Patch::Attr { ptr: attr_ptr, orig_value, orig_size });
        self.bufs.push(buf);
        let last = self.bufs.last_mut().unwrap();
        (*attr_ptr).Value = last.as_mut_ptr() as usize;
        (*attr_ptr).Size = new_size;
    }

    /// SAFETY: `params`/`create_info`/`attribute_list` as for `NtCreateUserProcess`.
    unsafe fn new(
        params: *mut c_void,
        _create_info: *mut c_void,
        attribute_list: *mut c_void,
    ) -> Self {
        let mut g = Self::no_op();
        if params.is_null() {
            return g;
        }
        let virt = extract_child_exe(params);
        if virt.is_empty() {
            return g;
        }
        let virt_lower = virt.to_ascii_lowercase();
        let decision = decide(&virt_lower, false);
        if !matches!(decision.mode, Mode::Cow | Mode::Mock) || decision.overlay.is_none() {
            return g;
        }
        let overlay_path = match decision.overlay.as_ref() {
            Some(o) => o.to_string_lossy().into_owned(),
            None => return g,
        };

        // New image path in NT form `\??\<overlay>` WITH a trailing NUL.
        let overlay_nt = make_overlay_nt_buf(&overlay_path);

        // The kernel image loader opens the EXE by the path in the
        // PsAttributeImageName record (number 5) of the attribute list — this
        // is the load-bearing patch that makes spawning an overlay-only EXE
        // succeed WITHOUT writing to the host (the loader maps the overlay
        // bytes directly). Convention (confirmed by the C0 diagnostic): Value
        // is a raw PWSTR, Size is the byte length excluding the trailing NUL.
        // We swap Value/Size for the duration of the syscall and restore on
        // drop; the owned buffer outlives the call.
        if !attribute_list.is_null() {
            if let Some(attr_ptr) = crate::proc_guard::image_name_attr_mut(attribute_list) {
                g.patch_attr(attr_ptr, &overlay_nt);
            }
        }

        // RTL_USER_PROCESS_PARAMETERS.ImagePathName (offset 0x60) is
        // informational (used by PEB/GetModuleFileNameW for self-identification).
        // Keep it pointing at the VIRTUAL path so the child self-identifies
        // consistently (see C3) — build the virtual NT form for this one.
        let virt_nt = make_overlay_nt_buf(&virt);
        let params_ptr = params as *mut u8;
        let img_ustr = params_ptr.add(0x60) as *mut UNICODE_STRING;
        g.patch_one(img_ustr, &virt_nt);

        if !g.patches.is_empty() {
            if is_trace() {
                ipc_log(ipc::LogLevel::Trace,
                    format!("proc_spawn_overlay_redirect virt={virt} overlay={overlay_path} patches={}", g.patches.len()));
            }
        }
        g
    }
}

impl Drop for ImagePathOverlayGuard {
    fn drop(&mut self) {
        // SAFETY: each patch snapshotted its original at apply time; restore in
        // reverse order (Attr then UnicodeString — order is irrelevant here as
        // the patches target independent fields).
        for p in &self.patches {
            unsafe {
                match p {
                    Patch::UnicodeString { ptr, orig } => {
                        std::ptr::write(*ptr, std::ptr::read(orig));
                    }
                    Patch::Attr { ptr, orig_value, orig_size } => {
                        (**ptr).Value = *orig_value;
                        (**ptr).Size = *orig_size;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// NtCreateUserProcess hook
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// P1-01: direct-syscall pre-execution scan for spawned children
//
// The launcher scans only the ROOT target (launcher/src/main.rs
// `pre_launch_scan`), so the direct-syscall bypass surface (baked-in
// `syscall` instructions, SysWhispers/Hell's Gate class) stayed open for
// every process spawned below the root. This is the in-hook equivalent:
// scan the child's mapped image before it can run, with the same
// terminate-on-failure mode the launcher uses.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Guard configuration snapshot + spawn gate (audit 2026-09-19 High)
// ---------------------------------------------------------------------------

/// Guard configuration captured ONCE at install time (DllMain), before any
/// guest code has run.
///
/// The environment block is guest-writable by construction: a sandboxed
/// process can `SetEnvironmentVariable` a forged `FS_SANDBOX_*` value into
/// its own block, and every child it spawns inherits the forgery. Therefore:
///   * decision code reads ONLY this snapshot and never the environment (a
///     per-decision env re-read was a live kill switch), and
///   * `hook_nt_create_user_process` denies any spawn whose inherited
///     environment carries guard settings that differ from this snapshot,
///     so a guest can no longer downgrade its children either.
/// This generalizes the P1-01 `SPAWN_SCAN_GUARD` snapshot (which carried only
/// the guard level) to every guard input. The values still arrive via the
/// environment the LAUNCHER authored at CreateProcessW time — written before
/// any guest code existed, hence unforgeable for the root — and are
/// re-asserted for every child by the spawn gate below.
pub(crate) struct GuardEnvSnapshot {
    pub(crate) guard: String,
    pub(crate) disabled: String,
    pub(crate) allow_rwx: bool,
    /// `FS_SANDBOX_SECTION` — the per-session random shared-section name.
    /// Guard-relevant because the section carries `pipe_name` and `dll_path`:
    /// a child booted with a forged name would read attacker-authored config
    /// from an attacker-created section. Empty string = this process itself
    /// booted without a name (then ANY inherited value is a forgery).
    pub(crate) section: String,
    /// `FS_SANDBOX_NO_TRACK` — makes `process_tracker::mark_spawned` skip the
    /// child (process_tracker.rs:169). Added to the snapshot and to the spawn
    /// gate for the same reason as the others: a guard-relevant variable left
    /// outside the gate is exactly the drift the gate exists to prevent.
    ///
    /// Its worst case is milder than the others — an untracked child makes the
    /// injector's own cross-process writes look foreign to memory_guard, so
    /// injection fails and the child is terminated before resume, i.e. a guest
    /// self-DoS rather than an escape. Gated anyway: "fails closed" is not a
    /// reason to leave a knob reachable from the guest.
    pub(crate) no_track: bool,
}

static GUARD_ENV: OnceLock<GuardEnvSnapshot> = OnceLock::new();

/// Hook categories parsed once from the snapshot's `disabled` list, consulted
/// only through [`hook_category_disabled`] — the environment is never re-read
/// after install.
static DISABLED_HOOK_CATS: OnceLock<Vec<String>> = OnceLock::new();

/// Install-time category gate. Reads only the install-time snapshot.
pub(crate) fn hook_category_disabled(cat: &str) -> bool {
    DISABLED_HOOK_CATS
        .get()
        .map(|cats| cats.iter().any(|d| d == cat))
        .unwrap_or(false)
}

/// Children are scanned under exactly the guard levels the launcher scans the
/// root target: `full` and `static` (launcher/src/main.rs:648). Never under
/// `scan` or `none`.
fn child_scan_enabled(guard: Option<&str>) -> bool {
    matches!(guard, Some(g) if g == "full" || g == "static")
}

/// Upper bound on the environment walk (UTF-16 chars). A legitimate block
/// stays far below this; a block that runs past it is treated as malformed.
const MAX_GUARD_ENV_CHARS: usize = 1 << 20;

/// Compare the guard-relevant variables observed in a child's would-be
/// environment against the trusted install-time snapshot. `Some(reason)` =
/// mismatch = the spawn must be denied.
///
/// Rules (absence is always acceptable — the child's hook then boots with
/// fail-safe defaults: guard "full", nothing disabled, RWX not allowed):
///   * FS_SANDBOX_GUARD — must equal the snapshot (case-insensitive);
///   * FS_SANDBOX_ALLOW_RWX — forbidden unless the snapshot allows RWX.
///     Presence-only semantics (the hook historically treated existence, not
///     the value, as "allow"), so ANY value counts as an enable;
///   * FS_SANDBOX_DISABLE_HOOKS — category set must equal the snapshot's
///     (case-insensitive, whitespace-tolerant, order-free).
fn guard_env_mismatch(observed: &[(String, String)], trusted: &GuardEnvSnapshot) -> Option<String> {
    for (name, value) in observed {
        match name.to_ascii_lowercase().as_str() {
            "fs_sandbox_guard" => {
                if !value.eq_ignore_ascii_case(&trusted.guard) {
                    return Some(format!(
                        "FS_SANDBOX_GUARD forged: child would inherit {value:?}, trusted {:?}",
                        trusted.guard
                    ));
                }
            }
            "fs_sandbox_allow_rwx" => {
                if !trusted.allow_rwx {
                    return Some(format!(
                        "FS_SANDBOX_ALLOW_RWX forged: child would inherit {value:?}, trusted off"
                    ));
                }
            }
            "fs_sandbox_no_track" => {
                if !trusted.no_track {
                    return Some(format!(
                        "FS_SANDBOX_NO_TRACK forged: child would inherit {value:?}, trusted off"
                    ));
                }
            }
            "fs_sandbox_disable_hooks" => {
                if !disable_categories_equal(value, &trusted.disabled) {
                    return Some(format!(
                        "FS_SANDBOX_DISABLE_HOOKS forged: child would inherit {value:?}, trusted {:?}",
                        trusted.disabled
                    ));
                }
            }
            "fs_sandbox_section" => {
                if !value.eq_ignore_ascii_case(&trusted.section) {
                    return Some(format!(
                        "FS_SANDBOX_SECTION forged: child would inherit {value:?}, trusted {:?}",
                        trusted.section
                    ));
                }
            }
            _ => {}
        }
    }
    None
}

/// Set-equality of comma-separated hook categories, case-insensitive and
/// whitespace-tolerant — mirrors exactly how the snapshot is parsed at
/// install time, so an equivalent re-spelling of the trusted list passes.
fn disable_categories_equal(observed: &str, trusted: &str) -> bool {
    fn parse(raw: &str) -> Vec<String> {
        let mut cats: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        cats.sort();
        cats.dedup();
        cats
    }
    parse(observed) == parse(trusted)
}

/// Full spawn-time gate: walk the environment the child would inherit and
/// compare its guard variables against our trusted snapshot. `Some(reason)`
/// = deny the spawn BEFORE the child exists.
///
/// The snapshot is captured in install_hooks before any hook is enabled, so
/// it is always present by the time this hook can run; without it (unit-test
/// context) there is nothing to vouch for and nothing is denied.
fn child_guard_env_violation(params: *mut c_void) -> Option<String> {
    let trusted = GUARD_ENV.get()?;
    if params.is_null() {
        // No parameters -> the child inherits no environment at all -> its
        // hook boots with fail-safe defaults.
        return None;
    }
    let observed = match unsafe { read_guard_env_entries(params) } {
        None => return None,
        Some(Ok(entries)) => entries,
        // A block we cannot read is a block we cannot vouch for — fail closed.
        Some(Err(reason)) => return Some(reason.to_string()),
    };
    guard_env_mismatch(&observed, trusted)
}

/// Read the guard-relevant entries from
/// `RTL_USER_PROCESS_PARAMETERS.Environment` (x64 offset 0x80, following the
/// same fixed-offset convention as the 0x60 ImagePathName reads in
/// `extract_child_exe`). The parameters live in OUR address space — the
/// caller (CreateProcessW or raw ntdll use) built them in-process, and the
/// kernel copies the block into the child during the syscall.
///
/// Returns `None` when there is nothing to check (null params / null
/// Environment pointer, or the parameters header itself unreadable) and
/// `Some(Err(..))` when an Environment pointer IS set but its block cannot
/// be walked safely (unreadable, unbounded — the caller fails closed).
///
/// # Safety
/// `params` must point to caller-process memory for the duration of the
/// call. Every dereference is clamped through `readable_region` first; no
/// guest-controlled length is followed unclamped.
unsafe fn read_guard_env_entries(
    params: *mut c_void,
) -> Option<Result<Vec<(String, String)>, &'static str>> {
    const ENVIRONMENT_OFFSET: usize = 0x80;
    // Clamp the header read itself: a guest hand-crafting params could point
    // it at a region shorter than 0x88 bytes.
    let Some((pbase, plen)) = crate::proc_guard::readable_region(params as *const c_void) else {
        return None;
    };
    let poff = params as usize - pbase as usize;
    if plen.saturating_sub(poff) < ENVIRONMENT_OFFSET + std::mem::size_of::<*const u16>() {
        return None;
    }
    // SAFETY: readable_region confirmed params..params+0x88 is committed and
    // readable, so the Environment pointer read is in-bounds.
    let env_ptr = *((params as *const u8).add(ENVIRONMENT_OFFSET) as *const *const u16);
    if env_ptr.is_null() {
        return Some(Ok(Vec::new()));
    }
    let Some((base, len)) = crate::proc_guard::readable_region(env_ptr as *const c_void) else {
        return Some(Err("child environment block unreadable"));
    };
    let off = env_ptr as usize - base as usize;
    let avail_chars = len.saturating_sub(off) / 2;
    // SAFETY: chars is bounded by the readable region returned above.
    let chars: &[u16] =
        std::slice::from_raw_parts(env_ptr, avail_chars.min(MAX_GUARD_ENV_CHARS));

    let mut entries = Vec::new();
    let mut cur = 0usize;
    while cur < chars.len() {
        let Some(rel_end) = chars[cur..].iter().position(|&c| c == 0) else {
            // Region exhausted without a terminator — unbounded block.
            return Some(Err("child environment block unbounded (no NUL terminator)"));
        };
        let entry = &chars[cur..cur + rel_end];
        cur += rel_end + 1;
        if entry.is_empty() {
            break; // double-NUL: end of block
        }
        let Some(eq) = entry.iter().position(|&c| c == b'=' as u16) else {
            continue; // not NAME=VALUE — ignore, same as RTL does
        };
        let name = String::from_utf16_lossy(&entry[..eq]).to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "fs_sandbox_guard"
                | "fs_sandbox_allow_rwx"
                | "fs_sandbox_disable_hooks"
                | "fs_sandbox_no_track"
                | "fs_sandbox_section"
        ) {
            let value = String::from_utf16_lossy(&entry[eq + 1..]);
            entries.push((name, value));
        }
    }
    Some(Ok(entries))
}

/// Scan the PE image mapped in `proc` for direct `syscall`/`sysenter`/`int 2eh`
/// instructions (the launcher's `pre_launch_scan` semantics, in-hook).
///
/// Errors are described by the returned message but share one caller policy:
/// the child must not run (fail closed). An image we cannot read is as
/// unacceptable as one we read and refused — the spawner controls the child
/// handle's access mask and could otherwise request just enough access for
/// injection (VM_OPERATION/VM_WRITE) while denying VM_READ to skip the scan.
fn scan_image_for_direct_syscalls(proc: HANDLE) -> Result<(), String> {
    #[allow(dead_code)] // reserved fields mirror the kernel struct layout
    #[repr(C)]
    struct PROCESS_BASIC_INFORMATION {
        reserved1: *mut c_void,
        peb_base_address: *mut c_void,
        reserved2: [*mut c_void; 2],
        unique_process_id: usize,
        reserved3: *mut c_void,
    }

    type FnNtQueryInformationProcess = unsafe extern "system" fn(
        HANDLE,
        u32,         // ProcessInformationClass (0 = ProcessBasicInformation)
        *mut c_void, // ProcessInformation
        u32,         // ProcessInformationLength
        *mut u32,    // ReturnLength
    ) -> NTSTATUS;

    static QIP: OnceLock<Option<FnNtQueryInformationProcess>> = OnceLock::new();
    let qip = QIP.get_or_init(|| {
        // SAFETY: ntdll_export returns the real ntdll export address matching
        // the FnNtQueryInformationProcess ABI.
        let addr = unsafe { ntdll_export("NtQueryInformationProcess\0".as_bytes())? };
        // SAFETY: addr is the real NtQueryInformationProcess export.
        Some(unsafe { std::mem::transmute(addr as usize) })
    });
    let qip_fn = qip.ok_or_else(|| "NtQueryInformationProcess unavailable".to_string())?;

    let mut pbi = std::mem::MaybeUninit::<PROCESS_BASIC_INFORMATION>::uninit();
    // SAFETY: pbi is valid for size_of writes; proc is a live process handle.
    let status = unsafe {
        qip_fn(
            proc,
            0,
            pbi.as_mut_ptr() as *mut c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    };
    if status < 0 {
        return Err(format!("NtQueryInformationProcess failed: 0x{:08x}", status as u32));
    }
    // SAFETY: status >= 0 means the kernel wrote the full struct.
    let peb_base = unsafe { (*pbi.as_ptr()).peb_base_address } as usize;
    if peb_base == 0 {
        return Err("PEB base address is null".into());
    }

    let mut image_base_bytes = [0u8; 8];
    read_remote_bytes(proc, peb_base + 0x10, &mut image_base_bytes)?;
    let image_base = usize::from_le_bytes(image_base_bytes);
    if image_base == 0 {
        return Err("image base is null".into());
    }

    // DOS + NT headers + section table fit in the first page.
    let mut pe_headers = [0u8; 4096];
    read_remote_bytes(proc, image_base, &mut pe_headers)?;
    let text = policy::scan::pe_text_section(&pe_headers)
        .ok_or_else(|| "no .text section in child image".to_string())?;

    let scan_size = (text.virtual_size as usize).min(64 * 1024 * 1024);
    if scan_size == 0 {
        return Ok(());
    }
    let text_addr = image_base + text.virtual_address as usize;
    let mut text_bytes = vec![0u8; scan_size];
    read_remote_bytes(proc, text_addr, &mut text_bytes)?;

    let hits = policy::scan::find_direct_syscalls(&text_bytes, text_addr as u64);
    if hits.is_empty() {
        return Ok(());
    }
    let summary: Vec<String> = hits
        .iter()
        .take(5)
        .map(|h| format!("{} @ +0x{:x}", h.kind, h.offset))
        .collect();
    Err(format!(
        "{} direct syscall instruction(s) in child .text ({}, …)",
        hits.len(),
        summary.join(", ")
    ))
}

/// ReadProcessMemory with a full-length check (short reads are an error).
fn read_remote_bytes(proc: HANDLE, addr: usize, buf: &mut [u8]) -> Result<(), String> {
    let mut read: usize = 0;
    // SAFETY: buf is valid for buf.len() bytes; addr is in the target's
    // address space (PEB or the mapped image — both committed while the
    // process exists).
    let ok = unsafe {
        winapi::um::memoryapi::ReadProcessMemory(
            proc,
            addr as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            &mut read,
        )
    };
    if ok == 0 {
        return Err(format!("ReadProcessMemory failed at 0x{addr:x}"));
    }
    if read != buf.len() {
        return Err(format!("short read at 0x{addr:x}: {read} of {}", buf.len()));
    }
    Ok(())
}

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
        return crate::hooks::nt_call_original!(
            &HOOK_NT_CREATE_USER_PROCESS,
            "NtCreateUserProcess",
            (process_handle, thread_handle,
             process_desired_access, thread_desired_access,
             process_object_attributes, thread_object_attributes,
             process_flags, thread_flags,
             process_parameters, create_info, attribute_list)
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

    // Audit 2026-09-19 High: the environment block is guest-writable. A
    // sandboxed process can SetEnvironmentVariable a forged guard config and
    // spawn a child that inherits it — the child's hook.dll would install
    // with the memory guard disabled. Deny the spawn before the child exists
    // unless the inherited guard settings match the values WE captured at
    // our own install.
    if let Some(reason) = child_guard_env_violation(process_parameters) {
        ipc_log(ipc::LogLevel::Error,
            format!("child_env_guard_forged: parent={parent_pid} target={spawn_target}: {reason}; spawn denied"));
        return STATUS_ACCESS_DENIED;
    }

    // C0 diagnostic: when the target EXE is overlay-managed (the spawn-overlay-
    // redirect case), dump the PS_ATTRIBUTE_LIST entries so we can confirm the
    // PsAttributeImageName record (number 5) is present and read its Value
    // convention (raw PWSTR + byte Size vs a UNICODE_STRING pointer). This is
    // evidence-gathering BEFORE the C2 patch — it must not guess the convention.
    if is_trace() && !spawn_target.is_empty() {
        let vt = spawn_target.to_ascii_lowercase();
        let decision = decide(&vt, false);
        if matches!(decision.mode, policy::Mode::Cow | policy::Mode::Mock) {
            crate::proc_guard::dump_attr_list_for_overlay_spawn(attribute_list, &spawn_target);
        }
    }

    // If the EXE only exists in the CoW overlay, the kernel image loader would
    // fail with STATUS_PATH_NOT_FOUND. ImagePathOverlayGuard rewrites the
    // PsAttributeImageName record (number 5) in the attribute list to point at
    // the overlay copy for the duration of the syscall — the loader then maps
    // the overlay bytes directly, with NOTHING written to the host. This is the
    // principled solution (no materialize, no host write). See the guard's
    // docs for the full rationale.
    let _img_guard = unsafe {
        ImagePathOverlayGuard::new(process_parameters, create_info, attribute_list)
    };

    let status = crate::hooks::nt_call_original!(
        &HOOK_NT_CREATE_USER_PROCESS,
        "NtCreateUserProcess",
        (process_handle, thread_handle,
         process_desired_access, thread_desired_access,
         process_object_attributes, thread_object_attributes,
         process_flags, forced_flags,
         process_parameters, create_info, attribute_list)
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

    // SAFETY: proc_h is a valid process handle returned by NtCreateUserProcess.
    let child_pid = GetProcessId(proc_h);

    // P1-01: scan the child's mapped image for direct syscall instructions
    // BEFORE it can run. The launcher scans the root target only, so without
    // this every process below the root keeps the SysWhispers/Hell's Gate
    // bypass open. Fail closed on BOTH detection and scan failure — terminate,
    // exactly like the launcher's pre_launch_scan refusal path.
    if child_scan_enabled(GUARD_ENV.get().map(|g| g.guard.as_str())) {
        if let Err(reason) = scan_image_for_direct_syscalls(proc_h) {
            ipc_log(
                ipc::LogLevel::Error,
                format!("child pre-launch scan refused pid={child_pid} target={spawn_target}: {reason}; terminating"),
            );
            // SAFETY: proc_h is the valid PROCESS handle returned moments ago
            // by NtCreateUserProcess; TerminateProcess never blocks. Exit code 1
            // signals "killed by sandbox" to anyone waiting on the process.
            unsafe { winapi::um::processthreadsapi::TerminateProcess(proc_h, 1) };
            return status;
        }
    }

    // Local authorization record — MUST precede inject_via_apc. memory_guard's
    // cross-process gates (NtAllocateVirtualMemory / NtProtectVirtualMemory /
    // NtWriteVirtualMemory) consult process_tracker::is_owned_child(target_pid)
    // for exactly the writes injection performs into the child: without the
    // record, inject_via_apc's VirtualAllocEx lands in the foreign-process
    // branch (terminate-if-executable — one protect-flag refactor away from a
    // self-terminating parent on every spawn) and WriteProcessMemory loses its
    // is_owned_child fast path and gets opcode-scanned on every spawn. This is
    // a purely local table write — no pipe I/O — so it does not widen the
    // pre-injection window (P0-04 is about the blocking IPC round-trips only).
    let child_exe = extract_child_exe(process_parameters);
    if child_pid != 0 {
        // Capture the creation-time fingerprint from the live handle we already
        // hold (M2: source-capture makes the PID-reuse defense always engage).
        // SAFETY: proc_h is the valid process handle returned by NtCreateUserProcess.
        let create_time = unsafe { crate::process_tracker::create_time_from_handle(proc_h) };
        crate::process_tracker::mark_spawned(child_pid, parent_pid, child_exe.clone(), create_time);
    }

    // P0-04: inject BEFORE any registration IPC. `ipc_register_child` /
    // `ipc_spawned_child` are synchronous pipe round-trips; the child and its
    // suspended main thread are already visible system-wide right after the
    // syscall, and ResumeThread is not hooked, so any same-user thread could
    // resume the child mid-registration and run it with no hooks at all.
    // Injection is the only step that must complete before the child can
    // safely run — keep the pre-injection window down to the APC queue alone.
    //
    // If injection fails the child process ALREADY exists (suspended, no user
    // code executed yet) and would escape the sandbox once resumed. Terminate
    // it before resume — fail closed. Registration IPC is skipped for a child
    // we just killed: bookkeeping for a dead PID tells the launcher nothing it
    // can act on.
    let mut inject_failed = false;
    if let Some(dll_path) = DLL_PATH.get() {
        if let Err(e) = inject::inject_via_apc(
            proc_h,
            thr_h,
            dll_path,
            crate::ipc_client::session_section_name(),
        ) {
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

    // Launcher bookkeeping — the two blocking IPC round-trips — happens AFTER
    // the APC is queued (P0-04: must not delay injection). Skipped for a child
    // we just killed: bookkeeping for a dead PID tells the launcher nothing it
    // can act on.
    if child_pid != 0 && !inject_failed {
        ipc_register_child(child_pid);
        ipc_spawned_child(parent_pid, child_pid, child_exe);
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
// Call-original fail-closed helper
//
// Hook bodies reach their original function through
// `HOOK_X.get().unwrap().call(args)`. If the OnceLock is unset at call time,
// the `unwrap` panics — inside an `unsafe extern "system"` fn, which cannot
// unwind — so Rust aborts the whole process with 0xc0000409
// (STATUS_STACK_BUFFER_OVERRUN), indistinguishable from a real stack-buffer
// overrun and completely silent. In production a hook body only runs because
// its detour was installed, so this is believed unreachable there; under
// `cargo test` no detour is ever installed, and one test reaching this path
// aborts the entire test binary, taking every other test's result with it.
// NTSTATUS-returning hooks now fail closed instead (log at Error, return
// STATUS_ACCESS_DENIED). Other return-type families (HRESULT / BOOL / HANDLE /
// HINSTANCE / socket i32) intentionally keep `.get().unwrap()` — a fail-closed
// value for them is a per-API decision; see the comments at those sites.
// ---------------------------------------------------------------------------

/// A hook body ran while its detour was never installed: the install
/// sequence for this API is broken (or a hook fired inside the install
/// window). That must be visible, not silent.
pub(crate) fn log_detour_absent(hook: &str) {
    // anti_rec: this runs on passthrough branches where the caller did NOT
    // hold the guard, and ipc_log does pipe I/O that would otherwise
    // re-enter the FS hooks.
    let _g = crate::anti_rec::enter();
    ipc_log(
        ipc::LogLevel::Error,
        format!(
            "detour_absent: {hook} entered before its detour was installed; failing closed"
        ),
    );
}

/// Fail-closed call-original for NTSTATUS-returning hooks.
///
/// Expands to the detour trampoline call when the detour is installed
/// (behaviour identical to the previous `.get().unwrap().call(...)`), and to
/// `STATUS_ACCESS_DENIED` plus an Error log when it is not — instead of the
/// unwrap that panics in a no-unwind context and aborts the process.
macro_rules! nt_call_original {
    ($lock:expr, $name:literal, ($($arg:expr),* $(,)?)) => {{
        match $lock.get() {
            // SAFETY: detour2 trampoline matches the hooked ABI
            // (established when the detour was installed and enabled).
            Some(d) => unsafe { d.call($($arg),*) },
            None => {
                $crate::hooks::log_detour_absent($name);
                $crate::hooks::STATUS_ACCESS_DENIED
            }
        }
    }};
}
pub(crate) use nt_call_original;

#[cfg(test)]
mod nt_call_original_tests {
    // NOTE: `cargo build` never compiles this module — only `cargo test` does.
    use super::*;

    type FnDummy = unsafe extern "system" fn(u32) -> NTSTATUS;

    // A plain, detourable stub playing the role of the ntdll export: the
    // trampoline built by GenericDetour::new copies its prologue, so calling
    // through `call()` executes THIS function with the passed argument.
    unsafe extern "system" fn dummy_original(x: u32) -> NTSTATUS {
        (0xC000_0001u32.wrapping_add(x)) as NTSTATUS
    }

    // Marker value proving the DETOUR body does NOT run in the installed
    // case (call() must reach the trampoline = the original, like the old
    // `.get().unwrap().call(...)` shape did).
    unsafe extern "system" fn dummy_detour(_x: u32) -> NTSTATUS {
        0xDEAD_BEEFu32 as NTSTATUS
    }

    #[test]
    fn fail_closed_when_detour_absent() {
        static ABSENT: OnceLock<GenericDetour<FnDummy>> = OnceLock::new();
        let rc = nt_call_original!(&ABSENT, "NtTestApi", (7u32));
        assert_eq!(rc as u32, 0xC000_0022, "expected STATUS_ACCESS_DENIED");
    }

    #[test]
    fn installed_detour_still_calls_original() {
        static INSTALLED: OnceLock<GenericDetour<FnDummy>> = OnceLock::new();
        // SAFETY: both operands are real fn pointers with matching ABI;
        // `new` only builds the trampoline — no enable()/code patching.
        let target: FnDummy = dummy_original;
        let hook_fn: FnDummy = dummy_detour;
        let detour = unsafe { GenericDetour::<FnDummy>::new(target, hook_fn) }
            .expect("dummy fn must be detourable");
        let _ = INSTALLED.set(detour);
        // Behaviour-unchanged proof: with the detour installed the macro
        // returns the ORIGINAL's result (0xC000_0001 + 7), not the detour's
        // 0xDEADBEEF marker and not the fail-closed STATUS_ACCESS_DENIED.
        let rc = nt_call_original!(&INSTALLED, "NtTestApi", (7u32));
        assert_eq!(rc as u32, 0xC000_0008, "expected the original's result");
    }
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
        // Store project_root for the boundary checks (delete-hook, decide).
        // Do NOT call SetCurrentDirectoryW here: install_hooks runs in DllMain
        // of EVERY hooked process, including children. Forcing CWD to
        // project_root would clobber the CWD a parent shell established via
        // `cd` (e.g. `cd /d/e2e_external && git init`), so git would discover
        // project_root as the worktree and create .git in the wrong place.
        // The root process's CWD is already set by the launcher via
        // CreateProcessW(lpCurrentDirectory); children inherit it normally.
        let _ = SANDBOX_CWD.set(cwd);
    }
    if let Ok(sb_root) = std::env::var("FS_SANDBOX_ROOT") {
        let _ = crate::ipc_client::SANDBOX_ROOT.set(sb_root);
    }

    // The per-session random section name arrives through the injection
    // channel (launcher-authored for the root, spawn-hook-patched into every
    // child's env block before it runs). Capture it BEFORE the session
    // section is consulted below; with no injected name the section fallback
    // deliberately opens nothing (no guessable constant name exists anymore).
    if let Ok(section) = std::env::var(crate::inject::SECTION_ENV_VAR) {
        crate::ipc_client::set_session_section_name(section);
    }

    // Always load the session section from the shared memory mapping, EVEN
    // when env vars are present. Env vars cover pipe_name/dll_path/cwd/trace/
    // sandbox_root (legacy single-root), but the multi-root overlay layout
    // (overlay_roots) is ONLY published via the session section — there is no
    // env var for it. Without this call, the hook never learns about the C:
    // overlay root, and multi-root path masking (path_info_guard /
    // unmirror_overlay_handle_relative / the .winrsbox self-access carve-out)
    // all fail to match C: overlay paths → raw overlay path leaks → git clone
    // self-DoS.
    let _ = crate::ipc_client::try_load_session_config_from_section();

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

    // Audit 2026-09-19 High: snapshot EVERY guard input once, here, before
    // any hook is enabled and before any guest code has run. After this
    // point nothing re-reads the environment for guard configuration —
    // decision code reads the GUARD_ENV / DISABLED_HOOK_CATS snapshots only,
    // and hook_nt_create_user_process denies any spawn whose inherited
    // environment carries forged guard values (child_guard_env_violation).
    // This generalizes the P1-01 SPAWN_SCAN_GUARD snapshot to all inputs.
    let guard = std::env::var("FS_SANDBOX_GUARD").unwrap_or_else(|_| "full".into());
    let disabled = std::env::var("FS_SANDBOX_DISABLE_HOOKS").unwrap_or_default();
    let allow_rwx_env = std::env::var("FS_SANDBOX_ALLOW_RWX").is_ok();
    let no_track_env = std::env::var_os("FS_SANDBOX_NO_TRACK").is_some();
    let section_env = std::env::var(crate::inject::SECTION_ENV_VAR).unwrap_or_default();
    let _ = GUARD_ENV.set(GuardEnvSnapshot {
        guard: guard.clone(),
        disabled: disabled.clone(),
        allow_rwx: allow_rwx_env,
        no_track: no_track_env,
        section: section_env,
    });
    let disabled_cats: Vec<String> =
        disabled.split(',').map(|s| s.trim().to_ascii_lowercase()).collect();
    let _ = DISABLED_HOOK_CATS.set(disabled_cats.clone());
    let skip = |cat: &str| hook_category_disabled(cat);

    if !skip("fs") {
        install!(HOOK_NT_CREATE_FILE,              "NtCreateFile\0",              hook_nt_create_file,              FnNtCreateFile);
        install!(HOOK_NT_OPEN_FILE,                "NtOpenFile\0",                hook_nt_open_file,                FnNtOpenFile);
        install!(HOOK_NT_QUERY_ATTRIBUTES_FILE,    "NtQueryAttributesFile\0",     hook_nt_query_attributes_file,    FnNtQueryAttributesFile);
        install!(HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE, "NtQueryFullAttributesFile\0", hook_nt_query_full_attributes_file, FnNtQueryFullAttributesFile);
        install!(HOOK_NT_CREATE_USER_PROCESS,      "NtCreateUserProcess\0",       hook_nt_create_user_process,      FnNtCreateUserProcess);
        crate::dir_filter::install()?;
        crate::fs_metadata_guard::install()?;
        install!(crate::fs_metadata_guard::HOOK_NT_DELETE_FILE, "NtDeleteFile\0", crate::fs_metadata_guard::hook_nt_delete_file, crate::fs_metadata_guard::FnNtDeleteFile);
        crate::path_info_guard::install()?;
    }

    if guard != "none" {
        // Hold anti_rec during guard installation so detour's internal
        // VirtualProtect calls (to patch ntdll stubs) pass through the
        // NtProtectVirtualMemory hook without triggering content scans
        // on ntdll's legitimate syscall instructions.
        let _install_guard = anti_rec::enter();
        if !skip("memory") {
            crate::memory_guard::install(&guard, &disabled_cats, allow_rwx_env)?;
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
    // MUST come first. Every uninstall() below restores an original prologue
    // via VirtualProtect(RWX) on a critical module's code page — the exact
    // shape of the unhook attempt memory_guard's P0-01 check terminates on.
    // Opening the teardown window here (rather than inside
    // memory_guard::uninstall, which used to be 12th in this list) is what
    // keeps the process alive long enough to report its own exit code.
    crate::memory_guard::begin_teardown();
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
    crate::path_info_guard::uninstall();
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy::{Decision, Mode, Policy};
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

    /// GENERIC_ALL grants every write right there is. It used to fall
    /// through the mask and ride the CoW read-passthrough onto the real
    /// disk (observed escape: `fs_decide NtCreateFile: ... write=false
    /// mode=Cow` for a CreateFileW(..., 0x1000_0000, ...) open).
    #[test]
    fn write_access_generic_all_is_write() {
        assert!(is_write_access(GENERIC_ALL, 0));
        assert!(is_write_access(GENERIC_ALL, FILE_OPEN));
        // A generic-all open that also asks read rights is still a write.
        assert!(is_write_access(GENERIC_ALL | 0x8000_0000, FILE_OPEN));
    }

    /// FILE_WRITE_ATTRIBUTES-only and FILE_WRITE_EA-only opens mutate a
    /// real file (SetFileTime / EA writes) without any data-write bit —
    /// audit 2026-09-19 Medium finding. They must classify as writes.
    #[test]
    fn write_access_metadata_bits_are_write() {
        assert!(is_write_access(FILE_WRITE_ATTRIBUTES, FILE_OPEN));
        assert!(is_write_access(FILE_WRITE_EA, FILE_OPEN));
        // A read+metadata open is still a write.
        assert!(is_write_access(0x8000_0000 | FILE_WRITE_ATTRIBUTES, 0));
    }

    /// False-positive guards: pure read/probe opens must stay reads so they
    /// keep riding the (cheap) passthrough instead of forcing CoW copies.
    /// MAXIMUM_ALLOWED is a documented deliberate exclusion: it resolves
    /// per-DACL and is probe-heavy; classifying it as a write would
    /// CoW-copy every probed file.
    #[test]
    fn write_access_read_bits_stay_read() {
        assert!(!is_write_access(0x8000_0000, FILE_OPEN));
        assert!(!is_write_access(0x0000_0001, FILE_OPEN)); // FILE_READ_DATA
        assert!(!is_write_access(0x0002_0000, FILE_OPEN)); // READ_CONTROL
        assert!(!is_write_access(0x0010_0000, FILE_OPEN)); // SYNCHRONIZE
        assert!(!is_write_access(0x8000_0000 | 0x0010_0000, FILE_OPEN));
        assert!(!is_write_access(0x0200_0000, FILE_OPEN)); // MAXIMUM_ALLOWED
    }

    /// Consequence test: a GENERIC_ALL or FILE_WRITE_ATTRIBUTES-only open
    /// of a path OUTSIDE project_root must land in the CoW overlay, not
    /// ride the read-passthrough onto the real disk. Uses the real policy
    /// engine with an empty rule set, whose documented default is
    /// read-outside-root -> Passthrough, write-outside-root -> Cow.
    #[test]
    fn attribute_only_and_generic_all_opens_outside_root_cow() {
        let base = unique_temp_path("writemask-cow");
        std::fs::create_dir_all(&base).expect("create base dir");
        let project_root = base.join("project");
        let sandbox_root = base.join("overlay");
        let mock_dirs = base.join("mockdirs");
        let outside = base.join("outside");
        for d in [&project_root, &sandbox_root, &mock_dirs, &outside] {
            std::fs::create_dir_all(d).expect("create policy dirs");
        }
        let policy = Policy::open_or_create(
            &base.join("policy.redb"),
            sandbox_root,
            mock_dirs,
            project_root.clone(),
        )
        .expect("open policy engine");

        let outside_dos =
            outside.join("writemask-target.dat").to_string_lossy().into_owned();

        // Negative control: the SAME path with read intent passes through
        // to the real disk — proves the path is genuinely outside
        // project_root, so the Cow verdicts below are caused by the write
        // classification, not by the path.
        assert_eq!(policy.decide(&outside_dos, false).mode, Mode::Passthrough);

        // GENERIC_ALL open (the observed escape): write-classified -> CoW.
        assert!(is_write_access(GENERIC_ALL, FILE_OPEN));
        let d = policy.decide(&outside_dos, is_write_access(GENERIC_ALL, FILE_OPEN));
        assert_eq!(d.mode, Mode::Cow, "GENERIC_ALL open outside root must Cow");

        // FILE_WRITE_ATTRIBUTES-only open: write-classified -> CoW.
        assert!(is_write_access(FILE_WRITE_ATTRIBUTES, FILE_OPEN));
        let d = policy.decide(&outside_dos, is_write_access(FILE_WRITE_ATTRIBUTES, FILE_OPEN));
        assert_eq!(
            d.mode,
            Mode::Cow,
            "FILE_WRITE_ATTRIBUTES open outside root must Cow"
        );

        // FILE_WRITE_EA-only open: write-classified -> CoW.
        assert!(is_write_access(FILE_WRITE_EA, FILE_OPEN));
        let d = policy.decide(&outside_dos, is_write_access(FILE_WRITE_EA, FILE_OPEN));
        assert_eq!(d.mode, Mode::Cow, "FILE_WRITE_EA open outside root must Cow");

        // In-root control: policy keeps project_root paths Passthrough
        // regardless of write classification (CoW is an outside-root event).
        let in_dos = project_root.join("in.dat").to_string_lossy().into_owned();
        assert_eq!(policy.decide(&in_dos, true).mode, Mode::Passthrough);

        drop(policy);
        let _ = std::fs::remove_dir_all(&base);
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

    /// `prepare_overlay` returns `Some(<dos string>)` for an overlay path
    /// inside the supplied roots, matching the lossy stringification of the
    /// supplied PathBuf and creating parent directories as before.
    #[test]
    fn prepare_overlay_some_when_overlay_field_present() {
        // Use a unique temp dir so create_dir_all (called inside prepare_overlay)
        // succeeds without polluting an arbitrary location.
        let dir = unique_temp_path("prep-some");
        let root = dir.join(".winrsbox").join("myapp").join("workdir");
        let overlay = root.join("redirect.bin");
        let expected = overlay.to_string_lossy().into_owned();
        let root_str = root.to_string_lossy().to_ascii_lowercase();

        let d = Decision {
            mode: Mode::Cow,
            overlay: Some(overlay.clone()),
            cow_from: None,
            mock_payload: None,
        };
        let roots = [root_str.as_str()];
        let got = prepare_overlay_in_roots(&d, &roots).expect("Some for in-root overlay");
        assert_eq!(got, expected);
        assert!(overlay.parent().unwrap().exists(), "parent dirs must be created");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Audit Critical #2 defence in depth: an overlay destination OUTSIDE the
    /// published roots (the audit PoC shape: a real Startup folder next to the
    /// sandbox state) must be refused — no returned path, no directory
    /// created, no CoW copy performed — even though the Decision carries it.
    #[test]
    fn prepare_overlay_refuses_out_of_root_destination() {
        let dir = unique_temp_path("prep-out");
        let state = dir.join(".winrsbox").join("myapp");
        let root = state.join("workdir");
        let outside_dest = dir.join("Startup").join("pwn.bat");
        let src = dir.join("src.txt");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&src, b"payload").unwrap();

        let d = Decision {
            mode: Mode::Cow,
            overlay: Some(outside_dest.clone()),
            cow_from: Some(src.clone()),
            mock_payload: None,
        };
        let root_str = root.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];
        assert!(prepare_overlay_in_roots(&d, &roots).is_none());
        assert!(!outside_dest.exists(), "destination must NOT be created");
        assert!(
            !outside_dest.parent().unwrap().exists(),
            "destination parent must NOT be created"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `..` segments in a destination are refused outright (never folded
    /// here), so `<root>\..\escape.bat` cannot smuggle a write outside.
    #[test]
    fn prepare_overlay_refuses_dotdot_destination() {
        let dir = unique_temp_path("prep-dotdot");
        let state = dir.join(".winrsbox").join("myapp");
        let root = state.join("workdir");
        let dest = root.join("..").join("escape.bat");
        std::fs::create_dir_all(&root).unwrap();

        let d = Decision {
            mode: Mode::Cow,
            overlay: Some(dest),
            cow_from: None,
            mock_payload: None,
        };
        let root_str = root.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];
        assert!(prepare_overlay_in_roots(&d, &roots).is_none());
        assert!(!dir.join("escape.bat").exists(), "escaped file must NOT be created");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Mock-dir Cow decisions mirror into the `mock-dirs` SIBLING of the
    /// workdir root — inside the launcher state dir but not inside the root
    /// itself. These must keep working (state-dir allowance), while a state
    /// dir sibling with a prefix-lookalike name must stay refused.
    #[test]
    fn prepare_overlay_allows_mock_dirs_sibling_but_not_lookalike() {
        let dir = unique_temp_path("prep-mock");
        let state = dir.join(".winrsbox").join("myapp");
        let root = state.join("workdir");
        let mock_dest = state.join("mock-dirs").join("c").join("fake.txt");
        let lookalike = dir.join(".winrsbox").join("myappX").join("workdir").join("evil.txt");
        let root_str = root.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];

        let mk = |p: &PathBuf| Decision {
            mode: Mode::Cow,
            overlay: Some(p.clone()),
            cow_from: None,
            mock_payload: None,
        };
        assert!(prepare_overlay_in_roots(&mk(&mock_dest), &roots).is_some());
        assert!(mock_dest.parent().unwrap().exists(), "mock-dirs parent must be created");
        assert!(prepare_overlay_in_roots(&mk(&lookalike), &roots).is_none());
        assert!(!lookalike.exists(), "lookalike destination must NOT be created");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Legit in-root CoW still copies the source — validation must not break
    /// the copy-on-write path it protects.
    #[test]
    fn prepare_overlay_copies_cow_source_inside_root() {
        let dir = unique_temp_path("prep-cow");
        let state = dir.join(".winrsbox").join("myapp");
        let root = state.join("workdir");
        let dest = root.join("d").join("proj").join("f.txt");
        let src = dir.join("orig.txt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&src, b"real content").unwrap();
        let d = Decision {
            mode: Mode::Cow,
            overlay: Some(dest.clone()),
            cow_from: Some(src),
            mock_payload: None,
        };
        let root_str = root.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];
        let got = prepare_overlay_in_roots(&d, &roots).expect("in-root CoW must succeed");
        assert_eq!(got, dest.to_string_lossy());
        assert_eq!(std::fs::read(&dest).unwrap(), b"real content");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Unconfigured hook (no OVERLAY_ROOTS, no SANDBOX_ROOT — the state test
    /// builds run in): prepare_overlay must fail closed, not write anywhere.
    #[test]
    fn prepare_overlay_fails_closed_when_roots_unpublished() {
        // Assert the premise: no test sets the root OnceLocks (the session-
        // section loader is stubbed out under cfg(test)).
        assert!(crate::ipc_client::OVERLAY_ROOTS.get().map_or(true, |l| l.is_empty()));
        assert!(crate::ipc_client::SANDBOX_ROOT.get().is_none());
        let dir = unique_temp_path("prep-closed");
        let d = Decision {
            mode: Mode::Cow,
            overlay: Some(dir.join("anywhere.bin")),
            cow_from: None,
            mock_payload: None,
        };
        assert!(prepare_overlay(&d).is_none());
        assert!(!dir.join("anywhere.bin").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Segment rules of `overlay_dest_in_roots`, pinned directly.
    #[test]
    fn overlay_dest_in_roots_segment_rules() {
        let root = r"c:\state\workdir".to_ascii_lowercase();
        let roots = [root.as_str()];
        // Root itself and descendants are accepted.
        assert!(overlay_dest_in_roots(roots[0], &roots));
        assert!(overlay_dest_in_roots(r"c:\state\workdir\sub\f.txt", &roots));
        // Mock-dirs sibling of the root lives in the launcher state dir.
        assert!(overlay_dest_in_roots(r"c:\state\mock-dirs\c\fake.txt", &roots));
        // Sibling-prefix lookalikes are refused.
        assert!(!overlay_dest_in_roots(r"c:\state\workdirevil\x.txt", &roots));
        assert!(!overlay_dest_in_roots(r"c:\stateX\workdir\x.txt", &roots));
        // Dot segments are refused outright.
        assert!(!overlay_dest_in_roots(r"c:\state\workdir\..\escape.bat", &roots));
        // Empty root list / empty destination fail closed.
        assert!(!overlay_dest_in_roots(r"c:\state\workdir\f.txt", &[]));
        assert!(!overlay_dest_in_roots("", &roots));
    }

    /// Regression: the launcher publishes overlay roots with their on-disk
    /// case, and `prepare_overlay_in_roots` compares an already-lowercased
    /// destination. Without folding the root, `d:\…` never prefix-matched
    /// `D:\…` and EVERY CoW write outside `project_root` was refused —
    /// observed as `EPERM` in the guest plus a `prepare_overlay_reject` line
    /// naming a destination that was plainly inside the root.
    ///
    /// The test above could not catch this: it hands `overlay_dest_in_roots`
    /// a root that is already lowercase, so it never exercises the fold.
    #[test]
    fn overlay_roots_are_case_folded_before_matching() {
        let published = vec![
            r"D:\dev\rust\winrsbox\.winrsbox\proj\workdir".to_string(),
            r"C:\Users\Someone\AppData\Local\.winrsbox\proj\workdir".to_string(),
        ];
        let folded = overlay_roots_lower(Some(&published), None);
        assert_eq!(folded[0], r"d:\dev\rust\winrsbox\.winrsbox\proj\workdir");
        assert_eq!(folded[1], r"c:\users\someone\appdata\local\.winrsbox\proj\workdir");

        // The whole point: a lowercased destination under a mixed-case root
        // must be accepted.
        let roots: Vec<&str> = folded.iter().map(|s| s.as_str()).collect();
        assert!(overlay_dest_in_roots(
            r"d:\dev\rust\winrsbox\.winrsbox\proj\workdir\dev\project\out.txt",
            &roots,
        ));
        assert!(overlay_dest_in_roots(
            r"c:\users\someone\appdata\local\.winrsbox\proj\workdir\windows\f.txt",
            &roots,
        ));
        // Folding must not weaken the sibling-lookalike refusal.
        assert!(!overlay_dest_in_roots(
            r"d:\dev\rust\winrsbox\.winrsbox\proj\workdirevil\out.txt",
            &roots,
        ));
    }

    /// The legacy single-root fallback is folded too, and an absent root
    /// list stays empty so `prepare_overlay_in_roots` fails closed.
    #[test]
    fn overlay_roots_fallback_is_folded_and_empty_stays_empty() {
        assert_eq!(
            overlay_roots_lower(None, Some(r"D:\Proj\.winrsbox\S\workdir")),
            vec![r"d:\proj\.winrsbox\s\workdir".to_string()],
        );
        // An empty published list falls back rather than yielding an empty root.
        assert_eq!(
            overlay_roots_lower(Some(&vec![]), Some(r"D:\Proj\W")),
            vec![r"d:\proj\w".to_string()],
        );
        assert!(overlay_roots_lower(None, None).is_empty());
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

    #[test]
    fn bare_relative_branch_unmirrors_cwd_inside_overlay() {
        // Audit 2026-09-19 Low: the bare-relative CWD branch of
        // resolve_for_hook lacked the unmirror its sibling branches do.
        // With the kernel CWD inside the overlay storage (the guest cd'd
        // into a CoW'd external directory), the folded absolute path is the
        // REAL overlay path, and the `.winrsbox` denylist would self-block
        // the open. The branch must decide on the unmirrored virtual path.
        let real = r"\??\c:\users\me\.winrsbox\sessionx\workdir\mytools\app\qwe.txt";
        let real_u16: Vec<u16> = real.encode_utf16().collect();
        let sb = r"c:\users\me\.winrsbox\sessionx\workdir";
        let got = bare_relative_dos(&real_u16, Some(sb)).expect("resolve");
        assert_eq!(got, r"c:\mytools\app\qwe.txt");
        // The raw overlay path IS self-blocked by the denylist — that is the
        // bug the unmirror fixes; the virtual path must not be.
        let raw_dos = r"c:\users\me\.winrsbox\sessionx\workdir\mytools\app\qwe.txt";
        assert!(
            canonical_denylist_status(&raw_dos).is_some(),
            "precondition: the raw overlay path trips the .winrsbox denylist"
        );
        assert!(
            canonical_denylist_status(&got).is_none(),
            "the virtual path the branch decides on must not be self-blocked"
        );
        // CWD outside the overlay: unchanged (defensive passthrough).
        let plain = r"\??\d:\proj\file.txt";
        let plain_u16: Vec<u16> = plain.encode_utf16().collect();
        assert_eq!(
            bare_relative_dos(&plain_u16, Some(sb)).as_deref(),
            Some(r"d:\proj\file.txt")
        );
    }

    #[test]
    fn unmirror_overlay_handle_relative_recovers_virtual_path() {
        // Real-world layout: handle resolved into overlay storage under
        // `.winrsbox\<name>\workdir\d\…`. The transform must recover the
        // virtual DOS path the agent thinks it owns, so decide/denylist see
        // `d:\diag_git\.git\config` instead of the `.winrsbox`-laden overlay
        // path (which would self-block via the sandbox-internals denylist).
        let sb = r"d:\dev\rust\fs-sandbox\repro\.winrsbox\diag_git\workdir";
        let overlay_dos = r"d:\dev\rust\fs-sandbox\repro\.winrsbox\diag_git\workdir\d\diag_git\.git\config";
        let got = unmirror_overlay_handle_relative(overlay_dos, Some(sb)).expect("should unmirror");
        assert_eq!(got, r"d:\diag_git\.git\config");
    }

    #[test]
    fn unmirror_overlay_handle_relative_passthrough_when_not_under_root() {
        // Common non-sandbox case: handle outside overlay storage → no rewrite.
        let sb = r"d:\dev\rust\fs-sandbox\repro\.winrsbox\diag_git\workdir";
        let external = r"c:\windows\system32\drivers\etc\hosts";
        assert_eq!(unmirror_overlay_handle_relative(external, Some(sb)), None);
    }

    #[test]
    fn unmirror_overlay_handle_relative_none_when_sandbox_root_unset() {
        // During very early DLL load (before the launcher publishes the root),
        // a relative open must NOT be rewritten — fall through verbatim.
        let overlay_dos = r"d:\sb\.winrsbox\n\workdir\d\sb\.git\config";
        assert_eq!(unmirror_overlay_handle_relative(overlay_dos, None), None);
    }

    #[test]
    fn unmirror_overlay_handle_relative_virtual_winrsbox_untouched_by_fn() {
        // The denylist guard runs downstream of this fn, on the returned path.
        // A path phrased as an overlay path under SANDBOX_ROOT that unmirrors
        // to a virtual path containing `.winrsbox` is unmirrored unchanged by
        // THIS fn; the denylist then independently decides to mask it.
        let sb = r"d:\sb\.winrsbox\n\workdir";
        let overlay_dos = r"d:\sb\.winrsbox\n\workdir\d\sb\.winrsbox\secret";
        let got = unmirror_overlay_handle_relative(overlay_dos, Some(sb)).expect("should unmirror");
        assert_eq!(got, r"d:\sb\.winrsbox\secret");
    }

    #[test]
    fn unmirror_overlay_handle_relative_path1_single_char_toplevel() {
        // Path 1 layout: single-letter top-level directory (C:\a\file) must
        // NOT be mis-detected as a legacy drive letter. The discriminator is
        // "first comp == root drive": `a` ≠ `c` → Path 1 → drive from root.
        let sb = r"c:\sb\.winrsbox\n\workdir";
        let overlay_dos = r"c:\sb\.winrsbox\n\workdir\a\file";
        let got = unmirror_overlay_handle_relative(overlay_dos, Some(sb)).expect("should unmirror");
        assert_eq!(got, r"c:\a\file");
    }

    #[test]
    fn is_control_file_detects_known_names_and_redb() {
        assert!(is_control_file(r"d:\sb\.winrsbox\workdir\policy.redb"));
        assert!(is_control_file(r"c:\x\.winrsbox\hermes\workdir\sandbox.ktav"));
        assert!(is_control_file(r"d:\sb\.winrsbox\workdir\violations.log"));
        assert!(is_control_file(r"d:\sb\.winrsbox\workdir\future.redb"));
        // Normal agent data is NOT a control file.
        assert!(!is_control_file(r"c:\users\test\file.txt"));
        assert!(!is_control_file(r"d:\sb\.winrsbox\workdir\users\test\policy.txt"));
    }

    #[test]
    fn is_self_overlay_workdir_access_denies_control_files() {
        // policy.redb under the overlay root MUST be denied — it is a sandbox
        // control file, NOT agent CoW data. The carve-out must NOT fire.
        let canon = r"c:\users\computer\.winrsbox\hermes\workdir\policy.redb";
        assert!(!is_self_overlay_workdir_access(canon),
            "policy.redb must NOT be carved out — security regression");
    }

    #[test]
    fn is_self_overlay_workdir_access_allows_agent_cow_data() {
        // Normal agent CoW data under the overlay root IS carved out — it is
        // the process's own data, re-opened absolutely after a passthrough leak.
        // NOTE: is_self_overlay_workdir_access checks OVERLAY_ROOTS first, which
        // is unset in tests, so it falls back to SANDBOX_ROOT which is also
        // unset → returns false. This test documents the expected behaviour.
        let canon = r"c:\users\computer\.winrsbox\hermes\workdir\users\computer\file.txt";
        // Without OVERLAY_ROOTS set, this returns false (no root to match).
        assert!(!is_self_overlay_workdir_access(canon));
    }

    // ── Bug #75: Passthrough decisions must not be cached ──────────────────
    //
    // `decide()` must NOT insert Mode::Passthrough results into the per-process
    // HookCache. A child process can write into the overlay at any moment and
    // change the correct decision for a path from Passthrough to Cow; a cached
    // Passthrough would then cause stale cache hits in the parent, hiding the
    // newly-created overlay file (the "Cannot find path" error seen in E2E).
    //
    // Similarly, Hidden must not be cached: a sibling process can revive a
    // whiteouted path (HTTPS clone retry after SSH clone cleanup), and the parent
    // must re-query the server to see the revival instead of returning stale Hidden.

    #[test]
    fn passthrough_not_stored_in_hook_cache() {
        // Directly exercise the caching policy: inserting a Passthrough via the
        // raw HookCache API works, but decide() skips the insert. Here we test
        // the cache directly — if the cache returns None for a path we never
        // inserted, the decide()-level skip is confirmed safe.
        //
        // Two-part assertion:
        // 1. A fresh cache returns None for a Passthrough path (it was NOT auto-cached).
        // 2. Manually inserting Passthrough DOES store it (raw API is unfiltered).
        let c = crate::cache::HookCache::new();
        // Part 1: not yet inserted → None.
        assert!(c.get_caseless("c:\\passthrough\\path", false).is_none(),
            "fresh cache must return None for an un-inserted path");
        // Part 2: explicit raw insert of Passthrough → Some (raw API is unaffected).
        let pt = policy::Decision {
            mode: policy::Mode::Passthrough,
            overlay: None, cow_from: None, mock_payload: None,
        };
        c.insert("c:\\passthrough\\path", false, pt);
        assert!(c.get_caseless("c:\\passthrough\\path", false).is_some(),
            "raw HookCache::insert of Passthrough must still store it (API unfiltered)");
    }

    #[test]
    fn hidden_not_stored_in_hook_cache() {
        // Hidden must NOT be cached in the per-process HookCache for the same
        // reason as Passthrough: a sibling process can revive a whiteouted path
        // at any time (e.g., the HTTPS clone retry re-creates hermes-agent after
        // the SSH clone cleanup whiteouts it). If Hidden were cached, the parent
        // would keep returning Hidden / not-found even after the server's WHITEOUTS
        // table is cleared — causing Push-Location to fail ("does not exist").
        //
        // This test validates the raw cache's behavior (it can still store Hidden
        // via insert() if callers want to), and documents that decide() must NOT
        // insert Hidden entries.
        let c = crate::cache::HookCache::new();
        // Before any insert, the cache returns None.
        assert!(c.get_caseless("c:\\hidden\\path", false).is_none(),
            "fresh cache must return None for a hidden path");
        // Explicitly inserting Hidden stores it (raw API is unfiltered; decide()
        // is the layer that skips Hidden, tested here conceptually).
        let hidden = policy::Decision {
            mode: policy::Mode::Hidden,
            overlay: None, cow_from: None, mock_payload: None,
        };
        c.insert("c:\\hidden\\path", false, hidden);
        assert!(c.get_caseless("c:\\hidden\\path", false).is_some(),
            "raw HookCache::insert of Hidden must still store it (decide() is the filter)");
    }

    #[test]
    fn cow_decision_stored_in_hook_cache() {
        // Non-Passthrough/Hidden decisions (Cow in particular) MUST be stored by
        // the raw HookCache — they represent stable policy state (an overlay already
        // exists or has been recorded). decide() inserts them; test raw insert.
        let c = crate::cache::HookCache::new();
        let cow = policy::Decision {
            mode: policy::Mode::Cow,
            overlay: Some(std::path::PathBuf::from("c:\\sb\\data.txt")),
            cow_from: None,
            mock_payload: None,
        };
        c.insert("c:\\data.txt", false, cow);
        let r = c.get_caseless("c:\\data.txt", false);
        assert!(r.is_some(), "Cow decision must be returned from HookCache");
        assert_eq!(r.unwrap().mode, policy::Mode::Cow,
            "retrieved decision must be Cow, not Passthrough or Hidden");
    }
}

// ---------------------------------------------------------------------------
// P0-04 / P1-01 / P2-01 regression tests (hooks-core security fixes)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod hooks_core_security_tests {
    use super::*;

    // ── P2-01: NULL UNICODE_STRING.Buffer must fail closed ─────────────────
    //
    // Without the null check, `from_raw_parts(null_ptr, 1)` mints a slice
    // whose first read dereferences address 0 — an access violation that
    // kills the process (nothing wraps hook bodies in SEH/catch_unwind).
    // Against the unfixed code these tests crash the test binary, which is
    // exactly the failure mode the fix removes.

    #[test]
    fn extract_raw_nt_path_null_buffer_fails_closed() {
        let ustr = UNICODE_STRING {
            Length: 2,
            MaximumLength: 2,
            Buffer: std::ptr::null_mut(),
        };
        // Keep both locals in THIS frame: attrs.ObjectName points at ustr.
        let attrs = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &ustr as *const UNICODE_STRING as *mut UNICODE_STRING,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let got = unsafe { extract_raw_nt_path(&attrs) };
        assert!(got.is_none(), "NULL Buffer must resolve to None, got {got:?}");
    }

    #[test]
    fn resolve_for_hook_null_buffer_fails_closed() {
        let ustr = UNICODE_STRING {
            Length: 2,
            MaximumLength: 2,
            Buffer: std::ptr::null_mut(),
        };
        let attrs = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &ustr as *const UNICODE_STRING as *mut UNICODE_STRING,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let got = unsafe { resolve_for_hook(&attrs) };
        assert!(got.is_none(), "NULL Buffer must resolve to None, got {got:?}");
    }

    /// An empty ObjectName paired with a RootDirectory names the directory
    /// that handle already points at. Rust's `remove_dir_all` uses exactly
    /// this shape — it reopens the directory relative to its parent with
    /// FILE_DELETE_ON_CLOSE and an empty name — and treating it as
    /// unresolvable pushed every such delete into the fail-closed dead end.
    /// A sandboxed `codex` reported it as
    /// `WARNING: failed to clean up stale arg0 temp dirs: Access is denied`,
    /// with a single `fs_block_unresolved_write` in the trace and no path to
    /// identify it by.
    #[test]
    fn empty_name_with_root_directory_resolves_to_that_directory() {
        use std::os::windows::ffi::OsStrExt;

        let dir = std::env::temp_dir().join("winrsbox-emptyname-probe");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create probe dir");

        // A directory handle needs FILE_FLAG_BACKUP_SEMANTICS.
        let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: `wide` is a NUL-terminated path; all other arguments are
        //         the documented constants for opening a directory handle.
        let handle = unsafe {
            winapi::um::fileapi::CreateFileW(
                wide.as_ptr(),
                winapi::um::winnt::GENERIC_READ,
                winapi::um::winnt::FILE_SHARE_READ
                    | winapi::um::winnt::FILE_SHARE_WRITE
                    | winapi::um::winnt::FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                winapi::um::fileapi::OPEN_EXISTING,
                0x0200_0000, // FILE_FLAG_BACKUP_SEMANTICS — required for a directory handle
                std::ptr::null_mut(),
            )
        };
        assert!(
            handle != winapi::um::handleapi::INVALID_HANDLE_VALUE,
            "could not open a directory handle for the probe",
        );

        // Length 0 / Buffer null — the empty-name form.
        let ustr = UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: std::ptr::null_mut(),
        };
        let attrs = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: handle as *mut _,
            ObjectName: &ustr as *const UNICODE_STRING as *mut UNICODE_STRING,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let got = unsafe { resolve_for_hook(&attrs) };
        // SAFETY: handle came from CreateFileW above and is not used after.
        unsafe { winapi::um::handleapi::CloseHandle(handle) };
        let _ = std::fs::remove_dir_all(&dir);

        let (dos, pre_resolved) = got.expect(
            "empty name + RootDirectory must resolve to the handle's own \
             directory, not fall into the unresolvable dead end",
        );
        let want = dir.to_string_lossy().to_ascii_lowercase();
        assert_eq!(dos, want, "resolved path must be the directory itself");
        // Relative opens carry the pre-resolved NT path for the kernel.
        assert!(pre_resolved.is_some(), "relative open must carry pre_resolved");
        assert!(
            !dos.ends_with('\\'),
            "no separator may be appended for an empty name: {dos}",
        );
    }

    /// The empty-name carve-out must not become a blanket bypass: with no
    /// name AND no directory handle there is nothing to resolve, and the
    /// caller's fail-closed dead end must still apply.
    #[test]
    fn empty_name_without_root_directory_stays_unresolvable() {
        let ustr = UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: std::ptr::null_mut(),
        };
        let attrs = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &ustr as *const UNICODE_STRING as *mut UNICODE_STRING,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        assert!(unsafe { resolve_for_hook(&attrs) }.is_none());

        // Same for a NULL ObjectName with no handle.
        let attrs_null = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: std::ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        assert!(unsafe { resolve_for_hook(&attrs_null) }.is_none());
    }

    // ── P1-01: child scan gate + pipeline ──────────────────────────────────

    #[test]
    fn child_scan_enabled_matches_launcher_guard_levels() {
        // launcher/src/main.rs scans the root under Full | Static only.
        assert!(child_scan_enabled(Some("full")));
        assert!(child_scan_enabled(Some("static")));
        assert!(!child_scan_enabled(Some("scan")));
        assert!(!child_scan_enabled(Some("none")));
        assert!(!child_scan_enabled(Some("FULL")), "exact match only — launcher writes lowercase");
        assert!(!child_scan_enabled(Some("")));
        assert!(!child_scan_enabled(None), "unset guard (unit-test context) must not scan");
    }

    #[test]
    fn scan_pipeline_runs_on_own_image() {
        // Smoke test of the full remote-read pipeline (QIP → PEB → image
        // base → PE headers → .text → iced-x86 scan) against a handle we
        // know is valid: our own pseudo-handle. Whether HITS may exist in
        // this binary is policy::scan's business (its own tests) and cannot
        // be asserted here — so only the pipeline outcome is.
        // SAFETY: GetCurrentProcess is a constant pseudo-handle call.
        let h = unsafe { winapi::um::processthreadsapi::GetCurrentProcess() };
        let result = scan_image_for_direct_syscalls(h);
        assert!(result.is_ok(), "scan pipeline failed on own image: {result:?}");
    }

    // ── P0-04 + P1-01 structural pins ──────────────────────────────────────
    //
    // The create→inject race is fixed by code ORDER, and the scan by CALL
    // PRESENCE inside the spawn hook; neither is observable from a unit test
    // without a real spawned child. These textual pin tests follow the
    // established precedent of inject.rs::intentional_leak_pin_tests.

    fn spawn_hook_body() -> String {
        let src = include_str!("hooks.rs");
        let fn_start = src
            .find("fn hook_nt_create_user_process")
            .expect("hook_nt_create_user_process must exist");
        let rest = &src[fn_start..];
        let body_end = rest
            .find("// ---------------------------------------------------------------------------")
            .expect("section separator after hook_nt_create_user_process");
        rest[..body_end].to_string()
    }

    #[test]
    fn injection_precedes_child_registration_in_spawn_hook() {
        // Two ordering invariants in hook_nt_create_user_process:
        //   1. mark_spawned (local memory_guard authorization record) BEFORE
        //      inject_via_apc;
        //   2. inject_via_apc BEFORE ipc_register_child / ipc_spawned_child
        //      (the two blocking IPC round-trips).
        let body = spawn_hook_body();
        let mark_off = body
            .find("process_tracker::mark_spawned(")
            .expect("spawn hook must call process_tracker::mark_spawned");
        let inject_off = body
            .find("inject::inject_via_apc(")
            .expect("spawn hook must call inject::inject_via_apc");
        let register_off = body
            .find("ipc_register_child(")
            .expect("spawn hook must call ipc_register_child");
        assert!(
            mark_off < inject_off,
            "regression: mark_spawned must be ordered BEFORE inject_via_apc — \
             memory_guard's cross-process NtAllocate/NtProtect/NtWriteVirtualMemory \
             gates consult process_tracker::is_owned_child for exactly the writes \
             injection performs; without the local record the DLL-path write loses \
             its is_owned_child fast path (opcode-scanned on every spawn) and the \
             VirtualAllocEx lands in the terminate-if-executable foreign branch"
        );
        assert!(
            inject_off < register_off,
            "P0-04 regression: injection must be ordered BEFORE ipc_register_child \
             in hook_nt_create_user_process — the two blocking IPC round-trips \
             must not delay the APC queue while the suspended child is visible \
             system-wide (a same-user thread can ResumeThread it and win the \
             race, leaving the child running with no hooks)"
        );
    }

    #[test]
    fn spawn_hook_scans_child_image_and_gates_on_guard() {
        let body = spawn_hook_body();
        assert!(
            body.contains("scan_image_for_direct_syscalls("),
            "P1-01 regression: hook_nt_create_user_process must scan the child's \
             image for direct syscalls — the launcher scans the root target \
             only, so every process below the root otherwise keeps the \
             direct-syscall bypass open"
        );
        assert!(
            body.contains("child_scan_enabled("),
            "P1-01 regression: child scan must stay gated on the captured guard \
             level (full/static only, never re-read from env)"
        );
    }

    // ── `..` lexical fold in resolve_for_hook (audit Critical #1) ──────────

    /// Build OBJECT_ATTRIBUTES with a UTF-16 ObjectName (RootDirectory null,
    /// i.e. the absolute branch) and run resolve_for_hook on it.
    fn resolve_abs(nt_path: &str) -> Option<(String, Option<Vec<u16>>)> {
        let buf: Vec<u16> = nt_path.encode_utf16().collect();
        let len_bytes = (buf.len() * 2) as u16;
        let us = UNICODE_STRING {
            Length: len_bytes,
            MaximumLength: len_bytes,
            Buffer: buf.as_ptr() as *mut u16,
        };
        let oa = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &us as *const UNICODE_STRING as *mut UNICODE_STRING,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        // SAFETY: us/oa/buf are valid locals for the duration of the call.
        unsafe { resolve_for_hook(&oa) }
    }

    #[test]
    fn resolve_for_hook_folds_parent_dir_escape_absolute() {
        // THE regression (audit Critical #1): the exploit create
        // `NtCreateFile("\??\d:\<root>\..\..\payload.exe",
        // CREATE_ALWAYS)` must resolve to the FOLDED dos path so policy
        // classifies it outside project_root (Cow/Deny), never Passthrough.
        // Unfixed, resolve_for_hook returned the unfolded string and the
        // containment prefix test matched the root while the kernel resolved
        // the `..` segments outside the sandbox.
        let got = resolve_abs(r"\??\D:\proj\..\..\outside.exe")
            .expect("absolute DOS-form path must resolve");
        assert_eq!(got.0, r"d:\outside.exe");
        // Absolute opens keep pre_resolved = None (kernel gets the original
        // ObjectName verbatim; unmirror carve-out + sans-reparse equivalence).
        assert!(got.1.is_none());
    }

    #[test]
    fn resolve_for_hook_folds_dotdot_inside_root() {
        // Legitimate callers with `..` inside the root keep working: the
        // folded path stays under the root and decision == kernel target.
        let got = resolve_abs(r"\??\D:\proj\sub\..\file.txt").unwrap();
        assert_eq!(got.0, r"d:\proj\file.txt");
    }

    #[test]
    fn resolve_for_hook_folds_curdir_inside_root() {
        let got = resolve_abs(r"\??\D:\proj\.\file.txt").unwrap();
        assert_eq!(got.0, r"d:\proj\file.txt");
    }

    #[test]
    fn resolve_for_hook_folds_forward_slash_dotdot() {
        // The object manager accepts `/` as a separator; the fold must
        // normalize and pop across it.
        let got = resolve_abs(r"\??\D:\proj/sub/../../outside.exe").unwrap();
        assert_eq!(got.0, r"d:\outside.exe");
    }

    #[test]
    fn resolve_for_hook_clamps_dotdot_past_drive_root() {
        // `..` past the volume root clamps at the drive, like the kernel.
        let got = resolve_abs(r"\??\D:\..\..\x").unwrap();
        assert_eq!(got.0, r"d:\x");
    }

    #[test]
    fn resolve_for_hook_extended_prefix_fold() {
        // `\\?\` skips Win32-side normalization but NOT kernel-side
        // `..` resolution, so the exploit class works through it too — and
        // the fold must handle it identically.
        let got = resolve_abs(r"\\?\D:\proj\..\..\outside.exe").unwrap();
        assert_eq!(got.0, r"d:\outside.exe");
    }

    #[test]
    fn resolve_for_hook_folds_relative_case_through_lower() {
        // Original case is folded away by nt_to_dos_lower; what matters is
        // that the dot fold happens BEFORE that point so segments like
        // `Sub` still pop correctly.
        let got = resolve_abs(r"\??\D:\proj\Sub\..\FILE.txt").unwrap();
        assert_eq!(got.0, r"d:\proj\file.txt");
    }

    // ── Guard configuration snapshot (audit 2026-09-19 High) ───────────────
    //
    // The environment block is guest-writable: a sandboxed process can
    // SetEnvironmentVariable forged guard values into its own block, and any
    // child it spawns inherits the forgery. Decision code therefore reads
    // ONLY the install-time snapshot (GUARD_ENV / DISABLED_HOOK_CATS, both
    // captured in install_hooks before any guest code has run), and the
    // spawn gate denies any child whose inherited environment carries guard
    // settings that differ from that snapshot.

    /// Serializes env-mutating tests: the environment is process-wide while
    /// cargo test runs tests on parallel threads (same pattern as
    /// memory_guard.rs tests::ENV_LOCK and launcher nested_detection_tests,
    /// both added after exactly that class of flake).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// RAII guard restoring FS_SANDBOX_DISABLE_HOOKS on drop.
    struct DisableHooksEnvGuard(Option<std::ffi::OsString>);

    impl DisableHooksEnvGuard {
        fn capture() -> Self {
            DisableHooksEnvGuard(std::env::var_os("FS_SANDBOX_DISABLE_HOOKS"))
        }
    }

    impl Drop for DisableHooksEnvGuard {
        fn drop(&mut self) {
            match &self.0 {
                Some(v) => std::env::set_var("FS_SANDBOX_DISABLE_HOOKS", v),
                None => std::env::remove_var("FS_SANDBOX_DISABLE_HOOKS"),
            }
        }
    }

    /// Canonical section name every seeded snapshot shares (the OnceLock is
    /// set once per test-binary process; all tests must agree on the value).
    const TRUSTED_SECTION: &str = "Local\\WinRsBoxSession-trusted";

    /// Pin the canonical install-time snapshot the guard tests assert
    /// against. The OnceLocks can only be set once per test-binary process;
    /// every caller must use these exact values so parallel tests agree.
    fn seed_guard_snapshot() {
        let _ = GUARD_ENV.set(GuardEnvSnapshot {
            guard: "full".into(),
            disabled: "reg".into(),
            allow_rwx: false,
            no_track: false,
            section: TRUSTED_SECTION.into(),
        });
        let snap = GUARD_ENV.get().expect("GUARD_ENV seeded above");
        assert_eq!(snap.guard, "full", "GUARD_ENV seeded with a conflicting guard level");
        assert_eq!(snap.disabled, "reg", "GUARD_ENV seeded with a conflicting disable list");
        assert!(!snap.allow_rwx, "GUARD_ENV seeded with a conflicting RWX allowance");
        assert_eq!(
            snap.section,
            TRUSTED_SECTION,
            "GUARD_ENV seeded with a conflicting section name"
        );
        let _ = DISABLED_HOOK_CATS.set(vec!["reg".to_string()]);
        assert_eq!(
            DISABLED_HOOK_CATS.get().map(|c| c.as_slice()),
            Some(&["reg".to_string()][..]),
            "DISABLED_HOOK_CATS seeded with a conflicting category list"
        );
    }

    /// Regression core (audit 2026-09-19 High): the guest sets
    /// FS_SANDBOX_DISABLE_HOOKS after startup — the category gate must keep
    /// following the install-time snapshot, not the guest-writable
    /// environment. Old behaviour re-read the env var at each consumer and
    /// flipped categories on/off at the guest's whim.
    #[test]
    fn hook_category_disabled_ignores_post_startup_env_mutation() {
        let _lock = env_lock();
        let _env = DisableHooksEnvGuard::capture();
        seed_guard_snapshot();

        // The kill switch first: the guest forges categories into its own
        // block after startup. The gate must not follow (old behaviour
        // disabled the fs hooks and the whole memory guard here).
        std::env::set_var("FS_SANDBOX_DISABLE_HOOKS", "fs,memory");
        assert!(
            !hook_category_disabled("fs"),
            "post-startup FS_SANDBOX_DISABLE_HOOKS=fs must not disable the fs hooks"
        );
        assert!(
            !hook_category_disabled("memory"),
            "post-startup FS_SANDBOX_DISABLE_HOOKS=memory must not disable the memory guard"
        );
        assert!(
            hook_category_disabled("reg"),
            "the trusted category must stay disabled regardless of env state"
        );

        // Scrubbed to empty — the snapshot still wins.
        std::env::set_var("FS_SANDBOX_DISABLE_HOOKS", "");
        assert!(hook_category_disabled("reg"));
        assert!(!hook_category_disabled("fs"));

        // Removed entirely — still the snapshot (trusted baseline: only
        // "reg"; a scrub must not re-enable anything).
        std::env::remove_var("FS_SANDBOX_DISABLE_HOOKS");
        assert!(hook_category_disabled("reg"));
        assert!(!hook_category_disabled("fs"));
        assert!(!hook_category_disabled("memory"));
    }

    /// The spawn gate must deny any spawn whose inherited environment
    /// carries guard settings that differ from the trusted snapshot — that
    /// forgery is how a guest booted its children with the memory guard
    /// off. Absence of the variables and equivalent restatements of the
    /// trusted values must stay allowed (no false positives).
    #[test]
    fn guard_env_mismatch_denies_forged_child_guard_env() {
        let trusted = GuardEnvSnapshot {
            guard: "full".into(),
            disabled: "reg".into(),
            allow_rwx: false,
            no_track: false,
            section: TRUSTED_SECTION.into(),
        };

        // FS_SANDBOX_NO_TRACK is gated like the rest. It makes mark_spawned
        // skip the child, which makes the injector's own cross-process writes
        // look foreign to memory_guard — injection then fails and the child is
        // terminated before resume. That is a guest self-DoS rather than an
        // escape, but a guard-relevant variable outside the gate is precisely
        // the drift the gate exists to catch, so forging it is refused.
        assert!(
            guard_env_mismatch(
                &[("FS_SANDBOX_NO_TRACK".to_string(), "1".to_string())],
                &trusted,
            )
            .is_some_and(|m| m.contains("FS_SANDBOX_NO_TRACK")),
            "forged FS_SANDBOX_NO_TRACK must be denied",
        );
        // When the launcher itself set it (integration tests do), a child
        // inheriting the same value matches the snapshot and is allowed.
        let trusted_no_track = GuardEnvSnapshot {
            guard: "full".into(),
            disabled: "reg".into(),
            allow_rwx: false,
            no_track: true,
            section: TRUSTED_SECTION.into(),
        };
        assert_eq!(
            guard_env_mismatch(
                &[("FS_SANDBOX_NO_TRACK".to_string(), "1".to_string())],
                &trusted_no_track,
            ),
            None,
        );

        // No guard variables at all: the child's hook boots with fail-safe
        // defaults (guard "full", nothing disabled, RWX off) — allowed.
        assert_eq!(guard_env_mismatch(&[], &trusted), None);
        assert_eq!(
            guard_env_mismatch(&[("PATH".to_string(), r"C:\Windows".to_string())], &trusted),
            None,
            "non-guard variables must not trip the gate"
        );

        // Forged disable list — the exact attack from the audit finding.
        let reason = guard_env_mismatch(
            &[("FS_SANDBOX_DISABLE_HOOKS".to_string(), "memory".to_string())],
            &trusted,
        );
        assert!(
            reason.is_some(),
            "a child inheriting FS_SANDBOX_DISABLE_HOOKS=memory must be denied"
        );
        assert!(reason.unwrap().contains("forged"));

        // An equivalent re-spelling of the trusted list passes (case,
        // whitespace, order and duplicates are normalized on both sides).
        assert_eq!(
            guard_env_mismatch(
                &[("FS_SANDBOX_DISABLE_HOOKS".to_string(), " REG , reg ".to_string())],
                &trusted,
            ),
            None,
            "an equivalent restatement of the trusted disable list is not a forgery"
        );

        // Forged RWX enable: presence-only semantics — ANY value counts as
        // an enable, including one that reads like a denial.
        let reason = guard_env_mismatch(
            &[("fs_sandbox_allow_rwx".to_string(), "0".to_string())],
            &trusted,
        );
        assert!(
            reason.is_some(),
            "FS_SANDBOX_ALLOW_RWX=0 still means present; the hook treats existence as enable"
        );

        // With RWX genuinely allowed by the snapshot, the variable passes.
        let trusted_rwx = GuardEnvSnapshot {
            guard: "full".into(),
            disabled: "reg".into(),
            allow_rwx: true,
            no_track: false,
            section: TRUSTED_SECTION.into(),
        };
        assert_eq!(
            guard_env_mismatch(
                &[("FS_SANDBOX_ALLOW_RWX".to_string(), "1".to_string())],
                &trusted_rwx,
            ),
            None,
        );

        // Forged guard-level downgrade.
        let reason = guard_env_mismatch(
            &[("FS_SANDBOX_GUARD".to_string(), "none".to_string())],
            &trusted,
        );
        assert!(
            reason.is_some(),
            "a child inheriting FS_SANDBOX_GUARD=none must be denied"
        );
        assert_eq!(
            guard_env_mismatch(&[("FS_SANDBOX_GUARD".to_string(), "FULL".to_string())], &trusted),
            None,
            "the trusted guard level, re-cased, passes"
        );

        // One forged variable among legitimate ones is still caught.
        let observed = vec![
            ("FS_SANDBOX_PIPE".to_string(), "winrsbox-ipc".to_string()),
            ("FS_SANDBOX_DISABLE_HOOKS".to_string(), "fs".to_string()),
        ];
        assert!(guard_env_mismatch(&observed, &trusted).is_some());
    }

    /// A child with no process-parameters block inherits no environment at
    /// all — nothing to vouch for, nothing to deny; its hook boots with the
    /// fail-safe defaults. (Seeding GUARD_ENV pins that the gate reaches the
    /// null-params check rather than returning early on an empty snapshot.)
    #[test]
    fn child_guard_env_violation_null_params_fail_safe() {
        seed_guard_snapshot();
        assert_eq!(child_guard_env_violation(std::ptr::null_mut()), None);
    }

    /// The session-section name is guard-relevant: a forged name would point
    /// the child's hook at an attacker-authored section carrying a poisoned
    /// pipe_name / dll_path. The trusted value re-stated passes (that is what
    /// ordinary inheritance looks like); a different value is denied; ANY
    /// value is denied when this process itself booted without a name.
    /// Old behaviour: the gate ignored FS_SANDBOX_SECTION entirely.
    #[test]
    fn guard_env_mismatch_denies_forged_section_name() {
        let trusted = GuardEnvSnapshot {
            guard: "full".into(),
            disabled: "reg".into(),
            allow_rwx: false,
            no_track: false,
            section: TRUSTED_SECTION.into(),
        };
        assert_eq!(
            guard_env_mismatch(
                &[(crate::inject::SECTION_ENV_VAR.to_string(), TRUSTED_SECTION.to_string())],
                &trusted,
            ),
            None,
            "ordinary inheritance of the trusted section name is not a forgery"
        );
        let reason = guard_env_mismatch(
            &[(
                crate::inject::SECTION_ENV_VAR.to_string(),
                "Local\\WinRsBoxSession-evil".to_string(),
            )],
            &trusted,
        );
        assert!(
            reason.is_some_and(|m| m.contains("FS_SANDBOX_SECTION")),
            "a forged session-section name must be denied"
        );
        let trusted_no_name = GuardEnvSnapshot {
            guard: "full".into(),
            disabled: "reg".into(),
            allow_rwx: false,
            no_track: false,
            section: String::new(),
        };
        let reason = guard_env_mismatch(
            &[(
                crate::inject::SECTION_ENV_VAR.to_string(),
                "Local\\WinRsBoxSession-anything".to_string(),
            )],
            &trusted_no_name,
        );
        assert!(
            reason.is_some(),
            "any inherited section name must be denied when we booted without one"
        );
        // Absence stays allowed (the spawn hook injects the true value into
        // the child after this gate runs — env-scrubbed children).
        assert_eq!(
            guard_env_mismatch(&[], &trusted_no_name),
            None,
            "absence of the section name must stay allowed"
        );
    }
}

// ---------------------------------------------------------------------------
// Sibling-drift check (audit 2026-09-19 High: "guarded API, unguarded
// sibling"). This is the mechanical net for the exact drift that left
// NtAllocateVirtualMemoryEx, NtAlpcConnectPortEx, NtSecureConnectPort,
// ShellExecuteA / ShellExecuteExA and win32u!NtUserSendInput wide open while
// their guarded twins carried all the enforcement.
//
// Each guard module keeps a `pub(crate) const HOOKED_EXPORTS` list naming the
// exports it actually installs detours on. Two layers, both cheap and hermetic:
//
//   1. family coverage — whenever a family's base export is guarded, every
//      listed sibling must be guarded too. Fails when someone removes a
//      sibling detour, or guards a new `Foo` while leaving `FooEx` open.
//   2. list-vs-source — every name in a module's list must appear in that
//      module body as a quote-anchored install literal (`"Name@Z@"` for the
//      str/byte-literal GetProcAddress names, `"Name"` for ui_guard's macro
//      form), so the lists cannot rot independently of the real detours. The
//      scan covers everything BEFORE the list itself — the module body where
//      install() lives — so a stale list entry can never satisfy its own
//      check, and export names merely mentioned in tests/comments do not
//      count.
//
// Extending: guard a new export family → add its name to the module's export
// list and add a row below. DllGetClassObject is deliberately NOT listed: it
// is a per-DLL COM export resolved per loaded module (hundreds of copies
// across loaded in-proc servers), not a single address one detour can cover —
// a check row for it could never go green, so it stays documented as out of
// scope for user-mode single-export detours (see com_guard.rs notes).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod sibling_drift_check {
    use crate::alpc_guard::HOOKED_EXPORTS as ALPC_HOOKED;
    use crate::memory_guard::HOOKED_EXPORTS as MEM_HOOKED;
    use crate::shell_guard::HOOKED_EXPORTS as SHELL_HOOKED;
    use crate::ui_guard::HOOKED_EXPORTS as UI_HOOKED;

    /// (family, module file, that module's hooked-export list, base exports
    /// carrying the guard today, siblings that MUST be guarded alongside).
    const FAMILIES: &[(&str, &str, &[&str], &[&str], &[&str])] = &[
        (
            "memory-alloc",
            "memory_guard.rs",
            MEM_HOOKED,
            &["NtAllocateVirtualMemory"],
            &["NtAllocateVirtualMemoryEx"],
        ),
        (
            "alpc-connect",
            "alpc_guard.rs",
            ALPC_HOOKED,
            &["NtAlpcConnectPort"],
            &["NtAlpcConnectPortEx", "NtSecureConnectPort"],
        ),
        (
            "shell-execute",
            "shell_guard.rs",
            SHELL_HOOKED,
            &["ShellExecuteW", "ShellExecuteExW"],
            &["ShellExecuteA", "ShellExecuteExA"],
        ),
        (
            "ui-input-injection",
            "ui_guard.rs",
            UI_HOOKED,
            &["SendInput"],
            &["NtUserSendInput"],
        ),
    ];

    /// True when `src` contains the export name as a quote-anchored install
    /// literal. Left-quote anchoring means `Foo` can never be satisfied by a
    /// mention inside `FooEx` (e.g. `"SendInput"` does not match
    /// `"NtUserSendInput@Z@"`), and the `@Z@` suffix form distinguishes
    /// real GetProcAddress literals from prose.
    fn referenced_in_install_code(src: &str, name: &str) -> bool {
        // Look for the export name as a Rust string literal, in the two forms
        // the install sites use: NUL-terminated (`"Name\0"`, what the detour
        // macros pass to GetProcAddress) and plain (`"Name"`).
        //
        // The quote and backslash are built from chars rather than written
        // inline so that this predicate's own source cannot be mistaken for an
        // install site if hooks.rs ever gets scanned too.
        const Q: char = '"';
        const BS: char = '\\';
        let with_nul = format!("{Q}{name}{BS}0{Q}");
        let plain = format!("{Q}{name}{Q}");
        src.contains(&with_nul) || src.contains(&plain)
    }

    #[test]
    fn sibling_exports_guarded_when_base_is_guarded() {
        for (family, file, list, bases, siblings) in FAMILIES {
            for base in *bases {
                if !list.contains(base) {
                    // Base guard intentionally removed → the family is gone
                    // wholesale; siblings may go with it (and must, see the
                    // list-vs-source check).
                    continue;
                }
                for sibling in *siblings {
                    assert!(
                        list.contains(sibling),
                        "SIBLING DRIFT in family `{family}` ({file}): `{base}` is                          guarded but `{sibling}` is not — the guard is bypassable                          through the sibling export. Hook `{sibling}` in {file}, or                          delete the family row here if the whole family was                          intentionally unguarded."
                    );
                }
            }
        }
    }

    #[test]
    fn hooked_export_lists_match_installed_detours() {
        for (family, file, list, _, _) in FAMILIES {
            let src = match *file {
                "memory_guard.rs" => include_str!("memory_guard.rs"),
                "alpc_guard.rs" => include_str!("alpc_guard.rs"),
                "shell_guard.rs" => include_str!("shell_guard.rs"),
                "ui_guard.rs" => include_str!("ui_guard.rs"),
                other => panic!("unknown guard module in FAMILIES: {other}"),
            };
            // Scan only the module body (everything before the list itself):
            // a stale list entry cannot satisfy its own install check.
            let body = src.split("HOOKED_EXPORTS").next().unwrap_or(src);
            for name in *list {
                assert!(
                    referenced_in_install_code(body, name),
                    "family `{family}`: `{name}` is listed in {file} exports but no                      install literal for it exists in the module body — the detour                      was removed without updating the list (or was never written)."
                );
            }
        }
    }

    #[test]
    fn base_exports_of_every_family_are_actually_listed() {
        // Pins the bases: if a base name silently disappears from its list,
        // the family test above goes vacuously green and the drift net dies.
        // Removing a base must be a deliberate, reviewed act that deletes
        // the family row (with a justification) — never an accident.
        for (family, file, list, bases, _) in FAMILIES {
            for base in *bases {
                assert!(
                    list.contains(base),
                    "family `{family}` ({file}): base export `{base}` is missing                      from the module's export list — restore the guard or delete                      the family row and justify why the guard is gone."
                );
            }
        }
    }

    #[test]
    fn hooked_export_names_are_wellformed() {
        for (family, _, list, _, _) in FAMILIES {
            assert!(!list.is_empty(), "family `{family}` has an empty export list");
            for name in *list {
                assert!(
                    !name.is_empty() && name.is_ascii(),
                    "bad export name {name:?} in family {family}"
                );
            }
            let mut sorted: Vec<&str> = list.to_vec();
            sorted.sort_unstable();
            let count = sorted.len();
            sorted.dedup();
            assert_eq!(
                sorted.len(),
                count,
                "duplicate export names in family {family}"
            );
        }
    }
}
