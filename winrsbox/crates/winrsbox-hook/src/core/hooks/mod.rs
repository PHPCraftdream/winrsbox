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

// Split-out submodules (mechanical move from this file). Plain `mod` lines only:
// `module_source` below parses `#[cfg(test)]` + `mod X;` pairs as test modules.
mod path_resolve;
mod denylist;
mod device;
mod overlay;
mod spawn;

pub(crate) use path_resolve::{extract_nt_basename, extract_raw_nt_path, make_overlay_nt_buf, resolve_for_hook, unmirror_overlay_handle_relative};
#[cfg(test)] pub(crate) use path_resolve::{bare_relative_dos, device_path_to_dos_nt, join_bare_relative_to_nt};
#[cfg(test)] use path_resolve::{ascii_to_lower_u16, device_drive_map};
pub(crate) use denylist::{canonical_denylist_status, canonicalize_for_denylist, check_path_traversal, strip_trailing_dot_space};
#[cfg(test)] use denylist::{is_control_file, is_self_overlay_workdir_access};
pub(crate) use device::{classify_device_open, is_fs_device_path, needs_short_name_resolve, DeviceVerdict};
pub(crate) use overlay::{materialize_mock_overlay, prepare_overlay};
#[cfg(test)] pub(crate) use overlay::overlay_dest_in_roots;
#[cfg(test)] use overlay::{overlay_roots_lower, prepare_overlay_in_roots};
pub(crate) use spawn::{GuardEnvSnapshot, hook_category_disabled};
use spawn::{DISABLED_HOOK_CATS, FnNtCreateUserProcess, GUARD_ENV, HOOK_NT_CREATE_USER_PROCESS, extract_child_exe, hook_nt_create_user_process};
#[cfg(test)] use spawn::{child_guard_env_violation, child_scan_enabled, guard_env_mismatch, scan_image_for_direct_syscalls};
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
mod checks;

/// Read a module's source at RUNTIME: a single file (`foo.rs`) or a module
/// directory (`foo/` — every `.rs` under it, concatenated in sorted order).
///
/// Structural tests pin things the type system cannot (call order inside the
/// spawn hook, install-site-vs-export-list agreement). `include_str!` broke
/// the moment a file became a directory — silently: the test kept passing
/// while scanning a string that could never contain its subject. Four P0
/// regressions rode a green suite into master that way; runtime reads remove
/// the coupling to any filename. Modules now live in group directories, so
/// the stem is resolved by scanning all of `src/`: `<stem>.rs` wins if
/// exactly one exists, else `<stem>/`.
///
/// Test modules are excluded: a pin searches for a literal like `fn
/// hook_nt_create_user_process`, and the test performing that search contains
/// the very same literal — concatenating it makes the pin match ITSELF
/// (observed twice). Which files are tests is read from `#[cfg(test)] mod X;`
/// declarations in every `mod.rs` encountered — the module's own and each
/// subdirectory's — not guessed from filenames.
#[cfg(test)]
pub(crate) fn module_source(name: &str) -> String {
    let stem = name.strip_suffix(".rs").unwrap_or(name);
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    // Resolve the stem anywhere under src/: prefer a file, else a directory.
    let mut file_hits: Vec<std::path::PathBuf> = Vec::new();
    let mut dir_hits: Vec<std::path::PathBuf> = Vec::new();
    let mut stack = vec![src_dir];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read dir {}: {e}", dir.display()))
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path.clone());
                if path.file_name().is_some_and(|n| n == std::ffi::OsStr::new(stem)) {
                    dir_hits.push(path);
                }
            } else if path
                .file_name()
                .is_some_and(|n| n == std::ffi::OsStr::new(&format!("{stem}.rs")))
            {
                file_hits.push(path);
            }
        }
    }
    assert!(
        file_hits.len() <= 1 && dir_hits.len() <= 1,
        "module `{stem}` is ambiguous under src: {file_hits:?} {dir_hits:?}"
    );
    if let Some(f) = file_hits.first() {
        return std::fs::read_to_string(f).unwrap_or_else(|e| panic!("read {}: {e}", f.display()));
    }
    let as_dir = match dir_hits.first() {
        Some(d) => d.clone(),
        None => panic!(
            "module `{stem}` is neither <stem>.rs nor a directory under src — a structural \
             test names a module that no longer exists"
        ),
    };

    let mut test_mods: Vec<String> = Vec::new();
    parse_test_mod_decls(&as_dir.join("mod.rs"), &mut test_mods);

    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut stack = vec![as_dir.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read dir {}: {e}", dir.display()))
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                // Parse the subdirectory's own mod.rs BEFORE pushing it, so
                // its test modules are excluded wherever they sit below it.
                parse_test_mod_decls(&path.join("mod.rs"), &mut test_mods);
                stack.push(path);
                continue;
            }
            if path.extension().is_some_and(|e| e != "rs") {
                continue;
            }
            let fname = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            if test_mods.contains(&fname) {
                continue;
            }
            files.push(path);
        }
    }
    assert!(!files.is_empty(), "module directory {} holds no .rs files", as_dir.display());
    // Sorted so the concatenation is deterministic across filesystems.
    files.sort();
    files
        .iter()
        .map(|p| std::fs::read_to_string(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display())))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Collect `X.rs` names from consecutive `#[cfg(test)]` + `mod X;` lines.
#[cfg(test)]
fn parse_test_mod_decls(mod_rs: &std::path::Path, out: &mut Vec<String>) {
    let Ok(s) = std::fs::read_to_string(mod_rs) else {
        return;
    };
    let mut cfg_test_seen = false;
    for line in s.lines() {
        let line = line.trim();
        if line == "#[cfg(test)]" {
            cfg_test_seen = true;
        } else if cfg_test_seen {
            if let Some(name) = line.strip_prefix("mod ").and_then(|r| r.strip_suffix(';')) {
                out.push(format!("{name}.rs"));
            }
            cfg_test_seen = false;
        }
    }
}
