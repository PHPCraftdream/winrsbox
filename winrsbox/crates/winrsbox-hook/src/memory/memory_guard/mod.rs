// Memory guard — preventive termination on suspicious executable memory operations.
//
// Hooks NtAllocateVirtualMemory, NtProtectVirtualMemory, NtMapViewOfSection,
// NtWriteVirtualMemory, NtUnmapViewOfSection.
// Terminates the process if user-initiated code attempts to create executable
// memory outside of normal DLL loading, or to make the code pages of critical
// modules (ntdll/kernel32/kernelbase/hook.dll) writable — the unhooking
// primitive (P0-01). See "Hook-integrity protection" below.
//
// Crate versions assumed (from Cargo.toml):
//   detour  = "0.8"
//   ntapi   = "0.4"
//   winapi  = "0.3"

use std::sync::OnceLock;

use detour2::GenericDetour;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS};
use winapi::ctypes::c_void;
use winapi::um::processthreadsapi::GetCurrentProcessId;

use crate::anti_rec;
use crate::hooks::{ipc_log, is_trace, nt_call_original, STATUS_ACCESS_DENIED};

mod detours;
mod policy;
mod response;

pub(crate) use detours::*;
pub use policy::*;
pub(crate) use response::*;

// ---------------------------------------------------------------------------
// Nt* function type aliases
// ---------------------------------------------------------------------------

type FnNtAllocateVirtualMemory = unsafe extern "system" fn(
    HANDLE,         // ProcessHandle
    *mut *mut c_void, // BaseAddress
    usize,          // ZeroBits
    *mut usize,     // RegionSize
    u32,            // AllocationType
    u32,            // Protect
) -> NTSTATUS;

// NtAllocateVirtualMemoryEx — Win10 1709+ sibling of NtAllocateVirtualMemory
// (audit 2026-09-19 High, "sibling API"): VirtualAlloc2 / VirtualAlloc2FromApp
// route through it, so the RWX / foreign-exec checks on the classic export
// never saw those calls. Same stub family, same manual-hook treatment
// (GenericDetour produces broken trampolines here — see HOOK_ALLOC note).
// The extended-parameter array is passed through uninterpreted: the guard
// decision depends only on the target process handle and PageProtection.
type FnNtAllocateVirtualMemoryEx = unsafe extern "system" fn(
    HANDLE,           // ProcessHandle
    *mut *mut c_void, // BaseAddress
    *mut usize,       // RegionSize
    u32,              // AllocationType
    u32,              // Protect
    *mut c_void,      // ExtendedParameters (PMEM_EXTENDED_PARAMETER)
    u32,              // ExtendedParameterCount
) -> NTSTATUS;

type FnNtProtectVirtualMemory = unsafe extern "system" fn(
    HANDLE,         // ProcessHandle
    *mut *mut c_void, // BaseAddress
    *mut usize,     // RegionSize
    u32,            // NewProtect
    *mut u32,       // OldProtect
) -> NTSTATUS;

type FnNtWriteVirtualMemory = unsafe extern "system" fn(
    HANDLE,         // ProcessHandle
    *mut c_void,    // BaseAddress
    *const c_void,  // Buffer
    usize,          // NumberOfBytesToWrite
    *mut usize,     // NumberOfBytesWritten
) -> NTSTATUS;

type FnNtMapViewOfSection = unsafe extern "system" fn(
    HANDLE,         // SectionHandle
    HANDLE,         // ProcessHandle
    *mut *mut c_void, // BaseAddress
    usize,          // ZeroBits
    usize,          // CommitSize
    *mut i64,       // SectionOffset
    *mut usize,     // ViewSize
    u32,            // InheritDisposition
    u32,            // AllocationType
    u32,            // Win32Protect
) -> NTSTATUS;

type FnNtUnmapViewOfSection = unsafe extern "system" fn(
    HANDLE,         // ProcessHandle
    *mut c_void,    // BaseAddress
) -> NTSTATUS;

// SectionInformationClass = 1 (SectionImageInformation).
// Used to probe whether a section was created with SEC_IMAGE before we map it,
// so we can distinguish PE image loads (legitimate PAGE_EXECUTE_WRITECOPY) from
// anonymous/file-mapped sections with surprising execute protection.
type FnNtQuerySection = unsafe extern "system" fn(
    HANDLE,         // SectionHandle
    u32,            // SectionInformationClass
    *mut c_void,    // SectionInformation
    usize,          // SectionInformationLength
    *mut usize,     // ReturnLength (optional)
) -> NTSTATUS;

static NT_QUERY_SECTION: OnceLock<FnNtQuerySection> = OnceLock::new();

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

// NtAllocateVirtualMemory uses a manual inline hook instead of GenericDetour
// because detour/detour2 trampoline generation for this specific syscall stub
// produces broken trampolines on our Windows build (infinite recursion → AV).
// We write the hook ourselves: copy prologue, patch with JMP rel32, done.
static HOOK_ALLOC: OnceLock<GenericDetour<FnNtAllocateVirtualMemory>> = OnceLock::new();
static MANUAL_ALLOC_TRAMPOLINE: OnceLock<FnNtAllocateVirtualMemory> = OnceLock::new();
static MANUAL_ALLOC_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
// Ex sibling — same manual-hook machinery, own trampoline/active slots.
static MANUAL_ALLOC_EX_TRAMPOLINE: OnceLock<FnNtAllocateVirtualMemoryEx> = OnceLock::new();
static MANUAL_ALLOC_EX_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
// TLS index for NtAlloc-specific re-entry guard. Unlike thread_local! Cell<bool>,
// TlsGetValue/TlsSetValue never allocate, so they can't re-enter our NtAlloc hook.
static ALLOC_TLS_INDEX: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0xFFFFFFFF);
static HOOK_PROTECT: OnceLock<GenericDetour<FnNtProtectVirtualMemory>> = OnceLock::new();
static HOOK_MAP_VIEW: OnceLock<GenericDetour<FnNtMapViewOfSection>> = OnceLock::new();
static HOOK_WRITE_MEM: OnceLock<GenericDetour<FnNtWriteVirtualMemory>> = OnceLock::new();
static HOOK_NT_UNMAP_VIEW: OnceLock<GenericDetour<FnNtUnmapViewOfSection>> = OnceLock::new();
// Resolved original NtUnmapViewOfSection — used for cleanup unmaps (double-map guard)
// where we need to call the raw function without triggering our own hook.
static NT_UNMAP_ORIG: OnceLock<FnNtUnmapViewOfSection> = OnceLock::new();

// Guard mode (mirrors the launcher GuardLevel):
//   "scan"   = content-aware: allow executable memory, scan W^X→exec transitions
//              for direct syscalls (NtProtect path).
//   "full"   = scan + DLL .text scan. JIT-SAFE: self RWX-direct allocation is
//              ALLOWED (node/V8 needs it). The residual gap — RWX-direct
//              shellcode that never calls NtProtect, so the content-scan never
//              sees it — is accepted in full (the real adversary is a
//              misbehaving agent, not a hand-rolled exploit) and closed in static.
//   "static" = hard containment: self RWX-direct allocation is TERMINATED
//              outright (the only way to deny the content-scan-evading
//              RWX-direct path), at the cost of breaking RWX-direct JIT.
static GUARD_MODE: OnceLock<String> = OnceLock::new();

/// RWX allowance captured ONCE at install time (audit 2026-09-19, High).
/// It used to be re-read from `FS_SANDBOX_ALLOW_RWX` on every decision — a
/// live kill switch, since the environment block is guest-writable and any
/// `SetEnvironmentVariable` in the sandboxed process flipped it instantly.
/// The value is now fixed for the process lifetime in DllMain, before any
/// guest code can run.
static ALLOW_RWX: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static SCAN_CACHE: OnceLock<crate::scan_cache::ScanCache> = OnceLock::new();

static OWN_IMAGE_SPAN: OnceLock<Option<(usize, usize)>> = OnceLock::new();

fn scan_cache() -> &'static crate::scan_cache::ScanCache {
    SCAN_CACHE.get_or_init(crate::scan_cache::ScanCache::new)
}

fn is_full_mode() -> bool {
    GUARD_MODE.get().map(|s| s == "full").unwrap_or(true)
}

/// Hard-containment tier. Only here do we blunt-kill self RWX-direct
/// allocations — the content-scan-evading pattern that user-mode hooking can't
/// otherwise inspect. `full`/`scan` allow it so JIT runtimes work.
fn is_static_mode() -> bool {
    GUARD_MODE.get().map(|s| s == "static").unwrap_or(false)
}

fn allow_rwx() -> bool {
    ALLOW_RWX.load(std::sync::atomic::Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Install / Uninstall
// ---------------------------------------------------------------------------

/// Install memory guard hooks (NtAllocateVirtualMemory, NtProtectVirtualMemory).
///
/// # SAFETY
/// Must be called from install_hooks() in DllMain(DLL_PROCESS_ATTACH) context,
/// or after all hooks are wired up. Only safe Win32 APIs are used.
pub unsafe fn install(
    guard_level: &str,
    disabled_cats: &[String],
    allow_rwx: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = GUARD_MODE.set(guard_level.to_string());
    // Both arrive pre-captured in the caller's install-time snapshot
    // (hooks.rs GUARD_ENV); the environment is never re-read here
    // (audit 2026-09-19, High).
    ALLOW_RWX.store(allow_rwx, std::sync::atomic::Ordering::Relaxed);

    macro_rules! install_guard {
        ($lock:expr, $sym:literal, $hook_fn:expr, $fn_ty:ty) => {{
            let addr = crate::hooks::ntdll_export($sym.as_bytes())
                .ok_or_else(|| format!("ntdll export not found: {}", $sym))?;
            // SAFETY: addr is the real ntdll export matching the type alias.
            let target: $fn_ty = std::mem::transmute(addr as usize);
            let hook_ptr: $fn_ty = $hook_fn;
            let detour = GenericDetour::<$fn_ty>::new(target, hook_ptr)
                .map_err(|e| format!("detour init {}: {:?}", $sym, e))?;
            $lock.set(detour).ok();
            $lock.get()
                .expect("set above")
                .enable()
                .map_err(|e| format!("detour enable {}: {:?}", $sym, e))?;
            // Snapshot the patched prologue for hook-integrity verification.
            record_detour_for_watch(addr as usize);
        }};
    }

    // Categories arrive pre-parsed from the caller's install-time snapshot.
    let skip = |c: &str| disabled_cats.iter().any(|d| d == c);

    if !skip("mem-alloc") {
        install_manual_alloc_hook()?;
        // Audit High sibling closure: same category, same fail-closed
        // posture as the classic hook (a missing / unpatchable Ex stub
        // fails the whole memory guard rather than leaving VirtualAlloc2
        // unguarded).
        install_manual_alloc_ex_hook()?;
    }
    if !skip("mem-protect") {
        install_guard!(HOOK_PROTECT, "NtProtectVirtualMemory\0",   hook_nt_protect_virtual_memory,  FnNtProtectVirtualMemory);
    }
    if !skip("mem-map") {
        install_guard!(HOOK_MAP_VIEW, "NtMapViewOfSection\0",      hook_nt_map_view_of_section,     FnNtMapViewOfSection);
    }
    if !skip("mem-write") {
        install_guard!(HOOK_WRITE_MEM,"NtWriteVirtualMemory\0",    hook_nt_write_virtual_memory,    FnNtWriteVirtualMemory);
    }
    if !skip("mem-unmap") {
        install_guard!(HOOK_NT_UNMAP_VIEW, "NtUnmapViewOfSection\0", hook_nt_unmap_view_of_section, FnNtUnmapViewOfSection);
    }
    // Always resolve the raw NtUnmapViewOfSection for cleanup unmaps used by
    // the MapView double-map guard (calls with NtCurrentProcess, which our
    // hook allows through, but using the raw address avoids any re-entrancy
    // concerns during terminate-path cleanup).
    if let Some(addr) = crate::hooks::ntdll_export("NtUnmapViewOfSection\0".as_bytes()) {
        let _ = NT_UNMAP_ORIG.set(std::mem::transmute::<usize, FnNtUnmapViewOfSection>(addr as usize));
    }
    // Resolve NtQuerySection for the SEC_IMAGE pre-check in the MapView hook.
    // Not all ntdll versions export this under the Nt* name; failure is non-fatal
    // (the post-mapping VirtualQuery path still handles the common case).
    if let Some(addr) = crate::hooks::ntdll_export("NtQuerySection\0".as_bytes()) {
        // SAFETY: addr is the real ntdll NtQuerySection export matching FnNtQuerySection.
        let _ = NT_QUERY_SECTION.set(std::mem::transmute::<usize, FnNtQuerySection>(addr as usize));
    }

    Ok(())
}

/// Open the teardown window and silence the two enforcement detours that
/// would otherwise fire on the teardown itself.
///
/// MUST be the first thing `uninstall_hooks` does, before ANY guard's
/// `uninstall()`. Every `GenericDetour::disable()` restores the original
/// prologue through `VirtualProtect(PAGE_EXECUTE_READWRITE)` on a critical
/// module's code page — which is exactly the unhook primitive the P0-01
/// check terminates on. With the flag set only inside `memory_guard::uninstall`
/// (12th in the teardown order), the eleven guards torn down before it each
/// tripped that check and killed the process during DLL_PROCESS_DETACH: every
/// target under `--guard scan`/`full` exited 0xC0000005 instead of its own
/// exit code, losing buffered stdout with it.
///
/// `HOOK_PROTECT` and `HOOK_WRITE_MEM` are disabled here rather than left to
/// the flag alone, so the teardown window is as short as possible: after this
/// returns, the remaining teardown is not observed at all.
///
/// # SAFETY
/// Must be called from DLL_PROCESS_DETACH only. Idempotent.
pub unsafe fn begin_teardown() {
    MEMGUARD_UNINSTALLING.store(true, std::sync::atomic::Ordering::Release);
    // These two disables are themselves critical-module writes; they are
    // covered by the flag stored above, not by their own detours.
    if let Some(h) = HOOK_PROTECT.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_WRITE_MEM.get() { let _ = h.disable(); }
}

/// Disable memory guard hooks.
///
/// # SAFETY
/// Must be called from DLL_PROCESS_DETACH only.
pub unsafe fn uninstall() {
    // Idempotent — `uninstall_hooks` already opened the window before the
    // first guard was torn down. Repeated here so a direct caller of
    // `uninstall()` is still safe.
    begin_teardown();
    if let Some(h) = HOOK_NT_UNMAP_VIEW.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_WRITE_MEM.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_MAP_VIEW.get() { let _ = h.disable(); }
    uninstall_manual_alloc_hook();
    if let Some(h) = HOOK_PROTECT.get() { let _ = h.disable(); }
}

// ---------------------------------------------------------------------------
// pub(crate) accessors for inject_guard
// ---------------------------------------------------------------------------

pub(crate) fn unmap_section_original_pub() -> Option<FnNtUnmapViewOfSection> {
    NT_UNMAP_ORIG.get().copied()
}

pub(crate) fn capture_stack_pub(skip: u32, count: u32) -> Vec<u64> {
    capture_stack(skip, count)
}

pub(crate) fn get_own_exe_path_pub() -> String {
    get_own_exe_path()
}

/// Exports this module installs detours on. Kept in lockstep with install()
/// — the sibling-drift check in hooks.rs verifies every name here still
/// appears as an install literal in this file, and that guarded families
/// have no unhooked siblings.
pub(crate) const HOOKED_EXPORTS: &[&str] = &[
    "NtAllocateVirtualMemory",
    "NtAllocateVirtualMemoryEx",
    "NtProtectVirtualMemory",
    "NtMapViewOfSection",
    "NtWriteVirtualMemory",
    "NtUnmapViewOfSection",
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Test-only: drive the install-time snapshot without installing real detours.
#[cfg(test)]
pub(crate) fn test_set_allow_rwx(v: bool) {
    ALLOW_RWX.store(v, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(test)]
mod tests;
