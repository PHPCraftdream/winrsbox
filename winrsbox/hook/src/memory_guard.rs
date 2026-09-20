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
// PAGE_EXECUTE_* detection
// ---------------------------------------------------------------------------

const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

const EXECUTE_MASK: u32 = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

pub fn is_executable(protect: u32) -> bool {
    protect & EXECUTE_MASK != 0
}

pub fn is_rwx(protect: u32) -> bool {
    protect & PAGE_EXECUTE_READWRITE != 0 || protect & PAGE_EXECUTE_WRITECOPY != 0
}

pub fn protect_name(protect: u32) -> &'static str {
    if protect & PAGE_EXECUTE_READWRITE != 0 { return "PAGE_EXECUTE_READWRITE"; }
    if protect & PAGE_EXECUTE_WRITECOPY != 0 { return "PAGE_EXECUTE_WRITECOPY"; }
    if protect & PAGE_EXECUTE_READ != 0 { return "PAGE_EXECUTE_READ"; }
    if protect & PAGE_EXECUTE != 0 { return "PAGE_EXECUTE"; }
    "non-execute"
}

// ---------------------------------------------------------------------------
// Module classification
// ---------------------------------------------------------------------------

/// Check if an address falls within a loaded module's image range.
///
/// Uses GetModuleHandleExW with GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS.
/// Returns true if the address belongs to any loaded module (DLL/EXE).
pub fn is_address_in_module(addr: *const c_void) -> bool {
    if addr.is_null() {
        return false;
    }
    // SAFETY: addr may point to any memory. GetModuleHandleExW with
    // FROM_ADDRESS flag probes the address safely via NT loader structures;
    // it does not dereference addr. UNCHANGED_REFCOUNT avoids incrementing
    // the module's load count (no cleanup needed).
    unsafe {
        let mut hmod: *mut c_void = std::ptr::null_mut();
        let flags: u32 = 0x00000004 /* GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS */
                       | 0x00000002 /* GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT */;
        let ok = winapi::um::libloaderapi::GetModuleHandleExW(
            flags,
            addr as *const u16,
            &mut hmod as *mut *mut c_void as *mut _,
        );
        ok != 0 && !hmod.is_null()
    }
}

/// Get the module file path for a given address, or None if the address
/// is not in any loaded module.
pub fn module_path_for_address(addr: *const c_void) -> Option<String> {
    if addr.is_null() {
        return None;
    }
    // SAFETY: same as is_address_in_module — GetModuleHandleExW probes safely.
    unsafe {
        let mut hmod: *mut c_void = std::ptr::null_mut();
        let flags: u32 = 0x00000004 | 0x00000002;
        let ok = winapi::um::libloaderapi::GetModuleHandleExW(
            flags,
            addr as *const u16,
            &mut hmod as *mut *mut c_void as *mut _,
        );
        if ok == 0 || hmod.is_null() {
            return None;
        }
        let mut buf = [0u16; 512];
        let len = winapi::um::libloaderapi::GetModuleFileNameW(
            hmod as _,
            buf.as_mut_ptr(),
            buf.len() as u32,
        );
        if len == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

// ---------------------------------------------------------------------------
// Critical DLL set (never allow double-mapping)
// ---------------------------------------------------------------------------

const CRITICAL_DLLS: &[&str] = &["ntdll.dll", "kernel32.dll", "kernelbase.dll", "hook.dll"];

pub fn is_critical_dll(basename_lower: &str) -> bool {
    CRITICAL_DLLS.iter().any(|&c| c == basename_lower)
}

pub fn extract_basename_lower(path: &str) -> &str {
    let p = path.rsplit_once('\\').map(|(_, b)| b).unwrap_or(path);
    // Path is already typically ASCII; we need lowercase for comparison.
    // Since we can't return owned from &str, caller must lowercase first.
    p
}

// ---------------------------------------------------------------------------
// Mapped file name helper
// ---------------------------------------------------------------------------

/// Get the full mapped file path (NT device path) for a base address.
fn get_mapped_file_path(addr: *const c_void) -> Option<String> {
    if addr.is_null() {
        return None;
    }
    // SAFETY: GetMappedFileNameW is safe on any address; returns 0 on failure.
    unsafe {
        let mut buf = [0u16; 1024];
        let len = winapi::um::psapi::GetMappedFileNameW(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            addr as *mut c_void,
            buf.as_mut_ptr(),
            buf.len() as u32,
        );
        if len == 0 { return None; }
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// Trusted subsystem directories below the real Windows root. A mapped image
/// whose backing file resolves under one of these is exempt from the .text
/// direct-syscall scan: core Win32 DLLs (System32/SysWOW64), the CLR runtime
/// (Microsoft.NET) and NGen'd native images (assembly) legitimately contain
/// `syscall` instructions.
const TRUSTED_SYSTEM_SUBDIRS: &[&str] = &["system32", "syswow64", "microsoft.net", "assembly"];

/// Component-anchored prefix test: `path_lower` equals `prefix_lower` or
/// continues with a path separator immediately after it. Never a bare
/// substring match — `...\tmp\windows\system32\evil.dll` does not start with
/// `<root>\system32`.
fn has_path_prefix(path_lower: &str, prefix_lower: &str) -> bool {
    if !path_lower.starts_with(prefix_lower) {
        return false;
    }
    let rest = &path_lower[prefix_lower.len()..];
    rest.is_empty() || rest.starts_with('\\')
}

/// Pure decision behind `is_system_dll_path`: trusted when `path` lies under
/// `<windows_root_nt>\<subdir>` for one of TRUSTED_SYSTEM_SUBDIRS, with the
/// root matched as whole path components.
// Production resolves the root once via `trusted_system_prefixes`; this
// explicit-root variant exists so tests can pin a canonical root instead of
// depending on the machine's actual volume numbering.
#[cfg(test)]
fn is_system_dll_path_under(path: &str, windows_root_nt: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let root_lower = windows_root_nt.to_ascii_lowercase();
    TRUSTED_SYSTEM_SUBDIRS
        .iter()
        .any(|sub| has_path_prefix(&lower, &format!("{}\\{}", root_lower, sub)))
}

/// Fallback used only when the real Windows root cannot be resolved (loader
/// API failure — not observed in practice): anchored-component match at a
/// volume root. Keeps the pre-canonicalization trust set minus the substring
/// hole: `C:\tmp\windows\system32\evil.dll` is NOT trusted.
fn is_system_dll_path_anchored(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let comps: Vec<&str> = lower.split('\\').collect();
    comps.iter().enumerate().any(|(i, c)| {
        *c == "windows"
            && (i == 1 || i == 3) // Win32 `C:\Windows\...` or NT `\Device\X\Windows\...`
            && comps
                .get(i + 1)
                .map(|sub| TRUSTED_SYSTEM_SUBDIRS.contains(sub))
                .unwrap_or(false)
    })
}

/// NT-device-form path of the real Windows root (e.g.
/// `\Device\HarddiskVolume3\Windows`), derived once from the loader's own
/// ntdll mapping. GetMappedFileNameW reports the kernel-resolved device path
/// of the backing file — the guest cannot influence it the way it can
/// influence a Win32 path string or a look-alike directory it created.
fn compute_trusted_windows_root_nt() -> Option<String> {
    let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    // SAFETY: ntdll.dll is always loaded; name is NUL-terminated.
    let hmod = unsafe { winapi::um::libloaderapi::GetModuleHandleW(name.as_ptr()) };
    if hmod.is_null() {
        return None;
    }
    let nt_path = get_mapped_file_path(hmod as *const c_void)?;
    // `\Device\Vol\Windows\System32\ntdll.dll` → strip the file name, then
    // the system-directory component, leaving the Windows root.
    let lower = nt_path.to_ascii_lowercase();
    let stem = lower.rsplit_once('\\')?.0; // ...\windows\system32
    let root = stem.rsplit_once('\\')?.0;  // ...\windows
    if root.is_empty() {
        None
    } else {
        Some(root.to_owned())
    }
}

static TRUSTED_WINDOWS_ROOT_NT: OnceLock<Option<String>> = OnceLock::new();
static TRUSTED_SYSTEM_PREFIXES: OnceLock<Option<Vec<String>>> = OnceLock::new();

/// Resolved real Windows root in NT device form (lowercased), if available.
fn trusted_windows_root_nt() -> Option<&'static str> {
    TRUSTED_WINDOWS_ROOT_NT
        .get_or_init(compute_trusted_windows_root_nt)
        .as_deref()
}

/// `<root>\<subdir>` prefixes for every trusted system directory, resolved
/// once from the real filesystem.
fn trusted_system_prefixes() -> Option<&'static [String]> {
    TRUSTED_SYSTEM_PREFIXES
        .get_or_init(|| {
            trusted_windows_root_nt().map(|root| {
                TRUSTED_SYSTEM_SUBDIRS
                    .iter()
                    .map(|sub| format!("{}\\{}", root, sub))
                    .collect()
            })
        })
        .as_deref()
}

/// Check if a NT-device-form path points to a trusted Windows system location
/// that should be exempt from the direct-syscall .text scan.
///
/// Trusted locations (under the REAL Windows root, resolved from the
/// loader's own ntdll mapping):
///   - System32 / SysWOW64: core Win32 DLLs
///   - Windows\Microsoft.NET\: CLR runtime DLLs (clr.dll, mscoreei.dll, ...)
///   - Windows\assembly\: CLR GAC and NGen'd native images (.ni.dll) whose
///     JIT-generated code legitimately contains `syscall` instructions.
///
/// The path must match one of these directories as whole path components
/// under the canonical root. The old substring test trusted ANY path
/// containing `\windows\system32\` — e.g. a guest-planted
/// `...\tmp\windows\system32\evil.dll` (the CoW mirror preserves guest
/// directory layout on the real disk), which silently skipped the .text
/// scan. The real root lives under C:\Windows, which the sandbox policy
/// write-denies, so it cannot be spoofed at runtime.
pub fn is_system_dll_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    match trusted_system_prefixes() {
        Some(prefixes) => prefixes.iter().any(|p| has_path_prefix(&lower, p)),
        None => is_system_dll_path_anchored(&lower),
    }
}

fn get_mapped_file_basename(addr: *const c_void) -> Option<String> {
    if addr.is_null() {
        return None;
    }
    // SAFETY: addr is a valid mapped base returned by NtMapViewOfSection.
    // GetMappedFileNameW is safe to call on any address — returns 0 on failure.
    unsafe {
        let mut buf = [0u16; 512];
        let len = winapi::um::psapi::GetMappedFileNameW(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            addr as *mut c_void,
            buf.as_mut_ptr(),
            buf.len() as u32,
        );
        if len == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        // GetMappedFileNameW returns NT device path like \Device\HarddiskVolume3\...\ntdll.dll
        // Extract basename
        let basename = path.rsplit_once('\\').map(|(_, b)| b).unwrap_or(&path);
        Some(basename.to_ascii_lowercase())
    }
}

// ---------------------------------------------------------------------------
// Hook-integrity protection (P0-01) — unhooking via NtProtectVirtualMemory /
// NtWriteVirtualMemory against already-loaded critical modules
// ---------------------------------------------------------------------------
//
// The detours live as patched prologues inside the executable pages of
// ntdll.dll / kernel32.dll / kernelbase.dll and this image. Any in-process
// primitive that makes those pages writable enables the classic unhook: protect
// → RW, memcpy the original ntdll bytes (readable from the clean system copy on
// disk), protect → RX — and every subsequent call in this process bypasses the
// entire hook stack.
//
// Guard-level semantics: the levels ("scan"/"full"/"static") tune policy for
// UNTRUSTED memory (JIT vs hard containment). Hook integrity is not tiered —
// it is enforced at EVERY level. SECURITY.md documents `--guard static` as
// closing the unhooking class; this check carries that guarantee at every
// tier, since none of the tier trade-offs (JIT, RWX) depend on rewriting
// system-DLL code pages.
//
// Discriminator vs legitimate re-protection: the NT loader, the CRT and our
// own detour installer only write critical-module code pages while
// `install_hooks` runs — every detour enable() happens with anti_rec held
// (hooks.rs), so those VirtualProtect calls pass through the protect/write
// hooks unexamined. DLL_PROCESS_DETACH teardown is gated by
// MEMGUARD_UNINSTALLING. After that, no legitimate in-process path makes a
// critical-module executable page writable: loader re-protection targets the
// image being loaded/unloaded, which is never one of the already-loaded
// critical modules. Consequently a WRITE grant there is terminated outright,
// and any other protection change overlapping those pages is allowed but
// re-verifies the recorded detour prologues afterwards (defense in depth —
// catches protect→tamper→re-protect sequences).
//
// Note: while a hook is already executing on a thread, anti_rec makes
// re-entrant protect/write calls pass through (pre-existing design property
// shared by every check in this file); hook-context code never makes such
// calls itself.

/// Base protections that grant WRITE access. Modifiers (PAGE_GUARD,
/// PAGE_NOCACHE, ...) are ignored — bit tests stay valid with them OR'd in.
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;

pub fn grants_write(protect: u32) -> bool {
    protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0
}

/// What the self-process hooks must do when the requested range overlaps
/// executable pages of a critical module.
#[derive(Debug, PartialEq, Eq)]
enum CriticalRangeResponse {
    /// Normal hook logic applies.
    Allow,
    /// Allow the operation, then re-verify the recorded detour prologues.
    Verify,
    /// WRITE grant on a hooked code page from in-process code outside the
    /// install/teardown windows — unhook attempt, terminate.
    Terminate,
}

fn critical_range_response(in_critical_exec: bool, write_granted: bool) -> CriticalRangeResponse {
    if !in_critical_exec {
        return CriticalRangeResponse::Allow;
    }
    if write_granted {
        CriticalRangeResponse::Terminate
    } else {
        CriticalRangeResponse::Verify
    }
}

const MEM_COMMIT: u32 = 0x1000;
/// Protection bits that allow reading (READONLY | READWRITE | WRITECOPY |
/// EXECUTE_READ | EXECUTE_READWRITE | EXECUTE_WRITECOPY).
const READABLE_MASK: u32 = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80;

/// (base, base+size_of_image) of the image containing `addr`, or None.
///
/// Used to recognise this DLL's own image (hook.dll): its path is not under
/// System32, so `is_system_dll_path` cannot classify it.
fn module_image_span(addr: *const c_void) -> Option<(usize, usize)> {
    if addr.is_null() {
        return None;
    }
    // SAFETY: GetModuleHandleExW with FROM_ADDRESS probes the address via the
    // loader structures without dereferencing it (same pattern as
    // is_address_in_module above).
    let hmod = unsafe {
        let mut h: *mut c_void = std::ptr::null_mut();
        let flags: u32 = 0x00000004 /* GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS */
                       | 0x00000002 /* GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT */;
        let ok = winapi::um::libloaderapi::GetModuleHandleExW(
            flags,
            addr as *const u16,
            &mut h as *mut *mut c_void as *mut _,
        );
        if ok == 0 || h.is_null() {
            return None;
        }
        h
    };
    let base = hmod as usize;
    // SAFETY: loaded-image headers are committed and readable; every read
    // stays inside the first page of the image. read_unaligned makes no
    // alignment assumption; the magic checks validate the structure before
    // the offsets are followed.
    let size_of_image = unsafe {
        let p = base as *const u8;
        if std::ptr::read(p) != b'M' || std::ptr::read(p.add(1)) != b'Z' {
            return None;
        }
        let lfanew = std::ptr::read_unaligned(p.add(0x3C) as *const u32) as usize;
        if lfanew < 0x40 || lfanew > 0x1000 {
            return None;
        }
        let nt = p.add(lfanew);
        if std::ptr::read(nt) != b'P' || std::ptr::read(nt.add(1)) != b'E' {
            return None;
        }
        // Optional header starts at NT headers + 0x18; SizeOfImage sits at
        // optional header + 0x38 (same offset for PE32 and PE32+).
        let soi = std::ptr::read_unaligned(nt.add(0x18 + 0x38) as *const u32) as usize;
        if soi == 0 || soi > 0x8000_0000 {
            return None;
        }
        soi
    };
    Some((base, base + size_of_image))
}

static OWN_IMAGE_SPAN: OnceLock<Option<(usize, usize)>> = OnceLock::new();

#[inline(never)]
fn own_image_marker() {}

/// (base, end) of this crate's own image. In the unit-test binary this
/// resolves to the test executable — same span logic.
fn own_image_span() -> Option<(usize, usize)> {
    *OWN_IMAGE_SPAN.get_or_init(|| module_image_span(own_image_marker as *const c_void))
}

/// True when [addr, addr+size) overlaps an executable page belonging to a
/// critical module: ntdll/kernel32/kernelbase (KnownDLLs, system copy only)
/// or this DLL's own image.
///
/// The System32-path requirement prevents spoofing via an application that
/// ships its own DLL with a critical name: a legitimately loaded copy from
/// the app directory is re-protected by the loader like any other DLL and
/// must not trip the unhook check.
fn overlaps_critical_exec(addr: *const c_void, size: usize) -> bool {
    if addr.is_null() || size == 0 {
        return false;
    }
    // NtProtectVirtualMemory rounds base down to a page and size up, so the
    // effective kernel-affected range is the page-aligned span.
    let start = addr as usize & !0xFFF;
    let end = (addr as usize).saturating_add(size).saturating_add(0xFFF) & !0xFFF;
    let mut cur = start;
    let mut blocks = 0usize;
    while cur < end {
        blocks += 1;
        if blocks > 4096 {
            // Absurdly fragmented query; stop walking (a real critical-module
            // range is inspected within the first blocks).
            return false;
        }
        // SAFETY: VirtualQuery is safe on any address — returns 0 on failure.
        let mut mbi: winapi::um::winnt::MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            winapi::um::memoryapi::VirtualQuery(
                cur as *const c_void,
                &mut mbi,
                std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
            )
        };
        if ret == 0 || mbi.RegionSize == 0 {
            return false;
        }
        if mbi.Protect & EXECUTE_MASK != 0 && mbi.Type == MEM_IMAGE {
            let own = own_image_span()
                .map(|(b, e)| {
                    let block_end = cur.saturating_add(mbi.RegionSize);
                    cur < e && block_end > b
                })
                .unwrap_or(false);
            if own {
                return true;
            }
            if let Some(basename) = get_mapped_file_basename(cur as *const c_void) {
                if is_critical_dll(&basename) {
                    let system_copy = get_mapped_file_path(cur as *const c_void)
                        .map(|p| is_system_dll_path(&p))
                        .unwrap_or(false);
                    if system_copy {
                        return true;
                    }
                }
            }
        }
        let next = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
        if next <= cur {
            break;
        }
        cur = next;
    }
    false
}

// Recorded (address, first-two-bytes) snapshot for every detour this module
// installs. A patched ntdll syscall stub starts with the detour jump
// (0xE9 rel32, or 0xFF 0x25 for the x64 absolute-jump form); the original
// stub starts with `4c 8b` (mov r10, rcx). Any mismatch against the
// post-install snapshot — including a page made unreadable — means the detour
// was overwritten. Only this module's own detours are recorded; the deny path
// above covers every other detour generically (they all live in the same
// critical-module executable pages).
static DETOUR_WATCH: std::sync::Mutex<Vec<(usize, [u8; 2])>> = std::sync::Mutex::new(Vec::new());
static MEMGUARD_UNINSTALLING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True when a detour's current bytes no longer match its post-install
/// snapshot. An unreadable target counts as tampered (fail closed).
fn detour_bytes_tampered(expected: [u8; 2], current: Option<[u8; 2]>) -> bool {
    match current {
        Some(cur) => cur != expected,
        None => true,
    }
}

/// First watch entry whose current bytes differ from its snapshot, if any.
/// `read` is injectable for testing.
fn first_tampered_detour(
    watch: &[(usize, [u8; 2])],
    read: impl Fn(usize) -> Option<[u8; 2]>,
) -> Option<usize> {
    watch
        .iter()
        .find(|(addr, expected)| detour_bytes_tampered(*expected, read(*addr)))
        .map(|(addr, _)| *addr)
}

/// Read two code bytes at `addr` if the page is committed and readable;
/// None otherwise.
fn read_code_bytes(addr: usize) -> Option<[u8; 2]> {
    if addr == 0 {
        return None;
    }
    // SAFETY: VirtualQuery is safe on any address — returns 0 on failure.
    let mut mbi: winapi::um::winnt::MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        winapi::um::memoryapi::VirtualQuery(
            addr as *const c_void,
            &mut mbi,
            std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
        )
    };
    if ret == 0 || mbi.State != MEM_COMMIT || mbi.Protect & READABLE_MASK == 0 {
        return None;
    }
    // SAFETY: VirtualQuery just reported addr as committed and readable; the
    // 2-byte read stays within the reported region.
    Some(unsafe { std::ptr::read(addr as *const [u8; 2]) })
}

/// Re-verify the recorded detour prologues and terminate on the first
/// mismatch. Called after an allowed operation that overlapped critical-module
/// executable pages. The reported target address is the tampered detour site.
fn verify_detours_or_die(kind: ipc::AllocKind, protect: u32, region_size: u64) {
    if MEMGUARD_UNINSTALLING.load(std::sync::atomic::Ordering::Acquire) {
        return;
    }
    let tampered = {
        let watch = match DETOUR_WATCH.lock() {
            Ok(w) => w,
            Err(poisoned) => poisoned.into_inner(),
        };
        first_tampered_detour(&watch, read_code_bytes)
    };
    if let Some(addr) = tampered {
        report_and_terminate(kind, protect, region_size, addr as u64);
    }
}

/// Record a freshly installed detour for tamper verification. Called once per
/// target right after enable(), from the single-threaded install path.
fn record_detour_for_watch(addr: usize) {
    if addr == 0 {
        return;
    }
    if let Some(bytes) = read_code_bytes(addr) {
        if let Ok(mut watch) = DETOUR_WATCH.lock() {
            watch.push((addr, bytes));
        }
    }
}

// ---------------------------------------------------------------------------
// Hook: NtUnmapViewOfSection — deny foreign-process unmap (Process Hollowing)
// ---------------------------------------------------------------------------

unsafe extern "system" fn hook_nt_unmap_view_of_section(
    process_handle: HANDLE,
    base_address: *mut c_void,
) -> NTSTATUS {
    let call_original = || {
        nt_call_original!(&HOOK_NT_UNMAP_VIEW, "NtUnmapViewOfSection", (process_handle, base_address))
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // Self-process: allow (legit DLL unload, JIT cleanup, etc.)
    if process_handle as isize == NT_CURRENT_PROCESS {
        return call_original();
    }

    // Resolve PID for real handles
    let target_pid = unsafe { winapi::um::processthreadsapi::GetProcessId(process_handle) };
    let self_pid = unsafe { GetCurrentProcessId() };
    if target_pid == 0 || target_pid == self_pid {
        return call_original();
    }

    // Foreign process: deny unconditionally.
    // Even our own owned children should not have their image unmapped —
    // that's the core of Process Hollowing.
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace,
            format!("mem_unmap_foreign_blocked pid={target_pid} base=0x{:x}",
                base_address as usize));
    }
    STATUS_ACCESS_DENIED
}

// ---------------------------------------------------------------------------
// VirtualQuery helper
// ---------------------------------------------------------------------------

const MEM_IMAGE: u32 = 0x1000000;

fn is_image_mapping(addr: *const c_void) -> bool {
    if addr.is_null() {
        return false;
    }
    // SAFETY: addr points to a mapped region. VirtualQuery is safe to call
    // on any address — returns 0 on failure.
    unsafe {
        let mut mbi: winapi::um::winnt::MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let ret = winapi::um::memoryapi::VirtualQuery(
            addr,
            &mut mbi,
            std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
        );
        ret != 0 && mbi.Type == MEM_IMAGE
    }
}

/// Query the section object via NtQuerySection(SectionImageInformation) to
/// determine if it was created with SEC_IMAGE (i.e., it maps a PE file as a
/// process image rather than a flat file-backed or anonymous mapping).
///
/// This is the authoritative pre-mapping check for distinguishing PE image
/// loads (where PAGE_EXECUTE_WRITECOPY is the normal NT loader protection)
/// from anonymous or plain file-backed sections (where executable protection
/// signals shellcode/manual-map).
///
/// Returns true if the section is SEC_IMAGE, false if not or on any error
/// (fails closed — the post-mapping VirtualQuery check then covers the rest).
fn is_section_image_backed(section_handle: HANDLE) -> bool {
    if section_handle.is_null() {
        return false;
    }
    let Some(nt_query) = NT_QUERY_SECTION.get() else {
        return false;
    };
    // SECTION_IMAGE_INFORMATION layout (first 64 bytes are always present).
    // We only care whether the call succeeds — a non-image section returns
    // STATUS_SECTION_NOT_IMAGE (0xC0000049) and we return false.
    let mut info = [0u8; 64];
    let mut ret_len: usize = 0;
    // SAFETY: info is a valid mutable buffer; section_handle was passed to
    // NtMapViewOfSection by the caller and is valid for the duration of the hook.
    // SectionInformationClass=1 = SectionImageInformation.
    let status = unsafe {
        nt_query(
            section_handle,
            1, // SectionImageInformation
            info.as_mut_ptr() as *mut c_void,
            info.len(),
            &mut ret_len,
        )
    };
    status >= 0
}

/// Decide whether a MapView mapping should be allowed based on its type and
/// protection.
///
/// `is_image`       — true when VirtualQuery reports MEM_IMAGE (SEC_IMAGE) or
///                    NtQuerySection confirmed SEC_IMAGE pre-mapping.
/// `is_file_backed` — true when GetMappedFileNameW returns a path for the
///                    mapping (file-backed section, not anonymous/pagefile).
/// `effective_protect` — win32_protect OR'd with mbi.Protect (actual pages).
///
/// Returns true when the mapping is ALLOWED, false when it should be DENIED.
///
/// Policy:
///   - SEC_IMAGE (is_image): all execute protections allowed. PAGE_EXECUTE_
///     WRITECOPY is the NT loader's normal protection for image sections; CLR
///     and all .NET apps depend on it.
///   - file-backed (is_file_backed, !is_image): non-image sections backed by
///     a disk file (GetMappedFileNameW succeeds). CLR maps .ni.dll/.dll as
///     plain file views; content-scan at full/static level catches injected
///     direct-syscall payloads without blocking legitimate CLR loads.
///   - anonymous (!is_image, !is_file_backed): pagefile-backed section with
///     no backing file — the classic shellcode / manual-map pattern → deny.
pub(crate) fn decide_mapview_protection(
    is_image: bool,
    is_file_backed: bool,
    effective_protect: u32,
) -> bool {
    if is_image {
        return true;
    }
    if !is_executable(effective_protect) {
        return true;
    }
    // Executable non-image: allow only file-backed (MEM_MAPPED) mappings;
    // deny anonymous (MEM_PRIVATE) mappings.
    is_file_backed
}

// ---------------------------------------------------------------------------
// Region scan — bounded-chunk linear sweep for direct syscalls
// ---------------------------------------------------------------------------

/// Decode-chunk size for region scans. This bounds the work and the hit
/// buffer of a single decode pass — it is NOT a coverage cap: every byte of
/// the region is scanned exactly once (plus the overlap below), regardless
/// of region size. The previous hard cap (regions > 64 MB were skipped
/// silently) was fail-open by construction.
const SCAN_CHUNK_BYTES: usize = 16 * 1024 * 1024;

/// Longest possible x86-64 instruction. Non-final chunks are extended this
/// many bytes into the next chunk so an instruction starting before the
/// boundary is still fully decoded by the earlier pass.
const SCAN_CHUNK_OVERLAP: usize = 15;

/// Linear-sweep `bytes` (based at `base_addr`) for direct syscall
/// instructions in bounded, forward-overlapping chunks. Returns true at the
/// first chunk that contains one. With `use_cache`, per-chunk verdicts are
/// memoized in the scan cache so repeated W^X flips of unchanged JIT pages
/// skip the decode.
fn region_has_direct_syscalls(bytes: &[u8], base_addr: usize, use_cache: bool) -> bool {
    region_has_direct_syscalls_with(bytes, base_addr, use_cache, SCAN_CHUNK_BYTES)
}

fn region_has_direct_syscalls_with(
    bytes: &[u8],
    base_addr: usize,
    use_cache: bool,
    chunk_size: usize,
) -> bool {
    debug_assert!(chunk_size > 0);
    let mut off = 0usize;
    while off < bytes.len() {
        let chunk_len = chunk_size.min(bytes.len() - off);
        // Extend non-final chunks into the next one so a syscall pair split
        // around the boundary is decoded; the extra bytes are re-scanned by
        // the next pass (harmless duplicate work).
        let extended = (chunk_len + SCAN_CHUNK_OVERLAP).min(bytes.len() - off);
        let chunk = &bytes[off..off + extended];
        let chunk_addr = base_addr.wrapping_add(off);
        let dirty = if use_cache {
            match scan_cache().lookup(chunk_addr, chunk.len(), chunk) {
                Some(clean) => !clean,
                None => {
                    let hits = policy::scan::find_direct_syscalls(chunk, chunk_addr as u64);
                    let dirty = !hits.is_empty();
                    if !dirty {
                        scan_cache().insert(chunk_addr, chunk.len(), chunk, true);
                    }
                    dirty
                }
            }
        } else {
            !policy::scan::find_direct_syscalls(chunk, chunk_addr as u64).is_empty()
        };
        if dirty {
            return true;
        }
        off += chunk_len;
    }
    false
}

// ---------------------------------------------------------------------------
// Stack capture
// ---------------------------------------------------------------------------

fn capture_stack(skip: u32, count: u32) -> Vec<u64> {
    let count = count.min(62); // RtlCaptureStackBackTrace max is 62
    let mut frames = vec![std::ptr::null_mut::<c_void>(); count as usize];
    // SAFETY: frames buffer is valid for `count` pointers.
    // RtlCaptureStackBackTrace is always available in ntdll.
    // SAFETY: frames buffer is valid for `count` pointers. RtlCaptureStackBackTrace
    // is in ntdll (re-exported via winapi::um::winnt) and is always available.
    let captured = unsafe {
        winapi::um::winnt::RtlCaptureStackBackTrace(
            skip,
            count,
            frames.as_mut_ptr(),
            std::ptr::null_mut(),
        )
    };
    frames.truncate(captured as usize);
    frames.iter().map(|p| *p as u64).collect()
}

// ---------------------------------------------------------------------------
// Self-process check
// ---------------------------------------------------------------------------

const NT_CURRENT_PROCESS: isize = -1;

fn is_current_process(handle: HANDLE) -> bool {
    if handle as isize == NT_CURRENT_PROCESS {
        return true;
    }
    if handle.is_null() {
        return false;
    }
    // Real handle: check if it points to our own PID
    // SAFETY: GetProcessId is safe on any HANDLE; returns 0 on invalid.
    unsafe {
        let pid = winapi::um::processthreadsapi::GetProcessId(handle);
        pid != 0 && pid == GetCurrentProcessId()
    }
}

// ---------------------------------------------------------------------------
// Report + terminate
// ---------------------------------------------------------------------------

fn report_and_terminate(kind: ipc::AllocKind, protect: u32, region_size: u64, target_addr: u64) -> ! {
    let pid = unsafe { GetCurrentProcessId() };

    // Capture stack (skip 3: report_and_terminate → hook_fn → relay)
    let stack = capture_stack(3, 16);

    // Find the first non-system frame for caller info
    let caller_pc = stack.first().copied().unwrap_or(0);
    let caller_module = module_path_for_address(caller_pc as *const c_void);

    let exe = get_own_exe_path();

    // IPC: fire-and-forget (best effort)
    let _ = crate::hooks::ipc_log_violation(ipc::Req::MemoryViolation {
        pid,
        exe: exe.clone(),
        kind,
        requested_protect: protect,
        region_size,
        target_address: target_addr,
        caller_pc,
        caller_module: caller_module.clone(),
        stack_top: stack.clone(),
    });

    // Local fallback log to %TEMP%
    write_local_fallback(pid, &exe, kind, protect, region_size, target_addr, caller_pc, &caller_module, &stack);

    // OutputDebugStringW for -d mode
    let msg = format!(
        "[VIOLATION] pid={pid} kind={kind} protect={} caller={} pc=0x{caller_pc:x}\0",
        protect_name(protect),
        caller_module.as_deref().unwrap_or("<anonymous>"),
    );
    let wide: Vec<u16> = msg.encode_utf16().collect();
    // SAFETY: wide is a valid null-terminated UTF-16 string.
    unsafe { winapi::um::debugapi::OutputDebugStringW(wide.as_ptr()) };

    // Terminate
    // SAFETY: GetCurrentProcess() always returns a valid pseudo-handle.
    unsafe {
        winapi::um::processthreadsapi::TerminateProcess(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            0xC000_0005, // STATUS_ACCESS_VIOLATION
        );
    }
    // TerminateProcess is asynchronous on self; loop to prevent returning
    loop {
        unsafe { winapi::um::synchapi::Sleep(1000) };
    }
}

fn get_own_exe_path() -> String {
    let mut buf = [0u16; 512];
    // SAFETY: buf is valid, len matches.
    let len = unsafe {
        winapi::um::libloaderapi::GetModuleFileNameW(
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
    };
    if len == 0 { String::new() } else { String::from_utf16_lossy(&buf[..len as usize]) }
}

fn write_local_fallback(
    pid: u32, exe: &str, kind: ipc::AllocKind, protect: u32,
    size: u64, addr: u64, caller_pc: u64, caller_module: &Option<String>,
    stack: &[u64],
) {
    let tmp = std::env::temp_dir();
    let path = tmp.join(format!("fs-sandbox-violation-{pid}.log"));
    let stack_str: Vec<String> = stack.iter().map(|f| format!("0x{f:x}")).collect();
    let line = format!(
        "{{\"pid\":{pid},\"exe\":\"{}\",\"kind\":\"{kind}\",\"protect\":\"{}\",\"size\":{size},\"addr\":\"0x{addr:x}\",\"caller_pc\":\"0x{caller_pc:x}\",\"caller_module\":{},\"stack\":[{}]}}\n",
        exe.replace('\\', "\\\\").replace('"', "\\\""),
        protect_name(protect),
        match caller_module {
            Some(m) => format!("\"{}\"", m.replace('\\', "\\\\").replace('"', "\\\"")),
            None => "null".to_string(),
        },
        stack_str.join(","),
    );
    let _ = std::fs::write(&path, line.as_bytes());
}

// ---------------------------------------------------------------------------
// Hook implementations
// ---------------------------------------------------------------------------

/// THE single allocation decision — shared by NtAllocateVirtualMemory AND
/// NtAllocateVirtualMemoryEx (audit 2026-09-19 High, sibling-API closure:
/// VirtualAlloc2 routes through the Ex variant, so a decision applied on only
/// the classic export is bypassable). Returns true when the call must
/// fail-stop.
///
/// Pure over its inputs (no IPC, no termination) so both entry points stay
/// policy-identical by construction and the decision stays unit-testable
/// without killing the test process. The caller reads BaseAddress/RegionSize
/// for the violation report only after this returns true.
fn alloc_decision_kill_required(process_handle: HANDLE, protect: u32) -> bool {
    if is_current_process(process_handle) {
        // Self RWX-direct allocation: the content-scan-evading JIT/shellcode
        // pattern. Blunt-killed ONLY in static (hard containment). In
        // full/scan it's allowed so RWX-direct JIT (node/V8) works; the
        // W^X JIT path is still content-scanned at NtProtect->exec time.
        is_rwx(protect) && !allow_rwx() && is_static_mode()
    } else {
        // Foreign-process allocation: executable memory in a process we do
        // not own is the injection primitive itself.
        // SAFETY: GetProcessId is safe on any HANDLE; returns 0 on invalid.
        let target_pid = unsafe {
            winapi::um::processthreadsapi::GetProcessId(process_handle)
        };
        target_pid != 0
            && !crate::process_tracker::is_owned_child(target_pid)
            && is_executable(protect)
    }
}

unsafe extern "system" fn hook_nt_allocate_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> NTSTATUS {
    let call_original = || {
        if let Some(tramp) = MANUAL_ALLOC_TRAMPOLINE.get() {
            tramp(process_handle, base_address, zero_bits,
                  region_size, allocation_type, protect)
        } else {
            // Fallback: GenericDetour; absent detour fails closed (was: unwrap-abort).
            nt_call_original!(
                &HOOK_ALLOC,
                "NtAllocateVirtualMemory",
                (process_handle, base_address, zero_bits,
                 region_size, allocation_type, protect)
            )
        }
    };

    if !alloc_anti_rec_enter() {
        return call_original();
    }

    let result = (|| {
        // Shared decision (also applied by hook_nt_allocate_virtual_memory_ex
        // below) — one gate for both alloc entry points.
        if alloc_decision_kill_required(process_handle, protect) {
            let size = if region_size.is_null() { 0 } else { *region_size as u64 };
            let addr = if base_address.is_null() { 0 } else { *base_address as u64 };
            report_and_terminate(ipc::AllocKind::Allocate, protect, size, addr);
        }
        call_original()
    })();

    alloc_anti_rec_leave();
    result
}

// NtAllocateVirtualMemoryEx — audit High sibling closure. VirtualAlloc2 /
// VirtualAlloc2FromApp route here (Win10 1709+), so the classic hook above
// never saw those calls. Same manual-hook family, same shared decision.
// SAFETY: Called with the ntdll!NtAllocateVirtualMemoryEx ABI (detour
// springboard); see install_manual_syscall_hook.
unsafe extern "system" fn hook_nt_allocate_virtual_memory_ex(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
    extended_parameters: *mut c_void,
    extended_parameter_count: u32,
) -> NTSTATUS {
    let call_original = || {
        if let Some(tramp) = MANUAL_ALLOC_EX_TRAMPOLINE.get() {
            // SAFETY: trampoline rebuilt from the original prologue matches
            // FnNtAllocateVirtualMemoryEx.
            tramp(process_handle, base_address, region_size, allocation_type,
                  protect, extended_parameters, extended_parameter_count)
        } else {
            // Unreachable: install_manual_syscall_hook populates the
            // trampoline BEFORE patching the stub (same invariant as the
            // classic hook). Panic rather than recurse into ourselves.
            panic!("alloc-ex trampoline missing but stub patched");
        }
    };

    if !alloc_anti_rec_enter() {
        return call_original();
    }

    let result = (|| {
        // THE shared allocation decision — identical gate to the classic
        // NtAllocateVirtualMemory hook by construction. The extended-
        // parameter array does not participate: the kill classes (foreign
        // exec / static-mode self RWX) depend only on handle + protect.
        if alloc_decision_kill_required(process_handle, protect) {
            let size = if region_size.is_null() { 0 } else { *region_size as u64 };
            let addr = if base_address.is_null() { 0 } else { *base_address as u64 };
            report_and_terminate(ipc::AllocKind::Allocate, protect, size, addr);
        }
        call_original()
    })();

    alloc_anti_rec_leave();
    result
}

unsafe extern "system" fn hook_nt_protect_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> NTSTATUS {
    let call_original = || {
        nt_call_original!(
            &HOOK_PROTECT,
            "NtProtectVirtualMemory",
            (process_handle, base_address, region_size,
             new_protect, old_protect)
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if !is_current_process(process_handle) {
        // Foreign process VirtualProtectEx
        let target_pid = winapi::um::processthreadsapi::GetProcessId(process_handle);
        if target_pid != 0 && !crate::process_tracker::is_owned_child(target_pid) {
            // External process making memory executable → block
            if is_executable(new_protect) && !base_address.is_null() {
                let addr = *base_address;
                let size = if region_size.is_null() { 0 } else { *region_size as u64 };
                report_and_terminate(ipc::AllocKind::Protect, new_protect, size, addr as u64);
            }
        }
        return call_original();
    }

    // Self-process content-aware scan: when non-module memory transitions to
    // executable, scan its content for direct syscall instructions. Module
    // memory (.text of loaded DLLs) is skipped — DLLs scanned at MapView time.
    if is_executable(new_protect) && !base_address.is_null() {
        let addr = *base_address;
        // Skip loaded module regions (loader operations, CRT, etc.)
        if !addr.is_null() && !is_address_in_module(addr) {
            let size = if region_size.is_null() { 0 } else { *region_size };
            if size > 0 {
                let bytes = std::slice::from_raw_parts(addr as *const u8, size);
                // Full-region scan in bounded chunks. The previous
                // `size <= 64 MB` gate silently skipped oversized regions —
                // fail-open by construction; every byte is covered now.
                if region_has_direct_syscalls(bytes, addr as usize, true) {
                    report_and_terminate(ipc::AllocKind::Protect, new_protect, size as u64, addr as u64);
                }
            }
        }
    }

    // Hook-integrity check (P0-01): a WRITE grant on an executable page of a
    // critical module from post-install in-process code is the unhooking
    // primitive — terminate. Any other protection change overlapping those
    // pages is allowed, then the recorded detour prologues are re-verified
    // (catches protect→tamper→re-protect sequences). Enforced at every guard
    // level — see "Hook-integrity protection" above.
    let mut verify_after: Option<(u32, u64)> = None;
    if !base_address.is_null() {
        let addr = *base_address;
        if !addr.is_null() {
            let size = if region_size.is_null() { 0 } else { *region_size };
            if overlaps_critical_exec(addr, size) {
                match critical_range_response(true, grants_write(new_protect)) {
                    CriticalRangeResponse::Terminate => {
                        report_and_terminate(
                            ipc::AllocKind::Protect, new_protect, size as u64, addr as u64,
                        );
                    }
                    CriticalRangeResponse::Verify => {
                        verify_after = Some((new_protect, size as u64));
                    }
                    CriticalRangeResponse::Allow => {}
                }
            }
        }
    }

    let status = call_original();
    if let Some((protect, size)) = verify_after {
        verify_detours_or_die(ipc::AllocKind::Protect, protect, size);
    }
    status
}

unsafe extern "system" fn hook_nt_map_view_of_section(
    section_handle: HANDLE,
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    commit_size: usize,
    section_offset: *mut i64,
    view_size: *mut usize,
    inherit_disposition: u32,
    allocation_type: u32,
    win32_protect: u32,
) -> NTSTATUS {
    let call_original = || {
        nt_call_original!(
            &HOOK_MAP_VIEW,
            "NtMapViewOfSection",
            (section_handle, process_handle, base_address, zero_bits,
             commit_size, section_offset, view_size, inherit_disposition,
             allocation_type, win32_protect)
        )
    };

    // Cross-process mapping deny:
    // If target is a foreign process (not self, not NtCurrentProcess), deny
    // independently of section content. Attacker mapping section into foreign
    // proc address space → when that proc reads/executes → runs attacker code.
    // Self-process mapping continues to existing content-aware path.
    if !is_current_process(process_handle) {
        let target_pid = unsafe { winapi::um::processthreadsapi::GetProcessId(process_handle) };
        let self_pid = unsafe { GetCurrentProcessId() };
        if target_pid != 0 && target_pid != self_pid {
            if is_trace() {
                ipc_log(ipc::LogLevel::Trace,
                    format!("mem_map_foreign_blocked pid={target_pid} win32protect=0x{:x}",
                        win32_protect));
            }
            return STATUS_ACCESS_DENIED;
        }
        // Handle belongs to self (pseudo-handle resolved to same PID)
        return call_original();
    }

    // anti_rec: if we're already inside a hook on this thread, pass through.
    // During process startup, NtMapViewOfSection is called heavily for DLL
    // loading. We must allow those (anti_rec handles it). After startup,
    // user code triggering this hook will have anti_rec available.
    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // Pre-mapping SEC_IMAGE check: query the section object BEFORE mapping it.
    // NtQuerySection(SectionImageInformation) succeeds only for SEC_IMAGE
    // sections (PE files opened by the NT loader). This is authoritative and
    // avoids the VirtualQuery ambiguity that causes the post-mapping
    // is_image_mapping() to return false for some CLR managed-assembly loads
    // (e.g. mscorlib.ni.dll, system.dll) where the NT loader maps a
    // file-backed section that VirtualQuery reports as MEM_MAPPED rather than
    // MEM_IMAGE, even though the underlying file IS a PE image.
    let section_is_image = is_section_image_backed(section_handle);

    // Call original first — we need the mapped base to distinguish SEC_IMAGE
    // (normal DLL loading) from anonymous sections (shellcode/manual map).
    let status = call_original();
    if status < 0 || base_address.is_null() {
        return status;
    }

    let mapped_base = *base_address;
    if mapped_base.is_null() {
        return status;
    }

    // Image mapping: either VirtualQuery confirms MEM_IMAGE, or the pre-mapping
    // NtQuerySection confirmed SEC_IMAGE (covers CLR managed-assembly paths where
    // VirtualQuery may report MEM_MAPPED for a valid PE image section).
    if is_image_mapping(mapped_base) || section_is_image {
        if let Some(basename) = get_mapped_file_basename(mapped_base) {
            if is_critical_dll(&basename) {
                if let Some(unmap_fn) = unmap_section_original_pub() {
                    // SAFETY: mapped_base was just mapped successfully; we unmap
                    // it before terminating to clean up.
                    unmap_fn(-1isize as HANDLE, mapped_base);
                }
                let size = if view_size.is_null() { 0 } else { *view_size as u64 };
                report_and_terminate(ipc::AllocKind::MapView, win32_protect, size, mapped_base as u64);
            }

            // Scan .text of user DLLs for direct syscalls at full level and
            // above. static is a superset of full — it MUST also run this scan
            // (skipping it would make the hardest tier weaker than full).
            if is_full_mode() || is_static_mode() {
            if let Some(full_path) = get_mapped_file_path(mapped_base) {
                if !is_system_dll_path(&full_path) {
                    // Bound every read to the actual mapped view. The PE header
                    // fields (virtual_address / virtual_size) are attacker-
                    // influenced for a manually-built section, so reading a flat
                    // 4 KiB header or `mapped_base + virtual_address` for
                    // `virtual_size` bytes could run past the mapping → OOB read /
                    // crash. Clamp to *view_size (the kernel-reported mapped size).
                    let view_bytes = if view_size.is_null() { 0usize } else { *view_size };
                    let header_len = view_bytes.min(4096);
                    if header_len >= 64 {
                        let header_slice = std::slice::from_raw_parts(mapped_base as *const u8, header_len);
                        if let Some(text) = policy::scan::pe_text_section(header_slice) {
                            let va = text.virtual_address as usize;
                            // Skip if the section claims to start at/after the view end.
                            if va < view_bytes {
                                let avail = view_bytes - va;
                                let scan_size = (text.virtual_size as usize).min(avail);
                                if scan_size > 0 {
                                    let text_addr = (mapped_base as usize + va) as *const u8;
                                    let text_slice = std::slice::from_raw_parts(text_addr, scan_size);
                                    if region_has_direct_syscalls(text_slice, text_addr as usize, false) {
                                        let unmap = unmap_section_original_pub();
                                        if let Some(unmap_fn) = unmap {
                                            unmap_fn(-1isize as HANDLE, mapped_base);
                                        }
                                        let size = if view_size.is_null() { 0 } else { *view_size as u64 };
                                        report_and_terminate(ipc::AllocKind::MapView, win32_protect, size, mapped_base as u64);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            } // full || static
        }
    } else {
        // Non-image mapping (VirtualQuery did not return MEM_IMAGE and
        // NtQuerySection did not confirm SEC_IMAGE).
        let mut effective = win32_protect;
        let mut mbi: winapi::um::winnt::MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let ret = winapi::um::memoryapi::VirtualQuery(
            mapped_base,
            &mut mbi,
            std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
        );
        if ret != 0 {
            effective |= mbi.Protect;
        }
        if is_executable(effective) {
            // Both anonymous (pagefile-backed) sections and file-backed sections
            // appear as MEM_MAPPED after NtMapViewOfSection. Distinguish them by
            // querying whether the mapping has an underlying file:
            //   - GetMappedFileNameW succeeds  → file-backed (disk-backed section).
            //     CLR maps managed assemblies (.ni.dll) this way with
            //     PAGE_EXECUTE_WRITECOPY — a legitimate read-only copy-on-write
            //     view. Blocking it terminates .NET / PowerShell at startup.
            //   - GetMappedFileNameW fails (returns 0) → anonymous / pagefile-
            //     backed section. This is the classic shellcode / manual-map
            //     injection pattern → deny regardless of mode.
            //   - VirtualQuery failed (ret == 0) → err on the side of caution
            //     and treat as anonymous → deny.
            let is_file_backed = get_mapped_file_path(mapped_base).is_some();

            if !is_file_backed {
                // Anonymous or pagefile-backed executable mapping: deny.
                let unmap = unmap_section_original_pub();
                if let Some(unmap_fn) = unmap {
                    unmap_fn(-1isize as HANDLE, mapped_base);
                }
                let size = if view_size.is_null() { 0 } else { *view_size as u64 };
                report_and_terminate(ipc::AllocKind::MapView, mbi.Protect, size, mapped_base as u64);
            }
            // File-backed non-image executable mapping: scan for direct
            // syscalls at full/static level. An attacker could write shellcode
            // to a file and map it; the content scan closes that gap without
            // blocking CLR's legitimate file-view PE loads.
            if (is_full_mode() || is_static_mode()) && is_file_backed {
                let view_bytes = if view_size.is_null() { 0usize } else { *view_size };
                if view_bytes > 0 {
                    let bytes = std::slice::from_raw_parts(mapped_base as *const u8, view_bytes);
                    if region_has_direct_syscalls(bytes, mapped_base as usize, false) {
                        let unmap = unmap_section_original_pub();
                        if let Some(unmap_fn) = unmap {
                            unmap_fn(-1isize as HANDLE, mapped_base);
                        }
                        let size = if view_size.is_null() { 0 } else { *view_size as u64 };
                        report_and_terminate(ipc::AllocKind::MapView, mbi.Protect, size, mapped_base as u64);
                    }
                }
            }
        }
    }

    status
}

/// Decision for a cross-process `NtWriteVirtualMemory` target that is not the
/// calling process (the self path is handled above with the P0-01
/// hook-integrity check).
#[derive(Debug, PartialEq, Eq)]
enum ForeignWriteDecision {
    /// `GetProcessId` could not resolve the handle (pid 0): let the original
    /// call fail downstream on its own merits.
    PassThrough,
    /// Self via a real handle, or a tracked owned child — the launcher's
    /// hook.dll injection path.
    Allow,
    /// Any other process. The write itself is the injection primitive;
    /// content heuristics cannot decide it.
    Deny,
}

fn foreign_write_decision(
    target_pid: u32,
    self_pid: u32,
    owned_child: bool,
) -> ForeignWriteDecision {
    if target_pid == 0 {
        ForeignWriteDecision::PassThrough
    } else if target_pid == self_pid || owned_child {
        ForeignWriteDecision::Allow
    } else {
        ForeignWriteDecision::Deny
    }
}

unsafe extern "system" fn hook_nt_write_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut c_void,
    _buffer: *const c_void,
    bytes_to_write: usize,
    bytes_written: *mut usize,
) -> NTSTATUS {
    let call_original = || {
        nt_call_original!(
            &HOOK_WRITE_MEM,
            "NtWriteVirtualMemory",
            (process_handle, base_address, _buffer, bytes_to_write, bytes_written)
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // Self-process write is fine (memcpy-style) EXCEPT when it targets an
    // executable page of a critical module (P0-01): patching detour prologues
    // through WriteProcessMemory(self) is the same unhooking primitive as
    // direct memcpy after a protect. Our own detour installer writes through
    // direct memory access during the anti_rec-held install window, so no
    // legitimate in-process path reaches this branch post-install. Enforced
    // at every guard level.
    if is_current_process(process_handle) {
        if !base_address.is_null()
            && bytes_to_write > 0
            && overlaps_critical_exec(base_address, bytes_to_write)
        {
            report_and_terminate(
                ipc::AllocKind::Write,
                0,
                bytes_to_write as u64,
                base_address as u64,
            );
        }
        return call_original();
    }

    // Foreign target: allow/deny decision, not a content heuristic. A
    // content scan only catches payload shapes it knows; any other bytes
    // (second-stage payloads, ROP stacks, data for an existing code cave)
    // sailed through. Cross-process WriteProcessMemory from inside the
    // sandbox is the injection primitive itself — fail-stop, matching the
    // foreign-exec paths of NtAllocateVirtualMemory / NtProtectVirtualMemory
    // above. Legitimate launcher injection into owned children is
    // unaffected (process_tracker::is_owned_child).
    let target_pid = winapi::um::processthreadsapi::GetProcessId(process_handle);
    let self_pid = GetCurrentProcessId();
    let owned = target_pid != 0 && crate::process_tracker::is_owned_child(target_pid);
    match foreign_write_decision(target_pid, self_pid, owned) {
        ForeignWriteDecision::PassThrough | ForeignWriteDecision::Allow => call_original(),
        ForeignWriteDecision::Deny => report_and_terminate(
            ipc::AllocKind::Write,
            0,
            bytes_to_write as u64,
            base_address as u64,
        ),
    }
}

// ---------------------------------------------------------------------------
// TLS-based re-entry guard for NtAllocateVirtualMemory
// ---------------------------------------------------------------------------

unsafe fn alloc_anti_rec_enter() -> bool {
    let idx = ALLOC_TLS_INDEX.load(std::sync::atomic::Ordering::Relaxed);
    if idx == 0xFFFFFFFF { return false; }
    // SAFETY: TlsGetValue never allocates. Returns NULL (0) if not set.
    let val = winapi::um::processthreadsapi::TlsGetValue(idx);
    if val as usize != 0 {
        return false; // already in hook on this thread
    }
    // SAFETY: TlsSetValue never allocates.
    winapi::um::processthreadsapi::TlsSetValue(idx, 1usize as *mut _);
    true
}

unsafe fn alloc_anti_rec_leave() {
    let idx = ALLOC_TLS_INDEX.load(std::sync::atomic::Ordering::Relaxed);
    if idx != 0xFFFFFFFF {
        winapi::um::processthreadsapi::TlsSetValue(idx, std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Manual inline hook for NtAllocateVirtualMemory
// ---------------------------------------------------------------------------

/// # SAFETY
/// Must be called once from install(). Patches ntdll in-place.
unsafe fn alloc_near(target: usize, size: usize) -> *mut c_void {
    // SAFETY: Try addresses within ±2GB of target in 64KB steps (allocation
    // granularity). VirtualAlloc returns NULL on failure → safe.
    let mut addr = (target & !0xFFFF).wrapping_sub(0x7FFF_0000);
    let end = (target & !0xFFFF).wrapping_add(0x7FFF_0000);
    while addr < end {
        let p = winapi::um::memoryapi::VirtualAlloc(
            addr as *mut _,
            size,
            0x1000 | 0x2000, // MEM_COMMIT | MEM_RESERVE
            0x40,             // PAGE_EXECUTE_READWRITE
        );
        if !p.is_null() { return p; }
        addr = addr.wrapping_add(0x10000);
    }
    std::ptr::null_mut()
}

/// Allocate the shared alloc-path TLS re-entry slot once. Both manual alloc
/// hooks (classic + Ex) share one slot: re-entrancy from our own bookkeeping
/// inside either hook is the same concern (TlsAlloc never uses NtAlloc).
unsafe fn ensure_alloc_tls_index() -> Result<(), Box<dyn std::error::Error>> {
    if ALLOC_TLS_INDEX.load(std::sync::atomic::Ordering::Relaxed) != 0xFFFFFFFF {
        return Ok(());
    }
    let tls_idx = winapi::um::processthreadsapi::TlsAlloc();
    if tls_idx == 0xFFFFFFFF {
        return Err("TlsAlloc failed".into());
    }
    ALLOC_TLS_INDEX.store(tls_idx, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Manual inline hook installer for a syscall stub with the prologue
/// `4c 8b d1 b8 <ssn>` (mov r10, rcx; mov eax, ssn). Copies the prologue to
/// a trampoline page near ntdll, patches the stub with a JMP to `$hook_fn`,
/// and records the site for hook-integrity verification. Shared by
/// NtAllocateVirtualMemory and NtAllocateVirtualMemoryEx (audit High sibling
/// closure) — GenericDetour produces broken trampolines on this stub family
/// (see the HOOK_ALLOC note above).
macro_rules! install_manual_syscall_hook {
    ($symbol:literal, $hook_fn:expr, $tramp_slot:expr, $active_flag:expr, $fn_ty:ty) => {{
        ensure_alloc_tls_index()?;

        let target_addr = crate::hooks::ntdll_export($symbol.as_bytes())
            .ok_or_else(|| format!("ntdll export not found: {}", $symbol))?;

        // Verify expected prologue: 4c 8b d1 b8 XX XX XX XX (8 bytes)
        let prologue = std::slice::from_raw_parts(target_addr as *const u8, 8);
        if prologue[0] != 0x4c || prologue[1] != 0x8b || prologue[2] != 0xd1 || prologue[3] != 0xb8 {
            return Err(format!(
                "unexpected {} prologue: {:02x} {:02x} {:02x} {:02x}",
                $symbol,
                prologue[0], prologue[1], prologue[2], prologue[3]
            ).into());
        }

        // Allocate trampoline page NEAR ntdll (within ±2GB for JMP rel32)
        let tramp_page = alloc_near(target_addr as usize, 4096);
        if tramp_page.is_null() {
            return Err("VirtualAlloc for trampoline failed (no space near ntdll)".into());
        }
        let tramp = tramp_page as *mut u8;

        // Trampoline: [original 8 bytes] [JMP rel32 to ntdll+8]
        std::ptr::copy_nonoverlapping(target_addr as *const u8, tramp, 8);
        let jmp_target = (target_addr as usize) + 8;
        let jmp_src = (tramp as usize) + 8 + 5;
        let rel32 = (jmp_target as isize - jmp_src as isize) as i32;
        *tramp.add(8) = 0xe9;
        std::ptr::copy_nonoverlapping(&rel32 as *const i32 as *const u8, tramp.add(9), 4);

        // SAFETY: tramp points to valid executable code matching $fn_ty.
        let trampoline_fn: $fn_ty = std::mem::transmute(tramp_page);
        let _ = $tramp_slot.set(trampoline_fn);

        // Springboard: [JMP rel32 to our hook] lives in the same near-page.
        // We write it at tramp+64. Then ntdll patch uses JMP rel32 to springboard,
        // and springboard uses indirect JMP to the real hook address.
        let spring = tramp.add(64);
        let hook_addr = $hook_fn as *const () as usize;
        // ff 25 00 00 00 00 [8-byte abs addr] = indirect JMP to absolute address
        *spring = 0xff;
        *spring.add(1) = 0x25;
        std::ptr::write_unaligned(spring.add(2) as *mut u32, 0u32); // RIP+0
        std::ptr::write_unaligned(spring.add(6) as *mut u64, hook_addr as u64);

        // Patch ntdll: JMP rel32 from the stub to springboard
        let spring_addr = spring as usize;
        let patch_src = (target_addr as usize) + 5;
        let hook_rel32 = (spring_addr as isize - patch_src as isize) as i32;

        let mut old_protect: u32 = 0;
        winapi::um::memoryapi::VirtualProtect(
            target_addr as *mut _, 8, 0x40, &mut old_protect,
        );
        let target = target_addr as *mut u8;
        *target = 0xe9;
        std::ptr::copy_nonoverlapping(&hook_rel32 as *const i32 as *const u8, target.add(1), 4);
        *target.add(5) = 0x90;
        *target.add(6) = 0x90;
        *target.add(7) = 0x90;
        let mut dummy: u32 = 0;
        winapi::um::memoryapi::VirtualProtect(
            target_addr as *mut _, 8, old_protect, &mut dummy,
        );

        // SAFETY: flush instruction cache for both trampoline and patched ntdll
        // to ensure CPU doesn't execute stale prefetched instructions.
        winapi::um::processthreadsapi::FlushInstructionCache(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            tramp_page,
            128,
        );
        winapi::um::processthreadsapi::FlushInstructionCache(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            target_addr as *mut _,
            8,
        );

        // Snapshot the patched prologue for hook-integrity verification.
        record_detour_for_watch(target_addr as usize);
        $active_flag.store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }};
}

unsafe fn install_manual_alloc_hook() -> Result<(), Box<dyn std::error::Error>> {
    install_manual_syscall_hook!(
        "NtAllocateVirtualMemory\0",
        hook_nt_allocate_virtual_memory,
        MANUAL_ALLOC_TRAMPOLINE,
        MANUAL_ALLOC_ACTIVE,
        FnNtAllocateVirtualMemory
    )
}

/// Audit High sibling closure: the same manual-hook treatment for the
/// NtAllocateVirtualMemoryEx stub (VirtualAlloc2's backend).
unsafe fn install_manual_alloc_ex_hook() -> Result<(), Box<dyn std::error::Error>> {
    install_manual_syscall_hook!(
        "NtAllocateVirtualMemoryEx\0",
        hook_nt_allocate_virtual_memory_ex,
        MANUAL_ALLOC_EX_TRAMPOLINE,
        MANUAL_ALLOC_EX_ACTIVE,
        FnNtAllocateVirtualMemoryEx
    )
}

/// Unpatch NtAllocateVirtualMemory manual hook.
unsafe fn uninstall_manual_alloc_hook() {
    if !MANUAL_ALLOC_ACTIVE.load(std::sync::atomic::Ordering::Acquire) {
        return;
    }
    // We don't restore original bytes here because DLL_PROCESS_DETACH runs during
    // process teardown — ntdll patching at that point is unsafe.
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

/// Disable memory guard hooks.
///
/// # SAFETY
/// Must be called from DLL_PROCESS_DETACH only.
pub unsafe fn uninstall() {
    // Disable hook-integrity verification FIRST: the detour teardown below
    // VirtualProtects ntdll stub pages back to writable to restore original
    // bytes, and GenericDetour::disable() must not trip the unhook check or
    // the post-op prologue verification during DLL_PROCESS_DETACH.
    MEMGUARD_UNINSTALLING.store(true, std::sync::atomic::Ordering::Release);
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
mod tests {
    use super::*;

    #[test]
    fn is_executable_page_readwrite() {
        assert!(!is_executable(0x04)); // PAGE_READWRITE
    }

    #[test]
    fn is_executable_page_execute() {
        assert!(is_executable(PAGE_EXECUTE));
    }

    #[test]
    fn is_executable_page_execute_read() {
        assert!(is_executable(PAGE_EXECUTE_READ));
    }

    #[test]
    fn is_executable_page_execute_readwrite() {
        assert!(is_executable(PAGE_EXECUTE_READWRITE));
    }

    #[test]
    fn is_executable_page_execute_writecopy() {
        assert!(is_executable(PAGE_EXECUTE_WRITECOPY));
    }

    #[test]
    fn is_executable_page_noaccess() {
        assert!(!is_executable(0x01)); // PAGE_NOACCESS
    }

    #[test]
    fn is_executable_page_readonly() {
        assert!(!is_executable(0x02)); // PAGE_READONLY
    }

    #[test]
    fn is_executable_combined_guard() {
        // PAGE_EXECUTE_READ | PAGE_GUARD (0x100)
        assert!(is_executable(0x20 | 0x100));
    }

    #[test]
    fn is_executable_zero() {
        assert!(!is_executable(0));
    }

    #[test]
    fn protect_name_covers_all_exec() {
        assert_eq!(protect_name(PAGE_EXECUTE_READWRITE), "PAGE_EXECUTE_READWRITE");
        assert_eq!(protect_name(PAGE_EXECUTE_WRITECOPY), "PAGE_EXECUTE_WRITECOPY");
        assert_eq!(protect_name(PAGE_EXECUTE_READ), "PAGE_EXECUTE_READ");
        assert_eq!(protect_name(PAGE_EXECUTE), "PAGE_EXECUTE");
        assert_eq!(protect_name(0x04), "non-execute");
    }

    #[test]
    fn is_address_in_module_null() {
        assert!(!is_address_in_module(std::ptr::null()));
    }

    #[test]
    fn is_address_in_module_ntdll() {
        // GetModuleHandleW("ntdll.dll") gives us an address inside ntdll.
        // SAFETY: ntdll.dll is always loaded.
        let hmod = unsafe {
            let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
            winapi::um::libloaderapi::GetModuleHandleW(name.as_ptr())
        };
        assert!(!hmod.is_null());
        // The module handle IS the base address — it's inside the module.
        assert!(is_address_in_module(hmod as *const c_void));
    }

    #[test]
    fn is_address_in_module_heap_allocation() {
        // Heap allocation is NOT in any module.
        let v = vec![0u8; 64];
        assert!(!is_address_in_module(v.as_ptr() as *const c_void));
    }

    #[test]
    fn module_path_for_ntdll() {
        let hmod = unsafe {
            let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
            winapi::um::libloaderapi::GetModuleHandleW(name.as_ptr())
        };
        let path = module_path_for_address(hmod as *const c_void);
        assert!(path.is_some());
        let p = path.unwrap().to_lowercase();
        assert!(p.contains("ntdll.dll"), "got: {p}");
    }

    #[test]
    fn module_path_for_heap_is_none() {
        let v = vec![0u8; 64];
        assert!(module_path_for_address(v.as_ptr() as *const c_void).is_none());
    }

    #[test]
    fn nt_current_process_check() {
        assert!(is_current_process(-1isize as HANDLE));
        assert!(!is_current_process(std::ptr::null_mut()));
        assert!(!is_current_process(42usize as HANDLE));
    }

    #[test]
    fn critical_dll_detection() {
        assert!(is_critical_dll("ntdll.dll"));
        assert!(is_critical_dll("kernel32.dll"));
        assert!(is_critical_dll("kernelbase.dll"));
        assert!(is_critical_dll("hook.dll"));
        assert!(!is_critical_dll("user32.dll"));
        assert!(!is_critical_dll("evil.dll"));
        assert!(!is_critical_dll(""));
    }

    #[test]
    fn extract_basename_lower_works() {
        assert_eq!(extract_basename_lower(r"C:\Windows\System32\ntdll.dll"), "ntdll.dll");
        assert_eq!(extract_basename_lower(r"\Device\HarddiskVolume3\Windows\System32\kernel32.dll"), "kernel32.dll");
        assert_eq!(extract_basename_lower("hook.dll"), "hook.dll");
        assert_eq!(extract_basename_lower(""), "");
    }

    #[test]
    fn is_image_mapping_for_ntdll_base() {
        // ntdll's base should be MEM_IMAGE
        let hmod = unsafe {
            let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
            winapi::um::libloaderapi::GetModuleHandleW(name.as_ptr())
        };
        assert!(!hmod.is_null());
        assert!(is_image_mapping(hmod as *const c_void));
    }

    #[test]
    fn is_image_mapping_for_heap_is_false() {
        let v = vec![0u8; 64];
        assert!(!is_image_mapping(v.as_ptr() as *const c_void));
    }

    #[test]
    fn is_system_dll_path_under_matches_whole_components() {
        // Previously-trusted layouts stay trusted under an explicit canonical
        // root; matching is whole-component, never substring.
        let root = r"\Device\HarddiskVolume3\Windows";
        assert!(is_system_dll_path_under(r"\Device\HarddiskVolume3\Windows\System32\user32.dll", root));
        assert!(is_system_dll_path_under(r"\Device\HarddiskVolume3\Windows\SysWOW64\kernel32.dll", root));
        assert!(is_system_dll_path_under(r"\device\harddiskvolume3\windows\system32\ntdll.dll", root));
        assert!(is_system_dll_path_under(
            r"\Device\HarddiskVolume3\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll",
            root
        ));
        assert!(is_system_dll_path_under(
            r"\Device\HarddiskVolume3\Windows\assembly\NativeImages_v4.0.30319_64\mscorlib\abc\mscorlib.ni.dll",
            root
        ));
        // A different volume's Windows tree is not this root.
        assert!(!is_system_dll_path_under(r"\Device\HarddiskVolume9\Windows\System32\user32.dll", root));
        // Component boundary: System32X / System32.evildir must not match.
        assert!(!is_system_dll_path_under(r"\Device\HarddiskVolume3\Windows\System32X\evil.dll", root));
        assert!(!is_system_dll_path_under(r"\Device\HarddiskVolume3\Windows\System32.evildir\evil.dll", root));
        // Nested look-alike: the trusted component must sit directly under
        // the root, not deeper in the tree.
        assert!(!is_system_dll_path_under(r"\Device\HarddiskVolume3\Windows\spoof\system32\evil.dll", root));
    }

    #[test]
    fn is_system_dll_path_rejects_spoofed_substring() {
        // Regression (audit 2026-09-19, Medium): the old implementation
        // trusted any path CONTAINING `\windows\system32\`. Every one of
        // these must be untrusted.
        assert!(!is_system_dll_path(r"\Device\HarddiskVolume9\tmp\windows\system32\evil.dll"));
        assert!(!is_system_dll_path(r"C:\tmp\windows\system32\evil.dll"));
        assert!(!is_system_dll_path(
            r"\Device\HarddiskVolume3\Users\x\AppData\Local\Temp\windows\system32\evil.dll"
        ));
        // Pre-existing negatives keep failing closed.
        assert!(!is_system_dll_path(r"\Device\HarddiskVolume3\Users\x\AppData\evil.dll"));
        assert!(!is_system_dll_path(r"\Device\HarddiskVolume3\Program Files\app\plugin.dll"));
        assert!(!is_system_dll_path(""));
    }

    #[test]
    fn is_system_dll_path_anchored_fallback() {
        // Fallback (root resolution unavailable): component-anchored at a
        // volume root — still never a substring match.
        assert!(is_system_dll_path_anchored(r"\Device\HarddiskVolume3\Windows\System32\ntdll.dll"));
        assert!(is_system_dll_path_anchored(r"C:\Windows\SysWOW64\kernel32.dll"));
        assert!(!is_system_dll_path_anchored(r"C:\tmp\windows\system32\evil.dll"));
        assert!(!is_system_dll_path_anchored(r"\Device\HarddiskVolume3\tmp\windows\system32\evil.dll"));
        assert!(!is_system_dll_path_anchored(r"\Device\HarddiskVolume3\Windows\System32X\evil.dll"));
        assert!(!is_system_dll_path_anchored(""));
    }

    #[test]
    fn is_system_dll_path_real_root_resolution() {
        // Production path: prefixes resolved from the loader's own ntdll
        // mapping. The real System32 must be trusted; the same tail planted
        // one component deeper must not.
        match trusted_windows_root_nt() {
            Some(root) => {
                assert!(is_system_dll_path(&format!("{}\\system32\\user32.dll", root)));
                assert!(is_system_dll_path(&format!("{}\\syswow64\\kernel32.dll", root)));
                assert!(!is_system_dll_path(&format!("{}\\spoof\\system32\\user32.dll", root)));
            }
            None => {
                // Root unresolved in this environment: the fallback must
                // still reject the substring spoof.
                assert!(!is_system_dll_path(r"C:\tmp\windows\system32\evil.dll"));
            }
        }
    }

    #[test]
    fn get_mapped_file_basename_for_ntdll() {
        let hmod = unsafe {
            let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
            winapi::um::libloaderapi::GetModuleHandleW(name.as_ptr())
        };
        let basename = get_mapped_file_basename(hmod as *const c_void);
        assert!(basename.is_some());
        assert_eq!(basename.unwrap(), "ntdll.dll");
    }

    // ---------------------------------------------------------------------------
    // decide_mapview_protection tests
    // ---------------------------------------------------------------------------

    #[test]
    fn decide_image_section_always_allowed() {
        // SEC_IMAGE sections: all protect values allowed, including RWX variants.
        assert!(decide_mapview_protection(true, false, PAGE_EXECUTE_WRITECOPY));
        assert!(decide_mapview_protection(true, false, PAGE_EXECUTE_READWRITE));
        assert!(decide_mapview_protection(true, false, PAGE_EXECUTE_READ));
        assert!(decide_mapview_protection(true, false, PAGE_EXECUTE));
        assert!(decide_mapview_protection(true, false, 0x04)); // PAGE_READWRITE
    }

    #[test]
    fn decide_file_backed_non_exec_allowed() {
        // MEM_MAPPED without execute: no threat.
        assert!(decide_mapview_protection(false, true, 0x02)); // PAGE_READONLY
        assert!(decide_mapview_protection(false, true, 0x04)); // PAGE_READWRITE
    }

    #[test]
    fn decide_file_backed_exec_allowed_for_clr() {
        // CLR maps .ni.dll/.dll as file-backed (MEM_MAPPED) with
        // PAGE_EXECUTE_WRITECOPY. This must be allowed — blocking it
        // terminates .NET / PowerShell at startup (bug #80).
        assert!(decide_mapview_protection(false, true, PAGE_EXECUTE_WRITECOPY));
        assert!(decide_mapview_protection(false, true, PAGE_EXECUTE_READ));
    }

    #[test]
    fn decide_private_exec_denied() {
        // Anonymous (MEM_PRIVATE) executable mapping: shellcode pattern → deny.
        assert!(!decide_mapview_protection(false, false, PAGE_EXECUTE_WRITECOPY));
        assert!(!decide_mapview_protection(false, false, PAGE_EXECUTE_READWRITE));
        assert!(!decide_mapview_protection(false, false, PAGE_EXECUTE_READ));
        assert!(!decide_mapview_protection(false, false, PAGE_EXECUTE));
    }

    #[test]
    fn decide_private_non_exec_allowed() {
        // Anonymous non-executable mapping: fine (data).
        assert!(decide_mapview_protection(false, false, 0x04)); // PAGE_READWRITE
        assert!(decide_mapview_protection(false, false, 0x02)); // PAGE_READONLY
    }

    #[test]
    fn decide_vquery_fail_exec_denied() {
        // When VirtualQuery fails (is_file_backed=false, is_image=false),
        // treat as anonymous → deny if executable.
        assert!(!decide_mapview_protection(false, false, PAGE_EXECUTE));
        // Non-executable with VirtualQuery failure: allow.
        assert!(decide_mapview_protection(false, false, 0x04));
    }

    // -------------------------------------------------------------------------
    // Hook-integrity protection (P0-01) tests
    // -------------------------------------------------------------------------

    #[test]
    fn grants_write_matrix() {
        assert!(grants_write(0x04)); // PAGE_READWRITE — the P0-01 hole
        assert!(grants_write(0x08)); // PAGE_WRITECOPY (CoW image write)
        assert!(grants_write(PAGE_EXECUTE_READWRITE));
        assert!(grants_write(PAGE_EXECUTE_WRITECOPY));
        // Modifiers must not defeat the bit test.
        assert!(grants_write(0x04 | 0x100)); // PAGE_READWRITE | PAGE_GUARD
        // Read/execute-only grants are not write grants.
        assert!(!grants_write(0x02)); // PAGE_READONLY
        assert!(!grants_write(0x01)); // PAGE_NOACCESS
        assert!(!grants_write(PAGE_EXECUTE));
        assert!(!grants_write(PAGE_EXECUTE_READ));
        assert!(!grants_write(0));
    }

    #[test]
    fn critical_range_response_matrix() {
        use CriticalRangeResponse::{Allow, Terminate, Verify};
        // Regression core: a WRITE grant on a critical range terminates even
        // though the pre-fix logic only inspected EXECUTE grants and let
        // PAGE_READWRITE straight through.
        assert_eq!(critical_range_response(true, grants_write(0x04)), Terminate);
        assert_eq!(critical_range_response(true, grants_write(PAGE_EXECUTE_READWRITE)), Terminate);
        assert_eq!(critical_range_response(true, grants_write(0x08)), Terminate);
        // Non-write protection changes on critical ranges: allow + verify.
        assert_eq!(critical_range_response(true, grants_write(PAGE_EXECUTE_READ)), Verify);
        assert_eq!(critical_range_response(true, grants_write(0x01)), Verify);
        // Outside critical ranges the pre-fix behaviour is preserved.
        assert_eq!(critical_range_response(false, grants_write(0x04)), Allow);
        assert_eq!(critical_range_response(false, grants_write(PAGE_EXECUTE_READWRITE)), Allow);
    }

    #[test]
    fn overlaps_critical_exec_covers_hooked_ntdll_stubs() {
        // The P0-01 scenario: making a HOOKED ntdll page writable must land in
        // the deny zone. Both the module base and a real syscall-stub export
        // are executable MEM_IMAGE pages of a critical module.
        // SAFETY: ntdll.dll is always loaded; GetProcAddress on a valid module
        // with a NUL-terminated name.
        let (ntdll_base, ntdll_create_file) = unsafe {
            let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
            let hmod = winapi::um::libloaderapi::GetModuleHandleW(name.as_ptr());
            assert!(!hmod.is_null());
            let proc_addr = winapi::um::libloaderapi::GetProcAddress(
                hmod,
                b"NtCreateFile\0".as_ptr() as *const i8,
            );
            assert!(
                !proc_addr.is_null(),
                "NtCreateFile export must resolve"
            );
            (hmod, proc_addr)
        };
        let stub = ntdll_create_file as usize as *const c_void;
        assert!(overlaps_critical_exec(ntdll_base as *const c_void, 0x2000));
        assert!(
            overlaps_critical_exec(stub, 16),
            "a hooked ntdll stub address must be inside the critical-exec deny zone"
        );
        // Non-critical memory stays outside the deny zone.
        let heap = vec![0u8; 64];
        assert!(!overlaps_critical_exec(heap.as_ptr() as *const c_void, 64));
        assert!(!overlaps_critical_exec(std::ptr::null(), 64));
        assert!(!overlaps_critical_exec(ntdll_base as *const c_void, 0));
    }

    #[test]
    fn overlaps_critical_exec_covers_own_image() {
        // hook.dll's own image is not under System32; the own-image span check
        // must classify it as critical. In the unit-test binary this resolves
        // to the test executable — the span logic under test is identical.
        assert!(overlaps_critical_exec(own_image_marker as *const c_void, 16));
    }

    #[test]
    fn own_image_span_resolution() {
        let (base, end) = own_image_span().expect("own image span must resolve");
        assert!(end > base);
        let marker = own_image_marker as *const () as usize;
        assert!(marker >= base && marker < end);
        let heap = vec![0u8; 64];
        let hp = heap.as_ptr() as usize;
        assert!(hp < base || hp >= end);
    }

    #[test]
    fn detour_tamper_detection() {
        // Snapshot intact → clean.
        assert_eq!(
            first_tampered_detour(&[(0x1000, [0xE9, 0x10])], |_| Some([0xE9, 0x10])),
            None
        );
        // Original ntdll prologue restored (4c 8b d1 ...) → tampered.
        assert_eq!(
            first_tampered_detour(&[(0x1000, [0xE9, 0x10])], |_| Some([0x4C, 0x8B])),
            Some(0x1000)
        );
        // x64 absolute-jump detour form (ff 25 ...) is a valid patched prologue.
        assert_eq!(
            first_tampered_detour(&[(0x2000, [0xFF, 0x25])], |_| Some([0xFF, 0x25])),
            None
        );
        // Unreadable page → fail closed.
        assert_eq!(first_tampered_detour(&[(0x3000, [0xE9, 0x10])], |_| None), Some(0x3000));
        // Multi-entry watch: reports the tampered entry.
        let watch = [(0x1000, [0xE9, 0x10]), (0x2000, [0xFF, 0x25])];
        assert_eq!(
            first_tampered_detour(&watch, |a| if a == 0x2000 {
                Some([0x4C, 0x8B])
            } else {
                Some([0xE9, 0x10])
            }),
            Some(0x2000)
        );
    }

    #[test]
    fn detour_bytes_tampered_fail_closed() {
        assert!(!detour_bytes_tampered([0xE9, 0x10], Some([0xE9, 0x10])));
        assert!(detour_bytes_tampered([0xE9, 0x10], Some([0x4C, 0x8B])));
        assert!(detour_bytes_tampered([0xE9, 0x10], None));
    }

    #[test]
    fn detour_watch_is_clean_in_test_process() {
        // The unit-test binary never runs install(), so the watch is empty and
        // verification is a no-op; under a real sandboxed process the watch
        // holds every installed detour and this same call must return None
        // while the hooks are intact. Pins the no-tamper contract end to end.
        let watch = DETOUR_WATCH.lock().unwrap();
        assert_eq!(first_tampered_detour(&watch, read_code_bytes), None);
    }

    // -------------------------------------------------------------------------
    // Full-region chunked scan (audit 2026-09-19, Medium — 64 MB scan cap)
    // -------------------------------------------------------------------------

    #[test]
    fn region_scan_empty_is_clean() {
        assert!(!region_has_direct_syscalls_with(&[], 0x1000, false, 4));
        assert!(!region_has_direct_syscalls(&[], 0x1000, false));
    }

    #[test]
    fn region_scan_finds_syscall_in_first_chunk() {
        let mut bytes = [0x90u8; 64];
        bytes[2] = 0x0F;
        bytes[3] = 0x05;
        assert!(region_has_direct_syscalls_with(&bytes, 0x1000, false, 4));
        assert!(!region_has_direct_syscalls_with(&[0x90u8; 64], 0x1000, false, 4));
    }

    #[test]
    fn region_scan_finds_syscall_straddling_chunk_boundary() {
        // chunk_size 4 with a 15-byte forward overlap: the 0F 05 pair starts
        // one byte before the chunk boundary and must still be decoded.
        let mut bytes = [0x90u8; 64];
        bytes[3] = 0x0F;
        bytes[4] = 0x05;
        assert!(region_has_direct_syscalls_with(&bytes, 0x1000, false, 4));
    }

    #[test]
    fn region_scan_finds_syscall_in_last_chunk() {
        let mut bytes = [0x90u8; 64];
        bytes[62] = 0x0F;
        bytes[63] = 0x05;
        assert!(region_has_direct_syscalls_with(&bytes, 0x1000, false, 4));
    }

    #[test]
    fn region_scan_clean_region_stays_clean_with_cache() {
        let bytes = [0x90u8; 64];
        assert!(!region_has_direct_syscalls_with(&bytes, 0x42000, true, 4));
        // Second transition of the same pages: cache-served, same verdict.
        assert!(!region_has_direct_syscalls_with(&bytes, 0x42000, true, 4));
    }

    #[test]
    fn region_scan_covers_full_chunked_region() {
        // Region larger than one decode chunk: coverage must NOT stop at the
        // chunk size (the old code skipped regions past a 64 MB cap entirely).
        let n = SCAN_CHUNK_BYTES + 1;
        let base = 0x7000_0000usize;
        // Hit straddling the first chunk boundary.
        let mut mid = vec![0x90u8; n];
        mid[SCAN_CHUNK_BYTES - 1] = 0x0F;
        mid[SCAN_CHUNK_BYTES] = 0x05;
        assert!(
            region_has_direct_syscalls(&mid, base, false),
            "syscall at the first chunk boundary must be found"
        );
        // Fresh region: hit only in the final partial chunk — proves the tail
        // is scanned. A cap here would be fail-open by construction.
        let mut tail = vec![0x90u8; n];
        tail[n - 2] = 0x0F;
        tail[n - 1] = 0x05;
        assert!(
            region_has_direct_syscalls(&tail, base + 0x1000, false),
            "syscall in the final partial chunk must be found"
        );
    }

    // -------------------------------------------------------------------------
    // Foreign NtWriteVirtualMemory decision (audit 2026-09-19, Medium)
    // -------------------------------------------------------------------------

    #[test]
    fn foreign_write_decision_matrix() {
        const SELF: u32 = 4242;
        // Unresolvable handle: pass through, the original call fails on its own.
        assert_eq!(foreign_write_decision(0, SELF, false), ForeignWriteDecision::PassThrough);
        assert_eq!(foreign_write_decision(0, SELF, true), ForeignWriteDecision::PassThrough);
        // Real handle to self (defensive — is_current_process catches it first).
        assert_eq!(foreign_write_decision(SELF, SELF, false), ForeignWriteDecision::Allow);
        // Owned child: legitimate launcher injection.
        assert_eq!(foreign_write_decision(777, SELF, true), ForeignWriteDecision::Allow);
        // Regression core: ANY other target is denied. The old code
        // content-scanned the buffer and allowed everything whose shape it
        // did not recognise.
        assert_eq!(foreign_write_decision(999, SELF, false), ForeignWriteDecision::Deny);
        assert_eq!(foreign_write_decision(4, SELF, false), ForeignWriteDecision::Deny);
    }

    // -------------------------------------------------------------------------
    // allow_rwx snapshot (audit 2026-09-19 High)
    // -------------------------------------------------------------------------

    /// Serializes env-mutating tests: the environment is process-wide while
    /// cargo test runs tests on parallel threads (same pattern as launcher
    /// nested_detection_tests::ENV_LOCK, added after exactly that flake).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// RAII guard restoring FS_SANDBOX_ALLOW_RWX on drop.
    struct AllowRwxEnvGuard(Option<std::ffi::OsString>);

    impl AllowRwxEnvGuard {
        fn capture() -> Self {
            AllowRwxEnvGuard(std::env::var_os("FS_SANDBOX_ALLOW_RWX"))
        }
    }

    impl Drop for AllowRwxEnvGuard {
        fn drop(&mut self) {
            match &self.0 {
                Some(v) => std::env::set_var("FS_SANDBOX_ALLOW_RWX", v),
                None => std::env::remove_var("FS_SANDBOX_ALLOW_RWX"),
            }
        }
    }

    /// Regression core: the guest sets FS_SANDBOX_ALLOW_RWX after startup —
    /// the per-decision gate must keep following the install-time snapshot,
    /// not the (guest-writable) environment.
    #[test]
    fn allow_rwx_snapshot_ignores_later_env_set() {
        let _lock = env_lock();
        let _g = AllowRwxEnvGuard::capture();
        std::env::remove_var("FS_SANDBOX_ALLOW_RWX");
        test_set_allow_rwx(false);
        std::env::set_var("FS_SANDBOX_ALLOW_RWX", "1");
        assert!(
            !allow_rwx(),
            "post-startup FS_SANDBOX_ALLOW_RWX=1 must not flip the snapshot"
        );
    }

    #[test]
    fn allow_rwx_snapshot_true_survives_env_removal() {
        let _lock = env_lock();
        let _g = AllowRwxEnvGuard::capture();
        std::env::set_var("FS_SANDBOX_ALLOW_RWX", "1");
        test_set_allow_rwx(true);
        std::env::remove_var("FS_SANDBOX_ALLOW_RWX");
        assert!(
            allow_rwx(),
            "post-startup env removal must not flip the snapshot"
        );
    }

    // -----------------------------------------------------------------
    // Sibling-entry closure (audit High): NtAllocateVirtualMemoryEx must
    // apply the SAME allocation decision as the classic hook. The decision
    // itself is shared (alloc_decision_kill_required) and asserted here.
    // The hook bodies cannot be invoked from unit tests because their deny
    // path terminates the process (report_and_terminate -> !), so Ex
    // entry-point presence is pinned by the sibling-drift check in hooks.rs
    // and by alloc_sibling_exports_resolve_in_ntdll below.
    // -----------------------------------------------------------------

    /// Open a real handle to a process that is neither ours nor a tracked
    /// child.
    ///
    /// This used to open PID 4 (System). System does exist on every Windows
    /// host, but OPENING it requires elevation — the assert fired on any
    /// ordinary developer machine or CI runner, which made the two tests below
    /// depend on how the suite happened to be launched rather than on the code
    /// under test.
    ///
    /// A process we spawned ourselves is openable unconditionally and is still
    /// "foreign" for this guard's purposes: `alloc_decision_kill_required`
    /// classifies by `process_tracker::is_owned_child`, and `mark_spawned` is
    /// never called under `cargo test`, so the child is not a tracked child.
    /// The handle stays valid after the child exits, and `GetProcessId` keeps
    /// working on it, so there is no race to lose.
    fn foreign_process_handle() -> HANDLE {
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        let child = std::process::Command::new("cmd.exe")
            .args(["/c", "exit"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawning a helper process must succeed");
        let pid = child.id();
        // SAFETY: OpenProcess with query-limited access on a process we just
        // created; returns NULL on failure, which we refuse to skip.
        let h = unsafe {
            winapi::um::processthreadsapi::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            )
        };
        assert!(
            !h.is_null(),
            "OpenProcess on our own helper child (pid {pid}) must succeed"
        );
        h
    }

    #[test]
    fn alloc_decision_foreign_exec_terminated() {
        let h = foreign_process_handle();
        // The VirtualAlloc2 attack shape: an executable allocation into a
        // foreign, non-owned process — exactly what the Ex sibling must
        // catch (pre-fix this call rode the unhooked Ex export).
        assert!(
            alloc_decision_kill_required(h, PAGE_EXECUTE_READWRITE),
            "foreign exec allocation must be a kill decision"
        );
        assert!(
            alloc_decision_kill_required(h, PAGE_EXECUTE),
            "foreign PAGE_EXECUTE allocation must be a kill decision"
        );
        // SAFETY: handle from OpenProcess above.
        unsafe { winapi::um::handleapi::CloseHandle(h) };
    }

    #[test]
    fn alloc_decision_foreign_non_exec_allowed() {
        let h = foreign_process_handle();
        assert!(
            !alloc_decision_kill_required(h, PAGE_READWRITE),
            "foreign non-executable allocation must pass"
        );
        // SAFETY: handle from OpenProcess above.
        unsafe { winapi::um::handleapi::CloseHandle(h) };
    }

    #[test]
    fn alloc_decision_self_rwx_static_mode() {
        // Serialize ALLOW_RWX access with the snapshot tests.
        let _lock = env_lock();
        // GUARD_MODE is install-time state and install() never runs under
        // --lib tests; pin it here (OnceLock.set is a no-op if already set).
        GUARD_MODE.set("static".to_string()).ok();
        test_set_allow_rwx(false);
        // Self RWX-direct in static (hard containment): kill decision.
        // SAFETY: GetCurrentProcess always returns the pseudo handle.
        let cur = unsafe { winapi::um::processthreadsapi::GetCurrentProcess() };
        assert!(
            alloc_decision_kill_required(cur, PAGE_EXECUTE_READWRITE),
            "self RWX-direct must be a kill decision in static mode"
        );
        // Documented escape hatch: the ALLOW_RWX snapshot permits it.
        test_set_allow_rwx(true);
        assert!(
            !alloc_decision_kill_required(cur, PAGE_EXECUTE_READWRITE),
            "allow_rwx must suppress the self-RWX kill"
        );
        test_set_allow_rwx(false);
    }

    #[test]
    fn alloc_decision_self_benign_pass() {
        // Current-process pseudo handle + non-exec protect: the JIT/loader
        // path — never a kill decision in any mode.
        // SAFETY: GetCurrentProcess always returns the pseudo handle.
        let cur = unsafe { winapi::um::processthreadsapi::GetCurrentProcess() };
        assert!(!alloc_decision_kill_required(cur, PAGE_READWRITE));

        // A REAL handle to our own process resolves through GetProcessId and
        // takes the same self branch (guards the handle-comparison path).
        // SAFETY: OpenProcess on our own pid with query-limited access.
        let h = unsafe {
            winapi::um::processthreadsapi::OpenProcess(
                0x1000,
                0,
                winapi::um::processthreadsapi::GetCurrentProcessId(),
            )
        };
        if !h.is_null() {
            assert!(is_current_process(h));
            assert!(!alloc_decision_kill_required(h, PAGE_READWRITE));
            // SAFETY: handle from OpenProcess above.
            unsafe { winapi::um::handleapi::CloseHandle(h) };
        }
    }

    /// Export-name tripwire for the alloc siblings: a typo'd / renamed
    /// export would fail install fatally, but resolution is pinned here so
    /// the drift check's list-vs-source test cannot silently rot either.
    #[test]
    fn alloc_sibling_exports_resolve_in_ntdll() {
        // SAFETY: GetProcAddress wrapper over the always-loaded ntdll.
        unsafe {
            for name in [
                "NtAllocateVirtualMemory\0",
                "NtAllocateVirtualMemoryEx\0",
            ] {
                assert!(
                    crate::hooks::ntdll_export(name.as_bytes()).is_some(),
                    "ntdll export must resolve: {name}"
                );
            }
        }
    }
}
