use super::c_void;
use super::OnceLock;
use super::OWN_IMAGE_SPAN;
use super::detours::MEM_IMAGE;

// ---------------------------------------------------------------------------
// PAGE_EXECUTE_* detection
// ---------------------------------------------------------------------------

pub(crate) const PAGE_EXECUTE: u32 = 0x10;
pub(crate) const PAGE_EXECUTE_READ: u32 = 0x20;
pub(crate) const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub(crate) const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

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
pub(crate) fn get_mapped_file_path(addr: *const c_void) -> Option<String> {
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
pub(crate) fn is_system_dll_path_under(path: &str, windows_root_nt: &str) -> bool {
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
pub(crate) fn is_system_dll_path_anchored(path: &str) -> bool {
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
pub(crate) fn trusted_windows_root_nt() -> Option<&'static str> {
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

pub(crate) fn get_mapped_file_basename(addr: *const c_void) -> Option<String> {
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
pub(crate) const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;

pub fn grants_write(protect: u32) -> bool {
    protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0
}

/// What the self-process hooks must do when the requested range overlaps
/// executable pages of a critical module.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CriticalRangeResponse {
    /// Normal hook logic applies.
    Allow,
    /// Allow the operation, then re-verify the recorded detour prologues.
    Verify,
    /// WRITE grant on a hooked code page from in-process code outside the
    /// install/teardown windows — unhook attempt, terminate.
    Terminate,
}

pub(crate) fn critical_range_response(in_critical_exec: bool, write_granted: bool) -> CriticalRangeResponse {
    if !in_critical_exec {
        return CriticalRangeResponse::Allow;
    }
    if write_granted {
        CriticalRangeResponse::Terminate
    } else {
        CriticalRangeResponse::Verify
    }
}

pub(crate) const MEM_COMMIT: u32 = 0x1000;
/// Protection bits that allow reading (READONLY | READWRITE | WRITECOPY |
/// EXECUTE_READ | EXECUTE_READWRITE | EXECUTE_WRITECOPY).
pub(crate) const READABLE_MASK: u32 = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80;

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

#[inline(never)]
pub(crate) fn own_image_marker() {}

/// (base, end) of this crate's own image. In the unit-test binary this
/// resolves to the test executable — same span logic.
pub(crate) fn own_image_span() -> Option<(usize, usize)> {
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
pub(crate) fn overlaps_critical_exec(addr: *const c_void, size: usize) -> bool {
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

