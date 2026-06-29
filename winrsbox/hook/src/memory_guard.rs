// Memory guard — preventive termination on suspicious executable memory operations.
//
// Hooks NtAllocateVirtualMemory, NtProtectVirtualMemory, NtMapViewOfSection,
// NtUnmapViewOfSection.
// Terminates the process if user-initiated code attempts to create executable
// memory outside of normal DLL loading.
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
use crate::hooks::{ipc_log, is_trace, STATUS_ACCESS_DENIED};

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
    std::env::var("FS_SANDBOX_ALLOW_RWX").is_ok()
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

/// Check if a NT-device-form path points to a trusted Windows system location
/// that should be exempt from the direct-syscall .text scan.
///
/// Trusted locations:
///   - System32 / SysWOW64: core Win32 DLLs (always trusted)
///   - Windows\Microsoft.NET\: CLR runtime DLLs (clr.dll, mscoreei.dll, etc.)
///   - Windows\assembly\: CLR GAC and NGen'd native images (.ni.dll).
///     NGen precompiles managed assemblies to native code; the resulting
///     .ni.dll files legitimately contain `syscall` instructions generated
///     by the CLR JIT for P/Invoke and runtime-internal calls.
///
/// All of these paths are under C:\Windows, which is write-denied in the
/// sandbox policy, so the path cannot be spoofed by the agent at runtime.
pub fn is_system_dll_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains(r"\windows\system32\")
        || lower.contains(r"\windows\syswow64\")
        || lower.contains(r"\windows\microsoft.net\")
        || lower.contains(r"\windows\assembly\")
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
// Hook: NtUnmapViewOfSection — deny foreign-process unmap (Process Hollowing)
// ---------------------------------------------------------------------------

unsafe extern "system" fn hook_nt_unmap_view_of_section(
    process_handle: HANDLE,
    base_address: *mut c_void,
) -> NTSTATUS {
    let call_original = || {
        HOOK_NT_UNMAP_VIEW.get().unwrap().call(process_handle, base_address)
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
            // Fallback: try GenericDetour (may not be set)
            HOOK_ALLOC.get().unwrap().call(
                process_handle, base_address, zero_bits,
                region_size, allocation_type, protect,
            )
        }
    };

    if !alloc_anti_rec_enter() {
        return call_original();
    }

    let result = (|| {
        if is_current_process(process_handle) {
            // Self RWX-direct allocation: the content-scan-evading JIT/shellcode
            // pattern. Blunt-killed ONLY in static (hard containment). In
            // full/scan it's allowed so RWX-direct JIT (node/V8) works; the
            // W^X JIT path is still content-scanned at NtProtect→exec time.
            if is_rwx(protect) && !allow_rwx() && is_static_mode() {
                let size = if region_size.is_null() { 0 } else { *region_size as u64 };
                let addr = if base_address.is_null() { 0 } else { *base_address as u64 };
                report_and_terminate(ipc::AllocKind::Allocate, protect, size, addr);
            }
        } else {
            let target_pid = winapi::um::processthreadsapi::GetProcessId(process_handle);
            if target_pid != 0 && !crate::process_tracker::is_owned_child(target_pid) {
                if is_executable(protect) {
                    let size = if region_size.is_null() { 0 } else { *region_size as u64 };
                    let addr = if base_address.is_null() { 0 } else { *base_address as u64 };
                    report_and_terminate(ipc::AllocKind::Allocate, protect, size, addr);
                }
            }
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
        HOOK_PROTECT.get().unwrap().call(
            process_handle, base_address, region_size,
            new_protect, old_protect,
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
            if size > 0 && size <= 64 * 1024 * 1024 {
                let bytes = std::slice::from_raw_parts(addr as *const u8, size);
                // Check scan cache first — avoids re-scanning unchanged JIT pages
                let cached = scan_cache().lookup(addr as usize, size, bytes);
                let is_clean = match cached {
                    Some(clean) => clean,
                    None => {
                        let hits = policy::scan::find_direct_syscalls(bytes, addr as u64);
                        let clean = hits.is_empty();
                        scan_cache().insert(addr as usize, size, bytes, clean);
                        clean
                    }
                };
                if !is_clean {
                    report_and_terminate(ipc::AllocKind::Protect, new_protect, size as u64, addr as u64);
                }
            }
        }
    }

    call_original()
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
        HOOK_MAP_VIEW.get().unwrap().call(
            section_handle, process_handle, base_address, zero_bits,
            commit_size, section_offset, view_size, inherit_disposition,
            allocation_type, win32_protect,
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
                                let scan_size = (text.virtual_size as usize)
                                    .min(avail)
                                    .min(64 * 1024 * 1024);
                                if scan_size > 0 {
                                    let text_addr = (mapped_base as usize + va) as *const u8;
                                    let text_slice = std::slice::from_raw_parts(text_addr, scan_size);
                                    let hits = policy::scan::find_direct_syscalls(text_slice, text_addr as u64);
                                    if !hits.is_empty() {
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
                if view_bytes > 0 && view_bytes <= 64 * 1024 * 1024 {
                    let bytes = std::slice::from_raw_parts(mapped_base as *const u8, view_bytes);
                    let hits = policy::scan::find_direct_syscalls(bytes, mapped_base as u64);
                    if !hits.is_empty() {
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

unsafe extern "system" fn hook_nt_write_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut c_void,
    buffer: *const c_void,
    bytes_to_write: usize,
    bytes_written: *mut usize,
) -> NTSTATUS {
    let call_original = || {
        HOOK_WRITE_MEM.get().unwrap().call(
            process_handle, base_address, buffer, bytes_to_write, bytes_written,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // Self-process write is fine (memcpy-style)
    if is_current_process(process_handle) {
        return call_original();
    }

    // Foreign process: distinguish our injection target from external
    let target_pid = winapi::um::processthreadsapi::GetProcessId(process_handle);
    if target_pid == 0 || crate::process_tracker::is_owned_child(target_pid) {
        return call_original();
    }

    // External process write: scan buffer for direct syscall instructions.
    // Bound the scan to avoid pathological inputs.
    if !buffer.is_null() && bytes_to_write > 0 && bytes_to_write <= 64 * 1024 * 1024 {
        let slice = std::slice::from_raw_parts(buffer as *const u8, bytes_to_write);
        let hits = policy::scan::find_direct_syscalls(slice, base_address as u64);
        if !hits.is_empty() {
            report_and_terminate(
                ipc::AllocKind::Write,
                0,
                bytes_to_write as u64,
                base_address as u64,
            );
        }
    }

    call_original()
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

unsafe fn install_manual_alloc_hook() -> Result<(), Box<dyn std::error::Error>> {
    // Allocate TLS index for re-entry guard (TlsAlloc never uses NtAlloc).
    let tls_idx = winapi::um::processthreadsapi::TlsAlloc();
    if tls_idx == 0xFFFFFFFF {
        return Err("TlsAlloc failed".into());
    }
    ALLOC_TLS_INDEX.store(tls_idx, std::sync::atomic::Ordering::Relaxed);

    let target_addr = crate::hooks::ntdll_export("NtAllocateVirtualMemory\0".as_bytes())
        .ok_or("NtAllocateVirtualMemory not found")?;

    // Verify expected prologue: 4c 8b d1 b8 XX XX XX XX (8 bytes)
    let prologue = std::slice::from_raw_parts(target_addr as *const u8, 8);
    if prologue[0] != 0x4c || prologue[1] != 0x8b || prologue[2] != 0xd1 || prologue[3] != 0xb8 {
        return Err(format!(
            "unexpected NtAllocateVirtualMemory prologue: {:02x} {:02x} {:02x} {:02x}",
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

    // SAFETY: tramp points to valid executable code matching FnNtAllocateVirtualMemory.
    let trampoline_fn: FnNtAllocateVirtualMemory = std::mem::transmute(tramp_page);
    let _ = MANUAL_ALLOC_TRAMPOLINE.set(trampoline_fn);

    // Springboard: [JMP rel32 to our hook] lives in the same near-page.
    // We write it at tramp+64. Then ntdll patch uses JMP rel32 to springboard,
    // and springboard uses indirect JMP to the real hook address.
    let spring = tramp.add(64);
    let hook_addr = hook_nt_allocate_virtual_memory as *const () as usize;
    // ff 25 00 00 00 00 [8-byte abs addr] = indirect JMP to absolute address
    *spring = 0xff;
    *spring.add(1) = 0x25;
    std::ptr::write_unaligned(spring.add(2) as *mut u32, 0u32); // RIP+0
    std::ptr::write_unaligned(spring.add(6) as *mut u64, hook_addr as u64);

    // Patch ntdll: JMP rel32 from NtAllocateVirtualMemory to springboard
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

    MANUAL_ALLOC_ACTIVE.store(true, std::sync::atomic::Ordering::Release);
    Ok(())
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
pub unsafe fn install(guard_level: &str) -> Result<(), Box<dyn std::error::Error>> {
    let _ = GUARD_MODE.set(guard_level.to_string());

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
        }};
    }

    let disabled = std::env::var("FS_SANDBOX_DISABLE_HOOKS").unwrap_or_default();
    let disabled_cats: Vec<String> = disabled.split(',').map(|s| s.trim().to_ascii_lowercase()).collect();
    let skip = |c: &str| disabled_cats.iter().any(|d| d == c);

    if !skip("mem-alloc") {
        install_manual_alloc_hook()?;
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
    fn is_system_dll_path_detection() {
        // Win32 system dirs
        assert!(is_system_dll_path(r"\Device\HarddiskVolume3\Windows\System32\user32.dll"));
        assert!(is_system_dll_path(r"\Device\HarddiskVolume3\Windows\SysWOW64\kernel32.dll"));
        assert!(is_system_dll_path(r"\device\harddiskvolume1\windows\system32\ntdll.dll"));
        // CLR runtime (.NET Framework)
        assert!(is_system_dll_path(r"\Device\HarddiskVolume4\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll"));
        assert!(is_system_dll_path(r"\Device\HarddiskVolume4\Windows\Microsoft.NET\Framework64\v4.0.30319\mscoreei.dll"));
        // NGen'd native images — contain legitimate syscall instructions
        assert!(is_system_dll_path(r"\Device\HarddiskVolume4\Windows\assembly\NativeImages_v4.0.30319_64\mscorlib\abc\mscorlib.ni.dll"));
        assert!(is_system_dll_path(r"\device\harddiskvolume3\windows\assembly\nativeimages_v4.0.30319_64\system.ni.dll"));
        // Untrusted user-space paths
        assert!(!is_system_dll_path(r"\Device\HarddiskVolume3\Users\x\AppData\evil.dll"));
        assert!(!is_system_dll_path(r"\Device\HarddiskVolume3\Program Files\app\plugin.dll"));
        assert!(!is_system_dll_path(""));
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
}
