// Memory guard — preventive termination on suspicious executable memory operations.
//
// Hooks NtAllocateVirtualMemory, NtProtectVirtualMemory, and NtMapViewOfSection.
// Terminates the process if user-initiated code attempts to create executable
// memory outside of normal DLL loading.
//
// Crate versions assumed (from Cargo.toml):
//   detour  = "0.8"
//   ntapi   = "0.4"
//   winapi  = "0.3"

use std::sync::OnceLock;

use detour::GenericDetour;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS};
use winapi::ctypes::c_void;
use winapi::um::processthreadsapi::GetCurrentProcessId;

use crate::anti_rec;

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

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

static HOOK_ALLOC: OnceLock<GenericDetour<FnNtAllocateVirtualMemory>> = OnceLock::new();
static HOOK_PROTECT: OnceLock<GenericDetour<FnNtProtectVirtualMemory>> = OnceLock::new();
static HOOK_MAP_VIEW: OnceLock<GenericDetour<FnNtMapViewOfSection>> = OnceLock::new();
static HOOK_WRITE_MEM: OnceLock<GenericDetour<FnNtWriteVirtualMemory>> = OnceLock::new();
static NT_UNMAP: OnceLock<FnNtUnmapViewOfSection> = OnceLock::new();

// Guard mode: "scan" = content-aware (scan bytes for syscall), "full" = scan + DLL scan
static GUARD_MODE: OnceLock<String> = OnceLock::new();
static SCAN_CACHE: OnceLock<crate::scan_cache::ScanCache> = OnceLock::new();

fn scan_cache() -> &'static crate::scan_cache::ScanCache {
    SCAN_CACHE.get_or_init(crate::scan_cache::ScanCache::new)
}

fn is_full_mode() -> bool {
    GUARD_MODE.get().map(|s| s == "full").unwrap_or(true)
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

/// Check if a NT-device-form path points to a system DLL (System32/SysWOW64).
/// Used to skip scanning trusted Microsoft DLLs.
pub fn is_system_dll_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains(r"\windows\system32\") || lower.contains(r"\windows\syswow64\")
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
        HOOK_ALLOC.get().unwrap().call(
            process_handle, base_address, zero_bits,
            region_size, allocation_type, protect,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if is_current_process(process_handle) {
        // RWX-from-start: block only in full mode. In scan mode, allow for
        // JIT runtimes (.NET CLR, V8). Content scan on VirtualProtect remains.
        if is_rwx(protect) && !allow_rwx() && is_full_mode() {
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

    if !is_current_process(process_handle) {
        return call_original();
    }

    // anti_rec: if we're already inside a hook on this thread, pass through.
    // During process startup, NtMapViewOfSection is called heavily for DLL
    // loading. We must allow those (anti_rec handles it). After startup,
    // user code triggering this hook will have anti_rec available.
    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

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

    // Post-check: SEC_IMAGE double-map of critical system DLLs
    if is_image_mapping(mapped_base) {
        if let Some(basename) = get_mapped_file_basename(mapped_base) {
            if is_critical_dll(&basename) {
                let unmap = NT_UNMAP.get();
                if let Some(unmap_fn) = unmap {
                    // SAFETY: mapped_base was just mapped successfully; we unmap
                    // it before terminating to clean up.
                    unmap_fn(-1isize as HANDLE, mapped_base);
                }
                let size = if view_size.is_null() { 0 } else { *view_size as u64 };
                report_and_terminate(ipc::AllocKind::MapView, win32_protect, size, mapped_base as u64);
            }

            // In full mode: scan .text of user DLLs for direct syscalls
            if is_full_mode() {
            if let Some(full_path) = get_mapped_file_path(mapped_base) {
                if !is_system_dll_path(&full_path) {
                    // Read PE headers from the mapped image
                    let header_slice = std::slice::from_raw_parts(mapped_base as *const u8, 4096);
                    if let Some(text) = policy::scan::pe_text_section(header_slice) {
                        let text_addr = (mapped_base as usize + text.virtual_address as usize) as *const u8;
                        let scan_size = (text.virtual_size as usize).min(64 * 1024 * 1024);
                        let text_slice = std::slice::from_raw_parts(text_addr, scan_size);
                        let hits = policy::scan::find_direct_syscalls(text_slice, text_addr as u64);
                        if !hits.is_empty() {
                            let unmap = NT_UNMAP.get();
                            if let Some(unmap_fn) = unmap {
                                unmap_fn(-1isize as HANDLE, mapped_base);
                            }
                            let size = if view_size.is_null() { 0 } else { *view_size as u64 };
                            report_and_terminate(ipc::AllocKind::MapView, win32_protect, size, mapped_base as u64);
                        }
                    }
                }
            }
            } // is_full_mode
        }
    } else {
        // Non-image mapping: block if executable (requested OR actual protection)
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
            let unmap = NT_UNMAP.get();
            if let Some(unmap_fn) = unmap {
                unmap_fn(-1isize as HANDLE, mapped_base);
            }
            let size = if view_size.is_null() { 0 } else { *view_size as u64 };
            report_and_terminate(ipc::AllocKind::MapView, mbi.Protect, size, mapped_base as u64);
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

    install_guard!(HOOK_ALLOC,   "NtAllocateVirtualMemory\0",  hook_nt_allocate_virtual_memory, FnNtAllocateVirtualMemory);
    install_guard!(HOOK_PROTECT, "NtProtectVirtualMemory\0",   hook_nt_protect_virtual_memory,  FnNtProtectVirtualMemory);
    install_guard!(HOOK_MAP_VIEW, "NtMapViewOfSection\0",      hook_nt_map_view_of_section,     FnNtMapViewOfSection);
    install_guard!(HOOK_WRITE_MEM,"NtWriteVirtualMemory\0",    hook_nt_write_virtual_memory,    FnNtWriteVirtualMemory);
    // Resolve NtUnmapViewOfSection for cleanup before terminate
    if let Some(addr) = crate::hooks::ntdll_export("NtUnmapViewOfSection\0".as_bytes()) {
        // SAFETY: addr is a valid ntdll export with the FnNtUnmapViewOfSection signature.
        let _ = NT_UNMAP.set(std::mem::transmute::<usize, FnNtUnmapViewOfSection>(addr as usize));
    }

    Ok(())
}

/// Disable memory guard hooks.
///
/// # SAFETY
/// Must be called from DLL_PROCESS_DETACH only.
pub unsafe fn uninstall() {
    if let Some(h) = HOOK_WRITE_MEM.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_MAP_VIEW.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_ALLOC.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_PROTECT.get() { let _ = h.disable(); }
}

// ---------------------------------------------------------------------------
// pub(crate) accessors for inject_guard
// ---------------------------------------------------------------------------

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
        assert!(is_system_dll_path(r"\Device\HarddiskVolume3\Windows\System32\user32.dll"));
        assert!(is_system_dll_path(r"\Device\HarddiskVolume3\Windows\SysWOW64\kernel32.dll"));
        assert!(is_system_dll_path(r"\device\harddiskvolume1\windows\system32\ntdll.dll"));
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
}
