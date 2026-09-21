use super::anti_rec;
use super::c_void;
use super::GetCurrentProcessId;
use super::HANDLE;
use super::NTSTATUS;
use super::ipc_log;
use super::is_trace;
use super::nt_call_original;
use super::STATUS_ACCESS_DENIED;
use super::allow_rwx;
use super::is_full_mode;
use super::is_static_mode;
use super::scan_cache;
use super::unmap_section_original_pub;
use super::FnNtAllocateVirtualMemory;
use super::FnNtAllocateVirtualMemoryEx;
use super::HOOK_ALLOC;
use super::MANUAL_ALLOC_TRAMPOLINE;
use super::MANUAL_ALLOC_ACTIVE;
use super::MANUAL_ALLOC_EX_TRAMPOLINE;
use super::MANUAL_ALLOC_EX_ACTIVE;
use super::ALLOC_TLS_INDEX;
use super::HOOK_PROTECT;
use super::HOOK_MAP_VIEW;
use super::HOOK_WRITE_MEM;
use super::HOOK_NT_UNMAP_VIEW;
use super::NT_QUERY_SECTION;
use super::policy::{
    CriticalRangeResponse, critical_range_response, get_mapped_file_basename,
    get_mapped_file_path, grants_write, is_address_in_module, is_critical_dll,
    is_executable, is_rwx, is_system_dll_path, overlaps_critical_exec,
};
use super::response::{
    NT_CURRENT_PROCESS, is_current_process, record_detour_for_watch,
    report_and_terminate, teardown_in_progress, verify_detours_or_die,
};

// ---------------------------------------------------------------------------
// Hook: NtUnmapViewOfSection — deny foreign-process unmap (Process Hollowing)
// ---------------------------------------------------------------------------

pub(crate) unsafe extern "system" fn hook_nt_unmap_view_of_section(
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

pub(crate) const MEM_IMAGE: u32 = 0x1000000;

pub(crate) fn is_image_mapping(addr: *const c_void) -> bool {
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
pub(crate) const SCAN_CHUNK_BYTES: usize = 16 * 1024 * 1024;

/// Longest possible x86-64 instruction. Non-final chunks are extended this
/// many bytes into the next chunk so an instruction starting before the
/// boundary is still fully decoded by the earlier pass.
const SCAN_CHUNK_OVERLAP: usize = 15;

/// Linear-sweep `bytes` (based at `base_addr`) for direct syscall
/// instructions in bounded, forward-overlapping chunks. Returns true at the
/// first chunk that contains one. With `use_cache`, per-chunk verdicts are
/// memoized in the scan cache so repeated W^X flips of unchanged JIT pages
/// skip the decode.
pub(crate) fn region_has_direct_syscalls(bytes: &[u8], base_addr: usize, use_cache: bool) -> bool {
    region_has_direct_syscalls_with(bytes, base_addr, use_cache, SCAN_CHUNK_BYTES)
}

pub(crate) fn region_has_direct_syscalls_with(
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
/// True while this thread is inside the shared hook window (`anti_rec`).
///
/// The allocation hooks keep their own TLS re-entry counter
/// (`alloc_anti_rec_*`), which deliberately does not see that window — so
/// they used to apply the kill decision to the hook's OWN allocations. The
/// install path is the case that matters: `install_hooks` holds `anti_rec`
/// across every guard's `enable()`, and `memory_guard::install` runs first,
/// so every detour installed after it allocates an RWX trampoline through an
/// already-armed allocation hook. Under `--guard static` that is a
/// self-RWX-direct allocation, and hook.dll terminated its own process during
/// DllMain — init never signalled, the launcher killed the child, and NO
/// target could start under `static`, JIT or not.
///
/// This is the same property the protect/write hooks already have (they pass
/// through entirely when `anti_rec` is held) and it grants a guest nothing:
/// only our own code ever enters the window, and the window's invariant 1
/// forbids running guest code inside it.
pub(crate) fn in_trusted_hook_window() -> bool {
    crate::anti_rec::in_hook()
}

/// THE gate both allocation hooks apply, so they stay policy-identical by
/// construction (same reason the decision below is shared). Reads the
/// thread's window state and hands it to the pure decision.
pub(crate) fn alloc_kill_gate(process_handle: HANDLE, protect: u32) -> bool {
    alloc_decision_kill_required(process_handle, protect, in_trusted_hook_window())
}

pub(crate) fn alloc_decision_kill_required(
    process_handle: HANDLE,
    protect: u32,
    in_trusted_window: bool,
) -> bool {
    if is_current_process(process_handle) {
        // Self RWX-direct allocation: the content-scan-evading JIT/shellcode
        // pattern. Blunt-killed ONLY in static (hard containment). In
        // full/scan it's allowed so RWX-direct JIT (node/V8) works; the
        // W^X JIT path is still content-scanned at NtProtect->exec time.
        //
        // `in_trusted_window` excuses exactly one caller: ourselves. Detour
        // trampolines are allocated RWX while `install_hooks` holds
        // `anti_rec` across every guard's `enable()`, and memory_guard
        // installs first — so in static mode hook.dll used to terminate its
        // own process during DllMain and no target could start at all. The
        // exemption is deliberately confined to THIS branch: a foreign-process
        // allocation stays a kill regardless of the window (see below).
        is_rwx(protect) && !allow_rwx() && is_static_mode() && !in_trusted_window
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
        if alloc_kill_gate(process_handle, protect) {
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
        if alloc_kill_gate(process_handle, protect) {
            let size = if region_size.is_null() { 0 } else { *region_size as u64 };
            let addr = if base_address.is_null() { 0 } else { *base_address as u64 };
            report_and_terminate(ipc::AllocKind::Allocate, protect, size, addr);
        }
        call_original()
    })();

    alloc_anti_rec_leave();
    result
}

pub(crate) unsafe extern "system" fn hook_nt_protect_virtual_memory(
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
            if !teardown_in_progress() && overlaps_critical_exec(addr, size) {
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

pub(crate) unsafe extern "system" fn hook_nt_map_view_of_section(
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
pub(crate) enum ForeignWriteDecision {
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

pub(crate) fn foreign_write_decision(
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

pub(crate) unsafe extern "system" fn hook_nt_write_virtual_memory(
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
            && !teardown_in_progress()
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

pub(crate) unsafe fn install_manual_alloc_hook() -> Result<(), Box<dyn std::error::Error>> {
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
pub(crate) unsafe fn install_manual_alloc_ex_hook() -> Result<(), Box<dyn std::error::Error>> {
    install_manual_syscall_hook!(
        "NtAllocateVirtualMemoryEx\0",
        hook_nt_allocate_virtual_memory_ex,
        MANUAL_ALLOC_EX_TRAMPOLINE,
        MANUAL_ALLOC_EX_ACTIVE,
        FnNtAllocateVirtualMemoryEx
    )
}

/// Unpatch NtAllocateVirtualMemory manual hook.
pub(crate) unsafe fn uninstall_manual_alloc_hook() {
    if !MANUAL_ALLOC_ACTIVE.load(std::sync::atomic::Ordering::Acquire) {
        return;
    }
    // We don't restore original bytes here because DLL_PROCESS_DETACH runs during
    // process teardown — ntdll patching at that point is unsafe.
}

