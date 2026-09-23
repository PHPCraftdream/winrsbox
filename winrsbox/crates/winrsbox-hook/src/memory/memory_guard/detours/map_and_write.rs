// NtMapViewOfSection + NtWriteVirtualMemory hooks.

use super::*;

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
    // pid 0 = unresolvable identity (invalid handle, or a handle with mutation
    // rights but no PROCESS_QUERY_LIMITED_INFORMATION — a documented
    // GetProcessId failure mode, XA review R02) → denied like any foreign
    // target. The self branch above only passes is_current_process, so pid 0
    // cannot reach here as self.
    // Self-process mapping continues to existing content-aware path.
    if !is_current_process(process_handle) {
        let target_pid = unsafe { winapi::um::processthreadsapi::GetProcessId(process_handle) };
        let self_pid = unsafe { GetCurrentProcessId() };
        if map_foreign_denied(target_pid, self_pid) {
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
                        // S06 gap 3: scan EVERY IMAGE_SCN_MEM_EXECUTE section,
                        // not just the one named ".text" — clean .text plus an
                        // extra executable section used to leave that section
                        // unscanned here.
                        for section in policy::scan::pe_executable_sections(header_slice) {
                            let va = section.virtual_address as usize;
                            // Skip if the section claims to start at/after the view end.
                            if va >= view_bytes {
                                continue;
                            }
                            let avail = view_bytes - va;
                            let scan_size = (section.virtual_size as usize).min(avail);
                            if scan_size == 0 {
                                continue;
                            }
                            let sec_addr = (mapped_base as usize + va) as *const u8;
                            let sec_slice = std::slice::from_raw_parts(sec_addr, scan_size);
                            if region_has_direct_syscalls(sec_slice, sec_addr as usize, false) {
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

/// Map decision (XA review R02): deny everything that is not exactly the
/// calling process. `target_pid == 0` means `GetProcessId` could not resolve
/// the handle — an invalid handle, or a documented failure mode: a handle
/// holding mutation rights without PROCESS_QUERY_LIMITED_INFORMATION.
/// Unresolvable identity is denied, not passed through.
pub(crate) fn map_foreign_denied(target_pid: u32, self_pid: u32) -> bool {
    target_pid != self_pid
}

/// Decision for a cross-process `NtWriteVirtualMemory` target that is not the
/// calling process (the self path is handled above with the P0-01
/// hook-integrity check).
///
/// A pid of 0 means `GetProcessId` could not resolve the target's identity:
/// an invalid handle, or — a documented `GetProcessId` failure mode (XA
/// review R02) — a handle holding mutation rights without
/// PROCESS_QUERY_LIMITED_INFORMATION. An unresolvable identity is DENIED,
/// matching the known-foreign response.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ForeignWriteDecision {
    /// Self via a real handle, or a tracked owned child — the launcher's
    /// hook.dll injection path.
    Allow,
    /// Any other process, and any target whose identity could not be
    /// resolved (pid 0 included). The write itself is the injection
    /// primitive; content heuristics cannot decide it.
    Deny,
}

pub(crate) fn foreign_write_decision(
    target_pid: u32,
    self_pid: u32,
    owned_child: bool,
) -> ForeignWriteDecision {
    if target_pid == 0 {
        // Unresolvable identity: never Allow, even with a stale owned flag.
        ForeignWriteDecision::Deny
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
    // pid 0 is never a tracked child (mark_spawned is gated on
    // child_pid != 0 in core/hooks/spawn.rs), so is_owned_child needs no
    // pid gate — an unresolvable identity (XA review R02) stays denied.
    let owned = crate::process_tracker::is_owned_child(target_pid);
    match foreign_write_decision(target_pid, self_pid, owned) {
        ForeignWriteDecision::Allow => call_original(),
        ForeignWriteDecision::Deny => report_and_terminate(
            ipc::AllocKind::Write,
            0,
            bytes_to_write as u64,
            base_address as u64,
        ),
    }
}
