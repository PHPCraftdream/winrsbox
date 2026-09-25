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

mod map_and_write;
mod manual_alloc;

pub(crate) use map_and_write::{hook_nt_map_view_of_section, hook_nt_write_virtual_memory};
// Decision helpers consumed only by memory_guard::tests (the hook bodies use
// them within map_and_write itself); gating keeps the lib build warning-free.
#[cfg(test)]
pub(crate) use map_and_write::{
    ForeignWriteDecision, foreign_write_decision, map_foreign_denied,
};
pub(crate) use manual_alloc::{
    install_manual_alloc_hook, install_manual_alloc_ex_hook, uninstall_manual_alloc_hook,
};
use manual_alloc::{alloc_anti_rec_enter, alloc_anti_rec_leave};

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
    // pid 0 = unresolvable identity (invalid handle, or a handle with
    // mutation rights but no PROCESS_QUERY_LIMITED_INFORMATION — a
    // documented GetProcessId failure mode, XA review R02) → denied like
    // any foreign target; only the real self PID passes.
    if unmap_foreign_denied(target_pid, self_pid) {
        // Foreign process: deny unconditionally.
        // Even our own owned children should not have their image unmapped —
        // that's the core of Process Hollowing.
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace,
                format!("mem_unmap_foreign_blocked pid={target_pid} base=0x{:x}",
                    base_address as usize));
        }
        return STATUS_ACCESS_DENIED;
    }
    call_original()
}

/// Unmap decision (XA review R02): deny everything that is not exactly the
/// calling process. `target_pid == 0` means `GetProcessId` could not resolve
/// the handle — an invalid handle, or a documented failure mode: a handle
/// holding mutation rights without PROCESS_QUERY_LIMITED_INFORMATION.
/// Unresolvable identity is denied, not passed through.
pub(crate) fn unmap_foreign_denied(target_pid: u32, self_pid: u32) -> bool {
    target_pid != self_pid
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
    // SECTION_IMAGE_INFORMATION may grow between Windows releases. We only
    // use query success, so provide spare output space and ignore its fields.
    let mut info = [0u8; 1024];
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

/// Page size for scan-range rounding (x64). VirtualProtect operates at this
/// granularity regardless of the caller-passed range.
const PAGE_SIZE: usize = 0x1000;

/// Round the caller-passed protect range `[addr, addr + size)` OUT to full
/// page boundaries, returning the rounded `(start, len)` — or None on
/// overflow (the caller must fail closed on None).
///
/// S06 gap 1 (XA review 2026-09-20): VirtualProtect changes the protection
/// of EVERY page the range touches, not just the bytes named. A RW→RX
/// request for one clean byte legitimizes execution of the whole first/last
/// page, including unscanned neighboring bytes outside the passed range.
/// The scan range is therefore widened to exactly the pages the kernel will
/// flip. The rounded range stays within pages the kernel itself touches, so
/// a legitimate call remains fully readable; anything else lands on the
/// existing `Unreadable → Deny` fail-closed path.
pub(crate) fn page_round_scan_range(addr: usize, size: usize) -> Option<(usize, usize)> {
    let start = addr & !(PAGE_SIZE - 1);
    let end = addr.checked_add(size)?.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1);
    Some((start, end - start))
}

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
            // Hash the chunk once: the same key serves the lookup and the
            // clean insert (the old lookup+insert pair hashed the bytes
            // twice on a miss; the miss path itself scans via the bool
            // predicate and never re-hashes).
            let key = crate::scan_cache::ScanCache::compute_key(chunk_addr, chunk.len(), chunk);
            match scan_cache().lookup_keyed(key) {
                Some(clean) => !clean,
                None => {
                    let dirty = policy::scan::has_direct_syscall(chunk, chunk_addr as u64);
                    if !dirty {
                        scan_cache().insert_keyed(key, true);
                    }
                    dirty
                }
            }
        } else {
            policy::scan::has_direct_syscall(chunk, chunk_addr as u64)
        };
        if dirty {
            return true;
        }
        off += chunk_len;
    }
    false
}

// ---------------------------------------------------------------------------
// Guarded (fault-safe) region read — S03 (XA review 2026-09-20)
// ---------------------------------------------------------------------------

/// Chunk size for the guarded copy scan. Small enough that the stack
/// buffer is safe on any guest thread (hooks run on the caller's stack),
/// large enough that the per-chunk copy syscall is noise next to the
/// instruction decode it feeds.
const GUARDED_SCAN_CHUNK_BYTES: usize = 16 * 1024;

/// What `guarded_scan_region` concluded about the caller-supplied range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuardedScanVerdict {
    /// Every byte was copied and the scan found no direct syscalls.
    Clean,
    /// The scan found a direct syscall instruction.
    SyscallsFound,
    /// The kernel-mediated copy could not produce the full range:
    /// unmapped, PAGE_NOACCESS/guard-protected, or partially readable.
    /// Never a fault — see `guarded_region_copy`.
    Unreadable,
}

/// Response for the protect-hook scan path, kept pure and unit-testable
/// (the hook body itself cannot run under `cargo test` — its kill path
/// terminates the process).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtectScanResponse {
    /// Scan passed; continue with the syscall.
    Proceed,
    /// Region could not be fully read: deny without calling the original.
    /// Fail-closed on purpose: skipping the scan and calling the original
    /// would let a caller hide syscall payloads behind unreadable pages
    /// and have them made executable unscanned.
    Deny,
    /// Direct syscall bytes found: terminate via report_and_terminate.
    Kill,
}

pub(crate) fn protect_scan_response(verdict: GuardedScanVerdict) -> ProtectScanResponse {
    match verdict {
        GuardedScanVerdict::Clean => ProtectScanResponse::Proceed,
        GuardedScanVerdict::SyscallsFound => ProtectScanResponse::Kill,
        GuardedScanVerdict::Unreadable => ProtectScanResponse::Deny,
    }
}

/// Copy `dst.len()` bytes from `src` in the CURRENT process without ever
/// raising a user-mode exception on this thread.
///
/// S03 (XA review 2026-09-20): the protect hook previously built a
/// `from_raw_parts` slice over the caller-controlled range and let the
/// scanner dereference it while `anti_rec` was held. A committed
/// PAGE_NOACCESS page made that read fault BEFORE the kernel call, and
/// Windows dispatches guest vectored/SEH handlers BEFORE stack unwinding
/// — guest code could then observe `anti_rec` set and call file APIs
/// through `call_original` with every guard suppressed (anti_rec
/// invariant 2 violated at the source).
///
/// `ReadProcessMemory` with the current-process pseudo handle performs a
/// kernel-mediated copy that probes the source under KERNEL SEH: an
/// unreadable source yields a failed or partial copy and an error return
/// — no user-mode exception dispatch happens, so no guest handler runs
/// and the TLS flag cannot be observed in-flight. A plain VirtualQuery
/// probe before a raw read is NOT a substitute: another thread can flip
/// the page protection between the query and the read.
///
/// Strict on purpose: returns true only when the FULL requested length
/// was copied. A partial copy (ERROR_PARTIAL_COPY) is reported as
/// failure so callers fail closed.
fn guarded_region_copy(src: *const u8, dst: &mut [u8]) -> bool {
    if src.is_null() || dst.is_empty() {
        return false;
    }
    let mut copied: usize = 0;
    // SAFETY: dst is a valid mutable buffer of dst.len() bytes. src is
    // never dereferenced by us — the kernel probes it under SEH and
    // never faults this thread. GetCurrentProcess returns the pseudo
    // handle, which is always valid.
    let ok = unsafe {
        winapi::um::memoryapi::ReadProcessMemory(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            src as *const c_void,
            dst.as_mut_ptr() as *mut c_void,
            dst.len(),
            &mut copied,
        )
    };
    ok != 0 && copied == dst.len()
}

/// Scan the range `[addr, addr + size)` for direct syscall instructions
/// through a fault-safe copy (`guarded_region_copy`), in bounded,
/// forward-overlapping chunks — the same overlap discipline as
/// `region_has_direct_syscalls_with`, applied at copy level, so an
/// instruction straddling a chunk boundary is still decoded. The scan
/// cache sees the copied snapshot; keys are content-hashed, so verdict
/// semantics are unchanged from scanning live bytes.
///
/// KNOWN LIMITATION — recorded per XA review S03, deliberately NOT fixed
/// in this patch: the `anti_rec` window this scan runs under is carried
/// by a TLS slot that lives in the guest's own address space. TlsAlloc
/// slot indices are process-wide and enumerable, so native guest code
/// that learns the index can call TlsSetValue to set the flag without
/// our consent (or clear it inside our window). The slot index therefore
/// cannot be a secret, and in-process hooks are not an impermeable
/// boundary against arbitrary native code. Closing this for real means
/// keeping the authorization state outside the guest (kernel-side or
/// out-of-process) — a redesign, not a patch.
pub(crate) fn guarded_scan_region(
    addr: *const u8,
    size: usize,
    use_cache: bool,
) -> GuardedScanVerdict {
    let mut buf = [0u8; GUARDED_SCAN_CHUNK_BYTES + SCAN_CHUNK_OVERLAP];
    let mut off = 0usize;
    while off < size {
        let n = (size - off).min(GUARDED_SCAN_CHUNK_BYTES);
        // Extend non-final chunks past the boundary so an instruction
        // split across chunks is decoded by the earlier pass (mirrors
        // the overlap rule of region_has_direct_syscalls_with).
        let ext = (n + SCAN_CHUNK_OVERLAP).min(size - off);
        // The pointer is never dereferenced here — the kernel validates
        // it during the copy; hostile/unmapped values surface as
        // `Unreadable`, not as a fault.
        let chunk = (addr as usize + off) as *const u8;
        if !guarded_region_copy(chunk, &mut buf[..ext]) {
            return GuardedScanVerdict::Unreadable;
        }
        if region_has_direct_syscalls(&buf[..ext], addr as usize + off, use_cache) {
            return GuardedScanVerdict::SyscallsFound;
        }
        off += n;
    }
    GuardedScanVerdict::Clean
}

/// Scan `[addr, addr + size)` for direct syscalls, then RE-VERIFY the
/// identical bytes immediately before the caller proceeds to the original
/// syscall. Returns the worse of the two verdicts.
///
/// KNOWN LIMITATION (TOCTOU) — S06 gap 5, XA review 2026-09-20 — recorded
/// rather than overclaimed as closed: the bytes are guest-writable RW at
/// scan time BY DEFINITION (this hook authorizes their RW→RX transition),
/// so another guest thread can write syscall bytes into the range while we
/// scan, and a SEC_IMAGE mapping likewise appears in the process before it
/// is scanned. The second pass narrows that race: when nothing changed it
/// is ~free (the scan cache keys on content hash, so the re-read hits the
/// cached verdict), and when a write DID land it re-decodes and catches
/// the tampered payload. What remains is the sliver between the second
/// pass and the kernel's protect — no in-process check can close that,
/// because the protecting syscall itself is the commit point. (A post-RX
/// write needs another NtProtect, which re-enters this hook and is
/// rescanned, so the sliver is the only window.) Residual risk accepted
/// and documented; closing it for real means moving the authorization
/// commit point outside the guest — the same redesign class as the S03
/// TLS-slot limitation documented on `guarded_scan_region` above.
pub(crate) fn guarded_scan_region_twice(
    addr: *const u8,
    size: usize,
    use_cache: bool,
) -> GuardedScanVerdict {
    let first = guarded_scan_region(addr, size, use_cache);
    if first != GuardedScanVerdict::Clean {
        return first;
    }
    guarded_scan_region(addr, size, use_cache)
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
        // SAFETY: GetProcessId is safe on any HANDLE; returns 0 on invalid,
        // and also on a handle holding mutation rights without
        // PROCESS_QUERY_LIMITED_INFORMATION (a documented failure mode, XA
        // review R02). pid 0 is never a tracked child (mark_spawned is
        // gated on child_pid != 0 in core/hooks/spawn.rs), so an
        // unresolvable identity is a kill for executable allocations.
        let target_pid = unsafe {
            winapi::um::processthreadsapi::GetProcessId(process_handle)
        };
        !crate::process_tracker::is_owned_child(target_pid) && is_executable(protect)
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

/// Protect decision (XA review R02): a foreign target is killed on an
/// executable protect unless it is a tracked owned child. `owned_child` is
/// computed by the caller from `target_pid`; because pid 0 is never a
/// tracked child, an unresolvable identity (`GetProcessId` returned 0 for a
/// handle with mutation rights but no PROCESS_QUERY_LIMITED_INFORMATION —
/// a documented failure mode) is killed like any foreign target.
pub(crate) fn protect_foreign_exec_kill(
    target_pid: u32,
    owned_child: bool,
    new_protect: u32,
) -> bool {
    // target_pid names the decision's subject for call-site symmetry with
    // the other foreign-target helpers; ownership alone decides here.
    let _ = target_pid;
    !owned_child && is_executable(new_protect)
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
        // is_owned_child(0) is always false (pid 0 is never tracked), so an
        // unresolvable identity — a handle with mutation rights but no
        // PROCESS_QUERY_LIMITED_INFORMATION, a documented GetProcessId
        // failure mode (XA review R02) — is killed on executable protect
        // like any foreign target. Non-executable protects keep passing,
        // matching the existing foreign policy.
        if protect_foreign_exec_kill(
            target_pid,
            crate::process_tracker::is_owned_child(target_pid),
            new_protect,
        ) {
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
    //
    // S03 (XA review 2026-09-20): the scan reads ONLY through the
    // kernel-mediated guarded copy — it can never fault in-window (an
    // in-window fault would dispatch the guest's own VEH with anti_rec
    // still set), and a region that cannot be fully read is DENIED, not
    // skipped: skipping would let unreadable pages carrying syscall
    // bytes be made executable unscanned.
    if is_executable(new_protect) && !base_address.is_null() {
        let addr = *base_address;
        // Skip loaded module regions (loader operations, CRT, etc.)
        if !addr.is_null() && !is_address_in_module(addr) {
            let size = if region_size.is_null() { 0 } else { *region_size };
            if size > 0 {
                // S06 gap 1: widen the scanned range to the full pages the
                // kernel will flip — see `page_round_scan_range`. Overflow
                // fails closed (None → Deny); an unreadable rounded page
                // fails closed through the existing Unreadable → Deny path.
                // S06 gap 5: the second pass re-verifies the bytes right
                // before the syscall (see `guarded_scan_region_twice`).
                let scanned = match page_round_scan_range(addr as usize, size) {
                    Some((scan_addr, scan_size)) => protect_scan_response(
                        guarded_scan_region_twice(scan_addr as *const u8, scan_size, true),
                    ),
                    None => ProtectScanResponse::Deny,
                };
                match scanned {
                    ProtectScanResponse::Kill => {
                        report_and_terminate(ipc::AllocKind::Protect, new_protect, size as u64, addr as u64);
                    }
                    ProtectScanResponse::Deny => return STATUS_ACCESS_DENIED,
                    ProtectScanResponse::Proceed => {}
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

// NtMapViewOfSection, NtWriteVirtualMemory: see detours::map_and_write.
// Manual NtAllocateVirtualMemory(Ex) hook install/uninstall: see
// detours::manual_alloc. Both re-exported above.
