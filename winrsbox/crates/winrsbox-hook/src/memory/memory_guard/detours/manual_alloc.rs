// TLS-based re-entry guard + manual inline hook for NtAllocateVirtualMemory
// (and its Ex sibling).

use super::*;

pub(super) unsafe fn alloc_anti_rec_enter() -> bool {
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

pub(super) unsafe fn alloc_anti_rec_leave() {
    let idx = ALLOC_TLS_INDEX.load(std::sync::atomic::Ordering::Relaxed);
    if idx != 0xFFFFFFFF {
        winapi::um::processthreadsapi::TlsSetValue(idx, std::ptr::null_mut());
    }
}

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

        // All trampoline-page bytes are in place (trampoline [0..13),
        // springboard [64..77)). Flush the instruction cache for the page,
        // then lock it down BEFORE the ntdll patch below: if the transition
        // or its verification fails, we bail with the stub still unpatched —
        // fail-closed, no live hook left on an RWX page. (At the end of the
        // macro the patch would already exist and neither posture would be
        // coherent: fail-open would silently keep the R01 hole, fail-closed
        // would report failure for an already-live, unwatched hook.)
        //
        // R01 residual-risk statement: the page is dedicated. Every install
        // allocates a fresh 4 KiB page (classic and Ex installs each get
        // their own) and nothing but the two code blobs above is ever
        // written to it — no writable data sits on the page, at install
        // time or after. Post-transition the hook machinery only reads and
        // executes it (uninstall never restores bytes; a re-install
        // allocates a new page; the failed-transition path leaks the page
        // once and aborts install — accepted, it is a 4 KiB one-time cost
        // on a path where the guard install fails anyway).
        //
        // R01 DynamicCodePolicy (ACG) research — measured empirically on
        // this host (Windows 10.0.19045) with SetProcessMitigationPolicy(
        // ProcessDynamicCodePolicy, ProhibitDynamicCode=1) in a standalone
        // throwaway probe (target/acg_probe/, gitignored, not committed):
        // a page transitioned RWX->PAGE_EXECUTE_READ BEFORE the policy was
        // applied can never become executable+writable again — RX->RWX,
        // RW->RX, RW->RWX VirtualProtect and fresh RWX/RX/PAGE_EXECUTE
        // VirtualAlloc all fail with ERROR_DYNAMIC_CODE_BLOCKED (1655). A
        // bare-writable state IS still reachable (RX->RW succeeds), so the
        // page can be corrupted, but the corruption cannot be executed
        // (exec cannot be restored) — tamper yields at most a fault/DoS of
        // the hook, not code execution. Conversely, an EXISTING RWX page is
        // completely unaffected by ACG (direct writes still succeed), so
        // leaving this page RWX would permanently defeat the policy for it
        // — the transition is load-bearing. Without ACG nothing enforces
        // this (any in-process code can VirtualProtect back to RWX), so
        // this transition is hardening whose write-side closure becomes
        // durable only when DynamicCodePolicy is applied to the process;
        // static mode must not be described as provably syscall-proof on
        // this basis alone.
        winapi::um::processthreadsapi::FlushInstructionCache(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            tramp_page,
            128,
        );
        let mut tramp_old_prot: u32 = 0;
        // SAFETY: tramp_page is the committed 4096-byte allocation from
        // alloc_near above; VirtualProtect only changes its protection.
        if winapi::um::memoryapi::VirtualProtect(
            tramp_page,
            4096,
            winapi::um::winnt::PAGE_EXECUTE_READ,
            &mut tramp_old_prot,
        ) == 0
        {
            return Err("VirtualProtect trampoline RWX->RX failed".into());
        }
        // Verify the ACTUAL resulting protection instead of assuming the
        // VirtualProtect took effect. Fail-closed: any mismatch aborts the
        // install before the ntdll patch exists.
        let mut mbi: winapi::um::winnt::MEMORY_BASIC_INFORMATION =
            std::mem::zeroed();
        let q = winapi::um::memoryapi::VirtualQuery(
            tramp_page,
            &mut mbi,
            std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
        );
        if q == 0
            || mbi.State != winapi::um::winnt::MEM_COMMIT
            || mbi.Protect != winapi::um::winnt::PAGE_EXECUTE_READ
            || mbi.RegionSize < 4096
        {
            return Err(format!(
                "trampoline page verify failed: expected PAGE_EXECUTE_READ, \
                 VirtualQuery={} state={:#x} protect={:#x} region={:#x}",
                q, mbi.State, mbi.Protect, mbi.RegionSize
            ).into());
        }

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

        // SAFETY: flush instruction cache for the patched ntdll stub to
        // ensure CPU doesn't execute stale prefetched instructions (the
        // trampoline page is already flushed earlier, in the lock-down
        // block above).
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
        super::hook_nt_allocate_virtual_memory,
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
        super::hook_nt_allocate_virtual_memory_ex,
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
