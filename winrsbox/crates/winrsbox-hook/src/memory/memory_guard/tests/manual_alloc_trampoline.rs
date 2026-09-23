// R01: the manual-inline-hook trampoline page (alloc_near +
// install_manual_syscall_hook!) must be PAGE_EXECUTE_READ — not
// PAGE_EXECUTE_READWRITE — once the install completes. The oracle below is
// the page's ACTUAL protection queried via VirtualQuery on the real
// allocated page, and the install is the real one (it patches this
// process's ntdll), not a check that some call was made.

use super::*;

#[test]
fn manual_alloc_trampoline_page_is_rx_after_install() {
    let _lock = env_lock();

    // Install once per process. Nothing else under --lib tests installs the
    // manual alloc hook (memory_guard::install() never runs there), so this
    // is normally the first and only install; the flag makes a re-run a
    // verification-only no-op.
    if !MANUAL_ALLOC_ACTIVE.load(std::sync::atomic::Ordering::Acquire) {
        // SAFETY: install-time-only Win32 APIs — VirtualAlloc/VirtualProtect
        // on our own freshly allocated page plus an 8-byte patch of this
        // process's ntdll NtAllocateVirtualMemory stub. After install, the
        // hook gates every allocation in this process; PAGE_READWRITE
        // allocations cannot trip the kill gate in any guard mode.
        let res = unsafe { super::detours::install_manual_alloc_hook() };
        assert!(
            res.is_ok(),
            "manual alloc hook install must succeed: {res:?}"
        );
    }
    assert!(MANUAL_ALLOC_ACTIVE.load(std::sync::atomic::Ordering::Acquire));

    let tramp = MANUAL_ALLOC_TRAMPOLINE
        .get()
        .expect("trampoline slot must be populated by install");
    let tramp_addr = *tramp as usize;

    // The oracle: the page's ACTUAL protection, queried from the kernel —
    // not an assertion that a call was made.
    let mut mbi: winapi::um::winnt::MEMORY_BASIC_INFORMATION =
        unsafe { std::mem::zeroed() };
    let q = unsafe {
        winapi::um::memoryapi::VirtualQuery(
            tramp_addr as *const winapi::ctypes::c_void,
            &mut mbi,
            std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
        )
    };
    assert_ne!(q, 0, "VirtualQuery on the trampoline page must succeed");
    assert_eq!(mbi.State, winapi::um::winnt::MEM_COMMIT);
    assert_eq!(mbi.Type, winapi::um::winnt::MEM_PRIVATE);
    assert!(
        mbi.BaseAddress as usize <= tramp_addr
            && tramp_addr < mbi.BaseAddress as usize + mbi.RegionSize,
        "queried region must cover the trampoline page"
    );
    assert!(
        mbi.RegionSize >= 4096,
        "region must cover the full 4 KiB trampoline page"
    );
    assert_ne!(
        mbi.Protect,
        PAGE_EXECUTE_READWRITE,
        "R01 regression: trampoline page must not stay RWX"
    );
    assert_eq!(
        mbi.Protect,
        PAGE_EXECUTE_READ,
        "trampoline page must be PAGE_EXECUTE_READ after install, got {:#x}",
        mbi.Protect
    );

    // Liveness: a real allocation must still succeed through the now-live
    // hook — the RX trampoline executes (original prologue + JMP back into
    // ntdll). This is the first end-to-end execution of the manual-hook
    // family under --lib tests.
    let p = unsafe {
        winapi::um::memoryapi::VirtualAlloc(
            std::ptr::null_mut(),
            8192,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    assert!(!p.is_null(), "allocation through the live hook must succeed");
    // SAFETY: p is the base returned above; MEM_RELEASE frees the whole
    // allocation.
    let ok = unsafe {
        winapi::um::memoryapi::VirtualFree(p as *mut winapi::ctypes::c_void, 0, MEM_RELEASE)
    };
    assert!(ok != 0, "VirtualFree must succeed");
}
