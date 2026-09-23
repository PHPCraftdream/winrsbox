// Anti-recursion guard: prevents re-entrant hook calls from the hook itself.
// Each thread has an independent flag so hooks in different threads don't interfere.
//
// IMPORTANT — why TlsAlloc and NOT Rust `thread_local!`:
//
// Rust `thread_local!` on the MSVC target compiles to native `__declspec(thread)`
// TLS. The access is a direct read of `TEB.ThreadLocalStoragePointer` (`gs:[0x58]`)
// followed by an indexed dereference into the static-TLS slot array:
//
//     movl <static_tls_index>(%rip), %eax
//     movq %gs:0x58, %rcx            ; TEB.ThreadLocalStoragePointer
//     movq (%rcx,%rax,8), %rax       ; ← STATUS_ACCESS_VIOLATION here
//
// hook.dll is injected late — via APC `LoadLibraryW` into the target process.
// For threads that already existed at load time (thread-pool workers that
// Schannel/WinHTTP recycle during a TLS handshake), the loader does NOT
// reliably initialize the static-TLS slot for a late-loaded DLL, so the slot
// read intermittently faults. This was the root cause of the ~1/3 crash rate
// of `iwr`/`irm` under the sandbox (STATUS_ACCESS_VIOLATION at a stable RVA,
// every fault on this exact instruction sequence).
//
// `TlsAlloc` allocates a slot in `TEB.TlsSlots` (`gs:0x1480`), a different
// array that the loader initializes for EVERY thread — including threads that
// existed before the DLL was loaded. `TlsGetValue`/`TlsSetValue` are kernel32
// function calls (not inline `gs:[0x58]` reads), so they are safe for a
// late-injected DLL. This is the standard, documented-safe mechanism for a
// DLL that cannot assume process-startup loading.

use std::sync::OnceLock;
use winapi::ctypes::c_void;
use winapi::um::processthreadsapi::{TlsAlloc, TlsGetValue, TlsSetValue};

static TLS_SLOT: OnceLock<u32> = OnceLock::new();

/// `TlsAlloc` returns this on failure.
const TLS_OUT_OF_INDEXES: u32 = 0xFFFFFFFF;

/// Resolve (allocating once) the runtime TLS slot for the in-hook flag.
fn slot() -> u32 {
    *TLS_SLOT.get_or_init(|| unsafe {
        let s = TlsAlloc();
        debug_assert!(s != TLS_OUT_OF_INDEXES, "TlsAlloc failed");
        s
    })
}

/// RAII guard that clears the in-hook flag on drop.
pub struct Guard;

impl Drop for Guard {
    fn drop(&mut self) {
        unsafe {
            TlsSetValue(slot(), std::ptr::null_mut());
        }
    }
}

/// Attempt to enter a hook. Returns Some(Guard) on success (caller is not
/// re-entrant), or None if we are already inside a hook on this thread.
///
/// # Window contract (audit 2026-09-19, Medium "anti_rec fail-open")
///
/// Everything between `enter()` and the `Guard` drop runs with hooks
/// suppressed. The window must stay this wide: it covers the hook's own
/// file/pipe I/O (e.g. ipc_client's named-pipe `CreateFileW` would
/// otherwise re-enter the FS hooks and recurse into IPC until the stack is
/// exhausted). Code inside the window therefore has three hard invariants:
///
/// 1. Never invoke guest code — no guest function pointers, and no
///    alertable waits (`SleepEx`, `WaitForSingleObjectEx(TRUE)`, overlapped
///    I/O with APC completion): a queued guest user-APC would otherwise be
///    delivered mid-frame and run with every guard suppressed. (Verified:
///    no such call exists anywhere in the hook today.)
/// 2. Assume any fault raised in-window dispatches guest vectored/SEH
///    handlers on this thread while the flag is set. The guard cannot
///    absorb that, and a VirtualQuery probe does NOT close it — another
///    thread can flip the page protection between the probe and the
///    read (XA review S03). Caller-controlled ranges are therefore read
///    only through a kernel-mediated guarded copy that returns an error
///    instead of faulting (memory_guard's guarded_scan_region);
///    in-window reads must stay confined to memory known readable.
///    Do not clear the flag during exception dispatch to "fix" this —
///    that re-opens invariant 1.
/// 3. The window must close BEFORE a callback-capable original is invoked —
///    any hooked API that can synchronously run application code on this
///    thread: `ShellExecute*` (shell verb handlers), COM activation
///    (`CoCreateInstance*`/`CoGetClassObject`/`RoGetActivationFactory`/
///    `RoActivateInstance` — in-proc server DllMain/DllGetClassObject/
///    QueryInterface), `SendMessage*` (the target window procedure runs in
///    this thread's frame). That dispatched code is guest-reachable; a
///    hooked call made from it while the flag was still set would be taken
///    for our own service code and every policy check skipped (audit F1,
///    R04). Affected guards therefore split into "decide under the window"
///    (string/struct reads, classification, deny-path pipe I/O) and "invoke
///    the original outside it"; the `enter() == None` passthrough remains
///    the only sanctioned suppressed invocation, for calls made while an
///    outer window is already held.
///
/// System DLLs called from the window for the hook's OWN bookkeeping
/// (ntdll/kernelbase calls, and the loader running system DllMains for the
/// install-time LoadLibraryW held open by `install_hooks`) are the trusted
/// system class every guard allow-lists elsewhere. That trust does NOT
/// extend to the callback-capable originals of invariant 3: shell32,
/// combase and user32 dispatching into verb handlers, in-proc servers or
/// window procedures runs APPLICATION code, whatever DLL it ships in.
/// True when this thread is already inside a hook window, without entering
/// one. Lets a guard that keeps its own re-entry counter (memory_guard's
/// allocation path) still honour the shared window — notably the install
/// window, which `install_hooks` holds open across every guard's `enable()`.
pub fn in_hook() -> bool {
    // SAFETY: `slot()` is a valid TlsAlloc slot; TlsGetValue is safe from any
    // thread and returns NULL when the slot is unset.
    unsafe { !TlsGetValue(slot()).is_null() }
}

pub fn enter() -> Option<Guard> {
    let s = slot();
    // SAFETY: `s` is a valid TlsAlloc slot; TlsGetValue is safe to call from
    // any thread and returns NULL when the slot is unset (not in hook).
    unsafe {
        if !TlsGetValue(s).is_null() {
            return None;
        }
        TlsSetValue(s, 1usize as *mut c_void);
    }
    Some(Guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset() {
        unsafe {
            TlsSetValue(slot(), std::ptr::null_mut());
        }
    }

    #[test]
    fn first_enter_succeeds() {
        reset();
        assert!(enter().is_some());
    }

    #[test]
    fn nested_enter_fails() {
        reset();
        let _g = enter().unwrap();
        assert!(enter().is_none());
    }

    /// `in_hook` must report the window without consuming it — memory_guard's
    /// allocation hooks call it to honour the install window while keeping
    /// their own re-entry counter. A version that entered the window would
    /// suppress the very hook that asked.
    #[test]
    fn in_hook_observes_window_without_consuming_it() {
        reset();
        assert!(!in_hook(), "no window held");
        let _g = enter().unwrap();
        assert!(in_hook(), "window held");
        // Still held after observing: the observation took nothing.
        assert!(in_hook());
        // And the window is genuinely still the one we hold.
        assert!(enter().is_none());
    }

    /// Dropping the guard closes the window `in_hook` reports.
    #[test]
    fn in_hook_clears_after_guard_drop() {
        reset();
        {
            let _g = enter().unwrap();
            assert!(in_hook());
        }
        assert!(!in_hook());
    }

    #[test]
    fn reenter_after_drop() {
        reset();
        {
            let _g = enter().unwrap();
        }
        let g2 = enter();
        assert!(g2.is_some());
    }

    #[test]
    fn threads_independent() {
        use std::sync::Arc;
        use std::sync::Barrier;
        let barrier = Arc::new(Barrier::new(2));
        let b2 = barrier.clone();
        let h = std::thread::spawn(move || {
            reset();
            let g = enter().unwrap();
            b2.wait();
            assert!(enter().is_none(), "nested in child should fail");
            drop(g);
            assert!(enter().is_some(), "after drop in child should succeed");
        });
        reset();
        let g = enter().unwrap();
        barrier.wait();
        assert!(enter().is_none(), "nested in main should fail");
        drop(g);
        assert!(enter().is_some(), "after drop in main should succeed");
        h.join().unwrap();
    }
}
