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
