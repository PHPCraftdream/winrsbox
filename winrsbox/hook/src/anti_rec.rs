// Anti-recursion guard: prevents re-entrant hook calls from the hook itself.
// Each thread has an independent flag so hooks in different threads don't interfere.

use std::cell::Cell;

thread_local! {
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

/// RAII guard that clears IN_HOOK on drop.
pub struct Guard;

impl Drop for Guard {
    fn drop(&mut self) {
        IN_HOOK.with(|f| f.set(false));
    }
}

/// Attempt to enter a hook. Returns Some(Guard) on success (caller is not
/// re-entrant), or None if we are already inside a hook on this thread.
pub fn enter() -> Option<Guard> {
    IN_HOOK.with(|f| {
        if f.get() {
            None
        } else {
            f.set(true);
            Some(Guard)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset() {
        IN_HOOK.with(|f| f.set(false));
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
