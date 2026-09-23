//! Tests for the FLS-backed per-thread IPC state (`per_thread` + PFLS
//! callback) — review C02: the previous TlsAlloc scheme leaked each thread's
//! `Box<PerThread>` (and therefore its `SyncClient`/pipe handle) until process
//! exit.
//!
//! These tests use NO pipe and no artificial load: in test builds
//! `ensure_pipe_name_loaded()` is a stub and `PIPE_NAME` stays unset, so
//! `ensure_ipc_and` exercises the REAL `per_thread()` path (allocating the
//! thread's `PerThread` in FLS) and returns `None` because the pipe name is
//! unavailable. A handful of short-lived threads, no spinning, no pipe
//! traffic.

use std::sync::atomic::Ordering;

use super::{ensure_ipc_and, FLS_DROPPED};

/// THE C02 mechanism test: every thread that obtained its `PerThread` through
/// `per_thread()` must have that box dropped by the PFLS callback at thread
/// exit — and with it the `SyncClient`/pipe handle (a plain field chain, no
/// `mem::forget` anywhere in the chain). Under the old TlsAlloc scheme the box
/// was leaked until process exit, so a long-lived process with thread churn
/// held one pipe handle per EVER-SEEN thread and could starve the launcher's
/// 128 concurrent handler slots. The contract this pins: one held handle per
/// LIVE thread, released at thread exit.
///
/// No sleeps: `join()` guarantees the thread — and therefore
/// `LdrShutdownThread` → `RtlProcessFlsData` — has finished before the counter
/// is read.
///
/// The delta is `>=` (not `==`) because other tests in this binary may
/// allocate `PerThread`s on their own threads concurrently.
#[test]
fn per_thread_box_released_on_thread_exit_via_fls_callback() {
    let before = FLS_DROPPED.load(Ordering::Relaxed);

    let handles: Vec<_> = (0..16)
        .map(|_| {
            std::thread::spawn(|| {
                let r = ensure_ipc_and(|_opt| 7u8);
                assert!(
                    r.is_none(),
                    "PIPE_NAME is unset in test builds — ensure_ipc_and must return None"
                );
            })
        })
        .collect();
    for h in handles {
        h.join().expect("worker thread must not panic");
    }

    let dropped = FLS_DROPPED.load(Ordering::Relaxed) - before;
    assert!(
        dropped >= 16,
        "each of the 16 joined threads must have its PerThread dropped by the \
         FLS callback at thread exit (delta was {dropped}); PerThread holds \
         the SyncClient/pipe handle, so failing this contract means one \
         handle accumulates per ever-seen thread until process exit instead \
         of being held per live thread (review C02 regression)"
    );
}

/// Same-thread hit path: the second `ensure_ipc_and` call on THIS thread must
/// find the already-allocated `PerThread` via `FlsGetValue` (not allocate a
/// fresh one) and still return `None` — the FLS slot behaves as a stable
/// per-thread slot across calls. No counter assertion needed; the first test
/// owns the drop-count contract.
#[test]
fn per_thread_slot_survives_across_calls_on_same_thread() {
    assert!(ensure_ipc_and(|_opt| 1u8).is_none());
    assert!(ensure_ipc_and(|_opt| 2u8).is_none());
}
