// ─── Child-exit drain (scales past MAXIMUM_WAIT_OBJECTS) ─────────────────────────────

use rustc_hash::FxHashSet;
use std::time::{Duration, Instant};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0},
        System::Threading::{OpenProcess, WaitForMultipleObjects, PROCESS_SYNCHRONIZE},
    },
};

/// S09: the pipe server pushes every SpawnedChild/RegisterChild PID into the
/// queue; drain_registered_children is its only consumer (grace-window wait +
/// stale proc-table pruning). The queue is soft bookkeeping, never a trust
/// input, but an unbounded hostile push loop would still be a launcher memory
/// DoS — cap it. 4096 slots ≈ 2000 buffered spawns (SpawnedChild and
/// RegisterChild both push the same PID).
pub(crate) const CHILD_PID_QUEUE_CAP: usize = 4096;

/// Validate + bounded-push a guest-reported child PID. Rejects pid == 0 and
/// pushes beyond CHILD_PID_QUEUE_CAP. Returns false when rejected so the
/// caller can count a violation; the queue itself stays uncorrupted. The cap
/// check uses `SegQueue::len` (crossbeam-queue 0.3.12: a constant number of
/// SeqCst atomic index loads, not proportional to queue length), so calling
/// it on every push is fine at this cap. Both pipe-server arms register
/// through this helper — SpawnedChild (pipe_server/mod.rs ~589) and
/// RegisterChild (pipe_server/mod.rs ~771) — so every guest-reported PID
/// passes the 4096 cap and pid != 0 checks here.
pub(crate) fn queue_child_pid(q: &crossbeam_queue::SegQueue<u32>, pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    if q.len() >= CHILD_PID_QUEUE_CAP {
        return false;
    }
    q.push(pid);
    true
}

/// Hard limit of WaitForMultipleObjects: a call naming more handles than
/// this fails with WAIT_FAILED instead of waiting.
const MAXIMUM_WAIT_OBJECTS: usize = 64;

/// Total grace window the launcher gives all sandboxed children to exit
/// after the root target is gone. Same budget the previous single
/// WaitForMultipleObjects call used — chunking must not extend it.
const CHILD_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// The one native call the drain loop is allowed to make. A trait so the
/// loop's >64-scaling, per-exit observation and pruning are unit-testable
/// without real process handles (see `child_drain_tests`).
trait ChildWaitSet {
    /// Block until at least one handle in `keys` signals, up to
    /// `timeout_ms`. Returns the index in `keys` of a signalled handle, or
    /// None on timeout or wait failure.
    fn wait_any(&mut self, keys: &[isize], timeout_ms: u32) -> Option<usize>;
}

struct Win32ChildWaitSet;

impl ChildWaitSet for Win32ChildWaitSet {
    fn wait_any(&mut self, keys: &[isize], timeout_ms: u32) -> Option<usize> {
        debug_assert!(!keys.is_empty(), "empty wait-set would block forever");
        debug_assert!(
            keys.len() <= MAXIMUM_WAIT_OBJECTS,
            "chunk overflow: {} > {MAXIMUM_WAIT_OBJECTS} - WaitForMultipleObjects would fail",
            keys.len()
        );
        let handles: Vec<HANDLE> = keys.iter().map(|&k| HANDLE(k as *mut _)).collect();
        // SAFETY: handles are PROCESS_SYNCHRONIZE handles opened via
        //         OpenProcess at the drain site and still open while this runs.
        let code = unsafe { WaitForMultipleObjects(&handles, false, timeout_ms) };
        // WAIT_OBJECT_0 + i names a signalled handle; anything else (timeout,
        // failure) is "no observation" — the caller's deadline and final
        // zero-timeout sweep handle the rest.
        let idx = code.0.wrapping_sub(WAIT_OBJECT_0.0);
        if (idx as usize) < keys.len() { Some(idx as usize) } else { None }
    }
}

/// Wait for every child handle to signal (process exited), observing each
/// exit the moment it happens: `on_exit` runs per child exactly once, so
/// exit-pruning is never batched behind the whole set. Handles are waited
/// on in chunks of at most MAXIMUM_WAIT_OBJECTS — a process tree wider
/// than 64 children stays fully tracked, which the previous single
/// bWaitAll=true call silently did not (it failed with WAIT_FAILED and the
/// grace window never happened). One deadline bounds the TOTAL grace across
/// all chunks, so chunking cannot extend the window. A final zero-timeout
/// sweep catches exits landing between the last wait and the deadline.
/// Handles are NOT closed here — the caller owns them.
fn wait_and_prune_children<W: ChildWaitSet>(
    waiter: &mut W,
    children: &[(u32, isize)],
    grace: Duration,
    on_exit: &mut dyn FnMut(u32),
) {
    let deadline = Instant::now() + grace;
    let mut observed = vec![false; children.len()];
    loop {
        let pending: Vec<usize> = (0..children.len()).filter(|&i| !observed[i]).collect();
        if pending.is_empty() {
            return;
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        let remaining_ms = remaining.as_millis().min(u32::MAX as u128) as u32;
        let chunk: Vec<isize> = pending
            .iter()
            .take(MAXIMUM_WAIT_OBJECTS)
            .map(|&i| children[i].1)
            .collect();
        let Some(idx) = waiter.wait_any(&chunk, remaining_ms) else {
            break;
        };
        let i = pending[idx];
        observed[i] = true;
        on_exit(children[i].0);
    }
    // Zero-timeout sweep: prune children that exited between the last wait
    // and the deadline without spending any more wall-clock time.
    for i in 0..children.len() {
        if observed[i] {
            continue;
        }
        if waiter.wait_any(&[children[i].1], 0).is_some() {
            observed[i] = true;
            on_exit(children[i].0);
        }
    }
}

/// Give any remaining child processes a brief window to finish: drain the
/// PIDs registered by the hook's RegisterChild IPC, wait out the grace
/// window (see `wait_and_prune_children`) and prune every exited child from
/// the global proc table so a recycled PID is never trusted again.
pub(crate) async fn drain_registered_children(child_pids: &crossbeam_queue::SegQueue<u32>) {
    // Drain registered child PIDs into a deduplicated set and open handles.
    let mut seen = FxHashSet::default();
    let mut children: Vec<(u32, isize)> = Vec::new();
    while let Some(pid) = child_pids.pop() {
        if seen.insert(pid) {
            if let Ok(h) = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) } {
                children.push((pid, h.0 as isize));
            } else {
                // OpenProcess failed — the child is already gone and its PID
                // freed (or otherwise unreopenable); drop the dead child's
                // tracking entry so it can never be trusted again.
                super::proc_table::global_proc_info().pin().remove(&pid);
            }
        }
    }

    if !children.is_empty() {
        // The list can exceed MAXIMUM_WAIT_OBJECTS (64): a process tree wider
        // than that must still be waited on and pruned. The old single
        // WaitForMultipleObjects(bWaitAll=true) failed outright past 64
        // handles (WAIT_FAILED, result discarded) and silently skipped the
        // whole grace window; the chunked drain below keeps the same 5 s
        // budget and observes every exit.
        let wait_list = children.clone();
        tokio::task::spawn_blocking(move || {
            let mut waiter = Win32ChildWaitSet;
            wait_and_prune_children(&mut waiter, &wait_list, CHILD_DRAIN_GRACE, &mut |pid| {
                super::proc_table::global_proc_info().pin().remove(&pid);
            });
        })
        .await
        .unwrap_or_else(|e| eprintln!("[sandbox] child-wait task failed: {e}"));
        for (_, h) in &children {
            // SAFETY: h is a handle we own from OpenProcess above.
            unsafe { CloseHandle(HANDLE(*h as *mut _)).ok() };
        }
    }
}

#[cfg(test)]
mod child_drain_tests {
    use super::*;
    use std::collections::HashSet;

    /// Fake wait-set standing in for WaitForMultipleObjects: any key marked
    /// as exited signals immediately at its position; otherwise the call
    /// "times out" (None), exactly like the real API returning
    /// WAIT_TIMEOUT / WAIT_FAILED. Every call's chunk size is recorded so
    /// the tests can pin the MAXIMUM_WAIT_OBJECTS bound.
    struct FakeWaitSet {
        exited: HashSet<isize>,
        chunk_sizes: Vec<usize>,
    }

    impl FakeWaitSet {
        fn new(exited: &[isize]) -> Self {
            Self { exited: exited.iter().copied().collect(), chunk_sizes: Vec::new() }
        }
    }

    impl ChildWaitSet for FakeWaitSet {
        fn wait_any(&mut self, keys: &[isize], _timeout_ms: u32) -> Option<usize> {
            self.chunk_sizes.push(keys.len());
            keys.iter().position(|k| self.exited.contains(k))
        }
    }

    fn kids(count: u32) -> Vec<(u32, isize)> {
        (0..count).map(|i| (1000 + i, i as isize)).collect()
    }

    /// THE containment regression: a tree wider than MAXIMUM_WAIT_OBJECTS
    /// must still be waited on in full and every exit observed. The old
    /// single WaitForMultipleObjects(bWaitAll=true) call failed outright
    /// past 64 handles and observed nothing.
    #[test]
    fn more_than_64_children_all_waited_and_observed() {
        let children = kids(100); // > MAXIMUM_WAIT_OBJECTS
        let exited: Vec<isize> = children.iter().map(|(_, h)| *h).collect();
        let mut ws = FakeWaitSet::new(&exited);
        let mut pruned: Vec<u32> = Vec::new();
        wait_and_prune_children(&mut ws, &children, CHILD_DRAIN_GRACE, &mut |pid| {
            pruned.push(pid);
        });

        // every child observed exactly once
        assert_eq!(pruned.len(), children.len());
        let mut sorted = pruned.clone();
        sorted.sort_unstable();
        let mut want: Vec<u32> = children.iter().map(|(p, _)| *p).collect();
        want.sort_unstable();
        assert_eq!(sorted, want);

        // and no single native wait ever exceeded the 64-handle limit
        assert!(
            ws.chunk_sizes.iter().all(|&n| n <= MAXIMUM_WAIT_OBJECTS),
            "chunk sizes exceeded MAXIMUM_WAIT_OBJECTS: {:?}",
            ws.chunk_sizes
        );
        assert!(
            ws.chunk_sizes.iter().any(|&n| n == MAXIMUM_WAIT_OBJECTS),
            "expected at least one full chunk of {MAXIMUM_WAIT_OBJECTS}"
        );
    }

    /// Partial exits: only the exited child is observed (here via the wait
    /// loop, because it sits inside the first chunk); the rest stay
    /// unobserved and the deadline ends the drain instead of hanging.
    #[test]
    fn partial_exits_observe_only_the_exited_child() {
        let children = kids(10);
        let mut ws = FakeWaitSet::new(&[7]); // handle 7 == pid 1007 exited
        let mut pruned: Vec<u32> = Vec::new();
        wait_and_prune_children(&mut ws, &children, CHILD_DRAIN_GRACE, &mut |pid| {
            pruned.push(pid);
        });
        assert_eq!(pruned, vec![1007]);
    }

    /// Exits landing after the wait loop gave up are still caught by the
    /// final zero-timeout sweep (no extra wall-clock spent).
    #[test]
    fn sweep_catches_exit_outside_the_wait_chunk() {
        let children = kids(10);
        // handle 7 is in the first chunk, so make a later one exit instead:
        // fake that never signals inside wait_any, but does on a 0-timeout
        // call (the sweep) for handle 9.
        let mut ws = NeverSignals { sweep_exits: vec![9] };
        let mut pruned: Vec<u32> = Vec::new();
        wait_and_prune_children(&mut ws, &children, CHILD_DRAIN_GRACE, &mut |pid| {
            pruned.push(pid);
        });
        assert_eq!(pruned, vec![1009]);
    }

    /// Fake that always times out in the wait loop, but reports handle 9
    /// exited when polled with a zero timeout (the sweep's shape).
    struct NeverSignals {
        sweep_exits: Vec<isize>,
    }
    impl ChildWaitSet for NeverSignals {
        fn wait_any(&mut self, keys: &[isize], timeout_ms: u32) -> Option<usize> {
            if timeout_ms == 0 {
                return keys.iter().position(|k| self.sweep_exits.contains(k));
            }
            None
        }
    }

    /// Empty input is a no-op and never calls the native wait with an empty
    /// set (real WaitForMultipleObjects with nCount=0 is UB).
    #[test]
    fn empty_child_list_makes_no_wait_calls() {
        let mut ws = FakeWaitSet::new(&[]);
        let mut pruned: Vec<u32> = Vec::new();
        wait_and_prune_children(&mut ws, &[], CHILD_DRAIN_GRACE, &mut |pid| {
            pruned.push(pid);
        });
        assert!(pruned.is_empty());
        assert!(ws.chunk_sizes.is_empty());
    }

    /// The real Win32ChildWaitSet maps a signalled handle to the right
    /// index (here: the promptly-exiting child at index 1, while the child
    /// at index 0 is still alive) and honours the timeout on a live handle.
    #[test]
    fn win32_waitset_reports_signalled_index_and_times_out() {
        use std::os::windows::io::AsRawHandle;

        let mut fast = std::process::Command::new("cmd")
            .args(["/c", "exit 0"])
            .spawn()
            .expect("spawn cmd");
        let mut slow = std::process::Command::new("ping")
            .args(["-n", "2", "127.0.0.1"])
            .spawn()
            .expect("spawn ping");
        let fast_h = fast.as_raw_handle() as isize;
        let slow_h = slow.as_raw_handle() as isize;

        let mut ws = Win32ChildWaitSet;
        // fast is at index 1 and exits immediately; slow lives ~1s.
        let got = ws.wait_any(&[slow_h, fast_h], 10_000);
        assert_eq!(got, Some(1), "expected index 1 (the exiting child)");
        // a live process must time out, not be misreported as signalled
        let got = ws.wait_any(&[slow_h], 200);
        assert_eq!(got, None, "live child must not be reported as exited");

        fast.wait().unwrap();
        slow.wait().unwrap();
    }
}

#[cfg(test)]
mod child_queue_tests {
    use super::*;

    /// pid 0 is rejected outright (no live process ever has PID 0) and the
    /// queue is left untouched.
    #[test]
    fn queue_child_pid_rejects_zero() {
        let q = crossbeam_queue::SegQueue::<u32>::new();
        assert!(!queue_child_pid(&q, 0));
        assert_eq!(q.len(), 0);
    }

    /// Nonzero PIDs are accepted one by one and popped back in FIFO order,
    /// with `len` tracking the count.
    #[test]
    fn queue_child_pid_accepts_and_pushes() {
        let q = crossbeam_queue::SegQueue::<u32>::new();
        assert!(queue_child_pid(&q, 4100));
        assert!(queue_child_pid(&q, 4101));
        assert!(queue_child_pid(&q, 4102));
        assert_eq!(q.len(), 3);
        assert_eq!(q.pop(), Some(4100));
        assert_eq!(q.pop(), Some(4101));
        assert_eq!(q.pop(), Some(4102));
    }

    /// The cap holds: CHILD_PID_QUEUE_CAP distinct PIDs fill the queue, the
    /// next push is rejected, and the length stays exactly at the cap — a
    /// hostile push loop cannot grow launcher memory past this bound.
    #[test]
    fn queue_child_pid_enforces_cap() {
        let q = crossbeam_queue::SegQueue::<u32>::new();
        for pid in 1..=CHILD_PID_QUEUE_CAP as u32 {
            assert!(queue_child_pid(&q, pid), "pid {pid} below the cap must be accepted");
        }
        assert!(!queue_child_pid(&q, CHILD_PID_QUEUE_CAP as u32 + 1));
        assert_eq!(q.len(), CHILD_PID_QUEUE_CAP);
    }
}
