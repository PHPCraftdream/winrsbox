use super::security::PipeSecurity;
use std::io::Read;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX},
        System::Pipes::{
            CreateNamedPipeW, DisconnectNamedPipe,
            PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
        },
    },
};

// ─── Pipe accept loop ─────────────────────────────────────────────────────────

/// Audit M-A3: cap concurrent handler tasks so a hostile sandboxed process that
/// hammers the named pipe in a loop cannot exhaust tokio's blocking pool
/// (default 512 threads) and freeze the launcher. The cap applies only to
/// per-connection handlers; the accept-side `ConnectNamedPipe` (which itself
/// uses `spawn_blocking`) is intentionally outside this budget — only one
/// accept is in flight at a time, so it never competes with handlers for
/// the cap, and leaving it uncapped guarantees the loop can always make
/// progress even when all 128 handler slots are busy.
pub(crate) const MAX_CONCURRENT_HANDLERS: usize = 128;

/// Number of parallel `ConnectNamedPipe` acceptors that share the pipe
/// namespace. Each acceptor owns its own pipe instance, so up to N clients
/// can `CreateFile`-connect simultaneously without anyone seeing
/// `ERROR_PIPE_BUSY`. Before this pool, the accept loop was single-instance:
/// MSYS2's first-run setup (which spawns ~8 helper processes in the same
/// second from a single bash invocation) raced for that one pipe, lost,
/// and burned the hook-side connect/retry budget — cascading
/// self-terminates.
///
/// 32 absorbs every burst we've measured live (MSYS2 first-run spawns 27+
/// bash helpers in 1 s, npm install, cargo build, claude-code agent fan-out)
/// with generous headroom; each instance costs only the 64 KiB in/out buffer
/// (and one tokio task while idle), so the total footprint is ~2 MiB.
pub(crate) const PIPE_ACCEPT_POOL_SIZE: usize = 32;

/// Audit (2026-09-19, Medium): message size (ipc::MAX_MSG_LEN, 16 MiB) and
/// handler concurrency (MAX_CONCURRENT_HANDLERS, 128) were each bounded,
/// but their product was not: 128 handlers each reading one maximal
/// message could hold ~2 GiB of guest-driven buffers. This budget caps the
/// TOTAL bytes of in-flight message bodies across all connections: each
/// handler reserves the guest-declared body length before the body is read
/// and holds the reservation until the message is handled. Typical
/// requests are a few hundred bytes, so normal traffic never nears the
/// cap; it only binds when many large declared sizes are in flight.
pub(crate) const MAX_INFLIGHT_MSG_BYTES: usize = 64 * 1024 * 1024;

/// How long a handler may wait for byte budget before its connection is
/// dropped. Only a pathological guest (declare a 16 MiB body, then never
/// send it, repeatedly) can exhaust the budget for long; 30 s dwarfs any
/// legitimate transfer over a local named pipe while guaranteeing the cap
/// cannot wedge the server permanently.
pub(crate) const BYTE_BUDGET_WAIT: Duration = Duration::from_secs(30);

/// Process-wide cap on total in-flight message-body bytes (see
/// MAX_INFLIGHT_MSG_BYTES). Blocking reservations via Mutex+Condvar are
/// fine here: handlers already run on blocking threads.
pub(crate) struct ByteBudget {
    max: usize,
    in_use: Mutex<usize>,
    cv: Condvar,
}

/// A live reservation of `n` bytes of the budget; released on drop.
pub(crate) struct ByteReservation<'a> {
    budget: &'a ByteBudget,
    n: usize,
}

impl ByteBudget {
    pub(crate) fn new(max: usize) -> Self {
        Self { max, in_use: Mutex::new(0), cv: Condvar::new() }
    }

    #[cfg(test)]
    pub(crate) fn try_reserve(&self, n: usize) -> Option<ByteReservation<'_>> {
        let mut in_use = self.in_use.lock().unwrap();
        if *in_use + n > self.max {
            return None;
        }
        *in_use += n;
        Some(ByteReservation { budget: self, n })
    }

    /// Block until `n` bytes fit under the cap, or `timeout` elapses.
    /// Single amounts above the whole budget are clamped to it (one
    /// oversized-but-legal message still goes through, bounded by the cap).
    pub(crate) fn reserve_timeout(&self, n: usize, timeout: Duration) -> Option<ByteReservation<'_>> {
        let n = n.min(self.max);
        let deadline = Instant::now() + timeout;
        let mut in_use = self.in_use.lock().unwrap();
        loop {
            if *in_use + n <= self.max {
                *in_use += n;
                return Some(ByteReservation { budget: self, n });
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return None;
            };
            let (guard, wait) = self.cv.wait_timeout(in_use, remaining).unwrap();
            in_use = guard;
            if wait.timed_out() {
                return None;
            }
        }
    }
}

impl Drop for ByteReservation<'_> {
    fn drop(&mut self) {
        let mut in_use = self.budget.in_use.lock().unwrap();
        *in_use -= self.n;
        drop(in_use);
        self.budget.cv.notify_all();
    }
}

/// Serves a 4-byte length prefix that was already read off the wire, then
/// delegates to the pipe. This lets `handle_connection` inspect the
/// guest-declared body length (for budget reservation) before the body is
/// read, while `ipc::read_msg` still owns the whole message parse,
/// header included.
pub(crate) struct PrefixedReader<'a, R: Read> {
    pub(crate) prefix: [u8; 4],
    pub(crate) pos: usize,
    pub(crate) inner: &'a mut R,
}

impl<R: Read> Read for PrefixedReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

/// Build one server-side instance of the launcher pipe. Pure FFI wrapper so
/// the accept loop body stays focused on the connect/validate flow. The
/// caller MUST pass `is_first = true` on exactly ONE call (the very first
/// instance created for this pipe name) to claim the kernel namespace via
/// `FILE_FLAG_FIRST_PIPE_INSTANCE`; subsequent calls MUST pass `false`
/// (the flag is illegal once an instance already exists).
///
/// Returns the handle as `isize` so it crosses tokio's `.await` / task
/// boundaries (`HANDLE`'s raw pointer is `!Send`); reconstruct with
/// `HANDLE(ph as *mut _)` on the consuming side.
pub(crate) fn create_pipe_instance(
    pipe_name_wide: &[u16],
    pipe_sec: &PipeSecurity,
    is_first: bool,
) -> Result<isize, String> {
    let dw_open_mode = if is_first {
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE
    } else {
        PIPE_ACCESS_DUPLEX
    };
    let dw_pipe_mode =
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
    // SAFETY: pipe_name_wide is a valid null-terminated UTF-16 string; pipe_sec
    //         contains a valid SECURITY_ATTRIBUTES that lives at least until the
    //         FFI call returns (caller owns it).
    unsafe {
        let h = CreateNamedPipeW(
            PCWSTR(pipe_name_wide.as_ptr()),
            dw_open_mode,
            dw_pipe_mode,
            255,    // max instances (kernel-imposed cap on this name)
            65536,  // out buffer size
            65536,  // in buffer size
            0,      // default timeout
            Some(&pipe_sec.sa as *const SECURITY_ATTRIBUTES),
        );
        if h.is_invalid() {
            Err(format!("{:?}", windows::core::Error::from_win32()))
        } else {
            Ok(h.0 as isize)
        }
    }
}

/// RAII teardown guard for an accepted pipe connection's server-side handle.
///
/// Audit M-A3 (robustness / resource leak): the per-connection handler runs
/// inside a `spawn_blocking` closure. If `handle_connection` panics, any
/// teardown written as plain statements *after* the call would be skipped
/// during unwind, leaking the pipe handle (and leaving the connection
/// un-disconnected) for that connection. This guard moves the teardown into
/// `Drop`, so `DisconnectNamedPipe` + `CloseHandle` run on *every* exit path —
/// normal return, `?`/early return, or panic-unwind.
///
/// Stores the `isize` repr of the handle (not a `HANDLE` / raw pointer) so the
/// value remains trivially `Send` across the `spawn_blocking` boundary, exactly
/// as the surrounding accept loop already does; the `HANDLE` is reconstructed
/// only inside `Drop`, on the worker thread that owns it.
///
/// panic=abort caveat: the workspace *release* profile uses `panic = "abort"`,
/// under which a panic terminates the process before unwinding and Drop does not
/// run. That is acceptable — an aborting process frees all its handles anyway.
/// Under `panic = "unwind"` (debug/test, and any future config change) the guard
/// is what prevents the leak. RAII is the correct pattern regardless of profile.
pub(crate) struct PipeConnGuard {
    /// `isize` repr of the connection's server-side pipe `HANDLE`.
    pub(crate) raw: isize,
}

impl Drop for PipeConnGuard {
    fn drop(&mut self) {
        // SAFETY: `raw` is the `isize` repr of the valid server-side pipe HANDLE
        //         for this connection, handed to us by the accept loop. It is not
        //         closed anywhere else on this path (`handle_connection`
        //         deliberately `mem::forget`s its `File` wrapper so teardown is
        //         the guard's sole responsibility), so this is the unique close.
        let h = HANDLE(self.raw as *mut _);
        unsafe { DisconnectNamedPipe(h).ok() };
        unsafe { CloseHandle(h).ok() };
    }
}
