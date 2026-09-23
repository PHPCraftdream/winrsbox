//! Synchronous (no-tokio) IPC client for hook.dll.
//!
//! Split out of lib.rs together with [`crate::timed_pipe`]: the timed
//! transport (`SyncIo::Timed`) is what makes a live-but-silent launcher
//! survivable — before it existed, `send` could block a hooked process's
//! thread forever and the hook's fail-closed counter (which only counts
//! calls that RETURN) could never advance.

use std::io;
use std::time::{Duration, Instant};

use crate::framing::shrink_scratch;
use crate::timed_pipe::TimedPipe;
use crate::{
    decode_frame, encode_msg_into, frame_len_guard, read_msg_with_buf, write_msg_with_buf,
    IpcError, Req, Resp,
};

/// Sync IPC client (для hook.dll — без tokio).
///
/// Per-connection scratch buffers (`enc`/`frame`/`recv`) are reused across
/// every exchange so steady-state traffic neither allocates nor pre-zeroes
/// fresh Vecs per message; a one-off huge frame's peak capacity is released
/// again via [`crate::framing::SCRATCH_SOFT_CAP`] (see `shrink_scratch`).
pub struct SyncClient {
    io: SyncIo,
    /// Encode scratch, reused by both transports.
    enc: Vec<u8>,
    /// Coalesced outbound frame scratch (4-byte prefix + body, one write).
    frame: Vec<u8>,
    /// Inbound frame body scratch.
    recv: Vec<u8>,
}

/// Transport behind a `SyncClient`. `Timed` is the production path — every
/// op bounded by a per-exchange deadline; `Raw` exists only so tests can
/// inject an arbitrary `std::fs::File` (no deadline there, see
/// `from_file_for_test`).
enum SyncIo {
    Timed(TimedPipe),
    Raw(std::fs::File),
}

/// Retry budget for the hook→launcher pipe connect. 60 attempts × 150 ms ≈
/// 9 s of patience.
///
/// History: started at 10×50 ms (500 ms), raised to 30×100 ms (3 s), now
/// 60×150 ms (9 s). Under MSYS2 first-run 27+ bash helpers spawn in 1 s;
/// even with a 32-instance accept pool, late children may see transient
/// `ERROR_PIPE_BUSY` while the pool drains the burst. 9 s gives generous
/// headroom without meaningfully delaying a genuine "launcher dead" detect
/// (the hook-side fail-closed bound is IPC_FAIL_THRESHOLD × (connect retry
/// budget on reconnects; `SEND_TIMEOUT` on a stuck established call) —
/// stuck established reads are now deadline-bounded too, so that bound
/// covers them).
pub const CONNECT_RETRY_ATTEMPTS: u32 = 60;
pub const CONNECT_RETRY_INTERVAL_MS: u64 = 150;

/// Per-exchange deadline for the timed send path.
///
/// WHY 10 s: launcher handlers are in-memory with observed round-trips of
/// sub-ms to a few ms, so 10 s sits ~3 orders of magnitude above any
/// legitimate exchange and never fires on healthy traffic; a hung (accepted
/// but silent) launcher, on the other hand, now unblocks the hook thread and
/// lets the hook's IPC_CONSECUTIVE_FAILURES counter advance — it can only
/// count calls that return, and before this deadline existed a stuck call
/// never did. Worst case 8 stuck calls × 10 s ≈ 80 s to fail-closed
/// self-terminate, instead of "never" before.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(10);

impl SyncClient {
    /// Открыть соединение к launcher pipe.
    ///
    /// Retry policy: `CONNECT_RETRY_ATTEMPTS` × `CONNECT_RETRY_INTERVAL_MS`.
    /// See the doc on those constants for the budget rationale.
    pub fn connect(pipe_name: &str) -> Result<Self, IpcError> {
        let mut last_err = None;
        for _ in 0..CONNECT_RETRY_ATTEMPTS {
            match TimedPipe::open_named_pipe(pipe_name) {
                Ok(pipe) => {
                    return Ok(Self {
                        io: SyncIo::Timed(pipe),
                        enc: Vec::new(),
                        frame: Vec::new(),
                        recv: Vec::new(),
                    })
                }
                Err(e) => {
                    last_err = Some(e);
                    std::thread::sleep(
                        std::time::Duration::from_millis(CONNECT_RETRY_INTERVAL_MS),
                    );
                }
            }
        }
        let detail = last_err
            .map(|e| format!("{} attempts, last os error: {e}", CONNECT_RETRY_ATTEMPTS))
            .unwrap_or_else(|| "no attempts".into());
        Err(IpcError::Io(io::Error::new(io::ErrorKind::TimedOut, detail)))
    }

    pub fn send(&mut self, req: &Req) -> Result<Resp, IpcError> {
        self.send_with_timeout(req, SEND_TIMEOUT)
    }

    /// `send` with an explicit deadline for the whole exchange (write +
    /// length-prefixed read share one deadline). Test hook for the timeout
    /// path; production callers go through `send`/`SEND_TIMEOUT`.
    pub fn send_with_timeout(&mut self, req: &Req, timeout: Duration) -> Result<Resp, IpcError> {
        match &mut self.io {
            SyncIo::Timed(pipe) => {
                send_timed(pipe, req, timeout, &mut self.enc, &mut self.frame, &mut self.recv)
            }
            SyncIo::Raw(file) => {
                write_msg_with_buf(file, req, &mut self.enc)?;
                read_msg_with_buf(file, &mut self.recv)
            }
        }
    }

    /// Test-only constructor: wrap an arbitrary `std::fs::File` (typically
    /// the write-end of an anonymous pipe whose read-end has been closed,
    /// so `write` is guaranteed to fail) into a `SyncClient`. The `send`
    /// method then returns `Err` on the first call, which is what we need
    /// to drive the reconnect-on-error path in `hook::ipc_client::try_send`
    /// from a unit test.
    ///
    /// Hidden from rustdoc and stable callers. Behaviour for production
    /// callers is exactly equivalent to `connect` followed by an immediate
    /// pipe break — nothing to gain, nothing to lose. NOTE: the wrapped file
    /// rides the `SyncIo::Raw` path, which has NO deadline — this
    /// constructor is test-only precisely because of that.
    #[doc(hidden)]
    pub fn from_file_for_test(pipe: std::fs::File) -> Self {
        Self {
            io: SyncIo::Raw(pipe),
            enc: Vec::new(),
            frame: Vec::new(),
            recv: Vec::new(),
        }
    }
    /// Raw NT handle of the connected pipe, for the client-side server-identity check (GetNamedPipeServerProcessId). Borrowed — do not close.
    pub fn pipe_raw_handle(&self) -> std::os::windows::io::RawHandle {
        use std::os::windows::io::AsRawHandle;
        match &self.io {
            SyncIo::Timed(pipe) => pipe.as_raw_handle(),
            SyncIo::Raw(file) => file.as_raw_handle(),
        }
    }
}

/// Timed exchange over an established pipe: one frame out, one frame back,
/// both against the same deadline. Mirrors `write_msg`/`read_msg` step for
/// step (via the shared encode/guard/decode helpers in `crate::framing`) so
/// the timed path cannot drift from the protocol the launcher speaks.
///
/// The three scratch buffers come from the owning `SyncClient` and are
/// reused across exchanges; the single-coalesced-write property of `frame`
/// is preserved (a deadline that expired mid-frame can never strand half a
/// message in the pipe). `TimedPipe::read_exact_deadline` needs an
/// initialised `&mut [u8]`, so the inbound body keeps its zeroing `resize`
/// (safe Rust only).
fn send_timed(
    pipe: &TimedPipe,
    req: &Req,
    timeout: Duration,
    enc: &mut Vec<u8>,
    frame: &mut Vec<u8>,
    recv: &mut Vec<u8>,
) -> Result<Resp, IpcError> {
    encode_msg_into(req, enc)?;
    // One buffer for prefix + body: a deadline that expired mid-frame can
    // never strand half a message in the pipe.
    frame.clear();
    frame.reserve(4 + enc.len());
    frame.extend_from_slice(&(enc.len() as u32).to_le_bytes());
    frame.extend_from_slice(enc);
    let deadline = Instant::now() + timeout;
    pipe.write_all_deadline(frame, deadline).map_err(IpcError::Io)?;
    let mut len_buf = [0u8; 4];
    pipe.read_exact_deadline(&mut len_buf, deadline).map_err(IpcError::Io)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    frame_len_guard(len)?;
    recv.clear();
    recv.reserve(len);
    recv.resize(len, 0);
    pipe.read_exact_deadline(recv, deadline).map_err(IpcError::Io)?;
    let resp = decode_frame(recv)?;
    // Release a one-off huge frame's peak capacity (shrink only after the
    // body bytes are gone — shrink_to never drops capacity below len).
    recv.clear();
    shrink_scratch(recv);
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::FromRawHandle;
    use std::ptr;
    use std::sync::atomic::{AtomicU32, Ordering};

    use winapi::shared::ntdef::HANDLE;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::namedpipeapi::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe};
    use winapi::um::winbase::{
        PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
        PIPE_WAIT,
    };

    /// Unique-per-run pipe name: two `cargo test` processes in the same
    /// session must never collide on the 1-instance server.
    static PIPE_SEQ: AtomicU32 = AtomicU32::new(0);
    fn unique_pipe_name() -> String {
        let n = PIPE_SEQ.fetch_add(1, Ordering::Relaxed);
        format!(r"\\.\pipe\winrsbox-ipc-timeout-{}-{n}", std::process::id())
    }

    /// RAII in-process named-pipe server. Drop does
    /// DisconnectNamedPipe + CloseHandle, so a panicking test can't leak the
    /// kernel handle or leave a server instance registered under the name.
    ///
    /// Safety: `Send` because the raw HANDLE is an owned kernel value with
    /// no thread affinity — each test transfers it to exactly one accept
    /// thread, which alone touches it until the handle is joined back and
    /// dropped on the originating thread.
    struct PipeServer {
        handle: HANDLE,
    }
    unsafe impl Send for PipeServer {}
    impl PipeServer {
        fn new(name: &str) -> Self {
            let mut wide: Vec<u16> = name.encode_utf16().collect();
            wide.push(0);
            let handle = unsafe {
                CreateNamedPipeW(
                    wide.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    1, // single instance — exactly one client per test
                    4096,
                    4096,
                    0, // default wait timeout
                    ptr::null_mut(),
                )
            };
            assert!(
                handle != INVALID_HANDLE_VALUE,
                "CreateNamedPipeW failed: {}",
                unsafe { GetLastError() }
            );
            Self { handle }
        }
        fn handle(&self) -> HANDLE {
            self.handle
        }
    }
    impl Drop for PipeServer {
        fn drop(&mut self) {
            unsafe {
                DisconnectNamedPipe(self.handle);
                CloseHandle(self.handle);
            }
        }
    }

    /// Borrow the server's pipe handle as a std File alias for serving with
    /// the exact `ipc::read_msg`/`ipc::write_msg` the launcher speaks. The
    /// alias is never dropped (ManuallyDrop): only `PipeServer::drop` closes
    /// the handle once.
    fn server_file(server: &PipeServer) -> std::mem::ManuallyDrop<std::fs::File> {
        std::mem::ManuallyDrop::new(unsafe {
            std::fs::File::from_raw_handle(server.handle() as _)
        })
    }

    /// Serve one Hello → Ok exchange. See `server_file` for handle ownership.
    fn serve_hello_then_ok(server: &PipeServer) {
        let mut file = server_file(server);
        let req: Req = crate::read_msg(&mut *file).expect("server reads Hello");
        assert!(matches!(req, Req::Hello { .. }), "unexpected req: {req:?}");
        crate::write_msg(&mut *file, &Resp::Ok).expect("server writes Ok");
    }

    /// Serve a three-exchange sequence on ONE connection, asserting each
    /// request's fields before answering with a distinct response. The
    /// connection deliberately stays open between messages — the point is
    /// that the client's reused scratch buffers must carry no state across
    /// messages (no cross-message staleness).
    fn serve_three_exchanges(server: &PipeServer) {
        let mut file = server_file(server);
        // 1: Hello(pid=1) → Decision (CoW overlay)
        let req: Req = crate::read_msg(&mut *file).expect("server reads exchange 1");
        match req {
            Req::Hello { pid, exe_path } => {
                assert_eq!(pid, 1);
                assert_eq!(exe_path, r"c:\a.exe");
            }
            other => panic!("exchange 1: unexpected req: {other:?}"),
        }
        crate::write_msg(
            &mut *file,
            &Resp::Decision(policy::Decision {
                mode: policy::Mode::Cow,
                overlay: Some(std::path::PathBuf::from(r"\sb\a")),
                cow_from: None,
                mock_payload: None,
            }),
        )
        .expect("server writes exchange 1 reply");
        // 2: NetDecide → NetDecision { allow: false }
        let req: Req = crate::read_msg(&mut *file).expect("server reads exchange 2");
        match req {
            Req::NetDecide { host, port } => {
                assert_eq!(host, "x");
                assert_eq!(port, 2);
            }
            other => panic!("exchange 2: unexpected req: {other:?}"),
        }
        crate::write_msg(&mut *file, &Resp::NetDecision { allow: false })
            .expect("server writes exchange 2 reply");
        // 3: a different Hello → Ok
        let req: Req = crate::read_msg(&mut *file).expect("server reads exchange 3");
        match req {
            Req::Hello { pid, exe_path } => {
                assert_eq!(pid, 2);
                assert_eq!(exe_path, r"c:\b.exe");
            }
            other => panic!("exchange 3: unexpected req: {other:?}"),
        }
        crate::write_msg(&mut *file, &Resp::Ok).expect("server writes exchange 3 reply");
    }

    /// Pin the connect-retry budget against accidental tightening. The total
    /// budget (attempts × interval) must clear ~3 s — anything less re-opens
    /// the MSYS2 first-run-burst cascade-self-terminate path documented at
    /// the constants.
    #[test]
    fn connect_retry_budget_at_least_nine_seconds() {
        let budget_ms =
            CONNECT_RETRY_ATTEMPTS as u64 * CONNECT_RETRY_INTERVAL_MS;
        assert!(
            budget_ms >= 9_000,
            "connect retry budget {budget_ms}ms < 9000ms — MSYS2 burst regression risk",
        );
    }

    /// Defensive: very small intervals burn CPU on every spurious failure;
    /// very large intervals push past the hook-side fail-closed threshold
    /// (IPC_FAIL_THRESHOLD × per-call connect budget). 50–500 ms is the
    /// sane range; pin it.
    #[test]
    fn connect_retry_interval_in_sane_range() {
        assert!(
            (100..=500).contains(&CONNECT_RETRY_INTERVAL_MS),
            "CONNECT_RETRY_INTERVAL_MS={CONNECT_RETRY_INTERVAL_MS} out of [100,500]ms",
        );
    }

    /// The whole point of SEND_TIMEOUT: a live-but-silent peer must NOT hang
    /// the caller forever. The server accepts the connect and then reads and
    /// writes nothing; send_with_timeout must come back TimedOut within the
    /// test-scoped budget (200 ms — NOT the production value).
    #[test]
    fn send_with_timeout_fires_against_silent_peer() {
        let name = unique_pipe_name();
        let server = PipeServer::new(&name);
        let accept = std::thread::spawn(move || {
            // Blocks until the client's CreateFileW shows up (or fails with
            // ERROR_PIPE_CONNECTED when the client won the race). Either way
            // the thread ends promptly once connected; the server handle
            // stays alive in this thread until the test tears it down.
            let server = server;
            unsafe { ConnectNamedPipe(server.handle(), ptr::null_mut()) };
            // Deliberately NO read/write: the peer stays live but silent.
            server
        });
        let mut client = SyncClient::connect(&name).expect("connect to in-test pipe server");

        let started = Instant::now();
        let res = client.send_with_timeout(
            &Req::Hello { pid: std::process::id(), exe_path: "t".into() },
            Duration::from_millis(200),
        );
        let elapsed = started.elapsed();

        match res
            .expect_err("send against a silent peer must fail, not succeed")
        {
            IpcError::Io(e) => {
                assert_eq!(e.kind(), io::ErrorKind::TimedOut, "got: {e}");
            }
            other => panic!("expected Io(TimedOut), got: {other:?}"),
        }
        assert!(
            elapsed >= Duration::from_millis(150),
            "fired at {elapsed:?} — earlier than the 200ms deadline allows",
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "fired at {elapsed:?} — deadline did not bound the call",
        );

        drop(client);
        // Release the server: DisconnectNamedPipe + CloseHandle, then the
        // accept thread has nothing left to block on.
        let server = accept.join().expect("accept thread must not panic");
        drop(server);
    }

    /// The timed path must still complete a normal exchange: the server
    /// answers via the very same `read_msg`/`write_msg` helpers the real
    /// launcher uses, so this pins protocol compatibility, not just I/O.
    #[test]
    fn send_with_timeout_roundtrip_against_responsive_peer() {
        let name = unique_pipe_name();
        let server = PipeServer::new(&name);
        let accept = std::thread::spawn(move || {
            let server = server;
            unsafe { ConnectNamedPipe(server.handle(), ptr::null_mut()) };
            serve_hello_then_ok(&server);
            server
        });
        let mut client = SyncClient::connect(&name).expect("connect to in-test pipe server");
        let res = client.send_with_timeout(
            &Req::Hello { pid: std::process::id(), exe_path: "t".into() },
            Duration::from_secs(2),
        );
        match res.expect("timed roundtrip against a responsive peer must succeed") {
            Resp::Ok => {}
            other => panic!("expected Resp::Ok, got: {other:?}"),
        }
        let server = accept.join().expect("accept thread must not panic");
        drop(server);
    }

    /// One SyncClient, three exchanges on ONE connection with distinct
    /// request/response pairs: the client's reused enc/frame/recv scratch
    /// buffers must produce exactly the right response for every request —
    /// the no-cross-message-staleness proof for the buffer reuse.
    #[test]
    fn send_reuses_buffers_across_multi_message_sequence() {
        let name = unique_pipe_name();
        let server = PipeServer::new(&name);
        let accept = std::thread::spawn(move || {
            let server = server;
            unsafe { ConnectNamedPipe(server.handle(), ptr::null_mut()) };
            serve_three_exchanges(&server);
            server
        });
        let mut client = SyncClient::connect(&name).expect("connect to in-test pipe server");

        let r1 = client
            .send(&Req::Hello { pid: 1, exe_path: r"c:\a.exe".into() })
            .expect("exchange 1 must round-trip");
        match r1 {
            Resp::Decision(d) => {
                assert_eq!(d.mode, policy::Mode::Cow);
                assert_eq!(d.overlay, Some(std::path::PathBuf::from(r"\sb\a")));
            }
            other => panic!("exchange 1: unexpected resp: {other:?}"),
        }

        let r2 = client
            .send(&Req::NetDecide { host: "x".into(), port: 2 })
            .expect("exchange 2 must round-trip");
        match r2 {
            Resp::NetDecision { allow } => assert!(!allow),
            other => panic!("exchange 2: unexpected resp: {other:?}"),
        }

        let r3 = client
            .send(&Req::Hello { pid: 2, exe_path: r"c:\b.exe".into() })
            .expect("exchange 3 must round-trip");
        match r3 {
            Resp::Ok => {}
            other => panic!("exchange 3: unexpected resp: {other:?}"),
        }

        drop(client);
        // Release the server: DisconnectNamedPipe + CloseHandle, then the
        // accept thread has nothing left to block on.
        let server = accept.join().expect("accept thread must not panic");
        drop(server);
    }

    /// Defensive pin: the production deadline must stay in the range where
    /// it cannot fire on healthy traffic (sub-ms round-trips) yet still
    /// bounds a stuck call well inside the hook's fail-closed window.
    #[test]
    fn send_timeout_pin_sane_range() {
        let secs = SEND_TIMEOUT.as_secs();
        assert!(
            (5..=30).contains(&secs),
            "SEND_TIMEOUT={SEND_TIMEOUT:?} out of [5,30]s — either healthy \
             traffic now risks false timeouts or a hung launcher stays \
             stuck far past the fail-closed budget",
        );
    }
}
