//! Deadline-bounded I/O over a named-pipe client handle.
//!
//! WHY: `SyncClient::send` used to ride a plain `std::fs::File` opened with
//! `OpenOptions` — a synchronous handle with no way to bound a stalled op —
//! so a launcher that accepted the connect but then never answered blocked
//! the hooked process's calling thread forever. The hook's fail-closed
//! consecutive-failure counter never advanced because it only counts calls
//! that RETURN, and this call never returned. Every op here is bounded by a
//! deadline: the I/O is issued overlapped on a `FILE_FLAG_OVERLAPPED`
//! handle, waited on with the remaining budget (`WaitForSingleObject` on an
//! auto-reset event), and on expiry the pending op is cancelled
//! (`CancelIoEx`) and drained so the kernel-side op and its completion
//! signal cannot bleed into the next exchange before `TimedOut` is
//! reported.

use std::io::{self, ErrorKind};
use std::mem;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr;
use std::time::Instant;

use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
use winapi::shared::ntdef::HANDLE;
use winapi::shared::winerror::{
    ERROR_BROKEN_PIPE, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_MORE_DATA,
    ERROR_OPERATION_ABORTED, ERROR_PIPE_NOT_CONNECTED, WAIT_TIMEOUT,
};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileW, ReadFile, WriteFile, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ioapiset::{CancelIoEx, GetOverlappedResult};
use winapi::um::minwinbase::{OVERLAPPED, SECURITY_ATTRIBUTES};
use winapi::um::synchapi::{CreateEventW, WaitForSingleObject};
use winapi::um::winbase::{FILE_FLAG_OVERLAPPED, WAIT_FAILED, WAIT_OBJECT_0};
use winapi::um::winnt::{FILE_ATTRIBUTE_NORMAL, GENERIC_READ, GENERIC_WRITE};

/// An owned named-pipe client handle (opened `FILE_FLAG_OVERLAPPED`) plus
/// the auto-reset event its overlapped ops wait on.
///
/// Both handles are `OwnedHandle`, so Drop closes them in order — no manual
/// CloseHandle paths to leak. Ops on one instance are serialised by
/// construction (single client, one exchange at a time), which is what makes
/// reusing a single auto-reset event safe: each completion signal is
/// consumed exactly once by a wait, so a signal left over from a previous op
/// can cause at most one spurious wake (reaped as ERROR_IO_INCOMPLETE),
/// never a misattributed completion.
pub(crate) struct TimedPipe {
    handle: OwnedHandle,
    event: OwnedHandle,
}

impl TimedPipe {
    /// std's `RawHandle` and winapi's `HANDLE` are both `*mut c_void` but
    /// distinct nominal types (std::ffi vs winapi::ctypes) — cast once here
    /// at the winapi boundary instead of at every call site.
    fn pipe_handle(&self) -> HANDLE {
        self.handle.as_raw_handle() as HANDLE
    }

    fn event_handle(&self) -> HANDLE {
        self.event.as_raw_handle() as HANDLE
    }

    /// Open a named pipe as a duplex client, replacing the equivalent
    /// `OpenOptions::new().read(true).write(true).open(pipe_name)` with an
    /// overlapped handle. Share mode 0 and OPEN_EXISTING match what std's
    /// OpenOptions produced, so existing server-side assumptions hold.
    ///
    /// Errors come back as `from_raw_os_error(GetLastError())` so
    /// `ERROR_PIPE_BUSY` keeps its OS identity for the connect retry loop.
    pub(crate) fn open_named_pipe(pipe_name: &str) -> io::Result<Self> {
        let mut wide: Vec<u16> = pipe_name.encode_utf16().collect();
        wide.push(0);
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0, // no sharing — identical to the std open this replaces
                ptr::null_mut::<SECURITY_ATTRIBUTES>(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::from_raw_os_error(unsafe { GetLastError() } as i32));
        }
        // Auto-reset, initially unset, unnamed: one wait consumes one signal,
        // so a completion that lands between ops can never satisfy the NEXT
        // op's wait with a stale result (see struct doc).
        let event = unsafe { CreateEventW(ptr::null_mut(), FALSE, FALSE, ptr::null()) };
        if event.is_null() {
            let err = io::Error::from_raw_os_error(unsafe { GetLastError() } as i32);
            unsafe { CloseHandle(handle) };
            return Err(err);
        }
        Ok(Self {
            handle: unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) },
            event: unsafe { OwnedHandle::from_raw_handle(event as RawHandle) },
        })
    }

    /// Raw NT handle of the pipe (borrowed), for the server-identity check.
    pub(crate) fn as_raw_handle(&self) -> RawHandle {
        self.handle.as_raw_handle()
    }

    /// `Read::read_exact` semantics under a deadline: fills `buf` completely
    /// or fails before `deadline`. Byte-mode pipe reads complete with
    /// whatever chunk is available, so partial fills accumulate.
    pub(crate) fn read_exact_deadline(&self, buf: &mut [u8], deadline: Instant) -> io::Result<()> {
        let mut filled = 0usize;
        while filled < buf.len() {
            let n = self.read_once(&mut buf[filled..], deadline)?;
            if n == 0 {
                // A completed read that moved zero bytes on a pipe means the
                // write end is gone — same story as std's UnexpectedEof.
                return Err(io::Error::new(ErrorKind::UnexpectedEof, "pipe closed"));
            }
            filled += n;
        }
        Ok(())
    }

    /// `Write::write_all` semantics under a deadline: writes all of `buf` or
    /// fails before `deadline`.
    pub(crate) fn write_all_deadline(&self, mut buf: &[u8], deadline: Instant) -> io::Result<()> {
        while !buf.is_empty() {
            let n = self.write_once(buf, deadline)?;
            buf = &buf[n..];
        }
        Ok(())
    }

    /// One overlapped ReadFile, bounded by `deadline`; returns bytes moved
    /// by this op only (caller accumulates).
    fn read_once(&self, buf: &mut [u8], deadline: Instant) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut ov = self.new_overlapped();
        let ok = unsafe {
            ReadFile(
                self.pipe_handle(),
                buf.as_mut_ptr() as *mut _,
                buf.len() as DWORD,
                // Byte count must come from GetOverlappedResult on an
                // overlapped handle — the plain out-param must be NULL.
                ptr::null_mut(),
                &mut ov,
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err != ERROR_IO_PENDING {
                return Err(map_err_code(err, /* is_read */ true));
            }
        }
        Ok(self.await_result(&mut ov, deadline, /* is_read */ true)? as usize)
    }

    /// One overlapped WriteFile, bounded by `deadline`; returns bytes moved
    /// by this op only (caller advances).
    fn write_once(&self, buf: &[u8], deadline: Instant) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut ov = self.new_overlapped();
        let ok = unsafe {
            WriteFile(
                self.pipe_handle(),
                buf.as_ptr() as *const _,
                buf.len() as DWORD,
                ptr::null_mut(),
                &mut ov,
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err != ERROR_IO_PENDING {
                return Err(map_err_code(err, /* is_read */ false));
            }
        }
        Ok(self.await_result(&mut ov, deadline, /* is_read */ false)? as usize)
    }

    fn new_overlapped(&self) -> OVERLAPPED {
        // Zeroed, not Default: Offset/OffsetHigh must be 0 for pipes, and the
        // struct has padding that must not be garbage when the kernel writes
        // the result through it.
        let mut ov: OVERLAPPED = unsafe { mem::zeroed() };
        ov.hEvent = self.event_handle();
        ov
    }

    /// Reap an already-issued overlapped op, waiting only until `deadline`.
    ///
    /// Completion is polled with `GetOverlappedResult(bWait=FALSE)`; while
    /// the op is still in flight (ERROR_IO_INCOMPLETE) we sit in
    /// `WaitForSingleObject` for the remaining budget. On expiry the op is
    /// cancelled and drained before `TimedOut` is raised, so no kernel op or
    /// late completion signal outlives this call (see struct doc).
    fn await_result(
        &self,
        ov: &mut OVERLAPPED,
        deadline: Instant,
        is_read: bool,
    ) -> io::Result<DWORD> {
        loop {
            let mut transferred: DWORD = 0;
            let complete =
                unsafe { GetOverlappedResult(self.pipe_handle(), ov, &mut transferred, FALSE) };
            if complete != 0 {
                return Ok(transferred);
            }
            match unsafe { GetLastError() } {
                // Op not finished yet — wait for the event below.
                ERROR_IO_INCOMPLETE => {}
                // Partial completion (message-mode quirk): the byte count is
                // still valid, hand it back and let the caller accumulate.
                ERROR_MORE_DATA => return Ok(transferred),
                err => return Err(map_err_code(err, is_read)),
            }
            match remaining_ms(deadline) {
                None => {
                    self.cancel_and_drain(ov);
                    return Err(io::Error::new(
                        ErrorKind::TimedOut,
                        "IPC read/write timed out",
                    ));
                }
                Some(ms) => match unsafe { WaitForSingleObject(self.event_handle(), ms) } {
                    // Event set: loop — GetOverlappedResult above reaps it.
                    // (ERROR_IO_INCOMPLETE after a wake means the signal was
                    // stale; the next wait is bounded as usual.)
                    WAIT_OBJECT_0 => {}
                    WAIT_TIMEOUT => {
                        self.cancel_and_drain(ov);
                        return Err(io::Error::new(
                            ErrorKind::TimedOut,
                            "IPC read/write timed out",
                        ));
                    }
                    WAIT_FAILED => {
                        return Err(io::Error::from_raw_os_error(unsafe { GetLastError() } as i32))
                    }
                    other => {
                        return Err(io::Error::other(format!(
                            "unexpected WaitForSingleObject result: 0x{other:x}"
                        )))
                    }
                },
            }
        }
    }

    /// Cancel everything pending on the handle (ops are serialised, so that
    /// is exactly the op `ov` belongs to), then reap its completion with a
    /// blocking GetOverlappedResult — CancelIoEx guarantees the op finishes
    /// (aborted) promptly, so this cannot hang, and draining keeps the event
    /// and kernel state clean for the next exchange.
    fn cancel_and_drain(&self, ov: &mut OVERLAPPED) {
        unsafe {
            CancelIoEx(self.pipe_handle(), ptr::null_mut());
            let mut transferred: DWORD = 0;
            // Result deliberately discarded: the op ends aborted (or, in a
            // race, completed) — either way the count is meaningless here.
            GetOverlappedResult(self.pipe_handle(), ov, &mut transferred, TRUE);
        }
    }
}

/// Milliseconds left until `deadline`, or None once it has passed.
fn remaining_ms(deadline: Instant) -> Option<DWORD> {
    let now = Instant::now();
    if now >= deadline {
        return None;
    }
    Some((deadline - now).as_millis().min(DWORD::MAX as u128) as DWORD)
}

/// Shared error mapping for overlapped pipe ops. `is_read` only steers the
/// dead-peer case: on read it is a clean EOF (the launcher side went away),
/// on write a genuine error worth reporting verbatim.
fn map_err_code(code: DWORD, is_read: bool) -> io::Error {
    match code {
        ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED if is_read => {
            io::Error::new(ErrorKind::UnexpectedEof, "pipe closed")
        }
        // Only our own cancel produces this here, and we cancel solely on
        // deadline expiry — so an aborted op is reported as a timeout.
        ERROR_OPERATION_ABORTED => io::Error::new(
            ErrorKind::TimedOut,
            "IPC read/write timed out (operation aborted)",
        ),
        _ => io::Error::from_raw_os_error(code as i32),
    }
}
