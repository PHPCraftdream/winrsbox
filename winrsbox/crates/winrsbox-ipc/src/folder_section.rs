//! Folder-section raw layout: a seqlock-protected snapshot of the current
//! broker's identity, pipe name and trusted-launcher set, shared across
//! every `winrsbox` process rooted at one state dir via a named
//! memory-mapped section.
//!
//! This module owns ONLY the layout and the seqlock protocol over a raw
//! pointer to mapped memory — it never calls `CreateFileMapping`/
//! `MapViewOfFile` itself, so both `winrsbox-launcher` (writer/owner) and
//! `winrsbox-hook` (reader) can depend on it without pulling in `windows`.
//! The launcher-side owner (creation, DACL, publishing the handle) lives in
//! `winrsbox-launcher::contain::session_section` (`FolderSection`).
//!
//! ## Layout (`#[repr(C)]`, one build only — never shared across binary
//! versions; see `version`/`magic` validation)
//!
//! `magic, version, generation, broker_pid, broker_create_time, pipe_name
//! ([u16; 128], NUL-terminated), launchers_len, launchers[32] (pid,
//! create_time)`.
//!
//! ## Concurrency model
//!
//! Any number of readers may call [`FolderSectionView::snapshot`]
//! concurrently at any time, from any process holding a view of the
//! mapping. `generation` is a seqlock counter: odd means a write is in
//! progress, even means the payload is quiescent; a reader that observes an
//! odd counter, or a counter that changed between its first and last read,
//! retries.
//!
//! Writers are **not** synchronized against each other by this module: per
//! the broker-per-folder design exactly one process (the current broker)
//! calls the write methods at any given time. Callers must not invoke
//! `set_broker`/`add_launcher`/`remove_launcher` concurrently from more
//! than one thread or process against the same section — doing so
//! corrupts the payload (two interleaved writers can each observe the
//! other's odd generation as "quiescent" only if they happen to run their
//! critical sections without overlapping, which this module does not
//! enforce).
//!
//! ## Why every payload field access is `read_volatile`/`write_volatile`
//!
//! The mapped memory is written and read by *other processes*, invisible
//! to the Rust/LLVM memory model, which assumes no unannounced concurrent
//! access to plain (non-atomic, non-volatile) memory — an assumption that
//! is false here and would make ordinary field reads/writes undefined
//! behaviour. `generation` uses `AtomicU64::from_ptr` (documented for
//! exactly this "atomics over shared/mapped memory" use case) with
//! `SeqCst` throughout: this primitive is touched at broker start, at
//! launcher join/leave and once per hook reconnect — nowhere near a hot
//! path — so the full barrier costs nothing measurable and removes any
//! doubt about acquire/release directionality on a seqlock's two reads.

use std::sync::atomic::{AtomicU64, Ordering};

/// "WRFB" (WinRsBox Folder) little-endian, distinct from
/// `ipc::SESSION_CONFIG_MAGIC` ("WRSB") so a stale mapping of the wrong
/// kind fails validation immediately instead of decoding garbage.
pub const FOLDER_SECTION_MAGIC: u32 = 0x4246_5257;
pub const FOLDER_SECTION_VERSION: u32 = 1;

/// Max simultaneously-tracked launcher processes in one folder.
pub const MAX_LAUNCHERS: usize = 32;
/// Pipe name buffer width in UTF-16 code units, including the NUL terminator.
pub const PIPE_NAME_WCHARS: usize = 128;

/// Seqlock retry budget for [`FolderSectionView::snapshot`]. Generous on
/// purpose: this primitive is never on a hot path (broker start, launcher
/// join/leave, hook reconnect), so paying for a large budget costs nothing
/// in production and removes read-side flakiness under heavy test
/// contention. A writer that stays odd forever (crashed mid-write) still
/// exhausts this and surfaces [`FolderSectionError::SeqlockRetryExhausted`]
/// rather than hanging.
pub const FOLDER_SECTION_SEQLOCK_MAX_RETRIES: u32 = 10_000;

#[repr(C)]
#[derive(Clone, Copy)]
struct LauncherSlot {
    pid: u32,
    create_time: u64,
}

#[repr(C)]
struct RawFolderSection {
    magic: u32,
    version: u32,
    generation: u64,
    broker_pid: u32,
    broker_create_time: u64,
    pipe_name: [u16; PIPE_NAME_WCHARS],
    launchers_len: u32,
    launchers: [LauncherSlot; MAX_LAUNCHERS],
}

/// Total mapped-section size the owner must reserve
/// (`CreateFileMappingW(..., FOLDER_SECTION_SIZE, ...)`).
pub const FOLDER_SECTION_SIZE: usize = std::mem::size_of::<RawFolderSection>();

/// An owned, internally-consistent copy of the folder section's payload at
/// one point in time (identified by `generation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderSectionSnapshot {
    pub generation: u64,
    pub broker_pid: u32,
    pub broker_create_time: u64,
    pub pipe_name: String,
    pub launchers: Vec<(u32, u64)>,
}

impl FolderSectionSnapshot {
    /// Whether `(pid, create_time)` identifies the current broker or a
    /// tracked launcher — the identity check the hook runs against a pipe
    /// server before trusting its responses.
    pub fn is_trusted_server(&self, pid: u32, create_time: u64) -> bool {
        (self.broker_pid == pid && self.broker_create_time == create_time)
            || self
                .launchers
                .iter()
                .any(|&(p, ct)| p == pid && ct == create_time)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FolderSectionError {
    #[error("folder section magic mismatch: 0x{0:08x}")]
    BadMagic(u32),
    #[error("folder section version mismatch: {0} (expected {FOLDER_SECTION_VERSION})")]
    BadVersion(u32),
    #[error("folder section launchers_len {0} exceeds MAX_LAUNCHERS ({MAX_LAUNCHERS})")]
    LaunchersLenOverflow(u32),
    #[error("folder section pipe_name is not NUL-terminated")]
    PipeNameNotTerminated,
    #[error(
        "seqlock read did not converge after {0} attempts \
         (writer stalled or crashed mid-write)"
    )]
    SeqlockRetryExhausted(u32),
    #[error("launcher list is full ({MAX_LAUNCHERS} entries)")]
    LaunchersFull,
    #[error("launcher (pid={pid}, create_time={create_time}) already present")]
    DuplicateLauncher { pid: u32, create_time: u64 },
    #[error(
        "pipe name too long for folder section: {0} UTF-16 code units \
         (max {PIPE_NAME_WCHARS} incl. NUL)"
    )]
    PipeNameTooLong(usize),
    #[error("rebuild: {0} launchers exceeds MAX_LAUNCHERS ({MAX_LAUNCHERS})")]
    TooManyLaunchers(usize),
}

fn encode_pipe_name(name: &str) -> Result<[u16; PIPE_NAME_WCHARS], FolderSectionError> {
    let wide: Vec<u16> = name.encode_utf16().collect();
    if wide.len() + 1 > PIPE_NAME_WCHARS {
        return Err(FolderSectionError::PipeNameTooLong(wide.len()));
    }
    let mut arr = [0u16; PIPE_NAME_WCHARS];
    arr[..wide.len()].copy_from_slice(&wide);
    Ok(arr)
}

fn decode_pipe_name(arr: &[u16; PIPE_NAME_WCHARS]) -> Result<String, FolderSectionError> {
    let nul_pos = arr
        .iter()
        .position(|&c| c == 0)
        .ok_or(FolderSectionError::PipeNameNotTerminated)?;
    Ok(String::from_utf16_lossy(&arr[..nul_pos]))
}

/// A lightweight, `Copy`able view over a mapped folder section. Does not own
/// the mapping — the caller (`winrsbox-launcher::contain::session_section::FolderSection`) must keep
/// the underlying `MapViewOfFile`/`CreateFileMappingW` handles alive for at
/// least as long as any `FolderSectionView` built from them is in use.
#[derive(Clone, Copy)]
pub struct FolderSectionView {
    ptr: *mut u8,
}

// SAFETY: `ptr` addresses OS-backed shared memory, not process-local state —
// there is nothing thread-affine about it. All field access goes through
// `read_volatile`/`write_volatile` or `AtomicU64::from_ptr`, never a plain
// reference to the pointee, so handing the view to another thread is sound
// as long as the pointee itself outlives the view (the caller's contract,
// documented on `new`).
unsafe impl Send for FolderSectionView {}
unsafe impl Sync for FolderSectionView {}

impl FolderSectionView {
    /// Wrap a raw pointer to mapped folder-section memory.
    ///
    /// # Safety
    /// `ptr` must be valid for reads of `FOLDER_SECTION_SIZE` bytes — and
    /// for writes too, if the caller will ever invoke a write method
    /// (`init`/`set_broker`/`add_launcher`/`remove_launcher`) on the
    /// resulting view; a read-only mapping (e.g. a guest's `FILE_MAP_READ`
    /// view) is fine as long as only [`snapshot`](Self::snapshot) is called
    /// on it. `ptr` must be aligned to `align_of::<u64>()` (8 bytes —
    /// `MapViewOfFile` always returns page-aligned addresses, so this holds
    /// for any real mapping), and must remain valid for the entire lifetime
    /// of the returned `FolderSectionView` (and every `Copy` of it).
    pub unsafe fn new(ptr: *mut u8) -> Self {
        debug_assert_eq!(
            ptr as usize % std::mem::align_of::<RawFolderSection>(),
            0,
            "folder section pointer must be 8-byte aligned"
        );
        Self { ptr }
    }

    fn raw(&self) -> *mut RawFolderSection {
        self.ptr.cast()
    }

    /// SAFETY (of the returned reference's use): every access to the
    /// generation field, anywhere in this module, goes through this atomic
    /// view — never a plain load/store — satisfying `AtomicU64::from_ptr`'s
    /// contract that all accesses to the location use atomic operations of
    /// matching size.
    fn generation_atomic(&self) -> &AtomicU64 {
        // SAFETY: `new`'s contract guarantees `self.ptr` is valid and
        // 8-byte aligned for `FOLDER_SECTION_SIZE` bytes for this view's
        // whole lifetime; `generation` sits at a `repr(C)`-computed offset
        // that is a multiple of 8 (it is itself a `u64` field, so the
        // compiler pads the two preceding `u32`s to keep it aligned).
        unsafe { AtomicU64::from_ptr(std::ptr::addr_of_mut!((*self.raw()).generation)) }
    }

    fn begin_write(&self) {
        debug_assert_eq!(
            self.generation_atomic().load(Ordering::SeqCst) % 2,
            0,
            "begin_write called while a write was already in progress — \
             writes must be serialized by the caller (only the broker \
             process writes at any given time)"
        );
        // Odd generation announces "write in progress" to readers.
        self.generation_atomic().fetch_add(1, Ordering::SeqCst);
    }

    fn end_write(&self) {
        // Back to even: readers that were retrying can now succeed.
        self.generation_atomic().fetch_add(1, Ordering::SeqCst);
    }

    /// Initialize a freshly created (not-yet-published) section: writes
    /// magic/version, the initial broker identity, and an empty launcher
    /// list. MUST be called exactly once, before the section's name/handle
    /// is shared with any other process — no seqlock is needed here because
    /// no reader can exist yet.
    pub fn init(
        &self,
        broker_pid: u32,
        broker_create_time: u64,
        pipe_name: &str,
    ) -> Result<(), FolderSectionError> {
        let pipe_name_arr = encode_pipe_name(pipe_name)?;
        let raw = self.raw();
        // SAFETY: see `new`'s contract; this runs before publication, so
        // there is no concurrent reader/writer to race with.
        unsafe {
            std::ptr::write_volatile(std::ptr::addr_of_mut!((*raw).magic), FOLDER_SECTION_MAGIC);
            std::ptr::write_volatile(
                std::ptr::addr_of_mut!((*raw).version),
                FOLDER_SECTION_VERSION,
            );
            std::ptr::write_volatile(std::ptr::addr_of_mut!((*raw).broker_pid), broker_pid);
            std::ptr::write_volatile(
                std::ptr::addr_of_mut!((*raw).broker_create_time),
                broker_create_time,
            );
            std::ptr::write_volatile(std::ptr::addr_of_mut!((*raw).pipe_name), pipe_name_arr);
            std::ptr::write_volatile(std::ptr::addr_of_mut!((*raw).launchers_len), 0u32);
        }
        self.generation_atomic().store(0, Ordering::SeqCst);
        Ok(())
    }

    /// Read the current launcher list directly (no seqlock): valid ONLY for
    /// the sole writer's own use between write calls — per this module's
    /// single-writer contract, nothing else is mutating this section while
    /// the writer is between calls, and the writer's own last write always
    /// leaves `generation` even.
    fn read_launchers_for_writer(&self) -> (usize, [LauncherSlot; MAX_LAUNCHERS]) {
        let raw = self.raw();
        // SAFETY: see `new`'s contract; single-writer invariant documented
        // on the type and this fn.
        unsafe {
            let len = std::ptr::read_volatile(std::ptr::addr_of!((*raw).launchers_len)) as usize;
            let launchers = std::ptr::read_volatile(std::ptr::addr_of!((*raw).launchers));
            (len.min(MAX_LAUNCHERS), launchers)
        }
    }

    /// Publish a new broker identity and pipe name. Bumps `generation`.
    pub fn set_broker(
        &self,
        broker_pid: u32,
        broker_create_time: u64,
        pipe_name: &str,
    ) -> Result<(), FolderSectionError> {
        let pipe_name_arr = encode_pipe_name(pipe_name)?;
        let raw = self.raw();
        self.begin_write();
        // SAFETY: see `new`'s contract; writes go through `write_volatile`
        // exclusively, guarded by the seqlock above/below.
        unsafe {
            std::ptr::write_volatile(std::ptr::addr_of_mut!((*raw).broker_pid), broker_pid);
            std::ptr::write_volatile(
                std::ptr::addr_of_mut!((*raw).broker_create_time),
                broker_create_time,
            );
            std::ptr::write_volatile(std::ptr::addr_of_mut!((*raw).pipe_name), pipe_name_arr);
        }
        self.end_write();
        Ok(())
    }

    /// Add `(pid, create_time)` to the trusted-launcher set. Rejects an
    /// exact duplicate tuple and a full list without touching the seqlock
    /// (no-op writes never bump `generation`).
    pub fn add_launcher(&self, pid: u32, create_time: u64) -> Result<(), FolderSectionError> {
        let (len, launchers) = self.read_launchers_for_writer();
        if launchers[..len]
            .iter()
            .any(|s| s.pid == pid && s.create_time == create_time)
        {
            return Err(FolderSectionError::DuplicateLauncher { pid, create_time });
        }
        if len >= MAX_LAUNCHERS {
            return Err(FolderSectionError::LaunchersFull);
        }
        let raw = self.raw();
        self.begin_write();
        // SAFETY: see `new`'s contract; `len < MAX_LAUNCHERS` checked above,
        // so `base.add(len)` stays within the fixed-size `launchers` array.
        unsafe {
            let base = std::ptr::addr_of_mut!((*raw).launchers).cast::<LauncherSlot>();
            std::ptr::write_volatile(base.add(len), LauncherSlot { pid, create_time });
            std::ptr::write_volatile(std::ptr::addr_of_mut!((*raw).launchers_len), (len + 1) as u32);
        }
        self.end_write();
        Ok(())
    }

    /// Remove `(pid, create_time)` from the trusted-launcher set. Returns
    /// `false` (no seqlock write) if no matching entry was present. Uses
    /// swap-remove to keep the array packed — launcher order carries no
    /// meaning.
    pub fn remove_launcher(&self, pid: u32, create_time: u64) -> bool {
        let (len, launchers) = self.read_launchers_for_writer();
        let Some(idx) = launchers[..len]
            .iter()
            .position(|s| s.pid == pid && s.create_time == create_time)
        else {
            return false;
        };
        let raw = self.raw();
        self.begin_write();
        // SAFETY: see `new`'s contract; `idx < len <= MAX_LAUNCHERS` and
        // `len - 1 < MAX_LAUNCHERS`, so both offsets stay in-bounds.
        unsafe {
            let base = std::ptr::addr_of_mut!((*raw).launchers).cast::<LauncherSlot>();
            if idx != len - 1 {
                let last = launchers[len - 1];
                std::ptr::write_volatile(base.add(idx), last);
            }
            std::ptr::write_volatile(
                std::ptr::addr_of_mut!((*raw).launchers_len),
                (len - 1) as u32,
            );
        }
        self.end_write();
        true
    }

    /// MP-7 §2 (failover): full rewrite of the section's payload, used by a
    /// failover winner INSTEAD OF [`set_broker`](Self::set_broker) — never
    /// on top of it. Rationale (review MP-1): a broker killed mid-write
    /// leaves `generation` odd; every [`snapshot`](Self::snapshot) then
    /// fails with `SeqlockRetryExhausted`, and a plain `begin_write`/
    /// `end_write` pair (what `set_broker`/`add_launcher`/`remove_launcher`
    /// use) only flips the counter back to even WITHOUT fixing whatever the
    /// crashed writer left half-written underneath it — readers would
    /// resume trusting a payload that was never fully written. `rebuild`
    /// instead overwrites every field unconditionally (broker identity,
    /// pipe name, AND the launcher set — not just the broker tuple) and
    /// forces `generation` to a value strictly greater than whatever is
    /// currently stored, rounded to even, regardless of whether that stored
    /// value was itself even (clean generation N -> N+2) or stuck odd
    /// (crashed mid-write at generation N -> N+1): `(current | 1) + 1` is
    /// exactly that value in both cases (`current | 1` is always odd, so
    /// used as the "write in progress" marker; adding 1 lands on the next
    /// even value strictly above `current`).
    ///
    /// `launchers` replaces the ENTIRE trusted-launcher set — MP-7's chosen
    /// policy is "empty + self, then let every surviving client re-Attach"
    /// (see the plan's "Folder section и job при смерти брокера"): stale
    /// `(pid, create_time)` entries carried over from the dead broker's own
    /// bookkeeping are not something this process can independently verify
    /// as still-live launchers, so the caller is expected to pass just its
    /// own identity here (or, in principle, a set it has itself verified —
    /// this method does not care, it only requires `launchers.len() <=
    /// MAX_LAUNCHERS`).
    pub fn rebuild(
        &self,
        broker_pid: u32,
        broker_create_time: u64,
        pipe_name: &str,
        launchers: &[(u32, u64)],
    ) -> Result<(), FolderSectionError> {
        if launchers.len() > MAX_LAUNCHERS {
            return Err(FolderSectionError::TooManyLaunchers(launchers.len()));
        }
        let pipe_name_arr = encode_pipe_name(pipe_name)?;
        let raw = self.raw();

        // Deliberately NOT `begin_write`/`end_write`: those assert the
        // current generation is even (a precondition this method exists
        // specifically to violate — the whole point is tolerating a
        // crashed writer's stuck-odd generation). Read the raw current
        // value directly instead of through `snapshot()` (which would
        // itself fail on a stuck-odd generation).
        let current = self.generation_atomic().load(Ordering::SeqCst);
        let target_gen = (current | 1) + 1; // strictly > current, always even
        let write_marker = target_gen - 1; // == current | 1: always odd

        // Odd generation announces "write in progress" to any reader,
        // exactly like `begin_write` — just via a plain store (the
        // generation may already be non-quiescent) rather than fetch_add.
        self.generation_atomic().store(write_marker, Ordering::SeqCst);
        // SAFETY: see `new`'s contract; every field is fully overwritten
        // below, so no stale bytes from a crashed writer survive.
        unsafe {
            std::ptr::write_volatile(std::ptr::addr_of_mut!((*raw).magic), FOLDER_SECTION_MAGIC);
            std::ptr::write_volatile(
                std::ptr::addr_of_mut!((*raw).version),
                FOLDER_SECTION_VERSION,
            );
            std::ptr::write_volatile(std::ptr::addr_of_mut!((*raw).broker_pid), broker_pid);
            std::ptr::write_volatile(
                std::ptr::addr_of_mut!((*raw).broker_create_time),
                broker_create_time,
            );
            std::ptr::write_volatile(std::ptr::addr_of_mut!((*raw).pipe_name), pipe_name_arr);
            let base = std::ptr::addr_of_mut!((*raw).launchers).cast::<LauncherSlot>();
            for (i, &(pid, create_time)) in launchers.iter().enumerate() {
                std::ptr::write_volatile(base.add(i), LauncherSlot { pid, create_time });
            }
            std::ptr::write_volatile(
                std::ptr::addr_of_mut!((*raw).launchers_len),
                launchers.len() as u32,
            );
        }
        // Back to even and strictly greater than any generation any reader
        // could have observed before this call.
        self.generation_atomic().store(target_gen, Ordering::SeqCst);
        Ok(())
    }

    /// Take a consistent snapshot of the section, retrying while a writer
    /// is active or a write raced the read. Validates magic/version,
    /// `launchers_len` bounds, and pipe-name NUL-termination before
    /// returning.
    pub fn snapshot(&self) -> Result<FolderSectionSnapshot, FolderSectionError> {
        let raw = self.raw();
        for _ in 0..FOLDER_SECTION_SEQLOCK_MAX_RETRIES {
            let g1 = self.generation_atomic().load(Ordering::SeqCst);
            if !g1.is_multiple_of(2) {
                std::hint::spin_loop();
                continue;
            }
            // SAFETY: see `new`'s contract; every field below is read via
            // `read_volatile`, never a plain reference to `*raw` — required
            // because a concurrent writer (another process) may be
            // mutating this memory right now, which this generation check
            // is what detects.
            let (magic, version, broker_pid, broker_create_time, pipe_name_raw, launchers_len, launchers) = unsafe {
                (
                    std::ptr::read_volatile(std::ptr::addr_of!((*raw).magic)),
                    std::ptr::read_volatile(std::ptr::addr_of!((*raw).version)),
                    std::ptr::read_volatile(std::ptr::addr_of!((*raw).broker_pid)),
                    std::ptr::read_volatile(std::ptr::addr_of!((*raw).broker_create_time)),
                    std::ptr::read_volatile(std::ptr::addr_of!((*raw).pipe_name)),
                    std::ptr::read_volatile(std::ptr::addr_of!((*raw).launchers_len)),
                    std::ptr::read_volatile(std::ptr::addr_of!((*raw).launchers)),
                )
            };
            let g2 = self.generation_atomic().load(Ordering::SeqCst);
            if g1 != g2 {
                std::hint::spin_loop();
                continue;
            }

            if magic != FOLDER_SECTION_MAGIC {
                return Err(FolderSectionError::BadMagic(magic));
            }
            if version != FOLDER_SECTION_VERSION {
                return Err(FolderSectionError::BadVersion(version));
            }
            if launchers_len as usize > MAX_LAUNCHERS {
                return Err(FolderSectionError::LaunchersLenOverflow(launchers_len));
            }
            let pipe_name = decode_pipe_name(&pipe_name_raw)?;
            let launchers_vec = launchers[..launchers_len as usize]
                .iter()
                .map(|s| (s.pid, s.create_time))
                .collect();
            return Ok(FolderSectionSnapshot {
                generation: g1,
                broker_pid,
                broker_create_time,
                pipe_name,
                launchers: launchers_vec,
            });
        }
        Err(FolderSectionError::SeqlockRetryExhausted(
            FOLDER_SECTION_SEQLOCK_MAX_RETRIES,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Heap-backed stand-in for a mapped section. The box's address is
    /// stable for its lifetime (moving the `Box` handle never moves the
    /// heap allocation), so handing out a raw pointer derived from it and
    /// keeping the box alive alongside every `FolderSectionView` built from
    /// that pointer is sound.
    fn blank_storage() -> Box<RawFolderSection> {
        Box::new(RawFolderSection {
            magic: 0,
            version: 0,
            generation: 0,
            broker_pid: 0,
            broker_create_time: 0,
            pipe_name: [0u16; PIPE_NAME_WCHARS],
            launchers_len: 0,
            launchers: [LauncherSlot { pid: 0, create_time: 0 }; MAX_LAUNCHERS],
        })
    }

    fn view_of(storage: &mut Box<RawFolderSection>) -> FolderSectionView {
        let ptr = storage.as_mut() as *mut RawFolderSection as *mut u8;
        // SAFETY: `ptr` points into `storage`'s heap allocation, sized and
        // aligned for `RawFolderSection`; the caller keeps `storage` alive
        // for at least as long as the returned view is used.
        unsafe { FolderSectionView::new(ptr) }
    }

    fn new_initialized(broker_pid: u32, ct: u64, pipe: &str) -> (Box<RawFolderSection>, FolderSectionView) {
        let mut storage = blank_storage();
        let view = view_of(&mut storage);
        view.init(broker_pid, ct, pipe).expect("init");
        (storage, view)
    }

    #[test]
    fn init_then_snapshot_roundtrips() {
        let (_storage, view) = new_initialized(111, 222, r"\\.\pipe\winrsbox-broker-abc");
        let snap = view.snapshot().expect("snapshot");
        assert_eq!(snap.generation, 0);
        assert_eq!(snap.broker_pid, 111);
        assert_eq!(snap.broker_create_time, 222);
        assert_eq!(snap.pipe_name, r"\\.\pipe\winrsbox-broker-abc");
        assert!(snap.launchers.is_empty());
    }

    #[test]
    fn set_broker_bumps_generation_and_updates_fields() {
        let (_storage, view) = new_initialized(1, 1, "old");
        let before = view.snapshot().unwrap();
        view.set_broker(9, 99, "new").unwrap();
        let after = view.snapshot().unwrap();
        assert!(after.generation > before.generation);
        assert_eq!(after.broker_pid, 9);
        assert_eq!(after.broker_create_time, 99);
        assert_eq!(after.pipe_name, "new");
    }

    #[test]
    fn add_launcher_rejects_exact_duplicate() {
        let (_storage, view) = new_initialized(1, 1, "p");
        view.add_launcher(50, 500).unwrap();
        let err = view.add_launcher(50, 500).unwrap_err();
        assert_eq!(err, FolderSectionError::DuplicateLauncher { pid: 50, create_time: 500 });
    }

    #[test]
    fn add_launcher_same_pid_different_create_time_is_not_a_duplicate() {
        // Different create_time means a different process (PID reuse) —
        // not the "same launcher added twice" case add_launcher rejects.
        let (_storage, view) = new_initialized(1, 1, "p");
        view.add_launcher(50, 500).unwrap();
        view.add_launcher(50, 600).unwrap();
        let snap = view.snapshot().unwrap();
        assert_eq!(snap.launchers.len(), 2);
    }

    #[test]
    fn add_launcher_overflow_rejected_at_max_launchers() {
        let (_storage, view) = new_initialized(1, 1, "p");
        for i in 0..MAX_LAUNCHERS as u32 {
            view.add_launcher(i, u64::from(i)).unwrap();
        }
        let err = view.add_launcher(9999, 9999).unwrap_err();
        assert_eq!(err, FolderSectionError::LaunchersFull);
        assert_eq!(view.snapshot().unwrap().launchers.len(), MAX_LAUNCHERS);
    }

    #[test]
    fn remove_launcher_frees_a_slot_for_reuse() {
        let (_storage, view) = new_initialized(1, 1, "p");
        for i in 0..MAX_LAUNCHERS as u32 {
            view.add_launcher(i, u64::from(i)).unwrap();
        }
        assert!(view.remove_launcher(5, 5));
        view.add_launcher(9999, 9999).expect("slot freed by remove");
        let snap = view.snapshot().unwrap();
        assert_eq!(snap.launchers.len(), MAX_LAUNCHERS);
        assert!(!snap.launchers.contains(&(5, 5)));
        assert!(snap.launchers.contains(&(9999, 9999)));
    }

    #[test]
    fn remove_launcher_missing_entry_is_a_noop_no_seqlock_write() {
        let (_storage, view) = new_initialized(1, 1, "p");
        view.add_launcher(1, 1).unwrap();
        let before = view.snapshot().unwrap().generation;
        assert!(!view.remove_launcher(404, 404));
        let after = view.snapshot().unwrap().generation;
        assert_eq!(before, after, "a no-op remove must not bump generation");
    }

    #[test]
    fn is_trusted_server_matches_broker_and_launchers_only() {
        let (_storage, view) = new_initialized(10, 100, "p");
        view.add_launcher(20, 200).unwrap();
        let snap = view.snapshot().unwrap();
        assert!(snap.is_trusted_server(10, 100), "broker identity must be trusted");
        assert!(snap.is_trusted_server(20, 200), "tracked launcher must be trusted");
        assert!(!snap.is_trusted_server(20, 999), "create_time must match exactly");
        assert!(!snap.is_trusted_server(30, 300), "unknown pid must not be trusted");
    }

    #[test]
    fn snapshot_rejects_bad_magic() {
        let mut storage = blank_storage();
        storage.magic = 0xDEAD_BEEF;
        storage.version = FOLDER_SECTION_VERSION;
        let view = view_of(&mut storage);
        let err = view.snapshot().unwrap_err();
        assert_eq!(err, FolderSectionError::BadMagic(0xDEAD_BEEF));
    }

    #[test]
    fn snapshot_rejects_bad_version() {
        let mut storage = blank_storage();
        storage.magic = FOLDER_SECTION_MAGIC;
        storage.version = 0xFFFF_FFFF;
        let view = view_of(&mut storage);
        let err = view.snapshot().unwrap_err();
        assert_eq!(err, FolderSectionError::BadVersion(0xFFFF_FFFF));
    }

    #[test]
    fn snapshot_rejects_launchers_len_overflow() {
        let mut storage = blank_storage();
        storage.magic = FOLDER_SECTION_MAGIC;
        storage.version = FOLDER_SECTION_VERSION;
        storage.launchers_len = MAX_LAUNCHERS as u32 + 1;
        let view = view_of(&mut storage);
        let err = view.snapshot().unwrap_err();
        assert_eq!(
            err,
            FolderSectionError::LaunchersLenOverflow(MAX_LAUNCHERS as u32 + 1)
        );
    }

    #[test]
    fn snapshot_rejects_pipe_name_without_nul_terminator() {
        let mut storage = blank_storage();
        storage.magic = FOLDER_SECTION_MAGIC;
        storage.version = FOLDER_SECTION_VERSION;
        storage.pipe_name = [0x41u16; PIPE_NAME_WCHARS]; // all 'A', no NUL anywhere
        let view = view_of(&mut storage);
        let err = view.snapshot().unwrap_err();
        assert_eq!(err, FolderSectionError::PipeNameNotTerminated);
    }

    // ─── rebuild (MP-7 §2) ─────────────────────────────────────────────

    #[test]
    fn rebuild_from_clean_even_generation_advances_and_replaces_everything() {
        let (_storage, view) = new_initialized(1, 1, "old");
        view.add_launcher(50, 500).unwrap();
        let before = view.snapshot().unwrap();
        assert_eq!(before.generation % 2, 0);

        view.rebuild(9, 99, "new", &[(9, 99)]).expect("rebuild");

        let after = view.snapshot().expect("snapshot after rebuild");
        assert!(after.generation > before.generation, "generation must strictly advance");
        assert_eq!(after.generation % 2, 0, "generation must land even");
        assert_eq!(after.broker_pid, 9);
        assert_eq!(after.broker_create_time, 99);
        assert_eq!(after.pipe_name, "new");
        assert_eq!(after.launchers, vec![(9, 99)], "old launcher set must be fully replaced");
    }

    #[test]
    fn rebuild_recovers_from_a_stuck_odd_generation_left_by_a_crashed_writer() {
        // Simulate exactly the MP-1-review scenario: a writer crashed
        // mid-write, leaving generation permanently odd. snapshot() must
        // fail beforehand (proving the stuck state is real), and rebuild
        // must both succeed and leave a fresh, readable, strictly-greater
        // even generation behind.
        let mut storage = blank_storage();
        storage.magic = FOLDER_SECTION_MAGIC;
        storage.version = FOLDER_SECTION_VERSION;
        storage.generation = 41; // stuck odd — as if begin_write() ran and the writer died
        storage.broker_pid = 111; // whatever the dead writer half-wrote
        let view = view_of(&mut storage);

        assert!(
            matches!(view.snapshot(), Err(FolderSectionError::SeqlockRetryExhausted(_))),
            "precondition: a stuck-odd generation must make snapshot() fail"
        );

        view.rebuild(22, 222, "recovered", &[]).expect("rebuild must succeed on a stuck-odd section");

        let after = view.snapshot().expect("snapshot must succeed after rebuild");
        assert!(after.generation > 41, "new generation must exceed the stuck value");
        assert_eq!(after.generation % 2, 0);
        assert_eq!(after.broker_pid, 22);
        assert_eq!(after.broker_create_time, 222);
        assert_eq!(after.pipe_name, "recovered");
        assert!(after.launchers.is_empty());
    }

    #[test]
    fn rebuild_rejects_too_many_launchers_without_touching_the_section() {
        let (_storage, view) = new_initialized(1, 1, "p");
        let before = view.snapshot().unwrap();
        let too_many: Vec<(u32, u64)> =
            (0..MAX_LAUNCHERS as u32 + 1).map(|i| (i, u64::from(i))).collect();

        let err = view.rebuild(2, 2, "x", &too_many).unwrap_err();
        assert_eq!(err, FolderSectionError::TooManyLaunchers(MAX_LAUNCHERS + 1));

        let after = view.snapshot().unwrap();
        assert_eq!(after, before, "a rejected rebuild must not mutate the section at all");
    }

    #[test]
    fn rebuild_rejects_oversized_pipe_name_without_touching_the_section() {
        let (_storage, view) = new_initialized(1, 1, "p");
        let before = view.snapshot().unwrap();
        let too_long = "x".repeat(PIPE_NAME_WCHARS);

        let err = view.rebuild(2, 2, &too_long, &[]).unwrap_err();
        assert!(matches!(err, FolderSectionError::PipeNameTooLong(_)));

        let after = view.snapshot().unwrap();
        assert_eq!(after, before, "a rejected rebuild must not mutate the section at all");
    }

    #[test]
    fn rebuild_generation_strictly_exceeds_any_previously_observed_value() {
        // "строго БОЛЬШЕГО любого ранее наблюдённого" — exercise both
        // parities of the pre-rebuild generation to pin the (current | 1)
        // + 1 formula against regression.
        let (_storage, view) = new_initialized(1, 1, "p");
        let even_before = view.snapshot().unwrap().generation;
        view.rebuild(2, 2, "a", &[]).unwrap();
        let after_even = view.snapshot().unwrap().generation;
        assert_eq!(after_even, even_before + 2);

        // Now force a stuck-odd generation (simulated crash) and rebuild again.
        view.generation_atomic().store(after_even + 1, Ordering::SeqCst);
        view.rebuild(3, 3, "b", &[]).unwrap();
        let after_odd = view.snapshot().unwrap().generation;
        assert_eq!(after_odd, after_even + 2);
    }

    #[test]
    fn encode_pipe_name_rejects_oversized_input() {
        let too_long = "x".repeat(PIPE_NAME_WCHARS);
        let (_storage, view) = new_initialized(1, 1, "p");
        let err = view.set_broker(2, 2, &too_long).unwrap_err();
        assert!(matches!(err, FolderSectionError::PipeNameTooLong(_)));
    }

    /// THE core seqlock property: a background writer continuously
    /// publishing whole-tuple updates (broker identity + pipe name written
    /// together under one seqlock cycle), racing many concurrent readers,
    /// must never let a reader observe a torn / mixed combination of two
    /// different writes — every snapshot must be exactly one of the
    /// writer's complete, self-consistent tuples.
    #[test]
    fn concurrent_writer_and_many_readers_never_see_a_torn_snapshot() {
        const ITERATIONS: u32 = 2_000;
        const READERS: usize = 8;

        // Sentinel pid the writer never produces (ITERATIONS << u32::MAX),
        // so the pre-write init state can't alias iteration 0's tuple and
        // create a false "torn snapshot" failure.
        const INIT_PID: u32 = u32::MAX;

        let mut storage = blank_storage();
        let view = view_of(&mut storage);
        view.init(INIT_PID, 0, "start").expect("init");

        std::thread::scope(|scope| {
            scope.spawn(move || {
                for i in 0..ITERATIONS {
                    // Every write publishes a complete, internally-linked
                    // tuple: create_time is always exactly pid * 1000, and
                    // the pipe name always encodes the same pid. A reader
                    // that ever sees pid/create_time/pipe_name disagree
                    // caught a torn read.
                    let pid = i;
                    let ct = u64::from(i) * 1000;
                    let pipe = format!(r"\\.\pipe\winrsbox-gen-{i}");
                    view.set_broker(pid, ct, &pipe).expect("set_broker");
                }
            });

            for _ in 0..READERS {
                scope.spawn(move || {
                    let mut observed_any = false;
                    for _ in 0..ITERATIONS {
                        let snap = match view.snapshot() {
                            Ok(s) => s,
                            Err(FolderSectionError::SeqlockRetryExhausted(_)) => continue,
                            Err(e) => panic!("unexpected snapshot error: {e}"),
                        };
                        if snap.broker_pid == INIT_PID {
                            // Pre-write state: valid on its own, not a torn
                            // mix with any writer iteration (INIT_PID is
                            // never produced by the writer).
                            assert_eq!(snap.broker_create_time, 0);
                            assert_eq!(snap.pipe_name, "start");
                        } else {
                            assert_eq!(
                                snap.broker_create_time,
                                u64::from(snap.broker_pid) * 1000,
                                "torn snapshot: pid={} create_time={} disagree",
                                snap.broker_pid,
                                snap.broker_create_time,
                            );
                            let expected_pipe =
                                format!(r"\\.\pipe\winrsbox-gen-{}", snap.broker_pid);
                            assert_eq!(
                                snap.pipe_name, expected_pipe,
                                "torn snapshot: pipe_name doesn't match broker_pid"
                            );
                        }
                        observed_any = true;
                    }
                    assert!(observed_any, "reader never got a single consistent snapshot");
                });
            }
        });

        let final_snap = view.snapshot().expect("final snapshot");
        assert_eq!(final_snap.broker_pid, ITERATIONS - 1);
    }
}
