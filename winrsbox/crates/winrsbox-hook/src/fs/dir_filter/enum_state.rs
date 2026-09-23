//! Per-handle enumeration state for the merged CoW-overlay directory view.
//!
//! `NtQueryDirectoryFile` is stateful: the kernel keeps an enumeration cursor
//! in the FILE_OBJECT so successive calls page through the directory. Our
//! hook layers a second stream — overlay-only entries — on top of the real
//! one, and that stream needs its own per-handle bookkeeping:
//!
//!  - `overlay_cursor` + `delivered`: which extras were already delivered
//!    this pass. Without it, a call whose output buffer filled mid-pass
//!    would reload the extras from scratch on the next call and re-append
//!    names the caller had already seen;
//!  - `real_done`: the real FS stream is exhausted — STATUS_NO_MORE_FILES
//!    from the real side must not hide still-pending overlay extras, and a
//!    failed real call means the caller's buffer is stale (appends must
//!    start at offset 0, not at the stale Information);
//!  - `mask`: the search mask retained on the handle. Real Windows retains
//!    the FileName filter from the first call; passing a new FileName
//!    replaces it, passing NULL keeps the retained one, and RestartScan
//!    resets the position without clearing the mask.
//!
//! Concurrency and identity (why keying by the raw handle value is sound):
//!
//!  - Handle-value recycling (a closed HANDLE's numeric value reused for an
//!    unrelated file) is neutralized by the `dir` identity check: a stored
//!    state is only reused when the freshly resolved virtual directory
//!    matches the one the state was created for; anything else builds fresh
//!    state (see `process_dir_output`).
//!  - A duplicated handle (different handle value, same kernel FILE_OBJECT)
//!    intentionally gets independent fresh overlay state. NT's own
//!    enumeration cursor lives in the FILE_OBJECT, so the real-side stream
//!    is shared regardless; only the overlay continuation restarts.
//!  - Two threads issuing queries on the SAME handle value concurrently is
//!    undefined in NT anyway (the kernel cursor is not synchronized for that
//!    either); this registry makes no attempt to serialize beyond the mutex
//!    around the Vec itself.
//!
//! "Release on close/exhaustion" is simply not storing the state back —
//! there is no close hook, so the `ENUM_STATES_CAP` bound (with FIFO
//! eviction) is what keeps abandoned handles from growing the registry
//! without limit. The mutex is held ONLY inside the three functions below —
//! never across IPC or kernel calls. A poisoned lock is recovered with
//! `into_inner`: one panicking hook call must not permanently break
//! enumeration for the whole process.
//!
//! Snapshot lifetime guarantee (`case_map` / `extras`): both are cached per
//! enumeration GENERATION — the lifetime of one logical listing on one
//! handle, exactly the lifetime of the rest of `DirEnumState`. They are
//! rebuilt whenever a fresh generation starts (restart-scan, dir change,
//! new handle), so directory content changes — including case on disk and
//! overlay additions/removals — become visible no later than the NEXT
//! generation. Whiteouts are NOT part of the snapshot: they stay per-portion
//! (fetched fresh on every call, see `process_dir_output`) so a tombstone
//! recorded between portions still hides not-yet-delivered entries. Nothing
//! is cached across unrelated calls or forever: release-on-exhaustion (no
//! store-back) and the `ENUM_STATES_CAP` registry cap still bound
//! everything.

use std::collections::HashMap;
use std::sync::Mutex;

/// Per-handle overlay-merge state for one directory enumeration pass.
#[derive(Clone, Debug)]
pub(crate) struct DirEnumState {
    /// Resolved virtual dir this state belongs to (identity check against
    /// handle-value recycling).
    pub(crate) dir: Option<String>,
    /// Bumped on every RestartScan over an existing state; lets tests (and
    /// trace readers) tell a restarted pass from a brand-new handle.
    pub(crate) generation: u64,
    /// Retained search mask (as given; compared case-insensitively).
    pub(crate) mask: Option<String>,
    /// Real FS stream exhausted for this pass.
    pub(crate) real_done: bool,
    /// Extras consumed this pass (index into the overlay children list).
    pub(crate) overlay_cursor: usize,
    /// Extras exhausted for this pass.
    pub(crate) overlay_done: bool,
    /// Whole-pass lowercase delivered names — real page names (including
    /// hidden ones) plus appended overlay extras.
    pub(crate) delivered: std::collections::HashSet<String>,
    /// Generation-scoped real-disk case snapshot (lowercase name →
    /// original-case UTF-16), so the per-page `read_dir` walk runs once per
    /// generation instead of once per delivered page. Outer `None`: not
    /// built yet this generation (also left when the dir resolution
    /// transiently failed — the next portion retries); inner `None`: built
    /// and empty/unavailable — final for this generation.
    pub(crate) case_map: Option<Option<HashMap<String, Vec<u16>>>>,
    /// Generation-scoped overlay-children snapshot, so the OVERLAY_CHILDREN
    /// IPC runs once per generation instead of once per portion. Outer
    /// `None`: not fetched yet this generation; inner `None`: transient IPC
    /// failure — NOT final, the next portion retries (cursor untouched).
    pub(crate) extras: Option<Option<Vec<policy::OverlayChildMeta>>>,
}

/// Bounded registry of per-handle enumeration states, keyed by the raw
/// handle value. Vec insertion order doubles as FIFO order for the
/// eviction cap below.
static ENUM_STATES: Mutex<Vec<(usize, DirEnumState)>> = Mutex::new(Vec::new());

/// Maximum tracked handles. Bounds memory for handles that are closed
/// mid-enumeration (no close hook exists to release their state eagerly).
const ENUM_STATES_CAP: usize = 256;

/// Remove and return the state stored for `key`, if any. Taking (rather
/// than reading) the state means a concurrent call on the same handle can
/// never double-consume the overlay cursor.
pub(crate) fn take_enum_state(key: usize) -> Option<DirEnumState> {
    let mut states = ENUM_STATES.lock().unwrap_or_else(|p| p.into_inner());
    let pos = states.iter().position(|(k, _)| *k == key)?;
    Some(states.remove(pos).1)
}

/// Store (or replace) the state for `key`. When the registry is full the
/// OLDEST entry is evicted first (FIFO) so the cap bounds abandoned handles.
pub(crate) fn store_enum_state(key: usize, st: DirEnumState) {
    let mut states = ENUM_STATES.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(slot) = states.iter_mut().find(|(k, _)| *k == key) {
        slot.1 = st;
        return;
    }
    if states.len() >= ENUM_STATES_CAP {
        states.remove(0);
    }
    states.push((key, st));
}

/// Read-only clone of the state for `key` — for test assertions only; the
/// production flow always takes (removes) the state so a concurrent call on
/// the same handle cannot double-consume the overlay cursor.
#[cfg(test)]
pub(crate) fn peek_enum_state(key: usize) -> Option<DirEnumState> {
    let states = ENUM_STATES.lock().unwrap_or_else(|p| p.into_inner());
    states.iter().find(|(k, _)| *k == key).map(|(_, st)| st.clone())
}
