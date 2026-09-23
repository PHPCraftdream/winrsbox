use std::collections::HashSet;
use std::sync::OnceLock;

use ntapi::ntioapi::IO_STATUS_BLOCK;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES};

use winapi::ctypes::c_void;

use crate::hooks;

use super::r#match::{
    append_overlay_entries, buffer_live_size, build_case_map, collect_present_names_lower,
    dot_winrsbox_u16, filter_entries, filename_matches_pattern, rewrite_entry_case,
};
// enum_state items come through the `pub(crate) use enum_state::*` glob in
// `super` (same channel as the status constants) so the re-export stays the
// single public surface of the submodules.
use super::{DirEnumState, store_enum_state, take_enum_state};
use super::{STATUS_NO_MORE_FILES, STATUS_NO_SUCH_FILE, resolve_virtual_dir};

// ---------------------------------------------------------------------------
// Asynchronous-query supervision
// ---------------------------------------------------------------------------

/// STATUS_PENDING — the original call returned before the kernel filled the
/// output buffer (the handle was opened for asynchronous I/O). Every other
/// non-success status either failed the query outright (nothing valid in the
/// buffer) or is STATUS_NO_SUCH_FILE (handled separately below); only
/// STATUS_PENDING means "data is still in flight".
pub(crate) const STATUS_PENDING: NTSTATUS = 0x0000_0103_u32 as NTSTATUS;

/// Returned when a query cannot be supervised at all (our completion event
/// could not be created). Deliberately an error: an unsupervised async
/// enumeration would complete later with a raw, unfiltered listing.
pub(crate) const STATUS_INSUFFICIENT_RESOURCES: NTSTATUS = 0xC000_009A_u32 as NTSTATUS;

pub(crate) type FnNtCreateEvent = unsafe extern "system" fn(
    *mut HANDLE,             // EventHandle (out)
    u32,                     // DesiredAccess
    *mut OBJECT_ATTRIBUTES,  // ObjectAttributes (unnamed event)
    i32,                     // EventType (0 = NotificationEvent)
    u8,                      // InitialState (BOOLEAN)
) -> NTSTATUS;
pub(crate) type FnNtWaitForSingleObject = unsafe extern "system" fn(
    HANDLE,                  // Handle
    u8,                      // Alertable (BOOLEAN) — always FALSE here
    *mut c_void,             // PLARGE_INTEGER Timeout — null = wait forever
) -> NTSTATUS;
pub(crate) type FnNtSetEvent = unsafe extern "system" fn(
    HANDLE,                  // EventHandle
    *mut u32,                // PULONG PreviousState (optional)
) -> NTSTATUS;
pub(crate) type FnNtClose = unsafe extern "system" fn(HANDLE) -> NTSTATUS;

/// ntdll entry points used to supervise asynchronous directory queries.
pub(crate) struct EventApi {
    pub(crate) create_event: FnNtCreateEvent,
    pub(crate) wait_for_single_object: FnNtWaitForSingleObject,
    pub(crate) set_event: FnNtSetEvent,
    pub(crate) close: FnNtClose,
}

static EVENT_API: OnceLock<EventApi> = OnceLock::new();

/// Resolve the supervision entry points from ntdll.
///
/// # SAFETY
/// Reads ntdll's export table; the resolved addresses are only ever called
/// through the ABI-correct aliases above.
unsafe fn resolve_event_api() -> Option<EventApi> {
    // SAFETY: one transmute per export, pattern-matching install()'s
    // `transmute(addr as usize)`; each address is a live ntdll export whose
    // ABI matches the alias it is transmuted to.
    let create_event: FnNtCreateEvent =
        std::mem::transmute(hooks::ntdll_export(b"NtCreateEvent\0")? as usize);
    let wait_for_single_object: FnNtWaitForSingleObject =
        std::mem::transmute(hooks::ntdll_export(b"NtWaitForSingleObject\0")? as usize);
    let set_event: FnNtSetEvent =
        std::mem::transmute(hooks::ntdll_export(b"NtSetEvent\0")? as usize);
    let close: FnNtClose =
        std::mem::transmute(hooks::ntdll_export(b"NtClose\0")? as usize);
    Some(EventApi { create_event, wait_for_single_object, set_event, close })
}

/// Lazily resolved (once) supervision API. Falls back to resolving in-process
/// so unit tests — which never run install() — exercise the same primitives
/// the hooks use.
pub(crate) fn event_api() -> Option<&'static EventApi> {
    if let Some(api) = EVENT_API.get() {
        return Some(api);
    }
    // SAFETY: ntdll export-table read; the addresses are only ever called
    // through the typed aliases in `EventApi`.
    let api = unsafe { resolve_event_api()? };
    EVENT_API.set(api).ok();
    EVENT_API.get()
}

/// Supervises one `NtQueryDirectoryFile[_Ex]` call whose I/O may complete
/// asynchronously.
///
/// A query issued on a handle opened for asynchronous I/O returns
/// STATUS_PENDING before the kernel has written anything into the caller's
/// buffer — if that status reached the caller, the guest would later read a
/// raw, *unfiltered* listing once the I/O completed. Wrapping the caller's
/// completion mechanism (event/APC) would need APC trampolines, and refusing
/// the query pre-call would need per-handle async tracking, so this instead
/// passes its OWN fresh, initially-non-signaled NotificationEvent to the
/// original call. On STATUS_PENDING the hook blocks until the supervised I/O
/// completes, adopts the final IoStatusBlock status, and only then lets
/// `process_dir_output` filter the buffer; the caller's own event is
/// signaled in Drop — strictly AFTER filtering — and the substitute event is
/// closed.
///
/// Semantic change (deliberate): asynchronous directory enumeration becomes
/// synchronous per call. Callers that passed an event still get it set,
/// callers with an APC still get it queued (delivered later, reading the
/// already-filtered buffer), and the value returned to the caller is the
/// final status — never STATUS_PENDING.
///
/// With the R03 staging buffer (see [`DirQueryStaging`]) the kernel never
/// writes the caller's buffer at all: the event substitution's remaining
/// job is to keep the caller's observation ATOMIC — the caller's event
/// fires (in Drop) only after `process_dir_output` has filtered the
/// private buffer and `publish` has copied the filtered bytes and
/// rewritten Status/Information into the caller's IOSB. Completion ports
/// are not routed through the Event argument, so a guest woken by IOCP
/// can observe its (untouched) buffer before that — stale guest bytes and
/// a transient raw byte count, never kernel-written name content.
///
/// Fail-closed: if the substitute event cannot be created, [`Self::new`]
/// returns None and the hook refuses the query with
/// STATUS_INSUFFICIENT_RESOURCES rather than running it unsupervised.
pub(crate) struct DirQuerySupervision {
    caller_event: HANDLE, // the caller's Event argument (may be null)
    event: HANDLE,        // our own fresh event handed to the original call
}

impl DirQuerySupervision {
    /// Create the substitute completion event. Returns None (fail-closed)
    /// when the supervision API is unavailable or the event cannot be
    /// created.
    pub(crate) fn new(caller_event: HANDLE) -> Option<Self> {
        let api = event_api()?;
        // SAFETY: OBJECT_ATTRIBUTES is all-integer/pointer fields, so a
        // zeroed value is a valid base; Length is set right after, following
        // InitializeObjectAttributes' convention (unnamed event — ObjectName
        // stays null).
        let mut oa: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
        oa.Length = std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
        let mut event: HANDLE = std::ptr::null_mut();
        // SAFETY: api.create_event is the ABI-correct ntdll export; the
        // out-handle and ObjectAttributes pointers are valid for the call.
        let status = unsafe {
            (api.create_event)(
                &mut event,
                0x0010_0002, // DesiredAccess: SYNCHRONIZE | EVENT_MODIFY_STATE
                &mut oa,
                0, // EventType: NotificationEvent (manual-reset)
                0, // InitialState: BOOLEAN FALSE (non-signaled)
            )
        };
        if status != 0 {
            return None;
        }
        Some(Self { caller_event, event })
    }

    /// The substitute event to pass to the original call in place of the
    /// caller's own.
    pub(crate) fn query_event(&self) -> HANDLE {
        self.event
    }

    /// If `status` is STATUS_PENDING, block until the supervised I/O
    /// completes and return the final status the kernel wrote into
    /// `io_status_block`; any other status is returned immediately,
    /// unchanged — the query is already complete.
    ///
    /// # SAFETY
    /// `io_status_block` must be the same pointer the original call was
    /// given (or null, which is passed through untouched).
    pub(crate) unsafe fn wait_if_pending(
        &self,
        status: NTSTATUS,
        io_status_block: *mut IO_STATUS_BLOCK,
    ) -> NTSTATUS {
        if status != STATUS_PENDING {
            return status;
        }
        if io_status_block.is_null() {
            // Unreachable through the hooks — the kernel rejects a null IOSB
            // synchronously — kept so this contract stays null-safe.
            return status;
        }
        loop {
            // SAFETY: self.event is the valid self-owned event from `new`;
            // Alertable = FALSE and a null timeout waits forever. Any result
            // other than STATUS_WAIT_0 (0) is not reachable for a valid
            // self-owned event with an infinite timeout — keep waiting
            // rather than return while the kernel may still write the
            // caller's buffer.
            let wait = (event_api().expect("event_api resolved by new()").wait_for_single_object)(
                self.event,
                0,
                std::ptr::null_mut(),
            );
            if wait == 0 {
                break;
            }
        }
        // SAFETY: the kernel writes the final status into the IOSB BEFORE
        // signaling our event, so the wait above orders this read after that
        // write. The Status union member sits at offset 0. The IOSB is the
        // hooked caller's, so the read must not assume its alignment.
        (io_status_block as *const NTSTATUS).read_unaligned()
    }
}

impl Drop for DirQuerySupervision {
    fn drop(&mut self) {
        // Runs after process_dir_output has filtered the buffer, so the
        // caller can never observe pre-filter data through a signaled event.
        let Some(api) = event_api() else { return };
        // SAFETY: caller_event is the caller's own event handle (null is
        // skipped) and event is ours from `new`; both are valid here.
        unsafe {
            if !self.caller_event.is_null() {
                (api.set_event)(self.caller_event, std::ptr::null_mut());
            }
            (api.close)(self.event);
        }
    }
}

/// Hook-private staging buffer for one supervised directory query
/// (review XA 2026-09-20, R03).
///
/// The real `NtQueryDirectoryFile[_Ex]` call is never given the caller's
/// `FileInformation` pointer. It writes its raw enumeration into `words`
/// (8-byte aligned, ≥ `capacity` bytes, zeroed); after `process_dir_output`
/// has filtered that private copy, [`Self::publish`] copies exactly the
/// live bytes into the caller's buffer. Two observation channels are
/// closed by construction that the completion-event substitution alone
/// could not close:
///
/// 1. A second guest thread that can name (or scan for) the caller's
///    buffer address can no longer read the raw kernel output — raw bytes
///    land only in hook-owned memory, and the caller's buffer is written
///    once, after filtering, from inside the hook frame.
/// 2. A completion-port wake-up is not routed through the Event argument,
///    so substituting the event cannot delay it. A guest thread woken by
///    IOCP now reads its own buffer, which is still untouched at that
///    moment (stale guest data, no kernel content), and the packet's
///    OVERLAPPED is still the caller's own IOSB pointer, so guest
///    completion logic is preserved.
///
/// Residual (documented, deliberately not "fixed"): between kernel
/// completion and `publish`, the caller's IOSB `Information` — and the
/// IOCP packet's byte count — hold the RAW byte count. Owning a private
/// IOSB instead would change the packet's OVERLAPPED identity and break
/// guest completion logic. A guest that ignores every completion signal
/// and polls its own IOSB can observe that size; no name content is ever
/// exposed. Callers honoring the NT contract (wait on the event / APC /
/// completion status) observe only the post-`publish` state: the caller's
/// event is signaled in `DirQuerySupervision`'s Drop — after `publish` —
/// and a kernel-queued APC runs on the issuing thread only at a later
/// alertable wait (the thread is blocked non-alertable inside
/// `wait_if_pending` until the hook returns), i.e. after the buffer and
/// IOSB are already filtered.
pub(crate) struct DirQueryStaging {
    /// Zeroed, 8-byte aligned, ≥ `capacity` bytes. Alignment mirrors the
    /// strictest field alignment (LARGE_INTEGER) any FILE_*_INFORMATION
    /// writer assumes; the kernel itself only 1-byte-probes the output
    /// buffer, so this is never weaker than what a guest heap buffer would
    /// have provided.
    words: Vec<u64>,
    /// Exactly the caller's Length argument — the byte length the kernel
    /// was given and the bound `process_dir_output` appends within.
    capacity: usize,
    /// The caller's `FileInformation` pointer. Never written until
    /// [`Self::publish`].
    caller_buffer: *mut c_void,
}

impl DirQueryStaging {
    /// Allocate the private output buffer for one query. Returns None when
    /// the reservation fails — `capacity` is guest-controlled, so
    /// allocation failure must stay a normal status (try_reserve_exact
    /// keeps it non-aborting) and the hook refuses the query fail-closed.
    pub(crate) fn new(caller_buffer: *mut c_void, capacity: usize) -> Option<Self> {
        let words = capacity.div_ceil(8).max(1);
        let mut buf: Vec<u64> = Vec::new();
        buf.try_reserve_exact(words).ok()?;
        buf.resize(words, 0);
        Some(Self { words: buf, capacity, caller_buffer })
    }

    /// The destination handed to the real syscall in place of the caller's
    /// `FileInformation`.
    ///
    /// Deriving a `*mut` from the shared `Vec` reference is fine here: the
    /// buffer is hook-owned scratch memory whose entire purpose is to be
    /// written by the kernel through this raw pointer — Rust's constness on
    /// the pointer type is not observable through the FFI boundary.
    pub(crate) fn kernel_ptr(&self) -> *mut c_void {
        self.words.as_ptr() as *mut c_void
    }

    /// Copy the final filtered bytes into the caller's buffer. The live
    /// byte count is read from the caller's IOSB `Information` (offset 8,
    /// x64) — `process_dir_output` rewrites it on every path that reports
    /// data, and on kernel-error pass-through paths it holds whatever the
    /// kernel itself wrote there (publishing those bytes reproduces exactly
    /// what the kernel would have written into the caller's buffer
    /// directly, pre-fix). A null IOSB or a zero count copies nothing; a
    /// count beyond the declared capacity is clamped (the kernel contract
    /// keeps Information ≤ Length — the clamp only bounds a hostile or
    /// stale IOSB value).
    ///
    /// # SAFETY
    /// `io_status_block` must be the pointer the original call was given
    /// (or null); the caller buffer handed to [`Self::new`] must be
    /// writable for `capacity` bytes and must not have been freed.
    pub(crate) unsafe fn publish(&self, io_status_block: *mut IO_STATUS_BLOCK) {
        if io_status_block.is_null() {
            return;
        }
        // SAFETY: offset-8 read_unaligned — the IOSB's alignment is
        // caller-controlled (same convention as wait_if_pending).
        let live =
            ((io_status_block as *const u8).add(8) as *const usize).read_unaligned();
        let n = live.min(self.capacity);
        if n == 0 {
            return;
        }
        // SAFETY: [0, n) of the staging buffer holds kernel/merge-written
        // bytes (n ≤ capacity = the Length the kernel was given); the
        // caller's buffer is writable for capacity ≥ n bytes. This is the
        // only write into guest memory, and it happens after filtering.
        std::ptr::copy_nonoverlapping(
            self.words.as_ptr() as *const u8,
            self.caller_buffer as *mut u8,
            n,
        );
    }
}

/// Where `process_dir_output` obtains the overlay's view of a directory.
/// Production wires the IPC client functions themselves; unit tests
/// substitute stub closures so the merge logic is testable without the
/// policy daemon. A `None` return is treated as a TRANSIENT failure (IPC
/// hiccup): cursors are preserved and the phase retried on the next call.
pub(crate) struct DirMergeSources<'a> {
    /// Overlay-only children of a directory (name + stat metadata).
    pub(crate) overlay_children: &'a dyn Fn(&str) -> Option<Vec<policy::OverlayChildMeta>>,
    /// Names whiteouted (tombstoned) directly under a directory.
    pub(crate) whiteouts_under: &'a dyn Fn(&str) -> Option<Vec<String>>,
}

/// Everything one `NtQueryDirectoryFile[_Ex]` hook call hands to the merge.
/// Groups the old positional arguments plus the flags the old code dropped
/// on the floor (`return_single_entry`, `restart_scan`) and a re-entry
/// closure for paging past hidden-only real pages.
pub(crate) struct DirQueryCtx<'a> {
    /// Caller's output buffer (kernel-filled on a successful real call).
    pub(crate) file_information: *mut c_void,
    /// Caller's IO_STATUS_BLOCK — Status at offset 0, Information at offset 8
    /// (x64); alignment is caller-controlled.
    pub(crate) io_status_block: *mut IO_STATUS_BLOCK,
    /// FileInformationClass of the query.
    pub(crate) class: u32,
    /// Byte capacity of `file_information` (the caller's Length argument).
    pub(crate) capacity: usize,
    /// Raw handle value — the key into the per-handle enumeration registry.
    pub(crate) handle: HANDLE,
    /// SL_RETURN_SINGLE_ENTRY — at most one entry may be delivered per call.
    pub(crate) return_single_entry: bool,
    /// SL_RESTART_SCAN — restart the enumeration from the beginning.
    pub(crate) restart_scan: bool,
    /// Search mask from THIS call's FileName argument. `None` means "keep
    /// the mask retained on the handle" (real Windows retains the first
    /// call's mask; a new FileName replaces it).
    pub(crate) pattern_from_call: Option<String>,
    /// Raw handle path; `resolve_virtual_dir` is applied inside. May be
    /// `None` on a transient path-resolution failure — existing cursors
    /// must survive that.
    pub(crate) dir_dos: Option<String>,
    /// Status the original (supervised) kernel call returned.
    pub(crate) original_status: NTSTATUS,
    /// Re-invokes the original syscall with RestartScan cleared (same
    /// buffer/IOSB/substitute event), used to pull further real pages past
    /// hidden-only pages.
    pub(crate) requery: &'a mut dyn FnMut() -> NTSTATUS,
    /// Overlay view of the directory (IPC in production, stubs in tests).
    pub(crate) sources: DirMergeSources<'a>,
}

/// Merge the CoW overlay into one `NtQueryDirectoryFile[_Ex]` reply.
///
/// Replaces the old shape, which returned early on any non-success status,
/// re-read the search mask from the current call, and had no per-handle
/// continuation state. A listing is now a STATEFUL two-phase merge:
///
/// Real-stream phase — pages the real FS through `ctx.requery` until a page
/// with visible entries arrives or the kernel reports exhaustion. A page
/// consisting entirely of hidden entries (`.winrsbox`/whiteouts) is no
/// longer reported as end-of-enumeration, because later real pages may
/// still hold visible files. Every name the real side carried — INCLUDING
/// hidden ones — is recorded in the per-handle `DirEnumState.delivered` set,
/// so an overlay child sharing a whiteouted name stays hidden.
///
/// Overlay phase — appends overlay-only entries the real pages never
/// showed, one at a time, tracking a cursor in `DirEnumState` so entries
/// that did not fit are delivered (once) on a later call instead of being
/// silently reloaded or duplicated.
///
/// End phase — writes IoStatusBlock.Status and Information consistently on
/// EVERY return path (the old code changed Information/return value but
/// left a stale Status in the IOSB on the synthetic-success and
/// hidden-only-EOF paths), and returns STATUS_NO_MORE_FILES when the merged
/// pass is exhausted. The old dedicated STATUS_NO_SUCH_FILE synthesis block
/// is subsumed by the unified flow: real_done + overlay merge with base 0
/// produces the same ghost-file reply.
///
/// Generation-scoped snapshots — the two per-portion lookups that depend
/// only on the DIRECTORY are cached in `DirEnumState` and reused across
/// portions of one logical enumeration instead of being redone for every
/// delivered page:
///
///  - `case_map`: the real-disk case map (`build_case_map` — one full
///    `read_dir` walk of the real directory) used to restore original-case
///    names on the lowercase physical mirror. Built once per generation;
///    a transient dir-resolution failure (dir None) does not cache an
///    empty result — the next portion retries.
///  - `extras`: the overlay children (one OVERLAY_CHILDREN IPC round-trip;
///    the policy side re-walks its subtree per call). Fetched once per
///    generation and reused; an inner None (transient IPC failure) is not
///    final — the next portion retries with the cursor untouched.
///
/// Both snapshots are rebuilt whenever a fresh generation starts
/// (restart-scan, dir change, new handle), so directory content changes
/// become visible no later than the next generation. Mid-pass overlay
/// mutations are bounded deliberately: whiteouts stay PER-PORTION (fetched
/// fresh on every call, before both phases) and are applied to
/// not-yet-delivered cached extras too, so a tombstone recorded between
/// portions still hides its entry; overlay additions become visible on the
/// next generation. Nothing is cached across unrelated calls or forever
/// (release-on-exhaustion and the registry cap still bound everything).
///
/// # SAFETY
/// `ctx.file_information` must be writable for `ctx.capacity` bytes and (on
/// a successful real call) hold a valid chain for `ctx.class`;
/// `ctx.io_status_block` must be the hooked caller's IOSB. Both are
/// caller-controlled addresses — every access goes through
/// read_unaligned/write_unaligned. `ctx.requery` re-enters the original
/// syscall with the caller's buffer/IOSB; the anti-recursion guard must be
/// held by the caller (hook context), which also keeps the inner
/// `build_case_map` read_dir on the real disk.
pub(crate) unsafe fn process_dir_output(ctx: &mut DirQueryCtx) -> NTSTATUS {
    // A null IOSB cannot be reported through — hand back the kernel's own
    // status untouched (unreachable via the hooks: the kernel rejects a
    // null IOSB synchronously).
    if ctx.io_status_block.is_null() {
        return ctx.original_status;
    }
    let dir: Option<String> = resolve_virtual_dir(ctx.dir_dos.as_deref());
    let key = ctx.handle as usize;

    // Per-handle state. A stored state is REUSED only when this call
    // continues the same pass: no RestartScan, and the resolved directory
    // still matches — or the resolution transiently failed (dir None),
    // which must not reset cursors. Everything else starts a fresh pass;
    // RestartScan over an existing state bumps its generation.
    let mut st = match take_enum_state(key) {
        Some(mut prev) if !ctx.restart_scan && (dir.is_none() || prev.dir == dir) => {
            // Mask retention: a FileName on THIS call replaces the retained
            // one; NULL keeps it. RestartScan resets position but does not
            // clear the mask (and lands in the fresh-state arm anyway).
            if let Some(ref p) = ctx.pattern_from_call {
                prev.mask = Some(p.clone());
            }
            prev
        }
        Some(prev) => DirEnumState {
            generation: if ctx.restart_scan { prev.generation + 1 } else { 0 },
            dir: dir.clone(),
            mask: ctx.pattern_from_call.clone(),
            real_done: false,
            overlay_cursor: 0,
            overlay_done: false,
            delivered: HashSet::new(),
            case_map: None,
            extras: None,
        },
        None => DirEnumState {
            generation: 0,
            dir: dir.clone(),
            mask: ctx.pattern_from_call.clone(),
            real_done: false,
            overlay_cursor: 0,
            overlay_done: false,
            delivered: HashSet::new(),
            case_map: None,
            extras: None,
        },
    };

    // Nothing filterable without a buffer (kernel-contract violation — a
    // successful query never has a null one). Keep the possibly re-masked
    // state so cursors survive.
    if ctx.file_information.is_null() {
        store_enum_state(key, st);
        return ctx.original_status;
    }
    // SAFETY: file_information is the hooked caller's output buffer —
    // writable for ctx.capacity bytes (the original Length argument).
    let buf = ctx.file_information as *mut u8;

    // Real-stream phase: page the real FS (through `requery`) until a page
    // with visible entries arrives or the kernel reports exhaustion.
    let mut status = ctx.original_status;
    // Append point for the overlay phase: past the fresh visible page when
    // one landed this call, else 0 — on a failed/empty call the caller's
    // buffer is STALE (the kernel does not clear it between calls), so
    // appends must start at offset 0, never at the stale Information.
    let mut base = 0usize;
    let mut delivered_this_call = false;

    // Hide set, built ONCE per call: `.winrsbox` is always hidden, plus any
    // whiteouted direct children of the directory being enumerated. An IPC
    // failure (None) just skips the whiteout part of the set. This now runs
    // on EVERY portion — including ones whose real stream is already
    // exhausted — deliberately: the whiteout set is per-portion (NOT part
    // of the generation snapshots) so the overlay phase below also sees
    // tombstones recorded between portions.
    let mut hide_names: Vec<Vec<u16>> = vec![dot_winrsbox_u16()];
    if let Some(ref d) = dir {
        if let Some(names) = (ctx.sources.whiteouts_under)(d) {
            for n in names {
                hide_names.push(n.encode_utf16().collect());
            }
        }
    }
    // ASCII-lowercased view of the same set for the overlay-extras filter
    // (extras are compared by lowercased name; whiteout names are already
    // lowercase, but fold them anyway — ".winrsbox" included).
    let hide_lower: HashSet<String> = hide_names.iter()
        .map(|w| String::from_utf16_lossy(w).to_ascii_lowercase())
        .collect();

    // Diagnostic: log the hide set so we can trace WHY entries
    // disappear from a given directory listing.
    if hooks::is_trace() && hide_names.len() > 1 {
        let extra: Vec<String> = hide_names.iter().skip(1)
            .map(|w| String::from_utf16_lossy(w).to_string())
            .collect();
        hooks::ipc_log(ipc::LogLevel::Trace,
            format!("fs_hide_enum_whitelist dir={} whiteouts={:?}",
                dir.as_deref().unwrap_or("<none>"),
                extra));
    }

    if !st.real_done {
        loop {
            if status == STATUS_NO_SUCH_FILE || status == STATUS_NO_MORE_FILES {
                // NO_SUCH_FILE: the (retained) mask matched nothing real.
                // NO_MORE_FILES: the real enumeration is exhausted. (The old
                // dedicated STATUS_NO_SUCH_FILE synthesis block lived here;
                // the overlay phase below with base 0 covers it.)
                st.real_done = true;
                break;
            }
            if status != 0 {
                // Unrelated kernel error: the kernel wrote the IOSB — pass
                // status and IOSB through unchanged, keeping the state so
                // the pass can continue once the caller recovers.
                store_enum_state(key, st);
                return status;
            }
            // SAFETY: io_status_block validated non-null at the top.
            // Information sits at offset 8 on x64; read unaligned — the
            // caller's IO_STATUS_BLOCK only guarantees 4-byte alignment.
            let mut info_size =
                ((ctx.io_status_block as *const u8).add(8) as *const usize).read_unaligned();
            if info_size == 0 {
                // Zero-byte success page: nothing real (and nothing
                // walkable) — treat as exhausted rather than spin on
                // requeries.
                st.real_done = true;
                break;
            }

            // Record every name the real page carried — INCLUDING names
            // about to be hidden: an overlay child sharing a whiteouted name
            // must stay hidden, not be re-injected by the dedup below.
            st.delivered
                .extend(collect_present_names_lower(buf, info_size, ctx.class));

            let mut only_hidden = false;
            // SAFETY: buf holds a kernel-filled chain of info_size bytes for
            // ctx.class (status 0 above); filter_entries compacts it in
            // place, keeping the chain walkable.
            let filtered =
                filter_entries(buf, info_size, ctx.class, &hide_names, &mut only_hidden);
            if only_hidden {
                if hooks::is_trace() {
                    hooks::ipc_log(ipc::LogLevel::Trace,
                        format!("fs_hide_enum: only hidden entries dir={}",
                            dir.as_deref().unwrap_or("<none>")));
                }
                // The whole page is hidden — but this is NOT necessarily
                // end-of-enumeration: later real pages may still hold
                // visible files. Zero the stale Information and pull the
                // next real page (RestartScan cleared) through the requery.
                // SAFETY: offset-8 write_unaligned; IOSB alignment is
                // caller-controlled.
                ((ctx.io_status_block as *mut u8).add(8) as *mut usize)
                    .write_unaligned(0usize);
                status = (ctx.requery)();
                continue;
            }
            if filtered && hooks::is_trace() {
                hooks::ipc_log(ipc::LogLevel::Trace,
                    format!("fs_hide_enum: entries filtered from listing dir={}",
                        dir.as_deref().unwrap_or("<none>")));
            }

            // Case-rewrite: look up each surviving entry's name on the real
            // host disk and restore original case (the physical overlay
            // stores everything lowercase). Only when the virtual dir
            // resolves to a real directory; overlay-only dirs are skipped
            // (build_case_map → None). The read_dir inside is anti_rec-
            // guarded by the hook that called us, so it reads the REAL disk.
            //
            // Generation-scoped snapshot: the walk runs once per generation
            // (cached in the per-handle state), not once per delivered
            // page. Only dir Some marks the snapshot built — a transient
            // dir-resolution failure keeps the outer None so the next
            // portion retries (today's behavior). An inner None (overlay-
            // only dir / empty lookup) stays final for the generation.
            if let Some(d) = dir.as_deref() {
                if st.case_map.is_none() {
                    st.case_map = Some(unsafe { build_case_map(d) });
                }
                if let Some(Some(case_map)) = st.case_map.as_ref() {
                    if !case_map.is_empty() {
                        // SAFETY: buf is a valid writable chain of info_size
                        // bytes for ctx.class; the rewrite is
                        // length-preserving.
                        rewrite_entry_case(buf, info_size, ctx.class, case_map);
                    }
                }
            }

            // Filtering shrank the chain — report the live tail (offset just
            // past the terminator record) so the IOSB never advertises
            // removed bytes as live records.
            info_size = buffer_live_size(buf, info_size, ctx.class);
            // SAFETY: offset-8 write_unaligned as above.
            ((ctx.io_status_block as *mut u8).add(8) as *mut usize).write_unaligned(info_size);
            base = info_size;
            delivered_this_call = true;
            break;
        }
    }

    // Overlay phase: append overlay-only entries the real pages never
    // showed. A CoW write outside project_root into a directory that also
    // exists on the real disk isolates into the overlay without ever
    // touching the real directory (policy::decide::compute), so the real
    // listing alone never includes it even though a direct open by name
    // already resolves it via OVERLAY_IDX — the "ghost file" bug. Inject
    // those entries here so both channels agree.
    if !st.overlay_done {
        if let Some(ref d) = dir {
            // Generation-scoped snapshot: the OVERLAY_CHILDREN IPC (the
            // policy side re-walks its subtree per call) runs once per
            // generation, not once per portion. An inner None (transient
            // IPC failure) is NOT final — the guard refetches on the next
            // portion, preserving today's transient-failure semantics.
            if st.extras.as_ref().is_none_or(|inner| inner.is_none()) {
                st.extras = Some((ctx.sources.overlay_children)(d));
            }
            // Take the Vec out so cursor/delivered can mutate while the
            // loop borrows it; always stored back below on every path.
            let fetched = st.extras.take();
            if let Some(Some(extras)) = fetched {
                // IPC Some: reuse/snapshot valid for this generation.
                // The RETAINED mask applies to injected entries exactly as
                // it did to the real ones — else e.g. `dir *.log` would also
                // inject an unrelated overlay-only `.txt` file.
                let mask_lower = st.mask.as_ref().map(|m| m.to_ascii_lowercase());
                let mut added = 0usize;
                for (i, e) in extras.iter().enumerate().skip(st.overlay_cursor) {
                    let lower = e.name.to_ascii_lowercase();
                    // Mask mismatch: consumed under the CURRENT retained
                    // mask (cursor advances past it — a later mask change
                    // mid-pass intentionally does not resurrect it).
                    if mask_lower.as_deref()
                        .is_some_and(|pat| !filename_matches_pattern(&lower, pat))
                    {
                        st.overlay_cursor = i + 1;
                        continue;
                    }
                    // Whole-pass dedup against real page names (including
                    // hidden ones) and previously appended extras.
                    if st.delivered.contains(&lower) {
                        st.overlay_cursor = i + 1;
                        continue;
                    }
                    // Whiteout recorded mid-pass against a not-yet-delivered
                    // cached extra: consumed like a mask mismatch (cursor
                    // advances; it is NOT resurrected later in this pass —
                    // the whiteout set is re-read fresh each portion, so a
                    // cleared tombstone re-delivers on the next generation).
                    if hide_lower.contains(&lower) {
                        st.overlay_cursor = i + 1;
                        continue;
                    }
                    // Single-entry mode: at most one entry per call — and
                    // the pending entry must NOT advance the cursor (it
                    // stays pending for the next call).
                    if ctx.return_single_entry && delivered_this_call {
                        break;
                    }
                    // Append ONE entry at a time so a filled buffer leaves
                    // this and every later extra pending (cursor untouched)
                    // instead of dropping them until the pass restarted, as
                    // the old batch append did. O(k²) worst case in extras
                    // count — acceptable at this layer; keep
                    // append_overlay_entries' signature (and its tests) as is.
                    // SAFETY: buf is writable for ctx.capacity bytes; [0,
                    // base) is either the fresh valid chain built above or
                    // empty-for-walking purposes (stale buffer — the append
                    // starts from offset 0 and rewrites the chain there).
                    let new_size = append_overlay_entries(
                        buf, base, ctx.capacity, ctx.class, std::slice::from_ref(e),
                    );
                    // `> base` alone would misread append's append-point
                    // rounding (unaligned base, entry didn't fit → returns
                    // aligned(base) > base with nothing written) as a
                    // delivery; a real record is always ≥ 8 aligned bytes,
                    // so require a full record of growth.
                    if new_size >= base + 8 {
                        base = new_size;
                        delivered_this_call = true;
                        added += 1;
                        st.delivered.insert(lower);
                        st.overlay_cursor = i + 1;
                    } else {
                        // Didn't fit — stays pending for the next call.
                        break;
                    }
                }
                if st.overlay_cursor >= extras.len() {
                    st.overlay_done = true;
                }
                if added > 0 && hooks::is_trace() {
                    hooks::ipc_log(ipc::LogLevel::Trace,
                        format!("fs_enum_overlay_merge dir={d} added={added} cursor={} done={}",
                            st.overlay_cursor, st.overlay_done));
                }
                st.extras = Some(Some(extras));
            } else {
                // IPC None is a TRANSIENT failure: leave overlay_done false
                // and the cursor untouched. Store Some(None) back so the
                // next portion retries the fetch (see guard above).
                st.extras = fetched;
            }
        }
    }

    // End phase — IOSB.Status and Information are written CONSISTENTLY on
    // every return path: callers may inspect either (the old code changed
    // Information/return value but left a stale Status in the IOSB on the
    // synthetic-success and hidden-only-EOF paths).
    if delivered_this_call {
        // SAFETY: Status (offset 0) and Information (offset 8) writes go
        // through write_unaligned — the IOSB's alignment is caller-
        // controlled.
        (ctx.io_status_block as *mut u32).write_unaligned(0u32);
        ((ctx.io_status_block as *mut u8).add(8) as *mut usize).write_unaligned(base);
        store_enum_state(key, st);
        return 0; // STATUS_SUCCESS
    }

    // Nothing new delivered: the caller's buffer must not advertise stale
    // bytes as a live record (FindNextFile walks Information bytes).
    // SAFETY: offset-8 write_unaligned as above.
    ((ctx.io_status_block as *mut u8).add(8) as *mut usize).write_unaligned(0usize);

    let exhausted = st.real_done && st.overlay_done;
    if !exhausted {
        // Pass continues — keep the cursors for the next call.
        store_enum_state(key, st);
    }
    // else: both streams exhausted — release the state by NOT storing it
    // back. There is no close hook; exhaustion is the natural release
    // point, and the registry cap bounds abandoned handles.

    if status == STATUS_NO_SUCH_FILE {
        // The kernel already wrote Status = STATUS_NO_SUCH_FILE for this
        // call — "the mask matched nothing" stays distinct from "exhausted".
        return status;
    }
    // End-of-enumeration: report it through BOTH channels (return value and
    // IOSB.Status), whatever stale Status the failed real call left behind.
    // SAFETY: offset-0 write_unaligned as above.
    (ctx.io_status_block as *mut u32).write_unaligned(STATUS_NO_MORE_FILES as u32);
    STATUS_NO_MORE_FILES
}
