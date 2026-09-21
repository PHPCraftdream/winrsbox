use std::sync::OnceLock;

use ntapi::ntioapi::IO_STATUS_BLOCK;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES};

use winapi::ctypes::c_void;

use crate::hooks;

use super::{STATUS_NO_MORE_FILES, STATUS_NO_SUCH_FILE, resolve_virtual_dir};
use super::r#match::{
    append_overlay_entries, build_case_map, collect_present_names_lower, dot_winrsbox_u16,
    filter_entries, filename_matches_pattern, rewrite_entry_case,
};

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

pub(crate) unsafe fn process_dir_output(
    file_information: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information_class: u32,
    dir_dos: Option<&str>,
    original_status: NTSTATUS,
    capacity: usize,
    search_pattern: Option<&str>,
) -> NTSTATUS {
    if io_status_block.is_null() {
        return original_status;
    }

    // Single-name (or wildcard) lookup that found nothing real: `dir
    // <exact-file>` and similar queries pass the target as the FileName
    // filter. The real syscall fails FAST here — none of the merge logic
    // below ever runs, because there are no real entries to merge into. If
    // the pattern matches an overlay-only file, synthesize the whole reply
    // from scratch; this is the same "ghost file" bug as the listing case,
    // reached through a different code path.
    if original_status == STATUS_NO_SUCH_FILE {
        if file_information.is_null() {
            return original_status;
        }
        let Some(pattern) = search_pattern else {
            return original_status; // no filter given — genuinely nothing to synthesize
        };
        let Some(dir) = resolve_virtual_dir(dir_dos) else {
            return original_status;
        };
        let pattern_lower = pattern.to_ascii_lowercase();
        let Some(extras) = crate::ipc_client::ipc_overlay_children(&dir) else {
            return original_status;
        };
        let matches: Vec<policy::OverlayChildMeta> = extras.into_iter()
            .filter(|e| filename_matches_pattern(&e.name.to_ascii_lowercase(), &pattern_lower))
            .collect();
        if matches.is_empty() {
            return original_status;
        }
        // SAFETY: file_information is writable for `capacity` bytes (the
        // caller's original NtQueryDirectoryFile `length` argument) — the
        // real syscall wrote nothing into it (it failed), so we own the
        // whole buffer from offset 0.
        let new_size = append_overlay_entries(
            file_information as *mut u8, 0, capacity, file_information_class, &matches,
        );
        if new_size == 0 {
            return original_status; // didn't fit / unsupported class
        }
        // SAFETY: io_status_block validated non-null above; Information sits
        // at offset 8 on x64 (4-byte Status/Pointer union + 4 pad). The
        // caller's IO_STATUS_BLOCK only guarantees 4-byte alignment, so the
        // usize write goes through write_unaligned.
        ((io_status_block as *mut u8).add(8) as *mut usize).write_unaligned(new_size);
        if hooks::is_trace() {
            hooks::ipc_log(ipc::LogLevel::Trace,
                format!("fs_enum_overlay_synthesize dir={dir} pattern={pattern} matched={}", matches.len()));
        }
        return 0; // STATUS_SUCCESS
    }

    if original_status != 0 {
        return original_status;
    }
    if file_information.is_null() {
        return original_status;
    }
    // IoStatusBlock.Information (offset 8 on x64) contains bytes written.
    // SAFETY: io_status_block validated non-null; Information at offset 8 on
    // x64. Read unaligned: the caller's IO_STATUS_BLOCK only guarantees
    // 4-byte alignment, not the 8 a plain usize load assumes.
    let info_size = ((io_status_block as *const u8).add(8) as *const usize).read_unaligned();
    if info_size == 0 {
        return original_status;
    }

    let virtual_dir: Option<String> = resolve_virtual_dir(dir_dos);

    // Build the hide set: `.winrsbox` is always hidden, plus any whiteouted
    // direct children of the directory being enumerated.
    let mut hide_names: Vec<Vec<u16>> = vec![dot_winrsbox_u16()];
    if let Some(ref dir) = virtual_dir {
        if let Some(names) = crate::ipc_client::ipc_whiteouts_under(dir) {
            for n in names {
                hide_names.push(n.encode_utf16().collect());
            }
        }
    }

    // Diagnostic: log the hide set and directory being filtered so we can
    // trace WHY entries disappear from a given directory listing.
    if hooks::is_trace() && hide_names.len() > 1 {
        let extra: Vec<String> = hide_names.iter().skip(1)
            .map(|w| String::from_utf16_lossy(w).to_string())
            .collect();
        hooks::ipc_log(ipc::LogLevel::Trace,
            format!("fs_hide_enum_whitelist dir={} whiteouts={:?}",
                virtual_dir.as_deref().unwrap_or("<none>"),
                extra));
    }

    let mut only_hidden = false;
    if filter_entries(
        file_information as *mut u8,
        info_size,
        file_information_class,
        &hide_names,
        &mut only_hidden,
    ) {
        if only_hidden {
            if hooks::is_trace() {
                hooks::ipc_log(ipc::LogLevel::Trace,
                    format!("fs_hide_enum: only hidden entries dir={}",
                        virtual_dir.as_deref().unwrap_or("<none>")));
            }
            // SAFETY: io_status_block validated non-null at the top of this fn;
            // Information at offset 8 on x64. Zeroed so the stale pre-filter
            // byte count is no longer readable as a live record via FindNextFile
            // — nothing valid remains in the buffer when every entry was hidden.
            // The IOSB is the hooked caller's, so the write must not assume
            // its alignment (matches the read_unaligned/write_unaligned used
            // everywhere else in this file for the same field).
            ((io_status_block as *mut u8).add(8) as *mut usize).write_unaligned(0);
            return STATUS_NO_MORE_FILES;
        }
        if hooks::is_trace() {
            hooks::ipc_log(ipc::LogLevel::Trace,
                format!("fs_hide_enum: entries filtered from listing dir={}",
                    virtual_dir.as_deref().unwrap_or("<none>")));
        }
    }

    // Case-rewrite: look up each surviving entry's name on the real host disk
    // and restore original case. Only applies when virtual_dir resolves to a
    // real directory on disk; overlay-only dirs are skipped (build_case_map → None).
    if let Some(ref dir) = virtual_dir {
        // std::fs::read_dir(virtual_dir) with anti_rec held → NtCreateFile
        // hook bypasses CoW (anti_rec::enter() returns None → calls original)
        // → original NtCreateFile opens the real host disk at virtual_dir.
        // Result: case_map contains original-case names from the real disk.
        if let Some(case_map) = build_case_map(dir) {
            if !case_map.is_empty() {
                rewrite_entry_case(
                    file_information as *mut u8,
                    info_size,
                    file_information_class,
                    &case_map,
                );
            }
        }
    }

    // Merge overlay-only entries: a CoW write outside project_root into a
    // directory that also exists on the real disk isolates into the overlay
    // without ever touching the real directory (policy::decide::compute), so
    // the real NtQueryDirectoryFile result above never includes it even
    // though a direct open by name already resolves it via OVERLAY_IDX — the
    // "ghost file" bug. Inject those entries here so both channels agree.
    if let Some(ref dir) = virtual_dir {
        if let Some(mut extras) = crate::ipc_client::ipc_overlay_children(dir) {
            if !extras.is_empty() {
                // SAFETY: file_information is valid for info_size bytes (kernel-filled).
                let present = collect_present_names_lower(
                    file_information as *const u8, info_size, file_information_class,
                );
                // A wildcard/exact FileName filter on this call must apply to
                // injected entries exactly as it did to the real ones — else
                // e.g. `dir *.log` (real matches only) would also inject an
                // unrelated overlay-only `.txt` file that never matched.
                let pattern_lower = search_pattern.map(|p| p.to_ascii_lowercase());
                extras.retain(|e| {
                    !present.contains(&e.name.to_ascii_lowercase())
                        && pattern_lower.as_deref()
                            .is_none_or(|pat| filename_matches_pattern(&e.name.to_ascii_lowercase(), pat))
                });
                if !extras.is_empty() {
                    // SAFETY: file_information is writable for `capacity` bytes
                    // (the caller's original NtQueryDirectoryFile `length` argument).
                    let new_size = append_overlay_entries(
                        file_information as *mut u8,
                        info_size,
                        capacity,
                        file_information_class,
                        &extras,
                    );
                    if new_size > info_size {
                        // SAFETY: io_status_block validated non-null above; Information
                        // sits at offset 8 on x64. The caller's IO_STATUS_BLOCK only
                        // guarantees 4-byte alignment, so the usize write goes through
                        // write_unaligned.
                        ((io_status_block as *mut u8).add(8) as *mut usize).write_unaligned(new_size);
                        if hooks::is_trace() {
                            hooks::ipc_log(ipc::LogLevel::Trace,
                                format!("fs_enum_overlay_merge dir={dir} added={}", extras.len()));
                        }
                    }
                }
            }
        }
    }

    original_status
}
