use super::*;
use super::match_tests::{
    MergeCallCfg, build_dir_info_buffer, collect_names, drive_merge_call,
};

/// Test-only builder for a zeroed-metadata `OverlayChildMeta` — used by
/// tests that only care about name/type presence, not size/times. (Same
/// helper as `tests::meta`; kept module-local so the two test files stay
/// independent.)
fn meta(name: &str, is_dir: bool) -> policy::OverlayChildMeta {
    policy::OverlayChildMeta {
        name: name.to_string(),
        is_dir,
        size: 0,
        creation_time: 0,
        last_access_time: 0,
        last_write_time: 0,
    }
}

// ── stateful overlay merge (review C01: per-handle enumeration state) ──
//
// The old merge was stateless: it reloaded overlay extras on every call,
// dropped the current+following extras when the buffer filled, never
// flushed pending extras once the real FS reported NO_MORE_FILES, treated
// a fully hidden real page as end-of-enumeration, ignored
// return_single_entry/restart_scan, and re-read the search mask from the
// current call instead of retaining it on the handle. These tests drive
// process_dir_output through multi-call passes via the per-handle
// DirEnumState registry.

/// Defects #1/#2 + stale-buffer rule: overlay extras that don't fit the
/// output buffer must stay PENDING (cursor) and be delivered on the NEXT
/// call — including a call where the real FS already reported
/// NO_MORE_FILES and the caller's buffer is stale (appends must start at
/// offset 0, not at the stale Information). Once the last extra is
/// delivered, a further call releases the state and reports end-of-enum.
#[test]
fn process_dir_output_overlay_extras_survive_buffer_exhaustion() {
    // class-1 records for 10/12-char names are 0x58 bytes aligned
    // (align8(0x40 + 2*10) = 0x58), so a 0xB0 buffer fits exactly two
    // appended extras and the third pends.
    const ENTRY: usize = 0x58;
    let mut buf = vec![0u8; 2 * ENTRY];
    let handle = 0x0000_C003usize as HANDLE;
    let key = handle as usize;
    let dir = r"C:\proj\merged".to_string();

    let extras = vec![
        meta("ov_one.txt", false),
        meta("ov_two.txt", false),
        meta("ov_three.txt", false),
    ];
    let children = move |_: &str| -> Option<Vec<policy::OverlayChildMeta>> { Some(extras.clone()) };
    let no_whiteouts = |_: &str| -> Option<Vec<String>> { Some(Vec::new()) };
    let mut requery = || -> NTSTATUS { STATUS_NO_MORE_FILES };

    // Call 1: empty real page (Information 0) → real stream done; the
    // overlay phase fills the buffer up to capacity.
    let mut iosb1: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let status1 = {
        let sources = DirMergeSources {
            overlay_children: &children,
            whiteouts_under: &no_whiteouts,
        };
        let mut ctx = DirQueryCtx {
            file_information: buf.as_mut_ptr() as *mut c_void,
            io_status_block: &mut iosb1,
            class: 1,
            capacity: buf.len(),
            handle,
            return_single_entry: false,
            restart_scan: false,
            pattern_from_call: None,
            dir_dos: Some(dir.clone()),
            original_status: 0,
            requery: &mut requery,
            sources,
        };
        // SAFETY: buf is a valid writable class-1 buffer; iosb1 valid stack
        // memory; sources are IPC-free stubs.
        unsafe { process_dir_output(&mut ctx) }
    };
    assert_eq!(status1, 0, "call 1 must deliver the two fitting extras");
    assert_eq!(collect_names(&buf[..2 * ENTRY]),
        vec!["ov_one.txt".to_string(), "ov_two.txt".to_string()]);
    assert_eq!(iosb1.Information, 2 * ENTRY);
    let st1 = peek_enum_state(key).expect("call 1 must keep the pass state");
    assert_eq!(st1.overlay_cursor, 2, "two extras consumed, third pending");
    assert!(!st1.overlay_done && st1.real_done);
    assert_eq!(st1.delivered, ["ov_one.txt", "ov_two.txt"].into_iter()
        .map(String::from).collect());

    // Call 2: kernel says NO_MORE_FILES; the buffer is STALE (still holds
    // call 1's records) — the pending extra must be appended at offset 0,
    // never at the stale Information (0xFFFF here to prove it's ignored).
    let mut iosb2: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    iosb2.Information = 0xFFFF;
    let status2 = {
        let sources = DirMergeSources {
            overlay_children: &children,
            whiteouts_under: &no_whiteouts,
        };
        let mut ctx = DirQueryCtx {
            file_information: buf.as_mut_ptr() as *mut c_void,
            io_status_block: &mut iosb2,
            class: 1,
            capacity: buf.len(),
            handle,
            return_single_entry: false,
            restart_scan: false,
            pattern_from_call: None,
            dir_dos: Some(dir.clone()),
            original_status: STATUS_NO_MORE_FILES,
            requery: &mut requery,
            sources,
        };
        // SAFETY: as call 1.
        unsafe { process_dir_output(&mut ctx) }
    };
    assert_eq!(status2, 0, "the pending extra must be flushed after NO_MORE_FILES");
    assert_eq!(collect_names(&buf[..ENTRY]), vec!["ov_three.txt".to_string()],
        "the stale-buffer append must start at offset 0");
    assert_eq!(iosb2.Information, ENTRY);
    let st2 = peek_enum_state(key).expect("call 2 delivered, so state is stored");
    assert!(st2.overlay_done, "cursor reached the end of the extras list");

    // Call 3: both streams exhausted → nothing delivered → state released
    // and end-of-enumeration reported.
    let mut iosb3: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let status3 = {
        let sources = DirMergeSources {
            overlay_children: &children,
            whiteouts_under: &no_whiteouts,
        };
        let mut ctx = DirQueryCtx {
            file_information: buf.as_mut_ptr() as *mut c_void,
            io_status_block: &mut iosb3,
            class: 1,
            capacity: buf.len(),
            handle,
            return_single_entry: false,
            restart_scan: false,
            pattern_from_call: None,
            dir_dos: Some(dir),
            original_status: STATUS_NO_MORE_FILES,
            requery: &mut requery,
            sources,
        };
        // SAFETY: as call 1.
        unsafe { process_dir_output(&mut ctx) }
    };
    assert_eq!(status3, STATUS_NO_MORE_FILES);
    assert_eq!(iosb3.Information, 0);
    assert!(peek_enum_state(key).is_none(),
        "an exhausted pass must release its registry entry");
}

/// Defect #4: return_single_entry must cap the merged reply at one entry
/// per call AND leave the not-yet-delivered extras pending (cursor frozen,
/// not advanced past them), so each subsequent call delivers exactly the
/// next one.
#[test]
fn process_dir_output_return_single_entry_pends_remaining_extras() {
    let mut buf = vec![0u8; 0x100];
    let handle = 0x0000_C004usize as HANDLE;
    let key = handle as usize;
    let dir = r"C:\proj\single".to_string();
    let extras = vec![meta("se_a.txt", false), meta("se_b.txt", false)];
    let children = move |_: &str| -> Option<Vec<policy::OverlayChildMeta>> { Some(extras.clone()) };
    let no_whiteouts = |_: &str| -> Option<Vec<String>> { Some(Vec::new()) };
    let mut requery = || -> NTSTATUS { STATUS_NO_MORE_FILES };

    // Call 1: real side exhausted; exactly one overlay extra delivered.
    let mut iosb1: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let status1 = {
        let sources = DirMergeSources {
            overlay_children: &children,
            whiteouts_under: &no_whiteouts,
        };
        let mut ctx = DirQueryCtx {
            file_information: buf.as_mut_ptr() as *mut c_void,
            io_status_block: &mut iosb1,
            class: 1,
            capacity: buf.len(),
            handle,
            return_single_entry: true,
            restart_scan: false,
            pattern_from_call: None,
            dir_dos: Some(dir.clone()),
            original_status: STATUS_NO_MORE_FILES,
            requery: &mut requery,
            sources,
        };
        // SAFETY: buf is a valid writable class-1 buffer; iosb1 valid stack
        // memory; sources are IPC-free stubs.
        unsafe { process_dir_output(&mut ctx) }
    };
    assert_eq!(status1, 0);
    assert_eq!(collect_names(&buf[..0x50]), vec!["se_a.txt".to_string()]);
    assert_eq!(iosb1.Information, 0x50);
    let st1 = peek_enum_state(key).expect("state stored after single delivery");
    assert_eq!(st1.overlay_cursor, 1, "the second extra must stay pending");
    assert!(!st1.overlay_done);

    // Call 2: the pending extra is the single delivery of this call.
    let mut iosb2: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let status2 = {
        let sources = DirMergeSources {
            overlay_children: &children,
            whiteouts_under: &no_whiteouts,
        };
        let mut ctx = DirQueryCtx {
            file_information: buf.as_mut_ptr() as *mut c_void,
            io_status_block: &mut iosb2,
            class: 1,
            capacity: buf.len(),
            handle,
            return_single_entry: true,
            restart_scan: false,
            pattern_from_call: None,
            dir_dos: Some(dir),
            original_status: STATUS_NO_MORE_FILES,
            requery: &mut requery,
            sources,
        };
        // SAFETY: as call 1.
        unsafe { process_dir_output(&mut ctx) }
    };
    assert_eq!(status2, 0);
    assert_eq!(collect_names(&buf[..0x50]), vec!["se_b.txt".to_string()]);
    let st2 = peek_enum_state(key).expect("state stored after second delivery");
    assert!(st2.overlay_done);
    // Pass exhausted: one more call releases the state.
    let mut iosb3: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let sources = DirMergeSources {
        overlay_children: &children,
        whiteouts_under: &no_whiteouts,
    };
    let mut ctx3 = DirQueryCtx {
        file_information: buf.as_mut_ptr() as *mut c_void,
        io_status_block: &mut iosb3,
        class: 1,
        capacity: buf.len(),
        handle,
        return_single_entry: true,
        restart_scan: false,
        pattern_from_call: None,
        dir_dos: None,
        original_status: STATUS_NO_MORE_FILES,
        requery: &mut requery,
        sources,
    };
    // SAFETY: as call 1.
    let status3 = unsafe { process_dir_output(&mut ctx3) };
    assert_eq!(status3, STATUS_NO_MORE_FILES);
    assert!(peek_enum_state(key).is_none());
}

/// Defect #5: the search mask is retained on the HANDLE (real Windows
/// keeps the mask from the first call). Call 1 passes "*.log"; call 2
/// passes no FileName — the retained mask must still gate the overlay
/// extras (m_b.txt stays invisible, m_a.log not re-delivered).
#[test]
fn process_dir_output_retains_mask_on_handle_across_calls() {
    let mut buf = vec![0u8; 0x100];
    let handle = 0x0000_C005usize as HANDLE;
    let key = handle as usize;
    let dir = r"C:\proj\masked".to_string();
    let extras = vec![meta("m_a.log", false), meta("m_b.txt", false)];
    let children = move |_: &str| -> Option<Vec<policy::OverlayChildMeta>> { Some(extras.clone()) };
    let no_whiteouts = |_: &str| -> Option<Vec<String>> { Some(Vec::new()) };
    let mut requery = || -> NTSTATUS { STATUS_NO_MORE_FILES };

    // Call 1: the mask matched nothing real (STATUS_NO_SUCH_FILE) — the
    // overlay-only *.log match is merged in from offset 0 (the old
    // synthesis path, now part of the unified flow).
    let mut iosb1: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let status1 = {
        let sources = DirMergeSources {
            overlay_children: &children,
            whiteouts_under: &no_whiteouts,
        };
        let mut ctx = DirQueryCtx {
            file_information: buf.as_mut_ptr() as *mut c_void,
            io_status_block: &mut iosb1,
            class: 1,
            capacity: buf.len(),
            handle,
            return_single_entry: false,
            restart_scan: false,
            pattern_from_call: Some("*.log".to_string()),
            dir_dos: Some(dir.clone()),
            original_status: STATUS_NO_SUCH_FILE,
            requery: &mut requery,
            sources,
        };
        // SAFETY: buf is a valid writable class-1 buffer; iosb1 valid stack
        // memory; sources are IPC-free stubs.
        unsafe { process_dir_output(&mut ctx) }
    };
    assert_eq!(status1, 0, "the overlay-only mask match must be merged in");
    assert_eq!(collect_names(&buf[..0x50]), vec!["m_a.log".to_string()]);
    let st1 = peek_enum_state(key).expect("state stored after delivery");
    assert_eq!(st1.mask.as_deref(), Some("*.log"), "mask retained on the handle");
    assert!(st1.overlay_done, "m_b.txt was consumed under the current mask");

    // Call 2: no FileName argument — the retained mask applies; nothing new
    // matches (m_a.log already delivered, m_b.txt mask-consumed), the pass
    // is exhausted and the state released.
    let mut iosb2: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let status2 = {
        let sources = DirMergeSources {
            overlay_children: &children,
            whiteouts_under: &no_whiteouts,
        };
        let mut ctx = DirQueryCtx {
            file_information: buf.as_mut_ptr() as *mut c_void,
            io_status_block: &mut iosb2,
            class: 1,
            capacity: buf.len(),
            handle,
            return_single_entry: false,
            restart_scan: false,
            pattern_from_call: None,
            dir_dos: Some(dir),
            original_status: STATUS_NO_MORE_FILES,
            requery: &mut requery,
            sources,
        };
        // SAFETY: as call 1.
        unsafe { process_dir_output(&mut ctx) }
    };
    assert_eq!(status2, STATUS_NO_MORE_FILES,
        "no re-delivery under the retained mask; pass exhausted");
    assert_eq!(iosb2.Information, 0);
    assert!(peek_enum_state(key).is_none());
}

/// Defect #3 + the hide-first dedup rule: a real page whose every entry is
/// whiteouted must NOT be reported as end-of-enumeration — the hook
/// requeries (the stub's next page is kernel exhaustion) — and the
/// whiteouted name recorded from the real page must keep a same-named
/// overlay child hidden while unrelated overlay children still merge in.
#[test]
fn process_dir_output_whiteouted_real_page_requeries_and_stays_hidden() {
    let mut buf = build_dir_info_buffer(&["gone.txt"]);
    let live_size = buf.len(); // 0x50 for an 8-char class-1 record
    buf.resize(live_size + 0x100, 0); // append headroom
    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    iosb.Information = live_size;

    let handle = 0x0000_C006usize as HANDLE;
    let key = handle as usize;
    let requery_calls = std::cell::Cell::new(0usize);
    let mut requery = || -> NTSTATUS {
        requery_calls.set(requery_calls.get() + 1);
        STATUS_NO_MORE_FILES // kernel exhaustion on the next real page
    };
    let extras = vec![meta("gone.txt", false), meta("live.txt", false)];
    let children = move |_: &str| -> Option<Vec<policy::OverlayChildMeta>> { Some(extras.clone()) };
    let whiteouts = move |_: &str| -> Option<Vec<String>> {
        Some(vec!["gone.txt".to_string()])
    };
    let sources = DirMergeSources {
        overlay_children: &children,
        whiteouts_under: &whiteouts,
    };
    let mut ctx = DirQueryCtx {
        file_information: buf.as_mut_ptr() as *mut c_void,
        io_status_block: &mut iosb,
        class: 1,
        capacity: buf.len(),
        handle,
        return_single_entry: false,
        restart_scan: false,
        pattern_from_call: None,
        dir_dos: Some(r"C:\proj\ghosted".to_string()),
        original_status: 0,
        requery: &mut requery,
        sources,
    };
    // SAFETY: buf is a valid writable class-1 buffer; iosb is valid stack
    // memory; sources are IPC-free stubs.
    let status = unsafe { process_dir_output(&mut ctx) };
    assert_eq!(status, 0, "the unrelated overlay child must still merge in");
    assert_eq!(requery_calls.get(), 1,
        "a fully hidden real page must pull the next page, not report EOF");
    assert_eq!(collect_names(&buf[..live_size]), vec!["live.txt".to_string()],
        "gone.txt must stay hidden (real whiteout AND overlay child)");
    assert_eq!(iosb.Information, live_size);
    let st = peek_enum_state(key).expect("state stored after delivery");
    assert!(st.delivered.contains("gone.txt"),
        "the whiteouted real name must be recorded as delivered");
    assert!(st.delivered.contains("live.txt"));
    let _ = take_enum_state(key);
}

/// Hidden-page EOF rule, part 2: a page whose real entries are ENTIRELY
/// hidden (`.winrsbox` always-hidden + a whiteouted real file) must be
/// followed by a requery — the NEXT page's visible real entries are then
/// delivered normally instead of the whole enumeration ending early.
#[test]
fn process_dir_output_hidden_real_page_then_visible_page_delivers() {
    // Page 1: 0x58 + 0x50 = 0xA8 bytes; it doubles as the caller capacity,
    // which page 2 (0x58) easily fits.
    let mut buf = build_dir_info_buffer(&[".winrsbox", "gone.txt"]);
    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    iosb.Information = buf.len(); // the kernel-filled page-1 size
    let page2 = build_dir_info_buffer(&["visible.txt"]); // 0x58
    let buf_ptr = buf.as_mut_ptr();
    let iosb_ptr = &mut iosb as *mut IO_STATUS_BLOCK;
    let requery_calls = std::cell::Cell::new(0usize);

    let handle = 0x0000_C007usize as HANDLE;
    let key = handle as usize;
    let no_children = move |_: &str| -> Option<Vec<policy::OverlayChildMeta>> {
        Some(Vec::new())
    };
    let whiteouts = move |_: &str| -> Option<Vec<String>> {
        Some(vec!["gone.txt".to_string()])
    };
    let mut requery = || -> NTSTATUS {
        requery_calls.set(requery_calls.get() + 1);
        // Simulate the kernel's NEXT page: write the page bytes into the
        // caller's buffer and report its length via IOSB.Information.
        // SAFETY: buf_ptr stays valid for the whole test (buf outlives every
        // call) and page 2 is smaller than the caller's capacity.
        unsafe {
            std::ptr::copy_nonoverlapping(page2.as_ptr(), buf_ptr, page2.len());
            ((iosb_ptr as *mut u8).add(8) as *mut usize).write_unaligned(page2.len());
        }
        0
    };
    let sources = DirMergeSources {
        overlay_children: &no_children,
        whiteouts_under: &whiteouts,
    };
    let mut ctx = DirQueryCtx {
        file_information: buf.as_mut_ptr() as *mut c_void,
        io_status_block: &mut iosb,
        class: 1,
        capacity: buf.len(),
        handle,
        return_single_entry: false,
        restart_scan: false,
        pattern_from_call: None,
        dir_dos: Some(r"C:\proj\hidden_page".to_string()),
        original_status: 0,
        requery: &mut requery,
        sources,
    };
    // SAFETY: buf is a valid writable class-1 buffer; iosb is valid stack
    // memory; sources are IPC-free stubs.
    let status = unsafe { process_dir_output(&mut ctx) };
    assert_eq!(status, 0, "page 2's visible real entries must be delivered");
    assert_eq!(requery_calls.get(), 1,
        "the fully hidden page must pull the next page, not end the enumeration");
    assert_eq!(collect_names(&buf[..page2.len()]),
        vec!["visible.txt".to_string()]);
    // Kernel Information contract: the LAST record's actual extent, without
    // trailing alignment padding — 0x40 + 2*11 = 0x56 for "visible.txt".
    assert_eq!(iosb.Information, 0x56);
    let _ = take_enum_state(key);
}

/// Multi-page enumeration with an overlay extra INTERLEAVED between the
/// real pages: the extra pends when page 1 leaves the buffer too full, is
/// delivered exactly once alongside page 2, and the third call (kernel
/// exhaustion) ends the pass and releases the state.
#[test]
fn process_dir_output_multi_page_real_and_overlay_interleaved() {
    // "x_long_name" is 11 chars → a 0x58 class-1 record (align8(0x40+22)).
    let page1 = build_dir_info_buffer(&["a.txt", "b.txt"]); // 0xA0
    let page2 = build_dir_info_buffer(&["c.txt"]); // 0x50
    let capacity: usize = 0xB0; // fits page1 (0xA0), not page1 + the 0x58 extra
    let mut buf = vec![0u8; capacity];
    buf[..page1.len()].copy_from_slice(&page1);
    let handle = 0x0000_C008usize as HANDLE;
    let key = handle as usize;
    let dir = r"C:\proj\interleaved".to_string();
    let extras = vec![meta("x_long_name", false)];
    let children = move |_: &str| -> Option<Vec<policy::OverlayChildMeta>> {
        Some(extras.clone())
    };
    let no_whiteouts = |_: &str| -> Option<Vec<String>> { Some(Vec::new()) };
    let mut requery = || -> NTSTATUS { STATUS_NO_MORE_FILES };

    // Call 1: page 1 (a, b) leaves no room for the extra — the append point
    // is align8(0x9A) = 0xA0 and 0xA0 + 0x58 > 0xB0, so it must stay PENDING,
    // not be dropped. The kernel reports Information as the last record's
    // ACTUAL extent: 0x50 (a.txt, aligned) + 0x40 + 2*5 = 0x9A.
    let mut iosb1: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    iosb1.Information = 0x9A;
    let status1 = {
        let sources = DirMergeSources {
            overlay_children: &children,
            whiteouts_under: &no_whiteouts,
        };
        let mut ctx = DirQueryCtx {
            file_information: buf.as_mut_ptr() as *mut c_void,
            io_status_block: &mut iosb1,
            class: 1,
            capacity,
            handle,
            return_single_entry: false,
            restart_scan: false,
            pattern_from_call: None,
            dir_dos: Some(dir.clone()),
            original_status: 0,
            requery: &mut requery,
            sources,
        };
        // SAFETY: buf is a valid writable class-1 buffer; iosb1 is valid
        // stack memory; sources are IPC-free stubs.
        unsafe { process_dir_output(&mut ctx) }
    };
    assert_eq!(status1, 0);
    assert_eq!(collect_names(&buf[..iosb1.Information]),
        vec!["a.txt".to_string(), "b.txt".to_string()],
        "the 0x58 extra does not fit after page 1 (align8(0x9A) + 0x58 > 0xB0)");
    assert_eq!(iosb1.Information, 0x9A);
    let st1 = peek_enum_state(key).expect("the pass continues — state stored");
    assert_eq!(st1.overlay_cursor, 0, "the extra is still pending");
    assert!(!st1.overlay_done);
    assert_eq!(st1.delivered,
        ["a.txt", "b.txt"].into_iter().map(String::from).collect());

    // Call 2: the kernel delivers page 2 (c; actual extent 0x4A) — the
    // pending extra is appended at align8(0x4A) = 0x50 (0x50 + 0x58 = 0xA8
    // ≤ 0xB0) and appears EXACTLY ONCE across the whole pass (call 1's
    // buffer showed only a, b; this call shows c + extra).
    buf[..page2.len()].copy_from_slice(&page2);
    let mut iosb2: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    iosb2.Information = 0x4A;
    let status2 = {
        let sources = DirMergeSources {
            overlay_children: &children,
            whiteouts_under: &no_whiteouts,
        };
        let mut ctx = DirQueryCtx {
            file_information: buf.as_mut_ptr() as *mut c_void,
            io_status_block: &mut iosb2,
            class: 1,
            capacity,
            handle,
            return_single_entry: false,
            restart_scan: false,
            pattern_from_call: None,
            dir_dos: Some(dir.clone()),
            original_status: 0,
            requery: &mut requery,
            sources,
        };
        // SAFETY: as call 1.
        unsafe { process_dir_output(&mut ctx) }
    };
    assert_eq!(status2, 0);
    assert_eq!(collect_names(&buf[..iosb2.Information]),
        vec!["c.txt".to_string(), "x_long_name".to_string()],
        "the pended extra is delivered once, interleaved with the real page");
    // 0xA8: align8(0x4A) append point (0x50) + the 0x58 extra — the append
    // result keeps the last record's 8-byte-aligned extent.
    assert_eq!(iosb2.Information, 0xA8);
    let st2 = peek_enum_state(key).expect("state stored after delivery");
    assert_eq!(st2.overlay_cursor, 1,
        "cursor == extras.len() — the extras list is exhausted");
    assert!(st2.overlay_done);

    // Call 3: the real kernel stream is exhausted and the extras are done →
    // end-of-enumeration and the registry entry is released.
    let mut iosb3: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let status3 = {
        let sources = DirMergeSources {
            overlay_children: &children,
            whiteouts_under: &no_whiteouts,
        };
        let mut ctx = DirQueryCtx {
            file_information: buf.as_mut_ptr() as *mut c_void,
            io_status_block: &mut iosb3,
            class: 1,
            capacity,
            handle,
            return_single_entry: false,
            restart_scan: false,
            pattern_from_call: None,
            dir_dos: Some(dir),
            original_status: STATUS_NO_MORE_FILES,
            requery: &mut requery,
            sources,
        };
        // SAFETY: as call 1.
        unsafe { process_dir_output(&mut ctx) }
    };
    assert_eq!(status3, STATUS_NO_MORE_FILES);
    assert_eq!(iosb3.Information, 0);
    assert!(peek_enum_state(key).is_none(),
        "an exhausted pass must release its registry entry");
}

/// RestartScan mid-enumeration must start the merge over (fresh delivered
/// set, extras cursor reset to re-consume the extras) while BUMPING the
/// generation instead of resetting it, and keeping the resolved dir — so a
/// restarted pass stays distinguishable from a brand-new handle.
#[test]
fn process_dir_output_restart_mid_enumeration_resets_state() {
    let page1 = build_dir_info_buffer(&["a.txt", "b.txt"]); // 0xA0
    let mut buf = vec![0u8; 0x200];
    buf[..page1.len()].copy_from_slice(&page1);
    let handle = 0x0000_C009usize as HANDLE;
    let key = handle as usize;
    let dir = r"C:\proj\restart".to_string();
    let extras = vec![meta("x.txt", false)]; // 0x50 record; extras.len() == 1
    let children = move |_: &str| -> Option<Vec<policy::OverlayChildMeta>> {
        Some(extras.clone())
    };
    let no_whiteouts = |_: &str| -> Option<Vec<String>> { Some(Vec::new()) };
    let mut requery = || -> NTSTATUS { STATUS_NO_MORE_FILES };

    // Call 1: a plain pass delivers a, b and the extra x.
    let mut iosb1: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    iosb1.Information = page1.len();
    let status1 = {
        let sources = DirMergeSources {
            overlay_children: &children,
            whiteouts_under: &no_whiteouts,
        };
        let mut ctx = DirQueryCtx {
            file_information: buf.as_mut_ptr() as *mut c_void,
            io_status_block: &mut iosb1,
            class: 1,
            capacity: buf.len(),
            handle,
            return_single_entry: false,
            restart_scan: false,
            pattern_from_call: None,
            dir_dos: Some(dir.clone()),
            original_status: 0,
            requery: &mut requery,
            sources,
        };
        // SAFETY: buf is a valid writable class-1 buffer; iosb1 is valid
        // stack memory; sources are IPC-free stubs.
        unsafe { process_dir_output(&mut ctx) }
    };
    assert_eq!(status1, 0);
    assert_eq!(collect_names(&buf[..iosb1.Information]),
        vec!["a.txt".to_string(), "b.txt".to_string(), "x.txt".to_string()]);
    assert_eq!(iosb1.Information, 0xF0); // 0xA0 page + 0x50 extra
    let st1 = peek_enum_state(key).expect("state stored after delivery");
    assert_eq!(st1.generation, 0);
    assert!(st1.overlay_done);
    assert_eq!(st1.delivered,
        ["a.txt", "b.txt", "x.txt"].into_iter().map(String::from).collect());

    // Call 2: the kernel RESTARTED the scan (same page 1 again) — the pass
    // starts over: the delivered set was cleared and the extras cursor reset,
    // so a, b, x are delivered AGAIN.
    buf[..page1.len()].copy_from_slice(&page1);
    let mut iosb2: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    iosb2.Information = page1.len();
    let status2 = {
        let sources = DirMergeSources {
            overlay_children: &children,
            whiteouts_under: &no_whiteouts,
        };
        let mut ctx = DirQueryCtx {
            file_information: buf.as_mut_ptr() as *mut c_void,
            io_status_block: &mut iosb2,
            class: 1,
            capacity: buf.len(),
            handle,
            return_single_entry: false,
            restart_scan: true,
            pattern_from_call: None,
            dir_dos: Some(dir.clone()),
            original_status: 0,
            requery: &mut requery,
            sources,
        };
        // SAFETY: as call 1.
        unsafe { process_dir_output(&mut ctx) }
    };
    assert_eq!(status2, 0, "a restarted pass delivers from the beginning again");
    assert_eq!(collect_names(&buf[..iosb2.Information]),
        vec!["a.txt".to_string(), "b.txt".to_string(), "x.txt".to_string()],
        "the delivered set was cleared and the extras cursor reset");
    assert_eq!(iosb2.Information, 0xF0);
    let st2 = peek_enum_state(key).expect("state stored after the restarted call");
    assert_eq!(st2.generation, 1,
        "RestartScan bumps the generation instead of resetting it");
    assert_eq!(st2.overlay_cursor, 1,
        "the extra was re-consumed (cursor == extras.len())");
    assert!(st2.overlay_done);
    assert_eq!(st2.dir, st1.dir, "the resolved dir is unchanged across restarts");

    // Call 3: restarting yet again bumps the generation once more.
    buf[..page1.len()].copy_from_slice(&page1);
    let mut iosb3: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    iosb3.Information = page1.len();
    let status3 = {
        let sources = DirMergeSources {
            overlay_children: &children,
            whiteouts_under: &no_whiteouts,
        };
        let mut ctx = DirQueryCtx {
            file_information: buf.as_mut_ptr() as *mut c_void,
            io_status_block: &mut iosb3,
            class: 1,
            capacity: buf.len(),
            handle,
            return_single_entry: false,
            restart_scan: true,
            pattern_from_call: None,
            dir_dos: Some(dir),
            original_status: 0,
            requery: &mut requery,
            sources,
        };
        // SAFETY: as call 1.
        unsafe { process_dir_output(&mut ctx) }
    };
    assert_eq!(status3, 0);
    let st3 = peek_enum_state(key).expect("state stored after the third call");
    assert_eq!(st3.generation, 2);
    let _ = take_enum_state(key);
}

/// An empty real directory (immediate NO_MORE_FILES) with only overlay
/// children: both extras flush from offset 0 — the caller's stale
/// Information (0x777 garbage) must be ignored — the IOSB Status FIELD must
/// read success too (defect #6), and the follow-up call reports
/// end-of-enumeration through BOTH channels and releases the state.
#[test]
fn process_dir_output_empty_real_dir_with_only_overlay_entries() {
    let mut buf = vec![0u8; 0x200];
    let handle = 0x0000_C00Ausize as HANDLE;
    let key = handle as usize;
    let dir = r"C:\proj\overlay_only".to_string();
    // 7-char names → 0x50 records each, so the two appended extras total
    // 0xA0 (the "two 0x50 records" arithmetic the assertions below pin).
    let extras = vec![meta("one.txt", false), meta("two.txt", false)];
    let children = move |_: &str| -> Option<Vec<policy::OverlayChildMeta>> {
        Some(extras.clone())
    };
    let no_whiteouts = |_: &str| -> Option<Vec<String>> { Some(Vec::new()) };
    let mut requery = || -> NTSTATUS { STATUS_NO_MORE_FILES };

    // Call 1: real side exhausted immediately; Information is stale garbage
    // (0x777) — the append must start at offset 0, never at Information.
    let mut iosb1: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    iosb1.Information = 0x777;
    let status1 = {
        let sources = DirMergeSources {
            overlay_children: &children,
            whiteouts_under: &no_whiteouts,
        };
        let mut ctx = DirQueryCtx {
            file_information: buf.as_mut_ptr() as *mut c_void,
            io_status_block: &mut iosb1,
            class: 1,
            capacity: buf.len(),
            handle,
            return_single_entry: false,
            restart_scan: false,
            pattern_from_call: None,
            dir_dos: Some(dir.clone()),
            original_status: STATUS_NO_MORE_FILES,
            requery: &mut requery,
            sources,
        };
        // SAFETY: buf is a valid writable class-1 buffer; iosb1 is valid
        // stack memory; sources are IPC-free stubs.
        unsafe { process_dir_output(&mut ctx) }
    };
    assert_eq!(status1, 0, "overlay-only entries must flush on this call");
    // SAFETY: Status (NTSTATUS) sits at offset 0 of the IOSB.
    let iosb1_status = unsafe {
        (std::ptr::addr_of!(iosb1) as *const NTSTATUS).read_unaligned()
    };
    assert_eq!(iosb1_status, 0,
        "defect #6: the NO_MORE_FILES flush path must write Status too");
    assert_eq!(iosb1.Information, 0xA0,
        "two 0x50 records appended from offset 0 (stale Information ignored)");
    assert_eq!(collect_names(&buf[..iosb1.Information]),
        vec!["one.txt".to_string(), "two.txt".to_string()]);

    // Call 2: both streams are done → end-of-enumeration through the return
    // value AND the IOSB Status field, Information 0, state released.
    let mut iosb2: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let status2 = {
        let sources = DirMergeSources {
            overlay_children: &children,
            whiteouts_under: &no_whiteouts,
        };
        let mut ctx = DirQueryCtx {
            file_information: buf.as_mut_ptr() as *mut c_void,
            io_status_block: &mut iosb2,
            class: 1,
            capacity: buf.len(),
            handle,
            return_single_entry: false,
            restart_scan: false,
            pattern_from_call: None,
            dir_dos: Some(dir),
            original_status: STATUS_NO_MORE_FILES,
            requery: &mut requery,
            sources,
        };
        // SAFETY: as call 1.
        unsafe { process_dir_output(&mut ctx) }
    };
    assert_eq!(status2, STATUS_NO_MORE_FILES);
    assert_eq!(iosb2.Information, 0);
    // SAFETY: Status (NTSTATUS) sits at offset 0 of the IOSB.
    let iosb2_status = unsafe {
        (std::ptr::addr_of!(iosb2) as *const NTSTATUS).read_unaligned()
    };
    assert_eq!(iosb2_status, STATUS_NO_MORE_FILES);
    assert!(peek_enum_state(key).is_none(),
        "the pass is exhausted — the registry entry is released");
    let _ = take_enum_state(key);
}

/// The return-path distinction: when the (retained) mask matched nothing
/// real, STATUS_NO_SUCH_FILE must be preserved — both as the return value
/// and in the IOSB Status field — even though the mask also consumed the
/// overlay extra (exhausted pass → state released, Information 0). The
/// NO_MORE_FILES rewrite on the exhaustion path must NOT swallow it.
#[test]
fn process_dir_output_no_such_file_preserved_when_nothing_matches() {
    let mut buf = vec![0u8; 0x100];
    let handle = 0x0000_C00Busize as HANDLE;
    let key = handle as usize;
    let dir = r"C:\proj\nomatch".to_string();
    let extras = vec![meta("not_a_log.txt", false)]; // consumed by the mask
    let children = move |_: &str| -> Option<Vec<policy::OverlayChildMeta>> {
        Some(extras.clone())
    };
    let no_whiteouts = |_: &str| -> Option<Vec<String>> { Some(Vec::new()) };
    let mut requery = || -> NTSTATUS { STATUS_NO_MORE_FILES };

    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    // SAFETY: Status (NTSTATUS) sits at offset 0 of the IOSB — simulate the
    // kernel's write for the failed real call.
    unsafe {
        (std::ptr::addr_of_mut!(iosb) as *mut NTSTATUS)
            .write_unaligned(STATUS_NO_SUCH_FILE);
    }
    let sources = DirMergeSources {
        overlay_children: &children,
        whiteouts_under: &no_whiteouts,
    };
    let mut ctx = DirQueryCtx {
        file_information: buf.as_mut_ptr() as *mut c_void,
        io_status_block: &mut iosb,
        class: 1,
        capacity: buf.len(),
        handle,
        return_single_entry: false,
        restart_scan: false,
        pattern_from_call: Some("*.log".to_string()),
        dir_dos: Some(dir),
        original_status: STATUS_NO_SUCH_FILE,
        requery: &mut requery,
        sources,
    };
    // SAFETY: buf is a valid writable class-1 buffer; iosb is valid stack
    // memory; sources are IPC-free stubs.
    let status = unsafe { process_dir_output(&mut ctx) };
    assert_eq!(status, STATUS_NO_SUCH_FILE,
        "mask-matched-nothing must NOT be rewritten into NO_MORE_FILES");
    // SAFETY: Status (NTSTATUS) sits at offset 0 of the IOSB.
    let iosb_status = unsafe {
        (std::ptr::addr_of!(iosb) as *const NTSTATUS).read_unaligned()
    };
    assert_eq!(iosb_status, STATUS_NO_SUCH_FILE,
        "the kernel's IOSB Status must not be overwritten");
    assert_eq!(iosb.Information, 0);
    assert!(peek_enum_state(key).is_none(),
        "the mask consumed the extra — the pass is exhausted and released");
    let _ = take_enum_state(key);
}

// ── generation-scoped extras snapshot (perf fix) ───────────────────────
//
// overlay_children is fetched ONCE per generation (DirEnumState.extras);

/// Three single-entry calls over ONE pass: the stub is hit exactly once,
/// both cached extras are delivered across calls (each once — no
/// duplicates), and the third call reports end-of-enumeration without a
/// re-fetch; the exhausted pass releases its state.
#[test]
fn process_dir_output_overlay_children_fetched_once_per_generation() {
    let mut buf = vec![0u8; 0x100];
    let handle = 0x0000_C010usize as HANDLE;
    let key = handle as usize;
    let dir = r"C:\proj\snap_once";
    let fetches = std::cell::Cell::new(0usize);
    let extras = [meta("snap_a.txt", false), meta("snap_b.txt", false)];
    let children = |_: &str| -> Option<Vec<policy::OverlayChildMeta>> {
        fetches.set(fetches.get() + 1);
        Some(extras.to_vec())
    };
    let no_whiteouts = |_: &str| -> Option<Vec<String>> { Some(Vec::new()) };
    let cfg = MergeCallCfg { restart_scan: false, return_single_entry: true,
        original_status: STATUS_NO_MORE_FILES };
    let mut iosb1: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    assert_eq!(drive_merge_call(&mut buf, &mut iosb1, handle, dir, &cfg,
        (&children, &no_whiteouts)), 0);
    assert_eq!(collect_names(&buf[..iosb1.Information]),
        vec!["snap_a.txt".to_string()]);
    let mut iosb2: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    assert_eq!(drive_merge_call(&mut buf, &mut iosb2, handle, dir, &cfg,
        (&children, &no_whiteouts)), 0);
    assert_eq!(collect_names(&buf[..iosb2.Information]),
        vec!["snap_b.txt".to_string()], "the second extra, once — no duplicates");
    let mut iosb3: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    assert_eq!(drive_merge_call(&mut buf, &mut iosb3, handle, dir, &cfg,
        (&children, &no_whiteouts)), STATUS_NO_MORE_FILES);
    assert_eq!(fetches.get(), 1, "overlay_children fetched exactly ONCE per generation");
    assert!(peek_enum_state(key).is_none(), "the exhausted pass released its state");
}

/// RestartScan starts a FRESH generation: the extras snapshot is
/// re-fetched, so the stub's second (different) list is what the restarted
/// pass delivers — restart re-snapshots instead of replaying the old cache.
#[test]
fn process_dir_output_restart_refetches_overlay_children() {
    let mut buf = vec![0u8; 0x100];
    let handle = 0x0000_C011usize as HANDLE;
    let key = handle as usize;
    let dir = r"C:\proj\snap_restart";
    let fetches = std::cell::Cell::new(0usize);
    let first = [meta("r1_a.txt", false)];
    let second = [meta("r2_b.txt", false)];
    let children = |_: &str| -> Option<Vec<policy::OverlayChildMeta>> {
        fetches.set(fetches.get() + 1);
        Some(if fetches.get() == 1 { first.to_vec() } else { second.to_vec() })
    };
    let no_whiteouts = |_: &str| -> Option<Vec<String>> { Some(Vec::new()) };
    let no_restart = MergeCallCfg { restart_scan: false, return_single_entry: false,
        original_status: STATUS_NO_MORE_FILES };
    let mut iosb1: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    assert_eq!(drive_merge_call(&mut buf, &mut iosb1, handle, dir, &no_restart,
        (&children, &no_whiteouts)), 0);
    assert_eq!(collect_names(&buf[..iosb1.Information]),
        vec!["r1_a.txt".to_string()]);
    // Call 2 carries restart_scan: a fresh generation re-snapshots.
    let restart = MergeCallCfg { restart_scan: true, return_single_entry: false,
        original_status: STATUS_NO_MORE_FILES };
    let mut iosb2: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    assert_eq!(drive_merge_call(&mut buf, &mut iosb2, handle, dir, &restart,
        (&children, &no_whiteouts)), 0);
    assert_eq!(fetches.get(), 2, "the restart re-fetched overlay_children");
    assert_eq!(collect_names(&buf[..iosb2.Information]),
        vec!["r2_b.txt".to_string()], "the restarted pass delivers from the NEW list");
    assert_eq!(peek_enum_state(key).map(|st| st.generation), Some(1));
    let _ = take_enum_state(key);
}

/// Mid-pass whiteout vs the cached extras: call 1 delivers only the first
/// extra (0x58 capacity fits exactly one 0x50 record); a whiteout for the
/// still-pending second extra is recorded BETWEEN portions. Call 2's fresh
/// per-portion whiteout fetch hides it against the CACHED extras list — it
/// is consumed, the pass exhausts, and the extras stub is still hit once.
#[test]
fn process_dir_output_whiteouted_extra_skipped_mid_pass() {
    let mut buf = vec![0u8; 0x58];
    let handle = 0x0000_C012usize as HANDLE;
    let key = handle as usize;
    let dir = r"C:\proj\snap_whiteout";
    let fetches = std::cell::Cell::new(0usize);
    let extras = [meta("wa_a.txt", false), meta("wa_b.txt", false)];
    let children = |_: &str| -> Option<Vec<policy::OverlayChildMeta>> {
        fetches.set(fetches.get() + 1);
        Some(extras.to_vec())
    };
    let toombs = std::cell::RefCell::new(Vec::<String>::new());
    let whiteouts = |_: &str| -> Option<Vec<String>> { Some(toombs.borrow().clone()) };
    let cfg = MergeCallCfg { restart_scan: false, return_single_entry: false,
        original_status: STATUS_NO_MORE_FILES };
    let mut iosb1: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    assert_eq!(drive_merge_call(&mut buf, &mut iosb1, handle, dir, &cfg,
        (&children, &whiteouts)), 0);
    assert_eq!(collect_names(&buf[..iosb1.Information]),
        vec!["wa_a.txt".to_string()]);
    // A tombstone lands BETWEEN the portions for the pending extra.
    *toombs.borrow_mut() = vec!["wa_b.txt".to_string()];
    let mut iosb2: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    assert_eq!(drive_merge_call(&mut buf, &mut iosb2, handle, dir, &cfg,
        (&children, &whiteouts)), STATUS_NO_MORE_FILES,
        "the whiteouted pending extra is consumed, not delivered");
    assert_eq!(iosb2.Information, 0);
    assert_eq!(fetches.get(), 1, "the cached extras list was reused, not refetched");
    assert!(peek_enum_state(key).is_none(), "the pass exhausted and released");
}

