use super::*;
use super::match_tests::{build_dir_info_buffer, collect_names};

// ── more unaligned-read regression (same class as the probes above) ──
//
// extract_search_pattern reads the caller's UNICODE_STRING search
// argument and two paths touch the caller's IO_STATUS_BLOCK (final
// status after supervision, Information zeroing when every entry was
// hidden). All three bases are hooked-caller addresses with no
// alignment guarantee; these probes force them onto odd addresses.

/// Byte offset within `backing` whose address is ODD.
fn odd_offset(backing: &[u8]) -> usize {
    let off = 1 - (backing.as_ptr() as usize % 2);
    assert_eq!((backing.as_ptr() as usize + off) % 2, 1, "probe must sit at an odd address");
    off
}

/// Copy `value`'s bytes to `dst` — any alignment.
unsafe fn place_at<T>(dst: *mut u8, value: &T) {
    std::ptr::copy_nonoverlapping(
        value as *const T as *const u8,
        dst,
        std::mem::size_of::<T>(),
    );
}

/// UNICODE_STRING header AND WCHAR buffer each placed at an odd address:
/// the old `&*p` asserted 8-byte header alignment and
/// `from_raw_parts::<u16>(Buffer)` asserted Buffer evenness — both abort.
#[test]
fn extract_search_pattern_reads_misaligned_header_and_buffer() {
    let pattern = "*.txt";
    let wchars: Vec<u16> = pattern.encode_utf16().collect();
    let mut text_backing = vec![0u8; wchars.len() * 2 + 8];
    let toff = odd_offset(&text_backing);
    // SAFETY: u8 view of an aligned Vec<u16> payload of the same length.
    let wc_bytes = unsafe {
        std::slice::from_raw_parts(wchars.as_ptr() as *const u8, wchars.len() * 2)
    };
    text_backing[toff..toff + wc_bytes.len()].copy_from_slice(wc_bytes);

    let mut header_backing = vec![0u8; std::mem::size_of::<UNICODE_STRING>() + 8];
    let hoff = odd_offset(&header_backing);
    let header = UNICODE_STRING {
        Length: (wchars.len() * 2) as u16,
        MaximumLength: (wchars.len() * 2 + 2) as u16,
        // SAFETY: points at the odd window in `text_backing`, valid for
        // Length bytes; the backing outlives the call below.
        Buffer: unsafe { text_backing.as_ptr().add(toff) } as *mut u16,
    };
    // SAFETY: hoff ≤ 1, struct fits the backing.
    unsafe { place_at(header_backing.as_mut_ptr().add(hoff), &header) };
    // SAFETY: the odd header is a byte-identical, live UNICODE_STRING.
    let result = unsafe {
        extract_search_pattern(header_backing.as_ptr().add(hoff) as *const UNICODE_STRING)
    };
    assert_eq!(result, Some(pattern.to_string()));
}

/// The kernel-mirrored final status must be read out of a misaligned IOSB
/// (the hooked caller chose its address) — the old plain
/// `*(io_status_block as *const NTSTATUS)` aborted instead.
#[test]
fn supervised_final_status_is_read_from_misaligned_iosb() {
    let sup = DirQuerySupervision::new(std::ptr::null_mut())
        .expect("DirQuerySupervision::new must create a supervision event");
    let raw_event = sup.query_event();
    let mut iosb_backing = vec![0u8; std::mem::size_of::<IO_STATUS_BLOCK>() + 8];
    let ioff = odd_offset(&iosb_backing);
    // SAFETY: ioff ≤ 1, IO_STATUS_BLOCK fits the backing.
    let iosb_raw: *mut IO_STATUS_BLOCK =
        unsafe { iosb_backing.as_mut_ptr().add(ioff) } as *mut IO_STATUS_BLOCK;
    let iosb_for_thread = SendRaw(iosb_raw);
    let event_for_thread = SendRaw(raw_event);
    let handle = std::thread::spawn(move || {
        // Mirroring the kernel: final IOSB written BEFORE the event.
        std::thread::sleep(std::time::Duration::from_millis(50));
        // SAFETY: iosb_for_thread.0 points at the main thread's backing,
        // which outlives this thread (joined below); the 4-byte status is
        // stored byte-wise because the address is odd on purpose.
        unsafe {
            let status_bytes = 0xC000_0034_u32.to_le_bytes();
            std::ptr::copy_nonoverlapping(
                status_bytes.as_ptr(),
                iosb_for_thread.get() as *mut u8,
                4,
            );
        }
        let api = event_api().expect(
            "event_api must resolve NtCreateEvent, NtWaitForSingleObject, NtSetEvent, NtClose",
        );
        // SAFETY: event_for_thread.0 is `sup`'s own event; sup outlives
        // the join below.
        unsafe { (api.set_event)(event_for_thread.get(), std::ptr::null_mut()); }
    });
    // SAFETY: iosb_raw is the pointer the (simulated) original call was
    // given; wait_if_pending reads it only after the event fires.
    let status = unsafe { sup.wait_if_pending(STATUS_PENDING, iosb_raw) };
    handle.join().expect("supervision helper thread must not panic");
    assert_eq!(status, 0xC000_0034_u32 as NTSTATUS,
        "final status must be readable from an odd-address IOSB");
}

/// The only-hidden path zeroes Information in the caller's IOSB — the
/// old plain `*((iosb + 8) as *mut usize) = 0` aborted on an odd IOSB.
#[test]
fn only_hidden_zeroes_information_in_misaligned_iosb() {
    let built = build_dir_info_buffer(&[".winrsbox"]);
    let (mut backing, off) = odd_window(&built);
    assert_eq!((backing.as_ptr() as usize + off) % 2, 1,
        "probe buffer must start at an odd address");
    let mut iosb_backing = vec![0u8; std::mem::size_of::<IO_STATUS_BLOCK>() + 8];
    let ioff = odd_offset(&iosb_backing);
    // SAFETY: ioff ≤ 1, IO_STATUS_BLOCK fits the backing.
    let iosb_ptr: *mut IO_STATUS_BLOCK =
        unsafe { iosb_backing.as_mut_ptr().add(ioff) } as *mut IO_STATUS_BLOCK;
    // Stale pre-filter byte count at Information (offset 8, x64), written
    // byte-wise — an aligned usize store would trip the same precondition.
    // SAFETY: 8 bytes at iosb+8 stay inside the backing.
    unsafe {
        let stale = (built.len() as u64).to_le_bytes();
        std::ptr::copy_nonoverlapping(stale.as_ptr(), (iosb_ptr as *mut u8).add(8), 8);
    }
    // SAFETY: buf is a valid writable class-1 buffer at an odd base; the
    // iosb is the (misaligned) caller IOSB stand-in. dir_dos None keeps
    // the fn off IPC entirely.
    let status = unsafe {
        process_dir_output(
            backing.as_mut_ptr().add(off) as *mut c_void,
            iosb_ptr, 1, None, 0, built.len(), None,
        )
    };
    assert_eq!(status, STATUS_NO_MORE_FILES);
    // SAFETY: read the Information field back byte-wise from the backing.
    let mut info_bytes = [0u8; 8];
    unsafe {
        std::ptr::copy_nonoverlapping((iosb_ptr as *const u8).add(8), info_bytes.as_mut_ptr(), 8);
    }
    assert_eq!(usize::from_le_bytes(info_bytes), 0,
        "stale Information must be zeroed even in a misaligned IOSB");
}

// ── overlay-entry injection (enum-merge fix: ghost-file listing bug) ───
//
// A CoW write outside project_root into a directory that ALSO exists on
// the real disk gets isolated into the overlay (never touching the real
// directory — see policy::decide's merged-view model). The real
// NtQueryDirectoryFile result for that directory is therefore real-disk-
// only and never shows the overlay-only file, even though a direct open
// by name finds it via OVERLAY_IDX — a "ghost file" invisible to
// `dir`/`ls` but readable via `type`/`cat`. These functions merge
// overlay-only entries into the listing buffer so both channels agree.

/// Collect (lowercase name, FileAttributes) pairs from a class-1 buffer.
/// Test-only helper; production code never needs to READ attributes.
fn collect_names_and_attrs(buf: &[u8]) -> Vec<(String, u32)> {
    const ATTR_OFF: usize = 0x38;
    const NAME_LEN_OFF: usize = 0x3C;
    const NAME_OFF: usize = 0x40;
    let mut out = Vec::new();
    let mut cur = 0usize;
    while cur < buf.len() {
        if cur + NAME_OFF > buf.len() { break; }
        let next_off = u32::from_le_bytes([buf[cur], buf[cur+1], buf[cur+2], buf[cur+3]]) as usize;
        let attrs = u32::from_le_bytes([
            buf[cur+ATTR_OFF], buf[cur+ATTR_OFF+1], buf[cur+ATTR_OFF+2], buf[cur+ATTR_OFF+3],
        ]);
        let name_len = u32::from_le_bytes([
            buf[cur+NAME_LEN_OFF], buf[cur+NAME_LEN_OFF+1],
            buf[cur+NAME_LEN_OFF+2], buf[cur+NAME_LEN_OFF+3],
        ]) as usize;
        if name_len == 0 || cur + NAME_OFF + name_len > buf.len() { break; }
        let chars = name_len / 2;
        let mut name = String::new();
        for j in 0..chars {
            let off = cur + NAME_OFF + j * 2;
            let u = u16::from_le_bytes([buf[off], buf[off+1]]);
            name.push(char::from_u32(u as u32).unwrap_or('?'));
        }
        out.push((name, attrs));
        if next_off == 0 { break; }
        cur += next_off;
    }
    out
}

#[test]
fn dir_info_attr_offset_known_classes() {
    assert_eq!(dir_info_attr_offset(1), Some(0x38));
    assert_eq!(dir_info_attr_offset(2), Some(0x38));
    assert_eq!(dir_info_attr_offset(3), Some(0x38));
    assert_eq!(dir_info_attr_offset(37), Some(0x38));
    assert_eq!(dir_info_attr_offset(38), Some(0x38));
}

#[test]
fn dir_info_attr_offset_class_12_has_no_attribute_field() {
    assert_eq!(dir_info_attr_offset(12), None);
}

#[test]
fn dir_info_attr_offset_unhandled_class_is_none() {
    assert_eq!(dir_info_attr_offset(999), None);
}

#[test]
fn collect_present_names_lower_reads_existing_entries() {
    let buf = build_dir_info_buffer(&["Foo.txt", "bar.log"]);
    // SAFETY: buf is a valid class-1 buffer built above.
    let present = unsafe { collect_present_names_lower(buf.as_ptr(), buf.len(), 1) };
    assert!(present.contains("foo.txt"));
    assert!(present.contains("bar.log"));
    assert_eq!(present.len(), 2);
}

#[test]
fn collect_present_names_lower_empty_buffer() {
    let present = unsafe { collect_present_names_lower(std::ptr::null(), 0, 1) };
    assert!(present.is_empty());
}

/// Test-only builder for a zeroed-metadata `OverlayChildMeta` — used by
/// tests that only care about name/type presence, not size/times.
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

/// REGRESSION: the kernel reports IoStatusBlock.Information as "offset of
/// the last entry + that entry's actual length" — with NO trailing
/// alignment padding — so `used_size` is routinely NOT a multiple of 8.
/// Appending straight at that offset started a record on a misaligned
/// address: UB for the u32/u64 field writes, caught at runtime by Rust's
/// debug alignment check ("misaligned pointer dereference", aborting the
/// process with STATUS_STACK_BUFFER_OVERRUN), and a violation of the NT
/// contract that every record sits on an 8-byte boundary. The append
/// point is now rounded up; the chain stays walkable across the gap.
#[test]
fn append_overlay_entries_after_unaligned_used_size() {
    let mut buf = build_dir_info_buffer(&["a.txt"]);
    // 0x40 header + 10 name bytes = 0x4A — what a real kernel reports,
    // vs the 0x50 our test helper pads every entry to.
    let unaligned_used = 0x4A;
    buf.resize(1024, 0);
    buf[0..4].copy_from_slice(&0u32.to_le_bytes()); // single entry = terminator
    let extra = vec![meta("injected.txt", false)];
    // SAFETY: buf is a writable 1024-byte scratch buffer.
    let new_size = unsafe {
        append_overlay_entries(buf.as_mut_ptr(), unaligned_used, buf.len(), 1, &extra)
    };
    assert_eq!(new_size % 8, 0, "new used size must stay 8-byte aligned");
    let names = collect_names(&buf[..new_size]);
    assert_eq!(names, vec!["a.txt".to_string(), "injected.txt".to_string()],
        "the appended record must be reachable across the alignment gap");
}

#[test]
fn append_overlay_entries_into_empty_buffer() {
    let mut buf = vec![0u8; 256];
    let extra = vec![meta("new.txt", false)];
    // SAFETY: buf is a writable 256-byte scratch buffer.
    let new_size = unsafe {
        append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 1, &extra)
    };
    assert!(new_size > 0);
    let names = collect_names(&buf[..new_size]);
    assert_eq!(names, vec!["new.txt".to_string()]);
}

#[test]
fn append_overlay_entries_after_existing_tail() {
    let mut existing = build_dir_info_buffer(&["a.txt", "b.txt"]);
    let used = existing.len();
    existing.resize(used + 256, 0); // free space for the appended entry
    let extra = vec![meta("new.txt", false)];
    // SAFETY: existing is writable, sized used+256.
    let new_size = unsafe {
        append_overlay_entries(existing.as_mut_ptr(), used, existing.len(), 1, &extra)
    };
    assert!(new_size > used);
    let names = collect_names(&existing[..new_size]);
    assert_eq!(names, vec!["a.txt".to_string(), "b.txt".to_string(), "new.txt".to_string()],
        "appended entry must be reachable by walking the existing chain");
}

#[test]
fn append_overlay_entries_multiple_extras_all_fit() {
    let mut buf = vec![0u8; 512];
    let extra = vec![
        meta("one.txt", false),
        meta("two.txt", false),
        meta("three.txt", false),
    ];
    // SAFETY: buf is a writable 512-byte scratch buffer.
    let new_size = unsafe {
        append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 1, &extra)
    };
    let names = collect_names(&buf[..new_size]);
    assert_eq!(names, vec!["one.txt".to_string(), "two.txt".to_string(), "three.txt".to_string()]);
}

#[test]
fn append_overlay_entries_empty_extra_list_is_noop() {
    let mut buf = build_dir_info_buffer(&["a.txt"]);
    let used = buf.len();
    let original = buf.clone();
    // SAFETY: buf is a valid class-1 buffer.
    let new_size = unsafe {
        append_overlay_entries(buf.as_mut_ptr(), used, used, 1, &[])
    };
    assert_eq!(new_size, used);
    assert_eq!(buf, original);
}

#[test]
fn append_overlay_entries_sets_directory_attribute_bit() {
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    let mut buf = vec![0u8; 256];
    let extra = vec![meta("subdir", true)];
    // SAFETY: buf is a writable 256-byte scratch buffer.
    let new_size = unsafe {
        append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 1, &extra)
    };
    let entries = collect_names_and_attrs(&buf[..new_size]);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "subdir");
    assert_eq!(entries[0].1 & FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_DIRECTORY,
        "directory entry must carry FILE_ATTRIBUTE_DIRECTORY");
}

#[test]
fn append_overlay_entries_sets_normal_attribute_bit_for_file() {
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    let mut buf = vec![0u8; 256];
    let extra = vec![meta("probe.txt", false)];
    // SAFETY: buf is a writable 256-byte scratch buffer.
    let new_size = unsafe {
        append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 1, &extra)
    };
    let entries = collect_names_and_attrs(&buf[..new_size]);
    assert_eq!(entries[0].1, FILE_ATTRIBUTE_NORMAL);
}

/// Read (EndOfFile, CreationTime, LastAccessTime, LastWriteTime) from a
/// single class-1 entry at buffer offset 0 — test-only helper for
/// verifying the metadata-realism fix (previously all-zero placeholders
/// showed as 0-byte / 1601-01-01 in `dir`, a stealth-defeating tell a
/// live agent flagged against the real bash `ls` view of the same file).
fn read_meta_fields(buf: &[u8]) -> (u64, u64, u64, u64) {
    let field = |off: usize| u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
    (field(0x28), field(0x08), field(0x10), field(0x18))
}

#[test]
fn append_overlay_entries_writes_real_size_and_times() {
    let mut buf = vec![0u8; 256];
    let extra = vec![policy::OverlayChildMeta {
        name: "probe.txt".to_string(),
        is_dir: false,
        size: 12345,
        creation_time: 133_700_000_000_000_001,
        last_access_time: 133_700_000_000_000_002,
        last_write_time: 133_700_000_000_000_003,
    }];
    // SAFETY: buf is a writable 256-byte scratch buffer.
    let new_size = unsafe {
        append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 1, &extra)
    };
    let (end_of_file, ctime, atime, mtime) = read_meta_fields(&buf[..new_size]);
    assert_eq!(end_of_file, 12345);
    assert_eq!(ctime, 133_700_000_000_000_001);
    assert_eq!(atime, 133_700_000_000_000_002);
    assert_eq!(mtime, 133_700_000_000_000_003);
}

#[test]
fn append_overlay_entries_zeroed_meta_still_writes_zero_fields() {
    // A stale/unreadable overlay path (OverlayChildMeta all-zero per
    // policy::stat_overlay_phys's documented fallback) must not panic
    // and must legitimately report zero — this is the honest "we don't
    // know" case, distinct from silently leaving garbage stack bytes.
    let mut buf = vec![0xFFu8; 256]; // non-zero sentinel: proves an explicit zero-write happened
    let extra = vec![meta("stale.txt", false)];
    // SAFETY: buf is a writable 256-byte scratch buffer.
    let new_size = unsafe {
        append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 1, &extra)
    };
    let (end_of_file, ctime, atime, mtime) = read_meta_fields(&buf[..new_size]);
    assert_eq!((end_of_file, ctime, atime, mtime), (0, 0, 0, 0));
}

#[test]
fn append_overlay_entries_class_12_metadata_ignored_no_panic() {
    // class 12 (FileNamesInformation) has no time/size fields at all —
    // metadata must be silently skipped, not panic on an out-of-bounds
    // offset write.
    let mut buf = vec![0u8; 128];
    let extra = vec![policy::OverlayChildMeta {
        name: "new.txt".to_string(),
        is_dir: false,
        size: 999,
        creation_time: 111,
        last_access_time: 222,
        last_write_time: 333,
    }];
    // SAFETY: buf is a writable 128-byte scratch buffer.
    let new_size = unsafe {
        append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 12, &extra)
    };
    assert!(new_size > 0);
}

#[test]
fn append_overlay_entries_respects_capacity_drops_overflow() {
    // class-1 entry for "a.txt" (5 chars) is exactly 0x50 bytes
    // (0x40 header + 10 name bytes, aligned up to 0x50) — capacity fits
    // exactly one such entry and nothing more; the second, much longer
    // name must be dropped, not overflow the buffer.
    let mut buf = vec![0xAAu8; 0x60]; // 0xAA sentinel: detects OOB writes past capacity
    let capacity = 0x50;
    let extra = vec![meta("a.txt", false), meta("this_one_does_not_fit.txt", false)];
    // SAFETY: buf is 0x60 bytes; we pass capacity=0x50 as the hard limit.
    let new_size = unsafe {
        append_overlay_entries(buf.as_mut_ptr(), 0, capacity, 1, &extra)
    };
    assert_eq!(new_size, capacity, "the one entry that fits must exactly fill capacity");
    let names = collect_names(&buf[..new_size]);
    assert_eq!(names, vec!["a.txt".to_string()], "second (too-long) name must be dropped");
    // Bytes beyond `capacity` must be untouched (still the 0xAA sentinel).
    assert!(buf[capacity..].iter().all(|&b| b == 0xAA),
        "must not write past the caller-provided capacity");
}

#[test]
fn append_overlay_entries_unsupported_class_is_noop() {
    let mut buf = vec![0u8; 256];
    let extra = vec![meta("new.txt", false)];
    // SAFETY: buf is writable; class 999 is unhandled.
    let new_size = unsafe {
        append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 999, &extra)
    };
    assert_eq!(new_size, 0, "unsupported class must not append anything");
}

#[test]
fn append_overlay_entries_class_12_no_attribute_field() {
    // class 12: FileNamesInformation — 0x0C header, no FileAttributes field.
    let mut buf = vec![0u8; 128];
    let extra = vec![meta("new.txt", false)];
    // SAFETY: buf is a writable 128-byte scratch buffer.
    let new_size = unsafe {
        append_overlay_entries(buf.as_mut_ptr(), 0, buf.len(), 12, &extra)
    };
    assert!(new_size > 0);
    // Walk class-12 layout directly (NAME_LEN_OFF=0x08, NAME_OFF=0x0C).
    const NAME_LEN_OFF_12: usize = 0x08;
    const NAME_OFF_12: usize = 0x0C;
    let name_len = u32::from_le_bytes([
        buf[NAME_LEN_OFF_12], buf[NAME_LEN_OFF_12+1], buf[NAME_LEN_OFF_12+2], buf[NAME_LEN_OFF_12+3],
    ]) as usize;
    let chars = name_len / 2;
    let mut name = String::new();
    for j in 0..chars {
        let off = NAME_OFF_12 + j * 2;
        name.push(char::from_u32(u16::from_le_bytes([buf[off], buf[off+1]]) as u32).unwrap_or('?'));
    }
    assert_eq!(name, "new.txt");
}

// ── hidden-record leak + async-supervision fixes ───────────────────────
//
// Two bugs: (1) the only-hidden path returned 0x0000_0104 (STATUS_REPARSE
// — success severity) with a stale Information byte count, so FindNextFile
// handed the guest the record the filter had just removed; (2) a query on
// an async handle returned STATUS_PENDING and the guest later read the
// raw, unfiltered listing once the I/O completed.

/// Test-only `Send` wrapper for raw handles/pointers shared with the
/// supervision helper thread. Sound here: the main thread joins before
/// any further access, and the kernel-event signal orders the helper's
/// IOSB write before the supervised read. Access goes through `get` — a
/// raw `.0` field access inside the closure would capture the non-Send
/// pointer directly (edition-2021 disjoint capture) and skip the wrapper.
struct SendRaw<T>(T);
unsafe impl<T> Send for SendRaw<T> {}
impl<T: Copy> SendRaw<T> {
    fn get(&self) -> T {
        self.0
    }
}

#[test]
fn status_no_more_files_is_the_real_ntstatus() {
    assert_eq!(STATUS_NO_MORE_FILES, 0x8000_0006_u32 as NTSTATUS);
    // 0x104 is STATUS_REPARSE, the pre-fix bug value — success severity,
    // so callers trusted the filtered buffer and the hidden record leaked
    // through FindNextFile.
    assert_ne!(STATUS_NO_MORE_FILES, 0x0000_0104_u32 as NTSTATUS);
    // STATUS_NO_MORE_ENTRIES is a different status.
    assert_ne!(STATUS_NO_MORE_FILES, 0x8000_001A_u32 as NTSTATUS);
    assert_ne!(STATUS_NO_MORE_FILES, STATUS_PENDING);
}

#[test]
fn process_dir_output_only_hidden_zeroes_information_and_reports_no_more_files() {
    let mut buf = build_dir_info_buffer(&[".winrsbox"]);
    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    iosb.Information = buf.len();
    // SAFETY: buf is a valid writable class-1 buffer; iosb is a valid
    // stack IO_STATUS_BLOCK. dir_dos None keeps the fn off IPC entirely;
    // original_status 0; unhandled-class safe.
    let status = unsafe {
        process_dir_output(buf.as_mut_ptr() as *mut c_void, &mut iosb, 1, None, 0, buf.len(), None)
    };
    assert_eq!(status, 0x8000_0006_u32 as NTSTATUS);
    // Stale pre-filter bytes must not be readable as a live record via
    // FindNextFile.
    assert_eq!(iosb.Information, 0);
}

#[test]
fn event_api_resolves_and_round_trips() {
    let api = event_api().expect(
        "event_api must resolve NtCreateEvent, NtWaitForSingleObject, NtSetEvent, NtClose",
    );
    // SAFETY: same unnamed-event dance as DirQuerySupervision::new; every
    // call below uses a freshly created, self-owned event handle. The
    // event is set BEFORE the wait and a NotificationEvent stays
    // signaled, so the null (infinite) timeout cannot hang.
    unsafe {
        let mut oa: OBJECT_ATTRIBUTES = std::mem::zeroed();
        oa.Length = std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
        let mut event: HANDLE = std::ptr::null_mut();
        assert_eq!((api.create_event)(&mut event, 0x0010_0002, &mut oa, 0, 0), 0);
        assert_eq!((api.set_event)(event, std::ptr::null_mut()), 0);
        assert_eq!((api.wait_for_single_object)(event, 0, std::ptr::null_mut()), 0);
        assert_eq!((api.close)(event), 0);
    }
}

#[test]
fn pending_status_is_supervised_to_completion() {
    let sup = DirQuerySupervision::new(std::ptr::null_mut())
        .expect("DirQuerySupervision::new must create a supervision event");
    let raw_event = sup.query_event();
    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let iosb_raw: *mut IO_STATUS_BLOCK = &mut iosb;
    let iosb_for_thread = SendRaw(iosb_raw);
    let event_for_thread = SendRaw(raw_event);
    let handle = std::thread::spawn(move || {
        // Mirroring the kernel: the final IOSB is written BEFORE the
        // completion event is signaled.
        std::thread::sleep(std::time::Duration::from_millis(50));
        // SAFETY: iosb_for_thread.0 points at the main thread's `iosb`,
        // which outlives this thread (joined below) and is not read again
        // until the event wait orders the read after this write.
        unsafe { *(iosb_for_thread.get() as *mut NTSTATUS) = 0xC000_0034_u32 as NTSTATUS; };
        let api = event_api().expect(
            "event_api must resolve NtCreateEvent, NtWaitForSingleObject, NtSetEvent, NtClose",
        );
        // SAFETY: event_for_thread.0 is the supervision event owned by
        // `sup`, which is still alive while this thread runs (join before
        // sup drops).
        unsafe { (api.set_event)(event_for_thread.get(), std::ptr::null_mut()); }
    });
    // SAFETY: iosb_raw is the valid local `iosb` above; wait_if_pending
    // only reads it after the supervised event fires.
    let status = unsafe { sup.wait_if_pending(STATUS_PENDING, iosb_raw) };
    handle.join().expect("supervision helper thread must not panic");
    assert_eq!(status, 0xC000_0034_u32 as NTSTATUS);
    // Returning STATUS_PENDING unchanged is the pre-fix bug — the guest
    // then read the unfiltered listing once the I/O completed.
    assert_ne!(status, STATUS_PENDING);
}

#[test]
fn already_final_status_passes_through_unchanged() {
    let sup = DirQuerySupervision::new(std::ptr::null_mut())
        .expect("DirQuerySupervision::new must create a supervision event");
    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    // SAFETY: iosb is a valid stack IO_STATUS_BLOCK; a non-pending status
    // must be returned immediately, without any wait.
    unsafe {
        assert_eq!(sup.wait_if_pending(0, &mut iosb), 0);
        let av = 0xC000_0005_u32 as NTSTATUS;
        assert_eq!(sup.wait_if_pending(av, &mut iosb), av);
    }
}

// ── unaligned-buffer regression (alignment-UB class, mirrors 9d73d34) ──
//
// build_dir_info_buffer pads EVERY entry — including the last — so any
// buffer it produces is 8-aligned at the base and the tail. Real callers
// hand NtQueryDirectoryFile a buffer of their own choosing: the base can
// be an odd address, and then every record field sits at an odd address
// too. These probes force the record chain onto an odd address; every
// field access in the walkers must tolerate it (the old plain aligned
// dereferences abort under the debug alignment check with
// STATUS_STACK_BUFFER_OVERRUN instead of reading the field).

/// Copy `buf` into a larger backing allocation so the record chain starts
/// at an ODD address regardless of the allocator's base alignment.
fn odd_window(buf: &[u8]) -> (Vec<u8>, usize) {
    let mut backing = vec![0u8; buf.len() + 512];
    let off = 1 - (backing.as_ptr() as usize % 2);
    backing[off..off + buf.len()].copy_from_slice(buf);
    (backing, off)
}

/// Middle-entry hide on an odd buffer base: exercises the NextEntryOffset
/// and FileNameLength reads, the unaligned FileName read inside
/// name_matches_any_unaligned, and the previous record's NextEntryOffset
/// read + patch write — all at misaligned addresses.
#[test]
fn filter_entries_middle_hide_on_odd_base() {
    let built = build_dir_info_buffer(&["a.txt", "gone.md", "c.txt"]);
    let (mut backing, off) = odd_window(&built);
    assert_eq!(
        (backing.as_ptr() as usize + off) % 2,
        1,
        "probe buffer must start at an odd address",
    );
    let mut only_hidden = false;
    let hide = vec![
        dot_winrsbox_u16(),
        "gone.md".encode_utf16().collect::<Vec<u16>>(),
    ];
    // SAFETY: backing[off..off+built.len()] is a valid writable class-1
    // buffer with 512 spare bytes behind it.
    let filtered = unsafe {
        filter_entries(
            backing.as_mut_ptr().add(off),
            built.len(),
            1,
            &hide,
            &mut only_hidden,
        )
    };
    assert!(filtered);
    assert!(!only_hidden);
    let names = collect_names(&backing[off..off + built.len()]);
    assert_eq!(
        names,
        vec!["a.txt".to_string(), "c.txt".to_string()],
        "middle hide must stay correct on an odd buffer base",
    );
}

/// First-entry hide on an odd base: the shift path (memmove) driven by
/// the odd-address NextEntryOffset read.
#[test]
fn filter_entries_first_hide_shift_on_odd_base() {
    let built = build_dir_info_buffer(&["gone.md", "b.txt", "c.txt"]);
    let (mut backing, off) = odd_window(&built);
    let mut only_hidden = false;
    let hide = vec![
        dot_winrsbox_u16(),
        "gone.md".encode_utf16().collect::<Vec<u16>>(),
    ];
    // SAFETY: backing[off..off+built.len()] is a valid writable class-1
    // buffer with 512 spare bytes behind it.
    let filtered = unsafe {
        filter_entries(
            backing.as_mut_ptr().add(off),
            built.len(),
            1,
            &hide,
            &mut only_hidden,
        )
    };
    assert!(filtered);
    assert!(!only_hidden);
    let names = collect_names(&backing[off..off + built.len()]);
    assert_eq!(names, vec!["b.txt".to_string(), "c.txt".to_string()]);
}

/// Case rewrite on an odd buffer base: the unaligned FileName decode and
/// the in-place rewrite must both produce the mapped casing byte-exactly.
#[test]
fn rewrite_entry_case_on_odd_base() {
    let built = build_dir_info_buffer(&["mixed"]);
    let (mut backing, off) = odd_window(&built);
    let mut case_map = HashMap::new();
    case_map.insert("mixed".to_string(), "MiXeD".encode_utf16().collect::<Vec<u16>>());
    // SAFETY: backing[off..off+built.len()] is a valid writable class-1
    // buffer with 512 spare bytes behind it.
    unsafe {
        rewrite_entry_case(
            backing.as_mut_ptr().add(off),
            built.len(),
            1,
            &case_map,
        );
    }
    let names = collect_names(&backing[off..off + built.len()]);
    assert_eq!(
        names,
        vec!["MiXeD".to_string()],
        "case rewrite must be byte-exact on an odd buffer base",
    );
}
