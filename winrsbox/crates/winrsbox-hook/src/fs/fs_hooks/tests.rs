use super::*;

// Note: the former `reparse_flag_constant`, `is_reparse_create_*` tests
// (5 total) used to live here. They covered a now-removed predicate; the
// real escape vector `FSCTL_SET_REPARSE_POINT[_EX]` is tested in
// fs_metadata_guard. See the comment block near the top of this file.

#[test]
fn is_ea_present_empty_cases() {
    // Null buffer with zero length: no EA.
    assert!(!is_ea_present(std::ptr::null(), 0));
    // Null buffer with non-zero length: still no EA (defensive — kernel
    // would reject this too, but we never want to dereference null).
    assert!(!is_ea_present(std::ptr::null(), 32));
    // Non-null buffer with zero length: no EA payload.
    let dummy = 0u8;
    assert!(!is_ea_present(&dummy as *const u8 as *const c_void, 0));
}

#[test]
fn is_ea_present_supplied() {
    let dummy = 0u8;
    assert!(is_ea_present(&dummy as *const u8 as *const c_void, 1));
    assert!(is_ea_present(&dummy as *const u8 as *const c_void, u32::MAX));
}

#[test]
fn is_create_disposition_classifies_revive() {
    // Dispositions that (re)create the file → revive path on whiteout.
    assert!(is_create_disposition(FILE_SUPERSEDE)); // 0
    assert!(is_create_disposition(FILE_CREATE));     // 2
    assert!(is_create_disposition(FILE_OPEN_IF));    // 3
    assert!(is_create_disposition(FILE_OVERWRITE_IF)); // 5
}

// ── Mock malformed-decision fail-closed pins (audit 2026-09-19 Low) ──
//
// The four Mode::Mock arms live inside unsafe extern "system" hook bodies
// that cannot be invoked without a live ntdll detour, so the invariant is
// pinned textually (same technique as hooks.rs::spawn_hook_body and
// inject.rs::intentional_leak_pin_tests): a Mock arm that falls through to
// the original syscall on a payload/overlay-missing Mock decision re-opens
// the fail-open hole these arms were patched to close.

fn fn_body(src: &str, fn_sig: &str) -> String {
    let start = src
        .find(fn_sig)
        .unwrap_or_else(|| panic!("fn signature missing: {fn_sig}"));
    let rest = &src[start..];
    let end = rest
        .find("
pub(crate)")
        .or_else(|| rest.find("
#[cfg(test)]"))
        .expect("next item bounds the fn body");
    rest[..end].to_string()
}

fn mock_arm(body: &str) -> String {
    let start = body
        .find("Mode::Mock => {")
        .expect("Mode::Mock arm must exist");
    let rest = &body[start..];
    let end = rest.find("Mode::Cow").unwrap_or(rest.len());
    rest[..end].to_string()
}

#[test]
fn mock_create_open_arms_fail_closed_on_malformed_decision() {
    let src = &crate::hooks::module_source("fs_hooks");
    for (sig, tag) in [
        ("fn hook_nt_create_file", "create"),
        ("fn hook_nt_open_file", "open"),
    ] {
        let arm = mock_arm(&fn_body(src, sig));
        assert!(
            !arm.contains("return call_original"),
            "{tag}: Mode::Mock arm must never fall through to the original syscall on a malformed (payload/overlay-missing) Mock decision"
        );
        assert!(
            arm.contains("mock_malformed_decision_deny"),
            "{tag}: Mode::Mock arm must log the malformed decision"
        );
        assert!(
            arm.contains("STATUS_ACCESS_DENIED"),
            "{tag}: Mode::Mock arm must fail closed (ACCESS_DENIED)"
        );
    }
}

#[test]
fn mock_query_arms_fail_closed_on_malformed_decision() {
    let src = &crate::hooks::module_source("fs_hooks");
    for (sig, tag) in [
        ("fn hook_nt_query_attributes_file", "query_attributes"),
        ("fn hook_nt_query_full_attributes_file", "query_full"),
    ] {
        let arm = mock_arm(&fn_body(src, sig));
        assert!(
            !arm.contains(".call(object_attributes, file_information)"),
            "{tag}: Mode::Mock arm must not pass the original path through on a malformed (payload/overlay-missing) Mock decision"
        );
        assert!(
            arm.contains("mock_malformed_decision_deny"),
            "{tag}: Mode::Mock arm must log the malformed decision"
        );
        assert!(
            arm.contains("STATUS_ACCESS_DENIED"),
            "{tag}: Mode::Mock arm must fail closed (ACCESS_DENIED)"
        );
    }
}

#[test]
fn is_create_disposition_rejects_pure_open() {
    // FILE_OPEN (1) and FILE_OVERWRITE (4) are NOT creates:
    // a hidden path must surface not-found for these, not revive.
    assert!(!is_create_disposition(1)); // FILE_OPEN
    assert!(!is_create_disposition(4)); // FILE_OVERWRITE
    // Unknown dispositions are also not revives.
    assert!(!is_create_disposition(99));
}

// ── P0-03: dead-end write intent + device-block deny ───────────────────

#[test]
fn dead_end_write_intent_masks() {
    // Plain data-write and generic masks.
    assert!(dead_end_write_intent(crate::hooks::GENERIC_WRITE, None, 0));
    assert!(dead_end_write_intent(crate::hooks::FILE_WRITE_DATA, None, 0));
    assert!(dead_end_write_intent(crate::hooks::FILE_APPEND_DATA, None, 0));
    // Metadata / EA / generic-all / delete / security ops — the
    // canonical mask, not a dead-end-private one.
    assert!(dead_end_write_intent(crate::hooks::GENERIC_ALL, None, 0));
    assert!(dead_end_write_intent(crate::hooks::FILE_WRITE_ATTRIBUTES, None, 0));
    assert!(dead_end_write_intent(crate::hooks::FILE_WRITE_EA, None, 0));
    assert!(dead_end_write_intent(crate::hooks::DELETE, None, 0));
    assert!(dead_end_write_intent(crate::hooks::WRITE_DAC, None, 0));
    assert!(dead_end_write_intent(crate::hooks::WRITE_OWNER, None, 0));
    // Generic READ must not count as a write.
    assert!(!dead_end_write_intent(0x8000_0000, None, 0));
    assert!(!dead_end_write_intent(0, None, 0));
}

/// The dead end must never disagree with the canonical mask: it is the
/// same definition plus the CreateOptions DELETE_ON_CLOSE bit. If this
/// table ever diverges from `is_write_access`, an open classified as a
/// read on one path and a write on the other is one edit away.
#[test]
fn dead_end_write_intent_agrees_with_is_write_access() {
    let access_cases: [u32; 11] = [
        crate::hooks::GENERIC_ALL,
        crate::hooks::GENERIC_WRITE,
        crate::hooks::FILE_WRITE_DATA,
        crate::hooks::FILE_APPEND_DATA,
        crate::hooks::FILE_WRITE_EA,
        crate::hooks::FILE_WRITE_ATTRIBUTES,
        crate::hooks::DELETE,
        crate::hooks::WRITE_DAC,
        crate::hooks::WRITE_OWNER,
        crate::hooks::MAXIMUM_ALLOWED, // MAXIMUM_ALLOWED — potential write on BOTH paths (S01)
        0x8000_0000, // GENERIC_READ — must stay a read on BOTH paths
    ];
    let dispositions = [0, 1, 2, 3, 4, 5]; // SUPERSEDE..OVERWRITE_IF incl. FILE_OPEN
    for &a in &access_cases {
        for &d in &dispositions {
            assert_eq!(
                dead_end_write_intent(a, Some(d), 0),
                is_write_access(a, d),
                "dead-end vs canonical disagreement for access={a:#010x} disposition={d}"
            );
        }
    }
}

#[test]
fn dead_end_write_intent_dispositions_and_options() {
    use crate::hooks::FILE_OVERWRITE;
    // Create dispositions count as writes even with no access bits.
    assert!(dead_end_write_intent(0, Some(FILE_CREATE), 0));
    assert!(dead_end_write_intent(0, Some(FILE_OPEN_IF), 0));
    assert!(dead_end_write_intent(0, Some(FILE_OVERWRITE), 0));
    assert!(dead_end_write_intent(0, Some(FILE_OVERWRITE_IF), 0));
    assert!(dead_end_write_intent(0, Some(FILE_SUPERSEDE), 0));
    // Pure open stays a read.
    assert!(!dead_end_write_intent(0, Some(1), 0)); // FILE_OPEN
    // FILE_DELETE_ON_CLOSE turns even a read-mode open into a write.
    assert!(dead_end_write_intent(0, None, FILE_DELETE_ON_CLOSE));
    assert!(!dead_end_write_intent(0, None, 0));
}

/// Calls `classify_device_open` on an NT path; returns its verdict.
fn device_block_for(path: &str, write: bool) -> DeviceVerdict {
    use ntapi::winapi::shared::ntdef::UNICODE_STRING;
    let buf: Vec<u16> = path.encode_utf16().collect();
    let len_bytes = (buf.len() * 2) as u16;
    let mut us = UNICODE_STRING {
        Length: len_bytes,
        MaximumLength: len_bytes,
        Buffer: buf.as_ptr() as *mut u16,
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: &mut us,
        Attributes: 0,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    // SAFETY: us/oa/buf are valid locals for the duration of the call.
    unsafe { crate::hooks::classify_device_open(&oa as *const OBJECT_ATTRIBUTES, write) }
}

const DENIED: DeviceVerdict = DeviceVerdict::Deny(STATUS_ACCESS_DENIED);

#[test]
fn check_device_block_denies_unc_write() {
    // P0-03: `\??\UNC\…` (the NT form of `\\localhost\c$\…`) must not
    // pass a write through — it reaches the REAL volume via the network
    // redirector, outside the CoW overlay.
    assert_eq!(
        device_block_for(r"\??\UNC\localhost\c$\Users\Public\evil.exe", true),
        DENIED
    );
    // Raw Win32 UNC spelling classifies the same.
    assert_eq!(
        device_block_for(r"\\localhost\c$\Users\Public\evil.exe", true),
        DENIED
    );
}

#[test]
fn check_device_block_allows_unc_read() {
    // Reads keep the documented pass-through behaviour. `Unhandled`, not
    // `PassThrough`: a UNC read is still a filesystem read and the
    // caller's own logic owns it.
    assert_eq!(
        device_block_for(r"\??\UNC\localhost\c$\Users\Public\evil.exe", false),
        DeviceVerdict::Unhandled
    );
}

#[test]
fn check_device_block_enforces_systemquery_write_deny() {
    // The SystemQuery contract is "read OK, write denied" — CldFlt is the
    // canonical SystemQuery member. Before the P0-03 fix this carried on
    // for writes too.
    assert_eq!(device_block_for(r"\device\cldflt", true), DENIED);
    assert_eq!(device_block_for(r"\device\cldflt", false), DeviceVerdict::Unhandled);
}

#[test]
fn check_device_block_keeps_hard_blocks_and_volume_reads() {
    // Hard blocks deny regardless of direction.
    assert_eq!(device_block_for(r"\device\physicaldrive0", false), DENIED);
    // Ordinary volume reads still pass the device gate.
    assert_eq!(
        device_block_for(r"\device\harddiskvolume2\foo", false),
        DeviceVerdict::Unhandled
    );
}

/// A volume device must NOT become `PassThrough`: the dead-end write deny
/// is exactly what stops `\Device\HarddiskVolumeN\…` writes from reaching
/// the real disk without a `decide()` call.
#[test]
fn volume_device_write_stays_subject_to_dead_end_deny() {
    assert_eq!(
        device_block_for(r"\device\harddiskvolume2\foo", true),
        DeviceVerdict::Unhandled
    );
}

/// Regression: every one of these carries write access and resolves to no
/// DOS path, so the dead-end deny used to refuse it — which took out
/// `CreatePipe`, `child_process.spawn` and every console TTY open, at
/// EVERY guard level including `none`. Observed as
/// `spawnSync ... EPERM` from node with `fs_block_unresolved_write` in the
/// trace. None of these has a filesystem behind it.
#[test]
fn non_filesystem_devices_pass_through_writes() {
    // libuv's own pipe naming, verbatim from the failing trace.
    assert_eq!(
        device_block_for(r"\??\pipe\uv\18446744073709551615-50184", true),
        DeviceVerdict::PassThrough
    );
    assert_eq!(
        device_block_for(r"\Device\NamedPipe\some-ipc-channel", true),
        DeviceVerdict::PassThrough
    );
    // Console: the TTY handles crossterm and libuv open read/write.
    assert_eq!(device_block_for(r"\??\CONOUT$", true), DeviceVerdict::PassThrough);
    assert_eq!(device_block_for(r"\??\CONIN$", true), DeviceVerdict::PassThrough);
    assert_eq!(device_block_for(r"\Device\ConDrv\Output", true), DeviceVerdict::PassThrough);
    // NUL and sockets.
    assert_eq!(device_block_for(r"\??\NUL", true), DeviceVerdict::PassThrough);
    assert_eq!(device_block_for(r"\Device\Afd\Endpoint", true), DeviceVerdict::PassThrough);
}

/// The pass-through above must not reopen the dangerous-pipe hole: those
/// classify as `Unknown` and stay denied in both directions.
#[test]
fn dangerous_pipes_stay_denied_despite_pass_through() {
    assert_eq!(device_block_for(r"\??\pipe\svcctl", true), DENIED);
    assert_eq!(device_block_for(r"\??\pipe\svcctl", false), DENIED);
    assert_eq!(device_block_for(r"\??\pipe\atsvc", true), DENIED);
}

// ── S05 (docs/review-xa-2026-09-20): passthrough pre-open alias probe ──
//
// The testable surface of the S05 hook-side backstop is deliberately PURE:
// `probe_passthrough` (real-filesystem component walk) and
// `aliased_resolution_permits` (verdict mapping). `passthrough_alias_decision`
// is NEVER called here — its UNIT-TEST HAZARD note (detours.rs) explains why:
// its Aliased arm calls the IPC client `decide()`, and the hook's fail-stop
// on consecutive IPC failures TERMINATES this test process. The hook-body
// wiring is pinned textually instead (the last test below), the same
// technique the Mock malformed-decision pins at the top of this file use.

/// S05 fixture root INSIDE the worktree (gitignored target/): real
/// junctions/symlinks/hardlinks must live INSIDE the fixture tree for the
/// probe walk to see them, and %TEMP% sits outside this worktree. Mirrors
/// checks/tests.rs's `s05_fixture_dir`.
fn s05_probe_fixture_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target").join("s05-probe-fixtures")
        .join(format!("{tag}-{}-{nanos}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)))
}

/// Canonical (handle-resolved), prefix-stripped, lowercase form of `p` —
/// the exact normalization `detours::canonical_dos_lower` applies to probe
/// results, reimplemented locally because that helper is private to
/// detours.rs. Assertions compare against this rather than the fixture's
/// string path so they stay valid even if some worktree ancestor were
/// itself a reparse point.
fn s05_canon_lower(p: &std::path::Path) -> String {
    let c = std::fs::canonicalize(p).unwrap().to_string_lossy().into_owned();
    let stripped = if let Some(rest) = c.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = c.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        c
    };
    stripped.to_ascii_lowercase()
}

/// Create an NTFS junction `link` → `target` with the raw Windows APIs.
/// Mirrors checks/tests.rs's `s05_create_junction` helper (copied, not
/// shared, because core/hooks internals are not visible from here).
///
/// S05 (docs/review-xa-2026-09-20): `std::os::windows::fs::junction` is
/// still unstable (the `junction_point` feature on this toolchain), and
/// junctions are the ONE reparse point an unprivileged user can create —
/// the fixtures must use them, not symlinks. This mirrors std's unstable
/// implementation: create-and-open the link directory in one go, then post
/// an IO_REPARSE_TAG_MOUNT_POINT reparse buffer via NtFsControlFile
/// (FSCTL_SET_REPARSE_POINT; winapi's DeviceIoControl wrapper would need
/// the `ioapiset` feature, which is not enabled — NtFsControlFile from the
/// already-enabled ntapi is the same kernel operation).
///
/// Buffer layout/arithmetic matches std's sys::fs::windows
/// `junction_point`: `\??\`-prefixed NT substitute name,
/// ReparseDataLength = 12 + 2·len, empty print name.
fn s05_create_junction(
    target: &std::path::Path,
    link: &std::path::Path,
) -> Result<(), std::io::Error> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    // Create + open the (empty) link directory in one go; backup
    // semantics so the handle is a DIRECTORY handle. POSIX_SEMANTICS is
    // load-bearing: without it NTFS refuses FSCTL_SET_REPARSE_POINT on
    // the freshly created dir with STATUS_NOT_A_REPARSE_POINT
    // (0xC0000103) — probed empirically; std's junction_point passes the
    // same flag combination.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_POSIX_SEMANTICS: u32 = 0x0100_0000;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    let d = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .attributes(FILE_ATTRIBUTE_DIRECTORY)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS)
        .open(link)?;

    // NT-style absolute substitute name: `\??\D:\…` (canonicalize gives
    // the `\\?\`-prefixed form; swap the prefix).
    let canon = std::fs::canonicalize(target)?.to_string_lossy().into_owned();
    let sub: Vec<u16> = format!(r"\??\{}", &canon[4..]).encode_utf16().collect();

    // REPARSE_DATA_BUFFER header + MOUNT_POINT payload as one struct.
    #[repr(C)]
    struct MountPointBuffer {
        reparse_tag: u32,
        reparse_data_length: u16,
        reserved: u16,
        sub_name_offset: u16,
        sub_name_length: u16,
        print_name_offset: u16,
        print_name_length: u16,
        path_buffer: [u16; 1024],
    }
    let data_len = 12 + sub.len() * 2;
    let mut buf = MountPointBuffer {
        // IO_REPARSE_TAG_MOUNT_POINT
        reparse_tag: 0xA000_0003,
        reparse_data_length: data_len as u16,
        reserved: 0,
        sub_name_offset: 0,
        sub_name_length: (sub.len() * 2) as u16,
        print_name_offset: ((sub.len() + 1) * 2) as u16,
        print_name_length: 0,
        path_buffer: [0; 1024],
    };
    buf.path_buffer[..sub.len()].copy_from_slice(&sub);

    let mut iosb: ntapi::ntioapi::IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    // SAFETY: `d` owns a valid open directory handle for the call; `buf`
    // is a fully initialized MountPointBuffer whose declared input size
    // (8-byte REPARSE_DATA_BUFFER header + data_len) fits its real size
    // (16 + 2·1024 bytes); `iosb` is a valid zeroed out-parameter; the
    // null Event/ApcContext/OutputBuffer arguments are the documented
    // synchronous-call form of NtFsControlFile.
    let status = unsafe {
        ntapi::ntioapi::NtFsControlFile(
            d.as_raw_handle() as *mut _,
            std::ptr::null_mut(),
            None,
            std::ptr::null_mut(),
            &mut iosb,
            winapi::um::winioctl::FSCTL_SET_REPARSE_POINT,
            &mut buf as *mut _ as *mut _,
            (data_len + 8) as u32,
            std::ptr::null_mut(),
            0,
        )
    };
    if status < 0 {
        return Err(std::io::Error::other(format!(
            "NtFsControlFile(FSCTL_SET_REPARSE_POINT) failed: 0x{status:08X}"
        )));
    }
    Ok(())
}

#[test]
fn s05_probe_clean_plain_file() {
    let base = s05_probe_fixture_dir("probe-clean");
    let chain = base.join("chain");
    std::fs::create_dir_all(&chain).unwrap();
    let plain = chain.join("plain.txt");
    std::fs::write(&plain, b"x").unwrap();
    // Existing reparse-free dir chain + existing single-link file: the open
    // lands exactly on the decided path.
    assert_eq!(probe_passthrough(&plain.to_string_lossy()), PassthroughProbe::Clean);
    // Create-new path under the honest chain: every EXISTING component is
    // reparse-free and the missing tail resolves through that prefix.
    let created = chain.join("newdir").join("created.txt");
    assert_eq!(probe_passthrough(&created.to_string_lossy()), PassthroughProbe::Clean);

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn s05_delete_probe_allows_unlinking_one_hardlink_name() {
    let base = s05_probe_fixture_dir("probe-delete-hardlink");
    std::fs::create_dir_all(&base).unwrap();
    let original = base.join("original.o");
    let alias = base.join("alias.o");
    std::fs::write(&original, b"object").unwrap();
    std::fs::hard_link(&original, &alias).expect("create NTFS hardlink");

    assert_eq!(
        probe_passthrough(&alias.to_string_lossy()),
        PassthroughProbe::MultiLink
    );
    assert_eq!(
        probe_passthrough_delete(&alias.to_string_lossy()),
        PassthroughProbe::Clean
    );
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn s05_probe_flags_junction_component() {
    let base = s05_probe_fixture_dir("probe-junc");
    let root = base.join("root");
    let outside = base.join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("f.txt"), b"x").unwrap();
    // Junctions need no privilege.
    let link = root.join("link");
    s05_create_junction(&outside, &link).expect("create junction");
    let outside_l = s05_canon_lower(&outside);

    // (a) Final component EXISTS beyond the junction: the kernel would
    // silently open outside\f.txt while policy approved root\link\f.txt.
    match probe_passthrough(&link.join("f.txt").to_string_lossy()) {
        PassthroughProbe::Aliased { resolved } => {
            assert!(
                resolved.starts_with(&outside_l) && resolved.ends_with(r"\f.txt"),
                "resolved must be the junction target's f.txt: resolved={resolved} outside={outside_l}"
            );
        }
        other => panic!("expected Aliased for existing file through junction, got {other:?}"),
    }

    // (b) The junction itself as final component: opening it for a write
    // (e.g. a create inside it) lands on its target.
    match probe_passthrough(&link.to_string_lossy()) {
        PassthroughProbe::Aliased { resolved } => {
            assert_eq!(resolved, outside_l, "the junction must resolve to its target");
        }
        other => panic!("expected Aliased for the junction itself, got {other:?}"),
    }

    // (c) Create-new through the junction: nothing named new\created.txt
    // exists anywhere, so the kernel resolves through the deepest EXISTING
    // ancestor — the junction; the resolved tail is re-appended.
    let created = link.join("new").join("created.txt");
    match probe_passthrough(&created.to_string_lossy()) {
        PassthroughProbe::Aliased { resolved } => {
            assert_eq!(
                resolved,
                format!(r"{outside_l}\new\created.txt"),
                "create-new through the junction must resolve to the junction target + tail"
            );
        }
        other => panic!("expected Aliased for create-new through junction, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn s05_probe_flags_symlink_dir_component() {
    let base = s05_probe_fixture_dir("probe-symdir");
    let root = base.join("root");
    let outside = base.join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let sl = root.join("sl");
    if let Err(e) = std::os::windows::fs::symlink_dir(&outside, &sl) {
        eprintln!(
            "SKIPPED S05 symlink case: symlink_dir failed with {e}; creating \
             directory symlinks requires SeCreateSymbolicLinkPrivilege or \
             Windows Developer Mode"
        );
        let _ = std::fs::remove_dir_all(&base);
        return;
    }
    match probe_passthrough(&sl.join("f.txt").to_string_lossy()) {
        PassthroughProbe::Aliased { resolved } => {
            assert!(
                resolved.starts_with(&s05_canon_lower(&outside)),
                "resolved must sit under the symlink target: resolved={resolved}"
            );
        }
        other => panic!("expected Aliased for a path through a dir symlink, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn s05_probe_flags_symlink_file_final() {
    let base = s05_probe_fixture_dir("probe-symfile");
    let root = base.join("root");
    let outside = base.join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let t = outside.join("t.txt");
    std::fs::write(&t, b"x").unwrap();
    let fl = root.join("fl.txt");
    if let Err(e) = std::os::windows::fs::symlink_file(&t, &fl) {
        eprintln!(
            "SKIPPED S05 symlink case: symlink_file failed with {e}; creating \
             file symlinks requires SeCreateSymbolicLinkPrivilege or \
             Windows Developer Mode"
        );
        let _ = std::fs::remove_dir_all(&base);
        return;
    }
    match probe_passthrough(&fl.to_string_lossy()) {
        PassthroughProbe::Aliased { resolved } => {
            assert_eq!(
                resolved,
                s05_canon_lower(&t),
                "a file symlink as final component must resolve to its target file"
            );
        }
        other => panic!("expected Aliased for a file-symlink final component, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn s05_probe_multilink_hardlink() {
    let base = s05_probe_fixture_dir("probe-hardlink");
    let root = base.join("root");
    let outside = base.join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let shared = outside.join("shared.txt");
    std::fs::write(&shared, b"x").unwrap();
    let hl = root.join("hl.txt");
    std::fs::hard_link(&shared, &hl).unwrap();

    // The aliased name: the path string is honest, the OBJECT is not — one
    // underlying file answers to another name we cannot see.
    assert_eq!(
        probe_passthrough(&hl.to_string_lossy()),
        PassthroughProbe::MultiLink,
        "a hardlinked name must be refused for passthrough writes"
    );

    // The link count is per-OBJECT, not per-name: removing the second name
    // returns the object to single-link, and the SAME path then probes
    // Clean. (This is only a valid Clean assertion while the object truly
    // has one link — hence the remove_file first.)
    std::fs::remove_file(&hl).unwrap();
    assert_eq!(
        probe_passthrough(&shared.to_string_lossy()),
        PassthroughProbe::Clean,
        "the same object under a single name must stay allowed"
    );

    // Directory final component: Clean — dirs are exempt (NTFS cannot
    // hardlink dirs; a dir's link count legitimately exceeds 1 via the
    // children's `..` entries).
    assert_eq!(probe_passthrough(&root.to_string_lossy()), PassthroughProbe::Clean);

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn s05_probe_unverifiable_when_link_count_locked() {
    use std::os::windows::fs::OpenOptionsExt;
    let base = s05_probe_fixture_dir("probe-locked");
    let root = base.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let locked = root.join("locked.txt");
    std::fs::write(&locked, b"x").unwrap();
    // Exclusive handle: while held, NO other open of the object succeeds.
    let guard = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&locked)
        .expect("open with exclusive sharing");
    // The probe's own link-count open hits the sharing violation → None →
    // fail closed (Unverifiable), never a silent passthrough.
    assert_eq!(
        probe_passthrough(&locked.to_string_lossy()),
        PassthroughProbe::Unverifiable,
        "an unprovable link count must fail closed"
    );
    drop(guard);

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn s05_aliased_resolution_permits_pins() {
    // Only a fresh Passthrough verdict for the RESOLVED destination
    // authorizes the traversal; every other mode means the write would land
    // somewhere policy does not passthrough-authorize → refuse.
    assert!(aliased_resolution_permits(Mode::Passthrough));
    assert!(!aliased_resolution_permits(Mode::Cow));
    assert!(!aliased_resolution_permits(Mode::Deny));
    assert!(!aliased_resolution_permits(Mode::Mock));
    assert!(!aliased_resolution_permits(Mode::Hidden));
}

/// The S05 slice of the Passthrough match arm (same scraping style as
/// `mock_arm` above): from the arm start to the next `Mode::Deny` arm.
fn s05_passthrough_arm(body: &str) -> String {
    let start = body
        .find("Mode::Passthrough => {")
        .expect("Mode::Passthrough arm must exist");
    let rest = &body[start..];
    let end = rest.find("Mode::Deny").unwrap_or(rest.len());
    rest[..end].to_string()
}

/// S05 (docs/review-xa-2026-09-20): the pre-open alias probe must stay
/// wired into BOTH write-capable hook bodies' Mode::Passthrough arms,
/// ahead of the original-syscall call. The detour bodies themselves cannot
/// be invoked in unit tests (they need a live ntdll detour and, for the
/// probe's Aliased arm, a pipe server), so — guarding the same fail-closed
/// wiring the Mock pins at the top of this file protect — the invariant is
/// pinned textually via module_source.
#[test]
fn s05_passthrough_probe_wired_into_both_hook_bodies() {
    let src = &crate::hooks::module_source("fs_hooks");
    for (sig, tag) in [
        ("fn hook_nt_create_file", "create"),
        ("fn hook_nt_open_file", "open"),
    ] {
        let body = fn_body(src, sig);
        assert!(
            body.contains("passthrough_alias_decision(&dos, write)"),
            "{tag}: hook body must consult the S05 pre-open alias probe"
        );
        let arm = s05_passthrough_arm(&body);
        assert!(
            arm.contains("passthrough_alias_decision(&dos, write)"),
            "{tag}: the probe call must live INSIDE the Mode::Passthrough arm (before copy_passthrough_inner)"
        );
        assert!(
            arm.contains("is_delete_only_access(desired_access"),
            "{tag}: delete-only opens must use the no-hardlink-count probe"
        );
        assert!(
            arm.contains("passthrough_delete_alias_decision(&dos)"),
            "{tag}: delete-only opens must still check reparse traversal"
        );
        assert!(
            arm.contains("STATUS_ACCESS_DENIED"),
            "{tag}: a flagged passthrough open must fail closed (ACCESS_DENIED)"
        );
    }
}

// ── C04 (docs/review-xa-2026-09-20): stale cached Cow + publish ordering ──

#[test]
fn overlay_target_missing_matches_physical_state() {
    // Real-FS fixture: the probe must consult the LIVE filesystem, not just
    // the decision, so the overlay paths are created/left-missing for real.
    let base = std::env::temp_dir().join(format!(
        "winrsbox_c04_overlay_probe_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&base).unwrap();
    let present = base.join("overlay_present.bin");
    std::fs::write(&present, b"cow-copy").unwrap();
    let missing = base.join("overlay_absent.bin");

    // Overlay copy exists on disk → not missing.
    let d = Decision {
        mode: Mode::Cow,
        overlay: Some(present.clone()),
        cow_from: None,
        mock_payload: None,
    };
    assert!(!overlay_target_missing(&d));

    // Same decision shape, but the overlay copy is gone (a sibling deleted
    // it and recorded a whiteout) → missing.
    let d = Decision {
        mode: Mode::Cow,
        overlay: Some(missing.clone()),
        cow_from: None,
        mock_payload: None,
    };
    assert!(overlay_target_missing(&d));

    // No overlay target at all → nothing to be missing (Cow-without-overlay
    // is the fail-closed `prepare_overlay` case, not a staleness signal).
    let d = Decision { mode: Mode::Cow, overlay: None, cow_from: None, mock_payload: None };
    assert!(!overlay_target_missing(&d));

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn cow_publish_allowed_gates_on_ntsuccess() {
    // NT_SUCCESS is a non-negative NTSTATUS.
    assert!(cow_publish_allowed(0)); // STATUS_SUCCESS
    assert!(!cow_publish_allowed(STATUS_ACCESS_DENIED)); // 0xC000_0022 as i32
    let reparse: i32 = 0xC000_0274_u32 as i32;
    assert!(!cow_publish_allowed(reparse)); // STATUS_REPARSE_POINT_ENCOUNTERED
}

/// PERF-cow: publication is once-per-transition per process. The FIRST
/// publish must still invalidate the local decision cache (C04 semantics
/// unchanged); a redundant re-publish of an already-published path must skip
/// BOTH the IPC writes and the invalidation (the cache stays warm); and
/// `overlay_publish_forget` — the re-arm for any index/physical divergence —
/// must make the next publish invalidate again. Runs against the real global
/// `cache()` singleton (OnceLock, cannot be reset): the pid+nanos path makes
/// cross-test interference impossible (no other test touches cache()).
#[test]
fn publish_overlay_decision_skips_redundant_republish() {
    let p = std::env::temp_dir()
        .join(format!(
            "winrsbox_perf_cow_publish_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
        .to_string_lossy()
        .to_ascii_lowercase();
    // Dummy overlay target: publish performs no FS access, so the string
    // never has to exist on disk.
    let overlay = format!("{p}_overlay_copy.bin");
    let sentinel = Decision {
        mode: Mode::Cow,
        overlay: Some(std::path::PathBuf::from(&overlay)),
        cow_from: None,
        mock_payload: None,
    };

    // Phase 1 — first publish: both records are delivered (in tests the pipe
    // is simply not configured, which the IPC client treats as delivered),
    // so the path is marked AND the sentinel is still invalidated.
    cache().insert(&p, false, sentinel.clone());
    cache().insert(&p, true, sentinel.clone());
    publish_overlay_decision(&p, &overlay, &Some("Name.TXT".to_string()));
    assert!(
        cache().get_caseless(&p, false).is_none()
            && cache().get_caseless(&p, true).is_none(),
        "the first publish must invalidate the cached decision (C04 semantics unchanged)"
    );

    // Phase 2 — redundant re-publish: the skip ran (no IPC writes, no
    // invalidation), so both re-seeded entries survive.
    cache().insert(&p, false, sentinel.clone());
    cache().insert(&p, true, sentinel.clone());
    publish_overlay_decision(&p, &overlay, &Some("Name.TXT".to_string()));
    assert!(
        cache().get_caseless(&p, false).is_some()
            && cache().get_caseless(&p, true).is_some(),
        "a re-publish of an already-published path must leave the decision cache warm"
    );

    // Phase 3 — divergence: forgetting the marker re-arms publication, so
    // the next publish invalidates again.
    overlay_publish_forget(&p);
    cache().insert(&p, false, sentinel.clone());
    cache().insert(&p, true, sentinel);
    publish_overlay_decision(&p, &overlay, &Some("Name.TXT".to_string()));
    assert!(
        cache().get_caseless(&p, false).is_none()
            && cache().get_caseless(&p, true).is_none(),
        "after overlay_publish_forget the next publish must invalidate again"
    );
}

/// C04 (docs/review-xa-2026-09-20): the detour bodies cannot run without a
/// live ntdll detour, so the publish-ordering invariant is pinned textually
/// (same technique as the Mock/S05 pins above):
///  (i)   the publish is gated on `cow_publish_allowed(status)` and goes
///        through `publish_overlay_decision`;
///  (ii)  the gated publish sits AFTER the redirected kernel open;
///  (iii) the hook body no longer calls `ipc_record_overlay(` directly;
///  (iv)  the stale-Cow re-check runs BEFORE the mode dispatch;
///  (v)   the failed-open else branch evicts the cached Cow that produced
///        the redirect;
///  (vi)  the failed-open else branch also re-arms PERF-cow publication
///        (`overlay_publish_forget`) so the next success re-publishes.
fn assert_c04_publish_ordering(body: &str, tag: &str, recheck: &str) {
    let gate = body
        .find("if cow_publish_allowed(status) {")
        .unwrap_or_else(|| panic!("{tag}: cow publish gate missing"));
    let publish = body
        .find("publish_overlay_decision(&lower, &overlay_dos, &original_basename)")
        .unwrap_or_else(|| panic!("{tag}: publish_overlay_decision call missing"));
    let open = body
        .find("let status = nt_call_original!(")
        .unwrap_or_else(|| panic!("{tag}: redirected kernel open missing"));
    assert!(
        open < gate && gate < publish,
        "{tag}: the overlay index must be published AFTER the redirected kernel open, not before"
    );
    assert!(
        !body.contains("ipc_record_overlay("),
        "{tag}: index publication must go through publish_overlay_decision, not a direct ipc_record_overlay call"
    );
    let recheck_pos = body
        .find(recheck)
        .unwrap_or_else(|| panic!("{tag}: decide_fresh_if_overlay_missing re-check missing"));
    let dispatch = body
        .find("match decision.mode")
        .unwrap_or_else(|| panic!("{tag}: mode dispatch missing"));
    assert!(
        recheck_pos < dispatch,
        "{tag}: the stale-Cow re-check must run BEFORE the mode dispatch"
    );
    let gate_else = body[gate..]
        .find("} else {")
        .map(|off| gate + off)
        .unwrap_or_else(|| panic!("{tag}: publish gate must have an else branch"));
    body[gate_else..]
        .find("cache().invalidate(&lower);")
        .unwrap_or_else(|| {
            panic!("{tag}: a failed open must invalidate the cached Cow in the else branch")
        });
    body[gate_else..]
        .find("overlay_publish_forget(&lower);")
        .unwrap_or_else(|| {
            panic!("{tag}: a failed open must re-arm overlay publication in the else branch")
        });
}

#[test]
fn cow_index_published_only_after_successful_kernel_open() {
    let src = &crate::hooks::module_source("fs_hooks");
    let body = fn_body(src, "fn hook_nt_create_file");
    assert_c04_publish_ordering(&body, "create", "decide_fresh_if_overlay_missing(&decision, &dos, write)");
}

#[test]
fn cow_open_index_published_only_after_successful_kernel_open() {
    let src = &crate::hooks::module_source("fs_hooks");
    let body = fn_body(src, "fn hook_nt_open_file");
    assert_c04_publish_ordering(&body, "open", "decide_fresh_if_overlay_missing(&decision, &dos, write)");
}

/// PERF-cow: publication must happen at most once per transition. Pinned
/// textually (same technique as `assert_c04_publish_ordering` above):
///  (i)   the already-published skip precedes ANY IPC write inside
///        `publish_overlay_decision`;
///  (ii)  the stale-overlay re-decide re-arms publication;
///  (iii) both hook bodies re-arm publication on the failed-open path.
#[test]
fn publish_overlay_decision_writes_index_once_per_transition() {
    let src = &crate::hooks::module_source("fs_hooks");
    let body = fn_body(src, "fn publish_overlay_decision");
    let skip = body
        .find("overlay_already_published(lower)")
        .unwrap_or_else(|| panic!("publish skip check missing"));
    let ipc = body
        .find("ipc_record_overlay(")
        .unwrap_or_else(|| panic!("index publication missing"));
    assert!(
        skip < ipc,
        "the already-published skip must precede any IPC write in publish_overlay_decision"
    );
    let fresh = fn_body(src, "fn decide_fresh_if_overlay_missing");
    assert!(
        fresh.contains("overlay_publish_forget"),
        "the stale-overlay re-decide must re-arm overlay publication"
    );
    for (sig, tag) in [
        ("fn hook_nt_create_file", "create"),
        ("fn hook_nt_open_file", "open"),
    ] {
        let hook_body = fn_body(src, sig);
        assert!(
            hook_body.contains("overlay_publish_forget(&lower);"),
            "{tag}: the failed-open path must re-arm overlay publication"
        );
    }
}

/// C04: both read-only query hooks must re-decide a cached Cow whose overlay
/// target vanished BEFORE the Cow fall-through branch, so a whiteouted path
/// surfaces Hidden→NOT_FOUND here too while a genuinely-not-yet-copied Cow
/// keeps the stat-then-open-friendly passthrough.
#[test]
fn query_hooks_recheck_stale_cow_before_fallback() {
    let src = &crate::hooks::module_source("fs_hooks");
    for (sig, tag) in [
        ("fn hook_nt_query_attributes_file", "query_attributes"),
        ("fn hook_nt_query_full_attributes_file", "query_full"),
    ] {
        let body = fn_body(src, sig);
        let recheck = body
            .find("decide_fresh_if_overlay_missing(&decision, &dos, false)")
            .unwrap_or_else(|| panic!("{tag}: stale-Cow re-check missing"));
        let cow_fallthrough = body
            .find("Mode::Cow => {")
            .unwrap_or_else(|| panic!("{tag}: Mode::Cow arm missing"));
        assert!(
            recheck < cow_fallthrough,
            "{tag}: the fresh re-check must run BEFORE the Cow fall-through branch"
        );
    }
}
