use super::*;

/// Both legacy hooks must return STATUS_ACCESS_DENIED for any input —
/// including null pointers and zero scalar args — without dereferencing
/// anything. This is the contract that makes "unconditional deny" safe:
/// no params are inspected before the early-return.
#[test]
fn legacy_process_creation_denied() {
    let expected = STATUS_ACCESS_DENIED;

    let s1 = unsafe {
        hook_nt_create_process(
            std::ptr::null_mut(), // ProcessHandle
            0,                    // DesiredAccess
            std::ptr::null(),     // ObjectAttributes
            std::ptr::null_mut(), // ParentProcess
            0,                    // InheritObjectTable
            std::ptr::null_mut(), // SectionHandle
            std::ptr::null_mut(), // DebugPort
            std::ptr::null_mut(), // ExceptionPort
        )
    };
    assert_eq!(s1, expected, "NtCreateProcess must deny null-arg call");

    let s2 = unsafe {
        hook_nt_create_process_ex(
            std::ptr::null_mut(), // ProcessHandle
            0,                    // DesiredAccess
            std::ptr::null(),     // ObjectAttributes
            std::ptr::null_mut(), // ParentProcess
            0,                    // Flags
            std::ptr::null_mut(), // SectionHandle
            std::ptr::null_mut(), // DebugPort
            std::ptr::null_mut(), // ExceptionPort
            0,                    // InJob
        )
    };
    assert_eq!(s2, expected, "NtCreateProcessEx must deny null-arg call");
}

// -----------------------------------------------------------------------
// PID-reuse poisoning regression (P1-2 / T3)
// -----------------------------------------------------------------------
//
// Hook 5 (NtTerminateProcess → process_tracker::untrack) defends against:
//   1. our child dies → OS reuses its PID for a foreign process →
//   2. attacker calls into the foreign PID using PROCESS_VM_OPERATION etc.
//      → would succeed if `is_owned_child(reused_pid)` still returned true.
// These tests pin the untrack contract directly (decoupled from the
// OpenProcess→GetProcessId resolution chain).

#[test]
fn pid_reuse_after_terminate_does_not_lie() {
    let fake_pid = 999_999u32;
    // create_time 0 → membership-only: this test pins the untrack contract
    // for a non-live PID, decoupled from the live fingerprint re-query.
    crate::process_tracker::mark_spawned(fake_pid, 1, "fake_child.exe".into(), 0);
    assert!(crate::process_tracker::is_owned_child(fake_pid));

    // Simulate the untrack path the NtTerminateProcess hook would take.
    crate::process_tracker::untrack(fake_pid);
    assert!(
        !crate::process_tracker::is_owned_child(fake_pid),
        "after untrack, the PID must not look owned even if OS reuses it for a foreign process"
    );
}

#[test]
fn untracked_pid_treated_as_foreign() {
    let pid = 999_998u32;
    // PID was never marked → must read as foreign.
    assert!(!crate::process_tracker::is_owned_child(pid));
}

// -----------------------------------------------------------------------
// PS_ATTRIBUTE_LIST edge tests (M-T3)
// -----------------------------------------------------------------------
//
// The functions read `TotalLength` from the first usize of the buffer.
// The bounds expression `(total - size_of::<usize>()) / size_of::<PS_ATTRIBUTE>()`
// must not underflow on small `total` values.
//
// We can't pass a zero-length buffer (reading `TotalLength` itself would
// be UB), so for the "tiny total" cases we allocate a buffer at least
// size_of::<usize>() bytes and ENCODE the total value into the header.
//
// For the truly empty case we pass a null pointer (caller contract:
// null → early return false).

fn make_attr_buf(total_length: usize) -> Vec<u8> {
    // Always allocate at least one usize so reading TotalLength is sound.
    let mut buf = vec![0u8; std::mem::size_of::<usize>()];
    let bytes = total_length.to_ne_bytes();
    buf[..bytes.len()].copy_from_slice(&bytes);
    buf
}

#[test]
fn attr_list_null_pointer_is_safe() {
    assert!(!attribute_list_contains_parent_process(std::ptr::null()));
    assert!(!attribute_list_contains_handle_list(std::ptr::null()));
}

#[test]
fn attr_list_tiny_total_is_safe() {
    // total = 0 — header claims zero size; must not underflow / index.
    let buf = make_attr_buf(0);
    assert!(!attribute_list_contains_parent_process(buf.as_ptr() as _));
    assert!(!attribute_list_contains_handle_list(buf.as_ptr() as _));
}

#[test]
fn attr_list_total_below_header_is_safe() {
    // total = 4 < size_of::<usize>() (8 on x64) — must not underflow.
    let buf = make_attr_buf(4);
    assert!(!attribute_list_contains_parent_process(buf.as_ptr() as _));
    assert!(!attribute_list_contains_handle_list(buf.as_ptr() as _));
}

#[test]
fn attr_list_only_header_no_attrs() {
    // total = size_of::<usize>() — exactly the header, zero entries.
    // (total - header) / sizeof::<PS_ATTRIBUTE>() must == 0, so the
    // attr_count == 0 short-circuit fires.
    let buf = make_attr_buf(std::mem::size_of::<usize>());
    assert!(!attribute_list_contains_parent_process(buf.as_ptr() as _));
    assert!(!attribute_list_contains_handle_list(buf.as_ptr() as _));
}

#[test]
fn attr_list_parent_with_value_zero_is_not_a_match() {
    // A well-formed PARENT attribute (number=0) but with Value=0 must
    // not be reported as parent-spoof — Value is the PID handle and
    // a null handle is not a spoof.
    let header_size = std::mem::size_of::<usize>();
    let attr_size = std::mem::size_of::<PS_ATTRIBUTE>();
    let total = header_size + attr_size;
    let mut buf = vec![0u8; total];
    // TotalLength
    buf[..header_size].copy_from_slice(&total.to_ne_bytes());
    // PS_ATTRIBUTE { Attribute: 0 (parent), Size: 8, Value: 0, ReturnLength: null }
    // All zero by default — only Size needs setting, and Attribute=0 is parent.
    // Attribute = 0 (number 0 = parent, no INPUT flag — still matches by lower 16 bits).
    // The function checks `(Attribute & 0xFFFF) == 0 && Value != 0`.
    // With Value=0, must return false.
    assert!(!attribute_list_contains_parent_process(buf.as_ptr() as _));
}

#[test]
fn attr_list_with_both_parent_and_handle_list_detects_both() {
    // Two attributes: PARENT (number=0, Value=fake_pid_handle) and
    // HANDLE_LIST (number=2). Both detector functions must report true.
    let header_size = std::mem::size_of::<usize>();
    let attr_size = std::mem::size_of::<PS_ATTRIBUTE>();
    let total = header_size + attr_size * 2;
    let mut buf = vec![0u8; total];
    // TotalLength
    buf[..header_size].copy_from_slice(&total.to_ne_bytes());
    // Build two PS_ATTRIBUTE entries in place.
    let attrs_ptr = unsafe { buf.as_mut_ptr().add(header_size) } as *mut PS_ATTRIBUTE;
    unsafe {
        // [0] PARENT — number=0, Value=non-zero
        (*attrs_ptr.add(0)).Attribute = 0x0002_0000; // PsAttributeParentProcess | INPUT
        (*attrs_ptr.add(0)).Size = std::mem::size_of::<usize>();
        (*attrs_ptr.add(0)).Value = 0xDEAD_BEEF;
        (*attrs_ptr.add(0)).ReturnLength = std::ptr::null_mut();
        // [1] HANDLE_LIST — number=2
        (*attrs_ptr.add(1)).Attribute = 0x0002_0002; // PsAttributeHandleList | INPUT
        (*attrs_ptr.add(1)).Size = std::mem::size_of::<usize>();
        (*attrs_ptr.add(1)).Value = 0xCAFE_BABE;
        (*attrs_ptr.add(1)).ReturnLength = std::ptr::null_mut();
    }
    assert!(attribute_list_contains_parent_process(buf.as_ptr() as _));
    assert!(attribute_list_contains_handle_list(buf.as_ptr() as _));
}

// -----------------------------------------------------------------------
// C1 — image_name_attr_mut (PsAttributeImageName record = number 5)
// -----------------------------------------------------------------------

/// Build a synthetic PS_ATTRIBUTE_LIST with the given records (Attribute,
/// Size, Value) and return its backing buffer. Records are laid out after
/// the TotalLength header, and TotalLength is set to header + N*attr_size.
fn make_attr_list_with(records: &[(usize, usize, usize)]) -> Vec<u8> {
    let header_size = std::mem::size_of::<usize>();
    let attr_size = std::mem::size_of::<PS_ATTRIBUTE>();
    let total = header_size + attr_size * records.len();
    let mut buf = vec![0u8; total];
    buf[..header_size].copy_from_slice(&total.to_ne_bytes());
    let attrs_ptr = unsafe { buf.as_mut_ptr().add(header_size) } as *mut PS_ATTRIBUTE;
    unsafe {
        for (i, &(attr, size, value)) in records.iter().enumerate() {
            (*attrs_ptr.add(i)).Attribute = attr;
            (*attrs_ptr.add(i)).Size = size;
            (*attrs_ptr.add(i)).Value = value;
            (*attrs_ptr.add(i)).ReturnLength = std::ptr::null_mut();
        }
    }
    buf
}

#[test]
fn image_name_attr_finds_record_5() {
    // [0] IMAGE_NAME (number=5), Value points at a fake NT path.
    let buf = make_attr_list_with(&[(0x0002_0005, 10, 0xAAAA_BBBB)]);
    let ptr = buf.as_ptr() as *mut c_void;
    // SAFETY: buf is a valid, correctly-sized PS_ATTRIBUTE_LIST.
    let found = unsafe { image_name_attr_mut(ptr) };
    let found = found.expect("record 5 must be found");
    unsafe {
        assert_eq!((*found).Attribute & 0xFFFF, 5);
        assert_eq!((*found).Value, 0xAAAA_BBBB);
    }
}

#[test]
fn image_name_attr_skips_other_records() {
    // PARENT (0) + HANDLE_LIST (2), no IMAGE_NAME (5) → None.
    let buf = make_attr_list_with(&[
        (0x0002_0000, std::mem::size_of::<usize>(), 0x1000),
        (0x0002_0002, std::mem::size_of::<usize>(), 0x2000),
    ]);
    let ptr = buf.as_ptr() as *mut c_void;
    let found = unsafe { image_name_attr_mut(ptr) };
    assert!(found.is_none(), "no record 5 → None");
}

#[test]
fn image_name_attr_finds_record_5_among_many() {
    // IMAGE_NAME (5) is the 3rd entry; must skip the first two.
    let buf = make_attr_list_with(&[
        (0x0002_0000, 8, 0x1),
        (0x0002_0002, 8, 0x2),
        (0x0002_0005, 12, 0x3),
        (0x0002_0006, 8, 0x4),
    ]);
    let ptr = buf.as_ptr() as *mut c_void;
    let found = unsafe { image_name_attr_mut(ptr) }.expect("record 5 present");
    unsafe { assert_eq!((*found).Value, 0x3); }
}

#[test]
fn image_name_attr_null_safe() {
    assert!(unsafe { image_name_attr_mut(std::ptr::null_mut()) }.is_none());
}

#[test]
fn image_name_attr_malformed_total_safe() {
    // total below header → None, no underflow.
    let buf = make_attr_buf(4);
    assert!(unsafe { image_name_attr_mut(buf.as_ptr() as *mut c_void) }.is_none());
}

#[test]
fn image_name_attr_is_mutable_and_restorable() {
    // Mutate Value/Size through the returned pointer, then restore — this
    // is exactly the C2 guard's patch_attr flow.
    let mut buf = make_attr_list_with(&[(0x0002_0005, 10, 0x1111)]);
    let ptr = buf.as_mut_ptr() as *mut c_void;
    let attr = unsafe { image_name_attr_mut(ptr) }.unwrap();
    unsafe {
        let orig_value = (*attr).Value;
        let orig_size = (*attr).Size;
        (*attr).Value = 0x2222;
        (*attr).Size = 99;
        assert_eq!((*attr).Value, 0x2222);
        assert_eq!((*attr).Size, 99);
        // restore
        (*attr).Value = orig_value;
        (*attr).Size = orig_size;
        assert_eq!((*attr).Value, 0x1111);
        assert_eq!((*attr).Size, 10);
    }
}

// -----------------------------------------------------------------------
// M3 — content-based denylist (OriginalFilename) classification
// -----------------------------------------------------------------------

#[test]
fn denylist_matches_basename() {
    // Existing behavior preserved: a denylisted basename is blocked,
    // regardless of OriginalFilename.
    assert!(is_denylisted("C:\\Windows\\System32\\wsl.exe"));
    assert!(is_denylisted("c:/windows/system32/WSL.EXE")); // case + slash
    assert!(is_denylisted("rundll32.exe"));
    assert!(!is_denylisted("C:\\Windows\\System32\\notepad.exe"));
}

#[test]
fn denied_by_names_basename_only() {
    // Pure helper: basename hit, no original filename.
    assert!(is_denied_by_names("wsl.exe", None));
    assert!(is_denied_by_names("WSL.EXE", None)); // case-insensitive
    assert!(!is_denied_by_names("foo.exe", None));
    // Original present but also clean → not denied.
    assert!(!is_denied_by_names("foo.exe", Some("notepad.exe")));
}

#[test]
fn denylist_matches_original_filename_when_renamed() {
    // The copy-rename bypass: on-disk name is innocuous, but the PE's
    // OriginalFilename still reports the denylisted name. Must be blocked.
    assert!(is_denied_by_names("foo.exe", Some("wsl.exe")));
    assert!(is_denied_by_names("totally_legit.exe", Some("WSL.EXE")));
    // Neither name denylisted → allowed.
    assert!(!is_denied_by_names("a.exe", Some("b.exe")));
    // `bash.exe` is intentionally NOT in the basename denylist — the
    // path-locked check `is_path_locked_wsl_bash` covers the WSL stub
    // location while leaving Git Bash alone. So a renamed-from-bash.exe
    // is allowed by name; the path check is what catches the WSL case.
    assert!(!is_denied_by_names("a.exe", Some("bash.exe")));
}

// -- is_path_locked_wsl_bash ------------------------------------------------
//
// Regression coverage for the Git-Bash false-positive: we removed
// `bash.exe` from the basename denylist (it collided with Git's MinGW
// bash at `\Program Files\Git\…`), and re-added the legacy WSL stub
// coverage as a PATH-locked rule. These tests pin both halves of that
// contract.

#[test]
fn wsl_bash_at_system32_is_denied() {
    assert!(is_path_locked_wsl_bash(r"C:\Windows\System32\bash.exe"));
    // Case + slash variants.
    assert!(is_path_locked_wsl_bash(r"c:\windows\system32\BASH.EXE"));
    assert!(is_path_locked_wsl_bash(r"c:/windows/system32/bash.exe"));
}

#[test]
fn wsl_bash_at_sysnative_redirector_is_denied() {
    // 32-bit processes see the 64-bit System32 via `\Sysnative\`.
    // Cover that path so a 32-bit attacker spawn doesn't slip through.
    assert!(is_path_locked_wsl_bash(r"C:\Windows\Sysnative\bash.exe"));
}

#[test]
fn wsl_store_app_bash_is_denied() {
    // Modern WSL ships as an MSIX in `\WindowsApps\…`. The exact
    // package directory varies across builds — the predicate matches
    // any path under WindowsApps.
    assert!(is_path_locked_wsl_bash(
        r"C:\Program Files\WindowsApps\MicrosoftCorporationII.WindowsSubsystemForLinux_2.2.4.0_x64__8wekyb3d8bbwe\bash.exe"
    ));
}

#[test]
fn git_bash_is_allowed() {
    // The whole point of the fix: Git Bash at the default install
    // location must NOT be flagged as WSL.
    assert!(!is_path_locked_wsl_bash(r"C:\Program Files\Git\bin\bash.exe"));
    assert!(!is_path_locked_wsl_bash(r"C:\Program Files\Git\usr\bin\bash.exe"));
    // 32-bit Git, or per-user install in AppData.
    assert!(!is_path_locked_wsl_bash(r"C:\Program Files (x86)\Git\bin\bash.exe"));
    assert!(!is_path_locked_wsl_bash(
        r"C:\Users\alice\AppData\Local\Programs\Git\bin\bash.exe"
    ));
}

#[test]
fn msys_and_cygwin_bash_are_allowed() {
    assert!(!is_path_locked_wsl_bash(r"C:\msys64\usr\bin\bash.exe"));
    assert!(!is_path_locked_wsl_bash(r"C:\cygwin64\bin\bash.exe"));
}

#[test]
fn non_bash_exe_is_not_flagged() {
    // Predicate is for `bash.exe` only; other executables anywhere on
    // the system are out of its scope.
    assert!(!is_path_locked_wsl_bash(r"C:\Windows\System32\notepad.exe"));
    assert!(!is_path_locked_wsl_bash(r"C:\Windows\System32\bashlike.exe"));
    // Bare bash without the .exe extension — kernel never opens the
    // image like this on Windows, but defensively reject.
    assert!(!is_path_locked_wsl_bash(r"C:\Windows\System32\bash"));
}

#[test]
fn is_denylisted_combines_name_and_path_checks() {
    // The umbrella entrypoint MUST catch both:
    // (a) the basename-deny set (e.g. wsl.exe anywhere)
    assert!(is_denylisted(r"C:\Windows\System32\wsl.exe"));
    // (b) the path-locked WSL-bash stub
    assert!(is_denylisted(r"C:\Windows\System32\bash.exe"));
    // …without dragging Git Bash into either.
    assert!(!is_denylisted(r"C:\Program Files\Git\bin\bash.exe"));
    assert!(!is_denylisted(r"C:\Program Files\Git\usr\bin\bash.exe"));
}

#[test]
fn original_filename_of_self_does_not_panic() {
    // Read the running test exe's own version info. A test binary usually
    // has no VERSIONINFO resource, so None is the expected (and acceptable)
    // result — the contract is simply that this must not panic / UB.
    let exe = std::env::current_exe().expect("current_exe");
    let exe_str = exe.to_string_lossy().to_string();
    let result = original_filename(&exe_str);
    // Whatever it returns, a present value must be non-empty.
    if let Some(name) = result {
        assert!(!name.is_empty(), "OriginalFilename, if present, is non-empty");
    }
}

#[test]
fn original_filename_missing_file_is_none() {
    // Unreadable / nonexistent path → graceful None (fall back to basename).
    assert_eq!(
        original_filename("Z:\\no\\such\\path\\definitely-missing-xyz.exe"),
        None
    );
    // Empty path → None, no panic.
    assert_eq!(original_filename(""), None);
}

#[test]
fn original_filename_of_system_binary_when_available() {
    // Best-effort end-to-end: a real signed system binary normally carries
    // an OriginalFilename in its version resource. We do not hard-assert the
    // exact value (it varies across Windows builds / SKUs and the file may
    // be unreadable in some CI sandboxes); we only assert that IF we read a
    // value, it is sane. This documents the live behavior without making the
    // test flaky.
    let candidates = [
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\System32\\cmd.exe",
    ];
    for path in candidates {
        if let Some(name) = original_filename(path) {
            assert!(!name.is_empty());
            assert!(
                name.to_lowercase().ends_with(".exe")
                    || !name.contains('\\'),
                "OriginalFilename should be a bare file name, got {name:?}"
            );
        }
    }
}

// ── M4: MAXIMUM_ALLOWED / GENERIC_ALL mask coverage ─────────────────────

#[test]
fn dangerous_access_includes_maximum_allowed() {
    assert_ne!(DANGEROUS_ACCESS & 0x0200_0000, 0, "MAXIMUM_ALLOWED must be in DANGEROUS_ACCESS");
}

#[test]
fn dangerous_access_includes_generic_all() {
    assert_ne!(DANGEROUS_ACCESS & 0x1000_0000, 0, "GENERIC_ALL must be in DANGEROUS_ACCESS");
}

#[test]
fn dangerous_access_still_includes_specific_bits() {
    assert_ne!(DANGEROUS_ACCESS & 0x0002, 0, "PROCESS_CREATE_THREAD");
    assert_ne!(DANGEROUS_ACCESS & 0x0020, 0, "PROCESS_VM_WRITE");
    assert_ne!(DANGEROUS_ACCESS & 0x0040, 0, "PROCESS_DUP_HANDLE");
}

// -----------------------------------------------------------------------
// Attr-5 spawn veto + hostile-length clamping (audit 2026-09-19)
// -----------------------------------------------------------------------
//
// HIGH: the kernel loads the image named by PsAttributeImageName (attr 5),
// not RTL_USER_PROCESS_PARAMETERS.ImagePathName — the denylist veto must
// see attribute 5, else a decoyed ImagePathName lets a denylisted binary
// run.
// MEDIUM: TotalLength / attribute Size / UNICODE_STRING.Length are
// caller-controlled and must be clamped to the readable region before they
// are followed. Tests use guard-paged allocations so an unclamped walk
// faults deterministically instead of reading adjacent heap noise.

const PAGE_SIZE: usize = 0x1000;

/// Two-page allocation: page 0 committed PAGE_READWRITE, page 1 left as
/// PAGE_NOACCESS guard. Never freed — the test process exits first.
fn alloc_two_pages_first_committed() -> *mut u8 {
    use winapi::um::memoryapi::VirtualAlloc;
    use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE};
    // SAFETY: plain VirtualAlloc reserve; failure checked below.
    let base = unsafe {
        VirtualAlloc(std::ptr::null_mut(), 2 * PAGE_SIZE, MEM_RESERVE, PAGE_NOACCESS)
    };
    assert!(!base.is_null(), "VirtualAlloc(MEM_RESERVE) failed");
    // SAFETY: commits page 0 of the reservation made above.
    let committed =
        unsafe { VirtualAlloc(base, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE) };
    assert!(!committed.is_null(), "VirtualAlloc(MEM_COMMIT) failed");
    assert_eq!(committed as usize, base as usize, "commit must land at reservation base");
    base as *mut u8
}

/// PS_ATTRIBUTE_LIST with one PsAttributeImageName (number 5) record
/// pointing at `path` (PWSTR + Size in bytes, excluding the trailing
/// NUL — the C0-confirmed kernel convention). Returns the list buffer
/// and the wide-string backing store; caller must keep both alive.
fn make_image_name_list(path: &str) -> (Vec<u8>, Vec<u16>) {
    let mut wide: Vec<u16> = path.encode_utf16().collect();
    wide.push(0);
    let size_bytes = (wide.len() - 1) * 2;
    let buf = make_attr_list_with(&[(0x0002_0005, size_bytes, wide.as_ptr() as usize)]);
    (buf, wide)
}

/// Minimal caller-shaped RTL_USER_PROCESS_PARAMETERS: a 0x100-byte block
/// with UNICODE_STRING {Length, MaximumLength, Buffer} at offset 0x60
/// pointing at `path` (NUL-terminated UTF-16; Length excludes the NUL).
/// Returns (block, wide); caller must keep both alive.
fn make_params_with_image_path(path: &str) -> (Vec<u8>, Vec<u16>) {
    let mut wide: Vec<u16> = path.encode_utf16().collect();
    wide.push(0);
    let mut block = vec![0u8; 0x100];
    let ustr_offset = 0x60usize;
    let len_excl_nul = ((wide.len() - 1) * 2) as u16;
    let len_incl_nul = (wide.len() * 2) as u16;
    block[ustr_offset..ustr_offset + 2]
        .copy_from_slice(&len_excl_nul.to_ne_bytes());
    block[ustr_offset + 2..ustr_offset + 4]
        .copy_from_slice(&len_incl_nul.to_ne_bytes());
    block[ustr_offset + 8..ustr_offset + 16]
        .copy_from_slice(&(wide.as_ptr() as usize).to_ne_bytes());
    (block, wide)
}

#[test]
fn spoofed_attr5_denylisted_target_is_blocked() {
    // HIGH regression: benign decoy in ImagePathName, denylisted target
    // in attribute 5 (what the kernel actually loads). Before the fix
    // the veto functions never looked at attribute 5 and returned false
    // — the denylisted spawn ran.
    let (block, wide_p) = make_params_with_image_path(r"C:\Windows\System32\notepad.exe");
    let (list, wide_n) = make_image_name_list(r"C:\Windows\System32\wsl.exe");
    // The decoy really is benign by the old signal — only attr 5 catches it.
    let via_params = unsafe { extract_image_path(block.as_ptr() as *const c_void) };
    assert_eq!(via_params.as_deref(), Some(r"C:\Windows\System32\notepad.exe"));
    assert!(!is_denylisted(via_params.as_deref().unwrap()));
    // The kernel-real signal vetoes.
    assert!(
        attribute_list_contains_parent_process(list.as_ptr() as _),
        "denylisted PsAttributeImageName must veto the spawn"
    );
    assert!(
        attribute_list_contains_handle_list(list.as_ptr() as _),
        "denylisted PsAttributeImageName must veto at the second chokepoint too"
    );
    assert_eq!(
        image_name_from_attr_list(list.as_ptr() as _).as_deref(),
        Some(r"C:\Windows\System32\wsl.exe")
    );
    let _ = (wide_p, wide_n);
}

#[test]
fn benign_attr5_does_not_veto() {
    // No over-blocking: a benign attribute-5 name (missing file, so
    // OriginalFilename reads fail and basename matching alone applies)
    // must not block, with or without other records present.
    let (list, wide) = make_image_name_list(r"C:\definitely-missing-xyz\benign-tool.exe");
    assert!(!attribute_list_contains_parent_process(list.as_ptr() as _));
    assert!(!attribute_list_contains_handle_list(list.as_ptr() as _));
    let _ = wide;
}

#[test]
fn hostile_total_length_is_clamped_to_the_readable_region() {
    // MEDIUM regression: TotalLength claims ~4G of records; the list sits
    // at the very end of the committed page so any record past the two
    // in-page ones lands in the NOACCESS guard page. Before the fix the
    // walk followed the declared length and faulted (fatal in a hook —
    // no SEH). After the fix the count is clamped to the readable extent
    // and the in-page records are still examined.
    let base = alloc_two_pages_first_committed();
    let header = std::mem::size_of::<usize>();
    let attr_size = std::mem::size_of::<PS_ATTRIBUTE>();
    let list_off = PAGE_SIZE - header - 2 * attr_size;
    let list = unsafe { base.add(list_off) } as *mut PS_ATTRIBUTE_LIST;
    unsafe {
        (*list).TotalLength = 0xFFFF_FFFF;
        let attrs = (*list).Attributes.as_mut_ptr();
        // [0] PARENT — must still be detected within the clamped extent.
        (*attrs.add(0)).Attribute = 0x0002_0000;
        (*attrs.add(0)).Size = std::mem::size_of::<usize>();
        (*attrs.add(0)).Value = 0xDEAD_BEEF;
        // [1] HANDLE_LIST — ditto.
        (*attrs.add(1)).Attribute = 0x0002_0002;
        (*attrs.add(1)).Size = std::mem::size_of::<usize>();
        (*attrs.add(1)).Value = 0xCAFE_BABE;
    }
    let ptr = list as *const c_void;
    assert!(
        attribute_list_contains_parent_process(ptr),
        "parent record inside the clamped extent must still veto"
    );
    assert!(
        attribute_list_contains_handle_list(ptr),
        "handle-list record inside the clamped extent must still veto"
    );
    assert!(
        unsafe { image_name_attr_mut(list as *mut c_void) }.is_none(),
        "no record 5 inside the clamped extent"
    );
}

#[test]
fn attr5_value_validation_ladder() {
    // MEDIUM: every length on the attribute-5 path is validated before it
    // is followed. Ladder, in validation order:
    let base = alloc_two_pages_first_committed();
    // (1) Size above the 0x10000 cap → None without touching memory.
    let over_cap = make_attr_list_with(&[(0x0002_0005, 0x2_0000, base as usize)]);
    assert_eq!(image_name_from_attr_list(over_cap.as_ptr() as _), None);
    // (2) Odd Size → None.
    let odd = make_attr_list_with(&[(0x0002_0005, 7, base as usize)]);
    assert_eq!(image_name_from_attr_list(odd.as_ptr() as _), None);
    // (3) Size sane but Value inside the NOACCESS guard page → None, no fault.
    let guard_ptr = unsafe { base.add(PAGE_SIZE) } as usize;
    let in_guard = make_attr_list_with(&[(0x0002_0005, 16, guard_ptr)]);
    assert_eq!(image_name_from_attr_list(in_guard.as_ptr() as _), None);
    assert!(!attribute_list_contains_parent_process(in_guard.as_ptr() as _));
    // (4) Size sane but larger than the readable extent behind Value →
    // clamped to the region (here: the last 4 bytes of the page = the
    // two units "xe"; the declared Size claims far more).
    let name_ptr = unsafe { base.add(PAGE_SIZE - 4) } as *mut u16;
    unsafe {
        name_ptr.write(0x0078); // 'x'
        name_ptr.add(1).write(0x0065); // 'e' — ends exactly at the page end
    }
    let clamped = make_attr_list_with(&[(0x0002_0005, 0x8000, name_ptr as usize)]);
    assert_eq!(
        image_name_from_attr_list(clamped.as_ptr() as _),
        Some("xe".to_string())
    );
    assert!(!attribute_list_contains_parent_process(clamped.as_ptr() as _));
}

#[test]
fn extract_image_path_hostile_length_is_clamped() {
    // MEDIUM: UNICODE_STRING.Length claims 32767 chars; the buffer holds
    // only the last 4 bytes of the committed page ("xe" — the trailing
    // page end is the hard stop). Before the fix the full declared length
    // was followed into the NOACCESS guard page (fault). After the fix
    // the read is clamped to the readable extent.
    let base = alloc_two_pages_first_committed();
    let name_ptr = unsafe { base.add(PAGE_SIZE - 4) } as *mut u16;
    unsafe {
        name_ptr.write(0x0078); // 'x'
        name_ptr.add(1).write(0x0065); // 'e' — ends exactly at the page end
    }
    let mut block = vec![0u8; 0x100];
    let ustr_offset = 0x60usize;
    block[ustr_offset..ustr_offset + 2].copy_from_slice(&0xFFFEu16.to_ne_bytes());
    block[ustr_offset + 2..ustr_offset + 4].copy_from_slice(&0xFFFEu16.to_ne_bytes());
    block[ustr_offset + 8..ustr_offset + 16]
        .copy_from_slice(&(name_ptr as usize).to_ne_bytes());
    let got = unsafe { extract_image_path(block.as_ptr() as *const c_void) };
    assert_eq!(got.as_deref(), Some("xe"));
}

#[test]
fn extract_image_path_null_and_empty_stay_none() {
    // Existing defensive standard, pinned: null params, null Buffer and
    // zero Length all yield None without dereferencing.
    assert!(unsafe { extract_image_path(std::ptr::null()) }.is_none());
    let block = vec![0u8; 0x100]; // Buffer field = null (zeroed)
    assert!(unsafe { extract_image_path(block.as_ptr() as *const c_void) }.is_none());
    let (mut block2, wide) = make_params_with_image_path(r"C:\x\y.exe");
    // Length = 0 → None even with a valid buffer.
    block2[0x60..0x62].copy_from_slice(&0u16.to_ne_bytes());
    assert!(unsafe { extract_image_path(block2.as_ptr() as *const c_void) }.is_none());
    let _ = wide;
}

/// Regression (codex MCP): a parent must be able to put its own tracked child
/// into its job (kill-on-close lifetime); self and foreign stay denied.
#[test]
fn job_assign_only_for_owned_child() {
    let owned = |pid: u32| pid == 42;
    assert!(job_assign_allowed(42, 7, owned), "owned child must be assignable");
    assert!(!job_assign_allowed(7, 7, |_| true), "self reassignment stays denied");
    assert!(!job_assign_allowed(99, 7, owned), "foreign process stays denied");
    assert!(!job_assign_allowed(0, 7, |_| true), "unresolved handle stays denied");
}
