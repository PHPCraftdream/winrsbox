use super::*;

    // ── S05 (docs/review-xa-2026-09-20): a pre-existing junction/symlink/
    // hardlink inside a trusted tree must not redirect side-effecting writes
    // outside it ────────────────────────────────────────────────────────────
    //
    // These tests need REAL junction/symlink/hardlink fixtures, so the
    // fixture root lives INSIDE the worktree (gitignored target/): the
    // tested roots must CONTAIN the aliases, and %TEMP% sits outside this
    // worktree.

    /// S05 fixture root INSIDE the worktree (gitignored target/): real
    /// junctions, symlinks and hardlinks are created here with the actual
    /// Windows APIs, and the tested overlay root lives under it so the
    /// aliases sit INSIDE the roots.
    fn s05_fixture_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target").join("s05-hook-fixtures")
            .join(format!("{tag}-{}-{nanos}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)))
    }

    /// Create an NTFS junction `link` → `target` with the raw Windows APIs.
    ///
    /// S05 (docs/review-xa-2026-09-20): `std::os::windows::fs::junction` is
    /// still unstable (the `junction_ext` feature), and junctions are the ONE
    /// reparse point an unprivileged user can create — the fixtures must use
    /// them, not symlinks. This mirrors std's unstable implementation:
    /// create-and-open the link directory in one go, then post an
    /// IO_REPARSE_TAG_MOUNT_POINT reparse buffer via NtFsControlFile
    /// (FSCTL_SET_REPARSE_POINT; winapi's DeviceIoControl wrapper would need
    /// the `ioapiset` feature, which is not enabled — NtFsControlFile from
    /// the already-enabled ntapi is the same kernel operation).
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

    /// S05 (docs/review-xa-2026-09-20): a junction INSIDE the overlay root
    /// pointing OUTSIDE must not let prepare_overlay create through it. The
    /// destination string `<workdir>\link\evil.txt` looks in-root; only
    /// resolving the parent by handle sees the escape. Also covers the
    /// missing-tail variant: `link\new\created.txt` exists nowhere, so the
    /// deepest EXISTING ancestor of the destination parent is the junction
    /// itself.
    #[test]
    fn s05_prepare_overlay_refuses_junction_parent_escape() {
        let base = s05_fixture_dir("hook-junc-escape");
        let workdir = base.join("workdir");
        let outside = base.join("outside");
        std::fs::create_dir_all(&workdir).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let root_str = workdir.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];
        // Junctions need no privilege.
        let link = workdir.join("link");
        s05_create_junction(&outside, &link).expect("create junction");

        let d = Decision {
            mode: Mode::Cow,
            overlay: Some(link.join("evil.txt")),
            cow_from: None,
            mock_payload: None,
        };
        assert!(
            prepare_overlay_in_roots(&d, &roots).is_none(),
            "destination parent resolving outside the roots must be refused"
        );
        assert!(
            !outside.join("evil.txt").exists(),
            "the junctioned write must NOT have landed outside the roots"
        );

        // Missing-tail variant: `link\new\created.txt`.
        let d2 = Decision {
            mode: Mode::Cow,
            overlay: Some(link.join("new").join("created.txt")),
            cow_from: None,
            mock_payload: None,
        };
        assert!(
            prepare_overlay_in_roots(&d2, &roots).is_none(),
            "create-new through an out-of-root junction must be refused (deepest-existing-ancestor walk)"
        );
        assert!(
            !outside.join("new").exists(),
            "the missing tail must NOT be created on the junction target"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// S05 (docs/review-xa-2026-09-20) NEGATIVE CONTROL / no over-block: a
    /// junction whose target resolves back INSIDE the root stays allowed —
    /// the same tolerance as the merged policy-side gap-1 fix (containment
    /// against the root's own canonical form). The destination string is
    /// in-root and the junction resolves in-root, so the CoW prepare must
    /// succeed and the file must land inside the root.
    #[test]
    fn s05_prepare_overlay_junction_to_inside_root_still_allowed() {
        let base = s05_fixture_dir("hook-junc-inside");
        let workdir = base.join("workdir");
        std::fs::create_dir_all(workdir.join("realdir")).unwrap();
        let root_str = workdir.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];
        let link = workdir.join("ok");
        s05_create_junction(&workdir.join("realdir"), &link).expect("create junction");

        let d = Decision {
            mode: Mode::Cow,
            overlay: Some(link.join("f.txt")),
            // A real (honest, no-alias) source so the CoW copy shows WHERE
            // the write lands: through the junction into its in-root target.
            cow_from: Some(base.join("src.txt")),
            mock_payload: None,
        };
        std::fs::write(base.join("src.txt"), b"in-root-junction").unwrap();
        let got = prepare_overlay_in_roots(&d, &roots)
            .expect("in-root destination through an in-root junction must be allowed");
        assert_eq!(got, link.join("f.txt").to_string_lossy());
        assert_eq!(
            std::fs::read(workdir.join("realdir").join("f.txt")).unwrap(),
            b"in-root-junction",
            "the write must land at the junction's (in-root) target"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// S05 (docs/review-xa-2026-09-20): a CoW source that reaches an
    /// out-of-root file through a junction must NOT be copied into the
    /// overlay — but the refusal is a SKIPPED COPY, not a hard failure
    /// (legacy semantics: prepare still returns Some). An honest
    /// out-of-root source with no alias still copies, proving only aliased
    /// names are refused.
    #[test]
    fn s05_cow_copy_refuses_junctioned_source() {
        let base = s05_fixture_dir("hook-cow-junc-src");
        let workdir = base.join("workdir");
        let outside = base.join("outside");
        std::fs::create_dir_all(&workdir).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let root_str = workdir.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];
        std::fs::write(outside.join("secret.txt"), b"secret").unwrap();
        let srclink = workdir.join("srclink");
        s05_create_junction(&outside, &srclink).expect("create junction");

        let d = Decision {
            mode: Mode::Cow,
            overlay: Some(workdir.join("copy.txt")),
            cow_from: Some(srclink.join("secret.txt")),
            mock_payload: None,
        };
        assert!(
            prepare_overlay_in_roots(&d, &roots).is_some(),
            "a skipped copy is never a hard failure (legacy CoW semantics)"
        );
        assert!(
            !workdir.join("copy.txt").exists(),
            "an aliased CoW source must NOT be copied into the overlay"
        );
        assert_eq!(
            std::fs::read(outside.join("secret.txt")).unwrap(),
            b"secret",
            "the out-of-root original must be untouched"
        );

        // Negative control: an HONEST out-of-root source (no alias on any
        // component) still copy-on-writes.
        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("src.txt"), b"honest").unwrap();
        let d2 = Decision {
            mode: Mode::Cow,
            overlay: Some(workdir.join("copy2.txt")),
            cow_from: Some(real.join("src.txt")),
            mock_payload: None,
        };
        assert!(prepare_overlay_in_roots(&d2, &roots).is_some());
        assert_eq!(
            std::fs::read(workdir.join("copy2.txt")).unwrap(),
            b"honest",
            "out-of-root sources still CoW — only aliased names are refused"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// S05 (docs/review-xa-2026-09-20), symlink variant (skip-able: file
    /// symlinks need SeCreateSymbolicLinkPrivilege or Windows Developer
    /// Mode): a CoW source that is an in-root symlink to an out-of-root file
    /// must not be copied — the handle's resolved final path diverges from
    /// the named source.
    #[test]
    fn s05_cow_copy_refuses_symlinked_source() {
        let base = s05_fixture_dir("hook-cow-sym-src");
        let workdir = base.join("workdir");
        let outside = base.join("outside");
        std::fs::create_dir_all(&workdir).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let root_str = workdir.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];
        std::fs::write(outside.join("src.txt"), b"s").unwrap();
        if let Err(e) = std::os::windows::fs::symlink_file(
            outside.join("src.txt"),
            workdir.join("lnk.txt"),
        ) {
            eprintln!(
                "SKIPPED S05 symlink case: symlink_file failed with {e}; creating \
                 file symlinks requires SeCreateSymbolicLinkPrivilege or \
                 Windows Developer Mode"
            );
            let _ = std::fs::remove_dir_all(&base);
            return;
        }

        let d = Decision {
            mode: Mode::Cow,
            overlay: Some(workdir.join("out.txt")),
            cow_from: Some(workdir.join("lnk.txt")),
            mock_payload: None,
        };
        assert!(prepare_overlay_in_roots(&d, &roots).is_some());
        assert!(
            !workdir.join("out.txt").exists(),
            "a symlinked CoW source must NOT be copied into the overlay"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// S05 (docs/review-xa-2026-09-20), hardlink case: a hardlinked source
    /// name resolves to ITSELF — the very object the policy approved copying
    /// FROM — so the copy proceeds; and because the overlay object is a fresh
    /// separate file, overwriting the overlay never touches the shared
    /// original (the file-object-identity concern is neutralized by
    /// copying).
    #[test]
    fn s05_cow_copy_hardlink_source_copies_content_not_object() {
        let base = s05_fixture_dir("hook-cow-hard-src");
        let workdir = base.join("workdir");
        let outside = base.join("outside");
        std::fs::create_dir_all(&workdir).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let root_str = workdir.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];
        let shared = outside.join("shared.txt");
        std::fs::write(&shared, b"shared").unwrap();
        std::fs::hard_link(shared.as_path(), workdir.join("hl.txt")).unwrap();

        let d = Decision {
            mode: Mode::Cow,
            overlay: Some(workdir.join("copy3.txt")),
            cow_from: Some(workdir.join("hl.txt")),
            mock_payload: None,
        };
        assert!(
            prepare_overlay_in_roots(&d, &roots).is_some(),
            "a hardlink name resolves to itself — the approved object — so the copy proceeds"
        );
        assert_eq!(
            std::fs::read(workdir.join("copy3.txt")).unwrap(),
            b"shared",
            "the overlay copy must carry the source content"
        );
        std::fs::write(workdir.join("copy3.txt"), b"overlaid").unwrap();
        assert_eq!(
            std::fs::read(&shared).unwrap(),
            b"shared",
            "the overlay object is separate — writing it must not touch the hardlinked original"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// S05 (docs/review-xa-2026-09-20): mock materialization through an
    /// out-of-root junction must refuse — nothing may appear on the junction
    /// target — while the honest in-root positive control still materializes,
    /// idempotently (a second call with a different payload must not
    /// overwrite).
    #[test]
    fn s05_materialize_mock_refuses_junction_destination() {
        let base = s05_fixture_dir("hook-mock-junc");
        let workdir = base.join("workdir");
        let outside2 = base.join("outside2");
        std::fs::create_dir_all(&workdir).unwrap();
        std::fs::create_dir_all(&outside2).unwrap();
        let root_str = workdir.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];
        let mj = workdir.join("mj");
        s05_create_junction(&outside2, &mj).expect("create junction");

        materialize_mock_overlay_in_roots(&mj.join("m.txt"), b"p", &roots);
        assert!(
            !outside2.join("m.txt").exists(),
            "mock materialization must NOT land outside the roots via the junction"
        );

        // Positive control + idempotency under the new path.
        let m2 = workdir.join("okdir").join("m2.txt");
        materialize_mock_overlay_in_roots(&m2, b"p2", &roots);
        assert_eq!(std::fs::read(&m2).unwrap(), b"p2");
        materialize_mock_overlay_in_roots(&m2, b"DIFFERENT-MUST-NOT-LAND", &roots);
        assert_eq!(
            std::fs::read(&m2).unwrap(),
            b"p2",
            "second materialize must NOT overwrite (idempotency under the new path)"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// S05 (docs/review-xa-2026-09-20) THE regression test: a DANGLING
    /// symlink occupying an overlay name used to redirect the bare
    /// `std::fs::write` — the unfixed code follows the link and creates the
    /// target outside the roots. The no-follow create (create_new +
    /// FILE_FLAG_OPEN_REPARSE_POINT) fails instead, and the skip is swallowed
    /// like any other create error.
    #[test]
    fn s05_materialize_mock_does_not_follow_dangling_symlink() {
        let base = s05_fixture_dir("hook-mock-dangle");
        let workdir = base.join("workdir");
        let outside3 = base.join("outside3");
        std::fs::create_dir_all(&workdir).unwrap();
        // The PARENT of the symlink target must exist so the unfixed write
        // would actually have created the file out there; the file target
        // itself does not exist — the link dangles.
        std::fs::create_dir_all(&outside3).unwrap();
        let root_str = workdir.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];
        if let Err(e) = std::os::windows::fs::symlink_file(
            outside3.join("missing.txt"),
            workdir.join("dangle.txt"),
        ) {
            eprintln!(
                "SKIPPED S05 symlink case: symlink_file failed with {e}; creating \
                 file symlinks requires SeCreateSymbolicLinkPrivilege or \
                 Windows Developer Mode"
            );
            let _ = std::fs::remove_dir_all(&base);
            return;
        }

        materialize_mock_overlay_in_roots(&workdir.join("dangle.txt"), b"payload", &roots);
        assert!(
            !outside3.join("missing.txt").exists(),
            "the dangling symlink must NOT have created its target outside the roots"
        );
        assert!(
            std::fs::read_dir(&outside3).unwrap().next().is_none(),
            "no file may appear anywhere at the symlink target"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// S05 (docs/review-xa-2026-09-20), hardlink destination case: the
    /// overlay name is a hardlink to an out-of-root file. The idempotency
    /// fast path sees the existing object and returns; even without it, the
    /// no-follow create-new would refuse the occupied name. Either way the
    /// shared original must keep its content.
    #[test]
    fn s05_materialize_mock_hardlink_dest_not_overwritten() {
        let base = s05_fixture_dir("hook-mock-hard");
        let workdir = base.join("workdir");
        let outside4 = base.join("outside4");
        std::fs::create_dir_all(&workdir).unwrap();
        std::fs::create_dir_all(&outside4).unwrap();
        let root_str = workdir.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];
        let shared2 = outside4.join("shared2.txt");
        std::fs::write(&shared2, b"orig").unwrap();
        std::fs::hard_link(shared2.as_path(), workdir.join("hl2.txt")).unwrap();

        materialize_mock_overlay_in_roots(&workdir.join("hl2.txt"), b"payload", &roots);
        assert_eq!(
            std::fs::read(&shared2).unwrap(),
            b"orig",
            "materializing a name occupied by a hardlink must not overwrite the shared object"
        );

        let _ = std::fs::remove_dir_all(&base);
    }
