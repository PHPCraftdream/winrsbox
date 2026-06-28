pub mod path;
pub mod db;
pub mod reg;
pub mod reg_overlay;
pub mod dev;
pub mod net;
pub mod mem;
pub mod scan;

pub(crate) mod decide;
pub(crate) mod policy_impl;
pub(crate) mod registry;

use std::path::PathBuf;
use thiserror::Error;

pub use decide::{Verdict, ConsideredRule, TracedDecision};
pub use policy_impl::Policy;
pub use registry::{RegDecision, RegistryPolicy};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum Mode {
    Passthrough,
    Deny,
    Cow,
    Mock,
    /// OverlayFS-style whiteout: the path is hidden from the sandbox's merged
    /// view (open → not-found, absent from enumeration). The real lower file
    /// is never touched. A create at the same path clears the marker (revive)
    /// and re-enters the CoW overlay.
    Hidden,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Decision {
    pub mode: Mode,
    pub overlay: Option<PathBuf>,
    pub cow_from: Option<PathBuf>,
    pub mock_payload: Option<Vec<u8>>,
}

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("redb: {0}")]
    Db(#[from] redb::Error),
    #[error("redb database: {0}")]
    DbOpen(#[from] redb::DatabaseError),
    #[error("redb storage: {0}")]
    DbStorage(#[from] redb::StorageError),
    #[error("redb transaction: {0}")]
    DbTxn(#[from] redb::TransactionError),
    #[error("redb table: {0}")]
    DbTable(#[from] redb::TableError),
    #[error("redb commit: {0}")]
    DbCommit(#[from] redb::CommitError),
    #[error("ktav: {0}")]
    Ktav(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub(crate) fn ensure_lower(s: &str) -> std::borrow::Cow<'_, str> {
    // ASCII-only fold matches what the kernel uses (RtlDowncaseUnicodeString
    // for ASCII chars) AND every hook-side path comparison. Unicode
    // to_lowercase() would fold U+0130 to "i\u{307}", diverging from
    // kernel canonicalization and enabling bypass via inconsistent
    // normalization.
    if s.bytes().all(|b| !b.is_ascii_uppercase()) {
        std::borrow::Cow::Borrowed(s)
    } else {
        std::borrow::Cow::Owned(s.to_ascii_lowercase())
    }
}

/// Strip trailing `\` / `/` separators from a DOS path used as an OVERLAY_IDX
/// or WHITEOUTS key. NT allows opening a directory with a trailing separator
/// (`d:\foo\`), and the hook's `dos_path` extraction preserves it, so a create
/// at `d:\foo\` and a subsequent open at `d:\foo` would otherwise key the
/// overlay index differently — leaving the directory invisible to later
/// readers (observed with git's `.git/info` directory). Root (`d:\`) is
/// preserved.
pub(crate) fn trim_trailing_sep(s: &str) -> &str {
    let bytes = s.as_bytes();
    // Preserve drive roots like `d:\`.
    if bytes.len() <= 3 { return s; }
    let mut end = bytes.len();
    while end > 1 && (bytes[end - 1] == b'\\' || bytes[end - 1] == b'/') {
        end -= 1;
    }
    if end == bytes.len() { s } else { &s[..end] }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn ensure_lower_is_ascii_only() {
        assert_eq!(ensure_lower("CamelCase").as_ref(), "camelcase");
        assert_eq!(ensure_lower("already-lower").as_ref(), "already-lower");
        // U+0130 (LATIN CAPITAL LETTER I WITH DOT ABOVE) must pass through
        // untouched — Unicode to_lowercase() would fold it to "i\u{307}",
        // diverging from the kernel's ASCII-only RtlDowncaseUnicodeString.
        let input = "C:\\WIN\u{0130}DIR";
        assert_eq!(ensure_lower(input).as_ref(), "c:\\win\u{0130}dir");
    }

    #[test]
    fn ensure_lower_fast_path_borrows() {
        let s = "already-lowercase-ascii";
        let result = ensure_lower(s);
        assert!(matches!(result, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn fresh_db_defaults_passthrough_cow() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(
            &db_path,
            sandbox,
            mock_dirs,
            project,
        ).unwrap();

        let d = p.decide(r"c:\some\path", false);
        assert_eq!(d.mode, Mode::Passthrough);

        // External write with no explicit rule → CoW (isolated into the
        // sandbox overlay, never the real disk). This is the core isolation
        // invariant of the merged-view model.
        let d = p.decide(r"c:\some\path", true);
        assert_eq!(d.mode, Mode::Cow);
    }

    #[test]
    fn deny_rule_on_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(
            &db_path,
            sandbox,
            mock_dirs,
            project,
        ).unwrap();

        let cfg_path = dir.path().join("config.ktv");
        let mut f = std::fs::File::create(&cfg_path).unwrap();
        let cfg = "defaults: {\n\
            \x20   read: passthrough\n\
            \x20   write: cow\n\
            }\n\
            \n\
            rules: [\n\
            \x20   {\n\
            \x20       prefix: c:\\test\n\
            \x20       write: deny\n\
            \x20   }\n\
            ]";
        write!(f, "{}", cfg).unwrap();
        drop(f);

        p.load_config(&cfg_path).unwrap();
        let d = p.decide("c:\\test\\x", true);
        assert_eq!(d.mode, Mode::Deny);
    }

    #[test]
    fn record_overlay_then_read_cow() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(
            &db_path,
            sandbox,
            mock_dirs,
            project,
        ).unwrap();

        let overlay_path = dir.path().join("sb").join("c").join("data.txt");
        p.record_overlay(r"c:\data.txt", overlay_path.to_str().unwrap()).unwrap();

        let d = p.decide(r"c:\data.txt", false);
        assert_eq!(d.mode, Mode::Cow);
        assert!(d.overlay.is_some());
    }

    #[test]
    fn project_root_always_passthrough() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(
            &db_path,
            sandbox,
            mock_dirs,
            project.clone(),
        ).unwrap();

        let cfg_path = dir.path().join("config.ktv");
        let mut f = std::fs::File::create(&cfg_path).unwrap();
        let cfg = "defaults: {\n\
            \x20   read: deny\n\
            \x20   write: deny\n\
            }\n\
            \n\
            rules: [\n\
            \x20   {\n\
            \x20       prefix: c:\\deny_all\n\
            \x20       read: deny\n\
            \x20       write: deny\n\
            \x20   }\n\
            ]";
        write!(f, "{}", cfg).unwrap();
        drop(f);
        p.load_config(&cfg_path).unwrap();

        let inside = project.join("src").join("main.rs");
        let d = p.decide(inside.to_str().unwrap(), false);
        assert_eq!(d.mode, Mode::Passthrough);

        let d = p.decide(inside.to_str().unwrap(), true);
        assert_eq!(d.mode, Mode::Passthrough);
    }

    #[test]
    fn mock_dirs_prefix_cow() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(
            &db_path,
            sandbox,
            mock_dirs.clone(),
            project,
        ).unwrap();

        let cfg_path = dir.path().join("config.ktv");
        let mut f = std::fs::File::create(&cfg_path).unwrap();
        write!(f, "defaults: {{\n\
            read: passthrough\n\
            write: cow\n\
        }}\n\
        \n\
        mock_dirs: [\n\
            {{\n\
                prefix: c:\\fake\n\
            }}\n\
        ]\n\
        ").unwrap();
        drop(f);
        p.load_config(&cfg_path).unwrap();

        let d = p.decide(r"c:\fake\sub\file.txt", false);
        assert_eq!(d.mode, Mode::Cow);
        let expected = mock_dirs.join("c").join("fake").join("sub").join("file.txt");
        assert_eq!(d.overlay.unwrap(), expected);
    }

    // ── Additional policy integration tests ─────────────────────────────────

    #[test]
    fn decide_cache_hit_returns_same_decision() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
        let d1 = p.decide(r"c:\some\path", false);
        let d2 = p.decide(r"c:\some\path", false);
        assert_eq!(d1.mode, d2.mode);
        assert_eq!(d1.overlay, d2.overlay);
    }

    #[test]
    fn decide_cow_write_nonexistent_file_no_cow_from() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
        // Path outside project_root + write, no explicit rule → CoW by the
        // merged-view default (write isolation). The file does not exist on
        // the real disk, so cow_from must be None (nothing to copy from).
        let d = p.decide(r"c:\nonexistent\file.txt", true);
        assert_eq!(d.mode, Mode::Cow);
        assert!(d.cow_from.is_none(), "cow_from should be None for non-existent files");
        assert!(d.overlay.is_some());
    }

    #[test]
    fn record_overlay_invalidates_cache() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();

        // First call: default passthrough for read
        let d1 = p.decide(r"c:\data.txt", false);
        assert_eq!(d1.mode, Mode::Passthrough);

        // Record overlay
        let overlay = dir.path().join("sb").join("c").join("data.txt");
        p.record_overlay(r"c:\data.txt", overlay.to_str().unwrap()).unwrap();

        // Second call: should see Cow now
        let d2 = p.decide(r"c:\data.txt", false);
        assert_eq!(d2.mode, Mode::Cow);
    }

    #[test]
    fn sandbox_root_accessor() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox.clone(), mock_dirs, project).unwrap();
        assert_eq!(p.sandbox_root(), sandbox);
    }

    #[test]
    fn mock_dirs_root_accessor() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs.clone(), project).unwrap();
        assert_eq!(p.mock_dirs_root(), mock_dirs);
    }

    #[test]
    fn project_root_accessor_lowercase() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("ProjDir");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
        // project_root should be lowercased
        assert!(p.project_root().contains("projdir"));
        assert!(!p.project_root().contains("ProjDir"));
    }

    #[test]
    fn decide_with_mock_file() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();

        let cfg_path = dir.path().join("config.ktv");
        let mut f = std::fs::File::create(&cfg_path).unwrap();
        // NOTE: ktav includes the quotes as part of the string value
        write!(f, "defaults: {{\n\
            read: passthrough\n\
            write: cow\n\
        }}\n\
        \n\
        mocks: [\n\
            {{\n\
                path: c:\\fake\\token.txt\n\
                content_inline: secret data\n\
            }}\n\
        ]\n\
        ").unwrap();
        drop(f);
        p.load_config(&cfg_path).unwrap();

        let d = p.decide(r"c:\fake\token.txt", false);
        assert_eq!(d.mode, Mode::Mock);
        assert_eq!(d.mock_payload.unwrap(), b"secret data");
    }

    #[test]
    fn load_config_invalid_ktav_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();

        let cfg_path = dir.path().join("bad.ktv");
        std::fs::write(&cfg_path, "{{{{invalid}}}}").unwrap();
        let result = p.load_config(&cfg_path);
        assert!(result.is_err());
    }

    #[test]
    fn load_config_missing_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
        let result = p.load_config(dir.path().join("nonexistent.ktv").as_path());
        assert!(result.is_err());
    }

    // ── CoW-overlay isolation boundary tests ──────────────────────────────
    //
    // These pin the merged-view isolation model: writes to paths OUTSIDE
    // project_root are isolated into the sandbox overlay (CoW), never hitting
    // the real disk. Reads of un-recorded external paths fall through to the
    // real disk (read-through consults OVERLAY_IDX first). The agent's own
    // project_root stays real (passthrough). Explicit deny/passthrough rules
    // on external paths still override the default.

    fn make_policy_with_project(project_name: &str) -> (tempfile::TempDir, Policy, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join(project_name);
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project.clone()).unwrap();
        (dir, p, project)
    }

    #[test]
    fn out_of_project_write_isolated_to_overlay() {
        // Path outside project_root + write, no explicit rule → CoW with an
        // overlay target INSIDE sandbox_root. Real disk is never touched.
        let (_dir, p, _project) = make_policy_with_project("proj");
        let d = p.decide(r"d:\winrsbox_get_test\.git\head", true);
        assert_eq!(d.mode, Mode::Cow, "out-of-project write must be isolated (Cow)");
        assert!(d.overlay.is_some(), "overlay must be formed for out-of-project write");
    }

    #[test]
    fn out_of_project_read_falls_through_to_real_disk() {
        // Path outside project_root + read, no prior overlay entry →
        // Passthrough (read-through on the real disk). The read-through branch
        // still consults OVERLAY_IDX; with nothing recorded there, it falls
        // through to Passthrough.
        let (_dir, p, _project) = make_policy_with_project("proj");
        let d = p.decide(r"d:\winrsbox_get_test\.git\head", false);
        assert_eq!(d.mode, Mode::Passthrough);
        assert!(d.overlay.is_none());
    }

    #[test]
    fn inside_project_write_still_passthrough() {
        // Paths inside project_root remain passthrough (agent mutates its own
        // dir for real). No regression of the project_root short-circuit.
        let (_dir, p, project) = make_policy_with_project("proj");
        let inside = project.join("src").join("main.rs");
        let d = p.decide(inside.to_str().unwrap(), true);
        assert_eq!(d.mode, Mode::Passthrough);
        assert!(d.overlay.is_none());
    }

    #[test]
    fn explicit_deny_outside_project_still_deny() {
        // An explicit deny rule on a path outside project_root must still
        // take effect (isolation of C:\Windows etc. is not weakened).
        let (dir, p, _project) = make_policy_with_project("proj");
        let cfg_path = dir.path().join("config.ktv");
        let mut f = std::fs::File::create(&cfg_path).unwrap();
        write!(f, "defaults: {{\n    read: passthrough\n    write: cow\n}}\n\nrules: [\n    {{\n        prefix: c:\\windows\n        read: passthrough\n        write: deny\n    }}\n]").unwrap();
        drop(f);
        p.load_config(&cfg_path).unwrap();

        let d = p.decide(r"c:\windows\system32\evil.dll", true);
        assert_eq!(d.mode, Mode::Deny, "explicit deny rule must still apply outside project_root");
    }

    #[test]
    fn explicit_passthrough_rule_outside_project_overrides_default() {
        // Explicit passthrough rule overrides the default Cow isolation — the
        // operator can whitelist a specific external path to hit the real disk.
        let (dir, p, _project) = make_policy_with_project("proj");
        let cfg_path = dir.path().join("config.ktv");
        let mut f = std::fs::File::create(&cfg_path).unwrap();
        write!(f, "defaults: {{\n    read: deny\n    write: deny\n}}\n\nrules: [\n    {{\n        prefix: d:\\allowed\n        read: passthrough\n        write: passthrough\n    }}\n]").unwrap();
        drop(f);
        p.load_config(&cfg_path).unwrap();

        let d = p.decide(r"d:\allowed\file.txt", true);
        assert_eq!(d.mode, Mode::Passthrough);
        let d = p.decide(r"d:\allowed\file.txt", false);
        assert_eq!(d.mode, Mode::Passthrough);
    }

    // ── Isolation invariant tests (regression guards) ─────────────────────
    //
    // These exist so the isolation cannot silently regress again: they check
    // not just the mode but the *target* of the overlay, and the read-through
    // behavior for a previously-recorded external file.

    #[test]
    fn external_write_never_targets_real_disk() {
        // A write to a path outside project_root must (a) be CoW and (b)
        // redirect INTO sandbox_root — never back at the original external
        // path. This is the precise guarantee the bug broke.
        let (dir, p, _project) = make_policy_with_project("proj");
        let sandbox_root = dir.path().join("sb");
        let d = p.decide(r"d:\external\data\file.bin", true);
        assert_eq!(d.mode, Mode::Cow, "external write must be Cow");
        let overlay = d.overlay.expect("overlay must be present");
        let overlay_lower = overlay.to_string_lossy().to_lowercase();
        let sandbox_lower = sandbox_root.to_string_lossy().to_lowercase();
        assert!(
            overlay_lower.starts_with(&sandbox_lower),
            "overlay {:?} must live inside sandbox_root {:?}, not at the external path",
            overlay_lower, sandbox_lower,
        );
        // And specifically must NOT equal the original external path.
        assert_ne!(overlay_lower, r"d:\external\data\file.bin");
    }

    #[test]
    fn external_create_then_read_through() {
        // Simulate the hook recording an overlay entry for an external file
        // (record_overlay), then read the same path: the read must resolve to
        // Mode::Cow pointing at the recorded overlay (read-through).
        let (dir, p, _project) = make_policy_with_project("proj");
        let sandbox_root = dir.path().join("sb");
        let orig = r"d:\created\file.txt";
        let overlay_target = sandbox_root.join("d").join("created").join("file.txt");
        std::fs::create_dir_all(overlay_target.parent().unwrap()).unwrap();
        std::fs::write(&overlay_target, b"isolated").unwrap();
        p.record_overlay(orig, overlay_target.to_str().unwrap()).unwrap();

        let d = p.decide(orig, false);
        assert_eq!(d.mode, Mode::Cow, "read of recorded external file must hit the overlay (Cow)");
        assert_eq!(
            d.overlay.as_ref().map(|o| o.to_string_lossy().to_lowercase()),
            Some(overlay_target.to_string_lossy().to_lowercase()),
            "read-through must return the same recorded overlay path",
        );
    }

    // ── Whiteout (OverlayFS tombstone) tests ──────────────────────────────

    #[test]
    fn record_whiteout_then_is_whiteouted_true() {
        let (_dir, p, _project) = make_policy_with_project("proj");
        assert!(!p.is_whiteouted(r"d:\ext\file.txt"), "no marker before record");
        p.record_whiteout(r"d:\ext\File.txt").unwrap();
        assert!(p.is_whiteouted(r"d:\ext\file.txt"), "marker present after record");
        assert!(p.is_whiteouted(r"D:\EXT\FILE.TXT"), "marker lookup is case-insensitive");
    }

    #[test]
    fn clear_whiteout_removes_marker() {
        let (_dir, p, _project) = make_policy_with_project("proj");
        p.record_whiteout(r"d:\ext\file.txt").unwrap();
        assert!(p.is_whiteouted(r"d:\ext\file.txt"));
        p.clear_whiteout(r"d:\ext\file.txt").unwrap();
        assert!(!p.is_whiteouted(r"d:\ext\file.txt"), "marker gone after clear");
    }

    /// Bug #78: clear_whiteout must also remove descendant whiteouts.
    ///
    /// Scenario: SSH clone fails → git cleanup whiteouts the repo dir AND all
    /// children (.git, .git\config, …). HTTPS retry re-creates the repo dir
    /// (reviving its own whiteout) but `.git` keeps its stale whiteout so git's
    /// subsequent FILE_OPEN for `.git` sees Hidden → clone failure.
    ///
    /// The fix: `clear_whiteout(parent)` bulk-removes all `parent\*` entries.
    #[test]
    fn clear_whiteout_cascades_to_children() {
        let (_dir, p, _project) = make_policy_with_project("proj");
        // Simulate SSH-clone whiteouts: parent dir + children + deeper children.
        p.record_whiteout(r"d:\repo\hermes-agent").unwrap();
        p.record_whiteout(r"d:\repo\hermes-agent\.git").unwrap();
        p.record_whiteout(r"d:\repo\hermes-agent\.git\config").unwrap();
        p.record_whiteout(r"d:\repo\hermes-agent\.git\HEAD").unwrap();
        // Unrelated sibling prefix — must NOT be touched.
        p.record_whiteout(r"d:\repo\hermes-agent-old\file.txt").unwrap();

        // Revival of parent:
        p.clear_whiteout(r"d:\repo\hermes-agent").unwrap();

        assert!(!p.is_whiteouted(r"d:\repo\hermes-agent"), "parent whiteout cleared");
        assert!(!p.is_whiteouted(r"d:\repo\hermes-agent\.git"), ".git child cleared");
        assert!(!p.is_whiteouted(r"d:\repo\hermes-agent\.git\config"), "deep child cleared");
        assert!(!p.is_whiteouted(r"d:\repo\hermes-agent\.git\HEAD"), "deep child cleared");
        // Sibling prefix must survive.
        assert!(p.is_whiteouted(r"d:\repo\hermes-agent-old\file.txt"),
            "sibling-prefix entry must not be touched");
    }

    #[test]
    fn record_whiteout_invalidates_cache() {
        // record_overlay clears the cache; record_whiteout must do the same
        // so a subsequent decide() observes the marker.
        let (_dir, p, _project) = make_policy_with_project("proj");
        let path = r"d:\ext\wh\file.txt";
        // Prime the cache with a default decide (no marker).
        let d1 = p.decide(path, false);
        assert_ne!(d1.mode, Mode::Hidden);
        // Record the marker.
        p.record_whiteout(path).unwrap();
        // Now decide must reflect the whiteout.
        let d2 = p.decide(path, false);
        assert_eq!(d2.mode, Mode::Hidden, "cache must be invalidated so whiteout is seen");
    }

    #[test]
    fn whiteout_persists_across_db_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let sandbox = dir.path().join("sb");
        let mock_dirs = dir.path().join("md");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir_all(&mock_dirs).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        {
            let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
            p.record_whiteout(r"d:\persist\file.txt").unwrap();
            assert!(p.is_whiteouted(r"d:\persist\file.txt"));
        }
        // Reopen: the WHITEOUTS table is durable.
        let sandbox2 = dir.path().join("sb");
        let mock_dirs2 = dir.path().join("md");
        let project2 = dir.path().join("proj");
        let p = Policy::open_or_create(&db_path, sandbox2, mock_dirs2, project2).unwrap();
        assert!(p.is_whiteouted(r"d:\persist\file.txt"), "whiteout must survive db reopen");
    }

    #[test]
    fn whiteouts_under_returns_direct_children_only() {
        let (_dir, p, _project) = make_policy_with_project("proj");
        p.record_whiteout(r"d:\foo\a.txt").unwrap();
        p.record_whiteout(r"d:\foo\b.log").unwrap();
        // Descendant of a subdir — NOT a direct child of d:\foo.
        p.record_whiteout(r"d:\foo\sub\deep.txt").unwrap();
        // Different directory entirely.
        p.record_whiteout(r"d:\bar\c.txt").unwrap();

        let names = p.whiteouts_under(r"d:\foo");
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(sorted, vec!["a.txt".to_string(), "b.log".to_string()],
            "whiteouts_under must return only direct children, got {names:?}");
    }

    #[test]
    fn whiteouts_under_empty_when_no_match() {
        let (_dir, p, _project) = make_policy_with_project("proj");
        p.record_whiteout(r"d:\foo\a.txt").unwrap();
        let names = p.whiteouts_under(r"d:\empty");
        assert!(names.is_empty(), "no whiteouts under an unrelated dir");
    }

    #[test]
    fn whiteouts_under_sibling_prefix_not_confused() {
        // d:\foo vs d:\foobar — must not cross-contaminate.
        let (_dir, p, _project) = make_policy_with_project("proj");
        p.record_whiteout(r"d:\foobar\evil.txt").unwrap();
        let names = p.whiteouts_under(r"d:\foo");
        assert!(names.is_empty(), "d:\\foo must not see d:\\foobar's children");
    }

    // ── decide() + whiteout integration tests ─────────────────────────────

    #[test]
    fn external_whiteouted_path_decides_hidden() {
        let (_dir, p, _project) = make_policy_with_project("proj");
        let path = r"d:\ext\doomed.txt";
        // Before whiteout: passthrough read (read-through to real disk).
        assert_eq!(p.decide(path, false).mode, Mode::Passthrough);
        p.record_whiteout(path).unwrap();
        // After whiteout: Hidden (no overlay entry).
        let d = p.decide(path, false);
        assert_eq!(d.mode, Mode::Hidden, "whiteouted external path must be Hidden on read");
        assert!(d.overlay.is_none(), "Hidden must carry no overlay path");
        // Write disposition is also hidden — a pure open-for-write (no create)
        // still sees the path as gone. The revive happens only when disposition
        // is a create, which the hook layer handles by clearing the whiteout
        // BEFORE re-deciding.
        let d = p.decide(path, true);
        assert_eq!(d.mode, Mode::Hidden);
    }

    #[test]
    fn whiteout_then_overlay_revives_to_cow() {
        // After a whiteout, if an overlay entry is recorded (revive via create),
        // decide must return Cow pointing at the overlay — NOT Hidden.
        let (_dir, p, _project) = make_policy_with_project("proj");
        let path = r"d:\ext\phoenix.txt";
        p.record_whiteout(path).unwrap();
        assert_eq!(p.decide(path, false).mode, Mode::Hidden);

        // Simulate the hook recording the overlay after a revive-create.
        let overlay = r"D:\sb\d\ext\phoenix.txt";
        p.record_overlay(path, overlay).unwrap();
        let d = p.decide(path, false);
        assert_eq!(d.mode, Mode::Cow, "revive (overlay present) must override whiteout");
        assert_eq!(
            d.overlay.as_ref().map(|o| o.to_string_lossy().into_owned()),
            Some(overlay.to_string()),
        );
    }

    #[test]
    fn rename_revive_clears_whiteout_then_overlay_visible() {
        // Regression for the git-config "unknown error reading configuration
        // files" bug. The hook's rename handler now revives a whiteouted
        // destination before redirecting the rename into the overlay. This test
        // pins the policy-side sequence that revive performs:
        //   1. external path is whiteouted (e.g. by a prior `rm -rf .git`).
        //   2. rename handler calls clear_whiteout (revive) on the dest.
        //   3. rename handler records the new overlay entry for dest.
        //   4. decide(dest, write=true) MUST return Cow (not Hidden), and a
        //      subsequent read MUST also see Cow pointing at the new overlay —
        //      otherwise git's follow-up `git config --get` / `git add` reopen
        //      sees Hidden and fails with "unknown error reading config".
        let (_dir, p, _project) = make_policy_with_project("proj");
        let dest = r"d:\repo\.git\config";

        // (1) prior delete whiteouted the path, no overlay present.
        p.record_whiteout(dest).unwrap();
        assert_eq!(p.decide(dest, true).mode, Mode::Hidden);
        assert_eq!(p.decide(dest, false).mode, Mode::Hidden);

        // (2) hook rename-revive: clear_whiteout.
        p.clear_whiteout(dest).unwrap();
        // After clear, with no overlay, decide falls through to default
        // (write=Cow, read=Passthrough) — the rename will create the overlay.
        assert_eq!(p.decide(dest, true).mode, Mode::Cow);

        // (3) hook records the overlay destination after the rename.
        let overlay = r"D:\sb\d\repo\.git\config";
        p.record_overlay(dest, overlay).unwrap();

        // (4) the follow-up reopen (write=false) MUST see the new overlay.
        let d_read = p.decide(dest, false);
        assert_eq!(d_read.mode, Mode::Cow, "reopened dest must resolve to overlay, not Hidden/Passthrough");
        assert_eq!(
            d_read.overlay.as_ref().map(|o| o.to_string_lossy().into_owned()),
            Some(overlay.to_string()),
        );
    }

    #[test]
    fn whiteout_inside_project_root_is_passthrough() {
        // Whiteout markers only apply to external paths. A path inside
        // project_root short-circuits to Passthrough regardless of any marker
        // in the WHITEOUTS table (the agent mutates its own dir for real).
        let (_dir, p, project) = make_policy_with_project("proj");
        let inside = project.join("src").join("main.rs");
        // Even if a stray whiteout exists for an inside-project path, it must
        // not take effect.
        p.record_whiteout(inside.to_str().unwrap()).unwrap();
        let d = p.decide(inside.to_str().unwrap(), false);
        assert_eq!(d.mode, Mode::Passthrough, "whiteout must not apply inside project_root");
        assert!(d.overlay.is_none());
    }

    // ── Regression: delete-then-stat must see Hidden ──────────────────────
    //
    // This is the exact sequence the acceptance repro exercises:
    //   1. A write to an external path records an overlay entry (Cow).
    //   2. The delete hook physically removes the overlay copy AND clears the
    //      OVERLAY_IDX entry, then records a whiteout.
    //   3. A subsequent read (write=false) of the same path must return
    //      Mode::Hidden — NOT Cow, NOT Passthrough.
    //
    // The bug this pins: if the OVERLAY_IDX entry is NOT cleared on delete,
    // `compute` sees (whiteout=true, has_overlay=true) and falls through to
    // the normal flow, which returns Cow pointing at the now-missing overlay
    // file. The caller then sees the real lower file instead of not-found.
    #[test]
    fn delete_overlay_then_whiteout_read_is_hidden() {
        let (_dir, p, _project) = make_policy_with_project("proj");
        let path = r"d:\ext\doomed.txt";

        // Step 1: external write → Cow + overlay entry recorded (simulates the
        // hook recording the overlay after a CoW write).
        p.record_overlay(path, r"D:\sb\d\ext\doomed.txt").unwrap();
        let d_write = p.decide(path, true);
        assert_eq!(d_write.mode, Mode::Cow, "write must be Cow with overlay present");
        // Read also sees Cow (read-through to overlay).
        assert_eq!(p.decide(path, false).mode, Mode::Cow);

        // Step 2: delete — the hook clears the overlay index entry (the file is
        // gone) AND records a whiteout.
        p.clear_overlay(path).unwrap();
        p.record_whiteout(path).unwrap();

        // Step 3: read must be Hidden.
        let d_read = p.decide(path, false);
        assert_eq!(
            d_read.mode,
            Mode::Hidden,
            "after delete (clear_overlay + record_whiteout), read must be Hidden, got {:?}",
            d_read.mode,
        );

        // And a write-decide (pure open, not create) must also be Hidden.
        let d_write2 = p.decide(path, true);
        assert_eq!(
            d_write2.mode,
            Mode::Hidden,
            "after delete, write-decide must be Hidden too, got {:?}",
            d_write2.mode,
        );
    }

    // ── OVERLAY_CASE tests (variant B hybrid case-rewrite) ──────────────────

    /// 7.1 — Backward compat: existing OVERLAY_IDX entries (without any
    /// OVERLAY_CASE record) yield an empty Vec from overlay_children_with_case.
    /// No panic, no corruption.
    #[test]
    fn overlay_case_legacy_entries_yield_empty() {
        let (_dir, p, _project) = make_policy_with_project("proj");
        // Write to OVERLAY_IDX only (simulating a legacy entry).
        p.record_overlay(r"c:\test\some_dir", r"C:\sb\test\some_dir").unwrap();
        // overlay_children_with_case on the parent must return empty (no case
        // record exists for the child).
        let pairs = p.overlay_children_with_case(r"c:\test");
        assert!(
            pairs.is_empty(),
            "legacy entry without case record must yield empty pairs, got: {:?}", pairs
        );
    }

    /// 7.2 — Roundtrip: record a case for a new entry, retrieve it.
    #[test]
    fn overlay_case_roundtrip() {
        let (_dir, p, _project) = make_policy_with_project("proj");
        // Simulate an overlay write with original case "Mixed_Case_Dir".
        let lower_path = r"c:\localappdata\uv\cache\builds-v0\.tmpabcd\mixed_case_dir";
        let parent = r"c:\localappdata\uv\cache\builds-v0\.tmpabcd";
        p.record_overlay(lower_path, r"C:\sb\mixed_case_dir").unwrap();
        p.record_overlay_case(lower_path, "Mixed_Case_Dir");
        let pairs = p.overlay_children_with_case(parent);
        assert_eq!(pairs.len(), 1, "expected 1 pair, got: {:?}", pairs);
        let (lower, original) = &pairs[0];
        assert_eq!(lower, "mixed_case_dir");
        assert_eq!(original, "Mixed_Case_Dir");
    }

    /// 7.3 — Already-lowercase basename is NOT stored (optimization guard).
    #[test]
    fn overlay_case_lowercase_basename_not_stored() {
        let (_dir, p, _project) = make_policy_with_project("proj");
        let lower_path = r"c:\test\lowercase_dir";
        p.record_overlay(lower_path, r"C:\sb\lowercase_dir").unwrap();
        p.record_overlay_case(lower_path, "lowercase_dir"); // all lowercase → no-op
        let pairs = p.overlay_children_with_case(r"c:\test");
        assert!(
            pairs.is_empty(),
            "all-lowercase basename must not be stored, got: {:?}", pairs
        );
    }

    /// 7.4 — Multiple children, only those with case records returned.
    #[test]
    fn overlay_case_multiple_children_mixed() {
        let (_dir, p, _project) = make_policy_with_project("proj");
        let parent = r"c:\test";
        // child_a: has case record
        p.record_overlay(r"c:\test\child_a", r"C:\sb\child_a").unwrap();
        p.record_overlay_case(r"c:\test\child_a", "Child_A");
        // child_b: all-lowercase → no case record stored
        p.record_overlay(r"c:\test\child_b", r"C:\sb\child_b").unwrap();
        p.record_overlay_case(r"c:\test\child_b", "child_b");
        // child_c: has case record
        p.record_overlay(r"c:\test\child_c", r"C:\sb\child_c").unwrap();
        p.record_overlay_case(r"c:\test\child_c", "Child_C");

        let pairs = p.overlay_children_with_case(parent);
        assert_eq!(pairs.len(), 2, "only 2 children have case records, got: {:?}", pairs);
        let names: Vec<&str> = pairs.iter().map(|(_, o)| o.as_str()).collect();
        assert!(names.contains(&"Child_A"), "Child_A must be in pairs");
        assert!(names.contains(&"Child_C"), "Child_C must be in pairs");
    }

    /// 7.5 — Direct-child boundary: descendants beyond one level not included.
    #[test]
    fn overlay_case_only_direct_children() {
        let (_dir, p, _project) = make_policy_with_project("proj");
        let parent = r"c:\test";
        // Direct child.
        p.record_overlay(r"c:\test\Direct_Child", r"C:\sb\direct_child").unwrap();
        p.record_overlay_case(r"c:\test\direct_child", "Direct_Child");
        // Grandchild — must NOT appear under parent.
        p.record_overlay(r"c:\test\Direct_Child\Grandchild", r"C:\sb\direct_child\grandchild").unwrap();
        p.record_overlay_case(r"c:\test\direct_child\grandchild", "Grandchild");

        let pairs = p.overlay_children_with_case(parent);
        assert_eq!(pairs.len(), 1, "only direct child; grandchild must be excluded, got: {:?}", pairs);
        assert_eq!(pairs[0].1, "Direct_Child");
    }
}
