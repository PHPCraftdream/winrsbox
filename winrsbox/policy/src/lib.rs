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
}
