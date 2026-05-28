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
    if s.bytes().all(|b| !b.is_ascii_uppercase()) {
        std::borrow::Cow::Borrowed(s)
    } else {
        std::borrow::Cow::Owned(s.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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
}
