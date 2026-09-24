pub mod path;
pub mod db;
pub use registry::reg;
pub use registry::reg_overlay;

pub(crate) mod decide;
pub(crate) mod registry;
pub(crate) mod domains;

use thiserror::Error;

pub use decide::{Decision, Mode, Verdict, ConsideredRule, TracedDecision, OverlayChildMeta};
pub use policy_impl::Policy;
pub use registry::{RegDecision, RegistryPolicy};
pub use domains::{dev, mem, net, pe_cache, scan};
pub(crate) use domains::policy_impl;
pub(crate) use path::trim_trailing_sep;

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

pub fn ensure_lower(s: &str) -> std::borrow::Cow<'_, str> {
    // Canonical NTFS-identity fold: kernel upcase/downcase tables via ntdll
    // (path::case_fold) — the one fold every policy key and hook-side path
    // comparison shares. Rust's locale-aware to_lowercase() is NOT used: it
    // diverges from NTFS identity (full-mapping expansions, locale rules),
    // which would let differently-folded spellings of the same file produce
    // different keys. The ASCII fast path is byte-for-byte the historic
    // ASCII-only fold, so all persisted lowercase-ASCII keys stay identical
    // (no db migration).
    path::nt_case_fold(s)
}

#[cfg(test)]
mod tests;
