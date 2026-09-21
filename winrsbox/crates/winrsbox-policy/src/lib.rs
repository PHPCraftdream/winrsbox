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
pub use domains::{dev, mem, net, scan};
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
mod tests;
