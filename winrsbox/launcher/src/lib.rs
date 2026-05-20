// winrsbox library — exposes CLI modules for benchmarking and testing.
// The main binary lives in main.rs and uses these modules via `mod cli;`.

pub mod cli;
pub mod env_guard;
pub mod etw;
pub mod etw_listener;
pub mod hot_stats;
pub mod jobctl;
pub mod jsonl_log;
pub mod mitigations;
pub mod trust;
pub mod wfp;
