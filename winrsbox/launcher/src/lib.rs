// winrsbox library — exposes CLI modules for benchmarking and testing.
// The main binary lives in main.rs and uses these modules via `mod cli;`.

pub mod cli;
pub mod etw;
pub mod jobctl;
pub mod mitigations;
pub mod wfp;
