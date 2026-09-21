//! Shared artifact lookup for the integration suites.
//!
//! These tests drive the real launcher and inject the real `hook.dll`, so the
//! artifacts they pick ARE the system under test. Choosing them wrongly does
//! not fail the run — it silently validates something else.
//!
//! That happened. Every suite used to resolve a binary by trying
//! `target/release` first and falling back to `target/debug`, returning the
//! first that existed. A machine with stale release artifacts therefore ran
//! `cargo test` (a debug build) against a release launcher and hook from an
//! earlier commit: the whole 2026-09-19 hardening pass lived only in debug
//! while the integration suite kept exercising, and passing against, the
//! binaries from before it. Four separate P0 regressions — copy-on-write
//! refusing every write outside `project_root`, named pipes and console
//! opens denied, `--guard static` unable to launch anything, and every
//! target exiting 0xC0000005 — went unnoticed through a green suite, even
//! though the coverage for the first of them was already there and correct
//! (`memory_guard.rs` asserts a CoW write both misses the real disk and
//! reaches the overlay).
//!
//! So: pick the profile this test binary was itself built with, never fall
//! back to the other one, and refuse to run against an artifact older than
//! the sources. A loud failure telling the operator to rebuild is always
//! better than a green run that proves nothing.
//!
//! Practical consequence, and the reason the staleness check earns its keep:
//! `cargo test` does NOT refresh `target/<profile>/winrsbox.exe`. It compiles
//! the bin target as a test harness into `deps/`, which leaves the standalone
//! executable these tests launch at whatever the last `cargo build` produced.
//! Run `cargo build --workspace` first, or the suite is testing the previous
//! launcher — silently, before this check existed.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// The profile these tests must exercise: the one they were compiled with.
/// `cargo test` → debug, `cargo test --release` → release. Cargo builds the
/// workspace binaries with the same profile in the same invocation, so the
/// matching artifacts are the ones it just produced.
pub fn artifact_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

/// Workspace root (`…/winrsbox`). This crate's manifest lives at
/// `…/winrsbox/crates/winrsbox-integration-tests`, so the root is two levels up.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("integration-tests manifest dir is <root>/crates/<crate>")
        .to_path_buf()
}

/// Resolve the workspace target dir, respecting `CARGO_TARGET_DIR` (set when
/// the workspace uses a non-default target dir) and falling back to
/// `<workspace>/target` for the standard in-tree layout.
pub fn target_dir() -> PathBuf {
    std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root().join("target"))
}

/// The crates whose sources force a rebuild of `file_name`.
///
/// Deliberately not "the whole workspace": Cargo does not relink an artifact
/// whose own inputs are unchanged, so comparing every binary against every
/// source would report a stale launcher merely because the hook was edited.
/// These are the real input sets — if any of them changes, Cargo rebuilds the
/// artifact, so an older mtime genuinely means "not rebuilt".
fn source_crates_for(file_name: &str) -> &'static [&'static str] {
    // Crate directory names under `<workspace>/crates/`.
    match file_name {
        "winrsbox.exe" => &["winrsbox-launcher", "winrsbox-policy", "winrsbox-ipc"],
        "hook.dll" => &["winrsbox-hook", "winrsbox-policy", "winrsbox-ipc"],
        // Everything else here is an integration-test payload binary.
        _ => &["winrsbox-integration-tests", "winrsbox-policy", "winrsbox-ipc"],
    }
}

/// Newest modification time across the given crates' Rust sources.
fn newest_source_mtime(crates: &[&str]) -> Option<SystemTime> {
    let root = workspace_root();
    let mut newest: Option<SystemTime> = None;
    let mut stack: Vec<PathBuf> = crates
        .iter()
        .map(|c| root.join("crates").join(c).join("src"))
        .inspect(|p| {
            // A mistyped crate path would silently vanish here and leave the
            // freshness check with nothing to compare — the exact "silently
            // green" failure this whole module exists to prevent. Fail loudly.
            assert!(p.exists(), "source dir does not exist: {}", p.display());
        })
        .collect();
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().map(|e| e != "rs").unwrap_or(true) {
                continue;
            }
            if let Ok(modified) = entry.metadata().and_then(|m| m.modified()) {
                if newest.map(|n| modified > n).unwrap_or(true) {
                    newest = Some(modified);
                }
            }
        }
    }
    newest
}

/// Panic if `artifact` predates the newest workspace source. Silence here is
/// what let a stale binary masquerade as the system under test.
fn assert_not_stale(artifact: &Path, file_name: &str) {
    let crates = source_crates_for(file_name);
    let (Ok(meta), Some(newest_src)) = (std::fs::metadata(artifact), newest_source_mtime(crates))
    else {
        return; // Cannot tell — do not invent a failure.
    };
    let Ok(built) = meta.modified() else { return };
    if built >= newest_src {
        return;
    }
    panic!(
        "{} is older than the workspace sources — it is NOT the code under test.\n\
         Rebuild with the profile these tests were compiled for:\n\
         \x20   cargo build --workspace{}\n\
         (A stale artifact once let four P0 regressions pass a green suite; see\n\
         tests/common/mod.rs.)",
        artifact.display(),
        if artifact_profile() == "release" { " --release" } else { "" },
    );
}

/// Absolute path to a workspace binary built with this test's own profile.
/// Never falls back to the other profile.
pub fn find_binary(name: &str) -> PathBuf {
    find_artifact(&format!("{name}.exe"))
}

pub fn find_launcher() -> PathBuf {
    find_binary("winrsbox")
}

pub fn find_hook_dll() -> PathBuf {
    find_artifact("hook.dll")
}

fn find_artifact(file_name: &str) -> PathBuf {
    let profile = artifact_profile();
    let path = target_dir().join(profile).join(file_name);
    assert!(
        path.exists(),
        "{} not found under target/{profile} — build the workspace with the \
         profile these tests were compiled for before running them",
        path.display(),
    );
    assert_not_stale(&path, file_name);
    path
}
