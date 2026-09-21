//! Source-layout rules, enforced as a test.
//!
//! Two rules, set by the repository owner:
//!
//!   1. no source file exceeds [`MAX_FILE_LINES`] lines;
//!   2. no directory holds more than [`MAX_DIR_ENTRIES`] entries.
//!
//! They exist to keep files readable and directories navigable. A rule that
//! is only written down drifts back the moment someone is in a hurry, so it
//! lives here instead — as something that fails a build.
//!
//! Scope is the Rust workspace (`winrsbox/`), not the whole repository. The
//! repository root is exempt by decision: `README.md`, `LICENSE-*`,
//! `.gitignore`, `.gitattributes` and `.github/` have to sit there or GitHub
//! stops recognising them, so "at most seven" is unreachable without breaking
//! something real. Everything that CAN leave the root has been moved out; see
//! `EXEMPT_DIRS`.

use std::path::{Path, PathBuf};

/// Longest a source file may be. Beyond this the file becomes a directory:
/// `foo.rs` → `foo/mod.rs` plus submodules.
pub const MAX_FILE_LINES: usize = 1000;

/// Most entries a directory may hold. Beyond this the contents are grouped
/// into sub-directories by meaning.
pub const MAX_DIR_ENTRIES: usize = 7;

/// Directories never descended into: build output and scratch space, none of
/// it authored.
const SKIP_DIRS: &[&str] = &["target", "worktrees", ".git", "node_modules"];

/// Paths (relative to the repository root) exempt from the directory rule,
/// each with the reason. An exemption is a decision, not an oversight, so it
/// is listed explicitly and carries its justification.
const EXEMPT_DIRS: &[(&str, &str)] = &[(
    "",
    "repository root — README.md, LICENSE-*, .gitignore, .gitattributes and \
     .github/ must live here for GitHub to recognise them",
)];

/// File extensions the line-count rule applies to.
const SOURCE_EXTENSIONS: &[&str] = &["rs"];

/// The repository root: three levels up from this crate's manifest
/// (`<root>/winrsbox/crates/winrsbox-layout-guard`).
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("layout-guard lives at <root>/winrsbox/crates/winrsbox-layout-guard")
        .to_path_buf()
}

/// A file longer than the limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OversizedFile {
    pub path: String,
    pub lines: usize,
}

/// A directory holding more entries than the limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrowdedDir {
    pub path: String,
    pub entries: usize,
}

fn is_exempt(rel: &str) -> bool {
    EXEMPT_DIRS.iter().any(|(p, _)| *p == rel)
}

fn rel_to_root(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Walk `dir` (recursively) collecting both kinds of violation.
///
/// Returns them rather than asserting, so the same walk can be used by a
/// test, by a report, and — importantly — by a test that checks the checker
/// itself still detects a violation.
pub fn scan(root: &Path, dir: &Path) -> (Vec<OversizedFile>, Vec<CrowdedDir>) {
    let mut oversized = Vec::new();
    let mut crowded = Vec::new();
    let mut stack = vec![dir.to_path_buf()];

    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else { continue };
        let mut visible = 0usize;

        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            visible += 1;

            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let is_source = path
                .extension()
                .map(|e| SOURCE_EXTENSIONS.contains(&&*e.to_string_lossy()))
                .unwrap_or(false);
            if !is_source {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else { continue };
            let lines = text.lines().count();
            if lines > MAX_FILE_LINES {
                oversized.push(OversizedFile { path: rel_to_root(root, &path), lines });
            }
        }

        let rel = rel_to_root(root, &current);
        if visible > MAX_DIR_ENTRIES && !is_exempt(&rel) {
            crowded.push(CrowdedDir { path: rel, entries: visible });
        }
    }

    oversized.sort_by(|a, b| b.lines.cmp(&a.lines));
    crowded.sort_by(|a, b| b.entries.cmp(&a.entries));
    (oversized, crowded)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The workspace must satisfy both rules.
    ///
    /// The message lists every violator with its size, because "layout rule
    /// violated" without the list is a puzzle rather than a report.
    #[test]
    fn workspace_layout_obeys_both_rules() {
        let root = repo_root();
        let (oversized, crowded) = scan(&root, &root.join("winrsbox"));

        let mut problems = String::new();
        if !oversized.is_empty() {
            problems.push_str(&format!(
                "\n{} file(s) over {MAX_FILE_LINES} lines — each must become a \
                 directory (foo.rs -> foo/mod.rs + submodules):\n",
                oversized.len(),
            ));
            for f in &oversized {
                problems.push_str(&format!("  {:>6}  {}\n", f.lines, f.path));
            }
        }
        if !crowded.is_empty() {
            problems.push_str(&format!(
                "\n{} director(ies) over {MAX_DIR_ENTRIES} entries — group the \
                 contents into sub-directories by meaning:\n",
                crowded.len(),
            ));
            for d in &crowded {
                problems.push_str(&format!("  {:>6}  {}\n", d.entries, d.path));
            }
        }
        assert!(problems.is_empty(), "{problems}");
    }

    /// The checker has to be able to fail, or its green is worthless. Build a
    /// throwaway tree that breaks both rules and confirm both are reported.
    #[test]
    fn scan_detects_both_kinds_of_violation() {
        let base = std::env::temp_dir().join("layout-guard-selftest");
        let _ = std::fs::remove_dir_all(&base);
        let deep = base.join("crowded");
        std::fs::create_dir_all(&deep).expect("create probe tree");

        // Rule 1: one file over the line limit.
        let long = base.join("too_long.rs");
        std::fs::write(&long, "// line\n".repeat(MAX_FILE_LINES + 1)).unwrap();
        // Rule 2: one directory over the entry limit.
        for i in 0..=MAX_DIR_ENTRIES {
            std::fs::write(deep.join(format!("f{i}.txt")), "x").unwrap();
        }

        let (oversized, crowded) = scan(&base, &base);
        let _ = std::fs::remove_dir_all(&base);

        assert_eq!(oversized.len(), 1, "expected exactly one oversized file");
        assert_eq!(oversized[0].lines, MAX_FILE_LINES + 1);
        assert!(oversized[0].path.ends_with("too_long.rs"));
        assert_eq!(crowded.len(), 1, "expected exactly one crowded directory");
        assert_eq!(crowded[0].entries, MAX_DIR_ENTRIES + 1);
        assert!(crowded[0].path.ends_with("crowded"));
    }

    /// A file exactly at the limit passes; the rule is "no more than", not
    /// "fewer than".
    #[test]
    fn limits_are_inclusive() {
        let base = std::env::temp_dir().join("layout-guard-boundary");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("exact.rs"), "// line\n".repeat(MAX_FILE_LINES)).unwrap();
        for i in 0..(MAX_DIR_ENTRIES - 1) {
            std::fs::write(base.join(format!("p{i}.txt")), "x").unwrap();
        }
        let (oversized, crowded) = scan(&base, &base);
        let _ = std::fs::remove_dir_all(&base);
        assert!(oversized.is_empty(), "{MAX_FILE_LINES} lines is allowed: {oversized:?}");
        assert!(crowded.is_empty(), "{MAX_DIR_ENTRIES} entries is allowed: {crowded:?}");
    }

    /// Build output is not authored and must never be counted — `target/`
    /// alone would otherwise swamp the report with thousands of entries.
    #[test]
    fn build_output_is_not_scanned() {
        let base = std::env::temp_dir().join("layout-guard-skip");
        let _ = std::fs::remove_dir_all(&base);
        let target = base.join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("huge.rs"), "// line\n".repeat(MAX_FILE_LINES + 500)).unwrap();
        for i in 0..20 {
            std::fs::write(target.join(format!("x{i}.txt")), "x").unwrap();
        }
        let (oversized, crowded) = scan(&base, &base);
        let _ = std::fs::remove_dir_all(&base);
        assert!(oversized.is_empty(), "target/ must be skipped: {oversized:?}");
        assert!(crowded.is_empty(), "target/ must be skipped: {crowded:?}");
    }

    /// Every exemption carries a reason. An entry without one is an oversight
    /// wearing the costume of a decision.
    #[test]
    fn every_exemption_is_justified() {
        for (path, reason) in EXEMPT_DIRS {
            assert!(
                reason.len() > 20,
                "exemption for {path:?} needs a real justification, got {reason:?}",
            );
        }
    }
}
