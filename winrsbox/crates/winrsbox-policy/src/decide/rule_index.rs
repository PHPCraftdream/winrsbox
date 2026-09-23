//! Precompiled rule-matching index for `Snapshot`.
//!
//! Built once per snapshot load (`Snapshot::load_from_db`), the index
//! precompiles the three things `best_explicit_rule_match` used to recompute
//! on every decision for every rule:
//!
//! * pattern segments — `pattern.split('\\')` with empty segments dropped
//!   (FILTERED — exactly the split `path::pattern_matches_prefix` redid per
//!   rule per decision), enabling an O(L) trie walk for literal rules;
//! * total specificity — `pattern_specificity(pattern)` plus the `when`
//!   bonuses (`+1` for a present `when`, plus `pattern_specificity(exe)`
//!   for a present `when.exe`), previously recomputed per matching rule;
//! * `when` filter data — the depth minimum, and the exe pattern lowered at
//!   load (`ensure_lower` is the deterministic canonical NTFS-identity fold,
//!   so lowering at load is deterministic and safe) and split UNFILTERED,
//!   because
//!   `path::pattern_matches_exact` — unlike the prefix matcher — does NOT
//!   drop empty segments. The request path/exe are split exactly once per
//!   decision and every candidate reuses those segments.
//!
//! Complexity contract, honestly stated: literal rules (no `*`/`?` in any
//! filtered segment) are resolved by the trie in O(L) plus O(candidates);
//! wildcard rules are NOT indexed — all of them are appended as candidates
//! on every decision, and each wildcard candidate is RE-CHECKED per
//! decision by the caller with `path::prefix_match` against the rule's
//! precompiled segments (`CompiledRule::segs`, already FILTERED) — the
//! same backtracking algorithm (globstar semantics included) that the old
//! `pattern_matches_prefix` ran, but fed from precompiled segments instead
//! of re-splitting the pattern: zero allocation, per-rule match cost
//! unchanged. Trie candidates, by contrast, match by construction — the
//! trie walk itself proves their filtered segments are a segment-prefix of
//! the path, so they never need the re-check. `CompiledRule::wildcard`
//! records which side a rule landed on: true iff the rule went to the
//! wildcard list.
//!
//! Candidate order: trie hits are harvested in path order (each trie node's
//! rule list is ascending because rules are inserted in table order), then
//! all wildcard indices are appended. The combined order is NOT globally
//! sorted — the caller's tie-break comparator (`spec > best || (spec ==
//! best && idx < best_idx)`) resolves the winner identically for ANY
//! candidate order, which is provably equivalent to the old in-order
//! strict-`>` scan.

use super::SnapshotRule;
use crate::{ensure_lower, path};

/// One rule precompiled at snapshot-load time.
///
/// The two segment fields encode the FILTERED-vs-UNFILTERED distinction:
/// `segs` mirrors `path::pattern_matches_prefix` (empty segments dropped),
/// while `when_exe_segs` mirrors `path::pattern_matches_exact` (empty
/// segments KEPT — an exe pattern like `"a\\"` must fail against `"a"`).
pub(crate) struct CompiledRule {
    /// FILTERED pattern segments (`split('\\')`, empties dropped).
    pub(crate) segs: Box<[Box<str>]>,
    /// Precomputed total specificity: `pattern_specificity(pattern)`, plus
    /// `+1` when `when` is present, plus `pattern_specificity(exe)` when
    /// `when.exe` is present — arithmetic identical to the old decide-time
    /// computation (the exe bonus uses the ORIGINAL exe string, like the old
    /// code, which lowercased only for matching).
    pub(crate) spec: usize,
    /// `when.depth` (`None` when there is no `when` or no depth bound).
    pub(crate) when_min_depth: Option<u8>,
    /// `when.exe`, lowered at load and split UNFILTERED (`None` when absent).
    pub(crate) when_exe_segs: Option<Box<[Box<str>]>>,
    /// True iff the rule went to the wildcard list — trie candidates are
    /// exact by construction, wildcard candidates need the re-check.
    pub(crate) wildcard: bool,
}

/// Trie over literal rules + flat list of wildcard rules for a `Snapshot`.
pub(crate) struct RuleIndex {
    /// Precompiled rules, indexed by global rule idx == index into
    /// `Snapshot.rules`.
    compiled: Vec<CompiledRule>,
    /// Literal rules, keyed by filtered pattern segments. Zero-segment
    /// patterns (e.g. `"\\\\"`, which filters to nothing and matches every
    /// path) land in `root.rules`.
    root: TrieNode,
    /// Global indices of wildcard rules, ascending (rules are evaluated per
    /// decision; they cannot live in the literal trie).
    wildcards: Vec<usize>,
}

#[derive(Default)]
struct TrieNode {
    /// Global indices of rules whose filtered pattern ends exactly at this
    /// node; ascending because insertion follows table order.
    rules: Vec<usize>,
    children: rustc_hash::FxHashMap<Box<str>, TrieNode>,
}

impl RuleIndex {
    /// Build the index over `rules` (order defines the global rule idx used
    /// for tie-breaks and `compiled` lookups).
    pub(crate) fn build(rules: &[SnapshotRule]) -> RuleIndex {
        let mut index = RuleIndex {
            compiled: Vec::with_capacity(rules.len()),
            root: TrieNode::default(),
            wildcards: Vec::new(),
        };
        for (idx, sr) in rules.iter().enumerate() {
            // FILTERED split — same shape pattern_matches_prefix rebuilds for
            // every rule on every decision today.
            let segs: Box<[Box<str>]> = sr
                .pattern
                .split('\\')
                .filter(|s| !s.is_empty())
                .map(Box::<str>::from)
                .collect();
            let mut spec = path::pattern_specificity(&sr.pattern);
            if sr.row.when.is_some() { spec += 1; }
            if let Some(exe) = sr.row.when.as_ref().and_then(|w| w.exe.as_deref()) {
                spec += path::pattern_specificity(exe);
            }
            let when_min_depth = sr.row.when.as_ref().and_then(|w| w.depth);
            let when_exe_segs = sr
                .row
                .when
                .as_ref()
                .and_then(|w| w.exe.as_deref())
                .map(|exe| {
                    // UNFILTERED split — pattern_matches_exact keeps empty
                    // segments. Pre-lowered: ensure_lower is the
                    // deterministic canonical NTFS-identity fold, so this is
                    // exactly the value the old code recomputed per decision.
                    ensure_lower(exe)
                        .split('\\')
                        .map(Box::<str>::from)
                        .collect::<Box<[Box<str>]>>()
                });
            // A pattern contains a wildcard char iff any FILTERED segment
            // does: filtering only drops empty segments, which can never
            // carry `*`/`?` — so this classification is exact. Computed into
            // a local BEFORE `CompiledRule` construction so the flag lands
            // in the struct that `compiled.push` stores below.
            let wildcard = segs.iter().any(|s| s.contains('*') || s.contains('?'));
            let compiled =
                CompiledRule { segs, spec, when_min_depth, when_exe_segs, wildcard };
            if wildcard {
                index.wildcards.push(idx);
            } else {
                let mut node = &mut index.root;
                for seg in compiled.segs.iter() {
                    node = node.children.entry(seg.clone()).or_default();
                }
                node.rules.push(idx);
            }
            index.compiled.push(compiled);
        }
        index
    }

    /// Collect candidate rule indices for an already-FILTERED request path
    /// (the caller splits `lower_path` once and passes the segments here).
    ///
    /// Returns trie hits along the path (a literal rule matches iff its
    /// filtered segments are a segment-prefix of the path, so matching rules
    /// sit exactly on the nodes from the root down), then all wildcard
    /// indices. The result is NOT globally sorted; the caller's
    /// `(spec, idx)` comparator handles tie-breaks order-independently.
    pub(crate) fn candidate_indices(&self, path_segs: &[&str]) -> Vec<usize> {
        let mut out = Vec::new();
        // Iterative trie walk — no recursion, stops at the first missing
        // child (deeper literal rules cannot match a shorter prefix).
        out.extend_from_slice(&self.root.rules);
        let mut node = &self.root;
        for seg in path_segs {
            match node.children.get(*seg) {
                Some(child) => {
                    out.extend_from_slice(&child.rules);
                    node = child;
                }
                None => break,
            }
        }
        // Wildcard rules are always candidates; the caller re-checks each one
        // per decision (flagged by `CompiledRule::wildcard`) with
        // `path::prefix_match` on the rule's precompiled segments.
        out.extend_from_slice(&self.wildcards);
        out
    }

    /// The precompiled form of global rule `idx` (== index into
    /// `Snapshot.rules`).
    pub(crate) fn compiled(&self, idx: usize) -> &CompiledRule {
        &self.compiled[idx]
    }
}
