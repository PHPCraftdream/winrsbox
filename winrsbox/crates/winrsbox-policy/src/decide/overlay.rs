use super::*;

impl Policy {
    /// Decide what to do with a DOS path (legacy — no depth/exe context).
    pub fn decide(&self, dos_path: &str, write_access: bool) -> Decision {
        self.decide_with_context(dos_path, write_access, None, None)
    }

    /// Decide with optional depth and exe context for when-filter support.
    pub fn decide_with_context(
        &self,
        dos_path: &str,
        write_access: bool,
        depth: Option<u8>,
        exe_lower: Option<&str>,
    ) -> Decision {
        // Fold `.`/`..` lexically BEFORE the decision (audit Critical #1):
        // containment is a prefix test, and `d:\<root>\..\..\x` prefix-matches
        // the root when left unfolded while the kernel resolves it outside.
        // After folding, the path policy decides on is the path the kernel
        // will act on.
        let lower = ensure_lower(dos_path);
        let folded = path::fold_dos_dots(&lower);
        let key = cache_key(&folded, write_access, depth, exe_lower);
        if let Some(d) = self.inner.cache.get(&key) {
            return (*d).clone();
        }
        let d = self.compute(&folded, write_access, depth, exe_lower);
        self.inner.cache.insert(key, Arc::new(d.clone()));
        d
    }

    pub fn record_overlay(&self, orig: &str, overlay: &str) -> Result<(), PolicyError> {
        let txn = self.inner.db.begin_write()?;
        {
            let mut t = txn.open_table(db::OVERLAY_IDX)?;
            // Normalize trailing separators (create-at-`d:\foo\` vs open-at-
            // `d:\foo`) so the index key matches the lookup path used in
            // `compute`. Without this, a directory created with a trailing
            // separator disappears from later readers.
            let lower = ensure_lower(orig);
            let key = trim_trailing_sep(&lower);
            t.insert(key, overlay)?;
        }
        txn.commit()?;
        // Invalidate cache entries for all possible (depth, exe) combos for this path.
        // We can't know which combos are cached, so invalidate with None context
        // (the default-lookup key) — sufficient because record_overlay only runs
        // after a write decision, which uses the process's actual context.
        // For safety, we clear the entire cache on overlay recording (rare event).
        self.inner.cache.clear();
        Ok(())
    }

    /// Server-side validation of a guest-supplied `Req::RecordOverlay`
    /// (audit 2026-09-19 Critical #2). A legitimate hook can only ever name
    /// the destination the sandbox itself would have chosen: `overlay` must
    /// equal `mirror(orig)` — either the same-volume overlay-layout mirror or
    /// the mock-dirs mirror (mock-dir Cow decisions record there) — and live
    /// inside the corresponding launcher-owned root.
    ///
    /// The root-containment gate is checked first and fails closed on empty
    /// values, unfolded `.`/`..` segments and sibling-prefix lookalikes
    /// (`<root>evil\...`); the identity check against both canonical mirrors
    /// is the binding rule. Everything else is an escape attempt, not a
    /// mistake, and must be rejected before it reaches `OVERLAY_IDX`.
    pub fn validate_record_overlay(&self, orig: &str, overlay: &str) -> bool {
        let guest = ensure_lower(overlay);
        let guest_trim = trim_trailing_sep(&guest);
        if guest_trim.is_empty() {
            return false;
        }
        // Fail closed on unfolded dot segments (see `path_contained_in`):
        // containment is a prefix test and the kernel resolves `..` outside it.
        if guest_trim.split(|c| c == '\\' || c == '/').any(|seg| seg == "." || seg == "..") {
            return false;
        }

        // Containment in launcher-owned territory: the published overlay
        // roots and the mock-dirs root.
        let overlay_roots = self.inner.overlay_layout.all_roots().map(|(_, r)| {
            trim_trailing_sep(&ensure_lower(&r.to_string_lossy())).to_owned()
        });
        let mock_root = trim_trailing_sep(
            &ensure_lower(&self.inner.mock_dirs_root.to_string_lossy()),
        )
        .to_owned();
        let contained = overlay_roots
            .chain(std::iter::once(mock_root))
            .any(|root| !root.is_empty() && path_contained_in(guest_trim, &root));
        if !contained {
            return false;
        }

        // Identity: the value must be exactly the destination the sandbox
        // itself would choose for `orig`.
        let key_lower = ensure_lower(orig);
        let key = trim_trailing_sep(&key_lower);
        let overlay_mirror =
            path::mirror_into_overlay_layout(key, &self.inner.overlay_layout);
        let mock_mirror = path::mirror_into_overlay(key, &self.inner.mock_dirs_root);
        let matches_mirror = [&overlay_mirror, &mock_mirror].into_iter().any(|m| {
            guest_trim == trim_trailing_sep(&ensure_lower(&m.to_string_lossy()))
        });
        matches_mirror
    }

    /// Record the original-case basename for an overlay entry.
    ///
    /// Writes to `OVERLAY_CASE` using the same lowercase-virtual-path key
    /// as `OVERLAY_IDX`. The value is the caller-supplied original-case
    /// basename (e.g. `"Mixed_Case_Dir"`). No-op if `original_basename` is
    /// empty or already lowercase (nothing to preserve).
    ///
    /// This method is intentionally infallible from the caller's perspective:
    /// failure to record case is non-fatal — the hook's `build_case_map`
    /// falls back to real-disk enumeration for entries without a case record.
    pub fn record_overlay_case(&self, lower_path: &str, original_basename: &str) {
        if original_basename.is_empty() {
            return;
        }
        // Only worth storing when case differs from lowercase (optimization).
        if original_basename == original_basename.to_ascii_lowercase() {
            return;
        }
        let key = trim_trailing_sep(lower_path);
        let _ = (|| -> Result<(), PolicyError> {
            let txn = self.inner.db.begin_write()?;
            {
                let mut t = txn.open_table(db::OVERLAY_CASE)?;
                t.insert(key, original_basename)?;
            }
            txn.commit()?;
            Ok(())
        })();
    }

    /// Return `(lowercase_name, original_case_name)` pairs for all direct
    /// children of `dir` that have a recorded original-case basename in
    /// `OVERLAY_CASE`.
    ///
    /// `dir` must be the lowercase virtual DOS path of the parent directory
    /// (e.g. `c:\localappdata\uv\cache\builds-v0\.tmpXXXXXX`). Only
    /// DIRECT children (single path segment beyond `dir\`) are returned.
    ///
    /// Returns an empty Vec on any error or when no children with case
    /// records exist.
    pub fn overlay_children_with_case(&self, dir: &str) -> Vec<(String, String)> {
        let dir_lower = ensure_lower(dir);
        let dir_trimmed = dir_lower.trim_end_matches('\\');
        if dir_trimmed.is_empty() {
            return Vec::new();
        }
        let prefix_with_sep = format!("{}\\", dir_trimmed);
        let Ok(txn) = self.inner.db.begin_read() else { return Vec::new() };
        let Ok(t) = txn.open_table(db::OVERLAY_CASE) else { return Vec::new() };
        let mut out = Vec::new();
        let iter = if let Ok(iter) = t.range(prefix_with_sep.as_str()..) {
            iter
        } else {
            return Vec::new();
        };
        for entry in iter.flatten() {
            let key = entry.0.value();
            let Some(rest) = key.strip_prefix(&prefix_with_sep) else { break };
            // Direct children only — no further backslash.
            if rest.contains('\\') {
                continue;
            }
            let original_name = entry.1.value().to_owned();
            out.push((rest.to_owned(), original_name));
        }
        out
    }

    /// Return metadata for ALL overlay entries (OVERLAY_IDX) that are direct
    /// children of `dir`, regardless of whether an OVERLAY_CASE record exists
    /// (unlike `overlay_children_with_case`, which only reports entries with
    /// a recorded original-case basename).
    ///
    /// Used by the enum-hook to inject overlay-only files/directories into a
    /// real directory's listing — the merge `physical_overlay_path`'s doc
    /// comment defers to enumeration for "passthrough directory with sparse
    /// overlay children" (a CoW write outside `project_root` into a
    /// directory that also exists on the real disk).
    pub fn overlay_children(&self, dir: &str) -> Vec<OverlayChildMeta> {
        let dir_lower = ensure_lower(dir);
        let dir_trimmed = dir_lower.trim_end_matches('\\');
        if dir_trimmed.is_empty() {
            return Vec::new();
        }
        let prefix_with_sep = format!("{}\\", dir_trimmed);
        let Ok(txn) = self.inner.db.begin_read() else { return Vec::new() };
        let Ok(idx) = txn.open_table(db::OVERLAY_IDX) else { return Vec::new() };
        // OVERLAY_CASE is created lazily on the first `record_overlay_case`
        // write — a DB with only lowercase-created overlay entries never
        // touches it. Missing table just means "no case records anywhere",
        // not "bail out": every entry falls back to its lowercase key.
        let case = txn.open_table(db::OVERLAY_CASE).ok();

        let mut out = Vec::new();
        let Ok(iter) = idx.range(prefix_with_sep.as_str()..) else { return Vec::new() };
        for entry in iter.flatten() {
            let key = entry.0.value();
            let Some(rest) = key.strip_prefix(&prefix_with_sep) else { break };
            // Direct children only — no further backslash.
            if rest.contains('\\') {
                continue;
            }
            let overlay_phys = entry.1.value();
            let (is_dir, size, creation_time, last_access_time, last_write_time) =
                stat_overlay_phys(overlay_phys);
            let name = case.as_ref()
                .and_then(|t| t.get(key).ok().flatten())
                .map(|v| v.value().to_owned())
                .unwrap_or_else(|| rest.to_owned());
            out.push(OverlayChildMeta {
                name, is_dir, size, creation_time, last_access_time, last_write_time,
            });
        }
        out
    }

    /// Record a whiteout (delete-marker / tombstone) for `path`. The real
    /// lower file is never touched; the marker only hides the path from the
    /// sandbox's merged view. Keyed on the ASCII-lowercased virtual DOS path.
    /// Clears the entire decide-cache (same conservative approach as
    /// `record_overlay`) so subsequent `decide` calls observe the marker.
    pub fn record_whiteout(&self, path: &str) -> Result<(), PolicyError> {
        let lower_raw = ensure_lower(path);
        let lower = trim_trailing_sep(&lower_raw);
        let txn = self.inner.db.begin_write()?;
        {
            let mut t = txn.open_table(db::WHITEOUTS)?;
            t.insert(lower, ())?;
        }
        txn.commit()?;
        self.inner.cache.clear();
        Ok(())
    }

    /// Remove a whiteout marker for `path` (revive). Called when a create at a
    /// whiteouted path re-materialises the file in the overlay.
    ///
    /// Also removes all descendent whiteouts (paths under `path\`). This is
    /// the OverlayFS revival semantic: re-creating a parent directory implies a
    /// clean slate for its entire subtree. Without this, a retry-clone scenario
    /// where a failed SSH clone whiteouts both the parent dir and all its
    /// children (`.git`, `.git\config`, …) leaves the children permanently
    /// hidden even after the parent is re-created by the HTTPS retry, because
    /// git opens `.git` with FILE_OPEN (not FILE_CREATE), bypassing the
    /// per-path revive gate (bug #78).
    pub fn clear_whiteout(&self, path: &str) -> Result<(), PolicyError> {
        let lower_raw = ensure_lower(path);
        let lower = trim_trailing_sep(&lower_raw);
        let txn = self.inner.db.begin_write()?;
        {
            let mut t = txn.open_table(db::WHITEOUTS)?;
            // Remove exact entry.
            t.remove(lower)?;
            // Remove all descendant entries: keys with prefix `lower\`.
            let prefix = format!("{}\\", lower);
            let child_keys: Vec<String> = t
                .range(prefix.as_str()..)
                .map(|iter| {
                    iter.flatten()
                        .map(|(k, _v)| k.value().to_owned())
                        .take_while(|k| k.starts_with(&prefix))
                        .collect()
                })
                .unwrap_or_default();
            for k in child_keys {
                t.remove(k.as_str())?;
            }
        }
        txn.commit()?;
        self.inner.cache.clear();
        Ok(())
    }

    /// Remove an OVERLAY_IDX entry for `path`. Called by the delete hook when
    /// it physically deletes an overlay copy: the overlay file is gone, so the
    /// index must not keep pointing at it (otherwise `compute` would treat a
    /// whiteouted path as "revived" and fall through to the now-missing
    /// overlay, surfacing the real lower file instead of Hidden).
    pub fn clear_overlay(&self, path: &str) -> Result<(), PolicyError> {
        let lower_raw = ensure_lower(path);
        let lower = trim_trailing_sep(&lower_raw);
        let txn = self.inner.db.begin_write()?;
        {
            let mut t = txn.open_table(db::OVERLAY_IDX)?;
            t.remove(lower)?;
        }
        txn.commit()?;
        self.inner.cache.clear();
        Ok(())
    }

    /// True iff a whiteout marker currently exists for `path`.
    pub fn is_whiteouted(&self, path: &str) -> bool {
        let lower_raw = ensure_lower(path);
        let lower = trim_trailing_sep(&lower_raw);
        let Ok(txn) = self.inner.db.begin_read() else { return false };
        let Ok(t) = txn.open_table(db::WHITEOUTS) else { return false };
        t.get(lower).ok().flatten().is_some()
    }

    /// True iff an overlay entry exists for the (already lowercased) `lower`.
    /// Used internally to distinguish a pure whiteout (Hidden) from a revived
    /// whiteout (overlay present → Cow).
    fn has_overlay(&self, lower: &str) -> bool {
        let Ok(txn) = self.inner.db.begin_read() else { return false };
        let Ok(t) = txn.open_table(db::OVERLAY_IDX) else { return false };
        t.get(lower).ok().flatten().is_some()
    }

    /// Return the set of whiteouted paths that are direct children of `dir`
    /// (i.e. `dir\<single-segment>`). Returns only the trailing segment
    /// (filename), not the full path, so the enumerate hook can match it
    /// against directory entry names. Used to hide whiteouted entries from
    /// directory listings.
    ///
    /// `dir` is matched case-insensitively and with a trailing-backslash
    /// boundary so a whiteout for `c:\foo\bar` is reported under `c:\foo`
    /// but NOT under `c:\foobar`.
    pub fn whiteouts_under(&self, dir: &str) -> Vec<String> {
        let dir_lower = ensure_lower(dir);
        let dir_trimmed = dir_lower.trim_end_matches('\\');
        if dir_trimmed.is_empty() {
            return Vec::new();
        }
        let prefix_with_sep = format!("{}\\", dir_trimmed);
        let Ok(txn) = self.inner.db.begin_read() else { return Vec::new() };
        let Ok(t) = txn.open_table(db::WHITEOUTS) else { return Vec::new() };
        // Collect direct-child whiteout keys (full lowercase virtual paths) first
        // so the later revival check can open OVERLAY_IDX in the same read txn
        // without aliasing the WHITEOUTS iterator.
        let mut candidates: Vec<String> = Vec::new();
        // range over keys >= prefix_with_sep; stop once we pass the dir's scope.
        if let Ok(iter) = t.range(prefix_with_sep.as_str()..) {
            for entry in iter.flatten() {
                let key = entry.0.value();
                // Must start with `dir\` — otherwise it's a different directory.
                let Some(rest) = key.strip_prefix(&prefix_with_sep) else { break };
                // A direct child has no further backslash. Descendants of a
                // subdirectory (e.g. `dir\sub\file`) are not direct children of
                // `dir` and must not be reported here — enumeration of `dir`
                // would list `sub`, not `file`.
                if rest.contains('\\') {
                    continue;
                }
                candidates.push(key.to_owned());
            }
        }
        // A whiteout only HIDES a name in the merged view when that name is not
        // revived by a live overlay entry. This mirrors `compute` exactly:
        // whiteout + (idx_hit || phys_hit) => Mode::Cow (VISIBLE), only a bare
        // whiteout => Mode::Hidden. Enumeration MUST agree with `compute`, or a
        // name that `compute` resolves as a live Cow file would still be hidden
        // from listings — a "ghost": invisible to enumeration yet physically
        // present in the overlay. Such ghosts arise from `RecordWhiteoutKeepOverlay`
        // (blocked physical delete, e.g. contended uv cleanup of pywin32-311.data)
        // and make the parent directory un-removable: `read_dir` reports empty,
        // so a recursive delete issues a plain `rmdir`, which the kernel rejects
        // with STATUS_DIRECTORY_NOT_EMPTY (os error 145) — or, under POSIX-
        // semantics deletes, STATUS_REPARSE_POINT_ENCOUNTERED (os error 4395) —
        // because the physical child still exists. Skipping revived names here
        // re-exposes the child so the recursive delete can drain it leaf-up.
        let idx = txn.open_table(db::OVERLAY_IDX).ok();
        let mut out = Vec::new();
        for key in candidates {
            let idx_hit = idx
                .as_ref()
                .and_then(|t| t.get(key.as_str()).ok().flatten())
                .is_some();
            let revived = idx_hit
                || physical_overlay_path(&key, &self.inner.overlay_layout).is_some();
            if revived {
                continue;
            }
            if let Some(rest) = key.strip_prefix(&prefix_with_sep) {
                out.push(rest.to_owned());
            }
        }
        out
    }

    /// Traced decision for `why` / `what-if` — no caching, full chain info.
    pub fn decide_traced(
        &self,
        dos_path: &str,
        write_access: bool,
        depth: Option<u8>,
        exe_lower: Option<&str>,
    ) -> TracedDecision {
        let lower_raw = ensure_lower(dos_path);
        let lower_owned: String =
            path::fold_dos_dots(trim_trailing_sep(&lower_raw)).into_owned();
        let lower: &str = &lower_owned;

        // project_root always passthrough
        if path_contained_in(lower, &self.inner.project_root_lower) {
            return TracedDecision {
                decision: db::RuleMode::Passthrough,
                target_path: None,
                rule_id: None,
                rule_prefix: None,
                mock_match: None,
                mockdir_match: None,
                chain: vec![],
            };
        }

        // Whiteout check mirrors `compute`: a hidden external path is reported
        // as Passthrough in the trace's RuleMode field (there is no RuleMode::Hidden
        // — Hidden is a policy::Mode only the hook layer consumes), but with an
        // empty chain and no rule so `why` shows no rule drove the decision.
        // The authoritative Mode::Hidden outcome is produced by `compute`.
        //
        // The check runs on the FOLDED path (not the raw caller string) and
        // honours compute's full revive condition — a whiteout whose overlay
        // entry is indexed OR physically materialized is a revived path and
        // falls through to the normal flow. Checking the raw string or the
        // index alone made `why` report a whiteout the engine had already
        // superseded (audit 2026-09-19 Low: decide_traced diverges from
        // compute).
        let idx_hit = self.has_overlay(&lower);
        let phys_hit = !idx_hit
            && physical_overlay_path(&lower, &self.inner.overlay_layout).is_some();
        if self.is_whiteouted(&lower) && !(idx_hit || phys_hit) {
            return TracedDecision {
                decision: db::RuleMode::Passthrough,
                target_path: None,
                rule_id: Some("whiteout".into()),
                rule_prefix: None,
                mock_match: None,
                mockdir_match: None,
                chain: vec![],
            };
        }

        let txn = match self.inner.db.begin_read() {
            Ok(t) => t,
            Err(_) => return TracedDecision {
                decision: db::RuleMode::Passthrough,
                target_path: None,
                rule_id: None,
                rule_prefix: None,
                mock_match: None,
                mockdir_match: None,
                chain: vec![],
            },
        };

        // Check mocks
        if let Some(payload) = db::find_mock_payload(&txn, &lower) {
            let _ = payload; // we know it matched
            let overlay = path::mirror_into_overlay_layout(&lower, &self.inner.overlay_layout);
            return TracedDecision {
                decision: db::RuleMode::Cow, // mocks use Cow overlay path
                target_path: Some(overlay),
                rule_id: None,
                rule_prefix: None,
                mock_match: Some(lower.to_string()),
                mockdir_match: None,
                chain: vec![],
            };
        }

        // Check mock dirs
        if let Some(matched) = db::matched_mock_dir(&txn, &lower) {
            let overlay = path::mirror_into_overlay(&lower, &self.inner.mock_dirs_root);
            return TracedDecision {
                decision: db::RuleMode::Cow,
                target_path: Some(overlay),
                rule_id: None,
                rule_prefix: None,
                mock_match: None,
                mockdir_match: Some(matched),
                chain: vec![],
            };
        }

        // Trace through rules
        let mut chain = Vec::new();
        let table = match txn.open_table(db::RULES) {
            Ok(t) => t,
            Err(_) => return TracedDecision {
                decision: db::RuleMode::Passthrough,
                target_path: None,
                rule_id: None,
                rule_prefix: None,
                mock_match: None,
                mockdir_match: None,
                chain: vec![],
            },
        };

        let mut best: Option<(usize, db::RuleRow)> = None;
        let mut best_prefix: Option<String> = None;
        let mut default_row: Option<db::RuleRow> = None;

        for entry in table.range::<&str>(..).ok().into_iter().flatten() {
            let Ok((key, value)) = entry else { continue };
            let pattern = key.value();
            if pattern.is_empty() {
                default_row = db::decode_rule(value.value());
                continue;
            }
            let Some(row) = db::decode_rule(value.value()) else { continue };

            // Check prefix match
            if !path::pattern_matches_prefix(pattern, &lower) {
                chain.push(ConsideredRule {
                    id: row.id.clone(),
                    prefix: pattern.to_owned(),
                    verdict: Verdict::Skip { reason: "prefix mismatch".into() },
                });
                continue;
            }

            // Check when filter
            if let Some(ref when) = row.when {
                if let Some(min_depth) = when.depth {
                    if depth.is_some() && depth.unwrap() < min_depth {
                        chain.push(ConsideredRule {
                            id: row.id.clone(),
                            prefix: pattern.to_owned(),
                            verdict: Verdict::Skip { reason: format!("depth filter: need >= {min_depth}"), },
                        });
                        continue;
                    }
                }
                if let Some(ref exe_pattern) = when.exe {
                    if exe_lower.is_none() || !path::pattern_matches_exact(&ensure_lower(exe_pattern), exe_lower.unwrap()) {
                        chain.push(ConsideredRule {
                            id: row.id.clone(),
                            prefix: pattern.to_owned(),
                            verdict: Verdict::Skip { reason: "exe filter mismatch".into() },
                        });
                        continue;
                    }
                }
            }

            let mut spec = path::pattern_specificity(pattern);
            if row.when.is_some() { spec += 1; }
            if let Some(ref when) = row.when {
                if let Some(ref exe) = when.exe {
                    spec += path::pattern_specificity(exe);
                }
            }

            chain.push(ConsideredRule {
                id: row.id.clone(),
                prefix: pattern.to_owned(),
                verdict: Verdict::Match { specificity: spec },
            });

            match &best {
                None => { best_prefix = Some(pattern.to_owned()); best = Some((spec, row)); }
                Some((s, _)) if spec > *s => { best_prefix = Some(pattern.to_owned()); best = Some((spec, row)); }
                _ => {}
            }
        }

        // Mirror `compute`: fold in the configured default catch-all rule so
        // `why` / `what-if` report the same decision the live path takes. With
        // no explicit match, the default rule drives the outcome (read=pass,
        // write=cow under the merged-view isolation model), and when even the
        // default is absent the fallback is the hard-coded (Passthrough, Cow)
        // pair from `compute`.
        let matched = best.map(|(_, r)| r).or(default_row);
        let (mut decision, rule_id, rule_prefix) = match &matched {
            Some(row) => {
                let mode = if write_access { row.mode_write } else { row.mode_read };
                (mode, Some(row.id.clone()), best_prefix.clone().or_else(|| Some(String::new())))
            }
            // No rule and no default: `compute` isolates an external write
            // into the overlay (Cow) and lets reads pass. Reporting plain
            // Passthrough for the write here made `why` explain a real-disk
            // write where the engine actually redirects into the overlay
            // (audit 2026-09-19 Low: decide_traced diverges from compute).
            None if write_access => (db::RuleMode::Cow, None, None),
            None => (db::RuleMode::Passthrough, None, None),
        };

        let mut target_path = match decision {
            db::RuleMode::Deny => None,
            db::RuleMode::Passthrough => None,
            db::RuleMode::Cow | db::RuleMode::Redirect => {
                Some(path::mirror_into_overlay_layout(&lower, &self.inner.overlay_layout))
            }
        };

        // Read-through: compute's Passthrough arm redirects a READ into the
        // overlay when the path was already CoW'd there — OVERLAY_IDX hit
        // first, then the physical mirror tree. Mirror both or `why` reports
        // a real-disk read for a path the engine actually serves from the
        // overlay.
        if matches!(decision, db::RuleMode::Passthrough) && !write_access {
            let idx_overlay: Option<PathBuf> = txn
                .open_table(db::OVERLAY_IDX)
                .ok()
                .and_then(|t| t.get(&*lower).ok().flatten())
                .map(|v| PathBuf::from(v.value()));
            if let Some(ov) = idx_overlay {
                decision = db::RuleMode::Cow;
                target_path = Some(ov);
            } else if let Some(ov) = physical_overlay_path(&lower, &self.inner.overlay_layout) {
                decision = db::RuleMode::Cow;
                target_path = Some(ov);
            }
        }

        TracedDecision {
            decision,
            target_path,
            rule_id,
            rule_prefix,
            mock_match: None,
            mockdir_match: None,
            chain,
        }
    }

    /// Decide the fate of a DOS path under the **merged-view overlay** model.
    ///
    /// This is the core isolation policy, conceptually identical to OverlayFS
    /// or Sandboxie's sandbox: there is exactly one place an agent may mutate
    /// the real disk (its own `project_root`); every other write is isolated
    /// inside the sandbox overlay and never reaches the real disk.
    ///
    /// | Operation            | inside `project_root`            | outside `project_root`                 |
    /// |----------------------|----------------------------------|----------------------------------------|
    /// | Read                 | passthrough (real disk)          | overlay if recorded, else real disk    |
    /// | Write / create       | passthrough (real disk)          | **CoW → overlay** (isolated)           |
    /// | Delete / rename      | passthrough (real disk)          | blocked (`ACCESS_DENIED`) in the hook  |
    ///
    /// Resolution order:
    /// 1. **`project_root` short-circuit** — the agent's own dir is always real
    ///    (passthrough), regardless of any rule. This is the only path that may
    ///    hit the real disk for writes.
    /// 2. **Mock payload / mock dir** — synthesized content, never real disk.
    /// 3. **Rule lookup** via `best_rule_match` (explicit prefix rule, else the
    ///    configured default catch-all rule). An explicit rule may force
    ///    `Deny` (block) or `Passthrough` (override the default and touch the
    ///    real disk — use sparingly).
    /// 4. **Default** when nothing matched: read = `Passthrough` (read-through
    ///    will still consult `OVERLAY_IDX` so a previously-isolated file is
    ///    seen), write = `Cow` (isolate into the overlay). This is what makes
    ///    external writes land in the sandbox instead of on the real disk.
    ///
    /// The read-through branch inside the `Passthrough` arm consults
    /// `OVERLAY_IDX` so that a file previously CoW'd into the overlay is
    /// returned from there on read — the agent sees its own isolated view.
    pub(crate) fn compute(&self, dos_path: &str, write_access: bool, depth: Option<u8>, exe_lower: Option<&str>) -> Decision {
        let lower_raw = ensure_lower(dos_path);
        // Normalize trailing separators so OVERLAY_IDX / WHITEOUTS key lookups
        // agree across create-at-`d:\foo\` and open-at-`d:\foo` callers.
        let lower_owned: std::borrow::Cow<'_, str> = match lower_raw {
            std::borrow::Cow::Borrowed(b) => {
                let t = trim_trailing_sep(b);
                if std::ptr::eq(t.as_ptr(), b.as_ptr()) && t.len() == b.len() {
                    std::borrow::Cow::Borrowed(b)
                } else {
                    std::borrow::Cow::Owned(t.to_string())
                }
            }
            other => {
                let t = trim_trailing_sep(&other);
                if t.len() == other.len() { other } else { std::borrow::Cow::Owned(t.to_string()) }
            }
        };
        let lower: &str = lower_owned.as_ref();

        if path_contained_in(lower, &self.inner.project_root_lower) {
            return Decision { mode: Mode::Passthrough, overlay: None, cow_from: None, mock_payload: None };
        }

        // ── Whiteout (OverlayFS tombstone) check ────────────────────────────
        //
        // A path outside project_root may carry a whiteout marker recorded by a
        // previous delete. If it does, and there is no overlay entry for it
        // (i.e. it was not revived by a subsequent create), the merged view
        // hides it: open → not-found, absent from enumeration. We model that
        // with Mode::Hidden.
        //
        // If an overlay entry EXISTS (the agent re-created the file in the
        // overlay after deleting it), the whiteout is effectively superseded
        // — the file is alive in the overlay and reads resolve there. In that
        // case we fall through to the normal flow, which returns Mode::Cow
        // pointing at the overlay.
        //
        // Both tables are consulted in one read txn to keep this cheap.
        if let Ok(txn) = self.inner.db.begin_read() {
            let is_whiteouted = txn.open_table(db::WHITEOUTS)
                .ok()
                .and_then(|t| t.get(&*lower).ok().flatten().is_some().then_some(()))
                .is_some();
            if is_whiteouted {
                // "Alive in the overlay" = present in the index OR physically
                // materialized (relative-create holes). Either means the path
                // was revived after the delete; fall through to Cow below.
                let idx_hit = txn.open_table(db::OVERLAY_IDX)
                    .ok()
                    .and_then(|t| t.get(&*lower).ok().flatten().map(|_| ()))
                    .is_some();
                let phys_hit = !idx_hit
                    && physical_overlay_path(&lower, &self.inner.overlay_layout).is_some();
                if !(idx_hit || phys_hit) {
                    return Decision { mode: Mode::Hidden, overlay: None, cow_from: None, mock_payload: None };
                }
                // alive: fall through (revive) — normal flow returns Cow below.
            }
        }

        let snap = self.inner.snapshot.load();

        if let Some(payload) = snap.find_mock_payload(&lower) {
            let overlay = path::mirror_into_overlay_layout(&lower, &self.inner.overlay_layout);
            return Decision {
                mode: Mode::Mock,
                overlay: Some(overlay),
                cow_from: None,
                mock_payload: Some(payload),
            };
        }

        if snap.matched_mock_dir(&lower).is_some() {
            let overlay = path::mirror_into_overlay(&lower, &self.inner.mock_dirs_root);
            return Decision {
                mode: Mode::Cow,
                overlay: Some(overlay),
                cow_from: None,
                mock_payload: None,
            };
        }

        let rule = snap.best_rule_match(&lower, depth, exe_lower);

        // Merged-view default: a path outside project_root that matched no
        // explicit rule (and no configured default) is isolated — reads
        // passthrough (the read-through arm below still consults OVERLAY_IDX),
        // writes go CoW into the overlay so the real disk is never touched.
        // `best_rule_match` already folds in the configured default catch-all
        // rule, so an operator-supplied default overrides this fallback.
        let (mode_read, mode_write) = rule
            .map(|r| (r.mode_read, r.mode_write))
            .unwrap_or((db::RuleMode::Passthrough, db::RuleMode::Cow));

        let effective_mode = if write_access { mode_write } else { mode_read };

        match effective_mode {
            db::RuleMode::Deny => Decision { mode: Mode::Deny, overlay: None, cow_from: None, mock_payload: None },
            db::RuleMode::Passthrough => {
                if !write_access {
                    // Index first (fast path): an exact-key hit redirects the
                    // read into the overlay.
                    if let Ok(txn) = self.inner.db.begin_read() {
                        if let Ok(t) = txn.open_table(db::OVERLAY_IDX) {
                            if let Ok(Some(v)) = t.get(&*lower) {
                                let ov = PathBuf::from(v.value());
                                return Decision { mode: Mode::Cow, overlay: Some(ov), cow_from: None, mock_payload: None };
                            }
                        }
                    }
                    // Index MISS → consult the PHYSICAL overlay mirror tree
                    // (source of truth). This catches files that exist in the
                    // overlay but were never indexed (relative-open-create
                    // holes, e.g. a cloned repo's `.git`/`agent/`). Without it,
                    // the read passthroughs to the real disk and fails with
                    // STATUS_OBJECT_NAME_NOT_FOUND. The mirror check is a single
                    // local stat; HookCache amortizes it across repeated reads.
                    if let Some(ov) = physical_overlay_path(&lower, &self.inner.overlay_layout) {
                        return Decision { mode: Mode::Cow, overlay: Some(ov), cow_from: None, mock_payload: None };
                    }
                }
                passthrough()
            }
            db::RuleMode::Cow | db::RuleMode::Redirect => {
                let overlay = path::mirror_into_overlay_layout(&lower, &self.inner.overlay_layout);
                let existing_overlay = if let Ok(txn) = self.inner.db.begin_read() {
                    if let Ok(t) = txn.open_table(db::OVERLAY_IDX) {
                        t.get(&*lower).ok().flatten().map(|v| PathBuf::from(v.value()))
                    } else { None }
                } else { None };
                if let Some(ov) = existing_overlay {
                    return Decision { mode: Mode::Cow, overlay: Some(ov), cow_from: None, mock_payload: None };
                }
                // Defense in depth: only record a CoW source if the path is a
                // real, non-reparse file *at decision time*. The authoritative
                // TOCTOU fix lives at the copy site (hook::hooks::prepare_overlay,
                // src_is_reparse_point) because decision-time is far from
                // copy-time and the source is attacker-influenceable in between;
                // this merely avoids ever recording a known-reparse source.
                let cow_from = if write_access && path_is_plain_file(dos_path) {
                    Some(PathBuf::from(dos_path))
                } else {
                    None
                };
                Decision { mode: Mode::Cow, overlay: Some(overlay), cow_from, mock_payload: None }
            }
        }
    }
}
