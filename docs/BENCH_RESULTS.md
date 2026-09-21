# BENCH_RESULTS.md — winrsbox hot-path optimizations

## Applied optimizations

| # | Opt | Status | Files changed |
|---|-----|--------|---------------|
| 1 | `nt_to_dos` + inline ASCII lowercase | ✅ Applied | policy/src/path.rs, hook/src/hooks.rs |
| 2 | Iterator-based pattern matching (no Vec alloc) | ✅ Applied | policy/src/path.rs |
| 3 | Batch Xxh3 update (stack buffer) | ✅ Applied | hook/src/cache.rs |
| 4 | Arc\<Decision\> | ⏭ Skipped | user request |

All 61 workspace tests pass after each opt.

---

## Opt 1 — nt_to_dos with inline ASCII lowercase

Baseline: original `nt_to_dos` (post-initial, pre-opt1 values from first session).
After: rewritten to work on raw `u16` slices with optional ASCII lowercasing in one pass.
New function `nt_to_dos_lower()` used in hook's `extract_dos_path`, eliminating the separate `to_ascii_lowercase()` call.

| Bench | Before | After | Δ |
|-------|--------|-------|---|
| nt_to_dos_with_prefix | 417 ns | 174 ns | **-58% / 2.4×** |
| nt_to_dos_no_prefix | 466 ns | 178 ns | **-62% / 2.6×** |
| nt_to_dos_plus_lowercase (old pattern) | 301 ns | 190 ns (nt_to_dos_lower) | **-37% / 1.6×** |

---

## Opt 2 — Iterator-based pattern matching

Baseline: `before-iter`. After: lazy `split('\\')` iterators, byte-level `segment_match`.

| Bench | Before | After | Δ |
|-------|--------|-------|---|
| pattern_matches_prefix_hit | 1.27 µs | 259 ns | **-79% / 4.9×** |
| pattern_matches_prefix_miss | 313 ns | 124 ns | **-58% / 2.5×** |
| pattern_specificity | 40.8 ns | 39.4 ns | -3% (noise) |

---

## Opt 3 — Batch Xxh3 update (stack buffer)

Baseline: `before-batch`. After: `[u8; 512]` stack buffer → single `h.update()`.

| Bench | Before | After | Δ |
|-------|--------|-------|---|
| get_caseless_hit | 514 ns | 103 ns | **-80% / 5.0×** |
| get_caseless_miss | 241 ns | 98 ns | **-60% / 2.5×** |
| get_caseless_short_10b | 173 ns | 109 ns | **-37% / 1.6×** |
| get_caseless_long_200b | 1.77 µs | 152 ns | **-91% / 11.6×** |
| insert | 124 ns | 128 ns | +3% (noise) |
| invalidate | 1.82 µs | 1.70 µs | -7% (noise) |

---

## Summary

3 of 3 planned optimizations applied. No rollbacks.

**Hot-path impact (combined):**
- Hook cache lookup (get_caseless): **5× faster** (514→103 ns)
- Policy pattern matching: **5× faster** (1.27µ→259 ns)
- Path conversion (nt_to_dos + lowercase): **2.4× faster** (417→174 ns)
- Long-path cache lookup: **11.6× faster** (1.77µ→152 ns)

All gains come from eliminating heap allocations and reducing per-byte overhead.
Opt 4 (Arc\<Decision\>) deferred — would save 2 clone allocs on cache-miss path.

---

## Feature: depth + exe + `**` globs

New benchmarks added for `**` glob matching and `decide_with_context` (depth/exe filter).

### New benchmarks

| Bench | Description |
|-------|-------------|
| `pattern_double_star_short` | `C:\Users\**\.ssh` vs `C:\Users\alice\.ssh` |
| `pattern_double_star_long` | `C:\**\foo\**\.bar` vs `C:\a\b\c\foo\d\e\f\.bar` |
| `cache_miss_with_depth` | `decide_with_context(depth=2)` cache miss |
| `cache_miss_with_exe` | `decide_with_context(exe=...)` cache miss |
| `cache_miss_with_both` | `decide_with_context(depth=3, exe=...)` cache miss |

### Build verification

```
cargo test --workspace      → 155 passed, 0 failed
cargo bench --no-run         → compiles
cargo build --release        → compiles
```

---

## Composite cache key + FxHash audit

### Composite cache key (u128)

The `PolicyInner` cache key was extended from `u64` (path+write only) to `u128` via
bit-concatenation of two independent Xxh3 hashes:
- **path_hash** (high 64 bits): `Xxh3(path_bytes || write_flag)`
- **ctx_hash** (low 64 bits): `Xxh3(depth_tag || exe_bytes)` with tag bytes to
  disambiguate `None` vs `Some(0)` / `Some("")`.

This ensures that two processes with different `(depth, exe)` contexts for the same
path get independent cache entries, fixing `when` filter correctness.

### New tests

6 dedicated composite cache key tests:
- `composite_key_different_depth` — same path, depth 0 vs 1 → different keys
- `composite_key_different_exe` — same path, different exe → different keys
- `composite_key_none_vs_some_zero_depth` — `None` vs `Some(0)` → different keys (tag byte)
- `composite_key_none_vs_some_empty_exe` — `None` vs `Some("")` → different keys
- `composite_key_same_params_equal` — identical inputs → identical key (determinism)
- `composite_key_collision_sanity` — 500 unique triples → 500 unique keys

### New benchmarks

| Bench | Description |
|-------|-------------|
| `cache_key_composite_none` | Key computation with no depth/exe |
| `cache_key_composite_both` | Key computation with depth + exe |
| `cache_key_composite_short` | Key computation on short path |

### FxHash audit

Scanned all `.rs` files for `std::collections::HashMap`/`HashSet`/`BTreeMap`/`BTreeSet`:

| File | Change |
|------|--------|
| `launcher/src/main.rs:13` | `HashSet<u32>` → `FxHashSet<u32>` |
| `papaya::HashMap` in launcher | Left as-is (already uses ahash) |
| Test-only `HashSet` in policy | Left as-is (not production hot path) |

New dependency: `rustc-hash = "2"` added to workspace.

### Build verification

```
cargo test --workspace      → 161 passed, 0 failed
cargo bench --no-run         → compiles
cargo build --release        → compiles
```

---

## ArcSwap in-memory snapshot (replaces redb scan on cache miss)

Policy::compute now reads rules, mocks, mock_dirs from an in-memory `Snapshot`
served via `arc_swap::ArcSwap` (lock-free atomic pointer load). Redb read
transaction only for `overlay_idx` lookup.

### Cache miss path — before vs after

| Bench | Before (redb) | After (ArcSwap) | Δ |
|-------|---------------|-----------------|---|
| cache_miss_passthrough | 7.6 µs | 2.2 µs | **-71% / 3.5×** |
| cache_miss_with_depth | 12.6 µs | 2.6 µs | **-79% / 4.8×** |
| cache_miss_with_exe | 9.4 µs | 2.5 µs | **-73% / 3.8×** |
| cache_miss_with_both | 17.4 µs | 3.2 µs | **-82% / 5.4×** |
| cache_miss_deny | 85 µs | 74 µs | **-13%** |

### Rule match at scale

| Bench | Before | After | Δ |
|-------|--------|-------|---|
| best_rule_match n=1 | 73 µs | 65 µs | **-11%** |
| best_rule_match n=10 | 113 µs | 69 µs | **-39% / 1.6×** |
| best_rule_match n=50 | 116 µs | 85 µs | **-27%** |
| best_rule_match n=100 | 147 µs | 101 µs | **-31% / 1.5×** |

### Mock lookup

| Bench | Before | After | Δ |
|-------|--------|-------|---|
| find_mock_payload hit | 231 ns | 230 ns | ~0% |
| find_mock_payload miss n=1 | 9.5 µs | 3.3 µs | **-65% / 2.9×** |
| matched_mock_dir hit | 264 ns | 264 ns | ~0% |

### New P0/P1 benchmarks added

| Bench | Description | Time |
|-------|-------------|------|
| best_rule_match_scale/n={1,10,50,100} | Linear scan with N rules | 65–101 µs |
| find_mock_payload/{hit,miss}_n={1,10,50} | Exact + glob scan | 230 ns – 62 µs |
| matched_mock_dir/hit_n={1,10,50} | Prefix scan | 264–303 ns |
| pattern_matches_exact_{hit,miss,globstar} | Mock path glob matching | 877 ns – 1.04 µs |

### Build verification

```
cargo test --workspace      → 211 passed, 0 failed
cargo bench --no-run         → compiles
cargo build --release        → compiles
```
