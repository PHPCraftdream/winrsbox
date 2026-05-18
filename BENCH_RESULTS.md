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
