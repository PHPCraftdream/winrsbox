# Changelog

All notable changes to winrsbox are documented in this file.

## [Unreleased]

### Features

- **CLI policy management commands** — `rule add/remove/list/show/clear`,
  `mock add/remove/list`, `mockdir add/remove/list`, `defaults set/show`.
  Back-compatible with legacy `winrsbox -- prog args` invocation.
  All commands work directly on the persistent `policy.redb` without a running sandbox.

- **`why` policy simulator** — `winrsbox why <path>...` traces the full rule chain,
  showing which rules matched, were skipped, and why. Supports `--write`, `--depth`,
  `--exe`, `--json`, `--stdin` for batch JSONL.

- **`what-if` analysis** — `winrsbox what-if rule add --prefix=... -- <paths>...`
  applies a hypothetical rule to an ephemeral snapshot and shows a diff of decisions.
  Does not mutate the live database.

- **Export/Import** — `winrsbox export` dumps the full policy state as versioned JSON
  (`schema_version: 1`). `winrsbox import` merges or replaces from JSON stdin.
  `winrsbox import --ktav <file>` supports legacy ktav format.

- **Deterministic IDs** — Rules, mocks, and mockdirs get `<kind>-<8hex>` IDs from
  xxh3 of normalized arguments. Same args always produce the same ID (idempotent upsert).

- **TracedDecision** — `Policy::decide_traced()` returns full chain info with
  `ConsideredRule` entries (match with specificity, skip with reason).

### Tests

- 37 new unit tests covering rule CRUD, mock CRUD, mockdir CRUD, defaults,
  why tracing, what-if analysis, export/import roundtrip, and ktav legacy import.
- Total: 198 tests (was 161).

- **Composite cache key (u128)** — `PolicyInner` cache key extended from `u64`
  to `u128` via bit-concatenation of two independent Xxh3 hashes (path+write,
  depth+exe). Fixes `when` filter correctness: two processes with different
  `(depth, exe)` for the same path now get independent cache entries.

- **FxHash audit** — replaced `std::collections::HashSet` in `launcher/main.rs`
  with `rustc_hash::FxHashSet` (~3–4× faster on integer keys). Added
  `rustc-hash = "2"` to workspace dependencies.

- **`**` globstar support** — `**` as a standalone path segment matches zero or more
  intermediate directories. `C:\Users\**\.ssh` now matches `C:\Users\alice\.ssh`,
  `C:\Users\alice\sub\.ssh`, and `C:\Users\.ssh`. Mixed `**foo` is treated as a
  single-segment glob (same as `*`).

- **`when` filter in rules** — rules can include `when: { depth: N, exe: pattern }`
  to restrict application to specific process depths (>=N) and executable paths
  (glob match). The root target is depth 0, its children are depth 1, etc.

- **Lock-free PID→ProcInfo storage** — launcher uses `papaya::HashMap` (true lock-free)
  to track process depth and executable path. Hook.dll sends `Hello` on first IPC
  connection and `SpawnedChild` before resuming child processes.

- **New IPC messages**: `Hello { pid, exe_path }` and `SpawnedChild { parent_pid, child_pid, child_exe }`.

### Tests

- 161 workspace tests (up from 116 baseline): 11 `**` glob tests, 6 `when` filter tests,
  6 composite cache key tests, 6 PID storage tests, 7 mock integration tests,
  2 IPC roundtrip tests.

### Benchmarks

- Added `decide_with_depth`, `decide_with_exe`, `decide_with_both` to `policy/benches/decide.rs`.
- Added `pattern_double_star_short`, `pattern_double_star_long` to `policy/benches/path.rs`.
- Added `cache_key_composite_none`, `cache_key_composite_both`, `cache_key_composite_short` to `policy/benches/decide.rs`.

### Performance

**In-memory ArcSwap snapshot (biggest win):**

- **Policy::compute bypasses redb on cache miss** — rules, mocks, and mock_dirs are
  loaded into an immutable `Snapshot` and served via `arc_swap::ArcSwap` (load = single
  atomic instruction, zero locks, zero unsafe). Redb read transaction only needed for
  overlay_idx lookup. Snapshot is rebuilt atomically on `load_config` / CLI CRUD.

  | Bench | Before (redb scan) | After (ArcSwap) | Speedup |
  |-------|--------------------|-----------------|---------|
  | cache_miss_passthrough | 7.6 µs | 2.2 µs | **3.5×** |
  | cache_miss_with_both | 17.4 µs | 3.2 µs | **5.4×** |
  | cache_miss_with_depth | 12.6 µs | 2.6 µs | **4.8×** |
  | cache_miss_with_exe | 9.4 µs | 2.5 µs | **3.8×** |
  | best_rule_match n=10 | 113 µs | 69 µs | **1.6×** |
  | best_rule_match n=100 | 147 µs | 101 µs | **1.5×** |
  | mock miss n=1 | 9.5 µs | 3.3 µs | **2.9×** |

**Earlier hot-path optimizations:**

Full numbers in `BENCH_RESULTS.md`.

- **`nt_to_dos` rewritten on raw `u16` slices with inline ASCII lowercasing** —
  new `nt_to_dos_lower()` eliminates the separate `to_ascii_lowercase()` allocation
  on every hooked syscall. `winrsbox/policy/src/path.rs`, `winrsbox/hook/src/hooks.rs`.
  Speedup: **2.4×** (417 → 174 ns).

- **Iterator-based pattern matching without `Vec<&str>` allocation** —
  `pattern_matches_prefix`, `pattern_matches_exact`, `segment_match` now use lazy
  `split('\\')` iterators and operate on `&[u8]` for ASCII glob matching.
  `winrsbox/policy/src/path.rs`. Speedup: **4.9×** on hit (1.27 µs → 259 ns),
  **2.5×** on miss.

- **Batch `Xxh3` update via stack buffer in `HookCache`** —
  replaced per-byte `h.update(&[b])` loop with a single `update(&buf[..len])`
  call over a `[u8; 512]` stack buffer. `winrsbox/hook/src/cache.rs`.
  Speedup: **5.0×** on cache hit (514 → 103 ns), **11.6×** on long paths
  (1.77 µs → 152 ns).

### Tooling

- Added criterion benches for all hot paths: `hook/benches/{cache,is_write}.rs`,
  `policy/benches/{decide,path}.rs`, `ipc/benches/msg.rs`.
- Added `BENCH_RESULTS.md` with before/after numbers per optimization.

## [0.1.0] — 2026-05-18

Initial commit. Windows filesystem sandbox with ntdll-level hooks, Copy-on-Write
overlay, child-process injection, glob-based policy rules, and ktav config format.
