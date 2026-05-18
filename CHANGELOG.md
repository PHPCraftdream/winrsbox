# Changelog

All notable changes to winrsbox are documented in this file.

## [Unreleased]

### Performance

Hot-path optimizations on policy decision, path conversion, and cache lookup.
All 61 workspace tests pass; full numbers in `BENCH_RESULTS.md`.

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
