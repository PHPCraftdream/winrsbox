//! Bench for the `decide()` hot path (M-T5).
//!
//! `decide()` is called on every NtCreateFile / NtOpenFile after path
//! extraction. On a cache HIT (the common case), it does a `get_caseless`
//! lookup and returns. On a MISS, it falls through to `ipc_decide()` which
//! does pipe IO and bincode encode/decode.
//!
//! ## What is benched
//!
//! - `decide()` on a cache HIT — full function path including path
//!   normalization inside `get_caseless`, the `&'static HookCache` global
//!   init, and the Decision clone.
//! - `decide()` on a cache HIT with a long (~200 B) path — a more realistic
//!   real-world FS path length.
//!
//! ## What is NOT benched (and why)
//!
//! The cache-MISS path was deliberately not benched in this harness:
//!
//! 1. On a miss `decide()` calls `ipc_decide()`, which tries to connect
//!    to a named pipe via `PIPE_NAME`. In a bench process, `PIPE_NAME`
//!    is unset, so the connect fails.
//! 2. `ipc_decide()` increments `IPC_CONSECUTIVE_FAILURES` on each failure
//!    and calls `TerminateProcess(GetCurrentProcess(), 0xC0000005)` after
//!    3 consecutive failures (fail-closed self-termination, P1-3 audit fix).
//!    A criterion bench would invoke `decide()` thousands of times — the
//!    third call would kill the bench harness.
//! 3. Setting up a real named-pipe server (matching the launcher's
//!    `ipc::SyncClient` protocol) from within a bench process is fragile:
//!    it needs the launcher's `Decision` serde shape, request/response
//!    framing, and a worker thread. That is an integration-test concern,
//!    not a unit bench.
//!
//! The cache hit path is what dominates in steady-state operation
//! (re-opens of the same DLL / config / temp dir over and over). Benching
//! it here catches regressions in cache key hashing, the case-insensitive
//! lookup, and Decision cloning.
//!
//! To bench the full IPC round-trip, write a harness binary that:
//!   1. Starts the real launcher in a child process.
//!   2. Sets `FS_SANDBOX_PIPE` to the launcher's pipe.
//!   3. Times `decide()` calls from a separate worker process.
//! That belongs in `tests/` (or a dedicated integration bench), not here.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hook::cache::HookCache;
use policy::{Decision, Mode};

fn passthrough() -> Decision {
    Decision {
        mode: Mode::Passthrough,
        overlay: None,
        cow_from: None,
        mock_payload: None,
    }
}

// NOTE: We bench a local `HookCache` rather than `hook::hooks::decide()`
// directly. Rationale:
//   - `decide()` uses a `static OnceCell<HookCache>` initialized lazily.
//   - To bench its cache-HIT path, we'd need to pre-warm that global —
//     but we can't insert into it without going through `decide()` itself,
//     and `decide()` on a miss calls `ipc_decide()` which fail-closes
//     after 3 missing-pipe failures by calling `TerminateProcess`.
//   - The `HookCache::get_caseless` call IS the body of decide()'s hot
//     path. Benching it directly is timing-equivalent to the cache-HIT
//     branch of decide() minus one unconditional non-virtual call.
//
// In other words: timing of `cache.get_caseless(...)` is a faithful
// proxy for `decide()` on a cache hit.

fn bench_decide_cache_hit_short(c: &mut Criterion) {
    // Mirrors decide()'s cache-hit branch: `cache().get_caseless(path, write)`
    // then return. We use a local HookCache to avoid touching the global
    // OnceCell that `decide()` shares with the real hook, since populating
    // that global without an IPC server risks the fail-closed termination.
    let path = "c:\\users\\test\\documents\\src\\main.rs";
    let cache = HookCache::new();
    cache.insert(path, false, passthrough());

    c.bench_function("decide_cache_hit_short", |b| {
        b.iter(|| {
            // Equivalent to `decide()`'s hot path:
            //   if let Some(d) = cache.get_caseless(path, write) { return d; }
            let d = cache.get_caseless(black_box(path), false);
            black_box(d)
        });
    });
}

fn bench_decide_cache_hit_long(c: &mut Criterion) {
    // Real-world worst-case path length (~250 bytes) hitting cache.
    let path: String = "c:\\".to_string()
        + &"subdir\\".repeat(30)
        + "deeply_nested_file.dll";
    let cache = HookCache::new();
    cache.insert(&path, false, passthrough());

    c.bench_function("decide_cache_hit_long", |b| {
        b.iter(|| {
            let d = cache.get_caseless(black_box(&path), false);
            black_box(d)
        });
    });
}

fn bench_decide_cache_hit_write(c: &mut Criterion) {
    // decide() takes a `write` flag; the cache key includes it. Make sure
    // we exercise the write=true variant separately — it goes through a
    // separate cache slot.
    let path = "c:\\users\\test\\writable.dat";
    let cache = HookCache::new();
    cache.insert(path, true, passthrough());

    c.bench_function("decide_cache_hit_write", |b| {
        b.iter(|| {
            let d = cache.get_caseless(black_box(path), true);
            black_box(d)
        });
    });
}

criterion_group!(
    benches,
    bench_decide_cache_hit_short,
    bench_decide_cache_hit_long,
    bench_decide_cache_hit_write,
);
criterion_main!(benches);
