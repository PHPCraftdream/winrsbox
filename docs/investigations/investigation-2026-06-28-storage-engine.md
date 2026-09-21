# Storage-engine abstraction — research dossier (2026-06-28)

Captures the multi-turn investigation around the question
"replace redb with fjall / make a unified engine interface".

Discipline: every material claim is labelled **OBSERVED** (read by hand from
code, git, or disk) or **INFERRED** (reasoned but not directly verified).
"Hypothesis" stays a hypothesis. Smoothing uncertainty here would propagate
into the next session and produce another wrong root cause.

---

## 1. Origin & motivation

User request: *"replace redb with fjall — it is 4× faster and allows parallel
writes."*

Reframed mid-investigation to: *"build a single interface for engines so fjall
can be added cheaply later."*

A neighbour project, `D:\dev\rust\shamir-db`, was named as already having
both a Store trait and a working fjall backend, with a historical redb impl
somewhere in git history. The user explicitly forbade any git state mutation
in that repo (active worktree) — read-only investigation only.

---

## 2. Current redb usage in fs-sandbox (OBSERVED)

### 2.1 Surface

- Direct deps: `redb = "2"` in `winrsbox/policy/Cargo.toml:8` and
  `winrsbox/launcher/Cargo.toml:48`.
- redb is imported across **7 files** in 2 crates (`policy`, `launcher`); the
  hook crate does **not** touch redb (it talks IPC).
- Leakage into `launcher/cli/*` is direct and load-bearing —
  `redb::Database::create(...)` is called from CLI subcommands
  (`launcher/src/cli/mod.rs:125`, `cli/regwhy.rs:37,111,115`). Policy's own
  public API also exposes redb types (`pub fn ...(db: &redb::Database, ...)`
  and `... &redb::ReadTransaction ...`) in `policy/src/db.rs:130, 275, 294,
  315, 328, ...`.
- bincode coupling: 14 sites in `winrsbox/policy/src/` (`grep -c "bincode::"`).
  Serialisation format choice is currently baked into the engine layer.

### 2.2 Schema

10 tables (`policy/src/db.rs:5-36`), all keyed by `&str`, values are tiny:
`&[u8]` (encoded rows), `&str` (overlay-mirror paths), or `()` (membership).

```
RULES         &str -> &[u8]    bincode(RuleRow)
MOCKS         &str -> &[u8]
MOCK_DIRS     &str -> ()
OVERLAY_IDX   &str -> &str     virtual -> physical mirror path
WHITEOUTS     &str -> ()       tombstones
REG_RULES     &str -> &[u8]
REG_MOCKS     &str -> &[u8]
DEV_RULES     &str -> &[u8]
NET_RULES     &str -> &[u8]
DEFAULTS      &str -> &[u8]
```

### 2.3 Hot-path writes

Three writes happen on every intercepted syscall (via IPC to launcher):
- `Req::RecordOverlay` → `policy.record_overlay(orig, overlay)` →
  `OVERLAY_IDX.insert` + `commit` (`pipe_server.rs:1076`,
  `decide.rs:290`).
- `Req::RecordWhiteout` → `policy.record_whiteout(path)`
  (`pipe_server.rs:1086`, `decide.rs:317`).
- `Req::RegWrite` → `reg_policy.write_to_overlay(...)`
  (`pipe_server.rs:1236`).

**All writers are serialised through one launcher process**. There is no
concurrent writer anywhere. (OBSERVED — single pipe-server handler.)

### 2.4 Load-bearing semantics fs-sandbox relies on

Two redb properties are CRITICAL and broke once before (the OVERLAY_IDX
inconsistency saga that led to Direction 2, `c0c2a0a`):

- **Cross-table atomic write txn.** `apply_config` (`policy/src/db.rs:130-196`)
  opens RULES + MOCKS + MOCK_DIRS in ONE `begin_write` and commits them in a
  single atomic txn. If half-committed, the merged policy view diverges
  silently from the configured one.
- **Snapshot multi-table read.** The hot `decide` path
  (`policy/src/decide.rs:468` and around) opens ONE `begin_read` and then
  reads several tables off the same `ReadTransaction` for point-in-time
  consistency on the decision. Drop this and concurrent writers can split a
  decision across two views.

These are the two properties any future trait MUST preserve. They are also
exactly the two properties most KV abstractions silently flatten.

---

## 3. Honest analysis of "replace redb with fjall"

The motivation as stated does not hold up against the workload.

### 3.1 "4× faster" — UNVERIFIED on our workload

No benchmark cited, no oracle. **INFERRED** (high confidence): our hot path
bottleneck is the IPC round-trip (named pipe + hello + decide-reply), not
fsync of redb. A bench showing fjall 4× faster on bulk LSM sequential writes
without durability says nothing about our workload, which is short tagged
writes that need durable+atomic semantics.

This needs **three measurements** before any engine decision:

1. p50/p99 of `decide` IPC round-trip vs p50/p99 of `record_overlay` commit
   time. (Falsifies/confirms "the DB is the bottleneck".)
2. Group-commit window (5–10 ms) over `record_overlay` — currently every CoW
   create is its own commit; on a 12 000-file git clone that's 12 000 fsyncs.
   **Group commit is likely a bigger win than any engine swap**, with zero
   foreign-surface risk.
3. p99 tail of both. Tail latency is what the user actually feels.

### 3.2 "Parallel writes" — IRRELEVANT to fs-sandbox

All writes are serialised through one launcher process (OBSERVED §2.3).
Parallel-writer capability of a KV engine is invisible to our architecture.
Swapping engines to get a feature we cannot exercise is **negative-value**
work: foreign surface, new failure modes, no gain.

### 3.3 What actually hurts (OBSERVED from recent sessions)

None of these are "engine is slow":

- OVERLAY_IDX was incomplete because relative-create writes bypassed the
  recording path (D2 `c0c2a0a` fixed it by treating physical overlay as
  truth, index as cache).
- `policy.redb` sits **inside** `<sandbox_root>/workdir/`, so the carve-out
  in `31e954a` accidentally exposes it (security regression still open). This
  is a **layout** problem, not an engine problem.
- `decide` opens two short `begin_read`s per call (`decide.rs:728-744`).
  Cheap, but cache-friendly to amortise; again not an engine problem.

Replacing redb with fjall fixes literally zero of these.

---

## 4. Honest analysis of "single interface for engines"

The spirit is right (defer engine commitment, no marriage to redb). But
"trait now" has known traps that are especially expensive in our position.

### 4.1 Traps with naïve trait-now

1. **Lowest-common-denominator (LCD).** A trait expresses only what BOTH
   engines do. redb: native cross-table atomic txn; fjall: cross-partition
   atomicity via `Keyspace::batch`/`WriteBatch` with different durability and
   API shape. Hiding the difference would re-create the "index lies about
   reality" class we just spent weeks repairing.
2. **YAGNI.** One engine exists. Trait maintenance is forever; second engine
   may never ship (see §3 — current motivation does not justify it).
3. **Semantic abstraction is harder than API abstraction.** `open_table` is
   easy to hide; durability/atomicity/isolation/snapshot semantics are not,
   and they are exactly what cuts us in prod.
4. **One concrete impl shapes the trait wrong.** Trait without a second live
   backend is "redb-shaped". When fjall arrives it does not fit, and we
   rewrite — abstracting twice.
5. **Risk window.** Open security regression (`policy.redb` reachable via
   carve-out), 14 unpushed commits, freshly-stabilised path-leak saga. Large
   architectural moves now risk a new regression in the worst possible
   moment.

### 4.2 Two-phase recommendation

**Phase 1, NOW: encapsulate (no trait).** One module owns all redb +
bincode usage; outside world sees typed domain functions only. This delivers
the entire spirit of the request ("easy to swap later") without trait debt.

Concretely:
- Make `redb` a **private** dep of `winrsbox/policy`; remove from
  `winrsbox/launcher/Cargo.toml`.
- All `pub fn ...(db: &redb::Database, ...)` → typed Store handle with
  domain methods (`store.upsert_rule(&row)`, `store.record_overlay(orig,
  ov)`, `store.snapshot()` returning a read-handle, etc.).
- Hide `TableDefinition::new`, `bincode::*`, redb error types inside the
  module; convert at the boundary to `PolicyError`.
- Replace `redb::Database::create` in `launcher/src/cli/mod.rs:125` and
  `cli/regwhy.rs:37,111,115` with `policy::Store::open_create(state_dir)`.

This is strictly better code today, and any future migration (fjall, sled,
sqlite, in-memory) becomes a one-module change.

**Phase 2, LATER, ONLY if measurements (§3.1) demand it:** introduce a
trait against TWO concrete impls (redb + the new one), with a feature flag
and a canary period of dual-writes. The trait shape is forged by both real
backends, not guessed under one — escaping the LCD trap.

---

## 5. Sibling repo investigation — `D:\dev\rust\shamir-db`

Investigated read-only by a subagent. Repo HEAD unchanged; no git mutations
of any kind.

### 5.1 The Store trait found there

**Location:** `crates/shamir-storage/src/types.rs:29-262` (trait `Store`),
`:340-381` (`Repo`).

**Shape (OBSERVED, verbatim from subagent's read):**

```rust
#[async_trait]
pub trait Store: Send + Sync {
    async fn insert(&self, value: Bytes) -> DbResult<RecordKey>;
    async fn set(&self, key: RecordKey, value: Bytes) -> DbResult<bool>;
    async fn get(&self, key: RecordKey) -> DbResult<Bytes>;
    async fn get_many(&self, keys: Vec<RecordKey>) -> DbResult<Vec<Option<Bytes>>>;
    async fn remove(&self, key: RecordKey) -> DbResult<bool>;
    async fn flush(&self) -> DbResult<()>;
    async fn apply_buffer_config(&self, _c: &MemBufferConfig) -> DbResult<()>;
    async fn raw_backend(&self) -> Option<Arc<dyn Store>>;
    async fn insert_many(&self, values: Vec<Bytes>) -> DbResult<Vec<RecordKey>>;
    async fn set_many(&self, items: Vec<(RecordKey, Bytes)>) -> DbResult<Vec<bool>>;
    async fn remove_many(&self, keys: Vec<RecordKey>) -> DbResult<Vec<bool>>;
    async fn transact(&self, ops: Vec<KvOp>) -> DbResult<()>;
    fn iter_stream(&self, batch_size: usize) -> RecordStream;
    fn scan_prefix_stream(&self, prefix: Bytes, batch_size: usize) -> RecordStream;
    fn iter_range_stream(&self, start: Option<Bytes>, end: Option<Bytes>,
                         batch: usize) -> RecordStream;
    fn iter_range_stream_reverse(&self, ...) -> RecordStream;
}
```

Key/value model is fixed: `RecordKey = Bytes`, value `Bytes`. Errors flat via
`thiserror`. `KvOp = enum { Set(RecordKey, Bytes), Remove(RecordKey) }`.

**Key semantics (OBSERVED from doc-comments):**

- **A `Store` IS a single table/keyspace.** Atomicity unit = `transact` on
  one store. There is **no cross-table atomic txn in the trait**. fjall's
  impl can physically span keyspaces via `batch.insert(&keyspace, …)` but
  the trait signature does not expose this.
- **No snapshot / read-txn object.** Reads are point ops or fresh streams;
  each disk impl opens its own short read txn per batch. "Hold a consistent
  read view across many lookups" is not a primitive.
- **Scans (prefix, range, range-reverse) are first-class.** Async-streamed,
  batched, native LSM/B-tree seeks. Better than what we have today.
- **Durability:** eventually durable by default; `flush()` is the explicit
  fsync barrier (matches `Durability::None` + explicit-fsync style).

### 5.2 fjall implementation

**File:** `crates/shamir-storage/src/storage_fjall.rs` (`FjallRepo:18`,
`FjallStore:86`), fjall `3.0.1`. One `Store` == one `fjall::Keyspace`. Atomic
`transact` via `Database::batch()` → `OwnedWriteBatch.commit()`. `flush()` =
`persist(PersistMode::SyncAll)`. Native reverse cursor and prefix range via
`keyspace.range(...)`. All ops wrapped in `tokio::task::spawn_blocking`.

**Notable caveats (OBSERVED — gold):**
- `insert`/`set` are TOCTOU: `contains_key` then `insert` are two separate
  fjall ops. Safe only because keys there are random 128-bit `RecordId`s and
  writes are serialised per-table; the created/existed bool is racy under
  concurrent external writers. No CAS at this layer.

### 5.3 redb implementation, historical

**Removed in one shot** by commit `af2ff2d9` (2026-06-21), message:
*"arch(storage): drop nebari/persy/canopy/redb engines, fjall as sole
durable backend"*. Prior to that commit, redb (`3.1.0`) lived as a full
feature-gated peer backend for many commits — NOT a brief flag-then-delete.

**Deleted files (3 files, 1367 lines):**
- `crates/shamir-storage/src/storage_redb.rs` (640 lines — the impl)
- `crates/shamir-storage/src/tests/storage_redb_tests.rs` (275)
- `crates/shamir-engine/src/table/tests/index2_persistence_redb_tests.rs` (452)

**Read-only retrieval (no git state change in shamir-db):**

```sh
git -C D:/dev/rust/shamir-db show \
    af2ff2d9^:crates/shamir-storage/src/storage_redb.rs

git -C D:/dev/rust/shamir-db show \
    af2ff2d9^:crates/shamir-storage/src/tests/storage_redb_tests.rs
```

**What it did:** `RedbRepo { db: Arc<Database> }`; a `Store` == one redb
table named by string, `TableDefinition::<&[u8],&[u8]>::new(&name)`
re-opened per op. Per-write `begin_write` + `set_durability(Durability::None)`
+ `commit` (amortised durability). `flush()` = empty `Durability::Immediate`
commit. Native `transact` opens one `WriteTransaction`, applies all `KvOp`s
**in one table**, commits atomically. Native `range().rev()` reverse and
prefix scans. Same `&[u8]/Bytes` model — directly comparable to fjall.

A read-only verbatim copy of the impl was extracted (subagent) to
`D:\dev\rust\fs-sandbox\repro\storage_redb_historical.rs` for reference.
The repro/ dir is intentionally untracked.

### 5.4 Tests and engine-swap mechanism

- **Engine-agnostic tests:** shared backend-matrix suites in
  `shamir-storage/src/tests/`, `benches/backend_matrix.rs`,
  `crash_recovery.rs`. Per-engine tests also existed (the deleted
  `storage_redb_tests.rs`).
- **In-memory impl:** always-compiled, no extra deps —
  `storage_in_memory.rs` (`InMemoryRepo`/`InMemoryStore`), backed by
  `scc::TreeIndex` so prefix/range scans are real `O(log N)`, not `O(N)`.
- **Swap mechanism:** runtime enum dispatch (NOT generics).
  `BoxRepo` / `BoxRepoFactory` in
  `crates/shamir-engine/src/repo/repo_types.rs` — `#[cfg]`-gated variants
  (`InMemory`/`Sled`/`Fjall`/`MemBuffer`/`Cached`) + cargo features in
  `shamir-storage/Cargo.toml` (`default = ["all-backends"]`,
  `all-backends = ["sled","fjall"]`). Wrapper backends (`MemBufferStore`,
  `CachedStore`) stack on any inner via `raw_backend()` unwrapping.
  Selection = compile-time feature + runtime factory choice.

---

## 6. Fit assessment for fs-sandbox (OBSERVED, comparison)

| Our need | shamir-db `Store` | Verdict |
|---|---|---|
| 10 typed tables, key `&str`, values `&str`/`&[u8]`/`()` | One Store = one table; key forced to `Bytes`, value `Bytes` | Wedge — lose redb's compile-time `TableDefinition<&str,&[u8]>` typing. |
| **Cross-table atomic txn** (`apply_config` opens RULES+MOCKS+MOCK_DIRS in ONE `begin_write`, `db.rs:134-196`) | `transact` is per-store ONLY; trait has NO multi-store txn | **HARD MISMATCH.** Would force either collapse-tables-into-one-keyed-store, or drop down to a concrete `fjall::Database::batch()` — re-leaking the engine and defeating the abstraction. |
| **Snapshot multi-table reads on the hot `decide` path** (`decide.rs:468` opens one `begin_read`, reads RULES/MOCKS off the SAME `ReadTransaction`) | No read-txn object; each read is a fresh short txn | **MISMATCH.** Lose point-in-time consistency across multi-table read. For us this is the exact property whose violation produced D2 / OVERLAY_IDX bugs. |
| Prefix/range scans (`whiteouts_under`, `overlay_children`) | First-class `scan_prefix_stream` / `iter_range_stream`, native seeks | **Cleaner than current.** |
| Single writer (one launcher) | TOCTOU caveats assume serialised writes — matches | Fine. |
| Durability/flush barrier | `flush()` barrier, `Durability::None`-style amortisation | Clean fit. |

Note: current `record_overlay` (`decide.rs:290`) is single-table + a
`cache.clear()`, NOT multi-table-atomic. But `apply_config` genuinely is, and
the decide-read path genuinely is multi-table-snapshot. Those two are the
load-bearing semantics the shamir-db trait would force us to give up.

---

## 7. Recommendation

**Take the infrastructure; do NOT take the `Store` trait shape.**

Lift wholesale (well-considered, directly reusable):
1. `BoxRepo` / `BoxRepoFactory` runtime enum-dispatch + cargo-feature swap.
2. Always-compiled in-memory backend on `scc::TreeIndex` — instant fast
   tests, no temp-dir + no fsync, real `O(log N)` scans.
3. `flush()` durability-barrier pattern + amortised commits
   (group-commit window). This single change probably matters more than any
   engine swap.
4. `async + spawn_blocking` wrapping for disk backends (we are mostly sync
   today; this is a future-friendly shape).
5. Lift the historical redb impl from `af2ff2d9^` almost verbatim as our
   first concrete backend — durability/range/reverse model is already
   sound, and we already ship redb.
6. The §B13 TOCTOU lesson: created/updated semantics need to come from
   INSIDE the write txn — redb's `table.insert` returns the previous value
   (free); fjall would need a txn to do the same.

Design ourselves (do not borrow):
1. **A trait with a real transaction object** —
   `Store::begin_write() -> WriteTxn` and `Store::begin_read() -> ReadTxn`,
   where each transaction spans ALL 10 tables. This preserves our
   cross-table atomicity and snapshot-read invariants. (Both redb natively
   and fjall via `Keyspace::batch`/snapshots can implement this.)
2. **Keep `&str` typed keys at the API boundary** even if bytes
   underneath. The bincode encoding stays an internal detail of the
   backend implementation; callers stay in domain types.

---

## 8. Suggested phased execution

**Pre-phase (NOT optional):**
- Close the carve-out security regression (`policy.redb` is currently
  reachable via the `31e954a` carve-out, because it lives INSIDE
  `<sandbox_root>/workdir/`). The cleanest fix is to relocate control
  files out of `workdir/` — and that relocation is also Phase-1-shaped.
- Push the 14 backlogged commits AFTER the carve-out fix.

**Phase 1 — encapsulate (no trait yet):**
- Single `policy::store` module owns ALL `redb::*` and `bincode::*`.
- Typed methods only at the public boundary.
- Remove `redb` from `launcher/Cargo.toml`; CLI uses `policy::Store::*`.
- Lift the in-memory `scc::TreeIndex` backend pattern from shamir-db as
  a test-only impl (for fast unit tests).
- Lift the `flush()` + amortised-commit pattern; convert per-create commits
  to a group-commit window.
- Commit as a single refactor: "refactor(policy): encapsulate storage
  behind typed Store API — no engine swap".

**Phase 2 — trait, IF AND ONLY IF measurements show DB is the bottleneck
(see §3.1):**
- Introduce `trait Store` with `begin_write`/`begin_read` transaction
  objects spanning all tables.
- First impl: current redb wrapped to fit.
- Second impl: fjall (lifted from shamir-db, adapted to the txn surface).
- Lift `BoxRepo` enum-dispatch and cargo-feature mechanism.
- Canary phase: dual-write for one week, compare consistency.
- Switch default only after canary + p99 benchmark.

---

## 9. Open items at time of writing (HEAD = `31e954a`, ahead 14 not pushed)

- **Security regression (open):** `policy.redb` is reachable via the
  carve-out added in `31e954a` because it lives inside the carve-out's
  workdir root. Move control files OUT of `workdir/` and harden
  `is_self_overlay_workdir_access`. **OBSERVED** by direct disk inspection.
- **History hygiene:** `3bbe137` and `0454f1e` share an identical commit
  message but different content (`0454f1e` adds +14 lines in
  `path_info_guard.rs` on top of `3bbe137`). Rewrite messages before push.
- **Strategic:** the user-mode masking model has now cost us 7+ patches in
  one class (#60 → #64 → Bug A → Symptom 2 → residual leak → carve-out
  hole → ...). A bindflt / wcifs kernel-bind spike would dissolve the
  class by construction. Independent of the storage question.

---

## 10. Bibliography (file:line, commit hashes)

fs-sandbox:
- `winrsbox/policy/src/db.rs:5-36` — table definitions
- `winrsbox/policy/src/db.rs:130-196` — multi-table atomic `apply_config`
- `winrsbox/policy/src/decide.rs:290` — `record_overlay`
- `winrsbox/policy/src/decide.rs:468` — multi-table snapshot read
- `winrsbox/launcher/src/cli/mod.rs:125` — redb leak into launcher CLI
- `winrsbox/launcher/src/cli/regwhy.rs:37,111,115` — same
- Commits: `c0c2a0a` (D2), `6eafb39` (same-volume overlay), `0454f1e`
  (multi-root masking), `31e954a` (carve-out — security regression here)

shamir-db (read-only references — no git mutations performed):
- `crates/shamir-storage/src/types.rs:29-262` — `Store` trait
- `crates/shamir-storage/src/types.rs:340-381` — `Repo` trait
- `crates/shamir-storage/src/storage_fjall.rs:18,86,108-119,237-262,270`
- `crates/shamir-storage/src/storage_in_memory.rs` — always-on test backend
- `crates/shamir-engine/src/repo/repo_types.rs` — `BoxRepo` dispatch
- Commit `af2ff2d9` — removed redb impl (retrieve via
  `git show af2ff2d9^:<path>`)

Extracted artefact (read-only copy, gitignored):
- `D:\dev\rust\fs-sandbox\repro\storage_redb_historical.rs`
