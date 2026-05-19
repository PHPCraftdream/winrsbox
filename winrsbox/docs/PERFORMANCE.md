# Performance

Measurements on Windows 10.0.19045, i7-12700H, NVMe SSD, scan mode.

## Sandbox overhead

`cargo build` on a hello-world Rust project (3 runs, cold cache):

| Mode | Time (median) | Overhead |
|---|---|---|
| Bare (no sandbox) | 0.80s | baseline |
| Sandboxed (scan) | 1.56s | +0.76s (~95%) |

The overhead comes from:
- IPC round-trip for each FS decision (~480 decisions per cargo build)
- Hook.dll injection via CreateRemoteThread + LoadLibrary
- Named pipe setup + WFP filter registration

For comparison, Windows Sandbox (VM) startup alone takes ~30 seconds.

## Micro-benchmarks (hook internals)

### FS cache (hook.dll)

| Operation | Latency |
|---|---|
| Cache hit (caseless lookup) | ~120 ns |
| Cache miss (caseless lookup) | ~107 ns |
| Cache insert | ~140 ns |
| Cache invalidate | ~1.9 us |

### Content scanning (policy crate)

| Operation | Latency |
|---|---|
| Scan cache hit (xxhash3 lookup) | ~50 ns |
| Content scan (iced-x86 disasm, 4KB page) | ~47 us |

### Anti-recursion guard

| Operation | Latency |
|---|---|
| thread_local Cell check | ~2 ns |
| TLS-based guard (NtAlloc hook) | ~5 ns |

## Memory footprint

| Component | RSS |
|---|---|
| winrsbox.exe (launcher) | ~12 MB |
| hook.dll (injected per process) | ~2 MB |
| WFP filters (5 kernel filters) | negligible |
| Job Object | negligible |

## IPC throughput

Named pipe IPC (bincode serialization, per-thread connections):
- ~480 decisions for `cargo build` in 1.56s
- ~1500 decisions for `claude -p` session in ~60s
- Each decision: ~200 us round-trip (serialize → pipe → deserialize → decide → respond)

## Hot-stats example (Claude Code session)

```
fs_decides: 1439
fs_denies: 3
fs_cows: 33
reg_decides: 288
net_decides: 11
hellos: 50
children: 15
```

Top FS path: `~/.claude/sessions` (16 accesses).
Top registry key: `HKLM\Software` (39 accesses, certificate store queries).
