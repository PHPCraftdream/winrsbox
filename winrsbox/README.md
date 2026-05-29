# winrsbox

Windows filesystem sandbox for AI coding agents and compilers. Runs any program inside a CoW (copy-on-write) overlay with memory protection, network filtering, and process isolation — zero setup, no VM, no drivers.

## Quickstart

```bash
cargo build --release
# Run Claude Code in sandbox
target/release/winrsbox -- "C:\Users\you\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe" -p "your prompt"

# Run cargo build in sandbox
target/release/winrsbox -- cargo build

# Pre-flight check
target/release/winrsbox doctor
```

## What it does

winrsbox intercepts filesystem, memory, registry, and network operations at the NT syscall level. Writes go to a CoW overlay; reads pass through. Dangerous operations (code injection, direct syscalls, persistence) are blocked.

### Defense layers

```
Pre-launch .text scan
  Process Mitigation Policies (JIT-safe in full; +DynamicCode/Signature in static)
    ntdll inline hooks (FS, memory, inject, registry, network)
      WFP kernel network filtering (RFC1918 + SMB block)
        Job Object (kill-on-close + memory limits)
          Content scanning (syscall detection on RX transitions)
```

## Tested programs

All verified exit=0, violations=0:

| Program | Mode | Notes |
|---|---|---|
| Claude Code (`claude.exe -p`) | scan | Full API workflow, HTTPS, 15+ child processes |
| `cargo build` | scan/full | Multi-process Rust build, 480 FS decisions |
| PowerShell | scan | .NET CLR + JIT, 500+ FS queries |
| Python | scan | CPython interpreter |
| Node.js | scan | V8 JIT engine |
| Git | scan | status, log, clone |

## Comparison

| | winrsbox | Windows Sandbox | Sandboxie | WDAG |
|---|---|---|---|---|
| Isolation | Process-level hooks | VM (Hyper-V) | Process (driver) | VM (container) |
| Setup | None | 30s VM boot | Install + driver | Install + Enterprise |
| Writes | CoW overlay | Ephemeral | Per-box snapshot | Per-container |
| Network | WFP rules (granular) | All or none | Full access | Restricted |
| Config | KTAV text files | WSB XML | INI | Group Policy |
| License | MIT | Windows Pro+ | GPL/Commercial | Windows Enterprise |
| Drivers | None | Hyper-V | Kernel driver (SbieDrv) | Hyper-V |

## Architecture

```
                         winrsbox.exe (launcher)
                              |
            +-----------------+-----------------+
            |                 |                 |
       CreateProcessW    Named Pipe IPC    WFP Engine
       (suspended)       (policy decisions) (kernel filters)
            |                 |                 |
            v                 v                 v
        target.exe -----> hook.dll        fwpuclnt.dll
            |           (injected)        (5 filters)
            |               |
            |    +----------+----------+----------+
            |    |          |          |          |
            |  FS hooks  Memory    Inject     Reg/Net
            |  (CoW)     hooks     guard      hooks
            |            (scan)    (3-layer)
            |
        Job Object (kill-on-close)
```

**hook.dll** — injected via LoadLibrary into the target process. Intercepts:
- **FS**: NtCreateFile, NtOpenFile, NtQueryAttributesFile, NtQueryFullAttributesFile, NtCreateUserProcess
- **Memory**: NtAllocateVirtualMemory (manual hook), NtProtectVirtualMemory, NtMapViewOfSection, NtWriteVirtualMemory
- **Inject**: NtCreateThreadEx, NtCreateThread, NtQueueApcThread, NtSetContextThread
- **Registry**: NtCreateKey, NtSetValueKey, NtDeleteValueKey, NtDeleteKey
- **Network**: ws2_32!connect

## Guard modes

| Mode | Flag | Protection |
|---|---|---|
| Full | `-g full` (default) | All hooks + content scan + DLL scan + **JIT-safe** kernel mitigations (ASLR, heap-terminate, strict-handle, image-load PreferSystem32/NoRemote, speculative-execution). Does NOT prohibit dynamic code or require signed DLLs, so node/V8/.NET JIT and unsigned native extensions (`.pyd`/`.node`) run. |
| Scan | `-g scan` | All hooks + content scan. No kernel mitigations beyond image-load. Lightweight (no pre-launch/DLL `.text` scan). |
| Static | `-g static` | Full + ProhibitDynamicCode + Microsoft-signed-only DLLs. Hard containment that closes the direct-syscall / fresh-ntdll hook-bypass surface — **breaks JIT and unsigned `.pyd`/`.node`**. For pure-static signed targets only. |
| None | `-g none` | FS sandbox only. No memory/inject/reg/net hooks |

## Policy (KTAV config)

State directory: `<parent>/.winrsbox/<cwd-name>/`

```
# sandbox.ktav
defaults: {
    read: passthrough
    write: cow
}
rules: [
    { prefix: C:\Windows, read: passthrough, write: deny }
    { prefix: C:\Users\**\.cargo, read: passthrough, write: passthrough }
]
```

See [docs/RECIPES.md](docs/RECIPES.md) for common configurations.

## Observability

- **hot-stats.json** — top-50 accessed paths, totals (flushed every 5s)
- **sandbox.log.jsonl** — structured event log (hello, deny, violation, exit)
- **violations.log** — detailed violation records with stack traces
- `--trace` flag — verbose hook-level logging to console

## Security

See [docs/THREATMODEL.md](docs/THREATMODEL.md) for full threat model, allow-listed devices, known gaps, and 14 blocked escape techniques.

### Escape test coverage (all blocked)

`escape_alloc_rwx`, `escape_jit_protect`, `escape_heap_to_exec`, `escape_stack_exec`, `escape_map_anon_rwx`, `escape_ntdll_double_map`, `escape_remote_thread`, `escape_thread_hijack`, `escape_hwbp_injection`, `escape_apc_injection`, `escape_foreign_alloc_rwx`, `escape_foreign_write_syscall`, `escape_unpacker_syscall`, `escape_self_modify_syscall`

## Known limitations

- **cmd.exe /c** does not execute commands (hook.dll DllMain interferes with cmd.exe startup). Use `.exe` paths directly.
- **npm install** writes go to CoW overlay. Add passthrough rule for `node_modules/` if persistence needed.
- **.cmd/.bat wrappers** (npm.cmd, claude.cmd) — use direct `.exe` path instead.
- **NtAllocateVirtualMemory** uses manual inline hook (detour2 trampoline bug). Functionally correct.

## CLI

```
winrsbox [OPTIONS] -- TARGET [ARGS...]
winrsbox doctor                  # system pre-flight check
winrsbox rule add ...            # manage sandbox rules
winrsbox why <path>              # explain decision for a path
winrsbox export                  # dump state as JSON
```

Run `winrsbox --help` for full options.

## Tests

```bash
cargo test --lib                                    # 136 unit tests
cargo test -p integration-tests --test memory_guard # 28 e2e tests (serialized)
bash scripts/compat-check.sh                        # 7 program compat checks
```

## License

MIT
