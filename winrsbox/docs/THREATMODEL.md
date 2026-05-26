# Threat Model

winrsbox sandboxes AI coding agents (Claude Code, etc.) and compilers on Windows.
This document describes what we protect against, what we don't, and known gaps.

## In-scope threats

### Filesystem escape
Sandboxed writes go to a CoW overlay; reads pass through to the real FS.
Deny rules block writes to system directories (`C:\Windows`).

**Hooks**: NtCreateFile, NtOpenFile, NtQueryAttributesFile, NtQueryFullAttributesFile.

### Cross-process injection
Blocks the sandboxed process from injecting code into other processes.

**Hooks**: NtCreateThreadEx, NtCreateThread, NtQueueApcThread, NtSetContextThread.
**Checks**: three-layer filter (caller DLL, system PID, armed state).

### Direct syscall execution
Content scanning detects `syscall`/`sysenter`/`int 2eh` instructions in
executable memory before they can run.

**Hooks**: NtProtectVirtualMemory (RW->RX transition scan), NtMapViewOfSection
(.text section scan for user DLLs), NtAllocateVirtualMemory (foreign-process
exec alloc), NtWriteVirtualMemory (foreign-process write scan).

**Pre-launch**: .text section of target exe scanned before resume (full mode).

### RWX / JIT abuse
- **Full mode**: kernel `ProcessDynamicCodePolicy` blocks all RWX allocation.
- **Scan mode**: RWX allowed (for CLR/V8 JIT), content scanned on RX transition.

### Memory escalation in foreign processes
Blocks sandboxed process from allocating/protecting executable memory in
external (non-owned) processes. NtWriteVirtualMemory to external processes
scanned for syscall instructions.

### Registry persistence vectors
Deny writes to AppInit_DLLs, IFEO, AppCertDlls paths via NtSetValueKey hook.

### Network egress
- **WFP**: kernel-level outbound filters for RFC1918 (lateral movement block).
- **ws2_32 connect hook**: IPC-based destination approval.

### Process lifecycle
- **Job Object**: `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` + optional memory limits.
  All children auto-terminate when launcher exits.
- **Process Mitigation Policies** (full mode): `ProcessDynamicCodePolicy`,
  `ProcessSignaturePolicy` (MS-signed DLLs only), `ExtensionPointDisablePolicy`.

## Out-of-scope threats

| Threat | Why out-of-scope |
|---|---|
| Kernel-mode exploits | Sandbox lives in user-mode; kernel exploits bypass everything |
| CPU side-channels (Meltdown/Spectre) | Requires CPU-level mitigation, not software sandbox |
| Social engineering | Sandbox doesn't analyze code intent |
| WSL traffic | Separate kernel; WinDivert integration (future) needed |
| DLL search-order hijacking by sandbox | Sandbox DOES load hook.dll via injection; this is by design |

## Allow-listed device paths

Our NtCreateFile/NtOpenFile hooks classify NT device paths. Unknown devices
are blocked. The following are explicitly allowed:

| Device | Kind | Reason | Risk | Mitigation |
|---|---|---|---|---|
| `\Device\HarddiskVolume*` | HarddiskVolume | Normal file IO | FS-level | CoW + deny rules |
| `\Device\NamedPipe\*`, `\??\pipe\*` | NamedPipe | RPC, child IPC, DNS client | Scoped to named pipes | Process tree tracking |
| `\Device\ConDrv`, `CONIN$`, `CONOUT$` | Console | stdio | None | -- |
| `\Device\Null`, `NUL` | Null | `/dev/null` | None | -- |
| `\Device\Afd\*`, `\Device\Tcp`, `\Device\Udp` | Socket | Networking (TCP/UDP/DNS) | Direct IOCTL bypass of ws2_32 hook | WFP kernel filter enforces destination policy |
| `\Device\Nsi` | Socket | DNS resolver config queries | NsiSetParameter requires privileges | Sandbox runs unprivileged |
| `\Device\MountPointManager` | SystemQuery | .NET BCL volume queries | IOCTL_MOUNTMGR_CREATE_POINT needs SeRestorePrivilege | Sandbox lacks privilege |
| `\Device\IPT` | SystemQuery | Intel Processor Trace | Requires Admin | Sandbox is non-Admin |
| `\KernelObjects\*` | SystemQuery | Named sync primitives | Coordination side-channel | Accepted risk (not an escape) |
| `\Device\Dfs` | SystemQuery | DFS namespace resolution | UNC exfiltration via SMB | WFP SMB port 445 block (planned) |

### SystemQuery devices: read-only access enforced

SystemQuery devices (MountPointManager, IPT, KernelObjects, DFS) are allowed
for read-only access only. Write access (FILE_WRITE_DATA, GENERIC_WRITE) is
denied via `is_safe_with_access(kind, write)`. This prevents:
- MountPointManager: IOCTL_MOUNTMGR_CREATE_POINT (requires write handle)
- NSI: NsiSetParameter (requires write handle)

### Mitigated risk: direct AFD IOCTL

`\Device\Afd` is allowed, which means a sandboxed process can bypass our
ws2_32!connect hook by calling `NtDeviceIoControlFile` with `IOCTL_AFD_CONNECT`
directly. This is mitigated by WFP kernel filtering, which operates below
user-mode. If WFP filters are not registered (currently 0 on some configs),
this is an open gap.

**Status**: P2 audit in progress.

## Direct syscall defense analysis

Direct syscalls (Hell's Gate / Halo's Gate / Tartarus' Gate) bypass user-mode
ntdll hooks by reading the SSN at runtime and issuing `syscall` directly.
winrsbox defends against this with three layers:

| Layer | Mechanism | What it catches | Code |
|---|---|---|---|
| Pre-launch .text scan | `iced-x86` disassembly of target exe's `.text` section before resume | Compile-time embedded `syscall`/`sysenter`/`int 2eh` instructions | `launcher/src/main.rs:pre_launch_scan` |
| Content-aware RX scan | Disassembly of non-module memory on RW→RX transition | Runtime-generated shellcode containing syscall instructions | `hook/src/memory_guard.rs:hook_nt_protect_virtual_memory` |
| Process Mitigation Policies | `PROHIBIT_DYNAMIC_CODE_ALWAYS_ON` + `BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` | Prevents creation of new executable memory (kernel-enforced) | `launcher/src/mitigations.rs` |

**Test coverage**: `pre_launch_promotes_bypass_direct_syscall` (was `#[ignore]`, now
passes — pre-launch scan catches the `bypass_direct_syscall` payload before execution).
`pre_launch_refuses_static_syscall` verifies static syscall binaries are refused.

**Remaining gap**: A Hell's Gate variant that resolves the SSN at runtime and writes
the `syscall` instruction into dynamically-allocated memory. DynamicCodePolicy
blocks new executable memory creation (kernel-enforced), so this requires either:
- Bypassing DynamicCodePolicy (kernel exploit — out of scope)
- Using pre-existing executable memory from a loaded DLL (blocked by BLOCK_NON_MS)
- Operating in `--guard scan` mode (no DynamicCodePolicy — accepted risk for JIT)

**Decision**: Option A — accept as known gap. Rationale:
- AI-agent threat model: AI rarely writes direct-syscall shellcode
- Three defense layers raise the bar significantly
- ETW Threat Intelligence (Option B) requires admin/elevated launcher (non-default)
- Full ETW TI subscription is deferred until elevated launcher infrastructure exists

**Future work**: If elevated launcher becomes default, subscribe to
`Microsoft-Windows-Threat-Intelligence` ETW provider for real-time direct-syscall
monitoring and kill. ETW scoring already supports `DirectSyscallDetected` (score 15,
highest priority — see `launcher/src/etw.rs`).

## Known gaps

| Gap | Severity | Status |
|---|---|---|
| Runtime SSN-resolved direct syscall in scan mode | Low | Accepted (Option A): DynamicCodePolicy off for JIT compat; content-aware RX scan still active |
| ETW TI not subscribed (requires admin) | Low | Deferred: scoring infrastructure ready, needs elevated launcher |
| WFP registers 0 filters on some configs | ~~High~~ | **Fixed**: wrong condition key + missing sublayer/display |
| Direct AFD IOCTL bypasses ws2_32 hook | Medium | **Mitigated**: WFP now active (3 RFC1918 filters), kernel-level enforcement |
| DFS UNC exfiltration | ~~Medium~~ | **Fixed**: WFP blocks TCP ports 445 (SMB) and 139 (NetBIOS) |
| Junction/symlink/hardlink bypass | ~~High~~ | **Fixed**: link_guard blocks NtFsControlFile + NtSetInformationFile |
| COM/RPC/WMI escape | ~~High~~ | **Fixed**: alpc_guard blocks COM activation ALPC ports |
| Dangerous named pipes (SCM, TaskSched) | ~~Medium~~ | **Fixed**: pipe name deny-list in classify_device |
| Volume shadow copies | ~~Medium~~ | **Fixed**: shadowcopy paths classified as Unknown (blocked) |
| Privilege escalation | ~~Low~~ | **Fixed**: token_guard blocks dangerous NtAdjustPrivilegesToken |
| ETW behavioral detection not wired | ~~Low~~ | **Fixed**: ETW Kernel-Process listener active |
| Registry CoW (only deny-list) | Low | P3.2 (silent_ok for HKCU\Software writes) |
| cmd.exe /c doesn't work in sandbox | Low | Known limitation (DllMain injection) |
| NtAllocateVirtualMemory uses manual hook | Info | detour2 trampoline bug; manual hook works correctly |

## Defense in depth (layers)

```
Layer 1: Pre-launch .text scan (full mode)
  |
Layer 2: Process Mitigation Policies (DynamicCode, Signature, ExtensionPoint)
  |
Layer 3: ntdll inline hooks
  |-- FS hooks (NtCreateFile, NtOpenFile, NtQuery*)
  |-- Memory hooks (NtAllocate*, NtProtect*, NtMapView*, NtWrite*)
  |-- Inject hooks (NtCreateThread*, NtQueueApc*, NtSetContext*)
  |-- Registry hooks (NtCreateKey, NtSetValueKey, NtDeleteKey/Value)
  |-- Network hooks (ws2_32!connect)
  |
Layer 4: WFP kernel network filtering (RFC1918 block)
  |
Layer 5: Job Object (kill-on-close + memory limits)
  |
Layer 6: Content scanning (iced-x86 disassembly on RX transitions)
```

## Tested programs

All verified with exit=0, violations=0 in scan mode:

| Program | Notes |
|---|---|
| claude.exe -p "..." | Full API workflow, HTTPS, child processes |
| cargo --version, cargo build | Multi-process Rust build |
| PowerShell | .NET CLR, JIT, 500+ FS queries |
| python -c | CPython |
| node -e | V8 JIT |
| git status, git log | mingw64 git |
| curl (HTTPS) | TLS via schannel |

## 16 escape payloads (all blocked)

escape_alloc_rwx, escape_jit_protect, escape_heap_to_exec, escape_stack_exec,
escape_map_anon_rwx, escape_ntdll_double_map, escape_remote_thread,
escape_thread_hijack, escape_hwbp_injection, escape_apc_injection,
escape_foreign_alloc_rwx, escape_foreign_write_syscall,
escape_unpacker_syscall, escape_self_modify_syscall,
escape_static_syscall (pre-launch refused),
bypass_direct_syscall (pre-launch refused).
