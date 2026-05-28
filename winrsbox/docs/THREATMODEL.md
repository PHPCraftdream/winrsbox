# Threat Model

winrsbox sandboxes AI coding agents (Claude Code, etc.) and compilers on Windows.
This document describes what we protect against, what we don't, and known gaps.

Last updated: `8de757f` (2026-05-26).

## What's new since `ac0387a`

| Commit | Summary |
|---|---|
| `9849954` | **system_guard** -- NtCreateDebugObject unconditional deny |
| `66adbce` | `.winrsbox` enum filter offset fixes for all FileInformationClass variants |
| `dabe30f` | P0 escape via FILE_OPEN_IF + 6 P1 cleanups; link_guard deleted (merged into set_info hook) |
| `d53fd2a` | reg_hooks: remove dead duplicate handler |
| `dabe30f` | set_io_status 8-byte union write fix |
| `c853af2` | Narrowed `is_dangerous_pipe` to exact-segment match (was substring -- no false-positives) |
| `45efb7f` | hooks.rs split into focused sub-modules |
| `c568526` | **inject_guard** -- NtQueueApcThreadEx (Win10+ early-bird APC) |
| `cb576d3` | **proc_guard** -- NtSetInformationProcess foreign-PID dangerous class deny |
| `98f4c15` | **NtFsControlFile** -- FSCTL_PIPE_IMPERSONATE block |
| `15aba77` | FSCTL_PIPE_IMPERSONATE: closes named-pipe privilege escalation vector |
| `0df0404` | **alpc_guard** -- 5 additional security-service port patterns |
| `d327bb7` | **memory_guard** -- NtUnmapViewOfSection cross-proc deny |
| `c4bed1b` | **memory_guard** -- NtMapViewOfSection foreign-proc deny |
| `0d1f837` | **system_guard** -- NtShutdownSystem + NtSetSystemInformation deny |
| `818e0ee` | escape_unmap/map_foreign tests bypass proc_guard to exercise memory_guard directly |
| `535f1bd` | ipc_decide fail-closed after 3 consecutive failures (tightened from 10, audit T1) |
| `5b8a979` | proc_guard: NtTerminateProcess hook untrack child PID on exit |
| `f74930e` | Kernel Event signaling for hook.dll injection verification (P1-1) |
| `8de757f` | **alpc_guard** -- wmi/wbem port patterns; exact startsWith segment match |

## In-scope threats

### Filesystem escape
Sandboxed writes go to a CoW overlay; reads pass through to the real FS.
Deny rules block writes to system directories (`C:\Windows`).

**Hooks**: NtCreateFile, NtOpenFile, NtQueryAttributesFile, NtQueryFullAttributesFile.

#### FS path canonicalization (`check_path_traversal`)

Early-deny filter applied in NtCreateFile and NtOpenFile before any policy
decision. Blocks five classes of path-based sandbox escape:

| Vector | Detection | Result |
|---|---|---|
| `GLOBALROOT` alternate namespace (`\??\GLOBALROOT\Device\...`) | Substring match on lowercased NT path | STATUS_ACCESS_DENIED |
| `FILE_OPEN_BY_FILE_ID` (CreateOptions flag 0x2000) | Bit test on CreateOptions | STATUS_ACCESS_DENIED |
| Alternate Data Streams (colon after drive letter) | Second `:` after drive-letter colon; whitelisted: `Zone.Identifier`, `$DATA`, `$INDEX_ALLOCATION` | STATUS_ACCESS_DENIED (non-whitelisted) |
| 8.3 short names (`~<digit>` pattern, e.g. `PROGRA~1`) | `needs_short_name_resolve()` regex on lowercased path | STATUS_ACCESS_DENIED |
| `.winrsbox` segment | Substring/suffix match | STATUS_OBJECT_NAME_NOT_FOUND |

**Code**: `hook/src/fs_hooks.rs:check_path_traversal` (was `hooks.rs` -- split in `45efb7f`).

#### NtSetInformationFile -- rename/hardlink/delete guard

Blocks file operations that would move data or links outside the sandbox
working directory:

| FileInformationClass | What it blocks |
|---|---|
| FileRenameInformation (10, 65) | Rename target outside SANDBOX_CWD |
| FileLinkInformation (11, 72) | Hard-link target outside SANDBOX_CWD |
| FileDispositionInformation (13, 64) | Delete-on-close for source outside SANDBOX_CWD |

Note: the separate `link_guard` module was deleted in `dabe30f`; this logic now
lives exclusively in `hook_nt_set_information_file`.

**Code**: `hook/src/fs_hooks.rs:hook_nt_set_information_file`.

#### NtFsControlFile -- reparse-point + pipe-impersonation guard

Unconditionally denies junction/symlink creation and named-pipe privilege
escalation from within the sandbox:

- `FSCTL_SET_REPARSE_POINT` (0x900A4)
- `FSCTL_SET_REPARSE_POINT_EX` (0x900E4)
- `FSCTL_DELETE_REPARSE_POINT` (0x900AC)
- `FSCTL_PIPE_IMPERSONATE` (0x11C017) -- blocks server-side impersonation of the
  sandboxed client; prevents token theft via a named pipe server outside the sandbox.

**Code**: `hook/src/fs_hooks.rs:hook_nt_fs_control_file`.

#### Hide .winrsbox state directory

Sandbox state directory (overlay, policy, logs) is invisible to sandboxed
processes via two mechanisms:

1. **NtCreateFile/NtOpenFile**: `check_path_traversal` returns STATUS_OBJECT_NAME_NOT_FOUND for any path containing `\.winrsbox\` or ending with `\.winrsbox`.
2. **NtQueryDirectoryFile**: linked-list entry filter removes `.winrsbox` entries from directory listings for FileInformationClass 1, 2, 3, 12, 37, 38 (offset bug fixed in `66adbce`).

**Code**: `hook/src/fs_hooks.rs:filter_dot_winrsbox`.

### Cross-process injection
Blocks the sandboxed process from injecting code into other processes.

**Hooks**: NtCreateThreadEx, NtCreateThread, NtQueueApcThread, NtQueueApcThreadEx,
NtSetContextThread.

`NtQueueApcThreadEx` is the Win10+ extended variant used in early-bird APC
injection; it accepts an explicit `ApcRoutine` and `SystemArgument` with an
additional `QueueType` parameter. Deny policy mirrors `NtQueueApcThread`: any
target thread in a non-owned process is denied.

**Checks**: three-layer filter (caller DLL, system PID, armed state).

**Code**: `hook/src/inject_guard.rs`.

### Process guard (`proc_guard`)

Hooks that close cross-process manipulation and dangerous-spawn vectors:

| Hook | Target | Policy |
|---|---|---|
| NtOpenProcess | Foreign PIDs (non-owned) | Deny dangerous access: TERMINATE, CREATE_THREAD, VM_OPERATION, VM_WRITE, DUP_HANDLE, CREATE_PROCESS, SET_QUOTA, SET_INFORMATION, SUSPEND_RESUME. Allow VM_READ, QUERY_INFO. |
| NtCreateUserProcess | Image path | Denylist: `wsl`, `wmic`, `mshta`, `regsvr32`, `rundll32`, `bitsadmin`, `certutil`, `installutil`, `msbuild`, `regasm`, `regsvcs` (LOLBins). |
| NtCreateUserProcess | PROC_THREAD_ATTRIBUTE_PARENT_PROCESS | Block parent-PID spoofing -- unconditional deny if attribute present. |
| NtAssignProcessToJobObject | Any call | Unconditional deny -- prevents nested-Job escape on Win10+. |
| NtSetInformationProcess | Foreign PID, dangerous class | Deny ProcessAccessToken, ProcessUserModeIOPL, ProcessBreakOnTermination, ProcessMitigationPolicy for any non-owned PID. Prevents mitigation-policy stripping and token swaps on other processes. |
| NtTerminateProcess | Owned child PID | Calls `process_tracker::untrack` so the PID cannot be reused to impersonate a trusted child (PID-reuse poisoning prevention). |

Owned PIDs (self + tracked children via `process_tracker`) are allowed for
NtOpenProcess. The tracker is updated in `hook_nt_create_user_process` via
`process_tracker::mark_spawned` and decremented in `hook_nt_terminate_process`
via `process_tracker::untrack`.

**Code**: `hook/src/proc_guard.rs`.

### Memory guard (`memory_guard`)

Blocks process hollowing and cross-process memory manipulation:

| Hook | Policy |
|---|---|
| NtAllocateVirtualMemory | Foreign-process exec alloc denied |
| NtProtectVirtualMemory | RW->RX transition triggers content scan; foreign-process exec protect denied |
| NtMapViewOfSection | `.text` section of user DLLs scanned; **foreign-process mapping denied** (closes process-hollowing step 1) |
| NtUnmapViewOfSection | **Cross-process unmap denied** (closes process-hollowing step 2: unmapping the host image before writing shellcode) |
| NtWriteVirtualMemory | Foreign-process write scanned for syscall instructions |

Process hollowing requires both an unmap (evict host image) and a remap (load
attacker image). Both halves are now denied for non-owned processes, making the
attack fail-closed regardless of which step is attempted first.

**Test coverage**: `escape_unmap_foreign` and `escape_map_foreign` bypass
`proc_guard` (so the test process is allowed to open the target) and exercise
`memory_guard` hooks directly (`818e0ee`).

**Code**: `hook/src/memory_guard.rs`.

### System guard (`system_guard`)

Blocks system-level privileged operations:

| Hook | Policy |
|---|---|
| NtShutdownSystem | Unconditional deny -- prevents sandbox from rebooting/shutting down the host |
| NtSetSystemInformation | Unconditional deny -- blocks kernel parameter modification (e.g. loading drivers via SystemModuleInformation, altering memory limits) |
| NtCreateDebugObject | Unconditional deny -- prevents attaching a debugger to system or other processes; closes debug-attach-based APC/exception escape |

**Code**: `hook/src/system_guard.rs`.

### Process lifecycle and injection verification

#### Hook injection verification (P1-1)

After injecting `hook.dll` into the sandboxed child, the launcher waits on a
named kernel Event (`winrsbox-hook-ready-<pid>`) using `WaitForSingleObject`
with a 5-second timeout (executed via `spawn_blocking` so the async runtime
is not stalled).

- If `hook.dll` successfully initializes, it signals the Event from `DllMain`.
- If the Event is not signaled within the timeout (DLL injection failed, DLL was
  blocked by AV, or `DllMain` panicked), the launcher terminates the child and
  reports an injection failure.

This is fail-closed: a child that never signals readiness is killed, not
allowed to run unhooked.

**Code**: `launcher/src/main.rs` (Event wait), `hook/src/lib.rs` (Event signal).

#### IPC fail-closed

The in-process IPC channel (sandbox child -> launcher policy server) counts
consecutive failures. After **3 consecutive IPC failures** the sandboxed child
calls `TerminateProcess(GetCurrentProcess(), 1)` and exits. This prevents a
child from operating in a degraded / partially-hooked state where policy
decisions default to allow.

3 is chosen to fail closed quickly under adversarial pipe-kill; transient
hiccups are rare and 3 successive failures with retry already represents
~10s of latency. The threshold is pinned by a unit test in
`hook/src/ipc_client.rs` (`fail_threshold_pinned_to_three`).

**Code**: `hook/src/ipc.rs:ipc_decide`.

### COM guard (`com_guard`)

Hooks three COM activation functions in `combase.dll`:
- `CoCreateInstance`
- `CoCreateInstanceEx`
- `CoGetClassObject`

CLSID denylist (14 entries):

| CLSID name | Escape vector |
|---|---|
| Shell.Application | ShellExecute from COM |
| ShellWindows | Explorer shell automation |
| WScript.Shell | Scripting host -- Run/Exec |
| WScript.Shell.1 | Scripting host (versioned) |
| Scripting.FileSystemObject | FS access outside sandbox |
| WbemLocator | WMI -- Win32_Process.Create |
| WbemScripting.SWbemLocator | WMI (scripting variant) |
| Schedule.Service | Task Scheduler -- persistence |
| CTaskScheduler | Task Scheduler (legacy CLSID) |
| BackgroundCopyManager | BITS -- file download/upload |
| Excel.Application | Office automation -- macro exec |
| Word.Application | Office automation -- macro exec |
| Outlook.Application | Office automation -- email send |

**Code**: `hook/src/com_guard.rs`.

### Token guard (`token_guard`)

| Hook | Policy |
|---|---|
| NtAdjustPrivilegesToken | Block enabling: SeDebugPrivilege, SeTakeOwnershipPrivilege, SeRestorePrivilege, SeBackupPrivilege, SeLoadDriverPrivilege, SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege. DisableAllPrivileges=TRUE is allowed. |
| NtOpenProcessTokenEx | Foreign PID: deny TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_ASSIGN_PRIMARY, TOKEN_ADJUST_*. |
| NtDuplicateToken | Block TokenPrimary duplication. |
| NtSetInformationThread | Block ThreadImpersonationToken (class 5). |

**Code**: `hook/src/token_guard.rs`.

### Service guard (`service_guard`)

| Target | Denied access flags |
|---|---|
| SCM (OpenSCManagerW) | SC_MANAGER_CREATE_SERVICE, LOCK, MODIFY_BOOT_CONFIG, ALL_ACCESS, WRITE_DAC, WRITE_OWNER |
| Service (OpenServiceW) | SERVICE_CHANGE_CONFIG, START, STOP, PAUSE_CONTINUE, DELETE, ALL_ACCESS, WRITE_DAC, WRITE_OWNER |

**Code**: `hook/src/service_guard.rs`.

### UI guard (`ui_guard`)

**Tier 1 -- kill-on-call**: `SendInput`, `keybd_event`, `mouse_event`, `BlockInput`, `SetCursorPos`.

**Tier 2 -- soft deny**: `FindWindowW/A`, `FindWindowExW/A`, `PostMessageW/A`,
`SendMessageW/A` (foreign HWND only), `OpenClipboard`, `GetClipboardData`
(soft-deny by default; opt-in via `--strict-clipboard`).

**Code**: `hook/src/ui_guard.rs`.

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

### Registry persistence vectors

Deny writes to persistence-sensitive registry paths via NtSetValueKey/NtCreateKey hooks.
Policy enforced by `PERSISTENCE_DENY_SUFFIXES`:

| Denied suffix | Attack |
|---|---|
| `\Software\Microsoft\Windows NT\CurrentVersion\Windows` | AppInit_DLLs |
| `\Software\Wow6432Node\...\Windows` | AppInit_DLLs (WoW64) |
| `\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` | IFEO Debugger |
| `\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit` | SilentProcessExit MonitorProcess |
| `\System\CurrentControlSet\Control\Session Manager\AppCertDlls` | AppCertDlls |
| `\System\CurrentControlSet\Services\` | Service ImagePath |

**Registry CoW Phase 2**: in-memory overlay with tombstones for HKCU\Software
writes. Reads merge overlay + real registry.

**Code**: `hook/src/reg_hooks.rs`, `hook/src/reg_overlay.rs`.

### Network egress
- **WFP**: kernel-level outbound filters for RFC1918, TCP 445 (SMB), TCP 139 (NetBIOS).
- **ws2_32 connect hook**: IPC-based destination approval.

### ALPC guard (`alpc_guard`)

Hooks NtAlpcConnectPort. Blocks connections by port name prefix/segment match.

**Blocked patterns** (18 total):

| Pattern group | Ports |
|---|---|
| COM activation | `ole`, `actkernel`, `comlaunch` |
| Security services | `lsasspirpc`, `samss`, `netlogon`, `ntsvcs`, `svcctl` |
| WMI / WBEM | `wbem`, `wbemprox`, `wbemntf`, `wbemcore`, `winmgmt` |

Match uses exact startsWith on the final path segment (e.g. `\RPC Control\wbem`
matches; `\RPC Control\wbemNothing` also matches as a prefix, but `Console*`
false-positives that plagued the old substring match are eliminated).

`epmapper` is allowed (needed for DNS, print, etc.).

**Code**: `hook/src/alpc_guard.rs`.

### Process lifecycle
- **Job Object**: `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` + optional memory limits.
- **Job breakaway**: `BREAKAWAY_OK` and `SILENT_BREAKAWAY_OK` explicitly UNSET.
  `NtAssignProcessToJobObject` unconditionally denied by `proc_guard`.
- **Process Mitigation Policies** (full mode): `ProcessDynamicCodePolicy`,
  `ProcessSignaturePolicy` (MS-signed DLLs only), `ExtensionPointDisablePolicy`.

### DLL sideloading mitigation

`ProcessImageLoadPolicy` applied via:
1. **Launcher**: `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` with `PreferSystem32` + `NoRemote`.
2. **Hook DLL self-apply**: `SetProcessMitigationPolicy(ProcessImageLoadPolicy)` during hook init.

### Named pipe denylist

14 dangerous named pipes blocked via exact-segment match in `classify_device`:
`lsass`, `spoolss`, `samr`, `netlogon`, `wkssvc`, `lsarpc`, `eventlog`,
`browser`, `epmapper`, `svcctl`, `psexesvc`, `srvsvc`, `winreg`, `atsvc`.

Exact-segment match: `\Device\NamedPipe\svcctl` matches; `svcctlx` does not.

**Code**: `policy/src/dev.rs:is_dangerous_pipe`.

### Environment sanitization

`env_guard::sanitize()` strips sensitive environment variables before spawning.
Whitelisted: PATH, TEMP, HOME, USERPROFILE, SystemRoot, FS_SANDBOX_*.

**Code**: `launcher/src/env_guard.rs`.

## Out-of-scope threats

| Threat | Why out-of-scope |
|---|---|
| Kernel-mode exploits | Sandbox lives in user-mode |
| CPU side-channels (Meltdown/Spectre) | Requires CPU-level mitigation |
| Social engineering | Sandbox doesn't analyze code intent |
| WSL traffic | Separate kernel; WinDivert integration (future) |
| DLL search-order hijacking by sandbox | hook.dll injection is by design |

## Allow-listed device paths

| Device | Kind | Reason | Risk | Mitigation |
|---|---|---|---|---|
| `\Device\HarddiskVolume*` | HarddiskVolume | Normal file IO | FS-level | CoW + deny rules |
| `\Device\NamedPipe\*`, `\??\pipe\*` | NamedPipe | RPC, child IPC, DNS | Scoped | Process tree + 14-entry denylist |
| `\Device\ConDrv`, `CONIN$`, `CONOUT$` | Console | stdio | None | -- |
| `\Device\Null`, `NUL` | Null | `/dev/null` | None | -- |
| `\Device\Afd\*`, `\Device\Tcp`, `\Device\Udp` | Socket | Networking | Direct IOCTL bypass | WFP kernel filter |
| `\Device\Nsi` | Socket | DNS resolver config | NsiSetParameter needs privs | Sandbox is unprivileged |
| `\Device\MountPointManager` | SystemQuery | .NET BCL volume queries | IOCTL_MOUNTMGR_CREATE_POINT needs SeRestorePrivilege | Sandbox lacks privilege |
| `\Device\IPT` | SystemQuery | Intel Processor Trace | Requires Admin | Sandbox is non-Admin |
| `\KernelObjects\*` | SystemQuery | Named sync primitives | Side-channel | Accepted risk |
| `\Device\Dfs` | SystemQuery | DFS namespace resolution | UNC exfiltration | WFP SMB block |

SystemQuery devices: write access (FILE_WRITE_DATA, GENERIC_WRITE) denied.

### Mitigated risk: direct AFD IOCTL

`\Device\Afd` allowed; direct `IOCTL_AFD_CONNECT` bypasses ws2_32!connect hook.
Mitigated by WFP kernel filtering below user-mode.

## Direct syscall defense analysis

| Layer | Mechanism | What it catches |
|---|---|---|
| Pre-launch .text scan | `iced-x86` disassembly before resume | Compile-time `syscall`/`sysenter`/`int 2eh` |
| Content-aware RX scan | Disassembly on RW->RX transition | Runtime-generated shellcode |
| Process Mitigation Policies | `PROHIBIT_DYNAMIC_CODE_ALWAYS_ON` + `BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` | Prevents new executable memory (kernel-enforced) |

**Remaining gap**: Hell's Gate variant that resolves SSN at runtime into
dynamic memory. DynamicCodePolicy blocks this (full mode); scan mode accepts
the risk for JIT compat (content-aware RX scan still active).

**Future work**: `Microsoft-Windows-Threat-Intelligence` ETW provider subscription
when elevated launcher infrastructure exists.

## Known gaps

| Gap | Severity | Status |
|---|---|---|
| Runtime SSN-resolved direct syscall in scan mode | Low | Accepted: DynamicCodePolicy off for JIT; RX content scan still active |
| ETW TI not subscribed (requires admin) | Low | Deferred: scoring infra ready, needs elevated launcher |
| Direct AFD IOCTL bypasses ws2_32 hook | Low | Mitigated: WFP kernel-level enforcement |
| ALPC direct LRPC bypass (hand-crafted port name) | Low | Residual: 18 patterns cover known services; arbitrary hand-crafted port names not covered |
| Registry CoW overlay not covering all hives | Low | Phase 2 covers HKCU\Software; HKLM uses deny-only policy |
| cmd.exe /c doesn't work in sandbox | Low | Known limitation (DllMain injection timing) |
| NtAllocateVirtualMemory uses manual hook | Info | detour2 trampoline bug; manual hook works correctly |

### Resolved gaps (this cycle)

| Gap | Resolution | Commit |
|---|---|---|
| Process hollowing (unmap + remap) | NtUnmapViewOfSection + NtMapViewOfSection cross-proc deny | `d327bb7`, `c4bed1b` |
| Named-pipe privilege escalation (FSCTL_PIPE_IMPERSONATE) | Blocked in NtFsControlFile | `98f4c15` |
| NtSetInformationProcess token/mitigation swap | Foreign-PID dangerous class deny | `cb576d3` |
| Early-bird APC injection (NtQueueApcThreadEx) | Deny in inject_guard | `c568526` |
| Debug-attach escape (NtCreateDebugObject) | Unconditional deny in system_guard | `9849954` |
| Host shutdown/reboot + kernel param modification | NtShutdownSystem + NtSetSystemInformation deny | `0d1f837` |
| WMI/WBEM via direct ALPC (bypassing com_guard) | wbem* port patterns in alpc_guard | `8de757f` |
| Console* false-positives in alpc_guard | Exact startsWith segment match | `8de757f` |
| IPC silent fail-open | Fail-closed after 3 consecutive failures (tightened from 10, audit T1) | `535f1bd` |
| PID-reuse poisoning (stale tracker entry) | NtTerminateProcess untrack | `5b8a979` |
| Hook injection not verified (child ran unhooked on DLL fail) | Kernel Event + WaitForSingleObject, fail-closed on timeout | `f74930e` |
| P0 escape via FILE_OPEN_IF disposition | Fixed disposition handling + full audit | `dabe30f` |
| set_io_status union write (8-byte vs 4-byte) | Correct 8-byte union write | `dabe30f` |
| Surrogate pair corruption in path handling | u16 surrogate pair fix | `45efb7f` |
| dangerous_pipe substring false-positive | Exact-segment match | `c853af2` |
| link_guard and set_info hook duplication | link_guard deleted; logic consolidated | `dabe30f` |

### Previously resolved gaps

| Gap | Resolution |
|---|---|
| WFP registers 0 filters | Fixed: wrong condition key + missing sublayer/display |
| DFS UNC exfiltration | WFP blocks TCP 445 (SMB) and 139 (NetBIOS) |
| Junction/symlink/hardlink bypass | NtFsControlFile + NtSetInformationFile |
| COM/RPC/WMI escape | com_guard CLSID denylist + alpc_guard |
| Dangerous named pipes | 14-entry exact-segment pipe denylist |
| Volume shadow copies | shadowcopy paths classified Unknown |
| Privilege escalation | token_guard |
| ETW behavioral detection not wired | ETW Kernel-Process listener active |
| P0 escape via FILE_OPEN_IF | Full-repo audit |

## Defense in depth (layers)

```
Layer 1: Pre-launch .text scan (full mode)
  |
Layer 2: Process Mitigation Policies
  |-- DynamicCodePolicy (full mode)
  |-- SignaturePolicy -- MS-signed DLLs only (full mode)
  |-- ExtensionPointDisablePolicy
  |-- ImageLoadPolicy -- PreferSystem32 + NoRemote (scan + full)
  |
Layer 3: Hook injection verification
  |-- Kernel Event signal from DllMain; launcher waits 5s; fail-closed on timeout
  |
Layer 4: ntdll / win32 inline hooks
  |-- FS hooks (NtCreateFile, NtOpenFile, NtQuery*, NtSetInformationFile,
  |             NtFsControlFile [reparse + PIPE_IMPERSONATE], NtQueryDirectoryFile)
  |-- Memory hooks (NtAllocate*, NtProtect*, NtMapView* [+cross-proc deny],
  |                 NtUnmapView* [cross-proc deny], NtWrite*)
  |-- Inject hooks (NtCreateThread*, NtQueueApcThread, NtQueueApcThreadEx,
  |                 NtSetContextThread)
  |-- Process hooks (NtOpenProcess, NtAssignProcessToJobObject,
  |                  NtCreateUserProcess, NtSetInformationProcess,
  |                  NtTerminateProcess [untrack])
  |-- System hooks (NtShutdownSystem, NtSetSystemInformation, NtCreateDebugObject)
  |-- Registry hooks (NtCreateKey, NtSetValueKey, NtDeleteKey/Value)
  |-- Token hooks (NtAdjustPrivilegesToken, NtOpenProcessTokenEx,
  |                NtDuplicateToken, NtSetInformationThread)
  |-- Network hooks (ws2_32!connect)
  |-- ALPC hooks (NtAlpcConnectPort -- 18 blocked patterns)
  |-- COM hooks (CoCreateInstance, CoCreateInstanceEx, CoGetClassObject)
  |-- Service hooks (OpenSCManagerW, OpenServiceW)
  |-- UI hooks (SendInput, keybd_event, mouse_event, BlockInput, SetCursorPos,
  |             FindWindow*, PostMessage*, SendMessage*, OpenClipboard, GetClipboardData)
  |
Layer 5: IPC fail-closed (3 consecutive failures -> self-terminate)
  |
Layer 6: WFP kernel network filtering (RFC1918 + SMB/NetBIOS block)
  |
Layer 7: Job Object (kill-on-close + memory limits + breakaway blocked)
  |
Layer 8: Content scanning (iced-x86 disassembly on RX transitions)
  |
Layer 9: Environment sanitization (API keys / tokens stripped before spawn)
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

## 84 tests, 18 escape payloads (all blocked)

**Escape payloads**:
escape_alloc_rwx, escape_jit_protect, escape_heap_to_exec, escape_stack_exec,
escape_map_anon_rwx, escape_ntdll_double_map, escape_remote_thread,
escape_thread_hijack, escape_hwbp_injection, escape_apc_injection,
escape_foreign_alloc_rwx, escape_foreign_write_syscall,
escape_unpacker_syscall, escape_self_modify_syscall,
escape_static_syscall (pre-launch refused),
bypass_direct_syscall (pre-launch refused),
escape_unmap_foreign (NtUnmapViewOfSection cross-proc -- blocked by memory_guard),
escape_map_foreign (NtMapViewOfSection cross-proc -- blocked by memory_guard).
