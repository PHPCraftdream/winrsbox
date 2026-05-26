# Threat Model

winrsbox sandboxes AI coding agents (Claude Code, etc.) and compilers on Windows.
This document describes what we protect against, what we don't, and known gaps.

Last updated: `45efb7f` (2026-05-26).

## What's new since `92aeb62`

| Commit | Summary |
|---|---|
| `dff7d4e` | **proc_guard** -- NtOpenProcess dangerous-access deny, NtCreateUserProcess image denylist, parent-spoof block, NtAssignProcessToJobObject deny |
| `4c64a15` | **ui_guard** -- input-injection kill-on-call, cross-window soft deny, Job UI restrictions |
| `4fd192f` | `--strict-clipboard` opt-in flag (default-allow clipboard) |
| `15d9bac` | **com_guard** -- CoCreateInstance/Ex + CoGetClassObject CLSID denylist |
| `5a65f33` | **com_guard** -- close CoGetClassObject gap |
| `a9bfc65` | **FS path canonicalization** -- block GLOBALROOT, FILE_OPEN_BY_FILE_ID, ADS, 8.3 short names |
| `03419a9` | **Job breakaway block** -- NtAssignProcessToJobObject hook + BREAKAWAY flag invariant tests |
| `d3665f5` | **token_guard** -- NtOpenProcessTokenEx, NtDuplicateToken, NtSetInformationThread(ThreadImpersonationToken) |
| `7e7681a` | **DLL sideloading mitigation** -- PreferSystem32Images + NoRemoteImages via PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY + hook self-apply |
| `05f43d3` | **Reg hijack closure** -- SilentProcessExit + Services deny suffixes, IFEO e2e test |
| `ba8eb16` | **service_guard** -- OpenSCManagerW/OpenServiceW dangerous-access deny |
| `3f26a2d` | **Hide .winrsbox** -- STATUS_OBJECT_NAME_NOT_FOUND on open + NtQueryDirectoryFile enum filter |
| `d1f8349` | **NtSetInformationFile** -- block rename/hardlink/delete outside SANDBOX_CWD |
| `a1a04a0` | **NtFsControlFile** -- block FSCTL_SET_REPARSE_POINT/_EX, FSCTL_DELETE_REPARSE_POINT |
| `38d7eb0` | **Named pipe denylist** expanded to 14 entries (exact-segment match) |
| `c853af2` | Narrowed `is_dangerous_pipe` to exact-segment match (was substring) |
| `66adbce` | `.winrsbox` enum filter offset fixes for all FileInformationClass variants |
| `dabe30f` | P0 escape via FILE_OPEN_IF + 6 P1 cleanups |
| `6296501` | **Registry CoW Phase 2** -- in-memory overlay with tombstones |
| `465f0b1` | **Env sanitization** -- strip API keys/tokens/secrets before child spawn |

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

**Code**: `hook/src/hooks.rs:check_path_traversal`.

#### NtSetInformationFile -- rename/hardlink/delete guard

Blocks file operations that would move data or links outside the sandbox
working directory:

| FileInformationClass | What it blocks |
|---|---|
| FileRenameInformation (10, 65) | Rename target outside SANDBOX_CWD |
| FileLinkInformation (11, 72) | Hard-link target outside SANDBOX_CWD |
| FileDispositionInformation (13, 64) | Delete-on-close for source outside SANDBOX_CWD |

**Code**: `hook/src/hooks.rs:hook_nt_set_information_file`.

#### NtFsControlFile -- reparse-point guard

Unconditionally denies junction/symlink creation from within the sandbox:

- `FSCTL_SET_REPARSE_POINT` (0x900A4)
- `FSCTL_SET_REPARSE_POINT_EX` (0x900E4)
- `FSCTL_DELETE_REPARSE_POINT` (0x900AC)

**Code**: `hook/src/hooks.rs:hook_nt_fs_control_file`.

#### Hide .winrsbox state directory

Sandbox state directory (overlay, policy, logs) is invisible to sandboxed
processes via two mechanisms:

1. **NtCreateFile/NtOpenFile**: `check_path_traversal` returns STATUS_OBJECT_NAME_NOT_FOUND for any path containing `\.winrsbox\` or ending with `\.winrsbox`.
2. **NtQueryDirectoryFile**: linked-list entry filter removes `.winrsbox` entries from directory listings for FileInformationClass 1, 2, 3, 12, 37, 38.

**Code**: `hook/src/hooks.rs:filter_dot_winrsbox`.

### Cross-process injection
Blocks the sandboxed process from injecting code into other processes.

**Hooks**: NtCreateThreadEx, NtCreateThread, NtQueueApcThread, NtSetContextThread.
**Checks**: three-layer filter (caller DLL, system PID, armed state).

### Process guard (`proc_guard`)

Three hooks that close cross-process manipulation and dangerous-spawn vectors:

| Hook | Target | Policy |
|---|---|---|
| NtOpenProcess | Foreign PIDs (non-owned) | Deny dangerous access: TERMINATE, CREATE_THREAD, VM_OPERATION, VM_WRITE, DUP_HANDLE, CREATE_PROCESS, SET_QUOTA, SET_INFORMATION, SUSPEND_RESUME. Allow VM_READ, QUERY_INFO (info-leak is out of scope). |
| NtCreateUserProcess | Image path | Denylist: `wsl`, `wmic`, `mshta`, `regsvr32`, `rundll32`, `bitsadmin`, `certutil`, `installutil`, `msbuild`, `regasm`, `regsvcs` (LOLBins). |
| NtCreateUserProcess | PROC_THREAD_ATTRIBUTE_PARENT_PROCESS | Block parent-PID spoofing -- unconditional deny if attribute present. |
| NtAssignProcessToJobObject | Any call | Unconditional deny -- prevents nested-Job escape on Win10+. |

Owned PIDs (self + tracked children via `process_tracker`) are allowed for
NtOpenProcess. The tracker is updated in `hook_nt_create_user_process` via
`process_tracker::mark_spawned`.

**Code**: `hook/src/proc_guard.rs`.

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

Four hooks that block privilege escalation and token-based sandbox escape:

| Hook | Policy |
|---|---|
| NtAdjustPrivilegesToken | Block enabling: SeDebugPrivilege, SeTakeOwnershipPrivilege, SeRestorePrivilege, SeBackupPrivilege, SeLoadDriverPrivilege, SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege. DisableAllPrivileges=TRUE is allowed. |
| NtOpenProcessTokenEx | Foreign PID: deny TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_ASSIGN_PRIMARY, TOKEN_ADJUST_*. Self-token operations (GetTokenInformation etc.) pass through. |
| NtDuplicateToken | Block TokenPrimary duplication (prevents elevation via primary token). |
| NtSetInformationThread | Block ThreadImpersonationToken (class 5) -- prevents thread-level impersonation. |

**Code**: `hook/src/token_guard.rs`.

### Service guard (`service_guard`)

Hooks `advapi32.dll!OpenSCManagerW` and `advapi32.dll!OpenServiceW` to block
dangerous access masks. Read-only access (CONNECT, ENUMERATE, QUERY_CONFIG,
QUERY_STATUS, READ_CONTROL) is allowed.

| Target | Denied access flags |
|---|---|
| SCM (OpenSCManagerW) | SC_MANAGER_CREATE_SERVICE, LOCK, MODIFY_BOOT_CONFIG, ALL_ACCESS, WRITE_DAC, WRITE_OWNER |
| Service (OpenServiceW) | SERVICE_CHANGE_CONFIG, START, STOP, PAUSE_CONTINUE, DELETE, ALL_ACCESS, WRITE_DAC, WRITE_OWNER |

**Code**: `hook/src/service_guard.rs`.

### UI guard (`ui_guard`)

Two tiers of protection against UI-based escape:

**Tier 1 -- kill-on-call** (immediate process termination):
- `SendInput` -- synthetic keyboard/mouse input
- `keybd_event` -- legacy keyboard synthesis
- `mouse_event` -- legacy mouse synthesis
- `BlockInput` -- block all user input
- `SetCursorPos` -- cursor manipulation

**Tier 2 -- soft deny** (return NULL/FALSE, no kill):
- `FindWindowW/A`, `FindWindowExW/A` -- cross-window discovery
- `PostMessageW/A`, `SendMessageW/A` -- cross-process window messaging (foreign HWND only; own-process windows pass through)
- `OpenClipboard`, `GetClipboardData` -- clipboard access (soft-deny by default; opt-in via `--strict-clipboard`)

Job object UI limits (`JOB_OBJECT_UILIMIT_HANDLES`, `READCLIPBOARD`) are set
but not reliably enforced on Win10 19045 -- user-mode hooks fill the gap.

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

### Memory escalation in foreign processes
Blocks sandboxed process from allocating/protecting executable memory in
external (non-owned) processes. NtWriteVirtualMemory to external processes
scanned for syscall instructions.

### Registry persistence vectors

Deny writes to persistence-sensitive registry paths via NtSetValueKey/NtCreateKey hooks.
Policy is enforced by `PERSISTENCE_DENY_SUFFIXES` in the launcher IPC server:

| Denied suffix | Attack |
|---|---|
| `\Software\Microsoft\Windows NT\CurrentVersion\Windows` | AppInit_DLLs -- DLL injection into every GUI process |
| `\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows` | AppInit_DLLs (WoW64 variant) |
| `\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` | IFEO Debugger -- intercept any exe launch |
| `\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit` | SilentProcessExit MonitorProcess -- arbitrary code on target exit |
| `\System\CurrentControlSet\Control\Session Manager\AppCertDlls` | AppCertDlls -- DLL loaded into every CreateProcess caller |
| `\System\CurrentControlSet\Services\` | Service ImagePath -- SCM launches attacker binary as SYSTEM |

**Registry CoW Phase 2**: in-memory overlay with tombstones for HKCU\Software
writes (`reg_overlay.rs`). Writes are captured in the overlay; deletes recorded
as tombstones. Reads merge overlay + real registry. This replaces the
deny-only model for non-persistence paths.

**Code**: `hook/src/reg_hooks.rs`, `hook/src/reg_overlay.rs`, `launcher/src/main.rs`.

### Network egress
- **WFP**: kernel-level outbound filters for RFC1918 (lateral movement block),
  TCP 445 (SMB), TCP 139 (NetBIOS).
- **ws2_32 connect hook**: IPC-based destination approval.

### ALPC guard (`alpc_guard`)

Hooks NtAlpcConnectPort. Blocks connections to COM activation ALPC ports:
- `ole` -- COM/OLE activation service
- `actkernel` -- COM activation kernel port
- `comlaunch` -- COM launch service

Substring match on port ObjectName. `epmapper` is allowed (needed for DNS,
print, etc.) -- direct LRPC bypass is a theoretical gap (see Known gaps).

**Code**: `hook/src/alpc_guard.rs`.

### Process lifecycle
- **Job Object**: `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` + optional memory limits.
  All children auto-terminate when launcher exits.
- **Job breakaway**: `JOB_OBJECT_LIMIT_BREAKAWAY_OK` (0x0800) and
  `SILENT_BREAKAWAY_OK` (0x1000) are explicitly UNSET in `jobctl.rs`. Unit tests
  (`job_disallows_breakaway`, `job_disallows_breakaway_even_with_all_limits`)
  enforce this invariant. `NtAssignProcessToJobObject` is unconditionally denied
  by `proc_guard` to prevent nested-Job escape.
- **Process Mitigation Policies** (full mode): `ProcessDynamicCodePolicy`,
  `ProcessSignaturePolicy` (MS-signed DLLs only), `ExtensionPointDisablePolicy`.

### DLL sideloading mitigation

`ProcessImageLoadPolicy` applied via two paths:

1. **Launcher**: `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` includes
   `IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON` + `IMAGE_LOAD_NO_REMOTE_ALWAYS_ON`
   (both scan and full mode, see `mitigations.rs`).
2. **Hook DLL self-apply**: `SetProcessMitigationPolicy(ProcessImageLoadPolicy)`
   with `PreferSystem32Images` + `NoRemoteImages` flags, applied during hook
   initialization (`hooks.rs`).

This prevents:
- CWD/PATH DLL search-order hijacking (System32 always searched first)
- UNC path DLL loading (`\\server\share\evil.dll` blocked)

### Named pipe denylist

14 dangerous named pipes blocked via exact-segment match in `classify_device`
(classified as `DeviceKind::Unknown` which is denied):

`lsass`, `spoolss`, `samr`, `netlogon`, `wkssvc`, `lsarpc`, `eventlog`,
`browser`, `epmapper`, `svcctl`, `psexesvc`, `srvsvc`, `winreg`, `atsvc`.

Matching is exact-segment (e.g. `\Device\NamedPipe\svcctl` matches, but
`\Device\NamedPipe\svcctlx` does not).

**Code**: `policy/src/dev.rs:is_dangerous_pipe`.

### Environment sanitization

`env_guard::sanitize()` strips sensitive environment variables (API keys,
tokens, secrets, credentials, passwords) before spawning the sandboxed child.
Whitelisted: PATH, TEMP, HOME, USERPROFILE, SystemRoot, FS_SANDBOX_*.

**Code**: `launcher/src/env_guard.rs`.

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
| `\Device\NamedPipe\*`, `\??\pipe\*` | NamedPipe | RPC, child IPC, DNS client | Scoped to named pipes | Process tree tracking + 14-entry pipe denylist |
| `\Device\ConDrv`, `CONIN$`, `CONOUT$` | Console | stdio | None | -- |
| `\Device\Null`, `NUL` | Null | `/dev/null` | None | -- |
| `\Device\Afd\*`, `\Device\Tcp`, `\Device\Udp` | Socket | Networking (TCP/UDP/DNS) | Direct IOCTL bypass of ws2_32 hook | WFP kernel filter enforces destination policy |
| `\Device\Nsi` | Socket | DNS resolver config queries | NsiSetParameter requires privileges | Sandbox runs unprivileged |
| `\Device\MountPointManager` | SystemQuery | .NET BCL volume queries | IOCTL_MOUNTMGR_CREATE_POINT needs SeRestorePrivilege | Sandbox lacks privilege |
| `\Device\IPT` | SystemQuery | Intel Processor Trace | Requires Admin | Sandbox is non-Admin |
| `\KernelObjects\*` | SystemQuery | Named sync primitives | Coordination side-channel | Accepted risk (not an escape) |
| `\Device\Dfs` | SystemQuery | DFS namespace resolution | UNC exfiltration via SMB | WFP SMB port 445 block |

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
user-mode.

## Direct syscall defense analysis

Direct syscalls (Hell's Gate / Halo's Gate / Tartarus' Gate) bypass user-mode
ntdll hooks by reading the SSN at runtime and issuing `syscall` directly.
winrsbox defends against this with three layers:

| Layer | Mechanism | What it catches | Code |
|---|---|---|---|
| Pre-launch .text scan | `iced-x86` disassembly of target exe's `.text` section before resume | Compile-time embedded `syscall`/`sysenter`/`int 2eh` instructions | `launcher/src/main.rs:pre_launch_scan` |
| Content-aware RX scan | Disassembly of non-module memory on RW->RX transition | Runtime-generated shellcode containing syscall instructions | `hook/src/memory_guard.rs:hook_nt_protect_virtual_memory` |
| Process Mitigation Policies | `PROHIBIT_DYNAMIC_CODE_ALWAYS_ON` + `BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` | Prevents creation of new executable memory (kernel-enforced) | `launcher/src/mitigations.rs` |

**Test coverage**: `pre_launch_promotes_bypass_direct_syscall` (was `#[ignore]`, now
passes -- pre-launch scan catches the `bypass_direct_syscall` payload before execution).
`pre_launch_refuses_static_syscall` verifies static syscall binaries are refused.

**Remaining gap**: A Hell's Gate variant that resolves the SSN at runtime and writes
the `syscall` instruction into dynamically-allocated memory. DynamicCodePolicy
blocks new executable memory creation (kernel-enforced), so this requires either:
- Bypassing DynamicCodePolicy (kernel exploit -- out of scope)
- Using pre-existing executable memory from a loaded DLL (blocked by BLOCK_NON_MS)
- Operating in `--guard scan` mode (no DynamicCodePolicy -- accepted risk for JIT)

**Decision**: Option A -- accept as known gap. Rationale:
- AI-agent threat model: AI rarely writes direct-syscall shellcode
- Three defense layers raise the bar significantly
- ETW Threat Intelligence (Option B) requires admin/elevated launcher (non-default)
- Full ETW TI subscription is deferred until elevated launcher infrastructure exists

**Future work**: If elevated launcher becomes default, subscribe to
`Microsoft-Windows-Threat-Intelligence` ETW provider for real-time direct-syscall
monitoring and kill. ETW scoring already supports `DirectSyscallDetected` (score 15,
highest priority -- see `launcher/src/etw.rs`).

## Known gaps

| Gap | Severity | Status |
|---|---|---|
| Runtime SSN-resolved direct syscall in scan mode | Low | Accepted (Option A): DynamicCodePolicy off for JIT compat; content-aware RX scan still active |
| ETW TI not subscribed (requires admin) | Low | Deferred: scoring infrastructure ready, needs elevated launcher |
| Direct AFD IOCTL bypasses ws2_32 hook | Low | **Mitigated**: WFP now active (3 RFC1918 filters), kernel-level enforcement |
| ALPC direct LRPC bypass | Low | Theoretical: NtAlpcConnectPort covers 3 patterns (ole/actkernel/comlaunch); direct LRPC port name construction could bypass substring match |
| NtCreateSection cross-proc | Low | Deferred: low likelihood in AI-agent threat model |
| Direct syscall Hell's Gate variant in scan mode | Low | Acknowledged: 3-layer defense (pre-launch scan + content-aware RX scan + DynamicCodePolicy in full mode) |
| Registry CoW overlay not yet covering all hives | Low | Phase 2 covers HKCU\Software; HKLM writes use deny-only policy via IPC |
| cmd.exe /c doesn't work in sandbox | Low | Known limitation (DllMain injection timing) |
| NtAllocateVirtualMemory uses manual hook | Info | detour2 trampoline bug; manual hook works correctly |

### Resolved gaps

| Gap | Resolution |
|---|---|
| WFP registers 0 filters | **Fixed**: wrong condition key + missing sublayer/display |
| DFS UNC exfiltration | **Fixed**: WFP blocks TCP 445 (SMB) and 139 (NetBIOS) |
| Junction/symlink/hardlink bypass | **Fixed**: NtFsControlFile blocks reparse-point ops + NtSetInformationFile blocks rename/hardlink outside sandbox |
| COM/RPC/WMI escape | **Fixed**: com_guard CLSID denylist + alpc_guard ALPC port blocks |
| Dangerous named pipes (SCM, TaskSched) | **Fixed**: 14-entry exact-segment pipe denylist in classify_device |
| Volume shadow copies | **Fixed**: shadowcopy paths classified as Unknown (blocked) |
| Privilege escalation | **Fixed**: token_guard blocks NtAdjustPrivilegesToken + NtOpenProcessTokenEx + NtDuplicateToken + NtSetInformationThread |
| ETW behavioral detection not wired | **Fixed**: ETW Kernel-Process listener active |
| P0 escape via FILE_OPEN_IF | **Fixed**: `dabe30f` full-repo audit |

## Defense in depth (layers)

```
Layer 1: Pre-launch .text scan (full mode)
  |
Layer 2: Process Mitigation Policies
  |-- DynamicCodePolicy (full mode)
  |-- SignaturePolicy — MS-signed DLLs only (full mode)
  |-- ExtensionPointDisablePolicy
  |-- ImageLoadPolicy — PreferSystem32 + NoRemote (scan + full)
  |
Layer 3: ntdll / win32 inline hooks
  |-- FS hooks (NtCreateFile, NtOpenFile, NtQuery*, NtSetInformationFile, NtFsControlFile, NtQueryDirectoryFile)
  |-- Memory hooks (NtAllocate*, NtProtect*, NtMapView*, NtWrite*)
  |-- Inject hooks (NtCreateThread*, NtQueueApc*, NtSetContext*)
  |-- Process hooks (NtOpenProcess, NtAssignProcessToJobObject, NtCreateUserProcess)
  |-- Registry hooks (NtCreateKey, NtSetValueKey, NtDeleteKey/Value)
  |-- Token hooks (NtAdjustPrivilegesToken, NtOpenProcessTokenEx, NtDuplicateToken, NtSetInformationThread)
  |-- Network hooks (ws2_32!connect)
  |-- ALPC hooks (NtAlpcConnectPort)
  |-- COM hooks (CoCreateInstance, CoCreateInstanceEx, CoGetClassObject)
  |-- Service hooks (OpenSCManagerW, OpenServiceW)
  |-- UI hooks (SendInput, keybd_event, mouse_event, BlockInput, SetCursorPos,
  |             FindWindow*, PostMessage*, SendMessage*, OpenClipboard, GetClipboardData)
  |
Layer 4: WFP kernel network filtering (RFC1918 + SMB/NetBIOS block)
  |
Layer 5: Job Object (kill-on-close + memory limits + breakaway blocked)
  |
Layer 6: Content scanning (iced-x86 disassembly on RX transitions)
  |
Layer 7: Environment sanitization (API keys / tokens stripped before spawn)
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
