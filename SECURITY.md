# Security Policy

winrsbox is a security tool: it confines untrusted processes (AI agents, build
steps, unknown binaries) on Windows by redirecting their filesystem writes into a
copy-on-write overlay and blocking known containment-escape vectors. Because its
whole purpose is containment, a bug that lets a sandboxed process reach the real
disk, spawn an un-hooked process outside the sandbox, escalate privileges, or
otherwise break out **is a security vulnerability** — not just a bug.

## Supported versions

winrsbox is pre-1.0. Only the latest `master` and the most recent tagged release
receive security fixes. There are no backports to older tags.

| Version | Supported |
|---------|-----------|
| latest `master` / newest release | ✅ |
| older tags | ❌ |

## Reporting a vulnerability

**Please do not open a public GitHub issue for a suspected escape or security
bug.** Public disclosure before a fix gives an attacker a working bypass.

Instead, report privately via one of:

- **GitHub Private Vulnerability Reporting** — the "Report a vulnerability"
  button under the repository's **Security** tab
  (<https://github.com/PHPCraftdream/winrsbox/security/advisories/new>).
- **Email** — `phpcraftdream@gmail.com` with `[winrsbox security]` in the subject.

Please include, as far as you can:

- The winrsbox version / commit and the `--guard` level in use (`none` / `scan` /
  `full` / `static`).
- The Windows build (`cmd /c ver`) and architecture.
- A minimal reproduction: the exact command, the sandboxed payload, and what
  "escaped" (a file that appeared on the real disk, a process spawned outside the
  Job Object, a blocked broker that was reached, etc.).
- The `sandbox.log.jsonl` / `violations.log` from the run if available.

## What counts as a vulnerability

In scope — a **sandboxed** process (under `--guard scan` / `full` / `static`)
managing to:

- write to, rename into, or delete a path on the **real disk** instead of the
  CoW overlay (containment escape);
- spawn or influence a process **outside** the sandbox's hooks / Job Object
  (e.g. via COM activation, WMI `Win32_Process.Create`, the Task Scheduler, a
  service, or an un-hooked helper);
- escalate privileges, read credentials (SAM/LSA), or persist across reboots;
- bypass the ntdll hooks (direct syscalls, fresh-`ntdll` remap, unhooking) in a
  guard level that is documented to prevent it;
- read another sandbox's overlay or the launcher's control files.

Out of scope:

- Anything under `--guard none` — that level is FS-sandbox-only by design and
  provides **no** memory/process containment. It is not a security boundary.
- Denial of service against the sandboxed process itself (it is untrusted).
- Escapes that require the operator to have already granted the payload
  Administrator / SYSTEM rights, or to run the launcher elevated with a
  deliberately permissive policy.
- Known, documented limitations (see the README and `--guard` help text), e.g.
  WMI being unavailable under `scan`/`full` (use `--guard none` for WMI-dependent
  tools).
- **Writes to UNC / network-redirector paths are refused, not redirected.** The
  CoW overlay is keyed by DOS paths, so a write to `\\server\share\...`,
  `\\localhost\c$\...`, a mapped network drive or a WebDAV share has no
  representable overlay destination. Rather than let such a write reach the real
  target outside the sandbox, it is denied with `STATUS_ACCESS_DENIED`. Reads
  keep the documented pass-through. The same fail-closed rule applies to any
  path the policy cannot resolve to a DOS form, including unrecognized device
  namespaces.

## Behaviour changes from the hardening pass

Closing the audit findings turned several silent fall-throughs into refusals.
Each is intentional and fail-closed, but each can stop something that used to
work — they are listed here so an upgrade is not a surprise.

- **A cross-process `WriteProcessMemory` into a process the sandbox does not
  own terminates the caller.** It used to be content-scanned for syscall
  opcodes, which only ever caught the payload shapes it knew. Injection into
  the launcher's own children is unaffected.
- **An unresolvable call stack is treated as untrusted, not as "system".**
  A stack walk that fails in a legitimate context therefore terminates the
  process instead of granting it system trust.
- **Under `--guard full` / `static`, a spawned child whose image cannot be
  scanned is terminated**, not only one where a direct syscall is found.
  Otherwise a spawner could deny itself `VM_READ` to skip the scan.
- **`ShellExecute` verbs are allow-listed.** `runas`, `explore`, `find` and any
  verb not on the list are refused; `open`, `edit`, `print` and the default
  (NULL/empty) verb still work.
- **`NtCreateKey` under a deny-listed registry prefix is refused even with
  `KEY_READ`**, because the call creates the key regardless of the requested
  access. Read-only creation under CoW prefixes is unchanged.
- **An open that requests only `FILE_WRITE_ATTRIBUTES` (or `GENERIC_ALL`, or
  `FILE_WRITE_EA`) now counts as a write.** Outside `project_root` that means a
  timestamp-only touch of a large file triggers one full CoW copy, and
  attribute-write opens of directories fail with `OBJECT_NAME_NOT_FOUND`
  instead of mutating the real directory.
- **Asynchronous directory enumeration completes synchronously.** The hook must
  see the finished buffer to filter it, so a query that returned
  `STATUS_PENDING` now blocks until completion and returns the final status.
- **Writes into the sandbox's own installed directory are denied** even where
  the surrounding rule grants passthrough, and the launcher verifies the
  staged binaries against the installer's integrity manifest before injecting.
- **Policy keys are folded ASCII-only.** Entries written before this change
  under Unicode-folded, cased non-ASCII keys stop resolving: overlay reads fall
  back to the real file (no data loss; the next write re-copies), but mocks and
  rules whose prefix contains cased non-ASCII characters must be re-added.
- **The session config section is randomly named per session and read-only.**
  It no longer lives at a fixed `Local\WinRsBoxSession` name; the name is
  generated from the system CSPRNG and delivered to each process through the
  injection channel (patched into the suspended child's environment block
  before any guest code runs, so env-scrubbed children are covered too). RNG
  failure fails the launch rather than falling back to a guessable name, and
  the launcher refuses to publish into a section it did not create.

  Residual, stated plainly: a sandboxed process can read the name out of its
  own environment and open the section **for reading** — it runs as the same
  user, and the hook lives inside it, so no secret held there is secret from
  it. What it cannot do is rewrite the config: the DACL denies
  `SECTION_MAP_WRITE` to everyone and an `OWNER_RIGHTS` ACE suppresses the
  owner's implicit `WRITE_DAC`, so the guest cannot grant itself write either.
  A guest that has already obtained Administrator rights can take ownership and
  undo that — which is out of scope above, along with every other
  already-elevated escape.

## Network containment is off by default

**Out of the box winrsbox does not contain the network.** Unless the
per-folder `sandbox.ktav` says `network: guarded`, no WFP filter is
registered and the `connect` hook is not installed. A sandboxed process can
therefore reach anything the invoking user can reach, including RFC1918 hosts
and SMB shares. Filesystem, registry, process and memory containment are
unaffected by this setting.

This is a deliberate default, not an oversight. With it off, a sandboxed
program's traffic is indistinguishable from running that program directly:
the hook never proxied anything — it only ever allowed or refused, and the
connection is made by the guest's own process under its own image — and with
no filters registered the sandbox leaves no trace in the system's network
configuration. Turning it on is one line in the ktav; `--block-localhost` and
any configured `netrule` imply it, so a configured rule never sits inert.

If you are running genuinely untrusted code and care about lateral movement,
set `network: guarded`. The rest of this section describes what you get when
you do.

## What the kernel network filters do and do not cover

With `network: guarded`, winrsbox installs WFP filters (RFC1918 and
private-IPv6 egress, SMB ports 445/139) that the kernel enforces, so a direct
syscall cannot bypass them. Their scope is narrower than "the sandbox", and
the boundary is worth stating because it is invisible at runtime:

- **Every filter is bound to one image** via `FWPM_CONDITION_ALE_APP_ID`, an
  exact match on the NT device path of the process image. A filter whose app
  id cannot be built is never installed — an unscoped filter would apply to
  every process on the machine, which is a worse outcome than no filter.
- **Only the root target is covered.** Children the sandboxed process spawns
  run under a different image and are not matched by these filters. Network
  containment for the whole tree rests on the in-process hooks, with WFP as
  defence in depth for the root.
- **A `.bat` / `.cmd` target gets no WFP filters at all**, and the launcher
  says so on stderr. Such a target has no image of its own: kernel32 rewrites
  it to `%COMSPEC% /c <script>`, so the root process is `cmd.exe` and the
  script is an argument. Binding an app id to the script path would install
  filters that match no process, and binding to `cmd.exe` would look like
  coverage while the program that actually opens sockets runs as its child.

## Disclosure process

1. Acknowledgement of your report as soon as we can, typically within a few days.
2. We confirm and reproduce, then develop and test a fix on a private branch.
3. We release the fix and publish a GitHub Security Advisory crediting you (unless
   you prefer to remain anonymous).

Because this is a volunteer, best-effort project, we cannot commit to a fixed SLA,
but escape-class reports are treated as the highest priority.

## Threat model, in one paragraph

The adversary is the **sandboxed process itself**: a possibly-malicious or
compromised agent/binary running under our ntdll hooks and a restricted Job
Object. It may attempt any user-mode technique to reach the real filesystem or
escape the job. Containment rests on the ntdll hooks + the Job Object + the CoW
overlay + kernel process-mitigation policies; `--guard static` additionally
prohibits dynamic code and unsigned DLLs to close the direct-syscall /
fresh-`ntdll` bypass surface that user-mode hooking cannot cover on its own. The
operator and the launcher are trusted; the target process is not.
