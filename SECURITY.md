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
