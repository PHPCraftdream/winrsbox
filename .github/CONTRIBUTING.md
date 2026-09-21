# Contributing to winrsbox

Thanks for your interest in winrsbox. It's a Windows-only, security-sensitive
project (a filesystem/process sandbox built on ntdll hooks), so a few things work
a little differently than a typical Rust crate. This guide covers the essentials.

## Found a security issue?

**Do not open a public issue for a suspected sandbox escape or other security
vulnerability.** Follow the private reporting process in
[SECURITY.md](SECURITY.md) instead.

## Project layout

Everything Rust lives under `winrsbox/` (that's the Cargo workspace root — there
is no `Cargo.toml` at the repo root):

The crates sit under `winrsbox/crates/`, each named with a `winrsbox-` prefix.
Inside Rust sources they are still referred to by their short names (`policy`,
`ipc`), via the `package = "..."` rename in each manifest.

| Crate | Package | Role |
|-------|---------|------|
| `crates/winrsbox-launcher` | `winrsbox` | the `winrsbox.exe` launcher + CLI + policy management |
| `crates/winrsbox-hook` | `winrsbox-hook` | the injected `hook.dll` — ntdll hooks, CoW redirect, guards |
| `crates/winrsbox-policy` | `winrsbox-policy` | policy engine: glob rules, decisions, path/registry classification |
| `crates/winrsbox-ipc` | `winrsbox-ipc` | hook ↔ launcher IPC protocol (bincode over a named pipe) |
| `crates/winrsbox-integration-tests` | `winrsbox-integration-tests` | escape proof-of-concept binaries (not `cargo test`s) |
| `crates/winrsbox-layout-guard` | `winrsbox-layout-guard` | the source-layout rules, enforced as a test |

The `hook` crate pins `[lib] name = "hook"` and the launcher pins its bin name:
the injector loads `hook.dll` by that exact file name, so those two must not
follow their package names.

The Go programs under `workdir/` are **test helpers** for the escape suite, not
part of the sandbox.

## Building

Sandbox only (pure Rust, no Go needed):

```
cd winrsbox
cargo build --release      # -> ../bin/winrsbox.exe + ../bin/hook.dll (via build script paths)
```

Full build including the Go escape-test helpers (needs Go ≥ 1.21):

```
scriptsuild.cmd
```

## Before you open a pull request

Run what CI runs (from inside `winrsbox/`):

```
cargo build --workspace --all-targets
cargo test  --workspace --lib
cargo clippy --workspace --all-targets
```

- **Unit/lib tests must pass** (`cargo test --workspace --lib`). CI does not run
  the `integration-tests` binaries as `cargo test`s — they are standalone escape
  PoCs that need a built sandbox + the Go helpers at runtime.
- **Clippy** must not introduce new errors. The tree has some known, accepted
  style warnings; don't fight unrelated ones, but keep your own diff clean.
- Match the surrounding code: comment density, naming, and idioms. The hook and
  policy crates are heavily commented on purpose — a subtle FS/IPC change usually
  needs a *why*, not just a *what*.

## Changes that touch containment

If your change affects any guard (`fs`, `memory`, `inject`, `reg`, `net`, `alpc`,
`token`, `com`, `service`, `shell`, `system`, `mitigations`) or the CoW / overlay
logic, please:

- Explain the security reasoning in the PR description — what escape/behaviour
  changes, and why it stays safe.
- Add or update a test. Guard logic is unit-testable via pure classifier
  functions (see e.g. `alpc_guard::classify_port`, `com_guard::check_denylist`);
  containment behaviour has escape PoCs under `integration-tests`.
- **Never loosen a guard purely for convenience.** If a legitimate workload is
  blocked, prefer a narrowly-scoped, well-justified carve-out over disabling a
  category — and prove the escape it was preventing is still blocked.

`unsafe` blocks require a `// SAFETY:` comment naming the invariants relied on.

## Commit / PR conventions

- Keep commits focused; write a descriptive message (a `type(scope): summary`
  first line is appreciated, e.g. `fix(hook): ...`, `security(hook): ...`).
- Reference the issue you're fixing where relevant.
- Small, reviewable PRs over large sweeping ones.

## License

By contributing, you agree that your contributions are dual-licensed under
**MIT OR Apache-2.0**, matching the project (see [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE)). This is the standard Rust dual-license; no
CLA is required.
