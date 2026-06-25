# winrsbox — Windows filesystem sandbox for AI agents

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/platform-Windows%20x64-0078D6?style=flat-square&logo=windows&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/rust-MSVC-orange?style=flat-square&logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/github/stars/PHPCraftdream/winrsbox?style=flat-square&logo=github" alt="Stars">
  <img src="https://img.shields.io/github/last-commit/PHPCraftdream/winrsbox?style=flat-square" alt="Last commit">
  <img src="https://img.shields.io/github/issues/PHPCraftdream/winrsbox?style=flat-square" alt="Issues">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square" alt="PRs welcome">
</p>

Intercepts filesystem calls at the ntdll level and redirects them through a policy engine with a copy-on-write overlay, child-process injection, file/directory mocks, and glob-based rules — all configured via a `.ktav` policy file.

## Requirements

- Windows x64
- Rust toolchain (MSVC target)
- Go ≥ 1.21

## Quick start

```
build.cmd
cd bin
winrsbox -- your-program.exe [args]
```

## CLI

### Sandbox run (legacy)

```
winrsbox [-d] [-i] [--] <program> [args...]
  -d        show console window (default: hidden)
  -i        init sandbox state dir and exit
```

### Policy management commands

```
winrsbox rule    add [--id ID] --prefix=P [--read=MODE] [--write=MODE] [--depth=N] [--exe=GLOB]
winrsbox rule    remove --id=ID | --prefix=P
winrsbox rule    list [--json] [--write=MODE] [--depth-min=N]
winrsbox rule    show --id=ID [--json]
winrsbox rule    clear --force

winrsbox mock    add [--id ID] --path=P (--content=STR | --file=F | --stdin | --base64=B64)
winrsbox mock    remove --path=P
winrsbox mock    list [--json]

winrsbox mockdir add [--id ID] --prefix=P
winrsbox mockdir remove --prefix=P
winrsbox mockdir list [--json]

winrsbox defaults set [--read=MODE] [--write=MODE]
winrsbox defaults show [--json]
```

MODE ∈ `{passthrough, deny, cow, redirect}`.

### Why / What-if (policy simulator)

```
winrsbox why     <path>... [--write] [--depth=N] [--exe=PATH] [--json] [--stdin]
winrsbox what-if rule add --prefix=... [--write=...] ... -- <path>...
```

`why` traces the full policy chain for a given path, showing which rules were considered and which matched. Without `--write`, both read and write decisions are shown.

`what-if` simulates adding a hypothetical rule and shows which paths would change.

### Export / Import

```
winrsbox export  [--json]
winrsbox import  [--replace]
winrsbox import  --ktav <file>
```

All JSON output includes `"schema_version": 1`. Import merges by default; use `--replace` to wipe first.

## Config

The sandbox config is automatically created at `<parent>/.winrsbox/<project-name>/sandbox.ktav`.

### Config format (`.ktav`, format v0.6.1)

The policy file uses the [ktav](https://crates.io/crates/ktav) text format. A few rules to keep in mind when editing `sandbox.ktav` by hand:

- **Comments** are whole lines starting with `##` (two hashes). A single `#` is *literal content*, not a comment — `key: # value` puts `# value` into the value.
- **Backslashes are literal.** Windows paths use a single `\`: `C:\Windows`, never `C:\\Windows` (the latter would store two backslashes in the value, since ktav 0.6.1 has no `\` escape sequence).
- **No type hints.** Values are bare words: `read: passthrough`, `depth: 1`. Don't write `depth: u8 1`.
- **Scalars** are a bare token after `key:`: `write: deny`, `content_inline: FAKE_SECRET`.
- **Multi-line / literal strings** use parenthesised blocks `( ... )` — the common leading indent is stripped, so embedded `[app]` / `key=value` lines survive verbatim even though they look like ktav compounds:
  ```ktav
  content_inline: (
      [app]
      key=value
  )
  ```
- **Objects** use `{ ... }` and **arrays** use `[ ... ]`. An inline compound `{ ... }` must open and close on the same line if it starts inline; for readability put each field on its own line (see examples below).

### Pattern matching

Rules use glob patterns with `*` (zero or more chars) and `?` (one char) per path segment:

```
C:\Users\*\Documents     matches C:\Users\alice\Documents, C:\Users\bob\Documents
C:\*.log                 matches C:\app.log, C:\error.log
C:\Users\??\*            matches C:\Users\ab\..., but not C:\Users\alice\...
```

`**` matches zero or more path segments (must be a standalone segment):

```
C:\Users\**\.ssh         matches C:\Users\alice\.ssh, C:\Users\alice\sub\.ssh, C:\Users\.ssh
C:\**                     matches C:\anything, C:\a\b\c
C:\**\foo\**\.bar        matches C:\foo\.bar, C:\x\foo\y\.bar
```

Matches are prefix-based by default (rules don't require full path), unless used in `mocks` (exact match with globs).

### Example config

```ktav
## Comments start with two hashes. A single '#' would be literal content.
defaults: {
    read: passthrough
    write: cow
}

rules: [
    {
        prefix: C:\Windows
        read: passthrough
        write: deny
    }
    {
        prefix: C:\Users\*\AppData\Local\Temp
        write: deny
    }
    {
        prefix: C:\Program Files\MyApp\*.log
        write: redirect
    }
    {
        prefix: C:\Secret
        write: deny
        when: {
            depth: 1
            exe: c:\bin\target-app.exe
        }
    }
]

mocks: [
    {
        path: C:\config.ini
        ## multi-line literal string: ( ... ) strips the common leading indent.
        ## A bare `content_inline: [app]` would be parsed as an array — the
        ## parenthesised form keeps it a verbatim string.
        content_inline: (
            [app]
            key=value
        )
    }
    {
        path: C:\Users\*\secret.txt
        content_inline: FAKE_SECRET
    }
]

mock_dirs: [
    {
        prefix: C:\temp
    }
    {
        prefix: C:\Users\*\cache
    }
]
```

Policy modes: `passthrough` (allow), `deny` (reject), `cow` (copy-on-write), `redirect` (copy to overlay).

### `when` filter

Rules can include an optional `when` filter to restrict them to specific process depths and executables:

```ktav
when: {
    ## applies at depth >= 1 (children, grandchildren, etc.)
    depth: 1
    ## glob match on lowercase exe path
    exe: c:\bin\app.exe
}
```

- `depth`: rule applies only when the process is at this depth or deeper in the sandbox tree. The root target is depth 0, its children are depth 1, etc.
- `exe`: glob pattern matched against the lowercase executable path. Supports `*`, `?`, and `**`.
- Legacy callers (without depth/exe context) are treated as max-permissive: they pass through depth filters.

> See *Config format* above for ktav syntax rules (comments, paths, strings).

## How it works

1. The launcher spawns the target process with a DLL injected via `CreateProcess` + `CREATE_SUSPENDED`.
2. The injected DLL hooks ntdll filesystem syscalls (`NtCreateFile`, `NtWriteFile`, `NtDeleteFile`, etc.) in-process.
3. Every hooked call is forwarded over an IPC pipe back to the launcher, which evaluates policy and decides allow/redirect/block.
4. Redirected writes go to a CoW overlay directory; the target process sees a merged view. Child processes inherit the same hooks automatically.

## Integration tests

```
workdir\bin\integration-tests.exe
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
