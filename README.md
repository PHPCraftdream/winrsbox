# winrsbox — Windows filesystem sandbox for AI agents

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
defaults: {
    read: passthrough
    write: cow
}

rules: [
    {
        prefix: C:\\Windows
        read: passthrough
        write: deny
    }
    {
        prefix: C:\\Users\*\AppData\Local\Temp
        write: deny
    }
    {
        prefix: C:\\Program Files\MyApp\*.log
        write: redirect
    }
    {
        prefix: C:\\Secret
        write: deny
        when: {
            depth: 1
            exe: c:\\bin\target-app.exe
        }
    }
]

mocks: [
    { path: C:\\config.ini, content_inline: "[app]\nkey=value" }
    { path: C:\\Users\*\secret.txt, content_inline: "FAKE_SECRET" }
]

mock_dirs: [
    { prefix: C:\\temp }
    { prefix: C:\\Users\*\\cache }
]
```

Policy modes: `passthrough` (allow), `deny` (reject), `cow` (copy-on-write), `redirect` (copy to overlay).

### `when` filter

Rules can include an optional `when` filter to restrict them to specific process depths and executables:

```ktav
when: {
    depth: 1            # applies at depth >= 1 (children, grandchildren, etc.)
    exe: c:\bin\app.exe  # glob match on lowercase exe path
}
```

- `depth`: rule applies only when the process is at this depth or deeper in the sandbox tree. The root target is depth 0, its children are depth 1, etc.
- `exe`: glob pattern matched against the lowercase executable path. Supports `*`, `?`, and `**`.
- Legacy callers (without depth/exe context) are treated as max-permissive: they pass through depth filters.

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

MIT
