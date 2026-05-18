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

```
winrsbox [-d] [-i] [--] <program> [args...]
  -d        show console window (default: hidden)
  -i        init sandbox state dir and exit
```

## Config

The sandbox config is automatically created at `<parent>/.winrsbox/<project-name>/sandbox.ktav`.

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
]

# mocks: [
#     { path: C:\\Users\\Computer\\.config\\app.ini, content_inline: "fake content" }
# ]

# mock_dirs: [
#     { prefix: C:\\temp }
# ]
```

Policy modes: `passthrough` (allow), `deny`, `cow` (copy-on-write), `redirect` (copy to overlay).

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
