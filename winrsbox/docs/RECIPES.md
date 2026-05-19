# Recipes

Common configurations for running programs in winrsbox.

## Default behavior

- **Reads**: pass through to real filesystem
- **Writes**: go to CoW overlay (`<state_dir>/workdir/`)
- Changes are isolated; the real filesystem is untouched

## Claude Code

Works out of the box with default policy. Requires:
- `~/.claude/` in passthrough (credentials, settings) -- included in default policy
- `~/.config/` in passthrough -- included in default policy
- HTTPS to api.anthropic.com (allowed by default)

```bash
winrsbox -d -g scan -- "C:\Users\<you>\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe" -p "your prompt"
```

Note: `.cmd` wrappers (like `claude.cmd`) have a known issue with argument
passing. Use the `.exe` path directly.

## Cargo / Rust

Works out of the box. `~/.cargo/` and `~/.rustup/` are in passthrough.

```bash
winrsbox -d -g scan -- cargo build
```

## npm install

By default, `node_modules/` writes go to the CoW overlay. After the sandbox
exits, the real `node_modules/` is empty.

To persist `node_modules/`, add a passthrough rule to your `sandbox.ktav`:

```
rules: [
    {
        prefix: <your-project>\node_modules
        read: passthrough
        write: passthrough
    }
]
```

Or run npm outside the sandbox for dependency installation, then use winrsbox
for the application itself.

## Python / pip

pip cache is in passthrough by default (`AppData\Local\pip`).
Virtual environments created inside the sandbox go to CoW overlay.

To persist a venv, add a passthrough rule for the venv directory.

## Git

Works out of the box. Git operations (status, log, clone) run normally.
Write operations (commit, push) work but changes go to CoW overlay.

## PowerShell

Works in scan mode. Full mode may restrict some .NET JIT operations.

```bash
winrsbox -d -g scan -- powershell -Command "your command"
```

## Custom passthrough rules

Edit `<state_dir>/sandbox.ktav` to add paths:

```
rules: [
    {
        prefix: C:\Users\me\project\output
        read: passthrough
        write: passthrough
    }
]
```

State dir location: `<parent-of-cwd>/.winrsbox/<cwd-name>/`
