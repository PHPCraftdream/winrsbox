#!/usr/bin/env bash
# Build winrsbox + hook in release mode and deploy artifacts into ../bin/.
#
# Usage (from anywhere):
#   bash winrsbox/scripts/build-deploy.sh           # build + copy
#   bash winrsbox/scripts/build-deploy.sh --shell   # build + copy + re-install context-menu entries
#   bash winrsbox/scripts/build-deploy.sh --debug   # build debug profile instead of release
#
# Why the rename-then-copy dance: when a sandbox session is running, bin/winrsbox.exe
# and bin/hook.dll are mapped into running processes and `cp` over them fails with
# "Device or resource busy". Windows allows RENAMING a busy file, so we rotate the
# old artifact to .busy.<pid> and write the fresh one in its place. The old file
# stays usable for the running processes until they exit.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"   # winrsbox/
REPO_ROOT="$(cd "$WORKSPACE_DIR/.." && pwd)"    # fs-sandbox/
BIN_DIR="$REPO_ROOT/bin"

PROFILE="release"
PROFILE_FLAG="--release"
DO_SHELL_INSTALL=0

for arg in "$@"; do
    case "$arg" in
        --debug)  PROFILE="debug"; PROFILE_FLAG="" ;;
        --shell)  DO_SHELL_INSTALL=1 ;;
        -h|--help)
            sed -n '2,16p' "$0"
            exit 0
            ;;
        *)
            echo "unknown arg: $arg" >&2
            exit 2
            ;;
    esac
done

# Resolve the artifact directory the SAME WAY cargo does — by asking cargo.
# The previous logic only honoured the CARGO_TARGET_DIR env var and fell back
# to <workspace>/target/ otherwise, but cargo ALSO honours:
#   - build.target-dir in .cargo/config.toml (workspace or $CARGO_HOME)
#   - CARGO_BUILD_TARGET_DIR (prefixed form)
#   - a globally-exported CARGO_TARGET_DIR that the script's shell didn't inherit
# Any of those caused the script to look in the wrong place: if the wrong
# dir happened to hold a stale winrsbox.exe byte-identical to bin/, `cmp -s`
# correctly reported "unchanged" and a freshly-built binary was silently
# skipped — leaving tests running against a stale deploy.
#
# `cargo metadata` is cargo's own authoritative source for target_directory;
# it accounts for every config layer. We strip a trailing release/debug so we
# can re-append the active profile consistently.
echo "==> resolving target dir via cargo metadata"
TARGET_ROOT="$(
    cd "$WORKSPACE_DIR" && cargo metadata --no-deps --format-version=1 2>/dev/null \
        | python -c "import json,sys; print(json.load(sys.stdin)['target_directory'])" 2>/dev/null \
        || true
)"
if [[ -z "$TARGET_ROOT" ]]; then
    # Fallback: legacy env-then-workspace logic if cargo metadata is unavailable
    # (e.g. python missing). Better than hard-failing, but emits a warning.
    echo "  ! cargo metadata unavailable — falling back to CARGO_TARGET_DIR/workspace" >&2
    if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
        TARGET_ROOT="$CARGO_TARGET_DIR"
    else
        TARGET_ROOT="$WORKSPACE_DIR/target"
    fi
fi
# Normalise Windows-style "C:\..." to a bash-friendly "/c/..." so the path
# composes cleanly with $PROFILE below. cygpath -m gives a mixed-mode path
# that both bash and cmp/cp accept.
if command -v cygpath >/dev/null 2>&1; then
    TARGET_ROOT="$(cygpath -m "$TARGET_ROOT" 2>/dev/null || echo "$TARGET_ROOT")"
fi
TARGET_DIR="$TARGET_ROOT/$PROFILE"

mkdir -p "$BIN_DIR"

echo "==> building ($PROFILE) in $WORKSPACE_DIR"
( cd "$WORKSPACE_DIR" && cargo build $PROFILE_FLAG )

deploy_one() {
    local name="$1"
    local src="$TARGET_DIR/$name"
    local dst="$BIN_DIR/$name"

    if [[ ! -f "$src" ]]; then
        echo "  ! missing artifact: $src" >&2
        return 1
    fi

    # Same bytes already deployed → nothing to do.
    if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then
        echo "  = $name (unchanged)"
        return 0
    fi

    if [[ -f "$dst" ]]; then
        if cp -f "$src" "$dst" 2>/dev/null; then
            echo "  + $name (overwritten)"
            return 0
        fi
        # Busy: rotate the old file out of the way and write the new one.
        local rotated="$dst.busy.$$.$(date +%s)"
        mv "$dst" "$rotated"
        echo "  ~ $name busy — rotated old to $(basename "$rotated")"
    fi

    cp "$src" "$dst"
    echo "  + $name"
}

echo "==> deploying to $BIN_DIR"
deploy_one "winrsbox.exe"
deploy_one "hook.dll"

# Sweep stale .busy.* rotations from prior runs whose holding processes have exited.
shopt -s nullglob
for old in "$BIN_DIR"/*.busy.*; do
    if rm -f "$old" 2>/dev/null; then
        echo "  - swept $(basename "$old")"
    fi
done
shopt -u nullglob

if (( DO_SHELL_INSTALL )); then
    echo "==> refreshing shell context-menu entries"
    "$BIN_DIR/winrsbox.exe" shell uninstall || true
    "$BIN_DIR/winrsbox.exe" shell install
fi

echo "==> done"
