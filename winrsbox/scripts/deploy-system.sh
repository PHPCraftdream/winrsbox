#!/usr/bin/env bash
# Build winrsbox + hook.dll (release) and deploy them to the system-wide
# `winrsbox` install this machine actually runs day-to-day — i.e. wherever
# `winrsbox` resolves on PATH (default: D:\system_artefact\cargo\bin).
#
# This is the ONE canonical way to get a locally-built fix onto the running
# system. It exists so a fix-and-retest cycle is a single, identical,
# previously-reviewed command every time — not a new ad-hoc build+copy+hash
# sequence typed out fresh on each run, which is slow to get approved and
# easy to get subtly wrong under time pressure.
#
# Usage (from anywhere):
#   bash winrsbox/scripts/deploy-system.sh          # build + deploy
#   bash winrsbox/scripts/deploy-system.sh --test    # cargo test first, then build + deploy
#   bash winrsbox/scripts/deploy-system.sh --debug   # deploy the debug profile instead of release
#
# Override the target directory with WINRSBOX_INSTALL_DIR (git-bash style
# path, e.g. /d/some/other/bin) if this is ever run on a different machine.
#
# Why the rename-then-copy dance: while a sandbox session is running,
# winrsbox.exe/hook.dll are mapped into live processes and a plain `cp` over
# them fails with "Device or resource busy". Windows allows RENAMING a busy
# file, so the old artifact is rotated to .busy.<pid>.<ts> and the fresh one
# is written in its place; the old file stays usable for the still-running
# processes until they exit. Mirrors winrsbox/scripts/build-deploy.sh, which
# does the same thing for the repo-relative bin/ deploy target.
#
# integrity.json: the launcher verifies this SHA-256 manifest against the
# staged binaries at every launch and fails closed on a mismatch — so this
# script MUST regenerate it after every deploy, or a stale manifest would
# make the freshly deployed winrsbox.exe refuse to start.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"   # winrsbox/

RUN_TESTS=0
PROFILE="release"
PROFILE_FLAG="--release"

for arg in "$@"; do
    case "$arg" in
        --test)   RUN_TESTS=1 ;;
        --debug)  PROFILE="debug"; PROFILE_FLAG="" ;;
        -h|--help)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *)
            echo "unknown arg: $arg" >&2
            exit 2
            ;;
    esac
done

INSTALL_DIR="${WINRSBOX_INSTALL_DIR:-/d/system_artefact/cargo/bin}"
mkdir -p "$INSTALL_DIR"

if (( RUN_TESTS )); then
    echo "==> cargo test --workspace --lib --bins"
    ( cd "$WORKSPACE_DIR" && cargo test --workspace --lib --bins )
fi

echo "==> cargo build $PROFILE_FLAG -p winrsbox -p winrsbox-hook"
( cd "$WORKSPACE_DIR" && cargo build $PROFILE_FLAG -p winrsbox -p winrsbox-hook )

TARGET_DIR="$WORKSPACE_DIR/target/$PROFILE"

deploy_one() {
    local name="$1"
    local src="$TARGET_DIR/$name"
    local dst="$INSTALL_DIR/$name"

    if [[ ! -f "$src" ]]; then
        echo "  ! missing artifact: $src" >&2
        return 1
    fi

    if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then
        echo "  = $name (unchanged)"
        return 0
    fi

    if [[ -f "$dst" ]]; then
        if cp -f "$src" "$dst" 2>/dev/null; then
            echo "  + $name (overwritten)"
            return 0
        fi
        local rotated="$dst.busy.$$.$(date +%s)"
        mv "$dst" "$rotated"
        echo "  ~ $name busy — rotated old to $(basename "$rotated")"
    fi

    cp "$src" "$dst"
    echo "  + $name"
}

echo "==> deploying to $INSTALL_DIR"
deploy_one "winrsbox.exe"
deploy_one "hook.dll"

# Sweep stale .busy.* rotations from prior runs whose holding processes have exited.
shopt -s nullglob
for old in "$INSTALL_DIR"/*.busy.*; do
    if rm -f "$old" 2>/dev/null; then
        echo "  - swept $(basename "$old")"
    fi
done
shopt -u nullglob

echo "==> writing integrity.json"
(
    cd "$INSTALL_DIR"
    node -e '
        const fs = require("fs");
        const crypto = require("crypto");
        const files = {};
        for (const f of ["winrsbox.exe", "hook.dll"]) {
            files[f] = crypto.createHash("sha256").update(fs.readFileSync("./" + f)).digest("hex");
        }
        fs.writeFileSync(
            "./integrity.json",
            JSON.stringify({ algorithm: "sha256", files }, null, 2) + "\n"
        );
    '
)

echo "==> done: $INSTALL_DIR/winrsbox.exe + hook.dll (+ integrity.json)"
