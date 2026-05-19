#!/usr/bin/env bash
# Compatibility regression check for winrsbox.
# Run from workspace root: bash scripts/compat-check.sh
#
# Prerequisites:
#   cargo build --release -p winrsbox -p hook
#
# Exit 0 if all programs work; exit 1 on regression.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WB="$SCRIPT_DIR/../target/release/winrsbox.exe"
CLAUDE_EXE="$APPDATA/npm/node_modules/@anthropic-ai/claude-code/bin/claude.exe"
WORKDIR=$(mktemp -d)
HELLO_RS="$WORKDIR/hello-rs"

# Create minimal Rust project for cargo build test
mkdir -p "$HELLO_RS/src"
echo 'fn main() { println!("ok"); }' > "$HELLO_RS/src/main.rs"
cat > "$HELLO_RS/Cargo.toml" << 'TOML'
[package]
name = "hello_test"
version = "0.0.1"
edition = "2021"
TOML

PASS=0
FAIL=0
RESULTS=""

run_test() {
    local name="$1"
    shift
    local dir="$1"
    shift

    # Remove stale state
    local state_parent
    state_parent="$(dirname "$dir")/.winrsbox/$(basename "$dir")"
    rm -f "$state_parent/sandbox.ktav" 2>/dev/null || true

    local output exit_code
    output=$(cd "$dir" && timeout 30 "$WB" -d -g scan -- "$@" 2>&1) || true
    exit_code=$(echo "$output" | grep -oP 'exit=\K\d+' | tail -1)
    local violations
    violations=$(echo "$output" | grep -oP 'violations=\K\d+' | tail -1)

    if [ "${exit_code:-1}" = "0" ] && [ "${violations:-1}" = "0" ]; then
        RESULTS="$RESULTS\n  PASS  $name  (exit=$exit_code violations=$violations)"
        PASS=$((PASS + 1))
    else
        RESULTS="$RESULTS\n  FAIL  $name  (exit=${exit_code:-?} violations=${violations:-?})"
        FAIL=$((FAIL + 1))
    fi
}

echo "winrsbox compatibility check"
echo "============================"

run_test "cargo --version" "$WORKDIR" cargo --version
run_test "cargo build" "$HELLO_RS" cargo build
run_test "git status" "$(pwd)" git status
run_test "python -c" "$WORKDIR" python -c "print(1)"
run_test "node -e" "$WORKDIR" node -e "console.log(1)"
run_test "powershell" "$WORKDIR" powershell -Command "Write-Host OK"

if [ -f "$CLAUDE_EXE" ]; then
    run_test "claude.exe --version" "$WORKDIR" "$CLAUDE_EXE" --version
else
    RESULTS="$RESULTS\n  SKIP  claude.exe (not found)"
fi

echo -e "$RESULTS"
echo ""
echo "Result: $PASS passed, $FAIL failed"

rm -rf "$WORKDIR"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
