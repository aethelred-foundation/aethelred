#!/usr/bin/env bash
set -euo pipefail

# cli-smoke-test.sh
# Builds the Aethelred CLI from source and validates that basic commands work.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI_DIR="$ROOT_DIR/tools/cli"
CLI_CARGO_TOML="$CLI_DIR/Cargo.toml"

PASS=0
FAIL=0
SKIP=0
RESULTS=()

report() {
  local status="$1" test_name="$2" detail="${3:-}"
  case "$status" in
    PASS) PASS=$((PASS + 1)); RESULTS+=("PASS  $test_name") ;;
    FAIL) FAIL=$((FAIL + 1)); RESULTS+=("FAIL  $test_name  $detail") ;;
    SKIP) SKIP=$((SKIP + 1)); RESULTS+=("SKIP  $test_name  $detail") ;;
  esac
}

# ---------------------------------------------------------------------------
# Pre-checks
# ---------------------------------------------------------------------------
if [[ ! -f "$CLI_CARGO_TOML" ]]; then
  echo "ERROR: CLI Cargo.toml not found at $CLI_CARGO_TOML" >&2
  exit 1
fi

if ! command -v cargo &>/dev/null; then
  echo "ERROR: cargo not found in PATH" >&2
  exit 1
fi

echo "Aethelred CLI Smoke Test"
echo "========================"
echo ""

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
echo "== Building CLI =="
if cargo build --manifest-path "$CLI_CARGO_TOML" 2>&1; then
  report PASS "cargo-build"
else
  report FAIL "cargo-build" "cargo build failed"
  # If the build fails, remaining tests are pointless
  echo ""
  echo "Results:"
  for r in "${RESULTS[@]}"; do echo "  $r"; done
  echo ""
  echo "Total: $PASS passed, $FAIL failed, $SKIP skipped"
  exit 1
fi

# Locate the built binary
CLI_BIN="$ROOT_DIR/target/debug/aethelred"
if [[ ! -x "$CLI_BIN" ]]; then
  # Try the workspace-level target dir
  CLI_BIN="$(cargo metadata --manifest-path "$CLI_CARGO_TOML" --format-version 1 2>/dev/null \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["target_directory"])' 2>/dev/null)/debug/aethelred" || true
  if [[ ! -x "$CLI_BIN" ]]; then
    report FAIL "find-binary" "built binary not found"
    echo ""
    echo "Results:"
    for r in "${RESULTS[@]}"; do echo "  $r"; done
    echo ""
    echo "Total: $PASS passed, $FAIL failed, $SKIP skipped"
    exit 1
  fi
fi

echo "Binary: $CLI_BIN"
echo ""

# ---------------------------------------------------------------------------
# --help flag
# ---------------------------------------------------------------------------
echo "== Testing --help =="
if "$CLI_BIN" --help 2>&1 | grep -qi "aethelred"; then
  report PASS "--help"
else
  report FAIL "--help" "unexpected output"
fi

# ---------------------------------------------------------------------------
# --version flag
# ---------------------------------------------------------------------------
echo "== Testing --version =="
if "$CLI_BIN" --version 2>&1 | grep -qE '[0-9]+\.[0-9]+'; then
  report PASS "--version"
else
  report FAIL "--version" "no version string found"
fi

# ---------------------------------------------------------------------------
# config subcommand (if available)
# ---------------------------------------------------------------------------
echo "== Testing config subcommand =="
if "$CLI_BIN" config --help 2>&1 | grep -qi "config"; then
  report PASS "config-subcommand"
elif "$CLI_BIN" help config 2>&1 | grep -qi "config"; then
  report PASS "config-subcommand"
else
  # The config subcommand may not exist -- that is acceptable
  report SKIP "config-subcommand" "subcommand not available"
fi

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
echo ""
echo "========================"
echo "Results:"
echo ""
for r in "${RESULTS[@]}"; do
  echo "  $r"
done
echo ""
echo "Total: $PASS passed, $FAIL failed, $SKIP skipped"

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
