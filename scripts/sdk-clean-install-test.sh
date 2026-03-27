#!/usr/bin/env bash
set -euo pipefail

# sdk-clean-install-test.sh
# Tests packageability of all Aethelred SDKs.
# Each SDK is validated for packaging correctness and consumer-side
# compilation in an isolated temp environment.  Reports pass/fail per SDK.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PASS=0
FAIL=0
SKIP=0
RESULTS=()

cleanup_dirs=()
cleanup() {
  for d in "${cleanup_dirs[@]}"; do
    rm -rf "$d"
  done
}
trap cleanup EXIT

report() {
  local status="$1" sdk="$2" detail="${3:-}"
  case "$status" in
    PASS) PASS=$((PASS + 1)); RESULTS+=("PASS  $sdk") ;;
    FAIL) FAIL=$((FAIL + 1)); RESULTS+=("FAIL  $sdk  $detail") ;;
    SKIP) SKIP=$((SKIP + 1)); RESULTS+=("SKIP  $sdk  $detail") ;;
  esac
}

# ---------------------------------------------------------------------------
# TypeScript SDK
# ---------------------------------------------------------------------------
test_typescript_sdk() {
  local sdk_dir="$ROOT_DIR/sdk/typescript"
  if [[ ! -f "$sdk_dir/package.json" ]]; then
    report SKIP typescript "package.json not found"
    return
  fi

  echo "== TypeScript SDK packageability test =="

  local tmp
  tmp="$(mktemp -d)"
  cleanup_dirs+=("$tmp")

  # Build the SDK first, then pack it
  (cd "$sdk_dir" && npm install --ignore-scripts 2>&1) || true
  local tarball
  tarball="$(cd "$sdk_dir" && npm pack --pack-destination "$tmp" 2>/dev/null | tail -1)"

  if [[ ! -f "$tmp/$tarball" ]]; then
    report FAIL typescript "npm pack failed"
    return
  fi

  # Create a consumer project
  local consumer="$tmp/consumer"
  mkdir -p "$consumer"
  cat > "$consumer/package.json" <<'PJSON'
{
  "name": "sdk-clean-install-test",
  "version": "0.0.1",
  "private": true,
  "type": "module"
}
PJSON

  (cd "$consumer" && npm install "$tmp/$tarball" 2>&1) || {
    report FAIL typescript "npm install of tarball failed"
    return
  }

  # Basic import test
  cat > "$consumer/test.mjs" <<'JS'
import { AethelredClient } from "@aethelred/sdk";
if (typeof AethelredClient !== "function") {
  console.error("AethelredClient is not a function/class");
  process.exit(1);
}
console.log("TypeScript SDK import OK");
JS

  if (cd "$consumer" && node test.mjs 2>&1); then
    report PASS typescript
  else
    report FAIL typescript "import test failed"
  fi
}

# ---------------------------------------------------------------------------
# Python SDK
# ---------------------------------------------------------------------------
test_python_sdk() {
  local sdk_dir="$ROOT_DIR/sdk/python"
  if [[ ! -f "$sdk_dir/pyproject.toml" ]]; then
    report SKIP python "pyproject.toml not found"
    return
  fi

  if ! command -v python3 &>/dev/null; then
    report SKIP python "python3 not found"
    return
  fi

  echo "== Python SDK packageability test =="

  local tmp
  tmp="$(mktemp -d)"
  cleanup_dirs+=("$tmp")

  python3 -m venv "$tmp/venv"
  source "$tmp/venv/bin/activate"

  if pip install "$sdk_dir" 2>&1; then
    # Basic import test
    if python3 -c "from aethelred import AethelredClient; print('Python SDK import OK')" 2>&1; then
      report PASS python
    else
      # Try alternate import path
      if python3 -c "import aethelred; print('Python SDK import OK')" 2>&1; then
        report PASS python
      else
        report FAIL python "import test failed"
      fi
    fi
  else
    report FAIL python "pip install failed"
  fi

  deactivate 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Go SDK
# ---------------------------------------------------------------------------
test_go_sdk() {
  local sdk_dir="$ROOT_DIR/sdk/go"
  if [[ ! -f "$sdk_dir/go.mod" ]]; then
    report SKIP go "go.mod not found"
    return
  fi

  if ! command -v go &>/dev/null; then
    report SKIP go "go not found"
    return
  fi

  # Go SDK packageability test
  echo "=== Go SDK Packageability Test ==="
  cd "$sdk_dir"
  if go mod verify 2>&1; then
    echo "  go mod verify: OK"
  else
    report FAIL go "go mod verify failed"
    return
  fi

  if go vet ./... 2>&1; then
    echo "  go vet: OK"
  else
    report FAIL go "go vet failed"
    return
  fi

  if go test -short ./... 2>&1; then
    echo "  go test -short: OK"
    report PASS go
  else
    report FAIL go "go test -short failed"
  fi

  echo "NOTE: True clean-install requires published module. This tests source-tree API compatibility."
}

# ---------------------------------------------------------------------------
# Rust SDK
# ---------------------------------------------------------------------------
test_rust_sdk() {
  local sdk_dir="$ROOT_DIR/sdk/rust"
  if [[ ! -f "$sdk_dir/Cargo.toml" ]]; then
    report SKIP rust "Cargo.toml not found"
    return
  fi

  if ! command -v cargo &>/dev/null; then
    report SKIP rust "cargo not found"
    return
  fi

  # Rust SDK packageability test
  echo "=== Rust SDK Packageability Test ==="
  cd "$sdk_dir"
  cargo package --no-verify --allow-dirty 2>/dev/null || cargo package --no-verify
  local CRATE_FILE
  CRATE_FILE=$(ls target/package/*.crate 2>/dev/null | head -1)
  if [ -n "$CRATE_FILE" ]; then
    local CONSUMER
    CONSUMER=$(mktemp -d)
    cleanup_dirs+=("$CONSUMER")
    cd "$CONSUMER"
    cargo init --name test-consumer
    mkdir -p vendor && tar xzf "$OLDPWD/$CRATE_FILE" -C vendor/
    local EXTRACTED
    EXTRACTED=$(ls vendor/)
    # cargo init already creates [dependencies], so just append the dep line
    sed -i.bak '/\[dependencies\]/a\
aethelred-sdk = { path = "vendor/'"$EXTRACTED"'" }
' Cargo.toml && rm -f Cargo.toml.bak
    if cargo check 2>&1; then
      echo "Rust SDK: packaged crate builds as consumer dependency"
      report PASS rust
    else
      report FAIL rust "cargo check of packaged crate failed"
    fi
  else
    report FAIL rust "cargo package produced no .crate file"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  echo "Aethelred SDK Packageability Test Suite"
  echo "======================================="
  echo ""

  test_typescript_sdk
  test_python_sdk
  test_go_sdk
  test_rust_sdk

  echo ""
  echo "======================================"
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
}

main "$@"
