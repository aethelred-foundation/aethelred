#!/usr/bin/env bash
# =============================================================================
# SQ18: CLI Smoke Tests
# =============================================================================
# Verifies that CLI tools (aethel, seal-verifier, aethelred Rust CLI) can be
# built and respond to basic commands (--help, --version, etc.).
# Exits non-zero on any failure.
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PASS=0
FAIL=0
FAILURES=""

log_section() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"; }
log_pass()    { printf '  \033[1;32m[PASS]\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
log_fail()    { printf '  \033[1;31m[FAIL]\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); FAILURES="$FAILURES\n  - $1"; }

check_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# 1. aethel CLI (Node.js / TypeScript)
# ---------------------------------------------------------------------------
test_aethel_cli() {
  log_section "aethel CLI (@aethelred/cli)"

  local cli_dir="$REPO_ROOT/tools/cli/aethel"

  if [ ! -f "$cli_dir/package.json" ]; then
    log_fail "aethel package.json not found"
    return
  fi
  log_pass "package.json exists"

  if ! check_cmd node; then
    log_fail "node not found - skipping aethel CLI tests"
    return
  fi

  # -- Verify bin entry --
  local bin_name
  bin_name="$(node -e "const p=require('$cli_dir/package.json'); console.log(Object.keys(p.bin||{})[0]||'NONE')")"
  if [ "$bin_name" = "aethel" ]; then
    log_pass "bin entry: aethel"
  else
    log_fail "bin entry mismatch: expected aethel, got $bin_name"
  fi

  # -- Verify critical dependencies --
  local deps
  deps="$(node -e "const p=require('$cli_dir/package.json'); console.log(Object.keys(p.dependencies||{}).join(','))")"
  for dep in commander chalk ora; do
    if echo "$deps" | tr ',' '\n' | grep -q "^${dep}$"; then
      log_pass "dependency: $dep"
    else
      log_fail "missing dependency: $dep"
    fi
  done

  # -- Verify SDK dependency --
  if echo "$deps" | tr ',' '\n' | grep -q "@aethelred/sdk"; then
    log_pass "depends on @aethelred/sdk"
  else
    log_fail "missing @aethelred/sdk dependency"
  fi

  # -- Build the CLI --
  if [ -f "$cli_dir/dist/index.js" ]; then
    log_pass "dist/index.js already built"
  else
    if (cd "$cli_dir" && npm run build >/dev/null 2>&1); then
      log_pass "npm run build succeeded"
    else
      log_fail "npm run build failed (dist/index.js not present)"
      return
    fi
  fi

  # -- Run --help --
  if (cd "$cli_dir" && node dist/index.js --help >/dev/null 2>&1); then
    log_pass "aethel --help exits successfully"
  else
    # Some CLIs exit 0 on help, some exit 1 - check output instead
    local help_out
    help_out="$(cd "$cli_dir" && node dist/index.js --help 2>&1 || true)"
    if echo "$help_out" | grep -qi "usage\|help\|command\|aethel"; then
      log_pass "aethel --help produces help output"
    else
      log_fail "aethel --help produced no recognizable output"
    fi
  fi

  # -- Verify tsconfig.json --
  if [ -f "$cli_dir/tsconfig.json" ]; then
    log_pass "tsconfig.json present"
  else
    log_fail "tsconfig.json missing"
  fi

  # -- Verify src/index.ts entry point --
  if [ -f "$cli_dir/src/index.ts" ]; then
    log_pass "src/index.ts entry point exists"
  else
    log_fail "src/index.ts missing"
  fi
}

# ---------------------------------------------------------------------------
# 2. seal-verifier CLI (Node.js / TypeScript)
# ---------------------------------------------------------------------------
test_seal_verifier_cli() {
  log_section "seal-verifier CLI (@aethelred/seal-verifier)"

  local cli_dir="$REPO_ROOT/tools/cli/seal-verifier"

  if [ ! -f "$cli_dir/package.json" ]; then
    log_fail "seal-verifier package.json not found"
    return
  fi
  log_pass "package.json exists"

  if ! check_cmd node; then
    log_fail "node not found - skipping seal-verifier tests"
    return
  fi

  # -- Verify bin entry --
  local bin_name
  bin_name="$(node -e "const p=require('$cli_dir/package.json'); console.log(Object.keys(p.bin||{})[0]||'NONE')")"
  if [ "$bin_name" = "seal-verifier" ]; then
    log_pass "bin entry: seal-verifier"
  else
    log_fail "bin entry mismatch: expected seal-verifier, got $bin_name"
  fi

  # -- Verify @aethelred/sdk linkage --
  local sdk_ref
  sdk_ref="$(node -e "const p=require('$cli_dir/package.json'); console.log(p.dependencies?.['@aethelred/sdk']||'NONE')")"
  if [ "$sdk_ref" != "NONE" ]; then
    log_pass "@aethelred/sdk reference: $sdk_ref"
  else
    log_fail "@aethelred/sdk not in dependencies"
  fi

  # -- Build --
  if [ -f "$cli_dir/dist/index.js" ]; then
    log_pass "dist/index.js already built"
  else
    if (cd "$cli_dir" && npm run build >/dev/null 2>&1); then
      log_pass "npm run build succeeded"
    else
      log_fail "npm run build failed"
      return
    fi
  fi

  # -- Run --help --
  if (cd "$cli_dir" && node dist/index.js --help >/dev/null 2>&1); then
    log_pass "seal-verifier --help exits successfully"
  else
    local help_out
    help_out="$(cd "$cli_dir" && node dist/index.js --help 2>&1 || true)"
    if echo "$help_out" | grep -qi "usage\|help\|seal\|verify"; then
      log_pass "seal-verifier --help produces help output"
    else
      log_fail "seal-verifier --help produced no recognizable output"
    fi
  fi

  # -- Verify browser-extension assets --
  if [ -d "$cli_dir/browser-extension" ]; then
    log_pass "browser-extension/ directory present"
  else
    log_fail "browser-extension/ directory missing"
  fi
}

# ---------------------------------------------------------------------------
# 3. Rust CLI (aethelred-cli)
# ---------------------------------------------------------------------------
test_rust_cli() {
  log_section "Rust CLI (aethelred-cli)"

  local cli_dir="$REPO_ROOT/tools/cli"

  if [ ! -f "$cli_dir/Cargo.toml" ]; then
    log_fail "Cargo.toml not found in tools/cli/"
    return
  fi
  log_pass "Cargo.toml exists"

  if ! check_cmd cargo; then
    log_fail "cargo not found - skipping Rust CLI tests"
    return
  fi

  # -- Verify binary name --
  local bin_name
  bin_name="$(grep '^\[\[bin\]\]' -A2 "$cli_dir/Cargo.toml" | grep '^name' | head -1 | sed 's/.*"\(.*\)".*/\1/')"
  if [ "$bin_name" = "aethelred" ]; then
    log_pass "binary name: aethelred"
  else
    log_fail "binary name mismatch: expected aethelred, got $bin_name"
  fi

  # -- Verify clap dependency (CLI framework) --
  if grep -q 'clap' "$cli_dir/Cargo.toml"; then
    log_pass "clap CLI framework dependency present"
  else
    log_fail "clap not found in dependencies"
  fi

  # -- cargo check --
  if (cd "$cli_dir" && cargo check 2>/dev/null); then
    log_pass "cargo check succeeded"
  else
    log_fail "cargo check failed"
  fi

  # -- cargo build --
  if (cd "$cli_dir" && cargo build 2>/dev/null); then
    log_pass "cargo build succeeded"
  else
    log_fail "cargo build failed"
    return
  fi

  # -- Run --help --
  local bin_path="$cli_dir/target/debug/aethelred"
  if [ -f "$bin_path" ]; then
    if "$bin_path" --help >/dev/null 2>&1; then
      log_pass "aethelred --help exits successfully"
    else
      local help_out
      help_out="$("$bin_path" --help 2>&1 || true)"
      if echo "$help_out" | grep -qi "usage\|help\|aethelred"; then
        log_pass "aethelred --help produces help output"
      else
        log_fail "aethelred --help produced no recognizable output"
      fi
    fi

    # -- Run --version --
    local version_out
    version_out="$("$bin_path" --version 2>&1 || true)"
    if echo "$version_out" | grep -qi "aethelred\|[0-9]\.[0-9]"; then
      log_pass "aethelred --version output: $(echo "$version_out" | head -1)"
    else
      log_fail "aethelred --version produced no version string"
    fi
  else
    log_fail "binary not found at $bin_path"
  fi

  # -- Verify src/main.rs --
  if [ -f "$cli_dir/src/main.rs" ]; then
    log_pass "src/main.rs entry point exists"
  else
    log_fail "src/main.rs missing"
  fi
}

# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------
main() {
  printf '\033[1;35m%s\033[0m\n' "======================================================"
  printf '\033[1;35m  SQ18: CLI Smoke Tests\033[0m\n'
  printf '\033[1;35m%s\033[0m\n' "======================================================"
  printf '  Repo root:  %s\n' "$REPO_ROOT"
  printf '  Date:       %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  test_aethel_cli
  test_seal_verifier_cli
  test_rust_cli

  printf '\n\033[1;36m=== Summary ===\033[0m\n'
  printf '  Passed: \033[1;32m%d\033[0m\n' "$PASS"
  printf '  Failed: \033[1;31m%d\033[0m\n' "$FAIL"

  if [ "$FAIL" -gt 0 ]; then
    printf '\n\033[1;31mFailed tests:\033[0m'
    printf "$FAILURES\n"
    printf '\n'
    exit 1
  fi

  printf '\n\033[1;32mAll CLI smoke tests passed.\033[0m\n'
  exit 0
}

main "$@"
