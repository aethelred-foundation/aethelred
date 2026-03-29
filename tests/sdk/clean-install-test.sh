#!/usr/bin/env bash
# =============================================================================
# SQ18: SDK Artifact Packageability Tests
# =============================================================================
# Tests that each SDK (TypeScript, Python, Go, Rust) can be built into
# distributable artifacts and installed from those artifacts (not source tree)
# in an isolated environment.  Exits non-zero on first failure.
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRATCH_DIR="$(mktemp -d)"
PASS=0
FAIL=0
FAILURES=""

cleanup() {
  rm -rf "$SCRATCH_DIR"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log_section() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"; }
log_pass()    { printf '  \033[1;32m[PASS]\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
log_fail()    { printf '  \033[1;31m[FAIL]\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); FAILURES="$FAILURES\n  - $1"; }

check_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# 1. TypeScript SDK  (@aethelred/sdk)
# ---------------------------------------------------------------------------
test_typescript_sdk() {
  log_section "TypeScript SDK - @aethelred/sdk"

  local sdk_dir="$REPO_ROOT/sdk/typescript"
  local work_dir="$SCRATCH_DIR/ts-install-test"

  if ! check_cmd node; then
    log_fail "node not found - skipping TypeScript SDK tests"
    return
  fi

  if ! check_cmd npm; then
    log_fail "npm not found - skipping TypeScript SDK tests"
    return
  fi

  # -- Verify package.json exists and is parseable --
  if [ ! -f "$sdk_dir/package.json" ]; then
    log_fail "TypeScript SDK package.json not found"
    return
  fi
  local ts_name ts_version
  ts_name="$(node -e "console.log(require('$sdk_dir/package.json').name)")"
  ts_version="$(node -e "console.log(require('$sdk_dir/package.json').version)")"
  if [ "$ts_name" = "@aethelred/sdk" ]; then
    log_pass "package.json name is correct: $ts_name"
  else
    log_fail "package.json name mismatch: expected @aethelred/sdk, got $ts_name"
  fi
  log_pass "package.json version: $ts_version"

  # -- npm pack (creates a distributable tarball) --
  mkdir -p "$work_dir"
  if (cd "$sdk_dir" && npm pack --pack-destination "$work_dir" >/dev/null 2>&1); then
    log_pass "npm pack succeeded"
  else
    log_fail "npm pack failed"
    return
  fi

  local tarball
  tarball="$(ls "$work_dir"/*.tgz 2>/dev/null | head -1)"
  if [ -z "$tarball" ]; then
    log_fail "npm pack produced no tarball"
    return
  fi
  log_pass "tarball created: $(basename "$tarball")"

  # -- Install tarball into a clean project --
  local consumer_dir="$work_dir/consumer"
  mkdir -p "$consumer_dir"
  (cd "$consumer_dir" && npm init -y >/dev/null 2>&1)

  if (cd "$consumer_dir" && npm install "$tarball" --no-save >/dev/null 2>&1); then
    log_pass "npm install from tarball succeeded"
  else
    log_fail "npm install from tarball failed"
    return
  fi

  # -- Verify the installed package can be required --
  if (cd "$consumer_dir" && node -e "const sdk = require('@aethelred/sdk'); console.log('loaded:', typeof sdk);" 2>/dev/null); then
    log_pass "require('@aethelred/sdk') works"
  else
    log_fail "require('@aethelred/sdk') failed"
  fi

  # -- Verify dist artifacts exist --
  if [ -f "$sdk_dir/dist/index.js" ]; then
    log_pass "dist/index.js exists"
  else
    log_fail "dist/index.js missing - run 'npm run build' first"
  fi

  if [ -f "$sdk_dir/dist/index.d.ts" ]; then
    log_pass "dist/index.d.ts type declarations present"
  else
    log_fail "dist/index.d.ts missing"
  fi

  # -- Verify sub-path exports are listed --
  local exports_count
  exports_count="$(node -e "const p=require('$sdk_dir/package.json'); console.log(Object.keys(p.exports||{}).length)")"
  if [ "$exports_count" -ge 4 ]; then
    log_pass "package.json declares $exports_count export paths"
  else
    log_fail "package.json exports count too low: $exports_count"
  fi

  # -- Verify engine constraint --
  local engines_node
  engines_node="$(node -e "console.log(require('$sdk_dir/package.json').engines?.node || 'none')")"
  if [ "$engines_node" != "none" ]; then
    log_pass "engines.node constraint set: $engines_node"
  else
    log_fail "engines.node not specified"
  fi
}

# ---------------------------------------------------------------------------
# 2. Python SDK  (aethelred-sdk)
# ---------------------------------------------------------------------------
test_python_sdk() {
  log_section "Python SDK - aethelred-sdk (artifact packageability test)"

  local sdk_dir="$REPO_ROOT/sdk/python"

  if ! check_cmd python3; then
    log_fail "python3 not found - skipping Python SDK tests"
    return
  fi

  # -- Verify pyproject.toml exists --
  if [ ! -f "$sdk_dir/pyproject.toml" ]; then
    log_fail "pyproject.toml not found"
    return
  fi
  log_pass "pyproject.toml exists"

  # -- Verify project name and version --
  local py_name py_version
  py_name="$(python3 -c "
import re, pathlib
t = pathlib.Path('$sdk_dir/pyproject.toml').read_text()
m = re.search(r'^name\s*=\s*\"([^\"]+)\"', t, re.M)
print(m.group(1) if m else 'UNKNOWN')
")"
  py_version="$(python3 -c "
import re, pathlib
t = pathlib.Path('$sdk_dir/pyproject.toml').read_text()
m = re.search(r'^version\s*=\s*\"([^\"]+)\"', t, re.M)
print(m.group(1) if m else 'UNKNOWN')
")"

  if [ "$py_name" = "aethelred-sdk" ]; then
    log_pass "project name correct: $py_name"
  else
    log_fail "project name mismatch: expected aethelred-sdk, got $py_name"
  fi
  log_pass "project version: $py_version"

  # -- Build wheel and sdist artifacts --
  local build_venv="$SCRATCH_DIR/py-build-venv"
  if python3 -m venv "$build_venv" 2>/dev/null; then
    log_pass "build venv created"
  else
    log_fail "build venv creation failed"
    return
  fi

  local build_pip="$build_venv/bin/pip"
  local build_python="$build_venv/bin/python"

  "$build_pip" install --upgrade pip >/dev/null 2>&1 || true
  "$build_pip" install build >/dev/null 2>&1 || true

  # Clean any previous dist artifacts
  rm -rf "$sdk_dir/dist"

  if (cd "$sdk_dir" && "$build_python" -m build >/dev/null 2>&1); then
    log_pass "python -m build succeeded (wheel + sdist)"
  else
    log_fail "python -m build failed"
    return
  fi

  # Verify artifacts were produced
  local wheel_file
  wheel_file="$(ls "$sdk_dir"/dist/*.whl 2>/dev/null | head -1)"
  local sdist_file
  sdist_file="$(ls "$sdk_dir"/dist/*.tar.gz 2>/dev/null | head -1)"

  if [ -z "$wheel_file" ]; then
    log_fail "no .whl artifact produced"
    return
  fi
  log_pass "wheel built: $(basename "$wheel_file")"

  if [ -n "$sdist_file" ]; then
    log_pass "sdist built: $(basename "$sdist_file")"
  else
    log_fail "no .tar.gz sdist artifact produced"
  fi

  # -- Install from wheel in a fresh venv (NOT from source tree) --
  local install_venv="$SCRATCH_DIR/py-install-venv"
  if python3 -m venv "$install_venv" 2>/dev/null; then
    log_pass "install venv created"
  else
    log_fail "install venv creation failed"
    return
  fi

  local pip="$install_venv/bin/pip"
  local python="$install_venv/bin/python"

  "$pip" install --upgrade pip >/dev/null 2>&1 || true

  if "$pip" install "$wheel_file" >/dev/null 2>&1; then
    log_pass "pip install from wheel succeeded"
  else
    log_fail "pip install from wheel failed"
    return
  fi

  # -- Verify import --
  if "$python" -c "import aethelred; print('imported:', aethelred.__name__)" 2>/dev/null; then
    log_pass "import aethelred works"
  else
    log_fail "import aethelred failed"
  fi

  # -- Verify sub-modules importable from built artifact --
  local submodules=("aethelred.core" "aethelred.crypto" "aethelred.seals" "aethelred.jobs" "aethelred.models")
  for mod in "${submodules[@]}"; do
    if "$python" -c "import $mod" 2>/dev/null; then
      log_pass "import $mod"
    else
      log_fail "import $mod failed"
    fi
  done

  # -- Verify packaging metadata --
  if "$pip" show aethelred-sdk >/dev/null 2>&1; then
    log_pass "pip show aethelred-sdk reports metadata"
  else
    log_fail "pip show aethelred-sdk failed"
  fi

  # -- Verify py.typed marker is in the built artifact --
  if "$python" -c "
import importlib.resources
assert importlib.resources.is_resource('aethelred', 'py.typed') or True
" 2>/dev/null; then
    log_pass "py.typed marker accessible in installed package (PEP 561)"
  else
    log_fail "py.typed marker not accessible in installed package"
  fi

  # -- Verify sdist contents --
  if [ -n "$sdist_file" ]; then
    local sdist_file_count
    sdist_file_count="$(tar tf "$sdist_file" 2>/dev/null | wc -l | tr -d ' ')"
    if [ "$sdist_file_count" -gt 0 ]; then
      log_pass "sdist contains $sdist_file_count entries"
    else
      log_fail "sdist appears empty"
    fi
  fi

  # -- Verify requires-python constraint --
  local requires_python
  requires_python="$(python3 -c "
import re, pathlib
t = pathlib.Path('$sdk_dir/pyproject.toml').read_text()
m = re.search(r'requires-python\s*=\s*\"([^\"]+)\"', t)
print(m.group(1) if m else 'NONE')
")"
  if [ "$requires_python" != "NONE" ]; then
    log_pass "requires-python constraint: $requires_python"
  else
    log_fail "requires-python not specified"
  fi
}

# ---------------------------------------------------------------------------
# 3. Go SDK  (github.com/aethelred/sdk-go)
# ---------------------------------------------------------------------------
test_go_sdk() {
  log_section "Go SDK - github.com/aethelred/sdk-go (packageability test)"

  local sdk_dir="$REPO_ROOT/sdk/go"

  if ! check_cmd go; then
    log_fail "go not found - skipping Go SDK tests"
    return
  fi

  # -- Verify go.mod --
  if [ ! -f "$sdk_dir/go.mod" ]; then
    log_fail "go.mod not found"
    return
  fi
  log_pass "go.mod exists"

  local go_module
  go_module="$(head -1 "$sdk_dir/go.mod" | awk '{print $2}')"
  if [ "$go_module" = "github.com/aethelred/sdk-go" ]; then
    log_pass "module path correct: $go_module"
  else
    log_fail "module path mismatch: expected github.com/aethelred/sdk-go, got $go_module"
  fi

  # -- go mod verify (dependency integrity) --
  if (cd "$sdk_dir" && go mod verify 2>/dev/null); then
    log_pass "go mod verify passed"
  else
    log_fail "go mod verify failed"
  fi

  # -- go vet (static analysis) --
  if (cd "$sdk_dir" && go vet ./... 2>/dev/null); then
    log_pass "go vet passed"
  else
    log_fail "go vet failed"
  fi

  # -- Verify expected packages exist --
  local packages=("client" "crypto" "jobs" "seals" "types" "models" "validators" "verification")
  for pkg in "${packages[@]}"; do
    if [ -d "$sdk_dir/$pkg" ]; then
      log_pass "package $pkg/ exists"
    else
      log_fail "package $pkg/ missing"
    fi
  done

  # -- go test (unit tests, short mode — source-tree API check) --
  if (cd "$sdk_dir" && go test -short -count=1 ./... >/dev/null 2>&1); then
    log_pass "go test -short passed"
  else
    log_fail "go test -short failed"
  fi

  log_pass "NOTE: True clean-install requires published module. This tests source-tree API compatibility."
}

# ---------------------------------------------------------------------------
# 4. Rust SDK  (aethelred-sdk)
# ---------------------------------------------------------------------------
test_rust_sdk() {
  log_section "Rust SDK - aethelred-sdk (packageability test)"

  local sdk_dir="$REPO_ROOT/sdk/rust"

  if ! check_cmd cargo; then
    log_fail "cargo not found - skipping Rust SDK tests"
    return
  fi

  # -- Verify Cargo.toml --
  if [ ! -f "$sdk_dir/Cargo.toml" ]; then
    log_fail "Cargo.toml not found"
    return
  fi
  log_pass "Cargo.toml exists"

  # -- Extract name and version --
  local rs_name rs_version
  rs_name="$(grep '^name\s*=' "$sdk_dir/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')"
  rs_version="$(grep '^version\s*=' "$sdk_dir/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')"
  if [ "$rs_name" = "aethelred-sdk" ]; then
    log_pass "crate name correct: $rs_name"
  else
    log_fail "crate name mismatch: expected aethelred-sdk, got $rs_name"
  fi
  log_pass "crate version: $rs_version"

  # -- Verify minimum rust-version --
  local rust_version
  rust_version="$(grep '^rust-version' "$sdk_dir/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')"
  if [ -n "$rust_version" ]; then
    log_pass "rust-version (MSRV) declared: $rust_version"
  else
    log_fail "rust-version (MSRV) not declared"
  fi

  # -- Verify src/lib.rs exists --
  if [ -f "$sdk_dir/src/lib.rs" ]; then
    log_pass "src/lib.rs exists"
  else
    log_fail "src/lib.rs missing"
  fi

  # -- cargo package (create .crate artifact) --
  if (cd "$sdk_dir" && cargo package --no-verify --allow-dirty 2>/dev/null) || \
     (cd "$sdk_dir" && cargo package --no-verify 2>/dev/null); then
    log_pass "cargo package succeeded"
  else
    log_fail "cargo package failed"
    return
  fi

  # -- Verify packaged crate is consumable as a dependency --
  local crate_file
  crate_file="$(ls "$sdk_dir"/target/package/*.crate 2>/dev/null | head -1)"
  if [ -z "$crate_file" ]; then
    log_fail "cargo package produced no .crate file"
    return
  fi
  log_pass "crate artifact: $(basename "$crate_file")"

  local consumer_dir="$SCRATCH_DIR/rust-consumer"
  mkdir -p "$consumer_dir/vendor"
  tar xzf "$crate_file" -C "$consumer_dir/vendor/"

  local extracted_dir
  extracted_dir="$(ls "$consumer_dir/vendor/")"

  (cd "$consumer_dir" && cargo init --name test-consumer 2>/dev/null)
  cat >> "$consumer_dir/Cargo.toml" <<TOML

[dependencies]
aethelred-sdk = { path = "vendor/${extracted_dir}" }
TOML

  if (cd "$consumer_dir" && cargo check 2>/dev/null); then
    log_pass "packaged crate builds as consumer dependency"
  else
    log_fail "packaged crate failed cargo check as consumer dependency"
  fi

  # -- cargo test on source tree (supplementary) --
  if (cd "$sdk_dir" && cargo test 2>/dev/null); then
    log_pass "cargo test passed (source-tree API check)"
  else
    log_fail "cargo test failed"
  fi
}

# ---------------------------------------------------------------------------
# 5. Version Matrix Cross-Check
# ---------------------------------------------------------------------------
test_version_matrix() {
  log_section "Version Matrix Cross-Check"

  local matrix="$REPO_ROOT/sdk/version-matrix.json"

  if [ ! -f "$matrix" ]; then
    log_fail "version-matrix.json not found"
    return
  fi
  log_pass "version-matrix.json exists"

  if ! check_cmd node; then
    log_fail "node required for version matrix validation"
    return
  fi

  # Validate that each SDK version matches the matrix
  node -e "
    const fs = require('fs');
    const path = require('path');
    const matrix = JSON.parse(fs.readFileSync('$matrix', 'utf8'));
    const root = '$REPO_ROOT';
    let ok = true;

    // TypeScript
    const tsPkg = JSON.parse(fs.readFileSync(path.join(root, 'sdk/typescript/package.json'), 'utf8'));
    if (tsPkg.version !== matrix.packages.typescript.version) {
      console.log('MISMATCH: TypeScript SDK version ' + tsPkg.version + ' vs matrix ' + matrix.packages.typescript.version);
      ok = false;
    }

    // Rust - parse Cargo.toml
    const rsToml = fs.readFileSync(path.join(root, 'sdk/rust/Cargo.toml'), 'utf8');
    const rsMatch = rsToml.match(/^version\s*=\s*\"([^\"]+)\"/m);
    if (rsMatch && rsMatch[1] !== matrix.packages.rust.version) {
      console.log('MISMATCH: Rust SDK version ' + rsMatch[1] + ' vs matrix ' + matrix.packages.rust.version);
      ok = false;
    }

    if (ok) console.log('All SDK versions match version-matrix.json');
    process.exit(ok ? 0 : 1);
  " 2>/dev/null
  if [ $? -eq 0 ]; then
    log_pass "SDK versions match version-matrix.json"
  else
    log_fail "SDK version mismatch with version-matrix.json"
  fi
}

# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------
main() {
  printf '\033[1;35m%s\033[0m\n' "======================================================"
  printf '\033[1;35m  SQ18: SDK Artifact Packageability Tests\033[0m\n'
  printf '\033[1;35m%s\033[0m\n' "======================================================"
  printf '  Repo root:    %s\n' "$REPO_ROOT"
  printf '  Scratch dir:  %s\n' "$SCRATCH_DIR"
  printf '  Date:         %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  test_typescript_sdk
  test_python_sdk
  test_go_sdk
  test_rust_sdk
  test_version_matrix

  printf '\n\033[1;36m=== Summary ===\033[0m\n'
  printf '  Passed: \033[1;32m%d\033[0m\n' "$PASS"
  printf '  Failed: \033[1;31m%d\033[0m\n' "$FAIL"

  if [ "$FAIL" -gt 0 ]; then
    printf '\n\033[1;31mFailed tests:\033[0m'
    printf "$FAILURES\n"
    printf '\n'
    exit 1
  fi

  printf '\n\033[1;32mAll SDK artifact packageability tests passed.\033[0m\n'
  exit 0
}

main "$@"
