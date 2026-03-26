#!/usr/bin/env bash
# =============================================================================
# SQ19: Schema Compatibility Tests
# =============================================================================
# Validates that SDK types stay in sync with protobuf definitions and
# the OpenAPI specification.
#
# Checks:
#   1. Proto field names appear in each SDK's type definitions
#   2. SDK versions match version-matrix.json
#   3. OpenAPI spec covers required endpoints
#   4. Cross-SDK type parity (all SDKs define the same core types)
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PASS=0
FAIL=0
FAILURES=""

log_section() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"; }
log_pass()    { printf '  \033[1;32m[PASS]\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
log_fail()    { printf '  \033[1;31m[FAIL]\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); FAILURES="$FAILURES\n  - $1"; }
log_skip()    { printf '  \033[1;33m[SKIP]\033[0m %s\n' "$1"; }

# ---------------------------------------------------------------------------
# 1. Proto <-> TypeScript SDK field alignment
# ---------------------------------------------------------------------------
test_proto_typescript_compat() {
  log_section "Proto <-> TypeScript SDK Compatibility"

  local seal_proto="$REPO_ROOT/proto/aethelred/seal/v1/seal.proto"
  local verify_proto="$REPO_ROOT/proto/aethelred/verify/v1/verify.proto"
  local ts_seal="$REPO_ROOT/sdk/typescript/src/types/seal.ts"
  local ts_types_dir="$REPO_ROOT/sdk/typescript/src/types"

  if [ ! -f "$seal_proto" ]; then
    log_fail "seal.proto not found"
    return
  fi

  if [ ! -f "$ts_seal" ]; then
    log_fail "TypeScript seal types not found"
    return
  fi

  # Core DigitalSeal fields from proto (snake_case) -> expected camelCase in TS
  local -A seal_fields=(
    ["id"]="id"
    ["model_commitment"]="modelCommitment"
    ["input_commitment"]="inputCommitment"
    ["output_commitment"]="outputCommitment"
    ["block_height"]="blockHeight"
    ["timestamp"]="timestamp"
    ["validator_set"]="validatorSet"
    ["requested_by"]="requestedBy"
    ["purpose"]="purpose"
    ["status"]="status"
    ["tee_attestations"]="teeAttestations"
    ["zk_proof"]="zkProof"
    ["regulatory_info"]="regulatoryInfo"
  )

  for proto_field in "${!seal_fields[@]}"; do
    local ts_field="${seal_fields[$proto_field]}"

    # Check proto has the field
    if grep -q "$proto_field" "$seal_proto"; then
      # Check TS has the camelCase equivalent
      if grep -q "$ts_field" "$ts_seal"; then
        log_pass "DigitalSeal.$proto_field -> $ts_field"
      else
        log_fail "DigitalSeal.$proto_field exists in proto but $ts_field missing in TS"
      fi
    else
      log_skip "DigitalSeal.$proto_field not in proto (may have been removed)"
    fi
  done

  # Check VerificationType enum values
  if [ -f "$verify_proto" ]; then
    local verify_types=("TEE" "ZKML" "HYBRID")
    for vtype in "${verify_types[@]}"; do
      if grep -q "VERIFICATION_TYPE_${vtype}" "$verify_proto"; then
        local ts_lower
        ts_lower="$(echo "$vtype" | tr '[:upper:]' '[:lower:]')"
        if grep -qi "'${ts_lower}'\|\"${ts_lower}\"" "$ts_seal"; then
          log_pass "VerificationType.$vtype mapped in TS"
        else
          log_fail "VerificationType.$vtype in proto but not in TS types"
        fi
      fi
    done
  fi

  # Check SealStatus enum values
  local seal_statuses=("pending" "active" "revoked" "expired")
  for status in "${seal_statuses[@]}"; do
    if grep -q "'${status}'" "$ts_seal"; then
      log_pass "SealStatus '$status' defined in TS"
    else
      log_fail "SealStatus '$status' missing in TS"
    fi
  done
}

# ---------------------------------------------------------------------------
# 2. Proto <-> Python SDK field alignment
# ---------------------------------------------------------------------------
test_proto_python_compat() {
  log_section "Proto <-> Python SDK Compatibility"

  local seal_proto="$REPO_ROOT/proto/aethelred/seal/v1/seal.proto"
  local py_sdk="$REPO_ROOT/sdk/python/aethelred"

  if [ ! -f "$seal_proto" ]; then
    log_fail "seal.proto not found"
    return
  fi

  if [ ! -d "$py_sdk" ]; then
    log_fail "Python SDK directory not found"
    return
  fi

  # Look for seal-related types in Python SDK
  local py_seal_files
  py_seal_files="$(find "$py_sdk" -name '*.py' -type f 2>/dev/null | head -50)"

  if [ -z "$py_seal_files" ]; then
    log_fail "no Python files found in SDK"
    return
  fi

  # Core proto fields that must appear somewhere in Python SDK (snake_case preserved)
  local proto_fields=("model_commitment" "input_commitment" "output_commitment" "block_height" "validator_set" "requested_by" "tee_attestations" "zk_proof")

  for field in "${proto_fields[@]}"; do
    if grep -rq "$field" "$py_sdk" --include='*.py' 2>/dev/null; then
      log_pass "field '$field' found in Python SDK"
    else
      # Python might use the field without underscore or different naming
      local camel
      camel="$(echo "$field" | sed -E 's/_([a-z])/\U\1/g')"
      if grep -rq "$camel" "$py_sdk" --include='*.py' 2>/dev/null; then
        log_pass "field '$field' found as '$camel' in Python SDK"
      else
        log_fail "field '$field' not found in Python SDK"
      fi
    fi
  done

  # Verify core modules exist
  local core_modules=("seals" "jobs" "models" "crypto" "verification")
  for mod in "${core_modules[@]}"; do
    if [ -d "$py_sdk/$mod" ] || [ -f "$py_sdk/${mod}.py" ]; then
      log_pass "Python module '$mod' exists"
    else
      log_fail "Python module '$mod' missing"
    fi
  done
}

# ---------------------------------------------------------------------------
# 3. Proto <-> Go SDK field alignment
# ---------------------------------------------------------------------------
test_proto_go_compat() {
  log_section "Proto <-> Go SDK Compatibility"

  local seal_proto="$REPO_ROOT/proto/aethelred/seal/v1/seal.proto"
  local go_sdk="$REPO_ROOT/sdk/go"

  if [ ! -f "$seal_proto" ]; then
    log_fail "seal.proto not found"
    return
  fi

  if [ ! -d "$go_sdk" ]; then
    log_fail "Go SDK directory not found"
    return
  fi

  # Go uses PascalCase for exported fields
  local -A go_fields=(
    ["model_commitment"]="ModelCommitment"
    ["input_commitment"]="InputCommitment"
    ["output_commitment"]="OutputCommitment"
    ["block_height"]="BlockHeight"
    ["validator_set"]="ValidatorSet"
    ["requested_by"]="RequestedBy"
    ["tee_attestations"]="TEEAttestation"
    ["zk_proof"]="ZKProof\|ZkProof\|ZKMLProof"
  )

  for proto_field in "${!go_fields[@]}"; do
    local go_pattern="${go_fields[$proto_field]}"
    if grep -rqE "$go_pattern" "$go_sdk" --include='*.go' 2>/dev/null; then
      log_pass "field '$proto_field' -> Go pattern '$go_pattern' found"
    else
      log_fail "field '$proto_field' -> Go pattern '$go_pattern' not found"
    fi
  done

  # Verify core packages exist
  local go_packages=("client" "crypto" "seals" "jobs" "types" "verification")
  for pkg in "${go_packages[@]}"; do
    if [ -d "$go_sdk/$pkg" ]; then
      log_pass "Go package '$pkg/' exists"
    else
      log_fail "Go package '$pkg/' missing"
    fi
  done
}

# ---------------------------------------------------------------------------
# 4. Proto <-> Rust SDK field alignment
# ---------------------------------------------------------------------------
test_proto_rust_compat() {
  log_section "Proto <-> Rust SDK Compatibility"

  local seal_proto="$REPO_ROOT/proto/aethelred/seal/v1/seal.proto"
  local rs_sdk="$REPO_ROOT/sdk/rust/src"

  if [ ! -f "$seal_proto" ]; then
    log_fail "seal.proto not found"
    return
  fi

  if [ ! -d "$rs_sdk" ]; then
    log_fail "Rust SDK src/ not found"
    return
  fi

  # Rust uses snake_case for fields (same as proto)
  local proto_fields=("model_commitment" "input_commitment" "output_commitment" "block_height" "validator_set" "requested_by")

  for field in "${proto_fields[@]}"; do
    if grep -rq "$field" "$rs_sdk" --include='*.rs' 2>/dev/null; then
      log_pass "field '$field' found in Rust SDK"
    else
      log_fail "field '$field' not found in Rust SDK"
    fi
  done

  # Verify lib.rs exists and declares modules
  if [ -f "$rs_sdk/lib.rs" ]; then
    log_pass "src/lib.rs exists"
  else
    log_fail "src/lib.rs missing"
  fi
}

# ---------------------------------------------------------------------------
# 5. OpenAPI Spec Validation
# ---------------------------------------------------------------------------
test_openapi_spec() {
  log_section "OpenAPI Specification Checks"

  local openapi="$REPO_ROOT/integrations/api/openapi/aethelred-api-v1.yaml"

  if [ ! -f "$openapi" ]; then
    log_fail "OpenAPI spec not found at $openapi"
    return
  fi
  log_pass "OpenAPI spec exists"

  # Check it is valid YAML (basic check)
  if head -5 "$openapi" | grep -q 'openapi\|swagger'; then
    log_pass "OpenAPI spec starts with version declaration"
  else
    log_fail "OpenAPI spec missing version declaration"
  fi

  # Check required endpoint groups are defined
  local endpoint_patterns=("seal" "verify" "job" "health" "validator")
  for ep in "${endpoint_patterns[@]}"; do
    if grep -qi "$ep" "$openapi"; then
      log_pass "OpenAPI references '$ep' endpoint/schema"
    else
      log_fail "OpenAPI missing '$ep' endpoint/schema"
    fi
  done

  # Check schema definitions exist
  if grep -q 'schemas\|definitions' "$openapi"; then
    log_pass "OpenAPI contains schema definitions"
  else
    log_fail "OpenAPI missing schema definitions section"
  fi

  # Verify version matches version-matrix
  local matrix="$REPO_ROOT/sdk/version-matrix.json"
  if [ -f "$matrix" ] && command -v node >/dev/null 2>&1; then
    local matrix_api_version
    matrix_api_version="$(node -e "console.log(JSON.parse(require('fs').readFileSync('$matrix','utf8')).api.openapi_version)")"
    if grep -q "$matrix_api_version" "$openapi"; then
      log_pass "OpenAPI version matches version-matrix ($matrix_api_version)"
    else
      log_fail "OpenAPI version may not match version-matrix ($matrix_api_version)"
    fi
  fi
}

# ---------------------------------------------------------------------------
# 6. Cross-SDK Type Parity
# ---------------------------------------------------------------------------
test_cross_sdk_parity() {
  log_section "Cross-SDK Type Parity"

  # Core types that every SDK must define
  local core_types=("DigitalSeal\|digital_seal" "TEEAttestation\|tee_attestation" "ZKMLProof\|zkml_proof\|ZkProof" "SealStatus\|seal_status")

  local sdks=(
    "TypeScript:$REPO_ROOT/sdk/typescript/src:ts"
    "Python:$REPO_ROOT/sdk/python/aethelred:py"
    "Go:$REPO_ROOT/sdk/go:go"
    "Rust:$REPO_ROOT/sdk/rust/src:rs"
  )

  for core_type in "${core_types[@]}"; do
    local type_label
    type_label="$(echo "$core_type" | sed 's/\\|.*//')"

    for sdk_entry in "${sdks[@]}"; do
      local sdk_name sdk_dir sdk_ext
      sdk_name="$(echo "$sdk_entry" | cut -d: -f1)"
      sdk_dir="$(echo "$sdk_entry" | cut -d: -f2)"
      sdk_ext="$(echo "$sdk_entry" | cut -d: -f3)"

      if [ ! -d "$sdk_dir" ]; then
        log_skip "$sdk_name SDK dir not found"
        continue
      fi

      if grep -rqiE "$core_type" "$sdk_dir" --include="*.$sdk_ext" 2>/dev/null; then
        log_pass "$sdk_name defines $type_label"
      else
        log_fail "$sdk_name missing $type_label type definition"
      fi
    done
  done
}

# ---------------------------------------------------------------------------
# 7. Version Matrix Internal Consistency
# ---------------------------------------------------------------------------
test_version_matrix_consistency() {
  log_section "Version Matrix Consistency"

  local matrix="$REPO_ROOT/sdk/version-matrix.json"

  if [ ! -f "$matrix" ]; then
    log_fail "version-matrix.json not found"
    return
  fi

  if ! command -v node >/dev/null 2>&1; then
    log_skip "node required for version matrix checks"
    return
  fi

  node -e "
    const fs = require('fs');
    const path = require('path');
    const matrix = JSON.parse(fs.readFileSync('$matrix', 'utf8'));
    const root = '$REPO_ROOT';
    let pass = 0, fail = 0;

    function check(label, ok) {
      if (ok) { console.log('PASS:' + label); pass++; }
      else    { console.log('FAIL:' + label); fail++; }
    }

    // Validate all declared paths exist
    for (const [name, pkg] of Object.entries(matrix.packages)) {
      const p = path.join(root, pkg.path);
      check(name + ' path exists (' + pkg.path + ')', fs.existsSync(p));
    }

    // Validate release_train format
    check('release_train format', /^\d{4}\.Q[1-4]$/.test(matrix.release_train));

    // Validate policy_version is semver-ish
    check('policy_version is semver', /^\d+\.\d+\.\d+$/.test(matrix.policy_version));

    // Validate API section
    check('api.openapi_version defined', !!matrix.api?.openapi_version);
    check('api.rest_path_version defined', !!matrix.api?.rest_path_version);

    // Validate compatibility section
    check('compatibility rules defined', !!matrix.compatibility?.rule);

    console.log('---');
    console.log('TOTAL_PASS:' + pass);
    console.log('TOTAL_FAIL:' + fail);
  " 2>/dev/null | while IFS= read -r line; do
    case "$line" in
      PASS:*) log_pass "${line#PASS:}" ;;
      FAIL:*) log_fail "${line#FAIL:}" ;;
      TOTAL_*) ;; # handled by exit code
      ---) ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------
main() {
  printf '\033[1;35m%s\033[0m\n' "======================================================"
  printf '\033[1;35m  SQ19: Schema Compatibility Tests\033[0m\n'
  printf '\033[1;35m%s\033[0m\n' "======================================================"
  printf '  Repo root:  %s\n' "$REPO_ROOT"
  printf '  Date:       %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  test_proto_typescript_compat
  test_proto_python_compat
  test_proto_go_compat
  test_proto_rust_compat
  test_openapi_spec
  test_cross_sdk_parity
  test_version_matrix_consistency

  printf '\n\033[1;36m=== Summary ===\033[0m\n'
  printf '  Passed: \033[1;32m%d\033[0m\n' "$PASS"
  printf '  Failed: \033[1;31m%d\033[0m\n' "$FAIL"

  if [ "$FAIL" -gt 0 ]; then
    printf '\n\033[1;31mFailed tests:\033[0m'
    printf "$FAILURES\n"
    printf '\n'
    exit 1
  fi

  printf '\n\033[1;32mAll schema compatibility tests passed.\033[0m\n'
  exit 0
}

main "$@"
