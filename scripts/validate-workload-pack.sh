#!/usr/bin/env bash
# validate-workload-pack.sh — Validate an Aethelred workload pack directory
# Usage: scripts/validate-workload-pack.sh <pack-directory> [--check-evidence] [--json]
#
# Checks:
#   1. Required files exist (pack.md, demo-flow.md or embedded, benchmark-targets.md or embedded)
#   2. Required sections present in pack.md
#   3. Evidence output specification conforms to schema v1
#   4. Basic metadata validation
#
# Exit codes:
#   0 — All checks passed
#   1 — One or more checks failed
#   2 — Usage error

set -euo pipefail

# ─── Constants ────────────────────────────────────────────────────────────────

SCRIPT_NAME="$(basename "$0")"
VERSION="1.0.0"

# Required sections in pack.md (matched by heading text)
REQUIRED_SECTIONS=(
  "Pack Metadata"
  "Model Specification"
  "Circuit Specification"
  "TEE Lane Specification"
  "Policy Bundle"
  "Evidence Output Specification"
  "Compliance Mapping"
  "Demo Flow"
  "Benchmark Targets"
  "Deployment Configuration"
  "Acceptance Criteria"
)

# Evidence schema v1 required fields
EVIDENCE_FIELDS=(
  "evidence.model_hash"
  "evidence.input_hash"
  "evidence.output_hash"
  "evidence.zk_proof"
  "evidence.tee_attestation"
  "evidence.tee_platform"
  "evidence.tee_measurement"
  "evidence.timestamp"
  "evidence.validator_signature"
  "evidence.confidence_score"
  "evidence.chain_id"
  "evidence.job_id"
  "evidence.seal_id"
)

# Allowed evidence field values for "Populated" column
EVIDENCE_POPULATED_VALUES=("Yes" "No")

# ─── State ────────────────────────────────────────────────────────────────────

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
RESULTS=()
CHECK_EVIDENCE=false
JSON_OUTPUT=false

# ─── Functions ────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME <pack-directory> [OPTIONS]

Validate an Aethelred workload pack directory against the pack framework.

Options:
  --check-evidence   Also validate evidence output specification against schema v1
  --json             Output results as JSON
  -h, --help         Show this help message
  -v, --version      Show version

Examples:
  $SCRIPT_NAME docs/workload-packs/healthcare/radiology-v1
  $SCRIPT_NAME docs/workload-packs/finance/credit-risk-v1 --check-evidence --json
EOF
  exit 2
}

version() {
  echo "$SCRIPT_NAME $VERSION"
  exit 0
}

record_pass() {
  local check="$1"
  local detail="$2"
  PASS_COUNT=$((PASS_COUNT + 1))
  RESULTS+=("PASS|${check}|${detail}")
  if [ "$JSON_OUTPUT" = false ]; then
    echo "  [PASS] $check: $detail"
  fi
}

record_fail() {
  local check="$1"
  local detail="$2"
  FAIL_COUNT=$((FAIL_COUNT + 1))
  RESULTS+=("FAIL|${check}|${detail}")
  if [ "$JSON_OUTPUT" = false ]; then
    echo "  [FAIL] $check: $detail"
  fi
}

record_warn() {
  local check="$1"
  local detail="$2"
  WARN_COUNT=$((WARN_COUNT + 1))
  RESULTS+=("WARN|${check}|${detail}")
  if [ "$JSON_OUTPUT" = false ]; then
    echo "  [WARN] $check: $detail"
  fi
}

# ─── Check: Required Files ───────────────────────────────────────────────────

check_required_files() {
  local pack_dir="$1"

  if [ "$JSON_OUTPUT" = false ]; then
    echo ""
    echo "=== File Structure Checks ==="
  fi

  # pack.md is mandatory
  if [ -f "$pack_dir/pack.md" ]; then
    record_pass "FILE-01" "pack.md exists"
  else
    record_fail "FILE-01" "pack.md not found in $pack_dir"
  fi

  # demo-flow.md — can be standalone or embedded in pack.md Section 8
  if [ -f "$pack_dir/demo-flow.md" ]; then
    record_pass "FILE-02" "demo-flow.md exists as standalone file"
  elif [ -f "$pack_dir/pack.md" ] && grep -q "## .*Demo Flow" "$pack_dir/pack.md" 2>/dev/null; then
    record_pass "FILE-02" "Demo flow embedded in pack.md Section 8"
  else
    record_fail "FILE-02" "demo-flow.md not found and not embedded in pack.md"
  fi

  # benchmark-targets.md — can be standalone or embedded in pack.md Section 9
  if [ -f "$pack_dir/benchmark-targets.md" ]; then
    record_pass "FILE-03" "benchmark-targets.md exists as standalone file"
  elif [ -f "$pack_dir/pack.md" ] && grep -q "## .*Benchmark Targets" "$pack_dir/pack.md" 2>/dev/null; then
    record_pass "FILE-03" "Benchmark targets embedded in pack.md Section 9"
  else
    record_fail "FILE-03" "benchmark-targets.md not found and not embedded in pack.md"
  fi
}

# ─── Check: Required Sections ────────────────────────────────────────────────

check_required_sections() {
  local pack_dir="$1"

  if [ "$JSON_OUTPUT" = false ]; then
    echo ""
    echo "=== Section Checks (pack.md) ==="
  fi

  if [ ! -f "$pack_dir/pack.md" ]; then
    record_fail "SECT-00" "Cannot check sections — pack.md missing"
    return
  fi

  local section_num=1
  for section in "${REQUIRED_SECTIONS[@]}"; do
    local check_id
    check_id=$(printf "SECT-%02d" "$section_num")

    if grep -qi "## .*${section}" "$pack_dir/pack.md" 2>/dev/null; then
      record_pass "$check_id" "Section '$section' found"
    else
      record_fail "$check_id" "Section '$section' not found in pack.md"
    fi

    section_num=$((section_num + 1))
  done
}

# ─── Check: Metadata Validation ──────────────────────────────────────────────

check_metadata() {
  local pack_dir="$1"

  if [ "$JSON_OUTPUT" = false ]; then
    echo ""
    echo "=== Metadata Checks ==="
  fi

  if [ ! -f "$pack_dir/pack.md" ]; then
    record_fail "META-00" "Cannot check metadata — pack.md missing"
    return
  fi

  # Check Pack Name is filled (not placeholder)
  if grep -q '| \*\*Pack Name\*\*' "$pack_dir/pack.md" 2>/dev/null; then
    if grep '| \*\*Pack Name\*\*' "$pack_dir/pack.md" | grep -q '<unique-kebab-case-name>'; then
      record_fail "META-01" "Pack Name still contains placeholder"
    else
      record_pass "META-01" "Pack Name is filled"
    fi
  else
    record_warn "META-01" "Pack Name row not found in metadata table"
  fi

  # Check Version is SemVer-like
  if grep -q '| \*\*Version\*\*' "$pack_dir/pack.md" 2>/dev/null; then
    local version_line
    version_line=$(grep '| \*\*Version\*\*' "$pack_dir/pack.md" | head -1)
    if echo "$version_line" | grep -qE '[0-9]+\.[0-9]+\.[0-9]+'; then
      record_pass "META-02" "Version appears to be valid SemVer"
    else
      record_fail "META-02" "Version does not match SemVer pattern (X.Y.Z)"
    fi
  else
    record_warn "META-02" "Version row not found in metadata table"
  fi

  # Check Status is valid
  if grep -q '| \*\*Status\*\*' "$pack_dir/pack.md" 2>/dev/null; then
    local status_line
    status_line=$(grep '| \*\*Status\*\*' "$pack_dir/pack.md" | head -1)
    if echo "$status_line" | grep -qE 'draft|review|certified|deprecated'; then
      record_pass "META-03" "Status is a valid lifecycle value"
    else
      record_fail "META-03" "Status must be one of: draft, review, certified, deprecated"
    fi
  else
    record_warn "META-03" "Status row not found in metadata table"
  fi

  # Check Vertical is valid
  if grep -q '| \*\*Vertical\*\*' "$pack_dir/pack.md" 2>/dev/null; then
    local vertical_line
    vertical_line=$(grep '| \*\*Vertical\*\*' "$pack_dir/pack.md" | head -1)
    if echo "$vertical_line" | grep -qiE 'healthcare|finance|energy|supply-chain|identity|climate|general'; then
      record_pass "META-04" "Vertical is a recognized value"
    else
      record_warn "META-04" "Vertical not recognized (expected: healthcare, finance, energy, supply-chain, identity, climate, general)"
    fi
  else
    record_warn "META-04" "Vertical row not found in metadata table"
  fi

  # Check evidence schema version
  if grep -q 'evidence_schema_version' "$pack_dir/pack.md" 2>/dev/null; then
    if grep 'evidence_schema_version' "$pack_dir/pack.md" | grep -q '"v1"'; then
      record_pass "META-05" "Evidence schema version is v1"
    else
      record_fail "META-05" "Evidence schema version must be v1"
    fi
  else
    record_warn "META-05" "evidence_schema_version not found in pack.md"
  fi
}

# ─── Check: Evidence Output Specification ─────────────────────────────────────

check_evidence_spec() {
  local pack_dir="$1"

  if [ "$JSON_OUTPUT" = false ]; then
    echo ""
    echo "=== Evidence Specification Checks (Schema v1) ==="
  fi

  if [ ! -f "$pack_dir/pack.md" ]; then
    record_fail "EVID-00" "Cannot check evidence spec — pack.md missing"
    return
  fi

  # Check that Evidence Output Specification section exists
  if ! grep -qi "## .*Evidence Output Specification" "$pack_dir/pack.md" 2>/dev/null; then
    record_fail "EVID-00" "Evidence Output Specification section missing"
    return
  fi

  # Check each required evidence field is mentioned
  local field_num=1
  for field in "${EVIDENCE_FIELDS[@]}"; do
    local check_id
    check_id=$(printf "EVID-%02d" "$field_num")

    if grep -q "$field" "$pack_dir/pack.md" 2>/dev/null; then
      # Check that the field has a Yes or No value
      local field_line
      field_line=$(grep "$field" "$pack_dir/pack.md" | head -1)
      if echo "$field_line" | grep -qE '\| *(Yes|No) *\|'; then
        record_pass "$check_id" "Field '$field' present with Yes/No populated status"
      else
        record_warn "$check_id" "Field '$field' present but populated status unclear (expected Yes or No)"
      fi
    else
      record_fail "$check_id" "Required evidence field '$field' not found"
    fi

    field_num=$((field_num + 1))
  done

  # Check evidence_schema_version
  local evid_check_id
  evid_check_id=$(printf "EVID-%02d" "$field_num")
  if grep -q 'evidence_schema_version.*v1' "$pack_dir/pack.md" 2>/dev/null; then
    record_pass "$evid_check_id" "Evidence schema version declared as v1"
  else
    record_fail "$evid_check_id" "Evidence schema version must be v1"
  fi
}

# ─── Output: JSON ─────────────────────────────────────────────────────────────

output_json() {
  local pack_dir="$1"
  echo "{"
  echo "  \"pack_directory\": \"$pack_dir\","
  echo "  \"validator_version\": \"$VERSION\","
  echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"summary\": {"
  echo "    \"total\": $((PASS_COUNT + FAIL_COUNT + WARN_COUNT)),"
  echo "    \"pass\": $PASS_COUNT,"
  echo "    \"fail\": $FAIL_COUNT,"
  echo "    \"warn\": $WARN_COUNT,"
  echo "    \"result\": \"$([ "$FAIL_COUNT" -eq 0 ] && echo "PASS" || echo "FAIL")\""
  echo "  },"
  echo "  \"checks\": ["

  local first=true
  for result in "${RESULTS[@]}"; do
    local status check detail
    status=$(echo "$result" | cut -d'|' -f1)
    check=$(echo "$result" | cut -d'|' -f2)
    detail=$(echo "$result" | cut -d'|' -f3)

    if [ "$first" = true ]; then
      first=false
    else
      echo ","
    fi
    printf '    {"status": "%s", "check": "%s", "detail": "%s"}' "$status" "$check" "$detail"
  done

  echo ""
  echo "  ]"
  echo "}"
}

# ─── Output: Summary ──────────────────────────────────────────────────────────

output_summary() {
  local pack_dir="$1"
  echo ""
  echo "═══════════════════════════════════════════════════"
  echo "  Workload Pack Validation Report"
  echo "  Pack: $pack_dir"
  echo "  Validator: $SCRIPT_NAME v$VERSION"
  echo "  Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "═══════════════════════════════════════════════════"
  echo ""
  echo "  PASS: $PASS_COUNT"
  echo "  FAIL: $FAIL_COUNT"
  echo "  WARN: $WARN_COUNT"
  echo "  TOTAL: $((PASS_COUNT + FAIL_COUNT + WARN_COUNT))"
  echo ""
  if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "  RESULT: PASS -- Pack structure is valid"
  else
    echo "  RESULT: FAIL -- $FAIL_COUNT check(s) failed"
  fi
  echo ""
  echo "═══════════════════════════════════════════════════"
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
  local pack_dir=""

  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage ;;
      -v|--version) version ;;
      --check-evidence) CHECK_EVIDENCE=true; shift ;;
      --json) JSON_OUTPUT=true; shift ;;
      -*)
        echo "Error: Unknown option $1" >&2
        usage
        ;;
      *)
        if [ -z "$pack_dir" ]; then
          pack_dir="$1"
        else
          echo "Error: Multiple pack directories specified" >&2
          usage
        fi
        shift
        ;;
    esac
  done

  if [ -z "$pack_dir" ]; then
    echo "Error: Pack directory is required" >&2
    usage
  fi

  if [ ! -d "$pack_dir" ]; then
    echo "Error: Directory not found: $pack_dir" >&2
    exit 2
  fi

  # Run checks
  check_required_files "$pack_dir"
  check_required_sections "$pack_dir"
  check_metadata "$pack_dir"

  if [ "$CHECK_EVIDENCE" = true ]; then
    check_evidence_spec "$pack_dir"
  fi

  # Output
  if [ "$JSON_OUTPUT" = true ]; then
    output_json "$pack_dir"
  else
    output_summary "$pack_dir"
  fi

  # Exit code
  if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
  fi
  exit 0
}

main "$@"
