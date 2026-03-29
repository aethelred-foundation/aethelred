#!/usr/bin/env bash
# ============================================================================
# SQ20 - Observability/HSM: HSM Preflight Validation
# ============================================================================
# Validates HSM connectivity, key availability, signing capability, and
# signer failover path before a validator node starts signing blocks.
#
# Usage:
#   chmod +x scripts/hsm/preflight-check.sh
#   ./scripts/hsm/preflight-check.sh [--failover]
#
# Environment variables:
#   HSM_TYPE          HSM type: softhsm|thales|yubihsm|aws-cloudhsm (default: softhsm)
#   HSM_MODULE_PATH   Path to PKCS#11 module library
#   HSM_SLOT          HSM slot number (default: 0)
#   HSM_PIN           HSM user PIN (or path to PIN file prefixed with @)
#   HSM_KEY_LABEL     Consensus signing key label (default: aethelred-consensus)
#   FAILOVER_HSM_MODULE_PATH   Failover HSM PKCS#11 module path
#   FAILOVER_HSM_SLOT          Failover HSM slot
#   FAILOVER_HSM_PIN           Failover HSM PIN
#
# Prerequisites:
#   - pkcs11-tool (from opensc package)
#   - openssl (for signature verification)
# ============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HSM_TYPE="${HSM_TYPE:-softhsm}"
HSM_SLOT="${HSM_SLOT:-0}"
HSM_PIN="${HSM_PIN:-}"
HSM_KEY_LABEL="${HSM_KEY_LABEL:-aethelred-consensus}"
HSM_KEY_LABEL_PQC="${HSM_KEY_LABEL_PQC:-aethelred-dilithium3}"

FAILOVER_ENABLED=false
[[ "${1:-}" == "--failover" ]] && FAILOVER_ENABLED=true

# Default PKCS#11 module paths per HSM type
case "$HSM_TYPE" in
  softhsm)
    HSM_MODULE_PATH="${HSM_MODULE_PATH:-/usr/lib/softhsm/libsofthsm2.so}"
    ;;
  thales)
    HSM_MODULE_PATH="${HSM_MODULE_PATH:-/usr/lib/libluna.so}"
    ;;
  yubihsm)
    HSM_MODULE_PATH="${HSM_MODULE_PATH:-/usr/lib/pkcs11/yubihsm_pkcs11.so}"
    ;;
  aws-cloudhsm)
    HSM_MODULE_PATH="${HSM_MODULE_PATH:-/opt/cloudhsm/lib/libcloudhsm_pkcs11.so}"
    ;;
  *)
    HSM_MODULE_PATH="${HSM_MODULE_PATH:-/usr/lib/softhsm/libsofthsm2.so}"
    ;;
esac

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNINGS=0
RESULTS=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf "[%s] %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

record_pass() {
  local check="$1" detail="${2:-}"
  TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
  PASSED_CHECKS=$((PASSED_CHECKS + 1))
  RESULTS+=("PASS|${check}|${detail}")
  log "  PASS: ${check} ${detail:+- ${detail}}"
}

record_fail() {
  local check="$1" detail="${2:-}"
  TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
  FAILED_CHECKS=$((FAILED_CHECKS + 1))
  RESULTS+=("FAIL|${check}|${detail}")
  log "  FAIL: ${check} ${detail:+- ${detail}}"
}

record_warn() {
  local check="$1" detail="${2:-}"
  WARNINGS=$((WARNINGS + 1))
  RESULTS+=("WARN|${check}|${detail}")
  log "  WARN: ${check} ${detail:+- ${detail}}"
}

pkcs11_tool() {
  local pin_args=()
  if [[ -n "$HSM_PIN" ]]; then
    if [[ "$HSM_PIN" == @* ]]; then
      pin_args=(--pin "$(cat "${HSM_PIN#@}")")
    else
      pin_args=(--pin "$HSM_PIN")
    fi
  fi
  pkcs11-tool --module "$HSM_MODULE_PATH" --slot "$HSM_SLOT" "${pin_args[@]}" "$@" 2>&1
}

# ---------------------------------------------------------------------------
# Check: Prerequisites
# ---------------------------------------------------------------------------
check_prerequisites() {
  log "--- Checking prerequisites ---"

  if command -v pkcs11-tool >/dev/null 2>&1; then
    record_pass "pkcs11-tool available" "$(pkcs11-tool --version 2>&1 | head -1)"
  else
    record_fail "pkcs11-tool available" "Install opensc: apt install opensc / brew install opensc"
    return 1
  fi

  if command -v openssl >/dev/null 2>&1; then
    record_pass "openssl available" "$(openssl version 2>&1)"
  else
    record_fail "openssl available" "openssl not found in PATH"
  fi

  if [[ -f "$HSM_MODULE_PATH" ]]; then
    record_pass "PKCS#11 module exists" "$HSM_MODULE_PATH"
  else
    record_fail "PKCS#11 module exists" "Not found: $HSM_MODULE_PATH"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Check: HSM Connectivity
# ---------------------------------------------------------------------------
check_connectivity() {
  log "--- Checking HSM connectivity ---"

  local slot_info
  if slot_info=$(pkcs11_tool --list-slots 2>&1); then
    if echo "$slot_info" | grep -q "Slot ${HSM_SLOT}"; then
      record_pass "HSM slot ${HSM_SLOT} accessible"
    else
      record_fail "HSM slot ${HSM_SLOT} accessible" "Slot not found in output"
      return 1
    fi
  else
    record_fail "HSM connectivity" "pkcs11-tool --list-slots failed"
    return 1
  fi

  # Check token info
  local token_info
  if token_info=$(pkcs11_tool --list-token-slots 2>&1); then
    record_pass "HSM token enumeration" "$(echo "$token_info" | grep -c 'token label' || echo 0) token(s) found"
  else
    record_warn "HSM token enumeration" "Could not list token slots"
  fi
}

# ---------------------------------------------------------------------------
# Check: Key Availability
# ---------------------------------------------------------------------------
check_key_availability() {
  log "--- Checking key availability ---"

  local objects
  if objects=$(pkcs11_tool --list-objects --type privkey 2>&1); then
    # Check consensus signing key (ECDSA)
    if echo "$objects" | grep -q "$HSM_KEY_LABEL"; then
      record_pass "Consensus key present" "label=${HSM_KEY_LABEL}"
    else
      record_fail "Consensus key present" "Key '${HSM_KEY_LABEL}' not found"
    fi

    # Check PQC key (Dilithium3) if label is configured
    if [[ -n "$HSM_KEY_LABEL_PQC" ]]; then
      if echo "$objects" | grep -q "$HSM_KEY_LABEL_PQC"; then
        record_pass "PQC (Dilithium3) key present" "label=${HSM_KEY_LABEL_PQC}"
      else
        record_warn "PQC (Dilithium3) key present" "Key '${HSM_KEY_LABEL_PQC}' not found (PQC optional for testnet)"
      fi
    fi
  else
    record_fail "Key enumeration" "Could not list private keys"
  fi

  # Check public keys
  if pkcs11_tool --list-objects --type pubkey 2>&1 | grep -q "$HSM_KEY_LABEL"; then
    record_pass "Consensus public key present" "label=${HSM_KEY_LABEL}"
  else
    record_warn "Consensus public key present" "Public key not separately stored (may be embedded in cert)"
  fi
}

# ---------------------------------------------------------------------------
# Check: Signing Capability
# ---------------------------------------------------------------------------
check_signing_capability() {
  log "--- Checking signing capability ---"

  local test_data_file
  test_data_file=$(mktemp)
  local sig_file="${test_data_file}.sig"
  echo "aethelred-hsm-preflight-$(date +%s)" > "$test_data_file"

  # Attempt a test sign operation
  if pkcs11_tool --sign --label "$HSM_KEY_LABEL" \
       --mechanism ECDSA-SHA256 \
       --input-file "$test_data_file" \
       --output-file "$sig_file" 2>&1; then
    if [[ -f "$sig_file" && -s "$sig_file" ]]; then
      local sig_size
      sig_size=$(wc -c < "$sig_file" | tr -d ' ')
      record_pass "ECDSA signing test" "Produced ${sig_size}-byte signature"
    else
      record_fail "ECDSA signing test" "Signature file empty or missing"
    fi
  else
    record_fail "ECDSA signing test" "pkcs11-tool --sign failed"
  fi

  rm -f "$test_data_file" "$sig_file"
}

# ---------------------------------------------------------------------------
# Check: Signer Failover
# ---------------------------------------------------------------------------
check_failover() {
  log "--- Checking signer failover path ---"

  if [[ "$FAILOVER_ENABLED" != "true" ]]; then
    record_warn "Failover test" "Skipped (run with --failover to test)"
    return 0
  fi

  local ORIG_MODULE="$HSM_MODULE_PATH"
  local ORIG_SLOT="$HSM_SLOT"
  local ORIG_PIN="$HSM_PIN"

  # Switch to failover HSM
  HSM_MODULE_PATH="${FAILOVER_HSM_MODULE_PATH:-$HSM_MODULE_PATH}"
  HSM_SLOT="${FAILOVER_HSM_SLOT:-$HSM_SLOT}"
  HSM_PIN="${FAILOVER_HSM_PIN:-$HSM_PIN}"

  if [[ "$HSM_MODULE_PATH" == "$ORIG_MODULE" && "$HSM_SLOT" == "$ORIG_SLOT" ]]; then
    record_warn "Failover HSM distinct" "Failover config is identical to primary"
  fi

  if [[ ! -f "$HSM_MODULE_PATH" ]]; then
    record_fail "Failover PKCS#11 module exists" "Not found: $HSM_MODULE_PATH"
    HSM_MODULE_PATH="$ORIG_MODULE"
    HSM_SLOT="$ORIG_SLOT"
    HSM_PIN="$ORIG_PIN"
    return 1
  fi

  # Test connectivity to failover
  if pkcs11_tool --list-slots 2>&1 | grep -q "Slot ${HSM_SLOT}"; then
    record_pass "Failover HSM connectivity" "Slot ${HSM_SLOT} accessible"
  else
    record_fail "Failover HSM connectivity" "Cannot reach failover HSM"
  fi

  # Test key availability on failover
  if pkcs11_tool --list-objects --type privkey 2>&1 | grep -q "$HSM_KEY_LABEL"; then
    record_pass "Failover consensus key present" "label=${HSM_KEY_LABEL}"
  else
    record_fail "Failover consensus key present" "Key not found on failover HSM"
  fi

  # Restore original
  HSM_MODULE_PATH="$ORIG_MODULE"
  HSM_SLOT="$ORIG_SLOT"
  HSM_PIN="$ORIG_PIN"
}

# ---------------------------------------------------------------------------
# Check: Firmware Version Compatibility
# ---------------------------------------------------------------------------
# Minimum firmware versions known to support all required mechanisms
MINIMUM_FW_VERSIONS="softhsm:2.6|thales:7.3|yubihsm:2.3|aws-cloudhsm:3.4"

check_firmware_version() {
  log "--- Checking firmware version compatibility ---"

  local fw_info
  fw_info=$(pkcs11_tool --list-slots 2>&1 || true)

  # Extract firmware version from slot info
  local fw_version=""
  fw_version=$(echo "$fw_info" | grep -i "firmware version" | head -1 | sed 's/.*firmware version:[[:space:]]*//' | tr -d '[:space:]')

  if [[ -z "$fw_version" ]]; then
    # Try alternate extraction from token info
    fw_version=$(pkcs11_tool --list-token-slots 2>&1 | grep -i "firmware" | head -1 | sed 's/.*:[[:space:]]*//' | tr -d '[:space:]')
  fi

  if [[ -z "$fw_version" ]]; then
    record_warn "Firmware version" "Could not determine firmware version from PKCS#11 info"
    return 0
  fi

  record_pass "Firmware version detected" "${HSM_TYPE} firmware ${fw_version}"

  # Extract minimum version for this HSM type
  local min_version=""
  min_version=$(echo "$MINIMUM_FW_VERSIONS" | tr '|' '\n' | grep "^${HSM_TYPE}:" | cut -d: -f2)

  if [[ -z "$min_version" ]]; then
    record_warn "Firmware version check" "No minimum version defined for HSM type '${HSM_TYPE}'"
    return 0
  fi

  # Compare major.minor versions
  local fw_major fw_minor min_major min_minor
  fw_major=$(echo "$fw_version" | cut -d. -f1)
  fw_minor=$(echo "$fw_version" | cut -d. -f2)
  min_major=$(echo "$min_version" | cut -d. -f1)
  min_minor=$(echo "$min_version" | cut -d. -f2)

  if (( fw_major > min_major )) || (( fw_major == min_major && fw_minor >= min_minor )); then
    record_pass "Firmware version compatible" "${fw_version} >= ${min_version} (minimum for ${HSM_TYPE})"
  else
    record_fail "Firmware version compatible" "${fw_version} < ${min_version} (upgrade required for ${HSM_TYPE})"
  fi
}

# ---------------------------------------------------------------------------
# Check: Key Backup Status
# ---------------------------------------------------------------------------
check_key_backup_status() {
  log "--- Checking key backup status ---"

  # Check if key is marked as extractable (should NOT be for production HSMs)
  local key_attrs
  key_attrs=$(pkcs11_tool --list-objects --type privkey 2>&1 || true)

  if echo "$key_attrs" | grep -q "$HSM_KEY_LABEL"; then
    # Check CKA_EXTRACTABLE attribute -- production keys must be non-extractable
    if echo "$key_attrs" | grep -A5 "$HSM_KEY_LABEL" | grep -qi "extractable.*true\|CKA_EXTRACTABLE.*true"; then
      record_warn "Key extractable flag" "Consensus key is extractable -- should be non-extractable in production"
    else
      record_pass "Key extractable flag" "Consensus key is non-extractable (correct for production)"
    fi

    # Check CKA_SENSITIVE attribute -- must be true for production
    if echo "$key_attrs" | grep -A5 "$HSM_KEY_LABEL" | grep -qi "sensitive.*true\|CKA_SENSITIVE.*true"; then
      record_pass "Key sensitive flag" "Consensus key is marked sensitive"
    else
      record_warn "Key sensitive flag" "Could not verify CKA_SENSITIVE attribute"
    fi
  else
    record_warn "Key backup status" "Cannot check attributes -- consensus key not found"
    return 0
  fi

  # Check for backup token/slot if configured
  local backup_slot="${HSM_BACKUP_SLOT:-}"
  if [[ -n "$backup_slot" ]]; then
    local backup_check
    backup_check=$(pkcs11-tool --module "$HSM_MODULE_PATH" --slot "$backup_slot" \
      --list-objects --type privkey 2>&1 || true)
    if echo "$backup_check" | grep -q "$HSM_KEY_LABEL"; then
      record_pass "Key backup present" "Backup key found on slot ${backup_slot}"
    else
      record_fail "Key backup present" "Backup key NOT found on slot ${backup_slot}"
    fi
  else
    record_warn "Key backup slot" "HSM_BACKUP_SLOT not configured -- backup verification skipped"
  fi

  # Check if wrapping key exists (for key export/backup ceremonies)
  local wrap_key
  wrap_key=$(pkcs11_tool --list-objects --type privkey 2>&1 | grep -c "aethelred-wrap" || echo "0")
  if (( wrap_key > 0 )); then
    record_pass "Wrapping key present" "Key backup ceremony wrapping key found"
  else
    record_warn "Wrapping key present" "No wrapping key found (needed for key backup ceremonies)"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
log "=== HSM Preflight Validation ==="
log "HSM type       : ${HSM_TYPE}"
log "PKCS#11 module : ${HSM_MODULE_PATH}"
log "Slot           : ${HSM_SLOT}"
log "Key label      : ${HSM_KEY_LABEL}"
log "Failover test  : ${FAILOVER_ENABLED}"
log ""

check_prerequisites || true
check_connectivity || true
check_key_availability || true
check_signing_capability || true
check_failover || true
check_firmware_version || true
check_key_backup_status || true

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
log ""
log "=== HSM Preflight Report ==="
log "Total checks  : ${TOTAL_CHECKS}"
log "Passed        : ${PASSED_CHECKS}"
log "Failed        : ${FAILED_CHECKS}"
log "Warnings      : ${WARNINGS}"
log ""

for result in "${RESULTS[@]}"; do
  IFS='|' read -r status check detail <<< "$result"
  printf "  [%-4s] %-40s %s\n" "$status" "$check" "$detail"
done

log ""

if (( FAILED_CHECKS > 0 )); then
  log "RESULT: FAIL - ${FAILED_CHECKS} preflight check(s) failed. Do NOT start the validator."
  exit 1
elif (( WARNINGS > 0 )); then
  log "RESULT: WARN - All critical checks passed but ${WARNINGS} warning(s) noted."
  exit 0
else
  log "RESULT: PASS - All preflight checks passed. Validator is cleared to start."
  exit 0
fi
