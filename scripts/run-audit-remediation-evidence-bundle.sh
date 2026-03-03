#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-$(pwd)}"
STAMP="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="${AUDIT_EVIDENCE_LOG:-/tmp/aethelred-audit-remediation-evidence-${STAMP}.log}"

run_step() {
  local title="$1"
  local cwd="$2"
  shift 2

  echo "" | tee -a "$LOG_FILE"
  echo "===== ${title} =====" | tee -a "$LOG_FILE"
  echo "cwd: ${cwd}" | tee -a "$LOG_FILE"
  echo "cmd: $*" | tee -a "$LOG_FILE"
  (
    cd "$cwd"
    "$@"
  ) 2>&1 | tee -a "$LOG_FILE"
}

echo "Audit remediation evidence bundle starting at $(date -u +"%Y-%m-%dT%H:%M:%SZ")" | tee "$LOG_FILE"
echo "root: $ROOT" | tee -a "$LOG_FILE"

run_step "Contracts regressions (critical/high/medium + ISB/automation)" \
  "$ROOT/contracts" \
  npm test -- \
    test/bridge.emergency.test.ts \
    test/vesting.critical.test.ts \
    test/high.findings.regression.test.ts \
    test/medium.findings.regression.test.ts \
    test/institutional.stablecoin.integration.test.ts \
    test/institutional.reserve.automation.keeper.test.ts

run_step "TypeScript SDK security regressions" \
  "$ROOT/sdk/typescript" \
  npx vitest run \
    src/crypto/pqc.test.ts \
    src/crypto/tee.test.ts \
    src/core/client.test.ts \
    --config vitest.config.ts

run_step "Validator keeper regressions (M-04)" \
  "$ROOT" \
  go test ./x/validator/keeper

run_step "Compose security guard (C-06/H-12)" \
  "$ROOT" \
  bash ./scripts/validate-compose-security.sh .

run_step "PoUW medium guards (M-05/M-08)" \
  "$ROOT" \
  bash ./scripts/validate-pouw-medium-guards.sh .

run_step "Low findings guards (L-01..L-08 static/hygiene)" \
  "$ROOT" \
  bash ./scripts/validate-low-findings-guards.sh .

run_step "Devnet genesis guards (M-09/M-10)" \
  "$ROOT" \
  python3 ./scripts/validate-devnet-genesis.py ./tools/devnet/genesis.json

run_step "Rust attestation engine regression (M-07) header parsing" \
  "$ROOT" \
  cargo test \
    --manifest-path "$ROOT/services/tee-worker/nitro-sdk/Cargo.toml" \
    --features attestation-evidence \
    --lib \
    attestation::engine::tests::test_quote_type_detection_uses_intel_header_fields \
    -- --exact

run_step "Rust attestation engine regression (M-07) Nitro detection" \
  "$ROOT" \
  cargo test \
    --manifest-path "$ROOT/services/tee-worker/nitro-sdk/Cargo.toml" \
    --features attestation-evidence \
    --lib \
    attestation::engine::tests::test_nitro_detection_requires_cose_and_nitro_markers \
    -- --exact

run_step "Rust attestation engine regression (L-03) EPID generic error" \
  "$ROOT" \
  cargo test \
    --manifest-path "$ROOT/services/tee-worker/nitro-sdk/Cargo.toml" \
    --features attestation-evidence \
    --lib \
    attestation::engine::tests::test_epid_quotes_return_generic_unsupported_format_error \
    -- --exact

echo "" | tee -a "$LOG_FILE"
echo "Audit remediation evidence bundle completed successfully." | tee -a "$LOG_FILE"
echo "Log: $LOG_FILE" | tee -a "$LOG_FILE"
