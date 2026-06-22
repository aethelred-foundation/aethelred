#!/usr/bin/env bash
# Prepare local M42 pilot evidence directories and run pre-testnet validation.
#
# Environment overrides:
#   M42_EVIDENCE_PATH          Local evidence directory
#   M42_ARCHIVE_DEST           Archive endpoint to report as a preflight gate
#   M42_ALERTMANAGER_ENDPOINT  Alertmanager endpoint to report as a preflight gate
#   M42_ALERTMANAGER           Backward-compatible alias for M42_ALERTMANAGER_ENDPOINT
#   M42_PROMETHEUS_ENDPOINT    Prometheus endpoint to report as a preflight gate
#   M42_PILOT_NAME             Pilot name in the validation report
#   M42_WORKLOAD_PACK          Optional workload pack JSON path
#   M42_REGISTRY_DIR           Optional model/circuit registry directory
#   M42_MODEL_HASH             Optional expected pilot model hash
#   M42_CIRCUIT_HASH           Optional expected pilot circuit hash
#   M42_SKIP_DOC_PACK_VALIDATION=true to skip docs/workload-packs validation

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

EVIDENCE_PATH="${M42_EVIDENCE_PATH:-$ROOT_DIR/config/pilots/m42/evidence}"
ARCHIVE_DEST="${M42_ARCHIVE_DEST:-localhost:19200}"
ALERTMANAGER_ENDPOINT="${M42_ALERTMANAGER_ENDPOINT:-${M42_ALERTMANAGER:-localhost:19093}}"
PROMETHEUS_ENDPOINT="${M42_PROMETHEUS_ENDPOINT:-localhost:19090}"
PILOT_NAME="${M42_PILOT_NAME:-m42-med42-synthetic-eval}"
WORKLOAD_PACK="${M42_WORKLOAD_PACK:-$ROOT_DIR/config/pilots/m42/workload-pack.json}"
REGISTRY_DIR="${M42_REGISTRY_DIR:-$ROOT_DIR/config/pilots/m42/registry}"
REPORT_PATH="${M42_VALIDATION_REPORT:-$ROOT_DIR/.cache/m42-pilot-evidence/exports/m42-pretestnet-validation.json}"
DOC_PACK_DIR="$ROOT_DIR/docs/workload-packs/m42"

read_workload_pack_value() {
    local expression="$1"
    if [[ -f "$WORKLOAD_PACK" ]] && command -v jq >/dev/null 2>&1; then
        jq -r "$expression // empty" "$WORKLOAD_PACK" 2>/dev/null || true
    fi
}

MODEL_HASH="${M42_MODEL_HASH:-$(read_workload_pack_value '.model.hash // .model.measurement_hash')}"
CIRCUIT_HASH="${M42_CIRCUIT_HASH:-$(read_workload_pack_value '.circuit.hash // .circuit.circuit_hash')}"

if [[ -z "$MODEL_HASH" || -z "$CIRCUIT_HASH" ]]; then
    echo "ERROR: Could not resolve M42 model/circuit hashes from $WORKLOAD_PACK. Install jq or set M42_MODEL_HASH and M42_CIRCUIT_HASH." >&2
    exit 2
fi

mkdir -p \
    "$EVIDENCE_PATH/attestations" \
    "$EVIDENCE_PATH/proofs" \
    "$EVIDENCE_PATH/exports" \
    "$EVIDENCE_PATH/archives" \
    "$(dirname "$REPORT_PATH")"

if [[ "${M42_SKIP_DOC_PACK_VALIDATION:-false}" != "true" ]]; then
    echo "Validating M42 workload documentation pack: $DOC_PACK_DIR" >&2
    bash "$ROOT_DIR/scripts/validate-workload-pack.sh" "$DOC_PACK_DIR" --check-evidence >&2
fi

echo "Prepared M42 local evidence directory: $EVIDENCE_PATH" >&2
echo "Writing validation report to: $REPORT_PATH" >&2

exec bash "$ROOT_DIR/scripts/validate-pilot-deployment.sh" \
    --pre-testnet \
    --skip-enterprise \
    --pilot-name "$PILOT_NAME" \
    --evidence-path "$EVIDENCE_PATH" \
    --archive-dest "$ARCHIVE_DEST" \
    --alertmanager "$ALERTMANAGER_ENDPOINT" \
    --prometheus "$PROMETHEUS_ENDPOINT" \
    --workload-pack "$WORKLOAD_PACK" \
    --model-hash "$MODEL_HASH" \
    --circuit-hash "$CIRCUIT_HASH" \
    --registry-dir "$REGISTRY_DIR" \
    --output "$REPORT_PATH" \
    "$@"
