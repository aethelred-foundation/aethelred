#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:-.}"
BUDGET="${NITRO_SDK_ATTESTATION_EVIDENCE_WARNING_BUDGET:-0}"

if [[ "${2:-}" == "--budget" ]]; then
  if [[ -z "${3:-}" ]]; then
    echo "usage: $0 [root_dir] [--budget <count>]" >&2
    exit 2
  fi
  BUDGET="$3"
fi

if [[ -f "${ROOT_DIR%/}/nitro-sdk/Cargo.toml" ]]; then
  MANIFEST_PATH="${ROOT_DIR%/}/nitro-sdk/Cargo.toml"
else
  MANIFEST_PATH="${ROOT_DIR%/}/services/tee-worker/nitro-sdk/Cargo.toml"
fi

if [[ ! -f "$MANIFEST_PATH" ]]; then
  echo "nitro-sdk Cargo.toml not found at: $MANIFEST_PATH" >&2
  exit 2
fi

LOG_FILE="$(mktemp -t nitro-sdk-attestation-evidence-warning-budget.XXXXXX.log)"
trap 'rm -f "$LOG_FILE"' EXIT

echo "Running cargo test --no-run for nitro-sdk (attestation-evidence) with warning budget <= ${BUDGET}"

set +e
cargo test --manifest-path "$MANIFEST_PATH" --features attestation-evidence --lib --no-run 2>&1 | tee "$LOG_FILE"
CARGO_EXIT=${PIPESTATUS[0]}
set -e

if [[ "$CARGO_EXIT" -ne 0 ]]; then
  echo "cargo test --no-run failed (exit $CARGO_EXIT)" >&2
  exit "$CARGO_EXIT"
fi

SUMMARY_COUNT="$(
  grep -E "warning: .* generated [0-9]+ warnings" "$LOG_FILE" \
    | tail -1 \
    | grep -Eo "[0-9]+" \
    | tail -1 || true
)"

if [[ -n "${SUMMARY_COUNT:-}" ]]; then
  WARNING_COUNT="$SUMMARY_COUNT"
else
  # When there are zero warnings, cargo often emits no summary line.
  WARNING_COUNT="$(grep -Ec '^warning:' "$LOG_FILE" || true)"
fi

echo "nitro-sdk attestation-evidence warning count: ${WARNING_COUNT}"
echo "nitro-sdk attestation-evidence warning budget: ${BUDGET}"

if (( WARNING_COUNT > BUDGET )); then
  echo "Warning budget exceeded: ${WARNING_COUNT} > ${BUDGET}" >&2
  exit 1
fi

echo "Attestation-evidence warning budget check passed."
