#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:-.}"
BUDGET="${NITRO_SDK_WARNING_BUDGET:-0}"

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

LOG_FILE="$(mktemp -t nitro-sdk-warning-budget.XXXXXX.log)"
trap 'rm -f "$LOG_FILE"' EXIT

echo "Running cargo check for nitro-sdk (full-sdk) with warning budget <= ${BUDGET}"

set +e
cargo check --manifest-path "$MANIFEST_PATH" --features full-sdk 2>&1 | tee "$LOG_FILE"
CARGO_EXIT=${PIPESTATUS[0]}
set -e

if [[ "$CARGO_EXIT" -ne 0 ]]; then
  echo "cargo check failed (exit $CARGO_EXIT)" >&2
  exit "$CARGO_EXIT"
fi

SUMMARY_COUNT="$(
  grep -E "warning: .* generated [0-9]+ warnings?" "$LOG_FILE" \
    | tail -1 \
    | grep -Eo "[0-9]+" \
    | tail -1 || true
)"

if [[ -n "${SUMMARY_COUNT:-}" ]]; then
  WARNING_COUNT="$SUMMARY_COUNT"
else
  # When summary parsing fails, count raw warning lines and subtract the cargo summary line if present.
  WARNING_COUNT="$(grep -Ec '^warning:' "$LOG_FILE" || true)"
  if grep -Eq '^warning: `.*` \(lib\) generated [0-9]+ warnings?$' "$LOG_FILE"; then
    WARNING_COUNT=$(( WARNING_COUNT - 1 ))
  fi
fi

echo "nitro-sdk full-sdk warning count: ${WARNING_COUNT}"
echo "nitro-sdk full-sdk warning budget: ${BUDGET}"

if (( WARNING_COUNT > BUDGET )); then
  echo "Warning budget exceeded: ${WARNING_COUNT} > ${BUDGET}" >&2
  exit 1
fi

echo "Warning budget check passed."
