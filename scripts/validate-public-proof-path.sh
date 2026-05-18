#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_DIR="$ROOT_DIR/docs/demo/public-proof-path"
WORK_DIR="${AETHELRED_PROOF_VALIDATE_DIR:-$(mktemp -d)}"

cleanup() {
  if [[ -z "${AETHELRED_PROOF_VALIDATE_DIR:-}" ]]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

cd "$DEMO_DIR"

npm test

node src/cli.mjs list-scenarios >/dev/null

for scenario in finance healthcare carbon external-finance; do
  scenario_dir="$WORK_DIR/$scenario"
  mkdir -p "$scenario_dir"
  node src/cli.mjs run --scenario="$scenario" --output-dir="$scenario_dir" >/dev/null
  node src/cli.mjs verify --output-dir="$scenario_dir" >/dev/null
  node src/cli.mjs regulator-pack --output-dir="$scenario_dir" >/dev/null
  node src/cli.mjs anchor --output-dir="$scenario_dir" >/dev/null
  node src/cli.mjs external-report --output-dir="$scenario_dir" >/dev/null
  node src/cli.mjs redaction-manifest --output-dir="$scenario_dir" >/dev/null
  node src/cli.mjs verifier-onboarding --output-dir="$scenario_dir" >/dev/null
  node src/cli.mjs procurement-pack --output-dir="$scenario_dir" >/dev/null
  node src/cli.mjs sovereign-scorecard --output-dir="$scenario_dir" >/dev/null
done

echo "Aethelred public proof path validation passed."
