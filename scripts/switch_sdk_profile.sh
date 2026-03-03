#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<USAGE
Usage: scripts/switch_sdk_profile.sh <offline|minimal|full-online> [--vendor] [--validate]

Modes:
  offline|minimal  Restore strict offline SDK manifests.
  full-online      Restore full online SDK manifests.

Options:
  --vendor         Rebuild vendor/ using current manifests (requires network).
  --validate       Run cargo check for SDK crates after switching.
USAGE
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

MODE="$1"
shift

DO_VENDOR=0
DO_VALIDATE=0

for arg in "$@"; do
  case "$arg" in
    --vendor) DO_VENDOR=1 ;;
    --validate) DO_VALIDATE=1 ;;
    *)
      echo "Unknown option: $arg" >&2
      usage
      exit 1
      ;;
  esac
done

copy_manifest() {
  local src="$1"
  local dst="$2"
  cp "$src" "$dst"
  echo "Updated: $dst"
}

case "$MODE" in
  offline|minimal)
    copy_manifest "$ROOT_DIR/sdk/aethelred-sdk/Cargo.offline.toml" "$ROOT_DIR/sdk/aethelred-sdk/Cargo.toml"
    copy_manifest "$ROOT_DIR/sdk/aethelred-py/Cargo.offline.toml" "$ROOT_DIR/sdk/aethelred-py/Cargo.toml"
    ;;
  full-online)
    copy_manifest "$ROOT_DIR/sdk/aethelred-sdk/Cargo.full-online.toml" "$ROOT_DIR/sdk/aethelred-sdk/Cargo.toml"
    copy_manifest "$ROOT_DIR/sdk/aethelred-py/Cargo.full-online.toml" "$ROOT_DIR/sdk/aethelred-py/Cargo.toml"
    ;;
  *)
    echo "Unknown mode: $MODE" >&2
    usage
    exit 1
    ;;
esac

if [[ "$DO_VENDOR" -eq 1 ]]; then
  echo "Rebuilding vendor/ (network required)..."
  cargo vendor --manifest-path "$ROOT_DIR/crates/core/Cargo.toml" \
    --sync "$ROOT_DIR/crates/consensus/Cargo.toml" \
    --sync "$ROOT_DIR/crates/mempool/Cargo.toml" \
    --sync "$ROOT_DIR/crates/bridge/Cargo.toml" \
    --sync "$ROOT_DIR/crates/demo/falcon-lion/Cargo.toml" \
    --sync "$ROOT_DIR/crates/demo/helix-guard/Cargo.toml" \
    --sync "$ROOT_DIR/crates/vm/Cargo.toml" \
    --sync "$ROOT_DIR/sdk/rust/Cargo.toml" \
    --sync "$ROOT_DIR/sdk/aethelred-sdk/Cargo.toml" \
    --sync "$ROOT_DIR/sdk/aethelred-py/Cargo.toml" \
    > "$ROOT_DIR/.cargo/vendor-config.generated.toml"
  echo "Vendor refresh complete."
fi

if [[ "$DO_VALIDATE" -eq 1 ]]; then
  echo "Running SDK checks..."
  (cd "$ROOT_DIR/sdk/aethelred-sdk" && cargo check)
  (cd "$ROOT_DIR/sdk/aethelred-py" && cargo check)
  echo "Validation complete."
fi
