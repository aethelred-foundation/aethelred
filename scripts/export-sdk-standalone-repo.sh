#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'USAGE'
Usage:
  export-sdk-standalone-repo.sh <typescript|rust> [output-dir]

Examples:
  ./scripts/export-sdk-standalone-repo.sh typescript /tmp/aethelred-sdk-js
  ./scripts/export-sdk-standalone-repo.sh rust /tmp/aethelred-sdk-rust
USAGE
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 1
fi

SDK_KIND="$1"
OUT_DIR="${2:-}"

case "$SDK_KIND" in
  typescript)
    REPO_NAME="aethelred-sdk-ts"
    DEFAULT_OUT="/tmp/aethelred-sdk-ts"
    ;;
  rust)
    REPO_NAME="aethelred-sdk-rs"
    DEFAULT_OUT="/tmp/aethelred-sdk-rs"
    ;;
  *)
    echo "Unsupported SDK kind: $SDK_KIND" >&2
    usage
    exit 1
    ;;
esac

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="$DEFAULT_OUT"
fi

exec bash "$ROOT_DIR/scripts/export-public-repo.sh" "$REPO_NAME" "$OUT_DIR"
