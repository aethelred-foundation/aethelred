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
    SRC_DIR="$ROOT_DIR/sdk/typescript"
    TEMPLATE_WORKFLOW="$ROOT_DIR/sdk/repo-templates/typescript-sdk-ci.yml"
    DEFAULT_OUT="/tmp/aethelred-sdk-js"
    ;;
  rust)
    SRC_DIR="$ROOT_DIR/sdk/rust"
    TEMPLATE_WORKFLOW="$ROOT_DIR/sdk/repo-templates/rust-sdk-ci.yml"
    DEFAULT_OUT="/tmp/aethelred-sdk-rust"
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

mkdir -p "$OUT_DIR"

rsync -a --delete \
  --exclude '.git' \
  --exclude 'node_modules' \
  --exclude 'dist' \
  --exclude 'target' \
  --exclude '.pytest_cache' \
  --exclude '__pycache__' \
  "$SRC_DIR"/ "$OUT_DIR"/

mkdir -p "$OUT_DIR/.github/workflows"
cp "$TEMPLATE_WORKFLOW" "$OUT_DIR/.github/workflows/ci.yml"

cat > "$OUT_DIR/REPO_SPLIT_ORIGIN.md" <<EOF
# Exported from AethelredMVP Monorepo

- Source path: \`$SRC_DIR\`
- Exported by: \`scripts/export-sdk-standalone-repo.sh\`

This directory is a standalone-repo export intended to be pushed to a dedicated GitHub repository.
EOF

echo "Exported $SDK_KIND SDK to: $OUT_DIR"
