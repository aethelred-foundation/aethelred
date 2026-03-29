#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "==> GitHub auth"
if gh auth status >/tmp/aethelred-gh-auth-status.txt 2>&1; then
  cat /tmp/aethelred-gh-auth-status.txt
else
  cat /tmp/aethelred-gh-auth-status.txt
  echo "warning: gh auth status did not validate in script context; verify manually before push."
fi

echo
echo "==> Workflow YAML parse"
python3 - <<'PY'
from pathlib import Path
import sys
import yaml

root = Path(".github/workflows")
errors = []
for path in sorted(root.glob("*.yml")):
    try:
        yaml.safe_load(path.read_text())
    except Exception as exc:
        errors.append((str(path), str(exc)))

if errors:
    for path, exc in errors:
        print(f"{path}: {exc}")
    sys.exit(1)

print("all workflow yaml parsed")
PY

echo
echo "==> Canonical truth"
python3 scripts/validate_canonical_product_truth.py

echo
echo "==> Go validation"
go test ./app/... -count=1
go test ./x/pouw/keeper/... -count=1
go test ./x/verify/... -count=1
go test ./x/seal/... -count=1

echo
echo "==> Rust VM validation"
cargo test --manifest-path crates/vm/Cargo.toml -p aethelred-vm --quiet

echo
echo "==> Git status (excluding historical cache path noise)"
git status --short --branch -- . ':(exclude).cache'
