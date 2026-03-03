#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "[1/6] sdk-release-check"
make sdk-release-check

echo "[2/6] Python build/twine check"
python3 -m pip install --upgrade pip build twine
rm -rf sdk/python/dist
python3 -m build ./sdk/python
python3 -m twine check ./sdk/python/dist/*

echo "[3/6] TypeScript install/build/pack"
(
  cd sdk/typescript
  rm -rf node_modules
  npm install
  npm run build
  npm pack
)

echo "[4/6] Rust package verify"
cargo package --manifest-path ./sdk/rust/Cargo.toml --allow-dirty

echo "[5/6] Go SDK tests"
(
  cd sdk/go
  GOCACHE="$(pwd)/.cache/go-build" go test ./...
)

echo "[6/6] Tag validation smoke checks"
python3 scripts/validate_sdk_release_tag.py --tag "sdk-python-v1.0.0" >/dev/null
python3 scripts/validate_sdk_release_tag.py --tag "sdk-typescript-v1.0.0" >/dev/null
python3 scripts/validate_sdk_release_tag.py --tag "sdk-rust-v1.0.0" >/dev/null
python3 scripts/validate_sdk_release_tag.py --tag "sdk-go-v2.0.0" >/dev/null

echo "SDK publish dry-run completed successfully."
