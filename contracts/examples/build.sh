#!/usr/bin/env bash
#
# contracts/examples/build.sh — deterministic build of the reference contracts.
#
# Pinned toolchain: solc 0.8.20, optimizer on (200 runs), EVM target shanghai.
# Output artifacts (bin + abi) are committed so tests execute the exact
# reviewed bytecode without requiring solc on the test machine.
set -euo pipefail

cd "$(dirname "$0")"

SOLC="${SOLC:-solc}"
EXPECTED_VERSION="0.8.20"

version=$("$SOLC" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
if [ "$version" != "$EXPECTED_VERSION" ]; then
  echo "ERROR: solc $EXPECTED_VERSION required, found $version" >&2
  exit 1
fi

mkdir -p artifacts

"$SOLC" \
  --optimize --optimize-runs 200 \
  --evm-version shanghai \
  --bin --abi \
  --overwrite \
  --base-path ../.. \
  -o artifacts \
  AIGatedVault.sol

echo "artifacts:"
ls -la artifacts/AIGatedVault.*
shasum -a 256 artifacts/AIGatedVault.bin
