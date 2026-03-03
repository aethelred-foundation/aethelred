#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/reports/benchmarks"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
GO_BIN="${GO_BIN:-go}"

mkdir -p "${OUT_DIR}"

echo "Running benchmarks..."
${GO_BIN} test -run=^$ -bench=. -benchmem ./x/pouw/... ./x/verify/... | tee "${OUT_DIR}/bench-${TS}.txt"

echo "Benchmark report written to ${OUT_DIR}/bench-${TS}.txt"
