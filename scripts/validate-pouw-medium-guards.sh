#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
POUW_DIR="$ROOT/x/pouw/keeper"
OVERRIDE_FILE="$POUW_DIR/consensus_testing_override_nonprod.go"
STAKING_FILE="$POUW_DIR/staking.go"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

search_go() {
  local pattern="$1"
  if command -v rg >/dev/null 2>&1; then
    rg -n "$pattern" "$POUW_DIR" -g'*.go'
  else
    grep -R -n --include='*.go' -E "$pattern" "$POUW_DIR"
  fi
}

has_match() {
  local pattern="$1"
  local file="$2"
  if command -v rg >/dev/null 2>&1; then
    rg -q "$pattern" "$file"
  else
    grep -Eq "$pattern" "$file"
  fi
}

[[ -f "$OVERRIDE_FILE" ]] || fail "missing $OVERRIDE_FILE"
[[ -f "$STAKING_FILE" ]] || fail "missing $STAKING_FILE"

grep -q '^//go:build !production$' "$OVERRIDE_FILE" || fail "M-08 guard missing !production build tag"

# The testing-only threshold override must not appear in non-test production files.
while IFS= read -r line; do
  case "$line" in
    *"consensus_testing_override_nonprod.go:"*|*"_test.go:"*)
      ;;
    *)
      fail "M-08 guard violated: SetConsensusThresholdForTesting found outside test/nonprod override: $line"
      ;;
  esac
done < <(search_go 'SetConsensusThresholdForTesting')

# M-05: deterministic + entropy-salted tie-break path must remain in production selection logic.
has_match 'selectionSeed := vs\.selectionEntropySeed' "$STAKING_FILE" \
  || fail "M-05 guard missing selectionEntropySeed tie-break seeding"
has_match 'selectionTieBreaker\(selectionSeed, candidate\.Address\)' "$STAKING_FILE" \
  || fail "M-05 guard missing per-validator entropy tie-breaker"
has_match 'bytes\.Compare\(ib\[:\], jb\[:\]\)' "$STAKING_FILE" \
  || fail "M-05 guard missing deterministic tie-break comparison"
has_match 'return candidates\[i\]\.Address < candidates\[j\]\.Address' "$STAKING_FILE" \
  || fail "M-05 guard missing final deterministic fallback"

echo "PoUW medium guards OK (M-05, M-08)"
