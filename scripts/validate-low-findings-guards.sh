#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
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

list_has_match() {
  local pattern="$1"
  if command -v rg >/dev/null 2>&1; then
    rg -q "$pattern"
  else
    grep -Eq "$pattern"
  fi
}

require_line() {
  local pattern="$1"
  local file="$2"
  has_match "$pattern" "$file" || fail "missing pattern '$pattern' in $file"
}

require_fixed() {
  local text="$1"
  local file="$2"
  grep -Fq "$text" "$file" || fail "missing text '$text' in $file"
}

# L-01: quadratic burn critical path uses fixed-point integer math + saturating mul.
QB="$ROOT/crates/core/src/pillars/quadratic_burn.rs"
[[ -f "$QB" ]] || fail "missing $QB"
require_line 'const BURN_RATE_SCALE: u128' "$QB"
require_line 'fn burn_rate_to_fixed' "$QB"
require_line 'saturating_mul\(burn_rate_fixed\)' "$QB"
require_line '/ BURN_RATE_SCALE' "$QB"

# L-02: storage gaps present in upgradeable bridge contracts.
AB="$ROOT/contracts/contracts/AethelredBridge.sol"
ISB="$ROOT/contracts/contracts/InstitutionalStablecoinBridge.sol"
[[ -f "$AB" ]] || fail "missing $AB"
[[ -f "$ISB" ]] || fail "missing $ISB"
require_line 'uint256\[50\] private __gap;' "$AB"
require_line 'uint256\[50\] private __gap;' "$ISB"

# L-04: cosine similarity NaN/zero-denominator guard remains fail-closed.
VV="$ROOT/crates/core/src/pillars/vector_vault.rs"
[[ -f "$VV" ]] || fail "missing $VV"
require_line 'const EPSILON: f32' "$VV"
require_line '!denom\.is_finite\(\) \|\| denom <= EPSILON' "$VV"
require_line 'if score\.is_finite\(\)' "$VV"
require_line '0\.0' "$VV"

# L-03: generic unsupported attestation format error (avoid EPID-specific leak).
NITRO_ENGINE="$ROOT/services/tee-worker/nitro-sdk/src/attestation/engine.rs"
[[ -f "$NITRO_ENGINE" ]] || fail "missing $NITRO_ENGINE"
require_fixed 'Unsupported attestation quote format' "$NITRO_ENGINE"
if has_match '"[^"]*(Unsupported[^"]*EPID|EPID[^"]*unsupported)[^"]*"' "$NITRO_ENGINE"; then
  fail "L-03 guard violated: EPID-specific unsupported-format string leaked in $NITRO_ENGINE"
fi

# L-05/L-06: repository hygiene ignore rules.
for file in \
  "$ROOT/contracts/.gitignore" \
  "$ROOT/.gitignore" \
  "$ROOT/services/tee-worker/nitro-sdk/.gitignore"
do
  [[ -f "$file" ]] || fail "missing $file"
  require_fixed '.DS_Store' "$file"
done
require_fixed 'target/' "$ROOT/services/tee-worker/nitro-sdk/.gitignore"

# If subdirectories are git repos, ensure no tracked .DS_Store / target artifacts remain.
for repo in \
  "$ROOT/contracts" \
  "$ROOT" \
  "$ROOT/services/tee-worker/nitro-sdk"
do
  if git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if git -C "$repo" ls-files | list_has_match '\.DS_Store$'; then
      fail "tracked .DS_Store detected in $repo"
    fi
    if git -C "$repo" ls-files | list_has_match '(^|/)target/'; then
      fail "tracked target/ artifact detected in $repo"
    fi
  fi
done

# L-07: TS Nitro root trust remains fail-closed by default.
TS_TEE="$ROOT/sdk/typescript/src/crypto/tee.ts"
[[ -f "$TS_TEE" ]] || fail "missing $TS_TEE"
require_line "export const NITRO_ROOT_CERT = ''" "$TS_TEE"
require_fixed 'nitroTrustedRootsPem?: string[];' "$TS_TEE"

# L-08: TS client supports API key header.
TS_CLIENT="$ROOT/sdk/typescript/src/core/client.ts"
[[ -f "$TS_CLIENT" ]] || fail "missing $TS_CLIENT"
require_line "'X-API-Key'" "$TS_CLIENT"

echo "Low finding guards OK (L-01, L-02, L-03, L-04, L-05, L-06, L-07, L-08)"
