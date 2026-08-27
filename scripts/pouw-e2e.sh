#!/usr/bin/env bash
#
# scripts/pouw-e2e.sh — end-to-end Proof-of-Useful-Work pipeline test.
#
# Brings up a local N-validator network, onboards every validator, registers a
# model, submits a zkML job, and asserts the full pipeline stage by stage:
#
#   submit-job → EndBlock assignment → ExtendVote verification → ≥67% quorum
#   → PreBlocker Digital Seal → job COMPLETED → validator stats credited
#   → verification reward paid from the genesis reward pool
#   → identical app hash on every validator (no consensus divergence)
#
# It prints PASS/FAIL per stage and exits non-zero if any stage fails, so it can
# gate CI. Runs against the deterministic pipeline — no external hardware.
#
# Usage:
#   scripts/pouw-e2e.sh              # build if needed, run, tear down
#   N=5 scripts/pouw-e2e.sh          # 5 validators
#   KEEP=1 scripts/pouw-e2e.sh       # leave the network running afterwards
#
# Env: BINARY (default: build/aethelredd or PATH), BASE_DIR, CHAIN_ID, N.
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
N="${N:-4}"
CHAIN_ID="${CHAIN_ID:-aethelred-localnet-1}"
BASE_DIR="${BASE_DIR:-$HOME/.aethelred-localnet}"
KEYRING="${KEYRING:-test}"
KEEP="${KEEP:-0}"

BINARY="${BINARY:-aethelredd}"
if command -v "$BINARY" >/dev/null 2>&1; then BIN="$BINARY"
elif [ -x "$ROOT/build/aethelredd" ]; then BIN="$ROOT/build/aethelredd"
else
  echo ">>> building aethelredd"
  ( cd "$ROOT" && go build -o build/aethelredd ./cmd/aethelredd ) || { echo "build failed"; exit 1; }
  BIN="$ROOT/build/aethelredd"
fi

pass=0; fail=0
ok()   { printf '  \033[1;32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[1;31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
check_eq(){ if [ "$2" = "$3" ]; then ok "$1 ($2)"; else bad "$1 (got '$2', want '$3')"; fi; }
check_ge(){ if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then ok "$1 ($2 >= $3)"; else bad "$1 (got '${2:-0}', want >= $3)"; fi; }

home_i(){ echo "$BASE_DIR/node$1"; }
url_i(){ echo "tcp://127.0.0.1:$((26657 + 100*$1))"; }
addr_i(){ "$BIN" keys show "val$1" -a --keyring-backend "$KEYRING" --home "$(home_i "$1")" 2>/dev/null; }
hybrid_key(){ grep "hybrid_public_key=" "$1" 2>/dev/null | head -1 | sed 's/\x1b\[[0-9;]*m//g' | sed 's/.*hybrid_public_key=//' | grep -oE '^[0-9a-f]+'; }
# Count log lines matching a pattern across all node logs. Strips ANSI color
# codes first — the node colorizes key=value attributes, so a raw grep for a
# pattern that spans a key/value boundary (e.g. "action=job_completed") misses.
log_count(){ local pat="$1"; local total=0 c; for i in $(seq 0 $((N-1))); do c=$(sed 's/\x1b\[[0-9;]*m//g' "$(home_i "$i")/node.log" 2>/dev/null | grep -ciE "$pat"); total=$((total + ${c:-0})); done; echo "$total"; }
status_field(){ "$BIN" query pouw status --validator "$1" --home "$(home_i 0)" --node "$(url_i 0)" --output json 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('$2'))" 2>/dev/null; }

# broadcast a tx on node <i> with key val<i>, wait for commit, echo result code
btx(){ local i="$1"; shift
  local out h
  out=$("$BIN" tx "$@" --from "val$i" --keyring-backend "$KEYRING" --home "$(home_i "$i")" \
        --node "$(url_i "$i")" --chain-id "$CHAIN_ID" --fees 200uaethel --gas 700000 --yes --output json 2>&1)
  h=$(printf '%s' "$out" | python3 -c "import sys,json;print(json.load(sys.stdin).get('txhash',''))" 2>/dev/null)
  [ -z "$h" ] && { echo "no-broadcast"; return; }
  sleep 6
  "$BIN" query tx "$h" --home "$(home_i "$i")" --node "$(url_i "$i")" --output json 2>/dev/null \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('code'))" 2>/dev/null
}

lncmd(){ N="$N" BINARY="$BIN" BASE_DIR="$BASE_DIR" AETHELRED_TEE_MODE=simulated bash "$ROOT/scripts/localnet.sh" "$1" >/dev/null 2>&1; }

echo "======================================================================"
echo "PoUW end-to-end pipeline test — $N validators"
echo "======================================================================"

# ── 1. bring up the network ──────────────────────────────────────────────
echo ">>> [1/6] starting $N-validator localnet"
lncmd reset; lncmd init; lncmd start
for _ in $(seq 1 20); do
  h=$(curl -s --max-time 2 "http://127.0.0.1:26657/status" 2>/dev/null | sed -n 's/.*"latest_block_height":"\([0-9]*\)".*/\1/p' | head -1)
  [ "${h:-0}" -ge 3 ] 2>/dev/null && break
  sleep 2
done
up=0; for i in $(seq 0 $((N-1))); do curl -s --max-time 2 "http://127.0.0.1:$((26657+100*i))/status" >/dev/null 2>&1 && up=$((up+1)); done
check_ge "network up (nodes responding)" "$up" "$N"

# ── 2. onboard every validator ───────────────────────────────────────────
echo ">>> [2/6] onboarding validators (pcr0 + capability + hybrid key)"
PCR0=$(printf 'ab%.0s' $(seq 1 32))
for i in $(seq 0 $((N-1))); do
  K=$(hybrid_key "$(home_i "$i")/node.log")
  btx "$i" pouw register-pcr0 "$PCR0" >/dev/null
  btx "$i" pouw register-validator-capability --tee-platforms aws-nitro,amd-sev-snp --zkml-systems groth16 --max-concurrent-jobs 4 >/dev/null
  btx "$i" pouw register-hybrid-key "$K" >/dev/null
done
ready=0; for i in $(seq 0 $((N-1))); do [ "$(status_field "$(addr_i "$i")" ready_for_pouw)" = "True" ] && ready=$((ready+1)); done
check_ge "validators ready_for_pouw" "$ready" "$N"

# ── 3. register model + submit job ───────────────────────────────────────
echo ">>> [3/6] registering model and submitting job"
check_eq "register-model committed" "$(btx 0 pouw register-model --model resnet50-v1 --model-id resnet50 --name ResNet-50 --verifying-key-hash vk-resnet50-v1)" "0"
check_eq "submit-job committed"     "$(btx 0 pouw submit-job --model resnet50-v1 --input sample-batch-0 --proof-type zkml --purpose pouw-e2e)" "0"

# ── 4. wait for the seal ─────────────────────────────────────────────────
echo ">>> [4/6] waiting for the job to reach a quorum seal"
for _ in $(seq 1 20); do
  [ "$(log_count 'action=job_completed')" -ge "$N" ] 2>/dev/null && break
  sleep 4
done

# ── 5. assert pipeline stages ────────────────────────────────────────────
echo ">>> [5/6] asserting pipeline stages"
check_ge "job assigned (EndBlock)"            "$(log_count 'Assigned PoUW job')" 1
check_ge "consensus reached on output"        "$(log_count 'Consensus reached for job')" 1
check_ge "seal transaction created"           "$(log_count 'Seal transaction created')" 1
check_ge "job COMPLETED on all validators"    "$(log_count 'action=job_completed')" "$N"
check_eq "validator stats credited"           "$(status_field "$(addr_i 0)" validator_stats_found)" "True"
check_ge "successful jobs recorded"           "$(status_field "$(addr_i 0)" successful_jobs)" 1
check_eq "reward not withheld (pool funded)"  "$(log_count 'reward withheld|Failed to distribute verification reward')" "0"
check_eq "no consensus divergence (app hash)" "$(log_count 'wrong Block.Header.AppHash')" "0"

# ── 6. summary ───────────────────────────────────────────────────────────
echo ">>> [6/6] done"
if [ "$KEEP" = "1" ]; then echo "    (network left running — 'scripts/localnet.sh stop' to tear down)"; else lncmd stop; fi
echo "======================================================================"
printf 'RESULT: \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n' "$pass" "$fail"
echo "======================================================================"
[ "$fail" -eq 0 ]
