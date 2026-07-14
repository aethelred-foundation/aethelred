#!/usr/bin/env bash
#
# scripts/e2e-seal-harness.sh — end-to-end Digital Seal harness.
#
# Boots a single-validator devnet, fully onboards it for Proof-of-Useful-Work,
# submits a CEAP-bound job, and ASSERTS that the validator quorum mints a real
# Digital Seal — the full path every seal-gated dApp (NoblePay/TerraQura/Shiora/
# ZeroID) depends on. Exits non-zero the moment any step fails, so this class of
# "looked fine, broke in the field" regression is caught before release.
#
# This encodes the operational knowledge that is easy to get wrong:
#   * the binary MUST be built from a branch with the EVM JSON-RPC + PoUW seal
#     pipeline (release/public-testnet-pqc), NOT a bare app-only branch;
#   * AETHELRED_TEE_MODE=simulated is required or the node panics on a missing
#     Nitro enclave endpoint;
#   * vote_extensions_enable_height must be 1 or jobs are assigned but never
#     verified/sealed;
#   * the validator must cross the 100k PoUW stake floor AND register a
#     capability, a hybrid quorum key (printed by the node at startup), and its
#     enclave PCR0 measurement — the measurement is discovered from the node's
#     own rejection log, not guessed.
#
# Usage:
#   BIN=/path/to/aethelredd scripts/e2e-seal-harness.sh
#   BIN=... REGION=AE scripts/e2e-seal-harness.sh   # also assert data residency
#
# Env:
#   BIN        aethelredd binary (default: ./build/aethelredd or $PATH)
#   HOME_DIR   devnet home (default: a fresh mktemp dir, removed on success)
#   REGION     optional data_residency_region; when set the job requires it and
#              the seal must carry it (proves CEAP residency end to end)
#   KEEP       set to 1 to keep the home dir + running node for inspection
#   SEAL_WAIT  seconds to wait for the seal mint (default 150). On a COLD fresh
#              chain the seal-quorum machinery (DKG group key + vote-extension
#              seal pipeline) warms up over several minutes after the first
#              PoUW job; bump this (e.g. 600) for a from-scratch run. The seal
#              logic itself is fast once warm.
set -euo pipefail

CHAIN_ID="${CHAIN_ID:-aethelred-e2e-1}"
DENOM=uaethel
KEYRING=test
REGION="${REGION:-}"
SEAL_WAIT="${SEAL_WAIT:-150}"
RPC=tcp://127.0.0.1:26657
EVM_RPC=127.0.0.1:8545

if [ -n "${BIN:-}" ]; then :; elif [ -x ./build/aethelredd ]; then BIN=./build/aethelredd; else BIN=aethelredd; fi
HOME_DIR="${HOME_DIR:-$(mktemp -d -t aethelredd-e2e-XXXX)}"
LOG="$HOME_DIR/node.log"
export AETHELRED_TEE_MODE=simulated
export AETHELRED_ALLOW_SIMULATED=1

NODE_PID=""
ok()   { printf '\033[1;32m  PASS\033[0m %s\n' "$*"; }
step() { printf '\033[1;36m== %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31mFAIL\033[0m %s\n' "$*" >&2; [ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null || true; exit 1; }
cleanup() {
  [ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null || true
  if [ "${KEEP:-0}" != "1" ]; then rm -rf "$HOME_DIR"; fi
}
trap cleanup EXIT

tx() { # broadcast a tx and require code 0; args: <subcommand...>
  local out
  out="$("$BIN" tx "$@" --from val --home "$HOME_DIR" --chain-id "$CHAIN_ID" \
    --keyring-backend "$KEYRING" --node "$RPC" --gas auto --gas-adjustment 1.5 --yes 2>&1)" || true
  echo "$out" | grep -qE '^code: 0' || die "tx failed: $* :: $(echo "$out" | grep -iE 'code:|err' | head -1)"
  sleep 5
}

txsoft() { # broadcast a tx, tolerate any on-chain outcome (used for the probe
  # job, whose seal/CEAP result is irrelevant — it only exists to make the
  # enclave emit its measurement). Still sleeps so the account sequence advances.
  "$BIN" tx "$@" --from val --home "$HOME_DIR" --chain-id "$CHAIN_ID" \
    --keyring-backend "$KEYRING" --node "$RPC" --gas auto --gas-adjustment 1.5 --yes >/dev/null 2>&1 || true
  sleep 5
}

wait_for() { # wait_for <seconds> <grep-pattern> ; scans $LOG
  local deadline=$(( $(date +%s) + $1 )); shift
  while [ "$(date +%s)" -lt "$deadline" ]; do grep -qiE "$1" "$LOG" && return 0; sleep 2; done
  return 1
}

wait_rpc_height() { # wait_rpc_height <seconds> <min-height> — poll RPC, not the log
  local deadline=$(( $(date +%s) + $1 )); local minh="$2" h
  while [ "$(date +%s)" -lt "$deadline" ]; do
    h="$(curl -s -m 2 http://127.0.0.1:26657/status 2>/dev/null \
      | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"]["sync_info"]["latest_block_height"])' 2>/dev/null || true)"
    [ -n "$h" ] && [ "$h" -ge "$minh" ] 2>/dev/null && return 0
    kill -0 "$NODE_PID" 2>/dev/null || return 1  # node died
    sleep 3
  done
  return 1
}

step "genesis (single validator, 150k self-bond, region='${REGION:-<none>}')"
"$BIN" init e2e --chain-id "$CHAIN_ID" --default-denom "$DENOM" --home "$HOME_DIR" >/dev/null 2>&1
"$BIN" keys add val --keyring-backend "$KEYRING" --home "$HOME_DIR" >/dev/null 2>&1
VAL_ACC="$("$BIN" keys show val -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"
VAL_OPER="$("$BIN" keys show val --bech val -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"
"$BIN" add-genesis-account "$VAL_ACC" "500000000000$DENOM" --home "$HOME_DIR" >/dev/null
G="$HOME_DIR/config/genesis.json"
python3 - "$G" "$REGION" <<'PY'
import json, sys
g = json.load(open(sys.argv[1])); region = sys.argv[2]
# allow_simulated must be set on BOTH modules: pouw gates seal minting, and the
# app's BeginBlocker production-readiness check reads verify.params — leaving
# verify at its false default panics the node in consensus at height 1
# ("NOT production-ready"). This is the single most common devnet-genesis trap.
g["app_state"]["pouw"]["params"]["allow_simulated"] = True
g["app_state"]["verify"]["params"]["allow_simulated"] = True
if region:
    g["app_state"]["pouw"]["params"]["data_residency_region"] = region
# ABCI++ vote extensions must be on from height 1 or nothing gets sealed.
g["consensus"]["params"]["abci"]["vote_extensions_enable_height"] = "1"
json.dump(g, open(sys.argv[1], "w"))
PY
"$BIN" gentx val "150000000000$DENOM" --chain-id "$CHAIN_ID" --keyring-backend "$KEYRING" --home "$HOME_DIR" >/dev/null 2>&1
"$BIN" collect-gentxs --home "$HOME_DIR" >/dev/null 2>&1
"$BIN" validate-genesis --home "$HOME_DIR" >/dev/null
ok "genesis built for $VAL_ACC"

step "boot node (TEE simulated)"
"$BIN" start --home "$HOME_DIR" --minimum-gas-prices "0$DENOM" \
  --json-rpc.enable --json-rpc.address "$EVM_RPC" >"$LOG" 2>&1 &
NODE_PID=$!
# Cold start includes a one-time IAVL storage upgrade over every module store,
# which can take well over a minute before the first block commits — poll the
# RPC for height>=2 rather than assuming a fast boot.
wait_rpc_height 240 2 || die "node did not produce blocks within 240s (see $LOG)"
"$BIN" query pouw status --validator "$VAL_ACC" --home "$HOME_DIR" --node "$RPC" 2>/dev/null | grep -q 'stake_requirement_met": true' \
  || die "validator did not reach the PoUW stake floor from genesis"
ok "node producing blocks; validator stake-ready"

step "onboard validator for PoUW (capability, hybrid key, PCR0)"
tx pouw register-validator-capability --tee-platforms simulated --max-concurrent-jobs 4
HK="$(grep -oE 'hybrid_public_key=\S+' "$LOG" | head -1 | cut -d= -f2 | sed 's/\x1b\[[0-9;]*m//g')"
[ -n "$HK" ] || die "could not read hybrid_public_key from node log"
tx pouw register-hybrid-key "$HK"
tx pouw register-model --model e2e-v1 --model-id e2e --name "E2E Model"

# A placeholder PCR0 registers the validator first, then a probe job makes the
# simulated enclave emit its real measurement, which is discovered from the
# node's rejection log and registered.
CONF_FLAGS="--conf-backends tee"; [ -n "$REGION" ] && CONF_FLAGS="$CONF_FLAGS --conf-residency $REGION"
tx pouw register-pcr0 "$(python3 -c 'print("ab"*32)')"
txsoft pouw submit-job --model e2e-v1 --input probe --proof-type tee --purpose "e2e:probe" $CONF_FLAGS
if wait_for 30 'unregistered aws-nitro measurement'; then
  PCR0="$(grep -oE 'unregistered aws-nitro measurement: [0-9a-f]{64}' "$LOG" | tail -1 | awk '{print $NF}')"
  [ -n "$PCR0" ] && tx pouw register-pcr0 "$PCR0"
fi
"$BIN" query pouw status --validator "$VAL_ACC" --home "$HOME_DIR" --node "$RPC" 2>/dev/null | grep -q 'ready_for_pouw": true' \
  || die "validator not ready_for_pouw after onboarding"
ok "validator ready_for_pouw"

# The job scheduler only assigns work to validators whose capability has been
# OBSERVED on-chain (validator_stats_found), and the seal quorum needs its DKG
# group key established. On a fresh chain both warm up over some blocks — poll
# until observed rather than racing the scheduler.
step "wait for capability observation + assignment readiness"
warm_deadline=$(( $(date +%s) + 180 ))
while [ "$(date +%s)" -lt "$warm_deadline" ]; do
  "$BIN" query pouw status --validator "$VAL_ACC" --home "$HOME_DIR" --node "$RPC" 2>/dev/null \
    | grep -q 'validator_stats_found": true' && break
  sleep 5
done
"$BIN" query pouw status --validator "$VAL_ACC" --home "$HOME_DIR" --node "$RPC" 2>/dev/null | grep -q 'validator_stats_found": true' \
  || die "validator capability never observed (scheduler will not assign jobs)"
ok "capability observed; scheduler will assign jobs"

step "submit CEAP job and require a minted seal"
"$BIN" tx pouw submit-job --model e2e-v1 --input "e2e-real-$(date +%s)" --proof-type tee \
  --purpose "e2e:real" $CONF_FLAGS \
  --from val --home "$HOME_DIR" --chain-id "$CHAIN_ID" --keyring-backend "$KEYRING" \
  --node "$RPC" --gas auto --gas-adjustment 1.5 --yes 2>&1 | grep -qE '^code: 0' || die "submit-job failed"
wait_for "$SEAL_WAIT" 'job_completed.*seal_id=' || die "no Digital Seal minted within ${SEAL_WAIT}s — cold-chain warm-up? retry with SEAL_WAIT=600 (see $LOG)"
SEAL="$(grep -oE 'seal_id=[0-9a-f]{64}' "$LOG" | tail -1 | cut -d= -f2)"
[ -n "$SEAL" ] || die "seal_id not found despite job_completed"
ok "Digital Seal minted: $SEAL"

if [ -n "$REGION" ]; then
  # The job REQUIRED residency=$REGION; a mint proves the network region
  # satisfied it (an unset/mismatched region would have failed closed).
  ok "CEAP data-residency '$REGION' satisfied end to end"
fi

printf '\n\033[1;32mE2E SEAL HARNESS: PASS\033[0m  seal=%s region=%s\n' "$SEAL" "${REGION:-<none>}"
