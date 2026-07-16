#!/usr/bin/env bash
#
# scripts/activate-precompiles-gov.sh
# ─────────────────────────────────────────────────────────────────────────────
# Activate the cosmos/evm staking (0x0800) + distribution (0x0801) precompiles
# on a RUNNING network via on-chain governance — no chain restart, no re-genesis.
#
# This is the exact procedure for the public testnet after validators upgrade to
# a binary that REGISTERS the precompiles (feat/staking-distribution-precompiles,
# merged as PR #154). Registration alone does nothing: x/vm gates activation on
# the `active_static_precompiles` PARAM, held in state. This script flips that
# param through a gov v1 `MsgUpdateParams` for the evm module.
#
# It is idempotent-safe to read: it first checks whether the precompiles are
# already active and exits early if so.
#
# CONSENSUS SAFETY (why this is a safe rolling upgrade):
#   1. The new binary changes NO behaviour until the param includes the two
#      addresses — validators can upgrade one at a time (rolling), and a node on
#      the new binary produces byte-identical app hashes to one on the old binary
#      as long as the param is unchanged. Proven by the mirror rehearsal:
#      delegate() REVERTS before the proposal even on the new binary.
#   2. The param change is a normal governed state transition applied
#      deterministically at the proposal's execution height on every node, so
#      there is no fork risk — every validator flips at the same height.
#   3. ALL validators MUST be on the new binary before the proposal executes.
#      A validator still on the old binary cannot register the precompile
#      handlers, so when the param activates them that node would compute a
#      different app hash and halt (apphash mismatch). Sequence is therefore:
#      upgrade every validator's binary FIRST, confirm the set is fully upgraded,
#      THEN submit + pass the proposal.
#
# Usage:
#   NODE=tcp://<rpc> CHAIN_ID=<id> FROM=<key> HOME_DIR=<home> \
#     KEYRING=<backend> scripts/activate-precompiles-gov.sh [--vote-all]
#
#   --vote-all   also cast YES from every local validator key val0..valN
#                (rehearsal / single-operator networks). On the public testnet,
#                each validator operator votes independently — omit this flag and
#                distribute the printed proposal id.
#
# Env (devnet-rehearsal defaults shown):
#   BIN         aethelredd binary (default: from PATH or ./build)
#   NODE        CometBFT RPC (default: tcp://127.0.0.1:26757)
#   CHAIN_ID    (default: aethelred-mirror-1)
#   FROM        proposer key (default: validator)
#   HOME_DIR    node home holding the keyring (default: ~/.aethelredd)
#   KEYRING     keyring backend (default: test)
#   DEPOSIT     proposal deposit (default: 10000000uaethel)
set -uo pipefail

BIN="${BIN:-aethelredd}"
if ! command -v "$BIN" >/dev/null 2>&1 && [ -x "./build/aethelredd" ]; then BIN="./build/aethelredd"; fi
NODE="${NODE:-tcp://127.0.0.1:26757}"
CHAIN_ID="${CHAIN_ID:-aethelred-mirror-1}"
FROM="${FROM:-validator}"
HOME_DIR="${HOME_DIR:-$HOME/.aethelredd}"
KEYRING="${KEYRING:-test}"
DEPOSIT="${DEPOSIT:-10000000uaethel}"
VOTE_ALL=0; [ "${1:-}" = "--vote-all" ] && VOTE_ALL=1

STAKING_PC="0x0000000000000000000000000000000000000800"
DIST_PC="0x0000000000000000000000000000000000000801"

log(){ printf '\033[1;36m>>> %s\033[0m\n' "$*"; }
ok(){ printf '  \033[1;32mPASS\033[0m %s\n' "$1"; }
die(){ printf '  \033[1;31mFAIL\033[0m %s\n' "$1"; exit 1; }
# The CLI prints query output on stderr, so capture BOTH streams and only accept
# a result once it parses as JSON — this also rides out the "not ready" seconds
# right after startup.
q(){ local out; for _ in $(seq 1 15); do
  out=$("$BIN" query "$@" --node "$NODE" --output json 2>&1)
  if printf '%s' "$out" | python3 -c "import sys,json;json.load(sys.stdin)" >/dev/null 2>&1; then printf '%s' "$out"; return 0; fi
  sleep 2
done; return 1; }

log "current evm params"
PARAMS="$(q evm params)" || die "cannot query evm params (is NODE reachable?)"
CUR="$(printf '%s' "$PARAMS" | python3 -c "import sys,json; print(' '.join(json.load(sys.stdin)['params']['active_static_precompiles']))")"
echo "  active: $CUR"

if printf '%s' "$CUR" | grep -qi "$STAKING_PC" && printf '%s' "$CUR" | grep -qi "$DIST_PC"; then
  ok "0x0800 + 0x0801 already active — nothing to do"
  exit 0
fi

GOV_ADDR="$(q auth module-account gov | python3 -c "import sys,json; print(json.load(sys.stdin)['account']['value']['address'])")"
[ -n "$GOV_ADDR" ] || die "could not resolve the gov module authority"
log "gov authority: $GOV_ADDR"

# Build the MsgUpdateParams proposal. MsgUpdateParams REPLACES the whole params
# object, so we take the CURRENT params verbatim and only append the two
# precompiles (sorted + de-duplicated — x/vm ValidatePrecompiles requires it).
# Params passed via env (not stdin) so the embedded program reads cleanly.
PROP="$(mktemp)"
PARAMS_JSON="$PARAMS" GOV_ADDR="$GOV_ADDR" STAKING_PC="$STAKING_PC" \
DIST_PC="$DIST_PC" DEPOSIT="$DEPOSIT" python3 > "$PROP" <<'PY'
import os, json
params = json.loads(os.environ["PARAMS_JSON"])["params"]
pcs = {a.lower() for a in params["active_static_precompiles"]}
pcs |= {os.environ["STAKING_PC"].lower(), os.environ["DIST_PC"].lower()}
params["active_static_precompiles"] = sorted(pcs)
proposal = {
    "messages": [{
        "@type": "/cosmos.evm.vm.v1.MsgUpdateParams",
        "authority": os.environ["GOV_ADDR"],
        "params": params,
    }],
    "metadata": "activate-staking-distribution-precompiles",
    "deposit": os.environ["DEPOSIT"],
    "title": "Activate staking (0x0800) and distribution (0x0801) precompiles",
    "summary": ("Add the cosmos/evm staking and distribution precompiles to "
                "active_static_precompiles so EVM contracts (the Cruzible "
                "liquid-staking vault) can delegate and claim earned rewards. "
                "All validators must be on the PR #154 binary before execution."),
}
print(json.dumps(proposal, indent=2))
PY
log "proposal written: $PROP"
python3 -c "import json;p=json.load(open('$PROP'));print('  new active_static_precompiles:', p['messages'][0]['params']['active_static_precompiles'])"

log "submit proposal (from $FROM)"
TXOUT="$("$BIN" tx gov submit-proposal "$PROP" --from "$FROM" --keyring-backend "$KEYRING" \
  --home "$HOME_DIR" --node "$NODE" --chain-id "$CHAIN_ID" --fees 4000uaethel --gas 600000 \
  --yes --output json 2>&1)"
TXH="$(printf '%s' "$TXOUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('txhash',''))" 2>/dev/null)"
[ -n "$TXH" ] || die "submit failed: $TXOUT"
sleep 5
PID="$("$BIN" query tx "$TXH" --node "$NODE" --output json 2>/dev/null | python3 -c "
import sys,json
for ev in json.load(sys.stdin).get('events',[]):
    if ev['type']=='submit_proposal':
        for a in ev['attributes']:
            if a['key']=='proposal_id': print(a['value'])
" 2>/dev/null | head -1)"
[ -n "$PID" ] || die "could not read proposal id from tx $TXH"
ok "proposal #$PID submitted (tx $TXH)"

if [ "$VOTE_ALL" = "1" ]; then
  log "casting YES from every local validator key"
  for k in $("$BIN" keys list --keyring-backend "$KEYRING" --home "$HOME_DIR" --output json 2>/dev/null | python3 -c "import sys,json;[print(x['name']) for x in json.load(sys.stdin)]"); do
    "$BIN" tx gov vote "$PID" yes --from "$k" --keyring-backend "$KEYRING" --home "$HOME_DIR" \
      --node "$NODE" --chain-id "$CHAIN_ID" --fees 2000uaethel --gas 300000 --yes >/dev/null 2>&1 \
      && echo "  voted YES from $k"
  done
else
  log "proposal #$PID open for voting — each validator operator runs:"
  echo "  $BIN tx gov vote $PID yes --from <valkey> --chain-id $CHAIN_ID --node $NODE ..."
fi

log "waiting for the voting period to end + execution"
for _ in $(seq 1 30); do
  ST="$(q gov proposal "$PID" | python3 -c "import sys,json; print(json.load(sys.stdin)['proposal']['status'])" 2>/dev/null)"
  echo "  status: $ST"
  case "$ST" in
    PROPOSAL_STATUS_PASSED) break ;;
    PROPOSAL_STATUS_REJECTED|PROPOSAL_STATUS_FAILED) die "proposal $ST" ;;
  esac
  sleep 4
done
[ "$ST" = "PROPOSAL_STATUS_PASSED" ] || die "proposal did not pass in time (status $ST)"
ok "proposal #$PID PASSED"

log "verify the precompiles are now active (no restart)"
NEW="$(q evm params | python3 -c "import sys,json; print(' '.join(json.load(sys.stdin)['params']['active_static_precompiles']))")"
echo "  active: $NEW"
printf '%s' "$NEW" | grep -qi "$STAKING_PC" || die "0x0800 not active after execution"
printf '%s' "$NEW" | grep -qi "$DIST_PC" || die "0x0801 not active after execution"
ok "staking + distribution precompiles ACTIVE on the running chain"
echo
echo "ACTIVATION COMPLETE — proposal #$PID applied without a restart."
