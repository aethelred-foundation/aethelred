#!/usr/bin/env bash
#
# scripts/gov-e2e.sh — end-to-end on-chain governance test.
#
# Brings up a local N-validator network (with short voting periods), submits a
# gov v1 proposal that updates the mint module's params via MsgUpdateParams, has
# every validator vote YES, waits out the voting period, and asserts the full
# loop executed:
#
#   submit-proposal → deposit meets minimum → voting → >quorum & >threshold YES
#   → PROPOSAL_STATUS_PASSED → the proposed param change is applied on-chain
#
# Proves governance works end to end (proposal, deposit, voting, tally, and — the
# part that actually matters — execution of the passed proposal). Prints
# PASS/FAIL per stage and exits non-zero on failure.
#
# Usage:  scripts/gov-e2e.sh        (build if needed, run, tear down)
#         KEEP=1 scripts/gov-e2e.sh (leave the network running)
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
N="${N:-4}"
CHAIN_ID="${CHAIN_ID:-aethelred-localnet-1}"
BASE_DIR="${BASE_DIR:-$HOME/.aethelred-localnet}"
KEYRING="${KEYRING:-test}"
KEEP="${KEEP:-0}"
NEW_BLOCKS_PER_YEAR="${NEW_BLOCKS_PER_YEAR:-6000000}"

BINARY="${BINARY:-aethelredd}"
if command -v "$BINARY" >/dev/null 2>&1; then BIN="$BINARY"
elif [ -x "$ROOT/build/aethelredd" ]; then BIN="$ROOT/build/aethelredd"
else echo ">>> building"; ( cd "$ROOT" && go build -o build/aethelredd ./cmd/aethelredd ) || exit 1; BIN="$ROOT/build/aethelredd"; fi

pass=0; fail=0
ok(){ printf '  \033[1;32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad(){ printf '  \033[1;31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
check_eq(){ if [ "$2" = "$3" ]; then ok "$1 ($2)"; else bad "$1 (got '$2', want '$3')"; fi; }
check_ne(){ if [ "$2" != "$3" ]; then ok "$1 ($3 -> $2)"; else bad "$1 (unchanged: $2)"; fi; }

home_i(){ echo "$BASE_DIR/node$1"; }
url_i(){ echo "tcp://127.0.0.1:$((26657 + 100*$1))"; }
# Query node0 for JSON. The CLI prints query output on stderr, so capture both
# streams and only accept a result once it parses as JSON — this also rides out
# the few seconds of "not ready" errors right after multi-node startup.
q(){ local out; for _ in $(seq 1 20); do
  out=$("$BIN" query "$@" --home "$(home_i 0)" --node "$(url_i 0)" --output json 2>&1)
  if printf '%s' "$out" | python3 -c "import sys,json;json.load(sys.stdin)" >/dev/null 2>&1; then printf '%s' "$out"; return 0; fi
  sleep 2
done; return 1; }
lncmd(){ N="$N" BINARY="$BIN" BASE_DIR="$BASE_DIR" AETHELRED_TEE_MODE=simulated bash "$ROOT/scripts/localnet.sh" "$1" >/dev/null 2>&1; }

echo "======================================================================"
echo "Governance end-to-end test — $N validators"
echo "======================================================================"

# ── 1. bring up the network with short gov params ────────────────────────
echo ">>> [1/5] starting localnet with short voting period"
lncmd reset; lncmd init
python3 - "$BASE_DIR" <<'PY'
import json,glob,sys
for gf in glob.glob(sys.argv[1]+"/node*/config/genesis.json"):
    d=json.load(open(gf)); p=d["app_state"]["gov"]["params"]
    p["voting_period"]="20s"; p["max_deposit_period"]="40s"; p["expedited_voting_period"]="10s"
    p["min_deposit"]=[{"denom":"uaethel","amount":"1000000"}]
    p["expedited_min_deposit"]=[{"denom":"uaethel","amount":"2000000"}]
    json.dump(d,open(gf,"w"),indent=1)
PY
lncmd start
for _ in $(seq 1 20); do
  h=$(curl -s --max-time 2 "$(url_i 0 | sed 's#tcp://#http://#')/status" 2>/dev/null | sed -n 's/.*"latest_block_height":"\([0-9]*\)".*/\1/p'|head -1)
  [ "${h:-0}" -ge 3 ] 2>/dev/null && break; sleep 2
done
up=0; for i in $(seq 0 $((N-1))); do curl -s --max-time 2 "$(url_i "$i"|sed 's#tcp://#http://#')/status" >/dev/null 2>&1 && up=$((up+1)); done
check_eq "network up" "$up" "$N"

# ── 2. build the proposal (MsgUpdateParams for mint) ─────────────────────
echo ">>> [2/5] building + submitting proposal"
GOV_ADDR=$(q auth module-account gov | python3 -c "import sys,json;print(json.load(sys.stdin)['account']['value']['address'])" 2>/dev/null)
BEFORE=$(q mint params | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('params',d).get('blocks_per_year'))" 2>/dev/null)
PROP="$BASE_DIR/gov-prop.json"
q mint params | python3 -c "
import sys,json
d=json.load(sys.stdin); params=d.get('params',d)
params['blocks_per_year']='$NEW_BLOCKS_PER_YEAR'
prop={'messages':[{'@type':'/cosmos.mint.v1beta1.MsgUpdateParams','authority':'$GOV_ADDR','params':params}],
      'metadata':'','deposit':'2000000uaethel',
      'title':'Update mint blocks_per_year','summary':'gov-e2e smoke'}
json.dump(prop,open('$PROP','w'),indent=1)
"
H=$("$BIN" tx gov submit-proposal "$PROP" --from val0 --keyring-backend "$KEYRING" --home "$(home_i 0)" --node "$(url_i 0)" --chain-id "$CHAIN_ID" --fees 2000uaethel --gas 400000 --yes --output json 2>&1 | python3 -c "import sys,json;print(json.load(sys.stdin).get('txhash',''))" 2>/dev/null)
sleep 6
PID=$("$BIN" query tx "$H" --home "$(home_i 0)" --node "$(url_i 0)" --output json 2>&1 | python3 -c "
import sys,json
d=json.load(sys.stdin)
for ev in d.get('events',[]):
    for a in ev.get('attributes',[]):
        if a.get('key')=='proposal_id': print(a.get('value')); sys.exit()
" 2>/dev/null)
check_eq "proposal submitted (has id)" "$([ -n "$PID" ] && echo yes || echo no)" "yes"
echo "    proposal id=$PID, blocks_per_year $BEFORE -> $NEW_BLOCKS_PER_YEAR"

# ── 3. everyone votes YES ────────────────────────────────────────────────
echo ">>> [3/5] voting YES from all $N validators"
voted=0
for i in $(seq 0 $((N-1))); do
  vh=$("$BIN" tx gov vote "$PID" yes --from "val$i" --keyring-backend "$KEYRING" --home "$(home_i "$i")" --node "$(url_i "$i")" --chain-id "$CHAIN_ID" --fees 2000uaethel --gas 300000 --yes --output json 2>&1 | python3 -c "import sys,json;print(json.load(sys.stdin).get('txhash',''))" 2>/dev/null)
  [ -n "$vh" ] && voted=$((voted+1)); sleep 3
done
check_eq "votes cast" "$voted" "$N"

# ── 4. wait out the voting period ────────────────────────────────────────
echo ">>> [4/5] waiting out the voting period (~20s)"
for _ in $(seq 1 12); do
  st=$(q gov proposal "$PID" | python3 -c "import sys,json;print(json.load(sys.stdin).get('proposal',{}).get('status'))" 2>/dev/null)
  [ "$st" = "PROPOSAL_STATUS_PASSED" ] || [ "$st" = "PROPOSAL_STATUS_REJECTED" ] || [ "$st" = "PROPOSAL_STATUS_FAILED" ] && break
  sleep 4
done

# ── 5. assert it passed AND executed ─────────────────────────────────────
echo ">>> [5/5] asserting tally + execution"
STATUS=$(q gov proposal "$PID" | python3 -c "import sys,json;print(json.load(sys.stdin).get('proposal',{}).get('status'))" 2>/dev/null)
AFTER=$(q mint params | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('params',d).get('blocks_per_year'))" 2>/dev/null)
check_eq "proposal PASSED" "$STATUS" "PROPOSAL_STATUS_PASSED"
check_eq "param executed on-chain" "$AFTER" "$NEW_BLOCKS_PER_YEAR"
check_ne "param actually changed" "$AFTER" "$BEFORE"

if [ "$KEEP" = "1" ]; then echo "    (network left running)"; else lncmd stop; fi
echo "======================================================================"
printf 'RESULT: \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n' "$pass" "$fail"
echo "======================================================================"
[ "$fail" -eq 0 ]
