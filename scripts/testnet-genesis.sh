#!/usr/bin/env bash
#
# scripts/testnet-genesis.sh — DISTRIBUTED testnet genesis + validator key
# generator.
#
# localnet.sh provisions N validators on a single machine; this script
# generates the complete genesis and per-server deployment bundles for a
# distributed testnet in which each validator runs on its own server
# (IP:port supplied by the operator). Relaunching the testnet requires only
# re-running this script: key generation, genesis composition, and peer
# configuration are fully automated and reproducible.
#
# What it produces (in --out):
#   <name>/                 one deployable node home PER validator (keys,
#                           genesis, config wired with persistent_peers +
#                           external_address for the given IPs)
#   accounts-keyring/       keyring holding the non-validator genesis
#                           accounts (faucet, deployers, treasury, ...)
#   secrets/                key mnemonics, chmod 600 — BACK UP THEN DELETE
#   accounts-manifest.csv   every genesis account: name, category,
#                           aethel1... address, 0x EVM view, balance
#   DEPLOY.txt              per-server copy + start instructions
#
# Usage:
#   scripts/testnet-genesis.sh --validators validators.txt \
#     [--accounts testnet-genesis-accounts.csv] [--out DIR] \
#     [--chain-id aethelred-testnet-1] [--zero-inflation] [--force]
#
# validators.txt format (one per line; '#' comments allowed):
#   <name> <public-ip-or-dns> [p2p-port]        # port defaults to 26656
#   validator-1 203.0.113.10
#   validator-2 203.0.113.20 26656
#
# LOCAL DRY-RUN: give every validator the same IP (127.0.0.1) and the script
# detects the co-location and offsets each node's service ports (base + 100*n),
# producing a runnable local multi-node testnet from the SAME bundle logic the
# distributed deployment uses — so a genesis set can be booted and block
# production confirmed on one machine before shipping to real servers.
#
# Accounts CSV: the allocation sheet (config/testnet-genesis-accounts.csv
# in the main repo). Rows whose "Genesis coin string" ends in the denom are
# funded; validator-named rows fund that validator's operator key; every
# other row gets a fresh key in accounts-keyring. Rows marked "do NOT
# add-genesis-account" (module-minted supply) are skipped by construction.
# Rows marked "Fee-sponsored: Yes" additionally receive a genesis x/feegrant
# BasicAllowance from the treasury (FEEGRANT_GRANTER / FEEGRANT_SPEND_LIMIT),
# so sponsored clients can transact with zero balance of their own.
#
# Design notes (all verified against the chain):
#   - Every key is created with --algo eth_secp256k1 (coin-type 60) so each
#     account works on BOTH faces: native aethel1... AND the EVM 0x view.
#     A vanilla-algo key's funds would be EVM-stranded.
#   - Genesis is composed in uaethel (6-dec bank denom). The EVM face shows
#     the same balances 18-dec via x/precisebank — never fund "the EVM
#     side"; there isn't one.
#   - PoUW participation requires >= 100,000 AETHEL BONDED per validator
#     (x/pouw stake_security.go). The script warns if a self-bond is below.
#   - --zero-inflation implements the fixed-supply model (x/mint params to
#     zero); without it the chain inflates 7-20%/yr toward 67% bonded.
#
set -euo pipefail

BINARY="${BINARY:-./build/aethelredd}"
CHAIN_ID="aethelred-testnet-1"
DENOM="${DENOM:-uaethel}"
MIN_GAS_PRICES="${MIN_GAS_PRICES:-0.001uaethel}"
KEYRING="${KEYRING:-test}"
# Used only for validators absent from the accounts CSV.
DEFAULT_VALIDATOR_FUNDING="${DEFAULT_VALIDATOR_FUNDING:-150000000000}" # 150k AETHEL
DEFAULT_SELF_BOND="${DEFAULT_SELF_BOND:-120000000000}"                 # 120k AETHEL
POUW_MIN_BOND_UAETHEL=100000000000                                     # 100k AETHEL (hardcoded chain-side)
# Genesis x/feegrant for rows marked "Fee-sponsored: Yes" in the accounts CSV.
FEEGRANT_GRANTER="${FEEGRANT_GRANTER:-treasury}"           # granter key name (must be a CSV row)
FEEGRANT_SPEND_LIMIT="${FEEGRANT_SPEND_LIMIT:-1000000000}" # 1k AETHEL gas budget per grantee

VALIDATORS_FILE=""
ACCOUNTS_CSV=""
OUT_DIR=""
ZERO_INFLATION=0
FORCE=0

while [ $# -gt 0 ]; do
	case "$1" in
	--validators) VALIDATORS_FILE="$2"; shift 2 ;;
	--accounts) ACCOUNTS_CSV="$2"; shift 2 ;;
	--out) OUT_DIR="$2"; shift 2 ;;
	--chain-id) CHAIN_ID="$2"; shift 2 ;;
	--zero-inflation) ZERO_INFLATION=1; shift ;;
	--force) FORCE=1; shift ;;
	*) echo "unknown flag: $1"; exit 2 ;;
	esac
done

[ -n "$VALIDATORS_FILE" ] || { echo "--validators <file> is required"; exit 2; }
[ -f "$VALIDATORS_FILE" ] || { echo "validators file not found: $VALIDATORS_FILE"; exit 2; }
[ -z "$ACCOUNTS_CSV" ] || [ -f "$ACCOUNTS_CSV" ] || { echo "accounts csv not found: $ACCOUNTS_CSV"; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 2; }

# Resolve binary (PATH, ./build, as-given).
if command -v "$BINARY" >/dev/null 2>&1; then BIN="$BINARY"
elif [ -x "$BINARY" ]; then BIN="$BINARY"
else echo "aethelredd binary not found at '$BINARY' (build with: go build -o build/aethelredd ./cmd/aethelredd)"; exit 2; fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

OUT_DIR="${OUT_DIR:-testnet-artifacts-$(date +%Y%m%d-%H%M%S)}"
if [ -e "$OUT_DIR" ] && [ "$FORCE" -ne 1 ]; then
	echo "output dir '$OUT_DIR' exists — refusing to overwrite key material (use --force)"
	exit 2
fi
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/secrets" "$OUT_DIR/gentxs"
chmod 700 "$OUT_DIR/secrets"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

log() { printf '\033[1;36m>>> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!!! %s\033[0m\n' "$*"; }

# ── parse validators file ────────────────────────────────────────────────
V_NAMES=() V_IPS=() V_PORTS=()
while read -r name ip port _; do
	case "$name" in ''|\#*) continue ;; esac
	V_NAMES+=("$name"); V_IPS+=("$ip"); V_PORTS+=("${port:-26656}")
done <"$VALIDATORS_FILE"
N=${#V_NAMES[@]}
[ "$N" -ge 1 ] || { echo "no validators parsed from $VALIDATORS_FILE"; exit 2; }
log "validators: $N ($(printf '%s ' "${V_NAMES[@]}"))"
[ "$N" -ge 4 ] || warn "$N validator(s) < 4: no fault tolerance (BFT tolerates floor((N-1)/3) down)"

# ── service ports, co-location aware ─────────────────────────────────────
# Each node needs distinct P2P/RPC/gRPC/LCD/EVM-RPC/pprof ports only when it
# shares a host with another node. Nodes on unique IPs keep the standard
# ports (26656/26657/9090/1317/8545) — what a one-node-per-server deployment
# wants. When an IP repeats (e.g. every validator on 127.0.0.1 for a local
# multi-node run), the Nth node on that IP is offset by 100*N, matching
# localnet.sh's convention, so the whole set runs on one machine.
P2P_BASE=26656 RPC_BASE=26657 GRPC_BASE=9090 API_BASE=1317 EVMRPC_BASE=8545 PPROF_BASE=6060
V_P2P=() V_RPC=() V_GRPC=() V_API=() V_EVMRPC=() V_PPROF=() V_OFFSET=()
COLOCATED=0
# bash 3.2 has no associative arrays; count earlier occurrences by scanning.
for i in $(seq 0 $((N - 1))); do
	ip="${V_IPS[$i]}"
	localidx=0
	for (( j=0; j<i; j++ )); do [ "${V_IPS[$j]}" = "$ip" ] && localidx=$((localidx + 1)); done
	off=$((100 * localidx))
	[ "$localidx" -gt 0 ] && COLOCATED=1
	V_OFFSET+=("$off")
	# Honor an explicit p2p port only for the first node on its IP; co-located
	# peers follow the offset scheme so they cannot collide.
	if [ "$localidx" -eq 0 ]; then V_P2P+=("${V_PORTS[$i]}"); else V_P2P+=("$((P2P_BASE + off))"); fi
	V_RPC+=("$((RPC_BASE + off))")
	V_GRPC+=("$((GRPC_BASE + off))")
	V_API+=("$((API_BASE + off))")
	V_EVMRPC+=("$((EVMRPC_BASE + off))")
	V_PPROF+=("$((PPROF_BASE + off))")
done
[ "$COLOCATED" -eq 1 ] && log "co-located nodes detected (shared IP) — offsetting service ports per host"

# ── helper: create an eth_secp256k1 key, persist its mnemonic secret ─────
# Prints the bech32 address on stdout.
make_key() { # <keyname> <keyring-home>
	local out
	out="$("$BIN" keys add "$1" --algo eth_secp256k1 --keyring-backend "$KEYRING" \
		--home "$2" --output json 2>&1)"
	printf '%s' "$out" >"$OUT_DIR/secrets/$1.json"
	chmod 600 "$OUT_DIR/secrets/$1.json"
	printf '%s' "$out" | python3 -c 'import sys,json;print(json.load(sys.stdin)["address"])'
}

# ── 1. init every validator home + operator key + node id ───────────────
V_ADDRS=() V_NODEIDS=()
for i in $(seq 0 $((N - 1))); do
	name="${V_NAMES[$i]}" home="$OUT_DIR/${V_NAMES[$i]}"
	log "init $name"
	"$BIN" init "$name" --chain-id "$CHAIN_ID" --default-denom "$DENOM" --home "$home" >/dev/null 2>&1
	V_ADDRS+=("$(make_key "$name" "$home")")
	# comet show-node-id prints to STDERR (known gotcha) — capture both.
	V_NODEIDS+=("$("$BIN" comet show-node-id --home "$home" 2>&1 | grep -oE '[0-9a-f]{40}' | head -1)")
done

COMPOSER="$OUT_DIR/${V_NAMES[0]}"

# ── 2. patch the composer genesis (dev/testnet flags + optional policy) ──
log "patch genesis: allow_simulated, vote extensions${ZERO_INFLATION:+, zero inflation}"
python3 - "$COMPOSER/config/genesis.json" "$ZERO_INFLATION" <<'PYEOF'
import json, sys
path, zero_inflation = sys.argv[1], sys.argv[2] == "1"
g = json.load(open(path))
# No-hardware testnet: simulated TEE/zkML verification (NOT for production).
for mod in ("pouw", "verify"):
    params = g["app_state"].get(mod, {}).get("params")
    if isinstance(params, dict) and "allow_simulated" in params:
        params["allow_simulated"] = True
# PoUW verification -> Digital Seal pipeline runs in vote extensions.
g["consensus"]["params"]["abci"]["vote_extensions_enable_height"] = "1"
if zero_inflation:
    # Fixed-supply model: stakers earn from fees + the PoUW work pool.
    p = g["app_state"]["mint"]["params"]
    p["inflation_rate_change"] = "0.000000000000000000"
    p["inflation_max"] = "0.000000000000000000"
    p["inflation_min"] = "0.000000000000000000"
    g["app_state"]["mint"]["minter"]["inflation"] = "0.000000000000000000"
json.dump(g, open(path, "w"), indent=1)
PYEOF

# ── 3. fund genesis accounts ─────────────────────────────────────────────
# Emits per-account lines "name|category|coin" from the CSV (rows whose coin
# string ends in the denom; module-minted / TOTAL / CHECK rows skipped), and
# per-validator self-bond overrides "BOND|name|uaethel".
ACCOUNTS_KEYRING="$OUT_DIR/accounts-keyring"
declare -a M_NAMES=() M_CATS=() M_ADDRS=() M_COINS=()
declare -a SPONSORED_NAMES=() SPONSORED_ADDRS=()
declare -a V_BONDS=()
for i in $(seq 0 $((N - 1))); do V_BONDS+=("$DEFAULT_SELF_BOND"); done

fund() { # <name> <category> <address> <coin>
	"$BIN" genesis add-genesis-account "$3" "$4" --home "$COMPOSER" >/dev/null 2>&1 ||
		"$BIN" add-genesis-account "$3" "$4" --home "$COMPOSER"
	M_NAMES+=("$1"); M_CATS+=("$2"); M_ADDRS+=("$3"); M_COINS+=("$4")
}

if [ -n "$ACCOUNTS_CSV" ]; then
	log "funding accounts from $(basename "$ACCOUNTS_CSV")"
	while IFS='|' read -r name category coin bond sponsored; do
		vidx=-1
		for i in $(seq 0 $((N - 1))); do
			[ "${V_NAMES[$i]}" = "$name" ] && vidx=$i && break
		done
		if [ "$vidx" -ge 0 ]; then
			fund "$name" "$category" "${V_ADDRS[$vidx]}" "$coin"
			[ -n "$bond" ] && V_BONDS[$vidx]="$bond"
			addr="${V_ADDRS[$vidx]}"
		else
			addr="$(make_key "$name" "$ACCOUNTS_KEYRING")"
			fund "$name" "$category" "$addr" "$coin"
		fi
		if [ "$sponsored" = "Yes" ]; then
			SPONSORED_NAMES+=("$name"); SPONSORED_ADDRS+=("$addr")
		fi
	done < <(python3 - "$ACCOUNTS_CSV" "$DENOM" <<'PYEOF'
import csv, sys
path, denom = sys.argv[1], sys.argv[2]
for row in list(csv.reader(open(path)))[1:]:
    if len(row) < 10 or not row[0].strip().isdigit():
        continue
    name, category, coin, bond = row[1].strip(), row[2].strip(), row[8].strip(), row[9].strip()
    if not coin.endswith(denom):
        continue  # module-minted rows ("do NOT add-genesis-account") etc.
    bond_u = str(int(bond) * 10**6) if bond.isdigit() else ""
    sponsored = row[10].strip() if len(row) > 10 else ""
    print(f"{name}|{category}|{coin}|{bond_u}|{sponsored}")
PYEOF
	)
	# Validators in the file but absent from the CSV still need funding.
	for i in $(seq 0 $((N - 1))); do
		found=0
		for j in "${!M_NAMES[@]}"; do [ "${M_NAMES[$j]}" = "${V_NAMES[$i]}" ] && found=1 && break; done
		if [ "$found" -eq 0 ]; then
			warn "validator ${V_NAMES[$i]} not in accounts CSV — funding default ${DEFAULT_VALIDATOR_FUNDING}${DENOM}"
			fund "${V_NAMES[$i]}" "Validator" "${V_ADDRS[$i]}" "${DEFAULT_VALIDATOR_FUNDING}${DENOM}"
		fi
	done
else
	log "no accounts CSV — funding validators only (${DEFAULT_VALIDATOR_FUNDING}${DENOM} each)"
	for i in $(seq 0 $((N - 1))); do
		fund "${V_NAMES[$i]}" "Validator" "${V_ADDRS[$i]}" "${DEFAULT_VALIDATOR_FUNDING}${DENOM}"
	done
fi

# ── 3b. feegrant allowances for fee-sponsored accounts ───────────────────
# Rows marked "Fee-sponsored: Yes" in the allocation sheet get a genesis
# x/feegrant BasicAllowance from the treasury: they can transact (pay gas)
# with ZERO spendable balance of their own — the zero-balance client UX.
# The allowance caps the treasury's exposure per grantee.
if [ ${#SPONSORED_ADDRS[@]} -gt 0 ]; then
	granter=""
	for j in "${!M_NAMES[@]}"; do
		[ "${M_NAMES[$j]}" = "$FEEGRANT_GRANTER" ] && granter="${M_ADDRS[$j]}" && break
	done
	if [ -z "$granter" ]; then
		warn "fee-sponsored rows present but granter '$FEEGRANT_GRANTER' not in accounts — skipping feegrant"
	else
		log "feegrant: $FEEGRANT_GRANTER sponsors ${#SPONSORED_ADDRS[@]} account(s) at ${FEEGRANT_SPEND_LIMIT}${DENOM} each (${SPONSORED_NAMES[*]})"
		python3 - "$COMPOSER/config/genesis.json" "$granter" "$FEEGRANT_SPEND_LIMIT" "$DENOM" "${SPONSORED_ADDRS[@]}" <<'PYEOF'
import json, sys
path, granter, limit, denom, grantees = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]
g = json.load(open(path))
fg = g["app_state"].setdefault("feegrant", {"allowances": []})
fg.setdefault("allowances", [])
existing = {(a["granter"], a["grantee"]) for a in fg["allowances"]}
for grantee in grantees:
    if (granter, grantee) in existing or grantee == granter:
        continue
    fg["allowances"].append({
        "granter": granter,
        "grantee": grantee,
        "allowance": {
            "@type": "/cosmos.feegrant.v1beta1.BasicAllowance",
            "spend_limit": [{"denom": denom, "amount": limit}],
            "expiration": None,
        },
    })
json.dump(g, open(path, "w"), indent=1)
PYEOF
	fi
fi

# ── 4. gentx per validator (with its PUBLIC ip:port), collect, validate ──
for i in $(seq 0 $((N - 1))); do
	name="${V_NAMES[$i]}" home="$OUT_DIR/$name"
	[ "${V_BONDS[$i]}" -ge "$POUW_MIN_BOND_UAETHEL" ] ||
		warn "$name self-bond ${V_BONDS[$i]}$DENOM < 100k AETHEL PoUW minimum — it will produce blocks but CANNOT join PoUW verification"
	[ "$home" = "$COMPOSER" ] || cp "$COMPOSER/config/genesis.json" "$home/config/genesis.json"
	log "gentx $name (bond ${V_BONDS[$i]}$DENOM, peer ${V_IPS[$i]}:${V_P2P[$i]})"
	"$BIN" gentx "$name" "${V_BONDS[$i]}$DENOM" --chain-id "$CHAIN_ID" \
		--keyring-backend "$KEYRING" --home "$home" \
		--ip "${V_IPS[$i]}" --p2p-port "${V_P2P[$i]}" >/dev/null 2>&1
	cp "$home/config/gentx/"*.json "$OUT_DIR/gentxs/"
done
mkdir -p "$COMPOSER/config/gentx"
cp "$OUT_DIR/gentxs/"*.json "$COMPOSER/config/gentx/"
log "collect gentxs + validate"
"$BIN" collect-gentxs --home "$COMPOSER" >/dev/null 2>&1
"$BIN" validate-genesis --home "$COMPOSER" >/dev/null

# ── 5. distribute final genesis + wire per-node config ──────────────────
for i in $(seq 0 $((N - 1))); do
	name="${V_NAMES[$i]}" home="$OUT_DIR/$name"
	[ "$home" = "$COMPOSER" ] || cp "$COMPOSER/config/genesis.json" "$home/config/genesis.json"

	peers=""
	for j in $(seq 0 $((N - 1))); do
		[ "$j" -eq "$i" ] && continue
		peers="${peers:+$peers,}${V_NODEIDS[$j]}@${V_IPS[$j]}:${V_P2P[$j]}"
	done
	cfg="$home/config/config.toml"
	/usr/bin/sed -i.bak \
		-e "s|^persistent_peers = .*|persistent_peers = \"$peers\"|" \
		-e "s|^external_address = .*|external_address = \"${V_IPS[$i]}:${V_P2P[$i]}\"|" \
		-e "s|^laddr = \"tcp://0.0.0.0:26656\"|laddr = \"tcp://0.0.0.0:${V_P2P[$i]}\"|" \
		-e "s|^laddr = \"tcp://127.0.0.1:26657\"|laddr = \"tcp://0.0.0.0:${V_RPC[$i]}\"|" \
		-e "s|^pprof_laddr = \".*\"|pprof_laddr = \"localhost:${V_PPROF[$i]}\"|" \
		"$cfg"
	# Co-located nodes share 127.0.0.1; CometBFT rejects duplicate peer IPs by
	# default, which prevents the mesh from forming. Relax only for the local
	# case — a distributed deployment keeps the secure defaults.
	if [ "$COLOCATED" -eq 1 ]; then
		/usr/bin/sed -i.bak4 \
			-e "s|^addr_book_strict = true|addr_book_strict = false|" \
			-e "s|^allow_duplicate_ip = false|allow_duplicate_ip = true|" \
			"$cfg"
	fi

	appcfg="$home/config/app.toml"
	/usr/bin/sed -i.bak \
		-e "s|^minimum-gas-prices = .*|minimum-gas-prices = \"$MIN_GAS_PRICES\"|" \
		-e "s|^address = \"localhost:9090\"|address = \"localhost:${V_GRPC[$i]}\"|" \
		"$appcfg"
	# Enable LCD (REST) — required for standard clients/wallet native path.
	/usr/bin/sed -i.bak2 '/^\[api\]/,/^\[/ s/^enable = false/enable = true/' "$appcfg"
	/usr/bin/sed -i.bak3 "/^\[api\]/,/^\[/ s|^address = \"tcp://localhost:1317\"|address = \"tcp://0.0.0.0:${V_API[$i]}\"|" "$appcfg"
	# EVM JSON-RPC (HTTP + WS) + real PQC (read via viper: app.toml sections).
	printf '\n[json-rpc]\nenable = true\naddress = "0.0.0.0:%s"\nws-address = "0.0.0.0:%s"\n\n[aethelred.pqc]\nenabled = true\nmode = "hybrid"\n' \
		"${V_EVMRPC[$i]}" "$((V_EVMRPC[i] + 1))" >>"$appcfg"
	rm -f "$home/config/"*.bak "$home/config/"*.bak2 "$home/config/"*.bak3 "$home/config/"*.bak4
done

# ── 6. manifest: every account, both faces, balances ─────────────────────
MANIFEST="$OUT_DIR/accounts-manifest.csv"
{
	echo "name,category,address_bech32,address_evm,balance"
	for j in "${!M_NAMES[@]}"; do
		evm="$(python3 -c "
CHARSET='qpzry9x8gf2tvdw0s3jn54khce6mua7l'
s='${M_ADDRS[$j]}'
hrp,data=s.rsplit('1',1)
vals=[CHARSET.index(c) for c in data][:-6]
acc=0;bits=0;out=[]
for v in vals:
    acc=(acc<<5)|v;bits+=5
    while bits>=8: bits-=8;out.append((acc>>bits)&0xff)
print('0x'+bytes(out).hex())
")"
		echo "${M_NAMES[$j]},${M_CATS[$j]},${M_ADDRS[$j]},$evm,${M_COINS[$j]}"
	done
} >"$MANIFEST"

# ── 7. deployment instructions ───────────────────────────────────────────
DEPLOY="$OUT_DIR/DEPLOY.txt"
{
	if [ "$COLOCATED" -eq 1 ]; then
		echo "Aethelred testnet — LOCAL multi-node run ($CHAIN_ID, $(date -u +%Y-%m-%dT%H:%M:%SZ))"
		echo
		echo "Nodes share a host; service ports are offset per node (base + 100*n)."
		echo "Start each in its own shell from $OUT_DIR:"
		for i in $(seq 0 $((N - 1))); do
			echo
			echo "  ${V_NAMES[$i]}  (${V_IPS[$i]})"
			echo "    AETHELRED_TEE_MODE=simulated aethelredd start --home ${V_NAMES[$i]}"
			echo "    p2p ${V_P2P[$i]}  rpc ${V_RPC[$i]}  lcd ${V_API[$i]}  grpc ${V_GRPC[$i]}  evm-rpc ${V_EVMRPC[$i]}"
		done
	else
		echo "Aethelred distributed testnet — deployment ($CHAIN_ID, $(date -u +%Y-%m-%dT%H:%M:%SZ))"
		echo
		echo "Per server (repeat for each validator):"
		for i in $(seq 0 $((N - 1))); do
			echo
			echo "  ${V_NAMES[$i]}  @ ${V_IPS[$i]}"
			echo "    rsync -a ${V_NAMES[$i]}/ user@${V_IPS[$i]}:~/.aethelredd/"
			echo "    AETHELRED_TEE_MODE=simulated aethelredd start --home ~/.aethelredd"
			echo "    open ports: ${V_P2P[$i]}/p2p ${V_RPC[$i]}/rpc ${V_API[$i]}/lcd ${V_EVMRPC[$i]}/evm-rpc (firewall lcd/evm as needed)"
		done
	fi
	echo
	echo "SECURITY:"
	echo "  - node homes contain priv_validator_key.json, node_key.json, and a"
	echo "    '$KEYRING' keyring with the operator key — treat each bundle as secret."
	echo "  - $OUT_DIR/secrets/ holds every mnemonic: back it up OFFLINE, then delete."
	echo "  - accounts-keyring/ holds the non-validator account keys (faucet,"
	echo "    deployers, treasury). Move treasury to a multisig before real value."
	echo
	echo "Chain identity: cosmos chain-id $CHAIN_ID, EVM chain-id 7332,"
	echo "denom $DENOM (6-dec; EVM face 18-dec via precisebank), min gas $MIN_GAS_PRICES."
	[ "$ZERO_INFLATION" -eq 1 ] && echo "Inflation: ZEROED (fixed-supply model)." ||
		echo "Inflation: DEFAULT COSMOS PARAMS (7-20%/yr) — pass --zero-inflation for fixed supply."
} >"$DEPLOY"

log "DONE"
echo
echo "  artifacts:   $OUT_DIR"
echo "  manifest:    $MANIFEST"
echo "  deploy plan: $DEPLOY"
echo
column -t -s, "$MANIFEST" | head -25
echo
cat "$DEPLOY"
