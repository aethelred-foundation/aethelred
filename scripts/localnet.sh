#!/usr/bin/env bash
#
# scripts/localnet.sh — bring up an N-validator Aethelred network on ONE machine.
#
# Each validator gets its own home dir and a unique set of ports, all sharing one
# genesis and wired as persistent peers. This is for testing the multi-node-only
# features locally before deploying validators across separate hosts: BFT
# consensus across validators, vote-extension aggregation, DKG-backed assignment,
# and the >=67% Digital Seal quorum.
#
# Usage:
#   scripts/localnet.sh init     # build genesis + config for N nodes (idempotent-ish)
#   scripts/localnet.sh start    # start all N nodes in the background
#   scripts/localnet.sh stop     # stop all nodes
#   scripts/localnet.sh status   # show each node's height
#   scripts/localnet.sh reset    # delete everything (DESTRUCTIVE)
#
# Key env overrides:
#   N=4 CHAIN_ID=aethelred-localnet-1 BASE_DIR=$HOME/.aethelred-localnet \
#     scripts/localnet.sh init
#
# Node i (0-based) uses port base + 100*i:
#   RPC 26657, 26757, 26857, ...   P2P 26656, 26756, ...   gRPC 9090, 9190, ...
#
set -euo pipefail

BINARY="${BINARY:-aethelredd}"
N="${N:-4}"
CHAIN_ID="${CHAIN_ID:-aethelred-localnet-1}"
DENOM="${DENOM:-uaethel}"
BASE_DIR="${BASE_DIR:-$HOME/.aethelred-localnet}"
KEYRING="${KEYRING:-test}"
GENESIS_BALANCE="${GENESIS_BALANCE:-500000000000${DENOM}}" # 500,000 AETHEL per validator
SELF_DELEGATION="${SELF_DELEGATION:-150000000000${DENOM}}" # 150,000 AETHEL self-bond (> 100k PoUW min)

# Port bases (node i = base + 100*i).
P2P_BASE=26656; RPC_BASE=26657; GRPC_BASE=9090; API_BASE=1317; PPROF_BASE=6060

export AETHELRED_TEE_MODE="${AETHELRED_TEE_MODE:-simulated}"

if command -v "$BINARY" >/dev/null 2>&1; then BIN="$BINARY"
elif [ -x "./build/$BINARY" ]; then BIN="./build/$BINARY"
else BIN="$BINARY"; fi

log() { printf '\033[1;36m>>> %s\033[0m\n' "$*"; }
home_i() { echo "$BASE_DIR/node$1"; }
port()   { echo $(( $2 + 100 * $1 )); } # port <i> <base>

cmd_reset() { log "reset: removing $BASE_DIR"; rm -rf "$BASE_DIR"; }

cmd_init() {
	if [ -f "$BASE_DIR/node0/config/genesis.json" ]; then
		log "already initialized at $BASE_DIR (run '$0 reset' first)"; return 0
	fi
	mkdir -p "$BASE_DIR"

	# 1) init each node + create its validator key
	local addrs=()
	for i in $(seq 0 $((N-1))); do
		local h; h="$(home_i "$i")"
		log "init node$i ($h)"
		"$BIN" init "node$i" --chain-id "$CHAIN_ID" --default-denom "$DENOM" --home "$h" >/dev/null 2>&1
		"$BIN" keys add "val$i" --keyring-backend "$KEYRING" --home "$h" >/dev/null 2>&1
		addrs+=("$("$BIN" keys show "val$i" -a --keyring-backend "$KEYRING" --home "$h")")
	done

	# 2) fund every validator account in node0's genesis
	local g0; g0="$(home_i 0)"
	for i in $(seq 0 $((N-1))); do
		log "fund ${addrs[$i]} ($GENESIS_BALANCE)"
		"$BIN" add-genesis-account "${addrs[$i]}" "$GENESIS_BALANCE" --home "$g0" >/dev/null
	done

	# 3) enable simulated verification (dev) in node0 genesis, then share it so
	#    every node's gentx validates against the funded genesis.
	sed -i.bak 's/"allow_simulated": false/"allow_simulated": true/g' "$g0/config/genesis.json"
	# Enable ABCI++ vote extensions. The PoUW verification → Digital Seal pipeline
	# runs entirely in ExtendVote/VerifyVoteExtension, which CometBFT only invokes
	# when vote_extensions_enable_height > 0. Left at 0, jobs are assigned but never
	# verified or sealed.
	sed -i.bak 's/"vote_extensions_enable_height": "0"/"vote_extensions_enable_height": "1"/' "$g0/config/genesis.json"
	rm -f "$g0/config/genesis.json.bak"
	for i in $(seq 1 $((N-1))); do cp "$g0/config/genesis.json" "$(home_i "$i")/config/genesis.json"; done

	# 4) each node creates its gentx; collect them all into node0
	for i in $(seq 0 $((N-1))); do
		log "gentx node$i (self-bond $SELF_DELEGATION)"
		"$BIN" gentx "val$i" "$SELF_DELEGATION" --chain-id "$CHAIN_ID" \
			--keyring-backend "$KEYRING" --home "$(home_i "$i")" >/dev/null 2>&1
	done
	mkdir -p "$g0/config/gentx"
	for i in $(seq 1 $((N-1))); do cp "$(home_i "$i")"/config/gentx/*.json "$g0/config/gentx/"; done
	log "collect-gentxs ($N validators)"
	"$BIN" collect-gentxs --home "$g0" >/dev/null 2>&1
	"$BIN" validate-genesis --home "$g0" >/dev/null

	# 5) distribute the final genesis to every node
	for i in $(seq 1 $((N-1))); do cp "$g0/config/genesis.json" "$(home_i "$i")/config/genesis.json"; done

	# 6) build the persistent_peers string: <nodeID>@127.0.0.1:<p2p>
	# Note: `comet show-node-id` prints the ID to stderr, so capture both streams
	# and extract the 40-char hex node ID explicitly.
	local peers=""
	for i in $(seq 0 $((N-1))); do
		local raw id p
		raw="$("$BIN" comet show-node-id --home "$(home_i "$i")" 2>&1 || true)"
		id="$(printf '%s' "$raw" | grep -oE '[0-9a-f]{40}' | head -1 || true)"
		if [ -z "$id" ]; then echo "ERROR: could not resolve node$i ID from: $raw" >&2; exit 1; fi
		p="$(port "$i" "$P2P_BASE")"
		peers+="${peers:+,}${id}@127.0.0.1:${p}"
	done

	# 7) per-node config: ports, peers, same-host p2p relaxations, real PQC
	for i in $(seq 0 $((N-1))); do
		local h cfg app
		h="$(home_i "$i")"; cfg="$h/config/config.toml"; app="$h/config/app.toml"
		local p2p rpc grpc api pprof
		p2p="$(port "$i" "$P2P_BASE")"; rpc="$(port "$i" "$RPC_BASE")"
		grpc="$(port "$i" "$GRPC_BASE")"; api="$(port "$i" "$API_BASE")"; pprof="$(port "$i" "$PPROF_BASE")"

		sed -i.bak -E \
			-e "s|^laddr = \"tcp://127.0.0.1:26657\"|laddr = \"tcp://127.0.0.1:${rpc}\"|" \
			-e "s|^laddr = \"tcp://0.0.0.0:26656\"|laddr = \"tcp://0.0.0.0:${p2p}\"|" \
			-e "s|^pprof_laddr = \".*\"|pprof_laddr = \"localhost:${pprof}\"|" \
			-e "s|^persistent_peers = \".*\"|persistent_peers = \"${peers}\"|" \
			-e "s|^addr_book_strict = true|addr_book_strict = false|" \
			-e "s|^allow_duplicate_ip = false|allow_duplicate_ip = true|" \
			-e "s|^create_empty_blocks = false|create_empty_blocks = true|" \
			-e "s|^prometheus = true|prometheus = false|" \
			"$cfg"
		rm -f "$cfg.bak"

		sed -i.bak -E \
			-e "s|^minimum-gas-prices = \".*\"|minimum-gas-prices = \"0${DENOM}\"|" \
			-e "s|^address = \"localhost:9090\"|address = \"localhost:${grpc}\"|" \
			-e "s|^address = \"tcp://localhost:1317\"|address = \"tcp://localhost:${api}\"|" \
			"$app"
		rm -f "$app.bak"
		printf '\n[aethelred.pqc]\nenabled = true\nmode = "hybrid"\n' >>"$app"
	done

	log "init complete: $N validators in $BASE_DIR"
	log "consensus threshold is 67%; a Digital Seal needs ceil($N*0.67) = $(( (N*67 + 99) / 100 )) validators to agree"
}

cmd_start() {
	[ -f "$BASE_DIR/node0/config/genesis.json" ] || { log "not initialized; run '$0 init'"; exit 1; }
	for i in $(seq 0 $((N-1))); do
		local h rpc; h="$(home_i "$i")"; rpc="$(port "$i" "$RPC_BASE")"
		log "start node$i (rpc :$rpc, log $h/node.log)"
		AETHELRED_TEE_MODE="$AETHELRED_TEE_MODE" nohup "$BIN" start --home "$h" \
			--minimum-gas-prices "0${DENOM}" >"$h/node.log" 2>&1 &
	done
	log "all $N nodes starting; check with '$0 status'"
}

cmd_stop() {
	for i in $(seq 0 $((N-1))); do pkill -f "start --home $(home_i "$i")" 2>/dev/null || true; done
	log "stopped"
}

cmd_status() {
	for i in $(seq 0 $((N-1))); do
		local rpc; rpc="$(port "$i" "$RPC_BASE")"
		local h; h="$(curl -s --max-time 2 "http://127.0.0.1:${rpc}/status" 2>/dev/null \
			| sed -n 's/.*"latest_block_height":"\([0-9]*\)".*/\1/p' | head -1)"
		printf '  node%s  rpc :%s  height %s\n' "$i" "$rpc" "${h:-DOWN}"
	done
}

case "${1:-}" in
init)   cmd_init ;;
start)  cmd_start ;;
stop)   cmd_stop ;;
status) cmd_status ;;
reset)  cmd_stop 2>/dev/null || true; cmd_reset ;;
*) echo "usage: $0 {init|start|stop|status|reset}   (N=$N validators)"; exit 1 ;;
esac
