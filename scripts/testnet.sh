#!/usr/bin/env bash
#
# scripts/testnet.sh — bootstrap and run a local single-node Aethelred testnet.
#
# Reproduces the full genesis bootstrap with CLI commands (no manual JSON edits
# beyond the one documented dev flag), so a chain can be brought up from scratch
# deterministically.
#
# Usage:
#   scripts/testnet.sh init     # bootstrap genesis only (idempotent; skips if present)
#   scripts/testnet.sh start    # bootstrap-if-needed, then run the node (foreground)
#   scripts/testnet.sh stop     # stop a running node
#   scripts/testnet.sh reset    # delete the home dir (DESTRUCTIVE)
#
# Override defaults via env, e.g.:
#   CHAIN_ID=aethelred-testnet-1 DENOM=uaethel HOME_DIR=$HOME/.aethelredd \
#     scripts/testnet.sh start
#
set -euo pipefail

BINARY="${BINARY:-aethelredd}"
CHAIN_ID="${CHAIN_ID:-aethelred-testnet-1}"
MONIKER="${MONIKER:-testnode}"
HOME_DIR="${HOME_DIR:-$HOME/.aethelredd}"
KEY_NAME="${KEY_NAME:-validator}"
KEYRING="${KEYRING:-test}"
DENOM="${DENOM:-uaethel}"
GENESIS_BALANCE="${GENESIS_BALANCE:-100000000000${DENOM}}" # 100,000 AETHEL
SELF_DELEGATION="${SELF_DELEGATION:-70000000000${DENOM}}"  # 70,000 AETHEL self-bond

# This is a NO-HARDWARE dev/testnet. Opt into simulated TEE/verification so the
# node starts without a real Nitro enclave / EZKL verifier endpoint.
# DO NOT use these settings for a production chain.
export AETHELRED_TEE_MODE="${AETHELRED_TEE_MODE:-simulated}"

# Resolve the binary: PATH, then ./build, then as-given.
if command -v "$BINARY" >/dev/null 2>&1; then BIN="$BINARY"
elif [ -x "./build/$BINARY" ]; then BIN="./build/$BINARY"
else BIN="$BINARY"; fi

log() { printf '\033[1;36m>>> %s\033[0m\n' "$*"; }

cmd_reset() {
	log "reset: removing $HOME_DIR"
	rm -rf "$HOME_DIR"
}

cmd_bootstrap() {
	if [ -f "$HOME_DIR/config/genesis.json" ] && [ -d "$HOME_DIR/config/gentx" ]; then
		log "already bootstrapped at $HOME_DIR (run '$0 reset' to start fresh)"
		return 0
	fi

	log "init chain $CHAIN_ID (denom $DENOM)"
	"$BIN" init "$MONIKER" --chain-id "$CHAIN_ID" --default-denom "$DENOM" --home "$HOME_DIR"

	# Enable simulated verification (dev/testnet only). The node's production
	# readiness check otherwise panics in BeginBlocker when zkML/TEE endpoints
	# are not configured. pouw.params and verify.params both carry the flag.
	log "enable simulated verification in genesis (dev/testnet only)"
	sed -i.bak 's/"allow_simulated": false/"allow_simulated": true/g' "$HOME_DIR/config/genesis.json"
	rm -f "$HOME_DIR/config/genesis.json.bak"

	# Enable REAL post-quantum crypto (Cloudflare circl ML-DSA-65 / ML-KEM-768
	# hybrid). The TEE/zkML verification stays simulated above (no hardware), but
	# validator signing and Digital Seals use genuine PQC.
	log "enable real PQC (hybrid) in app.toml"
	printf '\n[aethelred.pqc]\nenabled = true\nmode = "hybrid"\n' >>"$HOME_DIR/config/app.toml"

	log "create validator key '$KEY_NAME' ($KEYRING keyring)"
	"$BIN" keys add "$KEY_NAME" --keyring-backend "$KEYRING" --home "$HOME_DIR"
	local addr
	addr="$("$BIN" keys show "$KEY_NAME" -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"

	log "fund genesis account $addr ($GENESIS_BALANCE)"
	"$BIN" add-genesis-account "$addr" "$GENESIS_BALANCE" --home "$HOME_DIR"

	log "create genesis validator tx (self-bond $SELF_DELEGATION)"
	"$BIN" gentx "$KEY_NAME" "$SELF_DELEGATION" \
		--chain-id "$CHAIN_ID" --keyring-backend "$KEYRING" --home "$HOME_DIR"

	log "collect gentxs"
	"$BIN" collect-gentxs --home "$HOME_DIR"

	log "validate genesis"
	"$BIN" validate-genesis --home "$HOME_DIR"

	log "bootstrap complete: $HOME_DIR"
}

cmd_start() {
	cmd_bootstrap
	log "starting node (AETHELRED_TEE_MODE=$AETHELRED_TEE_MODE) — Ctrl-C to stop"
	exec "$BIN" start --home "$HOME_DIR" --minimum-gas-prices "0${DENOM}"
}

cmd_stop() {
	if pkill -f "$BIN start --home $HOME_DIR" 2>/dev/null; then
		log "stopped"
	else
		log "no running node found"
	fi
}

case "${1:-}" in
init) cmd_bootstrap ;;
start) cmd_start ;;
stop) cmd_stop ;;
reset) cmd_reset ;;
*)
	echo "usage: $0 {init|start|stop|reset}"
	exit 1
	;;
esac
