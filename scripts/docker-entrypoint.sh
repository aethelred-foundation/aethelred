#!/bin/bash
set -e

# Aethelred Docker Entrypoint Script
# This script initializes and starts an Aethelred node

CHAIN_ID="${CHAIN_ID:-aethelred-testnet-1}"
MONIKER="${MONIKER:-aethelred-node}"
SEEDS="${SEEDS:-}"
HOME_DIR="${HOME_DIR:-/home/aethelred/.aethelred}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Initialize node if not already initialized
init_node() {
    if [ ! -f "$HOME_DIR/config/config.toml" ]; then
        log_info "Initializing node with moniker: $MONIKER"
        aethelredd init "$MONIKER" --chain-id "$CHAIN_ID" --home "$HOME_DIR"

        # Faster blocks for local testing (one-time; safe to leave as-is on restart).
        sed -i 's/timeout_commit = "5s"/timeout_commit = "1s"/g' "$HOME_DIR/config/config.toml"
        sed -i 's/timeout_propose = "3s"/timeout_propose = "1s"/g' "$HOME_DIR/config/config.toml"

        log_info "Node initialized successfully"
    else
        log_info "Node already initialized"
    fi
}

# Apply endpoint/CORS configuration on EVERY start — idempotently.
#
# This MUST NOT live inside init_node's "first init only" branch: an
# already-initialised node (e.g. one that has deployed contracts) would then
# never receive these settings, so browser dApps hit the EVM JSON-RPC with no
# Access-Control-Allow-Origin and every request is blocked. The seds are
# key-anchored and force the value regardless of the current one, so re-running
# is a safe no-op.
#
# Set NODE_PUBLIC_ENDPOINTS=false to keep the API/JSON-RPC bound to localhost.
configure_node() {
    local app="$HOME_DIR/config/app.toml"
    local cfg="$HOME_DIR/config/config.toml"

    # ── EVM JSON-RPC + REST API: enable and open CORS ────────────────────────
    # The EVM JSON-RPC (:8545) reads its CORS from the [api] section
    # (cosmos/evm routes it through config.API.EnableUnsafeCORS). This is the
    # ONE setting that unblocks browser dApps; config.toml cors_allowed_origins
    # only covers the CometBFT RPC (:26657).
    sed -i -E 's/^enabled-unsafe-cors = .*/enabled-unsafe-cors = true/' "$app"
    # Enable the [api] and [json-rpc] servers (both use `enable = ...`).
    sed -i -E 's/^enable = false/enable = true/' "$app"
    # CometBFT RPC CORS (:26657) for completeness.
    sed -i -E 's/^cors_allowed_origins = \[\]/cors_allowed_origins = ["*"]/' "$cfg"

    # ── Bind endpoints so external browsers/dApps can reach them ─────────────
    if [ "${NODE_PUBLIC_ENDPOINTS:-true}" = "true" ]; then
        # EVM JSON-RPC + WS, and the cosmos REST API.
        sed -i -E 's|^address = "127.0.0.1:8545"|address = "0.0.0.0:8545"|' "$app"
        sed -i -E 's|^ws-address = "127.0.0.1:8546"|ws-address = "0.0.0.0:8546"|' "$app"
        sed -i -E 's|^address = "tcp://localhost:1317"|address = "tcp://0.0.0.0:1317"|' "$app"
        # CometBFT RPC laddr.
        sed -i -E 's|^laddr = "tcp://127.0.0.1:26657"|laddr = "tcp://0.0.0.0:26657"|' "$cfg"
    fi

    log_info "Node endpoints configured (EVM JSON-RPC CORS + bindings applied)"
}

# Configure seeds if provided
configure_seeds() {
    if [ -n "$SEEDS" ]; then
        log_info "Configuring seeds: $SEEDS"
        sed -i "s/seeds = \"\"/seeds = \"$SEEDS\"/g" "$HOME_DIR/config/config.toml"
    fi
}

# Wait for genesis file (for non-primary validators)
wait_for_genesis() {
    if [ -n "$GENESIS_URL" ]; then
        log_info "Waiting for genesis file from $GENESIS_URL"
        until curl -s "$GENESIS_URL" > "$HOME_DIR/config/genesis.json"; do
            log_warn "Genesis not ready, waiting..."
            sleep 5
        done
        log_info "Genesis file downloaded"
    fi
}

# Main execution
case "$1" in
    "init")
        init_node
        ;;
    "start")
        init_node
        configure_node
        configure_seeds
        wait_for_genesis
        log_info "Starting Aethelred node..."
        exec aethelredd start --home "$HOME_DIR" "${@:2}"
        ;;
    "validate")
        init_node
        configure_node
        configure_seeds
        log_info "Starting Aethelred validator node..."
        exec aethelredd start --home "$HOME_DIR" --pruning="nothing" "${@:2}"
        ;;
    *)
        exec aethelredd "$@"
        ;;
esac
