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

        # Configure for local testing
        sed -i 's/timeout_commit = "5s"/timeout_commit = "1s"/g' "$HOME_DIR/config/config.toml"
        sed -i 's/timeout_propose = "3s"/timeout_propose = "1s"/g' "$HOME_DIR/config/config.toml"

        # Enable API and unsafe CORS for development
        sed -i 's/enable = false/enable = true/g' "$HOME_DIR/config/app.toml"
        sed -i 's/enabled-unsafe-cors = false/enabled-unsafe-cors = true/g' "$HOME_DIR/config/app.toml"
        sed -i 's/cors_allowed_origins = \[\]/cors_allowed_origins = ["*"]/g' "$HOME_DIR/config/config.toml"

        log_info "Node initialized successfully"
    else
        log_info "Node already initialized"
    fi
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
        configure_seeds
        wait_for_genesis
        log_info "Starting Aethelred node..."
        exec aethelredd start --home "$HOME_DIR" "${@:2}"
        ;;
    "validate")
        init_node
        configure_seeds
        log_info "Starting Aethelred validator node..."
        exec aethelredd start --home "$HOME_DIR" --pruning="nothing" "${@:2}"
        ;;
    *)
        exec aethelredd "$@"
        ;;
esac
