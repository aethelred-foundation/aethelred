#!/usr/bin/env bash
#
# scripts/dapp-endpoints.sh — open a node's dApp/wallet-facing endpoints.
#
# By default a node exposes only CometBFT RPC (26657) and gRPC (9090), with the
# REST API and all CORS turned OFF — so a browser dApp or wallet cannot connect.
# This script patches a node's config so local dApps (Cruzible, ZeroID, the
# wallet, …) can reach it, and prints the connection settings a dApp needs.
#
# Usage:
#   scripts/dapp-endpoints.sh [HOME_DIR]        # default: $HOME/.aethelredd
#   PUBLIC=1 scripts/dapp-endpoints.sh <HOME>   # bind 0.0.0.0 for a public host
#
# For a localnet, run it against each node home (per-node ports are base+100*i):
#   for i in 0 1 2 3; do scripts/dapp-endpoints.sh ~/.aethelred-localnet/node$i; done
#
# Restart the node afterward for the changes to take effect.
#
set -euo pipefail

HOME_DIR="${1:-$HOME/.aethelredd}"
PUBLIC="${PUBLIC:-0}"
APP="$HOME_DIR/config/app.toml"
CFG="$HOME_DIR/config/config.toml"
[ -f "$APP" ] || { echo "no app.toml at $APP — run 'aethelredd init' / scripts/testnet.sh init first"; exit 1; }

bind_api="tcp://localhost:1317"; bind_grpc="localhost:9090"; rpc_bind="tcp://127.0.0.1:26657"
if [ "$PUBLIC" = "1" ]; then bind_api="tcp://0.0.0.0:1317"; bind_grpc="0.0.0.0:9090"; rpc_bind="tcp://0.0.0.0:26657"; fi

# app.toml: enable REST API + swagger + (dev) CORS. The only `enable = false` is
# under [api]; [grpc] and [grpc-web] are already true.
sed -i.bak \
  -e 's|^enable = false|enable = true|' \
  -e 's|^swagger = false|swagger = true|' \
  -e 's|^enabled-unsafe-cors = false|enabled-unsafe-cors = true|' \
  -e "s|^address = \"tcp://localhost:1317\"|address = \"$bind_api\"|" \
  -e "s|^address = \"localhost:9090\"|address = \"$bind_grpc\"|" \
  "$APP"
rm -f "$APP.bak"

# config.toml: allow browser origins to reach CometBFT RPC (26657).
sed -i.bak \
  -e 's|^cors_allowed_origins = \[\]|cors_allowed_origins = ["*"]|' \
  "$CFG"
if [ "$PUBLIC" = "1" ]; then
  sed -i.bak2 -e 's|^laddr = "tcp://127.0.0.1:26657"|laddr = "tcp://0.0.0.0:26657"|' "$CFG"
fi
rm -f "$CFG.bak" "$CFG.bak2"

rpc=$(grep -m1 '^laddr = "tcp://' "$CFG" | grep -oE '[0-9]+$')
api=$(grep -m1 '^address = "tcp://' "$APP" | grep -oE '[0-9]+"' | tr -d '"')
grpc=$(grep -A3 '^\[grpc\]' "$APP" | grep -m1 '^address' | grep -oE '[0-9]+"' | tr -d '"')
host="127.0.0.1"; [ "$PUBLIC" = "1" ] && host="<your-public-host>"

cat <<EOF

>>> dApp endpoints enabled for $HOME_DIR $([ "$PUBLIC" = "1" ] && echo "(PUBLIC bind)")
    Restart the node for changes to take effect.

    Connection settings for a dApp / wallet:
      chain-id            : $(grep -m1 '"chain_id"' "$HOME_DIR/config/genesis.json" | sed 's/.*: *"//;s/".*//')
      RPC   (CometBFT)    : http://$host:$rpc
      REST  (LCD/API)     : http://$host:$api        (swagger at /swagger/)
      gRPC                : $host:$grpc
      gRPC-web            : enabled (same LCD host)
      bech32 prefix       : aethel  (val: aethelvaloper, cons: aethelvalcons)
      base denom          : uaethel   (display: aethel, 6 decimals)
      coin type (HD path) : 118

EOF
if [ "$PUBLIC" = "1" ]; then
  echo "    PUBLIC checklist: put TLS + a reverse proxy in front of 1317/26657,"
  echo "    open only the ports you intend to expose, and prefer a per-origin CORS"
  echo "    allowlist over \"*\" once your dApp origins are known."
  echo
fi
