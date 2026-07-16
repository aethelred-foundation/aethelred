#!/usr/bin/env bash
#
# scripts/faucet.sh — send testnet AETHEL to any recipient, given either address
# form.
#
# Aethelred accounts have one identity with two renderings: the EVM `0x…` hex
# and the native `aethel1…` bech32. The bank module (`tx bank send`) requires
# the bech32 form; a wallet usually shows the `0x…`. This helper accepts either
# and converts a `0x…` recipient to `aethel1…` automatically before sending.
#
# Usage:
#   scripts/faucet.sh <recipient-0x-or-aethel1> [amount-uaethel]
#
# Examples:
#   scripts/faucet.sh 0xDF59bAC6DEF0EaCcf804C2D77a9f42f9c82690eB
#   scripts/faucet.sh aethel1mavm43k77r4ve7qyctth486zl8yzdy8t4kchw2 5000000000
#
# Env (override as needed):
#   BINARY        aethelredd binary            (default: ./build/aethelredd)
#   KEYRING_HOME  home holding the faucet key  (default: testnet-bundle/accounts-keyring)
#   FAUCET_KEY    faucet key name              (default: faucet)
#   CHAIN_ID      cosmos chain id              (default: aethelred-testnet-1)
#   NODE          CometBFT RPC of any validator(default: tcp://54.165.44.130:26657)
#   AMOUNT        default drip in uaethel      (default: 1000000000 = 1000 AETHEL)
#   FEES          tx fee                       (default: 5000uaethel)
#
set -euo pipefail

BINARY="${BINARY:-./build/aethelredd}"
KEYRING_HOME="${KEYRING_HOME:-testnet-bundle/accounts-keyring}"
FAUCET_KEY="${FAUCET_KEY:-faucet}"
CHAIN_ID="${CHAIN_ID:-aethelred-testnet-1}"
NODE="${NODE:-tcp://54.165.44.130:26657}"
FEES="${FEES:-5000uaethel}"

RECIPIENT="${1:-}"
AMOUNT="${2:-${AMOUNT:-1000000000}}"

if [ -z "$RECIPIENT" ]; then
	echo "usage: $0 <recipient-0x-or-aethel1> [amount-uaethel]"
	exit 2
fi
command -v python3 >/dev/null || { echo "python3 is required"; exit 2; }

if command -v "$BINARY" >/dev/null 2>&1; then BIN="$BINARY"
elif [ -x "$BINARY" ]; then BIN="$BINARY"
else echo "aethelredd not found at '$BINARY' (set BINARY=...)"; exit 2; fi

# Convert a 0x… address to aethel1…; pass an aethel1… through unchanged.
to_bech32() {
	python3 - "$1" <<'PY'
import sys
addr = sys.argv[1].strip()
if addr.startswith(("aethel1",)):
    print(addr); sys.exit(0)
if not (addr.startswith(("0x","0X")) and len(addr) == 42):
    sys.stderr.write(f"not a recognizable 0x or aethel1 address: {addr}\n"); sys.exit(1)
raw = bytes.fromhex(addr[2:])
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GEN = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
def polymod(values):
    chk = 1
    for v in values:
        b = chk >> 25; chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk
def convertbits(data, frm, to):
    acc = bits = 0; ret = []; maxv = (1 << to) - 1
    for b in data:
        acc = (acc << frm) | b; bits += frm
        while bits >= to:
            bits -= to; ret.append((acc >> bits) & maxv)
    if bits: ret.append((acc << (to - bits)) & maxv)
    return ret
hrp = "aethel"; data = convertbits(list(raw), 8, 5)
values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data
pm = polymod(values + [0]*6) ^ 1
checksum = [(pm >> 5*(5-i)) & 31 for i in range(6)]
print(hrp + "1" + "".join(CHARSET[d] for d in data + checksum))
PY
}

TO="$(to_bech32 "$RECIPIENT")"
echo ">>> recipient: $RECIPIENT"
[ "$TO" != "$RECIPIENT" ] && echo ">>> converted : $TO"
echo ">>> sending ${AMOUNT}uaethel from '$FAUCET_KEY' via $NODE"

OUT="$("$BIN" tx bank send "$FAUCET_KEY" "$TO" "${AMOUNT}uaethel" \
	--home "$KEYRING_HOME" --keyring-backend test \
	--chain-id "$CHAIN_ID" --node "$NODE" \
	--fees "$FEES" --yes --output json 2>&1)"

# The CLI reports CheckTx acceptance as "code": 0 with a txhash. A non-zero
# code (or a raw error) means the broadcast was rejected — surface it fully.
printf '%s' "$OUT" | python3 -c '
import sys, json
raw = sys.stdin.read()
try:
    d = json.loads(raw)
except Exception:
    sys.stderr.write(">>> broadcast failed:\n" + raw[:400] + "\n"); sys.exit(1)
code = d.get("code", -1)
sys.stdout.write(">>> broadcast code=%s txhash=%s\n" % (code, d.get("txhash", "")))
sys.exit(0 if code == 0 else 1)
'

echo ">>> sent. The recipient shows the amount as a native uaethel balance and,"
echo ">>> on the EVM face (eth_getBalance), the same value x 1e12 — precisebank"
echo ">>> presents one balance in both renderings; there is no separate EVM pool."
