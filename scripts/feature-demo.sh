#!/usr/bin/env bash
#
# scripts/feature-demo.sh — exercise Aethelred's headline features against a
# locally running single node.
#
# Prerequisites:
#   1. Build the binary:        go build -o build/aethelredd ./cmd/aethelredd
#   2. Bring up a local node:   scripts/testnet.sh start   (in another terminal)
#   3. Then run:                scripts/feature-demo.sh
#
# What it demonstrates:
#   A. Real hardware-agnostic TEE attestation verification (6 platforms)   [no chain needed]
#   B. Real BN254 Groth16 zkML proof verification (valid/tampered/off-curve)[no chain needed]
#   C. On-chain queries (validator PoUW status)
#   D. On-chain transactions: register-pcr0, register-model, submit-job
#
# Everything runs in the no-hardware dev/testnet profile (simulated TEE/zkML
# execution; REAL crypto for signing, attestation parsing, and pairing checks).
#
set -uo pipefail

BINARY="${BINARY:-aethelredd}"
CHAIN_ID="${CHAIN_ID:-aethelred-testnet-1}"
HOME_DIR="${HOME_DIR:-$HOME/.aethelredd}"
KEY_NAME="${KEY_NAME:-validator}"
KEYRING="${KEYRING:-test}"
DENOM="${DENOM:-uaethel}"
NODE="${NODE:-tcp://localhost:26657}"
FEES="${FEES:-200${DENOM}}"
GAS="${GAS:-400000}"

# Resolve the binary: PATH, then ./build, then as-given.
if command -v "$BINARY" >/dev/null 2>&1; then BIN="$BINARY"
elif [ -x "./build/$BINARY" ]; then BIN="./build/$BINARY"
else BIN="$BINARY"; fi

# Demo model/input identifiers (SHA-256 hashed to 32-byte handles by the CLI).
MODEL="${MODEL:-resnet50-v1}"
INPUT="${INPUT:-sample-batch-0}"
PROOF_TYPE="${PROOF_TYPE:-zkml}"
# A valid 64-hex-char (32-byte) PCR0 measurement for the demo.
PCR0_HEX="${PCR0_HEX:-$(printf 'ab%.0s' {1..32})}"

bold() { printf '\033[1;36m%s\033[0m\n' "$*"; }
rule() { printf '\033[2m%s\033[0m\n' "----------------------------------------------------------------------"; }
note() { printf '\033[2m%s\033[0m\n' "$*"; }

tx() { # tx <description> <args...>
	local desc="$1"; shift
	bold ">>> $desc"
	local out
	out="$("$BIN" "$@" \
		--from "$KEY_NAME" --keyring-backend "$KEYRING" --home "$HOME_DIR" \
		--chain-id "$CHAIN_ID" --node "$NODE" \
		--fees "$FEES" --gas "$GAS" --yes --output json 2>&1)"
	local hash
	hash="$(printf '%s' "$out" | sed -n 's/.*"txhash":"\([0-9A-F]*\)".*/\1/p' | head -1)"
	if [ -z "$hash" ]; then
		printf '  broadcast failed: %s\n' "$(printf '%s' "$out" | head -1)"
		return 1
	fi
	printf '  broadcast txhash: %s\n' "$hash"
	sleep 4
	"$BIN" query tx "$hash" --home "$HOME_DIR" --node "$NODE" --output json 2>/dev/null \
		| sed -n 's/.*"height":"\([0-9]*\)".*/  included at height \1/p' | head -1
	"$BIN" query tx "$hash" --home "$HOME_DIR" --node "$NODE" --output json 2>/dev/null \
		| sed -n 's/.*"code":\([0-9]*\).*/  result code \1 (0 = success)/p' | head -1
	rule
}

ADDR="$("$BIN" keys show "$KEY_NAME" -a --keyring-backend "$KEYRING" --home "$HOME_DIR" 2>/dev/null || true)"

echo "======================================================================"
bold "Aethelred feature demo"
echo "  binary:    $BIN"
echo "  chain-id:  $CHAIN_ID    node: $NODE"
echo "  validator: ${ADDR:-<keyring '$KEYRING' has no key '$KEY_NAME'>}"
echo "======================================================================"
rule

bold "[A] Real hardware-agnostic TEE attestation (6 platforms, no chain needed)"
note "AMD SEV-SNP, AWS Nitro, Intel TDX, Azure MAA, GCP Confidential Space, NVIDIA GPU."
note "Real COSE/JWT/binary parse + ECDSA/RSA + X.509 chain; tamper + vendor-root boundary."
go run ./cmd/aethelred-attestation-demo || note "(build cmd/aethelred-attestation-demo to run this)"
rule

bold "[B] Real BN254 Groth16 zkML proof verification (no chain needed)"
note "Live pairing check e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ)==1 with on-curve +"
note "prime-order-subgroup checks. Valid accepted; tampered + off-curve rejected."
go run ./cmd/aethelred-zkml-demo || note "(build cmd/aethelred-zkml-demo to run this)"
rule

bold "[C] On-chain query: validator PoUW readiness status"
if [ -n "$ADDR" ]; then
	"$BIN" query pouw status --validator "$ADDR" --home "$HOME_DIR" --node "$NODE" --output json 2>&1 | head -40
else
	note "(no validator key found; skipping)"
fi
rule

if [ -z "$ADDR" ]; then
	note "No signing key available — skipping transaction demos [D]."
	exit 0
fi

bold "[D] On-chain transactions"
note "Register an AWS Nitro PCR0 measurement for this validator."
tx "tx pouw register-pcr0 $PCR0_HEX" tx pouw register-pcr0 "$PCR0_HEX"

note "Confirm the PCR0 is now registered."
"$BIN" query pouw is-pcr0-registered "$PCR0_HEX" --home "$HOME_DIR" --node "$NODE" 2>&1 | head -5
rule

note "Register a model so jobs can target it (model hash = sha256('$MODEL'))."
tx "tx pouw register-model --model $MODEL --model-id resnet50 --name ResNet-50" \
	tx pouw register-model --model "$MODEL" --model-id resnet50 --name "ResNet-50" --architecture cnn

note "Submit a $PROOF_TYPE verification job against the registered model."
note "(Builds + signs + broadcasts a real MsgSubmitJob and persists it on chain"
note " as a Pending job. Assignment -> verification -> Digital Seal then requires"
note " a multi-node validator quorum — see docs/testnet/FEATURE_TESTING.md.)"
tx "tx pouw submit-job --model $MODEL --input $INPUT --proof-type $PROOF_TYPE" \
	tx pouw submit-job --model "$MODEL" --input "$INPUT" \
	--proof-type "$PROOF_TYPE" --purpose "feature-demo inference"

bold "Demo complete."
note "TEE [A] and zkML [B] exercise the REAL verification code paths the chain"
note "uses. [C]/[D] drive the live single node. See FEATURE_TESTING.md for the"
note "full command reference and the simulated-vs-production trust boundary."
