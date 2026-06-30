# Aethelred Single-Node Feature Testing

This guide shows how to exercise Aethelred's headline features on a local
single node: **real hardware-agnostic TEE attestation verification**, **real
BN254 Groth16 zkML proof verification**, and the **on-chain PoUW transaction
flow** (queries, validator registration, model registration, job submission).

It targets the no-hardware **dev/testnet profile**: TEE/zkML *execution* is
simulated (no enclave or prover endpoint required), but the *cryptography* is
real — PQC-hybrid signing, attestation parsing/signature/X.509 verification, and
the elliptic-curve pairing check all run the same code the production chain uses.

See [TESTNET_DEPLOY.md](TESTNET_DEPLOY.md) for bringing the chain up from genesis.

---

## 0. Prerequisites

```bash
# Build the node binary
go build -o build/aethelredd ./cmd/aethelredd

# Bring up a local single node (genesis bootstrap + start), in its own terminal.
# This sets allow_simulated=true, AETHELRED_TEE_MODE=simulated, real PQC hybrid.
scripts/testnet.sh start
```

The node listens on `tcp://localhost:26657` (CometBFT RPC). The default validator
key is `validator` in the `test` keyring under `~/.aethelredd`.

> **Tip — quieter blocks for tx testing.** By default the chain produces a block
> every few seconds. To make state queries and tx broadcasts land in a calm,
> stable window you can set `create_empty_blocks = false` in
> `~/.aethelredd/config/config.toml` before `start` (it still advances on txs and
> proposal-injected data).

---

## 1. One-shot tour

```bash
scripts/feature-demo.sh
```

Runs all of the below in sequence against the running node:
TEE demo → zkML demo → validator status query → register-pcr0 → register-model →
submit-job. Override `BINARY`, `HOME_DIR`, `CHAIN_ID`, `NODE`, `MODEL`, etc. via
env. Read on for the individual commands.

---

## 2. Real TEE attestation verification (no chain required)

```bash
go run ./cmd/aethelred-attestation-demo
```

Verifies one attestation per platform — **AMD SEV-SNP, AWS Nitro, Intel TDX,
Azure MAA, GCP Confidential Space, NVIDIA GPU** — through the real
`internal/attestation` verifier: COSE/JWT/binary document parse, ECDSA/RSA
signature check, and X.509 certificate-chain validation. It then shows that:

- flipping a single measurement byte is **rejected** (signature fails), and
- requiring a silicon **vendor** root rejects evidence that only chains to the
  pilot **test** root (the honest trust boundary — pinning the vendor's
  production root flips `trust_basis` to `vendor_root` with no code change).

## 3. Real BN254 Groth16 zkML verification (no chain required)

```bash
go run ./cmd/aethelred-zkml-demo
```

Builds a mathematically valid Groth16 instance and runs the chain's real pairing
check (`github.com/consensys/gnark-crypto`):
`e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ) == 1`, with mandatory on-curve and
prime-order-subgroup checks. It demonstrates:

- a valid proof is **accepted**,
- a tampered proof (`A` scaled) is **rejected**, and
- an off-curve proof point is **rejected** (`G1 point not on curve`).

This is the exact verification path `x/verify/groth16` runs on-chain. The trust
boundary is the circuit's verifying key.

---

## 4. On-chain queries

```bash
ADDR=$(aethelredd keys show validator -a --keyring-backend test)

# Validator PoUW readiness (staking + PCR0 + capability + DKG signals)
aethelredd query pouw status --validator "$ADDR"

# Is a given PCR0 measurement registered?
aethelredd query pouw is-pcr0-registered <pcr0-hex>

# Validator's registered PCR0
aethelredd query pouw validator-pcr0 "$ADDR"

# A Digital Seal's validator quorum
aethelredd query pouw seal-quorum <seal-id>
```

## 5. On-chain transactions

All custom-module messages are signed with the hybrid (secp256k1 + ML-DSA) key
and broadcast normally:

```bash
COMMON="--from validator --keyring-backend test --chain-id aethelred-testnet-1 \
        --fees 200uaethel --gas 400000 --yes"

# Register an AWS Nitro PCR0 measurement (64 hex chars / 32 bytes)
aethelredd tx pouw register-pcr0 $(printf 'ab%.0s' {1..32}) $COMMON

# Register a validator's hybrid public key for Digital Seal quorum signing.
# The node derives this key from priv_validator_key.json and logs it at startup:
#   INF Validator private key configured for vote extension signing hybrid_public_key=<hex>
# Copy that hex (≈1987 bytes / 3974 hex chars: secp256k1 + ML-DSA-65) here.
aethelredd tx pouw register-hybrid-key <hybrid-pubkey-hex> $COMMON

# Advertise compute capabilities (joins the assignment pool)
aethelredd tx pouw register-validator-capability \
  --tee-platforms aws-nitro,amd-sev-snp --zkml-systems groth16 \
  --max-concurrent-jobs 4 $COMMON

# Register a model (model hash = sha256 of --model, or pass 64 hex chars directly)
aethelredd tx pouw register-model \
  --model resnet50-v1 --model-id resnet50 --name "ResNet-50" --architecture cnn $COMMON

# Submit a verification job against a registered model
aethelredd tx pouw submit-job \
  --model resnet50-v1 --input sample-batch-0 \
  --proof-type zkml --purpose "demo inference" $COMMON
```

`--model` / `--input` accept either a 32-byte hash (64 hex chars, optionally
`0x`-prefixed) or any string, which is SHA-256 hashed to a 32-byte handle — pass
the **same** `--model` value to `register-model` and `submit-job` so the hashes
match. `--proof-type` is `tee | zkml | hybrid`.

---

## 6. Known limitations (honest status)

- **Job → Digital Seal completion requires a multi-node validator quorum.**
  `submit-job` now signs, broadcasts, and **persists the job on chain** (the
  earlier proto/`Coin` marshaling defect is fixed — the fee is recorded under the
  reserved `scheduler.fee` metadata key instead of the unmarshalable proto Coin
  field). The submitted job is stored as `Pending` and awaits assignment. The
  assignment → verification → seal steps require a DKG-backed validator quorum
  (a single validator's signature is not a quorum), so the **final Digital Seal
  is produced only on a multi-node testnet**, not on a single node. To exercise
  the seal quorum itself off-chain, use the `public-proof-path` SDK demo.

- **Simulated vs production.** This profile sets `allow_simulated=true` and
  `AETHELRED_TEE_MODE=simulated`, so PoUW *execution* is simulated. The
  attestation and pairing **verification** code is real (sections 2–3).
  Production additionally requires real enclaves / a prover endpoint, the
  silicon vendor's production attestation roots, and `allow_simulated=false`.

---

## 7. Required node fixes baked into this branch

Two pre-existing defects that made the chain unusable beyond block production
were fixed here; **a fresh genesis (`scripts/testnet.sh reset`) is required** to
pick them up:

1. **Empty mounted stores broke all versioned state.** Store keys were mounted
   for modules with no keeper/`InitGenesis` (`gov`, `feegrant`, `evidence`,
   `authz`, `crisis`) and for keeper-only modules that never seeded their store
   (`upgrade`, `insurance`, `sovereign_crisis`, `ibc`). An empty mounted IAVL
   store cannot be loaded by version under iavl v1.x (`version does not exist`),
   which made **every** account/state query fail (blocking all tx broadcasts)
   and prevented the node from reloading state on restart. Orphaned store keys
   were removed; the remaining keeper-only stores are now seeded at genesis.

2. **Custom-module messages had no signer.** The `pouw` / `seal` / `verify`
   protos lack the `(cosmos.msg.v1.signer)` option, so the x/tx signing context
   could not determine their signers and every custom-module tx failed CheckTx
   with *"no cosmos.msg.v1.signer option found"*. Signers are now registered in
   Go via `CustomGetSigners` (see `app/encoding.go`).
