# Aethelred Public Testnet — Deployment Guide

Branch: **`release/public-testnet-pqc`** (latest `main` + testnet bootstrap fixes + real circl PQC).

This testnet runs on **real post-quantum crypto** (Cloudflare circl ML-DSA-65 /
ML-KEM-768 hybrid for validator signing and Digital Seals) with **simulated
TEE/zkML verification** (no enclave/prover hardware required). It produces blocks
out of the box.

---

## 1. Hardware requirements

### Testnet node (this branch — real PQC, simulated TEE/zkML)

No special hardware. PQC is pure CPU; simulated TEE/zkML means **no Nitro
enclave and no GPU** are needed.

| | Minimum (single-node dev) | Recommended (public testnet validator) |
|---|---|---|
| CPU | 2 vCPU | 4–8 vCPU (x86-64 or arm64) |
| RAM | 4 GB | 16–32 GB |
| Disk | 50 GB SSD | 200–500 GB NVMe SSD (state grows) |
| OS | Linux (Ubuntu 22.04+) | Linux (Ubuntu 22.04 LTS) |
| Build toolchain | Go 1.25.x | Go 1.25.x |
| Network | outbound OK | static IP, stable bandwidth |

Open ports: **26656** (p2p), **26657** (RPC), **1317** (REST), **9090** (gRPC).

### Production node (future — real verifiable AI; NOT required for this testnet)

To run with `allow_simulated=false` (real verification), you additionally need:

- **TEE attestation:** AWS Nitro Enclaves — a Nitro-Enclave-capable EC2 instance
  (e.g. `c5`/`m5`/`r5` `.xlarge`+ with `EnclaveOptions` enabled, vCPU/RAM carved
  out for the enclave), **or** Intel SGX/TDX bare metal. Run with
  `AETHELRED_TEE_MODE=nitro` and a real executor endpoint.
- **zkML verifier:** an EZKL verifier endpoint (CPU; the prover side may need a
  GPU), configured via the node's `zk_verifier_endpoint`.
- **Trusted measurements + attestation endpoints** registered on-chain.

Until that infrastructure exists, keep the testnet settings below.

---

## 2. Build

```bash
git fetch origin
git checkout release/public-testnet-pqc
go build -o aethelredd ./cmd/aethelredd
# optionally: sudo mv aethelredd /usr/local/bin/
```

## 3. Run (single-node quickstart)

```bash
scripts/testnet.sh start
```

This bootstraps and runs the chain in one step: `init` → enable simulated
verification + real PQC → create validator key → `add-genesis-account` →
`gentx` → `collect-gentxs` → `validate-genesis` → `start`. It produces blocks
immediately. `scripts/testnet.sh {stop|reset}` to stop / wipe.

Override defaults via env, e.g.:
```bash
CHAIN_ID=aethelred-testnet-1 DENOM=uaethel HOME_DIR=$HOME/.aethelredd \
  scripts/testnet.sh start
```

## 4. Run (manual steps — same as the script)

```bash
export AETHELRED_TEE_MODE=simulated                 # no TEE hardware
aethelredd init <moniker> --chain-id aethelred-testnet-1 --default-denom uaethel

# dev/testnet settings (the script does these automatically):
#  a) enable simulated TEE/zkML verification
sed -i 's/"allow_simulated": false/"allow_simulated": true/g' ~/.aethelredd/config/genesis.json
#  b) enable real hybrid PQC
printf '\n[aethelred.pqc]\nenabled = true\nmode = "hybrid"\n' >> ~/.aethelredd/config/app.toml

aethelredd keys add validator --keyring-backend test
aethelredd add-genesis-account "$(aethelredd keys show validator -a --keyring-backend test)" 100000000000uaethel
aethelredd gentx validator 70000000000uaethel --chain-id aethelred-testnet-1 --keyring-backend test
aethelredd collect-gentxs
aethelredd validate-genesis
aethelredd start --minimum-gas-prices 0uaethel
```

## 5. Verify it's running on real PQC

In the node logs at startup you should see:
```
INF PQC mode configured  circl_available=true  mode=Hybrid
INF PQC mode enabled successfully
```
and blocks finalizing. Confirm height advances:
```bash
curl -s localhost:26657/status | jq '.result.sync_info.latest_block_height'
```

## 6. What is real vs simulated on this testnet

| Component | Status |
|---|---|
| Validator signing, Digital Seals (ML-DSA-65 / ML-KEM-768 + secp256k1) | **Real** (circl) |
| Consensus, settlement, genesis, staking | **Real** |
| TEE attestation (Nitro) | **Simulated** (no hardware) |
| zkML proof verification | **Simulated** (no prover/verifier endpoint) |

> Running a multi-validator testnet (persistent peers, port offsets) is a
> follow-up; `scripts/testnet.sh` covers the single-node case.
