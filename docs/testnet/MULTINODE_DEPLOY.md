# Aethelred Multi-Node Testnet Bring-Up

Checklist for going from a working single node to a multi-validator testnet — the
configuration that unlocks the features a single node cannot exercise: BFT
consensus across validators, vote-extension aggregation, DKG-backed job
assignment, and the **≥67% Digital Seal quorum**.

Prerequisite: the single-node Tier 0/1 checks pass (see
[FEATURE_TESTING.md](FEATURE_TESTING.md)). Build first:
`go build -o build/aethelredd ./cmd/aethelredd`.

---

## 0. Sizing and the quorum math

| Parameter | Value | Source |
|-----------|-------|--------|
| Consensus / seal threshold | **67%** (BFT-safe, `ceil(total · 0.67)`) | `pouw` params `ConsensusThreshold`, min 67 |
| Reference profile `MinValidators` | **5** | `x/pouw/keeper/mainnet_params.go` |
| BFT fault tolerance | tolerates `f` faulty with `3f+1` nodes | CometBFT |

Seal agreement needed by validator count:

| Validators (N) | Need to agree `ceil(N·0.67)` | Tolerates offline |
|----------------|------------------------------|-------------------|
| 4 | 3 | 1 |
| 5 | 4 | 1 |
| 7 | 5 | 2 |

**Recommendation:** **4 validators** is the BFT floor (tolerates one failure);
use **5+** to match the production profile's `MinValidators`. Below 4 there is no
meaningful quorum.

---

## Part A — Local multi-node (one machine), for testing the quorum

`scripts/localnet.sh` brings up N validators on a single host with separate home
dirs, per-node ports (base + 100·i), one shared genesis, and persistent peers
wired automatically. Use it to validate the multi-node-only features before
deploying real hosts.

```bash
N=4 scripts/localnet.sh init     # genesis + config for 4 validators
N=4 scripts/localnet.sh start    # start all 4 in the background
N=4 scripts/localnet.sh status   # heights advancing in lockstep == healthy BFT
N=4 scripts/localnet.sh stop
N=4 scripts/localnet.sh reset    # destroy everything
```

Node `i` RPC is `26657 + 100·i` (node0 :26657, node1 :26757, …). Each validator
self-bonds 150,000 AETHEL at genesis (above the 100k PoUW minimum), so
`stake_requirement_met` is true from height 1.

Verified: a 4-node localnet forms consensus and advances in lockstep with each
node connected to the other three. From here, run the onboarding (§3) and
job→seal validation (§4) against the per-node RPC ports.

---

## Part B — Distributed multi-node (validators on separate hosts)

Same model, but keys never leave their host; only public artifacts (validator
addresses, gentxs, the final genesis, node IDs) are exchanged. Pick one host as
**coordinator**.

### B.1 Per validator (every host)
```bash
MONIKER=val-<name>; CHAIN_ID=aethelred-testnet-1
aethelredd init "$MONIKER" --chain-id "$CHAIN_ID" --default-denom uaethel
aethelredd keys add validator --keyring-backend test
aethelredd keys show validator -a --keyring-backend test   # send this ADDRESS to the coordinator
```

### B.2 Coordinator builds the shared genesis
```bash
# Fund every validator's account (collect all addresses first)
for addr in <addr1> <addr2> <addr3> <addr4>; do
  aethelredd add-genesis-account "$addr" 500000000000uaethel
done
# Dev/testnet: enable simulated TEE/zkML execution
sed -i 's/"allow_simulated": false/"allow_simulated": true/g' ~/.aethelred*/config/genesis.json
# Send this genesis.json to every validator host
```

### B.3 Each validator gentxs, coordinator collects
```bash
# On each host (genesis.json from B.2 must be in place first):
aethelredd gentx validator 150000000000uaethel --chain-id "$CHAIN_ID" --keyring-backend test
#   -> produces config/gentx/gentx-*.json; send that file to the coordinator

# On the coordinator: drop all gentx files into config/gentx/, then:
aethelredd collect-gentxs
aethelredd validate-genesis
#   -> distribute this FINAL genesis.json to every host (overwrite)
```

### B.4 Wire peers and config (every host)
```bash
# Get each node's ID (note: printed to stderr):
aethelredd comet show-node-id
# In config.toml set persistent_peers to a comma-separated list of:
#   <nodeID>@<host-ip>:26656
# Recommended for a testnet:
#   config.toml : create_empty_blocks=false  (calm blocks for tx testing)
#   app.toml    : minimum-gas-prices="0uaethel"  and append:
#                 [aethelred.pqc]
#                 enabled = true
#                 mode    = "hybrid"
```

### B.5 Start (every host)
```bash
AETHELRED_TEE_MODE=simulated aethelredd start
```
Open ports between hosts: **26656** (p2p). Keep **26657/1317/9090** local or
firewalled. Healthy when every node reports the same advancing height
(`aethelredd status`) and `net_info` shows `n_peers = N-1`.

---

## 3. Per-validator onboarding (order matters)

For **each** validator, against its own node, in this order:

```bash
C="--from validator --keyring-backend test --chain-id aethelred-testnet-1 \
   --fees 200uaethel --gas 600000 --yes"        # add --node tcp://127.0.0.1:<rpc> on localnet

# 1) Stake >= 100k AETHEL bonded (localnet validators are already self-bonded; skip)
aethelredd tx pouw stake --amount 100000aethel --validator $(aethelredd keys show validator --bech val -a --keyring-backend test) $C

# 2) Register the Nitro PCR0 measurement (64 hex chars)
aethelredd tx pouw register-pcr0 <pcr0-hex> $C

# 3) Register compute capability (REQUIRES bonded stake >= 100k first)
aethelredd tx pouw register-validator-capability \
  --tee-platforms aws-nitro,amd-sev-snp --zkml-systems groth16 --max-concurrent-jobs 4 $C

# 4) Register the hybrid (secp256k1 + ML-DSA) seal-signing key.
#    The node logs it at startup: "Validator private key configured for vote
#    extension signing hybrid_public_key=<hex>" — copy that hex:
aethelredd tx pouw register-hybrid-key <hybrid-pubkey-hex> $C
```

Confirm readiness on each: `aethelredd query pouw status --validator <addr>` →
`ready_for_pouw: true`. Once a quorum of validators is ready, `dkg_state`
progresses past `eligible` toward DKG completion (DKG needs multiple
participants — it cannot complete on a single node).

---

## 4. Job → Digital Seal validation (the multi-node milestone)

This is what a single node cannot do. With ≥4 ready validators:

```bash
# Register a model once (any validator). A zkML job REQUIRES a 32-byte
# verifying-key hash on the model, so pass --verifying-key-hash:
aethelredd tx pouw register-model --model resnet50-v1 --model-id resnet50 \
  --name "ResNet-50" --verifying-key-hash vk-resnet50-v1 $C

# Submit a verification job
aethelredd tx pouw submit-job --model resnet50-v1 --input sample-batch-0 \
  --proof-type zkml --purpose "multinode seal validation" $C
```

The pipeline then runs deterministically across the quorum:
1. `submit-job` stores the job (returns code 0).
2. EndBlock **assigns** it to the eligible validators (writes
   `scheduler.assigned_to`) and moves it PENDING → PROCESSING.
3. Each assigned validator runs the (simulated) verification in `ExtendVote` and
   carries the result in its signed vote extension.
4. When `ceil(N·0.67)` validators agree, `PrepareProposal` emits a
   `create_seal_from_consensus` tx; the `PreBlocker` applies it, creating the
   **Digital Seal** and marking the job COMPLETED.

Watch for it:
```bash
grep -iE "Consensus reached for job|Seal transaction created|JOB_STATUS_COMPLETED" <node>/node.log
```
Expected (verified on a 4-validator localnet): `validators_agreed=4 total_votes=4`,
`Seal transaction created`, and `JOB_STATUS_COMPLETED` on every node with zero
app-hash mismatches.

> **Single-node note.** On one node the job is assigned and verified but never
> reaches the `ceil(N·0.67)` quorum, so no seal is created — by design, the seal
> quorum is a multi-node property. Use `scripts/localnet.sh` (≥4 validators) for
> this test, or the `public-proof-path` SDK demo to exercise seal signing
> off-chain on one machine.

---

## 5. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `no ID` in persistent_peers | `comet show-node-id` prints to **stderr**; capture `2>&1` (localnet.sh handles this) |
| Peers won't connect (localnet) | set `allow_duplicate_ip=true`, `addr_book_strict=false` (localnet.sh sets these) |
| `version does not exist` on any query/tx, or panic on restart | running an old binary — rebuild from this branch and `reset` (fixed: empty-store load) |
| `no cosmos.msg.v1.signer option found` | old binary — rebuild (fixed: CustomGetSigners) |
| `register-validator-capability` fails: "does not meet minimum bonded stake" | run `stake` (≥100k AETHEL) **before** capability |
| Chain halts when a validator stops | you dropped below `ceil(N·0.67)` online — restart it (BFT needs >2/3) |
| `dkg_state` never completes | DKG needs multiple ready validators; confirm each is `ready_for_pouw` |
