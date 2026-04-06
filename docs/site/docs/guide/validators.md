# Mainnet Validator Requirements

This page describes the planned production validator profile for Aethelred mainnet. If you are onboarding to the public testnet, use [Testnet Validator Onboarding](/guide/validator-testnet) and the canonical repository runbook instead.

Validators are the backbone of the Aethelred network. They participate in BFT consensus, execute AI compute jobs inside TEE enclaves, and produce attestation quotes and zkML proofs. In return, they earn AETHEL token rewards proportional to the useful work they contribute.

## Planned Mainnet Requirements

### Hardware

| Component | Minimum | Recommended |
|---|---|---|
| CPU | 16 cores (x86_64) | 64 cores (AMD EPYC / Intel Xeon) |
| RAM | 64 GB | 256 GB |
| Storage | 1 TB NVMe SSD | 4 TB NVMe SSD (RAID-1) |
| GPU | 1x NVIDIA A10 (24 GB) | 4x NVIDIA A100 (80 GB) |
| TEE | At least one of: SGX2, SEV-SNP, Nitro | SGX2 + SEV-SNP for multi-platform attestation |
| Network | 1 Gbps | 10 Gbps + low-latency peering |

### Staking

| Parameter | Value |
|---|---|
| Minimum self-stake | 100,000 AETHEL |
| Maximum commission | 20% |
| Unbonding period | 21 days |
| Slashing for downtime | 1.0% of stake |
| Slashing for double-sign | 50% of stake |
| Slashing for invalid attestation | 10% of stake |

## Mainnet Setup Flow

### 1. Initialize the Node

```bash
aethelred node init \
  --chain-id aethelred-mainnet-1 \
  --moniker "my-validator" \
  --home /opt/aethelred
```

### 2. Configure TEE

```bash
# Intel SGX
aethelred node tee setup --platform sgx \
  --pccs-url https://pccs.aethelred.io \
  --home /opt/aethelred

# AMD SEV-SNP
aethelred node tee setup --platform sev-snp \
  --home /opt/aethelred

# Verify TEE
aethelred node tee verify
# ✓ SGX DCAP: MRENCLAVE=0xabc... TCB=UpToDate
```

### 3. Create Validator Keys

```bash
# Generate hybrid ECDSA + Dilithium3 validator key
aethelred keys add validator --keyring-backend file --algo hybrid

# Export the consensus public key
aethelred tendermint show-validator
```

### 4. Submit Create-Validator Transaction

```bash
aethelred tx staking create-validator \
  --amount 100000000000uaethel \
  --pubkey $(aethelred tendermint show-validator) \
  --moniker "my-validator" \
  --commission-rate 0.05 \
  --commission-max-rate 0.20 \
  --commission-max-change-rate 0.01 \
  --min-self-delegation 100000000000 \
  --from validator \
  --chain-id aethelred-mainnet-1 \
  --gas auto \
  --gas-adjustment 1.3 \
  --fees 5000uaethel
```

### 5. Start the Node

```bash
aethelred node start \
  --home /opt/aethelred \
  --tee-enabled \
  --gpu-enabled \
  --compute-workers 4
```

## Reward Calculation

Validators earn rewards from two sources:

### Network Incentive Flow

Aethelred uses a fixed-supply token model with no post-genesis inflation. Validator rewards are funded from protocol fee flows and governed incentive pools.

```
epoch_reward = governed_reward_pool * (validator_power / total_power)
validator_share = epoch_reward + verification_fees
delegator_reward = validator_share * (1 - commission_rate)
```

### Compute Rewards (PoUW)

Earned by executing AI compute jobs. These are the primary reward mechanism.

```
compute_reward = job_fee * 0.70   # 70% to executing validator
network_fee    = job_fee * 0.20   # 20% to community pool
seal_fee       = job_fee * 0.10   # 10% burned
```

## Monitoring

### CLI

```bash
aethelred query staking validator <operator-address>
aethelred query distribution rewards <delegator-address>
aethelred node status
```

### Metrics

The validator node exposes Prometheus metrics on port `26660`:

| Metric | Description |
|---|---|
| `aethelred_consensus_height` | Current block height |
| `aethelred_consensus_rounds` | Consensus rounds per block |
| `aethelred_compute_jobs_completed` | Total jobs executed |
| `aethelred_compute_jobs_failed` | Failed job executions |
| `aethelred_tee_attestations_generated` | TEE quotes produced |
| `aethelred_validator_voting_power` | Current voting power |
| `aethelred_validator_missed_blocks` | Missed block proposals |

### Alerting

Recommended alert thresholds:

```yaml
# Prometheus alerting rules
groups:
  - name: aethelred-validator
    rules:
      - alert: ValidatorDown
        expr: up{job="aethelred-validator"} == 0
        for: 2m
      - alert: MissedBlocks
        expr: increase(aethelred_validator_missed_blocks[1h]) > 10
        for: 5m
      - alert: LowDiskSpace
        expr: node_filesystem_avail_bytes{mountpoint="/opt/aethelred"} < 50e9
        for: 10m
```

## Slashing

| Infraction | Penalty | Jailing | Evidence Window |
|---|---|---|---|
| Downtime (missing >95% of blocks in a window) | 1.0% slash | 10 min jail | 10,000 blocks |
| Double signing | 50% slash | Permanent tombstone | Unlimited |
| Invalid TEE attestation | 10% slash | 24h jail | 50,000 blocks |
| Fraudulent compute result | 10% slash + reward clawback | 7 day jail | 100,000 blocks |

### Unjailing

```bash
aethelred tx slashing unjail --from validator --chain-id aethelred-mainnet-1
```

## Delegation

Token holders can delegate to validators to earn a share of rewards:

```bash
aethelred tx staking delegate <validator-operator-addr> 10000000000uaethel \
  --from delegator \
  --chain-id aethelred-mainnet-1
```

## Related Pages

- [Testnet Validator Onboarding](/guide/validator-testnet) -- public testnet operator flow
- [Connecting to Network](/guide/network) -- node configuration
- [TEE Attestation](/guide/tee-attestation) -- validator TEE requirements
- [Submitting Jobs](/guide/jobs) -- jobs executed by validators
- [Architecture](/guide/architecture) -- consensus layer details
