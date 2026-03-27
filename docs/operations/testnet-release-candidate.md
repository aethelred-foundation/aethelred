# Testnet Release Candidate: aethelred-testnet-1

**Release Branch:** `release/testnet-v1.0`
**Image Tag:** `aethelred/node:testnet-v1.0.0`
**Chain ID:** `aethelred-testnet-1`
**Genesis Time:** April 1, 2026 14:00 UTC
**Freeze Policy:** [FREEZE_POLICY.md](./FREEZE_POLICY.md)

---

## Genesis Artifact

| File | Path | SHA-256 |
|------|------|---------|
| Genesis JSON | `config/genesis/testnet-genesis.json` | `3d1444f8aad97614323b5ddefaf85f27caf5c65cd9465a9aa4b84de8e018c36d` |
| Checksum file | `config/genesis/testnet-genesis.sha256` | — |

### How to Verify Genesis

```bash
# Clone the release branch
git clone -b release/testnet-v1.0 https://github.com/aethelred/aethelred.git
cd aethelred

# Verify checksum
shasum -a 256 -c config/genesis/testnet-genesis.sha256

# Expected output:
# testnet-genesis.json: OK
```

---

## Network Endpoints

| Service | URL |
|---------|-----|
| RPC | `https://rpc.testnet.aethelred.io` |
| REST API | `https://api.testnet.aethelred.io` |
| gRPC | `grpc.testnet.aethelred.io:9090` |
| Explorer | `https://explorer.testnet.aethelred.io` |
| Faucet | `https://faucet.testnet.aethelred.io` |

## Seed Nodes

```
seed-1@seed1.testnet.aethelred.io:26656
seed-2@seed2.testnet.aethelred.io:26656
```

## Persistent Peers

```
peer-1@peer1.testnet.aethelred.io:26656
peer-2@peer2.testnet.aethelred.io:26656
peer-3@peer3.testnet.aethelred.io:26656
```

---

## Key Differences from Mainnet Genesis

| Parameter | Testnet | Mainnet |
|-----------|---------|---------|
| Chain ID | `aethelred-testnet-1` | `aethelred-mainnet-1` |
| Token symbol | `tAETHEL` | `AETHEL` |
| Bond denom | `utaethelel` | `uaethelel` |
| Min validators | 4 | 21 |
| Active set size | 50 | 100 |
| Min validator stake | 1,000 tAETHEL | 100,000 AETHEL |
| Unbonding period | 1 day | 21 days |
| Min uptime | 80% | 95% |
| Bridge chain | Sepolia (11155111) | Ethereum (1) |
| Challenge period | 1 hour | 7 days |
| `allow_simulated` | `true` | `false` |
| Compliance modules | Disabled | Enabled |
| Faucet | Enabled | N/A |
| Governance voting period | 2 days | 7 days |

---

## Validator Onboarding

1. **Get testnet tokens** from `https://faucet.testnet.aethelred.io`
2. **Follow the testnet validator runbook**: [TESTNET_VALIDATOR_RUNBOOK.md](../TESTNET_VALIDATOR_RUNBOOK.md)
3. **Join the validator channel**: Slack `#validators-testnet`

---

## Acceptance Criteria for Launch

Per [FREEZE_POLICY.md](./FREEZE_POLICY.md) and [GATE_INVENTORY.md](./GATE_INVENTORY.md):

- [ ] Release branch `release/testnet-v1.0` exists and is frozen
- [ ] Genesis artifact published with checksum
- [ ] All 18 CI gates green on release branch
- [ ] Loadtest harness produces bounded pass/fail in under 5 minutes
- [ ] Validator runbook current with testnet-specific instructions
- [ ] Go/no-go review by RC-01 committee (March 29, 2026)
- [ ] Hard freeze entered (March 29, 2026 00:00 UTC)
- [ ] Tag cut from frozen branch (April 1, 2026)

---

## RC-01 Committee Sign-off

| Role | Name | Sign-off | Date |
|------|------|----------|------|
| Release Manager | | | |
| Security Lead | | | |
| Protocol Lead | | | |
| QA Lead | | | |

**Quorum required:** 3 of 4
