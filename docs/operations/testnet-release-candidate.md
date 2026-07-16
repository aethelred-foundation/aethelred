# Testnet Release Candidate: aethelred-testnet-1

**Current Status:** `BLOCKED FOR PUBLIC LAUNCH`
**Status Date:** 2026-05-24
**Readiness Gate:** `make public-testnet-readiness`

**Release Branch:** `release/testnet-v1.0`
**Image Tag:** `ghcr.io/aethelred-foundation/aethelred/aethelredd:testnet-v1.0.1`
**Chain ID:** `aethelred-testnet-1`
**Genesis Time:** April 1, 2026 14:00 UTC
**Freeze Policy:** [FREEZE_POLICY.md](./FREEZE_POLICY.md)

---

## Genesis Artifact

| File | Path | SHA-256 |
|------|------|---------|
| Genesis JSON | `config/genesis/testnet-genesis.json` | `9da89ba135c96aa7fe26ea3d340c0677f2772468eb8895207b878d03dd556c0f` |
| Checksum file | `config/genesis/testnet-genesis.sha256` | — |

### How to Verify Genesis

```bash
# Clone the release branch
git clone -b release/testnet-v1.0 https://github.com/aethelred-foundation/aethelred.git
cd aethelred

# Verify checksum
shasum -a 256 -c config/genesis/testnet-genesis.sha256

# Expected output:
# config/genesis/testnet-genesis.json: OK
```

---

## Public Launch Blockers

The repository can run internal rehearsal, but public validator onboarding must not begin until `make public-testnet-readiness` passes on `release/testnet-v1.0`.

Current blockers:

- External audit scopes `/contracts/ethereum` and `Consensus + vote extensions` are still marked `In progress` unless a signed public-testnet waiver is approved.
- Genesis time is stale and must be regenerated for the actual public launch window.
- Sepolia bridge is enabled with the zero contract address.
- Seed and persistent peer entries use placeholder node IDs instead of real `nodeID@host:port` values.

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
| Bond denom | `uaethel` | `uaethel` |
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

- [ ] `make public-testnet-readiness` passes on `release/testnet-v1.0`
- [ ] Release branch `release/testnet-v1.0` exists and is frozen
- [ ] Genesis artifact published with checksum
- [ ] All 18 CI gates green on release branch
- [ ] Public validator image pulls anonymously: `ghcr.io/aethelred-foundation/aethelred/aethelredd:testnet-v1.0.1`
- [ ] Public DNS resolves for RPC, explorer, faucet, seeds, and peers
- [ ] Loadtest harness produces bounded pass/fail in under 5 minutes
- [ ] Validator runbook current with testnet-specific instructions
- [ ] Clean-room validator onboarding walkthrough passes from docs only
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
