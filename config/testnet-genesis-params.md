# Aethelred Testnet Genesis Parameters

Chain ID: `aethelred-testnet-1`

## Genesis Configuration

| Parameter | Value |
|-----------|-------|
| Chain ID | `aethelred-testnet-1` |
| Genesis Time | `2026-04-01T14:00:00Z` (April 1, 2026 2:00 PM UTC) |
| Consensus Engine | CometBFT with Proof-of-Useful-Work (PoUW) |
| Block Time Target | 6 seconds |
| Max Block Gas | 40,000,000 |

## Staking Parameters

| Parameter | Value |
|-----------|-------|
| Max Validators | 100 |
| Min Self-Delegation (Stake) | 1,000,000 uaeth (1 AETH) |
| Unbonding Period | 21 days (1,814,400 seconds) |
| Historical Entries | 10,000 |
| Bond Denom | `uaeth` |

## Inflation / Mint Parameters

| Parameter | Value |
|-----------|-------|
| Initial Inflation | 7% |
| Max Inflation | 20% |
| Min Inflation | 7% |
| Goal Bonded | 67% |
| Blocks Per Year | 5,256,000 (based on 6s block time) |

## Distribution Parameters

| Parameter | Value |
|-----------|-------|
| Community Tax | 2% |
| Base Proposer Reward | 1% |
| Bonus Proposer Reward | 4% |
| Withdraw Address Enabled | true |

## Slashing Parameters

| Parameter | Value |
|-----------|-------|
| Slash Fraction Double Sign | 5% (0.05) |
| Slash Fraction Downtime | 0.01% (0.0001) |
| Downtime Jail Duration | 600 seconds (10 minutes) |
| Signed Blocks Window | 100 |
| Min Signed Per Window | 50% (0.5) |

## Governance Parameters

| Parameter | Value |
|-----------|-------|
| Min Deposit | 10,000,000 uaeth (10 AETH) |
| Max Deposit Period | 172,800 seconds (2 days) |
| Voting Period | 172,800 seconds (2 days) |
| Quorum | 33.4% |
| Threshold | 50% |
| Veto Threshold | 33.4% |

## Module-Specific Configuration

### IBC

- Status: **enabled**
- Allowed clients: `07-tendermint`, `09-localhost`

### Vote Extensions

- Status: **enabled** (required for PoUW consensus)
- Vote extensions carry AI inference attestations from validators
- Extensions are verified during `ProcessProposal`

### Seal Verification (x/verify)

- Mode: **testnet** (simulated verifier)
- TEE attestation verification uses simulated backend
- ZK proof verification enabled with relaxed timing constraints

### Bridge (x/ibc, crates/bridge)

- Status: **paused**
- Bridge relayer will remain paused until the bridge security drill passes
- Contract addresses will be populated after Sepolia deployment is verified

### PoUW (x/pouw)

- AI job scheduling: enabled
- VRF-based validator selection: enabled
- Reward distribution: enabled
- Minimum useful work threshold: testnet-adjusted (lower than mainnet)

## Genesis Accounts

Genesis accounts and allocations will be finalized in a separate document prior to genesis time. The testnet faucet address will be included in the genesis allocation.

## Generating the Genesis File

```bash
# Initialize the node
aethelredd init <moniker> --chain-id aethelred-testnet-1

# The genesis.json will be created at ~/.aethelred/config/genesis.json
# Replace with the canonical testnet genesis once published.
```
