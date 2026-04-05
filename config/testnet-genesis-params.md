# Aethelred Testnet Genesis Parameters

Chain ID: `aethelred-testnet-1`

## Genesis Configuration

| Parameter | Value |
|-----------|-------|
| Chain ID | `aethelred-testnet-1` |
| Genesis Time | `2026-04-01T14:00:00Z` (April 1, 2026 2:00 PM UTC) |
| Consensus Engine | CometBFT with Proof-of-Useful-Work (PoUW) |
| Block Time Target | 6 seconds |
| Epoch Length | 43,200 blocks (3 days) |
| Active Validator Set | 50 |

## Token / Supply Parameters

| Parameter | Value |
|-----------|-------|
| Token Symbol | `tAETHEL` |
| Bond Denom | `uaethel` |
| Decimals | 6 |
| Total Supply | `10,000,000,000 tAETHEL` |
| Post-Genesis Inflation | `0%` |
| Faucet Drip | `10,000 tAETHEL` per request |
| Faucet Cooldown | 86,400 seconds (1 day) |

## Staking Parameters

| Parameter | Value |
|-----------|-------|
| Min Validators | 4 |
| Max Validators | 200 |
| Min Validator Stake | `1,000,000,000 uaethel` (1,000 tAETHEL) |
| Max Validator Stake | `500,000,000,000 uaethel` (500,000 tAETHEL) |
| Min Delegator Stake | `10,000,000 uaethel` (10 tAETHEL) |
| Unbonding Period | 86,400 seconds (1 day) |
| Historical Entries | 10,000 |
| Min Uptime | 80% |

## Slashing Parameters

| Parameter | Value |
|-----------|-------|
| Slash Fraction Double Sign | 50% (0.50) |
| Slash Fraction Downtime | 0.5% (0.005) |
| Downtime Jail Duration | 300 seconds (5 minutes) |
| Signed Blocks Window | 5,000 |
| Min Signed Per Window | 80% (0.80) |

## Governance Parameters

| Parameter | Value |
|-----------|-------|
| Min Deposit | `10,000,000,000 uaethel` (10,000 tAETHEL) |
| Max Deposit Period | 172,800 seconds (2 days) |
| Voting Period | 172,800 seconds (2 days) |
| Quorum | 25% |
| Threshold | 50% |
| Veto Threshold | 33% |

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
- ZK proof verification remains enabled for integration testing

### Bridge (x/ibc, crates/bridge)

- Status: **paused**
- Target chain: **Ethereum Sepolia (`11155111`)**
- Challenge period: 3,600 seconds (1 hour)
- Bridge relayer remains paused until the bridge security drill passes

### PoUW (x/pouw)

- AI job scheduling: enabled
- VRF-based validator selection: enabled
- Reward distribution: enabled
- Minimum useful work threshold: testnet-adjusted (lower than mainnet)

## Genesis Accounts

Genesis accounts and allocations are finalized in the canonical testnet genesis file. The faucet allocation is included in that published artifact.

## Generating the Genesis File

```bash
# Initialize the node
aethelredd init <moniker> --chain-id aethelred-testnet-1

# The genesis.json will be created at ~/.aethelred/config/genesis.json
# Replace it with the canonical published testnet genesis before starting.
```
