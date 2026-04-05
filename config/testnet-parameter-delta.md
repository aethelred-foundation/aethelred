# Aethelred Testnet vs Mainnet Parameter Delta

This document enumerates every parameter where `aethelred-testnet-1` intentionally diverges from the planned mainnet configuration, along with the rationale for each difference.

## Summary

The testnet relaxes security thresholds and operational requirements to enable rapid iteration, lower the barrier for validator onboarding, and allow testing of features that are not yet audit-cleared for production.

## Parameter Differences

### Consensus / Validator Set

| Parameter | Testnet | Mainnet | Rationale |
|-----------|---------|---------|-----------|
| Min Validators | 4 | 21 | Lower quorum allows testnet to launch with a smaller initial validator set |
| Max Validators | 200 | 1000 | Testnet supports a broader experimental set while mainnet keeps a tighter operational envelope |
| Active Validator Set | 50 | 100 | Smaller active set reduces launch complexity on testnet |
| Min Validator Stake | 1,000,000,000 uaethel (1,000 tAETHEL) | 100,000,000,000 uaethel (100,000 AETHEL) | Lower barrier to entry for testnet validators |
| Min Delegator Stake | 10,000,000 uaethel (10 tAETHEL) | 100,000,000 uaethel (100 AETHEL) | Lower barrier for testnet delegators |
| Unbonding Period | 86,400s (1 day) | 1,814,400s (21 days) | Faster iteration and validator recovery during testnet |

### Seal / TEE Verification (x/verify)

| Parameter | Testnet | Mainnet | Rationale |
|-----------|---------|---------|-----------|
| Verification Mode | Simulated | Production TEE (SGX/Nitro) | Testnet uses a simulated verifier backend so operators do not need TEE hardware to participate |
| Attestation Enforcement | Permissive (log-only on failure) | Strict (reject on failure) | Allows testing attestation flows without hard-blocking on verification failures |
| ZK Proof Timeout | 120 seconds | 30 seconds | Relaxed to accommodate slower test environments |

### Bridge (crates/bridge, x/ibc)

| Parameter | Testnet | Mainnet | Rationale |
|-----------|---------|---------|-----------|
| Bridge Status | Paused | Active (after audit signoff) | Bridge is paused on testnet until the bridge security drill passes and Sepolia contracts are verified |
| Relayer Auto-Start | Disabled | Enabled | Bridge relayer does not start automatically; must be manually enabled after drill |
| Target Chain | Sepolia (Ethereum testnet) | Ethereum mainnet | Testnet bridges to Sepolia for safe integration testing |

### PoUW (x/pouw)

| Parameter | Testnet | Mainnet | Rationale |
|-----------|---------|---------|-----------|
| Min Useful Work Threshold | 50% of mainnet | 100% | Reduced threshold allows validators with limited GPU resources to participate |
| Job Difficulty Range | 1-5 | 3-10 | Lower difficulty range for faster iteration on AI job scheduling |
| VRF Election Delay | 1 block | 3 blocks | Shorter delay speeds up testing of validator election cycles |

### Governance

| Parameter | Testnet | Mainnet | Rationale |
|-----------|---------|---------|-----------|
| Voting Period | 172,800s (2 days) | 604,800s (7 days) | Shortened to allow rapid governance iteration |
| Max Deposit Period | 172,800s (2 days) | 604,800s (7 days) | Shortened for the same reason |
| Min Deposit | 10,000 tAETHEL | 100,000 AETHEL | Lower deposit to encourage governance testing |
| Quorum | 25% | 33% | Testnet quorum is relaxed to match the smaller validator population |

### Slashing

| Parameter | Testnet | Mainnet | Rationale |
|-----------|---------|---------|-----------|
| Slash Fraction Double Sign | 50% | 50% | Double-signing penalty is identical to mainnet to preserve safety discipline during testnet |
| Slash Fraction Downtime | 0.5% | 1.0% | Testnet is less punitive for uptime misses while still exercising the slashing path |
| Downtime Jail Duration | 300s | 600s | Shorter jail time reduces operator friction during testnet iteration |
| Min Signed Per Window | 80% | 95% | Testnet tolerates more operational instability while operators tune infrastructure |

### Network / P2P

| Parameter | Testnet | Mainnet | Rationale |
|-----------|---------|---------|-----------|
| addr_book_strict | false | true | Relaxed to allow peering from private/NAT networks during testing |
| allow_duplicate_ip | true | false | Permits multiple validators on same host for development setups |

### Mempool

| Parameter | Testnet | Mainnet | Rationale |
|-----------|---------|---------|-----------|
| Encrypted Mempool | Optional | Required | Testnet allows unencrypted transactions for easier debugging and inspection |

## Parameters Identical to Mainnet

The following parameters are intentionally kept at mainnet values to ensure accurate testing:

- Block time target (6 seconds)
- Bond denom (`uaethel`, 6 decimals)
- Fixed-supply token model with zero post-genesis inflation
- IBC enabled
- Vote extensions enabled

## Updating This Document

When a parameter is changed on either testnet or mainnet, this document must be updated to reflect the current delta. Each change should include the rationale for the divergence or convergence.
