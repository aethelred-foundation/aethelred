# Aethelred Testnet vs Mainnet Parameter Delta

This document enumerates every parameter where `aethelred-testnet-1` intentionally diverges from the planned mainnet configuration, along with the rationale for each difference.

## Summary

The testnet relaxes security thresholds and operational requirements to enable rapid iteration, lower the barrier for validator onboarding, and allow testing of features that are not yet audit-cleared for production.

## Parameter Differences

### Consensus / Validator Set

| Parameter | Testnet | Mainnet | Rationale |
|-----------|---------|---------|-----------|
| Min Validators | 7 | 21 | Lower quorum allows testnet to launch with a smaller initial validator set |
| Max Validators | 100 | 100 | Same |
| Min Self-Delegation | 1,000,000 uaeth (1 AETH) | 10,000,000 uaeth (10 AETH) | Lower barrier to entry for testnet validators |

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
| Max Deposit Period | 172,800s (2 days) | 1,209,600s (14 days) | Shortened for same reason |
| Min Deposit | 10 AETH | 100 AETH | Lower deposit to encourage governance testing |

### Slashing

| Parameter | Testnet | Mainnet | Rationale |
|-----------|---------|---------|-----------|
| Slash Fraction Double Sign | 5% | 5% | Same -- double signing penalty is kept identical to mainnet to test real consequences |
| Slash Fraction Downtime | 0.01% | 0.01% | Same |
| Downtime Jail Duration | 600s | 600s | Same |

Slashing parameters are intentionally identical between testnet and mainnet. Validators should experience the same penalty model during testing.

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
- Unbonding period (21 days)
- Inflation model (7% initial, 7-20% range)
- Community tax (2%)
- Slashing parameters (all)
- IBC enabled
- Vote extensions enabled

## Updating This Document

When a parameter is changed on either testnet or mainnet, this document must be updated to reflect the current delta. Each change should include the rationale for the divergence or convergence.
