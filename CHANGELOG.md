# Changelog

All notable changes to the Aethelred protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Security
- Bound TEE attestation `UserData` to block height + chain ID (`SHA256(outputHash || LE64(height) || chainID)`)
- Strict vote extension validation: unsigned extensions rejected in production mode
- Eliminated `float64` in consensus-critical emission schedule (audit fix M-05)
- Added `AllowSimulated` fail-closed guard to `cryptographicVerify` (production path)

### Added
- ABCI++ `ExtendVoteHandler` and `VerifyVoteExtensionHandler` for PoUW consensus
- On-chain ZK proof verifier (`x/verify`) with EZKL, RISC Zero, Groth16, Halo2, Plonky2 support
- Verifying key and circuit registry with tamper-proof SHA-256 hash enforcement
- Fee distribution: 40% validators / 30% treasury / 20% burn / 10% insurance (integer math, no dust loss)
- Reputation-scaled validator rewards: `reward * (50 + rep/2) / 100`
- `AethelredBridge.sol`: enterprise-grade Ethereum bridge with 2-of-N guardian multi-sig
- Dynamic fee market: congestion-based multiplier (1x → 5x at 70% utilization)
- Exponential emission decay (deterministic integer arithmetic, halving every 6 years)
- Four slashing tiers: minor_fault (0.5%) → critical_byzantine (100% + permaban)
- Encrypted mempool bridge (threshold encryption, anti-front-running)
- VRF-based validator job assignment scheduler
- `make local-testnet-up` / `make local-testnet-doctor` for local development
- Exploit simulation suite (network partition, eclipse attack, Byzantine scenarios)
- Post-quantum Dilithium3 signature support in Rust `crates/core`

### Changed
- Default consensus threshold raised from 51% to **67%** (BFT-safe floor enforced on-chain)
- `UaethToWeiScaleFactor = 10^12` canonical conversion (audit fix C-02)
- Validator commission floor raised to 5% minimum

---

## [0.1.0] - 2026-01-15

### Added
- Initial Aethelred L1 implementation
- `x/pouw`, `x/seal`, `x/verify` core modules
- CometBFT consensus integration
- IBC support (cross-chain proof relay)
- Basic TEE client interface (Nitro / SGX / simulated)
