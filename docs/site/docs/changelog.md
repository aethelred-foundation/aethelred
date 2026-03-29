# Changelog

All notable changes to the Aethelred platform. Dates follow ISO 8601 (YYYY-MM-DD).

---

## v2.0.0 -- 2026-03-01

**Post-quantum cryptography, hybrid signatures, and the new CLI.**

### Breaking Changes

- **Hybrid signatures required on MainNet and TestNet.** Transactions must include both ECDSA and Dilithium3 signatures. See [Security Parameters](/cryptography/security-parameters).
- **Config file format changed from YAML to TOML.** Run `aethelred config import` to migrate.
- **`aethelred seal create` now requires `--output` hash.** The previous auto-detection behavior has been removed.
- **Minimum Rust version raised to 1.75.**

### Features

- Hybrid post-quantum signature scheme (ECDSA secp256k1 + Dilithium3) with NIST FIPS 204 compliance.
- ML-KEM (Kyber768) key encapsulation for encrypted node-to-node communication (NIST FIPS 203).
- Governance-controlled Quantum Threat Level system with five escalation stages.
- HSM support via PKCS#11 for AWS CloudHSM, Thales Luna, and YubiHSM 2.
- `ValidatorHsmSigner` with primary/backup HSM failover.
- CLI interactive mode (`aethelred interactive`) with syntax highlighting and history.
- `aethelred compliance` subcommand for on-chain legal linting.
- `aethelred hardware` subcommand for TEE detection and GPU simulation.
- Model quantization support (int8, int4, fp16, bf16, fp8) via `aethelred model quantize`.
- Shell completions for Bash, Zsh, Fish, Elvish, and PowerShell.
- Batch signature verification for improved throughput.

### Fixes

- Fixed constant-time comparison for signature verification (`subtle::ConstantTimeEq`).
- Fixed secret key debug output leaking bytes (now prints `[REDACTED]`).
- Fixed gas estimation overflow on large model deployments.
- Resolved connection timeout when switching between networks rapidly.

### Performance

- Release builds now use LTO, single codegen unit, and symbol stripping for smaller binaries.
- `reqwest` switched to `rustls-tls` -- removes OpenSSL runtime dependency.

---

## v1.1.0 -- 2025-11-15

**Digital seals, benchmarking, and DevNet launch.**

### Features

- Digital seal creation and verification (`aethelred seal create`, `aethelred seal verify`).
- Seal export in JSON, PDF, and XML formats.
- `aethelred benchmark` suite covering inference, training, network, and memory benchmarks.
- Benchmark result comparison via `aethelred bench compare`.
- DevNet network profile with faucet at `https://devnet-faucet.aethelred.io`.
- Model deployment with configurable replica count (`--replicas`).
- Job submission with TEE requirement and zkML proof generation flags.

### Fixes

- Fixed keyring file backend failing on first use when directory did not exist.
- Fixed `aethelred node start` hanging when the P2P port was already in use.
- Corrected chain ID validation for custom networks.

---

## v1.0.0 -- 2025-08-01

**Initial public release.**

### Features

- Core CLI with `init`, `status`, `key`, `node`, `validator`, `deploy`, `query`, and `tx` commands.
- ECDSA secp256k1 signature support.
- Four network profiles: MainNet, TestNet, DevNet, Local.
- TOML-based configuration with environment variable overrides.
- Keyring backends: OS, file, and test.
- Gas configuration with adjustable limit, price, and auto-adjustment.
- Account creation, import, export, and balance queries.
- Validator registration, staking, and status monitoring.
- JSON, YAML, text, and table output formats.
- `aethelred version` with build metadata (git SHA, Rust version, SDK version).
- Model registration and listing.
- Basic node management (start, stop, info).

### Known Issues

- No post-quantum signature support (added in v2.0.0).
- Shell completions not yet available (added in v2.0.0).
