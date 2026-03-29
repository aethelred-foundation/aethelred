<p align="center">
 <img src="README-logo.png" alt="Aethelred" width="320" />
</p>

<h1 align="center">Aethelred</h1>

<p align="center">
 <strong>The Sovereign Layer 1 for Verifiable AI</strong><br/>
 Proof-of-Useful-Work consensus · Quantum-safe cryptography · On-chain zkML & TEE verification
</p>

<p align="center">
 <a href="https://github.com/aethelred-foundation/aethelred/actions/workflows/ci.yml"><img src="https://github.com/aethelred-foundation/aethelred/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
 <a href="https://github.com/aethelred-foundation/aethelred/actions/workflows/security-scans.yml"><img src="https://github.com/aethelred-foundation/aethelred/actions/workflows/security-scans.yml/badge.svg" alt="Security"></a>
 <img src="https://img.shields.io/badge/status-pre--launch-yellow?style=flat-square" alt="Status: Pre-Launch">
 <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License"></a>
 <a href="https://discord.gg/aethelred"><img src="https://img.shields.io/badge/Discord-community-5865F2?style=flat-square&logo=discord" alt="Discord"></a>
 <a href="https://aethelred-foundation.github.io/aethelred/"><img src="https://img.shields.io/badge/docs-aethelred.io-orange?style=flat-square" alt="Docs"></a>
 <a href="https://github.com/aethelred-foundation/AIPs"><img src="https://img.shields.io/badge/AIPs-proposals-purple?style=flat-square" alt="AIPs"></a>
</p>

---

## What is Aethelred?

Aethelred is a sovereign **Cosmos SDK / CometBFT** Layer 1 blockchain purpose-built for **verifiable AI computation**. Instead of burning energy on meaningless hashes, validators perform **Proof-of-Useful-Work (PoUW)** - running AI inference jobs inside **Intel SGX / AWS Nitro TEEs** and generating **zero-knowledge ML proofs** (EZKL, RISC Zero, Groth16, Halo2, Plonky2) that are verified on-chain in every block.

```
AI Job Submitted → VRF Scheduler → Validator TEE Execution
 ↓
 zkML Proof Generated → Vote Extension (ABCI++)
 ↓
 2/3 Consensus → Digital Seal Minted → Job Settled
```

### Why Aethelred?

| Feature | Aethelred | Ethereum L2s | Centralized APIs |
|---|---|---|---|
| **Verifiable AI** | On-chain TEE + zkML | Off-chain only | Trust-based |
| **Quantum-Safe** | Dilithium3 + ECDSA | ECDSA only | No |
| **Decentralized** | 100+ validators | Partial | No |
| **Compliance** | GDPR/HIPAA/OFAC native | No | Partial |
| **IBC Ready** | Yes | Partial | No |

---

## Architecture

```
┌─────────────────────── Aethelred Node ───────────────────────────┐
│ │
│ app/ ABCI++ handlers (ExtendVote, PrepareProposal …) │
│ x/pouw/ Proof-of-Useful-Work module (jobs, rewards, VRF) │
│ x/seal/ Digital Seal module (attestation anchoring) │
│ x/verify/ ZK + TEE proof verification module │
│ x/ibc/ Cross-chain proof relay │
│ │
│ ┌─────────────────┐ ┌─────────────────────────────────────┐ │
│ │ Go Node │ │ Rust Services │ │
│ │ Cosmos SDK │◄──┤ TEE Worker · Bridge Relayer │ │
│ │ CometBFT │ │ VM Precompiles · Mempool │ │
│ └─────────────────┘ └─────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────┘
 │ IBC │ Ethereum Bridge
 ▼ ▼
 Cosmos Ecosystem AethelredBridge.sol
 (Lock-and-Mint, EIP-712)
```

---

## Monorepo Structure

```
aethelred/
├── app/ # ABCI application (BeginBlock, EndBlock, ABCI++ handlers)
├── cmd/
│ ├── aethelredd/ # Node binary
│ └── aethelred-loadtest/ # Load test CLI
├── crates/ # Rust workspace
│ ├── core/ # PQC primitives (Dilithium3, Kyber)
│ ├── consensus/ # VRF, reputation
│ ├── vm/ # WASM + zkML precompiles
│ ├── mempool/ # Custom priority mempool
│ └── bridge/ # Ethereum relayer
├── x/ # Cosmos SDK custom modules
│ ├── pouw/ # Proof-of-Useful-Work
│ ├── seal/ # Digital Seals
│ └── verify/ # ZK + TEE verification
├── proto/ # Protobuf definitions
├── scripts/ # Dev tooling
├── tools/ # Load testing, devnet scripts
├── infrastructure/ # Helm charts, Terraform
└── docs/ # Architecture docs
```

---

## Quick Start

**Requirements**: Go 1.24+, Rust 1.75+, Docker

```bash
# 1. Clone
git clone https://github.com/aethelred-foundation/aethelred.git && cd aethelred

# 2. Start local testnet (4 validators, Docker)
make local-testnet-up

# 3. Check node health
make local-testnet-doctor
```

Submit an AI compute job:
```bash
aethel tx pouw submit-job \
 --model-hash <sha256> \
 --input-data ./my_input.json \
 --verification-type hybrid \
 --from mykey
```

---

## Ecosystem Repos

| Repo | Description |
|---|---|
| [contracts](https://github.com/aethelred-foundation/contracts) | Solidity bridge + staking contracts |
| [aethelred-sdk-ts](https://github.com/aethelred-foundation/aethelred-sdk-ts) | TypeScript SDK |
| [aethelred-sdk-py](https://github.com/aethelred-foundation/aethelred-sdk-py) | Python SDK |
| [aethelred-sdk-go](https://github.com/aethelred-foundation/aethelred-sdk-go) | Go SDK |
| [aethelred-sdk-rs](https://github.com/aethelred-foundation/aethelred-sdk-rs) | Rust SDK |
| [aethelred-cli](https://github.com/aethelred-foundation/aethelred-cli) | `aethel` CLI |
| [vscode-aethelred](https://github.com/aethelred-foundation/vscode-aethelred) | VSCode extension |
| [aethelred-docs](https://github.com/aethelred-foundation/aethelred-docs) | Documentation site |
| [AIPs](https://github.com/aethelred-foundation/AIPs) | Aethelred Improvement Proposals |

---

## Key Commands

```bash
make build # Build Go node binary
make test # Run all Go tests
make test-integration # Run integration tests
make loadtest-scenarios # Run exploit simulations
make local-testnet-up # Start Docker testnet
make local-testnet-doctor # Health check all services
make proto-gen # Regenerate protobuf
cargo build --workspace # Build all Rust crates
cargo test --workspace # Test all Rust crates
```

---

## Security

Aethelred has been security-audited with **27 findings remediated** (2026-02-28).

- Post-Quantum Cryptography: Ed25519 + Dilithium3 dual-key
- TEE Platforms: Intel SGX, AWS Nitro Enclaves, AMD SEV-SNP
- Circuit Breaker: Automatic halt on anomaly detection
- Encrypted Mempool: Threshold encryption against front-running
- Compliance: GDPR, HIPAA, OFAC, CCPA native enforcement

Found a vulnerability? See [SECURITY.md](SECURITY.md).

---

## Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

- [Aethelred Improvement Proposals](https://github.com/aethelred-foundation/AIPs)
- [Discord](https://discord.gg/aethelred)
- [Bug Reports](https://github.com/aethelred-foundation/aethelred/issues/new?template=bug_report.md)

---

## License

Apache-2.0 - see [LICENSE](LICENSE)

<p align="center">Built by the Aethelred Team</p>
