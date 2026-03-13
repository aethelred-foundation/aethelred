<p align="center">
 <img src="docs/assets/aethelred-banner.png" alt="Aethelred" width="800" />
</p>

<h1 align="center">Aethelred</h1>

<p align="center">
 <strong>The Sovereign Layer 1 for Verifiable AI</strong><br/>
 Proof-of-Useful-Work consensus · Quantum-safe cryptography · On-chain zkML & TEE verification
</p>

<p align="center">
 <a href="https://github.com/AethelredFoundation/aethelred/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/AethelredFoundation/aethelred/ci.yml?branch=main&style=flat-square&label=CI&logo=github" alt="CI"></a>
 <a href="https://github.com/AethelredFoundation/aethelred/actions/workflows/security.yml"><img src="https://img.shields.io/github/actions/workflow/status/AethelredFoundation/aethelred/security.yml?branch=main&style=flat-square&label=Security&logo=shield" alt="Security"></a>
 <a href="docs/security/release-provenance.md"><img src="https://img.shields.io/badge/release-provenance%20tracked-0e8a16?style=flat-square" alt="Release provenance"></a>
 <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License"></a>
 <a href="https://discord.gg/aethelred"><img src="https://img.shields.io/discord/aethelred?style=flat-square&logo=discord&label=Discord&color=5865F2" alt="Discord"></a>
 <a href="https://docs.aethelred.io"><img src="https://img.shields.io/badge/docs-aethelred.io-orange?style=flat-square" alt="Docs"></a>
 <a href="https://github.com/AethelredFoundation/AIPs"><img src="https://img.shields.io/badge/AIPs-proposals-purple?style=flat-square" alt="AIPs"></a>
 <a href="docs/audits/STATUS.md"><img src="https://img.shields.io/badge/audit-program%20active-f59e0b?style=flat-square" alt="Audit program active"></a>
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

**Requirements**: Go 1.22+, Rust 1.75+, Docker

```bash
# 1. Clone
git clone https://github.com/AethelredFoundation/aethelred.git && cd aethelred

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

## Repository Authority

`AethelredFoundation/aethelred` is the canonical public source of truth for the
Aethelred protocol.

- Chain releases, security patch provenance, and governance-linked source should
  trace back to this repository.
- Standalone public repos exist for packaging, discoverability, and focused
  contributor workflows. They do not replace the canonical authority of this
  repository.
- The machine-readable authority records live in [repo-authority.json](repo-authority.json)
  and [repo-role.json](repo-role.json).

---

## Ecosystem Repos

| Repo | Role | Monorepo Source |
|---|---|---|
| [contracts](https://github.com/AethelredFoundation/contracts) | Standalone Solidity distribution repo | `contracts/` |
| [aethelred-sdk-ts](https://github.com/AethelredFoundation/aethelred-sdk-ts) | TypeScript / JavaScript SDK | `sdk/typescript/` |
| [aethelred-sdk-py](https://github.com/AethelredFoundation/aethelred-sdk-py) | Python SDK | `sdk/python/` |
| [aethelred-sdk-go](https://github.com/AethelredFoundation/aethelred-sdk-go) | Go SDK | `sdk/go/` |
| [aethelred-sdk-rs](https://github.com/AethelredFoundation/aethelred-sdk-rs) | Rust SDK | `sdk/rust/` |
| [aethelred-cli](https://github.com/AethelredFoundation/aethelred-cli) | Developer CLI | `tools/cli/aethel/` |
| [vscode-aethelred](https://github.com/AethelredFoundation/vscode-aethelred) | VS Code extension | `tools/vscode-aethelred/` |
| [aethelred-docs](https://github.com/AethelredFoundation/aethelred-docs) | Documentation site | `docs/site/` |
| [AIPs](https://github.com/AethelredFoundation/AIPs) | Governance specs and protocol proposals | `docs/AIPs/` |
| [cruzible](https://github.com/AethelredFoundation/cruzible) | Explorer, staking, and governance app | `dApps/cruzible/` |

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

Aethelred runs an active security review and release-provenance program.

- Internal full-protocol review: completed
- External consultant VRF review: completed
- External mainnet audits for contracts and consensus-critical paths: in progress
- Security evidence index: [docs/audits/README.md](docs/audits/README.md)
- Release provenance: [docs/security/release-provenance.md](docs/security/release-provenance.md)

Found a vulnerability? See [SECURITY.md](SECURITY.md).

---

## Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

- [Aethelred Improvement Proposals](https://github.com/AethelredFoundation/AIPs)
- [Discord](https://discord.gg/aethelred)
- [Bug Reports](https://github.com/AethelredFoundation/aethelred/issues/new?template=bug_report.md)

---

## License

Apache-2.0 - see [LICENSE](LICENSE)

<p align="center">Built by the Aethelred Team</p>
