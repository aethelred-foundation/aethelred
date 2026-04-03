<p align="center">
 <img src="README-logo.png" alt="Aethelred" width="320" />
</p>

<h1 align="center">Aethelred</h1>

<p align="center">
 <strong>The Sovereign Layer 1 for Verifiable AI</strong><br/>
 Proof-of-Useful-Work consensus · ML-DSA-65 + ECDSA hybrid · On-chain zkML &amp; TEE verification
</p>

<p align="center">
 <a href="https://github.com/aethelred-foundation/aethelred/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/aethelred-foundation/aethelred/ci.yml?branch=main&style=flat-square&label=CI" alt="CI"></a>
 <a href="https://github.com/aethelred-foundation/aethelred/actions/workflows/security-scans.yml"><img src="https://img.shields.io/github/actions/workflow/status/aethelred-foundation/aethelred/security-scans.yml?branch=main&style=flat-square&label=Security" alt="Security"></a>
 <a href="https://github.com/aethelred-foundation/aethelred/actions/workflows/contracts-ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/aethelred-foundation/aethelred/contracts-ci.yml?branch=main&style=flat-square&label=Contracts" alt="Contracts"></a>
 <a href="https://github.com/aethelred-foundation/aethelred/actions/workflows/rust-crates-ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/aethelred-foundation/aethelred/rust-crates-ci.yml?branch=main&style=flat-square&label=Rust" alt="Rust"></a>
 <img src="https://img.shields.io/badge/status-testnet--v1.0-yellow?style=flat-square" alt="Status: Testnet v1.0">
 <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License"></a>
</p>
<p align="center">
 <img src="https://img.shields.io/badge/Go-1.24-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
 <img src="https://img.shields.io/badge/Rust-1.85-DEA584?style=flat-square&logo=rust&logoColor=white" alt="Rust">
 <img src="https://img.shields.io/badge/Solidity-0.8.20-363636?style=flat-square&logo=solidity&logoColor=white" alt="Solidity">
 <img src="https://img.shields.io/badge/Cosmos_SDK-v0.50-2E3148?style=flat-square" alt="Cosmos SDK">
 <img src="https://img.shields.io/badge/CometBFT-v0.38-blue?style=flat-square" alt="CometBFT">
 <img src="https://img.shields.io/badge/PQC-ML--KEM--768+ML--DSA--65-purple?style=flat-square" alt="PQC">
</p>
<p align="center">
 <a href="https://discord.gg/aethelred"><img src="https://img.shields.io/badge/Discord-community-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord"></a>
 <a href="https://www.aethelred.org"><img src="https://img.shields.io/badge/website-aethelred.org-111827?style=flat-square" alt="Website"></a>
 <a href="https://www.aethelred.io"><img src="https://img.shields.io/badge/protocol-aethelred.io-f97316?style=flat-square" alt="Protocol"></a>
 <a href="https://docs.aethelred.io"><img src="https://img.shields.io/badge/docs-docs.aethelred.io-orange?style=flat-square" alt="Docs"></a>
 <a href="https://github.com/aethelred-foundation/AIPs"><img src="https://img.shields.io/badge/AIPs-proposals-purple?style=flat-square" alt="AIPs"></a>
 <a href="docs/WHITEPAPER.md"><img src="https://img.shields.io/badge/whitepaper-public%20draft-0f766e?style=flat-square" alt="Whitepaper"></a>
 <a href="docs/TOKENOMICS.md"><img src="https://img.shields.io/badge/tokenomics-public%20draft-14532d?style=flat-square" alt="Tokenomics"></a>
</p>

---

> **Classification: Public Reference** — This README is a public-facing project overview. For canonical disclosure documents, see `docs/WHITEPAPER.md` and `docs/TOKENOMICS.md`. ADGM DLT Foundation registration is in preparation. No content in this repository constitutes an offer of securities or regulated financial products.

---

## What is Aethelred?

Aethelred is a sovereign **Cosmos SDK / CometBFT** Layer 1 built for **regulated and high-assurance AI workloads**. It combines deterministic settlement, **Proof-of-Useful-Work (PoUW)**, confidential execution in approved **TEE backends**, **zkML verification**, and **Digital Seals** so enterprises, operators, and auditors can verify what ran, where it ran, and how the result was anchored on-chain.

The public-facing protocol posture is governed by the canonical draft [whitepaper](docs/WHITEPAPER.md), public [tokenomics paper](docs/TOKENOMICS.md), and the official sites at [aethelred.org](https://www.aethelred.org) and [aethelred.io](https://www.aethelred.io). Launch, valuation, float, and counterparty claims are intentionally withheld from this overview until approved for public disclosure.

```
AI Job Submitted → VRF Scheduler → Validator TEE Execution
 ↓
 zkML Proof Generated → Vote Extension (ABCI++)
 ↓
 2/3 Consensus → Digital Seal Minted → Job Settled
```

### Protocol Snapshot

| Metric | Current Public Posture |
|---|---|
| **Native token** | `AETHEL` |
| **Total supply** | `10,000,000,000 AETHEL` fixed at genesis |
| **Post-genesis inflation** | `0%` |
| **Core token utility** | Staking, fees, slashing collateral, governance, verified-compute settlement |
| **Verification surface** | Digital Seals, TEE attestation, zkML proof verification |
| **Supported proof systems** | Groth16, PLONK, EZKL, Halo2, STARK |
| **Confidential compute posture** | Intel SGX, AMD SEV-SNP, AWS Nitro, Azure Confidential VMs, Google Confidential VMs, NVIDIA confidential-computing paths |
| **Public disclosure rule** | Performance, launch, float, valuation, and counterparty claims publish only after canonical approval |

### Why Aethelred?

| Feature | Aethelred | Ethereum L2s | Centralized APIs |
|---|---|---|---|
| **Verifiable AI** | TEE + zkML + Digital Seals | Mostly off-chain | Trust-based |
| **Confidential compute** | Policy-aware confidential execution | Limited / app-specific | Vendor-controlled |
| **Post-quantum posture** | ML-DSA-65 + ML-KEM-768 hybrid design | Classical-first | Rare |
| **Evidence portability** | Portable seal + proof artifact model | Fragmented | Fragmented |
| **Governed disclosure** | Claims, readiness, and launch posture tracked in-repo | Rare | Opaque |

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

**Requirements**: Go 1.24+, Rust 1.85+, Docker

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

### Core Infrastructure & SDKs

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

### Flagship dApps

| dApp | Description |
|---|---|
| [cruzible](https://github.com/aethelred-foundation/cruzible) | Liquid staking — stake AETHEL and receive liquid staking tokens |
| [zeroid](https://github.com/aethelred-foundation/zeroid) | Decentralized identity — ZK-backed self-sovereign identity on-chain |
| [noblepay](https://github.com/aethelred-foundation/noblepay) | Cross-border payments — TEE-verified stablecoin settlement |
| [terraqura](https://github.com/aethelred-foundation/terraqura) | Carbon credits — verifiable carbon credit issuance and retirement |
| [shiora](https://github.com/aethelred-foundation/shiora) | Health data platform — sovereign, jurisdiction-bound health data compute |

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

## Operator Model

Aethelred separates **consensus participation** from **compute-heavy verification responsibilities** so the network can support both standard validator operations and higher-assurance confidential-compute paths.

- **Consensus validators** handle block proposal, settlement, and protocol state transitions.
- **Compute-capable operators** add TEE-backed execution, proof generation, and heavier verification workloads.
- **Operator truth source** is the release bundle and runbooks, not this overview page.

For current operator guidance, use:

- [Testnet Validator Runbook](docs/TESTNET_VALIDATOR_RUNBOOK.md)
- [Mainnet Validator Runbook](docs/VALIDATOR_RUNBOOK.md)
- [Hardware Requirements](docs/validator/HARDWARE_REQUIREMENTS.md)

---

## Cross-Chain Bridge

Aethelred bridges to Ethereum via **Circle CCTP V2** (native USDC — no wrapped tokens, no AMM/LP custody):

1. Source-chain USDC is burned via Circle `TokenMessengerV2`
2. Cross-domain attestation validated by Circle infrastructure
3. Destination-chain USDC natively minted after message validation

Additional sovereign stablecoins (USDU, DDSC) are supported through separate institutional asset controls. The Security Council can freeze bridge transfers immediately via emergency halt.

---

## Current Public Delivery Posture

This repository follows the same disclosure posture as the public whitepaper and tokenomics paper:

- **Architecture, token design, and operator surfaces** are public.
- **Fixed supply and zero post-genesis inflation** are public.
- **Launch timing, float, valuation, fundraising, and named commercial counterparties** are not asserted here unless approved for public disclosure.
- **Testnet readiness** is treated as an operational program backed by release bundles, runbooks, CI evidence, and hosted topology checks.
- **Mainnet and TGE communications** remain gated by technical readiness, legal review, and disclosure approval.

Canonical public references:

- [Whitepaper](docs/WHITEPAPER.md)
- [Tokenomics](docs/TOKENOMICS.md)
- [Protocol Overview](docs/protocol/overview.md)
- [Official site](https://www.aethelred.org)
- [Protocol site](https://www.aethelred.io)

---

## Security

Aethelred's public security posture is tracked in-repo and backed by evidence:

- Post-Quantum Cryptography: ML-DSA-65 (Dilithium3, FIPS 204) + ECDSA hybrid signatures; ML-KEM-768 (FIPS 203) for key exchange
- TEE Platforms: Intel SGX (DCAP), AMD SEV-SNP, AWS Nitro Enclaves, Azure Confidential VMs, Google Confidential VMs, NVIDIA H100 CC
- Circuit Breaker: Automatic halt on anomaly detection
- Encrypted Mempool: Threshold encryption against front-running
- Internal Security Review: **27 findings remediated and verified**
- Internal Full Audit v2: **36 findings closed**
- External audit scopes: **in progress**

See:

- [Audit Status Tracker](docs/audits/STATUS.md)
- [Security Policy](SECURITY.md)
- [Threat Model](docs/security/threat-model.md)
- [Release Provenance](docs/security/release-provenance.md)

---

## Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

- [Aethelred Improvement Proposals](https://github.com/aethelred-foundation/AIPs)
- [Discord](https://discord.gg/aethelred)
- [Bug Reports](https://github.com/aethelred-foundation/aethelred/issues/new?template=bug_report.yml)

---

## License

Apache-2.0 - see [LICENSE](LICENSE)

<p align="center">Built by the Aethelred Team</p>
