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
 <a href="https://aethelred-foundation.github.io/aethelred/"><img src="https://img.shields.io/badge/docs-aethelred.io-orange?style=flat-square" alt="Docs"></a>
 <a href="https://github.com/aethelred-foundation/AIPs"><img src="https://img.shields.io/badge/AIPs-proposals-purple?style=flat-square" alt="AIPs"></a>
</p>

---

## What is Aethelred?

Aethelred is a sovereign **Cosmos SDK / CometBFT** Layer 1 blockchain purpose-built for **verifiable AI computation**. Instead of burning energy on meaningless hashes, validators perform **Proof-of-Useful-Work (PoUW)** — running AI inference jobs inside **Intel SGX · AMD SEV-SNP · AWS Nitro · Azure Confidential VMs · Google Confidential VMs · NVIDIA H100 CC** TEEs and generating **zero-knowledge ML proofs** (Groth16, PLONK, EZKL, Halo2, STARK) that are verified on-chain in every block.

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
| **Quantum-Safe** | ML-DSA-65 + ECDSA | ECDSA only | No |
| **Decentralized** | Up to 100 institutional validators | Partial | No |
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

## Validator Network

Aethelred operates a **dual-tier validator architecture**:

| Node Type | Role | Revenue Share | TEE Required | Min Stake |
|---|---|---|---|---|
| **Standard Validator** | Consensus, block proposal, light verification | 30% of fees | Optional | 100,000 AETHEL |
| **Compute Prover** | AI inference, zkML proof generation, heavy TEE workloads | 70% of fees | **Mandatory** | 250,000 AETHEL |

**Compute Prover minimum hardware:** NVIDIA A100/H100 80GB GPU · Xilinx Alveo U280 FPGA · 64-core AMD EPYC · 256 GB ECC RAM · Intel SGX or AMD SEV-SNP TEE

Operators may run both node types on the same machine. See [Hardware Requirements](docs/validator/HARDWARE_REQUIREMENTS.md) for full specs and reference architectures.

---

## Cross-Chain Bridge

Aethelred bridges to Ethereum via **Circle CCTP V2** (native USDC — no wrapped tokens, no AMM/LP custody):

1. Source-chain USDC is burned via Circle `TokenMessengerV2`
2. Cross-domain attestation validated by Circle infrastructure
3. Destination-chain USDC natively minted after message validation

Additional sovereign stablecoins (USDU, DDSC) are supported through separate institutional asset controls. The Security Council can freeze bridge transfers immediately via emergency halt.

---

## Roadmap

| Date | Milestone |
|---|---|
| Mar 2026 | Seals Points Program launch · Seed Round closes |
| **May 2026** | **Testnet infrastructure live — points begin accruing** |
| Jun–Jul 2026 | Echo Community Round ($150M FDV) |
| Aug 2026 | Trail of Bits audit complete |
| Sep 2026 | Binance strategic allocation signed |
| Oct–Nov 2026 | Binance Prime Sale ($300M FDV) |
| Nov 2026 | Airdrop snapshot taken |
| **Dec 7–10, 2026** | **TGE @ Abu Dhabi FinTech Week (ADFW) · $3B FDV** |
| 2027 | Phase 2: Jurisdiction-specific shards (UAE, EU, US) via IBC |
| 2028 | Phase 3: Dedicated DA layer for model weights (petabyte-scale) |

---

## Security

Aethelred has been security-audited with **27 findings remediated** (2026-02-28).

- Post-Quantum Cryptography: ML-DSA-65 (Dilithium3, FIPS 204) + ECDSA hybrid signatures; ML-KEM-768 (FIPS 203) for key exchange
- TEE Platforms: Intel SGX (DCAP), AMD SEV-SNP, AWS Nitro Enclaves, Azure Confidential VMs, Google Confidential VMs, NVIDIA H100 CC
- Circuit Breaker: Automatic halt on anomaly detection
- Encrypted Mempool: Threshold encryption against front-running
- Compliance: GDPR, HIPAA, OFAC, CCPA native enforcement (certification pending)

Found a vulnerability? See [SECURITY.md](SECURITY.md).

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
