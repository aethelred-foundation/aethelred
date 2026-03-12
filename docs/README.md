<h1 align="center">Aethelred Documentation</h1>

<p align="center">
  <strong>Official documentation for the Aethelred sovereign L1 blockchain</strong>
</p>

<p align="center">
  <a href="https://docs.aethelred.io"><img src="https://img.shields.io/badge/live_docs-docs.aethelred.io-orange?style=flat-square" alt="Live Docs"></a>
  <a href="https://github.com/AethelredFoundation/aethelred-docs/actions"><img src="https://img.shields.io/github/actions/workflow/status/AethelredFoundation/aethelred-docs/docs-ci.yml?branch=main&style=flat-square&label=Build" alt="Build"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License"></a>
</p>

---

## Document Information

| Attribute | Value |
|-----------|-------|
| **Version** | 2.0.0 |
| **Status** | Approved for Engineering Implementation |
| **Classification** | Confidential - Authorized Personnel Only |
| **Effective Date** | February 2026 |
| **Review Date** | August 2026 |
| **Document Owner** | Aethelred Protocol Foundation |
| **Approved By** | Technical Steering Committee |

---

## Executive Summary

Aethelred is a **Layer-1 blockchain** purpose-built for **Verifiable AI Computation**. Unlike legacy blockchains that sell "blockspace," Aethelred sells **"Verified Intelligence"** - cryptographically proven AI outputs that enterprises can trust for regulatory compliance, financial decisions, and healthcare diagnostics.

### The Trust Trilemma Solution

| Challenge | Traditional Approach | Aethelred Solution |
|-----------|---------------------|-------------------|
| **Speed** | Software virtualization | Bare-metal GPU acceleration (NVIDIA H100) |
| **Privacy** | Encryption at rest | Hardware-enforced TEE (Intel SGX, AMD SEV) |
| **Verification** | Trust the operator | Zero-Knowledge proofs + Proof of Useful Work |

---

## Quick Start

### Installation

```bash
# Install the Aethelred CLI
curl -sSL https://get.aethelred.io | bash

# Verify installation
aethel --version
# aethelred-cli 2.0.0 (rustc 1.75.0)

# Initialize your first project
aethel init my-sovereign-app --template finance
cd my-sovereign-app
```

### Your First Sovereign Function

```python
from aethelred import sovereign, SovereignData
from aethelred.hardware import Hardware, Compliance

@sovereign(
    hardware=Hardware.AWS_NITRO,
    compliance=Compliance.UAE_DATA_RESIDENCY | Compliance.GDPR,
)
def analyze_transaction(data: SovereignData) -> SovereignData:
    """
    Analyze a financial transaction within UAE jurisdiction.
    Data never leaves the TEE enclave.
    """
    # Your ML model here
    result = model.predict(data.access())
    return SovereignData(result, jurisdiction="UAE")

# Execute with verification
result = analyze_transaction(transaction_data)
print(f"Seal ID: {result.seal_id}")  # Cryptographic proof on-chain
```

### Deploy to Testnet

```bash
# Configure your wallet
aethel account create --name developer

# Get testnet tokens (requires proof-of-work)
aethel faucet claim --network testnet

# Deploy and run
aethel run src/main.py --network testnet --hardware aws-nitro
```

---

## Documentation Structure

### Core Protocol

| Document | Description | Audience |
|----------|-------------|----------|
| [Protocol Overview](protocol/overview.md) | Mission, philosophy, and architecture | All |
| [Consensus Mechanism](protocol/consensus.md) | Proof of Useful Work (PoUW) deep dive | Architects |
| [Cryptographic Standards](protocol/cryptography.md) | Hybrid signatures, attestation | Security |
| [Tokenomics](protocol/tokenomics.md) | AETHEL utility and economics | Investors |
| [Institutional Stablecoin TRD V2](protocol/institutional-stablecoin-integration-trd-v2.md) | Testnet integration spec for USDC/USDT/USDU/DDSC | Protocol Engineers |
| [Multi-Architecture TEE Verification Protocol (Q3 2026)](protocol/multi-architecture-tee-verification-protocol-q3-2026.md) | SGX DCAP + AMD SEV-SNP parsing and consensus-safe translation rules | Protocol/Security Engineers |
| [Insurance Payout Formula Whitepaper (Nov 2026)](protocol/insurance-fund-actuarial-model-pre-mainnet-nov-2026.md) | Actuarial refund curve and per-incident indemnification cap for `x/insurance` | Risk, Treasury, Auditors |
| [DAO Transition Architecture (2027)](protocol/dao-transition-architecture-2027.md) | Role migration from institutional emergency control to OpenZeppelin Governor | Governance/Protocol Engineers |
| [Governance](governance/bicameral.md) | Bi-cameral governance model | Legal |

### Developer Guides

| Document | Description | Audience |
|----------|-------------|----------|
| [Getting Started](guides/getting-started.md) | First sovereign function | Developers |
| [Validator Onboarding CLI](guides/validator-onboarding-cli.md) | Institutional validator onboarding flow (stake + PCR0 + readiness) | Node Operators |
| [Python SDK](sdk/python.md) | Data science integration | ML Engineers |
| [TypeScript SDK](sdk/typescript.md) | Frontend and web3 | Web Developers |
| [Rust SDK](sdk/rust.md) | High-performance systems | Systems Engineers |
| [Official SDKs (Release Readiness)](sdk/official-sdks.md) | Install methods, version matrix, and registry/GitHub readiness for Python/TS/Rust/Go | SDK Maintainers / Integrators |
| [SDK Repo Split Playbook](sdk/REPO_SPLIT_PLAYBOOK.md) | Export `sdk/typescript` and `sdk/rust` into standalone GitHub-ready repos | SDK Maintainers / Release Engineering |
| [Helix DSL](sdk/helix-dsl.md) | Verifiable AI language (`.helix`) | Protocol/App Engineers |
| [Helix Tooling](guides/helix-tooling.md) | Editor/toolchain integration for `.helix` | App/Tooling Engineers |
| [Developer Tools Suite](sdk/developer-tools.md) | CLI, seal verifier, VS Code extension, local testnet, model registry, dev dashboard | App/Tooling Engineers |
| [Smart Contracts](guides/smart-contracts.md) | Sovereign contracts | Solidity Devs |

### API Reference

| Document | Description | Audience |
|----------|-------------|----------|
| [REST API](api/rest.md) | Node RPC endpoints | Backend |
| [GraphQL API](api/graphql.md) | Complex queries | Frontend |
| [WebSocket API](api/websocket.md) | Real-time subscriptions | Applications |

### Security & Compliance

| Document | Description | Audience |
|----------|-------------|----------|
| [Security Model](security/model.md) | Threat analysis and mitigations | Security |
| [Attestation](security/attestation.md) | TEE verification deep dive | Auditors |
| [Compliance Guide](security/compliance.md) | Regulatory requirements | Legal |
| [Best Practices](security/best-practices.md) | Production checklist | DevOps |

### Appendices

| Document | Description |
|---|---|
| [Developer Quickstart](DEVELOPER_QUICKSTART.md) | Get a local node running in 10 minutes |
| [Architecture](architecture.md) | System architecture deep-dive |
| [API Reference](API_REFERENCE.md) | Full REST + gRPC + WebSocket API |
| [SDK Guide](SDK_GUIDE.md) | Using the TypeScript, Python, Go, and Rust SDKs |
| [Validator Runbook](VALIDATOR_RUNBOOK.md) | Running a production validator node |
| [Cosmos Node](cosmos-node.md) | Cosmos SDK specifics |

---

## Sections

```
docs/
├── architecture.md          # System architecture
├── API_REFERENCE.md         # REST / gRPC / WS API reference
├── DEVELOPER_QUICKSTART.md  # Get started in 10 minutes
├── SDK_GUIDE.md             # SDK usage guide
├── VALIDATOR_RUNBOOK.md     # Validator operations
├── AIPs/                    # Aethelred Improvement Proposals (mirrored)
├── api/                     # Detailed API schemas
├── architecture/            # Architecture diagrams
├── cryptography/            # Cryptography specifications
├── governance/              # Governance process
├── guides/                  # Step-by-step guides
├── operations/              # Node operations
├── audits/                  # Security audit reports
└── appendices/              # Reference material
```

---

## Contributing to Docs

Found an error or want to improve the docs?

1. Fork this repo
2. Edit the relevant `.md` file
3. Open a PR - docs PRs are reviewed within 48 hours

For major doc changes or new sections, please open an [issue](https://github.com/AethelredFoundation/aethelred-docs/issues) first.

---

## Live Site

Docs are deployed automatically on every push to `main` via GitHub Pages / Vercel.

Live: **[docs.aethelred.io](https://docs.aethelred.io)**
