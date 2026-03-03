<p align="center">
 <img src="https://raw.githubusercontent.com/aethelred/.github/main/profile/banner.png" alt="Aethelred" width="900" />
</p>

<h2 align="center">Aethelred — The Sovereign Layer 1 for Verifiable AI</h2>

<p align="center">
 Proof-of-Useful-Work · Zero-Knowledge ML Proofs · TEE-backed Consensus · Post-Quantum Ready
</p>

<p align="center">
 <a href="https://docs.aethelred.io"><img src="https://img.shields.io/badge/docs-aethelred.io-orange?style=flat-square" /></a>
 <a href="https://discord.gg/aethelred"><img src="https://img.shields.io/discord/aethelred?style=flat-square&logo=discord&label=Discord&color=5865F2" /></a>
 <a href="https://twitter.com/aethelred_io"><img src="https://img.shields.io/badge/follow-%40aethelred__io-1DA1F2?style=flat-square&logo=twitter" /></a>
 <img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" />
</p>

---

### What We're Building

Aethelred is the first blockchain where **validator work has real-world value**. Instead of burning energy on meaningless hashes, validators run AI inference inside hardware TEEs and generate on-chain zero-knowledge proofs — creating a permanent, tamper-proof record of every AI computation.

```
AI job arrives → Validator TEE executes → zkML proof generated
 ↓
 2/3 BFT consensus → Digital Seal minted
```

---

### Ecosystem

| Repo | Description |
|---|---|
| [aethelred](https://github.com/AethelredFoundation/aethelred) | Core monorepo — Go node + Rust crates + x/ modules |
| [contracts](https://github.com/AethelredFoundation/contracts) | Solidity bridge, oracle, and governance contracts |
| [aethelred-sdk-ts](https://github.com/AethelredFoundation/aethelred-sdk-ts) | TypeScript / JavaScript SDK |
| [aethelred-sdk-py](https://github.com/AethelredFoundation/aethelred-sdk-py) | Python SDK |
| [aethelred-sdk-go](https://github.com/AethelredFoundation/aethelred-sdk-go) | Go SDK |
| [aethelred-sdk-rs](https://github.com/AethelredFoundation/aethelred-sdk-rs) | Rust SDK |
| [aethelred-cli](https://github.com/AethelredFoundation/aethelred-cli) | `aethel` CLI |
| [vscode-aethelred](https://github.com/AethelredFoundation/vscode-aethelred) | VS Code extension (unique in L1 space) |
| [aethelred-docs](https://github.com/AethelredFoundation/aethelred-docs) | Documentation site |
| [AIPs](https://github.com/AethelredFoundation/AIPs) | Aethelred Improvement Proposals |

---

### Technology Stack

| Layer | Technology |
|---|---|
| Consensus | CometBFT + ABCI++ (ExtendVote / PrepareProposal) |
| Application | Cosmos SDK (x/pouw, x/seal, x/verify) |
| Verification | EZKL, RISC Zero, Groth16, Halo2, Plonky2 |
| TEE | Intel SGX, AWS Nitro Enclaves, AMD SEV-SNP |
| Cryptography | Ed25519 + Dilithium3 (post-quantum) |
| Bridge | UUPS Solidity + EIP-712 relayer protocol |
| Cross-chain | IBC (Cosmos ecosystem) |
| Language | Go 1.22 (node), Rust 1.75 (VM/TEE), Solidity 0.8 (contracts) |

---

### Quick Links

- [Documentation](https://docs.aethelred.io)
- [Roadmap](https://docs.aethelred.io/roadmap)
- [Discord](https://discord.gg/aethelred)
- [Twitter](https://twitter.com/aethelred_io)
- [AIPs](https://github.com/AethelredFoundation/AIPs)
- [Security Policy](https://github.com/AethelredFoundation/aethelred/blob/main/SECURITY.md)
