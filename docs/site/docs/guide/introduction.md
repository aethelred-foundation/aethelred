# Introduction

Aethelred is an enterprise-grade AI blockchain platform that unifies post-quantum cryptography, trusted execution environments, and zero-knowledge machine-learning proofs into a single decentralized protocol. It is designed for organizations that need cryptographic guarantees over AI model integrity, data sovereignty, and regulatory compliance -- without sacrificing performance.

## Why Aethelred?

Traditional blockchains treat computation as an afterthought. Aethelred treats it as the primary workload. Every node in the network can attest hardware capabilities, execute AI inference inside TEE enclaves, and produce succinct zero-knowledge proofs that a given model produced a given output -- all while keeping training data private and jurisdiction-bound.

| Capability | How Aethelred Delivers It |
|---|---|
| **Post-quantum signatures** | Hybrid ECDSA + Dilithium3 on every transaction |
| **Post-quantum key exchange** | Kyber768 KEM for node-to-node channels |
| **TEE attestation** | SGX DCAP, AMD SEV-SNP, AWS Nitro -- first-class on-chain verification |
| **zkML proofs** | Groth16, PLONK, and STARK backends for model-inference verification |
| **Sovereign data** | Compile-time jurisdiction enforcement with hardware-backed constraints |
| **Consensus** | BFT + Proof-of-Useful-Work (PoUW) -- validators earn rewards by running real AI workloads |

## Key Differentiators

### 1. Digital Seals

A [Digital Seal](/guide/digital-seals) binds a model checkpoint, its training provenance, and a TEE attestation quote into a single on-chain artifact. Downstream consumers can verify, in constant time, that a model was trained on declared data inside a genuine enclave.

### 2. Sovereign Data Containers

[Sovereign Data](/guide/sovereign-data) containers enforce jurisdictional rules at the SDK level. Data tagged with `EU-GDPR` constraints physically cannot leave an EU-region enclave -- the runtime refuses to serialize it across non-compliant boundaries.

### 3. Proof-of-Useful-Work

Unlike proof-of-stake or proof-of-work, Aethelred's PoUW consensus rewards [validators](/guide/validators) for executing real AI inference and training jobs submitted by network participants. Wasted energy is minimized; useful computation is maximized.

### 4. Multi-Language SDKs

Aethelred ships first-party SDKs in four languages:

- **[Go SDK](/api/go/)** -- idiomatic client, runtime, tensor, neural-network, and crypto packages
- **[Rust SDK](/api/rust/)** -- zero-copy sovereign containers, attestation, and zk-tensor crate
- **[TypeScript SDK](/api/typescript/)** -- browser and Node.js compatible, WASM-accelerated tensors
- **[Python SDK](/api/python/)** -- NumPy-interoperable tensors, PyTorch-compatible training loops

## Architecture at a Glance

```
 User / Application
       |
  SDK (Go / Rust / TS / Python)
       |
  ┌────┴────┐
  │  Client │ ── RPC / gRPC ──► Aethelred Node
  └────┬────┘                      │
       │                    ┌──────┴──────┐
  Local Compute             │  Consensus  │
  (Runtime, Tensors,        │  (BFT+PoUW) │
   Neural Nets)             └──────┬──────┘
       │                           │
  TEE Enclave               On-chain State
  (SGX / SEV / Nitro)       (Seals, Models, Jobs)
```

For a detailed breakdown, see [Architecture](/guide/architecture).

## Who Is Aethelred For?

- **Financial institutions** that need auditable AI decisions with post-quantum security
- **Healthcare organizations** running federated learning across jurisdictions
- **Defense and intelligence** agencies requiring hardware-attested model provenance
- **Research labs** publishing reproducible ML results with on-chain verification
- **Enterprises** adopting AI agents that must prove their reasoning chain

## Next Steps

- [Quick Start](/guide/getting-started) -- run your first Aethelred transaction in five minutes
- [Installation](/guide/installation) -- set up SDKs and the CLI
- [Architecture](/guide/architecture) -- deep dive into the protocol layers
