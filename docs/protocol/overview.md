# Protocol Overview

<p align="center">
  <strong>Aethelred Protocol Technical Specification</strong><br/>
  <em>Version 2.0.0 | February 2026</em>
</p>

---

## Table of Contents

1. [Mission Statement](#1-mission-statement)
2. [The Sovereign Philosophy](#2-the-sovereign-philosophy)
3. [The Eight Pillars of Architecture](#3-the-eight-pillars-of-architecture)
4. [System Architecture](#4-system-architecture)
5. [Network Topology](#5-network-topology)
6. [Transaction Lifecycle](#6-transaction-lifecycle)
7. [Performance Characteristics](#7-performance-characteristics)

---

## 1. Mission Statement

### 1.1 Vision

Aethelred is a **Verifiable Compute Cloud** built on a Layer-1 blockchain. Unlike legacy chains (Ethereum, Solana) that sell "Blockspace," Aethelred sells **"Verified Intelligence"** — cryptographically proven AI computation results that enterprises can trust for regulatory compliance, financial decisions, and healthcare diagnostics.

Supported proof systems: **Groth16, PLONK, EZKL, Halo2, STARK** — all routing through the unified on-chain verifier surface.

Post-quantum cryptography: **ML-DSA-65** (FIPS 204, formerly Dilithium3) for signatures · **ML-KEM-768** (FIPS 203, formerly Kyber768) for key exchange.

### 1.2 The Trust Trilemma

Modern AI systems face a fundamental trust trilemma:

```
                    ┌─────────────────┐
                    │     SPEED       │
                    │   (Performance) │
                    └────────┬────────┘
                             │
              Can only pick two...
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    │                    ▼
┌───────────────┐            │            ┌───────────────┐
│    PRIVACY    │◄───────────┴───────────►│ VERIFICATION  │
│ (Confidential)│                         │   (Provable)  │
└───────────────┘                         └───────────────┘
```

**Aethelred resolves this trilemma:**

| Dimension | Challenge | Aethelred Solution |
|-----------|-----------|-------------------|
| **Speed** | Software virtualization adds 10-100x overhead | Bare-metal GPU acceleration with NVIDIA H100 Confidential Computing |
| **Privacy** | Data must be decrypted for processing | Hardware-enforced TEEs (Intel SGX, AMD SEV-SNP) enable "Blind Compute" |
| **Verification** | Black-box models produce unverifiable outputs | Zero-Knowledge proofs + Proof of Useful Work consensus |

### 1.3 Value Proposition

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           AETHELRED VALUE STACK                             │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                        VERIFIED INTELLIGENCE                         │  │
│   │   • Cryptographic proof that AI output is correct                   │  │
│   │   • Immutable audit trail for regulatory compliance                 │  │
│   │   • Digital seals for every computation                             │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                    │                                        │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                         SOVEREIGN COMPUTE                            │  │
│   │   • Data never leaves specified jurisdiction                        │  │
│   │   • Hardware-level isolation (TEE)                                  │  │
│   │   • Compliance built into consensus                                 │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                    │                                        │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                      DECENTRALIZED TRUST                             │  │
│   │   • No single point of failure                                      │  │
│   │   • Permissionless participation                                    │  │
│   │   • Cryptographic guarantees, not contractual                       │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. The Sovereign Philosophy

### 2.1 What is Sovereign Data?

Aethelred introduces the concept of **Sovereign Data Types**. Data on Aethelred is not just "bytes"; it is **"bytes + laws"**. The protocol enforces data sovereignty at the consensus level.

```rust
/// A piece of data bound to a legal jurisdiction
pub struct Sovereign<T> {
    /// The encrypted data payload
    data: EncryptedPayload<T>,

    /// Legal jurisdiction binding
    jurisdiction: Jurisdiction,

    /// Data classification level
    classification: DataClassification,

    /// Compliance requirements
    compliance: ComplianceFlags,

    /// Hardware requirements for access
    hardware_requirement: HardwareType,

    /// Access control policy
    access_policy: AccessPolicy,

    /// Cryptographic commitment
    commitment: Blake3Hash,
}
```

### 2.2 Jurisdiction Types

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SUPPORTED JURISDICTIONS                              │
├───────────────┬─────────────────────────────────────────────────────────────┤
│ Jurisdiction  │ Requirements                                                 │
├───────────────┼─────────────────────────────────────────────────────────────┤
│ UAE           │ Data residency required, TEE mandatory, ADGM/DIFC compliance (pending)│
│ Saudi Arabia  │ PDPL compliance, data localization (pending)                │
│ European Union│ GDPR compliance, adequacy decisions recognized (pending)    │
│ United Kingdom│ UK-GDPR, post-Brexit data transfer rules (pending)          │
│ United States │ CCPA, NY DFS, sector-specific HIPAA (pending)               │
│ Singapore     │ PDPA compliance, MAS guidelines for financial (pending)     │
│ China         │ PIPL, data localization, cross-border transfer rules (pending)│
│ Switzerland   │ nDSG / revDSG compliance, FINMA guidelines (pending)       │
│ India         │ DPDP Act 2023, data localization requirements (pending)     │
│ Global        │ Minimal restrictions, hardware verification only            │
└───────────────┴─────────────────────────────────────────────────────────────┘
```

### 2.3 Data Classification Levels

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DATA CLASSIFICATION MATRIX                           │
├─────────────┬───────────────┬────────────────┬────────────────┬─────────────┤
│ Level       │ Encryption    │ Hardware       │ Audit          │ Retention   │
├─────────────┼───────────────┼────────────────┼────────────────┼─────────────┤
│ PUBLIC      │ Optional      │ Generic        │ Optional       │ Unlimited   │
│ INTERNAL    │ At rest       │ Generic        │ Required       │ Policy      │
│ CONFIDENTIAL│ E2E           │ TEE preferred  │ Required       │ 7 years     │
│ SENSITIVE   │ E2E + PQ      │ TEE required   │ Immutable      │ Compliance  │
│ RESTRICTED  │ E2E + PQ + MPC│ TEE + Attested │ Immutable      │ Legal hold  │
│ TOP_SECRET  │ Multi-party   │ Air-gapped TEE │ Real-time      │ Indefinite  │
└─────────────┴───────────────┴────────────────┴────────────────┴─────────────┘
```

---

## 3. The Eight Pillars of Architecture

Aethelred's architecture is built on eight foundational pillars, collectively known as **"The Octagon"**. Each pillar represents a critical capability that together form the protocol's competitive moat.

```
                              ┌─────────────────┐
                              │   AETHELRED     │
                              │   PROTOCOL      │
                              └────────┬────────┘
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         │                             │                             │
    ┌────┴────┐                   ┌────┴────┐                   ┌────┴────┐
    │CONSENSUS│                   │SECURITY │                   │ PRIVACY │
    │  PoUW   │                   │Quantum  │                   │Sovereign│
    │         │                   │Immune   │                   │  TEE    │
    └────┬────┘                   └────┬────┘                   └────┬────┘
         │                             │                             │
    ┌────┴────┐                   ┌────┴────┐                   ┌────┴────┐
    │  SPEED  │                   │ ECONOMY │                   │GOVERNANCE│
    │   AI    │                   │Congestion│                  │Bi-Cameral│
    │Precompiles                  │Squared  │                   │ Senate  │
    └────┬────┘                   └────┬────┘                   └────┬────┘
         │                             │                             │
         └──────────┬──────────────────┼──────────────────┬──────────┘
                    │                  │                  │
               ┌────┴────┐        ┌────┴────┐        ┌────┴────┐
               │ INTEROP │        │ STORAGE │        │COMPLIANCE│
               │Zero-Copy│        │Vector   │        │  Legal  │
               │ Bridge  │        │ Vault   │        │ Linter  │
               └─────────┘        └─────────┘        └─────────┘
```

### Pillar Details

| # | Pillar | Feature | Function | Competitive Advantage |
|---|--------|---------|----------|----------------------|
| 1 | **Consensus** | Proof of Useful Work (PoUW) | 80% compute → AI inference, 20% → consensus | Replaces wasteful hashing with productive AI jobs |
| 2 | **Security** | Native Quantum Immunity | Hybrid signatures (Dilithium3 + ECDSA) | Protects assets from post-2030 quantum computers |
| 3 | **Privacy** | Sovereign TEE Enclaves | Intel SGX / AMD SEV-SNP hardware isolation | Enables "Blind Compute" for medical/banking data |
| 4 | **Speed** | AI Pre-Compiles | Native VM opcodes for MatMul, ReLU, Attention | 1,000x faster verification of neural networks |
| 5 | **Economy** | Congestion-Squared Burn | Fee burn = Network Load² | High demand creates exponential deflation |
| 6 | **Governance** | Bi-Cameral Senate | House of Tokens + House of Validators | Prevents mob rule while ensuring enterprise stability |
| 7 | **Interop** | Zero-Copy Data Bridge | Pointer swizzling for external data | Process petabytes of S3 data without on-chain movement |
| 8 | **Storage** | Vector-Vault | Native vector embedding storage | Protocol acts as global database for LLMs |

---

## 4. System Architecture

### 4.1 Layered Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              APPLICATION LAYER                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ Python SDK  │  │   TS SDK    │  │  Rust SDK   │  │   Go SDK    │        │
│  │ @sovereign  │  │ ZK Forms    │  │ no_std      │  │ Terraform   │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
├─────────────────────────────────────────────────────────────────────────────┤
│                              EXECUTION LAYER                                 │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         AETHELRED VIRTUAL MACHINE                      │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │  │
│  │  │   EVM++     │  │ AI Precompile│ │  WASM RT    │  │ Helix DSL   │   │  │
│  │  │ Compatible  │  │ MatMul/Attn │  │ Sandboxed   │  │ Compiler    │   │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────────────────┤
│                              CONSENSUS LAYER                                 │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                     PROOF OF USEFUL WORK (PoUW)                        │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │  │
│  │  │ Job Router  │  │ Validator   │  │ Verification│  │ Finality    │   │  │
│  │  │ (Matching)  │  │ Selection   │  │ (ZK + TEE)  │  │ (CometBFT)  │   │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                DATA LAYER                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   State     │  │  Vector     │  │   Blob      │  │   Bridge    │        │
│  │   Merkle    │  │   Vault     │  │   Storage   │  │   Proofs    │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
├─────────────────────────────────────────────────────────────────────────────┤
│                              NETWORK LAYER                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │    P2P      │  │  Gossip     │  │    Sync     │  │   Mempool   │        │
│  │  (libp2p)   │  │  Protocol   │  │  (Warp)     │  │   (FIFO)    │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
├─────────────────────────────────────────────────────────────────────────────┤
│                              HARDWARE LAYER                                  │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      TRUSTED EXECUTION ENVIRONMENTS                    │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │  │
│  │  │ Intel SGX   │  │  AMD SEV    │  │ AWS Nitro   │  │ NVIDIA H100 │   │  │
│  │  │   DCAP      │  │   SNP       │  │  Enclaves   │  │    CC       │   │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Module Dependency Graph

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AETHELRED CORE MODULES                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                          ┌───────────────┐                                  │
│                          │   aethelred   │                                  │
│                          │   (umbrella)  │                                  │
│                          └───────┬───────┘                                  │
│                                  │                                          │
│          ┌───────────────────────┼───────────────────────┐                  │
│          │                       │                       │                  │
│          ▼                       ▼                       ▼                  │
│   ┌─────────────┐         ┌─────────────┐         ┌─────────────┐          │
│   │  x/compute  │         │   x/seal    │         │ x/validator │          │
│   │   (Jobs)    │         │  (Proofs)   │         │  (Staking)  │          │
│   └──────┬──────┘         └──────┬──────┘         └──────┬──────┘          │
│          │                       │                       │                  │
│          └───────────────────────┼───────────────────────┘                  │
│                                  │                                          │
│                          ┌───────┴───────┐                                  │
│                          │    x/poc      │                                  │
│                          │  (Consensus)  │                                  │
│                          └───────┬───────┘                                  │
│                                  │                                          │
│          ┌───────────────────────┼───────────────────────┐                  │
│          │                       │                       │                  │
│          ▼                       ▼                       ▼                  │
│   ┌─────────────┐         ┌─────────────┐         ┌─────────────┐          │
│   │   crypto    │         │ attestation │         │ compliance  │          │
│   │(Signatures) │         │   (TEE)     │         │  (Legal)    │          │
│   └─────────────┘         └─────────────┘         └─────────────┘          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Network Topology

### 5.1 Node Types

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              NODE TYPES                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         VALIDATOR NODES                              │    │
│  │                                                                      │    │
│  │  Requirements:                                                       │    │
│  │  • Minimum Stake: 100,000 AETHEL                                    │    │
│  │  • Hardware: NVIDIA H100 (80GB) + Intel Ice Lake (SGX)              │    │
│  │  • Uptime SLA: 99.9%                                                │    │
│  │  • KYC/AML: Required for House of Sovereigns participation         │    │
│  │                                                                      │    │
│  │  Responsibilities:                                                   │    │
│  │  • Execute AI inference jobs in TEE                                 │    │
│  │  • Generate ZK proofs for computations                              │    │
│  │  • Participate in consensus voting                                  │    │
│  │  • Maintain attestation freshness                                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                          SENTRY NODES                                │    │
│  │                                                                      │    │
│  │  Requirements:                                                       │    │
│  │  • No stake required                                                │    │
│  │  • Standard server hardware                                         │    │
│  │  • DDoS protection recommended                                      │    │
│  │                                                                      │    │
│  │  Responsibilities:                                                   │    │
│  │  • Shield validators from direct internet exposure                  │    │
│  │  • Relay transactions and blocks                                    │    │
│  │  • Provide RPC endpoints for users                                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         ARCHIVE NODES                                │    │
│  │                                                                      │    │
│  │  Requirements:                                                       │    │
│  │  • Large storage (10+ TB)                                           │    │
│  │  • High bandwidth                                                   │    │
│  │                                                                      │    │
│  │  Responsibilities:                                                   │    │
│  │  • Store full historical state                                      │    │
│  │  • Serve historical queries                                         │    │
│  │  • Support block explorers                                          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                          LIGHT NODES                                 │    │
│  │                                                                      │    │
│  │  Requirements:                                                       │    │
│  │  • Minimal resources (mobile/browser)                               │    │
│  │                                                                      │    │
│  │  Responsibilities:                                                   │    │
│  │  • Verify block headers only                                        │    │
│  │  • Query state proofs                                               │    │
│  │  • Submit transactions via RPC                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Network Topology Diagram

```
                                 INTERNET
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
              ┌─────┴─────┐   ┌─────┴─────┐   ┌─────┴─────┐
              │  Sentry   │   │  Sentry   │   │  Sentry   │
              │  Node A   │   │  Node B   │   │  Node C   │
              └─────┬─────┘   └─────┬─────┘   └─────┬─────┘
                    │               │               │
                    └───────────────┼───────────────┘
                                    │
                          ┌─────────┴─────────┐
                          │   PRIVATE MESH    │
                          │    (Validator)    │
                          └─────────┬─────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         │                          │                          │
    ┌────┴────┐                ┌────┴────┐                ┌────┴────┐
    │Validator│                │Validator│                │Validator│
    │  UAE    │◄──────────────►│   SG    │◄──────────────►│   EU    │
    │ (H100)  │                │ (H100)  │                │ (H100)  │
    └────┬────┘                └────┬────┘                └────┬────┘
         │                          │                          │
    ┌────┴────┐                ┌────┴────┐                ┌────┴────┐
    │ Archive │                │ Archive │                │ Archive │
    │  UAE    │                │   SG    │                │   EU    │
    └─────────┘                └─────────┘                └─────────┘
```

---

## 6. Transaction Lifecycle

### 6.1 Compute Job Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         COMPUTE JOB LIFECYCLE                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Step 1: JOB SUBMISSION                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  User submits:                                                       │    │
│  │  • Model ID (hash of registered model)                              │    │
│  │  • Encrypted input data                                             │    │
│  │  • Hardware requirements                                            │    │
│  │  • Jurisdiction constraints                                         │    │
│  │  • Fee (in AETHEL)                                                  │    │
│  └───────────────────────────────────┬─────────────────────────────────┘    │
│                                      │                                       │
│                                      ▼                                       │
│  Step 2: ROUTER ALLOCATION                                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  The Useful Work Router:                                            │    │
│  │  • Matches job to validator based on:                               │    │
│  │    - Hardware capabilities                                          │    │
│  │    - Geographic jurisdiction                                        │    │
│  │    - Current load                                                   │    │
│  │    - Reputation score                                               │    │
│  │  • Creates binding commitment                                       │    │
│  └───────────────────────────────────┬─────────────────────────────────┘    │
│                                      │                                       │
│                                      ▼                                       │
│  Step 3: EXECUTION (In TEE)                                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Inside the secure enclave:                                         │    │
│  │  • Validator verifies attestation                                   │    │
│  │  • Decrypts input data using sealed keys                           │    │
│  │  • Loads model into TEE memory                                      │    │
│  │  • Executes inference                                               │    │
│  │  • Encrypts output for user                                         │    │
│  └───────────────────────────────────┬─────────────────────────────────┘    │
│                                      │                                       │
│                                      ▼                                       │
│  Step 4: PROOF GENERATION                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Validator generates:                                               │    │
│  │  • TEE attestation report (hardware proof)                          │    │
│  │  • ZK-SNARK (optional, for zkML verification)                       │    │
│  │  • Output commitment (hash of result)                               │    │
│  │  • Execution trace (for reproducibility)                            │    │
│  └───────────────────────────────────┬─────────────────────────────────┘    │
│                                      │                                       │
│                                      ▼                                       │
│  Step 5: CONSENSUS VERIFICATION                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Network validates:                                                 │    │
│  │  • Attestation signature chain                                      │    │
│  │  • ZK proof verification (if applicable)                           │    │
│  │  • Output commitment matches                                        │    │
│  │  • Jurisdiction compliance                                          │    │
│  └───────────────────────────────────┬─────────────────────────────────┘    │
│                                      │                                       │
│                                      ▼                                       │
│  Step 6: FINALITY                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Upon acceptance:                                                   │    │
│  │  • Block reward distributed to validator                            │    │
│  │  • Fee burned (congestion-squared)                                  │    │
│  │  • Digital Seal created on-chain                                    │    │
│  │  • User receives encrypted result                                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 State Transitions

```
    ┌─────────┐
    │ PENDING │  User submits job
    └────┬────┘
         │
         ▼ Router assigns validator
    ┌─────────┐
    │SCHEDULED│
    └────┬────┘
         │
         ▼ Validator accepts job
    ┌─────────┐
    │ RUNNING │  Execution in TEE
    └────┬────┘
         │
         ├────────────────────────────────┐
         │                                │
         ▼ Success                        ▼ Failure
    ┌─────────┐                      ┌─────────┐
    │VERIFYING│                      │ FAILED  │  → Retry/Refund
    └────┬────┘                      └─────────┘
         │
         ▼ Proof verified
    ┌─────────┐
    │COMPLETED│  → Digital Seal created
    └─────────┘
```

---

## 7. Performance Characteristics

### 7.1 Benchmarks

> **Note:** Specific throughput and finality numbers are withheld from public distribution pending benchmark pack verification. The figures below are internal testnet targets and are subject to change before mainnet.

| Metric | Target | Testnet Reference | Notes |
|--------|--------|----------|-------|
| Block Time | 3 seconds | ~2.8 seconds | CometBFT with optimizations |
| Finality | Instant | Instant | No reorgs (BFT) |
| TPS (Transfers) | 8,500+ | Internal target | Standard ECDSA transfers |
| TPS (Compute Jobs) | 500+ | Internal target | Depends on job complexity |
| Inference Latency | < 100ms | ~45ms | Llama-3 8B, batch size 1 |
| TEE Attestation Latency | < 5s | ~10ms (on-chain verify) | Hardware attestation + chain verify |
| ZK Proof Latency (Optional) | < 30s | 5–30 seconds | EZKL/Halo2 for small-to-mid models |

### 7.2 Scalability Roadmap

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SCALABILITY ROADMAP                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Phase 1: VERTICAL SCALING (Current)                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  • Single-chain with powerful validators                            │    │
│  │  • 100 validators, each with H100 + SGX                             │    │
│  │  • Target: 1,000 compute jobs/second                                │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  Phase 2: HORIZONTAL SCALING (2027)                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  • Jurisdiction-specific shards (UAE, EU, US)                       │    │
│  │  • Cross-shard communication via IBC                                │    │
│  │  • Target: 10,000 compute jobs/second                               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  Phase 3: DATA AVAILABILITY (2028)                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  • Dedicated DA layer for model weights                             │    │
│  │  • Erasure coding for redundancy                                    │    │
│  │  • Target: Petabyte-scale model storage                             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Next Steps

- **[Consensus Mechanism](consensus.md)**: Deep dive into Proof of Useful Work
- **[Cryptographic Standards](cryptography.md)**: Hybrid signatures and attestation
- **[Tokenomics](tokenomics.md)**: AETHEL utility and economics

---

<p align="center">
  <em>© 2026 Aethelred Protocol Foundation. All Rights Reserved.</em>
</p>
