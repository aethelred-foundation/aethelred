# ZeroID

**Self-sovereign identity. Zero-knowledge proofs. TEE-verified credentials.**

ZeroID is a full-stack self-sovereign identity platform built on [Aethelred](/guide/introduction) — a sovereign Layer 1 optimised for verifiable AI computation. Users can create decentralised identities, issue and verify credentials using zero-knowledge proofs, bridge identities across chains, and manage regulatory compliance — all without revealing private data.

> **Status** — Pre-mainnet. 20+ pages, 12 contracts, and 9 ZK circuits under active development.

## Features

### Self-Sovereign Identity
- DID creation and resolution (W3C-compliant)
- Verifiable credential issuance and management
- Selective disclosure with BBS+ signatures
- Cross-chain identity bridge (EVM, Cosmos)

### Zero-Knowledge Proofs
- Age verification without revealing date of birth
- Residency and nationality proof circuits
- Credit tier scoring with privacy preservation
- BBS+ selective disclosure and threshold credentials

### AI-Powered Compliance
- AI agent identity registry and verification
- Behavioral biometrics for fraud detection
- Real-time risk scoring engine
- Compliance copilot for regulatory guidance

### Enterprise & Government
- Multi-jurisdiction regulatory compliance
- OFAC and global sanctions screening
- Jurisdiction-aware policy engine
- Data sovereignty with geographic constraints

## Architecture

```
Frontend (Next.js 14 / React 18 / Tailwind CSS / RainbowKit / wagmi)
    |
API Gateway (Express / TypeScript / Prisma ORM / JWT Auth)
    |
    +--- ZK Circuit Layer (Circom 2.1 / snarkjs / 9 proof circuits)
    +--- Smart Contracts (Solidity 0.8.20 / Foundry + Hardhat / 12 contracts)
    +--- AI/ML Services (Agent Identity / Fraud Detection / Risk Scoring)
    +--- Rust SDK (TEE Attestation / Go + Python Bindings)
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | Next.js 14, React 18, Tailwind CSS, RainbowKit, wagmi/viem |
| Backend | Express, TypeScript 5.3, Prisma ORM |
| Smart Contracts | Solidity 0.8.20, Foundry + Hardhat dual build |
| ZK Circuits | Circom 2.1, snarkjs, Groth16 |
| Native | Rust (TEE attestation crate) |
| SDKs | Go, Python |
| AI/ML | Agent identity, fraud detection, risk scoring |

## Quick Start

### Prerequisites

| Tool | Version |
|------|---------|
| Node.js | >= 20.0.0 |
| Rust | >= 1.75.0 |
| Circom | >= 2.1.0 |
| Docker + Compose | latest |
| PostgreSQL | >= 16 |
| Foundry | latest |

### Installation

```bash
# Clone
git clone https://github.com/aethelred-foundation/zeroid.git
cd zeroid

# Install dependencies
npm ci

# Install backend dependencies
cd backend && npm ci && cd ..

# Configure
cp .env.example .env
# Edit .env with your configuration

# Compile ZK circuits
cd circuits && ./build.sh && cd ..

# Compile smart contracts (Foundry)
forge build

# Run database migrations
cd backend && npx prisma migrate dev && cd ..

# Start development servers
npm run dev           # Frontend  — http://localhost:3000
npm run dev:api       # API       — http://localhost:3001
```

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/zeroid

# Blockchain
RPC_URL=http://localhost:8545
CHAIN_ID=31337

# ZK Proofs
CIRCUITS_PATH=./circuits
PROVING_KEY_PATH=./circuits/keys

# TEE
TEE_ATTESTATION_ENDPOINT=http://localhost:8443

# Security
JWT_SECRET=your-secret-key
JWT_REFRESH_SECRET=your-refresh-secret
```

## Smart Contracts

ZeroID deploys 12 Solidity contracts on-chain:

| Contract | Purpose |
|----------|---------|
| `IdentityManager` | DID creation and management |
| `CredentialRegistry` | Verifiable credential registry |
| `AccumulatorRevocation` | Cryptographic accumulator-based revocation |
| `CrossChainIdentityBridge` | Cross-chain identity bridging |
| `ZKVerifier` | On-chain ZK proof verification |
| `ComplianceCredential` | Regulatory compliance attestations |
| `GovernanceVoting` | Decentralised governance |
| `StakingManager` | Validator staking |
| `ReputationOracle` | Reputation scoring |
| `FeeManager` | Protocol fee management |
| `BatchCredentialProcessor` | Batch credential operations |
| `IdentityRecovery` | Social recovery for identities |

## ZK Circuits

9 Circom circuits provide privacy-preserving verification:

| Circuit | Constraints | Purpose |
|---------|-------------|---------|
| `ageVerification` | ~2,500 | Prove age >= threshold without revealing DOB |
| `residencyProof` | ~3,000 | Prove country of residence |
| `nationalityProof` | ~2,800 | Prove nationality without revealing passport |
| `creditTierScoring` | ~4,200 | Prove credit tier without revealing score |
| `identityOwnership` | ~1,800 | Prove DID ownership |
| `credentialValidity` | ~3,500 | Prove credential without revealing contents |
| `selectiveDisclosure` | ~5,000 | BBS+ selective attribute disclosure |
| `thresholdCredential` | ~6,200 | Multi-party threshold issuance |
| `accumulatorMembership` | ~2,000 | Non-revocation proof via accumulator |

## Testing

```bash
# Frontend tests
npm test

# Backend tests
cd backend && npm test -- --runInBand

# Smart contract tests (Foundry)
forge test

# ZK circuit tests
cd circuits && npm test
```

## Security

- **TEE Attestation**: Intel SGX DCAP with real cryptographic verification
- **Post-Quantum Ready**: Hybrid ECDSA + Dilithium3 signature support
- **Audit Status**: ZK circuit + contract review completed
- **Formal Verification**: Accumulator and revocation invariants verified

## Resources

- [Application](https://zeroid.aethelred.io)
- [API Reference](https://api.aethelred.io/zeroid/docs)
- [GitHub Repository](https://github.com/aethelred-foundation/zeroid)
- [Aethelred Platform](/guide/introduction)
- [Cryptography Overview](/cryptography/overview)
- [TEE Attestation Guide](/guide/tee-attestation)
