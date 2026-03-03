# Cryptographic Standards

<p align="center">
  <strong>Aethelred Cryptographic Specification</strong><br/>
  <em>Version 2.0.0 | February 2026</em>
</p>

---

## Document Information

| Attribute | Value |
|-----------|-------|
| **Version** | 2.0.0 |
| **Status** | Approved for Engineering Implementation |
| **Classification** | Confidential - Authorized Personnel Only |
| **Effective Date** | February 2026 |
| **Document Owner** | Aethelred Protocol Foundation |
| **Security Review** | In progress (see `/audits/STATUS.md`) |

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Threat Model](#2-threat-model)
3. [Hybrid Signature Scheme](#3-hybrid-signature-scheme)
4. [Hash Functions](#4-hash-functions)
5. [Encryption Standards](#5-encryption-standards)
6. [Key Management](#6-key-management)
7. [TEE Attestation Cryptography](#7-tee-attestation-cryptography)
8. [Zero-Knowledge Proofs](#8-zero-knowledge-proofs)
9. [Cryptographic Commitments](#9-cryptographic-commitments)
10. [Post-Quantum Migration](#10-post-quantum-migration)

---

## 1. Introduction

### 1.1 Design Philosophy

Aethelred's cryptographic architecture is built on three foundational principles:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     CRYPTOGRAPHIC DESIGN PRINCIPLES                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  1. QUANTUM IMMUNITY BY DEFAULT                                        │  │
│  │                                                                        │  │
│  │  All new cryptographic operations use hybrid (classical + PQ) schemes │  │
│  │  to protect against "harvest now, decrypt later" attacks.             │  │
│  │                                                                        │  │
│  │  Threat Timeline: NIST estimates quantum computers capable of         │  │
│  │  breaking RSA-2048 by 2030-2035. Aethelred protects assets today.     │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  2. DEFENSE IN DEPTH                                                   │  │
│  │                                                                        │  │
│  │  Multiple independent cryptographic layers protect critical assets:   │  │
│  │  • Hardware (TEE isolation)                                           │  │
│  │  • Software (encryption + signatures)                                 │  │
│  │  • Protocol (ZK proofs + commitments)                                 │  │
│  │                                                                        │  │
│  │  Compromise of one layer does not break security.                     │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  3. STANDARDIZATION                                                    │  │
│  │                                                                        │  │
│  │  Use established standards where possible:                            │  │
│  │  • NIST FIPS 186-5 (ECDSA)                                            │  │
│  │  • NIST FIPS 204 (ML-DSA / Dilithium)                                 │  │
│  │  • NIST SP 800-185 (SHA-3 derivatives)                                │  │
│  │  • RFC 7748 (X25519)                                                  │  │
│  │                                                                        │  │
│  │  Custom cryptography only where necessary and formally verified.      │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Cryptographic Primitives Overview

| Primitive | Algorithm | Security Level | Standard | Use Case |
|-----------|-----------|---------------|----------|----------|
| **Classical Signature** | ECDSA (secp256k1) | 128-bit | SEC 2 | Ethereum compatibility |
| **PQ Signature** | ML-DSA-65 (Dilithium3) | NIST Level 3 | FIPS 204 | Quantum-resistant signing |
| **Hash Function** | BLAKE3 | 256-bit | - | General hashing |
| **Hash (Merkle)** | SHA3-256 | 256-bit | FIPS 202 | State trees |
| **Symmetric Encryption** | AES-256-GCM | 256-bit | FIPS 197 | Data at rest |
| **Stream Cipher** | ChaCha20-Poly1305 | 256-bit | RFC 8439 | Data in transit |
| **Key Exchange** | X25519 | 128-bit | RFC 7748 | ECDH key agreement |
| **PQ Key Exchange** | ML-KEM-768 (Kyber768) | NIST Level 3 | FIPS 203 | Quantum-resistant KEX |
| **Commitment** | Pedersen | DL-hard | - | Confidential values |
| **ZK Proofs** | Groth16 / Halo2 | 128-bit | - | Computation verification |

---

## 2. Threat Model

### 2.1 Adversary Capabilities

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            THREAT MODEL                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ADVERSARY TYPES                                                            │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  TYPE 1: CLASSICAL ADVERSARY (Present Day)                            │  │
│  │                                                                        │  │
│  │  Capabilities:                                                         │  │
│  │  • Unlimited classical computation (2^80 operations feasible)         │  │
│  │  • Network eavesdropping and MITM                                     │  │
│  │  • Control of up to 1/3 of validators                                 │  │
│  │  • Side-channel attacks on non-TEE systems                            │  │
│  │                                                                        │  │
│  │  Cannot:                                                               │  │
│  │  • Break 128-bit symmetric encryption                                 │  │
│  │  • Forge ECDSA signatures without private key                         │  │
│  │  • Extract data from genuine TEE enclaves                             │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  TYPE 2: QUANTUM ADVERSARY (2030-2035 Timeline)                       │  │
│  │                                                                        │  │
│  │  Capabilities:                                                         │  │
│  │  • Cryptographically Relevant Quantum Computer (CRQC)                 │  │
│  │  • Shor's algorithm for factoring / discrete log                      │  │
│  │  • Grover's algorithm for search (quadratic speedup)                  │  │
│  │                                                                        │  │
│  │  Can break (without PQ protection):                                   │  │
│  │  • RSA, DSA, ECDSA, EdDSA                                             │  │
│  │  • ECDH, DH key exchange                                              │  │
│  │                                                                        │  │
│  │  Cannot break:                                                         │  │
│  │  • AES-256 (Grover reduces to 2^128, still infeasible)                │  │
│  │  • ML-DSA (Dilithium) - lattice-based                                 │  │
│  │  • ML-KEM (Kyber) - lattice-based                                     │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  TYPE 3: NATION-STATE ADVERSARY                                        │  │
│  │                                                                        │  │
│  │  Capabilities:                                                         │  │
│  │  • Hardware implants and supply chain attacks                         │  │
│  │  • Coercion of cloud providers                                        │  │
│  │  • Access to TEE vulnerabilities (zero-days)                          │  │
│  │  • Long-term data collection ("harvest now, decrypt later")           │  │
│  │                                                                        │  │
│  │  Mitigations:                                                          │  │
│  │  • Multiple TEE vendors (SGX + SEV + Nitro)                           │  │
│  │  • Geographic distribution of validators                              │  │
│  │  • Hybrid PQ signatures (both must be broken)                         │  │
│  │  • Key rotation policies                                              │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Security Levels

| Security Level | Classical | Quantum (Grover) | Use Case |
|---------------|-----------|------------------|----------|
| **128-bit** | 2^128 ops | 2^64 ops | Standard transactions |
| **192-bit** | 2^192 ops | 2^96 ops | High-value assets |
| **256-bit** | 2^256 ops | 2^128 ops | Long-term secrets |
| **NIST Level 3** | ≥ 2^143 | Lattice-hard | PQ signatures (Dilithium3) |

---

## 3. Hybrid Signature Scheme

### 3.1 Overview

Aethelred uses a **hybrid signature scheme** that combines classical ECDSA with post-quantum ML-DSA (Dilithium). Both signatures must be valid for the overall signature to be accepted.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        HYBRID SIGNATURE SCHEME                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                           ┌─────────────┐                                   │
│                           │   Message   │                                   │
│                           │     (M)     │                                   │
│                           └──────┬──────┘                                   │
│                                  │                                          │
│                    ┌─────────────┴─────────────┐                            │
│                    │                           │                            │
│                    ▼                           ▼                            │
│           ┌────────────────┐          ┌────────────────┐                   │
│           │  ECDSA Sign    │          │  ML-DSA Sign   │                   │
│           │  (secp256k1)   │          │  (Dilithium3)  │                   │
│           └────────┬───────┘          └────────┬───────┘                   │
│                    │                           │                            │
│                    │ σ_ecdsa                   │ σ_pq                       │
│                    │ (64 bytes)                │ (3,293 bytes)              │
│                    │                           │                            │
│                    └───────────┬───────────────┘                            │
│                                │                                            │
│                                ▼                                            │
│                    ┌────────────────────┐                                   │
│                    │  Hybrid Signature  │                                   │
│                    │                    │                                   │
│                    │  σ = σ_ecdsa ‖ σ_pq │                                   │
│                    │  (3,357 bytes)     │                                   │
│                    └────────────────────┘                                   │
│                                                                              │
│  VERIFICATION:                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Valid(σ, M, pk) = ECDSA.Verify(σ_ecdsa, M, pk_ecdsa)              │    │
│  │                    AND                                              │    │
│  │                    ML-DSA.Verify(σ_pq, M, pk_pq)                   │    │
│  │                                                                     │    │
│  │  BOTH must pass for signature to be valid.                         │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Implementation

```rust
/// Hybrid Signature combining ECDSA + ML-DSA (Dilithium3)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Classical ECDSA signature (secp256k1)
    pub ecdsa: EcdsaSignature,

    /// Post-Quantum ML-DSA signature (Dilithium3)
    pub pq: DilithiumSignature,
}

impl HybridSignature {
    /// Total size of hybrid signature
    pub const SIZE: usize = 64 + 3293; // ECDSA + Dilithium3

    /// Sign a message with both algorithms
    pub fn sign(message: &[u8], keypair: &HybridKeyPair) -> Result<Self, SignError> {
        // Hash message with BLAKE3 for consistent input
        let hash = blake3::hash(message);

        // ECDSA signature (deterministic RFC 6979)
        let ecdsa = ecdsa::sign(&keypair.ecdsa_secret, hash.as_bytes())?;

        // ML-DSA signature (Dilithium3)
        let pq = dilithium3::sign(&keypair.pq_secret, hash.as_bytes())?;

        Ok(Self { ecdsa, pq })
    }

    /// Verify both signatures
    pub fn verify(
        &self,
        message: &[u8],
        public_key: &HybridPublicKey,
    ) -> Result<bool, VerifyError> {
        let hash = blake3::hash(message);

        // Both must verify
        let ecdsa_valid = ecdsa::verify(
            &public_key.ecdsa,
            hash.as_bytes(),
            &self.ecdsa,
        )?;

        let pq_valid = dilithium3::verify(
            &public_key.pq,
            hash.as_bytes(),
            &self.pq,
        )?;

        Ok(ecdsa_valid && pq_valid)
    }
}

/// Hybrid Key Pair
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridKeyPair {
    /// ECDSA secret key (32 bytes)
    ecdsa_secret: EcdsaSecretKey,

    /// ML-DSA secret key (4,032 bytes)
    pq_secret: DilithiumSecretKey,
}

/// Hybrid Public Key
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct HybridPublicKey {
    /// ECDSA public key (33 bytes compressed)
    pub ecdsa: EcdsaPublicKey,

    /// ML-DSA public key (1,952 bytes)
    pub pq: DilithiumPublicKey,
}

impl HybridPublicKey {
    /// Total size of hybrid public key
    pub const SIZE: usize = 33 + 1952; // ECDSA + Dilithium3

    /// Derive address from hybrid public key
    pub fn to_address(&self) -> Address {
        // Address = BLAKE3(ecdsa_pubkey || pq_pubkey)[0..20]
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.ecdsa.to_bytes());
        hasher.update(&self.pq.to_bytes());
        let hash = hasher.finalize();
        Address::from_slice(&hash.as_bytes()[0..20])
    }
}
```

### 3.3 Key Derivation

```rust
/// Hierarchical Deterministic (HD) Key Derivation for Hybrid Keys
///
/// Based on BIP-32 extended for post-quantum algorithms
pub struct HybridHD {
    /// Master seed (256 bits)
    seed: [u8; 32],
}

impl HybridHD {
    /// Derive hybrid keypair at path
    /// Path format: m/purpose'/coin'/account'/change/index
    pub fn derive(&self, path: &DerivationPath) -> Result<HybridKeyPair, DeriveError> {
        // Derive ECDSA key using standard BIP-32
        let ecdsa_master = self.derive_ecdsa_master()?;
        let ecdsa_child = ecdsa_master.derive(path)?;

        // Derive PQ key using SHAKE256-based KDF
        // We use a separate derivation to ensure independence
        let pq_seed = self.derive_pq_seed(path)?;
        let pq_keypair = dilithium3::keypair_from_seed(&pq_seed)?;

        Ok(HybridKeyPair {
            ecdsa_secret: ecdsa_child.secret_key,
            pq_secret: pq_keypair.secret_key,
        })
    }

    /// Derive PQ seed from master seed and path
    fn derive_pq_seed(&self, path: &DerivationPath) -> Result<[u8; 64], DeriveError> {
        // Use SHAKE256 for arbitrary-length output
        let mut shake = Shake256::default();
        shake.update(b"AETHELRED-PQ-DERIVE");
        shake.update(&self.seed);
        shake.update(&path.to_bytes());

        let mut pq_seed = [0u8; 64];
        shake.finalize_xof().read(&mut pq_seed);
        Ok(pq_seed)
    }
}

/// Derivation path for Aethelred
/// m/8821'/0'/account'/change/index
/// 8821 = Aethelred coin type (chain ID)
pub struct AethelredPath {
    account: u32,
    change: u32,
    index: u32,
}

impl AethelredPath {
    pub fn new(account: u32, change: u32, index: u32) -> Self {
        Self { account, change, index }
    }

    pub fn to_derivation_path(&self) -> DerivationPath {
        DerivationPath::from_str(&format!(
            "m/8821'/0'/{}'/{}/{}",
            self.account, self.change, self.index
        )).unwrap()
    }
}
```

### 3.4 Signature Size Comparison

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SIGNATURE SIZE COMPARISON                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────┬───────────────┬───────────────┬────────────────┐  │
│  │ Algorithm            │ Signature     │ Public Key    │ Security       │  │
│  ├──────────────────────┼───────────────┼───────────────┼────────────────┤  │
│  │ ECDSA (secp256k1)    │ 64 bytes      │ 33 bytes      │ 128-bit (PQ❌) │  │
│  │ Ed25519              │ 64 bytes      │ 32 bytes      │ 128-bit (PQ❌) │  │
│  │ RSA-2048             │ 256 bytes     │ 256 bytes     │ 112-bit (PQ❌) │  │
│  │ ML-DSA-44 (Dil2)     │ 2,420 bytes   │ 1,312 bytes   │ NIST L2 (PQ✓) │  │
│  │ ML-DSA-65 (Dil3)     │ 3,293 bytes   │ 1,952 bytes   │ NIST L3 (PQ✓) │  │
│  │ ML-DSA-87 (Dil5)     │ 4,595 bytes   │ 2,592 bytes   │ NIST L5 (PQ✓) │  │
│  │ SPHINCS+-128f        │ 17,088 bytes  │ 32 bytes      │ NIST L1 (PQ✓) │  │
│  │ SPHINCS+-256f        │ 49,856 bytes  │ 64 bytes      │ NIST L5 (PQ✓) │  │
│  ├──────────────────────┼───────────────┼───────────────┼────────────────┤  │
│  │ HYBRID (Aethelred)   │ 3,357 bytes   │ 1,985 bytes   │ 128+L3 (PQ✓)  │  │
│  │ ECDSA + ML-DSA-65    │               │               │               │  │
│  └──────────────────────┴───────────────┴───────────────┴────────────────┘  │
│                                                                              │
│  Note: Aethelred uses ML-DSA-65 (Dilithium3) for balance of size and        │
│  security. ML-DSA-87 (Dilithium5) available for critical infrastructure.   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Hash Functions

### 4.1 Hash Function Selection

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          HASH FUNCTION USAGE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  BLAKE3 (Primary)                                                      │  │
│  │                                                                        │  │
│  │  Usage:                                                                │  │
│  │  • Transaction hashing                                                 │  │
│  │  • Content addressing (model weights, inputs, outputs)                │  │
│  │  • General-purpose hashing                                            │  │
│  │                                                                        │  │
│  │  Properties:                                                           │  │
│  │  • 256-bit output                                                      │  │
│  │  • Fastest cryptographic hash (> 10 GB/s on modern CPUs)              │  │
│  │  • Tree-structured for parallel computation                           │  │
│  │  • Keyed mode (MAC), XOF mode, key derivation                         │  │
│  │                                                                        │  │
│  │  Implementation: blake3 crate (official)                              │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  SHA3-256 (Merkle Trees)                                               │  │
│  │                                                                        │  │
│  │  Usage:                                                                │  │
│  │  • State Merkle tree (account balances, storage)                      │  │
│  │  • Block header hashing                                               │  │
│  │  • Interoperability with other chains                                 │  │
│  │                                                                        │  │
│  │  Properties:                                                           │  │
│  │  • 256-bit output                                                      │  │
│  │  • NIST standardized (FIPS 202)                                       │  │
│  │  • Sponge construction (resistant to length extension)                │  │
│  │                                                                        │  │
│  │  Implementation: sha3 crate                                           │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  Keccak-256 (Ethereum Compatibility)                                   │  │
│  │                                                                        │  │
│  │  Usage:                                                                │  │
│  │  • EVM address derivation                                             │  │
│  │  • Smart contract function selectors                                  │  │
│  │  • Ethereum RLP encoding hashes                                       │  │
│  │                                                                        │  │
│  │  Note: Keccak-256 differs from SHA3-256 in padding. We use Keccak     │  │
│  │  only for Ethereum compatibility.                                     │  │
│  │                                                                        │  │
│  │  Implementation: tiny-keccak crate                                    │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  SHAKE256 (Extensible Output)                                          │  │
│  │                                                                        │  │
│  │  Usage:                                                                │  │
│  │  • Key derivation (arbitrary-length output)                           │  │
│  │  • Mask generation (MGF1 replacement)                                 │  │
│  │  • Random oracle instantiation                                        │  │
│  │                                                                        │  │
│  │  Properties:                                                           │  │
│  │  • Arbitrary-length output                                            │  │
│  │  • NIST standardized (SP 800-185)                                     │  │
│  │  • Used in ML-DSA internally                                          │  │
│  │                                                                        │  │
│  │  Implementation: sha3 crate (XOF mode)                                │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Hash Implementation

```rust
/// Cryptographic hash module
pub mod hash {
    use blake3::Hasher as Blake3Hasher;
    use sha3::{Digest, Sha3_256, Shake256};
    use tiny_keccak::{Hasher as _, Keccak};

    /// BLAKE3 hash (primary hash function)
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    pub struct Blake3Hash(pub [u8; 32]);

    impl Blake3Hash {
        /// Compute BLAKE3 hash of data
        pub fn hash(data: &[u8]) -> Self {
            Self(blake3::hash(data).into())
        }

        /// Compute BLAKE3 hash of multiple inputs
        pub fn hash_many(inputs: &[&[u8]]) -> Self {
            let mut hasher = Blake3Hasher::new();
            for input in inputs {
                hasher.update(input);
            }
            Self(hasher.finalize().into())
        }

        /// Keyed BLAKE3 (for MAC)
        pub fn keyed(key: &[u8; 32], data: &[u8]) -> Self {
            let mut hasher = Blake3Hasher::new_keyed(key);
            hasher.update(data);
            Self(hasher.finalize().into())
        }

        /// Derive key from context
        pub fn derive_key(context: &str, input: &[u8]) -> [u8; 32] {
            blake3::derive_key(context, input)
        }
    }

    /// SHA3-256 hash (for Merkle trees and block headers)
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    pub struct Sha3Hash(pub [u8; 32]);

    impl Sha3Hash {
        pub fn hash(data: &[u8]) -> Self {
            let mut hasher = Sha3_256::new();
            hasher.update(data);
            Self(hasher.finalize().into())
        }

        /// Merkle tree inner node hash
        pub fn merkle_inner(left: &Self, right: &Self) -> Self {
            let mut hasher = Sha3_256::new();
            hasher.update(&[0x01]); // Domain separator for inner nodes
            hasher.update(&left.0);
            hasher.update(&right.0);
            Self(hasher.finalize().into())
        }

        /// Merkle tree leaf hash
        pub fn merkle_leaf(data: &[u8]) -> Self {
            let mut hasher = Sha3_256::new();
            hasher.update(&[0x00]); // Domain separator for leaves
            hasher.update(data);
            Self(hasher.finalize().into())
        }
    }

    /// Keccak-256 hash (Ethereum compatibility)
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    pub struct Keccak256Hash(pub [u8; 32]);

    impl Keccak256Hash {
        pub fn hash(data: &[u8]) -> Self {
            let mut hasher = Keccak::v256();
            hasher.update(data);
            let mut output = [0u8; 32];
            hasher.finalize(&mut output);
            Self(output)
        }

        /// Derive EVM address from public key
        pub fn eth_address(pubkey: &[u8; 64]) -> [u8; 20] {
            let hash = Self::hash(pubkey);
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&hash.0[12..32]);
            addr
        }

        /// Function selector (first 4 bytes of keccak256)
        pub fn function_selector(signature: &str) -> [u8; 4] {
            let hash = Self::hash(signature.as_bytes());
            let mut selector = [0u8; 4];
            selector.copy_from_slice(&hash.0[0..4]);
            selector
        }
    }

    /// SHAKE256 XOF (for key derivation)
    pub struct Shake256Xof;

    impl Shake256Xof {
        /// Generate arbitrary-length output
        pub fn squeeze(data: &[u8], output_len: usize) -> Vec<u8> {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut hasher = Shake256::default();
            hasher.update(data);
            let mut reader = hasher.finalize_xof();
            let mut output = vec![0u8; output_len];
            reader.read(&mut output);
            output
        }
    }
}
```

---

## 5. Encryption Standards

### 5.1 Symmetric Encryption

```rust
/// Symmetric encryption module
pub mod symmetric {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::{Aead, Payload};
    use chacha20poly1305::ChaCha20Poly1305;

    /// AES-256-GCM encryption (data at rest)
    pub struct Aes256GcmCipher {
        cipher: Aes256Gcm,
    }

    impl Aes256GcmCipher {
        /// Create new cipher from 256-bit key
        pub fn new(key: &[u8; 32]) -> Self {
            Self {
                cipher: Aes256Gcm::new(key.into()),
            }
        }

        /// Encrypt with associated data
        pub fn encrypt(
            &self,
            nonce: &[u8; 12],
            plaintext: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>, EncryptError> {
            let payload = Payload {
                msg: plaintext,
                aad,
            };
            self.cipher
                .encrypt(Nonce::from_slice(nonce), payload)
                .map_err(|_| EncryptError::EncryptionFailed)
        }

        /// Decrypt with associated data
        pub fn decrypt(
            &self,
            nonce: &[u8; 12],
            ciphertext: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>, DecryptError> {
            let payload = Payload {
                msg: ciphertext,
                aad,
            };
            self.cipher
                .decrypt(Nonce::from_slice(nonce), payload)
                .map_err(|_| DecryptError::DecryptionFailed)
        }
    }

    /// ChaCha20-Poly1305 encryption (data in transit)
    pub struct ChaCha20Poly1305Cipher {
        cipher: ChaCha20Poly1305,
    }

    impl ChaCha20Poly1305Cipher {
        pub fn new(key: &[u8; 32]) -> Self {
            Self {
                cipher: ChaCha20Poly1305::new(key.into()),
            }
        }

        pub fn encrypt(
            &self,
            nonce: &[u8; 12],
            plaintext: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>, EncryptError> {
            let payload = Payload {
                msg: plaintext,
                aad,
            };
            self.cipher
                .encrypt(nonce.into(), payload)
                .map_err(|_| EncryptError::EncryptionFailed)
        }

        pub fn decrypt(
            &self,
            nonce: &[u8; 12],
            ciphertext: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>, DecryptError> {
            let payload = Payload {
                msg: ciphertext,
                aad,
            };
            self.cipher
                .decrypt(nonce.into(), payload)
                .map_err(|_| DecryptError::DecryptionFailed)
        }
    }
}
```

### 5.2 Hybrid Key Encapsulation

```rust
/// Hybrid Key Encapsulation Mechanism (X25519 + ML-KEM-768)
pub mod hybrid_kem {
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
    use pqc_kyber::*;

    /// Hybrid encapsulated key
    pub struct HybridEncapsulation {
        /// X25519 ephemeral public key
        pub ecdh_ephemeral: [u8; 32],

        /// ML-KEM-768 ciphertext
        pub pq_ciphertext: [u8; KYBER_CIPHERTEXTBYTES],

        /// Combined encrypted symmetric key
        pub wrapped_key: [u8; 48], // nonce (12) + encrypted key (32) + tag (4)
    }

    impl HybridEncapsulation {
        /// Encapsulate a symmetric key to a recipient's hybrid public key
        pub fn encapsulate(
            recipient_public: &HybridKemPublicKey,
            symmetric_key: &[u8; 32],
        ) -> Result<Self, KemError> {
            // Generate ephemeral X25519 keypair
            let ecdh_secret = StaticSecret::random_from_rng(OsRng);
            let ecdh_ephemeral = X25519PublicKey::from(&ecdh_secret);

            // X25519 key agreement
            let ecdh_shared = ecdh_secret.diffie_hellman(&recipient_public.ecdh);

            // ML-KEM-768 encapsulation
            let (pq_ciphertext, pq_shared) = encapsulate(
                &recipient_public.pq,
                &mut OsRng,
            )?;

            // Combine shared secrets: HKDF(ecdh_shared || pq_shared)
            let combined_secret = Self::combine_secrets(
                ecdh_shared.as_bytes(),
                &pq_shared,
            );

            // Wrap the symmetric key with combined secret
            let wrapped_key = Self::wrap_key(&combined_secret, symmetric_key)?;

            Ok(Self {
                ecdh_ephemeral: *ecdh_ephemeral.as_bytes(),
                pq_ciphertext,
                wrapped_key,
            })
        }

        /// Decapsulate to recover the symmetric key
        pub fn decapsulate(
            &self,
            recipient_secret: &HybridKemSecretKey,
        ) -> Result<[u8; 32], KemError> {
            // X25519 key agreement
            let ecdh_ephemeral = X25519PublicKey::from(self.ecdh_ephemeral);
            let ecdh_shared = recipient_secret.ecdh.diffie_hellman(&ecdh_ephemeral);

            // ML-KEM-768 decapsulation
            let pq_shared = decapsulate(
                &self.pq_ciphertext,
                &recipient_secret.pq,
            )?;

            // Combine shared secrets
            let combined_secret = Self::combine_secrets(
                ecdh_shared.as_bytes(),
                &pq_shared,
            );

            // Unwrap the symmetric key
            Self::unwrap_key(&combined_secret, &self.wrapped_key)
        }

        fn combine_secrets(ecdh: &[u8], pq: &[u8]) -> [u8; 32] {
            // HKDF-SHA256 with domain separation
            let ikm: Vec<u8> = ecdh.iter().chain(pq.iter()).copied().collect();
            let salt = b"AETHELRED-HYBRID-KEM-V1";
            let info = b"combined-secret";

            let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), &ikm);
            let mut okm = [0u8; 32];
            hk.expand(info, &mut okm).expect("valid output length");
            okm
        }

        fn wrap_key(secret: &[u8; 32], key: &[u8; 32]) -> Result<[u8; 48], KemError> {
            let cipher = Aes256GcmCipher::new(secret);
            let nonce = OsRng.gen::<[u8; 12]>();
            let ciphertext = cipher.encrypt(&nonce, key, b"key-wrap")?;

            let mut result = [0u8; 48];
            result[0..12].copy_from_slice(&nonce);
            result[12..48].copy_from_slice(&ciphertext);
            Ok(result)
        }

        fn unwrap_key(secret: &[u8; 32], wrapped: &[u8; 48]) -> Result<[u8; 32], KemError> {
            let cipher = Aes256GcmCipher::new(secret);
            let nonce: [u8; 12] = wrapped[0..12].try_into().unwrap();
            let ciphertext = &wrapped[12..];

            let key = cipher.decrypt(&nonce, ciphertext, b"key-wrap")?;
            Ok(key.try_into().unwrap())
        }
    }
}
```

---

## 6. Key Management

### 6.1 Key Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           KEY HIERARCHY                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                        ┌──────────────────────┐                              │
│                        │    MASTER SEED       │                              │
│                        │   (256-bit BIP-39)   │                              │
│                        └──────────┬───────────┘                              │
│                                   │                                          │
│          ┌────────────────────────┼────────────────────────┐                │
│          │                        │                        │                │
│          ▼                        ▼                        ▼                │
│  ┌───────────────┐       ┌───────────────┐       ┌───────────────┐         │
│  │ SIGNING KEYS  │       │ ENCRYPTION    │       │ VALIDATOR     │         │
│  │   m/8821'/0'  │       │    KEYS       │       │    KEYS       │         │
│  │               │       │  m/8821'/1'   │       │  m/8821'/2'   │         │
│  └───────┬───────┘       └───────┬───────┘       └───────┬───────┘         │
│          │                       │                       │                  │
│          ▼                       ▼                       ▼                  │
│  ┌───────────────┐       ┌───────────────┐       ┌───────────────┐         │
│  │  Hybrid Keys  │       │  X25519 +     │       │  Consensus    │         │
│  │  (ECDSA + PQ) │       │  ML-KEM-768   │       │  Signing      │         │
│  └───────────────┘       └───────────────┘       └───────────────┘         │
│                                                                              │
│  KEY PROTECTION LEVELS:                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Level 1: Software (encrypted at rest with passphrase)              │    │
│  │  Level 2: Hardware wallet (Ledger, Trezor)                          │    │
│  │  Level 3: HSM (AWS CloudHSM, Azure Key Vault)                       │    │
│  │  Level 4: TEE-sealed (keys never leave enclave)                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Key Storage

```rust
/// Secure key storage with multiple protection levels
pub enum KeyStorage {
    /// Software-protected (encrypted with passphrase)
    Software {
        encrypted_key: EncryptedKey,
        salt: [u8; 32],
        params: Argon2Params,
    },

    /// Hardware wallet (derivation path only)
    HardwareWallet {
        path: DerivationPath,
        device_type: HardwareWalletType,
    },

    /// HSM-backed (key reference)
    Hsm {
        key_id: String,
        provider: HsmProvider,
    },

    /// TEE-sealed (sealed to specific enclave)
    TeeSeal {
        sealed_blob: Vec<u8>,
        enclave_measurement: [u8; 32],
    },
}

/// Encrypted key with Argon2id KDF
pub struct EncryptedKey {
    /// Ciphertext (AES-256-GCM encrypted key material)
    ciphertext: Vec<u8>,

    /// Nonce for AES-GCM
    nonce: [u8; 12],

    /// Authentication tag
    tag: [u8; 16],
}

impl EncryptedKey {
    /// Encrypt key material with passphrase
    pub fn encrypt(
        key_material: &[u8],
        passphrase: &str,
        salt: &[u8; 32],
        params: &Argon2Params,
    ) -> Result<Self, CryptoError> {
        // Derive encryption key from passphrase using Argon2id
        let derived_key = Self::derive_key(passphrase, salt, params)?;

        // Encrypt with AES-256-GCM
        let cipher = Aes256GcmCipher::new(&derived_key);
        let nonce: [u8; 12] = OsRng.gen();
        let ciphertext = cipher.encrypt(&nonce, key_material, b"key-storage")?;

        Ok(Self {
            ciphertext: ciphertext[..ciphertext.len()-16].to_vec(),
            nonce,
            tag: ciphertext[ciphertext.len()-16..].try_into().unwrap(),
        })
    }

    /// Decrypt key material with passphrase
    pub fn decrypt(
        &self,
        passphrase: &str,
        salt: &[u8; 32],
        params: &Argon2Params,
    ) -> Result<Vec<u8>, CryptoError> {
        // Derive encryption key from passphrase
        let derived_key = Self::derive_key(passphrase, salt, params)?;

        // Decrypt with AES-256-GCM
        let cipher = Aes256GcmCipher::new(&derived_key);
        let mut ciphertext_with_tag = self.ciphertext.clone();
        ciphertext_with_tag.extend_from_slice(&self.tag);

        cipher.decrypt(&self.nonce, &ciphertext_with_tag, b"key-storage")
    }

    fn derive_key(
        passphrase: &str,
        salt: &[u8; 32],
        params: &Argon2Params,
    ) -> Result<[u8; 32], CryptoError> {
        use argon2::{Argon2, Algorithm, Version, Params};

        let params = Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(32),
        ).map_err(|_| CryptoError::KdfFailed)?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = [0u8; 32];
        argon2.hash_password_into(
            passphrase.as_bytes(),
            salt,
            &mut key,
        ).map_err(|_| CryptoError::KdfFailed)?;

        Ok(key)
    }
}

/// Argon2id parameters (OWASP recommendations)
pub struct Argon2Params {
    /// Memory cost (KiB)
    pub memory_kib: u32,

    /// Time cost (iterations)
    pub iterations: u32,

    /// Parallelism (threads)
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        // OWASP recommended parameters for Argon2id
        Self {
            memory_kib: 64 * 1024, // 64 MiB
            iterations: 3,
            parallelism: 4,
        }
    }
}
```

---

## 7. TEE Attestation Cryptography

### 7.1 Attestation Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       TEE ATTESTATION CRYPTOGRAPHY                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  INTEL SGX DCAP ATTESTATION FLOW                                            │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                                                                      │    │
│  │  1. ENCLAVE REPORT GENERATION                                       │    │
│  │     ┌─────────────────────────────────────────────────────────────┐ │    │
│  │     │  Enclave creates Report containing:                          │ │    │
│  │     │  • MRENCLAVE (hash of enclave code)                         │ │    │
│  │     │  • MRSIGNER (hash of signer's public key)                   │ │    │
│  │     │  • User Data (64 bytes - we include job ID + output hash)   │ │    │
│  │     │  • TCB info (platform security version)                     │ │    │
│  │     │                                                              │ │    │
│  │     │  Report signed with platform-specific key                   │ │    │
│  │     └─────────────────────────────────────────────────────────────┘ │    │
│  │                                   │                                  │    │
│  │                                   ▼                                  │    │
│  │  2. QUOTING ENCLAVE SIGNATURE                                       │    │
│  │     ┌─────────────────────────────────────────────────────────────┐ │    │
│  │     │  Quoting Enclave (QE) verifies Report and creates Quote:    │ │    │
│  │     │  • Signs with ECDSA-P256 attestation key                    │ │    │
│  │     │  • Includes certificate chain to Intel root                 │ │    │
│  │     └─────────────────────────────────────────────────────────────┘ │    │
│  │                                   │                                  │    │
│  │                                   ▼                                  │    │
│  │  3. PCCS VERIFICATION                                               │    │
│  │     ┌─────────────────────────────────────────────────────────────┐ │    │
│  │     │  Provisioning Certificate Caching Service (PCCS):           │ │    │
│  │     │  • Fetches Intel-signed PCK certificates                    │ │    │
│  │     │  • Provides TCB info and revocation lists                   │ │    │
│  │     │  • Caches for performance                                   │ │    │
│  │     └─────────────────────────────────────────────────────────────┘ │    │
│  │                                   │                                  │    │
│  │                                   ▼                                  │    │
│  │  4. ON-CHAIN VERIFICATION                                           │    │
│  │     ┌─────────────────────────────────────────────────────────────┐ │    │
│  │     │  Aethelred verifies:                                         │ │    │
│  │     │  • ECDSA-P256 signature on Quote                            │ │    │
│  │     │  • Certificate chain to Intel root (pinned)                 │ │    │
│  │     │  • MRENCLAVE matches registered enclave                     │ │    │
│  │     │  • TCB level not revoked                                    │ │    │
│  │     │  • User data matches expected values                        │ │    │
│  │     └─────────────────────────────────────────────────────────────┘ │    │
│  │                                                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Attestation Verification

```rust
/// TEE Attestation Verification
pub struct AttestationVerifier {
    /// Intel root CA certificate (pinned)
    intel_root_cert: Certificate,

    /// AMD root CA certificate (pinned)
    amd_root_cert: Certificate,

    /// AWS Nitro root CA certificate (pinned)
    aws_root_cert: Certificate,

    /// Registered enclave measurements
    enclave_registry: EnclaveRegistry,

    /// TCB revocation list
    revocation_list: RevocationList,
}

impl AttestationVerifier {
    /// Verify an SGX DCAP quote
    pub fn verify_sgx_quote(&self, quote: &SgxQuote) -> Result<AttestationResult, VerifyError> {
        // Step 1: Verify signature chain
        self.verify_certificate_chain(&quote.cert_chain, &self.intel_root_cert)?;

        // Step 2: Verify ECDSA-P256 signature on quote
        let signing_cert = &quote.cert_chain.last().unwrap();
        let signature_valid = ecdsa_p256::verify(
            &signing_cert.public_key,
            &quote.quote_body,
            &quote.signature,
        )?;

        if !signature_valid {
            return Err(VerifyError::InvalidSignature);
        }

        // Step 3: Check TCB level not revoked
        if self.revocation_list.is_revoked(&quote.tcb_info) {
            return Err(VerifyError::RevokedTcb);
        }

        // Step 4: Verify MRENCLAVE matches registered enclave
        let expected_measurement = self.enclave_registry.get(&quote.enclave_id)?;
        if quote.mr_enclave != expected_measurement.mr_enclave {
            return Err(VerifyError::MeasurementMismatch);
        }

        // Step 5: Verify MRSIGNER (optional, for signer-based policy)
        if let Some(expected_signer) = expected_measurement.mr_signer {
            if quote.mr_signer != expected_signer {
                return Err(VerifyError::SignerMismatch);
            }
        }

        // Step 6: Extract and validate user data
        let user_data = UserData::from_bytes(&quote.report_data)?;

        Ok(AttestationResult {
            valid: true,
            hardware_type: HardwareType::IntelSgx,
            enclave_id: quote.enclave_id.clone(),
            mr_enclave: quote.mr_enclave,
            tcb_level: quote.tcb_info.level,
            user_data,
            timestamp: quote.timestamp,
        })
    }

    /// Verify an AWS Nitro attestation document
    pub fn verify_nitro_attestation(
        &self,
        attestation: &NitroAttestation,
    ) -> Result<AttestationResult, VerifyError> {
        // Step 1: Parse COSE_Sign1 structure
        let cose = CoseSign1::from_bytes(&attestation.document)?;

        // Step 2: Verify signature chain (embedded in COSE)
        let cert_chain = cose.extract_certificate_chain()?;
        self.verify_certificate_chain(&cert_chain, &self.aws_root_cert)?;

        // Step 3: Verify ECDSA-P384 signature
        let signing_cert = &cert_chain.last().unwrap();
        let signature_valid = ecdsa_p384::verify(
            &signing_cert.public_key,
            &cose.payload,
            &cose.signature,
        )?;

        if !signature_valid {
            return Err(VerifyError::InvalidSignature);
        }

        // Step 4: Parse attestation document
        let doc = NitroDocument::from_cbor(&cose.payload)?;

        // Step 5: Verify PCRs (Platform Configuration Registers)
        let expected_pcrs = self.enclave_registry.get_nitro_pcrs(&doc.module_id)?;
        for (idx, expected) in expected_pcrs.iter() {
            if doc.pcrs.get(idx) != Some(expected) {
                return Err(VerifyError::PcrMismatch(*idx));
            }
        }

        // Step 6: Extract user data
        let user_data = UserData::from_bytes(&doc.user_data)?;

        Ok(AttestationResult {
            valid: true,
            hardware_type: HardwareType::AwsNitro,
            enclave_id: doc.module_id.clone(),
            mr_enclave: doc.pcrs.get(&0).cloned().unwrap_or_default(),
            tcb_level: TcbLevel::Latest, // Nitro doesn't have TCB levels
            user_data,
            timestamp: doc.timestamp,
        })
    }
}

/// User data embedded in attestation (64 bytes for SGX, variable for Nitro)
#[derive(Clone, Debug)]
pub struct UserData {
    /// Job ID being attested
    pub job_id: [u8; 16],

    /// Blake3 hash of computation output
    pub output_hash: [u8; 32],

    /// Timestamp (Unix seconds)
    pub timestamp: u64,

    /// Nonce for freshness
    pub nonce: [u8; 8],
}

impl UserData {
    pub fn new(job_id: &[u8; 16], output_hash: &[u8; 32], timestamp: u64) -> Self {
        Self {
            job_id: *job_id,
            output_hash: *output_hash,
            timestamp,
            nonce: OsRng.gen(),
        }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[0..16].copy_from_slice(&self.job_id);
        result[16..48].copy_from_slice(&self.output_hash);
        result[48..56].copy_from_slice(&self.timestamp.to_le_bytes());
        result[56..64].copy_from_slice(&self.nonce);
        result
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 64 {
            return Err(ParseError::InsufficientLength);
        }
        Ok(Self {
            job_id: bytes[0..16].try_into().unwrap(),
            output_hash: bytes[16..48].try_into().unwrap(),
            timestamp: u64::from_le_bytes(bytes[48..56].try_into().unwrap()),
            nonce: bytes[56..64].try_into().unwrap(),
        })
    }
}
```

---

## 8. Zero-Knowledge Proofs

### 8.1 ZK System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       ZERO-KNOWLEDGE PROOF SYSTEMS                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  AETHELRED ZK STACK                                                         │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  LAYER 1: zkML (EZKL)                                                  │  │
│  │                                                                        │  │
│  │  Purpose: Prove ML inference correctness                              │  │
│  │  Backend: Halo2 (IPA commitment)                                      │  │
│  │  Proof Size: ~10 KB                                                   │  │
│  │  Verification: ~50ms                                                  │  │
│  │  Prover Time: 5-30 seconds                                            │  │
│  │                                                                        │  │
│  │  Supports: Linear, Conv2D, ReLU, Softmax, MatMul, Attention           │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  LAYER 2: General ZK (Groth16)                                         │  │
│  │                                                                        │  │
│  │  Purpose: Arbitrary computation proofs                                │  │
│  │  Backend: BN254 pairing                                               │  │
│  │  Proof Size: 192 bytes (constant!)                                    │  │
│  │  Verification: ~3ms                                                   │  │
│  │  Prover Time: Depends on circuit                                      │  │
│  │                                                                        │  │
│  │  Trusted Setup: Required (circuit-specific)                           │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  LAYER 3: Recursion (Halo2 Accumulation)                               │  │
│  │                                                                        │  │
│  │  Purpose: Aggregate multiple proofs                                   │  │
│  │  Backend: Halo2 recursive verification                                │  │
│  │  Proof Size: ~10 KB (constant for any number of inner proofs)         │  │
│  │  Verification: ~100ms                                                 │  │
│  │                                                                        │  │
│  │  Use Case: Batch verification of multiple compute jobs                │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.2 zkML Implementation

```rust
/// zkML proof generation and verification (EZKL-based)
pub mod zkml {
    use ezkl::{circuit::*, proof::*, witness::*};

    /// zkML Prover for neural network inference
    pub struct ZkmlProver {
        /// Compiled circuit for the model
        circuit: CompiledCircuit,

        /// Proving key
        pk: ProvingKey,

        /// Model configuration
        config: ModelConfig,
    }

    impl ZkmlProver {
        /// Create prover for a specific ONNX model
        pub fn from_onnx(
            onnx_path: &Path,
            config: ModelConfig,
        ) -> Result<Self, ProverError> {
            // Step 1: Parse ONNX model
            let model = onnx::parse(onnx_path)?;

            // Step 2: Generate circuit from model
            let circuit_config = CircuitConfig {
                scale: config.scale,
                bits: config.bits,
                logrows: config.logrows,
            };
            let circuit = ezkl::circuit::compile(&model, &circuit_config)?;

            // Step 3: Generate proving key (trusted setup for Halo2)
            let pk = ezkl::setup::generate_pk(&circuit)?;

            Ok(Self { circuit, pk, config })
        }

        /// Generate ZK proof of correct inference
        pub fn prove(
            &self,
            input: &[f32],
            output: &[f32],
        ) -> Result<ZkmlProof, ProverError> {
            // Step 1: Create witness from input/output
            let witness = Witness::new(input, output, &self.config)?;

            // Step 2: Generate proof
            let proof_bytes = ezkl::prove(&self.circuit, &self.pk, &witness)?;

            // Step 3: Compute public inputs (commitments)
            let input_commitment = blake3::hash(input.as_bytes());
            let output_commitment = blake3::hash(output.as_bytes());
            let model_commitment = self.circuit.hash();

            Ok(ZkmlProof {
                proof: proof_bytes,
                public_inputs: PublicInputs {
                    input_commitment: input_commitment.into(),
                    output_commitment: output_commitment.into(),
                    model_commitment: model_commitment.into(),
                },
            })
        }
    }

    /// zkML Verifier
    pub struct ZkmlVerifier {
        /// Verification key
        vk: VerifyingKey,
    }

    impl ZkmlVerifier {
        /// Create verifier from verification key
        pub fn new(vk: VerifyingKey) -> Self {
            Self { vk }
        }

        /// Verify a zkML proof
        pub fn verify(&self, proof: &ZkmlProof) -> Result<bool, VerifyError> {
            // Prepare public inputs for verification
            let public_inputs = vec![
                proof.public_inputs.input_commitment,
                proof.public_inputs.output_commitment,
                proof.public_inputs.model_commitment,
            ];

            // Verify the proof
            ezkl::verify(&self.vk, &proof.proof, &public_inputs)
        }
    }

    /// zkML Proof structure
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ZkmlProof {
        /// Proof bytes (Halo2 proof)
        pub proof: Vec<u8>,

        /// Public inputs (commitments only - no private data)
        pub public_inputs: PublicInputs,
    }

    /// Public inputs for verification
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct PublicInputs {
        /// Blake3 hash of input data
        pub input_commitment: [u8; 32],

        /// Blake3 hash of output data
        pub output_commitment: [u8; 32],

        /// Blake3 hash of model weights
        pub model_commitment: [u8; 32],
    }
}
```

---

## 9. Cryptographic Commitments

### 9.1 Pedersen Commitments

```rust
/// Pedersen Commitment for confidential values
pub mod pedersen {
    use curve25519_dalek::{RistrettoPoint, Scalar, constants};

    /// Pedersen commitment parameters (generated via hash-to-curve)
    pub struct PedersenParams {
        /// Generator G
        g: RistrettoPoint,

        /// Generator H (independent of G)
        h: RistrettoPoint,
    }

    impl PedersenParams {
        /// Generate parameters from nothing-up-my-sleeve string
        pub fn generate() -> Self {
            let g = constants::RISTRETTO_BASEPOINT_POINT;

            // H = hash_to_curve("Aethelred-Pedersen-H")
            let h_bytes = blake3::hash(b"Aethelred-Pedersen-H");
            let h = RistrettoPoint::from_uniform_bytes(&h_bytes.as_bytes()
                .try_into().unwrap());

            Self { g, h }
        }
    }

    /// Pedersen commitment: C = v*G + r*H
    #[derive(Clone, Debug)]
    pub struct PedersenCommitment {
        /// Commitment point
        pub commitment: RistrettoPoint,
    }

    impl PedersenCommitment {
        /// Create commitment to value with blinding factor
        pub fn commit(
            params: &PedersenParams,
            value: &Scalar,
            blinding: &Scalar,
        ) -> Self {
            let commitment = params.g * value + params.h * blinding;
            Self { commitment }
        }

        /// Verify commitment opens to value with blinding
        pub fn verify(
            &self,
            params: &PedersenParams,
            value: &Scalar,
            blinding: &Scalar,
        ) -> bool {
            let expected = params.g * value + params.h * blinding;
            self.commitment == expected
        }

        /// Add two commitments (homomorphic)
        pub fn add(&self, other: &Self) -> Self {
            Self {
                commitment: self.commitment + other.commitment,
            }
        }
    }

    /// Range proof for confidential values (Bulletproofs)
    pub struct RangeProof {
        /// Bulletproof bytes
        pub proof: Vec<u8>,
    }

    impl RangeProof {
        /// Prove value is in range [0, 2^n)
        pub fn prove(
            value: u64,
            blinding: &Scalar,
            n: usize,
        ) -> Result<Self, ProofError> {
            let proof = bulletproofs::prove_range(value, blinding, n)?;
            Ok(Self { proof })
        }

        /// Verify range proof for commitment
        pub fn verify(
            &self,
            commitment: &PedersenCommitment,
            n: usize,
        ) -> Result<bool, VerifyError> {
            bulletproofs::verify_range(&commitment.commitment, &self.proof, n)
        }
    }
}
```

### 9.2 Vector Commitments (Verkle Trees)

```rust
/// Verkle Tree for efficient state commitments
pub mod verkle {
    use bandersnatch::{Point, Scalar, ipa::*};

    /// Verkle tree node
    pub enum VerkleNode {
        /// Internal node with 256 children
        Internal {
            commitment: Point,
            children: Box<[Option<VerkleNode>; 256]>,
        },

        /// Leaf node with key-value
        Leaf {
            key: [u8; 32],
            value: Vec<u8>,
            commitment: Point,
        },

        /// Empty node
        Empty,
    }

    /// Verkle tree implementation
    pub struct VerkleTree {
        root: VerkleNode,
        ipa_params: IpaParams,
    }

    impl VerkleTree {
        /// Create new empty Verkle tree
        pub fn new() -> Self {
            let ipa_params = IpaParams::generate(256);
            Self {
                root: VerkleNode::Empty,
                ipa_params,
            }
        }

        /// Get root commitment
        pub fn root_commitment(&self) -> Point {
            match &self.root {
                VerkleNode::Internal { commitment, .. } => *commitment,
                VerkleNode::Leaf { commitment, .. } => *commitment,
                VerkleNode::Empty => Point::identity(),
            }
        }

        /// Insert key-value pair
        pub fn insert(&mut self, key: &[u8; 32], value: &[u8]) -> Result<(), TreeError> {
            // Implementation uses IPA (Inner Product Argument) for commitments
            // This is more efficient than Merkle trees for state proofs
            todo!()
        }

        /// Generate proof of inclusion/exclusion
        pub fn prove(&self, key: &[u8; 32]) -> Result<VerkleProof, TreeError> {
            todo!()
        }

        /// Verify proof
        pub fn verify(
            root: &Point,
            key: &[u8; 32],
            value: Option<&[u8]>,
            proof: &VerkleProof,
        ) -> Result<bool, VerifyError> {
            todo!()
        }
    }

    /// Verkle proof (IPA-based)
    pub struct VerkleProof {
        /// Path commitments
        path: Vec<Point>,

        /// IPA proof
        ipa_proof: IpaProof,
    }
}
```

---

## 10. Post-Quantum Migration

### 10.1 Migration Timeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      POST-QUANTUM MIGRATION TIMELINE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  2024-2025: PREPARATION                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  • Implement hybrid signatures (ECDSA + Dilithium)                  │    │
│  │  • Deploy hybrid key infrastructure                                 │    │
│  │  • Audit PQ implementations                                         │    │
│  │  • Begin key migration for new accounts                             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  2026-2028: HYBRID MANDATORY                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  • All new keys must be hybrid                                      │    │
│  │  • Legacy ECDSA-only keys sunset warning                            │    │
│  │  • Hardware wallet integration                                      │    │
│  │  • HSM support for PQ algorithms                                    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  2028-2030: CLASSICAL DEPRECATION                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  • ECDSA-only signatures rejected by protocol                       │    │
│  │  • All accounts migrated to hybrid keys                             │    │
│  │  • Historical ECDSA signatures remain valid (read-only)             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  2030+: PQ-ONLY OPTION                                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  • Pure PQ signatures (Dilithium-only) available for new keys       │    │
│  │  • Hybrid remains supported for compatibility                       │    │
│  │  • Monitor NIST standards evolution                                 │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 10.2 Algorithm Agility

```rust
/// Cryptographic algorithm configuration (for future migration)
pub struct CryptoConfig {
    /// Signature algorithm selection
    pub signature: SignatureAlgorithm,

    /// Key encapsulation algorithm selection
    pub kem: KemAlgorithm,

    /// Hash function selection
    pub hash: HashAlgorithm,
}

#[derive(Clone, Copy, Debug)]
pub enum SignatureAlgorithm {
    /// Classical ECDSA only (deprecated, for legacy support)
    EcdsaOnly,

    /// Hybrid ECDSA + Dilithium3 (default)
    Hybrid,

    /// Pure post-quantum (Dilithium3 only)
    PqOnly,

    /// Future: Dilithium5 for higher security
    PqDilithium5,
}

#[derive(Clone, Copy, Debug)]
pub enum KemAlgorithm {
    /// Classical X25519 only (deprecated)
    X25519Only,

    /// Hybrid X25519 + Kyber768 (default)
    Hybrid,

    /// Pure post-quantum (Kyber768)
    PqOnly,

    /// Future: Kyber1024 for higher security
    PqKyber1024,
}

/// Protocol versioning for algorithm migration
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
    pub crypto_version: u8,
}

impl ProtocolVersion {
    /// Current protocol version
    pub const CURRENT: Self = Self {
        major: 2,
        minor: 0,
        crypto_version: 1, // Hybrid default
    };

    /// Minimum supported crypto version
    pub const MIN_CRYPTO_VERSION: u8 = 1;

    /// Check if version supports pure PQ
    pub fn supports_pq_only(&self) -> bool {
        self.crypto_version >= 2
    }
}
```

---

## Appendix A: NIST Standards Reference

| Standard | Algorithm | Status | Aethelred Usage |
|----------|-----------|--------|-----------------|
| FIPS 186-5 | ECDSA | Final | Hybrid signatures |
| FIPS 202 | SHA-3 | Final | Merkle trees, block headers |
| FIPS 203 | ML-KEM (Kyber) | Final | Hybrid key encapsulation |
| FIPS 204 | ML-DSA (Dilithium) | Final | Hybrid signatures |
| FIPS 205 | SLH-DSA (SPHINCS+) | Final | Backup (hash-based) |
| SP 800-185 | SHA-3 Derivatives | Final | SHAKE256 for KDF |

---

## Appendix B: Security Audit Status

| Audit Firm | Scope | Date | Status |
|------------|-------|------|--------|
| TBD | Hybrid Signature Implementation | 2026 | Planned |
| TBD | ZK Circuits (EZKL) | 2026 | Planned |
| TBD | TEE Attestation Flow | 2026 | Planned |
| TBD | Smart Contract Security | 2026 | Planned |

---

<p align="center">
  <em>© 2026 Aethelred Protocol Foundation. All Rights Reserved.</em>
</p>
