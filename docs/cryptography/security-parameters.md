# Aethelred Cryptographic Security Parameters

## Overview

Aethelred implements a **hybrid post-quantum cryptographic scheme** combining classical ECDSA (secp256k1) with Dilithium3 (NIST FIPS 204 / ML-DSA-65) for signatures, and Kyber768 (NIST FIPS 203 / ML-KEM-768) for key encapsulation. This provides quantum resistance while maintaining backward compatibility with Ethereum/Bitcoin wallet infrastructure.

## Signature Security Levels

| Component | Algorithm | Security (Classical) | Security (Quantum) | Key Size | Sig Size |
|-----------|-----------|:--------------------:|:-------------------:|----------:|----------:|
| Classical | ECDSA secp256k1 | 128-bit | 0-bit* | 33B (compressed) | 64B |
| **Default** | **Dilithium3 (ML-DSA-65)** | **192-bit** | **128-bit** | **1,952B** | **3,309B** |
| Level 2 | Dilithium2 (ML-DSA-44) | 128-bit | 64-bit | 1,312B | 2,420B |
| Level 5 | Dilithium5 (ML-DSA-87) | 256-bit | 192-bit | 2,592B | 4,627B |

> Sizes are the **standardized ML-DSA** (FIPS 204 final) values, not the legacy
> round-3 Dilithium sizes. The Go node uses Cloudflare circl's `sign/mldsa`; the
> Rust `crates/core` uses `pqcrypto-dilithium` 0.5 (also ML-DSA). Both are
> validated against the NIST ACVP keyGen vectors (see `crypto/pqc/nist_kat_test.go`).

> *ECDSA provides 0-bit quantum security. It exists for wallet compatibility only.

## Key Encapsulation (KEM) Security Levels

| Variant | Algorithm | Security (Classical) | Security (Quantum) | PK Size | CT Size | SS Size |
|---------|-----------|:--------------------:|:-------------------:|--------:|--------:|--------:|
| Kyber512 | ML-KEM-512 | 128-bit | 64-bit | 800B | 768B | 32B |
| **Default** | **Kyber768 (ML-KEM-768)** | **192-bit** | **128-bit** | **1,184B** | **1,088B** | **32B** |
| Kyber1024 | ML-KEM-1024 | 256-bit | 192-bit | 1,568B | 1,568B | 32B |

## Hybrid Signature Wire Format

```
┌─────────┬──────────────┬────────┬──────────────────┬───────┬──────────┐
│ Version │ Hybrid Marker│ ECDSA │ Sep │ Dilithium │ Level │ Metadata │
│ (1B) │ (1B) │ (64B) │(1B) │ (variable) │ (1B) │ (var) │
└─────────┴──────────────┴────────┴─────┴────────────┴───────┴──────────┘
```

| Field | Bytes | Description |
|-------|------:|-------------|
| Version | 1 | `0x01` - wire format version |
| Marker | 1 | `0xAE` - hybrid signature identifier |
| ECDSA | 64 | `r \|\| s` concatenation |
| Separator | 1 | `0xFF` - component boundary |
| Dilithium | 2420/3309/4627 | Level-dependent signature bytes (ML-DSA-44/65/87) |
| Level | 1 | `0x02`/`0x03`/`0x05` - Dilithium security level |
| Metadata | 0–18 | Optional: timestamp (9B) + chain_id (9B) |

### Metadata Encoding

```
┌──────────┬──────────────┬──────────┬──────────────┐
│ Has TS │ Timestamp │ Has CID │ Chain ID │
│ 0x00/01 │ u64 LE (8B) │ 0x00/01 │ u64 LE (8B) │
└──────────┴──────────────┴──────────┴──────────────┘
```

## Verifier Configuration by Network

| Parameter | DevNet | TestNet | **MainNet** | Panic Mode |
|-----------|:------:|:-------:|:-----------:|:----------:|
| Require ECDSA | No | Yes | **Yes** | No* |
| Require Dilithium | Yes | Yes | **Yes** | **YES** |
| Accept Level 2 | Yes | Yes | No | No |
| Accept Level 3 | Yes | Yes | **Yes** | **Yes** |
| Accept Level 5 | Yes | Yes | **Yes** | **Yes** |
| Enforce Chain ID | No | Yes | **Yes** | **Yes** |
| Allow Mock PQC | Yes | No | **No** | **No** |

> *Panic Mode: When quantum computers are detected, ECDSA is **ignored** and **only** Dilithium is verified.

## Go Node (Chain) Cryptography

The production chain (`cmd/aethelredd`) implements the same hybrid scheme in Go
(`crypto/pqc`), backed by **Cloudflare circl** (pure Go, no CGO):

| Concern | Implementation |
|---|---|
| Signatures | ML-DSA-65 (`sign/mldsa/mldsa65`) + secp256k1 (`btcec`), composite |
| Key exchange | ML-KEM-768 (`kem/mlkem/mlkem768`) + X25519 hybrid |
| Mode | `hybrid` by default; **no simulated-crypto path** (deleted, not gated) |
| Key derivation | One BIP39-style master seed → both keys via domain-separated HKDF; deterministic ML-DSA `NewKeyFromSeed` and version-stable secp256k1 scalar derivation |
| Validation | NIST ACVP keyGen KATs (`crypto/pqc/nist_kat_test.go`); sign/verify roundtrip + tamper/wrong-key rejection; size-drift guard against circl constants |

The node defaults to `hybrid` mode (`aethelred.pqc.mode` / `AETHELRED_PQC_MODE`);
the public-testnet readiness gate asserts the declared posture is `hybrid`/`production`.

## Digital Seal — Validator Quorum

A Digital Seal is authenticated by a **2/3+ voting-power quorum of validator
hybrid signatures** over the canonical seal claim
`(chainID, jobID, model, input, output)` — height is excluded so the claim is
identical at vote-extension time and from the finished seal.

| Step | Mechanism |
|---|---|
| Validator key | Derived from the ed25519 consensus key seed; registered on-chain (`MsgRegisterValidatorHybridKey` or genesis-seeded) |
| Signing | Each validator hybrid-signs the claim in its vote extension (bound into the ed25519-signed extension hash) |
| Aggregation | Agreeing validators' signatures are carried through consensus and persisted onto the seal |
| Verification (authoritative) | A power-weighted quorum is checked against each validator's **registered** key (not the embedded key) — see `sealtypes.VerifySealQuorum` / pouw `VerifyJobSealQuorum` |
| Verification (seal layer) | The seal verifier cryptographically verifies each hybrid signature over the claim **by default** (`HybridSealSignatureVerifier`, wired into `DefaultVerifierConfig`) — no insecure structural fallback |
| Offline audit | `GET /aethelred/pouw/v1/seals/{seal_id}/quorum` + `docs/api/digital-seal-offline-verification.md` |

## Memory Security

| Primitive | Key Zeroization | Mechanism |
|-----------|:---------------:|-----------|
| `EcdsaSecretKey` | Yes | `zeroize::ZeroizeOnDrop` |
| `DilithiumSecretKey` | Yes | `zeroize::ZeroizeOnDrop` |
| `KyberSecretKey` | Yes | `zeroize::ZeroizeOnDrop` |
| `HybridKeyPair` | Yes | Derives `ZeroizeOnDrop` |
| `SharedSecret` | Yes | `zeroize::ZeroizeOnDrop` |
| Debug output | Yes | `[REDACTED]` for all secret types |

## HSM Support

| HSM Type | Module Path | Status |
|----------|-------------|:------:|
| AWS CloudHSM | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` | Supported |
| Thales Luna | `/usr/safenet/lunaclient/lib/libCryptoki2_64.so` | Supported |
| YubiHSM 2 | `/usr/lib/libyubihsm_pkcs11.so` | Supported |
| SoftHSM | `/usr/lib/softhsm/libsofthsm2.so` | Dev Only |

## Algorithm Agility Migration Plan

1. **Current**: ECDSA + Dilithium3 (hybrid, both required on mainnet)
2. **Phase 2**: Dilithium-only (drop ECDSA once ecosystem migrates)
3. **Emergency**: Panic Mode - instant Dilithium-only via `VerifierConfig::enter_panic_mode()`
4. **Future**: Algorithm rotation via governance parameter update (`allowed_proof_types`)
