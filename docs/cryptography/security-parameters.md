# Aethelred Cryptographic Security Parameters

## Overview

Aethelred implements a **hybrid post-quantum cryptographic scheme** combining classical ECDSA (secp256k1) with Dilithium3 (NIST FIPS 204 / ML-DSA-65) for signatures, and Kyber768 (NIST FIPS 203 / ML-KEM-768) for key encapsulation. This provides quantum resistance while maintaining backward compatibility with Ethereum/Bitcoin wallet infrastructure.

## Signature Security Levels

| Component | Algorithm | Security (Classical) | Security (Quantum) | Key Size | Sig Size |
|-----------|-----------|:--------------------:|:-------------------:|----------:|----------:|
| Classical | ECDSA secp256k1 | 128-bit | 0-bit* | 33B (compressed) | 64B |
| **Default** | **Dilithium3 (ML-DSA-65)** | **192-bit** | **128-bit** | **1,952B** | **3,293B** |
| Level 2 | Dilithium2 (ML-DSA-44) | 128-bit | 64-bit | 1,312B | 2,420B |
| Level 5 | Dilithium5 (ML-DSA-87) | 256-bit | 192-bit | 2,592B | 4,595B |

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
│ Version │ Hybrid Marker│ ECDSA  │ Sep │ Dilithium  │ Level │ Metadata │
│  (1B)   │    (1B)      │ (64B)  │(1B) │ (variable) │ (1B)  │ (var)    │
└─────────┴──────────────┴────────┴─────┴────────────┴───────┴──────────┘
```

| Field | Bytes | Description |
|-------|------:|-------------|
| Version | 1 | `0x01` — wire format version |
| Marker | 1 | `0xAE` — hybrid signature identifier |
| ECDSA | 64 | `r \|\| s` concatenation |
| Separator | 1 | `0xFF` — component boundary |
| Dilithium | 2420/3293/4595 | Level-dependent signature bytes |
| Level | 1 | `0x02`/`0x03`/`0x05` — Dilithium security level |
| Metadata | 0–18 | Optional: timestamp (9B) + chain_id (9B) |

### Metadata Encoding

```
┌──────────┬──────────────┬──────────┬──────────────┐
│ Has TS   │ Timestamp    │ Has CID  │ Chain ID     │
│ 0x00/01  │ u64 LE (8B)  │ 0x00/01  │ u64 LE (8B)  │
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

## Memory Security

| Primitive | Key Zeroization | Mechanism |
|-----------|:---------------:|-----------|
| `EcdsaSecretKey` | ✅ | `zeroize::ZeroizeOnDrop` |
| `DilithiumSecretKey` | ✅ | `zeroize::ZeroizeOnDrop` |
| `KyberSecretKey` | ✅ | `zeroize::ZeroizeOnDrop` |
| `HybridKeyPair` | ✅ | Derives `ZeroizeOnDrop` |
| `SharedSecret` | ✅ | `zeroize::ZeroizeOnDrop` |
| Debug output | ✅ | `[REDACTED]` for all secret types |

## HSM Support

| HSM Type | Module Path | Status |
|----------|-------------|:------:|
| AWS CloudHSM | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` | ✅ Supported |
| Thales Luna | `/usr/safenet/lunaclient/lib/libCryptoki2_64.so` | ✅ Supported |
| YubiHSM 2 | `/usr/lib/libyubihsm_pkcs11.so` | ✅ Supported |
| SoftHSM | `/usr/lib/softhsm/libsofthsm2.so` | 🧪 Dev Only |

## Algorithm Agility Migration Plan

1. **Current**: ECDSA + Dilithium3 (hybrid, both required on mainnet)
2. **Phase 2**: Dilithium-only (drop ECDSA once ecosystem migrates)
3. **Emergency**: Panic Mode — instant Dilithium-only via `VerifierConfig::enter_panic_mode()`
4. **Future**: Algorithm rotation via governance parameter update (`allowed_proof_types`)
