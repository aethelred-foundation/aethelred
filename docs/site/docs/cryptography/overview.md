# Cryptography Overview

Aethelred implements a **hybrid post-quantum cryptographic scheme** that provides quantum resistance while maintaining backward compatibility.

## Why Hybrid?

| Concern | Solution |
|---------|----------|
| Quantum computers will break ECDSA | Dilithium3 provides 128-bit quantum security |
| Ecosystem still depends on secp256k1 | ECDSA maintained for wallet compatibility |
| Algorithm agility needed | `VerifierConfig` supports runtime algorithm selection |
| Emergency response | Panic Mode instantly drops classical crypto |

## Algorithm Stack

### Signatures (NIST FIPS 204)

| Level | Algorithm | Quantum Security | Use Case |
|-------|-----------|:----------------:|----------|
| 2 | ML-DSA-44 (Dilithium2) | 64-bit | DevNet only |
| **3** | **ML-DSA-65 (Dilithium3)** | **128-bit** | **Default (MainNet)** |
| 5 | ML-DSA-87 (Dilithium5) | 192-bit | High-security |

### Key Encapsulation (NIST FIPS 203)

| Level | Algorithm | Quantum Security | Use Case |
|-------|-----------|:----------------:|----------|
| 512 | ML-KEM-512 | 64-bit | Low-bandwidth |
| **768** | **ML-KEM-768** | **128-bit** | **Default** |
| 1024 | ML-KEM-1024 | 192-bit | Maximum security |

## Security Properties

- **Zeroization**: All secret keys implement `ZeroizeOnDrop`
- **Constant-time**: Signature comparison uses `subtle::ConstantTimeEq`
- **HSM support**: PKCS#11 for hardware key storage
- **Debug safety**: Secret types print `[REDACTED]`

## Further Reading

- [Security Parameters](/cryptography/security-parameters) - Wire format, key sizes, network configs
- [HSM Deployment](/cryptography/hsm-deployment) - Hardware Security Module setup guide
- [Key Management](/cryptography/key-management) - Key generation, rotation, backup
