# Security Parameters

Concrete key sizes, signature sizes, wire format, and NIST security levels for every algorithm used by Aethelred.

## Signature Algorithms (ML-DSA / Dilithium)

| Parameter | Dilithium2 (Level 2) | **Dilithium3 (Level 3)** | Dilithium5 (Level 5) |
|-----------|:--------------------:|:------------------------:|:--------------------:|
| NIST Standard | FIPS 204 | **FIPS 204** | FIPS 204 |
| Classical Security | 128-bit | **192-bit** | 256-bit |
| Quantum Security | 64-bit | **128-bit** | 128-bit |
| Public Key | 1,312 bytes | **1,952 bytes** | 2,592 bytes |
| Secret Key | 2,528 bytes | **4,000 bytes** | 4,896 bytes |
| Signature | 2,420 bytes | **3,293 bytes** | 4,595 bytes |
| Algorithm ID | `0x02` | **`0x03`** | `0x05` |

**Dilithium3 is the default** for MainNet and TestNet. Dilithium2 is permitted only on DevNet.

## Key Encapsulation (ML-KEM / Kyber)

| Parameter | Kyber512 | **Kyber768** | Kyber1024 |
|-----------|:--------:|:------------:|:---------:|
| NIST Standard | FIPS 203 | **FIPS 203** | FIPS 203 |
| Classical Security | 128-bit | **192-bit** | 256-bit |
| Quantum Security | 64-bit | **128-bit** | 192-bit |
| Public Key | 800 bytes | **1,184 bytes** | 1,568 bytes |
| Secret Key | 1,632 bytes | **2,400 bytes** | 3,168 bytes |
| Ciphertext | 768 bytes | **1,088 bytes** | 1,568 bytes |
| Shared Secret | 32 bytes | **32 bytes** | 32 bytes |

## Classical Signatures (ECDSA)

| Parameter | secp256k1 |
|-----------|:---------:|
| Public Key (compressed) | 33 bytes |
| Public Key (uncompressed) | 65 bytes |
| Signature | 64 bytes |
| Classical Security | 128-bit |
| Quantum Security | 0-bit (broken) |

## Hybrid Signature Format

The Hybrid scheme concatenates ECDSA and Dilithium3 signatures with a separator byte:

| Component | Size |
|-----------|------|
| ECDSA signature | 64 bytes |
| Dilithium3 signature | 3,309 bytes |
| Separator byte | 1 byte |
| **Total** | **3,374 bytes** |

The hybrid public key follows the same pattern:

| Component | Size |
|-----------|------|
| ECDSA public key (compressed) | 33 bytes |
| Dilithium3 public key | 1,952 bytes |
| Separator byte | 1 byte |
| **Total** | **1,986 bytes** |

## Wire Format

All keys and signatures are serialized with a one-byte algorithm prefix:

```
[algorithm_id: u8] [payload: variable]
```

| Algorithm ID | Meaning |
|:------------:|---------|
| `0x01` | ECDSA secp256k1 |
| `0x02` | Dilithium3 |
| `0x03` | Hybrid (ECDSA + Dilithium3) |
| `0x04` | Dilithium5 |

## Network-Specific Configurations

| Setting | MainNet | TestNet | DevNet |
|---------|---------|---------|--------|
| Min signature level | Dilithium3 | Dilithium3 | Dilithium2 |
| KEM default | Kyber768 | Kyber768 | Kyber512 |
| Hybrid required | Yes | Yes | No |
| Quantum Threat Level | Governance-set | 0 (None) | 0 (None) |

## Quantum Threat Levels

The chain tracks a governance-controlled threat level that affects signature policy:

| Level | Name | Classical Sigs | Quantum Sigs |
|:-----:|------|:--------------:|:------------:|
| 0 | None | Required | Required |
| 1 | Early Warning | Required | Required |
| 2 | Elevated | Required | Required |
| 3 | High | Optional | **Required** |
| 4 | Critical | Optional | **Required** |
| 5 | Q-Day | Ignored | **Required** |

## Zeroization and Safety

All secret key types implement `ZeroizeOnDrop` from the `zeroize` crate. Signature comparison uses `subtle::ConstantTimeEq` to prevent timing side-channels. Secret types print `[REDACTED]` in debug output.

## Further Reading

- [Cryptography Overview](/cryptography/overview) - Algorithm rationale and hybrid design
- [HSM Deployment](/cryptography/hsm-deployment) - Hardware key storage
- [Key Management](/cryptography/key-management) - Key lifecycle operations
