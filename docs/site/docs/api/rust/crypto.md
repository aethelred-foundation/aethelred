# Crypto Module

## `aethelred_core::crypto`

Post-quantum and classical cryptographic primitives for the Aethelred protocol. Implements NIST FIPS 204 (ML-DSA / Dilithium) digital signatures and NIST FIPS 203 (ML-KEM / Kyber) key encapsulation. All secret key types implement `Zeroize` and `ZeroizeOnDrop`.

See also: [Attestation Module](/api/rust/attestation) | [Sovereign Module](/api/rust/sovereign) | [Rust SDK Overview](/api/rust/)

---

### Signature Algorithms

#### `SignatureAlgorithm`

```rust
#[repr(u8)]
pub enum SignatureAlgorithm {
    EcdsaSecp256k1 = 0x01,
    Dilithium3     = 0x02,
    Hybrid         = 0x03,
    Dilithium5     = 0x04,
}
```

| Algorithm | Classical | Quantum | Sig Size | PK Size |
|-----------|-----------|---------|----------|---------|
| `EcdsaSecp256k1` | 128-bit | 0-bit (broken) | 64 B | 33 B |
| `Dilithium3` | 192-bit | 128-bit | 3,293 B | 1,952 B |
| `Dilithium5` | 256-bit | 128-bit | 4,627 B | 2,592 B |
| `Hybrid` | 192-bit | 128-bit | 3,374 B | 1,986 B |

##### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `from_byte` | `fn from_byte(b: u8) -> Option<Self>` | Parse from wire format |
| `is_quantum_safe` | `fn is_quantum_safe(&self) -> bool` | `true` for Dilithium3, Dilithium5, Hybrid |
| `signature_size` | `fn signature_size(&self) -> usize` | Signature byte length |
| `public_key_size` | `fn public_key_size(&self) -> usize` | Public key byte length |

---

### Dilithium (ML-DSA)

#### `Dilithium3`

Default post-quantum signature scheme (NIST Level 3).

```rust
use aethelred_core::crypto::dilithium::Dilithium3;

let keypair = Dilithium3::generate_keypair()?;
let signature = keypair.sign(b"transaction data")?;
assert!(keypair.verify(b"transaction data", &signature)?);
```

##### Constants

| Constant | Value |
|----------|-------|
| `PUBLIC_KEY_SIZE` | 1,952 bytes |
| `SECRET_KEY_SIZE` | 4,000 bytes |
| `SIGNATURE_SIZE` | 3,293 bytes |

##### Associated Functions

| Function | Signature |
|----------|-----------|
| `generate_keypair` | `fn generate_keypair() -> CryptoResult<DilithiumKeyPair>` |
| `sign` | `fn sign(message: &[u8], secret_key: &DilithiumSecretKey) -> CryptoResult<DilithiumSignature>` |
| `verify` | `fn verify(message: &[u8], signature: &DilithiumSignature, public_key: &DilithiumPublicKey) -> CryptoResult<bool>` |

#### `DilithiumKeyPair`

| Method | Signature | Description |
|--------|-----------|-------------|
| `from_keys` | `fn from_keys(pk: DilithiumPublicKey, sk: DilithiumSecretKey) -> CryptoResult<Self>` | Construct from existing keys (level-checked) |
| `sign` | `fn sign(&self, message: &[u8]) -> CryptoResult<DilithiumSignature>` | Sign a message |
| `verify` | `fn verify(&self, message: &[u8], sig: &DilithiumSignature) -> CryptoResult<bool>` | Verify a signature |
| `level` | `fn level(&self) -> DilithiumLevel` | Get security level |

#### `DilithiumLevel`

```rust
pub enum DilithiumLevel {
    Level2,  // ~128-bit classical, ~64-bit quantum
    Level3,  // ~192-bit classical, ~128-bit quantum [DEFAULT]
    Level5,  // ~256-bit classical, ~128-bit quantum
}
```

#### `batch_verify`

```rust
pub fn batch_verify(
    messages: &[&[u8]],
    signatures: &[&DilithiumSignature],
    public_keys: &[&DilithiumPublicKey],
) -> CryptoResult<bool>
```

Verifies multiple signatures. Returns `false` on the first failure.

---

### Kyber (ML-KEM)

#### `Kyber768`

Default post-quantum key encapsulation mechanism (NIST Level 3).

```rust
use aethelred_core::crypto::kyber::{Kyber768, KyberKeyPair, KyberLevel};

let keypair = Kyber768::generate_keypair()?;
let (ciphertext, shared_secret) = keypair.public_key().encapsulate()?;
let recovered = keypair.decapsulate(&ciphertext)?;
assert_eq!(shared_secret.as_bytes(), recovered.as_bytes());
```

##### Constants

| Constant | Value |
|----------|-------|
| `PUBLIC_KEY_SIZE` | 1,184 bytes |
| `SECRET_KEY_SIZE` | 2,400 bytes |
| `CIPHERTEXT_SIZE` | 1,088 bytes |
| `SHARED_SECRET_SIZE` | 32 bytes |

#### `KyberLevel`

| Variant | Classical | Quantum | PK Size | CT Size |
|---------|-----------|---------|---------|---------|
| `Kyber512` | 128-bit | 64-bit | 800 B | 768 B |
| `Kyber768` | 192-bit | 128-bit | 1,184 B | 1,088 B |
| `Kyber1024` | 256-bit | 192-bit | 1,568 B | 1,568 B |

#### `SharedSecret`

A 32-byte shared secret produced by Kyber KEM. Implements `Zeroize` and `ZeroizeOnDrop`.

| Method | Signature | Description |
|--------|-----------|-------------|
| `from_bytes` | `fn from_bytes(bytes: &[u8; 32]) -> Self` | Construct from raw bytes |
| `as_bytes` | `fn as_bytes(&self) -> &[u8; 32]` | Borrow the secret |
| `derive_key` | `fn derive_key(&self, info: &[u8], output: &mut [u8]) -> CryptoResult<()>` | HKDF-SHA256 key derivation |

---

### Hybrid Signatures

#### `HybridKeypair` (ECDSA + Dilithium3)

Enterprise-grade algorithm-agile scheme combining classical ECDSA secp256k1 with post-quantum Dilithium3. Verification behavior adapts to the global `QuantumThreatLevel`.

| Threat Level | Classical | Quantum | Behavior |
|--------------|-----------|---------|----------|
| 0--2 (Pre-Quantum) | Required | Required | Both must verify |
| 3--4 (Elevated) | Optional | Required | Quantum mandatory |
| 5+ (Q-Day) | Ignored | Required | Quantum-only mode |

---

### Quantum Threat Level

#### `QuantumThreatLevel`

Governance-controlled global threat level that gates signature verification mode.

```rust
pub struct QuantumThreatLevel(pub u8);
```

| Constant | Value | Meaning |
|----------|-------|---------|
| `NONE` | 0 | No known threat |
| `EARLY_WARNING` | 1 | Large QCs in development |
| `ELEVATED` | 2 | QCs approaching crypto relevance |
| `HIGH` | 3 | CRQC announced |
| `CRITICAL` | 4 | Active quantum attacks observed |
| `Q_DAY` | 5 | Classical crypto considered broken |

##### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `skip_classical()` | `bool` | `true` when level >= 5 |
| `classical_optional()` | `bool` | `true` when level >= 3 |
| `quantum_only()` | `bool` | `true` when level >= 5 |

---

### Utility Functions

```rust
// SDK-level crypto helpers (aethelred_sdk::crypto)
pub fn sha256(data: &[u8]) -> Vec<u8>
pub fn sha256_hex(data: &[u8]) -> String
pub fn to_hex(bytes: &[u8]) -> String
pub fn from_hex(hex_str: &str) -> Result<Vec<u8>, hex::FromHexError>
```

---

### Errors

#### `CryptoError`

| Variant | Description |
|---------|-------------|
| `InvalidSignatureLength { expected, actual }` | Wrong byte count for signature |
| `InvalidPublicKeyLength { expected, actual }` | Wrong byte count for public key |
| `InvalidSecretKeyLength { expected, actual }` | Wrong byte count for secret key |
| `VerificationFailed` | Signature did not verify |
| `KeyGenerationFailed(String)` | CSPRNG or parameter error |
| `InvalidKeyFormat(String)` | Deserialization or level mismatch |
| `HybridComponentMismatch` | Classical and quantum parts inconsistent |
| `QuantumThreatActive` | PQC-only mode rejects classical-only signature |
| `DecapsulationFailed` | Kyber decapsulation error |
