# Rust Cryptography API

The `aethelred-crypto` crate provides post-quantum cryptographic primitives: hybrid ECDSA+Dilithium3 signatures, Kyber768 key encapsulation, hashing, and key derivation.

## Import

```rust
use aethelred_crypto::{
    KeyPair, PublicKey, HybridSignature,
    KemKeyPair, KemPublicKey,
    hash, kdf,
};
```

## Key Pairs

### KeyPair::generate

Generates a hybrid ECDSA (secp256k1) + Dilithium3 key pair.

```rust
pub fn generate() -> Result<KeyPair>
```

### KeyPair Methods

```rust
impl KeyPair {
    pub fn generate() -> Result<Self>;
    pub fn public_key(&self) -> &PublicKey;
    pub fn address(&self) -> Address;
    pub fn sign(&self, msg: &[u8]) -> Result<HybridSignature>;
    pub fn export(&self, password: &str) -> Result<Vec<u8>>;
    pub fn import(data: &[u8], password: &str) -> Result<Self>;
}
```

### PublicKey

```rust
impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8>;
    pub fn from_bytes(data: &[u8]) -> Result<Self>;
    pub fn address(&self) -> Address;
    pub fn ecdsa_component(&self) -> &[u8; 33];
    pub fn dilithium_component(&self) -> &[u8; 1952];
    pub fn verify(&self, msg: &[u8], sig: &HybridSignature) -> Result<bool>;
}
```

## Hybrid Signatures

```rust
pub struct HybridSignature {
    pub ecdsa: [u8; 64],
    pub dilithium3: Vec<u8>,   // ~2,420 bytes
}

impl HybridSignature {
    pub fn to_bytes(&self) -> Vec<u8>;
    pub fn from_bytes(data: &[u8]) -> Result<Self>;
    pub fn verify_ecdsa_only(&self, pubkey: &PublicKey, msg: &[u8]) -> bool;
    pub fn verify_dilithium_only(&self, pubkey: &PublicKey, msg: &[u8]) -> bool;
}
```

### Sign and Verify

```rust
let kp = KeyPair::generate()?;
let msg = b"transfer 100 AETHEL";
let sig = kp.sign(msg)?;
let valid = kp.public_key().verify(msg, &sig)?;
assert!(valid);
```

### Size Constants

| Parameter | Size |
|---|---|
| ECDSA signature | 64 bytes |
| Dilithium3 signature | 3,293 bytes |
| Dilithium3 public key | 1,952 bytes |
| Dilithium3 secret key | 4,000 bytes |

## Key Encapsulation (Kyber768)

```rust
impl KemKeyPair {
    pub fn generate() -> Result<Self>;
    pub fn public_key(&self) -> &KemPublicKey;
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SharedSecret>;
}
```

```rust
let alice = KemKeyPair::generate()?;
let (shared_secret, ciphertext) = kem::encapsulate(alice.public_key())?;
let alice_secret = alice.decapsulate(&ciphertext)?;
assert_eq!(shared_secret.as_bytes(), alice_secret.as_bytes());
```

| Parameter | Size |
|---|---|
| Kyber768 public key | 1,184 bytes |
| Kyber768 secret key | 2,400 bytes |
| Kyber768 ciphertext | 1,088 bytes |
| Shared secret | 32 bytes |

## Hashing

```rust
pub mod hash {
    pub fn sha3_256(data: &[u8]) -> [u8; 32];
    pub fn sha3_512(data: &[u8]) -> [u8; 64];
    pub fn blake3(data: &[u8]) -> [u8; 32];
    pub fn keccak256(data: &[u8]) -> [u8; 32];
}
```

## Key Derivation

```rust
pub mod kdf {
    pub fn hkdf(secret: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>>;
    pub fn argon2id(password: &[u8], salt: &[u8], config: Argon2Config) -> Result<Vec<u8>>;
}
```

## Symmetric Encryption

```rust
pub mod aead {
    pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
}
```

## Related Pages

- [Cryptography Overview](/cryptography/overview) -- algorithm choices and rationale
- [Security Parameters](/cryptography/security-parameters) -- security levels and wire formats
- [Key Management](/cryptography/key-management) -- key lifecycle
- [Go Cryptography API](/api/go/crypto) -- Go equivalent
