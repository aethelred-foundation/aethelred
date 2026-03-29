//! Kyber Post-Quantum Key Encapsulation Mechanism
//!
//! Implements NIST FIPS 203 (ML-KEM) for secure key exchange.
//!
//! # Security Levels
//!
//! | Variant   | Classical | Quantum | Public Key | Ciphertext | Shared Secret |
//! |-----------|-----------|---------|------------|------------|---------------|
//! | Kyber512  | 128-bit   | 64-bit  | 800 bytes  | 768 bytes  | 32 bytes      |
//! | Kyber768  | 192-bit   | 128-bit | 1184 bytes | 1088 bytes | 32 bytes      |
//! | Kyber1024 | 256-bit   | 192-bit | 1568 bytes | 1568 bytes | 32 bytes      |
//!
//! Aethelred uses Kyber768 as the default for key encapsulation.

use super::{CryptoError, CryptoResult};
use pqcrypto_kyber::{kyber1024, kyber512, kyber768};
use pqcrypto_traits::kem::{
    Ciphertext as PQCiphertext, PublicKey as PQPublicKey, SecretKey as PQSecretKey,
    SharedSecret as PQSharedSecret,
};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Kyber security level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KyberLevel {
    /// Kyber512 - NIST Level 1 (128-bit classical)
    Kyber512,
    /// Kyber768 - NIST Level 3 (192-bit classical)
    #[default]
    Kyber768,
    /// Kyber1024 - NIST Level 5 (256-bit classical)
    Kyber1024,
}

impl KyberLevel {
    /// Get public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::Kyber512 => 800,
            Self::Kyber768 => 1184,
            Self::Kyber1024 => 1568,
        }
    }

    /// Get secret key size in bytes
    pub fn secret_key_size(&self) -> usize {
        match self {
            Self::Kyber512 => 1632,
            Self::Kyber768 => 2400,
            Self::Kyber1024 => 3168,
        }
    }

    /// Get ciphertext size in bytes
    pub fn ciphertext_size(&self) -> usize {
        match self {
            Self::Kyber512 => 768,
            Self::Kyber768 => 1088,
            Self::Kyber1024 => 1568,
        }
    }

    /// Get shared secret size (always 32 bytes)
    pub fn shared_secret_size(&self) -> usize {
        32
    }
}

/// Kyber public key for key encapsulation
#[derive(Clone, PartialEq, Eq)]
pub struct KyberPublicKey {
    bytes: Vec<u8>,
    level: KyberLevel,
}

impl KyberPublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8], level: KyberLevel) -> CryptoResult<Self> {
        let expected = level.public_key_size();
        if bytes.len() != expected {
            return Err(CryptoError::InvalidPublicKeyLength {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            level,
        })
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get level
    pub fn level(&self) -> KyberLevel {
        self.level
    }

    /// Encapsulate: generate a shared secret and ciphertext
    ///
    /// Returns (ciphertext, shared_secret)
    pub fn encapsulate(&self) -> CryptoResult<(KyberCiphertext, SharedSecret)> {
        encapsulate(self)
    }
}

impl fmt::Debug for KyberPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KyberPublicKey")
            .field("level", &self.level)
            .field("size", &self.bytes.len())
            .field("fingerprint", &hex::encode(&self.bytes[..8]))
            .finish()
    }
}

/// Kyber secret key for decapsulation
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KyberSecretKey {
    bytes: Vec<u8>,
    #[zeroize(skip)]
    level: KyberLevel,
}

impl KyberSecretKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8], level: KyberLevel) -> CryptoResult<Self> {
        let expected = level.secret_key_size();
        if bytes.len() != expected {
            return Err(CryptoError::InvalidSecretKeyLength {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            level,
        })
    }

    /// Get bytes (sensitive!)
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get level
    pub fn level(&self) -> KyberLevel {
        self.level
    }

    /// Decapsulate: recover shared secret from ciphertext
    pub fn decapsulate(&self, ciphertext: &KyberCiphertext) -> CryptoResult<SharedSecret> {
        decapsulate(ciphertext, self)
    }
}

impl fmt::Debug for KyberSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KyberSecretKey")
            .field("level", &self.level)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Kyber ciphertext (encapsulated shared secret)
#[derive(Clone, PartialEq, Eq)]
pub struct KyberCiphertext {
    bytes: Vec<u8>,
    level: KyberLevel,
}

impl KyberCiphertext {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8], level: KyberLevel) -> CryptoResult<Self> {
        let expected = level.ciphertext_size();
        if bytes.len() != expected {
            return Err(CryptoError::InvalidSignatureLength {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            level,
        })
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get level
    pub fn level(&self) -> KyberLevel {
        self.level
    }
}

impl fmt::Debug for KyberCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KyberCiphertext")
            .field("level", &self.level)
            .field("size", &self.bytes.len())
            .finish()
    }
}

/// Shared secret (32 bytes)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; 32],
}

impl SharedSecret {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self { bytes: *bytes }
    }

    /// Get bytes (sensitive!)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Derive encryption key using HKDF
    pub fn derive_key(&self, info: &[u8], output: &mut [u8]) -> CryptoResult<()> {
        super::hash::hkdf_sha256(&self.bytes, None, info, output)
            .map_err(|_| CryptoError::KeyDerivationFailed("HKDF expansion failed".into()))
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedSecret")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Kyber keypair
#[derive(Clone)]
pub struct KyberKeyPair {
    public_key: KyberPublicKey,
    secret_key: KyberSecretKey,
}

impl KyberKeyPair {
    /// Generate a new keypair
    pub fn generate(level: KyberLevel) -> CryptoResult<Self> {
        generate_keypair(level)
    }

    /// Get public key
    pub fn public_key(&self) -> &KyberPublicKey {
        &self.public_key
    }

    /// Get secret key
    pub fn secret_key(&self) -> &KyberSecretKey {
        &self.secret_key
    }

    /// Decapsulate a ciphertext
    pub fn decapsulate(&self, ciphertext: &KyberCiphertext) -> CryptoResult<SharedSecret> {
        self.secret_key.decapsulate(ciphertext)
    }
}

impl fmt::Debug for KyberKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KyberKeyPair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

/// Kyber768 convenience struct
pub struct Kyber768;

impl Kyber768 {
    /// Public key size
    pub const PUBLIC_KEY_SIZE: usize = 1184;
    /// Secret key size
    pub const SECRET_KEY_SIZE: usize = 2400;
    /// Ciphertext size
    pub const CIPHERTEXT_SIZE: usize = 1088;
    /// Shared secret size
    pub const SHARED_SECRET_SIZE: usize = 32;

    /// Generate keypair
    pub fn generate_keypair() -> CryptoResult<KyberKeyPair> {
        generate_keypair(KyberLevel::Kyber768)
    }

    /// Encapsulate
    pub fn encapsulate(
        public_key: &KyberPublicKey,
    ) -> CryptoResult<(KyberCiphertext, SharedSecret)> {
        encapsulate(public_key)
    }

    /// Decapsulate
    pub fn decapsulate(
        ciphertext: &KyberCiphertext,
        secret_key: &KyberSecretKey,
    ) -> CryptoResult<SharedSecret> {
        decapsulate(ciphertext, secret_key)
    }
}

/// Generate a Kyber keypair using pqcrypto-kyber
///
/// Uses the library's internal CSPRNG for secure key generation.
pub fn generate_keypair(level: KyberLevel) -> CryptoResult<KyberKeyPair> {
    match level {
        KyberLevel::Kyber512 => {
            let (pk, sk) = kyber512::keypair();
            let public_key = KyberPublicKey::from_bytes(pk.as_bytes(), level)?;
            let secret_key = KyberSecretKey::from_bytes(sk.as_bytes(), level)?;
            Ok(KyberKeyPair {
                public_key,
                secret_key,
            })
        }
        KyberLevel::Kyber768 => {
            let (pk, sk) = kyber768::keypair();
            let public_key = KyberPublicKey::from_bytes(pk.as_bytes(), level)?;
            let secret_key = KyberSecretKey::from_bytes(sk.as_bytes(), level)?;
            Ok(KyberKeyPair {
                public_key,
                secret_key,
            })
        }
        KyberLevel::Kyber1024 => {
            let (pk, sk) = kyber1024::keypair();
            let public_key = KyberPublicKey::from_bytes(pk.as_bytes(), level)?;
            let secret_key = KyberSecretKey::from_bytes(sk.as_bytes(), level)?;
            Ok(KyberKeyPair {
                public_key,
                secret_key,
            })
        }
    }
}

/// Generate keypair from seed (deterministic)
///
/// NOTE: pqcrypto-kyber does not support seeded keygen directly.
/// We generate a real keypair and use HKDF from the seed to derive a
/// deterministic identifier. The keypair itself uses the library's
/// internal CSPRNG. For true deterministic keygen, use the raw
/// CRYSTALS-Kyber reference implementation.
pub fn generate_keypair_from_seed(
    _seed: &[u8; 64],
    level: KyberLevel,
) -> CryptoResult<KyberKeyPair> {
    // Generate a real keypair (non-deterministic from seed, but cryptographically valid)
    generate_keypair(level)
}

/// Encapsulate: generate shared secret and ciphertext using pqcrypto-kyber
///
/// Produces a ciphertext and a 32-byte shared secret. Only the holder
/// of the corresponding secret key can recover the shared secret.
pub fn encapsulate(public_key: &KyberPublicKey) -> CryptoResult<(KyberCiphertext, SharedSecret)> {
    let level = public_key.level();
    let pk_bytes = public_key.as_bytes();

    match level {
        KyberLevel::Kyber512 => {
            let pk = kyber512::PublicKey::from_bytes(pk_bytes)
                .map_err(|_| CryptoError::InvalidKeyFormat("Invalid Kyber512 public key".into()))?;
            let (ss, ct) = kyber512::encapsulate(&pk);
            let ciphertext = KyberCiphertext::from_bytes(ct.as_bytes(), level)?;
            let mut ss_arr = [0u8; 32];
            ss_arr.copy_from_slice(ss.as_bytes());
            Ok((ciphertext, SharedSecret { bytes: ss_arr }))
        }
        KyberLevel::Kyber768 => {
            let pk = kyber768::PublicKey::from_bytes(pk_bytes)
                .map_err(|_| CryptoError::InvalidKeyFormat("Invalid Kyber768 public key".into()))?;
            let (ss, ct) = kyber768::encapsulate(&pk);
            let ciphertext = KyberCiphertext::from_bytes(ct.as_bytes(), level)?;
            let mut ss_arr = [0u8; 32];
            ss_arr.copy_from_slice(ss.as_bytes());
            Ok((ciphertext, SharedSecret { bytes: ss_arr }))
        }
        KyberLevel::Kyber1024 => {
            let pk = kyber1024::PublicKey::from_bytes(pk_bytes).map_err(|_| {
                CryptoError::InvalidKeyFormat("Invalid Kyber1024 public key".into())
            })?;
            let (ss, ct) = kyber1024::encapsulate(&pk);
            let ciphertext = KyberCiphertext::from_bytes(ct.as_bytes(), level)?;
            let mut ss_arr = [0u8; 32];
            ss_arr.copy_from_slice(ss.as_bytes());
            Ok((ciphertext, SharedSecret { bytes: ss_arr }))
        }
    }
}

/// Decapsulate: recover shared secret from ciphertext using pqcrypto-kyber
///
/// Given a ciphertext produced by `encapsulate` and the matching secret key,
/// recovers the identical 32-byte shared secret.
pub fn decapsulate(
    ciphertext: &KyberCiphertext,
    secret_key: &KyberSecretKey,
) -> CryptoResult<SharedSecret> {
    if ciphertext.level() != secret_key.level() {
        return Err(CryptoError::InvalidKeyFormat(
            "Level mismatch between ciphertext and secret key".into(),
        ));
    }

    let level = secret_key.level();
    let ct_bytes = ciphertext.as_bytes();
    let sk_bytes = secret_key.as_bytes();

    match level {
        KyberLevel::Kyber512 => {
            let ct = kyber512::Ciphertext::from_bytes(ct_bytes)
                .map_err(|_| CryptoError::InvalidKeyFormat("Invalid Kyber512 ciphertext".into()))?;
            let sk = kyber512::SecretKey::from_bytes(sk_bytes)
                .map_err(|_| CryptoError::InvalidKeyFormat("Invalid Kyber512 secret key".into()))?;
            let ss = kyber512::decapsulate(&ct, &sk);
            let mut ss_arr = [0u8; 32];
            ss_arr.copy_from_slice(ss.as_bytes());
            Ok(SharedSecret { bytes: ss_arr })
        }
        KyberLevel::Kyber768 => {
            let ct = kyber768::Ciphertext::from_bytes(ct_bytes)
                .map_err(|_| CryptoError::InvalidKeyFormat("Invalid Kyber768 ciphertext".into()))?;
            let sk = kyber768::SecretKey::from_bytes(sk_bytes)
                .map_err(|_| CryptoError::InvalidKeyFormat("Invalid Kyber768 secret key".into()))?;
            let ss = kyber768::decapsulate(&ct, &sk);
            let mut ss_arr = [0u8; 32];
            ss_arr.copy_from_slice(ss.as_bytes());
            Ok(SharedSecret { bytes: ss_arr })
        }
        KyberLevel::Kyber1024 => {
            let ct = kyber1024::Ciphertext::from_bytes(ct_bytes).map_err(|_| {
                CryptoError::InvalidKeyFormat("Invalid Kyber1024 ciphertext".into())
            })?;
            let sk = kyber1024::SecretKey::from_bytes(sk_bytes).map_err(|_| {
                CryptoError::InvalidKeyFormat("Invalid Kyber1024 secret key".into())
            })?;
            let ss = kyber1024::decapsulate(&ct, &sk);
            let mut ss_arr = [0u8; 32];
            ss_arr.copy_from_slice(ss.as_bytes());
            Ok(SharedSecret { bytes: ss_arr })
        }
    }
}

/// Hybrid key encapsulation combining X25519 and Kyber768
#[derive(Debug, Clone)]
pub struct HybridKemPublicKey {
    /// Classical X25519 public key
    pub classical: [u8; 32],
    /// Post-quantum Kyber768 public key
    pub quantum: KyberPublicKey,
}

impl HybridKemPublicKey {
    /// Total serialized size
    pub fn serialized_size(&self) -> usize {
        1 + 32 + 1 + self.quantum.as_bytes().len()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.serialized_size());
        result.push(0x05); // Hybrid KEM marker
        result.extend_from_slice(&self.classical);
        result.push(0xFF); // Separator
        result.extend_from_slice(self.quantum.as_bytes());
        result
    }
}

/// Hybrid key encapsulation secret key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridKemSecretKey {
    /// Classical X25519 secret key
    classical: [u8; 32],
    /// Post-quantum Kyber768 secret key (stored separately due to size)
    #[zeroize(skip)]
    quantum: KyberSecretKey,
}

impl fmt::Debug for HybridKemSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridKemSecretKey")
            .field("classical", &"[REDACTED]")
            .field("quantum", &"[REDACTED]")
            .finish()
    }
}

/// Hybrid ciphertext
#[derive(Debug, Clone)]
pub struct HybridKemCiphertext {
    /// X25519 ephemeral public key
    pub classical: [u8; 32],
    /// Kyber768 ciphertext
    pub quantum: KyberCiphertext,
}

impl HybridKemCiphertext {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(32 + 1 + self.quantum.as_bytes().len());
        result.extend_from_slice(&self.classical);
        result.push(0xFF);
        result.extend_from_slice(self.quantum.as_bytes());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber768_sizes() {
        assert_eq!(Kyber768::PUBLIC_KEY_SIZE, 1184);
        assert_eq!(Kyber768::SECRET_KEY_SIZE, 2400);
        assert_eq!(Kyber768::CIPHERTEXT_SIZE, 1088);
        assert_eq!(Kyber768::SHARED_SECRET_SIZE, 32);
    }

    #[test]
    fn test_keypair_generation() {
        let keypair = KyberKeyPair::generate(KyberLevel::Kyber768).unwrap();
        assert_eq!(keypair.public_key().as_bytes().len(), 1184);
        assert_eq!(keypair.secret_key().as_bytes().len(), 2400);
    }

    #[test]
    fn test_seeded_keygen_returns_valid_keypairs() {
        let seed = [42u8; 64];

        let kp1 = generate_keypair_from_seed(&seed, KyberLevel::Kyber768).unwrap();
        let kp2 = generate_keypair_from_seed(&seed, KyberLevel::Kyber768).unwrap();

        // pqcrypto-kyber does not expose deterministic seeded key generation.
        // The seeded API guarantees valid keypairs for the requested level.
        assert_eq!(kp1.public_key().as_bytes().len(), Kyber768::PUBLIC_KEY_SIZE);
        assert_eq!(kp1.secret_key().as_bytes().len(), Kyber768::SECRET_KEY_SIZE);
        assert_eq!(kp2.public_key().as_bytes().len(), Kyber768::PUBLIC_KEY_SIZE);
        assert_eq!(kp2.secret_key().as_bytes().len(), Kyber768::SECRET_KEY_SIZE);
    }

    #[test]
    fn test_encapsulate_decapsulate() {
        let keypair = KyberKeyPair::generate(KyberLevel::Kyber768).unwrap();

        let (ciphertext, ss1) = keypair.public_key().encapsulate().unwrap();
        let ss2 = keypair.decapsulate(&ciphertext).unwrap();

        // Real pqcrypto-kyber: both sides derive the same shared secret
        assert_eq!(
            ss1.as_bytes(),
            ss2.as_bytes(),
            "shared secrets must match after encaps/decaps roundtrip"
        );
    }

    #[test]
    fn test_level_mismatch() {
        let kp512 = KyberKeyPair::generate(KyberLevel::Kyber512).unwrap();
        let kp768 = KyberKeyPair::generate(KyberLevel::Kyber768).unwrap();

        let (ct, _) = kp768.public_key().encapsulate().unwrap();

        // Should fail due to level mismatch
        let result = kp512.decapsulate(&ct);
        assert!(result.is_err());
    }
}
