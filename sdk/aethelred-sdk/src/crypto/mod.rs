//! # Cryptographic Primitives
//!
//! **"Post-Quantum Ready from Day One"**
//!
//! This module provides hybrid cryptographic primitives that combine
//! classical ECDSA with post-quantum Dilithium3 signatures.
//!
//! ## Security Model
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    HYBRID SIGNATURE SCHEME                          │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                      │
//! │   Message ──┬──► ECDSA P-256 ──────┬──► Combined Signature          │
//! │             │                       │                                │
//! │             └──► Dilithium3 ───────┘                                │
//! │                  (NIST FIPS 204)                                    │
//! │                                                                      │
//! │   Verification: BOTH must pass                                      │
//! │   Security: max(classical, quantum)                                 │
//! │                                                                      │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Why Hybrid?
//!
//! - **Classical Security**: ECDSA is battle-tested and widely deployed
//! - **Quantum Security**: Dilithium3 provides post-quantum security
//! - **Future-Proof**: Data signed today remains secure after Q-Day
//! - **Gradual Migration**: Systems can verify either or both

mod hybrid;
mod hash;
mod kdf;
mod encryption;

pub use hybrid::*;
pub use hash::*;
pub use kdf::*;
pub use encryption::*;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Cryptographic errors
#[derive(Error, Debug, Clone)]
pub enum CryptoError {
    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// Signing failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Verification failed
    #[error("Signature verification failed")]
    VerificationFailed,

    /// Invalid key format
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    /// Invalid signature format
    #[error("Invalid signature format: {0}")]
    InvalidSignatureFormat(String),

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Random generation failed
    #[error("Random generation failed: {0}")]
    RandomFailed(String),
}

// ============================================================================
// Algorithm Identifiers
// ============================================================================

/// Signature algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// ECDSA with P-256 curve
    EcdsaP256,

    /// ECDSA with P-384 curve
    EcdsaP384,

    /// Ed25519
    Ed25519,

    /// Dilithium3 (NIST FIPS 204)
    Dilithium3,

    /// Dilithium5 (highest security)
    Dilithium5,

    /// Hybrid ECDSA P-256 + Dilithium3
    HybridEcdsaDilithium3,

    /// Hybrid Ed25519 + Dilithium3
    HybridEd25519Dilithium3,
}

impl SignatureAlgorithm {
    /// Get the signature size in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            SignatureAlgorithm::EcdsaP256 => 64,
            SignatureAlgorithm::EcdsaP384 => 96,
            SignatureAlgorithm::Ed25519 => 64,
            SignatureAlgorithm::Dilithium3 => 3293,
            SignatureAlgorithm::Dilithium5 => 4595,
            SignatureAlgorithm::HybridEcdsaDilithium3 => 64 + 3293 + 4,
            SignatureAlgorithm::HybridEd25519Dilithium3 => 64 + 3293 + 4,
        }
    }

    /// Get the public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            SignatureAlgorithm::EcdsaP256 => 64,
            SignatureAlgorithm::EcdsaP384 => 96,
            SignatureAlgorithm::Ed25519 => 32,
            SignatureAlgorithm::Dilithium3 => 1952,
            SignatureAlgorithm::Dilithium5 => 2592,
            SignatureAlgorithm::HybridEcdsaDilithium3 => 64 + 1952 + 4,
            SignatureAlgorithm::HybridEd25519Dilithium3 => 32 + 1952 + 4,
        }
    }

    /// Is this a post-quantum algorithm?
    pub fn is_post_quantum(&self) -> bool {
        matches!(
            self,
            SignatureAlgorithm::Dilithium3
                | SignatureAlgorithm::Dilithium5
                | SignatureAlgorithm::HybridEcdsaDilithium3
                | SignatureAlgorithm::HybridEd25519Dilithium3
        )
    }

    /// Is this a hybrid algorithm?
    pub fn is_hybrid(&self) -> bool {
        matches!(
            self,
            SignatureAlgorithm::HybridEcdsaDilithium3
                | SignatureAlgorithm::HybridEd25519Dilithium3
        )
    }

    /// NIST security level
    pub fn security_level(&self) -> u8 {
        match self {
            SignatureAlgorithm::EcdsaP256 => 2,
            SignatureAlgorithm::EcdsaP384 => 3,
            SignatureAlgorithm::Ed25519 => 2,
            SignatureAlgorithm::Dilithium3 => 3,
            SignatureAlgorithm::Dilithium5 => 5,
            SignatureAlgorithm::HybridEcdsaDilithium3 => 3,
            SignatureAlgorithm::HybridEd25519Dilithium3 => 3,
        }
    }
}

/// Encryption algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM
    Aes256Gcm,

    /// ChaCha20-Poly1305
    ChaCha20Poly1305,

    /// AES-256-GCM-SIV
    Aes256GcmSiv,
}

impl EncryptionAlgorithm {
    /// Get key size in bytes
    pub fn key_size(&self) -> usize {
        match self {
            EncryptionAlgorithm::Aes256Gcm => 32,
            EncryptionAlgorithm::ChaCha20Poly1305 => 32,
            EncryptionAlgorithm::Aes256GcmSiv => 32,
        }
    }

    /// Get nonce size in bytes
    pub fn nonce_size(&self) -> usize {
        match self {
            EncryptionAlgorithm::Aes256Gcm => 12,
            EncryptionAlgorithm::ChaCha20Poly1305 => 12,
            EncryptionAlgorithm::Aes256GcmSiv => 12,
        }
    }

    /// Get tag size in bytes
    pub fn tag_size(&self) -> usize {
        16 // All use 128-bit tags
    }
}

/// Key derivation algorithm
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfAlgorithm {
    /// HKDF with SHA-256
    HkdfSha256,

    /// HKDF with SHA-384
    HkdfSha384,

    /// Argon2id (for passwords)
    Argon2id,

    /// PBKDF2 with SHA-256
    Pbkdf2Sha256,
}

/// Hash algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SHA-256
    Sha256,

    /// SHA-384
    Sha384,

    /// SHA-512
    Sha512,

    /// SHA3-256
    Sha3_256,

    /// BLAKE3
    Blake3,
}

impl HashAlgorithm {
    /// Get output size in bytes
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
            HashAlgorithm::Sha3_256 => 32,
            HashAlgorithm::Blake3 => 32,
        }
    }
}

// ============================================================================
// Secure Random
// ============================================================================

/// Secure random number generation
pub struct SecureRandom;

impl SecureRandom {
    /// Generate random bytes
    pub fn fill_bytes(buffer: &mut [u8]) -> Result<(), CryptoError> {
        use rand::RngCore;
        rand::thread_rng()
            .try_fill_bytes(buffer)
            .map_err(|e| CryptoError::RandomFailed(e.to_string()))
    }

    /// Generate a random 32-byte value
    pub fn random_32() -> Result<[u8; 32], CryptoError> {
        let mut bytes = [0u8; 32];
        Self::fill_bytes(&mut bytes)?;
        Ok(bytes)
    }

    /// Generate a random nonce
    pub fn nonce(size: usize) -> Result<Vec<u8>, CryptoError> {
        let mut bytes = vec![0u8; size];
        Self::fill_bytes(&mut bytes)?;
        Ok(bytes)
    }
}

// ============================================================================
// Key Serialization
// ============================================================================

/// Key encoding format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEncoding {
    /// Raw bytes
    Raw,

    /// Base64
    Base64,

    /// Hex
    Hex,

    /// PEM (for X.509 compatibility)
    Pem,
}

/// Trait for keys that can be serialized
pub trait SerializableKey {
    /// Encode to bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Decode from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>
    where
        Self: Sized;

    /// Encode to string with format
    fn encode(&self, format: KeyEncoding) -> String {
        let bytes = self.to_bytes();
        match format {
            KeyEncoding::Raw => String::from_utf8_lossy(&bytes).to_string(),
            KeyEncoding::Base64 => base64::encode(&bytes),
            KeyEncoding::Hex => hex::encode(&bytes),
            KeyEncoding::Pem => {
                // Basic PEM encoding
                let b64 = base64::encode(&bytes);
                format!(
                    "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
                    b64
                )
            }
        }
    }

    /// Decode from string with format
    fn decode(s: &str, format: KeyEncoding) -> Result<Self, CryptoError>
    where
        Self: Sized,
    {
        let bytes = match format {
            KeyEncoding::Raw => s.as_bytes().to_vec(),
            KeyEncoding::Base64 => base64::decode(s)
                .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?,
            KeyEncoding::Hex => hex::decode(s)
                .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?,
            KeyEncoding::Pem => {
                // Extract base64 from PEM
                let content = s
                    .lines()
                    .filter(|l| !l.starts_with("-----"))
                    .collect::<String>();
                base64::decode(content.trim())
                    .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?
            }
        };
        Self::from_bytes(&bytes)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_sizes() {
        assert_eq!(SignatureAlgorithm::EcdsaP256.signature_size(), 64);
        assert_eq!(SignatureAlgorithm::Dilithium3.signature_size(), 3293);
        assert!(SignatureAlgorithm::HybridEcdsaDilithium3.signature_size() > 3293);
    }

    #[test]
    fn test_post_quantum() {
        assert!(!SignatureAlgorithm::EcdsaP256.is_post_quantum());
        assert!(SignatureAlgorithm::Dilithium3.is_post_quantum());
        assert!(SignatureAlgorithm::HybridEcdsaDilithium3.is_post_quantum());
    }

    #[test]
    fn test_secure_random() {
        let bytes = SecureRandom::random_32().unwrap();
        assert_eq!(bytes.len(), 32);

        // Check not all zeros
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_encryption_params() {
        assert_eq!(EncryptionAlgorithm::Aes256Gcm.key_size(), 32);
        assert_eq!(EncryptionAlgorithm::Aes256Gcm.nonce_size(), 12);
        assert_eq!(EncryptionAlgorithm::Aes256Gcm.tag_size(), 16);
    }
}
