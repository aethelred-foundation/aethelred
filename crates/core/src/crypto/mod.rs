//! Aethelred Cryptographic Primitives
//!
//! Enterprise-grade cryptographic implementations for:
//! - Post-Quantum signatures (Dilithium3 - NIST FIPS 204)
//! - Classical signatures (ECDSA secp256k1)
//! - Hybrid signature schemes
//! - Key encapsulation (Kyber768 - NIST FIPS 203)
//!
//! # Security Levels
//!
//! | Algorithm | Classical Security | Quantum Security |
//! |-----------|-------------------|------------------|
//! | ECDSA     | 128-bit           | 0-bit (broken)   |
//! | Dilithium3| 192-bit           | 128-bit          |
//! | Hybrid    | 192-bit           | 128-bit          |

pub mod dilithium;
pub mod ecdsa;
pub mod hash;
pub mod hybrid;
#[cfg(test)]
mod kat_tests;
pub mod kyber;
#[cfg(feature = "hsm")]
pub mod signer;

use thiserror::Error;

/// Cryptographic errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },

    #[error("Invalid public key length: expected {expected}, got {actual}")]
    InvalidPublicKeyLength { expected: usize, actual: usize },

    #[error("Invalid secret key length: expected {expected}, got {actual}")]
    InvalidSecretKeyLength { expected: usize, actual: usize },

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Hybrid signature component mismatch")]
    HybridComponentMismatch,

    #[error("Quantum threat level requires PQC-only signatures")]
    QuantumThreatActive,

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Decapsulation failed")]
    DecapsulationFailed,
}

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Signature algorithm identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SignatureAlgorithm {
    /// ECDSA on secp256k1 (Bitcoin/Ethereum compatible)
    EcdsaSecp256k1 = 0x01,
    /// Dilithium3 (NIST Level 3 post-quantum)
    Dilithium3 = 0x02,
    /// Hybrid: ECDSA + Dilithium3
    Hybrid = 0x03,
    /// Dilithium5 (NIST Level 5 post-quantum)
    Dilithium5 = 0x04,
}

impl SignatureAlgorithm {
    /// Parse from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::EcdsaSecp256k1),
            0x02 => Some(Self::Dilithium3),
            0x03 => Some(Self::Hybrid),
            0x04 => Some(Self::Dilithium5),
            _ => None,
        }
    }

    /// Convert to byte
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Check if algorithm is quantum-safe
    pub fn is_quantum_safe(&self) -> bool {
        matches!(self, Self::Dilithium3 | Self::Dilithium5 | Self::Hybrid)
    }

    /// Get signature size in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            Self::EcdsaSecp256k1 => 64,
            Self::Dilithium3 => 3309,
            Self::Dilithium5 => 4627,
            Self::Hybrid => 64 + 3309 + 1, // ECDSA + Dilithium3 + separator
        }
    }

    /// Get public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::EcdsaSecp256k1 => 33, // Compressed
            Self::Dilithium3 => 1952,
            Self::Dilithium5 => 2592,
            Self::Hybrid => 33 + 1952 + 1, // ECDSA + Dilithium3 + separator
        }
    }
}

/// Global quantum threat level
///
/// This value is updated via governance and affects signature verification:
/// - Level 0-2: Both classical and quantum signatures required
/// - Level 3-4: Classical optional, quantum mandatory
/// - Level 5+: Quantum-only mode (classical signatures ignored)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct QuantumThreatLevel(pub u8);

impl QuantumThreatLevel {
    /// No known threat
    pub const NONE: Self = Self(0);
    /// Early warning - large quantum computers in development
    pub const EARLY_WARNING: Self = Self(1);
    /// Elevated - quantum computers approaching cryptographic relevance
    pub const ELEVATED: Self = Self(2);
    /// High - CRQC (Cryptographically Relevant Quantum Computer) announced
    pub const HIGH: Self = Self(3);
    /// Critical - Active quantum attacks observed
    pub const CRITICAL: Self = Self(4);
    /// Q-Day - Classical crypto considered broken
    pub const Q_DAY: Self = Self(5);

    /// Check if classical signatures should be skipped
    pub fn skip_classical(&self) -> bool {
        self.0 >= 5
    }

    /// Check if classical signatures are optional
    pub fn classical_optional(&self) -> bool {
        self.0 >= 3
    }

    /// Check if only quantum signatures are accepted
    pub fn quantum_only(&self) -> bool {
        self.0 >= 5
    }
}

impl Default for QuantumThreatLevel {
    fn default() -> Self {
        Self::NONE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_algorithm_sizes() {
        assert_eq!(SignatureAlgorithm::EcdsaSecp256k1.signature_size(), 64);
        assert_eq!(SignatureAlgorithm::Dilithium3.signature_size(), 3309);
        assert!(SignatureAlgorithm::Hybrid.is_quantum_safe());
        assert!(!SignatureAlgorithm::EcdsaSecp256k1.is_quantum_safe());
    }

    #[test]
    fn test_quantum_threat_level() {
        assert!(!QuantumThreatLevel::NONE.skip_classical());
        assert!(!QuantumThreatLevel::HIGH.skip_classical());
        assert!(QuantumThreatLevel::Q_DAY.skip_classical());
        assert!(QuantumThreatLevel::Q_DAY.quantum_only());
    }
}
