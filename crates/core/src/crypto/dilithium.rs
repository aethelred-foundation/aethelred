//! Dilithium Post-Quantum Digital Signatures
//!
//! Production implementation using the pqcrypto-dilithium crate which provides
//! NIST FIPS 204 (ML-DSA) compliant lattice-based digital signatures.
//!
//! # Security Levels
//!
//! - Dilithium2 (Level 2): ~128-bit classical, ~64-bit quantum
//! - Dilithium3 (Level 3): ~192-bit classical, ~128-bit quantum [DEFAULT]
//! - Dilithium5 (Level 5): ~256-bit classical, ~128-bit quantum
//!
//! # Key Sizes (Dilithium3)
//!
//! | Parameter     | Size (bytes) |
//! |---------------|--------------|
//! | Public Key    | 1,952        |
//! | Secret Key    | 4,000        |
//! | Signature     | 3,293        |
//!
//! # Example
//!
//! ```rust,ignore
//! use aethelred_core::crypto::dilithium::{Dilithium3, KeyPair};
//!
//! // Generate keypair
//! let keypair = Dilithium3::generate_keypair()?;
//!
//! // Sign a message
//! let message = b"Transaction data";
//! let signature = keypair.sign(message)?;
//!
//! // Verify signature
//! assert!(Dilithium3::verify(message, &signature, &keypair.public_key)?);
//! ```

use super::{CryptoError, CryptoResult};
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as PQPublicKey, SecretKey as PQSecretKey,
};
use sha3::{Digest, Sha3_256};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Dilithium security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DilithiumLevel {
    /// NIST Level 2 (~128-bit classical, ~64-bit quantum)
    Level2,
    /// NIST Level 3 (~192-bit classical, ~128-bit quantum) [DEFAULT]
    Level3,
    /// NIST Level 5 (~256-bit classical, ~128-bit quantum)
    Level5,
}

impl DilithiumLevel {
    /// Get public key size in bytes
    pub const fn public_key_size(&self) -> usize {
        match self {
            Self::Level2 => dilithium2::public_key_bytes(),
            Self::Level3 => dilithium3::public_key_bytes(),
            Self::Level5 => dilithium5::public_key_bytes(),
        }
    }

    /// Get secret key size in bytes
    pub const fn secret_key_size(&self) -> usize {
        match self {
            Self::Level2 => dilithium2::secret_key_bytes(),
            Self::Level3 => dilithium3::secret_key_bytes(),
            Self::Level5 => dilithium5::secret_key_bytes(),
        }
    }

    /// Get signature size in bytes
    pub const fn signature_size(&self) -> usize {
        match self {
            Self::Level2 => dilithium2::signature_bytes(),
            Self::Level3 => dilithium3::signature_bytes(),
            Self::Level5 => dilithium5::signature_bytes(),
        }
    }

    /// Get algorithm identifier byte
    pub const fn algorithm_id(&self) -> u8 {
        match self {
            Self::Level2 => 0x02,
            Self::Level3 => 0x03,
            Self::Level5 => 0x05,
        }
    }
}

impl Default for DilithiumLevel {
    fn default() -> Self {
        Self::Level3
    }
}

/// Dilithium public key
#[derive(Clone, PartialEq, Eq)]
pub struct DilithiumPublicKey {
    /// Raw public key bytes
    bytes: Vec<u8>,
    /// Security level
    level: DilithiumLevel,
}

impl DilithiumPublicKey {
    /// Create from raw bytes with validation
    pub fn from_bytes(bytes: &[u8], level: DilithiumLevel) -> CryptoResult<Self> {
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

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get security level
    pub fn level(&self) -> DilithiumLevel {
        self.level
    }

    /// Compute fingerprint (first 16 bytes of SHA3-256 hash)
    pub fn fingerprint(&self) -> [u8; 16] {
        let hash = Sha3_256::digest(&self.bytes);
        let mut fp = [0u8; 16];
        fp.copy_from_slice(&hash[..16]);
        fp
    }

    /// Serialize with level prefix
    pub fn to_bytes_with_prefix(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + self.bytes.len());
        result.push(self.level.algorithm_id());
        result.extend_from_slice(&self.bytes);
        result
    }

    /// Deserialize with level prefix
    pub fn from_bytes_with_prefix(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.is_empty() {
            return Err(CryptoError::InvalidPublicKeyLength {
                expected: 1,
                actual: 0,
            });
        }

        let level = match bytes[0] {
            0x02 => DilithiumLevel::Level2,
            0x03 => DilithiumLevel::Level3,
            0x05 => DilithiumLevel::Level5,
            _ => {
                return Err(CryptoError::InvalidKeyFormat(format!(
                    "Unknown Dilithium level: 0x{:02x}",
                    bytes[0]
                )))
            }
        };

        Self::from_bytes(&bytes[1..], level)
    }
}

impl fmt::Debug for DilithiumPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DilithiumPublicKey")
            .field("level", &self.level)
            .field("fingerprint", &hex::encode(self.fingerprint()))
            .finish()
    }
}

/// Dilithium secret key (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DilithiumSecretKey {
    bytes: Vec<u8>,
    #[zeroize(skip)]
    level: DilithiumLevel,
}

impl DilithiumSecretKey {
    /// Create from raw bytes with validation
    pub fn from_bytes(bytes: &[u8], level: DilithiumLevel) -> CryptoResult<Self> {
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

    /// Get raw bytes (sensitive - use with caution)
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get security level
    pub fn level(&self) -> DilithiumLevel {
        self.level
    }
}

impl fmt::Debug for DilithiumSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DilithiumSecretKey")
            .field("level", &self.level)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Dilithium signature
#[derive(Clone, PartialEq, Eq)]
pub struct DilithiumSignature {
    bytes: Vec<u8>,
    level: DilithiumLevel,
}

impl DilithiumSignature {
    /// Create from raw bytes with validation
    pub fn from_bytes(bytes: &[u8], level: DilithiumLevel) -> CryptoResult<Self> {
        let expected = level.signature_size();
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

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get security level
    pub fn level(&self) -> DilithiumLevel {
        self.level
    }

    /// Serialize with level prefix
    pub fn to_bytes_with_prefix(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + self.bytes.len());
        result.push(self.level.algorithm_id());
        result.extend_from_slice(&self.bytes);
        result
    }

    /// Deserialize with level prefix
    pub fn from_bytes_with_prefix(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.is_empty() {
            return Err(CryptoError::InvalidSignatureLength {
                expected: 1,
                actual: 0,
            });
        }

        let level = match bytes[0] {
            0x02 => DilithiumLevel::Level2,
            0x03 => DilithiumLevel::Level3,
            0x05 => DilithiumLevel::Level5,
            _ => {
                return Err(CryptoError::InvalidKeyFormat(format!(
                    "Unknown Dilithium level: 0x{:02x}",
                    bytes[0]
                )))
            }
        };

        Self::from_bytes(&bytes[1..], level)
    }
}

impl fmt::Debug for DilithiumSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DilithiumSignature")
            .field("level", &self.level)
            .field("size", &self.bytes.len())
            .finish()
    }
}

/// Dilithium keypair
#[derive(Clone)]
pub struct DilithiumKeyPair {
    pub public_key: DilithiumPublicKey,
    secret_key: DilithiumSecretKey,
}

impl DilithiumKeyPair {
    /// Create from existing keys
    pub fn from_keys(
        public_key: DilithiumPublicKey,
        secret_key: DilithiumSecretKey,
    ) -> CryptoResult<Self> {
        if public_key.level != secret_key.level {
            return Err(CryptoError::InvalidKeyFormat(
                "Public and secret key levels don't match".into(),
            ));
        }

        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> &DilithiumPublicKey {
        &self.public_key
    }

    /// Get the secret key (sensitive)
    pub fn secret_key(&self) -> &DilithiumSecretKey {
        &self.secret_key
    }

    /// Get security level
    pub fn level(&self) -> DilithiumLevel {
        self.public_key.level
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> CryptoResult<DilithiumSignature> {
        sign(message, &self.secret_key)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &DilithiumSignature) -> CryptoResult<bool> {
        verify(message, signature, &self.public_key)
    }
}

impl fmt::Debug for DilithiumKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DilithiumKeyPair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

/// Dilithium3 implementation (default security level)
pub struct Dilithium3;

impl Dilithium3 {
    /// Public key size in bytes
    pub const PUBLIC_KEY_SIZE: usize = dilithium3::public_key_bytes();
    /// Secret key size in bytes
    pub const SECRET_KEY_SIZE: usize = dilithium3::secret_key_bytes();
    /// Signature size in bytes
    pub const SIGNATURE_SIZE: usize = dilithium3::signature_bytes();

    /// Generate a new keypair
    pub fn generate_keypair() -> CryptoResult<DilithiumKeyPair> {
        generate_keypair(DilithiumLevel::Level3)
    }

    /// Sign a message
    pub fn sign(
        message: &[u8],
        secret_key: &DilithiumSecretKey,
    ) -> CryptoResult<DilithiumSignature> {
        if secret_key.level != DilithiumLevel::Level3 {
            return Err(CryptoError::InvalidKeyFormat(
                "Expected Dilithium3 secret key".into(),
            ));
        }
        sign(message, secret_key)
    }

    /// Verify a signature
    pub fn verify(
        message: &[u8],
        signature: &DilithiumSignature,
        public_key: &DilithiumPublicKey,
    ) -> CryptoResult<bool> {
        if public_key.level != DilithiumLevel::Level3 || signature.level != DilithiumLevel::Level3 {
            return Err(CryptoError::InvalidKeyFormat(
                "Expected Dilithium3 keys and signature".into(),
            ));
        }
        verify(message, signature, public_key)
    }
}

/// Generate a Dilithium keypair using pqcrypto-dilithium
///
/// Uses the library's internal CSPRNG for secure key generation.
pub fn generate_keypair(level: DilithiumLevel) -> CryptoResult<DilithiumKeyPair> {
    match level {
        DilithiumLevel::Level2 => {
            let (pk, sk) = dilithium2::keypair();
            let public_key = DilithiumPublicKey::from_bytes(pk.as_bytes(), level)?;
            let secret_key = DilithiumSecretKey::from_bytes(sk.as_bytes(), level)?;
            DilithiumKeyPair::from_keys(public_key, secret_key)
        }
        DilithiumLevel::Level3 => {
            let (pk, sk) = dilithium3::keypair();
            let public_key = DilithiumPublicKey::from_bytes(pk.as_bytes(), level)?;
            let secret_key = DilithiumSecretKey::from_bytes(sk.as_bytes(), level)?;
            DilithiumKeyPair::from_keys(public_key, secret_key)
        }
        DilithiumLevel::Level5 => {
            let (pk, sk) = dilithium5::keypair();
            let public_key = DilithiumPublicKey::from_bytes(pk.as_bytes(), level)?;
            let secret_key = DilithiumSecretKey::from_bytes(sk.as_bytes(), level)?;
            DilithiumKeyPair::from_keys(public_key, secret_key)
        }
    }
}

/// Sign a message with a Dilithium secret key using pqcrypto-dilithium
pub fn sign(message: &[u8], secret_key: &DilithiumSecretKey) -> CryptoResult<DilithiumSignature> {
    let level = secret_key.level;

    let sig_bytes = match level {
        DilithiumLevel::Level2 => {
            let sk = dilithium2::SecretKey::from_bytes(secret_key.as_bytes()).map_err(|_| {
                CryptoError::InvalidKeyFormat("Invalid Dilithium2 secret key".into())
            })?;
            let sig = dilithium2::detached_sign(message, &sk);
            sig.as_bytes().to_vec()
        }
        DilithiumLevel::Level3 => {
            let sk = dilithium3::SecretKey::from_bytes(secret_key.as_bytes()).map_err(|_| {
                CryptoError::InvalidKeyFormat("Invalid Dilithium3 secret key".into())
            })?;
            let sig = dilithium3::detached_sign(message, &sk);
            sig.as_bytes().to_vec()
        }
        DilithiumLevel::Level5 => {
            let sk = dilithium5::SecretKey::from_bytes(secret_key.as_bytes()).map_err(|_| {
                CryptoError::InvalidKeyFormat("Invalid Dilithium5 secret key".into())
            })?;
            let sig = dilithium5::detached_sign(message, &sk);
            sig.as_bytes().to_vec()
        }
    };

    DilithiumSignature::from_bytes(&sig_bytes, level)
}

/// Verify a Dilithium signature using pqcrypto-dilithium
pub fn verify(
    message: &[u8],
    signature: &DilithiumSignature,
    public_key: &DilithiumPublicKey,
) -> CryptoResult<bool> {
    // Validate levels match
    if signature.level != public_key.level {
        return Err(CryptoError::InvalidKeyFormat(
            "Signature and public key levels don't match".into(),
        ));
    }

    let level = signature.level;

    let result = match level {
        DilithiumLevel::Level2 => {
            let pk = dilithium2::PublicKey::from_bytes(public_key.as_bytes()).map_err(|_| {
                CryptoError::InvalidKeyFormat("Invalid Dilithium2 public key".into())
            })?;
            let sig =
                dilithium2::DetachedSignature::from_bytes(signature.as_bytes()).map_err(|_| {
                    CryptoError::InvalidKeyFormat("Invalid Dilithium2 signature".into())
                })?;
            dilithium2::verify_detached_signature(&sig, message, &pk).is_ok()
        }
        DilithiumLevel::Level3 => {
            let pk = dilithium3::PublicKey::from_bytes(public_key.as_bytes()).map_err(|_| {
                CryptoError::InvalidKeyFormat("Invalid Dilithium3 public key".into())
            })?;
            let sig =
                dilithium3::DetachedSignature::from_bytes(signature.as_bytes()).map_err(|_| {
                    CryptoError::InvalidKeyFormat("Invalid Dilithium3 signature".into())
                })?;
            dilithium3::verify_detached_signature(&sig, message, &pk).is_ok()
        }
        DilithiumLevel::Level5 => {
            let pk = dilithium5::PublicKey::from_bytes(public_key.as_bytes()).map_err(|_| {
                CryptoError::InvalidKeyFormat("Invalid Dilithium5 public key".into())
            })?;
            let sig =
                dilithium5::DetachedSignature::from_bytes(signature.as_bytes()).map_err(|_| {
                    CryptoError::InvalidKeyFormat("Invalid Dilithium5 signature".into())
                })?;
            dilithium5::verify_detached_signature(&sig, message, &pk).is_ok()
        }
    };

    Ok(result)
}

/// Batch verify multiple signatures (more efficient than individual verification)
pub fn batch_verify(
    messages: &[&[u8]],
    signatures: &[&DilithiumSignature],
    public_keys: &[&DilithiumPublicKey],
) -> CryptoResult<bool> {
    if messages.len() != signatures.len() || signatures.len() != public_keys.len() {
        return Err(CryptoError::InvalidSignatureLength {
            expected: messages.len(),
            actual: signatures.len(),
        });
    }

    // Dilithium doesn't have native batch verification, so we verify individually
    // However, this can still be parallelized for better performance
    for ((message, signature), public_key) in messages
        .iter()
        .zip(signatures.iter())
        .zip(public_keys.iter())
    {
        if !verify(message, signature, public_key)? {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = Dilithium3::generate_keypair().unwrap();
        assert_eq!(
            keypair.public_key().as_bytes().len(),
            Dilithium3::PUBLIC_KEY_SIZE
        );
        assert_eq!(
            keypair.secret_key().as_bytes().len(),
            Dilithium3::SECRET_KEY_SIZE
        );
    }

    #[test]
    fn test_sign_verify() {
        let keypair = Dilithium3::generate_keypair().unwrap();
        let message = b"Test message for Dilithium3";

        let signature = keypair.sign(message).unwrap();
        assert_eq!(signature.as_bytes().len(), Dilithium3::SIGNATURE_SIZE);

        let is_valid = keypair.verify(message, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_sign_verify_wrong_message() {
        let keypair = Dilithium3::generate_keypair().unwrap();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = keypair.sign(message).unwrap();
        let is_valid = keypair.verify(wrong_message, &signature).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_different_levels() {
        // Test Level2
        let keypair2 = generate_keypair(DilithiumLevel::Level2).unwrap();
        let msg = b"Test";
        let sig2 = keypair2.sign(msg).unwrap();
        assert!(keypair2.verify(msg, &sig2).unwrap());

        // Test Level5
        let keypair5 = generate_keypair(DilithiumLevel::Level5).unwrap();
        let sig5 = keypair5.sign(msg).unwrap();
        assert!(keypair5.verify(msg, &sig5).unwrap());
    }

    #[test]
    fn test_serialization() {
        let keypair = Dilithium3::generate_keypair().unwrap();

        // Serialize with prefix
        let pk_bytes = keypair.public_key().to_bytes_with_prefix();
        assert_eq!(pk_bytes[0], DilithiumLevel::Level3.algorithm_id());

        // Deserialize
        let pk_restored = DilithiumPublicKey::from_bytes_with_prefix(&pk_bytes).unwrap();
        assert_eq!(pk_restored.as_bytes(), keypair.public_key().as_bytes());
    }

    #[test]
    fn test_cross_level_verification_fails() {
        let keypair3 = generate_keypair(DilithiumLevel::Level3).unwrap();
        let keypair5 = generate_keypair(DilithiumLevel::Level5).unwrap();

        let message = b"Test message";
        let sig3 = keypair3.sign(message).unwrap();

        // Attempting to verify with wrong level should fail
        let result = verify(message, &sig3, &keypair5.public_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_verify() {
        let keypair = Dilithium3::generate_keypair().unwrap();
        let messages: Vec<&[u8]> = vec![b"msg1", b"msg2", b"msg3"];

        let signatures: Vec<DilithiumSignature> =
            messages.iter().map(|m| keypair.sign(m).unwrap()).collect();

        let sig_refs: Vec<&DilithiumSignature> = signatures.iter().collect();
        let pk_refs: Vec<&DilithiumPublicKey> = vec![&keypair.public_key; 3];

        let result = batch_verify(&messages, &sig_refs, &pk_refs).unwrap();
        assert!(result);
    }
}
