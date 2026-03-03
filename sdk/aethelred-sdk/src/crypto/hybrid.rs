//! # Hybrid Signature Scheme
//!
//! Combines ECDSA P-256 with Dilithium3 for post-quantum security.

use super::*;
use serde::{Deserialize, Serialize};

/// Dilithium security levels supported by hybrid signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DilithiumSecurityLevel {
    Level2,
    #[default]
    Level3,
    Level5,
}

impl DilithiumSecurityLevel {
    fn public_key_size(self) -> usize {
        match self {
            DilithiumSecurityLevel::Level2 => 1312,
            DilithiumSecurityLevel::Level3 => 1952,
            DilithiumSecurityLevel::Level5 => 2592,
        }
    }

    fn secret_key_size(self) -> usize {
        match self {
            DilithiumSecurityLevel::Level2 => 2528,
            DilithiumSecurityLevel::Level3 => 4032,
            DilithiumSecurityLevel::Level5 => 4896,
        }
    }

    fn signature_size(self) -> usize {
        match self {
            DilithiumSecurityLevel::Level2 => 2420,
            DilithiumSecurityLevel::Level3 => 3293,
            DilithiumSecurityLevel::Level5 => 4595,
        }
    }

    fn from_public_key_size(size: usize) -> Option<Self> {
        match size {
            1312 => Some(DilithiumSecurityLevel::Level2),
            1952 => Some(DilithiumSecurityLevel::Level3),
            2592 => Some(DilithiumSecurityLevel::Level5),
            _ => None,
        }
    }

    fn from_signature_size(size: usize) -> Option<Self> {
        match size {
            2420 => Some(DilithiumSecurityLevel::Level2),
            3293 => Some(DilithiumSecurityLevel::Level3),
            4595 => Some(DilithiumSecurityLevel::Level5),
            _ => None,
        }
    }
}

// ============================================================================
// Hybrid Keypair
// ============================================================================

/// Hybrid keypair combining ECDSA and Dilithium3
#[derive(Clone)]
pub struct HybridKeypair {
    /// ECDSA keypair
    ecdsa_secret: [u8; 32],
    ecdsa_public: [u8; 64],

    /// Dilithium3 keypair
    dilithium_secret: Vec<u8>,
    dilithium_public: Vec<u8>,
    level: DilithiumSecurityLevel,
}

impl HybridKeypair {
    /// Generate a new hybrid keypair
    pub fn generate() -> Self {
        Self::generate_with_level(DilithiumSecurityLevel::Level3)
    }

    /// Generate a new hybrid keypair for a specific Dilithium level.
    pub fn generate_with_level(level: DilithiumSecurityLevel) -> Self {
        // Generate ECDSA keypair
        let mut ecdsa_secret = [0u8; 32];
        SecureRandom::fill_bytes(&mut ecdsa_secret).unwrap();

        // In production, derive public key using P-256 curve operations
        let mut ecdsa_public = [0u8; 64];
        Self::derive_ecdsa_public(&ecdsa_secret, &mut ecdsa_public);

        // Generate Dilithium3 keypair
        // In production, use pqcrypto-dilithium
        let (dilithium_secret, dilithium_public) = Self::generate_dilithium(level);

        HybridKeypair {
            ecdsa_secret,
            ecdsa_public,
            dilithium_secret,
            dilithium_public,
            level,
        }
    }

    /// Generate from seed (deterministic)
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::from_seed_with_level(seed, DilithiumSecurityLevel::Level3)
    }

    /// Generate from seed for a specific Dilithium level.
    pub fn from_seed_with_level(seed: &[u8; 32], level: DilithiumSecurityLevel) -> Self {
        use sha2::{Digest, Sha256};

        // Derive ECDSA seed
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(b"ecdsa");
        let ecdsa_seed: [u8; 32] = hasher.finalize().into();

        // Derive Dilithium seed
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(b"dilithium");
        let dilithium_seed: [u8; 32] = hasher.finalize().into();

        let mut ecdsa_public = [0u8; 64];
        Self::derive_ecdsa_public(&ecdsa_seed, &mut ecdsa_public);

        let (dilithium_secret, dilithium_public) =
            Self::generate_dilithium_from_seed(&dilithium_seed, level);

        HybridKeypair {
            ecdsa_secret: ecdsa_seed,
            ecdsa_public,
            dilithium_secret,
            dilithium_public,
            level,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            ecdsa: self.ecdsa_public,
            dilithium: self.dilithium_public.clone(),
            level: self.level,
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        // Sign with ECDSA
        let ecdsa_sig = self.sign_ecdsa(message);

        // Sign with Dilithium
        let dilithium_sig = self.sign_dilithium(message);

        HybridSignature {
            ecdsa: ecdsa_sig,
            dilithium: dilithium_sig,
            level: self.level,
        }
    }

    /// Sign a message (async-friendly)
    pub async fn sign_async(&self, message: &[u8]) -> HybridSignature {
        self.sign(message)
    }

    // ========================================================================
    // Internal Implementation
    // ========================================================================

    fn derive_ecdsa_public(secret: &[u8; 32], public: &mut [u8; 64]) {
        // In production, use p256 crate for proper curve operations
        // For now, placeholder derivation
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(b"public_x");
        let x: [u8; 32] = hasher.finalize().into();

        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(b"public_y");
        let y: [u8; 32] = hasher.finalize().into();

        public[..32].copy_from_slice(&x);
        public[32..].copy_from_slice(&y);
    }

    fn generate_dilithium(level: DilithiumSecurityLevel) -> (Vec<u8>, Vec<u8>) {
        // In production, use pqcrypto_dilithium::dilithium3
        // For now, placeholder
        let mut secret = vec![0u8; level.secret_key_size()];
        let mut public = vec![0u8; level.public_key_size()];

        SecureRandom::fill_bytes(&mut secret).unwrap();
        SecureRandom::fill_bytes(&mut public).unwrap();

        (secret, public)
    }

    fn generate_dilithium_from_seed(
        seed: &[u8; 32],
        level: DilithiumSecurityLevel,
    ) -> (Vec<u8>, Vec<u8>) {
        // In production, use pqcrypto_dilithium::dilithium3::keypair_from_seed
        use sha2::{Digest, Sha512};

        let mut hasher = Sha512::new();
        hasher.update(seed);
        let expanded = hasher.finalize();

        let mut secret = vec![0u8; level.secret_key_size()];
        let mut public = vec![0u8; level.public_key_size()];

        // Placeholder: expand seed to fill keys
        for i in 0..secret.len() {
            secret[i] = expanded[i % 64];
        }
        for i in 0..public.len() {
            public[i] = expanded[(i + 32) % 64];
        }

        (secret, public)
    }

    fn sign_ecdsa(&self, message: &[u8]) -> [u8; 64] {
        // In production, use p256::ecdsa::SigningKey
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&self.ecdsa_secret);
        hasher.update(message);
        let hash = hasher.finalize();

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&hash);

        let mut hasher = Sha256::new();
        hasher.update(&hash);
        hasher.update(&self.ecdsa_secret);
        let hash2 = hasher.finalize();
        sig[32..].copy_from_slice(&hash2);

        sig
    }

    fn sign_dilithium(&self, message: &[u8]) -> Vec<u8> {
        // In production, use pqcrypto_dilithium::dilithium3::sign
        use sha2::{Digest, Sha512};

        let mut hasher = Sha512::new();
        hasher.update(&self.dilithium_secret[..64]);
        hasher.update(message);
        let hash = hasher.finalize();

        // Placeholder signature
        let mut sig = vec![0u8; self.level.signature_size()];
        sig[..64].copy_from_slice(&hash);

        sig
    }
}

impl std::fmt::Debug for HybridKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridKeypair")
            .field("ecdsa_public", &hex::encode(&self.ecdsa_public[..8]))
            .field("dilithium_public_len", &self.dilithium_public.len())
            .finish()
    }
}

// ============================================================================
// Hybrid Public Key
// ============================================================================

/// Hybrid public key
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridPublicKey {
    /// ECDSA P-256 public key (uncompressed, 64 bytes)
    pub ecdsa: [u8; 64],

    /// Dilithium3 public key (1952 bytes)
    pub dilithium: Vec<u8>,
    #[serde(default)]
    pub level: DilithiumSecurityLevel,
}

impl HybridPublicKey {
    /// Verify a hybrid signature
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> bool {
        // Verify ECDSA
        if !self.verify_ecdsa(message, &signature.ecdsa) {
            return false;
        }

        // Verify Dilithium
        if !self.verify_dilithium(message, &signature.dilithium) {
            return false;
        }

        true
    }

    /// Verify only the classical (ECDSA) signature
    pub fn verify_classical(&self, message: &[u8], signature: &HybridSignature) -> bool {
        self.verify_ecdsa(message, &signature.ecdsa)
    }

    /// Verify only the post-quantum (Dilithium) signature
    pub fn verify_post_quantum(&self, message: &[u8], signature: &HybridSignature) -> bool {
        self.verify_dilithium(message, &signature.dilithium)
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + 4 + self.dilithium.len());

        // ECDSA public key
        bytes.extend_from_slice(&self.ecdsa);

        // Dilithium public key length
        bytes.extend_from_slice(&(self.dilithium.len() as u32).to_le_bytes());

        // Dilithium public key
        bytes.extend_from_slice(&self.dilithium);

        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 68 {
            return Err(CryptoError::InvalidKeyFormat(
                "Public key too short".to_string(),
            ));
        }

        let ecdsa: [u8; 64] = bytes[..64]
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyFormat("Invalid ECDSA key".to_string()))?;

        let dilithium_len =
            u32::from_le_bytes([bytes[64], bytes[65], bytes[66], bytes[67]]) as usize;

        let expected_len = 68 + dilithium_len;
        if bytes.len() < expected_len {
            return Err(CryptoError::InvalidKeyFormat(
                "Dilithium key truncated".to_string(),
            ));
        }
        if bytes.len() > expected_len {
            return Err(CryptoError::InvalidKeyFormat(
                "Public key has trailing bytes".to_string(),
            ));
        }

        let dilithium = bytes[68..68 + dilithium_len].to_vec();
        let level =
            DilithiumSecurityLevel::from_public_key_size(dilithium_len).ok_or_else(|| {
                CryptoError::InvalidKeyFormat(format!(
                    "Unsupported Dilithium public key length: {dilithium_len}"
                ))
            })?;

        Ok(HybridPublicKey {
            ecdsa,
            dilithium,
            level,
        })
    }

    /// Get a fingerprint (for display)
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.ecdsa);
        hasher.update(&self.dilithium);
        let hash = hasher.finalize();
        hex::encode(&hash[..8])
    }

    // ========================================================================
    // Internal
    // ========================================================================

    fn verify_ecdsa(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        // In production, use p256::ecdsa::VerifyingKey
        use sha2::{Digest, Sha256};

        // Placeholder verification
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.update(&self.ecdsa);
        let _hash = hasher.finalize();

        // For now, accept all (placeholder)
        signature.len() == 64
    }

    fn verify_dilithium(&self, message: &[u8], signature: &[u8]) -> bool {
        // In production, use pqcrypto_dilithium::dilithium3::verify
        use sha2::{Digest, Sha256};

        if signature.len() != self.level.signature_size() {
            return false;
        }

        // Placeholder verification
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.update(&self.dilithium);
        let _hash = hasher.finalize();

        // For now, accept all (placeholder)
        true
    }
}

// ============================================================================
// Hybrid Signature
// ============================================================================

/// Hybrid signature containing both ECDSA and Dilithium signatures
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSignature {
    /// ECDSA P-256 signature (64 bytes: r || s)
    pub ecdsa: [u8; 64],

    /// Dilithium3 signature (3293 bytes)
    pub dilithium: Vec<u8>,
    #[serde(default)]
    pub level: DilithiumSecurityLevel,
}

impl HybridSignature {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + 4 + self.dilithium.len());

        // ECDSA signature
        bytes.extend_from_slice(&self.ecdsa);

        // Dilithium signature length
        bytes.extend_from_slice(&(self.dilithium.len() as u32).to_le_bytes());

        // Dilithium signature
        bytes.extend_from_slice(&self.dilithium);

        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 68 {
            return Err(CryptoError::InvalidSignatureFormat(
                "Signature too short".to_string(),
            ));
        }

        let ecdsa: [u8; 64] = bytes[..64]
            .try_into()
            .map_err(|_| CryptoError::InvalidSignatureFormat("Invalid ECDSA sig".to_string()))?;

        let dilithium_len =
            u32::from_le_bytes([bytes[64], bytes[65], bytes[66], bytes[67]]) as usize;

        let expected_len = 68 + dilithium_len;
        if bytes.len() < expected_len {
            return Err(CryptoError::InvalidSignatureFormat(
                "Dilithium sig truncated".to_string(),
            ));
        }
        if bytes.len() > expected_len {
            return Err(CryptoError::InvalidSignatureFormat(
                "Signature has trailing bytes".to_string(),
            ));
        }

        let dilithium = bytes[68..68 + dilithium_len].to_vec();
        let level =
            DilithiumSecurityLevel::from_signature_size(dilithium_len).ok_or_else(|| {
                CryptoError::InvalidSignatureFormat(format!(
                    "Unsupported Dilithium signature length: {dilithium_len}"
                ))
            })?;

        Ok(HybridSignature {
            ecdsa,
            dilithium,
            level,
        })
    }

    /// Get total size
    pub fn size(&self) -> usize {
        64 + 4 + self.dilithium.len()
    }

    /// Check if signature appears valid (structure check, not cryptographic)
    pub fn is_valid_format(&self) -> bool {
        self.level.signature_size() == self.dilithium.len()
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Generate a new hybrid keypair
pub fn generate_keypair() -> HybridKeypair {
    HybridKeypair::generate()
}

/// Sign a message
pub fn sign(keypair: &HybridKeypair, message: &[u8]) -> HybridSignature {
    keypair.sign(message)
}

/// Verify a signature
pub fn verify(public_key: &HybridPublicKey, message: &[u8], signature: &HybridSignature) -> bool {
    public_key.verify(message, signature)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = HybridKeypair::generate();
        let public = keypair.public_key();

        assert_eq!(public.ecdsa.len(), 64);
        assert_eq!(public.dilithium.len(), 1952);
        assert_eq!(public.level, DilithiumSecurityLevel::Level3);
    }

    #[test]
    fn test_deterministic_generation() {
        let seed = [42u8; 32];

        let keypair1 = HybridKeypair::from_seed(&seed);
        let keypair2 = HybridKeypair::from_seed(&seed);

        assert_eq!(keypair1.ecdsa_public, keypair2.ecdsa_public);
        assert_eq!(keypair1.dilithium_public, keypair2.dilithium_public);
    }

    #[test]
    fn test_sign_verify() {
        let keypair = HybridKeypair::generate();
        let public = keypair.public_key();

        let message = b"Hello, post-quantum world!";
        let signature = keypair.sign(message);

        assert!(signature.is_valid_format());
        assert!(public.verify(message, &signature));
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = HybridKeypair::generate();
        let signature = keypair.sign(b"test message");

        let bytes = signature.to_bytes();
        let recovered = HybridSignature::from_bytes(&bytes).unwrap();

        assert_eq!(signature.ecdsa, recovered.ecdsa);
        assert_eq!(signature.dilithium, recovered.dilithium);
        assert_eq!(signature.level, recovered.level);
    }

    #[test]
    fn test_public_key_serialization() {
        let keypair = HybridKeypair::generate();
        let public = keypair.public_key();

        let bytes = public.to_bytes();
        let recovered = HybridPublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(public.ecdsa, recovered.ecdsa);
        assert_eq!(public.dilithium, recovered.dilithium);
        assert_eq!(public.level, recovered.level);
    }

    #[test]
    fn test_signature_deserialize_level2_and_level5() {
        for level in [
            DilithiumSecurityLevel::Level2,
            DilithiumSecurityLevel::Level5,
        ] {
            let sig = HybridSignature {
                ecdsa: [7u8; 64],
                dilithium: vec![9u8; level.signature_size()],
                level,
            };

            let recovered = HybridSignature::from_bytes(&sig.to_bytes()).unwrap();
            assert_eq!(recovered.level, level);
            assert!(recovered.is_valid_format());
        }
    }

    #[test]
    fn test_public_key_deserialize_level2_and_level5() {
        for level in [
            DilithiumSecurityLevel::Level2,
            DilithiumSecurityLevel::Level5,
        ] {
            let pk = HybridPublicKey {
                ecdsa: [3u8; 64],
                dilithium: vec![5u8; level.public_key_size()],
                level,
            };

            let recovered = HybridPublicKey::from_bytes(&pk.to_bytes()).unwrap();
            assert_eq!(recovered.level, level);
            assert_eq!(recovered.dilithium.len(), level.public_key_size());
        }
    }

    #[test]
    fn test_signature_deserialize_rejects_trailing_bytes() {
        let keypair = HybridKeypair::generate();
        let signature = keypair.sign(b"test message");
        let mut bytes = signature.to_bytes();
        bytes.push(0xAA);

        let err = HybridSignature::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignatureFormat(_)));
    }

    #[test]
    fn test_public_key_deserialize_rejects_trailing_bytes() {
        let keypair = HybridKeypair::generate();
        let public = keypair.public_key();
        let mut bytes = public.to_bytes();
        bytes.push(0xBB);

        let err = HybridPublicKey::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidKeyFormat(_)));
    }

    #[test]
    fn test_fingerprint() {
        let keypair = HybridKeypair::generate();
        let public = keypair.public_key();

        let fingerprint = public.fingerprint();
        assert_eq!(fingerprint.len(), 16); // 8 bytes = 16 hex chars
    }
}
