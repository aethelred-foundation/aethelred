//! # Hybrid Signature Scheme
//!
//! Combines ECDSA secp256k1 with Dilithium for post-quantum security.

use super::*;
use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature as EcdsaSignature, SigningKey, VerifyingKey,
};
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
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
            DilithiumSecurityLevel::Level2 => dilithium2::public_key_bytes(),
            DilithiumSecurityLevel::Level3 => dilithium3::public_key_bytes(),
            DilithiumSecurityLevel::Level5 => dilithium5::public_key_bytes(),
        }
    }

    fn signature_size(self) -> usize {
        match self {
            DilithiumSecurityLevel::Level2 => dilithium2::signature_bytes(),
            DilithiumSecurityLevel::Level3 => dilithium3::signature_bytes(),
            DilithiumSecurityLevel::Level5 => dilithium5::signature_bytes(),
        }
    }

    fn from_public_key_size(size: usize) -> Option<Self> {
        if size == dilithium2::public_key_bytes() {
            Some(DilithiumSecurityLevel::Level2)
        } else if size == dilithium3::public_key_bytes() {
            Some(DilithiumSecurityLevel::Level3)
        } else if size == dilithium5::public_key_bytes() {
            Some(DilithiumSecurityLevel::Level5)
        } else {
            None
        }
    }

    fn from_signature_size(size: usize) -> Option<Self> {
        if size == dilithium2::signature_bytes() {
            Some(DilithiumSecurityLevel::Level2)
        } else if size == dilithium3::signature_bytes() {
            Some(DilithiumSecurityLevel::Level3)
        } else if size == dilithium5::signature_bytes() {
            Some(DilithiumSecurityLevel::Level5)
        } else {
            None
        }
    }
}

// ============================================================================
// Hybrid Keypair
// ============================================================================

/// Hybrid keypair combining ECDSA secp256k1 and Dilithium
#[derive(Clone)]
pub struct HybridKeypair {
    /// ECDSA keypair
    ecdsa_secret: [u8; 32],
    ecdsa_public: [u8; 64],

    /// Dilithium keypair
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
        let (ecdsa_secret, ecdsa_public) = Self::generate_ecdsa_keypair();
        let (dilithium_secret, dilithium_public) = Self::generate_dilithium(level);

        HybridKeypair {
            ecdsa_secret,
            ecdsa_public,
            dilithium_secret,
            dilithium_public,
            level,
        }
    }

    /// Generate from seed (deterministic test helper)
    #[cfg(test)]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::from_seed_with_level(seed, DilithiumSecurityLevel::Level3)
    }

    /// Generate from seed for a specific Dilithium level.
    #[cfg(test)]
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

    fn generate_ecdsa_keypair() -> ([u8; 32], [u8; 64]) {
        loop {
            let mut secret = [0u8; 32];
            SecureRandom::fill_bytes(&mut secret).unwrap();

            if let Ok(signing_key) = SigningKey::from_slice(&secret) {
                return (
                    secret,
                    Self::encode_ecdsa_public(signing_key.verifying_key()),
                );
            }
        }
    }

    #[cfg(test)]
    fn derive_ecdsa_public(secret: &[u8; 32], public: &mut [u8; 64]) {
        let signing_key =
            SigningKey::from_slice(secret).expect("deterministic test seed must be valid");
        *public = Self::encode_ecdsa_public(signing_key.verifying_key());
    }

    fn encode_ecdsa_public(verifying_key: &VerifyingKey) -> [u8; 64] {
        let encoded = verifying_key.to_encoded_point(false);
        let bytes = encoded.as_bytes();
        let mut public = [0u8; 64];
        public.copy_from_slice(&bytes[1..65]);
        public
    }

    fn generate_dilithium(level: DilithiumSecurityLevel) -> (Vec<u8>, Vec<u8>) {
        match level {
            DilithiumSecurityLevel::Level2 => {
                let (public, secret) = dilithium2::keypair();
                (secret.as_bytes().to_vec(), public.as_bytes().to_vec())
            }
            DilithiumSecurityLevel::Level3 => {
                let (public, secret) = dilithium3::keypair();
                (secret.as_bytes().to_vec(), public.as_bytes().to_vec())
            }
            DilithiumSecurityLevel::Level5 => {
                let (public, secret) = dilithium5::keypair();
                (secret.as_bytes().to_vec(), public.as_bytes().to_vec())
            }
        }
    }

    #[cfg(test)]
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
        let signing_key =
            SigningKey::from_slice(&self.ecdsa_secret).expect("hybrid keypair stores valid ECDSA");
        let signature: EcdsaSignature = signing_key.sign(message);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&signature.to_bytes());
        sig
    }

    fn sign_dilithium(&self, message: &[u8]) -> Vec<u8> {
        match self.level {
            DilithiumSecurityLevel::Level2 => {
                let secret = dilithium2::SecretKey::from_bytes(&self.dilithium_secret)
                    .expect("hybrid keypair stores valid Dilithium2 secret key");
                dilithium2::detached_sign(message, &secret)
                    .as_bytes()
                    .to_vec()
            }
            DilithiumSecurityLevel::Level3 => {
                let secret = dilithium3::SecretKey::from_bytes(&self.dilithium_secret)
                    .expect("hybrid keypair stores valid Dilithium3 secret key");
                dilithium3::detached_sign(message, &secret)
                    .as_bytes()
                    .to_vec()
            }
            DilithiumSecurityLevel::Level5 => {
                let secret = dilithium5::SecretKey::from_bytes(&self.dilithium_secret)
                    .expect("hybrid keypair stores valid Dilithium5 secret key");
                dilithium5::detached_sign(message, &secret)
                    .as_bytes()
                    .to_vec()
            }
        }
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
    /// ECDSA secp256k1 public key (uncompressed x || y, 64 bytes)
    pub ecdsa: [u8; 64],

    /// Dilithium public key
    pub dilithium: Vec<u8>,
    #[serde(default)]
    pub level: DilithiumSecurityLevel,
}

impl HybridPublicKey {
    /// Verify a hybrid signature
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> bool {
        if self.level != signature.level {
            return false;
        }

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
        let mut encoded = [0u8; 65];
        encoded[0] = 0x04;
        encoded[1..].copy_from_slice(&self.ecdsa);

        let verifying_key = match VerifyingKey::from_sec1_bytes(&encoded) {
            Ok(key) => key,
            Err(_) => return false,
        };

        let signature = match EcdsaSignature::try_from(signature.as_slice()) {
            Ok(signature) => signature,
            Err(_) => return false,
        };

        verifying_key.verify(message, &signature).is_ok()
    }

    fn verify_dilithium(&self, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != self.level.signature_size() {
            return false;
        }
        if self.dilithium.len() != self.level.public_key_size() {
            return false;
        }

        match self.level {
            DilithiumSecurityLevel::Level2 => {
                let public = match dilithium2::PublicKey::from_bytes(&self.dilithium) {
                    Ok(public) => public,
                    Err(_) => return false,
                };
                let signature = match dilithium2::DetachedSignature::from_bytes(signature) {
                    Ok(signature) => signature,
                    Err(_) => return false,
                };
                dilithium2::verify_detached_signature(&signature, message, &public).is_ok()
            }
            DilithiumSecurityLevel::Level3 => {
                let public = match dilithium3::PublicKey::from_bytes(&self.dilithium) {
                    Ok(public) => public,
                    Err(_) => return false,
                };
                let signature = match dilithium3::DetachedSignature::from_bytes(signature) {
                    Ok(signature) => signature,
                    Err(_) => return false,
                };
                dilithium3::verify_detached_signature(&signature, message, &public).is_ok()
            }
            DilithiumSecurityLevel::Level5 => {
                let public = match dilithium5::PublicKey::from_bytes(&self.dilithium) {
                    Ok(public) => public,
                    Err(_) => return false,
                };
                let signature = match dilithium5::DetachedSignature::from_bytes(signature) {
                    Ok(signature) => signature,
                    Err(_) => return false,
                };
                dilithium5::verify_detached_signature(&signature, message, &public).is_ok()
            }
        }
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
    fn test_sign_verify_supported_levels() {
        for level in [
            DilithiumSecurityLevel::Level2,
            DilithiumSecurityLevel::Level3,
            DilithiumSecurityLevel::Level5,
        ] {
            let keypair = HybridKeypair::generate_with_level(level);
            let public = keypair.public_key();
            let signature = keypair.sign(b"multi-level verification");

            assert_eq!(public.level, level);
            assert_eq!(public.dilithium.len(), level.public_key_size());
            assert_eq!(signature.dilithium.len(), level.signature_size());
            assert!(public.verify(b"multi-level verification", &signature));
        }
    }

    #[test]
    fn test_verify_rejects_tampered_message() {
        let keypair = HybridKeypair::generate();
        let public = keypair.public_key();
        let signature = keypair.sign(b"message one");

        assert!(!public.verify(b"message two", &signature));
    }

    #[test]
    fn test_verify_rejects_tampered_dilithium_signature() {
        let keypair = HybridKeypair::generate();
        let public = keypair.public_key();
        let mut signature = keypair.sign(b"tamper check");
        signature.dilithium[0] ^= 0x01;

        assert!(!public.verify(b"tamper check", &signature));
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
