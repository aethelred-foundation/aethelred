//! Kyber-libp2p Transport Integration
//!
//! Provides a Kyber768 key encapsulation mechanism (KEM) integrated with
//! libp2p's transport layer for post-quantum secure peer-to-peer connections.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │              libp2p Transport                     │
//! │  ┌─────────────┐    ┌────────────────────────┐  │
//! │  │  Noise/TLS   │───▶│ Kyber768 KEM Handshake │  │
//! │  │  Upgrade     │    │ (Post-Quantum)         │  │
//! │  └─────────────┘    └────────────────────────┘  │
//! │         │                      │                 │
//! │         ▼                      ▼                 │
//! │  ┌─────────────────────────────────────────┐    │
//! │  │      Hybrid Shared Secret Derivation     │    │
//! │  │  HKDF(X25519_SS || Kyber768_SS)          │    │
//! │  └─────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! # Security Properties
//!
//! - **Hybrid key exchange**: X25519 + Kyber768 combined via HKDF
//! - **Forward secrecy**: Ephemeral keys per session
//! - **Quantum resistance**: Even if X25519 is broken, Kyber768 protects
//! - **Wire format**: Compatible with existing libp2p multistream negotiation

use std::fmt;

use hkdf::Hkdf;
use pqcrypto_kyber::{kyber1024, kyber512, kyber768};
use pqcrypto_traits::kem::{
    Ciphertext as PQCiphertext, PublicKey as PQPublicKey, SecretKey as PQSecretKey,
    SharedSecret as PQSharedSecret,
};
use sha2::Sha256;

/// Kyber security levels supported by the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum KyberLevel {
    /// ML-KEM-512: 64-bit quantum security (low-bandwidth scenarios)
    Kyber512,
    /// ML-KEM-768: 128-bit quantum security (default, recommended)
    #[default]
    Kyber768,
    /// ML-KEM-1024: 192-bit quantum security (maximum security)
    Kyber1024,
}

impl fmt::Display for KyberLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KyberLevel::Kyber512 => write!(f, "ML-KEM-512"),
            KyberLevel::Kyber768 => write!(f, "ML-KEM-768"),
            KyberLevel::Kyber1024 => write!(f, "ML-KEM-1024"),
        }
    }
}

/// Key sizes for each Kyber level.
impl KyberLevel {
    pub fn public_key_size(&self) -> usize {
        match self {
            KyberLevel::Kyber512 => 800,
            KyberLevel::Kyber768 => 1184,
            KyberLevel::Kyber1024 => 1568,
        }
    }

    pub fn secret_key_size(&self) -> usize {
        match self {
            KyberLevel::Kyber512 => 1632,
            KyberLevel::Kyber768 => 2400,
            KyberLevel::Kyber1024 => 3168,
        }
    }

    pub fn ciphertext_size(&self) -> usize {
        match self {
            KyberLevel::Kyber512 => 768,
            KyberLevel::Kyber768 => 1088,
            KyberLevel::Kyber1024 => 1568,
        }
    }

    pub fn shared_secret_size(&self) -> usize {
        32 // 256 bits for all levels
    }
}

/// Errors that can occur during Kyber transport operations.
#[derive(Debug, thiserror::Error)]
pub enum KyberTransportError {
    #[error("Kyber key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Kyber encapsulation failed: {0}")]
    EncapsulationFailed(String),

    #[error("Kyber decapsulation failed: {0}")]
    DecapsulationFailed(String),

    #[error("Hybrid HKDF derivation failed: {0}")]
    HkdfDerivationFailed(String),

    #[error("Handshake protocol error: {0}")]
    HandshakeError(String),

    #[error("Invalid public key size: expected {expected}, got {got}")]
    InvalidPublicKeySize { expected: usize, got: usize },

    #[error("Invalid ciphertext size: expected {expected}, got {got}")]
    InvalidCiphertextSize { expected: usize, got: usize },

    #[error("Transport layer error: {0}")]
    TransportError(String),
}

/// Configuration for the Kyber transport layer.
#[derive(Debug, Clone)]
pub struct KyberTransportConfig {
    /// Kyber security level (default: Kyber768)
    pub level: KyberLevel,
    /// Maximum handshake timeout in milliseconds
    pub handshake_timeout_ms: u64,
    /// Whether to require Kyber in addition to classical key exchange
    pub require_pqc: bool,
    /// libp2p protocol ID for negotiation
    pub protocol_id: String,
}

impl Default for KyberTransportConfig {
    fn default() -> Self {
        Self {
            level: KyberLevel::Kyber768,
            handshake_timeout_ms: 30_000,
            require_pqc: true,
            protocol_id: "/aethelred/kyber/1.0.0".to_string(),
        }
    }
}

/// Kyber keypair for transport-layer key exchange.
#[derive(Clone)]
pub struct KyberTransportKeypair {
    pub public_key: Vec<u8>,
    secret_key: Vec<u8>,
    level: KyberLevel,
}

impl KyberTransportKeypair {
    /// Generate a new Kyber keypair at the specified security level.
    ///
    /// Uses `pqcrypto-kyber` for real CRYSTALS-Kyber key generation.
    pub fn generate(level: KyberLevel) -> Result<Self, KyberTransportError> {
        match level {
            KyberLevel::Kyber512 => {
                let (pk, sk) = kyber512::keypair();
                Ok(Self {
                    public_key: pk.as_bytes().to_vec(),
                    secret_key: sk.as_bytes().to_vec(),
                    level,
                })
            }
            KyberLevel::Kyber768 => {
                let (pk, sk) = kyber768::keypair();
                Ok(Self {
                    public_key: pk.as_bytes().to_vec(),
                    secret_key: sk.as_bytes().to_vec(),
                    level,
                })
            }
            KyberLevel::Kyber1024 => {
                let (pk, sk) = kyber1024::keypair();
                Ok(Self {
                    public_key: pk.as_bytes().to_vec(),
                    secret_key: sk.as_bytes().to_vec(),
                    level,
                })
            }
        }
    }

    /// Return the security level of this keypair.
    pub fn level(&self) -> KyberLevel {
        self.level
    }

    /// Return the public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

impl fmt::Debug for KyberTransportKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KyberTransportKeypair")
            .field("level", &self.level)
            .field("public_key_len", &self.public_key.len())
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for KyberTransportKeypair {
    fn drop(&mut self) {
        // RS-04 fix: Use zeroize crate instead of manual byte zeroing.
        // The compiler is permitted to optimize away manual dead stores,
        // but zeroize uses volatile writes that cannot be elided.
        use zeroize::Zeroize;
        self.secret_key.zeroize();
    }
}

/// Result of a Kyber encapsulation operation.
#[derive(Debug, Clone)]
pub struct KyberEncapsulation {
    /// Ciphertext to send to the peer
    pub ciphertext: Vec<u8>,
    /// Shared secret (kept locally)
    pub shared_secret: [u8; 32],
}

/// Result of the hybrid key derivation.
#[derive(Debug)]
pub struct HybridSharedSecret {
    /// Combined shared secret: HKDF(X25519_SS || Kyber_SS)
    pub derived_key: [u8; 32],
    /// Whether PQC was used (vs classical-only fallback)
    pub pqc_active: bool,
    /// Security level used
    pub level: KyberLevel,
}

/// Kyber-enhanced libp2p transport upgrade.
///
/// This is the main entry point for integrating Kyber KEM into
/// the libp2p connection handshake.
pub struct KyberTransportUpgrade {
    config: KyberTransportConfig,
    local_keypair: KyberTransportKeypair,
}

impl KyberTransportUpgrade {
    /// Create a new Kyber transport upgrade with default config.
    pub fn new() -> Result<Self, KyberTransportError> {
        Self::with_config(KyberTransportConfig::default())
    }

    /// Create with custom configuration.
    pub fn with_config(config: KyberTransportConfig) -> Result<Self, KyberTransportError> {
        let local_keypair = KyberTransportKeypair::generate(config.level)?;
        Ok(Self {
            config,
            local_keypair,
        })
    }

    /// Return the local public key for advertisement during handshake.
    pub fn local_public_key(&self) -> &[u8] {
        self.local_keypair.public_key()
    }

    /// Return the protocol ID for multistream negotiation.
    pub fn protocol_id(&self) -> &str {
        &self.config.protocol_id
    }

    /// Encapsulate a shared secret to a peer's public key.
    ///
    /// Called by the **initiator** during the handshake.
    /// Uses real CRYSTALS-Kyber KEM to produce a ciphertext and shared secret.
    pub fn encapsulate(
        &self,
        peer_public_key: &[u8],
    ) -> Result<KyberEncapsulation, KyberTransportError> {
        let expected_size = self.config.level.public_key_size();
        if peer_public_key.len() != expected_size {
            return Err(KyberTransportError::InvalidPublicKeySize {
                expected: expected_size,
                got: peer_public_key.len(),
            });
        }

        match self.config.level {
            KyberLevel::Kyber512 => {
                let pk = kyber512::PublicKey::from_bytes(peer_public_key).map_err(|_| {
                    KyberTransportError::EncapsulationFailed("Invalid Kyber512 public key".into())
                })?;
                let (ss, ct) = kyber512::encapsulate(&pk);
                let mut shared_secret = [0u8; 32];
                shared_secret.copy_from_slice(ss.as_bytes());
                Ok(KyberEncapsulation {
                    ciphertext: ct.as_bytes().to_vec(),
                    shared_secret,
                })
            }
            KyberLevel::Kyber768 => {
                let pk = kyber768::PublicKey::from_bytes(peer_public_key).map_err(|_| {
                    KyberTransportError::EncapsulationFailed("Invalid Kyber768 public key".into())
                })?;
                let (ss, ct) = kyber768::encapsulate(&pk);
                let mut shared_secret = [0u8; 32];
                shared_secret.copy_from_slice(ss.as_bytes());
                Ok(KyberEncapsulation {
                    ciphertext: ct.as_bytes().to_vec(),
                    shared_secret,
                })
            }
            KyberLevel::Kyber1024 => {
                let pk = kyber1024::PublicKey::from_bytes(peer_public_key).map_err(|_| {
                    KyberTransportError::EncapsulationFailed("Invalid Kyber1024 public key".into())
                })?;
                let (ss, ct) = kyber1024::encapsulate(&pk);
                let mut shared_secret = [0u8; 32];
                shared_secret.copy_from_slice(ss.as_bytes());
                Ok(KyberEncapsulation {
                    ciphertext: ct.as_bytes().to_vec(),
                    shared_secret,
                })
            }
        }
    }

    /// Decapsulate a ciphertext to recover the shared secret.
    ///
    /// Called by the **responder** during the handshake.
    /// Uses real CRYSTALS-Kyber decapsulation to recover the shared secret.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32], KyberTransportError> {
        let expected_size = self.config.level.ciphertext_size();
        if ciphertext.len() != expected_size {
            return Err(KyberTransportError::InvalidCiphertextSize {
                expected: expected_size,
                got: ciphertext.len(),
            });
        }

        let sk_bytes = &self.local_keypair.secret_key;

        match self.config.level {
            KyberLevel::Kyber512 => {
                let ct = kyber512::Ciphertext::from_bytes(ciphertext).map_err(|_| {
                    KyberTransportError::DecapsulationFailed("Invalid Kyber512 ciphertext".into())
                })?;
                let sk = kyber512::SecretKey::from_bytes(sk_bytes).map_err(|_| {
                    KyberTransportError::DecapsulationFailed("Invalid Kyber512 secret key".into())
                })?;
                let ss = kyber512::decapsulate(&ct, &sk);
                let mut shared_secret = [0u8; 32];
                shared_secret.copy_from_slice(ss.as_bytes());
                Ok(shared_secret)
            }
            KyberLevel::Kyber768 => {
                let ct = kyber768::Ciphertext::from_bytes(ciphertext).map_err(|_| {
                    KyberTransportError::DecapsulationFailed("Invalid Kyber768 ciphertext".into())
                })?;
                let sk = kyber768::SecretKey::from_bytes(sk_bytes).map_err(|_| {
                    KyberTransportError::DecapsulationFailed("Invalid Kyber768 secret key".into())
                })?;
                let ss = kyber768::decapsulate(&ct, &sk);
                let mut shared_secret = [0u8; 32];
                shared_secret.copy_from_slice(ss.as_bytes());
                Ok(shared_secret)
            }
            KyberLevel::Kyber1024 => {
                let ct = kyber1024::Ciphertext::from_bytes(ciphertext).map_err(|_| {
                    KyberTransportError::DecapsulationFailed("Invalid Kyber1024 ciphertext".into())
                })?;
                let sk = kyber1024::SecretKey::from_bytes(sk_bytes).map_err(|_| {
                    KyberTransportError::DecapsulationFailed("Invalid Kyber1024 secret key".into())
                })?;
                let ss = kyber1024::decapsulate(&ct, &sk);
                let mut shared_secret = [0u8; 32];
                shared_secret.copy_from_slice(ss.as_bytes());
                Ok(shared_secret)
            }
        }
    }

    /// Combine X25519 and Kyber shared secrets via HKDF.
    ///
    /// This is the core hybrid derivation:
    /// `derived_key = HKDF-SHA256(X25519_SS || Kyber_SS, info="aethelred-pqc-v1")`
    /// Combine X25519 and Kyber shared secrets via HKDF-SHA256.
    ///
    /// Uses the `hkdf` crate for standards-compliant key derivation:
    /// `derived_key = HKDF-SHA256(salt=None, ikm=X25519_SS || Kyber_SS, info="aethelred-pqc-v1")`
    pub fn derive_hybrid_secret(
        x25519_shared_secret: &[u8; 32],
        kyber_shared_secret: &[u8; 32],
        level: KyberLevel,
    ) -> Result<HybridSharedSecret, KyberTransportError> {
        // Concatenate both shared secrets as input keying material
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(x25519_shared_secret);
        ikm[32..].copy_from_slice(kyber_shared_secret);

        let info = b"aethelred-pqc-v1";

        // HKDF extract + expand with SHA-256
        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut derived_key = [0u8; 32];
        hk.expand(info, &mut derived_key)
            .map_err(|e| KyberTransportError::HkdfDerivationFailed(e.to_string()))?;

        Ok(HybridSharedSecret {
            derived_key,
            pqc_active: true,
            level,
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_level_key_sizes() {
        assert_eq!(KyberLevel::Kyber512.public_key_size(), 800);
        assert_eq!(KyberLevel::Kyber768.public_key_size(), 1184);
        assert_eq!(KyberLevel::Kyber1024.public_key_size(), 1568);

        assert_eq!(KyberLevel::Kyber768.ciphertext_size(), 1088);
        assert_eq!(KyberLevel::Kyber768.shared_secret_size(), 32);
    }

    #[test]
    fn test_default_level_is_768() {
        assert_eq!(KyberLevel::default(), KyberLevel::Kyber768);
    }

    #[test]
    fn test_keypair_generation() {
        let kp = KyberTransportKeypair::generate(KyberLevel::Kyber768).unwrap();
        assert_eq!(kp.public_key.len(), 1184);
        assert_eq!(kp.level(), KyberLevel::Kyber768);
    }

    #[test]
    fn test_keypair_debug_redacts_secret() {
        let kp = KyberTransportKeypair::generate(KyberLevel::Kyber768).unwrap();
        let debug_str = format!("{:?}", kp);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("secret_key: ["));
    }

    #[test]
    fn test_transport_upgrade_creation() {
        let upgrade = KyberTransportUpgrade::new().unwrap();
        assert_eq!(upgrade.protocol_id(), "/aethelred/kyber/1.0.0");
        assert_eq!(upgrade.local_public_key().len(), 1184);
    }

    #[test]
    fn test_encapsulate_rejects_wrong_key_size() {
        let upgrade = KyberTransportUpgrade::new().unwrap();
        let bad_key = vec![0u8; 100];
        let result = upgrade.encapsulate(&bad_key);
        assert!(result.is_err());
        match result.unwrap_err() {
            KyberTransportError::InvalidPublicKeySize { expected, got } => {
                assert_eq!(expected, 1184);
                assert_eq!(got, 100);
            }
            _ => panic!("Expected InvalidPublicKeySize error"),
        }
    }

    #[test]
    fn test_decapsulate_rejects_wrong_ciphertext_size() {
        let upgrade = KyberTransportUpgrade::new().unwrap();
        let bad_ct = vec![0u8; 100];
        let result = upgrade.decapsulate(&bad_ct);
        assert!(result.is_err());
        match result.unwrap_err() {
            KyberTransportError::InvalidCiphertextSize { expected, got } => {
                assert_eq!(expected, 1088);
                assert_eq!(got, 100);
            }
            _ => panic!("Expected InvalidCiphertextSize error"),
        }
    }

    #[test]
    fn test_encapsulate_produces_correct_sizes() {
        let initiator = KyberTransportUpgrade::new().unwrap();
        let responder = KyberTransportUpgrade::new().unwrap();

        let encap = initiator.encapsulate(responder.local_public_key()).unwrap();
        assert_eq!(encap.ciphertext.len(), 1088);
        assert_eq!(encap.shared_secret.len(), 32);
    }

    #[test]
    fn test_encapsulate_decapsulate_roundtrip() {
        let initiator = KyberTransportUpgrade::new().unwrap();
        let responder = KyberTransportUpgrade::new().unwrap();

        // Initiator encapsulates to responder's public key
        let encap = initiator.encapsulate(responder.local_public_key()).unwrap();

        // Responder decapsulates with their secret key
        let decap_secret = responder.decapsulate(&encap.ciphertext).unwrap();

        // Both sides must derive the same shared secret
        assert_eq!(
            encap.shared_secret, decap_secret,
            "encapsulate/decapsulate roundtrip must produce identical shared secrets"
        );
    }

    #[test]
    fn test_hybrid_derivation() {
        let x25519_ss = [42u8; 32];
        let kyber_ss = [99u8; 32];

        let hybrid = KyberTransportUpgrade::derive_hybrid_secret(
            &x25519_ss,
            &kyber_ss,
            KyberLevel::Kyber768,
        )
        .unwrap();

        assert_eq!(hybrid.derived_key.len(), 32);
        assert!(hybrid.pqc_active);
        assert_eq!(hybrid.level, KyberLevel::Kyber768);

        // Verify deterministic: same inputs → same output
        let hybrid2 = KyberTransportUpgrade::derive_hybrid_secret(
            &x25519_ss,
            &kyber_ss,
            KyberLevel::Kyber768,
        )
        .unwrap();
        assert_eq!(hybrid.derived_key, hybrid2.derived_key);
    }

    #[test]
    fn test_different_inputs_different_secrets() {
        let x1 = [1u8; 32];
        let x2 = [2u8; 32];
        let k = [99u8; 32];

        let h1 =
            KyberTransportUpgrade::derive_hybrid_secret(&x1, &k, KyberLevel::Kyber768).unwrap();
        let h2 =
            KyberTransportUpgrade::derive_hybrid_secret(&x2, &k, KyberLevel::Kyber768).unwrap();
        assert_ne!(h1.derived_key, h2.derived_key);
    }

    #[test]
    fn test_config_defaults() {
        let config = KyberTransportConfig::default();
        assert_eq!(config.level, KyberLevel::Kyber768);
        assert_eq!(config.handshake_timeout_ms, 30_000);
        assert!(config.require_pqc);
        assert_eq!(config.protocol_id, "/aethelred/kyber/1.0.0");
    }

    #[test]
    fn test_level_display() {
        assert_eq!(format!("{}", KyberLevel::Kyber512), "ML-KEM-512");
        assert_eq!(format!("{}", KyberLevel::Kyber768), "ML-KEM-768");
        assert_eq!(format!("{}", KyberLevel::Kyber1024), "ML-KEM-1024");
    }

    #[test]
    fn test_all_levels_generate_correct_sizes() {
        for level in [
            KyberLevel::Kyber512,
            KyberLevel::Kyber768,
            KyberLevel::Kyber1024,
        ] {
            let kp = KyberTransportKeypair::generate(level).unwrap();
            assert_eq!(kp.public_key.len(), level.public_key_size());
        }
    }
}
