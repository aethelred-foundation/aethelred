#![cfg(feature = "hsm")]
//! Hardware Security Module (HSM) Integration for Aethelred
//!
//! This module provides PKCS#11 HSM support for validator block signing.
//! Supports Thales Luna HSM, AWS CloudHSM, and YubiHSM.
//!
//! # Security Guarantee
//!
//! **Private keys NEVER leave the HSM hardware boundary.**
//! All cryptographic operations are performed inside the HSM.
//!
//! # Supported HSMs
//!
//! | HSM | FIPS Level | Certification |
//! |-----|------------|---------------|
//! | AWS CloudHSM | FIPS 140-2 Level 3 | PCI-DSS, SOC2 |
//! | Thales Luna | FIPS 140-2 Level 3 | Common Criteria EAL4+ |
//! | YubiHSM 2 | FIPS 140-2 Level 3 | For Development |
//!
//! # Usage
//!
//! ```rust,ignore
//! use aethelred_core::crypto::signer::HsmSigner;
//!
//! // Connect to HSM
//! let signer = HsmSigner::connect(
//!     "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
//!     "crypto_user:password",
//!     "aethelred-validator-key"
//! )?;
//!
//! // Sign block hash (key never leaves HSM)
//! let signature = signer.sign(&block_hash)?;
//! ```

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

// Re-export for convenience
pub use cryptoki;

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

/// HSM-related errors
#[derive(Error, Debug)]
pub enum HsmError {
    #[error("Failed to load PKCS#11 module: {0}")]
    ModuleLoadFailed(String),

    #[error("HSM initialization failed: {0}")]
    InitializationFailed(String),

    #[error("No slots with tokens found")]
    NoSlotsFound,

    #[error("Session open failed: {0}")]
    SessionOpenFailed(String),

    #[error("Login failed: {0}")]
    LoginFailed(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Signing operation failed: {0}")]
    SigningFailed(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("HSM connection lost")]
    ConnectionLost,

    #[error("Invalid PIN format")]
    InvalidPin,

    #[error("Session timeout")]
    SessionTimeout,

    #[error("HSM is in read-only mode")]
    ReadOnlyMode,

    #[error("Key already exists: {0}")]
    KeyAlreadyExists(String),

    #[error("Unsupported mechanism: {0}")]
    UnsupportedMechanism(String),
}

/// Result type for HSM operations
pub type HsmResult<T> = Result<T, HsmError>;

/// Supported HSM types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmType {
    /// AWS CloudHSM
    AwsCloudHsm,
    /// Thales Luna HSM
    ThalesLuna,
    /// Yubico YubiHSM 2
    YubiHsm,
    /// SoftHSM (for development only)
    SoftHsm,
}

impl HsmType {
    /// Get the default PKCS#11 module path for this HSM type
    pub fn default_module_path(&self) -> &'static str {
        match self {
            HsmType::AwsCloudHsm => "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
            HsmType::ThalesLuna => "/usr/safenet/lunaclient/lib/libCryptoki2_64.so",
            HsmType::YubiHsm => "/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so",
            HsmType::SoftHsm => "/usr/lib/softhsm/libsofthsm2.so",
        }
    }

    /// Detect HSM type from module path
    pub fn from_module_path(path: &str) -> Option<Self> {
        if path.contains("cloudhsm") {
            Some(HsmType::AwsCloudHsm)
        } else if path.contains("luna") || path.contains("safenet") {
            Some(HsmType::ThalesLuna)
        } else if path.contains("yubihsm") {
            Some(HsmType::YubiHsm)
        } else if path.contains("softhsm") {
            Some(HsmType::SoftHsm)
        } else {
            None
        }
    }
}

/// Supported signing algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// ECDSA with P-256 curve (secp256r1)
    EcdsaP256,
    /// ECDSA with P-384 curve (secp384r1)
    EcdsaP384,
    /// ECDSA with secp256k1 curve (Bitcoin/Ethereum)
    EcdsaSecp256k1,
    /// Ed25519
    Ed25519,
    /// RSA 2048-bit
    Rsa2048,
    /// RSA 4096-bit
    Rsa4096,
}

impl SigningAlgorithm {
    /// Get the PKCS#11 mechanism for this algorithm
    fn mechanism(&self) -> Mechanism {
        match self {
            SigningAlgorithm::EcdsaP256 => Mechanism::Ecdsa,
            SigningAlgorithm::EcdsaP384 => Mechanism::Ecdsa,
            SigningAlgorithm::EcdsaSecp256k1 => Mechanism::Ecdsa,
            SigningAlgorithm::Ed25519 => Mechanism::Eddsa,
            SigningAlgorithm::Rsa2048 => Mechanism::RsaPkcs,
            SigningAlgorithm::Rsa4096 => Mechanism::RsaPkcs,
        }
    }

    /// Get the expected signature size
    pub fn signature_size(&self) -> usize {
        match self {
            SigningAlgorithm::EcdsaP256 => 64,
            SigningAlgorithm::EcdsaP384 => 96,
            SigningAlgorithm::EcdsaSecp256k1 => 64,
            SigningAlgorithm::Ed25519 => 64,
            SigningAlgorithm::Rsa2048 => 256,
            SigningAlgorithm::Rsa4096 => 512,
        }
    }
}

/// HSM Signer Configuration
#[derive(Debug, Clone)]
pub struct HsmConfig {
    /// Path to the PKCS#11 module (.so file)
    pub module_path: String,
    /// HSM PIN (format: "user:password" or just "password")
    pub pin: String,
    /// Key label to use for signing
    pub key_label: String,
    /// Slot ID (None = auto-detect first slot with token)
    pub slot_id: Option<u64>,
    /// Signing algorithm
    pub algorithm: SigningAlgorithm,
    /// Session timeout
    pub session_timeout: Duration,
    /// Enable automatic reconnection
    pub auto_reconnect: bool,
    /// Maximum reconnection attempts
    pub max_reconnect_attempts: u32,
}

impl Default for HsmConfig {
    fn default() -> Self {
        Self {
            module_path: HsmType::SoftHsm.default_module_path().to_string(),
            pin: String::new(),
            key_label: "aethelred-validator-key".to_string(),
            slot_id: None,
            algorithm: SigningAlgorithm::EcdsaP256,
            session_timeout: Duration::from_secs(300), // 5 minutes
            auto_reconnect: true,
            max_reconnect_attempts: 3,
        }
    }
}

/// HSM Session State
struct HsmSession {
    pkcs11: Pkcs11,
    session: Session,
    key_handle: ObjectHandle,
    last_activity: Instant,
    algorithm: SigningAlgorithm,
}

/// Hardware Security Module Signer
///
/// Provides cryptographic signing operations using a PKCS#11-compliant HSM.
/// The private key NEVER leaves the HSM hardware boundary.
pub struct HsmSigner {
    config: HsmConfig,
    session: Arc<Mutex<Option<HsmSession>>>,
    hsm_type: Option<HsmType>,
    // Metrics
    sign_count: Arc<Mutex<u64>>,
    sign_errors: Arc<Mutex<u64>>,
}

impl HsmSigner {
    /// Connect to an HSM and locate the signing key
    ///
    /// # Arguments
    ///
    /// * `module_path` - Path to the PKCS#11 shared library
    /// * `pin` - HSM PIN (format depends on HSM type)
    /// * `key_label` - Label of the key to use for signing
    ///
    /// # Security
    ///
    /// The private key is stored inside the HSM and never leaves it.
    /// Only signatures are returned to the caller.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let signer = HsmSigner::connect(
    ///     "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
    ///     "crypto_user:mypassword",
    ///     "validator-signing-key"
    /// )?;
    /// ```
    pub fn connect(module_path: &str, pin: &str, key_label: &str) -> HsmResult<Self> {
        let config = HsmConfig {
            module_path: module_path.to_string(),
            pin: pin.to_string(),
            key_label: key_label.to_string(),
            ..Default::default()
        };
        Self::connect_with_config(config)
    }

    /// Connect to HSM with full configuration
    pub fn connect_with_config(config: HsmConfig) -> HsmResult<Self> {
        let hsm_type = HsmType::from_module_path(&config.module_path);

        // Load PKCS#11 module
        let pkcs11 = Pkcs11::new(&config.module_path)
            .map_err(|e| HsmError::ModuleLoadFailed(e.to_string()))?;

        // Initialize the library
        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .map_err(|e| HsmError::InitializationFailed(e.to_string()))?;

        // Find slot with token
        let slots = pkcs11
            .get_slots_with_token()
            .map_err(|e| HsmError::InitializationFailed(e.to_string()))?;

        if slots.is_empty() {
            return Err(HsmError::NoSlotsFound);
        }

        let slot = if let Some(slot_id) = config.slot_id {
            Slot::try_from(slot_id)
                .map_err(|e| HsmError::InitializationFailed(format!("invalid slot id: {e}")))?
        } else {
            slots[0]
        };

        // Open session
        let session = pkcs11
            .open_ro_session(slot)
            .map_err(|e| HsmError::SessionOpenFailed(e.to_string()))?;

        // Login
        let auth_pin = AuthPin::new(config.pin.clone());
        session
            .login(UserType::User, Some(&auth_pin))
            .map_err(|e| HsmError::LoginFailed(e.to_string()))?;

        // Find the key
        let key_handle = Self::find_key(&session, &config.key_label)?;

        let hsm_session = HsmSession {
            pkcs11,
            session,
            key_handle,
            last_activity: Instant::now(),
            algorithm: config.algorithm,
        };

        Ok(Self {
            config,
            session: Arc::new(Mutex::new(Some(hsm_session))),
            hsm_type,
            sign_count: Arc::new(Mutex::new(0)),
            sign_errors: Arc::new(Mutex::new(0)),
        })
    }

    /// Find a key by label
    fn find_key(session: &Session, label: &str) -> HsmResult<ObjectHandle> {
        let attributes = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(label.as_bytes().to_vec()),
        ];

        let keys = session
            .find_objects(&attributes)
            .map_err(|e| HsmError::KeyNotFound(e.to_string()))?;

        if keys.is_empty() {
            return Err(HsmError::KeyNotFound(format!(
                "Key with label '{}' not found",
                label
            )));
        }

        Ok(keys[0])
    }

    /// Sign data using the HSM
    ///
    /// **CRITICAL SECURITY**: The private key never leaves the HSM.
    /// Only the signature is returned.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to sign (typically a block hash)
    ///
    /// # Returns
    ///
    /// The signature bytes
    pub fn sign(&self, data: &[u8]) -> HsmResult<Vec<u8>> {
        let mut session_guard = self.session.lock().unwrap();
        let hsm_session = session_guard.as_mut().ok_or(HsmError::ConnectionLost)?;

        // Update last activity time
        hsm_session.last_activity = Instant::now();

        // Perform the signing operation inside the HSM
        let mechanism = hsm_session.algorithm.mechanism();
        let signature = hsm_session
            .session
            .sign(&mechanism, hsm_session.key_handle, data)
            .map_err(|e| {
                let mut errors = self.sign_errors.lock().unwrap();
                *errors += 1;
                HsmError::SigningFailed(e.to_string())
            })?;

        // Update metrics
        let mut count = self.sign_count.lock().unwrap();
        *count += 1;

        Ok(signature)
    }

    /// Sign with automatic reconnection on failure
    pub fn sign_with_retry(&self, data: &[u8]) -> HsmResult<Vec<u8>> {
        let mut attempts = 0;
        loop {
            match self.sign(data) {
                Ok(sig) => return Ok(sig),
                Err(e) => {
                    attempts += 1;
                    if !self.config.auto_reconnect || attempts >= self.config.max_reconnect_attempts
                    {
                        return Err(e);
                    }
                    // Try to reconnect
                    if self.reconnect().is_err() {
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Reconnect to the HSM
    fn reconnect(&self) -> HsmResult<()> {
        let mut session_guard = self.session.lock().unwrap();

        // Drop old session
        *session_guard = None;

        // Create new connection
        let pkcs11 = Pkcs11::new(&self.config.module_path)
            .map_err(|e| HsmError::ModuleLoadFailed(e.to_string()))?;

        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .map_err(|e| HsmError::InitializationFailed(e.to_string()))?;

        let slots = pkcs11
            .get_slots_with_token()
            .map_err(|e| HsmError::InitializationFailed(e.to_string()))?;

        if slots.is_empty() {
            return Err(HsmError::NoSlotsFound);
        }

        let slot = if let Some(slot_id) = self.config.slot_id {
            Slot::try_from(slot_id)
                .map_err(|e| HsmError::InitializationFailed(format!("invalid slot id: {e}")))?
        } else {
            slots[0]
        };

        let session = pkcs11
            .open_ro_session(slot)
            .map_err(|e| HsmError::SessionOpenFailed(e.to_string()))?;

        let auth_pin = AuthPin::new(self.config.pin.clone());
        session
            .login(UserType::User, Some(&auth_pin))
            .map_err(|e| HsmError::LoginFailed(e.to_string()))?;

        let key_handle = Self::find_key(&session, &self.config.key_label)?;

        *session_guard = Some(HsmSession {
            pkcs11,
            session,
            key_handle,
            last_activity: Instant::now(),
            algorithm: self.config.algorithm,
        });

        Ok(())
    }

    /// Get the public key from the HSM
    pub fn get_public_key(&self) -> HsmResult<Vec<u8>> {
        let session_guard = self.session.lock().unwrap();
        let hsm_session = session_guard.as_ref().ok_or(HsmError::ConnectionLost)?;

        // Find the corresponding public key
        let attributes = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(self.config.key_label.as_bytes().to_vec()),
        ];

        let keys = hsm_session
            .session
            .find_objects(&attributes)
            .map_err(|e| HsmError::KeyNotFound(e.to_string()))?;

        if keys.is_empty() {
            return Err(HsmError::KeyNotFound("Public key not found".to_string()));
        }

        // Get the EC point (public key value)
        let attrs = hsm_session
            .session
            .get_attributes(keys[0], &[AttributeType::EcPoint])
            .map_err(|e| HsmError::KeyNotFound(e.to_string()))?;

        for attr in attrs {
            if let Attribute::EcPoint(point) = attr {
                return Ok(point);
            }
        }

        Err(HsmError::KeyNotFound(
            "Could not extract public key".to_string(),
        ))
    }

    /// Generate a new key pair inside the HSM
    ///
    /// **CRITICAL**: The private key is generated and stored inside the HSM.
    /// It is marked as non-extractable.
    pub fn generate_key_pair(
        session: &Session,
        label: &str,
        algorithm: SigningAlgorithm,
    ) -> HsmResult<(ObjectHandle, ObjectHandle)> {
        let curve_oid = match algorithm {
            SigningAlgorithm::EcdsaP256 => {
                // P-256 OID: 1.2.840.10045.3.1.7
                vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
            }
            SigningAlgorithm::EcdsaP384 => {
                // P-384 OID: 1.3.132.0.34
                vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]
            }
            SigningAlgorithm::EcdsaSecp256k1 => {
                // secp256k1 OID: 1.3.132.0.10
                vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a]
            }
            _ => {
                return Err(HsmError::UnsupportedMechanism(format!(
                    "Key generation not supported for {:?}",
                    algorithm
                )));
            }
        };

        let pub_key_template = vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::EcParams(curve_oid.clone()),
            Attribute::Verify(true),
        ];

        let priv_key_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Sensitive(true),
            Attribute::Extractable(false), // CRITICAL: Key cannot be exported
            Attribute::Sign(true),
        ];

        let (pub_handle, priv_handle) = session
            .generate_key_pair(
                &Mechanism::EccKeyPairGen,
                &pub_key_template,
                &priv_key_template,
            )
            .map_err(|e| HsmError::KeyGenerationFailed(e.to_string()))?;

        Ok((pub_handle, priv_handle))
    }

    /// Check if the HSM session is still valid
    pub fn is_connected(&self) -> bool {
        let session_guard = self.session.lock().unwrap();
        session_guard.is_some()
    }

    /// Get the HSM type
    pub fn hsm_type(&self) -> Option<HsmType> {
        self.hsm_type
    }

    /// Get signing metrics
    pub fn metrics(&self) -> (u64, u64) {
        let count = *self.sign_count.lock().unwrap();
        let errors = *self.sign_errors.lock().unwrap();
        (count, errors)
    }

    /// Close the HSM session
    pub fn close(&self) -> HsmResult<()> {
        let mut session_guard = self.session.lock().unwrap();
        if let Some(hsm_session) = session_guard.take() {
            hsm_session
                .session
                .logout()
                .map_err(|e| HsmError::SessionOpenFailed(e.to_string()))?;
        }
        Ok(())
    }
}

impl Drop for HsmSigner {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// HSM Signer for Validators
///
/// High-level wrapper for validator block signing operations.
pub struct ValidatorHsmSigner {
    primary: HsmSigner,
    backup: Option<HsmSigner>,
    use_backup: Arc<Mutex<bool>>,
}

impl ValidatorHsmSigner {
    /// Create a new validator signer with optional backup HSM
    pub fn new(primary: HsmSigner, backup: Option<HsmSigner>) -> Self {
        Self {
            primary,
            backup,
            use_backup: Arc::new(Mutex::new(false)),
        }
    }

    /// Sign a block hash
    ///
    /// Automatically fails over to backup HSM if primary is unavailable.
    pub fn sign_block(&self, block_hash: &[u8; 32]) -> HsmResult<Vec<u8>> {
        let use_backup = *self.use_backup.lock().unwrap();

        if use_backup {
            if let Some(ref backup) = self.backup {
                return backup.sign(block_hash);
            }
        }

        match self.primary.sign(block_hash) {
            Ok(sig) => Ok(sig),
            Err(e) => {
                // Try backup
                if let Some(ref backup) = self.backup {
                    let mut use_backup = self.use_backup.lock().unwrap();
                    *use_backup = true;
                    backup.sign(block_hash)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Sign a vote extension
    pub fn sign_vote_extension(&self, data: &[u8]) -> HsmResult<Vec<u8>> {
        // Add domain separation for vote extensions
        let mut prefixed = Vec::with_capacity(data.len() + 16);
        prefixed.extend_from_slice(b"AETHELRED_VOTE:");
        prefixed.extend_from_slice(data);
        self.sign_block(&sha256_hash(&prefixed))
    }

    /// Check HSM health
    pub fn health_check(&self) -> (bool, Option<bool>) {
        let primary_ok = self.primary.is_connected();
        let backup_ok = self.backup.as_ref().map(|b| b.is_connected());
        (primary_ok, backup_ok)
    }
}

/// SHA-256 hash helper
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hsm_type_detection() {
        assert_eq!(
            HsmType::from_module_path("/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"),
            Some(HsmType::AwsCloudHsm)
        );
        assert_eq!(
            HsmType::from_module_path("/usr/safenet/lunaclient/lib/libCryptoki2_64.so"),
            Some(HsmType::ThalesLuna)
        );
        assert_eq!(
            HsmType::from_module_path("/usr/lib/softhsm/libsofthsm2.so"),
            Some(HsmType::SoftHsm)
        );
    }

    #[test]
    fn test_signature_sizes() {
        assert_eq!(SigningAlgorithm::EcdsaP256.signature_size(), 64);
        assert_eq!(SigningAlgorithm::EcdsaP384.signature_size(), 96);
        assert_eq!(SigningAlgorithm::Rsa2048.signature_size(), 256);
    }

    #[test]
    fn test_default_config() {
        let config = HsmConfig::default();
        assert_eq!(config.key_label, "aethelred-validator-key");
        assert!(config.auto_reconnect);
        assert_eq!(config.max_reconnect_attempts, 3);
    }
}
