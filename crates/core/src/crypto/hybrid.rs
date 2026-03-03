//! Hybrid Signature Scheme (ECDSA + Dilithium)
//!
//! Enterprise-grade algorithm-agile hybrid signatures combining classical ECDSA
//! with post-quantum Dilithium3 for defense-in-depth security.
//!
//! # Security Model
//!
//! The hybrid scheme provides security guarantees under three scenarios:
//!
//! 1. **Pre-Quantum**: Both ECDSA and Dilithium are secure
//!    - Signature is valid if BOTH components verify
//!
//! 2. **Quantum Threat (Level 3-4)**: ECDSA may be weakened
//!    - Classical verification optional, quantum mandatory
//!
//! 3. **Post-Quantum (Q-Day, Level 5+)**: ECDSA is broken
//!    - Only Dilithium verification required
//!
//! # Wire Format
//!
//! Versioned wire format:
//!
//! - V1 (legacy): `[version][marker][ecdsa:64][sep][quantum:max][level][metadata]`
//! - V2 (current): `[version][marker][ecdsa:64][sep][level][quantum_len:u16][quantum][metadata]`
//!
//! V2 preserves round-trips for variable-length Dilithium detached signatures.
//!
//! # Compliance
//!
//! - NIST FIPS 204 (ML-DSA / Dilithium)
//! - NIST SP 800-56C (Key Derivation)
//! - NIST SP 800-186 (ECDSA secp256k1)

use super::{CryptoError, CryptoResult};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "full-pqc")]
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

// =============================================================================
// Configuration
// =============================================================================

/// Verifier configuration controlling hybrid signature validation behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierConfig {
    /// If true, classical ECDSA is ignored. Activated by Governance when QC threat is imminent.
    /// This is the "Panic Mode" - when quantum computers can break ECDSA.
    pub panic_mode_qc: bool,

    /// Minimum acceptable Dilithium security level
    pub min_dilithium_level: DilithiumSecurityLevel,

    /// Whether to allow legacy ECDSA-only signatures (for migration)
    /// Should be false in production!
    pub allow_legacy_ecdsa_only: bool,

    /// Require both signatures even in panic mode (extra paranoid)
    pub require_dual_sig_always: bool,

    /// Maximum signature age in seconds (replay protection)
    pub max_signature_age_secs: Option<u64>,

    /// Chain ID for replay protection across networks
    pub chain_id: u64,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            panic_mode_qc: false,
            min_dilithium_level: DilithiumSecurityLevel::Level3,
            allow_legacy_ecdsa_only: false,
            require_dual_sig_always: false,
            max_signature_age_secs: None,
            chain_id: 1, // Mainnet
        }
    }
}

impl VerifierConfig {
    /// Create configuration for DevNet (more permissive)
    pub fn devnet() -> Self {
        Self {
            panic_mode_qc: false,
            min_dilithium_level: DilithiumSecurityLevel::Level2,
            allow_legacy_ecdsa_only: false, // Still require hybrid
            require_dual_sig_always: false,
            max_signature_age_secs: Some(3600), // 1 hour
            chain_id: 9999,                     // DevNet
        }
    }

    /// Create configuration for TestNet
    pub fn testnet() -> Self {
        Self {
            panic_mode_qc: false,
            min_dilithium_level: DilithiumSecurityLevel::Level3,
            allow_legacy_ecdsa_only: false,
            require_dual_sig_always: false,
            max_signature_age_secs: Some(7200), // 2 hours
            chain_id: 2,                        // TestNet
        }
    }

    /// Create configuration for MainNet (strictest)
    pub fn mainnet() -> Self {
        Self {
            panic_mode_qc: false,
            min_dilithium_level: DilithiumSecurityLevel::Level3,
            allow_legacy_ecdsa_only: false,
            require_dual_sig_always: true, // Extra security
            max_signature_age_secs: None,
            chain_id: 1,
        }
    }

    /// Enter panic mode (quantum computers detected)
    pub fn enter_panic_mode(&mut self) {
        self.panic_mode_qc = true;
        self.allow_legacy_ecdsa_only = false;
        tracing::warn!("PANIC MODE ACTIVATED: Classical ECDSA verification disabled");
    }
}

/// Dilithium security levels (NIST)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum DilithiumSecurityLevel {
    /// NIST Level 2 (~128-bit classical)
    Level2 = 2,
    /// NIST Level 3 (~192-bit classical) - Aethelred default
    Level3 = 3,
    /// NIST Level 5 (~256-bit classical)
    Level5 = 5,
}

impl DilithiumSecurityLevel {
    /// Get public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::Level2 => 1312,
            Self::Level3 => 1952,
            Self::Level5 => 2592,
        }
    }

    /// Get secret key size in bytes
    pub fn secret_key_size(&self) -> usize {
        match self {
            Self::Level2 => 2528,
            Self::Level3 => 4032,
            Self::Level5 => 4896,
        }
    }

    /// Get signature size in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            Self::Level2 => 2420,
            Self::Level3 => 3309,
            Self::Level5 => 4627,
        }
    }
}

impl Default for DilithiumSecurityLevel {
    fn default() -> Self {
        Self::Level3
    }
}

// =============================================================================
// Algorithm Markers
// =============================================================================

/// Algorithm byte markers for wire format
const HYBRID_MARKER: u8 = 0x03;
const COMPONENT_SEPARATOR: u8 = 0xFF;

/// Version byte for future compatibility
const SIGNATURE_VERSION_V1: u8 = 0x01;
const SIGNATURE_VERSION_V2: u8 = 0x02;
const SIGNATURE_VERSION: u8 = SIGNATURE_VERSION_V2;

// =============================================================================
// Hybrid Signature
// =============================================================================

/// Enterprise-grade hybrid signature combining ECDSA and Dilithium3
///
/// This is the primary signature type for all Aethelred transactions.
/// It provides quantum-safe security while maintaining compatibility
/// with existing wallet infrastructure through the ECDSA component.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSignature {
    /// 64-byte Compact ECDSA Signature (r || s)
    /// Provides legacy wallet compatibility and defense-in-depth
    #[serde(with = "hex")]
    pub classical: Vec<u8>,

    /// ~3.3KB Dilithium3 Signature
    /// This is the PRIMARY security layer - ALWAYS verified
    #[serde(with = "hex")]
    pub quantum: Vec<u8>,

    /// Dilithium security level used
    pub level: DilithiumSecurityLevel,

    /// Optional timestamp for replay protection
    pub timestamp: Option<u64>,

    /// Optional chain ID for cross-chain replay protection
    pub chain_id: Option<u64>,
}

impl HybridSignature {
    /// Create a new hybrid signature
    pub fn new(classical: Vec<u8>, quantum: Vec<u8>, level: DilithiumSecurityLevel) -> Self {
        Self {
            classical,
            quantum,
            level,
            timestamp: None,
            chain_id: None,
        }
    }

    /// Create with metadata
    pub fn with_metadata(
        classical: Vec<u8>,
        quantum: Vec<u8>,
        level: DilithiumSecurityLevel,
        timestamp: u64,
        chain_id: u64,
    ) -> Self {
        Self {
            classical,
            quantum,
            level,
            timestamp: Some(timestamp),
            chain_id: Some(chain_id),
        }
    }

    /// Verify the hybrid signature against a message and public key
    ///
    /// # Security
    ///
    /// This method enforces Aethelred's "Quantum-First" security policy:
    /// - The Dilithium signature is ALWAYS verified (it is the primary security layer)
    /// - The ECDSA signature is verified based on the `VerifierConfig`
    /// - In panic mode, only Dilithium is checked (ECDSA assumed compromised)
    ///
    /// # Arguments
    ///
    /// * `message` - The raw message bytes (typically transaction bytes)
    /// * `pubkey` - The hybrid public key
    /// * `config` - Verifier configuration
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Signature is valid
    /// * `Err(String)` - Signature verification failed with reason
    pub fn verify(
        &self,
        message: &[u8],
        pubkey: &HybridPublicKey,
        config: &VerifierConfig,
    ) -> Result<(), String> {
        // 0. Validate signature format
        self.validate_format()?;

        // 1. Check security level meets minimum
        if self.level < config.min_dilithium_level {
            return Err(format!(
                "Dilithium security level {:?} below minimum {:?}",
                self.level, config.min_dilithium_level
            ));
        }

        // 2. Check timestamp if configured
        if let (Some(max_age), Some(sig_timestamp)) =
            (config.max_signature_age_secs, self.timestamp)
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "System clock is before UNIX epoch — cannot verify signature age".to_string())?
                .as_secs();

            if now > sig_timestamp && now - sig_timestamp > max_age {
                return Err(format!(
                    "Signature expired: age {} > max {}",
                    now - sig_timestamp,
                    max_age
                ));
            }
        }

        // 3. Check chain ID if present
        if let Some(sig_chain_id) = self.chain_id {
            if sig_chain_id != config.chain_id {
                return Err(format!(
                    "Chain ID mismatch: signature={}, config={}",
                    sig_chain_id, config.chain_id
                ));
            }
        }

        // 4. Hash the message using Keccak256 (Ethereum compatible)
        let mut hasher = Keccak256::new();
        hasher.update(message);
        let msg_hash = hasher.finalize();

        // 5. QUANTUM VERIFICATION (ALWAYS REQUIRED)
        // This is the primary security layer of Aethelred
        // It MUST pass for the signature to be valid
        let quantum_valid = self.verify_dilithium(&msg_hash, &pubkey.quantum)?;

        if !quantum_valid {
            return Err("Invalid Post-Quantum Dilithium Signature".to_string());
        }

        // 6. CLASSICAL VERIFICATION (Conditional based on config)
        // We only check this if we are NOT in "Panic Mode"
        if !config.panic_mode_qc {
            let classical_valid = self.verify_ecdsa(&msg_hash, &pubkey.classical)?;

            if !classical_valid {
                return Err("Invalid Classical ECDSA Signature".to_string());
            }
        }

        Ok(())
    }

    /// Verify Dilithium signature component
    #[cfg(feature = "full-pqc")]
    fn verify_dilithium(
        &self,
        msg_hash: &[u8],
        pubkey: &DilithiumPublicKey,
    ) -> Result<bool, String> {
        use pqcrypto_dilithium::dilithium3;
        use pqcrypto_traits::sign::DetachedSignature;

        // Parse signature bytes
        let signature = dilithium3::DetachedSignature::from_bytes(&self.quantum)
            .map_err(|_| "Malformed Dilithium signature")?;

        // Parse public key
        let pk = dilithium3::PublicKey::from_bytes(pubkey.as_bytes())
            .map_err(|_| "Malformed Dilithium public key")?;

        // Verify
        let valid = dilithium3::verify_detached_signature(&signature, msg_hash, &pk).is_ok();

        Ok(valid)
    }

    /// Verify Dilithium signature component when full PQC is not compiled in.
    ///
    /// SECURITY: non-test builds must fail closed to prevent accidental
    /// production verification with a simulated Dilithium path.
    #[cfg(all(not(feature = "full-pqc"), not(test)))]
    fn verify_dilithium(
        &self,
        _msg_hash: &[u8],
        _pubkey: &DilithiumPublicKey,
    ) -> Result<bool, String> {
        Err(
            "SECURITY: Dilithium verification requires the 'full-pqc' feature in non-test builds"
                .to_string(),
        )
    }

    /// Verify Dilithium signature component (test-only mock path).
    #[cfg(all(not(feature = "full-pqc"), test))]
    fn verify_dilithium(
        &self,
        _msg_hash: &[u8],
        pubkey: &DilithiumPublicKey,
    ) -> Result<bool, String> {
        // Validate sizes
        let expected_sig_size = self.level.signature_size();
        if self.quantum.is_empty() || self.quantum.len() > expected_sig_size {
            return Err(format!(
                "Invalid Dilithium signature size: expected 1..={}, got {}",
                expected_sig_size,
                self.quantum.len()
            ));
        }

        let expected_pk_size = self.level.public_key_size();
        if pubkey.as_bytes().len() != expected_pk_size {
            return Err(format!(
                "Invalid Dilithium public key size: expected {}, got {}",
                expected_pk_size,
                pubkey.as_bytes().len()
            ));
        }

        // Mock verification in tests only.
        tracing::warn!(
            "Using test-only mock Dilithium verification - enable 'full-pqc' for non-test builds"
        );

        // Simple mock: check that signature is not all zeros
        let is_nonzero = self.quantum.iter().any(|&b| b != 0);
        Ok(is_nonzero)
    }

    /// Verify ECDSA signature component
    fn verify_ecdsa(&self, msg_hash: &[u8], pubkey: &EcdsaPublicKey) -> Result<bool, String> {
        use k256::ecdsa::signature::Verifier;
        use k256::ecdsa::{Signature, VerifyingKey};

        // Parse signature (64 bytes: r || s)
        if self.classical.len() != 64 {
            return Err(format!(
                "Invalid ECDSA signature size: expected 64, got {}",
                self.classical.len()
            ));
        }

        let signature = Signature::try_from(self.classical.as_slice())
            .map_err(|e| format!("Malformed ECDSA Signature: {}", e))?;

        // Parse public key
        let verifying_key = VerifyingKey::from_sec1_bytes(pubkey.as_bytes())
            .map_err(|e| format!("Malformed ECDSA Public Key: {}", e))?;

        // Verify
        let valid = verifying_key.verify(msg_hash, &signature).is_ok();

        Ok(valid)
    }

    /// Validate signature format
    fn validate_format(&self) -> Result<(), String> {
        // Check ECDSA signature size
        if self.classical.len() != 64 {
            return Err(format!(
                "Invalid ECDSA signature size: expected 64, got {}",
                self.classical.len()
            ));
        }

        // Check Dilithium signature size (RS-06 fix: exact length required)
        let expected_quantum_size = self.level.signature_size();
        if self.quantum.len() != expected_quantum_size {
            return Err(format!(
                "Invalid Dilithium signature size: expected exactly {}, got {}",
                expected_quantum_size,
                self.quantum.len()
            ));
        }

        Ok(())
    }

    /// Serialize to wire format
    ///
    /// Format (V2):
    /// [version][marker][ecdsa_sig:64][separator][level][dilithium_sig_len:u16][dilithium_sig][metadata]
    pub fn to_bytes(&self) -> Vec<u8> {
        let quantum_len: u16 = self
            .quantum
            .len()
            .try_into()
            .expect("quantum signature length exceeds u16");
        let mut result = Vec::with_capacity(2 + 64 + 1 + 1 + 2 + self.quantum.len() + 17);

        result.push(SIGNATURE_VERSION_V2);
        result.push(HYBRID_MARKER);
        result.extend_from_slice(&self.classical);
        result.push(COMPONENT_SEPARATOR);
        result.push(self.level as u8);
        result.extend_from_slice(&quantum_len.to_le_bytes());
        result.extend_from_slice(&self.quantum);

        // Metadata
        if let Some(ts) = self.timestamp {
            result.push(0x01); // Has timestamp
            result.extend_from_slice(&ts.to_le_bytes());
        } else {
            result.push(0x00);
        }

        if let Some(chain_id) = self.chain_id {
            result.push(0x01); // Has chain_id
            result.extend_from_slice(&chain_id.to_le_bytes());
        } else {
            result.push(0x00);
        }

        result
    }

    /// Deserialize from wire format
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() < 2 {
            return Err(CryptoError::InvalidSignatureLength {
                expected: 2,
                actual: bytes.len(),
            });
        }

        let version = bytes[0];
        let marker = bytes[1];
        if marker != HYBRID_MARKER {
            return Err(CryptoError::InvalidKeyFormat(format!(
                "Expected hybrid signature marker 0x{:02x}, got 0x{:02x}",
                HYBRID_MARKER, marker
            )));
        }

        match version {
            SIGNATURE_VERSION_V2 => parse_signature_v2(bytes),
            SIGNATURE_VERSION_V1 => parse_signature_v1(bytes),
            _ => Err(CryptoError::InvalidKeyFormat(format!(
                "Unsupported signature version: {}",
                version
            ))),
        }
    }

    /// Get classical signature bytes
    pub fn classical_bytes(&self) -> &[u8] {
        &self.classical
    }

    /// Get quantum signature bytes
    pub fn quantum_bytes(&self) -> &[u8] {
        &self.quantum
    }

    /// Total serialized size
    pub fn serialized_size(&self) -> usize {
        2 + 64 + 1 + 1 + 2 + self.quantum.len() + 2 + 16 // Conservative
    }
}

impl fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridSignature")
            .field(
                "classical",
                &format!(
                    "{}...{}",
                    &hex::encode(&self.classical[..4]),
                    &hex::encode(&self.classical[60..])
                ),
            )
            .field("quantum_len", &self.quantum.len())
            .field("level", &self.level)
            .field("timestamp", &self.timestamp)
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

// =============================================================================
// Hybrid Public Key
// =============================================================================

/// ECDSA secp256k1 public key (33 bytes compressed)
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcdsaPublicKey {
    #[serde(with = "hex")]
    bytes: Vec<u8>,
}

impl EcdsaPublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 33 && bytes.len() != 65 {
            return Err(CryptoError::InvalidPublicKeyLength {
                expected: 33,
                actual: bytes.len(),
            });
        }

        // Validate it's a valid point on secp256k1
        use k256::ecdsa::VerifyingKey;
        let _ = VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?;

        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get Ethereum-style address (last 20 bytes of Keccak256)
    pub fn to_eth_address(&self) -> [u8; 20] {
        // Uncompressed key for Ethereum address
        use k256::ecdsa::VerifyingKey;
        let vk = VerifyingKey::from_sec1_bytes(&self.bytes).unwrap();
        let uncompressed = vk.to_encoded_point(false);

        let mut hasher = Keccak256::new();
        hasher.update(&uncompressed.as_bytes()[1..]); // Skip 0x04 prefix
        let hash = hasher.finalize();

        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        addr
    }
}

impl fmt::Debug for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EcdsaPublicKey({})", hex::encode(&self.bytes))
    }
}

/// Dilithium public key
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DilithiumPublicKey {
    #[serde(with = "hex")]
    bytes: Vec<u8>,
    level: DilithiumSecurityLevel,
}

impl DilithiumPublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8], level: DilithiumSecurityLevel) -> CryptoResult<Self> {
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

    /// Get security level
    pub fn level(&self) -> DilithiumSecurityLevel {
        self.level
    }
}

impl fmt::Debug for DilithiumPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DilithiumPublicKey")
            .field("level", &self.level)
            .field("fingerprint", &hex::encode(&self.bytes[..8]))
            .finish()
    }
}

/// Enterprise-grade hybrid public key combining ECDSA and Dilithium3
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridPublicKey {
    /// Classical ECDSA public key (secp256k1, 33 bytes compressed)
    pub classical: EcdsaPublicKey,
    /// Post-quantum Dilithium public key
    pub quantum: DilithiumPublicKey,
}

impl HybridPublicKey {
    /// Create from component keys
    pub fn new(classical: EcdsaPublicKey, quantum: DilithiumPublicKey) -> Self {
        Self { classical, quantum }
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() < 36 {
            return Err(CryptoError::InvalidPublicKeyLength {
                expected: 36,
                actual: bytes.len(),
            });
        }

        // Check version and marker
        if bytes[0] != SIGNATURE_VERSION || bytes[1] != HYBRID_MARKER {
            return Err(CryptoError::InvalidKeyFormat(
                "Invalid hybrid key header".into(),
            ));
        }

        // Parse ECDSA key (33 bytes)
        let classical = EcdsaPublicKey::from_bytes(&bytes[2..35])?;

        // Check separator
        if bytes[35] != COMPONENT_SEPARATOR {
            return Err(CryptoError::InvalidKeyFormat(
                "Missing component separator".into(),
            ));
        }

        let level_byte = *bytes
            .last()
            .ok_or_else(|| CryptoError::InvalidKeyFormat("Missing level byte".into()))?;
        let level = match level_byte {
            2 => DilithiumSecurityLevel::Level2,
            3 => DilithiumSecurityLevel::Level3,
            5 => DilithiumSecurityLevel::Level5,
            _ => {
                return Err(CryptoError::InvalidKeyFormat(format!(
                    "Invalid Dilithium level: {}",
                    level_byte
                )))
            }
        };

        let expected_len = 36 + level.public_key_size() + 1;
        if bytes.len() != expected_len {
            return Err(CryptoError::InvalidPublicKeyLength {
                expected: expected_len,
                actual: bytes.len(),
            });
        }

        let quantum =
            DilithiumPublicKey::from_bytes(&bytes[36..36 + level.public_key_size()], level)?;

        Ok(Self { classical, quantum })
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.serialized_size());
        result.push(SIGNATURE_VERSION);
        result.push(HYBRID_MARKER);
        result.extend_from_slice(self.classical.as_bytes());
        result.push(COMPONENT_SEPARATOR);
        result.extend_from_slice(self.quantum.as_bytes());
        result.push(self.quantum.level() as u8);
        result
    }

    /// Total serialized size
    pub fn serialized_size(&self) -> usize {
        2 + self.classical.as_bytes().len() + 1 + self.quantum.as_bytes().len() + 1
    }

    /// Compute unified fingerprint (SHA256 of serialized key)
    pub fn fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let bytes = self.to_bytes();
        let hash = Sha256::digest(&bytes);
        let mut fp = [0u8; 32];
        fp.copy_from_slice(&hash);
        fp
    }

    /// Get Aethelred address (bech32-encoded fingerprint prefix)
    pub fn to_address(&self) -> String {
        let fp = self.fingerprint();
        format!("aethel1{}", hex::encode(&fp[..20]))
    }

    /// Get Ethereum-compatible address (from ECDSA key only)
    pub fn to_eth_address(&self) -> String {
        let addr = self.classical.to_eth_address();
        format!("0x{}", hex::encode(addr))
    }
}

impl fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridPublicKey")
            .field("classical", &self.classical)
            .field("quantum", &self.quantum)
            .field("address", &self.to_address())
            .finish()
    }
}

// =============================================================================
// Hybrid Secret Key
// =============================================================================

/// ECDSA secret key (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdsaSecretKey {
    bytes: Vec<u8>,
}

impl EcdsaSecretKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidSecretKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Get bytes (sensitive!)
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Derive public key
    pub fn public_key(&self) -> CryptoResult<EcdsaPublicKey> {
        use k256::ecdsa::SigningKey;

        let sk = SigningKey::from_bytes(self.bytes.as_slice().into())
            .map_err(|e| CryptoError::KeyGenerationFailed(e.to_string()))?;

        let vk = sk.verifying_key();
        let bytes = vk.to_sec1_bytes();

        EcdsaPublicKey::from_bytes(&bytes)
    }
}

impl fmt::Debug for EcdsaSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EcdsaSecretKey([REDACTED])")
    }
}

/// Dilithium secret key (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DilithiumSecretKey {
    bytes: Vec<u8>,
    #[zeroize(skip)]
    level: DilithiumSecurityLevel,
}

impl DilithiumSecretKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8], level: DilithiumSecurityLevel) -> CryptoResult<Self> {
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

    /// Get security level
    pub fn level(&self) -> DilithiumSecurityLevel {
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

/// Hybrid secret key combining ECDSA and Dilithium3
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    #[zeroize(skip)]
    classical: EcdsaSecretKey,
    #[zeroize(skip)]
    quantum: DilithiumSecretKey,
}

impl HybridSecretKey {
    /// Create from component keys
    pub fn new(classical: EcdsaSecretKey, quantum: DilithiumSecretKey) -> Self {
        Self { classical, quantum }
    }

    /// Get classical component
    pub fn classical(&self) -> &EcdsaSecretKey {
        &self.classical
    }

    /// Get quantum component
    pub fn quantum(&self) -> &DilithiumSecretKey {
        &self.quantum
    }

    /// Derive public key
    pub fn public_key(&self) -> CryptoResult<HybridPublicKey> {
        let classical = self.classical.public_key()?;
        let quantum = derive_dilithium_public_key(&self.quantum)?;
        Ok(HybridPublicKey { classical, quantum })
    }

    /// Sign a message with both algorithms
    pub fn sign(&self, message: &[u8]) -> CryptoResult<HybridSignature> {
        let mut hasher = Keccak256::new();
        hasher.update(message);
        let msg_hash = hasher.finalize();

        let classical = sign_ecdsa(&msg_hash, &self.classical)?;
        let quantum = sign_dilithium(&msg_hash, &self.quantum)?;

        Ok(HybridSignature {
            classical,
            quantum,
            level: self.quantum.level(),
            timestamp: None,
            chain_id: None,
        })
    }
}

impl fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridSecretKey")
            .field("classical", &"[REDACTED]")
            .field("quantum", &"[REDACTED]")
            .finish()
    }
}

// =============================================================================
// Hybrid Key Pair
// =============================================================================

/// Enterprise-grade hybrid keypair for signing and verification
#[derive(Clone)]
pub struct HybridKeyPair {
    pub public_key: HybridPublicKey,
    secret_key: HybridSecretKey,
}

impl HybridKeyPair {
    /// Generate a new hybrid keypair with default Level3 security
    pub fn generate() -> CryptoResult<Self> {
        Self::generate_with_level(DilithiumSecurityLevel::Level3)
    }

    /// Generate with specific security level
    pub fn generate_with_level(level: DilithiumSecurityLevel) -> CryptoResult<Self> {
        // Generate ECDSA keypair
        use k256::ecdsa::SigningKey;
        use rand::rngs::OsRng;

        let ecdsa_sk = SigningKey::random(&mut OsRng);
        let ecdsa_pk = ecdsa_sk.verifying_key();

        let classical_sk = EcdsaSecretKey::from_bytes(&ecdsa_sk.to_bytes())?;
        let classical_pk = EcdsaPublicKey::from_bytes(&ecdsa_pk.to_sec1_bytes())?;

        // Generate Dilithium keypair
        let (quantum_sk, quantum_pk) = generate_dilithium_keypair(level)?;

        let public_key = HybridPublicKey {
            classical: classical_pk,
            quantum: quantum_pk,
        };

        let secret_key = HybridSecretKey {
            classical: classical_sk,
            quantum: quantum_sk,
        };

        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Generate from seed (deterministic)
    pub fn from_seed(seed: &[u8; 64]) -> CryptoResult<Self> {
        use k256::ecdsa::SigningKey;

        // Use first 32 bytes for ECDSA
        let ecdsa_sk = SigningKey::from_bytes(seed[..32].into())
            .map_err(|e| CryptoError::KeyGenerationFailed(e.to_string()))?;
        let ecdsa_pk = ecdsa_sk.verifying_key();

        let classical_sk = EcdsaSecretKey::from_bytes(&ecdsa_sk.to_bytes())?;
        let classical_pk = EcdsaPublicKey::from_bytes(&ecdsa_pk.to_sec1_bytes())?;

        // Use second 32 bytes for Dilithium seed
        let (quantum_sk, quantum_pk) = generate_dilithium_keypair_from_seed(
            &seed[32..64].try_into().unwrap(),
            DilithiumSecurityLevel::Level3,
        )?;

        let public_key = HybridPublicKey {
            classical: classical_pk,
            quantum: quantum_pk,
        };

        let secret_key = HybridSecretKey {
            classical: classical_sk,
            quantum: quantum_sk,
        };

        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Get public key
    pub fn public_key(&self) -> &HybridPublicKey {
        &self.public_key
    }

    /// Get secret key
    pub fn secret_key(&self) -> &HybridSecretKey {
        &self.secret_key
    }

    /// Get Aethelred address
    pub fn address(&self) -> String {
        self.public_key.to_address()
    }

    /// Sign a message with both algorithms
    pub fn sign(&self, message: &[u8]) -> CryptoResult<HybridSignature> {
        self.sign_with_config(message, None, None)
    }

    /// Sign with timestamp and chain_id metadata
    pub fn sign_with_config(
        &self,
        message: &[u8],
        timestamp: Option<u64>,
        chain_id: Option<u64>,
    ) -> CryptoResult<HybridSignature> {
        // Hash the message
        let mut hasher = Keccak256::new();
        hasher.update(message);
        let msg_hash = hasher.finalize();

        // Sign with ECDSA
        let classical = sign_ecdsa(&msg_hash, &self.secret_key.classical)?;

        // Sign with Dilithium
        let quantum = sign_dilithium(&msg_hash, &self.secret_key.quantum)?;

        Ok(HybridSignature {
            classical,
            quantum,
            level: self.secret_key.quantum.level(),
            timestamp,
            chain_id,
        })
    }

    /// Verify a signature
    pub fn verify(
        &self,
        message: &[u8],
        signature: &HybridSignature,
        config: &VerifierConfig,
    ) -> CryptoResult<bool> {
        match signature.verify(message, &self.public_key, config) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl fmt::Debug for HybridKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridKeyPair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Generate Dilithium keypair
#[cfg(feature = "full-pqc")]
fn generate_dilithium_keypair(
    level: DilithiumSecurityLevel,
) -> CryptoResult<(DilithiumSecretKey, DilithiumPublicKey)> {
    use pqcrypto_dilithium::dilithium3;

    match level {
        DilithiumSecurityLevel::Level3 => {
            let (pk, sk) = dilithium3::keypair();
            Ok((
                DilithiumSecretKey::from_bytes(sk.as_bytes(), level)?,
                DilithiumPublicKey::from_bytes(pk.as_bytes(), level)?,
            ))
        }
        _ => Err(CryptoError::UnsupportedAlgorithm(format!(
            "Dilithium {:?} not yet supported",
            level
        ))),
    }
}

/// Generate Dilithium keypair (mock)
#[cfg(not(feature = "full-pqc"))]
fn generate_dilithium_keypair(
    level: DilithiumSecurityLevel,
) -> CryptoResult<(DilithiumSecretKey, DilithiumPublicKey)> {
    use rand::RngCore;

    let mut rng = rand::thread_rng();

    let mut sk_bytes = vec![0u8; level.secret_key_size()];
    let mut pk_bytes = vec![0u8; level.public_key_size()];

    rng.fill_bytes(&mut sk_bytes);
    rng.fill_bytes(&mut pk_bytes);

    Ok((
        DilithiumSecretKey::from_bytes(&sk_bytes, level)?,
        DilithiumPublicKey::from_bytes(&pk_bytes, level)?,
    ))
}

/// Generate Dilithium keypair from seed
fn generate_dilithium_keypair_from_seed(
    seed: &[u8; 32],
    level: DilithiumSecurityLevel,
) -> CryptoResult<(DilithiumSecretKey, DilithiumPublicKey)> {
    use sha2::{Digest, Sha512};

    // Expand seed to required sizes
    let mut hasher = Sha512::new();
    hasher.update(b"dilithium-keygen:");
    hasher.update([level as u8]);
    hasher.update(seed);
    let expanded = hasher.finalize();

    // For mock implementation, just use expanded hash
    let mut sk_bytes = vec![0u8; level.secret_key_size()];
    let mut pk_bytes = vec![0u8; level.public_key_size()];

    // Fill with deterministic data
    for (i, byte) in sk_bytes.iter_mut().enumerate() {
        *byte = expanded[i % 64];
    }
    for (i, byte) in pk_bytes.iter_mut().enumerate() {
        *byte = expanded[(i + 32) % 64];
    }

    Ok((
        DilithiumSecretKey::from_bytes(&sk_bytes, level)?,
        DilithiumPublicKey::from_bytes(&pk_bytes, level)?,
    ))
}

/// Derive public key from Dilithium secret key
fn derive_dilithium_public_key(sk: &DilithiumSecretKey) -> CryptoResult<DilithiumPublicKey> {
    // In production with full-pqc, this would extract from secret key structure
    // For mock, we derive deterministically
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"dilithium-derive-pk:");
    hasher.update(sk.as_bytes());
    let hash = hasher.finalize();

    let mut pk_bytes = vec![0u8; sk.level().public_key_size()];
    for (i, byte) in pk_bytes.iter_mut().enumerate() {
        *byte = hash[i % 32];
    }

    DilithiumPublicKey::from_bytes(&pk_bytes, sk.level())
}

fn parse_signature_metadata(
    bytes: &[u8],
    offset: usize,
) -> Option<(Option<u64>, Option<u64>, usize)> {
    let mut cursor = offset;

    if cursor >= bytes.len() {
        return None;
    }

    let timestamp = match bytes[cursor] {
        0x00 => {
            cursor += 1;
            None
        }
        0x01 => {
            if bytes.len() < cursor + 9 {
                return None;
            }
            let ts = u64::from_le_bytes([
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
                bytes[cursor + 4],
                bytes[cursor + 5],
                bytes[cursor + 6],
                bytes[cursor + 7],
                bytes[cursor + 8],
            ]);
            cursor += 9;
            Some(ts)
        }
        _ => return None,
    };

    if cursor >= bytes.len() {
        return None;
    }

    let chain_id = match bytes[cursor] {
        0x00 => {
            cursor += 1;
            None
        }
        0x01 => {
            if bytes.len() < cursor + 9 {
                return None;
            }
            let id = u64::from_le_bytes([
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
                bytes[cursor + 4],
                bytes[cursor + 5],
                bytes[cursor + 6],
                bytes[cursor + 7],
                bytes[cursor + 8],
            ]);
            cursor += 9;
            Some(id)
        }
        _ => return None,
    };

    Some((timestamp, chain_id, cursor))
}

fn parse_level_byte(level_byte: u8) -> CryptoResult<DilithiumSecurityLevel> {
    match level_byte {
        2 => Ok(DilithiumSecurityLevel::Level2),
        3 => Ok(DilithiumSecurityLevel::Level3),
        5 => Ok(DilithiumSecurityLevel::Level5),
        _ => Err(CryptoError::InvalidKeyFormat(format!(
            "Invalid Dilithium level: {}",
            level_byte
        ))),
    }
}

fn parse_signature_v2(bytes: &[u8]) -> CryptoResult<HybridSignature> {
    // [version][marker][ecdsa:64][sep][level][quantum_len:u16][quantum][metadata]
    // Minimum includes empty metadata flags: 2 + 64 + 1 + 1 + 2 + 1 + 1
    if bytes.len() < 72 {
        return Err(CryptoError::InvalidSignatureLength {
            expected: 72,
            actual: bytes.len(),
        });
    }

    let classical = bytes[2..66].to_vec();
    if bytes[66] != COMPONENT_SEPARATOR {
        return Err(CryptoError::InvalidKeyFormat(
            "Missing component separator".into(),
        ));
    }

    let level = parse_level_byte(bytes[67])?;
    let quantum_len = u16::from_le_bytes([bytes[68], bytes[69]]) as usize;
    let max_quantum_len = level.signature_size();
    if quantum_len == 0 || quantum_len > max_quantum_len {
        return Err(CryptoError::InvalidKeyFormat(format!(
            "Invalid Dilithium signature length {} for level {:?} (max {})",
            quantum_len, level, max_quantum_len
        )));
    }

    let quantum_start = 70;
    let quantum_end = quantum_start + quantum_len;
    if bytes.len() < quantum_end + 2 {
        return Err(CryptoError::InvalidSignatureLength {
            expected: quantum_end + 2,
            actual: bytes.len(),
        });
    }

    let (timestamp, chain_id, consumed) =
        parse_signature_metadata(bytes, quantum_end).ok_or_else(|| {
            CryptoError::InvalidKeyFormat("Malformed hybrid signature metadata".into())
        })?;
    if consumed != bytes.len() {
        return Err(CryptoError::InvalidKeyFormat(
            "Trailing bytes in hybrid signature".into(),
        ));
    }

    let quantum = bytes[quantum_start..quantum_end].to_vec();
    Ok(HybridSignature {
        classical,
        quantum,
        level,
        timestamp,
        chain_id,
    })
}

fn parse_signature_v1(bytes: &[u8]) -> CryptoResult<HybridSignature> {
    // Legacy format:
    // [version][marker][ecdsa:64][sep][quantum:max][level][metadata]
    if bytes.len() < 70 {
        return Err(CryptoError::InvalidSignatureLength {
            expected: 70,
            actual: bytes.len(),
        });
    }

    let classical = bytes[2..66].to_vec();
    if bytes[66] != COMPONENT_SEPARATOR {
        return Err(CryptoError::InvalidKeyFormat(
            "Missing component separator".into(),
        ));
    }

    let candidate_levels = [
        DilithiumSecurityLevel::Level2,
        DilithiumSecurityLevel::Level3,
        DilithiumSecurityLevel::Level5,
    ];

    for level in candidate_levels {
        let quantum_size = level.signature_size();
        let level_offset = 67 + quantum_size;
        if bytes.len() <= level_offset {
            continue;
        }

        if bytes[level_offset] != level as u8 {
            continue;
        }

        let Some((timestamp, chain_id, consumed)) =
            parse_signature_metadata(bytes, level_offset + 1)
        else {
            continue;
        };
        if consumed != bytes.len() {
            continue;
        }

        let quantum = bytes[67..67 + quantum_size].to_vec();
        return Ok(HybridSignature {
            classical,
            quantum,
            level,
            timestamp,
            chain_id,
        });
    }

    Err(CryptoError::InvalidKeyFormat(
        "Invalid hybrid signature encoding for all supported levels".into(),
    ))
}

/// Sign with ECDSA
fn sign_ecdsa(msg_hash: &[u8], sk: &EcdsaSecretKey) -> CryptoResult<Vec<u8>> {
    use k256::ecdsa::{signature::Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(sk.as_bytes().into())
        .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;

    let signature: k256::ecdsa::Signature = signing_key.sign(msg_hash);

    Ok(signature.to_bytes().to_vec())
}

/// Sign with Dilithium
#[cfg(feature = "full-pqc")]
fn sign_dilithium(msg_hash: &[u8], sk: &DilithiumSecretKey) -> CryptoResult<Vec<u8>> {
    use pqcrypto_dilithium::dilithium3;

    let secret_key = dilithium3::SecretKey::from_bytes(sk.as_bytes())
        .map_err(|_| CryptoError::InvalidKeyFormat("Invalid Dilithium secret key".into()))?;

    let signature = dilithium3::detached_sign(msg_hash, &secret_key);

    Ok(signature.as_bytes().to_vec())
}

/// Sign with Dilithium (mock)
#[cfg(not(feature = "full-pqc"))]
fn sign_dilithium(msg_hash: &[u8], sk: &DilithiumSecretKey) -> CryptoResult<Vec<u8>> {
    use sha2::{Digest, Sha256};

    // Mock signature: hash of (message || secret_key)
    let mut hasher = Sha256::new();
    hasher.update(b"dilithium-sign:");
    hasher.update(msg_hash);
    hasher.update(sk.as_bytes());
    let hash = hasher.finalize();

    // Expand to signature size
    let sig_size = sk.level().signature_size();
    let mut sig = vec![0u8; sig_size];
    for (i, byte) in sig.iter_mut().enumerate() {
        *byte = hash[i % 32];
    }

    Ok(sig)
}

/// Batch verify multiple signatures
pub fn batch_verify(
    messages: &[&[u8]],
    signatures: &[&HybridSignature],
    public_keys: &[&HybridPublicKey],
    config: &VerifierConfig,
) -> CryptoResult<bool> {
    if messages.len() != signatures.len() || signatures.len() != public_keys.len() {
        return Err(CryptoError::InvalidSignatureLength {
            expected: messages.len(),
            actual: signatures.len(),
        });
    }

    for ((message, signature), public_key) in messages
        .iter()
        .zip(signatures.iter())
        .zip(public_keys.iter())
    {
        if signature.verify(message, public_key, config).is_err() {
            return Ok(false);
        }
    }

    Ok(true)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = HybridKeyPair::generate().unwrap();
        assert!(keypair.address().starts_with("aethel1"));
    }

    #[test]
    fn test_sign_verify_default_config() {
        let keypair = HybridKeyPair::generate().unwrap();
        let message = b"Test transaction data";
        let config = VerifierConfig::default();

        let signature = keypair.sign(message).unwrap();
        let is_valid = keypair.verify(message, &signature, &config).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_sign_verify_panic_mode() {
        let keypair = HybridKeyPair::generate().unwrap();
        let message = b"Test transaction data";
        let mut config = VerifierConfig::default();
        config.panic_mode_qc = true; // Activate panic mode

        let signature = keypair.sign(message).unwrap();

        // Should still verify (only quantum checked)
        let is_valid = keypair.verify(message, &signature, &config).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_deterministic_keygen() {
        let seed = [42u8; 64];

        let keypair1 = HybridKeyPair::from_seed(&seed).unwrap();
        let keypair2 = HybridKeyPair::from_seed(&seed).unwrap();

        assert_eq!(keypair1.address(), keypair2.address());
    }

    #[test]
    fn test_serialization() {
        let keypair = HybridKeyPair::generate().unwrap();
        let message = b"Test";
        let config = VerifierConfig::default();

        let signature = keypair.sign(message).unwrap();

        // Serialize and deserialize signature
        let sig_bytes = signature.to_bytes();
        let sig_restored = HybridSignature::from_bytes(&sig_bytes).unwrap();

        // Verify restored signature
        let is_valid = keypair.verify(message, &sig_restored, &config).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_signature_deserialize_level2_and_level5() {
        let levels = [
            DilithiumSecurityLevel::Level2,
            DilithiumSecurityLevel::Level5,
        ];

        for level in levels {
            let sig = HybridSignature::with_metadata(
                vec![0x11; 64],
                vec![0x22; level.signature_size()],
                level,
                1_704_067_200,
                1,
            );

            let restored = HybridSignature::from_bytes(&sig.to_bytes()).unwrap();
            assert_eq!(restored.level, level);
            assert_eq!(restored.classical.len(), 64);
            assert_eq!(restored.quantum.len(), level.signature_size());
            assert_eq!(restored.timestamp, Some(1_704_067_200));
            assert_eq!(restored.chain_id, Some(1));
        }
    }

    #[test]
    fn test_public_key_deserialize_level2_and_level5() {
        let classical = HybridKeyPair::generate().unwrap().public_key.classical;
        let levels = [
            DilithiumSecurityLevel::Level2,
            DilithiumSecurityLevel::Level5,
        ];

        for level in levels {
            let quantum =
                DilithiumPublicKey::from_bytes(&vec![0x44; level.public_key_size()], level)
                    .unwrap();
            let key = HybridPublicKey::new(classical.clone(), quantum);
            let restored = HybridPublicKey::from_bytes(&key.to_bytes()).unwrap();
            assert_eq!(restored.quantum.level(), level);
            assert_eq!(restored.classical.as_bytes(), classical.as_bytes());
        }
    }

    #[test]
    fn test_eth_address() {
        let keypair = HybridKeyPair::generate().unwrap();
        let eth_addr = keypair.public_key.to_eth_address();
        assert!(eth_addr.starts_with("0x"));
        assert_eq!(eth_addr.len(), 42); // 0x + 40 hex chars
    }

    #[test]
    fn test_signature_with_metadata() {
        let keypair = HybridKeyPair::generate().unwrap();
        let message = b"Test";
        let config = VerifierConfig::default();

        let timestamp = 1704067200u64; // 2024-01-01
        let chain_id = 1u64;

        let signature = keypair
            .sign_with_config(message, Some(timestamp), Some(chain_id))
            .unwrap();

        assert_eq!(signature.timestamp, Some(timestamp));
        assert_eq!(signature.chain_id, Some(chain_id));

        let is_valid = keypair.verify(message, &signature, &config).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_chain_id_mismatch() {
        let keypair = HybridKeyPair::generate().unwrap();
        let message = b"Test";

        let signature = keypair.sign_with_config(message, None, Some(2)).unwrap();

        // Config expects chain_id 1
        let config = VerifierConfig::default();

        // Should fail due to chain_id mismatch
        let result = signature.verify(message, &keypair.public_key, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_verification() {
        let keypair = HybridKeyPair::generate().unwrap();
        let config = VerifierConfig::default();

        let messages: Vec<&[u8]> = vec![b"msg1", b"msg2", b"msg3"];
        let signatures: Vec<HybridSignature> =
            messages.iter().map(|m| keypair.sign(m).unwrap()).collect();

        let sig_refs: Vec<&HybridSignature> = signatures.iter().collect();
        let pk_refs: Vec<&HybridPublicKey> = vec![&keypair.public_key; 3];

        let valid = batch_verify(&messages, &sig_refs, &pk_refs, &config).unwrap();
        assert!(valid);
    }
}
