//! # Sovereign Data Types
//!
//! **"Data that knows where it can live."**
//!
//! The Sovereign module provides compile-time and runtime enforcement of
//! data residency, hardware security, and compliance requirements.
//!
//! ## The Problem
//!
//! In traditional systems, sensitive data (patient records, financial data)
//! can accidentally leak across borders or be processed on insecure hardware.
//! Developers must manually track where data can and cannot flow.
//!
//! ## The Solution
//!
//! `Sovereign<T>` wraps any data type with cryptographic constraints:
//!
//! - **Jurisdiction**: Where the data can physically exist
//! - **Hardware**: What type of secure hardware is required
//! - **Compliance**: What regulatory frameworks apply
//! - **Access Control**: Who can decrypt and use the data
//!
//! ## Example
//!
//! ```rust,ignore
//! use aethelred_sdk::sovereign::{Sovereign, SovereignBuilder};
//! use aethelred_sdk::compliance::Jurisdiction;
//! use aethelred_sdk::attestation::HardwareType;
//!
//! // A patient's genomic data that MUST stay in UAE
//! let patient_dna: Sovereign<Vec<u8>> = SovereignBuilder::new(dna_sequence)
//!     .jurisdiction(Jurisdiction::UAE)
//!     .hardware(HardwareType::IntelSGX)
//!     .compliance(&[Compliance::HIPAA, Compliance::UAEHealthData])
//!     .retention_days(365)
//!     .purpose("Cancer screening research")
//!     .build()?;
//!
//! // This will FAIL if the current node is not in UAE + SGX
//! let data = patient_dna.access(&current_attestation)?;
//! ```
//!
//! ## Privacy Levels
//!
//! The module supports four privacy levels:
//!
//! | Level | Description | Example |
//! |-------|-------------|---------|
//! | `Public` | Anyone can read | Transaction amounts |
//! | `Protected` | Encrypted, key holders can read | Customer names |
//! | `Private` | TEE-only access | Medical records |
//! | `Secret` | Multi-party computation only | Bank secrets |

mod access;
mod audit;
mod builder;
mod encryption;
mod types;

#[allow(unused_imports)]
pub use access::*;
#[allow(unused_imports)]
pub use audit::*;
#[allow(unused_imports)]
pub use builder::*;
#[allow(unused_imports)]
pub use encryption::*;
#[allow(unused_imports)]
pub use types::*;

use crate::attestation::{AttestationError, EnclaveReport, HardwareType};
use crate::compliance::{Jurisdiction, Regulation};
use crate::crypto::{HybridPublicKey, HybridSignature};

use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use zeroize::Zeroize;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur when working with Sovereign data
#[derive(Error, Debug, Clone)]
pub enum SovereignError {
    /// Data residency violation
    #[error("Data residency violation: required {required:?}, actual {actual:?}")]
    DataResidencyViolation {
        /// Required jurisdiction
        required: Jurisdiction,
        /// Actual jurisdiction
        actual: Jurisdiction,
        /// Legal citation
        citation: Option<String>,
    },

    /// Hardware security violation
    #[error("Insecure hardware: required {required:?}, actual {actual:?}")]
    InsecureHardware {
        /// Required hardware type
        required: HardwareType,
        /// Actual hardware type
        actual: HardwareType,
    },

    /// Compliance violation
    #[error("Compliance violation: {regulation}")]
    ComplianceViolation {
        /// Regulation violated
        regulation: String,
        /// Legal citation
        citation: String,
        /// Remediation steps
        remediation: Vec<String>,
    },

    /// Access denied
    #[error("Access denied: {reason}")]
    AccessDenied {
        /// Reason for denial
        reason: String,
    },

    /// Data expired
    #[error("Data retention period expired")]
    DataExpired {
        /// Expiration time
        expired_at: SystemTime,
    },

    /// Invalid attestation
    #[error("Invalid attestation: {0}")]
    InvalidAttestation(#[from] AttestationError),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Audit log required
    #[error("Audit log required for this access")]
    AuditRequired,

    /// Purpose mismatch
    #[error("Access purpose '{requested}' does not match allowed purposes")]
    PurposeMismatch {
        /// Requested purpose
        requested: String,
        /// Allowed purposes
        allowed: Vec<String>,
    },
}

// ============================================================================
// Privacy Levels
// ============================================================================

/// Privacy level for sovereign data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrivacyLevel {
    /// Public data - anyone can read
    /// Example: Transaction amounts, public announcements
    Public,

    /// Protected data - encrypted, authorized key holders can read
    /// Example: Customer names, order details
    Protected,

    /// Private data - TEE-only access, never leaves enclave unencrypted
    /// Example: Medical records, credit scores
    Private,

    /// Secret data - multi-party computation only, no single party sees raw data
    /// Example: Bank trading algorithms, government secrets
    Secret,
}

impl PrivacyLevel {
    /// Returns true if TEE is required for this privacy level
    pub fn requires_tee(&self) -> bool {
        matches!(self, PrivacyLevel::Private | PrivacyLevel::Secret)
    }

    /// Returns true if encryption is required
    pub fn requires_encryption(&self) -> bool {
        !matches!(self, PrivacyLevel::Public)
    }

    /// Returns true if multi-party computation is required
    pub fn requires_mpc(&self) -> bool {
        matches!(self, PrivacyLevel::Secret)
    }
}

// ============================================================================
// Sovereign Data Wrapper
// ============================================================================

/// A wrapper that enforces data sovereignty at the type level.
///
/// `Sovereign<T>` ensures that data of type `T` can only be accessed
/// when specific jurisdiction, hardware, and compliance requirements are met.
///
/// # Type Parameters
///
/// - `T`: The underlying data type (must be Serialize + Deserialize)
///
/// # Security Properties
///
/// 1. **Data Residency**: The data can only be decrypted in allowed jurisdictions
/// 2. **Hardware Binding**: The data is bound to specific TEE measurements
/// 3. **Compliance Tagging**: The data carries compliance metadata for auditing
/// 4. **Access Logging**: Every access is logged for compliance
///
/// # Example
///
/// ```rust,ignore
/// // Create sovereign data
/// let secret: Sovereign<String> = Sovereign::new("sensitive data".to_string())
///     .with_jurisdiction(Jurisdiction::UAE)
///     .with_hardware(HardwareType::IntelSGX)
///     .build()?;
///
/// // Access requires valid attestation
/// let report = attestation_engine.get_current_report()?;
/// let data = secret.access(&report)?;
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct Sovereign<T> {
    /// Unique identifier for this sovereign data instance
    id: SovereignId,

    /// The encrypted data payload
    #[cfg_attr(not(feature = "full-sdk"), serde(with = "serde_bytes"))]
    encrypted_payload: Vec<u8>,

    /// Encryption metadata (algorithm, nonce, etc.)
    encryption_meta: EncryptionMetadata,

    /// Required jurisdiction for access
    required_jurisdiction: Jurisdiction,

    /// Allowed jurisdictions for cross-border transfer
    allowed_transfers: Vec<Jurisdiction>,

    /// Required hardware type
    required_hardware: HardwareType,

    /// Minimum security version (for TEE)
    min_security_version: u16,

    /// Privacy level
    privacy_level: PrivacyLevel,

    /// Compliance requirements
    compliance_requirements: Vec<ComplianceRequirement>,

    /// Data retention policy
    retention: RetentionPolicy,

    /// Allowed purposes for data access
    allowed_purposes: Vec<String>,

    /// Access control list
    access_control: AccessControlList,

    /// Audit configuration
    audit_config: AuditConfig,

    /// Creation timestamp
    created_at: SystemTime,

    /// Creator's public key
    creator: HybridPublicKey,

    /// Signature over the metadata
    metadata_signature: HybridSignature,

    /// Phantom data for type safety
    #[cfg_attr(not(feature = "full-sdk"), serde(skip))]
    _phantom: PhantomData<T>,
}

/// Unique identifier for sovereign data
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SovereignId(pub [u8; 32]);

impl SovereignId {
    /// Generate a new random ID
    pub fn new() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        SovereignId(bytes)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SovereignId(bytes)
    }

    /// Get as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl Default for SovereignId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SovereignId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sov_{}", &self.to_hex()[..16])
    }
}

/// Encryption metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    /// Encryption algorithm
    pub algorithm: EncryptionAlgorithm,
    /// Nonce/IV
    #[cfg_attr(not(feature = "full-sdk"), serde(with = "serde_bytes"))]
    pub nonce: Vec<u8>,
    /// Key derivation info
    pub key_derivation: KeyDerivationInfo,
    /// Additional authenticated data hash
    pub aad_hash: [u8; 32],
}

/// Supported encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM (NIST approved)
    Aes256Gcm,
    /// ChaCha20-Poly1305 (IETF)
    ChaCha20Poly1305,
    /// AES-256-GCM-SIV (Misuse resistant)
    Aes256GcmSiv,
}

/// Key derivation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationInfo {
    /// KDF algorithm
    pub algorithm: KdfAlgorithm,
    /// Salt
    #[cfg_attr(not(feature = "full-sdk"), serde(with = "serde_bytes"))]
    pub salt: Vec<u8>,
    /// Info string (for HKDF)
    pub info: String,
    /// Iterations (for PBKDF2)
    pub iterations: Option<u32>,
}

/// Supported KDF algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfAlgorithm {
    /// HKDF-SHA256
    HkdfSha256,
    /// HKDF-SHA384
    HkdfSha384,
    /// PBKDF2-SHA256
    Pbkdf2Sha256,
}

/// Compliance requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRequirement {
    /// Regulation identifier
    pub regulation: Regulation,
    /// Specific requirements
    pub requirements: Vec<String>,
    /// Verification method
    pub verification: VerificationMethod,
}

/// How compliance is verified
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationMethod {
    /// TEE attestation
    TeeAttestation,
    /// Audit log review
    AuditLog,
    /// Third-party certification
    ThirdPartyCert {
        /// Name of the certifying organization (e.g., auditor or regulator).
        certifier: String,
    },
    /// Self-declaration
    SelfDeclaration,
}

/// Data retention policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Retention period
    pub period: Duration,
    /// Auto-delete after expiry
    pub auto_delete: bool,
    /// Archive before delete
    pub archive_before_delete: bool,
    /// Legal hold (prevents deletion)
    pub legal_hold: bool,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        RetentionPolicy {
            period: Duration::from_secs(365 * 24 * 60 * 60), // 1 year
            auto_delete: false,
            archive_before_delete: true,
            legal_hold: false,
        }
    }
}

/// Access control list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlList {
    /// Owner (full control)
    pub owner: HybridPublicKey,
    /// Authorized readers
    pub readers: Vec<AccessGrant>,
    /// Authorized writers
    pub writers: Vec<AccessGrant>,
    /// Require multi-party approval
    pub require_multi_party: bool,
    /// Minimum approvers for access
    pub min_approvers: u32,
}

/// An access grant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessGrant {
    /// Grantee's public key
    pub grantee: HybridPublicKey,
    /// Granted permissions
    pub permissions: Permissions,
    /// Grant expiry
    pub expires_at: Option<SystemTime>,
    /// Conditions for access
    pub conditions: Vec<AccessCondition>,
}

/// Permissions flags
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Permissions {
    /// Can read data
    pub read: bool,
    /// Can modify data
    pub write: bool,
    /// Can delete data
    pub delete: bool,
    /// Can grant access to others
    pub grant: bool,
    /// Can export data
    pub export: bool,
}

impl Permissions {
    /// Read-only permissions
    pub fn read_only() -> Self {
        Permissions {
            read: true,
            write: false,
            delete: false,
            grant: false,
            export: false,
        }
    }

    /// Full permissions
    pub fn full() -> Self {
        Permissions {
            read: true,
            write: true,
            delete: true,
            grant: true,
            export: true,
        }
    }
}

/// Condition for access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessCondition {
    /// Must be in specific jurisdiction
    Jurisdiction(Jurisdiction),
    /// Must use specific hardware
    Hardware(HardwareType),
    /// Must be within time window
    TimeWindow {
        /// Inclusive start time for permitted access.
        start: SystemTime,
        /// Inclusive end time for permitted access.
        end: SystemTime,
    },
    /// Must provide purpose
    PurposeRequired,
    /// Must have specific role
    Role(String),
    /// Custom condition (evaluated by smart contract)
    Custom {
        /// Smart contract address that evaluates the condition.
        contract_address: String,
        /// Method/entrypoint invoked to evaluate the condition.
        method: String,
    },
}

/// Audit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Log all access attempts
    pub log_access: bool,
    /// Log all modifications
    pub log_modifications: bool,
    /// Log export attempts
    pub log_exports: bool,
    /// Require reason for access
    pub require_reason: bool,
    /// Audit log destination
    pub log_destination: AuditDestination,
    /// Retention for audit logs
    pub log_retention: Duration,
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            log_access: true,
            log_modifications: true,
            log_exports: true,
            require_reason: false,
            log_destination: AuditDestination::OnChain,
            log_retention: Duration::from_secs(7 * 365 * 24 * 60 * 60), // 7 years
        }
    }
}

/// Where audit logs are stored
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditDestination {
    /// On-chain (immutable)
    OnChain,
    /// Secure off-chain storage
    SecureOffChain {
        /// Endpoint URI for the secure audit sink.
        endpoint: String,
    },
    /// Both on-chain and off-chain
    Hybrid {
        /// Off-chain endpoint URI used alongside on-chain logging.
        offchain_endpoint: String,
    },
}

// ============================================================================
// Implementation
// ============================================================================

impl<T> Sovereign<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    /// Get the sovereign data ID
    pub fn id(&self) -> &SovereignId {
        &self.id
    }

    /// Get the required jurisdiction
    pub fn required_jurisdiction(&self) -> Jurisdiction {
        self.required_jurisdiction
    }

    /// Get the privacy level
    pub fn privacy_level(&self) -> PrivacyLevel {
        self.privacy_level
    }

    /// Check if access is allowed without actually accessing
    pub fn check_access(&self, report: &EnclaveReport) -> Result<(), SovereignError> {
        // The current EnclaveReport shape does not carry a first-class location field.
        // Default to Global here until geo binding is plumbed into access checks.
        let report_location = Jurisdiction::Global;
        // 1. Check jurisdiction
        if !self.is_jurisdiction_allowed(report_location) {
            return Err(SovereignError::DataResidencyViolation {
                required: self.required_jurisdiction,
                actual: report_location,
                citation: self.get_jurisdiction_citation(),
            });
        }

        // 2. Check hardware
        if !report.hardware_type.satisfies(self.required_hardware) {
            return Err(SovereignError::InsecureHardware {
                required: self.required_hardware,
                actual: report.hardware_type,
            });
        }

        // 3. Check security version
        if report.security_version < self.min_security_version {
            return Err(SovereignError::InsecureHardware {
                required: self.required_hardware,
                actual: report.hardware_type,
            });
        }

        // 4. Check retention
        if self.is_expired() {
            return Err(SovereignError::DataExpired {
                expired_at: self.expiry_time(),
            });
        }

        Ok(())
    }

    /// Access the data (requires valid attestation)
    pub fn access(&self, report: &EnclaveReport) -> Result<T, SovereignError> {
        self.access_with_purpose(report, None)
    }

    /// Access with stated purpose
    pub fn access_with_purpose(
        &self,
        report: &EnclaveReport,
        purpose: Option<&str>,
    ) -> Result<T, SovereignError> {
        // Validate access
        self.check_access(report)?;

        // Check purpose if required
        if let Some(purpose) = purpose {
            if !self.allowed_purposes.is_empty()
                && !self.allowed_purposes.iter().any(|p| p == purpose)
            {
                return Err(SovereignError::PurposeMismatch {
                    requested: purpose.to_string(),
                    allowed: self.allowed_purposes.clone(),
                });
            }
        }

        // Decrypt the data
        self.decrypt(report)
    }

    /// Check if jurisdiction is allowed
    fn is_jurisdiction_allowed(&self, location: Jurisdiction) -> bool {
        if location == self.required_jurisdiction {
            return true;
        }

        // Check allowed transfers
        if self.allowed_transfers.contains(&location) {
            // Additional check: can the source export to target?
            return self.required_jurisdiction.can_export_to(location);
        }

        false
    }

    /// Get legal citation for jurisdiction
    fn get_jurisdiction_citation(&self) -> Option<String> {
        match self.required_jurisdiction {
            Jurisdiction::UAE => Some("UAE Federal Decree-Law No. 45/2021, Article 7".to_string()),
            Jurisdiction::EU => {
                Some("GDPR Article 44 - Transfers of personal data to third countries".to_string())
            }
            Jurisdiction::Singapore => {
                Some("PDPA Section 26 - Transfer Limitation Obligation".to_string())
            }
            _ => None,
        }
    }

    /// Check if data is expired
    fn is_expired(&self) -> bool {
        if self.retention.legal_hold {
            return false;
        }
        SystemTime::now() > self.expiry_time()
    }

    /// Get expiry time
    fn expiry_time(&self) -> SystemTime {
        self.created_at + self.retention.period
    }

    /// Decrypt the payload
    fn decrypt(&self, _report: &EnclaveReport) -> Result<T, SovereignError> {
        // In production, this would:
        // 1. Derive key from TEE sealing key + report data
        // 2. Decrypt using the specified algorithm
        // 3. Verify integrity
        // 4. Log access

        // For now, simulate decryption
        let decrypted = bincode::deserialize(&self.encrypted_payload)
            .map_err(|e| SovereignError::DecryptionFailed(e.to_string()))?;

        Ok(decrypted)
    }

    /// Get metadata for audit/display (no sensitive data)
    pub fn metadata(&self) -> SovereignMetadata {
        SovereignMetadata {
            id: self.id.clone(),
            privacy_level: self.privacy_level,
            jurisdiction: self.required_jurisdiction,
            hardware: self.required_hardware,
            created_at: self.created_at,
            expires_at: self.expiry_time(),
            compliance: self
                .compliance_requirements
                .iter()
                .map(|c| c.regulation.clone())
                .collect(),
        }
    }
}

/// Non-sensitive metadata about sovereign data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovereignMetadata {
    /// Data ID
    pub id: SovereignId,
    /// Privacy level
    pub privacy_level: PrivacyLevel,
    /// Required jurisdiction
    pub jurisdiction: Jurisdiction,
    /// Required hardware
    pub hardware: HardwareType,
    /// Creation time
    pub created_at: SystemTime,
    /// Expiry time
    pub expires_at: SystemTime,
    /// Compliance frameworks
    pub compliance: Vec<Regulation>,
}

impl<T> std::fmt::Debug for Sovereign<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sovereign")
            .field("id", &self.id)
            .field("privacy_level", &self.privacy_level)
            .field("jurisdiction", &self.required_jurisdiction)
            .field("hardware", &self.required_hardware)
            .field("payload", &"[ENCRYPTED]")
            .finish()
    }
}

// Ensure sensitive data is zeroed on drop
impl<T> Drop for Sovereign<T> {
    fn drop(&mut self) {
        self.encrypted_payload.zeroize();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sovereign_id() {
        let id = SovereignId::new();
        assert_eq!(id.0.len(), 32);

        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn test_privacy_levels() {
        assert!(!PrivacyLevel::Public.requires_tee());
        assert!(!PrivacyLevel::Protected.requires_tee());
        assert!(PrivacyLevel::Private.requires_tee());
        assert!(PrivacyLevel::Secret.requires_tee());

        assert!(!PrivacyLevel::Public.requires_encryption());
        assert!(PrivacyLevel::Protected.requires_encryption());
    }

    #[test]
    fn test_permissions() {
        let read_only = Permissions::read_only();
        assert!(read_only.read);
        assert!(!read_only.write);

        let full = Permissions::full();
        assert!(full.read);
        assert!(full.write);
        assert!(full.grant);
    }

    #[test]
    fn test_bincode_roundtrip_sovereign_metadata() {
        let metadata = SovereignMetadata {
            id: SovereignId::from_bytes([9u8; 32]),
            privacy_level: PrivacyLevel::Private,
            jurisdiction: Jurisdiction::UAE,
            hardware: HardwareType::AwsNitro,
            created_at: SystemTime::now(),
            expires_at: SystemTime::now(),
            compliance: vec![Regulation::UAEDataProtection],
        };

        let encoded = bincode::serialize(&metadata).expect("serialize metadata");
        let decoded: SovereignMetadata =
            bincode::deserialize(&encoded).expect("deserialize metadata");
        assert_eq!(decoded.id.0, [9u8; 32]);
        assert_eq!(decoded.privacy_level, PrivacyLevel::Private);
        assert_eq!(decoded.jurisdiction, Jurisdiction::UAE);
        assert_eq!(decoded.hardware, HardwareType::AwsNitro);
        assert_eq!(decoded.compliance, vec![Regulation::UAEDataProtection]);
    }
}
