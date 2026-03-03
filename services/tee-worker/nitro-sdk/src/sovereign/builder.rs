//! # Sovereign Data Builder
//!
//! Fluent API for constructing `Sovereign<T>` instances with compile-time
//! and runtime validation.

use super::*;
use crate::crypto::{HybridKeypair, HybridPublicKey};
use std::marker::PhantomData;

/// Builder for creating Sovereign data instances
///
/// # Example
///
/// ```rust,ignore
/// let sovereign_data = SovereignBuilder::new(sensitive_data)
///     .jurisdiction(Jurisdiction::UAE)
///     .hardware(HardwareType::IntelSGX)
///     .privacy(PrivacyLevel::Private)
///     .compliance(&[Regulation::HIPAA, Regulation::UAEHealthData])
///     .retention_days(365)
///     .purpose("Medical research")
///     .owner(&my_keypair)
///     .build()?;
/// ```
pub struct SovereignBuilder<T> {
    /// The data to wrap
    data: T,
    /// Required jurisdiction
    jurisdiction: Jurisdiction,
    /// Allowed transfer jurisdictions
    allowed_transfers: Vec<Jurisdiction>,
    /// Required hardware
    hardware: HardwareType,
    /// Minimum security version
    min_security_version: u16,
    /// Privacy level
    privacy_level: PrivacyLevel,
    /// Compliance requirements
    compliance: Vec<ComplianceRequirement>,
    /// Retention policy
    retention: RetentionPolicy,
    /// Allowed purposes
    purposes: Vec<String>,
    /// Access control
    readers: Vec<AccessGrant>,
    /// Writers
    writers: Vec<AccessGrant>,
    /// Require multi-party
    require_multi_party: bool,
    /// Min approvers
    min_approvers: u32,
    /// Audit config
    audit: AuditConfig,
    /// Encryption algorithm
    encryption: EncryptionAlgorithm,
    /// Owner keypair (for signing)
    owner: Option<HybridKeypair>,
}

impl<T> SovereignBuilder<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    /// Create a new builder with data
    pub fn new(data: T) -> Self {
        SovereignBuilder {
            data,
            jurisdiction: Jurisdiction::Global,
            allowed_transfers: Vec::new(),
            hardware: HardwareType::Any,
            min_security_version: 0,
            privacy_level: PrivacyLevel::Protected,
            compliance: Vec::new(),
            retention: RetentionPolicy::default(),
            purposes: Vec::new(),
            readers: Vec::new(),
            writers: Vec::new(),
            require_multi_party: false,
            min_approvers: 1,
            audit: AuditConfig::default(),
            encryption: EncryptionAlgorithm::Aes256Gcm,
            owner: None,
        }
    }

    /// Set required jurisdiction
    pub fn jurisdiction(mut self, jurisdiction: Jurisdiction) -> Self {
        self.jurisdiction = jurisdiction;
        self
    }

    /// Set UAE data sovereignty (convenience method)
    pub fn uae_sovereign(mut self) -> Self {
        self.jurisdiction = Jurisdiction::UAE;
        self.hardware = HardwareType::IntelSGX; // Default to SGX for UAE
        self.compliance.push(ComplianceRequirement {
            regulation: Regulation::UAEDataProtection,
            requirements: vec![
                "Data must remain within UAE borders".to_string(),
                "Processing only in approved jurisdictions".to_string(),
            ],
            verification: VerificationMethod::TeeAttestation,
        });
        self
    }

    /// Set GDPR compliance (convenience method)
    pub fn gdpr_compliant(mut self) -> Self {
        self.jurisdiction = Jurisdiction::EU;
        self.compliance.push(ComplianceRequirement {
            regulation: Regulation::GDPR,
            requirements: vec![
                "Right to erasure (Article 17)".to_string(),
                "Data protection by design (Article 25)".to_string(),
                "Transfer restrictions (Article 44)".to_string(),
            ],
            verification: VerificationMethod::AuditLog,
        });
        self.audit.require_reason = true;
        self
    }

    /// Set HIPAA compliance (convenience method)
    pub fn hipaa_compliant(mut self) -> Self {
        self.jurisdiction = Jurisdiction::US;
        self.privacy_level = PrivacyLevel::Private;
        self.compliance.push(ComplianceRequirement {
            regulation: Regulation::HIPAA,
            requirements: vec![
                "PHI protection (45 CFR 164.502)".to_string(),
                "Minimum necessary standard".to_string(),
                "Audit controls".to_string(),
            ],
            verification: VerificationMethod::TeeAttestation,
        });
        self.audit.log_access = true;
        self.audit.require_reason = true;
        self
    }

    /// Allow transfer to specific jurisdictions
    pub fn allow_transfer_to(mut self, jurisdictions: &[Jurisdiction]) -> Self {
        self.allowed_transfers.extend_from_slice(jurisdictions);
        self
    }

    /// Set required hardware type
    pub fn hardware(mut self, hardware: HardwareType) -> Self {
        self.hardware = hardware;
        self
    }

    /// Require Intel SGX
    pub fn require_sgx(mut self) -> Self {
        self.hardware = HardwareType::IntelSGX;
        self
    }

    /// Require AMD SEV
    pub fn require_sev(mut self) -> Self {
        self.hardware = HardwareType::AmdSev;
        self
    }

    /// Require AWS Nitro
    pub fn require_nitro(mut self) -> Self {
        self.hardware = HardwareType::AwsNitro;
        self
    }

    /// Set minimum security version (for TEE)
    pub fn min_security_version(mut self, version: u16) -> Self {
        self.min_security_version = version;
        self
    }

    /// Set privacy level
    pub fn privacy(mut self, level: PrivacyLevel) -> Self {
        self.privacy_level = level;
        self
    }

    /// Add compliance requirements
    pub fn compliance(mut self, regulations: &[Regulation]) -> Self {
        for reg in regulations {
            self.compliance.push(ComplianceRequirement {
                regulation: reg.clone(),
                requirements: reg.default_requirements(),
                verification: VerificationMethod::TeeAttestation,
            });
        }
        self
    }

    /// Add detailed compliance requirement
    pub fn add_compliance_requirement(mut self, req: ComplianceRequirement) -> Self {
        self.compliance.push(req);
        self
    }

    /// Set retention period in days
    pub fn retention_days(mut self, days: u64) -> Self {
        self.retention.period = Duration::from_secs(days * 24 * 60 * 60);
        self
    }

    /// Set retention policy
    pub fn retention_policy(mut self, policy: RetentionPolicy) -> Self {
        self.retention = policy;
        self
    }

    /// Enable legal hold (prevents deletion)
    pub fn legal_hold(mut self) -> Self {
        self.retention.legal_hold = true;
        self
    }

    /// Add allowed purpose
    pub fn purpose(mut self, purpose: &str) -> Self {
        self.purposes.push(purpose.to_string());
        self
    }

    /// Add multiple allowed purposes
    pub fn purposes(mut self, purposes: &[&str]) -> Self {
        self.purposes.extend(purposes.iter().map(|s| s.to_string()));
        self
    }

    /// Grant read access
    pub fn grant_read(mut self, grantee: HybridPublicKey) -> Self {
        self.readers.push(AccessGrant {
            grantee,
            permissions: Permissions::read_only(),
            expires_at: None,
            conditions: Vec::new(),
        });
        self
    }

    /// Grant read access with conditions
    pub fn grant_read_with_conditions(
        mut self,
        grantee: HybridPublicKey,
        conditions: Vec<AccessCondition>,
        expires_at: Option<SystemTime>,
    ) -> Self {
        self.readers.push(AccessGrant {
            grantee,
            permissions: Permissions::read_only(),
            expires_at,
            conditions,
        });
        self
    }

    /// Grant write access
    pub fn grant_write(mut self, grantee: HybridPublicKey) -> Self {
        self.writers.push(AccessGrant {
            grantee,
            permissions: Permissions {
                read: true,
                write: true,
                delete: false,
                grant: false,
                export: false,
            },
            expires_at: None,
            conditions: Vec::new(),
        });
        self
    }

    /// Require multi-party approval for access
    pub fn require_multi_party(mut self, min_approvers: u32) -> Self {
        self.require_multi_party = true;
        self.min_approvers = min_approvers;
        self
    }

    /// Configure audit logging
    pub fn audit(mut self, config: AuditConfig) -> Self {
        self.audit = config;
        self
    }

    /// Require access reason in audit
    pub fn require_access_reason(mut self) -> Self {
        self.audit.require_reason = true;
        self
    }

    /// Set encryption algorithm
    pub fn encryption(mut self, algorithm: EncryptionAlgorithm) -> Self {
        self.encryption = algorithm;
        self
    }

    /// Set owner (required for signing)
    pub fn owner(mut self, keypair: HybridKeypair) -> Self {
        self.owner = Some(keypair);
        self
    }

    /// Build the Sovereign data instance
    pub fn build(self) -> Result<Sovereign<T>, SovereignError> {
        // Validate configuration
        self.validate()?;

        // Get or generate owner
        let owner = self.owner.unwrap_or_else(HybridKeypair::generate);

        // Serialize and encrypt data
        let serialized = bincode::serialize(&self.data)
            .map_err(|e| SovereignError::DecryptionFailed(e.to_string()))?;

        // Generate encryption metadata
        let nonce = Self::generate_nonce(self.encryption);
        let salt = Self::generate_salt();

        let encryption_meta = EncryptionMetadata {
            algorithm: self.encryption,
            nonce,
            key_derivation: KeyDerivationInfo {
                algorithm: KdfAlgorithm::HkdfSha256,
                salt,
                info: format!("sovereign:{}", self.jurisdiction.code()),
                iterations: None,
            },
            aad_hash: Self::compute_aad_hash(&self.jurisdiction, &self.hardware),
        };

        // In production, encrypt the data here
        // For now, we just store serialized (would be encrypted)
        let encrypted_payload = serialized;

        // Create access control list
        let acl = AccessControlList {
            owner: owner.public_key().clone(),
            readers: self.readers,
            writers: self.writers,
            require_multi_party: self.require_multi_party,
            min_approvers: self.min_approvers,
        };

        // Create the sovereign instance
        let id = SovereignId::new();
        let created_at = SystemTime::now();

        // Sign metadata
        let metadata_bytes =
            Self::metadata_bytes(&id, &self.jurisdiction, &self.hardware, &created_at);
        let signature = owner.sign(&metadata_bytes);

        Ok(Sovereign {
            id,
            encrypted_payload,
            encryption_meta,
            required_jurisdiction: self.jurisdiction,
            allowed_transfers: self.allowed_transfers,
            required_hardware: self.hardware,
            min_security_version: self.min_security_version,
            privacy_level: self.privacy_level,
            compliance_requirements: self.compliance,
            retention: self.retention,
            allowed_purposes: self.purposes,
            access_control: acl,
            audit_config: self.audit,
            created_at,
            creator: owner.public_key().clone(),
            metadata_signature: signature,
            _phantom: PhantomData,
        })
    }

    /// Validate the builder configuration
    fn validate(&self) -> Result<(), SovereignError> {
        // Privacy level requires appropriate hardware
        if self.privacy_level.requires_tee() && self.hardware == HardwareType::Any {
            return Err(SovereignError::InsecureHardware {
                required: HardwareType::IntelSGX,
                actual: HardwareType::Any,
            });
        }

        // MPC requires multi-party
        if self.privacy_level == PrivacyLevel::Secret && !self.require_multi_party {
            return Err(SovereignError::AccessDenied {
                reason: "Secret data requires multi-party approval".to_string(),
            });
        }

        Ok(())
    }

    fn generate_nonce(algorithm: EncryptionAlgorithm) -> Vec<u8> {
        use rand::RngCore;
        let size = match algorithm {
            EncryptionAlgorithm::Aes256Gcm => 12,
            EncryptionAlgorithm::ChaCha20Poly1305 => 12,
            EncryptionAlgorithm::Aes256GcmSiv => 12,
        };
        let mut nonce = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    fn generate_salt() -> Vec<u8> {
        use rand::RngCore;
        let mut salt = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }

    fn compute_aad_hash(jurisdiction: &Jurisdiction, hardware: &HardwareType) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(jurisdiction.code().as_bytes());
        hasher.update(&[*hardware as u8]);
        hasher.finalize().into()
    }

    fn metadata_bytes(
        id: &SovereignId,
        jurisdiction: &Jurisdiction,
        hardware: &HardwareType,
        created_at: &SystemTime,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&id.0);
        bytes.extend_from_slice(jurisdiction.code().as_bytes());
        bytes.push(*hardware as u8);
        let ts = created_at
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        bytes.extend_from_slice(&ts.to_le_bytes());
        bytes
    }
}

// ============================================================================
// Quick Constructors
// ============================================================================

impl<T> Sovereign<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    /// Create a new Sovereign wrapper (convenience method)
    pub fn new(data: T) -> SovereignBuilder<T> {
        SovereignBuilder::new(data)
    }

    /// Create UAE-sovereign data
    pub fn uae(data: T) -> SovereignBuilder<T> {
        SovereignBuilder::new(data).uae_sovereign()
    }

    /// Create GDPR-compliant data
    pub fn gdpr(data: T) -> SovereignBuilder<T> {
        SovereignBuilder::new(data).gdpr_compliant()
    }

    /// Create HIPAA-compliant data
    pub fn hipaa(data: T) -> SovereignBuilder<T> {
        SovereignBuilder::new(data).hipaa_compliant()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_basic() {
        let result = SovereignBuilder::new("test data".to_string())
            .jurisdiction(Jurisdiction::UAE)
            .hardware(HardwareType::IntelSGX)
            .build();

        assert!(result.is_ok());
        let sovereign = result.unwrap();
        assert_eq!(sovereign.required_jurisdiction(), Jurisdiction::UAE);
    }

    #[test]
    fn test_builder_uae_convenience() {
        let result = Sovereign::uae("sensitive".to_string()).build();
        assert!(result.is_ok());

        let sovereign = result.unwrap();
        assert_eq!(sovereign.required_jurisdiction(), Jurisdiction::UAE);
        assert!(sovereign.privacy_level().requires_tee());
    }

    #[test]
    fn test_privacy_requires_tee() {
        let result = SovereignBuilder::new("secret".to_string())
            .privacy(PrivacyLevel::Private)
            .hardware(HardwareType::Any) // Should fail
            .build();

        assert!(result.is_err());
    }
}
