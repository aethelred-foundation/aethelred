//! Aethelred Digital Seal Types
//!
//! Digital Seals are immutable, on-chain records of verified AI computations.
//! They serve as cryptographic proof that a specific computation was performed
//! correctly by the Aethelred network.

use super::address::Address;
use super::job::JobId;
use crate::crypto::hash::{sha256, Hash256};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seal ID (32-byte hash)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SealId(pub Hash256);

impl SealId {
    /// Create from hash
    pub fn from_hash(hash: Hash256) -> Self {
        Self(hash)
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Get hex string
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl fmt::Debug for SealId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealId({}...)", &self.to_hex()[..8])
    }
}

impl fmt::Display for SealId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Seal status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealStatus {
    /// Seal is being created (validators still voting)
    Pending,
    /// Seal is finalized and valid
    Finalized,
    /// Seal was challenged and invalidated
    Invalidated,
    /// Seal expired (for time-limited seals)
    Expired,
}

/// Digital Seal - immutable record of verified computation
#[derive(Debug, Clone)]
pub struct DigitalSeal {
    /// Unique seal identifier
    pub id: SealId,
    /// Version
    pub version: u8,

    // === Computation Identity ===
    /// Original job that was verified
    pub job_id: JobId,
    /// Hash of the model used
    pub model_commitment: Hash256,
    /// Hash of the input data
    pub input_commitment: Hash256,
    /// Hash of the output data
    pub output_commitment: Hash256,

    // === Verification Evidence ===
    /// Evidence of verification
    pub evidence: SealEvidence,

    // === Metadata ===
    /// Block height where seal was created
    pub block_height: u64,
    /// Timestamp of seal creation (Unix epoch milliseconds)
    pub timestamp: u64,
    /// Address that requested the computation
    pub requester: Address,
    /// Validators who verified the computation
    pub validators: Vec<Address>,

    // === Audit Fields ===
    /// Purpose description (e.g., "credit_scoring", "fraud_detection")
    pub purpose: String,
    /// Compliance frameworks satisfied
    pub compliance_frameworks: Vec<String>,
    /// Data residency region (ISO 3166-1 alpha-2)
    pub data_residency: Option<String>,
    /// Seal status
    pub status: SealStatus,
}

impl DigitalSeal {
    /// Create a new seal builder
    pub fn builder(job_id: JobId) -> SealBuilder {
        SealBuilder::new(job_id)
    }

    /// Compute seal ID from contents
    pub fn compute_id(&self) -> SealId {
        let mut data = Vec::new();
        data.extend_from_slice(self.job_id.as_bytes());
        data.extend_from_slice(self.model_commitment.as_bytes());
        data.extend_from_slice(self.input_commitment.as_bytes());
        data.extend_from_slice(self.output_commitment.as_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        SealId::from_hash(sha256(&data))
    }

    /// Verify seal ID matches computed value
    pub fn verify_id(&self) -> bool {
        self.id == self.compute_id()
    }

    /// Check if seal is finalized
    pub fn is_finalized(&self) -> bool {
        self.status == SealStatus::Finalized
    }

    /// Check if seal has valid evidence
    pub fn has_valid_evidence(&self) -> bool {
        match &self.evidence {
            SealEvidence::TeeOnly { attestations } => !attestations.is_empty(),
            SealEvidence::ZkmlOnly { proof, .. } => !proof.is_empty(),
            SealEvidence::Hybrid {
                attestations,
                zkml_proof,
                ..
            } => !attestations.is_empty() && !zkml_proof.is_empty(),
        }
    }

    /// Get minimum required attestations for validity
    pub fn min_attestations(&self) -> usize {
        match &self.evidence {
            SealEvidence::TeeOnly { attestations } => attestations.len().min(2),
            SealEvidence::ZkmlOnly { .. } => 0,
            SealEvidence::Hybrid {
                min_attestations, ..
            } => *min_attestations as usize,
        }
    }

    /// Serialize seal for storage
    pub fn to_bytes(&self) -> Vec<u8> {
        // Simplified serialization for MVP
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.extend_from_slice(self.id.as_bytes());
        bytes.extend_from_slice(self.job_id.as_bytes());
        bytes.extend_from_slice(self.model_commitment.as_bytes());
        bytes.extend_from_slice(self.input_commitment.as_bytes());
        bytes.extend_from_slice(self.output_commitment.as_bytes());
        bytes.extend_from_slice(&self.block_height.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.requester.serialize());
        bytes.push(self.status as u8);
        bytes
    }

    /// Generate audit report
    pub fn audit_report(&self) -> SealAuditReport {
        SealAuditReport {
            seal_id: self.id,
            job_id: self.job_id,
            model_hash: self.model_commitment.to_hex(),
            input_hash: self.input_commitment.to_hex(),
            output_hash: self.output_commitment.to_hex(),
            verification_method: self.evidence.method_name(),
            validator_count: self.validators.len(),
            validators: self.validators.iter().map(|v| v.to_string()).collect(),
            block_height: self.block_height,
            timestamp: self.timestamp,
            purpose: self.purpose.clone(),
            compliance_frameworks: self.compliance_frameworks.clone(),
            data_residency: self.data_residency.clone(),
            status: format!("{:?}", self.status),
        }
    }
}

/// Evidence types for seal verification
#[derive(Debug, Clone)]
pub enum SealEvidence {
    /// TEE-only verification
    TeeOnly {
        /// TEE attestations from validators
        attestations: Vec<TeeAttestation>,
    },
    /// zkML-only verification
    ZkmlOnly {
        /// Zero-knowledge proof
        proof: Vec<u8>,
        /// Verifying key hash
        verifying_key_hash: Hash256,
        /// Public inputs
        public_inputs: Vec<u8>,
    },
    /// Hybrid verification (TEE + zkML)
    Hybrid {
        /// TEE attestations
        attestations: Vec<TeeAttestation>,
        /// zkML proof
        zkml_proof: Vec<u8>,
        /// Verifying key hash
        verifying_key_hash: Hash256,
        /// Minimum attestations required
        min_attestations: u32,
    },
}

impl SealEvidence {
    /// Get verification method name
    pub fn method_name(&self) -> &'static str {
        match self {
            Self::TeeOnly { .. } => "TEE-only",
            Self::ZkmlOnly { .. } => "zkML-only",
            Self::Hybrid { .. } => "Hybrid (TEE + zkML)",
        }
    }
}

/// TEE attestation from a validator
#[derive(Debug, Clone)]
pub struct TeeAttestation {
    /// Validator address
    pub validator: Address,
    /// TEE platform type
    pub platform: TeePlatform,
    /// Attestation document (AWS Nitro, SGX quote, etc.)
    pub attestation_doc: Vec<u8>,
    /// Platform-specific measurements
    pub measurements: TeeMeasurements,
    /// Signature over (job_id || output_hash || timestamp)
    pub signature: Vec<u8>,
    /// Attestation timestamp
    pub timestamp: u64,
}

/// Supported TEE platforms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TeePlatform {
    /// AWS Nitro Enclaves
    AwsNitro = 0x01,
    /// Intel SGX
    IntelSgx = 0x02,
    /// AMD SEV-SNP
    AmdSev = 0x03,
    /// ARM TrustZone
    ArmTrustzone = 0x04,
}

impl TeePlatform {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::AwsNitro),
            0x02 => Some(Self::IntelSgx),
            0x03 => Some(Self::AmdSev),
            0x04 => Some(Self::ArmTrustzone),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::AwsNitro => "AWS Nitro Enclaves",
            Self::IntelSgx => "Intel SGX",
            Self::AmdSev => "AMD SEV-SNP",
            Self::ArmTrustzone => "ARM TrustZone",
        }
    }
}

/// TEE platform-specific measurements
#[derive(Debug, Clone)]
pub struct TeeMeasurements {
    /// Platform identifier
    pub platform: TeePlatform,
    /// Enclave/image hash
    pub enclave_hash: Hash256,
    /// PCR values (for SGX/SEV)
    pub pcr_values: Option<Vec<Hash256>>,
    /// Signer identity
    pub signer_id: Option<Hash256>,
}

/// Seal audit report (human/machine readable)
#[derive(Debug, Clone)]
pub struct SealAuditReport {
    pub seal_id: SealId,
    pub job_id: JobId,
    pub model_hash: String,
    pub input_hash: String,
    pub output_hash: String,
    pub verification_method: &'static str,
    pub validator_count: usize,
    pub validators: Vec<String>,
    pub block_height: u64,
    pub timestamp: u64,
    pub purpose: String,
    pub compliance_frameworks: Vec<String>,
    pub data_residency: Option<String>,
    pub status: String,
}

impl SealAuditReport {
    /// Export to JSON
    pub fn to_json(&self) -> String {
        format!(
            r#"{{
  "seal_id": "{}",
  "job_id": "{}",
  "model_hash": "{}",
  "input_hash": "{}",
  "output_hash": "{}",
  "verification_method": "{}",
  "validator_count": {},
  "validators": {:?},
  "block_height": {},
  "timestamp": {},
  "purpose": "{}",
  "compliance_frameworks": {:?},
  "data_residency": {:?},
  "status": "{}"
}}"#,
            self.seal_id,
            self.job_id,
            self.model_hash,
            self.input_hash,
            self.output_hash,
            self.verification_method,
            self.validator_count,
            self.validators,
            self.block_height,
            self.timestamp,
            self.purpose,
            self.compliance_frameworks,
            self.data_residency,
            self.status
        )
    }
}

/// Builder for creating digital seals
pub struct SealBuilder {
    job_id: JobId,
    model_commitment: Hash256,
    input_commitment: Hash256,
    output_commitment: Hash256,
    evidence: Option<SealEvidence>,
    requester: Address,
    validators: Vec<Address>,
    purpose: String,
    compliance_frameworks: Vec<String>,
    data_residency: Option<String>,
}

impl SealBuilder {
    /// Create new builder
    pub fn new(job_id: JobId) -> Self {
        Self {
            job_id,
            model_commitment: Hash256::ZERO,
            input_commitment: Hash256::ZERO,
            output_commitment: Hash256::ZERO,
            evidence: None,
            requester: Address::ZERO,
            validators: Vec::new(),
            purpose: String::new(),
            compliance_frameworks: Vec::new(),
            data_residency: None,
        }
    }

    /// Set model commitment
    pub fn model_commitment(mut self, hash: Hash256) -> Self {
        self.model_commitment = hash;
        self
    }

    /// Set input commitment
    pub fn input_commitment(mut self, hash: Hash256) -> Self {
        self.input_commitment = hash;
        self
    }

    /// Set output commitment
    pub fn output_commitment(mut self, hash: Hash256) -> Self {
        self.output_commitment = hash;
        self
    }

    /// Set verification evidence
    pub fn evidence(mut self, evidence: SealEvidence) -> Self {
        self.evidence = Some(evidence);
        self
    }

    /// Set requester
    pub fn requester(mut self, requester: Address) -> Self {
        self.requester = requester;
        self
    }

    /// Add validator
    pub fn add_validator(mut self, validator: Address) -> Self {
        self.validators.push(validator);
        self
    }

    /// Set purpose
    pub fn purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = purpose.into();
        self
    }

    /// Add compliance framework
    pub fn add_compliance(mut self, framework: impl Into<String>) -> Self {
        self.compliance_frameworks.push(framework.into());
        self
    }

    /// Set data residency
    pub fn data_residency(mut self, region: impl Into<String>) -> Self {
        self.data_residency = Some(region.into());
        self
    }

    /// Build the seal
    pub fn build(self, block_height: u64) -> Result<DigitalSeal, &'static str> {
        let evidence = self.evidence.ok_or("Evidence required")?;

        let timestamp_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let timestamp = timestamp_millis.min(u64::MAX as u128) as u64;

        let mut seal = DigitalSeal {
            id: SealId::from_hash(Hash256::ZERO), // Placeholder
            version: 1,
            job_id: self.job_id,
            model_commitment: self.model_commitment,
            input_commitment: self.input_commitment,
            output_commitment: self.output_commitment,
            evidence,
            block_height,
            timestamp,
            requester: self.requester,
            validators: self.validators,
            purpose: self.purpose,
            compliance_frameworks: self.compliance_frameworks,
            data_residency: self.data_residency,
            status: SealStatus::Finalized,
        };

        // Compute actual seal ID
        seal.id = seal.compute_id();

        Ok(seal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_seal() -> DigitalSeal {
        let job_id = JobId::from_hash(sha256(b"test job"));

        DigitalSeal::builder(job_id)
            .model_commitment(sha256(b"model"))
            .input_commitment(sha256(b"input"))
            .output_commitment(sha256(b"output"))
            .evidence(SealEvidence::TeeOnly {
                attestations: vec![],
            })
            .purpose("test")
            .build(100)
            .unwrap()
    }

    #[test]
    fn test_seal_creation() {
        let seal = create_test_seal();
        assert!(seal.verify_id());
        assert!(seal.is_finalized());
    }

    #[test]
    fn test_seal_id_uniqueness() {
        let job_id = JobId::from_hash(sha256(b"test job"));

        let seal1 = DigitalSeal::builder(job_id)
            .model_commitment(sha256(b"model"))
            .input_commitment(sha256(b"input"))
            .output_commitment(sha256(b"output"))
            .evidence(SealEvidence::TeeOnly {
                attestations: vec![],
            })
            .build(100)
            .unwrap();

        // Different creation time should produce different IDs.
        std::thread::sleep(std::time::Duration::from_millis(10));

        let seal2 = DigitalSeal::builder(job_id)
            .model_commitment(sha256(b"model"))
            .input_commitment(sha256(b"input"))
            .output_commitment(sha256(b"output"))
            .evidence(SealEvidence::TeeOnly {
                attestations: vec![],
            })
            .build(100)
            .unwrap();

        // IDs differ due to millisecond timestamp input to ID derivation.
        assert_ne!(seal1.id, seal2.id);
    }

    #[test]
    fn test_audit_report() {
        let seal = create_test_seal();
        let report = seal.audit_report();

        assert_eq!(report.verification_method, "TEE-only");
        assert_eq!(report.purpose, "test");
    }

    #[test]
    fn test_evidence_method_names() {
        assert_eq!(
            SealEvidence::TeeOnly {
                attestations: vec![]
            }
            .method_name(),
            "TEE-only"
        );
        assert_eq!(
            SealEvidence::ZkmlOnly {
                proof: vec![],
                verifying_key_hash: Hash256::ZERO,
                public_inputs: vec![]
            }
            .method_name(),
            "zkML-only"
        );
    }

    #[test]
    fn test_tee_platform() {
        assert_eq!(TeePlatform::AwsNitro.name(), "AWS Nitro Enclaves");
        assert_eq!(TeePlatform::from_byte(0x01), Some(TeePlatform::AwsNitro));
        assert_eq!(TeePlatform::from_byte(0xFF), None);
    }
}
