//! # Project Helix-Guard: Sovereign Genomics Types
//!
//! Enterprise-grade type definitions for sovereign genomics collaboration
//! between M42 Health (UAE) and global pharmaceutical partners.
//!
//! ## Core Concepts
//!
//! - **Sovereign Data**: Genomic data that must never leave its jurisdiction
//! - **Blind Compute**: Computation where neither party sees the other's raw data
//! - **Efficacy Proof**: Cryptographic attestation of drug-genome interaction results
//!
//! ## Data Sovereignty Model
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────────────────┐
//! │                    HELIX-GUARD DATA SOVEREIGNTY MODEL                                    │
//! ├─────────────────────────────────────────────────────────────────────────────────────────┤
//! │                                                                                          │
//! │   ┌───────────────────────────────────────┐  ┌───────────────────────────────────────┐  │
//! │   │        M42 SOVEREIGN VAULT            │  │      PHARMA IP VAULT                  │  │
//! │   │        (Abu Dhabi, UAE)               │  │      (London/Boston)                  │  │
//! │   │                                       │  │                                       │  │
//! │   │  ┌─────────────────────────────────┐  │  │  ┌─────────────────────────────────┐  │  │
//! │   │  │ Emirati Genome Program          │  │  │  │ Drug Molecule Formula           │  │  │
//! │   │  │ • 100,000+ sequenced genomes    │  │  │  │ • Proprietary compounds         │  │  │
//! │   │  │ • Population-specific variants  │  │  │  │ • Clinical trial data           │  │  │
//! │   │  │ • Disease markers               │  │  │  │ • Efficacy predictions          │  │  │
//! │   │  └─────────────────────────────────┘  │  │  └─────────────────────────────────┘  │  │
//! │   │              │                        │  │              │                        │  │
//! │   │              │ DATA POINTER ONLY      │  │              │ ENCRYPTED UPLOAD       │  │
//! │   │              ▼                        │  │              ▼                        │  │
//! │   └──────────────┼────────────────────────┘  └──────────────┼────────────────────────┘  │
//! │                  │                                          │                           │
//! │                  └──────────────────┬───────────────────────┘                           │
//! │                                     │                                                   │
//! │                                     ▼                                                   │
//! │   ┌─────────────────────────────────────────────────────────────────────────────────┐  │
//! │   │                    AETHELRED TEE ENCLAVE (Intel SGX / AWS Nitro)                 │  │
//! │   │                                                                                  │  │
//! │   │   ┌──────────────────────────────────────────────────────────────────────────┐  │  │
//! │   │   │                         Med42 LLM Inference                               │  │  │
//! │   │   │                                                                           │  │  │
//! │   │   │   Input: [Genome Markers] + [Drug Structure]                             │  │  │
//! │   │   │   Output: Efficacy Score (0-100%)                                        │  │  │
//! │   │   │                                                                           │  │  │
//! │   │   │   ⚠️ RAM-Only Processing: Data NEVER touches disk                        │  │  │
//! │   │   │   ⚠️ Memory Encryption: Hardware-enforced isolation                      │  │  │
//! │   │   │                                                                           │  │  │
//! │   │   └──────────────────────────────────────────────────────────────────────────┘  │  │
//! │   │                                     │                                            │  │
//! │   │                                     ▼                                            │  │
//! │   │   ┌──────────────────────────────────────────────────────────────────────────┐  │  │
//! │   │   │                    Cryptographic Output                                   │  │  │
//! │   │   │                                                                           │  │  │
//! │   │   │   • Efficacy Score: 87% ± 3%                                             │  │  │
//! │   │   │   • Confidence Level: HIGH                                               │  │  │
//! │   │   │   • TEE Attestation: 0x7f3a...                                           │  │  │
//! │   │   │   • zkML Proof: [Optional]                                               │  │  │
//! │   │   │                                                                           │  │  │
//! │   │   └──────────────────────────────────────────────────────────────────────────┘  │  │
//! │   │                                                                                  │  │
//! │   └─────────────────────────────────────────────────────────────────────────────────┘  │
//! │                                                                                          │
//! └─────────────────────────────────────────────────────────────────────────────────────────┘
//! ```

use std::collections::HashMap;
use std::fmt;

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// TYPE ALIASES
// =============================================================================

/// 32-byte cryptographic hash (serde-compatible via serde_arrays feature)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash(#[serde(with = "serde_arrays")] pub [u8; 32]);

impl Default for Hash {
    fn default() -> Self {
        Self([0u8; 32])
    }
}

impl std::ops::Deref for Hash {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Hash {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<[u8; 32]> for Hash {
    fn from(arr: [u8; 32]) -> Self {
        Self(arr)
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// 64-byte signature
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Signature(#[serde(with = "serde_arrays")] pub [u8; 64]);

impl Default for Signature {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl std::ops::Deref for Signature {
    type Target = [u8; 64];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Signature {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<[u8; 64]> for Signature {
    fn from(arr: [u8; 64]) -> Self {
        Self(arr)
    }
}

/// Variable-length proof bytes
pub type ProofBytes = Vec<u8>;

/// Decentralized identifier
pub type Did = String;

/// Token amount (18 decimals)
pub type TokenAmount = u128;

// =============================================================================
// GENOMICS DATA TYPES
// =============================================================================

/// Genomic data cohort
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenomeCohort {
    /// Unique cohort identifier
    pub id: Uuid,
    /// Decentralized identifier (DID)
    pub did: Did,
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: String,
    /// Number of individuals in cohort
    pub population_size: u32,
    /// Data custodian organization
    pub custodian: DataCustodian,
    /// Sovereignty constraints
    pub sovereignty: SovereigntyConstraints,
    /// Available genetic markers
    pub available_markers: Vec<GeneticMarkerType>,
    /// Data quality metrics
    pub quality_metrics: DataQualityMetrics,
    /// Access control
    pub access_policy: AccessPolicy,
    /// Audit trail
    pub audit_log: Vec<AuditEntry>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated
    pub updated_at: DateTime<Utc>,
}

impl GenomeCohort {
    /// Create the Emirati Genome Program cohort (M42's flagship dataset)
    pub fn emirati_genome_program() -> Self {
        Self {
            id: Uuid::new_v4(),
            did: "did:m42:genome:emirati_program_v2".to_string(),
            name: "Emirati Genome Program".to_string(),
            description: "Comprehensive genomic sequencing of UAE national population, \
                         including rare disease markers and pharmacogenomic variants"
                .to_string(),
            population_size: 100_000,
            custodian: DataCustodian::m42(),
            sovereignty: SovereigntyConstraints::uae_genome_program(),
            available_markers: vec![
                GeneticMarkerType::Snp,
                GeneticMarkerType::Indel,
                GeneticMarkerType::Cnv,
                GeneticMarkerType::StructuralVariant,
                GeneticMarkerType::Pharmacogenomic,
                GeneticMarkerType::DiseaseAssociated,
            ],
            quality_metrics: DataQualityMetrics {
                sequencing_depth: 30.0,
                coverage_percentage: 99.5,
                variant_calling_accuracy: 99.9,
                annotation_completeness: 98.0,
                last_qc_date: Utc::now(),
            },
            access_policy: AccessPolicy {
                requires_ethics_approval: true,
                requires_doh_approval: true,
                requires_data_agreement: true,
                allowed_use_cases: vec![
                    UseCase::DrugDiscovery,
                    UseCase::RareDiseaseResearch,
                    UseCase::PrecisionMedicine,
                    UseCase::PublicHealth,
                ],
                prohibited_use_cases: vec![
                    UseCase::Insurance,
                    UseCase::Employment,
                    UseCase::LawEnforcement,
                ],
                minimum_aggregation_size: 100, // Minimum cohort size for queries
            },
            audit_log: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// Create a reference pointer (no data transfer)
    pub fn create_reference(&self) -> GenomeDataReference {
        GenomeDataReference {
            did: self.did.clone(),
            cohort_id: self.id,
            custodian_node: self.custodian.node_id.clone(),
            sovereignty_tag: self.sovereignty.compliance_standard,
            reference_hash: self.compute_reference_hash(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
        }
    }

    /// Compute reference hash (for integrity verification)
    fn compute_reference_hash(&self) -> Hash {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.did.as_bytes());
        hasher.update(&self.population_size.to_le_bytes());
        hasher.update(self.custodian.node_id.as_bytes());
        let result = hasher.finalize();
        let mut hash = Hash::default();
        hash.0.copy_from_slice(&result);
        hash
    }
}

/// Reference to genomic data (pointer, not actual data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenomeDataReference {
    /// DID of the referenced cohort
    pub did: Did,
    /// Cohort UUID
    pub cohort_id: Uuid,
    /// Node ID of data custodian
    pub custodian_node: String,
    /// Sovereignty compliance tag
    pub sovereignty_tag: ComplianceStandard,
    /// Hash of reference (for integrity)
    pub reference_hash: Hash,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Expiry timestamp
    pub expires_at: DateTime<Utc>,
}

/// Types of genetic markers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GeneticMarkerType {
    /// Single Nucleotide Polymorphism
    Snp,
    /// Insertion/Deletion
    Indel,
    /// Copy Number Variation
    Cnv,
    /// Structural Variant
    StructuralVariant,
    /// Pharmacogenomic markers (drug response)
    Pharmacogenomic,
    /// Disease-associated variants
    DiseaseAssociated,
    /// Ancestry informative markers
    AncestryInformative,
    /// Expression quantitative trait loci
    Eqtl,
}

impl GeneticMarkerType {
    /// Get clinical relevance score (1-10)
    pub fn clinical_relevance(&self) -> u8 {
        match self {
            Self::Pharmacogenomic => 10,
            Self::DiseaseAssociated => 9,
            Self::Cnv => 7,
            Self::StructuralVariant => 7,
            Self::Indel => 6,
            Self::Snp => 5,
            Self::Eqtl => 4,
            Self::AncestryInformative => 2,
        }
    }
}

/// Data quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataQualityMetrics {
    /// Average sequencing depth (e.g., 30x)
    pub sequencing_depth: f64,
    /// Genome coverage percentage
    pub coverage_percentage: f64,
    /// Variant calling accuracy percentage
    pub variant_calling_accuracy: f64,
    /// Annotation completeness percentage
    pub annotation_completeness: f64,
    /// Last quality control date
    pub last_qc_date: DateTime<Utc>,
}

// =============================================================================
// DATA CUSTODIAN & SOVEREIGNTY
// =============================================================================

/// Data custodian organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataCustodian {
    /// Organization ID
    pub id: Uuid,
    /// Organization name
    pub name: String,
    /// Legal entity identifier
    pub lei: Option<String>,
    /// Headquarters jurisdiction
    pub jurisdiction: Jurisdiction,
    /// Aethelred node ID
    pub node_id: String,
    /// TEE capabilities
    pub tee_capabilities: Vec<TeeType>,
    /// Certifications held
    pub certifications: Vec<Certification>,
    /// Contact information
    pub contact: ContactInfo,
}

impl DataCustodian {
    /// M42 Health (Abu Dhabi)
    pub fn m42() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: "M42 Health".to_string(),
            lei: Some("549300M42HEALTH0001".to_string()),
            jurisdiction: Jurisdiction::Uae,
            node_id: "m42-sovereign-node-1".to_string(),
            tee_capabilities: vec![TeeType::IntelSgx, TeeType::AwsNitro, TeeType::ArmTrustZone],
            certifications: vec![
                Certification::Iso27001,
                Certification::HipaaCompliant,
                Certification::DoHApproved,
                Certification::UaeDataResidency,
            ],
            contact: ContactInfo {
                department: "Omics Centre of Excellence".to_string(),
                email: "genomics@m42.ae".to_string(),
                phone: "+971 2 XXX XXXX".to_string(),
            },
        }
    }
}

/// Sovereignty constraints for data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovereigntyConstraints {
    /// Compliance standard
    pub compliance_standard: ComplianceStandard,
    /// Data residency requirement
    pub data_residency: DataResidency,
    /// Processing restrictions
    pub processing_restrictions: Vec<ProcessingRestriction>,
    /// Regulatory bodies with oversight
    pub regulatory_bodies: Vec<RegulatoryBody>,
    /// Export controls
    pub export_controls: ExportControls,
}

impl SovereigntyConstraints {
    /// UAE Genome Program constraints
    pub fn uae_genome_program() -> Self {
        Self {
            compliance_standard: ComplianceStandard::UaeGenomeProgram,
            data_residency: DataResidency {
                required_jurisdiction: Jurisdiction::Uae,
                allowed_processing_regions: vec!["uae-abudhabi-1".to_string()],
                cross_border_allowed: false,
                data_mirroring_allowed: false,
            },
            processing_restrictions: vec![
                ProcessingRestriction::TeeOnly,
                ProcessingRestriction::NoRawDataExport,
                ProcessingRestriction::AggregateOutputOnly,
                ProcessingRestriction::MinimumCohortSize(100),
                ProcessingRestriction::AuditRequired,
            ],
            regulatory_bodies: vec![
                RegulatoryBody::UaeDepartmentOfHealth,
                RegulatoryBody::UaeCentralBank, // For commercial agreements
                RegulatoryBody::EmiratiGenomeProgramBoard,
            ],
            export_controls: ExportControls {
                raw_data_exportable: false,
                aggregate_stats_exportable: true,
                model_outputs_exportable: true,
                requires_doh_approval: true,
                requires_board_approval: true,
            },
        }
    }
}

/// Data residency requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataResidency {
    /// Required jurisdiction for storage
    pub required_jurisdiction: Jurisdiction,
    /// Allowed processing regions
    pub allowed_processing_regions: Vec<String>,
    /// Is cross-border transfer allowed?
    pub cross_border_allowed: bool,
    /// Is data mirroring allowed?
    pub data_mirroring_allowed: bool,
}

/// Processing restrictions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcessingRestriction {
    /// Must be processed in TEE only
    TeeOnly,
    /// No raw data can leave enclave
    NoRawDataExport,
    /// Only aggregate outputs allowed
    AggregateOutputOnly,
    /// Minimum cohort size for queries
    MinimumCohortSize(u32),
    /// Audit trail required
    AuditRequired,
    /// Differential privacy required
    DifferentialPrivacy,
    /// Federated learning only
    FederatedOnly,
}

/// Export controls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportControls {
    /// Can raw data be exported?
    pub raw_data_exportable: bool,
    /// Can aggregate statistics be exported?
    pub aggregate_stats_exportable: bool,
    /// Can model outputs be exported?
    pub model_outputs_exportable: bool,
    /// Requires DoH approval?
    pub requires_doh_approval: bool,
    /// Requires board approval?
    pub requires_board_approval: bool,
}

/// Regulatory bodies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegulatoryBody {
    /// UAE Department of Health
    UaeDepartmentOfHealth,
    /// UAE Central Bank
    UaeCentralBank,
    /// Emirati Genome Program Board
    EmiratiGenomeProgramBoard,
    /// US FDA
    UsFda,
    /// European Medicines Agency
    Ema,
    /// UK MHRA
    UkMhra,
}

// =============================================================================
// PHARMACEUTICAL PARTNER TYPES
// =============================================================================

/// Pharmaceutical partner organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PharmaPartner {
    /// Partner ID
    pub id: Uuid,
    /// Company name
    pub name: String,
    /// LEI
    pub lei: Option<String>,
    /// Headquarters jurisdiction
    pub jurisdiction: Jurisdiction,
    /// Partner tier
    pub tier: PartnerTier,
    /// Areas of research
    pub research_areas: Vec<TherapeuticArea>,
    /// Aethelred node ID
    pub node_id: String,
    /// Contact
    pub contact: ContactInfo,
}

impl PharmaPartner {
    /// AstraZeneca (example partner)
    pub fn astrazeneca() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: "AstraZeneca PLC".to_string(),
            lei: Some("549300AZPLCWKUOEP04".to_string()),
            jurisdiction: Jurisdiction::UnitedKingdom,
            tier: PartnerTier::Strategic,
            research_areas: vec![
                TherapeuticArea::Oncology,
                TherapeuticArea::Cardiovascular,
                TherapeuticArea::Neuroscience,
                TherapeuticArea::Immunology,
            ],
            node_id: "astrazeneca-uk-node-1".to_string(),
            contact: ContactInfo {
                department: "R&D Precision Medicine".to_string(),
                email: "genomics@astrazeneca.com".to_string(),
                phone: "+44 XXX XXXX".to_string(),
            },
        }
    }
}

/// Partner tier level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PartnerTier {
    /// Highest access, lowest fees
    Strategic,
    /// Standard commercial partner
    Commercial,
    /// Academic/research partner
    Academic,
    /// Government/public health
    PublicHealth,
    /// Trial/evaluation access
    Trial,
}

impl PartnerTier {
    /// Get fee multiplier
    pub fn fee_multiplier(&self) -> Decimal {
        match self {
            Self::Strategic => Decimal::new(80, 2),    // 0.80x
            Self::Commercial => Decimal::new(100, 2),  // 1.00x
            Self::Academic => Decimal::new(50, 2),     // 0.50x
            Self::PublicHealth => Decimal::new(25, 2), // 0.25x
            Self::Trial => Decimal::new(0, 0),         // Free
        }
    }
}

/// Therapeutic area
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TherapeuticArea {
    /// Cancer treatments
    Oncology,
    /// Heart and circulatory system
    Cardiovascular,
    /// Brain and nervous system
    Neuroscience,
    /// Immune system disorders
    Immunology,
    /// Metabolic disorders and diabetes
    Metabolic,
    /// Rare and orphan diseases
    RareDisease,
    /// Viral, bacterial, fungal infections
    InfectiousDisease,
    /// Lung and breathing disorders
    Respiratory,
    /// Eye diseases
    Ophthalmology,
    /// Skin conditions
    Dermatology,
}

// =============================================================================
// DRUG CANDIDATE TYPES
// =============================================================================

/// Drug candidate submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrugCandidate {
    /// Candidate ID
    pub id: Uuid,
    /// Internal code name
    pub code_name: String,
    /// Therapeutic area
    pub therapeutic_area: TherapeuticArea,
    /// Target disease/condition
    pub target_condition: String,
    /// Molecular structure (encrypted)
    pub encrypted_structure: EncryptedPayload,
    /// Known pharmacogenomic markers
    pub target_markers: Vec<GeneticMarkerQuery>,
    /// Development phase
    pub development_phase: DevelopmentPhase,
    /// Submitting partner
    pub submitting_partner: Uuid,
    /// Submission timestamp
    pub submitted_at: DateTime<Utc>,
}

/// Encrypted payload (for IP protection)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// Encryption algorithm used
    pub algorithm: EncryptionAlgorithm,
    /// Encrypted data
    pub ciphertext: Vec<u8>,
    /// Initialization vector / nonce
    pub iv: Vec<u8>,
    /// Key derivation info (for TEE to decrypt)
    pub key_info: KeyInfo,
    /// Integrity tag
    pub auth_tag: Vec<u8>,
}

/// Encryption algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM
    Aes256Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
    /// Post-quantum hybrid
    Kyber768Aes256,
}

/// Key derivation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Key type
    pub key_type: KeyType,
    /// Public key or key ID
    pub public_key_or_id: Vec<u8>,
    /// Derivation parameters
    pub derivation_params: Option<String>,
}

/// Key type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// Ephemeral ECDH key
    EphemeralEcdh,
    /// TEE-sealed key
    TeeSealed,
    /// HSM-backed key
    HsmBacked,
}

/// Genetic marker query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneticMarkerQuery {
    /// Marker type
    pub marker_type: GeneticMarkerType,
    /// Gene/region identifier (e.g., "CYP2D6")
    pub gene_id: String,
    /// Specific variant (e.g., "rs1234567")
    pub variant_id: Option<String>,
    /// Query type
    pub query_type: MarkerQueryType,
}

/// Marker query type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MarkerQueryType {
    /// Check presence/absence
    Presence,
    /// Get allele frequency
    AlleleFrequency,
    /// Get genotype distribution
    GenotypeDistribution,
    /// Association analysis
    AssociationAnalysis,
}

/// Drug development phase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DevelopmentPhase {
    /// Discovery/preclinical
    Preclinical,
    /// Phase 1 clinical trials
    Phase1,
    /// Phase 2 clinical trials
    Phase2,
    /// Phase 3 clinical trials
    Phase3,
    /// Regulatory submission
    Submission,
    /// Approved/marketed
    Approved,
}

// =============================================================================
// TEE & COMPUTATION TYPES
// =============================================================================

/// TEE enclave type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TeeType {
    /// Intel Software Guard Extensions
    IntelSgx,
    /// AWS Nitro Enclaves
    AwsNitro,
    /// AMD Secure Encrypted Virtualization
    AmdSev,
    /// ARM TrustZone
    ArmTrustZone,
    /// NVIDIA Confidential Computing
    NvidiaH100Tee,
}

impl TeeType {
    /// Get attestation method
    pub fn attestation_method(&self) -> AttestationMethod {
        match self {
            Self::IntelSgx => AttestationMethod::EpidOrDcap,
            Self::AwsNitro => AttestationMethod::NsmAttestation,
            Self::AmdSev => AttestationMethod::SevSnpAttestation,
            Self::ArmTrustZone => AttestationMethod::PsaAttestation,
            Self::NvidiaH100Tee => AttestationMethod::NvidiaAttestation,
        }
    }
}

/// Attestation method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationMethod {
    /// Intel EPID or DCAP
    EpidOrDcap,
    /// AWS Nitro Security Module
    NsmAttestation,
    /// AMD SEV-SNP
    SevSnpAttestation,
    /// ARM Platform Security Architecture
    PsaAttestation,
    /// NVIDIA GPU attestation
    NvidiaAttestation,
}

/// Blind computation job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindComputeJob {
    /// Job ID
    pub id: Uuid,
    /// Job type
    pub job_type: ComputeJobType,
    /// Status
    pub status: JobStatus,
    /// Data custodian reference
    pub genome_reference: GenomeDataReference,
    /// Pharma partner submission
    pub drug_candidate_id: Uuid,
    /// AI model to use
    pub model_config: ModelConfig,
    /// SLA requirements
    pub sla: ServiceLevelAgreement,
    /// TEE requirements
    pub tee_requirements: TeeRequirements,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Started at
    pub started_at: Option<DateTime<Utc>>,
    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
    /// Result (if completed)
    pub result: Option<EfficacyResult>,
}

/// Compute job type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComputeJobType {
    /// Drug efficacy prediction
    EfficacyPrediction,
    /// Pharmacogenomic analysis
    PharmacogenomicAnalysis,
    /// Adverse event prediction
    AdverseEventPrediction,
    /// Biomarker discovery
    BiomarkerDiscovery,
    /// Population stratification
    PopulationStratification,
    /// Disease association
    DiseaseAssociation,
}

/// Job status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JobStatus {
    /// Queued
    Queued,
    /// Initializing TEE
    InitializingTee,
    /// Loading data
    LoadingData,
    /// Running inference
    RunningInference,
    /// Generating proof
    GeneratingProof,
    /// Completed
    Completed,
    /// Failed
    Failed,
    /// Cancelled
    Cancelled,
}

/// AI model configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    /// Model ID
    pub model_id: String,
    /// Model version
    pub version: String,
    /// Model type
    pub model_type: ModelType,
    /// Model hash (for integrity)
    pub model_hash: Hash,
    /// Required GPU type
    pub gpu_requirement: Option<GpuRequirement>,
}

impl ModelConfig {
    /// Med42 clinical LLM (M42's flagship model)
    pub fn med42_clinical() -> Self {
        let model_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"med42-70b-clinical-v2.0");
            let result = hasher.finalize();
            let mut hash = Hash::default();
            hash.0.copy_from_slice(&result);
            hash
        };

        Self {
            model_id: "med42-70b-clinical".to_string(),
            version: "2.0.0".to_string(),
            model_type: ModelType::ClinicalLlm,
            model_hash,
            gpu_requirement: Some(GpuRequirement::NvidiaH100),
        }
    }
}

/// Model type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModelType {
    /// Large language model for clinical use
    ClinicalLlm,
    /// Genomic sequence model
    GenomicSequence,
    /// Drug-target interaction model
    DrugTargetInteraction,
    /// ADMET prediction model
    AdmetPrediction,
    /// Ensemble model
    Ensemble,
}

/// GPU requirement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GpuRequirement {
    /// NVIDIA H100 (TEE-capable)
    NvidiaH100,
    /// NVIDIA A100
    NvidiaA100,
    /// NVIDIA H200
    NvidiaH200,
    /// Any NVIDIA Hopper+
    NvidiaHopperPlus,
}

/// TEE requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeRequirements {
    /// Required TEE type
    pub tee_type: TeeType,
    /// Memory encryption required
    pub memory_encryption: bool,
    /// RAM-only processing (no disk)
    pub ram_only: bool,
    /// Attestation required
    pub attestation_required: bool,
    /// Minimum enclave memory (GB)
    pub min_enclave_memory_gb: u32,
}

impl TeeRequirements {
    /// Strict TEE requirements for genomic data
    pub fn strict_genomic() -> Self {
        Self {
            tee_type: TeeType::NvidiaH100Tee,
            memory_encryption: true,
            ram_only: true,
            attestation_required: true,
            min_enclave_memory_gb: 80, // For large models
        }
    }
}

/// Service level agreement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceLevelAgreement {
    /// Maximum processing time (seconds)
    pub max_processing_time_secs: u64,
    /// Privacy level
    pub privacy_level: PrivacyLevel,
    /// Output visibility
    pub output_visibility: OutputVisibility,
    /// Minimum confidence threshold
    pub min_confidence: u8,
    /// Audit requirements
    pub audit_level: AuditLevel,
}

impl ServiceLevelAgreement {
    /// Default SLA for genomic analysis
    pub fn genomic_analysis() -> Self {
        Self {
            max_processing_time_secs: 300, // 5 minutes
            privacy_level: PrivacyLevel::TeeStrict,
            output_visibility: OutputVisibility::AggregateOnly,
            min_confidence: 85,
            audit_level: AuditLevel::Full,
        }
    }
}

/// Privacy level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrivacyLevel {
    /// Standard encryption
    Standard,
    /// TEE-only processing
    TeeStrict,
    /// TEE + zero-knowledge proofs
    TeeWithZk,
    /// Multi-party computation
    Mpc,
}

/// Output visibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OutputVisibility {
    /// Full output (if allowed)
    Full,
    /// Aggregate statistics only
    AggregateOnly,
    /// Binary yes/no only
    BinaryOnly,
    /// Score within range only
    ScoreRangeOnly,
}

/// Audit level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditLevel {
    /// Minimal logging
    Minimal,
    /// Standard logging
    Standard,
    /// Full audit trail
    Full,
    /// Immutable blockchain audit
    Blockchain,
}

// =============================================================================
// RESULT TYPES
// =============================================================================

/// Efficacy analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EfficacyResult {
    /// Result ID
    pub id: Uuid,
    /// Job ID
    pub job_id: Uuid,
    /// Efficacy score (0-100)
    pub efficacy_score: u8,
    /// Score confidence interval
    pub confidence_interval: ConfidenceInterval,
    /// Confidence level
    pub confidence_level: ConfidenceLevel,
    /// Population coverage
    pub population_coverage: PopulationCoverage,
    /// Key findings (sanitized)
    pub findings: Vec<Finding>,
    /// Cryptographic attestation
    pub attestation: TeeAttestation,
    /// Optional zkML proof
    pub zkml_proof: Option<ZkmlProof>,
    /// Royalty payment
    pub royalty_payment: RoyaltyPayment,
    /// Timestamp
    pub generated_at: DateTime<Utc>,
}

/// Confidence interval
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    /// Lower bound
    pub lower: f64,
    /// Upper bound
    pub upper: f64,
    /// Confidence level (e.g., 95%)
    pub level: u8,
}

/// Confidence level category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    /// Very high confidence (>95%)
    VeryHigh,
    /// High confidence (85-95%)
    High,
    /// Medium confidence (70-85%)
    Medium,
    /// Low confidence (50-70%)
    Low,
    /// Insufficient data
    Insufficient,
}

/// Population coverage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopulationCoverage {
    /// Total individuals analyzed
    pub total_analyzed: u32,
    /// Individuals with relevant markers
    pub with_markers: u32,
    /// Coverage percentage
    pub coverage_percent: f64,
    /// Subpopulation breakdown (anonymized)
    pub subpopulations: HashMap<String, u32>,
}

/// Finding from analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Finding ID
    pub id: Uuid,
    /// Category
    pub category: FindingCategory,
    /// Significance level
    pub significance: SignificanceLevel,
    /// Description (sanitized, no PII)
    pub description: String,
    /// Clinical relevance
    pub clinical_relevance: ClinicalRelevance,
}

/// Finding category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingCategory {
    /// Positive efficacy signal
    PositiveEfficacy,
    /// Negative efficacy signal
    NegativeEfficacy,
    /// Safety concern
    SafetyConcern,
    /// Population-specific effect
    PopulationSpecific,
    /// Dose-response relationship
    DoseResponse,
    /// Biomarker correlation
    BiomarkerCorrelation,
}

/// Significance level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignificanceLevel {
    /// Highly significant (p < 0.001)
    HighlySignificant,
    /// Significant (p < 0.01)
    Significant,
    /// Marginally significant (p < 0.05)
    Marginal,
    /// Not significant
    NotSignificant,
}

/// Clinical relevance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClinicalRelevance {
    /// High clinical relevance
    High,
    /// Moderate clinical relevance
    Moderate,
    /// Low clinical relevance
    Low,
    /// Research interest only
    ResearchOnly,
}

// =============================================================================
// ATTESTATION & PROOF TYPES
// =============================================================================

/// TEE attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeAttestation {
    /// Attestation ID
    pub id: Uuid,
    /// TEE type
    pub tee_type: TeeType,
    /// Attestation quote/report
    pub attestation_quote: Vec<u8>,
    /// Enclave measurement
    pub enclave_measurement: Hash,
    /// Signer identity
    pub signer_id: Vec<u8>,
    /// Platform info
    pub platform_info: PlatformInfo,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Signature
    pub signature: Signature,
}

/// Platform information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    /// CPU/TEE version
    pub version: String,
    /// Security level
    pub security_level: u8,
    /// Firmware version
    pub firmware_version: String,
    /// Region
    pub region: String,
}

/// zkML proof (optional additional verification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkmlProof {
    /// Proof ID
    pub id: Uuid,
    /// Proof system used
    pub proof_system: ZkProofSystem,
    /// Proof bytes
    pub proof_bytes: ProofBytes,
    /// Public inputs
    pub public_inputs: Vec<u8>,
    /// Verifying key hash
    pub vk_hash: Hash,
    /// Circuit hash
    pub circuit_hash: Hash,
    /// Generation time (ms)
    pub generation_time_ms: u64,
}

/// ZK proof system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZkProofSystem {
    /// EZKL for ML models
    Ezkl,
    /// Groth16
    Groth16,
    /// Plonk
    Plonk,
    /// Halo2
    Halo2,
}

// =============================================================================
// ROYALTY & PAYMENT TYPES
// =============================================================================

/// Royalty payment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoyaltyPayment {
    /// Payment ID
    pub id: Uuid,
    /// Recipient (data custodian)
    pub recipient: Uuid,
    /// Payer (pharma partner)
    pub payer: Uuid,
    /// Amount in AETHEL tokens
    pub amount_aethel: TokenAmount,
    /// Amount in USD equivalent
    pub amount_usd: Decimal,
    /// Payment status
    pub status: PaymentStatus,
    /// Transaction hash (if on-chain)
    pub tx_hash: Option<Hash>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Payment status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PaymentStatus {
    /// Pending
    Pending,
    /// Processing
    Processing,
    /// Confirmed
    Confirmed,
    /// Failed
    Failed,
    /// Refunded
    Refunded,
}

// =============================================================================
// COMMON TYPES
// =============================================================================

/// Jurisdiction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Jurisdiction {
    /// United Arab Emirates
    Uae,
    /// United Kingdom
    UnitedKingdom,
    /// United States
    UnitedStates,
    /// European Union
    EuropeanUnion,
    /// Singapore
    Singapore,
    /// Saudi Arabia
    SaudiArabia,
    /// Switzerland
    Switzerland,
    /// Japan
    Japan,
}

impl fmt::Display for Jurisdiction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uae => write!(f, "United Arab Emirates"),
            Self::UnitedKingdom => write!(f, "United Kingdom"),
            Self::UnitedStates => write!(f, "United States"),
            Self::EuropeanUnion => write!(f, "European Union"),
            Self::Singapore => write!(f, "Singapore"),
            Self::SaudiArabia => write!(f, "Saudi Arabia"),
            Self::Switzerland => write!(f, "Switzerland"),
            Self::Japan => write!(f, "Japan"),
        }
    }
}

/// Compliance standard
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceStandard {
    /// UAE Genome Program specific
    UaeGenomeProgram,
    /// UAE Data Residency Law
    UaeDataResidency,
    /// UAE Department of Health
    UaeDoh,
    /// HIPAA (US)
    Hipaa,
    /// GDPR (EU)
    Gdpr,
    /// Singapore PDPA
    SingaporePdpa,
}

/// Certification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Certification {
    /// ISO 27001
    Iso27001,
    /// ISO 13485 (Medical Devices)
    Iso13485,
    /// HIPAA Compliant
    HipaaCompliant,
    /// SOC 2 Type II
    Soc2TypeIi,
    /// UAE DoH Approved
    DoHApproved,
    /// UAE Data Residency
    UaeDataResidency,
    /// GxP Compliant
    GxpCompliant,
}

/// Use case categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UseCase {
    /// Drug discovery research
    DrugDiscovery,
    /// Rare disease research
    RareDiseaseResearch,
    /// Precision medicine
    PrecisionMedicine,
    /// Public health initiatives
    PublicHealth,
    /// Insurance underwriting (prohibited)
    Insurance,
    /// Employment screening (prohibited)
    Employment,
    /// Law enforcement (prohibited)
    LawEnforcement,
}

/// Access policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    /// Requires ethics approval
    pub requires_ethics_approval: bool,
    /// Requires DoH approval
    pub requires_doh_approval: bool,
    /// Requires data agreement
    pub requires_data_agreement: bool,
    /// Allowed use cases
    pub allowed_use_cases: Vec<UseCase>,
    /// Prohibited use cases
    pub prohibited_use_cases: Vec<UseCase>,
    /// Minimum aggregation size
    pub minimum_aggregation_size: u32,
}

/// Contact information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    /// Department
    pub department: String,
    /// Email
    pub email: String,
    /// Phone
    pub phone: String,
}

/// Audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Entry ID
    pub id: Uuid,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Action
    pub action: AuditAction,
    /// Actor
    pub actor: String,
    /// Actor jurisdiction
    pub actor_jurisdiction: Jurisdiction,
    /// Description
    pub description: String,
    /// Data hash
    pub data_hash: Option<Hash>,
}

/// Audit action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditAction {
    /// Resource created
    Created,
    /// Resource accessed
    Accessed,
    /// Data queried
    Queried,
    /// Resource modified
    Modified,
    /// Data exported
    Exported,
    /// Resource deleted
    Deleted,
    /// Request approved
    Approved,
    /// Request rejected
    Rejected,
    /// Computation performed
    Computed,
    /// Proof verified
    Verified,
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emirati_genome_program() {
        let cohort = GenomeCohort::emirati_genome_program();
        assert_eq!(cohort.population_size, 100_000);
        assert_eq!(cohort.custodian.jurisdiction, Jurisdiction::Uae);
        assert!(!cohort.sovereignty.data_residency.cross_border_allowed);
    }

    #[test]
    fn test_genome_reference() {
        let cohort = GenomeCohort::emirati_genome_program();
        let reference = cohort.create_reference();
        assert_eq!(
            reference.sovereignty_tag,
            ComplianceStandard::UaeGenomeProgram
        );
        assert!(!reference.reference_hash.0.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_pharma_partner() {
        let partner = PharmaPartner::astrazeneca();
        assert_eq!(partner.jurisdiction, Jurisdiction::UnitedKingdom);
        assert_eq!(partner.tier, PartnerTier::Strategic);
    }

    #[test]
    fn test_med42_config() {
        let config = ModelConfig::med42_clinical();
        assert_eq!(config.model_id, "med42-70b-clinical");
        assert_eq!(config.gpu_requirement, Some(GpuRequirement::NvidiaH100));
    }

    #[test]
    fn test_tee_requirements() {
        let reqs = TeeRequirements::strict_genomic();
        assert!(reqs.memory_encryption);
        assert!(reqs.ram_only);
        assert!(reqs.attestation_required);
    }

    #[test]
    fn test_partner_tier_fees() {
        assert!(PartnerTier::Strategic.fee_multiplier() < PartnerTier::Commercial.fee_multiplier());
        assert!(PartnerTier::Academic.fee_multiplier() < PartnerTier::Commercial.fee_multiplier());
    }
}
