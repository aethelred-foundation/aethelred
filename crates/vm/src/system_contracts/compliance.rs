//! Compliance Module - On-Chain Regulatory Enforcer
//!
//! This module implements the regulatory "moat" feature that allows the chain
//! to reject valid transactions if they violate regulatory rules. It enforces
//! GDPR, HIPAA, and OFAC sanctions at the protocol level.
//!
//! # Architecture
//!
//! The ComplianceModule operates as a pre-execution filter:
//! 1. Before any job submission, the compliance check runs
//! 2. Transactions failing compliance are rejected with clear error codes
//! 3. All compliance decisions are logged for audit trails
//!
//! # Supported Standards
//!
//! - **GDPR (EU)**: Data residency, right to erasure, consent verification
//! - **HIPAA (US)**: PHI handling, covered entity verification, BAA requirements
//! - **OFAC Sanctions**: Blocked addresses, sanctioned jurisdictions
//!
//! # Enterprise Features
//!
//! - Bloom filter for O(1) sanctions checking
//! - DID-based entity certification
//! - Jurisdiction mapping with granular rules
//! - Compliance attestation expiry tracking
//! - Audit log generation for regulators

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use super::error::{Result, SystemContractError};
use super::events::{ComplianceEvent, EventLog};
use super::types::{Address, Hash, TokenAmount, ZERO_ADDRESS};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of compliance standards that can be required for a job
pub const MAX_REQUIRED_STANDARDS: usize = 8;

/// Maximum number of certifications per entity
pub const MAX_CERTIFICATIONS_PER_ENTITY: usize = 32;

/// Bloom filter size for sanctions list (in bits)
pub const SANCTIONS_BLOOM_SIZE: usize = 1 << 20; // ~1M bits = 128KB

/// Number of hash functions for bloom filter
pub const SANCTIONS_BLOOM_HASHES: usize = 7;

/// Default certification validity period (365 days)
pub const DEFAULT_CERTIFICATION_VALIDITY: u64 = 365 * 24 * 60 * 60;

/// Grace period after certification expiry (30 days)
pub const CERTIFICATION_GRACE_PERIOD: u64 = 30 * 24 * 60 * 60;

// ============================================================================
// Compliance Standards
// ============================================================================

/// Regulatory compliance standards supported by the protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ComplianceStandard {
    /// EU General Data Protection Regulation
    /// Requires: Data residency in EU, consent tracking, erasure support
    GdprEu = 1,

    /// US Health Insurance Portability and Accountability Act
    /// Requires: Covered entity certification, BAA, PHI encryption
    HipaaUs = 2,

    /// US Office of Foreign Assets Control Sanctions
    /// Requires: Address not on sanctions list, jurisdiction checks
    OfacSanctions = 3,

    /// California Consumer Privacy Act
    /// Requires: Consumer consent, data deletion support
    CcpaCa = 4,

    /// Singapore Personal Data Protection Act
    /// Requires: Consent, data portability
    PdpaSg = 5,

    /// UAE Data Protection Law
    /// Requires: Data localization for sensitive data
    UaeDpl = 6,

    /// Basel III Financial Regulations
    /// Requires: Capital adequacy, risk assessment
    BaselIii = 7,

    /// Anti-Money Laundering
    /// Requires: KYC verification, transaction monitoring
    Aml = 8,
}

impl ComplianceStandard {
    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::GdprEu => "GDPR (EU)",
            Self::HipaaUs => "HIPAA (US)",
            Self::OfacSanctions => "OFAC Sanctions",
            Self::CcpaCa => "CCPA (California)",
            Self::PdpaSg => "PDPA (Singapore)",
            Self::UaeDpl => "UAE Data Protection",
            Self::BaselIii => "Basel III",
            Self::Aml => "AML",
        }
    }

    /// Get jurisdiction code
    pub fn jurisdiction(&self) -> &'static str {
        match self {
            Self::GdprEu => "EU",
            Self::HipaaUs => "US",
            Self::OfacSanctions => "US",
            Self::CcpaCa => "US-CA",
            Self::PdpaSg => "SG",
            Self::UaeDpl => "AE",
            Self::BaselIii => "INTL",
            Self::Aml => "INTL",
        }
    }

    /// Check if this standard requires entity certification
    pub fn requires_certification(&self) -> bool {
        matches!(
            self,
            Self::GdprEu | Self::HipaaUs | Self::CcpaCa | Self::PdpaSg | Self::UaeDpl
        )
    }

    /// Check if this standard involves sanctions screening
    pub fn involves_sanctions(&self) -> bool {
        matches!(self, Self::OfacSanctions | Self::Aml)
    }

    /// Get minimum certification level required (1-5)
    pub fn min_certification_level(&self) -> u8 {
        match self {
            Self::HipaaUs => 4, // Highest for PHI
            Self::OfacSanctions => 3,
            Self::BaselIii => 4,
            Self::Aml => 3,
            _ => 2,
        }
    }

    /// Convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::GdprEu),
            2 => Some(Self::HipaaUs),
            3 => Some(Self::OfacSanctions),
            4 => Some(Self::CcpaCa),
            5 => Some(Self::PdpaSg),
            6 => Some(Self::UaeDpl),
            7 => Some(Self::BaselIii),
            8 => Some(Self::Aml),
            _ => None,
        }
    }

    /// Convert from ComplianceRequirement type
    pub fn from_requirement(req: super::types::ComplianceRequirement) -> Self {
        match req {
            super::types::ComplianceRequirement::GdprEu => Self::GdprEu,
            super::types::ComplianceRequirement::HipaaUs => Self::HipaaUs,
            super::types::ComplianceRequirement::OfacSanctions => Self::OfacSanctions,
            super::types::ComplianceRequirement::CcpaCa => Self::CcpaCa,
            super::types::ComplianceRequirement::PdpaSg => Self::PdpaSg,
            super::types::ComplianceRequirement::UaeDpl => Self::UaeDpl,
            super::types::ComplianceRequirement::BaselIii => Self::BaselIii,
            super::types::ComplianceRequirement::Aml => Self::Aml,
        }
    }
}

// ============================================================================
// Compliance Violation Types
// ============================================================================

/// Types of compliance violations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationType {
    /// Entity not certified for required standard
    MissingCertification {
        standard: ComplianceStandard,
        entity: Address,
    },

    /// Certification has expired
    ExpiredCertification {
        standard: ComplianceStandard,
        entity: Address,
        expired_at: u64,
    },

    /// Address is on sanctions list
    SanctionedAddress { address: Address, list_name: String },

    /// Jurisdiction not allowed for operation
    JurisdictionBlocked {
        jurisdiction: String,
        reason: String,
    },

    /// Data residency requirement violated
    DataResidencyViolation {
        required_region: String,
        actual_region: String,
    },

    /// Consent not obtained
    MissingConsent {
        data_subject: Address,
        purpose: String,
    },

    /// Business Associate Agreement missing
    MissingBaa {
        covered_entity: Address,
        business_associate: Address,
    },

    /// Transaction exceeds AML threshold without verification
    AmlThresholdExceeded {
        amount: TokenAmount,
        threshold: TokenAmount,
    },

    /// KYC verification required but not present
    KycRequired { entity: Address, level_required: u8 },
}

impl ViolationType {
    /// Get error code for this violation
    pub fn error_code(&self) -> u32 {
        match self {
            Self::MissingCertification { .. } => 5001,
            Self::ExpiredCertification { .. } => 5002,
            Self::SanctionedAddress { .. } => 5003,
            Self::JurisdictionBlocked { .. } => 5004,
            Self::DataResidencyViolation { .. } => 5005,
            Self::MissingConsent { .. } => 5006,
            Self::MissingBaa { .. } => 5007,
            Self::AmlThresholdExceeded { .. } => 5008,
            Self::KycRequired { .. } => 5009,
        }
    }

    /// Check if violation is fatal (cannot proceed)
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::SanctionedAddress { .. }
                | Self::JurisdictionBlocked { .. }
                | Self::MissingCertification {
                    standard: ComplianceStandard::HipaaUs,
                    ..
                }
        )
    }
}

// ============================================================================
// Compliance Check Result
// ============================================================================

/// Result of a compliance check
#[derive(Debug, Clone)]
pub struct ComplianceCheckResult {
    /// Whether the check passed
    pub passed: bool,

    /// List of violations found (empty if passed)
    pub violations: Vec<ViolationType>,

    /// Standards that were checked
    pub standards_checked: Vec<ComplianceStandard>,

    /// Timestamp of the check
    pub checked_at: u64,

    /// Unique check ID for audit trail
    pub check_id: Hash,

    /// Risk score (0-100, lower is better)
    pub risk_score: u8,

    /// Warnings (non-fatal issues)
    pub warnings: Vec<String>,
}

impl ComplianceCheckResult {
    /// Create a passing result
    pub fn pass(standards: Vec<ComplianceStandard>, check_id: Hash, timestamp: u64) -> Self {
        Self {
            passed: true,
            violations: Vec::new(),
            standards_checked: standards,
            checked_at: timestamp,
            check_id,
            risk_score: 0,
            warnings: Vec::new(),
        }
    }

    /// Create a failing result
    pub fn fail(
        violations: Vec<ViolationType>,
        standards: Vec<ComplianceStandard>,
        check_id: Hash,
        timestamp: u64,
    ) -> Self {
        let risk_score = Self::calculate_risk_score(&violations);
        Self {
            passed: false,
            violations,
            standards_checked: standards,
            checked_at: timestamp,
            check_id,
            risk_score,
            warnings: Vec::new(),
        }
    }

    /// Calculate risk score based on violations
    fn calculate_risk_score(violations: &[ViolationType]) -> u8 {
        let mut score: u32 = 0;
        for v in violations {
            score += match v {
                ViolationType::SanctionedAddress { .. } => 100,
                ViolationType::JurisdictionBlocked { .. } => 80,
                ViolationType::MissingCertification {
                    standard: ComplianceStandard::HipaaUs,
                    ..
                } => 90,
                ViolationType::MissingCertification { .. } => 50,
                ViolationType::ExpiredCertification { .. } => 30,
                ViolationType::AmlThresholdExceeded { .. } => 70,
                ViolationType::KycRequired { .. } => 40,
                _ => 20,
            };
        }
        std::cmp::min(score, 100) as u8
    }

    /// Add a warning
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    /// Check if result has fatal violations
    pub fn has_fatal_violations(&self) -> bool {
        self.violations.iter().any(|v| v.is_fatal())
    }
}

// ============================================================================
// Entity Certification
// ============================================================================

/// Decentralized Identifier (DID) for entity identification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did {
    /// DID method (e.g., "aethelred", "web", "key")
    pub method: String,

    /// Method-specific identifier
    pub identifier: String,
}

impl Did {
    /// Create a new DID
    pub fn new(method: impl Into<String>, identifier: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            identifier: identifier.into(),
        }
    }

    /// Create an Aethelred chain DID from address
    pub fn from_address(address: &Address) -> Self {
        Self {
            method: "aethelred".to_string(),
            identifier: hex::encode(address),
        }
    }

    /// Get full DID string
    pub fn to_string(&self) -> String {
        format!("did:{}:{}", self.method, self.identifier)
    }

    /// Parse from string
    pub fn from_string(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() >= 3 && parts[0] == "did" {
            Some(Self {
                method: parts[1].to_string(),
                identifier: parts[2..].join(":"),
            })
        } else {
            None
        }
    }
}

/// Certification record for an entity
#[derive(Debug, Clone)]
pub struct Certification {
    /// Standard this certification is for
    pub standard: ComplianceStandard,

    /// Certified entity's DID
    pub entity_did: Did,

    /// Entity's on-chain address
    pub entity_address: Address,

    /// Certifying authority
    pub issuer: Did,

    /// Certification level (1-5, higher = more trust)
    pub level: u8,

    /// When certification was issued
    pub issued_at: u64,

    /// When certification expires
    pub expires_at: u64,

    /// Certification document hash (off-chain reference)
    pub document_hash: Hash,

    /// Additional metadata
    pub metadata: HashMap<String, String>,

    /// Whether certification has been revoked
    pub revoked: bool,

    /// Revocation reason (if revoked)
    pub revocation_reason: Option<String>,
}

impl Certification {
    /// Check if certification is currently valid
    pub fn is_valid(&self, current_time: u64) -> bool {
        !self.revoked && current_time < self.expires_at
    }

    /// Check if in grace period
    pub fn in_grace_period(&self, current_time: u64) -> bool {
        !self.revoked
            && current_time >= self.expires_at
            && current_time < self.expires_at + CERTIFICATION_GRACE_PERIOD
    }

    /// Get remaining validity in seconds
    pub fn remaining_validity(&self, current_time: u64) -> Option<u64> {
        if self.is_valid(current_time) {
            Some(self.expires_at - current_time)
        } else {
            None
        }
    }
}

// ============================================================================
// Bloom Filter for Sanctions
// ============================================================================

/// Bloom filter for O(1) sanctions checking
#[derive(Clone)]
pub struct SanctionsBloomFilter {
    /// Bit array
    bits: Vec<u64>,

    /// Number of hash functions
    num_hashes: usize,

    /// Number of items added
    count: usize,
}

impl SanctionsBloomFilter {
    /// Create a new bloom filter
    pub fn new() -> Self {
        let num_words = SANCTIONS_BLOOM_SIZE / 64;
        Self {
            bits: vec![0u64; num_words],
            num_hashes: SANCTIONS_BLOOM_HASHES,
            count: 0,
        }
    }

    /// Add an address to the filter
    pub fn add(&mut self, address: &Address) {
        let hashes = self.compute_hashes(address);
        for h in hashes {
            let word_idx = h / 64;
            let bit_idx = h % 64;
            self.bits[word_idx] |= 1u64 << bit_idx;
        }
        self.count += 1;
    }

    /// Check if an address might be in the filter
    /// Returns false if definitely not in filter
    /// Returns true if possibly in filter (may be false positive)
    pub fn possibly_contains(&self, address: &Address) -> bool {
        let hashes = self.compute_hashes(address);
        for h in hashes {
            let word_idx = h / 64;
            let bit_idx = h % 64;
            if (self.bits[word_idx] & (1u64 << bit_idx)) == 0 {
                return false;
            }
        }
        true
    }

    /// Compute hash values for an address
    fn compute_hashes(&self, address: &Address) -> Vec<usize> {
        use sha2::{Digest, Sha256};

        let mut hashes = Vec::with_capacity(self.num_hashes);
        let mut hasher = Sha256::new();
        hasher.update(address);
        let base_hash = hasher.finalize();

        // Use double hashing to generate k hash functions
        let h1 = u64::from_be_bytes(base_hash[0..8].try_into().unwrap()) as usize;
        let h2 = u64::from_be_bytes(base_hash[8..16].try_into().unwrap()) as usize;

        for i in 0..self.num_hashes {
            let h = (h1.wrapping_add(i.wrapping_mul(h2))) % SANCTIONS_BLOOM_SIZE;
            hashes.push(h);
        }

        hashes
    }

    /// Get estimated false positive rate
    pub fn false_positive_rate(&self) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        let m = SANCTIONS_BLOOM_SIZE as f64;
        let n = self.count as f64;
        let k = self.num_hashes as f64;
        (1.0 - (-k * n / m).exp()).powf(k)
    }

    /// Get number of items added
    pub fn count(&self) -> usize {
        self.count
    }

    /// Clear the filter
    pub fn clear(&mut self) {
        self.bits.fill(0);
        self.count = 0;
    }
}

impl Default for SanctionsBloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SanctionsBloomFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SanctionsBloomFilter")
            .field("size_bits", &SANCTIONS_BLOOM_SIZE)
            .field("num_hashes", &self.num_hashes)
            .field("count", &self.count)
            .field(
                "false_positive_rate",
                &format!("{:.6}", self.false_positive_rate()),
            )
            .finish()
    }
}

// ============================================================================
// Jurisdiction Configuration
// ============================================================================

/// Configuration for a specific jurisdiction
#[derive(Debug, Clone)]
pub struct JurisdictionConfig {
    /// Jurisdiction code (ISO 3166-1 alpha-2)
    pub code: String,

    /// Human-readable name
    pub name: String,

    /// Whether this jurisdiction is blocked entirely
    pub blocked: bool,

    /// Reason for blocking (if blocked)
    pub block_reason: Option<String>,

    /// Required standards for operations in this jurisdiction
    pub required_standards: Vec<ComplianceStandard>,

    /// Data residency requirements
    pub data_residency: Option<DataResidencyRule>,

    /// Maximum transaction amount without enhanced due diligence
    pub aml_threshold: TokenAmount,

    /// Risk level (1-5)
    pub risk_level: u8,
}

/// Data residency rule
#[derive(Debug, Clone)]
pub struct DataResidencyRule {
    /// Allowed regions for data storage
    pub allowed_regions: Vec<String>,

    /// Whether data must not leave the jurisdiction
    pub strict_localization: bool,

    /// Types of data subject to this rule
    pub data_types: Vec<String>,
}

// ============================================================================
// Consent Management
// ============================================================================

/// Consent record for data processing
#[derive(Debug, Clone)]
pub struct ConsentRecord {
    /// Data subject (whose data is being processed)
    pub data_subject: Address,

    /// Data controller (who is processing)
    pub data_controller: Address,

    /// Purposes for which consent was given
    pub purposes: Vec<String>,

    /// When consent was given
    pub given_at: u64,

    /// When consent expires (None = until revoked)
    pub expires_at: Option<u64>,

    /// Whether consent has been revoked
    pub revoked: bool,

    /// Revocation timestamp
    pub revoked_at: Option<u64>,

    /// Proof of consent (e.g., signature hash)
    pub proof: Hash,
}

impl ConsentRecord {
    /// Check if consent is currently valid for a purpose
    pub fn is_valid_for(&self, purpose: &str, current_time: u64) -> bool {
        if self.revoked {
            return false;
        }
        if let Some(expires) = self.expires_at {
            if current_time >= expires {
                return false;
            }
        }
        self.purposes.iter().any(|p| p == purpose || p == "*")
    }
}

// ============================================================================
// Compliance Module Configuration
// ============================================================================

/// Configuration for the compliance module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    /// Whether compliance is enabled
    pub enabled: bool,

    /// Default standards required for all jobs
    pub default_standards: Vec<ComplianceStandard>,

    /// Whether to enforce sanctions screening
    pub enforce_sanctions: bool,

    /// Whether to allow grace period for expired certifications
    pub allow_grace_period: bool,

    /// Trusted certification issuers
    pub trusted_issuers: Vec<Did>,

    /// AML threshold for enhanced due diligence
    pub aml_threshold: TokenAmount,

    /// Risk score threshold for rejection (0-100)
    pub risk_threshold: u8,

    /// Whether to log all compliance checks
    pub audit_logging: bool,

    /// Maximum certifications to cache
    pub certification_cache_size: usize,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self::mainnet()
    }
}

impl ComplianceConfig {
    /// Mainnet configuration (strict)
    pub fn mainnet() -> Self {
        Self {
            enabled: true,
            default_standards: vec![ComplianceStandard::OfacSanctions],
            enforce_sanctions: true,
            allow_grace_period: false,
            trusted_issuers: Vec::new(),
            aml_threshold: 10_000_000_000_000, // 10,000 tokens
            risk_threshold: 50,
            audit_logging: true,
            certification_cache_size: 10_000,
        }
    }

    /// Testnet configuration (relaxed)
    pub fn testnet() -> Self {
        Self {
            enabled: true,
            default_standards: vec![],
            enforce_sanctions: false,
            allow_grace_period: true,
            trusted_issuers: Vec::new(),
            aml_threshold: u128::MAX,
            risk_threshold: 80,
            audit_logging: true,
            certification_cache_size: 1_000,
        }
    }

    /// Devnet configuration (minimal)
    pub fn devnet() -> Self {
        Self {
            enabled: false,
            default_standards: vec![],
            enforce_sanctions: false,
            allow_grace_period: true,
            trusted_issuers: Vec::new(),
            aml_threshold: u128::MAX,
            risk_threshold: 100,
            audit_logging: false,
            certification_cache_size: 100,
        }
    }

    /// Validate config invariants.
    pub fn validate(&self) -> Result<()> {
        if self.risk_threshold > 100 {
            return Err(SystemContractError::InvalidConfig(
                "risk_threshold must be between 0 and 100".to_string(),
            ));
        }
        if self.certification_cache_size == 0 {
            return Err(SystemContractError::InvalidConfig(
                "certification_cache_size must be > 0".to_string(),
            ));
        }
        Ok(())
    }
}

// ============================================================================
// Compliance Module
// ============================================================================

/// The Compliance Module - On-Chain Regulatory Enforcer
///
/// This is the "moat" feature that distinguishes Aethelred from other chains.
/// It allows the protocol to reject valid transactions that violate regulatory
/// rules, making it suitable for regulated industries like healthcare and finance.
pub struct ComplianceModule {
    /// Configuration
    config: ComplianceConfig,

    /// Certified entities by address
    certifications: HashMap<Address, Vec<Certification>>,

    /// Sanctions bloom filter for O(1) checking
    sanctions_bloom: SanctionsBloomFilter,

    /// Confirmed sanctioned addresses (for bloom filter false positives)
    sanctioned_addresses: HashSet<Address>,

    /// Jurisdiction configurations
    jurisdictions: HashMap<String, JurisdictionConfig>,

    /// Consent records (data_subject -> records)
    consents: HashMap<Address, Vec<ConsentRecord>>,

    /// Business Associate Agreements (covered_entity -> associates)
    baas: HashMap<Address, HashSet<Address>>,

    /// Compliance check history for audit
    audit_log: Vec<EventLog>,

    /// Current timestamp
    current_time: u64,

    /// Check counter for unique IDs
    check_counter: u64,
}

impl ComplianceModule {
    /// Create a new compliance module
    pub fn new(config: ComplianceConfig) -> Self {
        let mut module = Self {
            config,
            certifications: HashMap::new(),
            sanctions_bloom: SanctionsBloomFilter::new(),
            sanctioned_addresses: HashSet::new(),
            jurisdictions: HashMap::new(),
            consents: HashMap::new(),
            baas: HashMap::new(),
            audit_log: Vec::new(),
            current_time: 0,
            check_counter: 0,
        };

        // Initialize default jurisdictions
        module.init_default_jurisdictions();

        module
    }

    /// Initialize default jurisdiction configurations
    fn init_default_jurisdictions(&mut self) {
        // United States
        self.jurisdictions.insert(
            "US".to_string(),
            JurisdictionConfig {
                code: "US".to_string(),
                name: "United States".to_string(),
                blocked: false,
                block_reason: None,
                required_standards: vec![ComplianceStandard::OfacSanctions],
                data_residency: None,
                aml_threshold: 10_000_000_000_000,
                risk_level: 1,
            },
        );

        // European Union (placeholder - would have each member state)
        self.jurisdictions.insert(
            "EU".to_string(),
            JurisdictionConfig {
                code: "EU".to_string(),
                name: "European Union".to_string(),
                blocked: false,
                block_reason: None,
                required_standards: vec![ComplianceStandard::GdprEu],
                data_residency: Some(DataResidencyRule {
                    allowed_regions: vec!["EU".to_string(), "EEA".to_string()],
                    strict_localization: false,
                    data_types: vec!["PII".to_string(), "sensitive".to_string()],
                }),
                aml_threshold: 15_000_000_000_000,
                risk_level: 1,
            },
        );

        // UAE
        self.jurisdictions.insert(
            "AE".to_string(),
            JurisdictionConfig {
                code: "AE".to_string(),
                name: "United Arab Emirates".to_string(),
                blocked: false,
                block_reason: None,
                required_standards: vec![ComplianceStandard::UaeDpl],
                data_residency: Some(DataResidencyRule {
                    allowed_regions: vec!["AE".to_string(), "GCC".to_string()],
                    strict_localization: true,
                    data_types: vec!["government".to_string(), "financial".to_string()],
                }),
                aml_threshold: 50_000_000_000_000,
                risk_level: 1,
            },
        );

        // Singapore
        self.jurisdictions.insert(
            "SG".to_string(),
            JurisdictionConfig {
                code: "SG".to_string(),
                name: "Singapore".to_string(),
                blocked: false,
                block_reason: None,
                required_standards: vec![ComplianceStandard::PdpaSg],
                data_residency: None,
                aml_threshold: 20_000_000_000_000,
                risk_level: 1,
            },
        );

        // North Korea (blocked)
        self.jurisdictions.insert(
            "KP".to_string(),
            JurisdictionConfig {
                code: "KP".to_string(),
                name: "North Korea".to_string(),
                blocked: true,
                block_reason: Some("OFAC comprehensive sanctions".to_string()),
                required_standards: vec![],
                data_residency: None,
                aml_threshold: 0,
                risk_level: 5,
            },
        );

        // Iran (blocked)
        self.jurisdictions.insert(
            "IR".to_string(),
            JurisdictionConfig {
                code: "IR".to_string(),
                name: "Iran".to_string(),
                blocked: true,
                block_reason: Some("OFAC comprehensive sanctions".to_string()),
                required_standards: vec![],
                data_residency: None,
                aml_threshold: 0,
                risk_level: 5,
            },
        );
    }

    /// Update the current timestamp
    pub fn update_time(&mut self, timestamp: u64) {
        self.current_time = timestamp;
    }

    // ========================================================================
    // Certification Management
    // ========================================================================

    /// Add a certification for an entity
    pub fn add_certification(&mut self, cert: Certification) -> Result<()> {
        // Verify issuer is trusted
        if !self.config.trusted_issuers.is_empty()
            && !self.config.trusted_issuers.contains(&cert.issuer)
        {
            return Err(SystemContractError::Compliance(format!(
                "Issuer {} is not trusted",
                cert.issuer.to_string()
            )));
        }

        // Verify certification is not expired
        if cert.expires_at <= self.current_time {
            return Err(SystemContractError::Compliance(
                "Certification has already expired".to_string(),
            ));
        }

        // Verify minimum level
        let min_level = cert.standard.min_certification_level();
        if cert.level < min_level {
            return Err(SystemContractError::Compliance(format!(
                "Certification level {} is below minimum {} for {}",
                cert.level,
                min_level,
                cert.standard.name()
            )));
        }

        let entity = cert.entity_address;
        let standard = cert.standard as u8;
        let expires_at = cert.expires_at;

        // Update storage first in a limited scope to avoid borrow conflicts with event emission.
        {
            let certs = self.certifications.entry(entity).or_default();

            // Check max certifications
            if certs.len() >= MAX_CERTIFICATIONS_PER_ENTITY {
                return Err(SystemContractError::Compliance(format!(
                    "Entity has maximum {} certifications",
                    MAX_CERTIFICATIONS_PER_ENTITY
                )));
            }

            // Remove any existing certification for the same standard
            certs.retain(|c| c.standard != cert.standard);
            certs.push(cert);
        }

        // Add new certification event
        let event = ComplianceEvent::CertificationAdded {
            entity,
            standard,
            expires_at,
        };
        self.emit_event(event);
        Ok(())
    }

    /// Revoke a certification
    pub fn revoke_certification(
        &mut self,
        entity: Address,
        standard: ComplianceStandard,
        reason: String,
    ) -> Result<()> {
        {
            let certs = self
                .certifications
                .get_mut(&entity)
                .ok_or_else(|| SystemContractError::Compliance("Entity not found".to_string()))?;

            let cert = certs
                .iter_mut()
                .find(|c| c.standard == standard)
                .ok_or_else(|| {
                    SystemContractError::Compliance("Certification not found".to_string())
                })?;

            cert.revoked = true;
            cert.revocation_reason = Some(reason.clone());
        }

        let event = ComplianceEvent::CertificationRevoked {
            entity,
            certification: standard.name().to_string(),
            reason,
            revoker: ZERO_ADDRESS,
            block_height: 0,
        };
        self.emit_event(event);

        Ok(())
    }

    /// Get certifications for an entity
    pub fn get_certifications(&self, entity: &Address) -> Option<&Vec<Certification>> {
        self.certifications.get(entity)
    }

    /// Check if entity has valid certification for a standard
    pub fn has_valid_certification(&self, entity: &Address, standard: ComplianceStandard) -> bool {
        if let Some(certs) = self.certifications.get(entity) {
            certs.iter().any(|c| {
                c.standard == standard
                    && (c.is_valid(self.current_time)
                        || (self.config.allow_grace_period && c.in_grace_period(self.current_time)))
            })
        } else {
            false
        }
    }

    // ========================================================================
    // Sanctions Management
    // ========================================================================

    /// Add an address to the sanctions list
    pub fn add_sanctioned_address(&mut self, address: Address, list_name: String) -> Result<()> {
        self.sanctions_bloom.add(&address);
        self.sanctioned_addresses.insert(address);

        let event = ComplianceEvent::AddressSanctioned {
            address,
            list: list_name,
        };
        self.emit_event(event);

        Ok(())
    }

    /// Remove an address from sanctions list
    pub fn remove_sanctioned_address(&mut self, address: Address) -> Result<()> {
        // Note: We can't remove from bloom filter, only from confirmed set
        // This means the bloom filter will have false positives for removed addresses
        self.sanctioned_addresses.remove(&address);

        let event = ComplianceEvent::AddressUnsanctioned { address };
        self.emit_event(event);

        Ok(())
    }

    /// Check if an address is sanctioned
    pub fn is_sanctioned(&self, address: &Address) -> bool {
        // First check bloom filter for O(1) rejection of definitely-not-sanctioned
        if !self.sanctions_bloom.possibly_contains(address) {
            return false;
        }

        // If bloom filter says maybe, check the confirmed set
        self.sanctioned_addresses.contains(address)
    }

    /// Bulk add sanctioned addresses (efficient for large lists)
    pub fn bulk_add_sanctioned(&mut self, addresses: Vec<Address>, list_name: &str) {
        for addr in addresses {
            self.sanctions_bloom.add(&addr);
            self.sanctioned_addresses.insert(addr);
        }

        let event = ComplianceEvent::SanctionsListUpdated {
            list: list_name.to_string(),
            count: self.sanctioned_addresses.len() as u32,
        };
        self.emit_event(event);
    }

    // ========================================================================
    // Consent Management (GDPR/CCPA)
    // ========================================================================

    /// Record consent from a data subject
    pub fn record_consent(&mut self, consent: ConsentRecord) -> Result<()> {
        let consents = self.consents.entry(consent.data_subject).or_default();

        // Check if there's existing consent for same controller
        if let Some(existing) = consents
            .iter_mut()
            .find(|c| c.data_controller == consent.data_controller && !c.revoked)
        {
            // Merge purposes
            for purpose in &consent.purposes {
                if !existing.purposes.contains(purpose) {
                    existing.purposes.push(purpose.clone());
                }
            }
            existing.given_at = consent.given_at;
            existing.expires_at = consent.expires_at;
            existing.proof = consent.proof;
        } else {
            consents.push(consent);
        }

        Ok(())
    }

    /// Revoke consent
    pub fn revoke_consent(
        &mut self,
        data_subject: Address,
        data_controller: Address,
    ) -> Result<()> {
        let consents = self.consents.get_mut(&data_subject).ok_or_else(|| {
            SystemContractError::Compliance("No consent records found".to_string())
        })?;

        let consent = consents
            .iter_mut()
            .find(|c| c.data_controller == data_controller && !c.revoked)
            .ok_or_else(|| {
                SystemContractError::Compliance("Active consent not found".to_string())
            })?;

        consent.revoked = true;
        consent.revoked_at = Some(self.current_time);

        let event = ComplianceEvent::ConsentRevoked {
            data_subject,
            data_controller,
        };
        self.emit_event(event);

        Ok(())
    }

    /// Check if consent exists for a specific purpose
    pub fn has_consent(
        &self,
        data_subject: &Address,
        data_controller: &Address,
        purpose: &str,
    ) -> bool {
        if let Some(consents) = self.consents.get(data_subject) {
            consents.iter().any(|c| {
                c.data_controller == *data_controller && c.is_valid_for(purpose, self.current_time)
            })
        } else {
            false
        }
    }

    // ========================================================================
    // Business Associate Agreements (HIPAA)
    // ========================================================================

    /// Register a Business Associate Agreement
    pub fn register_baa(
        &mut self,
        covered_entity: Address,
        business_associate: Address,
    ) -> Result<()> {
        // Verify both parties have HIPAA certification
        if !self.has_valid_certification(&covered_entity, ComplianceStandard::HipaaUs) {
            return Err(SystemContractError::Compliance(
                "Covered entity lacks HIPAA certification".to_string(),
            ));
        }

        if !self.has_valid_certification(&business_associate, ComplianceStandard::HipaaUs) {
            return Err(SystemContractError::Compliance(
                "Business associate lacks HIPAA certification".to_string(),
            ));
        }

        let associates = self.baas.entry(covered_entity).or_default();
        associates.insert(business_associate);

        let event = ComplianceEvent::BaaRegistered {
            covered_entity,
            business_associate,
        };
        self.emit_event(event);

        Ok(())
    }

    /// Check if BAA exists between two parties
    pub fn has_baa(&self, covered_entity: &Address, business_associate: &Address) -> bool {
        if let Some(associates) = self.baas.get(covered_entity) {
            associates.contains(business_associate)
        } else {
            false
        }
    }

    // ========================================================================
    // Main Compliance Check
    // ========================================================================

    /// Perform a comprehensive compliance check
    ///
    /// This is the main entry point for compliance enforcement.
    /// It should be called before any job submission.
    pub fn enforce(
        &mut self,
        requester: &Address,
        data_provider: Option<&Address>,
        required_standards: &[ComplianceStandard],
        jurisdiction: Option<&str>,
        amount: TokenAmount,
        metadata: &HashMap<String, String>,
    ) -> Result<ComplianceCheckResult> {
        // Skip if compliance is disabled
        if !self.config.enabled {
            let check_id = self.generate_check_id();
            return Ok(ComplianceCheckResult::pass(
                required_standards.to_vec(),
                check_id,
                self.current_time,
            ));
        }

        let check_id = self.generate_check_id();
        let mut violations = Vec::new();
        let mut warnings = Vec::new();

        // Combine default and required standards
        let mut all_standards: Vec<ComplianceStandard> = self.config.default_standards.clone();
        for std in required_standards {
            if !all_standards.contains(std) {
                all_standards.push(*std);
            }
        }

        // Add jurisdiction-specific standards
        if let Some(jur) = jurisdiction {
            if let Some(jur_config) = self.jurisdictions.get(jur) {
                // Check if jurisdiction is blocked
                if jur_config.blocked {
                    violations.push(ViolationType::JurisdictionBlocked {
                        jurisdiction: jur.to_string(),
                        reason: jur_config
                            .block_reason
                            .clone()
                            .unwrap_or_else(|| "Blocked jurisdiction".to_string()),
                    });
                }

                // Add jurisdiction-required standards
                for std in &jur_config.required_standards {
                    if !all_standards.contains(std) {
                        all_standards.push(*std);
                    }
                }

                // Check AML threshold
                if amount > jur_config.aml_threshold {
                    violations.push(ViolationType::AmlThresholdExceeded {
                        amount,
                        threshold: jur_config.aml_threshold,
                    });
                }
            }
        }

        // 1. Sanctions Check (always first - it's the most critical)
        if self.config.enforce_sanctions {
            if self.is_sanctioned(requester) {
                violations.push(ViolationType::SanctionedAddress {
                    address: *requester,
                    list_name: "OFAC SDN".to_string(),
                });
            }

            if let Some(provider) = data_provider {
                if self.is_sanctioned(provider) {
                    violations.push(ViolationType::SanctionedAddress {
                        address: *provider,
                        list_name: "OFAC SDN".to_string(),
                    });
                }
            }
        }

        // 2. Certification Checks
        for standard in &all_standards {
            if standard.requires_certification() {
                // Check requester
                if !self.has_valid_certification(requester, *standard) {
                    // Check if in grace period
                    if let Some(certs) = self.certifications.get(requester) {
                        if let Some(cert) = certs.iter().find(|c| c.standard == *standard) {
                            if cert.in_grace_period(self.current_time) {
                                warnings.push(format!(
                                    "Certification for {} expires soon",
                                    standard.name()
                                ));
                            } else if !cert.revoked {
                                violations.push(ViolationType::ExpiredCertification {
                                    standard: *standard,
                                    entity: *requester,
                                    expired_at: cert.expires_at,
                                });
                            }
                        } else {
                            violations.push(ViolationType::MissingCertification {
                                standard: *standard,
                                entity: *requester,
                            });
                        }
                    } else {
                        violations.push(ViolationType::MissingCertification {
                            standard: *standard,
                            entity: *requester,
                        });
                    }
                }

                // Check data provider if present
                if let Some(provider) = data_provider {
                    if !self.has_valid_certification(provider, *standard) {
                        violations.push(ViolationType::MissingCertification {
                            standard: *standard,
                            entity: *provider,
                        });
                    }
                }
            }
        }

        // 3. HIPAA-specific checks
        if all_standards.contains(&ComplianceStandard::HipaaUs) {
            if let Some(provider) = data_provider {
                if !self.has_baa(requester, provider) && requester != provider {
                    violations.push(ViolationType::MissingBaa {
                        covered_entity: *requester,
                        business_associate: *provider,
                    });
                }
            }
        }

        // 4. GDPR/CCPA consent checks
        if all_standards.contains(&ComplianceStandard::GdprEu)
            || all_standards.contains(&ComplianceStandard::CcpaCa)
        {
            let purpose = metadata
                .get("purpose")
                .map(|s| s.as_str())
                .unwrap_or("ai_computation");

            if let Some(provider) = data_provider {
                if !self.has_consent(provider, requester, purpose) {
                    violations.push(ViolationType::MissingConsent {
                        data_subject: *provider,
                        purpose: purpose.to_string(),
                    });
                }
            }
        }

        // 5. Data residency checks
        if let Some(jur) = jurisdiction {
            if let Some(jur_config) = self.jurisdictions.get(jur) {
                if let Some(residency) = &jur_config.data_residency {
                    if let Some(data_region) = metadata.get("data_region") {
                        if !residency.allowed_regions.contains(data_region) {
                            violations.push(ViolationType::DataResidencyViolation {
                                required_region: residency.allowed_regions.join(", "),
                                actual_region: data_region.clone(),
                            });
                        }
                    }
                }
            }
        }

        // Build result
        let mut result = if violations.is_empty() {
            ComplianceCheckResult::pass(all_standards, check_id, self.current_time)
        } else {
            ComplianceCheckResult::fail(violations, all_standards, check_id, self.current_time)
        };

        for warning in warnings {
            result.add_warning(warning);
        }

        // Emit event and log
        let event = ComplianceEvent::CheckPerformed {
            check_id,
            requester: *requester,
            passed: result.passed,
            risk_score: result.risk_score,
        };
        self.emit_event(event);

        // Check risk threshold
        if result.risk_score > self.config.risk_threshold {
            result.passed = false;
        }

        Ok(result)
    }

    /// Generate a unique check ID
    fn generate_check_id(&mut self) -> Hash {
        use sha2::{Digest, Sha256};

        self.check_counter += 1;

        let mut hasher = Sha256::new();
        hasher.update(b"compliance-check:");
        hasher.update(self.current_time.to_le_bytes());
        hasher.update(self.check_counter.to_le_bytes());

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Emit a compliance event
    fn emit_event(&mut self, event: ComplianceEvent) {
        if self.config.audit_logging {
            let log = EventLog::new(super::events::SystemEvent::Compliance(event));
            self.audit_log.push(log);
        }
    }

    // ========================================================================
    // Jurisdiction Management
    // ========================================================================

    /// Add or update a jurisdiction configuration
    pub fn set_jurisdiction(&mut self, config: JurisdictionConfig) {
        self.jurisdictions.insert(config.code.clone(), config);
    }

    /// Get jurisdiction configuration
    pub fn get_jurisdiction(&self, code: &str) -> Option<&JurisdictionConfig> {
        self.jurisdictions.get(code)
    }

    /// Check if a jurisdiction is blocked
    pub fn is_jurisdiction_blocked(&self, code: &str) -> bool {
        self.jurisdictions
            .get(code)
            .map(|j| j.blocked)
            .unwrap_or(false)
    }

    // ========================================================================
    // Audit & Statistics
    // ========================================================================

    /// Get audit log
    pub fn get_audit_log(&self) -> &[EventLog] {
        &self.audit_log
    }

    /// Get audit log since a timestamp
    pub fn get_audit_log_since(&self, since: u64) -> Vec<&EventLog> {
        self.audit_log
            .iter()
            .filter(|log| log.timestamp >= since)
            .collect()
    }

    /// Get compliance statistics
    pub fn statistics(&self) -> ComplianceStatistics {
        let total_checks = self.check_counter;

        let passed_checks = self
            .audit_log
            .iter()
            .filter(|log| {
                matches!(
                    &log.event,
                    super::events::SystemEvent::Compliance(ComplianceEvent::CheckPerformed {
                        passed: true,
                        ..
                    })
                )
            })
            .count() as u64;

        ComplianceStatistics {
            total_checks,
            passed_checks,
            failed_checks: total_checks.saturating_sub(passed_checks),
            total_certifications: self.certifications.values().map(|v| v.len()).sum(),
            active_certifications: self
                .certifications
                .values()
                .flat_map(|v| v.iter())
                .filter(|c| c.is_valid(self.current_time))
                .count(),
            sanctioned_addresses: self.sanctioned_addresses.len(),
            bloom_filter_size: SANCTIONS_BLOOM_SIZE,
            bloom_false_positive_rate: self.sanctions_bloom.false_positive_rate(),
            registered_jurisdictions: self.jurisdictions.len(),
            blocked_jurisdictions: self.jurisdictions.values().filter(|j| j.blocked).count(),
        }
    }
}

/// Compliance statistics
#[derive(Debug, Clone)]
pub struct ComplianceStatistics {
    pub total_checks: u64,
    pub passed_checks: u64,
    pub failed_checks: u64,
    pub total_certifications: usize,
    pub active_certifications: usize,
    pub sanctioned_addresses: usize,
    pub bloom_filter_size: usize,
    pub bloom_false_positive_rate: f64,
    pub registered_jurisdictions: usize,
    pub blocked_jurisdictions: usize,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address(seed: u8) -> Address {
        let mut addr = [0u8; 32];
        addr[0] = seed;
        addr
    }

    fn test_hash(seed: u8) -> Hash {
        let mut hash = [0u8; 32];
        hash[0] = seed;
        hash
    }

    #[test]
    fn test_bloom_filter_basic() {
        let mut bloom = SanctionsBloomFilter::new();

        let addr1 = test_address(1);
        let addr2 = test_address(2);
        let addr3 = test_address(3);

        // Initially no addresses
        assert!(!bloom.possibly_contains(&addr1));
        assert!(!bloom.possibly_contains(&addr2));

        // Add addr1
        bloom.add(&addr1);
        assert!(bloom.possibly_contains(&addr1));
        assert!(!bloom.possibly_contains(&addr2));

        // Add addr2
        bloom.add(&addr2);
        assert!(bloom.possibly_contains(&addr1));
        assert!(bloom.possibly_contains(&addr2));
        assert!(!bloom.possibly_contains(&addr3));

        assert_eq!(bloom.count(), 2);
    }

    #[test]
    fn test_certification_validity() {
        let cert = Certification {
            standard: ComplianceStandard::GdprEu,
            entity_did: Did::new("aethelred", "test"),
            entity_address: test_address(1),
            issuer: Did::new("aethelred", "issuer"),
            level: 3,
            issued_at: 1000,
            expires_at: 2000,
            document_hash: test_hash(1),
            metadata: HashMap::new(),
            revoked: false,
            revocation_reason: None,
        };

        // Before expiry
        assert!(cert.is_valid(1500));
        assert!(!cert.in_grace_period(1500));

        // At expiry boundary
        assert!(!cert.is_valid(2000));
        assert!(cert.in_grace_period(2000));

        // In grace period
        assert!(!cert.is_valid(2100));
        assert!(cert.in_grace_period(2100));

        // After grace period
        assert!(!cert.is_valid(2000 + CERTIFICATION_GRACE_PERIOD));
        assert!(!cert.in_grace_period(2000 + CERTIFICATION_GRACE_PERIOD + 1));
    }

    #[test]
    fn test_compliance_module_sanctions() {
        let mut module = ComplianceModule::new(ComplianceConfig::testnet());
        module.update_time(1000);

        let good_addr = test_address(1);
        let bad_addr = test_address(2);

        // Add sanctions
        module
            .add_sanctioned_address(bad_addr, "OFAC SDN".to_string())
            .unwrap();

        assert!(!module.is_sanctioned(&good_addr));
        assert!(module.is_sanctioned(&bad_addr));
    }

    #[test]
    fn test_compliance_check_pass() {
        let mut module = ComplianceModule::new(ComplianceConfig::devnet());
        module.update_time(1000);

        let requester = test_address(1);
        let metadata = HashMap::new();

        let result = module
            .enforce(&requester, None, &[], None, 0, &metadata)
            .unwrap();

        assert!(result.passed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_compliance_check_sanctions_fail() {
        let mut module = ComplianceModule::new(ComplianceConfig::mainnet());
        module.update_time(1000);

        let requester = test_address(1);
        module
            .add_sanctioned_address(requester, "OFAC SDN".to_string())
            .unwrap();

        let metadata = HashMap::new();

        let result = module
            .enforce(&requester, None, &[], None, 0, &metadata)
            .unwrap();

        assert!(!result.passed);
        assert!(result
            .violations
            .iter()
            .any(|v| matches!(v, ViolationType::SanctionedAddress { .. })));
    }

    #[test]
    fn test_compliance_check_missing_certification() {
        let mut module = ComplianceModule::new(ComplianceConfig::testnet());
        module.config.enabled = true;
        module.update_time(1000);

        let requester = test_address(1);
        let metadata = HashMap::new();

        let result = module
            .enforce(
                &requester,
                None,
                &[ComplianceStandard::HipaaUs],
                None,
                0,
                &metadata,
            )
            .unwrap();

        assert!(!result.passed);
        assert!(result.violations.iter().any(|v| matches!(
            v,
            ViolationType::MissingCertification {
                standard: ComplianceStandard::HipaaUs,
                ..
            }
        )));
    }

    #[test]
    fn test_compliance_with_valid_certification() {
        let mut module = ComplianceModule::new(ComplianceConfig::testnet());
        module.config.enabled = true;
        module
            .config
            .trusted_issuers
            .push(Did::new("aethelred", "trusted-issuer"));
        module.update_time(1000);

        let requester = test_address(1);

        // Add certification
        let cert = Certification {
            standard: ComplianceStandard::GdprEu,
            entity_did: Did::from_address(&requester),
            entity_address: requester,
            issuer: Did::new("aethelred", "trusted-issuer"),
            level: 3,
            issued_at: 500,
            expires_at: 5000,
            document_hash: test_hash(1),
            metadata: HashMap::new(),
            revoked: false,
            revocation_reason: None,
        };
        module.add_certification(cert).unwrap();

        let metadata = HashMap::new();

        let result = module
            .enforce(
                &requester,
                None,
                &[ComplianceStandard::GdprEu],
                None,
                0,
                &metadata,
            )
            .unwrap();

        assert!(result.passed);
    }

    #[test]
    fn test_blocked_jurisdiction() {
        let mut module = ComplianceModule::new(ComplianceConfig::mainnet());
        module.update_time(1000);

        let requester = test_address(1);
        let metadata = HashMap::new();

        // Try from blocked jurisdiction
        let result = module
            .enforce(&requester, None, &[], Some("KP"), 0, &metadata)
            .unwrap();

        assert!(!result.passed);
        assert!(result.violations.iter().any(|v| matches!(
            v,
            ViolationType::JurisdictionBlocked { jurisdiction, .. } if jurisdiction == "KP"
        )));
    }

    #[test]
    fn test_aml_threshold() {
        let mut module = ComplianceModule::new(ComplianceConfig::mainnet());
        module.update_time(1000);

        let requester = test_address(1);
        let metadata = HashMap::new();

        // Amount over AML threshold
        let large_amount = 100_000_000_000_000u128; // 100k tokens

        let result = module
            .enforce(&requester, None, &[], Some("US"), large_amount, &metadata)
            .unwrap();

        assert!(!result.passed);
        assert!(result
            .violations
            .iter()
            .any(|v| matches!(v, ViolationType::AmlThresholdExceeded { .. })));
    }

    #[test]
    fn test_baa_requirement() {
        let mut module = ComplianceModule::new(ComplianceConfig::testnet());
        module.config.enabled = true;
        module
            .config
            .trusted_issuers
            .push(Did::new("aethelred", "trusted"));
        module.update_time(1000);

        let covered_entity = test_address(1);
        let business_associate = test_address(2);

        // Add HIPAA certifications for both
        for addr in [covered_entity, business_associate] {
            let cert = Certification {
                standard: ComplianceStandard::HipaaUs,
                entity_did: Did::from_address(&addr),
                entity_address: addr,
                issuer: Did::new("aethelred", "trusted"),
                level: 4,
                issued_at: 500,
                expires_at: 5000,
                document_hash: test_hash(1),
                metadata: HashMap::new(),
                revoked: false,
                revocation_reason: None,
            };
            module.add_certification(cert).unwrap();
        }

        let metadata = HashMap::new();

        // Without BAA, should fail
        let result = module
            .enforce(
                &covered_entity,
                Some(&business_associate),
                &[ComplianceStandard::HipaaUs],
                None,
                0,
                &metadata,
            )
            .unwrap();

        assert!(!result.passed);
        assert!(result
            .violations
            .iter()
            .any(|v| matches!(v, ViolationType::MissingBaa { .. })));

        // Register BAA
        module
            .register_baa(covered_entity, business_associate)
            .unwrap();

        // Now should pass
        let result = module
            .enforce(
                &covered_entity,
                Some(&business_associate),
                &[ComplianceStandard::HipaaUs],
                None,
                0,
                &metadata,
            )
            .unwrap();

        assert!(result.passed);
    }

    #[test]
    fn test_consent_management() {
        let mut module = ComplianceModule::new(ComplianceConfig::testnet());
        module.update_time(1000);

        let data_subject = test_address(1);
        let data_controller = test_address(2);

        // No consent initially
        assert!(!module.has_consent(&data_subject, &data_controller, "ai_computation"));

        // Record consent
        let consent = ConsentRecord {
            data_subject,
            data_controller,
            purposes: vec!["ai_computation".to_string(), "analytics".to_string()],
            given_at: 1000,
            expires_at: Some(5000),
            revoked: false,
            revoked_at: None,
            proof: test_hash(1),
        };
        module.record_consent(consent).unwrap();

        // Now has consent
        assert!(module.has_consent(&data_subject, &data_controller, "ai_computation"));
        assert!(module.has_consent(&data_subject, &data_controller, "analytics"));
        assert!(!module.has_consent(&data_subject, &data_controller, "marketing"));

        // Revoke consent
        module
            .revoke_consent(data_subject, data_controller)
            .unwrap();

        // No longer has consent
        assert!(!module.has_consent(&data_subject, &data_controller, "ai_computation"));
    }

    #[test]
    fn test_did_parsing() {
        let did = Did::new("aethelred", "abc123");
        assert_eq!(did.to_string(), "did:aethelred:abc123");

        let parsed = Did::from_string("did:web:example.com:users:alice").unwrap();
        assert_eq!(parsed.method, "web");
        assert_eq!(parsed.identifier, "example.com:users:alice");

        assert!(Did::from_string("invalid").is_none());
    }

    #[test]
    fn test_statistics() {
        let mut module = ComplianceModule::new(ComplianceConfig::testnet());
        module.config.enabled = true;
        module.config.audit_logging = true;
        module.update_time(1000);

        let requester = test_address(1);
        let metadata = HashMap::new();

        // Perform some checks
        module
            .enforce(&requester, None, &[], None, 0, &metadata)
            .unwrap();
        module
            .enforce(&requester, None, &[], None, 0, &metadata)
            .unwrap();

        let stats = module.statistics();
        assert_eq!(stats.total_checks, 2);
        assert_eq!(stats.passed_checks, 2);
        assert_eq!(stats.failed_checks, 0);
    }
}
