//! # Compliance Engine
//!
//! **"The Lawyer in the Code"**
//!
//! This module provides compile-time and runtime compliance verification
//! for data sovereignty requirements across jurisdictions.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         COMPLIANCE ENGINE                               │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │   ┌──────────────────┐    ┌──────────────────┐    ┌─────────────────┐  │
//! │   │  Jurisdiction    │    │   Regulation     │    │  Legal Linter   │  │
//! │   │    Registry      │    │    Policies      │    │   (Live Check)  │  │
//! │   └────────┬─────────┘    └────────┬─────────┘    └────────┬────────┘  │
//! │            │                       │                        │           │
//! │            └───────────────────────┼────────────────────────┘           │
//! │                                    │                                     │
//! │                                    ▼                                     │
//! │                        ┌──────────────────────┐                         │
//! │                        │  Compliance Checker  │                         │
//! │                        └──────────────────────┘                         │
//! │                                    │                                     │
//! │            ┌───────────────────────┼───────────────────────┐            │
//! │            ▼                       ▼                       ▼            │
//! │   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    │
//! │   │ Transfer Rules  │    │ Retention Rules │    │ Audit Trail     │    │
//! │   └─────────────────┘    └─────────────────┘    └─────────────────┘    │
//! │                                                                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Key Features
//!
//! - **Jurisdiction Enforcement**: Compile-time + runtime checks
//! - **Regulation Mapping**: GDPR, HIPAA, CCPA, UAE Data Protection, etc.
//! - **Legal Linter**: Catches violations before deployment
//! - **Audit Trail**: Immutable compliance records
//! - **Cross-Border Rules**: Automatic transfer validation

mod jurisdiction;
mod regulation;
mod linter;
mod transfer;
mod audit;

pub use jurisdiction::*;
pub use regulation::*;
pub use linter::*;
pub use transfer::*;
pub use audit::*;

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

// ============================================================================
// Core Types
// ============================================================================

/// Jurisdiction identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Jurisdiction {
    /// Global (no specific jurisdiction)
    Global,

    /// United States
    US,

    /// European Union (GDPR zone)
    EU,

    /// United Kingdom
    UK,

    /// United Arab Emirates
    UAE,

    /// Saudi Arabia
    SaudiArabia,

    /// Singapore
    Singapore,

    /// China (mainland)
    China,

    /// India
    India,

    /// Japan
    Japan,

    /// Switzerland
    Switzerland,

    /// Brazil
    Brazil,

    /// Australia
    Australia,

    /// Canada
    Canada,

    /// South Korea
    SouthKorea,

    /// Hong Kong
    HongKong,

    /// Specific US state
    USState(USState),

    /// GCC (Gulf Cooperation Council) region
    GCC,

    /// APAC region
    APAC,
}

/// US State-specific regulations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum USState {
    California,  // CCPA/CPRA
    Colorado,    // CPA
    Connecticut, // CTDPA
    Virginia,    // VCDPA
    Utah,        // UCPA
    Texas,
    NewYork,
    Other,
}

impl Jurisdiction {
    /// Get the ISO 3166-1 alpha-2 country code
    pub fn code(&self) -> &'static str {
        match self {
            Jurisdiction::Global => "XX",
            Jurisdiction::US => "US",
            Jurisdiction::EU => "EU",
            Jurisdiction::UK => "GB",
            Jurisdiction::UAE => "AE",
            Jurisdiction::SaudiArabia => "SA",
            Jurisdiction::Singapore => "SG",
            Jurisdiction::China => "CN",
            Jurisdiction::India => "IN",
            Jurisdiction::Japan => "JP",
            Jurisdiction::Switzerland => "CH",
            Jurisdiction::Brazil => "BR",
            Jurisdiction::Australia => "AU",
            Jurisdiction::Canada => "CA",
            Jurisdiction::SouthKorea => "KR",
            Jurisdiction::HongKong => "HK",
            Jurisdiction::USState(_) => "US",
            Jurisdiction::GCC => "GC",
            Jurisdiction::APAC => "AP",
        }
    }

    /// Get the display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Jurisdiction::Global => "Global",
            Jurisdiction::US => "United States",
            Jurisdiction::EU => "European Union",
            Jurisdiction::UK => "United Kingdom",
            Jurisdiction::UAE => "United Arab Emirates",
            Jurisdiction::SaudiArabia => "Saudi Arabia",
            Jurisdiction::Singapore => "Singapore",
            Jurisdiction::China => "China",
            Jurisdiction::India => "India",
            Jurisdiction::Japan => "Japan",
            Jurisdiction::Switzerland => "Switzerland",
            Jurisdiction::Brazil => "Brazil",
            Jurisdiction::Australia => "Australia",
            Jurisdiction::Canada => "Canada",
            Jurisdiction::SouthKorea => "South Korea",
            Jurisdiction::HongKong => "Hong Kong",
            Jurisdiction::USState(USState::California) => "California, USA",
            Jurisdiction::USState(_) => "US State",
            Jurisdiction::GCC => "Gulf Cooperation Council",
            Jurisdiction::APAC => "Asia-Pacific",
        }
    }

    /// Check if this jurisdiction is part of another
    pub fn is_part_of(&self, other: &Jurisdiction) -> bool {
        match (self, other) {
            (_, Jurisdiction::Global) => true,
            (Jurisdiction::USState(_), Jurisdiction::US) => true,
            (Jurisdiction::UK, Jurisdiction::EU) => false, // Post-Brexit
            (Jurisdiction::UAE, Jurisdiction::GCC) => true,
            (Jurisdiction::SaudiArabia, Jurisdiction::GCC) => true,
            (Jurisdiction::Singapore, Jurisdiction::APAC) => true,
            (Jurisdiction::Japan, Jurisdiction::APAC) => true,
            (Jurisdiction::Australia, Jurisdiction::APAC) => true,
            (Jurisdiction::HongKong, Jurisdiction::APAC) => true,
            (Jurisdiction::SouthKorea, Jurisdiction::APAC) => true,
            (a, b) if a == b => true,
            _ => false,
        }
    }

    /// Get applicable regulations
    pub fn regulations(&self) -> Vec<Regulation> {
        match self {
            Jurisdiction::EU => vec![Regulation::GDPR],
            Jurisdiction::UK => vec![Regulation::GDPR, Regulation::UKDataProtection],
            Jurisdiction::US => vec![],
            Jurisdiction::USState(USState::California) => vec![Regulation::CCPA],
            Jurisdiction::UAE => vec![Regulation::UAEDataProtection],
            Jurisdiction::China => vec![Regulation::ChinaPIPL, Regulation::ChinaCybersecurity],
            Jurisdiction::India => vec![Regulation::IndiaDPDP],
            Jurisdiction::Brazil => vec![Regulation::BrazilLGPD],
            Jurisdiction::Singapore => vec![Regulation::SingaporePDPA],
            Jurisdiction::Japan => vec![Regulation::JapanAPPI],
            Jurisdiction::SouthKorea => vec![Regulation::KoreaPIPA],
            Jurisdiction::Canada => vec![Regulation::CanadaPIPEDA],
            Jurisdiction::Australia => vec![Regulation::AustraliaPrivacy],
            _ => vec![],
        }
    }

    /// Check if adequacy decision exists with another jurisdiction
    pub fn has_adequacy_with(&self, other: &Jurisdiction) -> bool {
        // EU adequacy decisions
        let eu_adequate = vec![
            Jurisdiction::Switzerland,
            Jurisdiction::Japan,
            Jurisdiction::SouthKorea,
            Jurisdiction::UK,
            Jurisdiction::Canada,
        ];

        match (self, other) {
            (Jurisdiction::EU, j) if eu_adequate.contains(j) => true,
            (j, Jurisdiction::EU) if eu_adequate.contains(j) => true,

            // GCC mutual recognition
            (Jurisdiction::UAE, Jurisdiction::SaudiArabia) => true,
            (Jurisdiction::SaudiArabia, Jurisdiction::UAE) => true,

            // Same jurisdiction
            (a, b) if a == b => true,

            _ => false,
        }
    }
}

impl Default for Jurisdiction {
    fn default() -> Self {
        Jurisdiction::Global
    }
}

// ============================================================================
// Regulations
// ============================================================================

/// Regulation identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Regulation {
    /// EU General Data Protection Regulation
    GDPR,

    /// US Health Insurance Portability and Accountability Act
    HIPAA,

    /// California Consumer Privacy Act
    CCPA,

    /// UAE Data Protection Law
    UAEDataProtection,

    /// UAE Health Data Protection
    UAEHealthData,

    /// UK Data Protection Act 2018
    UKDataProtection,

    /// China Personal Information Protection Law
    ChinaPIPL,

    /// China Cybersecurity Law
    ChinaCybersecurity,

    /// India Digital Personal Data Protection Act
    IndiaDPDP,

    /// Brazil LGPD
    BrazilLGPD,

    /// Singapore PDPA
    SingaporePDPA,

    /// Japan APPI
    JapanAPPI,

    /// Korea PIPA
    KoreaPIPA,

    /// Canada PIPEDA
    CanadaPIPEDA,

    /// Australia Privacy Act
    AustraliaPrivacy,

    /// PCI DSS (Payment Card)
    PCIDSS,

    /// SOC 2
    SOC2,

    /// ISO 27001
    ISO27001,

    /// Custom regulation
    Custom(String),
}

impl Regulation {
    /// Get display name
    pub fn display_name(&self) -> &str {
        match self {
            Regulation::GDPR => "General Data Protection Regulation (GDPR)",
            Regulation::HIPAA => "Health Insurance Portability and Accountability Act (HIPAA)",
            Regulation::CCPA => "California Consumer Privacy Act (CCPA)",
            Regulation::UAEDataProtection => "UAE Federal Data Protection Law",
            Regulation::UAEHealthData => "UAE Health Data Protection Regulations",
            Regulation::UKDataProtection => "UK Data Protection Act 2018",
            Regulation::ChinaPIPL => "China Personal Information Protection Law (PIPL)",
            Regulation::ChinaCybersecurity => "China Cybersecurity Law",
            Regulation::IndiaDPDP => "India Digital Personal Data Protection Act",
            Regulation::BrazilLGPD => "Brazil General Data Protection Law (LGPD)",
            Regulation::SingaporePDPA => "Singapore Personal Data Protection Act (PDPA)",
            Regulation::JapanAPPI => "Japan Act on Protection of Personal Information (APPI)",
            Regulation::KoreaPIPA => "Korea Personal Information Protection Act (PIPA)",
            Regulation::CanadaPIPEDA => "Canada PIPEDA",
            Regulation::AustraliaPrivacy => "Australia Privacy Act 1988",
            Regulation::PCIDSS => "Payment Card Industry Data Security Standard (PCI DSS)",
            Regulation::SOC2 => "SOC 2 Type II",
            Regulation::ISO27001 => "ISO/IEC 27001",
            Regulation::Custom(name) => name,
        }
    }

    /// Get default requirements for this regulation
    pub fn default_requirements(&self) -> Vec<String> {
        match self {
            Regulation::GDPR => vec![
                "Right to erasure (Article 17)".to_string(),
                "Data protection by design (Article 25)".to_string(),
                "Records of processing activities (Article 30)".to_string(),
                "Data breach notification (Article 33)".to_string(),
                "Data transfer restrictions (Article 44)".to_string(),
            ],
            Regulation::HIPAA => vec![
                "PHI protection (45 CFR 164.502)".to_string(),
                "Minimum necessary standard".to_string(),
                "Audit controls (45 CFR 164.312)".to_string(),
                "Access controls".to_string(),
                "Encryption requirements".to_string(),
            ],
            Regulation::CCPA => vec![
                "Right to know".to_string(),
                "Right to delete".to_string(),
                "Right to opt-out".to_string(),
                "Non-discrimination".to_string(),
            ],
            Regulation::UAEDataProtection => vec![
                "Data must remain within UAE borders".to_string(),
                "Processing only in approved jurisdictions".to_string(),
                "Consent requirements".to_string(),
                "Data subject rights".to_string(),
            ],
            Regulation::ChinaPIPL => vec![
                "Cross-border transfer restrictions".to_string(),
                "Data localization requirements".to_string(),
                "Security assessment for transfers".to_string(),
                "Consent requirements".to_string(),
            ],
            _ => vec![
                "Data protection requirements".to_string(),
                "Security controls".to_string(),
            ],
        }
    }

    /// Check if regulation requires data localization
    pub fn requires_localization(&self) -> bool {
        matches!(
            self,
            Regulation::ChinaPIPL
                | Regulation::ChinaCybersecurity
                | Regulation::IndiaDPDP
                | Regulation::UAEDataProtection
        )
    }

    /// Get maximum data retention period (if specified)
    pub fn max_retention(&self) -> Option<Duration> {
        match self {
            Regulation::GDPR => Some(Duration::from_secs(365 * 24 * 60 * 60 * 6)), // 6 years typical
            Regulation::HIPAA => Some(Duration::from_secs(365 * 24 * 60 * 60 * 6)), // 6 years
            _ => None,
        }
    }
}

// ============================================================================
// Compliance Requirement
// ============================================================================

/// A specific compliance requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRequirement {
    /// The regulation this requirement comes from
    pub regulation: Regulation,

    /// Specific requirements
    pub requirements: Vec<String>,

    /// How to verify compliance
    pub verification: VerificationMethod,
}

/// How compliance is verified
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationMethod {
    /// Verified through TEE attestation
    TeeAttestation,

    /// Verified through audit log review
    AuditLog,

    /// Verified through cryptographic proof
    ZkProof,

    /// Verified through manual audit
    ManualAudit,

    /// Verified through automated scanning
    AutomatedScan,

    /// Self-certified
    SelfCertification,
}

// ============================================================================
// Compliance Checker
// ============================================================================

/// Main compliance checking engine
pub struct ComplianceEngine {
    /// Jurisdiction rules
    jurisdiction_rules: JurisdictionRules,

    /// Transfer rules
    transfer_rules: TransferRules,

    /// Regulation policies
    regulation_policies: HashMap<Regulation, RegulationPolicy>,

    /// Audit trail
    audit_trail: AuditTrail,
}

impl ComplianceEngine {
    /// Create a new compliance engine
    pub fn new() -> Self {
        ComplianceEngine {
            jurisdiction_rules: JurisdictionRules::default(),
            transfer_rules: TransferRules::default(),
            regulation_policies: Self::default_policies(),
            audit_trail: AuditTrail::new(),
        }
    }

    /// Load default regulation policies
    fn default_policies() -> HashMap<Regulation, RegulationPolicy> {
        let mut policies = HashMap::new();

        // GDPR policy
        policies.insert(
            Regulation::GDPR,
            RegulationPolicy {
                regulation: Regulation::GDPR,
                data_localization: false,
                allowed_transfers: vec![
                    Jurisdiction::EU,
                    Jurisdiction::UK,
                    Jurisdiction::Switzerland,
                    Jurisdiction::Japan,
                    Jurisdiction::Canada,
                ],
                require_encryption: true,
                require_audit_log: true,
                require_consent: true,
                max_retention: Some(Duration::from_secs(365 * 24 * 60 * 60 * 6)),
                breach_notification_hours: Some(72),
            },
        );

        // UAE Data Protection policy
        policies.insert(
            Regulation::UAEDataProtection,
            RegulationPolicy {
                regulation: Regulation::UAEDataProtection,
                data_localization: true,
                allowed_transfers: vec![Jurisdiction::UAE, Jurisdiction::GCC],
                require_encryption: true,
                require_audit_log: true,
                require_consent: true,
                max_retention: None,
                breach_notification_hours: Some(72),
            },
        );

        // HIPAA policy
        policies.insert(
            Regulation::HIPAA,
            RegulationPolicy {
                regulation: Regulation::HIPAA,
                data_localization: false,
                allowed_transfers: vec![Jurisdiction::US],
                require_encryption: true,
                require_audit_log: true,
                require_consent: false, // Treatment exemption
                max_retention: Some(Duration::from_secs(365 * 24 * 60 * 60 * 6)),
                breach_notification_hours: Some(60 * 24), // 60 days
            },
        );

        // China PIPL policy
        policies.insert(
            Regulation::ChinaPIPL,
            RegulationPolicy {
                regulation: Regulation::ChinaPIPL,
                data_localization: true,
                allowed_transfers: vec![Jurisdiction::China],
                require_encryption: true,
                require_audit_log: true,
                require_consent: true,
                max_retention: None,
                breach_notification_hours: Some(72),
            },
        );

        policies
    }

    /// Check if a data transfer is allowed
    pub fn check_transfer(
        &self,
        from: Jurisdiction,
        to: Jurisdiction,
        regulations: &[Regulation],
    ) -> TransferResult {
        self.transfer_rules.check(from, to, regulations, &self.regulation_policies)
    }

    /// Check compliance for a data operation
    pub fn check_operation(
        &self,
        operation: &DataOperation,
    ) -> ComplianceResult {
        let mut violations = Vec::new();
        let mut warnings = Vec::new();

        // Check jurisdiction rules
        if let Some(violation) = self.check_jurisdiction_rules(operation) {
            violations.push(violation);
        }

        // Check regulation requirements
        for reg in &operation.applicable_regulations {
            if let Some(policy) = self.regulation_policies.get(reg) {
                if let Some(violation) = self.check_regulation(operation, policy) {
                    violations.push(violation);
                }
            }
        }

        // Check data classification
        if let Some(warning) = self.check_data_classification(operation) {
            warnings.push(warning);
        }

        // Record in audit trail
        self.audit_trail.record(AuditEntry {
            timestamp: SystemTime::now(),
            operation: operation.operation_type.clone(),
            jurisdiction: operation.jurisdiction,
            result: if violations.is_empty() {
                AuditResult::Allowed
            } else {
                AuditResult::Denied
            },
            violations: violations.clone(),
            actor: operation.actor.clone(),
        });

        ComplianceResult {
            compliant: violations.is_empty(),
            violations,
            warnings,
            audit_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Check jurisdiction rules
    fn check_jurisdiction_rules(&self, operation: &DataOperation) -> Option<ComplianceViolation> {
        // Check if operation is allowed in jurisdiction
        if !self.jurisdiction_rules.allows(operation.jurisdiction, &operation.operation_type) {
            return Some(ComplianceViolation {
                code: "JURISDICTION_RESTRICTION".to_string(),
                message: format!(
                    "Operation '{}' not allowed in jurisdiction '{}'",
                    operation.operation_type,
                    operation.jurisdiction.display_name()
                ),
                severity: ViolationSeverity::Critical,
                regulation: None,
                remediation: "Process data in an allowed jurisdiction".to_string(),
            });
        }

        None
    }

    /// Check regulation compliance
    fn check_regulation(
        &self,
        operation: &DataOperation,
        policy: &RegulationPolicy,
    ) -> Option<ComplianceViolation> {
        // Check data localization
        if policy.data_localization {
            if !policy.allowed_transfers.contains(&operation.jurisdiction) {
                return Some(ComplianceViolation {
                    code: "DATA_LOCALIZATION".to_string(),
                    message: format!(
                        "Data must remain in: {:?}",
                        policy.allowed_transfers
                    ),
                    severity: ViolationSeverity::Critical,
                    regulation: Some(policy.regulation.clone()),
                    remediation: "Process data in compliant jurisdiction".to_string(),
                });
            }
        }

        // Check encryption requirement
        if policy.require_encryption && !operation.is_encrypted {
            return Some(ComplianceViolation {
                code: "ENCRYPTION_REQUIRED".to_string(),
                message: "Data must be encrypted for this regulation".to_string(),
                severity: ViolationSeverity::High,
                regulation: Some(policy.regulation.clone()),
                remediation: "Enable encryption for data at rest and in transit".to_string(),
            });
        }

        // Check audit log requirement
        if policy.require_audit_log && !operation.audit_enabled {
            return Some(ComplianceViolation {
                code: "AUDIT_REQUIRED".to_string(),
                message: "Audit logging must be enabled".to_string(),
                severity: ViolationSeverity::Medium,
                regulation: Some(policy.regulation.clone()),
                remediation: "Enable audit logging for all data operations".to_string(),
            });
        }

        None
    }

    /// Check data classification
    fn check_data_classification(&self, operation: &DataOperation) -> Option<ComplianceWarning> {
        // Warn about sensitive data in non-secure environments
        if operation.data_classification == DataClassification::HighlySensitive
            && !operation.tee_verified
        {
            return Some(ComplianceWarning {
                code: "SENSITIVE_DATA_EXPOSURE".to_string(),
                message: "Highly sensitive data should be processed in TEE".to_string(),
                severity: WarningSeverity::High,
                recommendation: "Use TEE-enabled processing for this data".to_string(),
            });
        }

        None
    }

    /// Run legal linter on configuration
    pub fn lint(&self, config: &ComplianceConfig) -> LintResult {
        let linter = LegalLinter::new();
        linter.lint(config)
    }
}

impl Default for ComplianceEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Supporting Types
// ============================================================================

/// Regulation policy
#[derive(Debug, Clone)]
pub struct RegulationPolicy {
    pub regulation: Regulation,
    pub data_localization: bool,
    pub allowed_transfers: Vec<Jurisdiction>,
    pub require_encryption: bool,
    pub require_audit_log: bool,
    pub require_consent: bool,
    pub max_retention: Option<Duration>,
    pub breach_notification_hours: Option<u32>,
}

/// Data operation being checked
#[derive(Debug, Clone)]
pub struct DataOperation {
    pub operation_type: String,
    pub jurisdiction: Jurisdiction,
    pub applicable_regulations: Vec<Regulation>,
    pub data_classification: DataClassification,
    pub is_encrypted: bool,
    pub audit_enabled: bool,
    pub tee_verified: bool,
    pub actor: String,
}

/// Data classification levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Sensitive,
    HighlySensitive,
}

/// Result of compliance check
#[derive(Debug, Clone)]
pub struct ComplianceResult {
    pub compliant: bool,
    pub violations: Vec<ComplianceViolation>,
    pub warnings: Vec<ComplianceWarning>,
    pub audit_id: String,
}

/// Compliance violation
#[derive(Debug, Clone)]
pub struct ComplianceViolation {
    pub code: String,
    pub message: String,
    pub severity: ViolationSeverity,
    pub regulation: Option<Regulation>,
    pub remediation: String,
}

/// Violation severity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Compliance warning
#[derive(Debug, Clone)]
pub struct ComplianceWarning {
    pub code: String,
    pub message: String,
    pub severity: WarningSeverity,
    pub recommendation: String,
}

/// Warning severity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningSeverity {
    Info,
    Low,
    Medium,
    High,
}

/// Compliance configuration for linting
#[derive(Debug, Clone)]
pub struct ComplianceConfig {
    pub jurisdictions: Vec<Jurisdiction>,
    pub regulations: Vec<Regulation>,
    pub data_types: Vec<String>,
    pub transfer_rules: Vec<TransferRule>,
    pub retention_policies: HashMap<String, Duration>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jurisdiction_code() {
        assert_eq!(Jurisdiction::UAE.code(), "AE");
        assert_eq!(Jurisdiction::EU.code(), "EU");
        assert_eq!(Jurisdiction::US.code(), "US");
    }

    #[test]
    fn test_jurisdiction_part_of() {
        assert!(Jurisdiction::UAE.is_part_of(&Jurisdiction::GCC));
        assert!(Jurisdiction::USState(USState::California).is_part_of(&Jurisdiction::US));
        assert!(!Jurisdiction::UK.is_part_of(&Jurisdiction::EU));
    }

    #[test]
    fn test_adequacy() {
        assert!(Jurisdiction::EU.has_adequacy_with(&Jurisdiction::Switzerland));
        assert!(Jurisdiction::EU.has_adequacy_with(&Jurisdiction::Japan));
        assert!(!Jurisdiction::EU.has_adequacy_with(&Jurisdiction::China));
    }

    #[test]
    fn test_regulation_localization() {
        assert!(Regulation::ChinaPIPL.requires_localization());
        assert!(Regulation::UAEDataProtection.requires_localization());
        assert!(!Regulation::GDPR.requires_localization());
    }

    #[test]
    fn test_compliance_engine() {
        let engine = ComplianceEngine::new();

        let operation = DataOperation {
            operation_type: "process".to_string(),
            jurisdiction: Jurisdiction::EU,
            applicable_regulations: vec![Regulation::GDPR],
            data_classification: DataClassification::Sensitive,
            is_encrypted: true,
            audit_enabled: true,
            tee_verified: true,
            actor: "test".to_string(),
        };

        let result = engine.check_operation(&operation);
        assert!(result.compliant);
    }
}
