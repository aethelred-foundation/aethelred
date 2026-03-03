//! # Regulatory Hypervisor
//!
//! **"The Lawyer in the Code"**
//!
//! This module simulates real-world legal constraints with citations.
//! When data tries to cross a forbidden border, the sandbox doesn't just fail—
//! it explains WHY it fails with actual law references.
//!
//! ## Key Feature: The Jurisdiction Slider
//!
//! Users can slide between:
//! - **Wild West**: No checks (for early prototyping)
//! - **UAE Strict**: Full data sovereignty
//! - **GDPR Strict**: European data protection
//! - **Singapore MAS**: Financial regulatory compliance
//!
//! ## Example Violation Message
//!
//! ```text
//! ❌ VIOLATION: Article 44 (GDPR)
//!
//! Cross-border data transfer to non-adequate jurisdiction blocked.
//!
//! Source: Frankfurt, Germany (EU)
//! Destination: New York, USA (Non-adequate)
//!
//! Citation: Regulation (EU) 2016/679, Article 44
//! "Any transfer of personal data which are undergoing processing
//! or are intended for processing after transfer to a third country
//! shall take place only if..."
//!
//! Remediation Options:
//! 1. Enable Standard Contractual Clauses (SCCs)
//! 2. Route through UAE (adequate jurisdiction under UAE-EU agreement)
//! 3. Obtain explicit user consent
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::core::{
    ComplianceRule, FineEstimate, Jurisdiction, ViolationCondition, ViolationSeverity,
};

// ============================================================================
// The Regulatory Hypervisor Engine
// ============================================================================

/// The Regulatory Hypervisor - enforces legal compliance during simulation
pub struct RegulatoryHypervisor {
    /// Current jurisdiction mode
    jurisdiction: Jurisdiction,
    /// Active compliance rules
    #[allow(dead_code)]
    active_rules: Vec<ComplianceRule>,
    /// Data location tracking
    data_locations: HashMap<DataAssetId, DataLocation>,
    /// Transfer log
    transfer_log: Vec<DataTransfer>,
    /// Consent registry
    #[allow(dead_code)]
    consent_registry: HashMap<DataSubjectId, ConsentRecord>,
    /// Sanctions list
    sanctions_list: SanctionsList,
}

/// Unique identifier for a data asset
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DataAssetId(pub String);

/// Unique identifier for a data subject (person whose data is being processed)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DataSubjectId(pub String);

/// Location of data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataLocation {
    /// Country code (ISO 3166-1 alpha-2)
    pub country: String,
    /// Region within country
    pub region: Option<String>,
    /// City
    pub city: Option<String>,
    /// Data center ID
    pub data_center: Option<String>,
    /// Cloud provider
    pub provider: Option<String>,
    /// Is this inside a TEE?
    pub in_tee: bool,
    /// Encryption status
    pub encrypted: bool,
}

impl DataLocation {
    /// UAE-based location
    pub fn uae(city: &str) -> Self {
        DataLocation {
            country: "AE".to_string(),
            region: Some("Abu Dhabi".to_string()),
            city: Some(city.to_string()),
            data_center: None,
            provider: Some("Aethelred".to_string()),
            in_tee: true,
            encrypted: true,
        }
    }

    /// Singapore-based location
    pub fn singapore() -> Self {
        DataLocation {
            country: "SG".to_string(),
            region: None,
            city: Some("Singapore".to_string()),
            data_center: None,
            provider: Some("AWS".to_string()),
            in_tee: true,
            encrypted: true,
        }
    }

    /// EU-based location
    pub fn eu(country: &str, city: &str) -> Self {
        DataLocation {
            country: country.to_string(),
            region: None,
            city: Some(city.to_string()),
            data_center: None,
            provider: None,
            in_tee: false,
            encrypted: true,
        }
    }

    /// US-based location
    pub fn us(city: &str) -> Self {
        DataLocation {
            country: "US".to_string(),
            region: None,
            city: Some(city.to_string()),
            data_center: None,
            provider: None,
            in_tee: false,
            encrypted: false,
        }
    }
}

/// A record of data transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTransfer {
    /// Transfer ID
    pub id: String,
    /// Data asset being transferred
    pub asset_id: DataAssetId,
    /// Source location
    pub from: DataLocation,
    /// Destination location
    pub to: DataLocation,
    /// Data type
    pub data_type: DataType,
    /// Size in bytes
    pub size_bytes: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Whether transfer was allowed
    pub allowed: bool,
    /// Reason (if blocked)
    pub block_reason: Option<RegulatoryViolation>,
}

/// Types of data for classification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataType {
    /// Personally Identifiable Information
    PII,
    /// Protected Health Information
    PHI,
    /// Financial data
    Financial,
    /// Biometric data
    Biometric,
    /// Genetic data
    Genetic,
    /// Location data
    Location,
    /// Communication content
    Communications,
    /// AI model weights
    ModelWeights,
    /// AI inference results
    InferenceResults,
    /// Non-sensitive data
    NonSensitive,
}

impl DataType {
    /// Get sensitivity level (1-5)
    pub fn sensitivity_level(&self) -> u8 {
        match self {
            DataType::Genetic => 5,
            DataType::Biometric => 5,
            DataType::PHI => 5,
            DataType::PII => 4,
            DataType::Financial => 4,
            DataType::Location => 3,
            DataType::Communications => 3,
            DataType::InferenceResults => 2,
            DataType::ModelWeights => 2,
            DataType::NonSensitive => 1,
        }
    }
}

/// Consent record for a data subject
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRecord {
    /// Data subject ID
    pub subject_id: DataSubjectId,
    /// Consented purposes
    pub purposes: Vec<ConsentPurpose>,
    /// Consent timestamp
    pub consented_at: u64,
    /// Consent expiry
    pub expires_at: Option<u64>,
    /// Can be withdrawn?
    pub withdrawable: bool,
    /// Has been withdrawn?
    pub withdrawn: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentPurpose {
    Storage,
    Processing,
    CrossBorderTransfer,
    AIInference,
    ThirdPartySharing,
    Marketing,
    Research,
}

/// A regulatory violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatoryViolation {
    /// Violation type
    pub violation_type: ViolationType,
    /// Legal citation
    pub citation: LegalCitation,
    /// Severity
    pub severity: ViolationSeverity,
    /// Description
    pub description: String,
    /// Remediation options
    pub remediation: Vec<RemediationOption>,
    /// Estimated fine
    pub estimated_fine: Option<FineEstimate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationType {
    CrossBorderTransfer,
    UnencryptedPII,
    MissingConsent,
    RetentionViolation,
    SanctionedEntity,
    MissingAuditTrail,
    UnauthorizedAccess,
    DataBreach,
    AITransparency,
}

/// A legal citation with full reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegalCitation {
    /// Regulation name
    pub regulation: String,
    /// Article or section
    pub article: String,
    /// Full text excerpt
    pub text: String,
    /// Jurisdiction
    pub jurisdiction: String,
    /// URL to official source
    pub url: Option<String>,
}

impl LegalCitation {
    // ========================================================================
    // GDPR Citations
    // ========================================================================

    pub fn gdpr_article_44() -> Self {
        LegalCitation {
            regulation: "General Data Protection Regulation (GDPR)".to_string(),
            article: "Article 44".to_string(),
            text: "Any transfer of personal data which are undergoing processing or are \
                   intended for processing after transfer to a third country or to an \
                   international organisation shall take place only if, subject to the \
                   other provisions of this Regulation, the conditions laid down in this \
                   Chapter are complied with by the controller and processor..."
                .to_string(),
            jurisdiction: "European Union".to_string(),
            url: Some("https://gdpr-info.eu/art-44-gdpr/".to_string()),
        }
    }

    pub fn gdpr_article_17() -> Self {
        LegalCitation {
            regulation: "General Data Protection Regulation (GDPR)".to_string(),
            article: "Article 17 - Right to Erasure ('Right to be Forgotten')".to_string(),
            text: "The data subject shall have the right to obtain from the controller \
                   the erasure of personal data concerning him or her without undue delay \
                   and the controller shall have the obligation to erase personal data \
                   without undue delay..."
                .to_string(),
            jurisdiction: "European Union".to_string(),
            url: Some("https://gdpr-info.eu/art-17-gdpr/".to_string()),
        }
    }

    pub fn gdpr_article_25() -> Self {
        LegalCitation {
            regulation: "General Data Protection Regulation (GDPR)".to_string(),
            article: "Article 25 - Data Protection by Design and by Default".to_string(),
            text: "The controller shall implement appropriate technical and organisational \
                   measures for ensuring that, by default, only personal data which are \
                   necessary for each specific purpose of the processing are processed."
                .to_string(),
            jurisdiction: "European Union".to_string(),
            url: Some("https://gdpr-info.eu/art-25-gdpr/".to_string()),
        }
    }

    // ========================================================================
    // UAE Citations
    // ========================================================================

    pub fn uae_pdp_article_7() -> Self {
        LegalCitation {
            regulation: "UAE Federal Decree-Law No. 45/2021 (Personal Data Protection)".to_string(),
            article: "Article 7 - Cross-Border Data Transfer".to_string(),
            text: "Personal Data shall not be transferred or processed outside the State \
                   unless the receiving country provides an adequate level of protection \
                   for Personal Data in accordance with standards determined by the \
                   competent authority."
                .to_string(),
            jurisdiction: "United Arab Emirates".to_string(),
            url: None,
        }
    }

    pub fn uae_cbuae_data_residency() -> Self {
        LegalCitation {
            regulation: "CBUAE Consumer Protection Standards".to_string(),
            article: "Data Residency Requirements".to_string(),
            text: "Financial institutions shall ensure that all customer data related \
                   to UAE residents is stored and processed within data centers \
                   located in the United Arab Emirates."
                .to_string(),
            jurisdiction: "United Arab Emirates".to_string(),
            url: None,
        }
    }

    pub fn difc_dp_law() -> Self {
        LegalCitation {
            regulation: "DIFC Data Protection Law 2020".to_string(),
            article: "Article 26 - Transfer of Personal Data".to_string(),
            text: "A Controller may not transfer or allow the transfer of Personal Data \
                   to a recipient in a third country unless the transfer is to a third \
                   country that has an adequate level of protection..."
                .to_string(),
            jurisdiction: "Dubai International Financial Centre".to_string(),
            url: None,
        }
    }

    // ========================================================================
    // Singapore Citations
    // ========================================================================

    pub fn singapore_pdpa_transfer() -> Self {
        LegalCitation {
            regulation: "Personal Data Protection Act (PDPA)".to_string(),
            article: "Section 26 - Transfer Limitation Obligation".to_string(),
            text: "An organisation shall not transfer any personal data to a country \
                   or territory outside Singapore except in accordance with requirements \
                   prescribed under this Act to ensure that organisations provide a \
                   standard of protection to personal data so transferred..."
                .to_string(),
            jurisdiction: "Singapore".to_string(),
            url: None,
        }
    }

    pub fn mas_trm_guidelines() -> Self {
        LegalCitation {
            regulation: "MAS Technology Risk Management Guidelines".to_string(),
            article: "Section 11.2 - Data Protection".to_string(),
            text: "Financial institutions should implement adequate protection for \
                   customer data throughout its lifecycle, including collection, \
                   usage, storage, and disposal. Outsourcing arrangements should \
                   not compromise the confidentiality of customer information."
                .to_string(),
            jurisdiction: "Singapore".to_string(),
            url: None,
        }
    }

    // ========================================================================
    // US Citations
    // ========================================================================

    pub fn hipaa_privacy_rule() -> Self {
        LegalCitation {
            regulation: "Health Insurance Portability and Accountability Act (HIPAA)".to_string(),
            article: "45 CFR § 164.502 - Uses and disclosures of protected health information"
                .to_string(),
            text: "A covered entity or business associate may not use or disclose \
                   protected health information, except as permitted or required \
                   by this subpart or by subpart C of part 160 of this subchapter."
                .to_string(),
            jurisdiction: "United States".to_string(),
            url: Some("https://www.law.cornell.edu/cfr/text/45/164.502".to_string()),
        }
    }

    pub fn sox_section_404() -> Self {
        LegalCitation {
            regulation: "Sarbanes-Oxley Act".to_string(),
            article: "Section 404 - Management Assessment of Internal Controls".to_string(),
            text: "Each annual report required by section 13(a) or 15(d) of the \
                   Securities Exchange Act of 1934 shall contain an internal control \
                   report, which shall state the responsibility of management for \
                   establishing and maintaining an adequate internal control structure..."
                .to_string(),
            jurisdiction: "United States".to_string(),
            url: None,
        }
    }

    // ========================================================================
    // Swiss Citations
    // ========================================================================

    pub fn swiss_banking_secrecy() -> Self {
        LegalCitation {
            regulation: "Swiss Banking Act".to_string(),
            article: "Article 47 - Banking Secrecy".to_string(),
            text: "Any person who deliberately discloses confidential information \
                   entrusted to them in their capacity as a body, employee, agent, \
                   or liquidator of a bank, or as a body or employee of an auditing \
                   company, or who has obtained such information unlawfully, shall \
                   be liable to imprisonment or a fine."
                .to_string(),
            jurisdiction: "Switzerland".to_string(),
            url: None,
        }
    }
}

/// A remediation option to fix a violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationOption {
    /// Option ID
    pub id: String,
    /// Name
    pub name: String,
    /// Description
    pub description: String,
    /// Estimated cost
    pub estimated_cost: Option<String>,
    /// Implementation time
    pub implementation_time: Option<String>,
    /// Can be applied automatically?
    pub automatic: bool,
}

/// Sanctions list for entity screening
#[derive(Debug, Clone)]
pub struct SanctionsList {
    /// OFAC SDN list
    ofac_entries: HashSet<String>,
    /// EU sanctions
    eu_entries: HashSet<String>,
    /// UN sanctions
    un_entries: HashSet<String>,
}

impl Default for SanctionsList {
    fn default() -> Self {
        let mut ofac = HashSet::new();
        let mut eu = HashSet::new();
        let mut un = HashSet::new();

        // Example sanctioned entities (for simulation)
        ofac.insert("EVIL_CORP_LLC".to_string());
        ofac.insert("NORTH_KOREA_BANK".to_string());
        eu.insert("SANCTIONED_EU_ENTITY".to_string());
        un.insert("UN_SANCTIONED_ORG".to_string());

        SanctionsList {
            ofac_entries: ofac,
            eu_entries: eu,
            un_entries: un,
        }
    }
}

impl SanctionsList {
    pub fn is_sanctioned(&self, entity: &str) -> Option<&'static str> {
        let normalized = entity.to_uppercase();
        if self.ofac_entries.contains(&normalized) {
            return Some("OFAC SDN List");
        }
        if self.eu_entries.contains(&normalized) {
            return Some("EU Sanctions List");
        }
        if self.un_entries.contains(&normalized) {
            return Some("UN Sanctions List");
        }
        None
    }
}

// ============================================================================
// Jurisdiction Rules
// ============================================================================

/// Rules for adequate jurisdictions under GDPR
pub fn gdpr_adequate_countries() -> HashSet<&'static str> {
    let mut countries = HashSet::new();
    // EU/EEA
    countries.insert("DE");
    countries.insert("FR");
    countries.insert("IT");
    countries.insert("ES");
    countries.insert("NL");
    countries.insert("BE");
    countries.insert("AT");
    countries.insert("PL");
    countries.insert("PT");
    countries.insert("SE");
    countries.insert("FI");
    countries.insert("DK");
    countries.insert("IE");
    countries.insert("GR");
    countries.insert("CZ");
    countries.insert("RO");
    countries.insert("HU");
    countries.insert("SK");
    countries.insert("BG");
    countries.insert("HR");
    countries.insert("LT");
    countries.insert("SI");
    countries.insert("LV");
    countries.insert("EE");
    countries.insert("CY");
    countries.insert("LU");
    countries.insert("MT");
    // EEA
    countries.insert("NO");
    countries.insert("IS");
    countries.insert("LI");
    // Adequate countries (with decisions)
    countries.insert("AD"); // Andorra
    countries.insert("AR"); // Argentina
    countries.insert("CA"); // Canada
    countries.insert("FO"); // Faroe Islands
    countries.insert("GG"); // Guernsey
    countries.insert("IL"); // Israel
    countries.insert("IM"); // Isle of Man
    countries.insert("JP"); // Japan
    countries.insert("JE"); // Jersey
    countries.insert("NZ"); // New Zealand
    countries.insert("CH"); // Switzerland
    countries.insert("UY"); // Uruguay
    countries.insert("KR"); // South Korea
    countries.insert("GB"); // UK (post-Brexit adequacy)
    countries
}

/// UAE-approved jurisdictions for data transfer
pub fn uae_approved_countries() -> HashSet<&'static str> {
    let mut countries = HashSet::new();
    // GCC countries
    countries.insert("AE"); // UAE
    countries.insert("SA"); // Saudi Arabia
    countries.insert("KW"); // Kuwait
    countries.insert("QA"); // Qatar
    countries.insert("BH"); // Bahrain
    countries.insert("OM"); // Oman
                            // Additional approved
    countries.insert("SG"); // Singapore (financial hub)
    countries.insert("CH"); // Switzerland
    countries
}

/// Singapore approved jurisdictions
pub fn singapore_approved_countries() -> HashSet<&'static str> {
    let mut countries = HashSet::new();
    countries.insert("SG");
    countries.insert("AU"); // Australia
    countries.insert("NZ"); // New Zealand
    countries.insert("JP"); // Japan
    countries.insert("KR"); // South Korea
    countries.insert("HK"); // Hong Kong
    countries.insert("GB"); // UK
                            // ASEAN with data protection laws
    countries.insert("MY"); // Malaysia
    countries.insert("TH"); // Thailand
    countries
}

// ============================================================================
// Hypervisor Implementation
// ============================================================================

impl RegulatoryHypervisor {
    /// Create new hypervisor with jurisdiction
    pub fn new(jurisdiction: Jurisdiction) -> Self {
        let active_rules = Self::rules_for_jurisdiction(&jurisdiction);

        RegulatoryHypervisor {
            jurisdiction,
            active_rules,
            data_locations: HashMap::new(),
            transfer_log: Vec::new(),
            consent_registry: HashMap::new(),
            sanctions_list: SanctionsList::default(),
        }
    }

    /// Generate rules for a jurisdiction
    fn rules_for_jurisdiction(jurisdiction: &Jurisdiction) -> Vec<ComplianceRule> {
        match jurisdiction {
            Jurisdiction::WildWest => vec![],

            Jurisdiction::GDPRStrict {
                allow_adequacy_countries,
            } => {
                let rules = vec![
                    ComplianceRule {
                        id: "GDPR-44".to_string(),
                        name: "Cross-Border Transfer Restriction".to_string(),
                        citation: "GDPR Article 44".to_string(),
                        description: "Data may only be transferred to adequate jurisdictions"
                            .to_string(),
                        violation_condition: ViolationCondition::CrossBorderTransfer {
                            from_regions: vec!["EU".to_string()],
                            to_regions: if *allow_adequacy_countries {
                                vec!["NON-ADEQUATE".to_string()]
                            } else {
                                vec!["NON-EU".to_string()]
                            },
                        },
                        severity: ViolationSeverity::Critical,
                    },
                    ComplianceRule {
                        id: "GDPR-25".to_string(),
                        name: "Data Protection by Design".to_string(),
                        citation: "GDPR Article 25".to_string(),
                        description: "Must implement privacy by design".to_string(),
                        violation_condition: ViolationCondition::UnencryptedPII,
                        severity: ViolationSeverity::Error,
                    },
                    ComplianceRule {
                        id: "GDPR-17".to_string(),
                        name: "Right to Erasure".to_string(),
                        citation: "GDPR Article 17".to_string(),
                        description: "Data subjects can request deletion".to_string(),
                        violation_condition: ViolationCondition::RetentionExceeded {
                            max_days: 365,
                        },
                        severity: ViolationSeverity::Warning,
                    },
                ];
                rules
            }

            Jurisdiction::UAEDataSovereignty {
                allow_gcc_transfer,
                require_local_storage: _,
            } => {
                vec![
                    ComplianceRule {
                        id: "UAE-PDP-7".to_string(),
                        name: "Data Residency".to_string(),
                        citation: "UAE Federal Decree-Law No. 45/2021, Article 7".to_string(),
                        description: "Data must remain within UAE unless transferred to approved jurisdiction".to_string(),
                        violation_condition: ViolationCondition::CrossBorderTransfer {
                            from_regions: vec!["AE".to_string()],
                            to_regions: if *allow_gcc_transfer {
                                vec!["NON-GCC".to_string()]
                            } else {
                                vec!["NON-UAE".to_string()]
                            },
                        },
                        severity: ViolationSeverity::Critical,
                    },
                    ComplianceRule {
                        id: "CBUAE-DR".to_string(),
                        name: "Financial Data Residency".to_string(),
                        citation: "CBUAE Consumer Protection Standards".to_string(),
                        description: "Financial data must be stored in UAE data centers".to_string(),
                        violation_condition: ViolationCondition::CrossBorderTransfer {
                            from_regions: vec!["AE".to_string()],
                            to_regions: vec!["ANY-NON-UAE".to_string()],
                        },
                        severity: ViolationSeverity::Critical,
                    },
                ]
            }

            Jurisdiction::SingaporeMAS { pdpa_strict } => {
                vec![
                    ComplianceRule {
                        id: "PDPA-26".to_string(),
                        name: "Transfer Limitation".to_string(),
                        citation: "PDPA Section 26".to_string(),
                        description: "Transfers require adequate protection".to_string(),
                        violation_condition: ViolationCondition::CrossBorderTransfer {
                            from_regions: vec!["SG".to_string()],
                            to_regions: vec!["NON-ADEQUATE".to_string()],
                        },
                        severity: if *pdpa_strict {
                            ViolationSeverity::Critical
                        } else {
                            ViolationSeverity::Warning
                        },
                    },
                    ComplianceRule {
                        id: "MAS-TRM".to_string(),
                        name: "Technology Risk Management".to_string(),
                        citation: "MAS TRM Guidelines Section 11.2".to_string(),
                        description: "Must implement adequate data protection".to_string(),
                        violation_condition: ViolationCondition::MissingAuditTrail,
                        severity: ViolationSeverity::Error,
                    },
                ]
            }

            Jurisdiction::USRegulatory {
                hipaa,
                sox,
                ofac_screening,
            } => {
                let mut rules = vec![];
                if *hipaa {
                    rules.push(ComplianceRule {
                        id: "HIPAA-502".to_string(),
                        name: "PHI Protection".to_string(),
                        citation: "45 CFR § 164.502".to_string(),
                        description: "Protected health information requires authorization"
                            .to_string(),
                        violation_condition: ViolationCondition::MissingConsent {
                            data_type: "PHI".to_string(),
                        },
                        severity: ViolationSeverity::Critical,
                    });
                }
                if *sox {
                    rules.push(ComplianceRule {
                        id: "SOX-404".to_string(),
                        name: "Internal Controls".to_string(),
                        citation: "SOX Section 404".to_string(),
                        description: "Must maintain audit trail for financial data".to_string(),
                        violation_condition: ViolationCondition::MissingAuditTrail,
                        severity: ViolationSeverity::Critical,
                    });
                }
                if *ofac_screening {
                    rules.push(ComplianceRule {
                        id: "OFAC-SDN".to_string(),
                        name: "Sanctions Screening".to_string(),
                        citation: "OFAC Regulations".to_string(),
                        description: "Must screen against OFAC SDN list".to_string(),
                        violation_condition: ViolationCondition::SanctionedEntity,
                        severity: ViolationSeverity::Critical,
                    });
                }
                rules
            }

            Jurisdiction::SwissBanking => {
                vec![ComplianceRule {
                    id: "SBA-47".to_string(),
                    name: "Banking Secrecy".to_string(),
                    citation: "Swiss Banking Act Article 47".to_string(),
                    description: "Client information protected by banking secrecy".to_string(),
                    violation_condition: ViolationCondition::UnencryptedPII,
                    severity: ViolationSeverity::Critical,
                }]
            }

            Jurisdiction::Custom { rules, .. } => rules.clone(),
        }
    }

    /// Check if a data transfer is allowed
    pub fn check_transfer(
        &self,
        _asset_id: &DataAssetId,
        from: &DataLocation,
        to: &DataLocation,
        data_type: &DataType,
    ) -> Result<(), RegulatoryViolation> {
        // Wild West - everything allowed
        if matches!(self.jurisdiction, Jurisdiction::WildWest) {
            return Ok(());
        }

        // Check cross-border rules
        self.check_cross_border(from, to, data_type)?;

        // Check encryption
        if !to.encrypted && data_type.sensitivity_level() >= 3 {
            return Err(RegulatoryViolation {
                violation_type: ViolationType::UnencryptedPII,
                citation: LegalCitation::gdpr_article_25(),
                severity: ViolationSeverity::Error,
                description: format!(
                    "Sensitive data ({:?}) cannot be transferred to unencrypted destination",
                    data_type
                ),
                remediation: vec![RemediationOption {
                    id: "encrypt".to_string(),
                    name: "Enable Encryption".to_string(),
                    description: "Encrypt data before transfer".to_string(),
                    estimated_cost: Some("Low".to_string()),
                    implementation_time: Some("Immediate".to_string()),
                    automatic: true,
                }],
                estimated_fine: None,
            });
        }

        Ok(())
    }

    /// Check cross-border transfer rules
    fn check_cross_border(
        &self,
        from: &DataLocation,
        to: &DataLocation,
        _data_type: &DataType,
    ) -> Result<(), RegulatoryViolation> {
        // Same country - always OK
        if from.country == to.country {
            return Ok(());
        }

        match &self.jurisdiction {
            Jurisdiction::GDPRStrict {
                allow_adequacy_countries: _,
            } => {
                // Check if destination is in EU/EEA or adequate
                let is_eu = gdpr_adequate_countries().contains(from.country.as_str());
                if !is_eu {
                    return Ok(()); // Source not in EU, GDPR doesn't apply
                }

                let to_adequate = gdpr_adequate_countries().contains(to.country.as_str());
                if !to_adequate {
                    return Err(RegulatoryViolation {
                        violation_type: ViolationType::CrossBorderTransfer,
                        citation: LegalCitation::gdpr_article_44(),
                        severity: ViolationSeverity::Critical,
                        description: format!(
                            "Cross-border data transfer blocked.\n\
                             Source: {} (EU)\n\
                             Destination: {} (Non-adequate jurisdiction)\n\n\
                             Personal data cannot be transferred to countries without \
                             adequate data protection.",
                            from.city.as_deref().unwrap_or(&from.country),
                            to.city.as_deref().unwrap_or(&to.country),
                        ),
                        remediation: vec![
                            RemediationOption {
                                id: "scc".to_string(),
                                name: "Standard Contractual Clauses".to_string(),
                                description: "Implement SCCs with the recipient".to_string(),
                                estimated_cost: Some("$5,000 - $15,000".to_string()),
                                implementation_time: Some("2-4 weeks".to_string()),
                                automatic: false,
                            },
                            RemediationOption {
                                id: "consent".to_string(),
                                name: "Explicit Consent".to_string(),
                                description: "Obtain explicit consent from data subject"
                                    .to_string(),
                                estimated_cost: Some("Low".to_string()),
                                implementation_time: Some("Variable".to_string()),
                                automatic: false,
                            },
                            RemediationOption {
                                id: "route".to_string(),
                                name: "Route via UAE".to_string(),
                                description: "Process in UAE (adequate jurisdiction) first"
                                    .to_string(),
                                estimated_cost: Some("Medium".to_string()),
                                implementation_time: Some("1 week".to_string()),
                                automatic: true,
                            },
                        ],
                        estimated_fine: Some(FineEstimate {
                            currency: "EUR".to_string(),
                            min_amount: 10_000_000,
                            max_amount: 20_000_000,
                            basis: "4% of global annual turnover or €20M, whichever is higher"
                                .to_string(),
                        }),
                    });
                }
            }

            Jurisdiction::UAEDataSovereignty {
                allow_gcc_transfer: _,
                ..
            } => {
                if from.country != "AE" {
                    return Ok(()); // Source not in UAE
                }

                let approved = uae_approved_countries();
                let to_approved = approved.contains(to.country.as_str());

                if !to_approved {
                    return Err(RegulatoryViolation {
                        violation_type: ViolationType::CrossBorderTransfer,
                        citation: LegalCitation::uae_pdp_article_7(),
                        severity: ViolationSeverity::Critical,
                        description: format!(
                            "🇦🇪 UAE DATA SOVEREIGNTY VIOLATION\n\n\
                             Data export to {} is prohibited.\n\n\
                             UAE Federal Decree-Law No. 45/2021 requires that personal data \
                             remains within UAE or approved jurisdictions (GCC, Singapore, Switzerland).\n\n\
                             Your data is currently in: {}\n\
                             Attempted destination: {}",
                            to.country,
                            from.city.as_deref().unwrap_or(&from.country),
                            to.city.as_deref().unwrap_or(&to.country),
                        ),
                        remediation: vec![
                            RemediationOption {
                                id: "local".to_string(),
                                name: "Process Locally".to_string(),
                                description: "Keep data within UAE using Aethelred nodes".to_string(),
                                estimated_cost: Some("None - use UAE validators".to_string()),
                                implementation_time: Some("Immediate".to_string()),
                                automatic: true,
                            },
                            RemediationOption {
                                id: "tee".to_string(),
                                name: "TEE Processing".to_string(),
                                description: "Process in Intel SGX enclave (data never leaves UAE)".to_string(),
                                estimated_cost: Some("Premium validator tier".to_string()),
                                implementation_time: Some("Immediate".to_string()),
                                automatic: true,
                            },
                        ],
                        estimated_fine: Some(FineEstimate {
                            currency: "AED".to_string(),
                            min_amount: 50_000,
                            max_amount: 5_000_000,
                            basis: "Per violation, plus potential license revocation".to_string(),
                        }),
                    });
                }
            }

            Jurisdiction::SingaporeMAS { pdpa_strict } => {
                if from.country != "SG" {
                    return Ok(());
                }

                let approved = singapore_approved_countries();
                if !approved.contains(to.country.as_str()) {
                    return Err(RegulatoryViolation {
                        violation_type: ViolationType::CrossBorderTransfer,
                        citation: LegalCitation::singapore_pdpa_transfer(),
                        severity: if *pdpa_strict {
                            ViolationSeverity::Critical
                        } else {
                            ViolationSeverity::Warning
                        },
                        description: format!(
                            "PDPA Transfer Limitation:\n\
                             Transfer to {} requires additional safeguards.\n\
                             Source: Singapore\n\
                             Destination: {}",
                            to.country,
                            to.city.as_deref().unwrap_or(&to.country),
                        ),
                        remediation: vec![RemediationOption {
                            id: "contract".to_string(),
                            name: "Contractual Safeguards".to_string(),
                            description: "Implement binding corporate rules".to_string(),
                            estimated_cost: Some("$10,000 - $25,000".to_string()),
                            implementation_time: Some("4-8 weeks".to_string()),
                            automatic: false,
                        }],
                        estimated_fine: Some(FineEstimate {
                            currency: "SGD".to_string(),
                            min_amount: 10_000,
                            max_amount: 1_000_000,
                            basis: "Per breach, up to 10% of annual turnover".to_string(),
                        }),
                    });
                }
            }

            _ => {}
        }

        Ok(())
    }

    /// Screen entity against sanctions lists
    pub fn screen_sanctions(&self, entity_name: &str) -> Result<(), RegulatoryViolation> {
        if let Some(list) = self.sanctions_list.is_sanctioned(entity_name) {
            return Err(RegulatoryViolation {
                violation_type: ViolationType::SanctionedEntity,
                citation: LegalCitation {
                    regulation: list.to_string(),
                    article: "Entity Screening".to_string(),
                    text: format!("Entity '{}' appears on {}", entity_name, list),
                    jurisdiction: "International".to_string(),
                    url: None,
                },
                severity: ViolationSeverity::Critical,
                description: format!(
                    "🚨 SANCTIONED ENTITY DETECTED\n\n\
                     Entity: {}\n\
                     List: {}\n\n\
                     Transaction with this entity is PROHIBITED.",
                    entity_name, list
                ),
                remediation: vec![
                    RemediationOption {
                        id: "block".to_string(),
                        name: "Block Transaction".to_string(),
                        description: "Transaction cannot proceed".to_string(),
                        estimated_cost: None,
                        implementation_time: None,
                        automatic: true,
                    },
                    RemediationOption {
                        id: "report".to_string(),
                        name: "File SAR".to_string(),
                        description: "File Suspicious Activity Report".to_string(),
                        estimated_cost: None,
                        implementation_time: Some("Immediate".to_string()),
                        automatic: false,
                    },
                ],
                estimated_fine: Some(FineEstimate {
                    currency: "USD".to_string(),
                    min_amount: 1_000_000,
                    max_amount: 1_000_000_000,
                    basis: "Criminal penalties may apply".to_string(),
                }),
            });
        }
        Ok(())
    }

    /// Record a data transfer
    pub fn record_transfer(
        &mut self,
        asset_id: DataAssetId,
        from: DataLocation,
        to: DataLocation,
        data_type: DataType,
        size_bytes: u64,
    ) -> Result<String, RegulatoryViolation> {
        // First check if transfer is allowed
        let result = self.check_transfer(&asset_id, &from, &to, &data_type);

        let transfer_id = format!("xfer-{}", uuid::Uuid::new_v4());
        let transfer = DataTransfer {
            id: transfer_id.clone(),
            asset_id: asset_id.clone(),
            from,
            to: to.clone(),
            data_type,
            size_bytes,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            allowed: result.is_ok(),
            block_reason: result.clone().err(),
        };

        self.transfer_log.push(transfer);

        if result.is_ok() {
            // Update data location
            self.data_locations.insert(asset_id, to);
            Ok(transfer_id)
        } else {
            Err(result.unwrap_err())
        }
    }

    /// Get formatted violation report
    pub fn format_violation(violation: &RegulatoryViolation) -> String {
        let severity_icon = match violation.severity {
            ViolationSeverity::Info => "ℹ️",
            ViolationSeverity::Warning => "⚠️",
            ViolationSeverity::Error => "❌",
            ViolationSeverity::Critical => "🚨",
        };

        let mut report = format!(
            r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║ {} REGULATORY VIOLATION                                                      ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Type: {:?}                                         ║
║  Severity: {:?}                                                          ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  LEGAL CITATION                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Regulation: {}
║  Article: {}
║  Jurisdiction: {}
║                                                                               ║
║  Text:
{}
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  DESCRIPTION                                                                  ║
╠═══════════════════════════════════════════════════════════════════════════════╣
{}
╠═══════════════════════════════════════════════════════════════════════════════╣
║  REMEDIATION OPTIONS                                                          ║
╠═══════════════════════════════════════════════════════════════════════════════╣
"#,
            severity_icon,
            violation.violation_type,
            violation.severity,
            violation.citation.regulation,
            violation.citation.article,
            violation.citation.jurisdiction,
            Self::wrap_text(&violation.citation.text, 75, "║  "),
            Self::wrap_text(&violation.description, 75, "║  "),
        );

        for (i, option) in violation.remediation.iter().enumerate() {
            report.push_str(&format!(
                "║  {}. {} {}\n║     {}\n",
                i + 1,
                option.name,
                if option.automatic { "[AUTO]" } else { "" },
                option.description,
            ));
            if let Some(cost) = &option.estimated_cost {
                report.push_str(&format!("║     Cost: {}\n", cost));
            }
            if let Some(time) = &option.implementation_time {
                report.push_str(&format!("║     Time: {}\n", time));
            }
            report.push_str("║\n");
        }

        if let Some(fine) = &violation.estimated_fine {
            report.push_str(&format!(
                r#"╠═══════════════════════════════════════════════════════════════════════════════╣
║  ESTIMATED PENALTY                                                            ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  Currency: {}
║  Range: {} {} - {} {}
║  Basis: {}
"#,
                fine.currency,
                fine.currency,
                Self::format_number(fine.min_amount),
                fine.currency,
                Self::format_number(fine.max_amount),
                fine.basis,
            ));
        }

        report.push_str(
            "╚═══════════════════════════════════════════════════════════════════════════════╝\n",
        );

        report
    }

    fn wrap_text(text: &str, width: usize, prefix: &str) -> String {
        let mut result = String::new();
        let mut current_line = String::new();

        for word in text.split_whitespace() {
            if current_line.len() + word.len() + 1 > width {
                result.push_str(prefix);
                result.push_str(&current_line);
                result.push('\n');
                current_line = word.to_string();
            } else {
                if !current_line.is_empty() {
                    current_line.push(' ');
                }
                current_line.push_str(word);
            }
        }

        if !current_line.is_empty() {
            result.push_str(prefix);
            result.push_str(&current_line);
            result.push('\n');
        }

        result
    }

    fn format_number(n: u64) -> String {
        if n >= 1_000_000_000 {
            format!("{:.1}B", n as f64 / 1_000_000_000.0)
        } else if n >= 1_000_000 {
            format!("{:.1}M", n as f64 / 1_000_000.0)
        } else if n >= 1_000 {
            format!("{:.1}K", n as f64 / 1_000.0)
        } else {
            n.to_string()
        }
    }

    /// Get the jurisdiction slider widget
    pub fn jurisdiction_slider() -> String {
        r#"
┌─────────────────────────────────────────────────────────────────────────────┐
│                         🎚️  JURISDICTION SLIDER                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ◄━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━► │
│  ▼                    ▼                    ▼                    ▼          │
│  WILD WEST           UAE STRICT           GDPR                 SINGAPORE   │
│  (No Checks)         (Full Sovereignty)   (EU Protection)      (MAS)       │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  Current: █████████████░░░░░░░░░░░░░░░░░░  UAE DATA SOVEREIGNTY             │
│                                                                             │
│  Active Rules:                                                              │
│  ✓ Data must remain within UAE/GCC                                          │
│  ✓ Financial data requires local storage                                    │
│  ✓ TEE attestation required for processing                                  │
│  ✓ Audit trail for all data access                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
        "#
        .to_string()
    }
}

impl Default for RegulatoryHypervisor {
    fn default() -> Self {
        Self::new(Jurisdiction::UAEDataSovereignty {
            allow_gcc_transfer: true,
            require_local_storage: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gdpr_blocks_us_transfer() {
        let hypervisor = RegulatoryHypervisor::new(Jurisdiction::GDPRStrict {
            allow_adequacy_countries: true,
        });

        let from = DataLocation::eu("DE", "Frankfurt");
        let to = DataLocation::us("New York");
        let data_type = DataType::PII;

        let result =
            hypervisor.check_transfer(&DataAssetId("test".to_string()), &from, &to, &data_type);

        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(violation.violation_type, ViolationType::CrossBorderTransfer);
    }

    #[test]
    fn test_uae_allows_gcc_transfer() {
        let hypervisor = RegulatoryHypervisor::new(Jurisdiction::UAEDataSovereignty {
            allow_gcc_transfer: true,
            require_local_storage: true,
        });

        let from = DataLocation::uae("Abu Dhabi");
        let to = DataLocation {
            country: "SA".to_string(),
            region: None,
            city: Some("Riyadh".to_string()),
            data_center: None,
            provider: None,
            in_tee: true,
            encrypted: true,
        };

        let result = hypervisor.check_transfer(
            &DataAssetId("test".to_string()),
            &from,
            &to,
            &DataType::Financial,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_sanctions_screening() {
        let hypervisor = RegulatoryHypervisor::default();

        let result = hypervisor.screen_sanctions("EVIL_CORP_LLC");
        assert!(result.is_err());

        let result = hypervisor.screen_sanctions("LEGITIMATE_COMPANY");
        assert!(result.is_ok());
    }

    #[test]
    fn test_wild_west_allows_everything() {
        let hypervisor = RegulatoryHypervisor::new(Jurisdiction::WildWest);

        let from = DataLocation::eu("DE", "Frankfurt");
        let to = DataLocation::us("New York");

        let result =
            hypervisor.check_transfer(&DataAssetId("test".to_string()), &from, &to, &DataType::PII);

        assert!(result.is_ok());
    }
}
