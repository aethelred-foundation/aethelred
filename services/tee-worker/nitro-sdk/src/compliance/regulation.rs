//! # Regulation Policies
//!
//! Detailed regulation requirements and policies.

use super::*;

// This file provides additional regulation details
// Most regulation types are defined in mod.rs

/// Extended regulation information
pub struct RegulationInfo {
    /// Base regulation
    pub regulation: Regulation,

    /// Full official name
    pub official_name: String,

    /// Enactment date
    pub enacted: Option<String>,

    /// Effective date
    pub effective: Option<String>,

    /// Official URL
    pub url: Option<String>,

    /// Key articles
    pub key_articles: Vec<RegulationArticle>,

    /// Fines structure
    pub fines: Option<FineStructure>,
}

/// A specific article of a regulation
#[derive(Debug, Clone)]
pub struct RegulationArticle {
    /// Article number
    pub number: String,

    /// Title
    pub title: String,

    /// Summary
    pub summary: String,

    /// Is this article commonly violated?
    pub high_risk: bool,
}

/// Fine structure for a regulation
#[derive(Debug, Clone)]
pub struct FineStructure {
    /// Maximum fine (fixed amount in USD)
    pub max_fixed: Option<u64>,

    /// Maximum fine as percentage of revenue
    pub max_percentage: Option<f64>,

    /// Which is applied (higher or lower)
    pub apply_rule: FineRule,

    /// Currency
    pub currency: String,
}

/// Rule used to select which fine calculation applies.
#[derive(Debug, Clone)]
pub enum FineRule {
    /// Apply the higher of fixed amount vs percentage amount.
    Higher,
    /// Apply the lower of fixed amount vs percentage amount.
    Lower,
    /// Apply only the fixed amount.
    Fixed,
}

impl RegulationInfo {
    /// Get GDPR info
    pub fn gdpr() -> Self {
        RegulationInfo {
            regulation: Regulation::GDPR,
            official_name: "General Data Protection Regulation (EU) 2016/679".to_string(),
            enacted: Some("2016-04-14".to_string()),
            effective: Some("2018-05-25".to_string()),
            url: Some("https://eur-lex.europa.eu/eli/reg/2016/679/oj".to_string()),
            key_articles: vec![
                RegulationArticle {
                    number: "Article 5".to_string(),
                    title: "Principles relating to processing".to_string(),
                    summary: "Lawfulness, fairness, transparency, purpose limitation, data minimisation, accuracy, storage limitation, integrity and confidentiality, accountability".to_string(),
                    high_risk: true,
                },
                RegulationArticle {
                    number: "Article 6".to_string(),
                    title: "Lawfulness of processing".to_string(),
                    summary: "Six legal bases: consent, contract, legal obligation, vital interests, public task, legitimate interests".to_string(),
                    high_risk: true,
                },
                RegulationArticle {
                    number: "Article 17".to_string(),
                    title: "Right to erasure ('right to be forgotten')".to_string(),
                    summary: "Data subject has the right to obtain erasure of personal data".to_string(),
                    high_risk: true,
                },
                RegulationArticle {
                    number: "Article 25".to_string(),
                    title: "Data protection by design and by default".to_string(),
                    summary: "Implement appropriate technical and organisational measures".to_string(),
                    high_risk: false,
                },
                RegulationArticle {
                    number: "Article 33".to_string(),
                    title: "Notification of a personal data breach".to_string(),
                    summary: "Notify supervisory authority within 72 hours of becoming aware".to_string(),
                    high_risk: true,
                },
                RegulationArticle {
                    number: "Article 44-49".to_string(),
                    title: "Transfers to third countries".to_string(),
                    summary: "Restrictions on international data transfers".to_string(),
                    high_risk: true,
                },
            ],
            fines: Some(FineStructure {
                max_fixed: Some(20_000_000),
                max_percentage: Some(0.04),
                apply_rule: FineRule::Higher,
                currency: "EUR".to_string(),
            }),
        }
    }

    /// Get HIPAA info
    pub fn hipaa() -> Self {
        RegulationInfo {
            regulation: Regulation::HIPAA,
            official_name: "Health Insurance Portability and Accountability Act of 1996"
                .to_string(),
            enacted: Some("1996-08-21".to_string()),
            effective: Some("1996-08-21".to_string()),
            url: Some("https://www.hhs.gov/hipaa/index.html".to_string()),
            key_articles: vec![
                RegulationArticle {
                    number: "45 CFR 164.502".to_string(),
                    title: "Uses and disclosures of protected health information".to_string(),
                    summary: "General rules for use and disclosure of PHI".to_string(),
                    high_risk: true,
                },
                RegulationArticle {
                    number: "45 CFR 164.312".to_string(),
                    title: "Technical safeguards".to_string(),
                    summary: "Access controls, audit controls, integrity, transmission security"
                        .to_string(),
                    high_risk: true,
                },
                RegulationArticle {
                    number: "45 CFR 164.530".to_string(),
                    title: "Administrative requirements".to_string(),
                    summary: "Policies, training, sanctions, mitigation".to_string(),
                    high_risk: false,
                },
            ],
            fines: Some(FineStructure {
                max_fixed: Some(1_500_000),
                max_percentage: None,
                apply_rule: FineRule::Fixed,
                currency: "USD".to_string(),
            }),
        }
    }

    /// Get China PIPL info
    pub fn china_pipl() -> Self {
        RegulationInfo {
            regulation: Regulation::ChinaPIPL,
            official_name: "Personal Information Protection Law of the People's Republic of China".to_string(),
            enacted: Some("2021-08-20".to_string()),
            effective: Some("2021-11-01".to_string()),
            url: None,
            key_articles: vec![
                RegulationArticle {
                    number: "Article 38".to_string(),
                    title: "Cross-border transfer".to_string(),
                    summary: "Conditions for providing personal information to overseas recipients".to_string(),
                    high_risk: true,
                },
                RegulationArticle {
                    number: "Article 40".to_string(),
                    title: "Security assessment".to_string(),
                    summary: "Critical information infrastructure operators must undergo security assessment".to_string(),
                    high_risk: true,
                },
            ],
            fines: Some(FineStructure {
                max_fixed: Some(50_000_000),
                max_percentage: Some(0.05),
                apply_rule: FineRule::Higher,
                currency: "CNY".to_string(),
            }),
        }
    }

    /// Get UAE Data Protection info
    pub fn uae_data_protection() -> Self {
        RegulationInfo {
            regulation: Regulation::UAEDataProtection,
            official_name: "UAE Federal Decree-Law No. 45 of 2021 on Personal Data Protection"
                .to_string(),
            enacted: Some("2021-09-26".to_string()),
            effective: Some("2022-01-02".to_string()),
            url: None,
            key_articles: vec![
                RegulationArticle {
                    number: "Article 5".to_string(),
                    title: "Data processing principles".to_string(),
                    summary: "Lawfulness, transparency, purpose limitation, data minimisation"
                        .to_string(),
                    high_risk: true,
                },
                RegulationArticle {
                    number: "Article 22".to_string(),
                    title: "Cross-border transfer".to_string(),
                    summary: "Transfer to countries with adequate protection or with safeguards"
                        .to_string(),
                    high_risk: true,
                },
            ],
            fines: Some(FineStructure {
                max_fixed: Some(5_000_000),
                max_percentage: None,
                apply_rule: FineRule::Fixed,
                currency: "AED".to_string(),
            }),
        }
    }
}

/// Quick reference for common compliance questions
pub struct ComplianceQuickRef;

impl ComplianceQuickRef {
    /// Can EU data be transferred to the US?
    pub fn can_transfer_eu_to_us() -> &'static str {
        "Post-Schrems II, transfers to the US require:
1. Standard Contractual Clauses (SCCs) with supplementary measures, OR
2. Binding Corporate Rules (BCRs), OR
3. Specific derogations (consent, contract necessity, etc.)

Note: EU-US Data Privacy Framework (2023) provides adequacy for certified companies."
    }

    /// What is the breach notification timeline?
    pub fn breach_notification_timeline() -> &'static str {
        "• GDPR: 72 hours to supervisory authority
• HIPAA: 60 days to HHS (can be extended)
• CCPA: 'expeditiously' to consumers
• PIPL (China): immediately to authorities
• UAE: 72 hours to data office"
    }

    /// What is the maximum retention for personal data?
    pub fn max_retention_guidance() -> &'static str {
        "General principle: Data should not be kept longer than necessary for the purpose.

Common timeframes:
• Tax records: 7 years (most jurisdictions)
• Employment records: 6 years after employment ends
• Healthcare records: varies (6-30 years depending on jurisdiction)
• General marketing data: 2-3 years of inactivity

GDPR: No fixed maximum, but must justify retention period.
HIPAA: Minimum 6 years for records subject to HIPAA."
    }

    /// What are the consent requirements?
    pub fn consent_requirements() -> &'static str {
        "GDPR Consent Requirements:
1. Freely given
2. Specific
3. Informed
4. Unambiguous
5. Easy to withdraw

CCPA: Opt-out model for sales; opt-in for minors under 16

China PIPL: Separate consent required for:
• Sensitive personal information
• Cross-border transfers
• Public disclosure"
    }
}
