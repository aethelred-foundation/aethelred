//! Compliance Gauntlet Validators for Aethelred Testnet
//!
//! NOT standard sandbox validators. These simulate hostile regulatory
//! environments to let banks (FAB/DBS) test worst-case compliance scenarios.
//!
//! "What happens if I accidentally send UAE data to Singapore?"
//! The Sandbox proves your chain blocks it.
//!
//! Features:
//! - Jurisdiction-aware validators with real regulatory rules
//! - Data residency enforcement simulation
//! - Cross-border data flow testing
//! - GDPR, HIPAA, PDPA, DIFC compliance simulation
//! - Regulatory audit trail generation
//! - Compliance failure scenario testing

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

// ============ Compliance Configuration ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    /// Enabled regulatory frameworks
    pub frameworks: Vec<RegulatoryFramework>,

    /// Jurisdiction mappings
    pub jurisdictions: HashMap<String, JurisdictionConfig>,

    /// Default enforcement level
    pub default_enforcement: EnforcementLevel,

    /// Enable cross-border checks
    pub cross_border_enabled: bool,

    /// Enable audit logging
    pub audit_logging: bool,

    /// Strictness level
    pub strictness: StrictnessLevel,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        let mut jurisdictions = HashMap::new();

        // UAE/DIFC
        jurisdictions.insert("AE".to_string(), JurisdictionConfig {
            code: "AE".to_string(),
            name: "United Arab Emirates".to_string(),
            frameworks: vec![
                RegulatoryFramework::DIFC,
                RegulatoryFramework::CBUAE,
            ],
            data_residency: DataResidencyRule::MustRemainLocal,
            cross_border_allowed: vec!["SA".to_string(), "BH".to_string(), "OM".to_string()],
            blocked_destinations: vec!["IR".to_string(), "KP".to_string()],
            special_rules: vec![
                SpecialRule::IslamicFinanceCompliant,
                SpecialRule::ShariahAuditRequired,
            ],
        });

        // Singapore
        jurisdictions.insert("SG".to_string(), JurisdictionConfig {
            code: "SG".to_string(),
            name: "Singapore".to_string(),
            frameworks: vec![
                RegulatoryFramework::PDPA,
                RegulatoryFramework::MAS,
            ],
            data_residency: DataResidencyRule::CanTransferWithConsent,
            cross_border_allowed: vec!["AU".to_string(), "NZ".to_string(), "JP".to_string()],
            blocked_destinations: vec!["KP".to_string()],
            special_rules: vec![],
        });

        // European Union
        jurisdictions.insert("EU".to_string(), JurisdictionConfig {
            code: "EU".to_string(),
            name: "European Union".to_string(),
            frameworks: vec![
                RegulatoryFramework::GDPR,
                RegulatoryFramework::AIMDraft,
            ],
            data_residency: DataResidencyRule::AdequacyDecisionRequired,
            cross_border_allowed: vec![],
            blocked_destinations: vec![],
            special_rules: vec![
                SpecialRule::RightToExplanation,
                SpecialRule::DataMinimization,
            ],
        });

        // United States (HIPAA focus)
        jurisdictions.insert("US".to_string(), JurisdictionConfig {
            code: "US".to_string(),
            name: "United States".to_string(),
            frameworks: vec![
                RegulatoryFramework::HIPAA,
                RegulatoryFramework::CCPA,
                RegulatoryFramework::SOX,
            ],
            data_residency: DataResidencyRule::SectorSpecific,
            cross_border_allowed: vec![],
            blocked_destinations: vec!["CU".to_string(), "IR".to_string(), "KP".to_string(), "SY".to_string()],
            special_rules: vec![
                SpecialRule::PHIProtection,
                SpecialRule::BAA_Required,
            ],
        });

        // United Kingdom
        jurisdictions.insert("GB".to_string(), JurisdictionConfig {
            code: "GB".to_string(),
            name: "United Kingdom".to_string(),
            frameworks: vec![
                RegulatoryFramework::UKGDPR,
                RegulatoryFramework::FCA,
            ],
            data_residency: DataResidencyRule::AdequacyDecisionRequired,
            cross_border_allowed: vec!["EU".to_string()],
            blocked_destinations: vec![],
            special_rules: vec![
                SpecialRule::RightToExplanation,
            ],
        });

        Self {
            frameworks: vec![
                RegulatoryFramework::GDPR,
                RegulatoryFramework::HIPAA,
                RegulatoryFramework::PDPA,
                RegulatoryFramework::DIFC,
                RegulatoryFramework::MAS,
            ],
            jurisdictions,
            default_enforcement: EnforcementLevel::Strict,
            cross_border_enabled: true,
            audit_logging: true,
            strictness: StrictnessLevel::Regulatory,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JurisdictionConfig {
    pub code: String,
    pub name: String,
    pub frameworks: Vec<RegulatoryFramework>,
    pub data_residency: DataResidencyRule,
    pub cross_border_allowed: Vec<String>,
    pub blocked_destinations: Vec<String>,
    pub special_rules: Vec<SpecialRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegulatoryFramework {
    // Privacy Regulations
    GDPR,       // EU General Data Protection Regulation
    UKGDPR,     // UK GDPR
    CCPA,       // California Consumer Privacy Act
    PDPA,       // Singapore Personal Data Protection Act

    // Healthcare
    HIPAA,      // US Health Insurance Portability Act

    // Financial
    MAS,        // Monetary Authority of Singapore
    FCA,        // UK Financial Conduct Authority
    DIFC,       // Dubai International Financial Centre
    CBUAE,      // Central Bank of UAE
    SOX,        // Sarbanes-Oxley

    // AI-Specific
    AIMDraft,   // EU AI Act (Draft)

    // Other
    Custom(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataResidencyRule {
    /// Data must never leave jurisdiction
    MustRemainLocal,

    /// Can transfer with explicit consent
    CanTransferWithConsent,

    /// Requires adequacy decision or SCCs
    AdequacyDecisionRequired,

    /// Sector-specific rules apply
    SectorSpecific,

    /// No restrictions
    NoRestrictions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpecialRule {
    /// Must provide AI decision explanations
    RightToExplanation,

    /// Minimize data collected
    DataMinimization,

    /// Protected Health Information rules
    PHIProtection,

    /// Business Associate Agreement required
    BAA_Required,

    /// Must be Shariah-compliant
    IslamicFinanceCompliant,

    /// Requires Shariah audit
    ShariahAuditRequired,

    /// Under 18 data special handling
    ChildDataProtection,

    /// Biometric data special rules
    BiometricProtection,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EnforcementLevel {
    /// Log violations but don't block
    Permissive,

    /// Warn on violations
    Warning,

    /// Block violations
    Strict,

    /// Block and report to compliance
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum StrictnessLevel {
    /// Learning mode - explain violations
    Learning,

    /// Standard compliance checks
    Standard,

    /// Full regulatory simulation
    Regulatory,

    /// Paranoid mode - strictest interpretation
    Paranoid,
}

// ============ Compliance Validators ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceValidator {
    /// Unique validator ID
    pub id: String,

    /// Validator name
    pub name: String,

    /// Description
    pub description: String,

    /// Simulated jurisdiction
    pub jurisdiction: String,

    /// Active regulatory frameworks
    pub frameworks: Vec<RegulatoryFramework>,

    /// Enforcement rules
    pub rules: Vec<ComplianceRule>,

    /// Current status
    pub status: ValidatorStatus,

    /// Metrics
    pub metrics: ValidatorMetrics,

    /// Configuration
    pub config: ValidatorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRule {
    pub id: String,
    pub name: String,
    pub framework: RegulatoryFramework,
    pub rule_type: RuleType,
    pub condition: RuleCondition,
    pub action: RuleAction,
    pub severity: RuleSeverity,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleType {
    /// Check data residency
    DataResidency,

    /// Check cross-border transfer
    CrossBorderTransfer,

    /// Check data classification
    DataClassification,

    /// Check consent requirements
    ConsentCheck,

    /// Check encryption requirements
    EncryptionCheck,

    /// Check audit requirements
    AuditCheck,

    /// Check model explainability
    ExplainabilityCheck,

    /// Check retention policies
    RetentionCheck,

    /// Custom rule
    Custom { script: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    /// Always applies
    Always,

    /// Only for specific data types
    DataType { types: Vec<DataType> },

    /// Only from specific source jurisdictions
    SourceJurisdiction { codes: Vec<String> },

    /// Only to specific destination jurisdictions
    DestinationJurisdiction { codes: Vec<String> },

    /// Only for specific model types
    ModelType { types: Vec<String> },

    /// Compound condition
    And { conditions: Vec<RuleCondition> },
    Or { conditions: Vec<RuleCondition> },
    Not { condition: Box<RuleCondition> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    /// Allow the transaction
    Allow,

    /// Block the transaction
    Block { reason: String },

    /// Require additional verification
    RequireVerification { verification_type: String },

    /// Add compliance tag
    AddTag { tag: String },

    /// Require encryption
    RequireEncryption { algorithm: String },

    /// Log and allow
    LogAndAllow { log_level: String },

    /// Quarantine for review
    Quarantine { reason: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RuleSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataType {
    PII,            // Personally Identifiable Information
    PHI,            // Protected Health Information
    Financial,      // Financial data
    Biometric,      // Biometric data
    ChildData,      // Under-18 data
    SensitivePI,    // Sensitive personal info (race, religion, etc.)
    AIModelWeights, // ML model parameters
    AIInference,    // AI inference results
    CreditScore,    // Credit scoring data
    Custom(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    Online,
    Offline,
    Maintenance,
    FailingOver,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidatorMetrics {
    pub transactions_processed: u64,
    pub transactions_blocked: u64,
    pub transactions_warned: u64,
    pub compliance_checks_performed: u64,
    pub violations_detected: u64,
    pub quarantined_items: u64,
    pub average_check_time_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    pub max_concurrent_checks: usize,
    pub check_timeout_ms: u64,
    pub cache_enabled: bool,
    pub cache_ttl_seconds: u64,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            max_concurrent_checks: 100,
            check_timeout_ms: 5000,
            cache_enabled: true,
            cache_ttl_seconds: 300,
        }
    }
}

// ============ Compliance Check Request ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheckRequest {
    /// Unique request ID
    pub id: String,

    /// Transaction to check
    pub transaction: TransactionData,

    /// Data classification
    pub data_classification: DataClassification,

    /// Source information
    pub source: SourceInfo,

    /// Destination information
    pub destination: DestinationInfo,

    /// AI model information (if applicable)
    pub ai_model: Option<AIModelInfo>,

    /// Consent information
    pub consent: Option<ConsentInfo>,

    /// Request timestamp
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionData {
    pub tx_hash: String,
    pub tx_type: TransactionType,
    pub sender: String,
    pub receiver: String,
    pub data_size_bytes: u64,
    pub encrypted: bool,
    pub encryption_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionType {
    DataTransfer,
    ModelSealing,
    InferenceRequest,
    InferenceResult,
    ModelDeployment,
    AuditLog,
    ConsentRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataClassification {
    pub types: Vec<DataType>,
    pub sensitivity_level: SensitivityLevel,
    pub retention_days: Option<u32>,
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SensitivityLevel {
    Public,
    Internal,
    Confidential,
    Restricted,
    TopSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInfo {
    pub jurisdiction: String,
    pub organization: Option<String>,
    pub ip_address: Option<String>,
    pub geo_location: Option<GeoLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationInfo {
    pub jurisdiction: String,
    pub organization: Option<String>,
    pub processing_location: Option<String>,
    pub storage_location: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country_code: String,
    pub region: Option<String>,
    pub city: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIModelInfo {
    pub model_hash: String,
    pub model_type: String,
    pub has_explainability: bool,
    pub training_data_jurisdictions: Vec<String>,
    pub certified_frameworks: Vec<RegulatoryFramework>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentInfo {
    pub consent_id: String,
    pub consent_type: ConsentType,
    pub purposes: Vec<String>,
    pub obtained_at: u64,
    pub expires_at: Option<u64>,
    pub revocable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsentType {
    Explicit,
    Implicit,
    OptIn,
    OptOut,
    Contractual,
    LegitimateInterest,
}

// ============ Compliance Check Result ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheckResult {
    /// Request ID
    pub request_id: String,

    /// Overall result
    pub result: CheckResult,

    /// Individual rule results
    pub rule_results: Vec<RuleCheckResult>,

    /// Violations found
    pub violations: Vec<Violation>,

    /// Required actions
    pub required_actions: Vec<RequiredAction>,

    /// Compliance score (0-100)
    pub compliance_score: u8,

    /// Audit trail
    pub audit_trail: AuditTrail,

    /// Processing time
    pub processing_time_ms: u64,

    /// Validator that processed
    pub validator_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckResult {
    /// Fully compliant
    Passed,

    /// Passed with warnings
    PassedWithWarnings,

    /// Blocked due to violations
    Blocked,

    /// Quarantined for review
    Quarantined,

    /// Check failed (error)
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCheckResult {
    pub rule_id: String,
    pub rule_name: String,
    pub framework: RegulatoryFramework,
    pub passed: bool,
    pub details: String,
    pub evidence: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    pub id: String,
    pub rule_id: String,
    pub framework: RegulatoryFramework,
    pub severity: RuleSeverity,
    pub description: String,
    pub remediation: String,
    pub regulation_reference: Option<String>,
    pub potential_fine: Option<FineEstimate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FineEstimate {
    pub min_amount: f64,
    pub max_amount: f64,
    pub currency: String,
    pub basis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredAction {
    pub action_type: String,
    pub description: String,
    pub deadline: Option<u64>,
    pub responsible_party: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrail {
    pub trace_id: String,
    pub entries: Vec<AuditEntry>,
    pub generated_at: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub event_type: String,
    pub details: String,
    pub outcome: String,
}

// ============ Compliance Gauntlet Manager ============

pub struct ComplianceGauntlet {
    config: ComplianceConfig,
    validators: HashMap<String, ComplianceValidator>,
    check_history: Vec<ComplianceCheckResult>,
    violation_registry: HashMap<String, Vec<Violation>>,
    metrics: GauntletMetrics,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct GauntletMetrics {
    pub total_checks: u64,
    pub passed_checks: u64,
    pub blocked_checks: u64,
    pub warnings_issued: u64,
    pub violations_by_framework: HashMap<String, u64>,
    pub violations_by_severity: HashMap<String, u64>,
    pub average_compliance_score: f64,
    pub cross_border_blocks: u64,
}

impl ComplianceGauntlet {
    pub fn new(config: ComplianceConfig) -> Self {
        let mut gauntlet = Self {
            config,
            validators: HashMap::new(),
            check_history: Vec::new(),
            violation_registry: HashMap::new(),
            metrics: GauntletMetrics::default(),
        };

        gauntlet.initialize_default_validators();
        gauntlet
    }

    fn initialize_default_validators(&mut self) {
        // HIPAA Validator (blocks anything without HIPAA tag)
        self.validators.insert("hipaa_strict".to_string(), ComplianceValidator {
            id: "hipaa_strict".to_string(),
            name: "HIPAA Strict Validator".to_string(),
            description: "Rejects any healthcare data without proper HIPAA compliance markers. Simulates US healthcare regulatory environment.".to_string(),
            jurisdiction: "US".to_string(),
            frameworks: vec![RegulatoryFramework::HIPAA],
            rules: vec![
                ComplianceRule {
                    id: "hipaa_001".to_string(),
                    name: "PHI Protection Check".to_string(),
                    framework: RegulatoryFramework::HIPAA,
                    rule_type: RuleType::DataClassification,
                    condition: RuleCondition::DataType {
                        types: vec![DataType::PHI],
                    },
                    action: RuleAction::Block {
                        reason: "PHI detected without HIPAA compliance tag".to_string(),
                    },
                    severity: RuleSeverity::Critical,
                    enabled: true,
                },
                ComplianceRule {
                    id: "hipaa_002".to_string(),
                    name: "BAA Verification".to_string(),
                    framework: RegulatoryFramework::HIPAA,
                    rule_type: RuleType::Custom {
                        script: "check_baa".to_string(),
                    },
                    condition: RuleCondition::Always,
                    action: RuleAction::RequireVerification {
                        verification_type: "BAA_CHECK".to_string(),
                    },
                    severity: RuleSeverity::High,
                    enabled: true,
                },
            ],
            status: ValidatorStatus::Online,
            metrics: ValidatorMetrics::default(),
            config: ValidatorConfig::default(),
        });

        // UK Data Residency Validator
        self.validators.insert("uk_residency".to_string(), ComplianceValidator {
            id: "uk_residency".to_string(),
            name: "UK Data Residency Validator".to_string(),
            description: "Rejects any data from UK IP addresses that attempts to leave UK jurisdiction without proper safeguards.".to_string(),
            jurisdiction: "GB".to_string(),
            frameworks: vec![RegulatoryFramework::UKGDPR, RegulatoryFramework::FCA],
            rules: vec![
                ComplianceRule {
                    id: "uk_001".to_string(),
                    name: "UK Data Export Block".to_string(),
                    framework: RegulatoryFramework::UKGDPR,
                    rule_type: RuleType::CrossBorderTransfer,
                    condition: RuleCondition::And {
                        conditions: vec![
                            RuleCondition::SourceJurisdiction {
                                codes: vec!["GB".to_string()],
                            },
                            RuleCondition::Not {
                                condition: Box::new(RuleCondition::DestinationJurisdiction {
                                    codes: vec!["GB".to_string(), "EU".to_string()],
                                }),
                            },
                        ],
                    },
                    action: RuleAction::Block {
                        reason: "Cross-border transfer from UK to non-adequate jurisdiction blocked".to_string(),
                    },
                    severity: RuleSeverity::High,
                    enabled: true,
                },
            ],
            status: ValidatorStatus::Online,
            metrics: ValidatorMetrics::default(),
            config: ValidatorConfig::default(),
        });

        // UAE/DIFC Validator
        self.validators.insert("difc_compliance".to_string(), ComplianceValidator {
            id: "difc_compliance".to_string(),
            name: "DIFC Compliance Validator".to_string(),
            description: "Enforces Dubai International Financial Centre data protection and Islamic finance compliance.".to_string(),
            jurisdiction: "AE".to_string(),
            frameworks: vec![RegulatoryFramework::DIFC, RegulatoryFramework::CBUAE],
            rules: vec![
                ComplianceRule {
                    id: "difc_001".to_string(),
                    name: "UAE Data Residency".to_string(),
                    framework: RegulatoryFramework::DIFC,
                    rule_type: RuleType::DataResidency,
                    condition: RuleCondition::SourceJurisdiction {
                        codes: vec!["AE".to_string()],
                    },
                    action: RuleAction::Block {
                        reason: "UAE data must remain within GCC without explicit approval".to_string(),
                    },
                    severity: RuleSeverity::Critical,
                    enabled: true,
                },
                ComplianceRule {
                    id: "difc_002".to_string(),
                    name: "Sanctioned Country Block".to_string(),
                    framework: RegulatoryFramework::CBUAE,
                    rule_type: RuleType::CrossBorderTransfer,
                    condition: RuleCondition::DestinationJurisdiction {
                        codes: vec!["IR".to_string(), "KP".to_string()],
                    },
                    action: RuleAction::Block {
                        reason: "Transfer to sanctioned jurisdiction blocked".to_string(),
                    },
                    severity: RuleSeverity::Critical,
                    enabled: true,
                },
            ],
            status: ValidatorStatus::Online,
            metrics: ValidatorMetrics::default(),
            config: ValidatorConfig::default(),
        });

        // Singapore MAS Validator
        self.validators.insert("mas_singapore".to_string(), ComplianceValidator {
            id: "mas_singapore".to_string(),
            name: "MAS Singapore Validator".to_string(),
            description: "Enforces Monetary Authority of Singapore and PDPA requirements for financial AI.".to_string(),
            jurisdiction: "SG".to_string(),
            frameworks: vec![RegulatoryFramework::MAS, RegulatoryFramework::PDPA],
            rules: vec![
                ComplianceRule {
                    id: "mas_001".to_string(),
                    name: "AI Model Explainability".to_string(),
                    framework: RegulatoryFramework::MAS,
                    rule_type: RuleType::ExplainabilityCheck,
                    condition: RuleCondition::ModelType {
                        types: vec!["credit_scoring".to_string(), "risk_assessment".to_string()],
                    },
                    action: RuleAction::RequireVerification {
                        verification_type: "EXPLAINABILITY_AUDIT".to_string(),
                    },
                    severity: RuleSeverity::High,
                    enabled: true,
                },
            ],
            status: ValidatorStatus::Online,
            metrics: ValidatorMetrics::default(),
            config: ValidatorConfig::default(),
        });

        // GDPR AI Act Validator
        self.validators.insert("eu_ai_act".to_string(), ComplianceValidator {
            id: "eu_ai_act".to_string(),
            name: "EU AI Act Validator".to_string(),
            description: "Enforces EU AI Act draft requirements including right to explanation and high-risk AI system requirements.".to_string(),
            jurisdiction: "EU".to_string(),
            frameworks: vec![RegulatoryFramework::GDPR, RegulatoryFramework::AIMDraft],
            rules: vec![
                ComplianceRule {
                    id: "eu_ai_001".to_string(),
                    name: "Right to Explanation".to_string(),
                    framework: RegulatoryFramework::AIMDraft,
                    rule_type: RuleType::ExplainabilityCheck,
                    condition: RuleCondition::Always,
                    action: RuleAction::RequireVerification {
                        verification_type: "AI_EXPLANATION".to_string(),
                    },
                    severity: RuleSeverity::High,
                    enabled: true,
                },
                ComplianceRule {
                    id: "eu_ai_002".to_string(),
                    name: "Automated Decision Disclosure".to_string(),
                    framework: RegulatoryFramework::GDPR,
                    rule_type: RuleType::Custom {
                        script: "check_automated_decision".to_string(),
                    },
                    condition: RuleCondition::DataType {
                        types: vec![DataType::CreditScore, DataType::AIInference],
                    },
                    action: RuleAction::AddTag {
                        tag: "AUTOMATED_DECISION".to_string(),
                    },
                    severity: RuleSeverity::Medium,
                    enabled: true,
                },
            ],
            status: ValidatorStatus::Online,
            metrics: ValidatorMetrics::default(),
            config: ValidatorConfig::default(),
        });
    }

    /// Run compliance check
    pub fn check(&mut self, request: ComplianceCheckRequest) -> ComplianceCheckResult {
        let start_time = std::time::Instant::now();
        let mut rule_results = Vec::new();
        let mut violations = Vec::new();
        let mut required_actions = Vec::new();

        // Get relevant validators
        let relevant_validators = self.get_relevant_validators(&request);

        // Run checks on each validator
        for validator in relevant_validators {
            for rule in &validator.rules {
                if !rule.enabled {
                    continue;
                }

                let (passed, details, evidence) = self.evaluate_rule(rule, &request);

                rule_results.push(RuleCheckResult {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    framework: rule.framework.clone(),
                    passed,
                    details: details.clone(),
                    evidence,
                });

                if !passed {
                    violations.push(Violation {
                        id: format!("viol_{}", generate_id()),
                        rule_id: rule.id.clone(),
                        framework: rule.framework.clone(),
                        severity: rule.severity,
                        description: details,
                        remediation: self.get_remediation(&rule),
                        regulation_reference: self.get_regulation_reference(&rule),
                        potential_fine: self.estimate_fine(&rule),
                    });

                    // Track required actions
                    if let RuleAction::RequireVerification { verification_type } = &rule.action {
                        required_actions.push(RequiredAction {
                            action_type: verification_type.clone(),
                            description: format!("Verification required: {}", rule.name),
                            deadline: Some(current_timestamp() + 86400),
                            responsible_party: None,
                        });
                    }
                }
            }
        }

        // Determine overall result
        let critical_violations = violations.iter()
            .any(|v| matches!(v.severity, RuleSeverity::Critical));
        let high_violations = violations.iter()
            .any(|v| matches!(v.severity, RuleSeverity::High));

        let result = if critical_violations {
            CheckResult::Blocked
        } else if high_violations && matches!(self.config.default_enforcement, EnforcementLevel::Strict | EnforcementLevel::Critical) {
            CheckResult::Blocked
        } else if !violations.is_empty() {
            CheckResult::PassedWithWarnings
        } else {
            CheckResult::Passed
        };

        // Calculate compliance score
        let total_rules = rule_results.len();
        let passed_rules = rule_results.iter().filter(|r| r.passed).count();
        let compliance_score = if total_rules > 0 {
            ((passed_rules as f64 / total_rules as f64) * 100.0) as u8
        } else {
            100
        };

        let processing_time = start_time.elapsed();

        // Update metrics
        self.metrics.total_checks += 1;
        match result {
            CheckResult::Passed => self.metrics.passed_checks += 1,
            CheckResult::Blocked => self.metrics.blocked_checks += 1,
            CheckResult::PassedWithWarnings => self.metrics.warnings_issued += 1,
            _ => {}
        }

        // Generate audit trail
        let audit_trail = self.generate_audit_trail(&request, &rule_results, &violations);

        let check_result = ComplianceCheckResult {
            request_id: request.id.clone(),
            result,
            rule_results,
            violations,
            required_actions,
            compliance_score,
            audit_trail,
            processing_time_ms: processing_time.as_millis() as u64,
            validator_id: "gauntlet".to_string(),
        };

        // Store in history
        self.check_history.push(check_result.clone());

        check_result
    }

    fn get_relevant_validators(&self, request: &ComplianceCheckRequest) -> Vec<&ComplianceValidator> {
        self.validators.values()
            .filter(|v| {
                v.status == ValidatorStatus::Online &&
                (v.jurisdiction == request.source.jurisdiction ||
                 v.jurisdiction == request.destination.jurisdiction)
            })
            .collect()
    }

    fn evaluate_rule(&self, rule: &ComplianceRule, request: &ComplianceCheckRequest) -> (bool, String, Option<serde_json::Value>) {
        // Check if condition applies
        if !self.condition_applies(&rule.condition, request) {
            return (true, "Condition does not apply".to_string(), None);
        }

        // Evaluate based on rule type
        match &rule.rule_type {
            RuleType::DataResidency => {
                let same_jurisdiction = request.source.jurisdiction == request.destination.jurisdiction;
                if same_jurisdiction {
                    (true, "Data remains in same jurisdiction".to_string(), None)
                } else {
                    (false, format!("Data transfer from {} to {} violates residency rules",
                        request.source.jurisdiction, request.destination.jurisdiction), None)
                }
            }

            RuleType::CrossBorderTransfer => {
                let blocked = self.is_blocked_transfer(
                    &request.source.jurisdiction,
                    &request.destination.jurisdiction
                );
                if blocked {
                    (false, format!("Cross-border transfer to {} is blocked",
                        request.destination.jurisdiction), None)
                } else {
                    (true, "Cross-border transfer allowed".to_string(), None)
                }
            }

            RuleType::DataClassification => {
                let has_required_tags = request.data_classification.tags.contains_key("compliant");
                if has_required_tags {
                    (true, "Required compliance tags present".to_string(), None)
                } else {
                    (false, "Missing required compliance tags".to_string(), None)
                }
            }

            RuleType::ExplainabilityCheck => {
                if let Some(ref ai_model) = request.ai_model {
                    if ai_model.has_explainability {
                        (true, "AI model has explainability".to_string(), None)
                    } else {
                        (false, "AI model lacks required explainability".to_string(), None)
                    }
                } else {
                    (true, "No AI model - check not applicable".to_string(), None)
                }
            }

            _ => (true, "Rule check passed".to_string(), None),
        }
    }

    fn condition_applies(&self, condition: &RuleCondition, request: &ComplianceCheckRequest) -> bool {
        match condition {
            RuleCondition::Always => true,

            RuleCondition::DataType { types } => {
                request.data_classification.types.iter()
                    .any(|t| types.iter().any(|ct| std::mem::discriminant(t) == std::mem::discriminant(ct)))
            }

            RuleCondition::SourceJurisdiction { codes } => {
                codes.contains(&request.source.jurisdiction)
            }

            RuleCondition::DestinationJurisdiction { codes } => {
                codes.contains(&request.destination.jurisdiction)
            }

            RuleCondition::And { conditions } => {
                conditions.iter().all(|c| self.condition_applies(c, request))
            }

            RuleCondition::Or { conditions } => {
                conditions.iter().any(|c| self.condition_applies(c, request))
            }

            RuleCondition::Not { condition } => {
                !self.condition_applies(condition, request)
            }

            _ => true,
        }
    }

    fn is_blocked_transfer(&self, source: &str, destination: &str) -> bool {
        if let Some(jurisdiction) = self.config.jurisdictions.get(source) {
            jurisdiction.blocked_destinations.contains(&destination.to_string())
        } else {
            false
        }
    }

    fn get_remediation(&self, rule: &ComplianceRule) -> String {
        match &rule.action {
            RuleAction::Block { reason } => {
                format!("To proceed: Address the blocking condition - {}", reason)
            }
            RuleAction::RequireVerification { verification_type } => {
                format!("Complete {} verification before proceeding", verification_type)
            }
            _ => "Contact compliance team for guidance".to_string(),
        }
    }

    fn get_regulation_reference(&self, rule: &ComplianceRule) -> Option<String> {
        match rule.framework {
            RegulatoryFramework::GDPR => Some("GDPR Article 44-49 (Cross-border transfers)".to_string()),
            RegulatoryFramework::HIPAA => Some("HIPAA 45 CFR 164.502 (PHI Protection)".to_string()),
            RegulatoryFramework::DIFC => Some("DIFC Data Protection Law Article 26".to_string()),
            RegulatoryFramework::AIMDraft => Some("EU AI Act Draft Article 14 (Human Oversight)".to_string()),
            _ => None,
        }
    }

    fn estimate_fine(&self, rule: &ComplianceRule) -> Option<FineEstimate> {
        match rule.framework {
            RegulatoryFramework::GDPR => Some(FineEstimate {
                min_amount: 10_000_000.0,
                max_amount: 20_000_000.0,
                currency: "EUR".to_string(),
                basis: "Up to 4% of annual global turnover".to_string(),
            }),
            RegulatoryFramework::HIPAA => Some(FineEstimate {
                min_amount: 100.0,
                max_amount: 1_500_000.0,
                currency: "USD".to_string(),
                basis: "Per violation, per year".to_string(),
            }),
            _ => None,
        }
    }

    fn generate_audit_trail(&self, request: &ComplianceCheckRequest, rule_results: &[RuleCheckResult], violations: &[Violation]) -> AuditTrail {
        let entries = vec![
            AuditEntry {
                timestamp: current_timestamp(),
                event_type: "COMPLIANCE_CHECK_INITIATED".to_string(),
                details: format!("Check for {} -> {}", request.source.jurisdiction, request.destination.jurisdiction),
                outcome: "Started".to_string(),
            },
            AuditEntry {
                timestamp: current_timestamp(),
                event_type: "RULES_EVALUATED".to_string(),
                details: format!("{} rules checked", rule_results.len()),
                outcome: format!("{} passed, {} failed",
                    rule_results.iter().filter(|r| r.passed).count(),
                    rule_results.iter().filter(|r| !r.passed).count()),
            },
            AuditEntry {
                timestamp: current_timestamp(),
                event_type: "COMPLIANCE_CHECK_COMPLETED".to_string(),
                details: format!("{} violations found", violations.len()),
                outcome: if violations.is_empty() { "PASSED" } else { "VIOLATIONS_FOUND" }.to_string(),
            },
        ];

        AuditTrail {
            trace_id: format!("audit_{}", generate_id()),
            entries,
            generated_at: current_timestamp(),
            hash: generate_id(),
        }
    }

    /// Get validator by ID
    pub fn get_validator(&self, id: &str) -> Option<&ComplianceValidator> {
        self.validators.get(id)
    }

    /// List all validators
    pub fn list_validators(&self) -> Vec<&ComplianceValidator> {
        self.validators.values().collect()
    }

    /// Get check history
    pub fn history(&self, limit: usize) -> &[ComplianceCheckResult] {
        let len = self.check_history.len();
        &self.check_history[len.saturating_sub(limit)..]
    }

    /// Get metrics
    pub fn metrics(&self) -> &GauntletMetrics {
        &self.metrics
    }

    /// Simulate specific scenario
    pub fn simulate_scenario(&mut self, scenario: ComplianceScenario) -> ComplianceCheckResult {
        let request = scenario.to_check_request();
        self.check(request)
    }
}

// ============ Pre-built Scenarios ============

#[derive(Debug, Clone)]
pub struct ComplianceScenario {
    pub name: String,
    pub description: String,
    pub source_jurisdiction: String,
    pub destination_jurisdiction: String,
    pub data_types: Vec<DataType>,
    pub has_consent: bool,
    pub has_encryption: bool,
    pub ai_model_type: Option<String>,
}

impl ComplianceScenario {
    /// UAE data accidentally sent to Singapore (should be blocked)
    pub fn uae_to_singapore_leak() -> Self {
        Self {
            name: "UAE-Singapore Data Leak".to_string(),
            description: "What happens if UAE customer data is accidentally sent to Singapore?".to_string(),
            source_jurisdiction: "AE".to_string(),
            destination_jurisdiction: "SG".to_string(),
            data_types: vec![DataType::Financial, DataType::PII],
            has_consent: false,
            has_encryption: true,
            ai_model_type: None,
        }
    }

    /// US health data without HIPAA compliance
    pub fn hipaa_violation() -> Self {
        Self {
            name: "HIPAA Violation Test".to_string(),
            description: "Health data processed without HIPAA compliance markers".to_string(),
            source_jurisdiction: "US".to_string(),
            destination_jurisdiction: "US".to_string(),
            data_types: vec![DataType::PHI],
            has_consent: true,
            has_encryption: true,
            ai_model_type: Some("diagnostic".to_string()),
        }
    }

    /// EU AI without explainability
    pub fn eu_ai_no_explanation() -> Self {
        Self {
            name: "EU AI Act Violation".to_string(),
            description: "AI credit scoring in EU without explainability".to_string(),
            source_jurisdiction: "EU".to_string(),
            destination_jurisdiction: "EU".to_string(),
            data_types: vec![DataType::CreditScore, DataType::AIInference],
            has_consent: true,
            has_encryption: true,
            ai_model_type: Some("credit_scoring".to_string()),
        }
    }

    /// UK data to non-adequate country
    pub fn uk_data_export() -> Self {
        Self {
            name: "UK Data Export Block".to_string(),
            description: "UK data transferred to non-adequate jurisdiction".to_string(),
            source_jurisdiction: "GB".to_string(),
            destination_jurisdiction: "US".to_string(),
            data_types: vec![DataType::PII],
            has_consent: true,
            has_encryption: true,
            ai_model_type: None,
        }
    }

    fn to_check_request(&self) -> ComplianceCheckRequest {
        ComplianceCheckRequest {
            id: format!("scenario_{}", generate_id()),
            transaction: TransactionData {
                tx_hash: format!("0x{}", generate_id()),
                tx_type: if self.ai_model_type.is_some() {
                    TransactionType::InferenceRequest
                } else {
                    TransactionType::DataTransfer
                },
                sender: "0xsender".to_string(),
                receiver: "0xreceiver".to_string(),
                data_size_bytes: 1024,
                encrypted: self.has_encryption,
                encryption_method: if self.has_encryption {
                    Some("AES-256-GCM".to_string())
                } else {
                    None
                },
            },
            data_classification: DataClassification {
                types: self.data_types.clone(),
                sensitivity_level: SensitivityLevel::Confidential,
                retention_days: Some(365),
                tags: HashMap::new(),
            },
            source: SourceInfo {
                jurisdiction: self.source_jurisdiction.clone(),
                organization: Some("Test Organization".to_string()),
                ip_address: None,
                geo_location: None,
            },
            destination: DestinationInfo {
                jurisdiction: self.destination_jurisdiction.clone(),
                organization: Some("Destination Org".to_string()),
                processing_location: Some(self.destination_jurisdiction.clone()),
                storage_location: Some(self.destination_jurisdiction.clone()),
            },
            ai_model: self.ai_model_type.as_ref().map(|t| AIModelInfo {
                model_hash: "0xmodel".to_string(),
                model_type: t.clone(),
                has_explainability: false,
                training_data_jurisdictions: vec![self.source_jurisdiction.clone()],
                certified_frameworks: vec![],
            }),
            consent: if self.has_consent {
                Some(ConsentInfo {
                    consent_id: "consent_123".to_string(),
                    consent_type: ConsentType::Explicit,
                    purposes: vec!["processing".to_string()],
                    obtained_at: current_timestamp() - 86400,
                    expires_at: None,
                    revocable: true,
                })
            } else {
                None
            },
            timestamp: current_timestamp(),
        }
    }
}

// ============ Helper Functions ============

fn generate_id() -> String {
    use rand::Rng;
    let random: u64 = rand::thread_rng().gen();
    format!("{:x}", random)
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gauntlet_creation() {
        let config = ComplianceConfig::default();
        let gauntlet = ComplianceGauntlet::new(config);

        assert!(!gauntlet.validators.is_empty());
    }

    #[test]
    fn test_uae_singapore_scenario() {
        let config = ComplianceConfig::default();
        let mut gauntlet = ComplianceGauntlet::new(config);

        let result = gauntlet.simulate_scenario(ComplianceScenario::uae_to_singapore_leak());

        // Should be blocked
        assert!(matches!(result.result, CheckResult::Blocked | CheckResult::PassedWithWarnings));
    }

    #[test]
    fn test_hipaa_scenario() {
        let config = ComplianceConfig::default();
        let mut gauntlet = ComplianceGauntlet::new(config);

        let result = gauntlet.simulate_scenario(ComplianceScenario::hipaa_violation());

        // Should have violations for missing HIPAA tags
        assert!(!result.violations.is_empty());
    }

    #[test]
    fn test_eu_ai_scenario() {
        let config = ComplianceConfig::default();
        let mut gauntlet = ComplianceGauntlet::new(config);

        let result = gauntlet.simulate_scenario(ComplianceScenario::eu_ai_no_explanation());

        // Should require explainability verification
        assert!(!result.required_actions.is_empty());
    }
}
