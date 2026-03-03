//! # Scenario Library
//!
//! **"Bank-Grade Templates for C-Level Risk Simulation"**
//!
//! This module provides pre-built scenarios for financial institutions.
//! Each scenario includes:
//!
//! - Complete data model
//! - Regulatory requirements
//! - Expected test cases
//! - Risk assessment criteria
//!
//! ## Available Scenarios
//!
//! ```text
//! ╔═══════════════════════════════════════════════════════════════════════════════╗
//! ║                        📚 SCENARIO LIBRARY                                    ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║                                                                               ║
//! ║  TRADE FINANCE                                                                ║
//! ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
//! ║  │  📄 UAE-Singapore Trade Settlement                                      │ ║
//! ║  │     Cross-border LC processing with sovereign data requirements         │ ║
//! ║  │     Jurisdictions: UAE, Singapore                                       │ ║
//! ║  │     [Load Scenario]                                                     │ ║
//! ║  │                                                                         │ ║
//! ║  │  📄 Dubai-Mumbai Trade Corridor                                         │ ║
//! ║  │     Indian export finance with RBI compliance                           │ ║
//! ║  │     Jurisdictions: UAE, India                                           │ ║
//! ║  │     [Load Scenario]                                                     │ ║
//! ║  └─────────────────────────────────────────────────────────────────────────┘ ║
//! ║                                                                               ║
//! ║  HEALTHCARE                                                                   ║
//! ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
//! ║  │  🧬 M42 Genomic Blind Compute                                           │ ║
//! ║  │     Multi-party genomic analysis without revealing raw data             │ ║
//! ║  │     Compliance: HIPAA, UAE Health Data Protection                       │ ║
//! ║  │     [Load Scenario]                                                     │ ║
//! ║  └─────────────────────────────────────────────────────────────────────────┘ ║
//! ║                                                                               ║
//! ║  FINANCIAL CRIME                                                              ║
//! ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
//! ║  │  🔍 AML Transaction Monitoring                                          │ ║
//! ║  │     Real-time suspicious activity detection across institutions         │ ║
//! ║  │     Compliance: FATF, CBUAE AML, MAS AML                                │ ║
//! ║  │     [Load Scenario]                                                     │ ║
//! ║  │                                                                         │ ║
//! ║  │  🛡️ OFAC Sanctions Screening                                           │ ║
//! ║  │     Entity screening against global sanctions lists                     │ ║
//! ║  │     Lists: OFAC SDN, EU, UN, UAE Local                                  │ ║
//! ║  │     [Load Scenario]                                                     │ ║
//! ║  └─────────────────────────────────────────────────────────────────────────┘ ║
//! ║                                                                               ║
//! ╚═══════════════════════════════════════════════════════════════════════════════╝
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::regulatory::DataType;

// ============================================================================
// Scenario Types
// ============================================================================

/// A pre-built scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    /// Scenario ID
    pub id: String,
    /// Display name
    pub name: String,
    /// Description
    pub description: String,
    /// Category
    pub category: ScenarioCategory,
    /// Industry
    pub industry: Industry,
    /// Difficulty level
    pub complexity: Complexity,
    /// Estimated duration (minutes)
    pub duration_minutes: u32,
    /// Required jurisdictions
    pub jurisdictions: Vec<String>,
    /// Compliance requirements
    pub compliance: Vec<ComplianceRequirement>,
    /// Data model
    pub data_model: DataModel,
    /// Workflow steps
    pub workflow: Vec<WorkflowStep>,
    /// Test cases
    pub test_cases: Vec<TestCase>,
    /// Success criteria
    pub success_criteria: Vec<SuccessCriterion>,
    /// Tags
    pub tags: Vec<String>,
    /// Author
    pub author: String,
    /// Version
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScenarioCategory {
    TradeFinance,
    Healthcare,
    FinancialCrime,
    CreditRisk,
    AssetManagement,
    Insurance,
    RealEstate,
    SupplyChain,
    Custom,
}

impl ScenarioCategory {
    pub fn icon(&self) -> &'static str {
        match self {
            ScenarioCategory::TradeFinance => "📄",
            ScenarioCategory::Healthcare => "🧬",
            ScenarioCategory::FinancialCrime => "🔍",
            ScenarioCategory::CreditRisk => "💳",
            ScenarioCategory::AssetManagement => "💼",
            ScenarioCategory::Insurance => "🛡️",
            ScenarioCategory::RealEstate => "🏠",
            ScenarioCategory::SupplyChain => "🚚",
            ScenarioCategory::Custom => "⚙️",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Industry {
    Banking,
    Insurance,
    Healthcare,
    Government,
    Manufacturing,
    Retail,
    Technology,
    Energy,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Complexity {
    /// Simple, single-party
    Basic,
    /// Multi-party, single jurisdiction
    Intermediate,
    /// Multi-party, multi-jurisdiction
    Advanced,
    /// Complex regulatory, adversarial testing
    Expert,
}

impl Complexity {
    pub fn display(&self) -> &'static str {
        match self {
            Complexity::Basic => "⭐ Basic",
            Complexity::Intermediate => "⭐⭐ Intermediate",
            Complexity::Advanced => "⭐⭐⭐ Advanced",
            Complexity::Expert => "⭐⭐⭐⭐ Expert",
        }
    }
}

/// Compliance requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRequirement {
    /// Requirement ID
    pub id: String,
    /// Name
    pub name: String,
    /// Regulation
    pub regulation: String,
    /// Description
    pub description: String,
    /// Is mandatory
    pub mandatory: bool,
    /// Verification method
    pub verification: String,
}

// ============================================================================
// Data Model
// ============================================================================

/// Data model for a scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataModel {
    /// Entities involved
    pub entities: Vec<Entity>,
    /// Data fields
    pub fields: Vec<DataField>,
    /// Sample data
    pub sample_data: HashMap<String, serde_json::Value>,
}

/// An entity in the data model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    /// Entity ID
    pub id: String,
    /// Entity name
    pub name: String,
    /// Entity type
    pub entity_type: EntityType,
    /// Role in scenario
    pub role: String,
    /// Jurisdiction
    pub jurisdiction: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityType {
    Bank,
    Corporation,
    Individual,
    Government,
    Validator,
    DataProvider,
}

/// A data field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataField {
    /// Field name
    pub name: String,
    /// Data type
    pub data_type: DataType,
    /// Owner entity
    pub owner: String,
    /// Is sensitive
    pub sensitive: bool,
    /// Description
    pub description: String,
}

// ============================================================================
// Workflow
// ============================================================================

/// A workflow step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    /// Step number
    pub step: u32,
    /// Step name
    pub name: String,
    /// Description
    pub description: String,
    /// Actor (entity performing this step)
    pub actor: String,
    /// Action type
    pub action: ActionType,
    /// Expected duration (seconds)
    pub duration_secs: u32,
    /// Prerequisites
    pub prerequisites: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    DataSubmission,
    Verification,
    AIInference,
    Attestation,
    DataTransfer,
    ComplianceCheck,
    Approval,
    Settlement,
    AuditExport,
}

// ============================================================================
// Test Cases
// ============================================================================

/// A test case for the scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    /// Test case ID
    pub id: String,
    /// Name
    pub name: String,
    /// Description
    pub description: String,
    /// Test type
    pub test_type: TestType,
    /// Expected outcome
    pub expected_outcome: ExpectedOutcome,
    /// Inputs
    pub inputs: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestType {
    /// Happy path
    HappyPath,
    /// Regulatory violation
    ComplianceViolation,
    /// Adversarial attack
    AdversarialAttack,
    /// Performance test
    Performance,
    /// Edge case
    EdgeCase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExpectedOutcome {
    Success,
    Failure { reason: String },
    Blocked { violation: String },
    Timeout,
}

/// Success criterion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessCriterion {
    /// Criterion ID
    pub id: String,
    /// Description
    pub description: String,
    /// Metric
    pub metric: String,
    /// Target value
    pub target: String,
    /// Is critical
    pub critical: bool,
}

// ============================================================================
// Scenario Library
// ============================================================================

/// The Scenario Library
pub struct ScenarioLibrary {
    /// Available scenarios
    scenarios: HashMap<String, Scenario>,
}

impl ScenarioLibrary {
    pub fn new() -> Self {
        let mut library = ScenarioLibrary {
            scenarios: HashMap::new(),
        };

        library.load_default_scenarios();
        library
    }

    fn load_default_scenarios(&mut self) {
        // UAE-Singapore Trade Settlement
        self.scenarios.insert(
            "uae_sg_trade".to_string(),
            Scenario {
                id: "uae_sg_trade".to_string(),
                name: "UAE-Singapore Trade Settlement".to_string(),
                description: "Cross-border Letter of Credit processing with sovereign data \
                         requirements. FAB initiates LC, DBS verifies counterparty, \
                         settlement through Aethelred with Digital Seal."
                    .to_string(),
                category: ScenarioCategory::TradeFinance,
                industry: Industry::Banking,
                complexity: Complexity::Advanced,
                duration_minutes: 45,
                jurisdictions: vec!["AE".to_string(), "SG".to_string()],
                compliance: vec![
                    ComplianceRequirement {
                        id: "uae_ds".to_string(),
                        name: "UAE Data Sovereignty".to_string(),
                        regulation: "UAE Federal Decree-Law No. 45/2021".to_string(),
                        description: "Data must remain in UAE or approved jurisdictions"
                            .to_string(),
                        mandatory: true,
                        verification: "Data location audit".to_string(),
                    },
                    ComplianceRequirement {
                        id: "mas_outsourcing".to_string(),
                        name: "MAS Outsourcing Guidelines".to_string(),
                        regulation: "MAS Technology Risk Management".to_string(),
                        description: "Outsourced computation must meet MAS standards".to_string(),
                        mandatory: true,
                        verification: "TEE attestation".to_string(),
                    },
                ],
                data_model: DataModel {
                    entities: vec![
                        Entity {
                            id: "fab".to_string(),
                            name: "First Abu Dhabi Bank".to_string(),
                            entity_type: EntityType::Bank,
                            role: "LC Issuer".to_string(),
                            jurisdiction: "AE".to_string(),
                        },
                        Entity {
                            id: "dbs".to_string(),
                            name: "DBS Bank".to_string(),
                            entity_type: EntityType::Bank,
                            role: "LC Advising Bank".to_string(),
                            jurisdiction: "SG".to_string(),
                        },
                        Entity {
                            id: "importer".to_string(),
                            name: "UAE Importer Corp".to_string(),
                            entity_type: EntityType::Corporation,
                            role: "Applicant".to_string(),
                            jurisdiction: "AE".to_string(),
                        },
                        Entity {
                            id: "exporter".to_string(),
                            name: "Singapore Exporter Ltd".to_string(),
                            entity_type: EntityType::Corporation,
                            role: "Beneficiary".to_string(),
                            jurisdiction: "SG".to_string(),
                        },
                    ],
                    fields: vec![
                        DataField {
                            name: "lc_amount".to_string(),
                            data_type: DataType::Financial,
                            owner: "fab".to_string(),
                            sensitive: true,
                            description: "Letter of Credit amount".to_string(),
                        },
                        DataField {
                            name: "credit_score".to_string(),
                            data_type: DataType::Financial,
                            owner: "fab".to_string(),
                            sensitive: true,
                            description: "Importer credit score".to_string(),
                        },
                        DataField {
                            name: "counterparty_rating".to_string(),
                            data_type: DataType::Financial,
                            owner: "dbs".to_string(),
                            sensitive: true,
                            description: "Exporter rating".to_string(),
                        },
                    ],
                    sample_data: HashMap::new(),
                },
                workflow: vec![
                    WorkflowStep {
                        step: 1,
                        name: "LC Application".to_string(),
                        description: "FAB receives LC application from UAE Importer".to_string(),
                        actor: "fab".to_string(),
                        action: ActionType::DataSubmission,
                        duration_secs: 60,
                        prerequisites: vec![],
                    },
                    WorkflowStep {
                        step: 2,
                        name: "Credit Check".to_string(),
                        description: "Aethelred validates importer credit in TEE".to_string(),
                        actor: "validator".to_string(),
                        action: ActionType::AIInference,
                        duration_secs: 30,
                        prerequisites: vec![1],
                    },
                    WorkflowStep {
                        step: 3,
                        name: "Counterparty Verification".to_string(),
                        description: "DBS verifies exporter in clean room".to_string(),
                        actor: "dbs".to_string(),
                        action: ActionType::Verification,
                        duration_secs: 45,
                        prerequisites: vec![2],
                    },
                    WorkflowStep {
                        step: 4,
                        name: "Digital Seal".to_string(),
                        description: "Create immutable record of verification".to_string(),
                        actor: "validator".to_string(),
                        action: ActionType::Attestation,
                        duration_secs: 10,
                        prerequisites: vec![3],
                    },
                    WorkflowStep {
                        step: 5,
                        name: "Settlement".to_string(),
                        description: "Execute LC settlement".to_string(),
                        actor: "fab".to_string(),
                        action: ActionType::Settlement,
                        duration_secs: 30,
                        prerequisites: vec![4],
                    },
                ],
                test_cases: vec![
                    TestCase {
                        id: "happy_path".to_string(),
                        name: "Successful Settlement".to_string(),
                        description: "Normal LC processing with all checks passing".to_string(),
                        test_type: TestType::HappyPath,
                        expected_outcome: ExpectedOutcome::Success,
                        inputs: HashMap::new(),
                    },
                    TestCase {
                        id: "data_sovereignty".to_string(),
                        name: "US Data Transfer Block".to_string(),
                        description: "Attempt to process through US data center".to_string(),
                        test_type: TestType::ComplianceViolation,
                        expected_outcome: ExpectedOutcome::Blocked {
                            violation: "UAE Data Sovereignty".to_string(),
                        },
                        inputs: HashMap::new(),
                    },
                ],
                success_criteria: vec![
                    SuccessCriterion {
                        id: "data_locality".to_string(),
                        description: "Data never leaves approved jurisdictions".to_string(),
                        metric: "data_transfers_blocked".to_string(),
                        target: "0 violations".to_string(),
                        critical: true,
                    },
                    SuccessCriterion {
                        id: "seal_created".to_string(),
                        description: "Digital Seal created with valid attestation".to_string(),
                        metric: "seal_valid".to_string(),
                        target: "true".to_string(),
                        critical: true,
                    },
                ],
                tags: vec![
                    "trade-finance".to_string(),
                    "cross-border".to_string(),
                    "letter-of-credit".to_string(),
                ],
                author: "Aethelred Team".to_string(),
                version: "1.0.0".to_string(),
            },
        );

        // M42 Genomic Analysis
        self.scenarios.insert(
            "m42_genomics".to_string(),
            Scenario {
                id: "m42_genomics".to_string(),
                name: "M42 Genomic Blind Compute".to_string(),
                description: "Multi-party genomic analysis for personalized medicine. \
                         Multiple hospitals contribute encrypted patient data, \
                         AI model runs in TEE without exposing raw genomes."
                    .to_string(),
                category: ScenarioCategory::Healthcare,
                industry: Industry::Healthcare,
                complexity: Complexity::Expert,
                duration_minutes: 60,
                jurisdictions: vec!["AE".to_string()],
                compliance: vec![
                    ComplianceRequirement {
                        id: "hipaa".to_string(),
                        name: "HIPAA".to_string(),
                        regulation: "45 CFR 164.502".to_string(),
                        description: "PHI must be protected".to_string(),
                        mandatory: true,
                        verification: "Encryption + TEE".to_string(),
                    },
                    ComplianceRequirement {
                        id: "uae_health".to_string(),
                        name: "UAE Health Data Protection".to_string(),
                        regulation: "DOH Healthcare Data Policy".to_string(),
                        description: "Health data must remain in UAE".to_string(),
                        mandatory: true,
                        verification: "Data locality audit".to_string(),
                    },
                ],
                data_model: DataModel {
                    entities: vec![
                        Entity {
                            id: "cleveland_clinic".to_string(),
                            name: "Cleveland Clinic Abu Dhabi".to_string(),
                            entity_type: EntityType::DataProvider,
                            role: "Genomic Data Provider".to_string(),
                            jurisdiction: "AE".to_string(),
                        },
                        Entity {
                            id: "m42".to_string(),
                            name: "M42 Health".to_string(),
                            entity_type: EntityType::Corporation,
                            role: "Analysis Platform".to_string(),
                            jurisdiction: "AE".to_string(),
                        },
                    ],
                    fields: vec![
                        DataField {
                            name: "patient_genome".to_string(),
                            data_type: DataType::Genetic,
                            owner: "cleveland_clinic".to_string(),
                            sensitive: true,
                            description: "Patient genomic sequence (encrypted)".to_string(),
                        },
                        DataField {
                            name: "disease_markers".to_string(),
                            data_type: DataType::PHI,
                            owner: "cleveland_clinic".to_string(),
                            sensitive: true,
                            description: "Known disease markers".to_string(),
                        },
                    ],
                    sample_data: HashMap::new(),
                },
                workflow: vec![
                    WorkflowStep {
                        step: 1,
                        name: "Data Encryption".to_string(),
                        description: "Hospital encrypts genomic data for TEE".to_string(),
                        actor: "cleveland_clinic".to_string(),
                        action: ActionType::DataSubmission,
                        duration_secs: 120,
                        prerequisites: vec![],
                    },
                    WorkflowStep {
                        step: 2,
                        name: "TEE Ingestion".to_string(),
                        description: "Encrypted data loaded into Intel SGX enclave".to_string(),
                        actor: "validator".to_string(),
                        action: ActionType::DataTransfer,
                        duration_secs: 60,
                        prerequisites: vec![1],
                    },
                    WorkflowStep {
                        step: 3,
                        name: "Genomic Analysis".to_string(),
                        description: "AI model analyzes genome within TEE".to_string(),
                        actor: "validator".to_string(),
                        action: ActionType::AIInference,
                        duration_secs: 300,
                        prerequisites: vec![2],
                    },
                    WorkflowStep {
                        step: 4,
                        name: "Result Encryption".to_string(),
                        description: "Results encrypted for authorized recipients only".to_string(),
                        actor: "validator".to_string(),
                        action: ActionType::Attestation,
                        duration_secs: 30,
                        prerequisites: vec![3],
                    },
                ],
                test_cases: vec![
                    TestCase {
                        id: "blind_compute".to_string(),
                        name: "Blind Compute Success".to_string(),
                        description: "Analysis completes without data exposure".to_string(),
                        test_type: TestType::HappyPath,
                        expected_outcome: ExpectedOutcome::Success,
                        inputs: HashMap::new(),
                    },
                    TestCase {
                        id: "data_leak".to_string(),
                        name: "Data Leak Prevention".to_string(),
                        description: "Attempt to exfiltrate raw genome fails".to_string(),
                        test_type: TestType::AdversarialAttack,
                        expected_outcome: ExpectedOutcome::Blocked {
                            violation: "Data leak detected".to_string(),
                        },
                        inputs: HashMap::new(),
                    },
                ],
                success_criteria: vec![SuccessCriterion {
                    id: "no_plaintext".to_string(),
                    description: "Raw genomic data never leaves TEE".to_string(),
                    metric: "plaintext_exposure".to_string(),
                    target: "0 bytes".to_string(),
                    critical: true,
                }],
                tags: vec![
                    "healthcare".to_string(),
                    "genomics".to_string(),
                    "blind-compute".to_string(),
                    "tee".to_string(),
                ],
                author: "Aethelred Team".to_string(),
                version: "1.0.0".to_string(),
            },
        );

        // AML Transaction Monitoring
        self.scenarios.insert(
            "aml_monitoring".to_string(),
            Scenario {
                id: "aml_monitoring".to_string(),
                name: "AML Transaction Monitoring".to_string(),
                description: "Real-time suspicious activity detection across multiple \
                         financial institutions. AI models run in TEE to detect \
                         patterns without revealing individual transactions."
                    .to_string(),
                category: ScenarioCategory::FinancialCrime,
                industry: Industry::Banking,
                complexity: Complexity::Advanced,
                duration_minutes: 30,
                jurisdictions: vec!["AE".to_string(), "SG".to_string(), "UK".to_string()],
                compliance: vec![
                    ComplianceRequirement {
                        id: "fatf".to_string(),
                        name: "FATF Recommendations".to_string(),
                        regulation: "FATF Recommendation 20".to_string(),
                        description: "Suspicious transaction reporting".to_string(),
                        mandatory: true,
                        verification: "Audit trail".to_string(),
                    },
                    ComplianceRequirement {
                        id: "cbuae_aml".to_string(),
                        name: "CBUAE AML".to_string(),
                        regulation: "CBUAE AML Guidelines".to_string(),
                        description: "UAE-specific AML requirements".to_string(),
                        mandatory: true,
                        verification: "STR filing".to_string(),
                    },
                ],
                data_model: DataModel {
                    entities: vec![
                        Entity {
                            id: "bank_a".to_string(),
                            name: "UAE Bank A".to_string(),
                            entity_type: EntityType::Bank,
                            role: "Transaction Source".to_string(),
                            jurisdiction: "AE".to_string(),
                        },
                        Entity {
                            id: "bank_b".to_string(),
                            name: "SG Bank B".to_string(),
                            entity_type: EntityType::Bank,
                            role: "Transaction Destination".to_string(),
                            jurisdiction: "SG".to_string(),
                        },
                    ],
                    fields: vec![
                        DataField {
                            name: "transactions".to_string(),
                            data_type: DataType::Financial,
                            owner: "bank_a".to_string(),
                            sensitive: true,
                            description: "Transaction records".to_string(),
                        },
                        DataField {
                            name: "customer_profiles".to_string(),
                            data_type: DataType::PII,
                            owner: "bank_a".to_string(),
                            sensitive: true,
                            description: "Customer KYC data".to_string(),
                        },
                    ],
                    sample_data: HashMap::new(),
                },
                workflow: vec![
                    WorkflowStep {
                        step: 1,
                        name: "Transaction Ingestion".to_string(),
                        description: "Banks submit encrypted transactions".to_string(),
                        actor: "bank_a".to_string(),
                        action: ActionType::DataSubmission,
                        duration_secs: 10,
                        prerequisites: vec![],
                    },
                    WorkflowStep {
                        step: 2,
                        name: "Pattern Detection".to_string(),
                        description: "AI model detects suspicious patterns".to_string(),
                        actor: "validator".to_string(),
                        action: ActionType::AIInference,
                        duration_secs: 60,
                        prerequisites: vec![1],
                    },
                    WorkflowStep {
                        step: 3,
                        name: "Alert Generation".to_string(),
                        description: "Generate alerts for suspicious activity".to_string(),
                        actor: "validator".to_string(),
                        action: ActionType::ComplianceCheck,
                        duration_secs: 10,
                        prerequisites: vec![2],
                    },
                ],
                test_cases: vec![
                    TestCase {
                        id: "normal_transactions".to_string(),
                        name: "Normal Transactions".to_string(),
                        description: "Legitimate transactions pass without alert".to_string(),
                        test_type: TestType::HappyPath,
                        expected_outcome: ExpectedOutcome::Success,
                        inputs: HashMap::new(),
                    },
                    TestCase {
                        id: "suspicious_pattern".to_string(),
                        name: "Suspicious Pattern Detection".to_string(),
                        description: "Layering pattern detected and flagged".to_string(),
                        test_type: TestType::EdgeCase,
                        expected_outcome: ExpectedOutcome::Success,
                        inputs: HashMap::new(),
                    },
                ],
                success_criteria: vec![
                    SuccessCriterion {
                        id: "detection_rate".to_string(),
                        description: "Suspicious activity detection rate".to_string(),
                        metric: "detection_rate".to_string(),
                        target: ">95%".to_string(),
                        critical: true,
                    },
                    SuccessCriterion {
                        id: "false_positive".to_string(),
                        description: "False positive rate".to_string(),
                        metric: "false_positive_rate".to_string(),
                        target: "<5%".to_string(),
                        critical: false,
                    },
                ],
                tags: vec![
                    "aml".to_string(),
                    "compliance".to_string(),
                    "transaction-monitoring".to_string(),
                ],
                author: "Aethelred Team".to_string(),
                version: "1.0.0".to_string(),
            },
        );

        // Credit Scoring
        self.scenarios.insert(
            "credit_scoring".to_string(),
            Scenario {
                id: "credit_scoring".to_string(),
                name: "AI Credit Scoring Verification".to_string(),
                description: "Verifiable AI credit scoring for loan applications. \
                         Bank submits application data, AI model runs in TEE, \
                         Digital Seal provides audit trail."
                    .to_string(),
                category: ScenarioCategory::CreditRisk,
                industry: Industry::Banking,
                complexity: Complexity::Intermediate,
                duration_minutes: 15,
                jurisdictions: vec!["AE".to_string()],
                compliance: vec![ComplianceRequirement {
                    id: "fair_lending".to_string(),
                    name: "Fair Lending".to_string(),
                    regulation: "CBUAE Consumer Protection".to_string(),
                    description: "Non-discriminatory credit decisions".to_string(),
                    mandatory: true,
                    verification: "Model audit".to_string(),
                }],
                data_model: DataModel {
                    entities: vec![
                        Entity {
                            id: "lending_bank".to_string(),
                            name: "Lending Bank".to_string(),
                            entity_type: EntityType::Bank,
                            role: "Lender".to_string(),
                            jurisdiction: "AE".to_string(),
                        },
                        Entity {
                            id: "applicant".to_string(),
                            name: "Loan Applicant".to_string(),
                            entity_type: EntityType::Individual,
                            role: "Borrower".to_string(),
                            jurisdiction: "AE".to_string(),
                        },
                    ],
                    fields: vec![
                        DataField {
                            name: "income".to_string(),
                            data_type: DataType::Financial,
                            owner: "applicant".to_string(),
                            sensitive: true,
                            description: "Annual income".to_string(),
                        },
                        DataField {
                            name: "employment_history".to_string(),
                            data_type: DataType::PII,
                            owner: "applicant".to_string(),
                            sensitive: true,
                            description: "Employment history".to_string(),
                        },
                        DataField {
                            name: "credit_history".to_string(),
                            data_type: DataType::Financial,
                            owner: "lending_bank".to_string(),
                            sensitive: true,
                            description: "Credit bureau data".to_string(),
                        },
                    ],
                    sample_data: HashMap::new(),
                },
                workflow: vec![
                    WorkflowStep {
                        step: 1,
                        name: "Application Submission".to_string(),
                        description: "Bank submits loan application data".to_string(),
                        actor: "lending_bank".to_string(),
                        action: ActionType::DataSubmission,
                        duration_secs: 10,
                        prerequisites: vec![],
                    },
                    WorkflowStep {
                        step: 2,
                        name: "Credit Scoring".to_string(),
                        description: "AI model scores application in TEE".to_string(),
                        actor: "validator".to_string(),
                        action: ActionType::AIInference,
                        duration_secs: 30,
                        prerequisites: vec![1],
                    },
                    WorkflowStep {
                        step: 3,
                        name: "Digital Seal".to_string(),
                        description: "Create verifiable proof of scoring".to_string(),
                        actor: "validator".to_string(),
                        action: ActionType::Attestation,
                        duration_secs: 10,
                        prerequisites: vec![2],
                    },
                    WorkflowStep {
                        step: 4,
                        name: "Decision".to_string(),
                        description: "Bank receives verified credit decision".to_string(),
                        actor: "lending_bank".to_string(),
                        action: ActionType::Approval,
                        duration_secs: 5,
                        prerequisites: vec![3],
                    },
                ],
                test_cases: vec![
                    TestCase {
                        id: "approved".to_string(),
                        name: "Loan Approved".to_string(),
                        description: "Qualified applicant receives approval".to_string(),
                        test_type: TestType::HappyPath,
                        expected_outcome: ExpectedOutcome::Success,
                        inputs: HashMap::new(),
                    },
                    TestCase {
                        id: "denied".to_string(),
                        name: "Loan Denied".to_string(),
                        description: "Unqualified applicant receives denial".to_string(),
                        test_type: TestType::HappyPath,
                        expected_outcome: ExpectedOutcome::Success,
                        inputs: HashMap::new(),
                    },
                ],
                success_criteria: vec![SuccessCriterion {
                    id: "verifiable".to_string(),
                    description: "Decision is cryptographically verifiable".to_string(),
                    metric: "seal_valid".to_string(),
                    target: "true".to_string(),
                    critical: true,
                }],
                tags: vec![
                    "credit-scoring".to_string(),
                    "lending".to_string(),
                    "ai-verification".to_string(),
                ],
                author: "Aethelred Team".to_string(),
                version: "1.0.0".to_string(),
            },
        );
    }

    /// Get all scenarios
    pub fn get_all(&self) -> Vec<&Scenario> {
        self.scenarios.values().collect()
    }

    /// Get scenario by ID
    pub fn get(&self, id: &str) -> Option<&Scenario> {
        self.scenarios.get(id)
    }

    /// Get scenarios by category
    pub fn get_by_category(&self, category: ScenarioCategory) -> Vec<&Scenario> {
        self.scenarios
            .values()
            .filter(|s| s.category == category)
            .collect()
    }

    /// Generate library UI
    pub fn generate_ui(&self) -> String {
        let mut ui = String::new();

        ui.push_str(
            r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                        📚 SCENARIO LIBRARY                                    ║
╠═══════════════════════════════════════════════════════════════════════════════╣
"#,
        );

        // Group by category
        let categories = [
            ScenarioCategory::TradeFinance,
            ScenarioCategory::Healthcare,
            ScenarioCategory::FinancialCrime,
            ScenarioCategory::CreditRisk,
        ];

        for category in &categories {
            let scenarios = self.get_by_category(category.clone());
            if scenarios.is_empty() {
                continue;
            }

            ui.push_str(&format!(
                "║                                                                               ║\n\
                 ║  {:?}                                                          ║\n\
                 ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║\n",
                category
            ));

            for scenario in scenarios {
                ui.push_str(&format!(
                    "║  │  {} {}                                    │ ║\n",
                    scenario.category.icon(),
                    scenario.name
                ));
                ui.push_str(&format!(
                    "║  │     {}                   │ ║\n",
                    &scenario.description[..scenario.description.len().min(60)]
                ));
                ui.push_str(&format!(
                    "║  │     Jurisdictions: {}  {}               │ ║\n",
                    scenario.jurisdictions.join(", "),
                    scenario.complexity.display()
                ));
                ui.push_str("║  │     [Load Scenario]                                                     │ ║\n");
                ui.push_str("║  │                                                                         │ ║\n");
            }

            ui.push_str("║  └─────────────────────────────────────────────────────────────────────────┘ ║\n");
        }

        ui.push_str(
            "║                                                                               ║\n\
             ╚═══════════════════════════════════════════════════════════════════════════════╝\n",
        );

        ui
    }
}

impl Default for ScenarioLibrary {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scenario_library() {
        let library = ScenarioLibrary::new();

        assert!(library.get("uae_sg_trade").is_some());
        assert!(library.get("m42_genomics").is_some());
        assert!(library.get("aml_monitoring").is_some());
        assert!(library.get("credit_scoring").is_some());
    }

    #[test]
    fn test_get_by_category() {
        let library = ScenarioLibrary::new();

        let trade_scenarios = library.get_by_category(ScenarioCategory::TradeFinance);
        assert!(!trade_scenarios.is_empty());
    }
}
