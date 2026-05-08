//! Enterprise-grade regulated AI sandbox packs.
//!
//! This module turns the 2026 sandbox strategy into executable, testable
//! scenario definitions. It is intentionally conservative: first runs use
//! synthetic/non-production data, policy gates fail closed, and the generated
//! evidence record is a sandbox artifact, not a regulatory certification.

use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

/// Regulated verticals supported by the enterprise sandbox program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegulatedVertical {
    Finance,
    Healthcare,
    Defense,
    SupplyChain,
    AutonomousMobility,
    AiAgents,
    Research,
}

impl RegulatedVertical {
    pub fn as_str(self) -> &'static str {
        match self {
            RegulatedVertical::Finance => "finance",
            RegulatedVertical::Healthcare => "healthcare",
            RegulatedVertical::Defense => "defense",
            RegulatedVertical::SupplyChain => "supply_chain",
            RegulatedVertical::AutonomousMobility => "autonomous_mobility",
            RegulatedVertical::AiAgents => "ai_agents",
            RegulatedVertical::Research => "research",
        }
    }
}

/// Sandbox maturity levels used by the 2026 enterprise sandbox roadmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SandboxMaturity {
    Narrative = 0,
    ClickableDemo = 1,
    ExecutableSandbox = 2,
    AdversarialSandbox = 3,
    DesignPartnerPilot = 4,
    ProductionCandidate = 5,
}

/// First-party data-boundary choices. Production data is deliberately absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataBoundary {
    Synthetic,
    Anonymized,
    Public,
    EnterpriseApprovedNonProduction,
}

impl DataBoundary {
    pub fn is_sandbox_safe(self) -> bool {
        matches!(
            self,
            DataBoundary::Synthetic
                | DataBoundary::Anonymized
                | DataBoundary::Public
                | DataBoundary::EnterpriseApprovedNonProduction
        )
    }
}

/// High-level decision produced by the sandbox policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxDecision {
    Allow,
    ReviewRequired,
    Deny,
    FailClosed,
}

/// Faults used to exercise policy and adversarial behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SandboxFault {
    SensitiveDataOnChain,
    StaleModelVersion,
    MissingHumanReview,
    UnauthorizedReviewer,
    TamperedInput,
    MissingRequiredDocument,
    ExpiredCredential,
    PromptInjection,
    UnauthorizedToolCall,
    ScopeViolation,
    ClassificationLeakage,
    OutOfDomainOperation,
    DatasetChanged,
    MetricTampered,
    MissingReviewer,
    UnlicensedDataset,
}

impl SandboxFault {
    pub fn label(self) -> &'static str {
        match self {
            SandboxFault::SensitiveDataOnChain => "sensitive_data_on_chain",
            SandboxFault::StaleModelVersion => "stale_model_version",
            SandboxFault::MissingHumanReview => "missing_human_review",
            SandboxFault::UnauthorizedReviewer => "unauthorized_reviewer",
            SandboxFault::TamperedInput => "tampered_input",
            SandboxFault::MissingRequiredDocument => "missing_required_document",
            SandboxFault::ExpiredCredential => "expired_credential",
            SandboxFault::PromptInjection => "prompt_injection",
            SandboxFault::UnauthorizedToolCall => "unauthorized_tool_call",
            SandboxFault::ScopeViolation => "scope_violation",
            SandboxFault::ClassificationLeakage => "classification_leakage",
            SandboxFault::OutOfDomainOperation => "out_of_domain_operation",
            SandboxFault::DatasetChanged => "dataset_changed",
            SandboxFault::MetricTampered => "metric_tampered",
            SandboxFault::MissingReviewer => "missing_reviewer",
            SandboxFault::UnlicensedDataset => "unlicensed_dataset",
        }
    }
}

/// A vertical policy gate that can be evaluated during a sandbox run.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyGate {
    pub id: &'static str,
    pub name: &'static str,
    pub rule: &'static str,
    pub required: bool,
    pub blocks_on: Vec<SandboxFault>,
}

/// A negative test that proves the sandbox is not happy-path theater.
#[derive(Debug, Clone, Serialize)]
pub struct AdversarialTest {
    pub id: &'static str,
    pub name: &'static str,
    pub fault: SandboxFault,
    pub expected_result: SandboxDecision,
}

/// A data object shown in the sandbox scenario console.
#[derive(Debug, Clone, Serialize)]
pub struct SandboxDataObject {
    pub name: &'static str,
    pub fields: Vec<&'static str>,
    pub sensitivity: &'static str,
}

/// Evidence fields emitted by a sandbox run.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceField {
    pub name: &'static str,
    pub commitment_field: &'static str,
    pub description: &'static str,
}

/// Complete scenario pack for one regulated sandbox.
#[derive(Debug, Clone, Serialize)]
pub struct EnterpriseSandbox {
    pub id: &'static str,
    pub label: &'static str,
    pub vertical: RegulatedVertical,
    pub hero_scenario: &'static str,
    pub buyer_question: &'static str,
    pub target_accounts: Vec<&'static str>,
    pub jurisdiction_profile: &'static str,
    pub minimum_maturity: SandboxMaturity,
    pub data_objects: Vec<SandboxDataObject>,
    pub policy_gates: Vec<PolicyGate>,
    pub evidence_fields: Vec<EvidenceField>,
    pub adversarial_tests: Vec<AdversarialTest>,
    pub prohibited_scope: Vec<&'static str>,
    pub loi_conversion_ask: &'static str,
}

/// Input for an executable sandbox run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRunConfig {
    pub scenario_id: String,
    pub data_boundary: DataBoundary,
    pub reviewer_role: String,
    pub faults: Vec<SandboxFault>,
}

impl SandboxRunConfig {
    pub fn happy_path(scenario_id: impl Into<String>) -> Self {
        Self {
            scenario_id: scenario_id.into(),
            data_boundary: DataBoundary::Synthetic,
            reviewer_role: "authorized_reviewer".to_string(),
            faults: Vec::new(),
        }
    }

    pub fn with_fault(mut self, fault: SandboxFault) -> Self {
        if !self.faults.contains(&fault) {
            self.faults.push(fault);
        }
        self
    }

    pub fn with_data_boundary(mut self, data_boundary: DataBoundary) -> Self {
        self.data_boundary = data_boundary;
        self
    }
}

/// Result of evaluating one policy gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateResult {
    pub gate_id: String,
    pub gate_name: String,
    pub passed: bool,
    pub decision: SandboxDecision,
    pub triggered_faults: Vec<SandboxFault>,
}

/// Portable sandbox evidence record. This maps conceptually to the broader
/// Aethelred evidence-bundle model and can be exported for UI/audit surfaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxEvidenceRecord {
    pub schema_version: String,
    pub sandbox_id: String,
    pub scenario_id: String,
    pub vertical: RegulatedVertical,
    pub jurisdiction_profile: String,
    pub data_boundary: DataBoundary,
    pub event_id: String,
    pub event_type: String,
    pub model_or_agent_commitment: String,
    pub policy_version: String,
    pub input_commitment: String,
    pub output_commitment: String,
    pub review_commitment: String,
    pub policy_decision: SandboxDecision,
    pub data_boundary_status: String,
    pub adversarial_test_status: String,
    pub digital_seal_id: String,
    pub evidence_bundle_hash: String,
}

/// Full run report for a sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRunReport {
    pub sandbox_id: String,
    pub label: String,
    pub decision: SandboxDecision,
    pub gate_results: Vec<GateResult>,
    pub triggered_faults: Vec<SandboxFault>,
    pub evidence_record: SandboxEvidenceRecord,
    pub audit_summary: String,
    pub loi_ready: bool,
}

impl SandboxRunReport {
    pub fn passed(&self) -> bool {
        matches!(self.decision, SandboxDecision::Allow)
    }
}

/// Return all seven regulated enterprise sandbox packs.
pub fn regulated_sandbox_catalog() -> Vec<EnterpriseSandbox> {
    vec![
        finance_sandbox(),
        healthcare_sandbox(),
        defense_sandbox(),
        supply_chain_sandbox(),
        autonomous_mobility_sandbox(),
        ai_agent_sandbox(),
        research_sandbox(),
    ]
}

/// Lookup a sandbox by id.
pub fn get_enterprise_sandbox(id: &str) -> Option<EnterpriseSandbox> {
    regulated_sandbox_catalog()
        .into_iter()
        .find(|sandbox| sandbox.id == id)
}

/// Execute a sandbox pack with a run configuration.
pub fn execute_sandbox_run(
    sandbox: &EnterpriseSandbox,
    config: &SandboxRunConfig,
) -> SandboxRunReport {
    let mut gate_results = Vec::with_capacity(sandbox.policy_gates.len());
    let mut decision = SandboxDecision::Allow;

    if !config.data_boundary.is_sandbox_safe() {
        decision = SandboxDecision::FailClosed;
    }

    for gate in &sandbox.policy_gates {
        let triggered_faults = gate
            .blocks_on
            .iter()
            .copied()
            .filter(|fault| config.faults.contains(fault))
            .collect::<Vec<_>>();
        let passed = triggered_faults.is_empty();
        let gate_decision = if passed {
            SandboxDecision::Allow
        } else if gate.required {
            SandboxDecision::FailClosed
        } else {
            SandboxDecision::ReviewRequired
        };

        if matches!(gate_decision, SandboxDecision::FailClosed) {
            decision = SandboxDecision::FailClosed;
        } else if matches!(gate_decision, SandboxDecision::ReviewRequired)
            && matches!(decision, SandboxDecision::Allow)
        {
            decision = SandboxDecision::ReviewRequired;
        }

        gate_results.push(GateResult {
            gate_id: gate.id.to_string(),
            gate_name: gate.name.to_string(),
            passed,
            decision: gate_decision,
            triggered_faults,
        });
    }

    let evidence_record = build_evidence_record(sandbox, config, decision);
    let passed_count = gate_results.iter().filter(|result| result.passed).count();
    let audit_summary = format!(
        "{} produced decision {:?}: {}/{} policy gates passed; {} fault(s) triggered.",
        sandbox.label,
        decision,
        passed_count,
        gate_results.len(),
        config.faults.len()
    );
    let loi_ready = matches!(decision, SandboxDecision::Allow)
        && sandbox.minimum_maturity >= SandboxMaturity::ExecutableSandbox;

    SandboxRunReport {
        sandbox_id: sandbox.id.to_string(),
        label: sandbox.label.to_string(),
        decision,
        gate_results,
        triggered_faults: config.faults.clone(),
        evidence_record,
        audit_summary,
        loi_ready,
    }
}

/// Execute every configured adversarial test for a sandbox pack.
pub fn run_adversarial_suite(sandbox: &EnterpriseSandbox) -> Vec<SandboxRunReport> {
    sandbox
        .adversarial_tests
        .iter()
        .map(|test| {
            let config = SandboxRunConfig::happy_path(test.id).with_fault(test.fault);
            execute_sandbox_run(sandbox, &config)
        })
        .collect()
}

fn build_evidence_record(
    sandbox: &EnterpriseSandbox,
    config: &SandboxRunConfig,
    decision: SandboxDecision,
) -> SandboxEvidenceRecord {
    let event_id = format!("evt_{}_{}", sandbox.id, now_millis().unwrap_or_default());
    let base = format!(
        "{}:{}:{:?}:{:?}:{:?}",
        sandbox.id, config.scenario_id, sandbox.vertical, config.data_boundary, config.faults
    );
    let input_commitment = synthetic_commitment("input", &base);
    let output_commitment = synthetic_commitment("output", &base);
    let review_commitment = synthetic_commitment("review", &config.reviewer_role);
    let model_or_agent_commitment = synthetic_commitment("model_or_agent", sandbox.hero_scenario);
    let evidence_bundle_hash = synthetic_commitment(
        "evidence_bundle",
        &format!(
            "{}:{}:{}",
            input_commitment, output_commitment, review_commitment
        ),
    );

    SandboxEvidenceRecord {
        schema_version: "sandbox-evidence-v0.1".to_string(),
        sandbox_id: sandbox.id.to_string(),
        scenario_id: config.scenario_id.clone(),
        vertical: sandbox.vertical,
        jurisdiction_profile: sandbox.jurisdiction_profile.to_string(),
        data_boundary: config.data_boundary,
        event_id,
        event_type: "regulated_ai_sandbox_run".to_string(),
        model_or_agent_commitment,
        policy_version: format!("{}-policy-v0.1", sandbox.id),
        input_commitment,
        output_commitment,
        review_commitment,
        policy_decision: decision,
        data_boundary_status: if config.faults.contains(&SandboxFault::SensitiveDataOnChain) {
            "fail".to_string()
        } else {
            "pass".to_string()
        },
        adversarial_test_status: if config.faults.is_empty() {
            "not_run".to_string()
        } else if matches!(decision, SandboxDecision::Allow) {
            "unexpected_pass".to_string()
        } else {
            "blocked_or_review_required".to_string()
        },
        digital_seal_id: format!(
            "seal_{}",
            synthetic_commitment("seal", &evidence_bundle_hash)
        ),
        evidence_bundle_hash,
    }
}

fn now_millis() -> Option<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis())
}

fn synthetic_commitment(label: &str, value: &str) -> String {
    // Sandbox-only deterministic commitment. Production code should use the
    // protocol cryptography layer rather than DefaultHasher.
    let mut out = String::with_capacity(64);
    for salt in 0..4 {
        let mut hasher = DefaultHasher::new();
        label.hash(&mut hasher);
        value.hash(&mut hasher);
        salt.hash(&mut hasher);
        out.push_str(&format!("{:016x}", hasher.finish()));
    }
    out
}

fn gate(
    id: &'static str,
    name: &'static str,
    rule: &'static str,
    blocks_on: Vec<SandboxFault>,
) -> PolicyGate {
    PolicyGate {
        id,
        name,
        rule,
        required: true,
        blocks_on,
    }
}

fn optional_gate(
    id: &'static str,
    name: &'static str,
    rule: &'static str,
    blocks_on: Vec<SandboxFault>,
) -> PolicyGate {
    PolicyGate {
        id,
        name,
        rule,
        required: false,
        blocks_on,
    }
}

fn test(
    id: &'static str,
    name: &'static str,
    fault: SandboxFault,
    expected_result: SandboxDecision,
) -> AdversarialTest {
    AdversarialTest {
        id,
        name,
        fault,
        expected_result,
    }
}

fn data_object(
    name: &'static str,
    fields: Vec<&'static str>,
    sensitivity: &'static str,
) -> SandboxDataObject {
    SandboxDataObject {
        name,
        fields,
        sensitivity,
    }
}

fn evidence(
    name: &'static str,
    commitment_field: &'static str,
    description: &'static str,
) -> EvidenceField {
    EvidenceField {
        name,
        commitment_field,
        description,
    }
}

fn common_evidence_fields() -> Vec<EvidenceField> {
    vec![
        evidence(
            "Input snapshot",
            "input_commitment",
            "Approved sandbox input state",
        ),
        evidence(
            "AI output",
            "output_commitment",
            "Model, workflow, or agent result",
        ),
        evidence(
            "Policy receipt",
            "policy_version",
            "Policy version and decision",
        ),
        evidence(
            "Human review",
            "review_commitment",
            "Reviewer decision or escalation",
        ),
        evidence(
            "Digital Seal",
            "digital_seal_id",
            "Portable Aethelred evidence object",
        ),
    ]
}

fn finance_sandbox() -> EnterpriseSandbox {
    EnterpriseSandbox {
        id: "finance_ai_assurance",
        label: "Finance AI Assurance",
        vertical: RegulatedVertical::Finance,
        hero_scenario: "AI-assisted credit memo with human review",
        buyer_question:
            "Can we prove what data, model version, policy, human approval, and evidence existed when AI influenced a financial decision?",
        target_accounts: vec!["FAB", "EDB", "ADIO", "Khalifa Fund", "Mubadala", "IHC"],
        jurisdiction_profile: "UAE-CBUAE-ADGM-DFSA-design-partner",
        minimum_maturity: SandboxMaturity::AdversarialSandbox,
        data_objects: vec![
            data_object(
                "SME application",
                vec!["applicant_id", "sector", "revenue_band", "facility_amount"],
                "financial",
            ),
            data_object(
                "Credit review",
                vec!["risk_score", "impact_score", "reviewer_role", "decision"],
                "financial",
            ),
        ],
        policy_gates: vec![
            gate(
                "model_approval",
                "Approved model version",
                "Only approved model versions can issue sealable recommendations.",
                vec![SandboxFault::StaleModelVersion],
            ),
            gate(
                "human_authority",
                "Human decision authority",
                "Final financial decision requires authorized human review.",
                vec![SandboxFault::MissingHumanReview, SandboxFault::UnauthorizedReviewer],
            ),
            gate(
                "data_boundary",
                "No raw sensitive data on-chain",
                "Financial source records remain off-chain; commitments are anchored.",
                vec![SandboxFault::SensitiveDataOnChain],
            ),
            optional_gate(
                "fairness_alert",
                "Fairness and explainability alert",
                "Risk output must include reason codes and review path.",
                vec![SandboxFault::MissingRequiredDocument],
            ),
            gate(
                "evidence_integrity",
                "Evidence integrity",
                "Tampered source or output commitments fail verification.",
                vec![SandboxFault::TamperedInput],
            ),
        ],
        evidence_fields: common_evidence_fields(),
        adversarial_tests: vec![
            test(
                "finance_stale_model",
                "Stale model version is blocked",
                SandboxFault::StaleModelVersion,
                SandboxDecision::FailClosed,
            ),
            test(
                "finance_missing_review",
                "Missing human approval is blocked",
                SandboxFault::MissingHumanReview,
                SandboxDecision::FailClosed,
            ),
            test(
                "finance_tamper",
                "Tampered credit score fails verification",
                SandboxFault::TamperedInput,
                SandboxDecision::FailClosed,
            ),
        ],
        prohibited_scope: vec![
            "regulated financial product advice",
            "automated credit approval without human authority",
        ],
        loi_conversion_ask:
            "Evaluate one non-production finance workflow using synthetic or anonymized data, with risk, compliance, and technical reviewers.",
    }
}

fn healthcare_sandbox() -> EnterpriseSandbox {
    EnterpriseSandbox {
        id: "healthcare_ai_assurance",
        label: "Healthcare AI Assurance",
        vertical: RegulatedVertical::Healthcare,
        hero_scenario: "AI-assisted radiology triage with clinical reviewer",
        buyer_question:
            "Can we prove that a healthcare AI workflow used approved data, approved model versions, appropriate human review, and privacy-preserving evidence?",
        target_accounts: vec!["M42", "PureHealth", "Globalpharma", "Julphar", "Mubadala"],
        jurisdiction_profile: "UAE-health-data-design-partner",
        minimum_maturity: SandboxMaturity::ExecutableSandbox,
        data_objects: vec![
            data_object(
                "Synthetic patient case",
                vec!["case_id", "age_band", "modality", "severity_flag"],
                "healthcare",
            ),
            data_object(
                "Clinical review",
                vec!["reviewer_role", "decision", "escalation_reason"],
                "healthcare",
            ),
        ],
        policy_gates: vec![
            gate(
                "intended_use",
                "Approved intended use",
                "Model can only run on approved modality and scenario.",
                vec![SandboxFault::StaleModelVersion],
            ),
            gate(
                "privacy_scan",
                "Privacy and identifier scan",
                "Identifier leakage blocks accepted status.",
                vec![SandboxFault::SensitiveDataOnChain],
            ),
            gate(
                "clinical_review",
                "Qualified human review",
                "Clinical decision support requires qualified reviewer receipt.",
                vec![SandboxFault::MissingHumanReview, SandboxFault::UnauthorizedReviewer],
            ),
            gate(
                "evidence_integrity",
                "Evidence integrity",
                "Tampered case or model output fails verification.",
                vec![SandboxFault::TamperedInput],
            ),
        ],
        evidence_fields: common_evidence_fields(),
        adversarial_tests: vec![
            test(
                "healthcare_privacy_leak",
                "Hidden patient identifier is blocked",
                SandboxFault::SensitiveDataOnChain,
                SandboxDecision::FailClosed,
            ),
            test(
                "healthcare_missing_review",
                "Missing clinician review is blocked",
                SandboxFault::MissingHumanReview,
                SandboxDecision::FailClosed,
            ),
            test(
                "healthcare_tamper",
                "Tampered triage output fails verification",
                SandboxFault::TamperedInput,
                SandboxDecision::FailClosed,
            ),
        ],
        prohibited_scope: vec![
            "medical diagnosis claim",
            "clinical regulatory approval claim",
            "production patient-data processing in first sandbox",
        ],
        loi_conversion_ask:
            "Evaluate one non-production healthcare AI workflow with synthetic, anonymized, or approved sample cases and clinical/privacy review.",
    }
}

fn defense_sandbox() -> EnterpriseSandbox {
    EnterpriseSandbox {
        id: "defense_ai_assurance",
        label: "Defense AI Assurance",
        vertical: RegulatedVertical::Defense,
        hero_scenario: "AI-assisted defense asset readiness review",
        buyer_question:
            "Can we prove that AI-assisted defense workflows operate inside approved mission, data, human-command, and evidence boundaries?",
        target_accounts: vec!["EDGE", "Tawazun", "TII VentureOne", "Space42", "Presight AI"],
        jurisdiction_profile: "non-weaponized-defense-design-partner",
        minimum_maturity: SandboxMaturity::ExecutableSandbox,
        data_objects: vec![
            data_object(
                "Asset readiness record",
                vec!["asset_id", "subsystem", "readiness_score", "mission_category"],
                "restricted-synthetic",
            ),
            data_object(
                "After-action log",
                vec!["event_id", "reviewer_role", "escalation", "corrective_action"],
                "restricted-synthetic",
            ),
        ],
        policy_gates: vec![
            gate(
                "non_weaponized_scope",
                "Non-weaponized scope",
                "Sandbox is limited to readiness, logistics, cyber-defense, and mission support.",
                vec![SandboxFault::ScopeViolation],
            ),
            gate(
                "classification_gate",
                "Classification and export boundary",
                "Restricted fields are blocked or redacted in sandbox exports.",
                vec![SandboxFault::ClassificationLeakage, SandboxFault::SensitiveDataOnChain],
            ),
            gate(
                "human_command_authority",
                "Human command authority",
                "AI support cannot become autonomous command action.",
                vec![SandboxFault::MissingHumanReview, SandboxFault::UnauthorizedReviewer],
            ),
            gate(
                "evidence_integrity",
                "Evidence integrity",
                "Tampered readiness or sensor records fail verification.",
                vec![SandboxFault::TamperedInput],
            ),
        ],
        evidence_fields: common_evidence_fields(),
        adversarial_tests: vec![
            test(
                "defense_scope_violation",
                "Targeting scope attempt is blocked",
                SandboxFault::ScopeViolation,
                SandboxDecision::FailClosed,
            ),
            test(
                "defense_classification_leak",
                "Restricted export field is blocked",
                SandboxFault::ClassificationLeakage,
                SandboxDecision::FailClosed,
            ),
            test(
                "defense_unauthorized_reviewer",
                "Unauthorized reviewer cannot approve",
                SandboxFault::UnauthorizedReviewer,
                SandboxDecision::FailClosed,
            ),
        ],
        prohibited_scope: vec![
            "autonomous lethal targeting",
            "weapon release decision",
            "operational targeting recommendation",
            "production classified data in sandbox",
        ],
        loi_conversion_ask:
            "Evaluate a non-production, non-weaponized defense support workflow using synthetic or sanitized data and explicit legal/security boundaries.",
    }
}

fn supply_chain_sandbox() -> EnterpriseSandbox {
    EnterpriseSandbox {
        id: "supply_chain_integrity",
        label: "Supply Chain Integrity",
        vertical: RegulatedVertical::SupplyChain,
        hero_scenario: "Supplier certificate and batch provenance verification",
        buyer_question:
            "Can we prove provenance, integrity, AI review, and human approval behind a shipment, batch, supplier certificate, or industrial asset?",
        target_accounts: vec![
            "KEZAD",
            "ADNOC",
            "Masdar",
            "Al Masaood Energy",
            "Strata",
            "Globalpharma",
            "Julphar",
            "Dubai Investments",
        ],
        jurisdiction_profile: "industrial-supply-chain-design-partner",
        minimum_maturity: SandboxMaturity::ExecutableSandbox,
        data_objects: vec![
            data_object(
                "Supplier certificate",
                vec!["certificate_id", "supplier_id", "lot_id", "expiry"],
                "commercial-confidential",
            ),
            data_object(
                "Shipment or batch",
                vec!["shipment_id", "batch_id", "origin", "destination", "qa_status"],
                "commercial-confidential",
            ),
        ],
        policy_gates: vec![
            gate(
                "supplier_approval",
                "Supplier approval",
                "Supplier must be approved and certificate must be current.",
                vec![SandboxFault::ExpiredCredential],
            ),
            gate(
                "batch_linkage",
                "Batch and document linkage",
                "Certificate, QA record, and shipment must reference the same batch.",
                vec![SandboxFault::MissingRequiredDocument],
            ),
            gate(
                "qa_signoff",
                "QA or compliance signoff",
                "High-risk anomaly requires human QA/compliance review.",
                vec![SandboxFault::MissingHumanReview, SandboxFault::UnauthorizedReviewer],
            ),
            gate(
                "evidence_integrity",
                "Evidence integrity",
                "Forged or tampered documents fail verification.",
                vec![SandboxFault::TamperedInput],
            ),
        ],
        evidence_fields: common_evidence_fields(),
        adversarial_tests: vec![
            test(
                "supply_chain_forged_certificate",
                "Forged certificate fails verification",
                SandboxFault::TamperedInput,
                SandboxDecision::FailClosed,
            ),
            test(
                "supply_chain_expired_supplier",
                "Expired supplier approval is blocked",
                SandboxFault::ExpiredCredential,
                SandboxDecision::FailClosed,
            ),
            test(
                "supply_chain_missing_qa",
                "Missing QA signoff is blocked",
                SandboxFault::MissingHumanReview,
                SandboxDecision::FailClosed,
            ),
        ],
        prohibited_scope: vec!["production supplier data without NDA and data-boundary approval"],
        loi_conversion_ask:
            "Evaluate one non-production provenance workflow with synthetic or redacted sample documents and supply-chain/QA reviewers.",
    }
}

fn autonomous_mobility_sandbox() -> EnterpriseSandbox {
    EnterpriseSandbox {
        id: "autonomous_mobility",
        label: "Autonomous Mobility",
        vertical: RegulatedVertical::AutonomousMobility,
        hero_scenario: "Autonomous fleet incident reconstruction",
        buyer_question:
            "Can we reconstruct what an autonomous system perceived, which model and policy were active, whether it stayed inside its approved operating domain, and who reviewed exceptions?",
        target_accounts: vec!["TII VentureOne", "Space42", "MBRSC", "UAE Space Agency", "EDGE"],
        jurisdiction_profile: "autonomy-safety-case-design-partner",
        minimum_maturity: SandboxMaturity::ExecutableSandbox,
        data_objects: vec![
            data_object(
                "ODD profile",
                vec!["geofence", "route", "time_window", "weather", "mission_type"],
                "operational",
            ),
            data_object(
                "Incident timeline",
                vec!["sensor_event", "ai_decision", "operator_action", "near_miss"],
                "operational",
            ),
        ],
        policy_gates: vec![
            gate(
                "odd_boundary",
                "Operational design domain",
                "Out-of-domain operation blocks or escalates the workflow.",
                vec![SandboxFault::OutOfDomainOperation],
            ),
            gate(
                "model_approval",
                "Approved autonomy model",
                "Only approved autonomy model versions can be sealed green.",
                vec![SandboxFault::StaleModelVersion],
            ),
            gate(
                "human_escalation",
                "Human safety escalation",
                "High-risk or uncertain event requires operator/safety review.",
                vec![SandboxFault::MissingHumanReview, SandboxFault::UnauthorizedReviewer],
            ),
            gate(
                "event_integrity",
                "Incident event integrity",
                "Sensor, decision, and review timeline must match.",
                vec![SandboxFault::TamperedInput],
            ),
        ],
        evidence_fields: common_evidence_fields(),
        adversarial_tests: vec![
            test(
                "mobility_out_of_domain",
                "Out-of-domain route is blocked",
                SandboxFault::OutOfDomainOperation,
                SandboxDecision::FailClosed,
            ),
            test(
                "mobility_missing_operator",
                "Missing operator receipt is blocked",
                SandboxFault::MissingHumanReview,
                SandboxDecision::FailClosed,
            ),
            test(
                "mobility_tampered_event",
                "Tampered event log fails verification",
                SandboxFault::TamperedInput,
                SandboxDecision::FailClosed,
            ),
        ],
        prohibited_scope: vec!["production vehicle control authority in sandbox"],
        loi_conversion_ask:
            "Evaluate one simulation or sanitized autonomy incident workflow with safety, operations, legal, and technical reviewers.",
    }
}

fn ai_agent_sandbox() -> EnterpriseSandbox {
    EnterpriseSandbox {
        id: "ai_agent_control_plane",
        label: "AI Agent Control Plane",
        vertical: RegulatedVertical::AiAgents,
        hero_scenario: "Regulated procurement or credit analyst agent",
        buyer_question:
            "Can we let AI agents work in the enterprise without losing control, accountability, privacy, or auditability?",
        target_accounts: vec![
            "Core42",
            "Presight AI",
            "ADIO",
            "Khalifa Fund",
            "FAB",
            "EDB",
            "IHC",
            "Mubadala",
        ],
        jurisdiction_profile: "enterprise-agent-control-design-partner",
        minimum_maturity: SandboxMaturity::AdversarialSandbox,
        data_objects: vec![
            data_object(
                "Agent passport",
                vec!["agent_id", "sponsor", "owner", "purpose", "expiry", "revocation"],
                "governance",
            ),
            data_object(
                "Tool manifest",
                vec!["tool_id", "allowed_action", "risk_tier", "approval_required"],
                "governance",
            ),
        ],
        policy_gates: vec![
            gate(
                "active_passport",
                "Active agent passport",
                "Agent must have active passport, sponsor, owner, purpose, and expiry.",
                vec![SandboxFault::ExpiredCredential],
            ),
            gate(
                "tool_permission",
                "Tool permission",
                "Tool calls outside the manifest are blocked.",
                vec![SandboxFault::UnauthorizedToolCall],
            ),
            gate(
                "prompt_injection_defense",
                "Prompt-injection defense",
                "Untrusted instructions cannot override system policy.",
                vec![SandboxFault::PromptInjection],
            ),
            gate(
                "human_approval",
                "Privileged action approval",
                "Privileged actions require authorized human approval.",
                vec![SandboxFault::MissingHumanReview, SandboxFault::UnauthorizedReviewer],
            ),
            gate(
                "evidence_integrity",
                "Evidence integrity",
                "Changed tool manifest or output fails verification.",
                vec![SandboxFault::TamperedInput],
            ),
        ],
        evidence_fields: common_evidence_fields(),
        adversarial_tests: vec![
            test(
                "agent_prompt_injection",
                "Prompt injection is blocked",
                SandboxFault::PromptInjection,
                SandboxDecision::FailClosed,
            ),
            test(
                "agent_unauthorized_tool",
                "Unauthorized tool call is blocked",
                SandboxFault::UnauthorizedToolCall,
                SandboxDecision::FailClosed,
            ),
            test(
                "agent_expired_passport",
                "Expired agent passport blocks run",
                SandboxFault::ExpiredCredential,
                SandboxDecision::FailClosed,
            ),
        ],
        prohibited_scope: vec!["privileged production actions without human approval"],
        loi_conversion_ask:
            "Evaluate one agent role, one tool manifest, and one privileged action with prompt-injection red-team tests and evidence export.",
    }
}

fn research_sandbox() -> EnterpriseSandbox {
    EnterpriseSandbox {
        id: "research_reproducibility",
        label: "Research Reproducibility",
        vertical: RegulatedVertical::Research,
        hero_scenario: "AI model evaluation and reproducibility pack",
        buyer_question:
            "Can we prove which data, model, code, parameters, reviewer approvals, and result commitments produced a research finding?",
        target_accounts: vec![
            "MBZUAI",
            "Khalifa University",
            "TII",
            "UAE Space Agency",
            "MBRSC",
            "M42",
            "PureHealth",
        ],
        jurisdiction_profile: "research-integrity-design-partner",
        minimum_maturity: SandboxMaturity::ExecutableSandbox,
        data_objects: vec![
            data_object(
                "Dataset manifest",
                vec!["dataset_id", "source", "version", "license", "hash"],
                "research",
            ),
            data_object(
                "Experiment config",
                vec!["code_hash", "model_hash", "parameters", "random_seed"],
                "research",
            ),
        ],
        policy_gates: vec![
            gate(
                "dataset_permission",
                "Dataset permission",
                "Dataset must have acceptable source, license, consent, or synthetic status.",
                vec![SandboxFault::UnlicensedDataset],
            ),
            gate(
                "version_completeness",
                "Model, code, and parameter completeness",
                "Model, code, parameters, and random seed must be versioned.",
                vec![SandboxFault::MissingRequiredDocument],
            ),
            gate(
                "reviewer_completeness",
                "Reviewer completeness",
                "Required reviewer approval must be present before accepted status.",
                vec![SandboxFault::MissingReviewer, SandboxFault::MissingHumanReview],
            ),
            gate(
                "result_integrity",
                "Result integrity",
                "Reported result must match output commitment.",
                vec![SandboxFault::DatasetChanged, SandboxFault::MetricTampered],
            ),
        ],
        evidence_fields: common_evidence_fields(),
        adversarial_tests: vec![
            test(
                "research_dataset_changed",
                "Dataset changed after result fails verification",
                SandboxFault::DatasetChanged,
                SandboxDecision::FailClosed,
            ),
            test(
                "research_metric_tampered",
                "Edited metric fails verification",
                SandboxFault::MetricTampered,
                SandboxDecision::FailClosed,
            ),
            test(
                "research_unlicensed_dataset",
                "Unlicensed dataset is blocked",
                SandboxFault::UnlicensedDataset,
                SandboxDecision::FailClosed,
            ),
        ],
        prohibited_scope: vec!["publication or customer reference without written approval"],
        loi_conversion_ask:
            "Evaluate one public, synthetic, or approved dataset with one model experiment, reviewer receipt, and reproducibility export.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_contains_all_seven_vertical_sandboxes() {
        let catalog = regulated_sandbox_catalog();
        assert_eq!(catalog.len(), 7);

        for vertical in [
            RegulatedVertical::Finance,
            RegulatedVertical::Healthcare,
            RegulatedVertical::Defense,
            RegulatedVertical::SupplyChain,
            RegulatedVertical::AutonomousMobility,
            RegulatedVertical::AiAgents,
            RegulatedVertical::Research,
        ] {
            assert!(catalog.iter().any(|sandbox| sandbox.vertical == vertical));
        }
    }

    #[test]
    fn happy_paths_emit_allow_decisions_and_digital_seals() {
        for sandbox in regulated_sandbox_catalog() {
            let report = execute_sandbox_run(
                &sandbox,
                &SandboxRunConfig::happy_path(sandbox.hero_scenario),
            );
            assert_eq!(report.decision, SandboxDecision::Allow, "{}", sandbox.id);
            assert!(report.loi_ready, "{}", sandbox.id);
            assert!(report.evidence_record.digital_seal_id.starts_with("seal_"));
            assert_eq!(report.evidence_record.data_boundary_status, "pass");
        }
    }

    #[test]
    fn adversarial_suites_fail_closed_or_require_review() {
        for sandbox in regulated_sandbox_catalog() {
            let reports = run_adversarial_suite(&sandbox);
            assert!(!reports.is_empty(), "{}", sandbox.id);
            for report in reports {
                assert!(
                    matches!(
                        report.decision,
                        SandboxDecision::FailClosed | SandboxDecision::ReviewRequired
                    ),
                    "{} unexpectedly allowed adversarial test",
                    sandbox.id
                );
                assert!(!report.loi_ready);
            }
        }
    }

    #[test]
    fn defense_pack_keeps_non_weaponized_scope_boundary() {
        let defense =
            get_enterprise_sandbox("defense_ai_assurance").expect("defense sandbox should exist");
        assert!(defense
            .prohibited_scope
            .iter()
            .any(|scope| scope.contains("autonomous lethal targeting")));

        let report = execute_sandbox_run(
            &defense,
            &SandboxRunConfig::happy_path("targeting-attempt")
                .with_fault(SandboxFault::ScopeViolation),
        );
        assert_eq!(report.decision, SandboxDecision::FailClosed);
    }

    #[test]
    fn ai_agent_pack_blocks_prompt_injection_and_unauthorized_tools() {
        let agents =
            get_enterprise_sandbox("ai_agent_control_plane").expect("agent sandbox should exist");
        let report = execute_sandbox_run(
            &agents,
            &SandboxRunConfig::happy_path("procurement-agent")
                .with_fault(SandboxFault::PromptInjection)
                .with_fault(SandboxFault::UnauthorizedToolCall),
        );

        assert_eq!(report.decision, SandboxDecision::FailClosed);
        assert!(report
            .gate_results
            .iter()
            .any(|gate| gate.gate_id == "tool_permission" && !gate.passed));
        assert!(report
            .gate_results
            .iter()
            .any(|gate| gate.gate_id == "prompt_injection_defense" && !gate.passed));
    }
}
