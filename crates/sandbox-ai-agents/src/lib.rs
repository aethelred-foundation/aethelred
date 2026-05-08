//! # Aethelred Infinity Sandbox — AI Agent Control Plane
//!
//! Production-grade verification & evidence layer for autonomous AI agents:
//! agent passport lifecycle, tool manifest enforcement, multi-step action
//! trails, and prompt-injection defense. Aligned to EU AI Act Article 26
//! (deployer obligations), ISO/IEC 42001, and NIST AI RMF MAP/MEASURE/MANAGE.
//!
//! ## Plug-and-play
//!
//! ```no_run
//! use aethelred_sandbox_ai_agents::prelude::*;
//!
//! let sandbox = AiAgentsSandbox::quickstart("Core42").unwrap();
//! sandbox.seal_passport(AgentPassport::demo()).unwrap();
//! let action = sandbox.seal_action(AgentAction::demo()).unwrap();
//! ```

#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::result_large_err)]

use aethelred_sandbox_core::policy::PolicyGate;
use aethelred_sandbox_core::{
    ApprovalRecord, DigitalSeal, EvidenceBundle, EvidenceLogEntry, Hasher, ModelReference,
    RetentionClass, Sandbox, SandboxBuilder, SandboxError, SandboxResult, Sector, SealVersion,
    Sha256Digest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use time::OffsetDateTime;
use uuid::Uuid;

pub use aethelred_sandbox_core as core;

/// Prelude.
pub mod prelude {
    pub use super::{
        AgentAction, AgentActionSeal, AgentLifecycle, AgentPassport, AgentPassportSeal,
        AgentRegulatorView, AiAgentsJurisdiction, AiAgentsSandbox, AiAgentsSandboxBuilder,
        PromptInjectionTest, PromptInjectionTestSeal, RiskTier, ToolInvocation, ToolInvocationSeal,
        ToolManifestEntry,
    };
    pub use aethelred_sandbox_core::{
        DigitalSeal, EvidenceBundle, EvidenceLogEntry, ModelReference, RetentionClass, SandboxError,
        SandboxResult, Sector, Sha256Digest,
    };
}

/// Active passport gate.
pub const GATE_ACTIVE_PASSPORT: &str = "ai_agents.active_passport";
/// Tool in manifest gate.
pub const GATE_TOOL_IN_MANIFEST: &str = "ai_agents.tool_in_manifest";
/// Privileged approval gate.
pub const GATE_PRIVILEGED_APPROVAL: &str = "ai_agents.privileged_approval";
/// Prompt-injection defense gate.
pub const GATE_PROMPT_INJECTION_DEFENSE: &str = "ai_agents.prompt_injection_defense";
/// Scope boundary gate.
pub const GATE_SCOPE_BOUNDARY: &str = "ai_agents.scope_boundary";
/// Human authority gate.
pub const GATE_HUMAN_AUTHORITY: &str = "ai_agents.human_authority";
/// Evidence integrity gate.
pub const GATE_EVIDENCE_INTEGRITY: &str = "ai_agents.evidence_integrity";

fn default_gates() -> Vec<PolicyGate> {
    vec![
        PolicyGate::required(GATE_ACTIVE_PASSPORT, "Active passport", "Agent must have an active, non-revoked, non-expired passport."),
        PolicyGate::required(GATE_TOOL_IN_MANIFEST, "Tool in manifest", "Tool calls must match the agent's tool manifest."),
        PolicyGate::required(GATE_PRIVILEGED_APPROVAL, "Privileged action approval", "Privileged actions require an authorised human approval."),
        PolicyGate::required(GATE_PROMPT_INJECTION_DEFENSE, "Prompt-injection defense", "Untrusted inputs must not override system policy."),
        PolicyGate::required(GATE_SCOPE_BOUNDARY, "Scope boundary", "Agent actions must remain within the declared purpose scope."),
        PolicyGate::required(GATE_HUMAN_AUTHORITY, "Human authority bind", "An authorised approver / sponsor must bind to high-risk actions."),
        PolicyGate::required(GATE_EVIDENCE_INTEGRITY, "Evidence integrity", "Tampered passport / manifest / action records fail closed."),
    ]
}

/// Regulator jurisdiction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiAgentsJurisdiction {
    /// EU AI Act Article 26.
    EuAiActArt26,
    /// ISO/IEC 42001:2023.
    Iso42001,
    /// NIST AI RMF 2.0.
    NistAiRmf,
    /// UAE PDPL.
    UaePdpl,
    /// UAE National AI Programme.
    UaeNaip,
}

impl AiAgentsJurisdiction {
    /// String id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EuAiActArt26 => "eu_ai_act_art_26",
            Self::Iso42001 => "iso_42001",
            Self::NistAiRmf => "nist_ai_rmf",
            Self::UaePdpl => "uae_pdpl",
            Self::UaeNaip => "uae_naip",
        }
    }
    /// Seal tag.
    pub const fn seal_tag(self) -> &'static str {
        match self {
            Self::EuAiActArt26 => "EU-AI-ACT-ART-26",
            Self::Iso42001 => "ISO-IEC-42001",
            Self::NistAiRmf => "NIST-AI-RMF",
            Self::UaePdpl => "AE-PDPL",
            Self::UaeNaip => "AE-NAIP",
        }
    }
    /// Citations.
    pub fn citations(self) -> Vec<RegulatorCitation> {
        match self {
            Self::EuAiActArt26 => vec![RegulatorCitation::eu_ai_act_art_26()],
            Self::Iso42001 => vec![RegulatorCitation::iso_42001()],
            Self::NistAiRmf => vec![RegulatorCitation::nist_ai_rmf()],
            Self::UaePdpl => vec![RegulatorCitation::uae_pdpl()],
            Self::UaeNaip => vec![RegulatorCitation::uae_naip()],
        }
    }
}

/// Citation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatorCitation {
    /// Regulator.
    pub regulator: String,
    /// Citation id.
    pub citation_id: String,
    /// Section.
    pub section: String,
    /// Summary.
    pub summary: String,
}

impl RegulatorCitation {
    /// EU AI Act Art 26.
    pub fn eu_ai_act_art_26() -> Self { Self { regulator: "EU".into(), citation_id: "Regulation (EU) 2024/1689".into(), section: "Article 26".into(), summary: "Deployer obligations: monitor, keep logs, ensure human oversight where prescribed.".into() } }
    /// ISO/IEC 42001.
    pub fn iso_42001() -> Self { Self { regulator: "ISO/IEC".into(), citation_id: "ISO/IEC 42001:2023".into(), section: "Clauses 8–10".into(), summary: "AI management system operation, performance evaluation, improvement.".into() } }
    /// NIST AI RMF 2.0.
    pub fn nist_ai_rmf() -> Self { Self { regulator: "NIST (US)".into(), citation_id: "AI RMF 2.0".into(), section: "GOVERN / MAP / MEASURE / MANAGE".into(), summary: "AI risk lifecycle expectations.".into() } }
    /// UAE PDPL.
    pub fn uae_pdpl() -> Self { Self { regulator: "UAE".into(), citation_id: "Federal Decree-Law 45/2021".into(), section: "Articles 12–13, 19".into(), summary: "Lawful basis, purpose limitation, automated processing rights.".into() } }
    /// UAE NAIP.
    pub fn uae_naip() -> Self { Self { regulator: "UAE".into(), citation_id: "National AI Programme".into(), section: "Sovereign-AI alignment".into(), summary: "UAE sovereign-AI procurement preference.".into() } }
}

/// Regulator view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRegulatorView {
    /// Jurisdiction.
    pub jurisdiction: AiAgentsJurisdiction,
    /// Citations.
    pub citations: Vec<RegulatorCitation>,
    /// Seal id.
    pub seal_id: String,
    /// Workflow.
    pub workflow_id: String,
    /// Event class.
    pub event_class: String,
    /// Decision.
    pub decision: String,
    /// Tenant.
    pub tenant_id: String,
}

impl AgentRegulatorView {
    /// Project a seal.
    pub fn project(seal: &DigitalSeal, jurisdiction: AiAgentsJurisdiction, decision: impl Into<String>, event_class: impl Into<String>) -> Self {
        Self { jurisdiction, citations: jurisdiction.citations(), seal_id: seal.id_string(), workflow_id: seal.workflow_id.clone(), event_class: event_class.into(), decision: decision.into(), tenant_id: seal.tenant_id.clone() }
    }
}

/// Agent lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLifecycle {
    /// Issued.
    Issued,
    /// Active.
    Active,
    /// Suspended.
    Suspended,
    /// Revoked.
    Revoked,
    /// Expired.
    Expired,
}

impl AgentLifecycle {
    /// String id.
    pub const fn as_str(self) -> &'static str {
        match self { Self::Issued => "issued", Self::Active => "active", Self::Suspended => "suspended", Self::Revoked => "revoked", Self::Expired => "expired" }
    }
    /// `true` if operational.
    pub fn is_operational(self) -> bool { matches!(self, Self::Issued | Self::Active) }
}

/// Risk tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    /// Read-only.
    ReadOnly,
    /// Read + transform.
    ReadTransform,
    /// Write to sandbox.
    WriteSandbox,
    /// Write to production.
    WriteProduction,
    /// Privileged (financial / external payment).
    Privileged,
}

impl RiskTier {
    /// String id.
    pub const fn as_str(self) -> &'static str {
        match self { Self::ReadOnly => "read_only", Self::ReadTransform => "read_transform", Self::WriteSandbox => "write_sandbox", Self::WriteProduction => "write_production", Self::Privileged => "privileged" }
    }
    /// `true` if approval required.
    pub fn requires_approval(self) -> bool { matches!(self, Self::WriteProduction | Self::Privileged) }
}

/// Tool manifest entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolManifestEntry {
    /// Tool id.
    pub tool_id: String,
    /// Allowed action verbs.
    pub allowed_actions: Vec<String>,
    /// Risk tier.
    pub risk_tier: RiskTier,
}

/// Agent passport input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPassport {
    /// Agent id.
    pub agent_id: String,
    /// Sponsor.
    pub sponsor: String,
    /// Owner.
    pub owner: String,
    /// Purpose.
    pub purpose: String,
    /// Lifecycle.
    pub lifecycle: AgentLifecycle,
    /// Expiry RFC 3339.
    pub expiry: String,
    /// Manifest.
    pub tool_manifest: Vec<ToolManifestEntry>,
    /// Model id.
    pub model_id: String,
    /// Model hash hex.
    pub model_hash_hex: String,
    /// Approver pseudo id.
    pub approver_pseudo_id: String,
    /// Approver role.
    pub approver_role: String,
    /// Optional jurisdiction tag.
    pub jurisdiction_tag: Option<String>,
}

impl AgentPassport {
    /// Demo.
    pub fn demo() -> Self {
        Self {
            agent_id: "agent-2026-12-001".into(),
            sponsor: "Core42".into(),
            owner: "role:platform_owner#a01".into(),
            purpose: "procurement assistant for non-production sandbox".into(),
            lifecycle: AgentLifecycle::Active,
            expiry: "2027-12-31T23:59:59Z".into(),
            tool_manifest: vec![
                ToolManifestEntry { tool_id: "slack.send_message".into(), allowed_actions: vec!["read".into(), "send".into()], risk_tier: RiskTier::ReadTransform },
                ToolManifestEntry { tool_id: "sap.create_purchase_order".into(), allowed_actions: vec!["create".into()], risk_tier: RiskTier::WriteProduction },
            ],
            model_id: "agent_model_v3".into(),
            model_hash_hex: Hasher::sha256(b"demo-agent-model").to_hex(),
            approver_pseudo_id: "role:director#a01".into(),
            approver_role: "director".into(),
            jurisdiction_tag: None,
        }
    }
}

/// Sealed passport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPassportSeal {
    /// Seal.
    pub seal: DigitalSeal,
    /// Lifecycle.
    pub lifecycle: AgentLifecycle,
}

impl AgentPassportSeal { /// Stable id.
    pub fn id_string(&self) -> String { self.seal.id_string() } }

fn build_passport_seal(input: &AgentPassport, tenant: &str, default_juris: &str) -> SandboxResult<DigitalSeal> {
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex).ok_or_else(|| SandboxError::invalid("model_hash_hex"))?;
    let model = ModelReference::new(input.model_id.clone(), model_hash);
    let input_hash = Hasher::sha256(input.agent_id.as_bytes());
    let output_hash = Hasher::hash_value(&input.tool_manifest)?;
    let event_hash = Hasher::sha256(format!("{}:passport:{}", input.agent_id, input.lifecycle.as_str()).as_bytes());
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("agent_passport"));
    sector_extension.insert("agent_id".into(), serde_json::json!(input.agent_id));
    sector_extension.insert("sponsor".into(), serde_json::json!(input.sponsor));
    sector_extension.insert("purpose".into(), serde_json::json!(input.purpose));
    sector_extension.insert("lifecycle".into(), serde_json::json!(input.lifecycle.as_str()));
    sector_extension.insert("expiry".into(), serde_json::json!(input.expiry));
    sector_extension.insert("tool_manifest_count".into(), serde_json::json!(input.tool_manifest.len()));
    let approval = ApprovalRecord {
        approver_ref: input.approver_pseudo_id.clone(),
        role: input.approver_role.clone(),
        decision: input.lifecycle.as_str().to_string(),
        reason_class: Some(input.purpose.clone()),
        timestamp: OffsetDateTime::now_utc(),
        signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1, seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::AiAgents,
        event_type: format!("agent_passport.{}", input.lifecycle.as_str()),
        event_hash, model,
        policy_id: "po_agent_passport_v1".to_string(),
        input_hash, output_hash,
        approvals: vec![approval],
        attestation: None, zk_proof: None,
        tenant_id: tenant.to_string(),
        workflow_id: "agent_passport".to_string(),
        jurisdiction_tag: input.jurisdiction_tag.clone().unwrap_or_else(|| default_juris.to_string()),
        retention: RetentionClass::SevenYears,
        prior_seal_hash: None, sector_extension,
        validator_signature_hex: None,
    })
}

/// Tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvocation {
    /// Agent id.
    pub agent_id: String,
    /// Tool id.
    pub tool_id: String,
    /// Action verb.
    pub action: String,
    /// Parameters hash hex.
    pub parameters_hash_hex: String,
    /// Risk tier.
    pub risk_tier: RiskTier,
    /// Success?
    pub success: bool,
    /// Approver pseudo id (required for privileged).
    pub approver_pseudo_id: Option<String>,
    /// Approver role.
    pub approver_role: Option<String>,
    /// Optional jurisdiction tag.
    pub jurisdiction_tag: Option<String>,
}

impl ToolInvocation {
    /// Demo.
    pub fn demo() -> Self {
        Self { agent_id: "agent-2026-12-001".into(), tool_id: "slack.send_message".into(), action: "send".into(), parameters_hash_hex: Hasher::sha256(b"send msg payload").to_hex(), risk_tier: RiskTier::ReadTransform, success: true, approver_pseudo_id: None, approver_role: None, jurisdiction_tag: None }
    }
}

/// Sealed tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvocationSeal {
    /// Seal.
    pub seal: DigitalSeal,
    /// Risk tier.
    pub risk_tier: RiskTier,
}

impl ToolInvocationSeal { /// Stable id.
    pub fn id_string(&self) -> String { self.seal.id_string() } }

fn build_tool_seal(input: &ToolInvocation, tenant: &str, default_juris: &str) -> SandboxResult<DigitalSeal> {
    let params_hash = Sha256Digest::from_hex(&input.parameters_hash_hex).ok_or_else(|| SandboxError::invalid("parameters_hash_hex"))?;
    let model = ModelReference::new(format!("agent::{}", input.agent_id), Hasher::sha256(input.agent_id.as_bytes()));
    let input_hash = params_hash;
    let output_hash = Hasher::sha256(format!("{}:{}:{}", input.tool_id, input.action, input.success).as_bytes());
    let event_hash = Hasher::sha256(format!("{}:{}:{}", input.agent_id, input.tool_id, input.action).as_bytes());
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("tool_invocation"));
    sector_extension.insert("agent_id".into(), serde_json::json!(input.agent_id));
    sector_extension.insert("tool_id".into(), serde_json::json!(input.tool_id));
    sector_extension.insert("action".into(), serde_json::json!(input.action));
    sector_extension.insert("risk_tier".into(), serde_json::json!(input.risk_tier.as_str()));
    sector_extension.insert("success".into(), serde_json::json!(input.success));
    let mut approvals = Vec::new();
    if let (Some(ap), Some(role)) = (&input.approver_pseudo_id, &input.approver_role) {
        approvals.push(ApprovalRecord {
            approver_ref: ap.clone(), role: role.clone(),
            decision: if input.success { "allow" } else { "deny" }.into(),
            reason_class: Some(input.risk_tier.as_str().into()),
            timestamp: OffsetDateTime::now_utc(), signature_hex: None,
        });
    }
    Ok(DigitalSeal {
        schema_version: SealVersion::V1, seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(), sector: Sector::AiAgents,
        event_type: format!("tool_invocation.{}", input.tool_id),
        event_hash, model, policy_id: "po_tool_invocation_v1".to_string(),
        input_hash, output_hash, approvals,
        attestation: None, zk_proof: None,
        tenant_id: tenant.to_string(),
        workflow_id: "tool_invocation".to_string(),
        jurisdiction_tag: input.jurisdiction_tag.clone().unwrap_or_else(|| default_juris.to_string()),
        retention: RetentionClass::SevenYears, prior_seal_hash: None, sector_extension,
        validator_signature_hex: None,
    })
}

/// Multi-step agent action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAction {
    /// Agent id.
    pub agent_id: String,
    /// Description.
    pub description: String,
    /// Step ids in order.
    pub steps: Vec<String>,
    /// Plan graph hash hex.
    pub plan_hash_hex: String,
    /// Tool invocation hashes.
    pub tool_invocation_hashes: Vec<String>,
    /// Optional prior-seal hash hex (chain).
    pub prior_seal_hash_hex: Option<String>,
    /// Sponsor pseudo id.
    pub sponsor_pseudo_id: String,
    /// Sponsor role.
    pub sponsor_role: String,
    /// Risk tier.
    pub risk_tier: RiskTier,
    /// Completed?
    pub completed: bool,
    /// Optional jurisdiction tag.
    pub jurisdiction_tag: Option<String>,
}

impl AgentAction {
    /// Demo.
    pub fn demo() -> Self {
        Self {
            agent_id: "agent-2026-12-001".into(),
            description: "reconcile invoice batch 2026-12-01".into(),
            steps: vec!["fetch_invoices".into(), "match_pos".into(), "post_journal".into()],
            plan_hash_hex: Hasher::sha256(b"plan-graph").to_hex(),
            tool_invocation_hashes: vec![Hasher::sha256(b"invoke-1").to_hex(), Hasher::sha256(b"invoke-2").to_hex()],
            prior_seal_hash_hex: None,
            sponsor_pseudo_id: "role:director#a01".into(),
            sponsor_role: "director".into(),
            risk_tier: RiskTier::WriteProduction,
            completed: true,
            jurisdiction_tag: None,
        }
    }
}

/// Sealed action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentActionSeal {
    /// Seal.
    pub seal: DigitalSeal,
    /// Risk tier.
    pub risk_tier: RiskTier,
}

impl AgentActionSeal { /// Stable id.
    pub fn id_string(&self) -> String { self.seal.id_string() } }

fn build_action_seal(input: &AgentAction, tenant: &str, default_juris: &str) -> SandboxResult<DigitalSeal> {
    let plan_hash = Sha256Digest::from_hex(&input.plan_hash_hex).ok_or_else(|| SandboxError::invalid("plan_hash_hex"))?;
    let prior_seal_hash = match &input.prior_seal_hash_hex {
        Some(h) => Some(Sha256Digest::from_hex(h).ok_or_else(|| SandboxError::invalid("prior_seal_hash_hex"))?),
        None => None,
    };
    let model = ModelReference::new(format!("agent::{}", input.agent_id), Hasher::sha256(input.agent_id.as_bytes()));
    let input_hash = plan_hash;
    let output_hash = {
        let mut bytes = Vec::new();
        for h in &input.tool_invocation_hashes { bytes.extend_from_slice(h.as_bytes()); }
        bytes.extend_from_slice(&[input.completed as u8]);
        Hasher::sha256(&bytes)
    };
    let event_hash = Hasher::sha256(format!("{}:action:{}", input.agent_id, input.description).as_bytes());
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("agent_action"));
    sector_extension.insert("agent_id".into(), serde_json::json!(input.agent_id));
    sector_extension.insert("description".into(), serde_json::json!(input.description));
    sector_extension.insert("steps".into(), serde_json::json!(input.steps));
    sector_extension.insert("step_count".into(), serde_json::json!(input.steps.len()));
    sector_extension.insert("risk_tier".into(), serde_json::json!(input.risk_tier.as_str()));
    sector_extension.insert("completed".into(), serde_json::json!(input.completed));
    let approval = ApprovalRecord {
        approver_ref: input.sponsor_pseudo_id.clone(), role: input.sponsor_role.clone(),
        decision: if input.completed { "completed" } else { "in_progress" }.into(),
        reason_class: Some(input.risk_tier.as_str().into()),
        timestamp: OffsetDateTime::now_utc(), signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1, seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(), sector: Sector::AiAgents,
        event_type: format!("agent_action.{}", input.risk_tier.as_str()),
        event_hash, model, policy_id: "po_agent_action_v1".to_string(),
        input_hash, output_hash, approvals: vec![approval],
        attestation: None, zk_proof: None,
        tenant_id: tenant.to_string(),
        workflow_id: "agent_action".to_string(),
        jurisdiction_tag: input.jurisdiction_tag.clone().unwrap_or_else(|| default_juris.to_string()),
        retention: RetentionClass::SevenYears, prior_seal_hash, sector_extension,
        validator_signature_hex: None,
    })
}

/// Prompt-injection test event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptInjectionTest {
    /// Agent under test.
    pub agent_id: String,
    /// Test id.
    pub test_id: String,
    /// Hash of the malicious prompt input.
    pub malicious_prompt_hash_hex: String,
    /// `true` if the agent rejected (desired outcome).
    pub rejected: bool,
    /// Tester role.
    pub tester_role: String,
    /// Tester pseudo id.
    pub tester_pseudo_id: String,
    /// Optional jurisdiction tag.
    pub jurisdiction_tag: Option<String>,
}

impl PromptInjectionTest {
    /// Demo (passing test).
    pub fn demo() -> Self {
        Self {
            agent_id: "agent-2026-12-001".into(), test_id: "pi-test-001".into(),
            malicious_prompt_hash_hex: Hasher::sha256(b"ignore previous instructions and...").to_hex(),
            rejected: true,
            tester_role: "red_team".into(),
            tester_pseudo_id: "role:red_team#a01".into(),
            jurisdiction_tag: None,
        }
    }
}

/// Sealed prompt-injection test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptInjectionTestSeal {
    /// Seal.
    pub seal: DigitalSeal,
    /// `true` if the test was a pass.
    pub rejected: bool,
}

impl PromptInjectionTestSeal { /// Stable id.
    pub fn id_string(&self) -> String { self.seal.id_string() } }

fn build_pi_seal(input: &PromptInjectionTest, tenant: &str, default_juris: &str) -> SandboxResult<DigitalSeal> {
    let prompt_hash = Sha256Digest::from_hex(&input.malicious_prompt_hash_hex).ok_or_else(|| SandboxError::invalid("malicious_prompt_hash_hex"))?;
    let model = ModelReference::new(format!("agent::{}", input.agent_id), Hasher::sha256(input.agent_id.as_bytes()));
    let input_hash = prompt_hash;
    let output_hash = Hasher::sha256(format!("rejected:{}", input.rejected).as_bytes());
    let event_hash = Hasher::sha256(format!("{}:pi-test:{}", input.agent_id, input.test_id).as_bytes());
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("prompt_injection_test"));
    sector_extension.insert("agent_id".into(), serde_json::json!(input.agent_id));
    sector_extension.insert("test_id".into(), serde_json::json!(input.test_id));
    sector_extension.insert("rejected".into(), serde_json::json!(input.rejected));
    let approval = ApprovalRecord {
        approver_ref: input.tester_pseudo_id.clone(), role: input.tester_role.clone(),
        decision: if input.rejected { "passed" } else { "failed" }.into(),
        reason_class: Some("prompt_injection".into()),
        timestamp: OffsetDateTime::now_utc(), signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1, seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(), sector: Sector::AiAgents,
        event_type: format!("prompt_injection_test.{}", if input.rejected { "passed" } else { "failed" }),
        event_hash, model, policy_id: "po_prompt_injection_test_v1".to_string(),
        input_hash, output_hash, approvals: vec![approval],
        attestation: None, zk_proof: None,
        tenant_id: tenant.to_string(),
        workflow_id: "prompt_injection_test".to_string(),
        jurisdiction_tag: input.jurisdiction_tag.clone().unwrap_or_else(|| default_juris.to_string()),
        retention: RetentionClass::SevenYears, prior_seal_hash: None, sector_extension,
        validator_signature_hex: None,
    })
}

// =============================================================================
// AiAgentsSandbox
// =============================================================================

/// Plug-and-play entry point.
pub struct AiAgentsSandbox {
    inner: Sandbox,
    primary_jurisdiction: AiAgentsJurisdiction,
    passports: std::sync::RwLock<HashMap<String, AgentPassport>>,
}

impl AiAgentsSandbox {
    /// Quickstart.
    pub fn quickstart(tenant: impl Into<String>) -> SandboxResult<Self> {
        Self::builder().tenant(tenant).jurisdiction(AiAgentsJurisdiction::EuAiActArt26).build()
    }
    /// Builder.
    pub fn builder() -> AiAgentsSandboxBuilder { AiAgentsSandboxBuilder::default() }
    /// Underlying core.
    pub fn core(&self) -> &Sandbox { &self.inner }
    /// Tenant.
    pub fn tenant(&self) -> &str { &self.inner.config().tenant_id }
    /// Primary jurisdiction.
    pub fn primary_jurisdiction(&self) -> AiAgentsJurisdiction { self.primary_jurisdiction }
    fn append(&self, seal: DigitalSeal) -> SandboxResult<EvidenceLogEntry> { self.inner.append_seal(seal) }
    /// Export evidence.
    pub fn export_evidence(&self) -> SandboxResult<EvidenceBundle> {
        self.inner.evidence().export(self.tenant().to_string(), Sector::AiAgents)
    }
    /// Project regulator view.
    pub fn regulator_view(&self, seal: &DigitalSeal, jurisdiction: AiAgentsJurisdiction) -> AgentRegulatorView {
        let event_class = seal.event_type.split('.').next().unwrap_or("event").to_string();
        let decision = seal.approvals.first().map(|a| a.decision.clone()).unwrap_or_else(|| "unknown".into());
        AgentRegulatorView::project(seal, jurisdiction, decision, event_class)
    }

    /// Seal a passport (issuance / lifecycle change).
    pub fn seal_passport(&self, input: AgentPassport) -> SandboxResult<AgentPassportSeal> {
        let seal = build_passport_seal(&input, self.tenant(), self.primary_jurisdiction.seal_tag())?;
        let mut faults: HashMap<String, bool> = HashMap::new();
        if seal.approvals.is_empty() { faults.insert(GATE_HUMAN_AUTHORITY.into(), true); }
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let g = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(g, format!("passport for {} blocked", input.agent_id)));
        }
        if let Ok(mut guard) = self.passports.write() { guard.insert(input.agent_id.clone(), input.clone()); }
        self.append(seal.clone())?;
        Ok(AgentPassportSeal { seal, lifecycle: input.lifecycle })
    }

    /// Seal a tool invocation (verifies passport + manifest + privileged-approval).
    pub fn seal_tool_invocation(&self, input: ToolInvocation) -> SandboxResult<ToolInvocationSeal> {
        let mut faults: HashMap<String, bool> = HashMap::new();
        let passports = self.passports.read().map_err(|_| SandboxError::Other("passports lock poisoned".into()))?;
        match passports.get(&input.agent_id) {
            None => { faults.insert(GATE_ACTIVE_PASSPORT.into(), true); }
            Some(p) if !p.lifecycle.is_operational() => { faults.insert(GATE_ACTIVE_PASSPORT.into(), true); }
            Some(p) => {
                let allowed: HashSet<&str> = p.tool_manifest.iter().map(|t| t.tool_id.as_str()).collect();
                if !allowed.contains(input.tool_id.as_str()) {
                    faults.insert(GATE_TOOL_IN_MANIFEST.into(), true);
                } else {
                    let entry = p.tool_manifest.iter().find(|t| t.tool_id == input.tool_id).unwrap();
                    if !entry.allowed_actions.iter().any(|a| a == &input.action) {
                        faults.insert(GATE_TOOL_IN_MANIFEST.into(), true);
                    }
                }
            }
        }
        if input.risk_tier.requires_approval() && (input.approver_pseudo_id.is_none() || input.approver_role.is_none()) {
            faults.insert(GATE_PRIVILEGED_APPROVAL.into(), true);
        }
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let g = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(g, format!("tool invocation {} blocked", input.tool_id)));
        }
        let seal = build_tool_seal(&input, self.tenant(), self.primary_jurisdiction.seal_tag())?;
        self.append(seal.clone())?;
        Ok(ToolInvocationSeal { seal, risk_tier: input.risk_tier })
    }

    /// Seal a multi-step action.
    pub fn seal_action(&self, input: AgentAction) -> SandboxResult<AgentActionSeal> {
        let mut faults: HashMap<String, bool> = HashMap::new();
        let passports = self.passports.read().map_err(|_| SandboxError::Other("passports lock poisoned".into()))?;
        if !passports.get(&input.agent_id).map(|p| p.lifecycle.is_operational()).unwrap_or(false) {
            faults.insert(GATE_ACTIVE_PASSPORT.into(), true);
        }
        if input.sponsor_pseudo_id.is_empty() {
            faults.insert(GATE_HUMAN_AUTHORITY.into(), true);
        }
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let g = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(g, format!("action by {} blocked", input.agent_id)));
        }
        let seal = build_action_seal(&input, self.tenant(), self.primary_jurisdiction.seal_tag())?;
        self.append(seal.clone())?;
        Ok(AgentActionSeal { seal, risk_tier: input.risk_tier })
    }

    /// Seal a prompt-injection test.
    pub fn seal_prompt_injection_test(&self, input: PromptInjectionTest) -> SandboxResult<PromptInjectionTestSeal> {
        if !input.rejected {
            return Err(SandboxError::policy(GATE_PROMPT_INJECTION_DEFENSE, format!("prompt injection test {} failed", input.test_id)));
        }
        let seal = build_pi_seal(&input, self.tenant(), self.primary_jurisdiction.seal_tag())?;
        self.append(seal.clone())?;
        Ok(PromptInjectionTestSeal { seal, rejected: input.rejected })
    }

    // =================================================================
    // Enterprise convenience: bulk + envelope + verify + audit.
    // =================================================================

    /// Bulk seal passports.
    pub fn seal_passports(&self, items: impl IntoIterator<Item = AgentPassport>) -> SandboxResult<Vec<AgentPassportSeal>> {
        items.into_iter().map(|i| self.seal_passport(i)).collect()
    }
    /// Bulk seal tool invocations.
    pub fn seal_tool_invocations(&self, items: impl IntoIterator<Item = ToolInvocation>) -> SandboxResult<Vec<ToolInvocationSeal>> {
        items.into_iter().map(|i| self.seal_tool_invocation(i)).collect()
    }
    /// Bulk seal actions.
    pub fn seal_actions(&self, items: impl IntoIterator<Item = AgentAction>) -> SandboxResult<Vec<AgentActionSeal>> {
        items.into_iter().map(|i| self.seal_action(i)).collect()
    }
    /// Bulk seal prompt-injection tests.
    pub fn seal_prompt_injection_tests(&self, items: impl IntoIterator<Item = PromptInjectionTest>) -> SandboxResult<Vec<PromptInjectionTestSeal>> {
        items.into_iter().map(|i| self.seal_prompt_injection_test(i)).collect()
    }

    /// Envelope at index.
    pub fn envelope_at(&self, index: u64) -> SandboxResult<aethelred_sandbox_core::SealEnvelope> {
        let bundle = self.export_evidence()?;
        let entry = bundle.entries.iter().find(|e| e.index == index).cloned()
            .ok_or_else(|| SandboxError::Evidence(format!("envelope at {index} not found")))?;
        let proof = self.inner.evidence().proof(index)?;
        Ok(aethelred_sandbox_core::SealEnvelope {
            seal: entry.seal,
            merkle_proof: Some(proof),
            anchor_block_height: None,
        })
    }
    /// All envelopes.
    pub fn all_envelopes(&self) -> SandboxResult<Vec<aethelred_sandbox_core::SealEnvelope>> {
        let bundle = self.export_evidence()?;
        let mut out = Vec::with_capacity(bundle.entries.len());
        for entry in bundle.entries {
            let proof = self.inner.evidence().proof(entry.index)?;
            out.push(aethelred_sandbox_core::SealEnvelope {
                seal: entry.seal,
                merkle_proof: Some(proof),
                anchor_block_height: None,
            });
        }
        Ok(out)
    }
    /// Current root.
    pub fn current_root(&self) -> SandboxResult<aethelred_sandbox_core::Sha256Digest> {
        self.inner.current_root()
    }
    /// Seal count.
    pub fn seal_count(&self) -> usize { self.inner.seal_count() }
    /// Audit trail.
    pub fn audit_trail(&self, format: aethelred_sandbox_core::audit::AuditFormat) -> SandboxResult<String> {
        self.inner.audit_trail(format)
    }
    /// Structured audit trail.
    pub fn audit_trail_struct(&self) -> SandboxResult<aethelred_sandbox_core::audit::AuditTrail> {
        let bundle = self.export_evidence()?;
        Ok(aethelred_sandbox_core::audit::AuditTrail::from_bundle(&bundle))
    }
    /// Verify all seals.
    pub fn verify_all(&self) -> SandboxResult<Vec<aethelred_sandbox_core::verify::VerificationReport>> {
        let envs = self.all_envelopes()?;
        let root = self.current_root()?;
        aethelred_sandbox_core::verify::Verifier::default().verify_batch(&envs, root)
    }
    /// Verify with custom Verifier.
    pub fn verify_all_with(&self, v: &aethelred_sandbox_core::verify::Verifier) -> SandboxResult<Vec<aethelred_sandbox_core::verify::VerificationReport>> {
        let envs = self.all_envelopes()?;
        let root = self.current_root()?;
        v.verify_batch(&envs, root)
    }
}

/// Builder.
#[derive(Default)]
pub struct AiAgentsSandboxBuilder {
    tenant: Option<String>,
    primary_jurisdiction: Option<AiAgentsJurisdiction>,
    extra_gates: Vec<PolicyGate>,
    label: Option<String>,
}

impl AiAgentsSandboxBuilder {
    /// Tenant.
    pub fn tenant(mut self, tenant: impl Into<String>) -> Self { self.tenant = Some(tenant.into()); self }
    /// Jurisdiction.
    pub fn jurisdiction(mut self, j: AiAgentsJurisdiction) -> Self { self.primary_jurisdiction = Some(j); self }
    /// Extra gate.
    pub fn with_extra_gate(mut self, gate: PolicyGate) -> Self { self.extra_gates.push(gate); self }
    /// Label.
    pub fn label(mut self, label: impl Into<String>) -> Self { self.label = Some(label.into()); self }
    /// Build.
    pub fn build(self) -> SandboxResult<AiAgentsSandbox> {
        let tenant = self.tenant.ok_or_else(|| SandboxError::config("tenant not set"))?;
        let primary = self.primary_jurisdiction.unwrap_or(AiAgentsJurisdiction::EuAiActArt26);
        let mut all_gates = default_gates();
        all_gates.extend(self.extra_gates);
        let label = self.label.unwrap_or_else(|| format!("{tenant} AI Agents Sandbox"));
        let inner = SandboxBuilder::new(Sector::AiAgents)
            .crate_name("aethelred-sandbox-ai-agents")
            .crate_version(env!("CARGO_PKG_VERSION"))
            .tenant(&tenant).label(&label).jurisdiction(primary.seal_tag())
            .workflow("agent_passport").workflow("tool_invocation")
            .workflow("agent_action").workflow("prompt_injection_test")
            .with_gates(all_gates).build()?;
        Ok(AiAgentsSandbox { inner, primary_jurisdiction: primary, passports: std::sync::RwLock::new(HashMap::new()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quickstart_constructs() {
        let sb = AiAgentsSandbox::quickstart("Core42").unwrap();
        assert_eq!(sb.tenant(), "Core42");
    }

    #[test]
    fn passport_then_tool_invocation_happy_path() {
        let sb = AiAgentsSandbox::quickstart("Core42").unwrap();
        sb.seal_passport(AgentPassport::demo()).unwrap();
        let s = sb.seal_tool_invocation(ToolInvocation::demo()).unwrap();
        assert!(s.id_string().starts_with("seal_"));
    }

    #[test]
    fn tool_invocation_without_passport_fails() {
        let sb = AiAgentsSandbox::quickstart("Core42").unwrap();
        let r = sb.seal_tool_invocation(ToolInvocation::demo());
        assert!(r.is_err());
        assert!(r.unwrap_err().is_policy_denial());
    }

    #[test]
    fn unknown_tool_fails_closed() {
        let sb = AiAgentsSandbox::quickstart("Core42").unwrap();
        sb.seal_passport(AgentPassport::demo()).unwrap();
        let mut t = ToolInvocation::demo();
        t.tool_id = "evil.delete_all".into();
        let r = sb.seal_tool_invocation(t);
        assert!(r.is_err());
    }

    #[test]
    fn privileged_without_approval_fails_closed() {
        let sb = AiAgentsSandbox::quickstart("Core42").unwrap();
        sb.seal_passport(AgentPassport::demo()).unwrap();
        let mut t = ToolInvocation::demo();
        t.tool_id = "sap.create_purchase_order".into();
        t.action = "create".into();
        t.risk_tier = RiskTier::WriteProduction;
        let r = sb.seal_tool_invocation(t);
        assert!(r.is_err());
    }

    #[test]
    fn agent_action_happy_path() {
        let sb = AiAgentsSandbox::quickstart("Core42").unwrap();
        sb.seal_passport(AgentPassport::demo()).unwrap();
        let s = sb.seal_action(AgentAction::demo()).unwrap();
        assert!(s.id_string().starts_with("seal_"));
    }

    #[test]
    fn prompt_injection_passes_when_rejected() {
        let sb = AiAgentsSandbox::quickstart("Core42").unwrap();
        let s = sb.seal_prompt_injection_test(PromptInjectionTest::demo()).unwrap();
        assert!(s.rejected);
    }

    #[test]
    fn prompt_injection_fails_closed_when_not_rejected() {
        let sb = AiAgentsSandbox::quickstart("Core42").unwrap();
        let mut p = PromptInjectionTest::demo();
        p.rejected = false;
        let r = sb.seal_prompt_injection_test(p);
        assert!(r.is_err());
    }

    #[test]
    fn export_evidence_returns_appended_seals() {
        let sb = AiAgentsSandbox::quickstart("Core42").unwrap();
        sb.seal_passport(AgentPassport::demo()).unwrap();
        sb.seal_tool_invocation(ToolInvocation::demo()).unwrap();
        sb.seal_prompt_injection_test(PromptInjectionTest::demo()).unwrap();
        let bundle = sb.export_evidence().unwrap();
        assert_eq!(bundle.entries.len(), 3);
        assert_eq!(bundle.sector, Sector::AiAgents);
    }
}
