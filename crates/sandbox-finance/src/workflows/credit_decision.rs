//! Credit-decision workflow.
//!
//! Production target: AI-augmented credit / underwriting decisions for
//! consumer / SME / corporate banking. The seal carries adverse-action
//! reason classes (EU AI Act Annex III §5), MRM lineage (SR 11-7 / EBA), and
//! the human-authority approval bind.
//!
//! ## Plug-and-play
//!
//! ```no_run
//! use aethelred_sandbox_finance::prelude::*;
//! use rust_decimal::Decimal;
//!
//! let sandbox = FinanceSandbox::quickstart("FAB").unwrap();
//! let decision = CreditDecision::builder()
//!     .application_id("app-2026-12-3001")
//!     .applicant_pseudo_id("psn:8a3f")
//!     .product("sme_term_loan_v2")
//!     .amount(Decimal::new(2_500_000, 0)) // AED 2.5m
//!     .currency("AED")
//!     .model_id("credit_risk_v3.2")
//!     .model_hash_hex("4f...")
//!     .decision(CreditOutcome::Approved)
//!     .approver_role("underwriter")
//!     .approver_pseudo_id("role:underwriter#a3f1")
//!     .build()
//!     .unwrap();
//! let seal = sandbox.seal_credit_decision(decision).unwrap();
//! ```

use aethelred_sandbox_core::{
    ApprovalRecord, DigitalSeal, Hasher, ModelReference, RetentionClass, Sector, SealVersion,
    Sha256Digest,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// Credit-decision outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditOutcome {
    /// Approved at the requested terms.
    Approved,
    /// Approved at modified terms (limit / price / tenor adjusted).
    ApprovedWithCounterOffer,
    /// Adverse action — rejected.
    Rejected,
    /// Escalated to a higher authority for sign-off.
    Escalated,
    /// Pending — model emitted no decision; manual review required.
    Pending,
}

impl CreditOutcome {
    /// String form for the seal `event_class`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::ApprovedWithCounterOffer => "approved_with_counter_offer",
            Self::Rejected => "rejected",
            Self::Escalated => "escalated",
            Self::Pending => "pending",
        }
    }

    /// `true` when the outcome is adverse (used to gate the
    /// `adverse_action_explainability` policy gate).
    pub fn is_adverse(self) -> bool {
        matches!(self, Self::Rejected | Self::ApprovedWithCounterOffer)
    }
}

/// A typed credit-decision input.
///
/// Constructed via [`CreditDecision::builder`] (recommended) or directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditDecision {
    /// Bank-issued application id (case reference).
    pub application_id: String,
    /// Applicant pseudonymised id (e.g., `"psn:8a3f"`). Real KYC stays in the
    /// bank's source-of-record system.
    pub applicant_pseudo_id: String,
    /// Product id (e.g., `"sme_term_loan_v2"`).
    pub product: String,
    /// Decision amount (positive; in `currency`).
    pub amount: Decimal,
    /// ISO 4217 currency.
    pub currency: String,
    /// Model id (e.g., `"credit_risk_v3.2"`).
    pub model_id: String,
    /// Model hash (SHA-256 hex of the canonical weights / artefact).
    pub model_hash_hex: String,
    /// Optional model version (semver).
    pub model_version: Option<String>,
    /// Optional MRM document reference (e.g., `"mrm:credit_risk_v3.2-2026-q1"`).
    pub mrm_lineage_ref: Option<String>,
    /// Optional adverse-action reason class (e.g., `"high_dti"`,
    /// `"insufficient_revenue_history"`). Required when the outcome is
    /// adverse — the policy gate checks this.
    pub adverse_action_reason: Option<String>,
    /// Decision outcome.
    pub decision: CreditOutcome,
    /// Approver role (e.g., `"underwriter"`, `"credit_committee"`).
    pub approver_role: String,
    /// Approver pseudonymised id (e.g., `"role:underwriter#a3f1"`).
    pub approver_pseudo_id: String,
    /// Optional jurisdiction tag override (defaults to sandbox's).
    pub jurisdiction_tag: Option<String>,
    /// Optional input hash (e.g., hash of the underlying application
    /// snapshot). If `None`, the workflow derives one from the application id.
    pub input_hash_override: Option<Sha256Digest>,
}

impl CreditDecision {
    /// Builder for safe construction.
    pub fn builder() -> CreditDecisionBuilder {
        CreditDecisionBuilder::default()
    }

    /// Demo input — for examples and tests.
    pub fn demo() -> Self {
        Self {
            application_id: "app-2026-12-3001".into(),
            applicant_pseudo_id: "psn:8a3f".into(),
            product: "sme_term_loan_v2".into(),
            amount: Decimal::new(2_500_000, 0),
            currency: "AED".into(),
            model_id: "credit_risk_v3.2".into(),
            model_hash_hex: Hasher::sha256(b"demo-credit-model-weights").to_hex(),
            model_version: Some("3.2.0".into()),
            mrm_lineage_ref: Some("mrm:credit_risk_v3.2-2026-q1".into()),
            adverse_action_reason: None,
            decision: CreditOutcome::Approved,
            approver_role: "underwriter".into(),
            approver_pseudo_id: "role:underwriter#a3f1".into(),
            jurisdiction_tag: None,
            input_hash_override: None,
        }
    }
}

/// Builder for [`CreditDecision`]. Methods are chainable.
#[derive(Debug, Default, Clone)]
pub struct CreditDecisionBuilder {
    application_id: Option<String>,
    applicant_pseudo_id: Option<String>,
    product: Option<String>,
    amount: Option<Decimal>,
    currency: Option<String>,
    model_id: Option<String>,
    model_hash_hex: Option<String>,
    model_version: Option<String>,
    mrm_lineage_ref: Option<String>,
    adverse_action_reason: Option<String>,
    decision: Option<CreditOutcome>,
    approver_role: Option<String>,
    approver_pseudo_id: Option<String>,
    jurisdiction_tag: Option<String>,
    input_hash_override: Option<Sha256Digest>,
}

impl CreditDecisionBuilder {
    /// Set application id.
    pub fn application_id(mut self, id: impl Into<String>) -> Self {
        self.application_id = Some(id.into());
        self
    }
    /// Set applicant pseudo id.
    pub fn applicant_pseudo_id(mut self, id: impl Into<String>) -> Self {
        self.applicant_pseudo_id = Some(id.into());
        self
    }
    /// Set product.
    pub fn product(mut self, p: impl Into<String>) -> Self {
        self.product = Some(p.into());
        self
    }
    /// Set amount.
    pub fn amount(mut self, a: Decimal) -> Self {
        self.amount = Some(a);
        self
    }
    /// Set currency.
    pub fn currency(mut self, c: impl Into<String>) -> Self {
        self.currency = Some(c.into());
        self
    }
    /// Set model id.
    pub fn model_id(mut self, id: impl Into<String>) -> Self {
        self.model_id = Some(id.into());
        self
    }
    /// Set model hash (hex).
    pub fn model_hash_hex(mut self, h: impl Into<String>) -> Self {
        self.model_hash_hex = Some(h.into());
        self
    }
    /// Set model version.
    pub fn model_version(mut self, v: impl Into<String>) -> Self {
        self.model_version = Some(v.into());
        self
    }
    /// Set MRM lineage ref.
    pub fn mrm_lineage_ref(mut self, r: impl Into<String>) -> Self {
        self.mrm_lineage_ref = Some(r.into());
        self
    }
    /// Set adverse-action reason class.
    pub fn adverse_action_reason(mut self, r: impl Into<String>) -> Self {
        self.adverse_action_reason = Some(r.into());
        self
    }
    /// Set decision outcome.
    pub fn decision(mut self, d: CreditOutcome) -> Self {
        self.decision = Some(d);
        self
    }
    /// Set approver role.
    pub fn approver_role(mut self, r: impl Into<String>) -> Self {
        self.approver_role = Some(r.into());
        self
    }
    /// Set approver pseudo id.
    pub fn approver_pseudo_id(mut self, id: impl Into<String>) -> Self {
        self.approver_pseudo_id = Some(id.into());
        self
    }
    /// Set jurisdiction tag override.
    pub fn jurisdiction_tag(mut self, j: impl Into<String>) -> Self {
        self.jurisdiction_tag = Some(j.into());
        self
    }
    /// Set explicit input hash.
    pub fn input_hash(mut self, h: Sha256Digest) -> Self {
        self.input_hash_override = Some(h);
        self
    }

    /// Build the typed input. Returns
    /// [`aethelred_sandbox_core::SandboxError::InvalidInput`] on missing required
    /// field.
    pub fn build(self) -> aethelred_sandbox_core::SandboxResult<CreditDecision> {
        use aethelred_sandbox_core::SandboxError as E;
        let application_id = self.application_id.ok_or_else(|| E::invalid("application_id"))?;
        let applicant_pseudo_id = self
            .applicant_pseudo_id
            .ok_or_else(|| E::invalid("applicant_pseudo_id"))?;
        let product = self.product.ok_or_else(|| E::invalid("product"))?;
        let amount = self.amount.ok_or_else(|| E::invalid("amount"))?;
        let currency = self.currency.ok_or_else(|| E::invalid("currency"))?;
        let model_id = self.model_id.ok_or_else(|| E::invalid("model_id"))?;
        let model_hash_hex = self.model_hash_hex.ok_or_else(|| E::invalid("model_hash_hex"))?;
        let decision = self.decision.ok_or_else(|| E::invalid("decision"))?;
        let approver_role = self.approver_role.ok_or_else(|| E::invalid("approver_role"))?;
        let approver_pseudo_id = self
            .approver_pseudo_id
            .ok_or_else(|| E::invalid("approver_pseudo_id"))?;
        Ok(CreditDecision {
            application_id,
            applicant_pseudo_id,
            product,
            amount,
            currency,
            model_id,
            model_hash_hex,
            model_version: self.model_version,
            mrm_lineage_ref: self.mrm_lineage_ref,
            adverse_action_reason: self.adverse_action_reason,
            decision,
            approver_role,
            approver_pseudo_id,
            jurisdiction_tag: self.jurisdiction_tag,
            input_hash_override: self.input_hash_override,
        })
    }
}

/// Sealed credit decision — the typed output of [`crate::FinanceSandbox::seal_credit_decision`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditDecisionSeal {
    /// The underlying canonical seal.
    pub seal: DigitalSeal,
    /// Outcome (mirrored on the seal extension for fast lookups).
    pub outcome: CreditOutcome,
}

impl CreditDecisionSeal {
    /// Stable id string for the seal.
    pub fn id_string(&self) -> String {
        self.seal.id_string()
    }
}

/// Build a [`DigitalSeal`] from a [`CreditDecision`].
///
/// This is what [`crate::FinanceSandbox::seal_credit_decision`] does
/// internally after the policy engine has cleared the decision.
pub(crate) fn build_seal(
    input: &CreditDecision,
    tenant_id: &str,
    default_jurisdiction: &str,
) -> aethelred_sandbox_core::SandboxResult<DigitalSeal> {
    use aethelred_sandbox_core::SandboxError as E;
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex)
        .ok_or_else(|| E::invalid("model_hash_hex must be 64-char hex"))?;
    let model = ModelReference {
        model_hash,
        model_id: input.model_id.clone(),
        model_version: input.model_version.clone(),
        weights_commit_ref: input.mrm_lineage_ref.clone(),
        framework: None,
        framework_version: None,
        training_data_class: None,
    };
    let input_hash = input.input_hash_override.unwrap_or_else(|| {
        Hasher::sha256(input.application_id.as_bytes())
    });
    let output_hash = {
        // Hash of (decision, amount, currency, reason).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.decision.as_str().as_bytes());
        bytes.extend_from_slice(input.amount.to_string().as_bytes());
        bytes.extend_from_slice(input.currency.as_bytes());
        if let Some(r) = &input.adverse_action_reason {
            bytes.extend_from_slice(r.as_bytes());
        }
        Hasher::sha256(&bytes)
    };
    let event_hash = {
        // (application_id, model_id, decision)
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.application_id.as_bytes());
        bytes.extend_from_slice(input.model_id.as_bytes());
        bytes.extend_from_slice(input.decision.as_str().as_bytes());
        Hasher::sha256(&bytes)
    };
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("credit_decision"));
    sector_extension.insert("application_id".into(), serde_json::json!(input.application_id));
    sector_extension.insert("product".into(), serde_json::json!(input.product));
    sector_extension.insert("amount".into(), serde_json::json!(input.amount.to_string()));
    sector_extension.insert("currency".into(), serde_json::json!(input.currency));
    sector_extension.insert("decision".into(), serde_json::json!(input.decision.as_str()));
    if let Some(r) = &input.adverse_action_reason {
        sector_extension.insert("adverse_action_reason".into(), serde_json::json!(r));
    }
    if let Some(m) = &input.mrm_lineage_ref {
        sector_extension.insert("mrm_lineage_ref".into(), serde_json::json!(m));
    }
    let approval = ApprovalRecord {
        approver_ref: input.approver_pseudo_id.clone(),
        role: input.approver_role.clone(),
        decision: input.decision.as_str().to_string(),
        reason_class: input.adverse_action_reason.clone(),
        timestamp: OffsetDateTime::now_utc(),
        signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1,
        seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::Finance,
        event_type: format!("credit_decision.{}", input.decision.as_str()),
        event_hash,
        model,
        policy_id: format!("po_credit_{}_v1", input.product),
        input_hash,
        output_hash,
        approvals: vec![approval],
        attestation: None,
        zk_proof: None,
        tenant_id: tenant_id.to_string(),
        workflow_id: "credit_decision".to_string(),
        jurisdiction_tag: input
            .jurisdiction_tag
            .clone()
            .unwrap_or_else(|| default_jurisdiction.to_string()),
        retention: RetentionClass::SevenYears,
        prior_seal_hash: None,
        sector_extension,
        validator_signature_hex: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_requires_required_fields() {
        let r = CreditDecisionBuilder::default().build();
        assert!(r.is_err());
    }

    #[test]
    fn demo_round_trips_and_seals() {
        let d = CreditDecision::demo();
        let seal = build_seal(&d, "FAB", "AE-CBUAE").unwrap();
        assert_eq!(seal.workflow_id, "credit_decision");
        assert_eq!(seal.sector, Sector::Finance);
        assert!(seal.event_type.starts_with("credit_decision."));
        assert_eq!(seal.tenant_id, "FAB");
        assert_eq!(seal.jurisdiction_tag, "AE-CBUAE");
        assert_eq!(seal.retention, RetentionClass::SevenYears);
    }

    #[test]
    fn adverse_outcome_classification() {
        assert!(CreditOutcome::Rejected.is_adverse());
        assert!(CreditOutcome::ApprovedWithCounterOffer.is_adverse());
        assert!(!CreditOutcome::Approved.is_adverse());
        assert!(!CreditOutcome::Escalated.is_adverse());
    }
}
