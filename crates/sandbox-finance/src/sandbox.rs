//! `FinanceSandbox` — the plug-and-play entry point for the finance sector.
//!
//! Customers interact with this struct, not [`aethelred_sandbox_core`].
//! Everything is typed: the methods accept sector-specific input structs and
//! return sector-specific seal structs.

use crate::policy::{default_gates, GATE_ADVERSE_ACTION_EXPLAINABILITY, GATE_AMOUNT_BOUNDS,
    GATE_EVIDENCE_INTEGRITY, GATE_HUMAN_AUTHORITY, GATE_JURISDICTION_SUPPORTED,
    GATE_MODEL_APPROVAL, GATE_MRM_LINEAGE, GATE_NO_PII_ON_CHAIN, GATE_RISK_LIMIT_CHECK};
use crate::regulators::{FinanceJurisdiction, RegulatorView};
use crate::workflows::{
    advisory::{self, Advisory, AdvisorySeal},
    aml_screening::{self, AmlAlert, AmlAlertSeal},
    credit_decision::{self, CreditDecision, CreditDecisionSeal},
    trading_event::{self, RiskLimitStatus, TradingEvent, TradingEventSeal},
};
use aethelred_sandbox_core::audit::{AuditFormat, AuditTrail};
use aethelred_sandbox_core::policy::PolicyGate;
use aethelred_sandbox_core::verify::{VerificationReport, Verifier};
use aethelred_sandbox_core::{
    DigitalSeal, EvidenceBundle, EvidenceLogEntry, Sandbox, SandboxBuilder, SandboxError,
    SandboxResult, SealEnvelope, Sector, Sha256Digest,
};
use rust_decimal::Decimal;
use std::collections::HashMap;

/// Plug-and-play entry point for finance workflows.
///
/// Construct with [`FinanceSandbox::quickstart`] (one-line) or
/// [`FinanceSandbox::builder`] (declarative configuration).
pub struct FinanceSandbox {
    inner: Sandbox,
    primary_jurisdiction: FinanceJurisdiction,
    /// Maximum allowed monetary amount (sandbox-configured cap). Default: 1bn.
    max_amount: Decimal,
}

impl FinanceSandbox {
    /// One-line quickstart: defaults for design-partner sandboxes.
    ///
    /// Equivalent to:
    /// ```ignore
    /// FinanceSandbox::builder()
    ///     .institution(institution)
    ///     .jurisdiction(FinanceJurisdiction::Cbuae)
    ///     .build()?
    /// ```
    pub fn quickstart(institution: impl Into<String>) -> SandboxResult<Self> {
        Self::builder()
            .institution(institution)
            .jurisdiction(FinanceJurisdiction::Cbuae)
            .build()
    }

    /// New builder.
    pub fn builder() -> FinanceSandboxBuilder {
        FinanceSandboxBuilder::default()
    }

    /// Underlying core [`Sandbox`].
    pub fn core(&self) -> &Sandbox {
        &self.inner
    }

    /// Primary jurisdiction.
    pub fn primary_jurisdiction(&self) -> FinanceJurisdiction {
        self.primary_jurisdiction
    }

    /// Tenant id (the institution).
    pub fn institution(&self) -> &str {
        &self.inner.config().tenant_id
    }

    /// Append a seal to the evidence log.
    fn append(&self, seal: DigitalSeal) -> SandboxResult<EvidenceLogEntry> {
        self.inner.append_seal(seal)
    }

    /// Export the evidence log bundle.
    pub fn export_evidence(&self) -> SandboxResult<EvidenceBundle> {
        self.inner.export_evidence()
    }

    // ============================================================
    // Enterprise convenience: bulk seal API + audit + verification.
    // ============================================================

    /// Seal a batch of credit decisions in one call. Stops at the first
    /// policy denial and returns the `(successful_seals, error)`.
    pub fn seal_credit_decisions(
        &self,
        items: impl IntoIterator<Item = CreditDecision>,
    ) -> SandboxResult<Vec<CreditDecisionSeal>> {
        items.into_iter().map(|i| self.seal_credit_decision(i)).collect()
    }

    /// Seal a batch of AML alerts.
    pub fn seal_aml_alerts(
        &self,
        items: impl IntoIterator<Item = AmlAlert>,
    ) -> SandboxResult<Vec<AmlAlertSeal>> {
        items.into_iter().map(|i| self.seal_aml_alert(i)).collect()
    }

    /// Seal a batch of trading events.
    pub fn seal_trading_events(
        &self,
        items: impl IntoIterator<Item = TradingEvent>,
    ) -> SandboxResult<Vec<TradingEventSeal>> {
        items.into_iter().map(|i| self.seal_trading_event(i)).collect()
    }

    /// Seal a batch of advisories.
    pub fn seal_advisories(
        &self,
        items: impl IntoIterator<Item = Advisory>,
    ) -> SandboxResult<Vec<AdvisorySeal>> {
        items.into_iter().map(|i| self.seal_advisory(i)).collect()
    }

    /// Get a [`SealEnvelope`] (seal + Merkle proof against current root) for
    /// the seal at `index` in the evidence log.
    pub fn envelope_at(&self, index: u64) -> SandboxResult<SealEnvelope> {
        let bundle = self.export_evidence()?;
        let entry = bundle
            .entries
            .iter()
            .find(|e| e.index == index)
            .cloned()
            .ok_or_else(|| {
                SandboxError::Evidence(format!("envelope at index {index} not found"))
            })?;
        let proof = self.inner.evidence().proof(index)?;
        Ok(SealEnvelope {
            seal: entry.seal,
            merkle_proof: Some(proof),
            anchor_block_height: None,
        })
    }

    /// Get all envelopes (seal + Merkle proof) currently in the log, all
    /// against the current Merkle root.
    pub fn all_envelopes(&self) -> SandboxResult<Vec<SealEnvelope>> {
        let bundle = self.export_evidence()?;
        let mut out = Vec::with_capacity(bundle.entries.len());
        for entry in bundle.entries {
            let proof = self.inner.evidence().proof(entry.index)?;
            out.push(SealEnvelope {
                seal: entry.seal,
                merkle_proof: Some(proof),
                anchor_block_height: None,
            });
        }
        Ok(out)
    }

    /// Current Merkle root of the evidence log.
    pub fn current_root(&self) -> SandboxResult<Sha256Digest> {
        self.inner.current_root()
    }

    /// Number of seals currently in the log.
    pub fn seal_count(&self) -> usize {
        self.inner.seal_count()
    }

    /// Render an audit trail in the requested format.
    pub fn audit_trail(&self, format: AuditFormat) -> SandboxResult<String> {
        self.inner.audit_trail(format)
    }

    /// Build an [`AuditTrail`] (structured) for the current evidence bundle.
    pub fn audit_trail_struct(&self) -> SandboxResult<AuditTrail> {
        let bundle = self.export_evidence()?;
        Ok(AuditTrail::from_bundle(&bundle))
    }

    /// Independently verify all seals in the log against the current root.
    /// Returns one verification report per envelope.
    pub fn verify_all(&self) -> SandboxResult<Vec<VerificationReport>> {
        let envs = self.all_envelopes()?;
        let root = self.current_root()?;
        Verifier::default().verify_batch(&envs, root)
    }

    /// Independently verify all seals using a custom [`Verifier`] (e.g.,
    /// `Verifier::strict()`).
    pub fn verify_all_with(
        &self,
        verifier: &Verifier,
    ) -> SandboxResult<Vec<VerificationReport>> {
        let envs = self.all_envelopes()?;
        let root = self.current_root()?;
        verifier.verify_batch(&envs, root)
    }

    /// Project a seal into a regulator-shape view.
    ///
    /// Same canonical seal, different presentation. The seal itself does not
    /// change; the view bundles the appropriate citations and presentation
    /// shape for the named regulator.
    pub fn regulator_view(
        &self,
        seal: &DigitalSeal,
        jurisdiction: FinanceJurisdiction,
    ) -> RegulatorView {
        let event_class = seal
            .event_type
            .split('.')
            .next()
            .unwrap_or("event")
            .to_string();
        let decision = seal
            .approvals
            .first()
            .map(|a| a.decision.clone())
            .unwrap_or_else(|| "unknown".into());
        RegulatorView::project(seal, jurisdiction, decision, event_class)
    }

    // ============================================================
    // Typed sealing methods — one per workflow.
    // ============================================================

    /// Seal a credit decision.
    ///
    /// Runs the finance policy gate suite; on `FailClosed` returns a
    /// [`SandboxError::PolicyDenied`]. On success, produces a typed
    /// [`CreditDecisionSeal`] and appends it to the evidence log.
    pub fn seal_credit_decision(&self, input: CreditDecision) -> SandboxResult<CreditDecisionSeal> {
        // Build the seal first so we can use its content for gate checks.
        let mut seal =
            credit_decision::build_seal(&input, self.institution(), self.primary_jurisdiction.seal_tag())?;
        // Gate checks specific to credit:
        let mut faults: HashMap<String, bool> = HashMap::new();
        // Bound check on amount.
        if input.amount.is_sign_negative() || input.amount > self.max_amount {
            faults.insert(GATE_AMOUNT_BOUNDS.into(), true);
        }
        // Adverse-action explainability (optional gate).
        if input.decision.is_adverse() && input.adverse_action_reason.is_none() {
            faults.insert(GATE_ADVERSE_ACTION_EXPLAINABILITY.into(), true);
        }
        // MRM lineage (optional gate).
        if input.mrm_lineage_ref.is_none() {
            faults.insert(GATE_MRM_LINEAGE.into(), true);
        }
        // Jurisdiction support.
        if !is_supported_jurisdiction(&seal.jurisdiction_tag) {
            faults.insert(GATE_JURISDICTION_SUPPORTED.into(), true);
        }
        // Approval present? (the seal builder always installs one — this
        // gate fails only if a customer manually strips approvals).
        if seal.approvals.is_empty() {
            faults.insert(GATE_HUMAN_AUTHORITY.into(), true);
        }
        // Model approval — we accept any model_hash that is non-zero (a real
        // production deployment would compare against an approved-model
        // registry). The default policy is permissive in sandbox mode.
        if seal.model.model_hash.0 == [0u8; 32] {
            faults.insert(GATE_MODEL_APPROVAL.into(), true);
        }
        // Evidence integrity — the seal must have non-zero hashes.
        if seal.event_hash.0 == [0u8; 32] || seal.input_hash.0 == [0u8; 32] || seal.output_hash.0 == [0u8; 32] {
            faults.insert(GATE_EVIDENCE_INTEGRITY.into(), true);
        }
        // No-PII gate: if the application_id or applicant_pseudo_id contains
        // a forbidden marker (sandbox-only convention), fail closed. This
        // ensures customers don't accidentally pass real PII in via the
        // pseudo-id field.
        if has_pii_marker(&input.applicant_pseudo_id) || has_pii_marker(&input.application_id) {
            faults.insert(GATE_NO_PII_ON_CHAIN.into(), true);
        }
        let (decision, _outcomes) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            // Find first failing gate for the error.
            let gate = faults
                .iter()
                .find(|(_, v)| **v)
                .map(|(k, _)| k.clone())
                .unwrap_or_else(|| "finance.unknown".into());
            return Err(SandboxError::policy(
                gate,
                format!(
                    "credit decision policy denial for application {}",
                    input.application_id
                ),
            ));
        }
        let _ = self.append(seal.clone())?;
        // Mirror the outcome onto the typed seal wrapper.
        let outcome = input.decision;
        // Embed the outcome into the seal extension (if not already).
        seal.sector_extension
            .entry("decision".into())
            .or_insert_with(|| serde_json::json!(outcome.as_str()));
        Ok(CreditDecisionSeal { seal, outcome })
    }

    /// Seal an AML alert.
    pub fn seal_aml_alert(&self, input: AmlAlert) -> SandboxResult<AmlAlertSeal> {
        let seal =
            aml_screening::build_seal(&input, self.institution(), self.primary_jurisdiction.seal_tag())?;
        let mut faults: HashMap<String, bool> = HashMap::new();
        if seal.model.model_hash.0 == [0u8; 32] {
            faults.insert(GATE_MODEL_APPROVAL.into(), true);
        }
        if seal.approvals.is_empty() {
            faults.insert(GATE_HUMAN_AUTHORITY.into(), true);
        }
        if !is_supported_jurisdiction(&seal.jurisdiction_tag) {
            faults.insert(GATE_JURISDICTION_SUPPORTED.into(), true);
        }
        if has_pii_marker(&input.alert_id) || has_pii_marker(&input.customer_pseudo_id) {
            faults.insert(GATE_NO_PII_ON_CHAIN.into(), true);
        }
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let gate = faults
                .iter()
                .find(|(_, v)| **v)
                .map(|(k, _)| k.clone())
                .unwrap_or_else(|| "finance.unknown".into());
            return Err(SandboxError::policy(
                gate,
                format!("aml alert {} blocked by policy", input.alert_id),
            ));
        }
        self.append(seal.clone())?;
        Ok(AmlAlertSeal {
            seal,
            outcome: input.outcome,
        })
    }

    /// Seal a trading event.
    pub fn seal_trading_event(&self, input: TradingEvent) -> SandboxResult<TradingEventSeal> {
        let seal =
            trading_event::build_seal(&input, self.institution(), self.primary_jurisdiction.seal_tag())?;
        let mut faults: HashMap<String, bool> = HashMap::new();
        if input.quantity.is_sign_negative() {
            faults.insert(GATE_AMOUNT_BOUNDS.into(), true);
        }
        if let Some(notional) = input.notional {
            if notional > self.max_amount {
                faults.insert(GATE_AMOUNT_BOUNDS.into(), true);
            }
        }
        // Risk-limit gate (optional in sandbox; required for production).
        if matches!(input.risk_limit_status, RiskLimitStatus::Exceeded) {
            faults.insert(GATE_RISK_LIMIT_CHECK.into(), true);
        }
        if !is_supported_jurisdiction(&seal.jurisdiction_tag) {
            faults.insert(GATE_JURISDICTION_SUPPORTED.into(), true);
        }
        if seal.approvals.is_empty() {
            faults.insert(GATE_HUMAN_AUTHORITY.into(), true);
        }
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let gate = faults
                .iter()
                .find(|(_, v)| **v)
                .map(|(k, _)| k.clone())
                .unwrap_or_else(|| "finance.unknown".into());
            return Err(SandboxError::policy(
                gate,
                format!("trading event {} blocked by policy", input.order_id),
            ));
        }
        self.append(seal.clone())?;
        Ok(TradingEventSeal {
            seal,
            risk_limit_status: input.risk_limit_status,
        })
    }

    /// Seal an advisory recommendation.
    pub fn seal_advisory(&self, input: Advisory) -> SandboxResult<AdvisorySeal> {
        let seal = advisory::build_seal(&input, self.institution(), self.primary_jurisdiction.seal_tag())?;
        let mut faults: HashMap<String, bool> = HashMap::new();
        if input.amount.is_sign_negative() || input.amount > self.max_amount {
            faults.insert(GATE_AMOUNT_BOUNDS.into(), true);
        }
        if !is_supported_jurisdiction(&seal.jurisdiction_tag) {
            faults.insert(GATE_JURISDICTION_SUPPORTED.into(), true);
        }
        if seal.approvals.is_empty() {
            faults.insert(GATE_HUMAN_AUTHORITY.into(), true);
        }
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let gate = faults
                .iter()
                .find(|(_, v)| **v)
                .map(|(k, _)| k.clone())
                .unwrap_or_else(|| "finance.unknown".into());
            return Err(SandboxError::policy(
                gate,
                format!("advisory {} blocked by policy", input.recommendation_id),
            ));
        }
        self.append(seal.clone())?;
        Ok(AdvisorySeal {
            seal,
            suitability: input.suitability,
        })
    }
}

/// Builder for [`FinanceSandbox`].
#[derive(Default)]
pub struct FinanceSandboxBuilder {
    institution: Option<String>,
    primary_jurisdiction: Option<FinanceJurisdiction>,
    extra_gates: Vec<PolicyGate>,
    max_amount: Option<Decimal>,
    label: Option<String>,
}

impl FinanceSandboxBuilder {
    /// Set the institution (tenant id).
    pub fn institution(mut self, institution: impl Into<String>) -> Self {
        self.institution = Some(institution.into());
        self
    }

    /// Set the primary jurisdiction.
    pub fn jurisdiction(mut self, j: FinanceJurisdiction) -> Self {
        self.primary_jurisdiction = Some(j);
        self
    }

    /// Add an extra policy gate beyond the default finance gate set.
    pub fn with_extra_gate(mut self, gate: PolicyGate) -> Self {
        self.extra_gates.push(gate);
        self
    }

    /// Override the maximum amount (default: 1bn AED).
    pub fn max_amount(mut self, max: Decimal) -> Self {
        self.max_amount = Some(max);
        self
    }

    /// Override the sandbox label.
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Build.
    pub fn build(self) -> SandboxResult<FinanceSandbox> {
        let institution = self
            .institution
            .ok_or_else(|| SandboxError::config("institution not set"))?;
        let primary = self.primary_jurisdiction.unwrap_or(FinanceJurisdiction::Cbuae);
        let mut all_gates = default_gates();
        all_gates.extend(self.extra_gates);
        let label = self
            .label
            .unwrap_or_else(|| format!("{institution} Finance Sandbox"));
        let inner = SandboxBuilder::new(Sector::Finance)
            .crate_name("aethelred-sandbox-finance")
            .crate_version(env!("CARGO_PKG_VERSION"))
            .tenant(&institution)
            .label(&label)
            .jurisdiction(primary.seal_tag())
            .workflow("credit_decision")
            .workflow("aml_screening")
            .workflow("trading_event")
            .workflow("advisory")
            .with_gates(all_gates)
            .build()?;
        Ok(FinanceSandbox {
            inner,
            primary_jurisdiction: primary,
            max_amount: self.max_amount.unwrap_or_else(|| Decimal::new(1_000_000_000, 0)),
        })
    }
}

// ============================================================
// Helpers
// ============================================================

fn is_supported_jurisdiction(tag: &str) -> bool {
    matches!(
        tag,
        "AE-CBUAE" | "AE-SCA" | "AE-ADGM-FSRA" | "AE-DIFC-DFSA"
            | "UK-FCA" | "US-OCC" | "SG-MAS"
    )
}

/// Detect obvious PII markers (sandbox safety net). The pattern is
/// deliberately simple — production-grade detection lives in dedicated
/// scanners.
fn has_pii_marker(s: &str) -> bool {
    let lower = s.to_lowercase();
    // Sample patterns: email, phone, NID-like sequences.
    lower.contains('@') || lower.contains("ssn:") || lower.contains("emirates_id:")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflows::credit_decision::CreditOutcome;

    #[test]
    fn quickstart_constructs_with_defaults() {
        let sb = FinanceSandbox::quickstart("FAB").unwrap();
        assert_eq!(sb.institution(), "FAB");
        assert_eq!(sb.primary_jurisdiction(), FinanceJurisdiction::Cbuae);
    }

    #[test]
    fn seal_credit_decision_happy_path() {
        let sb = FinanceSandbox::quickstart("FAB").unwrap();
        let s = sb.seal_credit_decision(CreditDecision::demo()).unwrap();
        assert_eq!(s.outcome, CreditOutcome::Approved);
        assert!(s.id_string().starts_with("seal_"));
    }

    #[test]
    fn seal_aml_alert_happy_path() {
        let sb = FinanceSandbox::quickstart("FAB").unwrap();
        let s = sb.seal_aml_alert(AmlAlert::demo()).unwrap();
        assert!(s.id_string().starts_with("seal_"));
    }

    #[test]
    fn seal_trading_event_happy_path() {
        let sb = FinanceSandbox::quickstart("FAB").unwrap();
        let s = sb.seal_trading_event(TradingEvent::demo()).unwrap();
        assert_eq!(s.risk_limit_status, RiskLimitStatus::WithinLimits);
    }

    #[test]
    fn seal_advisory_happy_path() {
        let sb = FinanceSandbox::quickstart("FAB").unwrap();
        let s = sb.seal_advisory(Advisory::demo()).unwrap();
        assert!(s.id_string().starts_with("seal_"));
    }

    #[test]
    fn negative_amount_fails_closed() {
        let sb = FinanceSandbox::quickstart("FAB").unwrap();
        let mut d = CreditDecision::demo();
        d.amount = Decimal::new(-1, 0);
        let r = sb.seal_credit_decision(d);
        assert!(r.is_err());
        assert!(r.unwrap_err().is_policy_denial());
    }

    #[test]
    fn pii_marker_in_pseudo_id_fails_closed() {
        let sb = FinanceSandbox::quickstart("FAB").unwrap();
        let mut d = CreditDecision::demo();
        d.applicant_pseudo_id = "user@example.com".into();
        let r = sb.seal_credit_decision(d);
        assert!(r.is_err());
    }

    #[test]
    fn risk_limit_exceeded_blocks_trading_event() {
        let sb = FinanceSandbox::quickstart("FAB").unwrap();
        let mut t = TradingEvent::demo();
        t.risk_limit_status = RiskLimitStatus::Exceeded;
        let r = sb.seal_trading_event(t);
        assert!(r.is_err());
        assert!(r.unwrap_err().is_policy_denial());
    }

    #[test]
    fn export_evidence_returns_appended_seals() {
        let sb = FinanceSandbox::quickstart("FAB").unwrap();
        sb.seal_credit_decision(CreditDecision::demo()).unwrap();
        sb.seal_aml_alert(AmlAlert::demo()).unwrap();
        let bundle = sb.export_evidence().unwrap();
        assert_eq!(bundle.entries.len(), 2);
        assert_eq!(bundle.tenant_id, "FAB");
    }

    #[test]
    fn regulator_view_projects_with_citations() {
        let sb = FinanceSandbox::quickstart("FAB").unwrap();
        let s = sb.seal_credit_decision(CreditDecision::demo()).unwrap();
        let view = sb.regulator_view(&s.seal, FinanceJurisdiction::Cbuae);
        assert!(!view.citations.is_empty());
        let view_uk = sb.regulator_view(&s.seal, FinanceJurisdiction::FcaUk);
        assert!(view_uk
            .citations
            .iter()
            .any(|c| c.regulator == "FCA (UK)"));
    }
}
