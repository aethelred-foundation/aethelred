//! `HealthcareSandbox` — plug-and-play entry point for healthcare workflows.

use crate::policy::{
    default_gates, GATE_CLINICAL_REVIEW, GATE_DECISION_SUPPORT_ONLY, GATE_EVIDENCE_INTEGRITY,
    GATE_GENOMICS_DATASET_CLASS, GATE_JURISDICTION_SUPPORTED, GATE_MODEL_APPROVAL, GATE_NO_PHI,
};
use crate::regulators::{HealthcareJurisdiction, RegulatorView};
use crate::workflows::{
    ambient_scribe::{self, AmbientNote, AmbientNoteSeal},
    claims::{self, ClaimsAdjudication, ClaimsAdjudicationSeal},
    clinical_ai::{self, ClinicalInference, ClinicalInferenceSeal},
    genomics::{self, GenomicsDatasetClass, GenomicsInference, GenomicsInferenceSeal},
};
use aethelred_sandbox_core::audit::{AuditFormat, AuditTrail};
use aethelred_sandbox_core::policy::PolicyGate;
use aethelred_sandbox_core::verify::{VerificationReport, Verifier};
use aethelred_sandbox_core::{
    DigitalSeal, EvidenceBundle, EvidenceLogEntry, Sandbox, SandboxBuilder, SandboxError,
    SandboxResult, SealEnvelope, Sector, Sha256Digest,
};
use std::collections::HashMap;

/// Plug-and-play entry point for healthcare workflows.
pub struct HealthcareSandbox {
    inner: Sandbox,
    primary_jurisdiction: HealthcareJurisdiction,
}

impl HealthcareSandbox {
    /// One-line quickstart.
    pub fn quickstart(institution: impl Into<String>) -> SandboxResult<Self> {
        Self::builder()
            .institution(institution)
            .jurisdiction(HealthcareJurisdiction::DohAbuDhabi)
            .build()
    }

    /// New builder.
    pub fn builder() -> HealthcareSandboxBuilder {
        HealthcareSandboxBuilder::default()
    }

    /// Underlying core sandbox.
    pub fn core(&self) -> &Sandbox {
        &self.inner
    }

    /// Primary jurisdiction.
    pub fn primary_jurisdiction(&self) -> HealthcareJurisdiction {
        self.primary_jurisdiction
    }

    /// Tenant id (the institution).
    pub fn institution(&self) -> &str {
        &self.inner.config().tenant_id
    }

    fn append(&self, seal: DigitalSeal) -> SandboxResult<EvidenceLogEntry> {
        self.inner.append_seal(seal)
    }

    /// Export the evidence bundle.
    pub fn export_evidence(&self) -> SandboxResult<EvidenceBundle> {
        self.inner.export_evidence()
    }

    // ============================================================
    // Enterprise convenience: bulk seal, envelope, verify, audit.
    // ============================================================

    /// Seal a batch of genomics inferences.
    pub fn seal_genomics_batch(
        &self,
        items: impl IntoIterator<Item = GenomicsInference>,
    ) -> SandboxResult<Vec<GenomicsInferenceSeal>> {
        items.into_iter().map(|i| self.seal_genomics_inference(i)).collect()
    }

    /// Seal a batch of clinical inferences.
    pub fn seal_clinical_batch(
        &self,
        items: impl IntoIterator<Item = ClinicalInference>,
    ) -> SandboxResult<Vec<ClinicalInferenceSeal>> {
        items.into_iter().map(|i| self.seal_clinical_inference(i)).collect()
    }

    /// Seal a batch of ambient notes.
    pub fn seal_ambient_batch(
        &self,
        items: impl IntoIterator<Item = AmbientNote>,
    ) -> SandboxResult<Vec<AmbientNoteSeal>> {
        items.into_iter().map(|i| self.seal_ambient_note(i)).collect()
    }

    /// Seal a batch of claims.
    pub fn seal_claims_batch(
        &self,
        items: impl IntoIterator<Item = ClaimsAdjudication>,
    ) -> SandboxResult<Vec<ClaimsAdjudicationSeal>> {
        items.into_iter().map(|i| self.seal_claims_adjudication(i)).collect()
    }

    /// Get the [`SealEnvelope`] (seal + Merkle proof) at the given log index.
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

    /// Get all envelopes (seal + Merkle proof) currently in the log.
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

    /// Current Merkle root.
    pub fn current_root(&self) -> SandboxResult<Sha256Digest> {
        self.inner.current_root()
    }

    /// Number of seals in the log.
    pub fn seal_count(&self) -> usize {
        self.inner.seal_count()
    }

    /// Render an audit trail.
    pub fn audit_trail(&self, format: AuditFormat) -> SandboxResult<String> {
        self.inner.audit_trail(format)
    }

    /// Build a structured audit trail.
    pub fn audit_trail_struct(&self) -> SandboxResult<AuditTrail> {
        let bundle = self.export_evidence()?;
        Ok(AuditTrail::from_bundle(&bundle))
    }

    /// Independently verify all seals against the current root.
    pub fn verify_all(&self) -> SandboxResult<Vec<VerificationReport>> {
        let envs = self.all_envelopes()?;
        let root = self.current_root()?;
        Verifier::default().verify_batch(&envs, root)
    }

    /// Independently verify all seals using a custom Verifier.
    pub fn verify_all_with(
        &self,
        verifier: &Verifier,
    ) -> SandboxResult<Vec<VerificationReport>> {
        let envs = self.all_envelopes()?;
        let root = self.current_root()?;
        verifier.verify_batch(&envs, root)
    }

    /// Project a seal into a regulator-shape view.
    pub fn regulator_view(
        &self,
        seal: &DigitalSeal,
        jurisdiction: HealthcareJurisdiction,
    ) -> RegulatorView {
        let event_class = seal.event_type.split('.').next().unwrap_or("event").to_string();
        let decision = seal
            .approvals
            .first()
            .map(|a| a.decision.clone())
            .unwrap_or_else(|| "unknown".into());
        RegulatorView::project(seal, jurisdiction, decision, event_class)
    }

    // ============ Workflows ============

    /// Seal a genomics inference.
    pub fn seal_genomics_inference(
        &self,
        input: GenomicsInference,
    ) -> SandboxResult<GenomicsInferenceSeal> {
        let seal = genomics::build_seal(&input, self.institution(), self.primary_jurisdiction.seal_tag())?;
        let mut faults: HashMap<String, bool> = HashMap::new();
        if has_phi_marker(&input.sample_pseudo_id) {
            faults.insert(GATE_NO_PHI.into(), true);
        }
        if seal.model.model_hash.0 == [0u8; 32] {
            faults.insert(GATE_MODEL_APPROVAL.into(), true);
        }
        if seal.approvals.is_empty() {
            faults.insert(GATE_CLINICAL_REVIEW.into(), true);
        }
        if !is_supported_jurisdiction(&seal.jurisdiction_tag) {
            faults.insert(GATE_JURISDICTION_SUPPORTED.into(), true);
        }
        // Genomics dataset class soft gate.
        if !matches!(
            input.dataset_class,
            GenomicsDatasetClass::Synthetic
                | GenomicsDatasetClass::DeIdentified
                | GenomicsDatasetClass::Consented
        ) {
            faults.insert(GATE_GENOMICS_DATASET_CLASS.into(), true);
        }
        // Decision-support gate is satisfied if the seal extension flags it.
        let dso = seal
            .sector_extension
            .get("decision_support_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !dso {
            faults.insert(GATE_DECISION_SUPPORT_ONLY.into(), true);
        }
        // Evidence integrity.
        if seal.event_hash.0 == [0u8; 32] || seal.input_hash.0 == [0u8; 32] || seal.output_hash.0 == [0u8; 32] {
            faults.insert(GATE_EVIDENCE_INTEGRITY.into(), true);
        }
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let gate = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(
                gate,
                format!("genomics inference {} blocked by policy", input.variant_id),
            ));
        }
        self.append(seal.clone())?;
        Ok(GenomicsInferenceSeal {
            seal,
            classification: input.classification,
        })
    }

    /// Seal a clinical AI inference (radiology / pathology / etc.).
    pub fn seal_clinical_inference(
        &self,
        input: ClinicalInference,
    ) -> SandboxResult<ClinicalInferenceSeal> {
        let seal = clinical_ai::build_seal(&input, self.institution(), self.primary_jurisdiction.seal_tag())?;
        let mut faults: HashMap<String, bool> = HashMap::new();
        if has_phi_marker(&input.encounter_pseudo_id) {
            faults.insert(GATE_NO_PHI.into(), true);
        }
        if seal.model.model_hash.0 == [0u8; 32] {
            faults.insert(GATE_MODEL_APPROVAL.into(), true);
        }
        if seal.approvals.is_empty() {
            faults.insert(GATE_CLINICAL_REVIEW.into(), true);
        }
        if !is_supported_jurisdiction(&seal.jurisdiction_tag) {
            faults.insert(GATE_JURISDICTION_SUPPORTED.into(), true);
        }
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let gate = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(
                gate,
                format!("clinical inference {} blocked by policy", input.encounter_pseudo_id),
            ));
        }
        self.append(seal.clone())?;
        Ok(ClinicalInferenceSeal {
            seal,
            recommendation: input.recommendation,
        })
    }

    /// Seal an ambient AI scribe note.
    pub fn seal_ambient_note(&self, input: AmbientNote) -> SandboxResult<AmbientNoteSeal> {
        let seal = ambient_scribe::build_seal(&input, self.institution(), self.primary_jurisdiction.seal_tag())?;
        let mut faults: HashMap<String, bool> = HashMap::new();
        if has_phi_marker(&input.encounter_pseudo_id) {
            faults.insert(GATE_NO_PHI.into(), true);
        }
        if seal.model.model_hash.0 == [0u8; 32] {
            faults.insert(GATE_MODEL_APPROVAL.into(), true);
        }
        if !input.clinician_signed {
            faults.insert(GATE_CLINICAL_REVIEW.into(), true);
        }
        if !is_supported_jurisdiction(&seal.jurisdiction_tag) {
            faults.insert(GATE_JURISDICTION_SUPPORTED.into(), true);
        }
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let gate = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(
                gate,
                format!("ambient note for {} blocked by policy", input.encounter_pseudo_id),
            ));
        }
        self.append(seal.clone())?;
        Ok(AmbientNoteSeal {
            seal,
            clinician_signed: input.clinician_signed,
        })
    }

    /// Seal a claims adjudication.
    pub fn seal_claims_adjudication(
        &self,
        input: ClaimsAdjudication,
    ) -> SandboxResult<ClaimsAdjudicationSeal> {
        let seal = claims::build_seal(&input, self.institution(), self.primary_jurisdiction.seal_tag())?;
        let mut faults: HashMap<String, bool> = HashMap::new();
        if has_phi_marker(&input.member_pseudo_id) || has_phi_marker(&input.claim_id) {
            faults.insert(GATE_NO_PHI.into(), true);
        }
        if seal.model.model_hash.0 == [0u8; 32] {
            faults.insert(GATE_MODEL_APPROVAL.into(), true);
        }
        if seal.approvals.is_empty() {
            faults.insert(GATE_CLINICAL_REVIEW.into(), true);
        }
        if !is_supported_jurisdiction(&seal.jurisdiction_tag) {
            faults.insert(GATE_JURISDICTION_SUPPORTED.into(), true);
        }
        // Adverse outcomes must carry a reason class.
        if input.decision.is_adverse() && input.reason_class.is_none() {
            // Reuse model_approval gate id is wrong here; instead surface via
            // direct policy denial.
            return Err(SandboxError::policy(
                "healthcare.adverse_decision_explainability",
                format!("adverse decision {} requires reason_class", input.decision.as_str()),
            ));
        }
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let gate = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(
                gate,
                format!("claim {} blocked by policy", input.claim_id),
            ));
        }
        self.append(seal.clone())?;
        Ok(ClaimsAdjudicationSeal {
            seal,
            decision: input.decision,
        })
    }
}

/// Builder for [`HealthcareSandbox`].
#[derive(Default)]
pub struct HealthcareSandboxBuilder {
    institution: Option<String>,
    primary_jurisdiction: Option<HealthcareJurisdiction>,
    extra_gates: Vec<PolicyGate>,
    label: Option<String>,
}

impl HealthcareSandboxBuilder {
    /// Set institution.
    pub fn institution(mut self, institution: impl Into<String>) -> Self {
        self.institution = Some(institution.into());
        self
    }

    /// Set primary jurisdiction.
    pub fn jurisdiction(mut self, j: HealthcareJurisdiction) -> Self {
        self.primary_jurisdiction = Some(j);
        self
    }

    /// Add an extra policy gate.
    pub fn with_extra_gate(mut self, gate: PolicyGate) -> Self {
        self.extra_gates.push(gate);
        self
    }

    /// Override the sandbox label.
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Build.
    pub fn build(self) -> SandboxResult<HealthcareSandbox> {
        let institution = self
            .institution
            .ok_or_else(|| SandboxError::config("institution not set"))?;
        let primary = self
            .primary_jurisdiction
            .unwrap_or(HealthcareJurisdiction::DohAbuDhabi);
        let mut all_gates = default_gates();
        all_gates.extend(self.extra_gates);
        let label = self
            .label
            .unwrap_or_else(|| format!("{institution} Healthcare Sandbox"));
        let inner = SandboxBuilder::new(Sector::Healthcare)
            .crate_name("aethelred-sandbox-healthcare")
            .crate_version(env!("CARGO_PKG_VERSION"))
            .tenant(&institution)
            .label(&label)
            .jurisdiction(primary.seal_tag())
            .workflow("genomics_inference")
            .workflow("clinical_ai")
            .workflow("ambient_scribe")
            .workflow("claims_adjudication")
            .with_gates(all_gates)
            .build()?;
        Ok(HealthcareSandbox {
            inner,
            primary_jurisdiction: primary,
        })
    }
}

fn is_supported_jurisdiction(tag: &str) -> bool {
    matches!(
        tag,
        "AE-AD-DOH" | "AE-DXB-DHA" | "AE-MOHAP" | "AE-EHS" | "US-HIPAA" | "EU-AI-ACT" | "BH-NHRA"
    )
}

/// Detect obvious PHI markers (sandbox safety net).
fn has_phi_marker(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.contains('@')
        || lower.contains("mrn:")
        || lower.contains("emirates_id:")
        || lower.contains("ssn:")
        || lower.contains("dob:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quickstart_constructs_with_doh_default() {
        let sb = HealthcareSandbox::quickstart("M42").unwrap();
        assert_eq!(sb.institution(), "M42");
        assert_eq!(sb.primary_jurisdiction(), HealthcareJurisdiction::DohAbuDhabi);
    }

    #[test]
    fn seal_genomics_happy_path() {
        let sb = HealthcareSandbox::quickstart("M42").unwrap();
        let s = sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
        assert!(s.id_string().starts_with("seal_"));
    }

    #[test]
    fn seal_clinical_happy_path() {
        let sb = HealthcareSandbox::quickstart("M42").unwrap();
        let s = sb.seal_clinical_inference(ClinicalInference::demo()).unwrap();
        assert!(s.id_string().starts_with("seal_"));
    }

    #[test]
    fn seal_ambient_happy_path() {
        let sb = HealthcareSandbox::quickstart("M42").unwrap();
        let s = sb.seal_ambient_note(AmbientNote::demo()).unwrap();
        assert!(s.clinician_signed);
    }

    #[test]
    fn seal_claims_happy_path() {
        let sb = HealthcareSandbox::quickstart("PureHealth").unwrap();
        let s = sb.seal_claims_adjudication(ClaimsAdjudication::demo()).unwrap();
        assert!(s.id_string().starts_with("seal_"));
    }

    #[test]
    fn phi_marker_in_id_fails_closed() {
        let sb = HealthcareSandbox::quickstart("M42").unwrap();
        let mut g = GenomicsInference::demo();
        g.sample_pseudo_id = "patient@example.com".into();
        let r = sb.seal_genomics_inference(g);
        assert!(r.is_err());
        assert!(r.unwrap_err().is_policy_denial());
    }

    #[test]
    fn unsigned_ambient_note_fails_closed() {
        let sb = HealthcareSandbox::quickstart("M42").unwrap();
        let mut n = AmbientNote::demo();
        n.clinician_signed = false;
        let r = sb.seal_ambient_note(n);
        assert!(r.is_err());
    }

    #[test]
    fn adverse_claim_without_reason_fails_closed() {
        use crate::workflows::claims::ClaimDecision;
        let sb = HealthcareSandbox::quickstart("PureHealth").unwrap();
        let mut c = ClaimsAdjudication::demo();
        c.decision = ClaimDecision::Denied;
        c.reason_class = None;
        let r = sb.seal_claims_adjudication(c);
        assert!(r.is_err());
    }

    #[test]
    fn export_evidence_returns_seals_appended() {
        let sb = HealthcareSandbox::quickstart("M42").unwrap();
        sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
        sb.seal_clinical_inference(ClinicalInference::demo()).unwrap();
        let bundle = sb.export_evidence().unwrap();
        assert_eq!(bundle.entries.len(), 2);
        assert_eq!(bundle.tenant_id, "M42");
        assert_eq!(bundle.sector, Sector::Healthcare);
    }
}
