//! Healthcare-sector policy gates.

use aethelred_sandbox_core::policy::PolicyGate;

/// No raw PHI / patient identifiers on chain.
pub const GATE_NO_PHI: &str = "healthcare.no_phi_on_chain";
/// Approved clinical-AI model on the registry.
pub const GATE_MODEL_APPROVAL: &str = "healthcare.model_approval";
/// Clinical reviewer (clinician / radiologist / pathologist) approval bound.
pub const GATE_CLINICAL_REVIEW: &str = "healthcare.clinical_review";
/// Consent class is acceptable for the workflow.
pub const GATE_CONSENT_CLASS: &str = "healthcare.consent_class";
/// Output is annotated as decision-support, not autonomous diagnosis.
pub const GATE_DECISION_SUPPORT_ONLY: &str = "healthcare.decision_support_only";
/// Genomics-specific: dataset class is approved (synthetic / de-identified
/// / consented).
pub const GATE_GENOMICS_DATASET_CLASS: &str = "healthcare.genomics_dataset_class";
/// Evidence integrity (no tampering of input/output hashes).
pub const GATE_EVIDENCE_INTEGRITY: &str = "healthcare.evidence_integrity";
/// Jurisdiction supported.
pub const GATE_JURISDICTION_SUPPORTED: &str = "healthcare.jurisdiction_supported";
/// EU AI Act Annex III §3 — high-risk AI obligation.
pub const GATE_EU_AI_ACT_HIGH_RISK: &str = "healthcare.eu_ai_act_high_risk_compliance";

/// Default healthcare gate set.
pub fn default_gates() -> Vec<PolicyGate> {
    vec![
        PolicyGate::required(
            GATE_NO_PHI,
            "No PHI on chain",
            "Patient identifiers / medical records / genomic data must remain off-chain.",
        ),
        PolicyGate::required(
            GATE_MODEL_APPROVAL,
            "Approved clinical model",
            "Only approved clinical AI models may issue sealable recommendations.",
        ),
        PolicyGate::required(
            GATE_CLINICAL_REVIEW,
            "Qualified clinical reviewer",
            "Clinical-decision support requires a qualified reviewer signature.",
        ),
        PolicyGate::required(
            GATE_DECISION_SUPPORT_ONLY,
            "Decision-support only",
            "AI output must be annotated as decision-support, not autonomous diagnosis.",
        ),
        PolicyGate::required(
            GATE_EVIDENCE_INTEGRITY,
            "Evidence integrity",
            "Tampered input / output / model hashes fail closed.",
        ),
        PolicyGate::required(
            GATE_JURISDICTION_SUPPORTED,
            "Jurisdiction supported",
            "Workflow jurisdiction must be one of the configured regulator views.",
        ),
        PolicyGate::optional(
            GATE_CONSENT_CLASS,
            "Consent class acceptable",
            "Soft-fail to review when consent class is missing or unrecognised.",
        ),
        PolicyGate::optional(
            GATE_GENOMICS_DATASET_CLASS,
            "Genomics dataset class",
            "Genomics workflows soft-fail to review when dataset class is non-canonical.",
        ),
        PolicyGate::optional(
            GATE_EU_AI_ACT_HIGH_RISK,
            "EU AI Act high-risk Annex III §3",
            "Soft-fail to review when EU AI Act high-risk registration metadata is missing.",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_gates_have_unique_ids_and_required_majority() {
        let gates = default_gates();
        let mut ids: Vec<&String> = gates.iter().map(|g| &g.id).collect();
        ids.sort();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
        let req = gates.iter().filter(|g| g.required).count();
        assert!(req >= 5);
    }
}
