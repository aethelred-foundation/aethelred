//! Finance-sector policy gate set.
//!
//! These are the gates installed by [`crate::FinanceSandbox::builder`] by
//! default. Customers can extend this list (e.g., add an internal-policy gate
//! that checks "credit applications above AED 100m require Group Risk
//! sign-off") via `builder.with_extra_gate(...)`.

use aethelred_sandbox_core::policy::PolicyGate;

/// Gate id: model on the approved model registry.
pub const GATE_MODEL_APPROVAL: &str = "finance.model_approval";
/// Gate id: human-authority sign-off bound to the seal.
pub const GATE_HUMAN_AUTHORITY: &str = "finance.human_authority";
/// Gate id: no PII / transaction data on-chain.
pub const GATE_NO_PII_ON_CHAIN: &str = "finance.no_pii_on_chain";
/// Gate id: model-risk lineage (SR 11-7 / EBA equivalent) present.
pub const GATE_MRM_LINEAGE: &str = "finance.mrm_lineage";
/// Gate id: evidence integrity (no tampering of input/output hashes).
pub const GATE_EVIDENCE_INTEGRITY: &str = "finance.evidence_integrity";
/// Gate id: monetary amounts are non-negative and within configured cap.
pub const GATE_AMOUNT_BOUNDS: &str = "finance.amount_bounds";
/// Gate id: jurisdiction in the supported set.
pub const GATE_JURISDICTION_SUPPORTED: &str = "finance.jurisdiction_supported";
/// Gate id: adverse-action explainability (EU AI Act Annex III §5).
pub const GATE_ADVERSE_ACTION_EXPLAINABILITY: &str = "finance.adverse_action_explainability";
/// Gate id: AML / sanctions screening completed before high-value movement.
pub const GATE_AML_SCREENING_COMPLETE: &str = "finance.aml_screening_complete";
/// Gate id: trading risk-limit check.
pub const GATE_RISK_LIMIT_CHECK: &str = "finance.risk_limit_check";

/// Default finance gate set installed on every [`crate::FinanceSandbox`].
pub fn default_gates() -> Vec<PolicyGate> {
    vec![
        PolicyGate::required(
            GATE_MODEL_APPROVAL,
            "Approved model version",
            "Only approved model versions may issue sealable financial recommendations.",
        ),
        PolicyGate::required(
            GATE_HUMAN_AUTHORITY,
            "Human decision authority",
            "Final financial decisions require an authorised human reviewer signature.",
        ),
        PolicyGate::required(
            GATE_NO_PII_ON_CHAIN,
            "No PII on chain",
            "Customer / transaction PII must remain off-chain; only hashes & policy IDs travel.",
        ),
        PolicyGate::required(
            GATE_EVIDENCE_INTEGRITY,
            "Evidence integrity",
            "Tampered input or output commitments fail closed.",
        ),
        PolicyGate::required(
            GATE_AMOUNT_BOUNDS,
            "Amount bounds",
            "Monetary amounts must be non-negative and within sandbox-configured caps.",
        ),
        PolicyGate::required(
            GATE_JURISDICTION_SUPPORTED,
            "Jurisdiction supported",
            "Workflow jurisdiction must be one of the configured regulator views.",
        ),
        PolicyGate::optional(
            GATE_MRM_LINEAGE,
            "Model-risk-management lineage",
            "Model lineage (SR 11-7 / EBA equivalent) should be present; soft-fail to review.",
        ),
        PolicyGate::optional(
            GATE_ADVERSE_ACTION_EXPLAINABILITY,
            "Adverse-action explainability",
            "Adverse credit decisions should carry a reason class (EU AI Act Annex III §5).",
        ),
        PolicyGate::optional(
            GATE_AML_SCREENING_COMPLETE,
            "AML / sanctions screening complete",
            "High-value movements should be cross-checked against AML alerts.",
        ),
        PolicyGate::required(
            GATE_RISK_LIMIT_CHECK,
            "Risk-limit check",
            "Trading orders that exceed risk limits must be blocked or escalated.",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_gates_have_unique_ids() {
        let gates = default_gates();
        let mut ids: Vec<&String> = gates.iter().map(|g| &g.id).collect();
        ids.sort();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
        assert!(n >= 10);
    }

    #[test]
    fn required_gates_dominate_optional() {
        let gates = default_gates();
        let required = gates.iter().filter(|g| g.required).count();
        assert!(required >= 6, "expect at least 6 required gates");
    }
}
