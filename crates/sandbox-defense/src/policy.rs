//! Defense-sector policy gates.

use aethelred_sandbox_core::policy::PolicyGate;

/// Non-weaponised scope only.
pub const GATE_NON_WEAPONIZED_SCOPE: &str = "defense.non_weaponized_scope";
/// Classification / export boundary not violated.
pub const GATE_CLASSIFICATION_BOUNDARY: &str = "defense.classification_boundary";
/// Human command authority bound to the seal.
pub const GATE_HUMAN_COMMAND_AUTHORITY: &str = "defense.human_command_authority";
/// Approved AI / autonomy model.
pub const GATE_MODEL_APPROVAL: &str = "defense.model_approval";
/// Operational design domain (ODD) within bounds.
pub const GATE_ODD_BOUNDARY: &str = "defense.odd_boundary";
/// Evidence integrity (no tamper).
pub const GATE_EVIDENCE_INTEGRITY: &str = "defense.evidence_integrity";
/// Sovereignty: data + execution stays in sovereign environment.
pub const GATE_SOVEREIGNTY: &str = "defense.sovereignty";
/// Air-gap mode: no external network egress.
pub const GATE_AIR_GAP_RESPECTED: &str = "defense.air_gap_respected";
/// Jurisdiction supported.
pub const GATE_JURISDICTION_SUPPORTED: &str = "defense.jurisdiction_supported";

/// Default defense gate set.
pub fn default_gates() -> Vec<PolicyGate> {
    vec![
        PolicyGate::required(
            GATE_NON_WEAPONIZED_SCOPE,
            "Non-weaponised scope",
            "Sandbox is limited to readiness, logistics, cyber-defense, inspection, and mission support.",
        ),
        PolicyGate::required(
            GATE_CLASSIFICATION_BOUNDARY,
            "Classification + export boundary",
            "Restricted fields are blocked or redacted in sandbox exports.",
        ),
        PolicyGate::required(
            GATE_HUMAN_COMMAND_AUTHORITY,
            "Human command authority",
            "AI support cannot become autonomous command action without authorised human review.",
        ),
        PolicyGate::required(
            GATE_MODEL_APPROVAL,
            "Approved autonomy model",
            "Only approved autonomy / sensor-fusion model versions can issue sealable recommendations.",
        ),
        PolicyGate::required(
            GATE_EVIDENCE_INTEGRITY,
            "Evidence integrity",
            "Tampered sensor / decision / approval records fail closed.",
        ),
        PolicyGate::required(
            GATE_SOVEREIGNTY,
            "Sovereignty",
            "Data residency, validator quorum location, and signer set must respect sovereignty constraints.",
        ),
        PolicyGate::required(
            GATE_AIR_GAP_RESPECTED,
            "Air-gap respected (when enabled)",
            "If sandbox is configured for air-gap mode, no external egress is permitted.",
        ),
        PolicyGate::required(
            GATE_JURISDICTION_SUPPORTED,
            "Jurisdiction supported",
            "Workflow jurisdiction must be one of the configured regulator views.",
        ),
        PolicyGate::optional(
            GATE_ODD_BOUNDARY,
            "Operational design domain",
            "Out-of-domain operation soft-fails to escalation.",
        ),
    ]
}
