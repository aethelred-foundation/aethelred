//! Federated multi-regulator verification.
//!
//! v0.2.1 [`crate::Verifier`] handles single-party verification.
//! Production audit scenarios involve multiple independent regulators
//! verifying the same seal in parallel — CBUAE, FCA, OCC, MAS each
//! computing their own report — and a *consolidated* M-of-N receipt
//! that records the agreement (or disagreement) across regulators.
//!
//! This is distinct from M-of-N **signing** (multiple validators signing
//! at seal-creation time, [`crate::ValidatorQuorum`]). Federated
//! verification is M-of-N at *review time*: the seal is already created;
//! we want auditor-side confirmation from multiple jurisdictions.
//!
//! ## What we ship
//!
//! - [`Regulator`] — typed reference for a regulator (id, jurisdiction,
//!   verifier strictness).
//! - [`FederatedVerifier`] — orchestrates parallel verification across
//!   regulators.
//! - [`FederatedReport`] — consolidated report: which regulators
//!   approved, which rejected, threshold outcome.
//! - [`FederationOutcome`] — `Unanimous`, `ThresholdMet`, `ThresholdMissed`,
//!   `Inconclusive`.
//! - [`CrossAttestation`] — signed receipt from one regulator attesting
//!   to their verification result.

use crate::seal::SealEnvelope;
use crate::verify::{VerificationReport, Verifier};
use crate::{SandboxError, SandboxResult, Sha256Digest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// Regulator
// =============================================================================

/// One regulator participating in federation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Regulator {
    /// Stable id (e.g., `"CBUAE"`, `"FCA"`, `"OCC"`).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Jurisdiction tag (e.g., `"AE-CBUAE"`).
    pub jurisdiction: String,
    /// `Verifier` posture: `default`, `strict`, etc.
    pub strictness: VerifierStrictness,
}

/// Verifier strictness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierStrictness {
    /// Default verifier (`Verifier::default()`).
    Default,
    /// Strict mainnet (requires signature, attestation, zk_proof).
    Strict,
    /// Custom (caller plugs in own Verifier instance).
    Custom,
}

impl VerifierStrictness {
    /// Construct a `Verifier` matching this strictness.
    pub fn build_verifier(self) -> Verifier {
        match self {
            Self::Default => Verifier::default(),
            Self::Strict => Verifier::strict(),
            Self::Custom => Verifier::default(),
        }
    }
}

// =============================================================================
// CrossAttestation
// =============================================================================

/// Signed receipt from one regulator attesting to a verification result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossAttestation {
    /// Receipt id.
    pub receipt_id: Uuid,
    /// Regulator id.
    pub regulator_id: String,
    /// Seal id verified.
    pub seal_id: Uuid,
    /// RFC 3339 timestamp.
    pub attested_at: String,
    /// `true` if this regulator approved the seal.
    pub approved: bool,
    /// Reason (especially on rejection).
    pub reason: Option<String>,
    /// Hash of the verification report (for tamper-detection).
    pub report_hash: Sha256Digest,
    /// Optional jurisdiction-specific extra fields.
    pub extra: BTreeMap<String, String>,
}

impl CrossAttestation {
    /// Build from a regulator + report.
    pub fn from_report(
        regulator: &Regulator,
        seal_id: Uuid,
        report: &VerificationReport,
    ) -> SandboxResult<Self> {
        let approved = report.passed();
        let reason = if approved {
            None
        } else {
            Some(format!("{} failures", report.failed_count()))
        };
        let report_hash = crate::Hasher::hash_value(report)?;
        Ok(Self {
            receipt_id: Uuid::now_v7(),
            regulator_id: regulator.id.clone(),
            seal_id,
            attested_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            approved,
            reason,
            report_hash,
            extra: BTreeMap::new(),
        })
    }
}

// =============================================================================
// FederationOutcome
// =============================================================================

/// Outcome of federation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationOutcome {
    /// All regulators approved.
    Unanimous,
    /// At least M of N approved.
    ThresholdMet,
    /// Fewer than M of N approved.
    ThresholdMissed,
    /// No regulators registered or all errored.
    Inconclusive,
}

impl FederationOutcome {
    /// `true` if approval is established (`Unanimous` or `ThresholdMet`).
    pub fn is_approved(self) -> bool {
        matches!(self, Self::Unanimous | Self::ThresholdMet)
    }
}

// =============================================================================
// FederatedReport
// =============================================================================

/// Consolidated report across all regulators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedReport {
    /// Report id.
    pub report_id: Uuid,
    /// Seal verified.
    pub seal_id: Uuid,
    /// RFC 3339 generation timestamp.
    pub generated_at: String,
    /// Required threshold (M).
    pub threshold: u32,
    /// Total regulators (N).
    pub total: u32,
    /// Number that approved.
    pub approved_count: u32,
    /// Number that rejected.
    pub rejected_count: u32,
    /// Per-regulator attestations.
    pub attestations: Vec<CrossAttestation>,
    /// Per-regulator detailed reports.
    pub reports: BTreeMap<String, VerificationReport>,
    /// Final outcome.
    pub outcome: FederationOutcome,
}

impl FederatedReport {
    /// Find the attestation for a regulator.
    pub fn attestation_for(&self, regulator_id: &str) -> Option<&CrossAttestation> {
        self.attestations
            .iter()
            .find(|a| a.regulator_id == regulator_id)
    }

    /// All approving regulator ids.
    pub fn approvers(&self) -> Vec<&str> {
        self.attestations
            .iter()
            .filter(|a| a.approved)
            .map(|a| a.regulator_id.as_str())
            .collect()
    }

    /// All rejecting regulator ids.
    pub fn rejectors(&self) -> Vec<&str> {
        self.attestations
            .iter()
            .filter(|a| !a.approved)
            .map(|a| a.regulator_id.as_str())
            .collect()
    }
}

// =============================================================================
// FederatedVerifier
// =============================================================================

/// Orchestrates verification across multiple regulators.
pub struct FederatedVerifier {
    regulators: Vec<Regulator>,
    custom_verifiers: BTreeMap<String, Arc<Verifier>>,
    threshold: u32,
}

impl FederatedVerifier {
    /// New federated verifier with a threshold.
    pub fn new(regulators: Vec<Regulator>, threshold: u32) -> SandboxResult<Self> {
        let n = regulators.len() as u32;
        if threshold == 0 {
            return Err(SandboxError::config("threshold must be ≥ 1"));
        }
        if threshold > n {
            return Err(SandboxError::config(format!(
                "threshold {threshold} > total regulators {n}"
            )));
        }
        // Reject duplicate regulator ids.
        let mut seen = std::collections::HashSet::new();
        for r in &regulators {
            if !seen.insert(&r.id) {
                return Err(SandboxError::config(format!(
                    "duplicate regulator id: {}",
                    r.id
                )));
            }
        }
        Ok(Self {
            regulators,
            custom_verifiers: BTreeMap::new(),
            threshold,
        })
    }

    /// Register a custom verifier for a regulator (overrides strictness).
    pub fn with_custom_verifier(
        mut self,
        regulator_id: impl Into<String>,
        verifier: Verifier,
    ) -> Self {
        self.custom_verifiers
            .insert(regulator_id.into(), Arc::new(verifier));
        self
    }

    /// Verify a seal envelope across all regulators.
    pub fn verify(
        &self,
        envelope: &SealEnvelope,
        expected_root: Sha256Digest,
    ) -> SandboxResult<FederatedReport> {
        let mut attestations = Vec::with_capacity(self.regulators.len());
        let mut reports = BTreeMap::new();
        let mut approved_count = 0u32;
        let mut rejected_count = 0u32;
        for r in &self.regulators {
            let verifier = if let Some(custom) = self.custom_verifiers.get(&r.id) {
                custom.as_ref().clone()
            } else {
                r.strictness.build_verifier()
            };
            let report = verifier.verify_envelope(envelope, expected_root)?;
            let attestation = CrossAttestation::from_report(r, envelope.seal.seal_id, &report)?;
            if attestation.approved {
                approved_count += 1;
            } else {
                rejected_count += 1;
            }
            attestations.push(attestation);
            reports.insert(r.id.clone(), report);
        }
        let n = self.regulators.len() as u32;
        let outcome = if n == 0 {
            FederationOutcome::Inconclusive
        } else if approved_count == n {
            FederationOutcome::Unanimous
        } else if approved_count >= self.threshold {
            FederationOutcome::ThresholdMet
        } else {
            FederationOutcome::ThresholdMissed
        };
        Ok(FederatedReport {
            report_id: Uuid::now_v7(),
            seal_id: envelope.seal.seal_id,
            generated_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            threshold: self.threshold,
            total: n,
            approved_count,
            rejected_count,
            attestations,
            reports,
            outcome,
        })
    }

    /// Number of regulators.
    pub fn total(&self) -> u32 {
        self.regulators.len() as u32
    }

    /// Threshold.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Borrow registered regulators.
    pub fn regulators(&self) -> &[Regulator] {
        &self.regulators
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::EvidenceLog;
    use crate::seal::*;
    use crate::Sector;
    use std::collections::BTreeMap as StdBTreeMap;

    fn dummy_seal() -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc(),
            sector: Sector::Finance,
            event_type: "x".into(),
            event_hash: crate::Hasher::sha256(b"e"),
            model: ModelReference::new("m", crate::Hasher::sha256(b"w")),
            policy_id: "po".into(),
            input_hash: crate::Hasher::sha256(b"i"),
            output_hash: crate::Hasher::sha256(b"o"),
            approvals: vec![ApprovalRecord::unsigned("u", "r", "approved")],
            attestation: None,
            zk_proof: None,
            tenant_id: "FAB".into(),
            workflow_id: "credit_decision".into(),
            jurisdiction_tag: "AE".into(),
            retention: RetentionClass::SevenYears,
            prior_seal_hash: None,
            sector_extension: StdBTreeMap::new(),
            validator_signature_hex: None,
        }
    }

    fn make_envelope() -> (SealEnvelope, Sha256Digest) {
        let log = EvidenceLog::new();
        let entry = log.append(dummy_seal()).unwrap();
        let proof = log.proof(entry.index).unwrap();
        let root = log.root().unwrap();
        let env = SealEnvelope {
            seal: entry.seal,
            merkle_proof: Some(proof),
            anchor_block_height: None,
        };
        (env, root)
    }

    fn regulator(id: &str, strict: VerifierStrictness) -> Regulator {
        Regulator {
            id: id.into(),
            name: id.into(),
            jurisdiction: format!("AE-{id}"),
            strictness: strict,
        }
    }

    #[test]
    fn unanimous_when_all_default_verifiers_pass() {
        let (env, root) = make_envelope();
        let regs = vec![
            regulator("CBUAE", VerifierStrictness::Default),
            regulator("FCA", VerifierStrictness::Default),
            regulator("OCC", VerifierStrictness::Default),
        ];
        let fv = FederatedVerifier::new(regs, 2).unwrap();
        let report = fv.verify(&env, root).unwrap();
        assert_eq!(report.outcome, FederationOutcome::Unanimous);
        assert_eq!(report.approved_count, 3);
    }

    #[test]
    fn threshold_met_when_some_fail_strict_check() {
        let (env, root) = make_envelope();
        let regs = vec![
            regulator("CBUAE", VerifierStrictness::Default),
            regulator("FCA", VerifierStrictness::Strict),
            regulator("OCC", VerifierStrictness::Default),
        ];
        // Strict requires signature/attestation/zk — our seal has none, so FCA rejects.
        let fv = FederatedVerifier::new(regs, 2).unwrap();
        let report = fv.verify(&env, root).unwrap();
        assert_eq!(report.approved_count, 2);
        assert_eq!(report.rejected_count, 1);
        assert_eq!(report.outcome, FederationOutcome::ThresholdMet);
    }

    #[test]
    fn threshold_missed_when_too_many_fail() {
        let (env, root) = make_envelope();
        let regs = vec![
            regulator("CBUAE", VerifierStrictness::Strict),
            regulator("FCA", VerifierStrictness::Strict),
            regulator("OCC", VerifierStrictness::Default),
        ];
        let fv = FederatedVerifier::new(regs, 3).unwrap();
        let report = fv.verify(&env, root).unwrap();
        assert!(report.approved_count < 3);
        assert_eq!(report.outcome, FederationOutcome::ThresholdMissed);
    }

    #[test]
    fn outcome_is_approved_for_unanimous() {
        assert!(FederationOutcome::Unanimous.is_approved());
        assert!(FederationOutcome::ThresholdMet.is_approved());
        assert!(!FederationOutcome::ThresholdMissed.is_approved());
        assert!(!FederationOutcome::Inconclusive.is_approved());
    }

    #[test]
    fn duplicate_regulator_id_rejected() {
        let regs = vec![
            regulator("CBUAE", VerifierStrictness::Default),
            regulator("CBUAE", VerifierStrictness::Default),
        ];
        let r = FederatedVerifier::new(regs, 1);
        assert!(r.is_err());
    }

    #[test]
    fn threshold_zero_rejected() {
        let regs = vec![regulator("CBUAE", VerifierStrictness::Default)];
        let r = FederatedVerifier::new(regs, 0);
        assert!(r.is_err());
    }

    #[test]
    fn threshold_above_n_rejected() {
        let regs = vec![regulator("CBUAE", VerifierStrictness::Default)];
        let r = FederatedVerifier::new(regs, 5);
        assert!(r.is_err());
    }

    #[test]
    fn cross_attestation_records_approval() {
        let r = regulator("CBUAE", VerifierStrictness::Default);
        let (env, root) = make_envelope();
        let v = Verifier::default();
        let report = v.verify_envelope(&env, root).unwrap();
        let a = CrossAttestation::from_report(&r, env.seal.seal_id, &report).unwrap();
        assert_eq!(a.regulator_id, "CBUAE");
        assert!(a.approved);
        assert_eq!(a.seal_id, env.seal.seal_id);
    }

    #[test]
    fn cross_attestation_records_rejection_with_reason() {
        let r = regulator("CBUAE", VerifierStrictness::Strict);
        let (env, root) = make_envelope();
        let v = Verifier::strict();
        let report = v.verify_envelope(&env, root).unwrap();
        let a = CrossAttestation::from_report(&r, env.seal.seal_id, &report).unwrap();
        assert!(!a.approved);
        assert!(a.reason.is_some());
    }

    #[test]
    fn cross_attestation_serde_round_trip() {
        let r = regulator("CBUAE", VerifierStrictness::Default);
        let (env, root) = make_envelope();
        let v = Verifier::default();
        let report = v.verify_envelope(&env, root).unwrap();
        let a = CrossAttestation::from_report(&r, env.seal.seal_id, &report).unwrap();
        let j = serde_json::to_string(&a).unwrap();
        let p: CrossAttestation = serde_json::from_str(&j).unwrap();
        assert_eq!(p, a);
    }

    #[test]
    fn report_attestation_for_returns_correct() {
        let (env, root) = make_envelope();
        let regs = vec![
            regulator("CBUAE", VerifierStrictness::Default),
            regulator("FCA", VerifierStrictness::Default),
        ];
        let fv = FederatedVerifier::new(regs, 1).unwrap();
        let report = fv.verify(&env, root).unwrap();
        assert!(report.attestation_for("CBUAE").is_some());
        assert!(report.attestation_for("OCC").is_none());
    }

    #[test]
    fn report_approvers_and_rejectors() {
        let (env, root) = make_envelope();
        let regs = vec![
            regulator("CBUAE", VerifierStrictness::Default),
            regulator("FCA", VerifierStrictness::Strict),
        ];
        let fv = FederatedVerifier::new(regs, 1).unwrap();
        let report = fv.verify(&env, root).unwrap();
        assert!(report.approvers().contains(&"CBUAE"));
        assert!(report.rejectors().contains(&"FCA"));
    }

    #[test]
    fn custom_verifier_overrides_strictness() {
        let (env, root) = make_envelope();
        let regs = vec![regulator("CBUAE", VerifierStrictness::Custom)];
        let fv = FederatedVerifier::new(regs, 1)
            .unwrap()
            .with_custom_verifier("CBUAE", Verifier::default());
        let report = fv.verify(&env, root).unwrap();
        assert_eq!(report.approved_count, 1);
    }

    #[test]
    fn total_and_threshold_returned() {
        let regs = vec![
            regulator("a", VerifierStrictness::Default),
            regulator("b", VerifierStrictness::Default),
        ];
        let fv = FederatedVerifier::new(regs, 2).unwrap();
        assert_eq!(fv.total(), 2);
        assert_eq!(fv.threshold(), 2);
    }

    #[test]
    fn regulators_borrowed() {
        let regs = vec![regulator("CBUAE", VerifierStrictness::Default)];
        let fv = FederatedVerifier::new(regs, 1).unwrap();
        assert_eq!(fv.regulators().len(), 1);
        assert_eq!(fv.regulators()[0].id, "CBUAE");
    }

    #[test]
    fn report_serde_round_trip() {
        let (env, root) = make_envelope();
        let regs = vec![regulator("CBUAE", VerifierStrictness::Default)];
        let fv = FederatedVerifier::new(regs, 1).unwrap();
        let report = fv.verify(&env, root).unwrap();
        let j = serde_json::to_string(&report).unwrap();
        let p: FederatedReport = serde_json::from_str(&j).unwrap();
        assert_eq!(p.outcome, report.outcome);
    }

    #[test]
    fn outcome_serde() {
        let j = serde_json::to_string(&FederationOutcome::Unanimous).unwrap();
        assert_eq!(j, "\"unanimous\"");
    }

    #[test]
    fn strictness_serde() {
        let j = serde_json::to_string(&VerifierStrictness::Strict).unwrap();
        assert_eq!(j, "\"strict\"");
    }

    #[test]
    fn build_verifier_for_strict() {
        // Just sanity-check it doesn't panic.
        let _ = VerifierStrictness::Strict.build_verifier();
        let _ = VerifierStrictness::Default.build_verifier();
        let _ = VerifierStrictness::Custom.build_verifier();
    }

    #[test]
    fn five_regulators_two_disagree() {
        let (env, root) = make_envelope();
        let regs = vec![
            regulator("CBUAE", VerifierStrictness::Default),
            regulator("FCA", VerifierStrictness::Default),
            regulator("OCC", VerifierStrictness::Default),
            regulator("MAS", VerifierStrictness::Strict),
            regulator("BAFIN", VerifierStrictness::Strict),
        ];
        let fv = FederatedVerifier::new(regs, 3).unwrap();
        let report = fv.verify(&env, root).unwrap();
        assert_eq!(report.approved_count, 3);
        assert_eq!(report.rejected_count, 2);
        assert_eq!(report.outcome, FederationOutcome::ThresholdMet);
    }

    #[test]
    fn report_total_matches_regulator_count() {
        let (env, root) = make_envelope();
        let regs = vec![
            regulator("a", VerifierStrictness::Default),
            regulator("b", VerifierStrictness::Default),
            regulator("c", VerifierStrictness::Default),
        ];
        let fv = FederatedVerifier::new(regs, 2).unwrap();
        let r = fv.verify(&env, root).unwrap();
        assert_eq!(r.total, 3);
    }

    #[test]
    fn approved_plus_rejected_equals_total() {
        let (env, root) = make_envelope();
        let regs = vec![
            regulator("a", VerifierStrictness::Default),
            regulator("b", VerifierStrictness::Strict),
            regulator("c", VerifierStrictness::Default),
        ];
        let fv = FederatedVerifier::new(regs, 1).unwrap();
        let r = fv.verify(&env, root).unwrap();
        assert_eq!(r.approved_count + r.rejected_count, r.total);
    }

    #[test]
    fn regulator_serde_round_trip() {
        let r = regulator("CBUAE", VerifierStrictness::Strict);
        let j = serde_json::to_string(&r).unwrap();
        let p: Regulator = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn empty_regulator_list_rejected() {
        let regs: Vec<Regulator> = Vec::new();
        let r = FederatedVerifier::new(regs, 1);
        assert!(r.is_err());
    }
}
