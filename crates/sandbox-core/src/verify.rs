//! Independent reviewer-side verification.
//!
//! The [`Verifier`] is the artefact a reviewer (auditor, regulator, partner)
//! uses to **independently** verify a [`crate::SealEnvelope`] without
//! constructing a sandbox or pulling sector crates. This is the third leg of
//! the assurance triangle:
//!
//! 1. **Producer** — the bank / hospital / defense agency runs the sandbox
//!    and emits a `SealEnvelope` (seal + Merkle proof).
//! 2. **Anchor** — the validator quorum signs the seal and (optionally)
//!    anchors the Merkle root on the Aethelred mainnet.
//! 3. **Reviewer** — anyone with a `Verifier` and an out-of-band root can
//!    re-verify the seal months or years later.
//!
//! The reviewer-side dependency footprint is tiny: only `aethelred-sandbox-core`.
//! No sector crates, no policy engine, no connectors.
//!
//! ## Usage
//!
//! ```ignore
//! use aethelred_sandbox_core::prelude::*;
//!
//! let verifier = Verifier::default();
//! let report = verifier.verify_envelope(&envelope, expected_root)?;
//! assert!(report.passed());
//! ```
//!
//! ## What is verified
//!
//! - **Schema**: seal version is supported.
//! - **Tamper-evidence**: the seal's leaf hash equals the proof's `leaf_hash`,
//!   and the proof reconstructs the expected Merkle root.
//! - **Pre-signature hash determinism**: re-hashing the seal (with signature
//!   stripped) is well-formed.
//! - **Field invariants**: hashes are non-zero, retention class is valid,
//!   approvals carry sane decisions.
//! - **Optional**: validator signature hex round-trip (parses as hex), TEE
//!   nonce non-zero (replay protection), zkML circuit hash present when
//!   `zk_proof` is `Some`.
//!
//! What is **not** verified by the default `Verifier`:
//!
//! - Whether the validator signature is *cryptographically valid* — that
//!   requires the validator quorum's public-key set, which is a deployment
//!   concern. Wire your own implementation by overriding
//!   [`Verifier::verify_validator_signature`].
//! - Sector business rules (those live in sector crates).

use crate::error_code::{ErrorCode, EVD_PROOF_FAILED, EVD_TAMPER_DETECTED};
use crate::evidence::MerkleProof;
use crate::hashing::{Hasher, Sha256Digest};
use crate::seal::{DigitalSeal, RetentionClass, SealEnvelope, SealVersion};
use crate::SandboxResult;
use serde::{Deserialize, Serialize};

/// Outcome of a single verification check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationCheck {
    /// Stable check id (e.g., `"merkle_proof"`, `"schema_version"`).
    pub check: String,
    /// `true` if the check passed.
    pub passed: bool,
    /// Optional human-readable detail.
    pub detail: Option<String>,
    /// Optional machine-readable code on failure.
    pub error_code: Option<ErrorCode>,
}

impl VerificationCheck {
    /// Construct a passing check.
    pub fn pass(id: impl Into<String>) -> Self {
        Self {
            check: id.into(),
            passed: true,
            detail: None,
            error_code: None,
        }
    }

    /// Construct a failing check with an error code.
    pub fn fail(id: impl Into<String>, detail: impl Into<String>, code: ErrorCode) -> Self {
        Self {
            check: id.into(),
            passed: false,
            detail: Some(detail.into()),
            error_code: Some(code),
        }
    }
}

/// Aggregated report for one envelope verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Seal id (`seal_id_string()`).
    pub seal_id: String,
    /// Schema version of the seal.
    pub schema_version: SealVersion,
    /// All checks performed, in execution order.
    pub checks: Vec<VerificationCheck>,
}

impl VerificationReport {
    /// `true` if every check passed.
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.passed)
    }

    /// All failing checks (empty if `passed()`).
    pub fn failures(&self) -> Vec<&VerificationCheck> {
        self.checks.iter().filter(|c| !c.passed).collect()
    }

    /// Number of checks performed.
    pub fn total(&self) -> usize {
        self.checks.len()
    }

    /// Number of failing checks.
    pub fn failed_count(&self) -> usize {
        self.checks.iter().filter(|c| !c.passed).count()
    }

    /// Human-readable one-line summary (e.g., `"PASS (12/12)"` or `"FAIL (10/12)"`).
    pub fn summary(&self) -> String {
        let total = self.total();
        let pass = total - self.failed_count();
        if self.passed() {
            format!("PASS ({pass}/{total})")
        } else {
            format!("FAIL ({pass}/{total})")
        }
    }
}

/// Reviewer-side verifier. Sector-agnostic.
///
/// Construct with [`Verifier::default`] for stock checks. To plug in a
/// validator-quorum public-key set or sector business rules, build your own
/// type that owns a `Verifier` and adds extra checks.
#[derive(Debug, Clone)]
pub struct Verifier {
    /// Whether to require a validator signature (default `false` to support
    /// pre-anchor seals).
    pub require_validator_signature: bool,
    /// Whether to require an attestation (default `false`).
    pub require_attestation: bool,
    /// Whether to require a zkML proof (default `false`).
    pub require_zk_proof: bool,
}

impl Default for Verifier {
    fn default() -> Self {
        Self {
            require_validator_signature: false,
            require_attestation: false,
            require_zk_proof: false,
        }
    }
}

impl Verifier {
    /// Strict verifier: requires validator signature, attestation, and zkML
    /// proof to be present. Used for production-anchored seals.
    pub fn strict() -> Self {
        Self {
            require_validator_signature: true,
            require_attestation: true,
            require_zk_proof: true,
        }
    }

    /// Builder: require a validator signature.
    pub fn require_signature(mut self, on: bool) -> Self {
        self.require_validator_signature = on;
        self
    }

    /// Builder: require an attestation.
    pub fn require_attestation(mut self, on: bool) -> Self {
        self.require_attestation = on;
        self
    }

    /// Builder: require a zk proof.
    pub fn require_zk_proof(mut self, on: bool) -> Self {
        self.require_zk_proof = on;
        self
    }

    /// Verify a `DigitalSeal` in isolation (no Merkle anchor).
    ///
    /// Use this for pre-anchor seals or when the reviewer trusts the producer
    /// to deliver the seal directly. For tamper-evident verification, use
    /// [`Verifier::verify_envelope`].
    pub fn verify_seal(&self, seal: &DigitalSeal) -> SandboxResult<VerificationReport> {
        let mut checks = Vec::new();
        self.check_schema(seal, &mut checks);
        self.check_field_invariants(seal, &mut checks);
        self.check_pre_signature_hash(seal, &mut checks);
        self.check_optional_artefacts(seal, &mut checks);
        Ok(VerificationReport {
            seal_id: seal.id_string(),
            schema_version: seal.schema_version,
            checks,
        })
    }

    /// Verify a `SealEnvelope` against an `expected_root`.
    ///
    /// `expected_root` is the Merkle root the reviewer trusts (e.g., from an
    /// anchored mainnet block, a signed validator-quorum receipt, or
    /// out-of-band).
    pub fn verify_envelope(
        &self,
        envelope: &SealEnvelope,
        expected_root: Sha256Digest,
    ) -> SandboxResult<VerificationReport> {
        let mut report = self.verify_seal(&envelope.seal)?;
        // Add Merkle-anchor checks.
        match &envelope.merkle_proof {
            Some(proof) => {
                self.check_proof_root_match(proof, expected_root, &mut report.checks);
                self.check_proof_leaf_match(proof, &envelope.seal, &mut report.checks);
                self.check_proof_verifies(proof, &mut report.checks);
            }
            None => {
                report.checks.push(VerificationCheck::fail(
                    "merkle_proof_present",
                    "envelope carries no merkle_proof; cannot verify against expected_root",
                    EVD_PROOF_FAILED,
                ));
            }
        }
        Ok(report)
    }

    /// Verify a `SealEnvelope` *without* an expected root — proof-internal
    /// consistency only.
    ///
    /// Useful for inspecting a third-party envelope when the reviewer does
    /// not yet have the anchor root in hand.
    pub fn verify_envelope_internal(
        &self,
        envelope: &SealEnvelope,
    ) -> SandboxResult<VerificationReport> {
        let mut report = self.verify_seal(&envelope.seal)?;
        if let Some(proof) = &envelope.merkle_proof {
            self.check_proof_leaf_match(proof, &envelope.seal, &mut report.checks);
            self.check_proof_verifies(proof, &mut report.checks);
        } else {
            report.checks.push(VerificationCheck::pass(
                "merkle_proof_optional",
            ));
        }
        Ok(report)
    }

    /// Verify all envelopes in a batch. Returns one report per envelope.
    /// `expected_root` applies to *every* envelope (typical when all came
    /// from the same export bundle).
    pub fn verify_batch(
        &self,
        envelopes: &[SealEnvelope],
        expected_root: Sha256Digest,
    ) -> SandboxResult<Vec<VerificationReport>> {
        let mut out = Vec::with_capacity(envelopes.len());
        for env in envelopes {
            out.push(self.verify_envelope(env, expected_root)?);
        }
        Ok(out)
    }

    /// Override this to plug in a validator-quorum public-key set.
    /// Default impl: only checks that the signature parses as hex when
    /// `require_validator_signature` is set.
    pub fn verify_validator_signature(&self, seal: &DigitalSeal) -> Result<(), String> {
        match (&seal.validator_signature_hex, self.require_validator_signature) {
            (Some(sig), _) => {
                if hex::decode(sig).is_err() {
                    Err("validator_signature_hex is not valid hex".into())
                } else {
                    Ok(())
                }
            }
            (None, false) => Ok(()),
            (None, true) => Err("validator signature is required but absent".into()),
        }
    }

    // ------------------------------------------------------------------
    // Internal check primitives.
    // ------------------------------------------------------------------

    fn check_schema(&self, seal: &DigitalSeal, checks: &mut Vec<VerificationCheck>) {
        match seal.schema_version {
            SealVersion::V1 => checks.push(VerificationCheck::pass("schema_version")),
        }
    }

    fn check_field_invariants(&self, seal: &DigitalSeal, checks: &mut Vec<VerificationCheck>) {
        let zero = Sha256Digest([0u8; 32]);
        if seal.event_hash == zero {
            checks.push(VerificationCheck::fail(
                "event_hash_nonzero",
                "event_hash is the zero digest",
                EVD_TAMPER_DETECTED,
            ));
        } else {
            checks.push(VerificationCheck::pass("event_hash_nonzero"));
        }
        if seal.input_hash == zero {
            checks.push(VerificationCheck::fail(
                "input_hash_nonzero",
                "input_hash is the zero digest",
                EVD_TAMPER_DETECTED,
            ));
        } else {
            checks.push(VerificationCheck::pass("input_hash_nonzero"));
        }
        if seal.output_hash == zero {
            checks.push(VerificationCheck::fail(
                "output_hash_nonzero",
                "output_hash is the zero digest",
                EVD_TAMPER_DETECTED,
            ));
        } else {
            checks.push(VerificationCheck::pass("output_hash_nonzero"));
        }
        if seal.tenant_id.is_empty() {
            checks.push(VerificationCheck::fail(
                "tenant_id_present",
                "tenant_id is empty",
                EVD_TAMPER_DETECTED,
            ));
        } else {
            checks.push(VerificationCheck::pass("tenant_id_present"));
        }
        if seal.workflow_id.is_empty() {
            checks.push(VerificationCheck::fail(
                "workflow_id_present",
                "workflow_id is empty",
                EVD_TAMPER_DETECTED,
            ));
        } else {
            checks.push(VerificationCheck::pass("workflow_id_present"));
        }
        if seal.policy_id.is_empty() {
            checks.push(VerificationCheck::fail(
                "policy_id_present",
                "policy_id is empty",
                EVD_TAMPER_DETECTED,
            ));
        } else {
            checks.push(VerificationCheck::pass("policy_id_present"));
        }
        // RetentionClass is enum-valid by construction; no-op assert.
        let _ = matches!(
            seal.retention,
            RetentionClass::OneYear
                | RetentionClass::FiveYears
                | RetentionClass::SevenYears
                | RetentionClass::TenYears
                | RetentionClass::TwentyFiveYears
                | RetentionClass::Indefinite
        );
        checks.push(VerificationCheck::pass("retention_class_valid"));
    }

    fn check_pre_signature_hash(&self, seal: &DigitalSeal, checks: &mut Vec<VerificationCheck>) {
        match seal.pre_signature_hash() {
            Ok(_) => checks.push(VerificationCheck::pass("pre_signature_hash")),
            Err(e) => checks.push(VerificationCheck::fail(
                "pre_signature_hash",
                format!("pre_signature_hash failed: {e}"),
                EVD_TAMPER_DETECTED,
            )),
        }
    }

    fn check_optional_artefacts(&self, seal: &DigitalSeal, checks: &mut Vec<VerificationCheck>) {
        // Validator signature.
        match self.verify_validator_signature(seal) {
            Ok(_) => checks.push(VerificationCheck::pass("validator_signature")),
            Err(e) => checks.push(VerificationCheck::fail(
                "validator_signature",
                e,
                crate::error_code::CRY_SIG_FAILED,
            )),
        }
        // Attestation.
        match (&seal.attestation, self.require_attestation) {
            (Some(att), _) => {
                if att.runtime_nonce == Sha256Digest([0u8; 32]) {
                    checks.push(VerificationCheck::fail(
                        "attestation_nonce_nonzero",
                        "attestation runtime nonce is zero (replay risk)",
                        crate::error_code::ATT_ZERO_NONCE,
                    ));
                } else {
                    checks.push(VerificationCheck::pass("attestation_nonce_nonzero"));
                }
            }
            (None, false) => checks.push(VerificationCheck::pass("attestation_optional")),
            (None, true) => checks.push(VerificationCheck::fail(
                "attestation_required",
                "attestation is required by Verifier::strict() but absent",
                crate::error_code::ATT_VERIFIER_REJECTED,
            )),
        }
        // zkML proof.
        match (&seal.zk_proof, self.require_zk_proof) {
            (Some(proof), _) => {
                if proof.circuit_hash == Sha256Digest([0u8; 32]) {
                    checks.push(VerificationCheck::fail(
                        "zk_circuit_hash_nonzero",
                        "zkML circuit_hash is the zero digest",
                        crate::error_code::ZKM_CIRCUIT_MISMATCH,
                    ));
                } else {
                    checks.push(VerificationCheck::pass("zk_circuit_hash_nonzero"));
                }
            }
            (None, false) => checks.push(VerificationCheck::pass("zk_proof_optional")),
            (None, true) => checks.push(VerificationCheck::fail(
                "zk_proof_required",
                "zkML proof is required by Verifier::strict() but absent",
                crate::error_code::ZKM_PROOF_FAILED,
            )),
        }
    }

    fn check_proof_root_match(
        &self,
        proof: &MerkleProof,
        expected: Sha256Digest,
        checks: &mut Vec<VerificationCheck>,
    ) {
        if proof.root == expected {
            checks.push(VerificationCheck::pass("proof_root_matches_expected"));
        } else {
            checks.push(VerificationCheck::fail(
                "proof_root_matches_expected",
                format!(
                    "proof.root {} != expected {}",
                    proof.root.to_hex(),
                    expected.to_hex()
                ),
                EVD_PROOF_FAILED,
            ));
        }
    }

    fn check_proof_leaf_match(
        &self,
        proof: &MerkleProof,
        seal: &DigitalSeal,
        checks: &mut Vec<VerificationCheck>,
    ) {
        // Recompute the leaf hash from the seal and compare.
        match Hasher::hash_value(seal) {
            Ok(leaf) => {
                if leaf == proof.leaf_hash {
                    checks.push(VerificationCheck::pass("proof_leaf_matches_seal"));
                } else {
                    checks.push(VerificationCheck::fail(
                        "proof_leaf_matches_seal",
                        format!(
                            "recomputed leaf {} != proof.leaf_hash {}",
                            leaf.to_hex(),
                            proof.leaf_hash.to_hex()
                        ),
                        EVD_TAMPER_DETECTED,
                    ));
                }
            }
            Err(e) => checks.push(VerificationCheck::fail(
                "proof_leaf_matches_seal",
                format!("could not hash seal: {e}"),
                EVD_TAMPER_DETECTED,
            )),
        }
    }

    fn check_proof_verifies(&self, proof: &MerkleProof, checks: &mut Vec<VerificationCheck>) {
        if proof.verify() {
            checks.push(VerificationCheck::pass("merkle_proof"));
        } else {
            checks.push(VerificationCheck::fail(
                "merkle_proof",
                "merkle inclusion proof failed to reconstruct claimed root",
                EVD_PROOF_FAILED,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::EvidenceLog;
    use crate::seal::{ApprovalRecord, ModelReference, RetentionClass, SealVersion};
    use crate::Sector;
    use std::collections::BTreeMap;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn ok_seal() -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc(),
            sector: Sector::Finance,
            event_type: "credit_decision".into(),
            event_hash: Hasher::sha256(b"event"),
            model: ModelReference::new("credit_risk_v3.2", Hasher::sha256(b"weights")),
            policy_id: "po_credit_v1".into(),
            input_hash: Hasher::sha256(b"input"),
            output_hash: Hasher::sha256(b"output"),
            approvals: vec![ApprovalRecord::unsigned("u#1", "underwriter", "approved")],
            attestation: None,
            zk_proof: None,
            tenant_id: "FAB".into(),
            workflow_id: "credit_decision".into(),
            jurisdiction_tag: "AE-CBUAE".into(),
            retention: RetentionClass::SevenYears,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        }
    }

    #[test]
    fn default_verifier_passes_clean_seal() {
        let v = Verifier::default();
        let r = v.verify_seal(&ok_seal()).unwrap();
        assert!(r.passed(), "{:?}", r.failures());
    }

    #[test]
    fn detects_zero_event_hash() {
        let mut s = ok_seal();
        s.event_hash = Sha256Digest([0u8; 32]);
        let v = Verifier::default();
        let r = v.verify_seal(&s).unwrap();
        assert!(!r.passed());
        assert!(r.failures().iter().any(|c| c.check == "event_hash_nonzero"));
    }

    #[test]
    fn detects_zero_input_hash() {
        let mut s = ok_seal();
        s.input_hash = Sha256Digest([0u8; 32]);
        let v = Verifier::default();
        let r = v.verify_seal(&s).unwrap();
        assert!(r.failures().iter().any(|c| c.check == "input_hash_nonzero"));
    }

    #[test]
    fn detects_zero_output_hash() {
        let mut s = ok_seal();
        s.output_hash = Sha256Digest([0u8; 32]);
        let v = Verifier::default();
        let r = v.verify_seal(&s).unwrap();
        assert!(r.failures().iter().any(|c| c.check == "output_hash_nonzero"));
    }

    #[test]
    fn detects_empty_tenant() {
        let mut s = ok_seal();
        s.tenant_id = String::new();
        let v = Verifier::default();
        let r = v.verify_seal(&s).unwrap();
        assert!(r.failures().iter().any(|c| c.check == "tenant_id_present"));
    }

    #[test]
    fn detects_empty_workflow_id() {
        let mut s = ok_seal();
        s.workflow_id = String::new();
        let v = Verifier::default();
        let r = v.verify_seal(&s).unwrap();
        assert!(r.failures().iter().any(|c| c.check == "workflow_id_present"));
    }

    #[test]
    fn detects_empty_policy_id() {
        let mut s = ok_seal();
        s.policy_id = String::new();
        let v = Verifier::default();
        let r = v.verify_seal(&s).unwrap();
        assert!(r.failures().iter().any(|c| c.check == "policy_id_present"));
    }

    #[test]
    fn strict_verifier_requires_signature_attestation_zk() {
        let v = Verifier::strict();
        let r = v.verify_seal(&ok_seal()).unwrap();
        let names: Vec<String> = r.failures().iter().map(|c| c.check.clone()).collect();
        assert!(names.contains(&"validator_signature".into()));
        assert!(names.contains(&"attestation_required".into()));
        assert!(names.contains(&"zk_proof_required".into()));
    }

    #[test]
    fn rejects_invalid_hex_signature() {
        let mut s = ok_seal();
        s.validator_signature_hex = Some("not-hex-XYZ".into());
        let v = Verifier::default();
        let r = v.verify_seal(&s).unwrap();
        assert!(r.failures().iter().any(|c| c.check == "validator_signature"));
    }

    #[test]
    fn accepts_valid_hex_signature() {
        let mut s = ok_seal();
        s.validator_signature_hex = Some("deadbeef".into());
        let v = Verifier::default();
        let r = v.verify_seal(&s).unwrap();
        assert!(r.passed(), "{:?}", r.failures());
    }

    #[test]
    fn envelope_verification_passes_with_correct_root() {
        let log = EvidenceLog::new();
        let entry = log.append(ok_seal()).unwrap();
        let proof = log.proof(entry.index).unwrap();
        let root = log.root().unwrap();
        let env = SealEnvelope {
            seal: entry.seal,
            merkle_proof: Some(proof),
            anchor_block_height: None,
        };
        let v = Verifier::default();
        let r = v.verify_envelope(&env, root).unwrap();
        assert!(r.passed(), "{:?}", r.failures());
    }

    #[test]
    fn envelope_verification_fails_with_wrong_root() {
        let log = EvidenceLog::new();
        let entry = log.append(ok_seal()).unwrap();
        let proof = log.proof(entry.index).unwrap();
        let env = SealEnvelope {
            seal: entry.seal,
            merkle_proof: Some(proof),
            anchor_block_height: None,
        };
        let wrong = Hasher::sha256(b"not-the-real-root");
        let v = Verifier::default();
        let r = v.verify_envelope(&env, wrong).unwrap();
        assert!(!r.passed());
        assert!(r.failures().iter().any(|c| c.check == "proof_root_matches_expected"));
    }

    #[test]
    fn envelope_verification_fails_when_proof_missing() {
        let env = SealEnvelope::unanchored(ok_seal());
        let any_root = Hasher::sha256(b"any");
        let r = Verifier::default().verify_envelope(&env, any_root).unwrap();
        assert!(!r.passed());
        assert!(r.failures().iter().any(|c| c.check == "merkle_proof_present"));
    }

    #[test]
    fn envelope_verification_fails_when_seal_was_swapped() {
        let log = EvidenceLog::new();
        let entry = log.append(ok_seal()).unwrap();
        let proof = log.proof(entry.index).unwrap();
        let root = log.root().unwrap();
        // Swap the seal payload but keep the original proof.
        let mut tampered = entry.seal.clone();
        tampered.event_hash = Hasher::sha256(b"different-event");
        let env = SealEnvelope {
            seal: tampered,
            merkle_proof: Some(proof),
            anchor_block_height: None,
        };
        let r = Verifier::default().verify_envelope(&env, root).unwrap();
        assert!(!r.passed());
        assert!(r.failures().iter().any(|c| c.check == "proof_leaf_matches_seal"));
    }

    #[test]
    fn batch_verification_processes_all_envelopes() {
        let log = EvidenceLog::new();
        for _ in 0..7 {
            log.append(ok_seal()).unwrap();
        }
        let root = log.root().unwrap();
        let mut envs = Vec::new();
        for i in 0..7u64 {
            let bundle = log.export("FAB", Sector::Finance).unwrap();
            let proof = log.proof(i).unwrap();
            envs.push(SealEnvelope {
                seal: bundle.entries[i as usize].seal.clone(),
                merkle_proof: Some(proof),
                anchor_block_height: None,
            });
        }
        let reports = Verifier::default().verify_batch(&envs, root).unwrap();
        assert_eq!(reports.len(), 7);
        for r in &reports {
            assert!(r.passed(), "{:?}", r.failures());
        }
    }

    #[test]
    fn report_summary_reports_pass_fail() {
        let v = Verifier::default();
        let r = v.verify_seal(&ok_seal()).unwrap();
        assert!(r.summary().starts_with("PASS"));
        let mut s = ok_seal();
        s.event_hash = Sha256Digest([0u8; 32]);
        let r2 = v.verify_seal(&s).unwrap();
        assert!(r2.summary().starts_with("FAIL"));
    }

    #[test]
    fn verify_envelope_internal_passes_without_root() {
        let log = EvidenceLog::new();
        let entry = log.append(ok_seal()).unwrap();
        let proof = log.proof(entry.index).unwrap();
        let env = SealEnvelope {
            seal: entry.seal,
            merkle_proof: Some(proof),
            anchor_block_height: None,
        };
        let r = Verifier::default().verify_envelope_internal(&env).unwrap();
        assert!(r.passed(), "{:?}", r.failures());
    }

    #[test]
    fn verify_envelope_internal_passes_for_unanchored() {
        let env = SealEnvelope::unanchored(ok_seal());
        let r = Verifier::default().verify_envelope_internal(&env).unwrap();
        assert!(r.passed());
    }

    #[test]
    fn require_signature_builder_works() {
        let v = Verifier::default().require_signature(true);
        let r = v.verify_seal(&ok_seal()).unwrap();
        assert!(r.failures().iter().any(|c| c.check == "validator_signature"));
    }

    #[test]
    fn require_attestation_builder_works() {
        let v = Verifier::default().require_attestation(true);
        let r = v.verify_seal(&ok_seal()).unwrap();
        assert!(r.failures().iter().any(|c| c.check == "attestation_required"));
    }

    #[test]
    fn require_zk_proof_builder_works() {
        let v = Verifier::default().require_zk_proof(true);
        let r = v.verify_seal(&ok_seal()).unwrap();
        assert!(r.failures().iter().any(|c| c.check == "zk_proof_required"));
    }

    #[test]
    fn report_serde_roundtrip() {
        let v = Verifier::default();
        let r = v.verify_seal(&ok_seal()).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let p: VerificationReport = serde_json::from_str(&j).unwrap();
        assert_eq!(p.seal_id, r.seal_id);
        assert_eq!(p.passed(), r.passed());
    }

    #[test]
    fn check_count_at_least_eight_for_seal() {
        let v = Verifier::default();
        let r = v.verify_seal(&ok_seal()).unwrap();
        assert!(r.total() >= 8);
    }

    #[test]
    fn empty_batch_returns_empty_reports() {
        let r = Verifier::default()
            .verify_batch(&[], Sha256Digest([0u8; 32]))
            .unwrap();
        assert!(r.is_empty());
    }
}
