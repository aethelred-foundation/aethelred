//! End-to-end integration tests for sandbox-core.
//!
//! These exercise the public API surface a sector crate / customer would use:
//! build a sandbox, append seals via the bulk API, export evidence,
//! independently verify with `Verifier`, render an audit trail.

use aethelred_sandbox_core::audit::{AuditFormat, AuditTrail};
use aethelred_sandbox_core::error_code::{ErrorCategory, ENTERPRISE_API_VERSION};
use aethelred_sandbox_core::evidence::EvidenceLog;
use aethelred_sandbox_core::hashing::Hasher;
use aethelred_sandbox_core::policy::{Decision, PolicyEngine, PolicyGate};
use aethelred_sandbox_core::sandbox::{Sandbox, SandboxBuilder};
use aethelred_sandbox_core::seal::{
    ApprovalRecord, DigitalSeal, ModelReference, RetentionClass, SealEnvelope, SealVersion,
};
use aethelred_sandbox_core::tee::TeePlatform;
use aethelred_sandbox_core::verify::Verifier;
use aethelred_sandbox_core::zkml::ProofSystem;
use aethelred_sandbox_core::Sector;
use std::collections::{BTreeMap, HashMap};
use time::OffsetDateTime;
use uuid::Uuid;

fn build_sandbox() -> Sandbox {
    SandboxBuilder::new(Sector::Finance)
        .tenant("FAB")
        .label("FAB Finance")
        .jurisdiction("AE-CBUAE")
        .tee(TeePlatform::IntelTdx)
        .zkml(ProofSystem::Ezkl)
        .crate_name("aethelred-sandbox-finance")
        .crate_version("0.2.0")
        .workflow("credit_decision")
        .with_gate(PolicyGate::required("finance.human_authority", "Human Authority", "rule"))
        .with_gate(PolicyGate::required("finance.evidence_integrity", "Evidence Integrity", "rule"))
        .with_gate(PolicyGate::optional("finance.no_pii_on_chain", "No PII", "rule"))
        .build()
        .unwrap()
}

fn dummy_seal(seed: u64) -> DigitalSeal {
    DigitalSeal {
        schema_version: SealVersion::V1,
        seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::Finance,
        event_type: "credit_decision".into(),
        event_hash: Hasher::sha256(format!("event-{seed}").as_bytes()),
        model: ModelReference::new("credit_v3", Hasher::sha256(b"weights")),
        policy_id: "po_credit_v1".into(),
        input_hash: Hasher::sha256(format!("in-{seed}").as_bytes()),
        output_hash: Hasher::sha256(format!("out-{seed}").as_bytes()),
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
fn end_to_end_seal_export_verify_audit() {
    let sb = build_sandbox();
    // Bulk-seal a batch of credit decisions.
    let envs = sb
        .append_and_envelope_batch((0..5).map(dummy_seal))
        .unwrap();
    assert_eq!(envs.len(), 5);

    // Export the bundle.
    let bundle = sb.export_evidence().unwrap();
    assert_eq!(bundle.entries.len(), 5);

    // Verify every envelope independently with a fresh Verifier.
    let v = Verifier::default();
    let root = sb.current_root().unwrap();
    let reports = v.verify_batch(&envs, root).unwrap();
    for r in &reports {
        assert!(r.passed(), "verification failed: {:?}", r.failures());
    }

    // Render the audit trail in all three formats.
    for fmt in [AuditFormat::PlainText, AuditFormat::Markdown, AuditFormat::Csv] {
        let s = sb.audit_trail(fmt).unwrap();
        assert!(!s.is_empty());
    }
}

#[test]
fn evidence_bundle_roundtrip_through_audit() {
    let sb = build_sandbox();
    for i in 0..7 {
        sb.append_seal(dummy_seal(i)).unwrap();
    }
    let bundle = sb.export_evidence().unwrap();
    let trail = AuditTrail::from_bundle(&bundle);
    assert_eq!(trail.total, 7);
    assert_eq!(trail.entries.len(), 7);
}

#[test]
fn verifier_strict_rejects_unsealed_seal() {
    let sb = build_sandbox();
    let env = sb.append_and_envelope(dummy_seal(0)).unwrap();
    let root = sb.current_root().unwrap();
    let strict = Verifier::strict();
    let report = strict.verify_envelope(&env, root).unwrap();
    assert!(!report.passed());
    let names: Vec<String> = report.failures().iter().map(|c| c.check.clone()).collect();
    assert!(names.contains(&"validator_signature".into()));
    assert!(names.contains(&"attestation_required".into()));
    assert!(names.contains(&"zk_proof_required".into()));
}

#[test]
fn verifier_detects_seal_swap() {
    let log = EvidenceLog::new();
    let entry = log.append(dummy_seal(0)).unwrap();
    let proof = log.proof(entry.index).unwrap();
    let root = log.root().unwrap();
    // Swap content but keep proof.
    let mut tampered = entry.seal.clone();
    tampered.event_hash = Hasher::sha256(b"different");
    let env = SealEnvelope {
        seal: tampered,
        merkle_proof: Some(proof),
        anchor_block_height: None,
    };
    let report = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(!report.passed());
    assert!(report
        .failures()
        .iter()
        .any(|c| c.check == "proof_leaf_matches_seal"));
}

#[test]
fn policy_engine_blocks_on_required_fault() {
    let engine = PolicyEngine::new(vec![
        PolicyGate::required("a", "A", "rule"),
        PolicyGate::optional("b", "B", "rule"),
    ]);
    let mut faults = HashMap::new();
    faults.insert("a".into(), true);
    let (decision, _) = engine.evaluate(&faults);
    assert_eq!(decision, Decision::FailClosed);
}

#[test]
fn enterprise_api_version_is_one() {
    assert_eq!(ENTERPRISE_API_VERSION, 1);
}

#[test]
fn error_code_categories_are_distinct() {
    let cats = [
        ErrorCategory::Policy,
        ErrorCategory::Input,
        ErrorCategory::DataBoundary,
        ErrorCategory::Evidence,
        ErrorCategory::Crypto,
        ErrorCategory::Connector,
        ErrorCategory::Attestation,
        ErrorCategory::Zkml,
        ErrorCategory::Configuration,
        ErrorCategory::Other,
    ];
    let mut shorts: Vec<&str> = cats.iter().map(|c| c.as_short()).collect();
    let n = shorts.len();
    shorts.sort_unstable();
    shorts.dedup();
    assert_eq!(shorts.len(), n);
}
