//! Enterprise v0.2.0 test suite for sandbox-healthcare.

use aethelred_sandbox_healthcare::prelude::*;

fn m42() -> HealthcareSandbox {
    HealthcareSandbox::quickstart("M42").unwrap()
}

// ======================================================================
// Quickstart / Builder
// ======================================================================

#[test]
fn quickstart_uses_doh_default() {
    let sb = m42();
    assert_eq!(sb.institution(), "M42");
    assert_eq!(sb.primary_jurisdiction(), HealthcareJurisdiction::DohAbuDhabi);
}

#[test]
fn builder_supports_dha() {
    let sb = HealthcareSandbox::builder()
        .institution("DHA")
        .jurisdiction(HealthcareJurisdiction::Dha)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), HealthcareJurisdiction::Dha);
}

#[test]
fn builder_supports_mohap() {
    let sb = HealthcareSandbox::builder()
        .institution("MOHAP")
        .jurisdiction(HealthcareJurisdiction::Mohap)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), HealthcareJurisdiction::Mohap);
}

#[test]
fn builder_supports_hipaa() {
    let sb = HealthcareSandbox::builder()
        .institution("CMS")
        .jurisdiction(HealthcareJurisdiction::HipaaUs)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), HealthcareJurisdiction::HipaaUs);
}

#[test]
fn builder_supports_eu_ai_act() {
    let sb = HealthcareSandbox::builder()
        .institution("Charite")
        .jurisdiction(HealthcareJurisdiction::EuAiActGdpr)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), HealthcareJurisdiction::EuAiActGdpr);
}

#[test]
fn builder_supports_nhra() {
    let sb = HealthcareSandbox::builder()
        .institution("Bahrain-NHRA")
        .jurisdiction(HealthcareJurisdiction::NhraBahrain)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), HealthcareJurisdiction::NhraBahrain);
}

// ======================================================================
// Bulk seal
// ======================================================================

#[test]
fn bulk_seal_genomics() {
    let sb = m42();
    let inputs: Vec<_> = (0..5).map(|_| GenomicsInference::demo()).collect();
    let r = sb.seal_genomics_batch(inputs).unwrap();
    assert_eq!(r.len(), 5);
}

#[test]
fn bulk_seal_clinical() {
    let sb = m42();
    let inputs: Vec<_> = (0..3).map(|_| ClinicalInference::demo()).collect();
    let r = sb.seal_clinical_batch(inputs).unwrap();
    assert_eq!(r.len(), 3);
}

#[test]
fn bulk_seal_ambient() {
    let sb = m42();
    let inputs: Vec<_> = (0..7).map(|_| AmbientNote::demo()).collect();
    let r = sb.seal_ambient_batch(inputs).unwrap();
    assert_eq!(r.len(), 7);
}

#[test]
fn bulk_seal_claims() {
    let sb = HealthcareSandbox::quickstart("PureHealth").unwrap();
    let inputs: Vec<_> = (0..4).map(|_| ClaimsAdjudication::demo()).collect();
    let r = sb.seal_claims_batch(inputs).unwrap();
    assert_eq!(r.len(), 4);
}

#[test]
fn bulk_seal_empty_returns_empty() {
    let sb = m42();
    let v: Vec<GenomicsInference> = vec![];
    assert_eq!(sb.seal_genomics_batch(v).unwrap().len(), 0);
}

#[test]
fn bulk_seal_large() {
    let sb = m42();
    let inputs: Vec<_> = (0..50).map(|_| GenomicsInference::demo()).collect();
    let r = sb.seal_genomics_batch(inputs).unwrap();
    assert_eq!(r.len(), 50);
}

#[test]
fn mixed_workflow_evidence_log() {
    let sb = HealthcareSandbox::quickstart("PureHealth").unwrap();
    sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    sb.seal_clinical_inference(ClinicalInference::demo()).unwrap();
    sb.seal_ambient_note(AmbientNote::demo()).unwrap();
    sb.seal_claims_adjudication(ClaimsAdjudication::demo()).unwrap();
    assert_eq!(sb.seal_count(), 4);
}

// ======================================================================
// Envelope + Verifier
// ======================================================================

#[test]
fn envelope_at_returns_proof() {
    let sb = m42();
    sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    assert!(env.merkle_proof.is_some());
    assert!(env.merkle_proof.unwrap().verify());
}

#[test]
fn envelope_at_oor_errors() {
    let sb = m42();
    sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    assert!(sb.envelope_at(99).is_err());
}

#[test]
fn all_envelopes_share_root() {
    let sb = m42();
    for _ in 0..6 {
        sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    }
    let envs = sb.all_envelopes().unwrap();
    let root = sb.current_root().unwrap();
    for env in &envs {
        assert_eq!(env.merkle_proof.as_ref().unwrap().root, root);
    }
}

#[test]
fn verify_all_passes() {
    let sb = m42();
    for _ in 0..4 {
        sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    }
    let r = sb.verify_all().unwrap();
    assert!(r.iter().all(|x| x.passed()));
}

#[test]
fn verify_strict_fails_without_attestation() {
    let sb = m42();
    sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    let r = sb.verify_all_with(&Verifier::strict()).unwrap();
    assert!(!r[0].passed());
}

#[test]
fn current_root_changes() {
    let sb = m42();
    let r0 = sb.current_root().unwrap();
    sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    assert_ne!(r0, sb.current_root().unwrap());
}

// ======================================================================
// Audit trail
// ======================================================================

#[test]
fn audit_trail_plaintext() {
    let sb = m42();
    sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::PlainText).unwrap();
    assert!(s.contains("M42"));
}

#[test]
fn audit_trail_markdown() {
    let sb = m42();
    sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::Markdown).unwrap();
    assert!(s.contains("|"));
}

#[test]
fn audit_trail_csv() {
    let sb = m42();
    sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::Csv).unwrap();
    assert!(s.starts_with("position,seal_id,timestamp,"));
}

#[test]
fn audit_trail_struct_count() {
    let sb = m42();
    for _ in 0..3 {
        sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    }
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.total, 3);
}

// ======================================================================
// Adversarial — parameterized
// ======================================================================

#[test]
fn adversarial_email_in_genomics_pseudo_id() {
    let sb = m42();
    let mut g = GenomicsInference::demo();
    g.sample_pseudo_id = "patient@example.com".into();
    assert!(sb.seal_genomics_inference(g).is_err());
}

#[test]
fn adversarial_emirates_in_genomics_pseudo_id() {
    let sb = m42();
    let mut g = GenomicsInference::demo();
    g.sample_pseudo_id = "emirates_id:784-1990-1234567-1".into();
    assert!(sb.seal_genomics_inference(g).is_err());
}

#[test]
fn adversarial_mrn_in_clinical_pseudo_id() {
    let sb = m42();
    let mut c = ClinicalInference::demo();
    c.encounter_pseudo_id = "mrn:1234567".into();
    assert!(sb.seal_clinical_inference(c).is_err());
}

#[test]
fn adversarial_dob_in_clinical_pseudo_id() {
    let sb = m42();
    let mut c = ClinicalInference::demo();
    c.encounter_pseudo_id = "dob:1990-01-01".into();
    assert!(sb.seal_clinical_inference(c).is_err());
}

#[test]
fn adversarial_unsigned_ambient_blocks() {
    let sb = m42();
    let mut a = AmbientNote::demo();
    a.clinician_signed = false;
    assert!(sb.seal_ambient_note(a).is_err());
}

#[test]
fn adversarial_email_ambient_blocks() {
    let sb = m42();
    let mut a = AmbientNote::demo();
    a.encounter_pseudo_id = "patient@example.com".into();
    assert!(sb.seal_ambient_note(a).is_err());
}

#[test]
fn adversarial_denied_claim_no_reason() {
    let sb = HealthcareSandbox::quickstart("PureHealth").unwrap();
    let mut c = ClaimsAdjudication::demo();
    c.decision = ClaimDecision::Denied;
    c.reason_class = None;
    assert!(sb.seal_claims_adjudication(c).is_err());
}

#[test]
fn adversarial_adjusted_claim_no_reason() {
    let sb = HealthcareSandbox::quickstart("PureHealth").unwrap();
    let mut c = ClaimsAdjudication::demo();
    c.decision = ClaimDecision::ApprovedAdjusted;
    c.reason_class = None;
    assert!(sb.seal_claims_adjudication(c).is_err());
}

#[test]
fn adversarial_ssn_in_claim_pseudo_id() {
    let sb = HealthcareSandbox::quickstart("PureHealth").unwrap();
    let mut c = ClaimsAdjudication::demo();
    c.member_pseudo_id = "ssn:123-45-6789".into();
    assert!(sb.seal_claims_adjudication(c).is_err());
}

#[test]
fn edge_research_only_dataset_passes_with_review() {
    // ResearchOnly is a soft-fail gate — the seal still emits, but the
    // policy decision is ReviewRequired.
    let sb = m42();
    let mut g = GenomicsInference::demo();
    g.dataset_class = GenomicsDatasetClass::ResearchOnly;
    assert!(sb.seal_genomics_inference(g).is_ok());
}

// ======================================================================
// Multi-jurisdiction views
// ======================================================================

#[test]
fn doh_view_carries_citations() {
    let sb = m42();
    let s = sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, HealthcareJurisdiction::DohAbuDhabi);
    assert!(!view.citations.is_empty());
}

#[test]
fn dha_view_carries_citations() {
    let sb = m42();
    let s = sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, HealthcareJurisdiction::Dha);
    assert!(!view.citations.is_empty());
}

#[test]
fn mohap_view_carries_citations() {
    let sb = m42();
    let s = sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, HealthcareJurisdiction::Mohap);
    assert!(!view.citations.is_empty());
}

#[test]
fn ehs_view_carries_citations() {
    let sb = m42();
    let s = sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, HealthcareJurisdiction::Ehs);
    assert!(!view.citations.is_empty());
}

#[test]
fn hipaa_view_carries_citations() {
    let sb = m42();
    let s = sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, HealthcareJurisdiction::HipaaUs);
    assert!(!view.citations.is_empty());
}

#[test]
fn eu_ai_act_view_carries_citations() {
    let sb = m42();
    let s = sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, HealthcareJurisdiction::EuAiActGdpr);
    assert!(!view.citations.is_empty());
}

#[test]
fn nhra_view_carries_citations() {
    let sb = m42();
    let s = sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, HealthcareJurisdiction::NhraBahrain);
    assert!(!view.citations.is_empty());
}

// ======================================================================
// Fixtures
// ======================================================================

#[test]
fn fixtures_happy_count() {
    assert_eq!(HealthcareFixtures::happy_path().len(), 4);
}

#[test]
fn fixtures_adversarial_at_least_six() {
    assert!(HealthcareFixtures::adversarial().len() >= 6);
}

#[test]
fn fixtures_all_unique_ids() {
    let ids: Vec<&str> = HealthcareFixtures::all().iter().map(|f| f.id()).collect();
    let mut s = ids.clone();
    s.sort_unstable();
    let n = s.len();
    s.dedup();
    assert_eq!(s.len(), n);
}

#[test]
fn fixtures_run_happy_pass() {
    let sb = HealthcareSandbox::quickstart("PureHealth").unwrap();
    for f in HealthcareFixtures::happy_path() {
        f.run(&sb).unwrap_or_else(|e| panic!("{}: {e}", f.id()));
    }
}

#[test]
fn fixtures_run_adversarial_block() {
    let sb = m42();
    for f in HealthcareFixtures::adversarial() {
        f.run(&sb).unwrap_or_else(|e| panic!("{}: {e}", f.id()));
    }
}

#[test]
fn fixtures_descriptions_nonempty() {
    for f in HealthcareFixtures::all() {
        assert!(!f.description().is_empty());
    }
}

#[test]
fn fixtures_tags_nonempty() {
    for f in HealthcareFixtures::all() {
        assert!(!f.tags().is_empty());
    }
}

#[test]
fn fixtures_filter_by_phi() {
    let phi = HealthcareFixtures::by_tag("phi");
    assert!(phi.len() >= 3);
}

// ======================================================================
// Evidence
// ======================================================================

#[test]
fn merkle_proofs_verify_for_each_seal() {
    let sb = m42();
    for _ in 0..8 {
        sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    }
    let envs = sb.all_envelopes().unwrap();
    for env in envs {
        assert!(env.merkle_proof.unwrap().verify());
    }
}

#[test]
fn evidence_export_indices_monotonic() {
    let sb = m42();
    for _ in 0..5 {
        sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    }
    let bundle = sb.export_evidence().unwrap();
    for (i, e) in bundle.entries.iter().enumerate() {
        assert_eq!(e.index, i as u64);
    }
}

#[test]
fn evidence_root_matches_current() {
    let sb = m42();
    sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    let bundle = sb.export_evidence().unwrap();
    assert_eq!(bundle.merkle_root, sb.current_root().unwrap());
}

// ======================================================================
// Error code
// ======================================================================

#[test]
fn policy_denial_yields_policy_code() {
    let sb = m42();
    let mut g = GenomicsInference::demo();
    g.sample_pseudo_id = "patient@example.com".into();
    let err = sb.seal_genomics_inference(g).unwrap_err();
    assert_eq!(err.error_code().category, ErrorCategory::Policy);
}

// ======================================================================
// Approvals
// ======================================================================

#[test]
fn genomics_seal_has_approval() {
    let sb = m42();
    let s = sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn clinical_seal_has_approval() {
    let sb = m42();
    let s = sb.seal_clinical_inference(ClinicalInference::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn ambient_seal_has_approval_when_signed() {
    let sb = m42();
    let s = sb.seal_ambient_note(AmbientNote::demo()).unwrap();
    assert!(s.clinician_signed);
}

#[test]
fn claims_seal_has_approval() {
    let sb = HealthcareSandbox::quickstart("PureHealth").unwrap();
    let s = sb.seal_claims_adjudication(ClaimsAdjudication::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

// ======================================================================
// Serde
// ======================================================================

#[test]
fn genomics_serde_roundtrip() {
    let g = GenomicsInference::demo();
    let j = serde_json::to_string(&g).unwrap();
    let p: GenomicsInference = serde_json::from_str(&j).unwrap();
    assert_eq!(p.variant_id, g.variant_id);
}

#[test]
fn evidence_bundle_serde_roundtrip() {
    let sb = m42();
    sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    let b = sb.export_evidence().unwrap();
    let j = serde_json::to_string(&b).unwrap();
    let p: EvidenceBundle = serde_json::from_str(&j).unwrap();
    assert_eq!(p.entries.len(), b.entries.len());
}

#[test]
fn audit_trail_serde_roundtrip() {
    let sb = m42();
    sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    let t = sb.audit_trail_struct().unwrap();
    let j = serde_json::to_string(&t).unwrap();
    let p: AuditTrail = serde_json::from_str(&j).unwrap();
    assert_eq!(p.total, t.total);
}

// ======================================================================
// Additional PHI-marker coverage
// ======================================================================

#[test]
fn email_in_genomics_blocks() {
    let sb = m42();
    let mut g = GenomicsInference::demo();
    g.sample_pseudo_id = "patient.zero@hospital.ae".into();
    assert!(sb.seal_genomics_inference(g).is_err());
}

#[test]
fn email_in_clinical_blocks() {
    let sb = m42();
    let mut c = ClinicalInference::demo();
    c.encounter_pseudo_id = "patient@example.com".into();
    assert!(sb.seal_clinical_inference(c).is_err());
}

#[test]
fn ssn_marker_genomics_blocks() {
    let sb = m42();
    let mut g = GenomicsInference::demo();
    g.sample_pseudo_id = "ssn:111-22-3333".into();
    assert!(sb.seal_genomics_inference(g).is_err());
}

#[test]
fn dob_marker_genomics_blocks() {
    let sb = m42();
    let mut g = GenomicsInference::demo();
    g.sample_pseudo_id = "dob:1980-01-01".into();
    assert!(sb.seal_genomics_inference(g).is_err());
}

#[test]
fn dob_marker_ambient_blocks() {
    let sb = m42();
    let mut a = AmbientNote::demo();
    a.encounter_pseudo_id = "dob:1990-05-15".into();
    assert!(sb.seal_ambient_note(a).is_err());
}

#[test]
fn empty_seal_count_is_zero() {
    let sb = m42();
    assert_eq!(sb.seal_count(), 0);
}

#[test]
fn empty_log_audit_trail_is_empty() {
    let sb = m42();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.total, 0);
}

#[test]
fn verifier_independent_of_sandbox() {
    let sb = m42();
    sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    let root = sb.current_root().unwrap();
    // Reviewer side — no sandbox needed.
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(r.passed());
}

#[test]
fn verifier_detects_event_hash_tamper() {
    use aethelred_sandbox_healthcare::core::Hasher;
    let sb = m42();
    sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    let mut env = sb.envelope_at(0).unwrap();
    env.seal.event_hash = Hasher::sha256(b"tampered");
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(!r.passed());
}

#[test]
fn doh_jurisdiction_supported_in_seal() {
    let sb = m42();
    let s = sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    assert_eq!(s.seal.jurisdiction_tag, "AE-AD-DOH");
}

#[test]
fn dha_jurisdiction_supported_in_seal() {
    let sb = HealthcareSandbox::builder()
        .institution("DHA-Health")
        .jurisdiction(HealthcareJurisdiction::Dha)
        .build()
        .unwrap();
    let s = sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    assert_eq!(s.seal.jurisdiction_tag, "AE-DXB-DHA");
}

#[test]
fn evidence_log_ordering_preserved_across_workflows() {
    let sb = HealthcareSandbox::quickstart("PureHealth").unwrap();
    sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
    sb.seal_clinical_inference(ClinicalInference::demo()).unwrap();
    sb.seal_claims_adjudication(ClaimsAdjudication::demo()).unwrap();
    let bundle = sb.export_evidence().unwrap();
    let workflows: Vec<&str> = bundle
        .entries
        .iter()
        .map(|e| e.seal.workflow_id.as_str())
        .collect();
    assert_eq!(workflows[0], "genomics_inference");
    assert_eq!(workflows[1], "clinical_ai");
    assert_eq!(workflows[2], "claims_adjudication");
}
