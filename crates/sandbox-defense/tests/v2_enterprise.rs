//! Enterprise v0.2.0 test suite for sandbox-defense.

use aethelred_sandbox_defense::prelude::*;

fn edge() -> DefenseSandbox {
    DefenseSandbox::quickstart("EDGE").unwrap()
}

// ======================================================================
// Quickstart / Builder
// ======================================================================

#[test]
fn quickstart_uses_air_gap_default() {
    let sb = edge();
    assert!(sb.is_air_gap());
}

#[test]
fn builder_can_disable_air_gap() {
    let sb = DefenseSandbox::builder()
        .institution("Tawazun")
        .jurisdiction(DefenseJurisdiction::TawazunUae)
        .air_gap(false)
        .build()
        .unwrap();
    assert!(!sb.is_air_gap());
}

#[test]
fn builder_supports_uae_af() {
    let sb = DefenseSandbox::builder()
        .institution("UAE-AF")
        .jurisdiction(DefenseJurisdiction::UaeAf)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), DefenseJurisdiction::UaeAf);
}

#[test]
fn builder_supports_nato_pru() {
    let sb = DefenseSandbox::builder()
        .institution("NATO-AC323")
        .jurisdiction(DefenseJurisdiction::NatoPru)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), DefenseJurisdiction::NatoPru);
}

#[test]
fn builder_supports_us_dod_aiep() {
    let sb = DefenseSandbox::builder()
        .institution("DOD")
        .jurisdiction(DefenseJurisdiction::UsDodAiEp)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), DefenseJurisdiction::UsDodAiEp);
}

#[test]
fn builder_supports_uk_mod() {
    let sb = DefenseSandbox::builder()
        .institution("UK-MoD")
        .jurisdiction(DefenseJurisdiction::UkMod)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), DefenseJurisdiction::UkMod);
}

#[test]
fn builder_supports_itar() {
    let sb = DefenseSandbox::builder()
        .institution("ITAR")
        .jurisdiction(DefenseJurisdiction::Itar)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), DefenseJurisdiction::Itar);
}

#[test]
fn builder_supports_eu_dual_use() {
    let sb = DefenseSandbox::builder()
        .institution("EU-DUAL-USE")
        .jurisdiction(DefenseJurisdiction::EuDualUse)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), DefenseJurisdiction::EuDualUse);
}

// ======================================================================
// Bulk seal
// ======================================================================

#[test]
fn bulk_seal_logistics() {
    let sb = edge();
    let r = sb
        .seal_autonomous_logistics_batch((0..5).map(|_| AutonomousLogistics::demo()))
        .unwrap();
    assert_eq!(r.len(), 5);
}

#[test]
fn bulk_seal_fusion() {
    let sb = edge();
    let r = sb
        .seal_sensor_fusion_batch((0..3).map(|_| SensorFusion::demo()))
        .unwrap();
    assert_eq!(r.len(), 3);
}

#[test]
fn bulk_seal_inspection() {
    let sb = edge();
    let r = sb
        .seal_inspection_batch((0..7).map(|_| InspectionQa::demo()))
        .unwrap();
    assert_eq!(r.len(), 7);
}

#[test]
fn bulk_seal_cyber() {
    let sb = edge();
    let r = sb
        .seal_cyber_defense_batch((0..4).map(|_| CyberDefenseEvent::demo()))
        .unwrap();
    assert_eq!(r.len(), 4);
}

#[test]
fn bulk_seal_empty() {
    let sb = edge();
    let v: Vec<AutonomousLogistics> = vec![];
    assert_eq!(sb.seal_autonomous_logistics_batch(v).unwrap().len(), 0);
}

#[test]
fn bulk_seal_large() {
    let sb = edge();
    let r = sb
        .seal_autonomous_logistics_batch((0..50).map(|_| AutonomousLogistics::demo()))
        .unwrap();
    assert_eq!(r.len(), 50);
}

#[test]
fn mixed_workflow_log() {
    let sb = edge();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    sb.seal_sensor_fusion(SensorFusion::demo()).unwrap();
    sb.seal_inspection(InspectionQa::demo()).unwrap();
    sb.seal_cyber_defense(CyberDefenseEvent::demo()).unwrap();
    assert_eq!(sb.seal_count(), 4);
}

// ======================================================================
// Envelope + Verifier
// ======================================================================

#[test]
fn envelope_at_returns_proof() {
    let sb = edge();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    assert!(env.merkle_proof.is_some());
    assert!(env.merkle_proof.unwrap().verify());
}

#[test]
fn envelope_oor_errors() {
    let sb = edge();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    assert!(sb.envelope_at(99).is_err());
}

#[test]
fn all_envelopes_share_root() {
    let sb = edge();
    for _ in 0..5 {
        sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    }
    let envs = sb.all_envelopes().unwrap();
    let root = sb.current_root().unwrap();
    for env in &envs {
        assert_eq!(env.merkle_proof.as_ref().unwrap().root, root);
    }
}

#[test]
fn verify_all_passes() {
    let sb = edge();
    for _ in 0..4 {
        sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    }
    let r = sb.verify_all().unwrap();
    assert!(r.iter().all(|x| x.passed()));
}

#[test]
fn verify_strict_fails_without_attestation() {
    let sb = edge();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let r = sb.verify_all_with(&Verifier::strict()).unwrap();
    assert!(!r[0].passed());
}

#[test]
fn current_root_changes() {
    let sb = edge();
    let r0 = sb.current_root().unwrap();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    assert_ne!(r0, sb.current_root().unwrap());
}

// ======================================================================
// Audit trail
// ======================================================================

#[test]
fn audit_plaintext() {
    let sb = edge();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::PlainText).unwrap();
    assert!(s.contains("EDGE"));
}

#[test]
fn audit_markdown() {
    let sb = edge();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::Markdown).unwrap();
    assert!(s.contains("|"));
}

#[test]
fn audit_csv() {
    let sb = edge();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::Csv).unwrap();
    assert!(s.starts_with("position,seal_id,timestamp,"));
}

#[test]
fn audit_struct_count() {
    let sb = edge();
    for _ in 0..3 {
        sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    }
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.total, 3);
}

// ======================================================================
// Adversarial — defense-specific
// ======================================================================

#[test]
fn outside_odd_soft_fails_to_review() {
    // ODD is an optional (soft-fail) gate; the seal still emits but the
    // policy decision is ReviewRequired.
    let sb = edge();
    let mut a = AutonomousLogistics::demo();
    a.within_odd = false;
    assert!(sb.seal_autonomous_logistics(a).is_ok());
}

#[test]
fn classified_marker_blocks_check() {
    let sb = edge();
    assert!(sb
        .check_classification_boundary("CLASSIFICATION: TS//SCI")
        .is_err());
}

#[test]
fn classified_secret_marker_blocks() {
    let sb = edge();
    assert!(sb.check_classification_boundary("SECRET//NOFORN").is_err());
}

#[test]
fn classified_confidential_marker_blocks() {
    let sb = edge();
    assert!(sb
        .check_classification_boundary("CONFIDENTIAL//FOR OFFICIAL USE ONLY")
        .is_err());
}

#[test]
fn benign_string_passes_classification() {
    let sb = edge();
    assert!(sb
        .check_classification_boundary("regular logistics payload")
        .is_ok());
}

// ======================================================================
// Multi-jurisdiction views
// ======================================================================

#[test]
fn tawazun_view_carries_citations() {
    let sb = edge();
    let s = sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, DefenseJurisdiction::TawazunUae);
    assert!(!view.citations.is_empty());
}

#[test]
fn uae_af_view_carries_citations() {
    let sb = edge();
    let s = sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, DefenseJurisdiction::UaeAf);
    assert!(!view.citations.is_empty());
}

#[test]
fn nato_pru_view_carries_citations() {
    let sb = edge();
    let s = sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, DefenseJurisdiction::NatoPru);
    assert!(!view.citations.is_empty());
}

#[test]
fn us_dod_aiep_view_carries_citations() {
    let sb = edge();
    let s = sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, DefenseJurisdiction::UsDodAiEp);
    assert!(!view.citations.is_empty());
}

#[test]
fn uk_mod_view_carries_citations() {
    let sb = edge();
    let s = sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, DefenseJurisdiction::UkMod);
    assert!(!view.citations.is_empty());
}

#[test]
fn itar_view_carries_citations() {
    let sb = edge();
    let s = sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, DefenseJurisdiction::Itar);
    assert!(!view.citations.is_empty());
}

#[test]
fn eu_dual_use_view_carries_citations() {
    let sb = edge();
    let s = sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, DefenseJurisdiction::EuDualUse);
    assert!(!view.citations.is_empty());
}

// ======================================================================
// Fixtures
// ======================================================================

#[test]
fn fixtures_happy_count() {
    assert_eq!(DefenseFixtures::happy_path().len(), 4);
}

#[test]
fn fixtures_unique() {
    let ids: Vec<&str> = DefenseFixtures::all().iter().map(|f| f.id()).collect();
    let mut s = ids.clone();
    s.sort_unstable();
    let n = s.len();
    s.dedup();
    assert_eq!(s.len(), n);
}

#[test]
fn fixtures_run_happy() {
    let sb = edge();
    for f in DefenseFixtures::happy_path() {
        f.run(&sb).unwrap_or_else(|e| panic!("{}: {e}", f.id()));
    }
}

#[test]
fn fixtures_run_regulatory_edge() {
    let sb = edge();
    for f in DefenseFixtures::regulatory_edge() {
        f.run(&sb).unwrap_or_else(|e| panic!("{}: {e}", f.id()));
    }
}

#[test]
fn fixtures_descriptions_nonempty() {
    for f in DefenseFixtures::all() {
        assert!(!f.description().is_empty());
    }
}

#[test]
fn fixtures_tags_nonempty() {
    for f in DefenseFixtures::all() {
        assert!(!f.tags().is_empty());
    }
}

#[test]
fn fixtures_filter_by_tawazun() {
    let cb = DefenseFixtures::by_tag("tawazun");
    assert!(!cb.is_empty());
}

#[test]
fn fixtures_filter_unknown_empty() {
    assert!(DefenseFixtures::by_tag("nonexistent").is_empty());
}

// ======================================================================
// Evidence
// ======================================================================

#[test]
fn merkle_proofs_verify_for_each_seal() {
    let sb = edge();
    for _ in 0..8 {
        sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    }
    let envs = sb.all_envelopes().unwrap();
    for env in envs {
        assert!(env.merkle_proof.unwrap().verify());
    }
}

#[test]
fn evidence_indices_monotonic() {
    let sb = edge();
    for _ in 0..5 {
        sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    }
    let bundle = sb.export_evidence().unwrap();
    for (i, e) in bundle.entries.iter().enumerate() {
        assert_eq!(e.index, i as u64);
    }
}

#[test]
fn evidence_root_matches_current() {
    let sb = edge();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let bundle = sb.export_evidence().unwrap();
    assert_eq!(bundle.merkle_root, sb.current_root().unwrap());
}

#[test]
fn empty_seal_count_zero() {
    let sb = edge();
    assert_eq!(sb.seal_count(), 0);
}

#[test]
fn empty_audit_trail_zero() {
    let sb = edge();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.total, 0);
}

// ======================================================================
// Approval / sectors / serde
// ======================================================================

#[test]
fn logistics_seal_has_approval() {
    let sb = edge();
    let s = sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn fusion_seal_has_approval() {
    let sb = edge();
    let s = sb.seal_sensor_fusion(SensorFusion::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn inspection_seal_has_approval() {
    let sb = edge();
    let s = sb.seal_inspection(InspectionQa::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn cyber_seal_has_approval() {
    let sb = edge();
    let s = sb.seal_cyber_defense(CyberDefenseEvent::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn logistics_jurisdiction_set() {
    let sb = edge();
    let s = sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    assert_eq!(s.seal.jurisdiction_tag, "AE-TAWAZUN");
}

#[test]
fn evidence_bundle_serde_roundtrip() {
    let sb = edge();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let b = sb.export_evidence().unwrap();
    let j = serde_json::to_string(&b).unwrap();
    let p: EvidenceBundle = serde_json::from_str(&j).unwrap();
    assert_eq!(p.entries.len(), b.entries.len());
}

#[test]
fn audit_trail_serde_roundtrip() {
    let sb = edge();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let t = sb.audit_trail_struct().unwrap();
    let j = serde_json::to_string(&t).unwrap();
    let p: AuditTrail = serde_json::from_str(&j).unwrap();
    assert_eq!(p.total, t.total);
}

#[test]
fn verifier_independent() {
    let sb = edge();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(r.passed());
}

#[test]
fn error_code_routing_for_classification() {
    let sb = edge();
    let err = sb
        .check_classification_boundary("CLASSIFICATION: TS//SCI")
        .unwrap_err();
    assert_eq!(err.error_code().category, ErrorCategory::Policy);
}

#[test]
fn airgap_disabled_sandbox_works() {
    let sb = DefenseSandbox::builder()
        .institution("EDGE-NOAG")
        .jurisdiction(DefenseJurisdiction::TawazunUae)
        .air_gap(false)
        .build()
        .unwrap();
    assert!(!sb.is_air_gap());
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    assert_eq!(sb.seal_count(), 1);
}

// ======================================================================
// Verifier mutations + further audit checks
// ======================================================================

#[test]
fn verifier_detects_event_hash_tamper() {
    use aethelred_sandbox_defense::core::Hasher;
    let sb = edge();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let mut env = sb.envelope_at(0).unwrap();
    env.seal.event_hash = Hasher::sha256(b"tampered");
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(!r.passed());
}

#[test]
fn verifier_detects_input_hash_tamper() {
    use aethelred_sandbox_defense::core::Hasher;
    let sb = edge();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let mut env = sb.envelope_at(0).unwrap();
    env.seal.input_hash = Hasher::sha256(b"tampered-input");
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(!r.passed());
}

#[test]
fn verifier_detects_output_hash_tamper() {
    use aethelred_sandbox_defense::core::Hasher;
    let sb = edge();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let mut env = sb.envelope_at(0).unwrap();
    env.seal.output_hash = Hasher::sha256(b"tampered-output");
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(!r.passed());
}

#[test]
fn verify_with_wrong_root_fails() {
    use aethelred_sandbox_defense::core::Hasher;
    let sb = edge();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    let r = Verifier::default()
        .verify_envelope(&env, Hasher::sha256(b"wrong-root"))
        .unwrap();
    assert!(!r.passed());
}

#[test]
fn audit_records_workflow_id() {
    let sb = edge();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.entries[0].workflow_id, "autonomous_logistics");
}

#[test]
fn audit_records_sensor_fusion_workflow_id() {
    let sb = edge();
    sb.seal_sensor_fusion(SensorFusion::demo()).unwrap();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.entries[0].workflow_id, "sensor_fusion");
}

#[test]
fn audit_records_inspection_workflow_id() {
    let sb = edge();
    sb.seal_inspection(InspectionQa::demo()).unwrap();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.entries[0].workflow_id, "inspection_qa");
}

#[test]
fn audit_records_cyber_workflow_id() {
    let sb = edge();
    sb.seal_cyber_defense(CyberDefenseEvent::demo()).unwrap();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.entries[0].workflow_id, "cyber_defense");
}

// ======================================================================
// More classification boundary checks
// ======================================================================

#[test]
fn classified_lowercase_normalized() {
    // The classification check uppercases internally; lowercase markers
    // should be detected too.
    let sb = edge();
    assert!(sb
        .check_classification_boundary("classification: ts//sci ops")
        .is_err());
}

#[test]
fn classified_mixed_case_detected() {
    let sb = edge();
    assert!(sb
        .check_classification_boundary("Some text Confidential//Foo more")
        .is_err());
}

#[test]
fn empty_string_passes_classification() {
    let sb = edge();
    assert!(sb.check_classification_boundary("").is_ok());
}

// ======================================================================
// Cross-platform / cross-class checks
// ======================================================================

#[test]
fn ugv_logistics_works() {
    use aethelred_sandbox_defense::prelude::PlatformClass;
    let sb = edge();
    let mut a = AutonomousLogistics::demo();
    a.platform_class = PlatformClass::Ugv;
    sb.seal_autonomous_logistics(a).unwrap();
}

#[test]
fn uav_logistics_works() {
    use aethelred_sandbox_defense::prelude::PlatformClass;
    let sb = edge();
    let mut a = AutonomousLogistics::demo();
    a.platform_class = PlatformClass::Uav;
    sb.seal_autonomous_logistics(a).unwrap();
}

#[test]
fn empty_log_envelopes_empty() {
    let sb = edge();
    assert!(sb.all_envelopes().unwrap().is_empty());
}

#[test]
fn verify_empty_log() {
    let sb = edge();
    assert!(sb.verify_all().unwrap().is_empty());
}

#[test]
fn evidence_export_count_matches_seal_count() {
    let sb = edge();
    for _ in 0..6 {
        sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    }
    let bundle = sb.export_evidence().unwrap();
    assert_eq!(bundle.entries.len(), sb.seal_count());
}

#[test]
fn defense_sector_in_seal() {
    let sb = edge();
    let s = sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    assert_eq!(s.seal.sector, Sector::Defense);
}

#[test]
fn fusion_sector_in_seal() {
    let sb = edge();
    let s = sb.seal_sensor_fusion(SensorFusion::demo()).unwrap();
    assert_eq!(s.seal.sector, Sector::Defense);
}

#[test]
fn inspection_sector_in_seal() {
    let sb = edge();
    let s = sb.seal_inspection(InspectionQa::demo()).unwrap();
    assert_eq!(s.seal.sector, Sector::Defense);
}

#[test]
fn cyber_sector_in_seal() {
    let sb = edge();
    let s = sb.seal_cyber_defense(CyberDefenseEvent::demo()).unwrap();
    assert_eq!(s.seal.sector, Sector::Defense);
}

#[test]
fn extra_gate_can_be_appended() {
    use aethelred_sandbox_defense::core::policy::PolicyGate;
    let sb = DefenseSandbox::builder()
        .institution("EDGE-X")
        .jurisdiction(DefenseJurisdiction::TawazunUae)
        .with_extra_gate(PolicyGate::optional("test.extra", "Extra", "rule"))
        .build()
        .unwrap();
    sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
    assert_eq!(sb.seal_count(), 1);
}
