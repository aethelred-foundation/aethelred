//! Enterprise v0.2.0 test suite for sandbox-autonomous-mobility.

use aethelred_sandbox_autonomous_mobility::*;
use aethelred_sandbox_core::audit::{AuditFormat, AuditTrail};
use aethelred_sandbox_core::error_code::ErrorCategory;
use aethelred_sandbox_core::verify::Verifier;
use aethelred_sandbox_core::{EvidenceBundle, Sector};

fn rta() -> AutonomousMobilitySandbox {
    AutonomousMobilitySandbox::quickstart("RTA").unwrap()
}

// ======================================================================
// Quickstart / Builder
// ======================================================================

#[test]
fn quickstart_creates_sandbox() {
    let sb = rta();
    assert_eq!(sb.tenant(), "RTA");
}

#[test]
fn builder_iso_21448_sotif() {
    let sb = AutonomousMobilitySandbox::builder()
        .tenant("Mobileye")
        .jurisdiction(AmJurisdiction::Iso21448Sotif)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), AmJurisdiction::Iso21448Sotif);
}

#[test]
fn builder_iso_26262() {
    let sb = AutonomousMobilitySandbox::builder()
        .tenant("Bosch")
        .jurisdiction(AmJurisdiction::Iso26262)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), AmJurisdiction::Iso26262);
}

#[test]
fn builder_do_178c() {
    let sb = AutonomousMobilitySandbox::builder()
        .tenant("EDGE-Aero")
        .jurisdiction(AmJurisdiction::Do178c)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), AmJurisdiction::Do178c);
}

#[test]
fn builder_do_326a() {
    let sb = AutonomousMobilitySandbox::builder()
        .tenant("Boeing")
        .jurisdiction(AmJurisdiction::Do326a)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), AmJurisdiction::Do326a);
}

#[test]
fn builder_do_356a() {
    let sb = AutonomousMobilitySandbox::builder()
        .tenant("Airbus")
        .jurisdiction(AmJurisdiction::Do356a)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), AmJurisdiction::Do356a);
}

#[test]
fn builder_eu_unece_wp29() {
    let sb = AutonomousMobilitySandbox::builder()
        .tenant("EU-Manuf")
        .jurisdiction(AmJurisdiction::EuUneceWp29)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), AmJurisdiction::EuUneceWp29);
}

#[test]
fn builder_uae_ncema_rta() {
    let sb = AutonomousMobilitySandbox::builder()
        .tenant("RTA")
        .jurisdiction(AmJurisdiction::UaeNcemaRta)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), AmJurisdiction::UaeNcemaRta);
}

// ======================================================================
// Bulk seal
// ======================================================================

#[test]
fn bulk_seal_odd_validations() {
    let sb = rta();
    let r = sb
        .seal_odd_validations((0..5).map(|_| OddValidation::demo()))
        .unwrap();
    assert_eq!(r.len(), 5);
}

#[test]
fn bulk_seal_mission_steps() {
    let sb = rta();
    let r = sb
        .seal_mission_steps((0..3).map(|_| MissionStep::demo()))
        .unwrap();
    assert_eq!(r.len(), 3);
}

#[test]
fn bulk_seal_perception_events() {
    let sb = rta();
    let r = sb
        .seal_perception_events((0..7).map(|_| PerceptionEvent::demo()))
        .unwrap();
    assert_eq!(r.len(), 7);
}

#[test]
fn bulk_seal_safety_case_events() {
    let sb = rta();
    let r = sb
        .seal_safety_case_events((0..4).map(|_| SafetyCaseEvent::demo()))
        .unwrap();
    assert_eq!(r.len(), 4);
}

#[test]
fn bulk_seal_empty() {
    let sb = rta();
    let v: Vec<OddValidation> = vec![];
    assert_eq!(sb.seal_odd_validations(v).unwrap().len(), 0);
}

#[test]
fn bulk_seal_large() {
    let sb = rta();
    let r = sb
        .seal_odd_validations((0..50).map(|_| OddValidation::demo()))
        .unwrap();
    assert_eq!(r.len(), 50);
}

#[test]
fn mixed_workflow_log() {
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    sb.seal_mission_step(MissionStep::demo()).unwrap();
    sb.seal_perception_event(PerceptionEvent::demo()).unwrap();
    sb.seal_safety_case_event(SafetyCaseEvent::demo()).unwrap();
    assert_eq!(sb.seal_count(), 4);
}

// ======================================================================
// Envelope + Verifier
// ======================================================================

#[test]
fn envelope_at_returns_proof() {
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    assert!(env.merkle_proof.is_some());
    assert!(env.merkle_proof.unwrap().verify());
}

#[test]
fn envelope_oor_errors() {
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    assert!(sb.envelope_at(99).is_err());
}

#[test]
fn all_envelopes_share_root() {
    let sb = rta();
    for _ in 0..6 {
        sb.seal_odd_validation(OddValidation::demo()).unwrap();
    }
    let envs = sb.all_envelopes().unwrap();
    let root = sb.current_root().unwrap();
    for env in &envs {
        assert_eq!(env.merkle_proof.as_ref().unwrap().root, root);
    }
}

#[test]
fn verify_all_passes() {
    let sb = rta();
    for _ in 0..4 {
        sb.seal_odd_validation(OddValidation::demo()).unwrap();
    }
    let r = sb.verify_all().unwrap();
    assert!(r.iter().all(|x| x.passed()));
}

#[test]
fn verify_strict_fails_without_attestation() {
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let r = sb.verify_all_with(&Verifier::strict()).unwrap();
    assert!(!r[0].passed());
}

#[test]
fn current_root_changes() {
    let sb = rta();
    let r0 = sb.current_root().unwrap();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    assert_ne!(r0, sb.current_root().unwrap());
}

// ======================================================================
// Audit trail
// ======================================================================

#[test]
fn audit_plaintext() {
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::PlainText).unwrap();
    assert!(s.contains("RTA"));
}

#[test]
fn audit_markdown() {
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::Markdown).unwrap();
    assert!(s.contains("|"));
}

#[test]
fn audit_csv() {
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::Csv).unwrap();
    assert!(s.starts_with("position,seal_id,timestamp,"));
}

#[test]
fn audit_struct_count() {
    let sb = rta();
    for _ in 0..3 {
        sb.seal_odd_validation(OddValidation::demo()).unwrap();
    }
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.total, 3);
}

#[test]
fn audit_records_workflow_id() {
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.entries[0].workflow_id, "odd_validation");
}

// ======================================================================
// Multi-jurisdiction views
// ======================================================================

#[test]
fn iso_21448_view() {
    let sb = rta();
    let s = sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, AmJurisdiction::Iso21448Sotif);
    assert!(!view.citations.is_empty());
}

#[test]
fn iso_26262_view() {
    let sb = rta();
    let s = sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, AmJurisdiction::Iso26262);
    assert!(!view.citations.is_empty());
}

#[test]
fn do_178c_view() {
    let sb = rta();
    let s = sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, AmJurisdiction::Do178c);
    assert!(!view.citations.is_empty());
}

#[test]
fn do_326a_view() {
    let sb = rta();
    let s = sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, AmJurisdiction::Do326a);
    assert!(!view.citations.is_empty());
}

#[test]
fn do_356a_view() {
    let sb = rta();
    let s = sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, AmJurisdiction::Do356a);
    assert!(!view.citations.is_empty());
}

#[test]
fn eu_unece_wp29_view() {
    let sb = rta();
    let s = sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, AmJurisdiction::EuUneceWp29);
    assert!(!view.citations.is_empty());
}

#[test]
fn uae_ncema_rta_view() {
    let sb = rta();
    let s = sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, AmJurisdiction::UaeNcemaRta);
    assert!(!view.citations.is_empty());
}

// ======================================================================
// Vehicle class coverage
// ======================================================================

#[test]
fn ground_passenger_odd_validates() {
    let sb = rta();
    let mut o = OddValidation::demo();
    o.vehicle_class = VehicleClass::GroundPassenger;
    sb.seal_odd_validation(o).unwrap();
}

#[test]
fn ground_cargo_odd_validates() {
    let sb = rta();
    let mut o = OddValidation::demo();
    o.vehicle_class = VehicleClass::GroundCargo;
    sb.seal_odd_validation(o).unwrap();
}

#[test]
fn uav_odd_validates() {
    let sb = rta();
    let mut o = OddValidation::demo();
    o.vehicle_class = VehicleClass::Uav;
    sb.seal_odd_validation(o).unwrap();
}

// ======================================================================
// Weather coverage
// ======================================================================

#[test]
fn clear_weather_validates() {
    let sb = rta();
    let mut o = OddValidation::demo();
    o.current_weather = WeatherCondition::Clear;
    sb.seal_odd_validation(o).unwrap();
}

#[test]
fn rain_weather_validates() {
    let sb = rta();
    let mut o = OddValidation::demo();
    o.current_weather = WeatherCondition::Rain;
    sb.seal_odd_validation(o).unwrap();
}

#[test]
fn sand_storm_weather_validates() {
    let sb = rta();
    let mut o = OddValidation::demo();
    o.current_weather = WeatherCondition::SandStorm;
    sb.seal_odd_validation(o).unwrap();
}

// ======================================================================
// Safety event coverage
// ======================================================================

#[test]
fn safety_hazard_event_seals() {
    let sb = rta();
    let mut s = SafetyCaseEvent::demo();
    s.category = SafetyCategory::Hazard;
    sb.seal_safety_case_event(s).unwrap();
}

#[test]
fn safety_near_miss_event_seals() {
    let sb = rta();
    let mut s = SafetyCaseEvent::demo();
    s.category = SafetyCategory::NearMiss;
    sb.seal_safety_case_event(s).unwrap();
}

#[test]
fn safety_incident_event_seals() {
    let sb = rta();
    let mut s = SafetyCaseEvent::demo();
    s.category = SafetyCategory::Incident;
    sb.seal_safety_case_event(s).unwrap();
}

#[test]
fn safety_resolved_outcome_seals() {
    let sb = rta();
    let mut s = SafetyCaseEvent::demo();
    s.outcome = SafetyOutcome::Resolved;
    sb.seal_safety_case_event(s).unwrap();
}

#[test]
fn safety_escalated_outcome_seals() {
    let sb = rta();
    let mut s = SafetyCaseEvent::demo();
    s.outcome = SafetyOutcome::Escalated;
    sb.seal_safety_case_event(s).unwrap();
}

// ======================================================================
// Workflow ids + sectors
// ======================================================================

#[test]
fn odd_validation_workflow_id() {
    let sb = rta();
    let s = sb.seal_odd_validation(OddValidation::demo()).unwrap();
    assert_eq!(s.seal.workflow_id, "odd_validation");
}

#[test]
fn mission_step_workflow_id() {
    let sb = rta();
    let s = sb.seal_mission_step(MissionStep::demo()).unwrap();
    assert_eq!(s.seal.workflow_id, "mission_step");
}

#[test]
fn perception_event_workflow_id() {
    let sb = rta();
    let s = sb.seal_perception_event(PerceptionEvent::demo()).unwrap();
    assert_eq!(s.seal.workflow_id, "perception_event");
}

#[test]
fn safety_case_event_workflow_id() {
    let sb = rta();
    let s = sb.seal_safety_case_event(SafetyCaseEvent::demo()).unwrap();
    assert_eq!(s.seal.workflow_id, "safety_case_event");
}

#[test]
fn autonomous_mobility_sector_in_seal() {
    let sb = rta();
    let s = sb.seal_odd_validation(OddValidation::demo()).unwrap();
    assert_eq!(s.seal.sector, Sector::AutonomousMobility);
}

// ======================================================================
// Approvals
// ======================================================================

#[test]
fn odd_seal_has_approval() {
    let sb = rta();
    let s = sb.seal_odd_validation(OddValidation::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn mission_seal_has_approval() {
    let sb = rta();
    let s = sb.seal_mission_step(MissionStep::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn perception_seal_has_approval() {
    let sb = rta();
    let s = sb.seal_perception_event(PerceptionEvent::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn safety_seal_has_approval() {
    let sb = rta();
    let s = sb.seal_safety_case_event(SafetyCaseEvent::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

// ======================================================================
// Evidence
// ======================================================================

#[test]
fn merkle_proofs_verify_for_each_seal() {
    let sb = rta();
    for _ in 0..8 {
        sb.seal_odd_validation(OddValidation::demo()).unwrap();
    }
    let envs = sb.all_envelopes().unwrap();
    for env in envs {
        assert!(env.merkle_proof.unwrap().verify());
    }
}

#[test]
fn evidence_indices_monotonic() {
    let sb = rta();
    for _ in 0..5 {
        sb.seal_odd_validation(OddValidation::demo()).unwrap();
    }
    let bundle = sb.export_evidence().unwrap();
    for (i, e) in bundle.entries.iter().enumerate() {
        assert_eq!(e.index, i as u64);
    }
}

#[test]
fn evidence_root_matches_current() {
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let bundle = sb.export_evidence().unwrap();
    assert_eq!(bundle.merkle_root, sb.current_root().unwrap());
}

#[test]
fn empty_seal_count() {
    let sb = rta();
    assert_eq!(sb.seal_count(), 0);
}

#[test]
fn empty_audit_trail() {
    let sb = rta();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.total, 0);
}

#[test]
fn empty_envelopes() {
    let sb = rta();
    assert!(sb.all_envelopes().unwrap().is_empty());
}

#[test]
fn empty_verify_all() {
    let sb = rta();
    assert!(sb.verify_all().unwrap().is_empty());
}

// ======================================================================
// Verifier mutations + serde
// ======================================================================

#[test]
fn verifier_detects_event_hash_tamper() {
    use aethelred_sandbox_core::Hasher;
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let mut env = sb.envelope_at(0).unwrap();
    env.seal.event_hash = Hasher::sha256(b"tamper");
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(!r.passed());
}

#[test]
fn verify_with_wrong_root_fails() {
    use aethelred_sandbox_core::Hasher;
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    let r = Verifier::default()
        .verify_envelope(&env, Hasher::sha256(b"wrong-root"))
        .unwrap();
    assert!(!r.passed());
}

#[test]
fn evidence_bundle_serde_roundtrip() {
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let b = sb.export_evidence().unwrap();
    let j = serde_json::to_string(&b).unwrap();
    let p: EvidenceBundle = serde_json::from_str(&j).unwrap();
    assert_eq!(p.entries.len(), b.entries.len());
}

#[test]
fn audit_trail_serde_roundtrip() {
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let t = sb.audit_trail_struct().unwrap();
    let j = serde_json::to_string(&t).unwrap();
    let p: AuditTrail = serde_json::from_str(&j).unwrap();
    assert_eq!(p.total, t.total);
}

#[test]
fn odd_serde_roundtrip() {
    let o = OddValidation::demo();
    let j = serde_json::to_string(&o).unwrap();
    let p: OddValidation = serde_json::from_str(&j).unwrap();
    assert_eq!(p.vehicle_class, o.vehicle_class);
}

#[test]
fn extra_gate_can_be_added() {
    use aethelred_sandbox_core::policy::PolicyGate;
    let sb = AutonomousMobilitySandbox::builder()
        .tenant("RTA-X")
        .with_extra_gate(PolicyGate::optional("test.extra", "Extra", "rule"))
        .build()
        .unwrap();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    assert_eq!(sb.seal_count(), 1);
}

#[test]
fn label_override() {
    let sb = AutonomousMobilitySandbox::builder()
        .tenant("RTA")
        .label("Custom Label")
        .build()
        .unwrap();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
}

#[test]
fn verifier_independent() {
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(r.passed());
}

#[test]
fn many_clean_seals_verify_count() {
    let sb = rta();
    for _ in 0..15 {
        sb.seal_odd_validation(OddValidation::demo()).unwrap();
    }
    let r = sb.verify_all().unwrap();
    assert_eq!(r.len(), 15);
    for x in r {
        assert!(x.passed());
    }
}

#[test]
fn current_root_stable() {
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let r1 = sb.current_root().unwrap();
    let r2 = sb.current_root().unwrap();
    assert_eq!(r1, r2);
}

#[test]
fn verifier_basic_categories_routed() {
    use aethelred_sandbox_core::Hasher;
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let mut env = sb.envelope_at(0).unwrap();
    env.seal.event_hash = Hasher::sha256(b"x");
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    let codes: Vec<ErrorCategory> = r
        .failures()
        .iter()
        .filter_map(|c| c.error_code.as_ref().map(|e| e.category))
        .collect();
    assert!(!codes.is_empty());
}

#[test]
fn label_propagates_to_seal_events_count() {
    let sb = AutonomousMobilitySandbox::builder()
        .tenant("RTA-LBL")
        .build()
        .unwrap();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    assert_eq!(sb.seal_count(), 1);
}

// ======================================================================
// Additional ODD / weather / vehicle / safety coverage
// ======================================================================

#[test]
fn within_odd_set_in_validation() {
    let sb = rta();
    let mut o = OddValidation::demo();
    o.within_odd = true;
    sb.seal_odd_validation(o).unwrap();
}

#[test]
fn outside_odd_seals() {
    let sb = rta();
    let mut o = OddValidation::demo();
    o.within_odd = false;
    sb.seal_odd_validation(o).unwrap();
}

#[test]
fn high_speed_seals() {
    let sb = rta();
    let mut o = OddValidation::demo();
    o.current_speed = 100.0;
    sb.seal_odd_validation(o).unwrap();
}

#[test]
fn zero_speed_seals() {
    let sb = rta();
    let mut o = OddValidation::demo();
    o.current_speed = 0.0;
    sb.seal_odd_validation(o).unwrap();
}

#[test]
fn many_perception_events_seal() {
    let sb = rta();
    for _ in 0..20 {
        sb.seal_perception_event(PerceptionEvent::demo()).unwrap();
    }
    assert_eq!(sb.seal_count(), 20);
}

#[test]
fn evidence_log_ordering_preserved() {
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    sb.seal_mission_step(MissionStep::demo()).unwrap();
    sb.seal_perception_event(PerceptionEvent::demo()).unwrap();
    sb.seal_safety_case_event(SafetyCaseEvent::demo()).unwrap();
    let bundle = sb.export_evidence().unwrap();
    let workflows: Vec<&str> = bundle
        .entries
        .iter()
        .map(|e| e.seal.workflow_id.as_str())
        .collect();
    assert_eq!(workflows[0], "odd_validation");
    assert_eq!(workflows[1], "mission_step");
    assert_eq!(workflows[2], "perception_event");
    assert_eq!(workflows[3], "safety_case_event");
}

#[test]
fn audit_records_safety_workflow_id() {
    let sb = rta();
    sb.seal_safety_case_event(SafetyCaseEvent::demo()).unwrap();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.entries[0].workflow_id, "safety_case_event");
}

#[test]
fn audit_records_perception_workflow_id() {
    let sb = rta();
    sb.seal_perception_event(PerceptionEvent::demo()).unwrap();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.entries[0].workflow_id, "perception_event");
}

#[test]
fn audit_records_mission_workflow_id() {
    let sb = rta();
    sb.seal_mission_step(MissionStep::demo()).unwrap();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.entries[0].workflow_id, "mission_step");
}

#[test]
fn audit_csv_count_matches_seal_count() {
    let sb = rta();
    for _ in 0..3 {
        sb.seal_odd_validation(OddValidation::demo()).unwrap();
    }
    let csv = sb.audit_trail(AuditFormat::Csv).unwrap();
    assert_eq!(csv.lines().count(), 4); // header + 3
}

#[test]
fn perception_event_seal_id_uses_seal_prefix() {
    let sb = rta();
    let s = sb.seal_perception_event(PerceptionEvent::demo()).unwrap();
    assert!(s.id_string().starts_with("seal_"));
}

#[test]
fn safety_seal_id_uses_seal_prefix() {
    let sb = rta();
    let s = sb.seal_safety_case_event(SafetyCaseEvent::demo()).unwrap();
    assert!(s.id_string().starts_with("seal_"));
}

#[test]
fn fusion_seal_count_matches_explicit_appends() {
    let sb = rta();
    for _ in 0..3 {
        sb.seal_odd_validation(OddValidation::demo()).unwrap();
        sb.seal_mission_step(MissionStep::demo()).unwrap();
    }
    assert_eq!(sb.seal_count(), 6);
}

#[test]
fn empty_audit_csv_has_only_header() {
    let sb = rta();
    let csv = sb.audit_trail(AuditFormat::Csv).unwrap();
    assert_eq!(csv.lines().count(), 1); // header only
}

#[test]
fn verifier_check_categories_includes_evidence() {
    let sb = rta();
    sb.seal_odd_validation(OddValidation::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    // All checks should pass for a fresh seal+proof.
    assert!(r.passed());
    assert!(r.total() >= 8);
}

#[test]
fn _unused_error_category_import() {
    // Just to make sure the import is used (some test files import it but
    // never reference it directly).
    let _ = ErrorCategory::Policy;
}
