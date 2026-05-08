//! Enterprise v0.2.0 test suite for sandbox-supply-chain.

use aethelred_sandbox_core::audit::{AuditFormat, AuditTrail};
use aethelred_sandbox_core::error_code::ErrorCategory;
use aethelred_sandbox_core::verify::Verifier;
use aethelred_sandbox_core::{EvidenceBundle, Sector};
use aethelred_sandbox_supply_chain::*;
use rust_decimal::Decimal;

fn kezad() -> SupplyChainSandbox {
    SupplyChainSandbox::quickstart("KEZAD").unwrap()
}

fn masdar() -> SupplyChainSandbox {
    SupplyChainSandbox::quickstart("Masdar").unwrap()
}

// ======================================================================
// Quickstart / Builder
// ======================================================================

#[test]
fn quickstart_default_jurisdiction_is_cbam() {
    let sb = kezad();
    assert_eq!(sb.primary_jurisdiction(), SupplyChainJurisdiction::EuCbam);
}

#[test]
fn builder_supports_eu_methane() {
    let sb = SupplyChainSandbox::builder()
        .tenant("ADNOC")
        .jurisdiction(SupplyChainJurisdiction::EuMethane)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), SupplyChainJurisdiction::EuMethane);
}

#[test]
fn builder_supports_us_45v() {
    let sb = SupplyChainSandbox::builder()
        .tenant("Masdar")
        .jurisdiction(SupplyChainJurisdiction::Us45v)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), SupplyChainJurisdiction::Us45v);
}

#[test]
fn builder_supports_us_45q() {
    let sb = SupplyChainSandbox::builder()
        .tenant("ADNOC-Sequestration")
        .jurisdiction(SupplyChainJurisdiction::Us45q)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), SupplyChainJurisdiction::Us45q);
}

#[test]
fn builder_supports_eu_csrd() {
    let sb = SupplyChainSandbox::builder()
        .tenant("KEZAD-ESG")
        .jurisdiction(SupplyChainJurisdiction::EuCsrdIssb)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), SupplyChainJurisdiction::EuCsrdIssb);
}

#[test]
fn builder_supports_uae_ead() {
    let sb = SupplyChainSandbox::builder()
        .tenant("EAD")
        .jurisdiction(SupplyChainJurisdiction::UaeEadCustoms)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), SupplyChainJurisdiction::UaeEadCustoms);
}

#[test]
fn builder_supports_wco_safe() {
    let sb = SupplyChainSandbox::builder()
        .tenant("WCO-Member")
        .jurisdiction(SupplyChainJurisdiction::WcoSafe)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), SupplyChainJurisdiction::WcoSafe);
}

// ======================================================================
// Bulk seal API
// ======================================================================

#[test]
fn bulk_seal_batch_events() {
    let sb = kezad();
    let r = sb
        .seal_batch_events((0..5).map(|_| BatchEvent::demo()))
        .unwrap();
    assert_eq!(r.len(), 5);
}

#[test]
fn bulk_seal_customs_filings() {
    let sb = kezad();
    let r = sb
        .seal_customs_filings((0..3).map(|_| CustomsFiling::demo()))
        .unwrap();
    assert_eq!(r.len(), 3);
}

#[test]
fn bulk_seal_carbon_claims() {
    let sb = masdar();
    let r = sb
        .seal_carbon_claims((0..7).map(|_| CarbonClaim::demo()))
        .unwrap();
    assert_eq!(r.len(), 7);
}

#[test]
fn bulk_seal_methane_events() {
    let sb = SupplyChainSandbox::builder()
        .tenant("ADNOC")
        .jurisdiction(SupplyChainJurisdiction::EuMethane)
        .build()
        .unwrap();
    let r = sb
        .seal_methane_events((0..4).map(|_| MethaneEvent::demo()))
        .unwrap();
    assert_eq!(r.len(), 4);
}

#[test]
fn bulk_seal_empty() {
    let sb = kezad();
    let v: Vec<BatchEvent> = vec![];
    assert_eq!(sb.seal_batch_events(v).unwrap().len(), 0);
}

#[test]
fn bulk_seal_large() {
    let sb = kezad();
    let r = sb
        .seal_batch_events((0..50).map(|_| BatchEvent::demo()))
        .unwrap();
    assert_eq!(r.len(), 50);
}

#[test]
fn mixed_workflow_log() {
    let sb = kezad();
    sb.seal_batch_event(BatchEvent::demo()).unwrap();
    sb.seal_customs_filing(CustomsFiling::demo()).unwrap();
    sb.seal_carbon_claim(CarbonClaim::demo()).unwrap();
    assert_eq!(sb.seal_count(), 3);
}

// ======================================================================
// Envelope + Verifier
// ======================================================================

#[test]
fn envelope_at_returns_proof() {
    let sb = kezad();
    sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    assert!(env.merkle_proof.is_some());
    assert!(env.merkle_proof.unwrap().verify());
}

#[test]
fn envelope_oor_errors() {
    let sb = kezad();
    sb.seal_batch_event(BatchEvent::demo()).unwrap();
    assert!(sb.envelope_at(99).is_err());
}

#[test]
fn all_envelopes_share_root() {
    let sb = kezad();
    for _ in 0..6 {
        sb.seal_batch_event(BatchEvent::demo()).unwrap();
    }
    let envs = sb.all_envelopes().unwrap();
    let root = sb.current_root().unwrap();
    for env in &envs {
        assert_eq!(env.merkle_proof.as_ref().unwrap().root, root);
    }
}

#[test]
fn verify_all_passes() {
    let sb = kezad();
    for _ in 0..4 {
        sb.seal_batch_event(BatchEvent::demo()).unwrap();
    }
    let r = sb.verify_all().unwrap();
    assert!(r.iter().all(|x| x.passed()));
}

#[test]
fn verify_strict_fails_without_attestation() {
    let sb = kezad();
    sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let r = sb.verify_all_with(&Verifier::strict()).unwrap();
    assert!(!r[0].passed());
}

#[test]
fn current_root_changes() {
    let sb = kezad();
    let r0 = sb.current_root().unwrap();
    sb.seal_batch_event(BatchEvent::demo()).unwrap();
    assert_ne!(r0, sb.current_root().unwrap());
}

// ======================================================================
// Audit trail
// ======================================================================

#[test]
fn audit_plaintext() {
    let sb = kezad();
    sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::PlainText).unwrap();
    assert!(s.contains("KEZAD"));
}

#[test]
fn audit_markdown() {
    let sb = kezad();
    sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::Markdown).unwrap();
    assert!(s.contains("|"));
}

#[test]
fn audit_csv() {
    let sb = kezad();
    sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::Csv).unwrap();
    assert!(s.starts_with("position,seal_id,timestamp,"));
}

#[test]
fn audit_struct_count() {
    let sb = kezad();
    for _ in 0..3 {
        sb.seal_batch_event(BatchEvent::demo()).unwrap();
    }
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.total, 3);
}

#[test]
fn audit_records_workflow_id() {
    let sb = kezad();
    sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.entries[0].workflow_id, "batch_event");
}

// ======================================================================
// Adversarial — supply-chain-specific
// ======================================================================

#[test]
fn negative_emissions_block_carbon() {
    let sb = masdar();
    let mut c = CarbonClaim::demo();
    c.emissions_kg_co2e = Decimal::new(-1, 0);
    assert!(sb.seal_carbon_claim(c).is_err());
}

#[test]
fn negative_methane_emission_blocks() {
    let sb = SupplyChainSandbox::builder()
        .tenant("ADNOC")
        .jurisdiction(SupplyChainJurisdiction::EuMethane)
        .build()
        .unwrap();
    let mut m = MethaneEvent::demo();
    m.emission_kg_ch4 = Decimal::new(-1, 0);
    assert!(sb.seal_methane_event(m).is_err());
}

// ======================================================================
// Multi-jurisdiction views
// ======================================================================

#[test]
fn cbam_view_carries_citations() {
    let sb = kezad();
    let s = sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, SupplyChainJurisdiction::EuCbam);
    assert!(!view.citations.is_empty());
}

#[test]
fn methane_view_carries_citations() {
    let sb = kezad();
    let s = sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, SupplyChainJurisdiction::EuMethane);
    assert!(!view.citations.is_empty());
}

#[test]
fn us_45v_view_carries_citations() {
    let sb = kezad();
    let s = sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, SupplyChainJurisdiction::Us45v);
    assert!(!view.citations.is_empty());
}

#[test]
fn us_45q_view_carries_citations() {
    let sb = kezad();
    let s = sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, SupplyChainJurisdiction::Us45q);
    assert!(!view.citations.is_empty());
}

#[test]
fn csrd_view_carries_citations() {
    let sb = kezad();
    let s = sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, SupplyChainJurisdiction::EuCsrdIssb);
    assert!(!view.citations.is_empty());
}

#[test]
fn uae_ead_view_carries_citations() {
    let sb = kezad();
    let s = sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, SupplyChainJurisdiction::UaeEadCustoms);
    assert!(!view.citations.is_empty());
}

#[test]
fn wco_safe_view_carries_citations() {
    let sb = kezad();
    let s = sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, SupplyChainJurisdiction::WcoSafe);
    assert!(!view.citations.is_empty());
}

// ======================================================================
// Evidence
// ======================================================================

#[test]
fn merkle_proofs_verify_for_each_seal() {
    let sb = kezad();
    for _ in 0..8 {
        sb.seal_batch_event(BatchEvent::demo()).unwrap();
    }
    let envs = sb.all_envelopes().unwrap();
    for env in envs {
        assert!(env.merkle_proof.unwrap().verify());
    }
}

#[test]
fn evidence_indices_monotonic() {
    let sb = kezad();
    for _ in 0..5 {
        sb.seal_batch_event(BatchEvent::demo()).unwrap();
    }
    let bundle = sb.export_evidence().unwrap();
    for (i, e) in bundle.entries.iter().enumerate() {
        assert_eq!(e.index, i as u64);
    }
}

#[test]
fn evidence_root_matches_current() {
    let sb = kezad();
    sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let bundle = sb.export_evidence().unwrap();
    assert_eq!(bundle.merkle_root, sb.current_root().unwrap());
}

#[test]
fn empty_seal_count() {
    let sb = kezad();
    assert_eq!(sb.seal_count(), 0);
}

#[test]
fn empty_audit_trail() {
    let sb = kezad();
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.total, 0);
}

#[test]
fn empty_envelopes() {
    let sb = kezad();
    assert!(sb.all_envelopes().unwrap().is_empty());
}

#[test]
fn empty_verify_all() {
    let sb = kezad();
    assert!(sb.verify_all().unwrap().is_empty());
}

// ======================================================================
// Approvals + sectors
// ======================================================================

#[test]
fn batch_seal_has_approval() {
    let sb = kezad();
    let s = sb.seal_batch_event(BatchEvent::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn customs_seal_has_approval() {
    let sb = kezad();
    let s = sb.seal_customs_filing(CustomsFiling::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn carbon_seal_has_approval() {
    let sb = masdar();
    let s = sb.seal_carbon_claim(CarbonClaim::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn methane_seal_has_approval() {
    let sb = SupplyChainSandbox::builder()
        .tenant("ADNOC")
        .jurisdiction(SupplyChainJurisdiction::EuMethane)
        .build()
        .unwrap();
    let s = sb.seal_methane_event(MethaneEvent::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn supply_chain_sector_in_seal() {
    let sb = kezad();
    let s = sb.seal_batch_event(BatchEvent::demo()).unwrap();
    assert_eq!(s.seal.sector, Sector::SupplyChain);
}

// ======================================================================
// Verifier mutations
// ======================================================================

#[test]
fn verifier_detects_event_hash_tamper() {
    use aethelred_sandbox_core::Hasher;
    let sb = kezad();
    sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let mut env = sb.envelope_at(0).unwrap();
    env.seal.event_hash = Hasher::sha256(b"tampered");
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(!r.passed());
}

#[test]
fn verify_with_wrong_root_fails() {
    use aethelred_sandbox_core::Hasher;
    let sb = kezad();
    sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    let r = Verifier::default()
        .verify_envelope(&env, Hasher::sha256(b"wrong-root"))
        .unwrap();
    assert!(!r.passed());
}

// ======================================================================
// Error code
// ======================================================================

#[test]
fn negative_emissions_yields_policy_error_code() {
    let sb = masdar();
    let mut c = CarbonClaim::demo();
    c.emissions_kg_co2e = Decimal::new(-1, 0);
    let err = sb.seal_carbon_claim(c).unwrap_err();
    assert_eq!(err.error_code().category, ErrorCategory::Policy);
}

// ======================================================================
// Serde
// ======================================================================

#[test]
fn evidence_bundle_serde_roundtrip() {
    let sb = kezad();
    sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let b = sb.export_evidence().unwrap();
    let j = serde_json::to_string(&b).unwrap();
    let p: EvidenceBundle = serde_json::from_str(&j).unwrap();
    assert_eq!(p.entries.len(), b.entries.len());
}

#[test]
fn audit_trail_serde_roundtrip() {
    let sb = kezad();
    sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let t = sb.audit_trail_struct().unwrap();
    let j = serde_json::to_string(&t).unwrap();
    let p: AuditTrail = serde_json::from_str(&j).unwrap();
    assert_eq!(p.total, t.total);
}

#[test]
fn batch_event_serde_roundtrip() {
    let b = BatchEvent::demo();
    let j = serde_json::to_string(&b).unwrap();
    let p: BatchEvent = serde_json::from_str(&j).unwrap();
    assert_eq!(p.batch_id, b.batch_id);
}

// ======================================================================
// More EPCIS event types
// ======================================================================

#[test]
fn epcis_object_event_seals() {
    let sb = kezad();
    let mut b = BatchEvent::demo();
    b.epcis_event_type = EpcisEventType::Object;
    sb.seal_batch_event(b).unwrap();
}

#[test]
fn epcis_aggregation_event_seals() {
    let sb = kezad();
    let mut b = BatchEvent::demo();
    b.epcis_event_type = EpcisEventType::Aggregation;
    sb.seal_batch_event(b).unwrap();
}

#[test]
fn epcis_transformation_event_seals() {
    let sb = kezad();
    let mut b = BatchEvent::demo();
    b.epcis_event_type = EpcisEventType::Transformation;
    sb.seal_batch_event(b).unwrap();
}

#[test]
fn epcis_association_event_seals() {
    let sb = kezad();
    let mut b = BatchEvent::demo();
    b.epcis_event_type = EpcisEventType::Association;
    sb.seal_batch_event(b).unwrap();
}

// ======================================================================
// Customs decision variants
// ======================================================================

#[test]
fn customs_cleared_decision_seals() {
    let sb = kezad();
    let mut c = CustomsFiling::demo();
    c.decision = CustomsDecision::Cleared;
    sb.seal_customs_filing(c).unwrap();
}

#[test]
fn customs_held_decision_seals() {
    let sb = kezad();
    let mut c = CustomsFiling::demo();
    c.decision = CustomsDecision::HeldForInspection;
    sb.seal_customs_filing(c).unwrap();
}

#[test]
fn customs_rejected_decision_seals() {
    let sb = kezad();
    let mut c = CustomsFiling::demo();
    c.decision = CustomsDecision::Rejected;
    sb.seal_customs_filing(c).unwrap();
}

#[test]
fn customs_pending_info_decision_seals() {
    let sb = kezad();
    let mut c = CustomsFiling::demo();
    c.decision = CustomsDecision::PendingInfo;
    sb.seal_customs_filing(c).unwrap();
}

// ======================================================================
// Carbon standard variants
// ======================================================================

#[test]
fn carbon_eu_cbam_seals() {
    let sb = masdar();
    let mut c = CarbonClaim::demo();
    c.standard = CarbonStandard::EuCbam;
    sb.seal_carbon_claim(c).unwrap();
}

#[test]
fn carbon_us_45v_seals() {
    let sb = masdar();
    let mut c = CarbonClaim::demo();
    c.standard = CarbonStandard::Us45v;
    sb.seal_carbon_claim(c).unwrap();
}

#[test]
fn carbon_us_45q_seals() {
    let sb = masdar();
    let mut c = CarbonClaim::demo();
    c.standard = CarbonStandard::Us45q;
    sb.seal_carbon_claim(c).unwrap();
}

#[test]
fn carbon_ghg_scope1_seals() {
    let sb = masdar();
    let mut c = CarbonClaim::demo();
    c.standard = CarbonStandard::GhgProtocolScope1;
    sb.seal_carbon_claim(c).unwrap();
}

#[test]
fn carbon_ghg_scope2_seals() {
    let sb = masdar();
    let mut c = CarbonClaim::demo();
    c.standard = CarbonStandard::GhgProtocolScope2;
    sb.seal_carbon_claim(c).unwrap();
}

#[test]
fn carbon_ghg_scope3_seals() {
    let sb = masdar();
    let mut c = CarbonClaim::demo();
    c.standard = CarbonStandard::GhgProtocolScope3;
    sb.seal_carbon_claim(c).unwrap();
}

#[test]
fn carbon_iso_14064_seals() {
    let sb = masdar();
    let mut c = CarbonClaim::demo();
    c.standard = CarbonStandard::Iso14064_1;
    sb.seal_carbon_claim(c).unwrap();
}

#[test]
fn carbon_iso_14067_seals() {
    let sb = masdar();
    let mut c = CarbonClaim::demo();
    c.standard = CarbonStandard::Iso14067;
    sb.seal_carbon_claim(c).unwrap();
}

// ======================================================================
// OGMP methane levels
// ======================================================================

#[test]
fn ogmp_level3_seals() {
    let sb = SupplyChainSandbox::builder()
        .tenant("ADNOC")
        .jurisdiction(SupplyChainJurisdiction::EuMethane)
        .build()
        .unwrap();
    let mut m = MethaneEvent::demo();
    m.ogmp_level = OgmpLevel::L3;
    sb.seal_methane_event(m).unwrap();
}

#[test]
fn ogmp_level4_seals() {
    let sb = SupplyChainSandbox::builder()
        .tenant("ADNOC")
        .jurisdiction(SupplyChainJurisdiction::EuMethane)
        .build()
        .unwrap();
    let mut m = MethaneEvent::demo();
    m.ogmp_level = OgmpLevel::L4;
    sb.seal_methane_event(m).unwrap();
}

#[test]
fn ogmp_level5_seals() {
    let sb = SupplyChainSandbox::builder()
        .tenant("ADNOC")
        .jurisdiction(SupplyChainJurisdiction::EuMethane)
        .build()
        .unwrap();
    let mut m = MethaneEvent::demo();
    m.ogmp_level = OgmpLevel::L5;
    sb.seal_methane_event(m).unwrap();
}

// ======================================================================
// Cross-workflow + Builder-with-extra-gate
// ======================================================================

#[test]
fn extra_gate_can_be_added() {
    use aethelred_sandbox_core::policy::PolicyGate;
    let sb = SupplyChainSandbox::builder()
        .tenant("KEZAD-X")
        .jurisdiction(SupplyChainJurisdiction::EuCbam)
        .with_extra_gate(PolicyGate::optional("test.extra", "Extra", "rule"))
        .build()
        .unwrap();
    sb.seal_batch_event(BatchEvent::demo()).unwrap();
    assert_eq!(sb.seal_count(), 1);
}

#[test]
fn label_override() {
    let sb = SupplyChainSandbox::builder()
        .tenant("KEZAD")
        .label("Custom Label")
        .build()
        .unwrap();
    sb.seal_batch_event(BatchEvent::demo()).unwrap();
}

#[test]
fn batch_seal_workflow_id() {
    let sb = kezad();
    let s = sb.seal_batch_event(BatchEvent::demo()).unwrap();
    assert_eq!(s.seal.workflow_id, "batch_event");
}

#[test]
fn customs_seal_workflow_id() {
    let sb = kezad();
    let s = sb.seal_customs_filing(CustomsFiling::demo()).unwrap();
    assert_eq!(s.seal.workflow_id, "customs_filing");
}

#[test]
fn carbon_seal_workflow_id() {
    let sb = masdar();
    let s = sb.seal_carbon_claim(CarbonClaim::demo()).unwrap();
    assert_eq!(s.seal.workflow_id, "carbon_claim");
}

#[test]
fn methane_seal_workflow_id() {
    let sb = SupplyChainSandbox::builder()
        .tenant("ADNOC")
        .jurisdiction(SupplyChainJurisdiction::EuMethane)
        .build()
        .unwrap();
    let s = sb.seal_methane_event(MethaneEvent::demo()).unwrap();
    assert_eq!(s.seal.workflow_id, "methane_event");
}

#[test]
fn cbam_jurisdiction_in_seal() {
    let sb = kezad();
    let s = sb.seal_batch_event(BatchEvent::demo()).unwrap();
    assert_eq!(s.seal.jurisdiction_tag, "EU-CBAM");
}

#[test]
fn methane_jurisdiction_in_seal() {
    let sb = SupplyChainSandbox::builder()
        .tenant("ADNOC")
        .jurisdiction(SupplyChainJurisdiction::EuMethane)
        .build()
        .unwrap();
    let s = sb.seal_methane_event(MethaneEvent::demo()).unwrap();
    assert_eq!(s.seal.jurisdiction_tag, "EU-METHANE");
}

#[test]
fn verifier_independent_from_sandbox() {
    let sb = kezad();
    sb.seal_batch_event(BatchEvent::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    let root = sb.current_root().unwrap();
    let r = Verifier::default().verify_envelope(&env, root).unwrap();
    assert!(r.passed());
}

// ======================================================================
// Additional methane / OGMP / customs cases
// ======================================================================

#[test]
fn ogmp_l1_seals() {
    let sb = SupplyChainSandbox::builder()
        .tenant("ADNOC")
        .jurisdiction(SupplyChainJurisdiction::EuMethane)
        .build()
        .unwrap();
    let mut m = MethaneEvent::demo();
    m.ogmp_level = OgmpLevel::L1;
    sb.seal_methane_event(m).unwrap();
}

#[test]
fn ogmp_l2_seals() {
    let sb = SupplyChainSandbox::builder()
        .tenant("ADNOC")
        .jurisdiction(SupplyChainJurisdiction::EuMethane)
        .build()
        .unwrap();
    let mut m = MethaneEvent::demo();
    m.ogmp_level = OgmpLevel::L2;
    sb.seal_methane_event(m).unwrap();
}

#[test]
fn flaring_methane_event_seals() {
    let sb = SupplyChainSandbox::builder()
        .tenant("ADNOC")
        .jurisdiction(SupplyChainJurisdiction::EuMethane)
        .build()
        .unwrap();
    let mut m = MethaneEvent::demo();
    m.flaring = true;
    sb.seal_methane_event(m).unwrap();
}

#[test]
fn zero_emission_carbon_seals() {
    let sb = masdar();
    let mut c = CarbonClaim::demo();
    c.emissions_kg_co2e = Decimal::ZERO;
    sb.seal_carbon_claim(c).unwrap();
}

#[test]
fn zero_emission_methane_seals() {
    let sb = SupplyChainSandbox::builder()
        .tenant("ADNOC")
        .jurisdiction(SupplyChainJurisdiction::EuMethane)
        .build()
        .unwrap();
    let mut m = MethaneEvent::demo();
    m.emission_kg_ch4 = Decimal::ZERO;
    sb.seal_methane_event(m).unwrap();
}

#[test]
fn large_carbon_amount_seals() {
    let sb = masdar();
    let mut c = CarbonClaim::demo();
    c.emissions_kg_co2e = Decimal::new(1_000_000_000, 0);
    sb.seal_carbon_claim(c).unwrap();
}

#[test]
fn customs_filing_serde_roundtrip() {
    let c = CustomsFiling::demo();
    let j = serde_json::to_string(&c).unwrap();
    let p: CustomsFiling = serde_json::from_str(&j).unwrap();
    assert_eq!(p.filing_id, c.filing_id);
}

#[test]
fn carbon_claim_serde_roundtrip() {
    let c = CarbonClaim::demo();
    let j = serde_json::to_string(&c).unwrap();
    let p: CarbonClaim = serde_json::from_str(&j).unwrap();
    assert_eq!(p.claim_id, c.claim_id);
}

#[test]
fn methane_event_serde_roundtrip() {
    let m = MethaneEvent::demo();
    let j = serde_json::to_string(&m).unwrap();
    let p: MethaneEvent = serde_json::from_str(&j).unwrap();
    assert_eq!(p.event_id, m.event_id);
}
