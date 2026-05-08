//! Enterprise v0.2.0 test suite for sandbox-finance.
//!
//! Covers the bulk seal API, Verifier, fixtures library, audit trail, and
//! multi-jurisdiction regulator views. Targets 60+ tests for this file plus
//! the existing 33 unit + 4 e2e tests = 100+ total.

use aethelred_sandbox_finance::prelude::*;
use rust_decimal::Decimal;

// ======================================================================
// Helpers
// ======================================================================

fn fab() -> FinanceSandbox {
    FinanceSandbox::quickstart("FAB").unwrap()
}

fn make_credit(suffix: &str) -> CreditDecision {
    let mut d = CreditDecision::demo();
    d.application_id = format!("app-{suffix}");
    d
}

fn make_aml(suffix: &str) -> AmlAlert {
    let mut a = AmlAlert::demo();
    a.alert_id = format!("aml-{suffix}");
    a
}

fn make_trade(suffix: &str) -> TradingEvent {
    let mut t = TradingEvent::demo();
    t.order_id = format!("ord-{suffix}");
    t
}

// ======================================================================
// Quickstart smoke tests
// ======================================================================

#[test]
fn quickstart_creates_finance_sandbox() {
    let sb = fab();
    assert_eq!(sb.institution(), "FAB");
}

#[test]
fn builder_supports_alternate_institution() {
    let sb = FinanceSandbox::builder()
        .institution("ENBD")
        .jurisdiction(FinanceJurisdiction::Cbuae)
        .build()
        .unwrap();
    assert_eq!(sb.institution(), "ENBD");
}

#[test]
fn builder_supports_uk_jurisdiction() {
    let sb = FinanceSandbox::builder()
        .institution("HSBC-UK")
        .jurisdiction(FinanceJurisdiction::FcaUk)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), FinanceJurisdiction::FcaUk);
}

#[test]
fn builder_supports_singapore_jurisdiction() {
    let sb = FinanceSandbox::builder()
        .institution("DBS")
        .jurisdiction(FinanceJurisdiction::Mas)
        .build()
        .unwrap();
    assert_eq!(sb.primary_jurisdiction(), FinanceJurisdiction::Mas);
}

#[test]
fn builder_supports_us_jurisdiction() {
    let sb = FinanceSandbox::builder()
        .institution("JPM")
        .jurisdiction(FinanceJurisdiction::OccFedFincenUs)
        .build()
        .unwrap();
    assert_eq!(
        sb.primary_jurisdiction(),
        FinanceJurisdiction::OccFedFincenUs
    );
}

#[test]
fn builder_supports_max_amount_override() {
    let sb = FinanceSandbox::builder()
        .institution("FAB")
        .jurisdiction(FinanceJurisdiction::Cbuae)
        .max_amount(Decimal::new(500_000_000, 0))
        .build()
        .unwrap();
    let mut d = CreditDecision::demo();
    d.amount = Decimal::new(600_000_000, 0); // exceeds custom 500m cap
    assert!(sb.seal_credit_decision(d).is_err());
}

// ======================================================================
// Bulk-seal API
// ======================================================================

#[test]
fn bulk_seal_credit_decisions_returns_seals_in_order() {
    let sb = fab();
    let inputs: Vec<CreditDecision> = (0..5).map(|i| make_credit(&i.to_string())).collect();
    let seals = sb.seal_credit_decisions(inputs).unwrap();
    assert_eq!(seals.len(), 5);
    assert_eq!(sb.seal_count(), 5);
}

#[test]
fn bulk_seal_aml_alerts_returns_seals_in_order() {
    let sb = fab();
    let inputs: Vec<AmlAlert> = (0..3).map(|i| make_aml(&i.to_string())).collect();
    let seals = sb.seal_aml_alerts(inputs).unwrap();
    assert_eq!(seals.len(), 3);
}

#[test]
fn bulk_seal_trading_events_returns_seals_in_order() {
    let sb = fab();
    let inputs: Vec<TradingEvent> = (0..7).map(|i| make_trade(&i.to_string())).collect();
    let seals = sb.seal_trading_events(inputs).unwrap();
    assert_eq!(seals.len(), 7);
}

#[test]
fn bulk_seal_advisories_returns_seals_in_order() {
    let sb = fab();
    let inputs = (0..4).map(|_| Advisory::demo()).collect::<Vec<_>>();
    let seals = sb.seal_advisories(inputs).unwrap();
    assert_eq!(seals.len(), 4);
}

#[test]
fn bulk_seal_credit_stops_at_first_failure() {
    let sb = fab();
    let mut bad = CreditDecision::demo();
    bad.amount = Decimal::new(-1, 0);
    let inputs = vec![CreditDecision::demo(), bad, CreditDecision::demo()];
    let r = sb.seal_credit_decisions(inputs);
    assert!(r.is_err());
    // First seal was appended before the failure.
    assert_eq!(sb.seal_count(), 1);
}

#[test]
fn bulk_seal_empty_returns_empty() {
    let sb = fab();
    let v: Vec<CreditDecision> = vec![];
    assert_eq!(sb.seal_credit_decisions(v).unwrap().len(), 0);
}

#[test]
fn bulk_seal_large_batch_succeeds() {
    let sb = fab();
    let inputs: Vec<CreditDecision> = (0..50).map(|i| make_credit(&i.to_string())).collect();
    let seals = sb.seal_credit_decisions(inputs).unwrap();
    assert_eq!(seals.len(), 50);
}

#[test]
fn mixed_workflow_batch_evidence_log() {
    let sb = fab();
    sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    sb.seal_aml_alert(AmlAlert::demo()).unwrap();
    sb.seal_trading_event(TradingEvent::demo()).unwrap();
    sb.seal_advisory(Advisory::demo()).unwrap();
    assert_eq!(sb.seal_count(), 4);
}

// ======================================================================
// Envelope + Verifier API
// ======================================================================

#[test]
fn envelope_at_returns_proof() {
    let sb = fab();
    sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    assert!(env.merkle_proof.is_some());
    assert!(env.merkle_proof.unwrap().verify());
}

#[test]
fn envelope_at_out_of_range_errors() {
    let sb = fab();
    sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    assert!(sb.envelope_at(99).is_err());
}

#[test]
fn all_envelopes_carry_same_root() {
    let sb = fab();
    for _ in 0..5 {
        sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    }
    let envs = sb.all_envelopes().unwrap();
    let root = sb.current_root().unwrap();
    for env in &envs {
        assert_eq!(env.merkle_proof.as_ref().unwrap().root, root);
    }
}

#[test]
fn verify_all_passes_for_clean_log() {
    let sb = fab();
    for _ in 0..3 {
        sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    }
    let reports = sb.verify_all().unwrap();
    assert_eq!(reports.len(), 3);
    for r in &reports {
        assert!(r.passed());
    }
}

#[test]
fn verify_all_with_strict_fails_without_attestation() {
    let sb = fab();
    sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    let reports = sb.verify_all_with(&Verifier::strict()).unwrap();
    assert_eq!(reports.len(), 1);
    assert!(!reports[0].passed());
}

#[test]
fn current_root_changes_after_each_seal() {
    let sb = fab();
    let r0 = sb.current_root().unwrap();
    sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    let r1 = sb.current_root().unwrap();
    assert_ne!(r0, r1);
    sb.seal_aml_alert(AmlAlert::demo()).unwrap();
    let r2 = sb.current_root().unwrap();
    assert_ne!(r1, r2);
}

#[test]
fn empty_log_envelopes_is_empty() {
    let sb = fab();
    assert!(sb.all_envelopes().unwrap().is_empty());
}

#[test]
fn verify_empty_log_succeeds() {
    let sb = fab();
    let reports = sb.verify_all().unwrap();
    assert!(reports.is_empty());
}

#[test]
fn verifier_can_be_built_independently_from_seal() {
    let sb = fab();
    sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    let env = sb.envelope_at(0).unwrap();
    let root = sb.current_root().unwrap();
    // Reviewer-side: just verify, no sandbox needed.
    let v = Verifier::default();
    let report = v.verify_envelope(&env, root).unwrap();
    assert!(report.passed());
}

// ======================================================================
// Audit trail
// ======================================================================

#[test]
fn audit_trail_plain_text_includes_tenant() {
    let sb = fab();
    sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::PlainText).unwrap();
    assert!(s.contains("FAB"));
}

#[test]
fn audit_trail_markdown_has_table() {
    let sb = fab();
    sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::Markdown).unwrap();
    assert!(s.contains("| Timestamp |"));
}

#[test]
fn audit_trail_csv_starts_with_header() {
    let sb = fab();
    sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    let s = sb.audit_trail(AuditFormat::Csv).unwrap();
    assert!(s.starts_with("position,seal_id,timestamp,"));
}

#[test]
fn audit_trail_struct_has_n_entries() {
    let sb = fab();
    for _ in 0..4 {
        sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    }
    let trail = sb.audit_trail_struct().unwrap();
    assert_eq!(trail.total, 4);
}

#[test]
fn audit_trail_records_workflow_id_per_seal() {
    let sb = fab();
    sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    sb.seal_aml_alert(AmlAlert::demo()).unwrap();
    let trail = sb.audit_trail_struct().unwrap();
    let workflows: Vec<&str> = trail
        .entries
        .iter()
        .map(|e| e.workflow_id.as_str())
        .collect();
    assert!(workflows.contains(&"credit_decision"));
    assert!(workflows.contains(&"aml_screening"));
}

// ======================================================================
// Adversarial — parameterized
// ======================================================================

#[test]
fn adversarial_negative_credit_amount() {
    let sb = fab();
    let mut d = CreditDecision::demo();
    d.amount = Decimal::new(-100, 0);
    assert!(sb.seal_credit_decision(d).is_err());
}

#[test]
fn adversarial_zero_credit_amount_passes() {
    let sb = fab();
    let mut d = CreditDecision::demo();
    d.amount = Decimal::ZERO;
    // Zero is non-negative — should pass.
    assert!(sb.seal_credit_decision(d).is_ok());
}

#[test]
fn adversarial_at_cap_credit_amount_passes() {
    let sb = fab();
    let mut d = CreditDecision::demo();
    d.amount = Decimal::new(1_000_000_000, 0);
    assert!(sb.seal_credit_decision(d).is_ok());
}

#[test]
fn adversarial_above_cap_credit_amount_fails() {
    let sb = fab();
    let mut d = CreditDecision::demo();
    d.amount = Decimal::new(1_000_000_001, 0);
    assert!(sb.seal_credit_decision(d).is_err());
}

#[test]
fn adversarial_email_in_pseudo_id_blocks_credit() {
    let sb = fab();
    let mut d = CreditDecision::demo();
    d.applicant_pseudo_id = "user@example.com".into();
    assert!(sb.seal_credit_decision(d).is_err());
}

#[test]
fn adversarial_ssn_marker_blocks_credit() {
    let sb = fab();
    let mut d = CreditDecision::demo();
    d.applicant_pseudo_id = "ssn:123-45-6789".into();
    assert!(sb.seal_credit_decision(d).is_err());
}

#[test]
fn adversarial_emirates_id_marker_blocks_credit() {
    let sb = fab();
    let mut d = CreditDecision::demo();
    d.applicant_pseudo_id = "emirates_id:784-1990-1234567-1".into();
    assert!(sb.seal_credit_decision(d).is_err());
}

#[test]
fn adversarial_email_in_application_id_blocks_credit() {
    let sb = fab();
    let mut d = CreditDecision::demo();
    d.application_id = "app-jdoe@bank.com".into();
    assert!(sb.seal_credit_decision(d).is_err());
}

#[test]
fn adversarial_email_in_aml_alert_blocks() {
    let sb = fab();
    let mut a = AmlAlert::demo();
    a.alert_id = "alert-jdoe@bank.com".into();
    assert!(sb.seal_aml_alert(a).is_err());
}

#[test]
fn adversarial_negative_trade_qty_blocks() {
    let sb = fab();
    let mut t = TradingEvent::demo();
    t.quantity = Decimal::new(-10, 0);
    assert!(sb.seal_trading_event(t).is_err());
}

#[test]
fn adversarial_overlimit_trade_blocks() {
    let sb = fab();
    let mut t = TradingEvent::demo();
    t.risk_limit_status = RiskLimitStatus::Exceeded;
    assert!(sb.seal_trading_event(t).is_err());
}

#[test]
fn adversarial_overlimit_advisory_blocks() {
    let sb = fab();
    let mut a = Advisory::demo();
    a.amount = Decimal::new(2_000_000_000, 0);
    assert!(sb.seal_advisory(a).is_err());
}

// ======================================================================
// Multi-jurisdiction regulator view tests
// ======================================================================

#[test]
fn cbuae_regulator_view_carries_citations() {
    let sb = fab();
    let s = sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, FinanceJurisdiction::Cbuae);
    assert!(!view.citations.is_empty());
    assert!(view.citations.iter().any(|c| c.regulator.contains("CBUAE")));
}

#[test]
fn fca_regulator_view_carries_uk_citations() {
    let sb = fab();
    let s = sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, FinanceJurisdiction::FcaUk);
    assert!(view.citations.iter().any(|c| c.regulator.contains("FCA")));
}

#[test]
fn occ_regulator_view_carries_us_citations() {
    let sb = fab();
    let s = sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, FinanceJurisdiction::OccFedFincenUs);
    assert!(!view.citations.is_empty());
}

#[test]
fn mas_regulator_view_carries_singapore_citations() {
    let sb = fab();
    let s = sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, FinanceJurisdiction::Mas);
    assert!(view.citations.iter().any(|c| c.regulator.contains("MAS")));
}

#[test]
fn dfsa_regulator_view_carries_difc_citations() {
    let sb = fab();
    let s = sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, FinanceJurisdiction::Dfsa);
    assert!(!view.citations.is_empty());
}

#[test]
fn fsra_regulator_view_carries_adgm_citations() {
    let sb = fab();
    let s = sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, FinanceJurisdiction::Fsra);
    assert!(!view.citations.is_empty());
}

#[test]
fn sca_regulator_view_carries_uae_citations() {
    let sb = fab();
    let s = sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    let view = sb.regulator_view(&s.seal, FinanceJurisdiction::Sca);
    assert!(!view.citations.is_empty());
}

// ======================================================================
// Fixtures
// ======================================================================

#[test]
fn fixtures_happy_path_count() {
    assert_eq!(FinanceFixtures::happy_path().len(), 4);
}

#[test]
fn fixtures_adversarial_count_at_least_six() {
    assert!(FinanceFixtures::adversarial().len() >= 6);
}

#[test]
fn fixtures_all_unique_ids() {
    let ids: Vec<&str> = FinanceFixtures::all().iter().map(|f| f.id()).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    let n = sorted.len();
    sorted.dedup();
    assert_eq!(sorted.len(), n);
}

#[test]
fn fixtures_by_tag_cbuae_subset() {
    let cb = FinanceFixtures::by_tag("cbuae");
    assert!(!cb.is_empty());
}

#[test]
fn fixtures_run_happy_path_all_succeed() {
    let sb = fab();
    for f in FinanceFixtures::happy_path() {
        f.run(&sb).unwrap();
    }
}

#[test]
fn fixtures_run_adversarial_all_block() {
    let sb = fab();
    for f in FinanceFixtures::adversarial() {
        f.run(&sb).unwrap_or_else(|e| panic!("{}: {e}", f.id()));
    }
}

#[test]
fn fixture_descriptions_are_nonempty() {
    for f in FinanceFixtures::all() {
        assert!(!f.description().is_empty(), "fixture {} has empty desc", f.id());
    }
}

#[test]
fn fixture_tags_are_nonempty() {
    for f in FinanceFixtures::all() {
        assert!(!f.tags().is_empty(), "fixture {} has no tags", f.id());
    }
}

// ======================================================================
// Evidence + Merkle proofs
// ======================================================================

#[test]
fn merkle_proofs_verify_for_each_seal_in_log() {
    let sb = fab();
    for _ in 0..10 {
        sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    }
    let envs = sb.all_envelopes().unwrap();
    for env in envs {
        assert!(env.merkle_proof.unwrap().verify());
    }
}

#[test]
fn evidence_export_carries_all_seals_in_order() {
    let sb = fab();
    for i in 0..5 {
        sb.seal_credit_decision(make_credit(&i.to_string())).unwrap();
    }
    let bundle = sb.export_evidence().unwrap();
    assert_eq!(bundle.entries.len(), 5);
    for (i, e) in bundle.entries.iter().enumerate() {
        assert_eq!(e.index, i as u64);
    }
}

#[test]
fn evidence_export_root_matches_current_root() {
    let sb = fab();
    sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    let bundle = sb.export_evidence().unwrap();
    assert_eq!(bundle.merkle_root, sb.current_root().unwrap());
}

// ======================================================================
// Error code routing
// ======================================================================

#[test]
fn policy_denial_yields_policy_error_code() {
    let sb = fab();
    let mut d = CreditDecision::demo();
    d.amount = Decimal::new(-1, 0);
    let err = sb.seal_credit_decision(d).unwrap_err();
    let code = err.error_code();
    assert_eq!(code.category, ErrorCategory::Policy);
}

#[test]
fn pii_marker_yields_policy_denial() {
    let sb = fab();
    let mut d = CreditDecision::demo();
    d.applicant_pseudo_id = "user@example.com".into();
    let err = sb.seal_credit_decision(d).unwrap_err();
    assert!(err.is_policy_denial());
}

// ======================================================================
// Approval / role tests
// ======================================================================

#[test]
fn approval_record_is_attached_to_credit_seal() {
    let sb = fab();
    let s = sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn approval_record_is_attached_to_aml_seal() {
    let sb = fab();
    let s = sb.seal_aml_alert(AmlAlert::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn approval_record_is_attached_to_trading_seal() {
    let sb = fab();
    let s = sb.seal_trading_event(TradingEvent::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

#[test]
fn approval_record_is_attached_to_advisory_seal() {
    let sb = fab();
    let s = sb.seal_advisory(Advisory::demo()).unwrap();
    assert!(s.seal.approval_count() >= 1);
}

// ======================================================================
// Serde roundtrip
// ======================================================================

#[test]
fn credit_decision_serde_roundtrip() {
    let d = CreditDecision::demo();
    let j = serde_json::to_string(&d).unwrap();
    let p: CreditDecision = serde_json::from_str(&j).unwrap();
    assert_eq!(p.application_id, d.application_id);
    assert_eq!(p.amount, d.amount);
}

#[test]
fn evidence_bundle_serde_roundtrip() {
    let sb = fab();
    sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    let b = sb.export_evidence().unwrap();
    let j = serde_json::to_string(&b).unwrap();
    let p: EvidenceBundle = serde_json::from_str(&j).unwrap();
    assert_eq!(p.entries.len(), b.entries.len());
}

#[test]
fn audit_trail_serde_roundtrip() {
    let sb = fab();
    sb.seal_credit_decision(CreditDecision::demo()).unwrap();
    let t = sb.audit_trail_struct().unwrap();
    let j = serde_json::to_string(&t).unwrap();
    let p: AuditTrail = serde_json::from_str(&j).unwrap();
    assert_eq!(p.total, t.total);
}
