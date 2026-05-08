//! End-to-end plug-and-play smoke test. This test mirrors what a real
//! customer (e.g., FAB) would write as their *first* sandbox integration.

use aethelred_sandbox_finance::prelude::*;
use rust_decimal::Decimal;

#[test]
fn fab_pilot_one_liner_seals_and_exports() {
    // 1) The simplest possible integration. One line.
    let sandbox = FinanceSandbox::quickstart("FAB").unwrap();

    // 2) Seal four real-world workflows.
    let credit = sandbox
        .seal_credit_decision(
            CreditDecision::builder()
                .application_id("app-2026-12-3001")
                .applicant_pseudo_id("psn:8a3f")
                .product("sme_term_loan_v2")
                .amount(Decimal::new(2_500_000, 0))
                .currency("AED")
                .model_id("credit_risk_v3.2")
                .model_hash_hex(Sha256Digest::from_bytes([1u8; 32]).to_hex())
                .model_version("3.2.0")
                .mrm_lineage_ref("mrm:credit_risk_v3.2-2026-q1")
                .decision(CreditOutcome::Approved)
                .approver_role("underwriter")
                .approver_pseudo_id("role:underwriter#a3f1")
                .build()
                .unwrap(),
        )
        .unwrap();

    let aml = sandbox.seal_aml_alert(AmlAlert::demo()).unwrap();
    let trade = sandbox.seal_trading_event(TradingEvent::demo()).unwrap();
    let advisory = sandbox.seal_advisory(Advisory::demo()).unwrap();

    // 3) Export the evidence bundle.
    let bundle = sandbox.export_evidence().unwrap();
    assert_eq!(bundle.entries.len(), 4);
    assert_eq!(bundle.tenant_id, "FAB");
    assert_eq!(bundle.sector, Sector::Finance);

    // 4) Project a regulator view.
    let cbuae = sandbox.regulator_view(&credit.seal, FinanceJurisdiction::Cbuae);
    assert!(!cbuae.citations.is_empty());

    // 5) Sanity: every seal is uniquely id'd and has a non-zero pre-sig hash.
    let ids = vec![
        credit.id_string(),
        aml.id_string(),
        trade.id_string(),
        advisory.id_string(),
    ];
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), ids.len(), "all seal ids must be unique");

    let h = credit.seal.pre_signature_hash().unwrap();
    assert_ne!(h.0, [0u8; 32]);
}

#[test]
fn adversarial_negative_amount_fails_closed() {
    let sandbox = FinanceSandbox::quickstart("FAB").unwrap();
    let mut decision = CreditDecision::demo();
    decision.amount = Decimal::new(-1, 0);
    let r = sandbox.seal_credit_decision(decision);
    assert!(r.is_err());
    assert!(r.unwrap_err().is_policy_denial());
}

#[test]
fn adversarial_pii_in_pseudo_id_fails_closed() {
    let sandbox = FinanceSandbox::quickstart("FAB").unwrap();
    let mut decision = CreditDecision::demo();
    decision.applicant_pseudo_id = "user@example.com".into();
    let r = sandbox.seal_credit_decision(decision);
    assert!(r.is_err());
    assert!(r.unwrap_err().is_policy_denial());
}

#[test]
fn adversarial_risk_limit_exceeded_blocks_trade() {
    let sandbox = FinanceSandbox::quickstart("FAB").unwrap();
    let mut t = TradingEvent::demo();
    t.risk_limit_status = RiskLimitStatus::Exceeded;
    let r = sandbox.seal_trading_event(t);
    assert!(r.is_err());
    assert!(r.unwrap_err().is_policy_denial());
}
