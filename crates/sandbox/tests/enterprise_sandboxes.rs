use aethelred_sandbox::{
    execute_sandbox_run, get_enterprise_sandbox, regulated_sandbox_catalog, run_adversarial_suite,
    DataBoundary, RegulatedVertical, SandboxDecision, SandboxFault, SandboxRunConfig,
};

#[test]
fn all_regulated_verticals_have_executable_sandbox_packs() {
    let catalog = regulated_sandbox_catalog();
    assert_eq!(catalog.len(), 7);

    let expected = [
        RegulatedVertical::Finance,
        RegulatedVertical::Healthcare,
        RegulatedVertical::Defense,
        RegulatedVertical::SupplyChain,
        RegulatedVertical::AutonomousMobility,
        RegulatedVertical::AiAgents,
        RegulatedVertical::Research,
    ];

    for vertical in expected {
        let sandbox = catalog
            .iter()
            .find(|sandbox| sandbox.vertical == vertical)
            .unwrap_or_else(|| panic!("{vertical:?} sandbox missing"));
        assert!(!sandbox.policy_gates.is_empty());
        assert!(!sandbox.adversarial_tests.is_empty());
        assert!(!sandbox.evidence_fields.is_empty());

        let report = execute_sandbox_run(
            sandbox,
            &SandboxRunConfig::happy_path(sandbox.hero_scenario)
                .with_data_boundary(DataBoundary::EnterpriseApprovedNonProduction),
        );
        assert_eq!(report.decision, SandboxDecision::Allow);
        assert!(report.loi_ready);
        assert_eq!(
            report.evidence_record.schema_version,
            "sandbox-evidence-v0.1"
        );
        assert_eq!(report.evidence_record.data_boundary_status, "pass");
        assert_eq!(report.evidence_record.evidence_bundle_hash.len(), 64);
    }
}

#[test]
fn every_adversarial_suite_blocks_or_escalates_negative_tests() {
    for sandbox in regulated_sandbox_catalog() {
        let reports = run_adversarial_suite(&sandbox);
        assert!(
            reports.len() >= 3,
            "{} should have a meaningful adversarial suite",
            sandbox.id
        );

        for report in reports {
            assert!(
                matches!(
                    report.decision,
                    SandboxDecision::FailClosed | SandboxDecision::ReviewRequired
                ),
                "{} allowed an adversarial case: {:?}",
                sandbox.id,
                report.triggered_faults
            );
            assert!(!report.loi_ready);
        }
    }
}

#[test]
fn finance_sandbox_blocks_stale_model_and_missing_human_review() {
    let finance = get_enterprise_sandbox("finance_ai_assurance").unwrap();
    let report = execute_sandbox_run(
        &finance,
        &SandboxRunConfig::happy_path("credit-memo")
            .with_fault(SandboxFault::StaleModelVersion)
            .with_fault(SandboxFault::MissingHumanReview),
    );

    assert_eq!(report.decision, SandboxDecision::FailClosed);
    assert!(report
        .gate_results
        .iter()
        .any(|gate| gate.gate_id == "model_approval" && !gate.passed));
    assert!(report
        .gate_results
        .iter()
        .any(|gate| gate.gate_id == "human_authority" && !gate.passed));
}

#[test]
fn healthcare_sandbox_rejects_sensitive_data_on_chain() {
    let healthcare = get_enterprise_sandbox("healthcare_ai_assurance").unwrap();
    let report = execute_sandbox_run(
        &healthcare,
        &SandboxRunConfig::happy_path("radiology-triage")
            .with_fault(SandboxFault::SensitiveDataOnChain),
    );

    assert_eq!(report.decision, SandboxDecision::FailClosed);
    assert_eq!(report.evidence_record.data_boundary_status, "fail");
}

#[test]
fn research_sandbox_detects_result_tampering() {
    let research = get_enterprise_sandbox("research_reproducibility").unwrap();
    let report = execute_sandbox_run(
        &research,
        &SandboxRunConfig::happy_path("model-eval").with_fault(SandboxFault::MetricTampered),
    );

    assert_eq!(report.decision, SandboxDecision::FailClosed);
    assert!(report
        .gate_results
        .iter()
        .any(|gate| gate.gate_id == "result_integrity" && !gate.passed));
}
