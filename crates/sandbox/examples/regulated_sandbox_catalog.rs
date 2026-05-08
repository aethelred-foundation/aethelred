use aethelred_sandbox::{
    execute_sandbox_run, regulated_sandbox_catalog, run_adversarial_suite, SandboxRunConfig,
};

fn main() {
    let catalog = regulated_sandbox_catalog();
    if std::env::args().any(|arg| arg == "--json") {
        let reports = catalog
            .iter()
            .map(|sandbox| {
                execute_sandbox_run(
                    sandbox,
                    &SandboxRunConfig::happy_path(sandbox.hero_scenario),
                )
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string_pretty(&reports).expect("sandbox reports should serialize")
        );
        return;
    }

    for sandbox in catalog {
        let happy_path = execute_sandbox_run(
            &sandbox,
            &SandboxRunConfig::happy_path(sandbox.hero_scenario),
        );
        let adversarial_reports = run_adversarial_suite(&sandbox);
        let blocked_count = adversarial_reports
            .iter()
            .filter(|report| !report.passed())
            .count();

        println!("{} [{}]", sandbox.label, sandbox.id);
        println!("  Hero scenario: {}", sandbox.hero_scenario);
        println!("  Decision: {:?}", happy_path.decision);
        println!("  Seal: {}", happy_path.evidence_record.digital_seal_id);
        println!(
            "  Adversarial coverage: {}/{} blocked or escalated",
            blocked_count,
            adversarial_reports.len()
        );
        println!("  LOI ask: {}", sandbox.loi_conversion_ask);
        println!();
    }
}
