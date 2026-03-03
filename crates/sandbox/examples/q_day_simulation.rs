//! Q-Day Simulation
//!
//! This example demonstrates the Quantum Time-Machine feature,
//! simulating what happens when quantum computers can break ECDSA.

use aethelred_infinity_sandbox::quantum::*;

fn main() {
    println!("\n{}", QuantumThreatTimeline::display());

    // Create the Quantum Time Machine
    let mut machine = QuantumTimeMachine::new();

    // Load demo assets
    machine.load_demo_assets();

    println!("\n📊 Before Q-Day:\n");
    println!("{}", machine.generate_report());

    println!("\n");
    println!("╔═══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                                                                               ║");
    println!("║                    Press ENTER to simulate Q-Day...                           ║");
    println!("║                                                                               ║");
    println!("╚═══════════════════════════════════════════════════════════════════════════════╝");
    println!("\n");

    // In a real demo, we'd wait for input
    // For this example, we just proceed

    // ACTIVATE Q-DAY!
    println!("🔴 ACTIVATING QUANTUM TIME-MACHINE...\n");

    let results = machine.activate_q_day();

    println!("{}", machine.generate_report());

    // Summary
    println!("\n📊 Q-Day Impact Summary:");
    println!("   Total assets: {}", results.total_assets);
    println!(
        "   🔴 Broken:    {} ({:.1}%)",
        results.broken_assets,
        (results.broken_assets as f64 / results.total_assets.max(1) as f64) * 100.0
    );
    println!(
        "   🟢 Secure:    {} ({:.1}%)",
        results.secure_assets,
        (results.secure_assets as f64 / results.total_assets.max(1) as f64) * 100.0
    );

    println!("\n💰 Value at Risk:");
    println!(
        "   Vulnerable: ${:>15.2}M",
        results.value_at_risk.vulnerable as f64 / 100.0 / 1_000_000.0
    );
    println!(
        "   Protected:  ${:>15.2}M",
        results.value_at_risk.secure as f64 / 100.0 / 1_000_000.0
    );
    println!(
        "   Protection Ratio: {:.1}%",
        results.value_at_risk.protection_ratio * 100.0
    );

    println!("\n🛡️  Aethelred Protection:");
    println!(
        "   Digital Seals Protected: {}",
        results.aethelred_protection.seals_protected
    );
    println!(
        "   Hybrid Signatures:       {}",
        results.aethelred_protection.hybrid_signatures
    );
    println!(
        "   Migration Ready:         {}",
        if results.aethelred_protection.can_migrate {
            "YES"
        } else {
            "NO"
        }
    );

    println!("\n✅ Simulation Complete!");
    println!("   The simulation shows that Aethelred's Digital Seals using Dilithium3");
    println!("   remain secure even after quantum computers break ECDSA.");
}
