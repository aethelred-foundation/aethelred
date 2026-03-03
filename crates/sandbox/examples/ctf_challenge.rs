//! CTF Challenge Demo
//!
//! This example demonstrates the Capture The Flag mode,
//! showing how security researchers can compete to find vulnerabilities.

use aethelred_infinity_sandbox::ctf::*;

fn main() {
    println!("\n🚩 AETHELRED CAPTURE THE FLAG\n");
    println!("   Welcome to the Aethelred Security Challenge!");
    println!("   Find vulnerabilities. Capture flags. Earn rewards.\n");

    // Create CTF engine
    let mut ctf = CTFEngine::new();

    // Register players
    let player1 = ctf.register_player("CryptoNinja42".to_string());
    let player2 = ctf.register_player("ZKMLHacker".to_string());
    let player3 = ctf.register_player("QuantumSleuth".to_string());

    println!("👤 Players registered:");
    println!("   - CryptoNinja42");
    println!("   - ZKMLHacker");
    println!("   - QuantumSleuth\n");

    // Show available challenges
    println!("{}", ctf.generate_ui(None));

    // Start a challenge
    println!("\n📍 CryptoNinja42 starts 'Break the Lazy Prover' challenge...\n");
    let session1 = ctf.start_challenge(&player1, "lazy_prover").unwrap();

    // Show challenge details
    println!("{}", ctf.generate_ui(Some("lazy_prover")));

    // Player submits wrong flag
    println!("\n🔑 CryptoNinja42 tries: 'wrong_flag'");
    let result = ctf.submit_flag(&session1, "wrong_flag").unwrap();
    println!("   Result: {}\n", result.message);

    // Player 2 starts a different challenge
    let session2 = ctf.start_challenge(&player2, "compliance_maze").unwrap();

    // Player 2 gets it right first!
    println!("🔑 ZKMLHacker tries: 'AETHEL{{found_the_route}}'");
    let result = ctf.submit_flag(&session2, "AETHEL{found_the_route}").unwrap();
    println!("   Result: {}", result.message);
    println!("   Points earned: {}", result.points_earned);
    if result.first_blood {
        println!("   🩸 FIRST BLOOD!\n");
    }

    // Player 1 finally solves their challenge
    let session3 = ctf.start_challenge(&player1, "q_day_prep").unwrap();
    println!("🔑 CryptoNinja42 tries: 'AETHEL{{dilithium3_saved_us}}'");
    let result = ctf
        .submit_flag(&session3, "AETHEL{dilithium3_saved_us}")
        .unwrap();
    println!("   Result: {}", result.message);
    println!("   Points earned: {}\n", result.points_earned);

    // Player 3 joins late
    let session4 = ctf.start_challenge(&player3, "compliance_maze").unwrap();
    println!("🔑 QuantumSleuth tries: 'AETHEL{{uae_sg_route}}'");
    let result = ctf.submit_flag(&session4, "AETHEL{uae_sg_route}").unwrap();
    println!("   Result: {}", result.message);
    println!(
        "   Points earned: {} (no first blood bonus)\n",
        result.points_earned
    );

    // Show final leaderboard
    println!("\n🏆 FINAL LEADERBOARD\n");
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Rank  │  Player         │  Points  │  Flags  │  Badges   ║");
    println!("╠════════════════════════════════════════════════════════════╣");

    for entry in ctf.get_leaderboard() {
        let medal = match entry.rank {
            1 => "🥇",
            2 => "🥈",
            3 => "🥉",
            _ => "  ",
        };
        println!(
            "║  {} {:2}  │  {:14} │  {:>5}   │    {:>2}    │  {}    ║",
            medal,
            entry.rank,
            entry.username,
            entry.points,
            entry.flags,
            entry.badges.join(" ")
        );
    }

    println!("╚════════════════════════════════════════════════════════════╝");

    println!("\n🎉 CTF Demo Complete!");
    println!("   In a real deployment, players would:");
    println!("   - Analyze actual zkML proofs for vulnerabilities");
    println!("   - Attempt to break TEE enclaves");
    println!("   - Find compliance bypass routes");
    println!("   - Earn AETHEL tokens for successful exploits");
}
