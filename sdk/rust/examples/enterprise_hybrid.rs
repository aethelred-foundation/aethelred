//! Enterprise Hybrid Compute Job -- The Recommended Path (Rust SDK)
//!
//! Demonstrates the full enterprise lifecycle:
//!   1. Configure enterprise client
//!   2. Submit a hybrid job (TEE + zkML -- the default)
//!   3. Poll for completion
//!   4. Fetch the evidence bundle
//!   5. Verify the audit trail

use std::time::Duration;

// In a real project these come from `aethelred_sdk::*`
// use aethelred_sdk::{AethelredClient, Config, jobs::SubmitJobRequest};

fn main() {
    println!("{}", "=".repeat(60));
    println!("  Enterprise Hybrid Verification -- Rust SDK");
    println!("{}", "=".repeat(60));
    println!();

    // -- Step 1: Configure enterprise client -------------------
    //
    // let config = Config::testnet();
    // let client = AethelredClient::new(config).await?;
    println!("[1/5] Client configured (testnet)");

    // -- Step 2: Submit a hybrid job (the default) -------------
    //
    // proof_type is omitted -- the SDK fills in ProofTypeHybrid.
    //
    // let response = client.jobs().submit(SubmitJobRequest {
    //     model_hash: "0xabc123...".into(),
    //     input_hash: "0xdef456...".into(),
    //     proof_type: None, // defaults to HYBRID
    //     priority: Some(5),
    //     max_gas: None,
    //     timeout_blocks: Some(100),
    // }).await?;
    println!("[2/5] Submitted enterprise hybrid job");
    println!("      proof_type = HYBRID (TEE attestation + zkML proof)");

    // -- Step 3: Poll for completion ---------------------------
    //
    // let job = client.jobs().wait_for_completion(
    //     &response.job_id,
    //     Duration::from_secs(2),
    //     Duration::from_secs(120),
    // ).await?;
    println!("[3/5] Polling for completion (timeout 120 s)...");

    // -- Step 4: Fetch evidence bundle -------------------------
    //
    // let seal = client.seals().get(&job.metadata["seal_id"]).await?;
    println!("[4/5] Evidence bundle contains TEE attestation + zkML proof + on-chain seal");

    // -- Step 5: Verify audit trail ----------------------------
    //
    // let result = client.verification().verify_seal(&seal.id).await?;
    println!("[5/5] Audit trail verified");

    println!();
    println!("{}", "=".repeat(60));
    println!("  Enterprise hybrid flow complete.");
    println!();
    println!("  Why HYBRID is the enterprise default:");
    println!("    - TEE gives fast hardware attestation (~1 s)");
    println!("    - zkML adds a mathematical proof (~30 s)");
    println!("    - Together they satisfy SOC 2 / HIPAA / GDPR audits");
    println!("    - The Digital Seal anchors both proofs on-chain");
    println!("{}", "=".repeat(60));
}
