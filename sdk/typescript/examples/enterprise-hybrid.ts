/**
 * Enterprise Hybrid Compute Job — The Recommended Path
 *
 * This is the primary enterprise example. It demonstrates the full lifecycle:
 *   1. Configure enterprise mode
 *   2. Submit a hybrid job (TEE + zkML — the default)
 *   3. Poll for completion
 *   4. Fetch the evidence bundle (seal + attestation + proof)
 *   5. Verify the audit trail
 *
 * Run with: npx ts-node examples/enterprise-hybrid.ts
 */

import { AethelredClient, ProofType } from '../src';

async function main() {
  console.log('='.repeat(60));
  console.log('  Enterprise Hybrid Verification — Recommended Path');
  console.log('='.repeat(60));
  console.log();

  // ── Step 1: Configure enterprise mode ──────────────────────
  //
  // The SDK defaults proofType to HYBRID. No special flag needed;
  // just instantiate a client and submit jobs.

  const client = new AethelredClient({
    rpcUrl: process.env.AETHELRED_RPC_URL ?? 'https://rpc.testnet.aethelred.network',
    apiKey: process.env.AETHELRED_API_KEY,
  });

  const healthy = await client.healthCheck();
  console.log(`[1/5] Node health: ${healthy ? 'OK' : 'UNREACHABLE'}\n`);

  // ── Step 2: Submit a hybrid job (the default) ──────────────
  //
  // proofType is omitted deliberately — the SDK fills in HYBRID.

  const modelHash = '0xabc123...'; // Replace with real model hash
  const inputHash = '0xdef456...'; // Replace with real input hash

  console.log('[2/5] Submitting enterprise hybrid job...');
  console.log('      proof_type = HYBRID (TEE attestation + zkML proof)');

  const submitResponse = await client.jobs.submit({
    modelHash,
    inputHash,
    // proofType is intentionally omitted — defaults to HYBRID
    metadata: {
      compliance_framework: 'SOC2',
      enterprise_tier: 'production',
    },
  });

  console.log(`      Job ID : ${submitResponse.jobId}`);
  console.log(`      TX Hash: ${submitResponse.txHash}\n`);

  // ── Step 3: Poll for completion ────────────────────────────

  console.log('[3/5] Polling for completion (timeout 120s)...');
  const completedJob = await client.jobs.waitForCompletion(
    submitResponse.jobId,
    { pollInterval: 2000, timeout: 120_000 },
  );

  console.log(`      Status         : ${completedJob.status}`);
  console.log(`      Proof Type     : ${completedJob.proofType}`);
  console.log(`      Validator      : ${completedJob.validatorAddress ?? 'N/A'}`);
  console.log();

  // ── Step 4: Fetch the evidence bundle ──────────────────────
  //
  // For a HYBRID job the evidence bundle contains:
  //   • TEE attestation (platform, enclave hash, quote)
  //   • zkML proof (proof bytes, public inputs, verifying key hash)
  //   • Digital Seal anchored on-chain

  console.log('[4/5] Fetching evidence bundle...');

  if (completedJob.metadata?.seal_id) {
    const seal = await client.seals.get(completedJob.metadata.seal_id);
    console.log(`      Seal ID        : ${seal.id}`);
    console.log(`      Seal Status    : ${seal.status}`);

    if (seal.teeAttestation) {
      console.log(`      TEE Platform   : ${seal.teeAttestation.platform}`);
      console.log(`      Enclave Hash   : ${seal.teeAttestation.enclaveHash.slice(0, 16)}...`);
    }
    if (seal.zkmlProof) {
      console.log(`      Proof System   : ${seal.zkmlProof.proofSystem}`);
      console.log(`      Public Inputs  : ${seal.zkmlProof.publicInputs.length} elements`);
    }
  } else {
    console.log('      (No seal returned — expected in testnet dry-run mode)');
  }
  console.log();

  // ── Step 5: Verify the audit trail ─────────────────────────
  //
  // The verification module checks the seal's on-chain integrity,
  // TEE attestation freshness, and zkML proof soundness.

  console.log('[5/5] Verifying audit trail...');

  if (completedJob.metadata?.seal_id) {
    const verification = await client.verification.verifySeal(
      completedJob.metadata.seal_id,
    );
    console.log(`      On-chain valid : ${verification.valid}`);
    console.log(`      Proof checked  : ${verification.proofVerified ?? 'N/A'}`);
    console.log(`      TEE checked    : ${verification.teeVerified ?? 'N/A'}`);
  } else {
    console.log('      (Skipped — no seal to verify in dry-run)');
  }

  console.log();
  console.log('='.repeat(60));
  console.log('  Enterprise hybrid flow complete.');
  console.log();
  console.log('  Why HYBRID is the enterprise default:');
  console.log('    - TEE gives fast hardware attestation (~1 s)');
  console.log('    - zkML adds a mathematical proof (~30 s)');
  console.log('    - Together they satisfy SOC 2 / HIPAA / GDPR audits');
  console.log('    - The Digital Seal anchors both proofs on-chain');
  console.log('='.repeat(60));
}

main().catch(console.error);
