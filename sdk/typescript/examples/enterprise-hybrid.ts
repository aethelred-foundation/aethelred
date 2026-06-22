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

import { AethelredClient, type EvidenceBundle } from '../src';

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
    rpcUrl: process.env.AETHELRED_RPC_URL ?? 'https://rpc.testnet.aethelred.io',
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
  // For a HYBRID job the canonical evidence bundle contains:
  //   - TEE attestation
  //   - zkML proof
  //   - Digital Seal ID and validator signature
  //   - archive pointer and verification flags

  console.log('[4/5] Fetching evidence bundle...');

  const bundle = await client.seals.exportEvidenceBundle(submitResponse.jobId);
  assertPilotEvidenceBundle(bundle);

  if (completedJob.metadata?.seal_id && completedJob.metadata.seal_id !== bundle.seal_id) {
    throw new Error('completed job seal_id does not match evidence bundle seal_id');
  }

  console.log(`      Bundle ID      : ${bundle.bundle_id}`);
  console.log(`      Chain ID       : ${bundle.chain_id}`);
  console.log(`      Seal ID        : ${bundle.seal_id}`);
  console.log(`      TEE Platform   : ${bundle.tee_evidence.platform}`);
  console.log(`      Proof System   : ${bundle.zkml_evidence.proof_system}`);
  console.log(`      Archive        : ${bundle.archive_pointer.archive_type}/${bundle.archive_pointer.index}`);
  console.log(`      Confidence     : ${bundle.confidence_score}`);
  console.log(`      Validator Sig  : ${bundle.validator_signature.slice(0, 16)}...`);
  console.log();

  // ── Step 5: Verify the audit trail ─────────────────────────
  //
  // The verification module checks the seal's on-chain integrity,
  // TEE attestation freshness, and zkML proof soundness.

  console.log('[5/5] Verifying audit trail...');

  const verification = await client.seals.verify(bundle.seal_id);
  console.log(`      On-chain valid : ${verification.valid}`);
  console.log(`      Proof checked  : ${verification.verificationDetails?.zkml ?? bundle.verification.zkml_proof_verified}`);
  console.log(`      TEE checked    : ${verification.verificationDetails?.tee ?? bundle.verification.tee_attestation_verified}`);

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

function assertPilotEvidenceBundle(bundle: EvidenceBundle): void {
  if (bundle.policy_decision.mode !== 'hybrid') {
    throw new Error('enterprise evidence bundle must use hybrid policy mode');
  }
  if (bundle.policy_decision.require_both !== true || bundle.policy_decision.fallback_allowed !== false) {
    throw new Error('enterprise evidence bundle must require both TEE and zkML with fallback disabled');
  }
  if (!bundle.chain_id || !bundle.seal_id || !bundle.validator_signature) {
    throw new Error('enterprise evidence bundle is missing chain_id, seal_id, or validator_signature');
  }
  if (bundle.confidence_score < 0 || bundle.confidence_score > 1) {
    throw new Error('enterprise evidence bundle confidence_score must be between 0 and 1');
  }
  if (!bundle.archive_pointer.document_id || !bundle.archive_pointer.uri) {
    throw new Error('enterprise evidence bundle archive pointer is incomplete');
  }
  if (!bundle.verification.schema_verified || !bundle.verification.policy_verified) {
    throw new Error('enterprise evidence bundle must pass schema and policy verification');
  }
}
