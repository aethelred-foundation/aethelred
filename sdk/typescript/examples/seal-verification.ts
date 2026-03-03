/**
 * Digital Seal Verification Example
 *
 * This example demonstrates how to create, verify, and audit
 * Digital Seals for AI computations.
 *
 * Run with: npx ts-node examples/seal-verification.ts
 */

import { AethelredClient, utils } from '../src';
import { DirectSecp256k1HdWallet } from '@cosmjs/proto-signing';

async function main() {
  console.log('='.repeat(60));
  console.log('     Aethelred Digital Seal Verification Example');
  console.log('='.repeat(60));
  console.log();

  // For creating seals, we need a signer
  // In production, use your actual mnemonic securely
  const DEMO_MNEMONIC = process.env.MNEMONIC || 'demo mnemonic not set';

  let client: any;

  if (DEMO_MNEMONIC !== 'demo mnemonic not set') {
    // Connect with signer for full functionality
    const wallet = await DirectSecp256k1HdWallet.fromMnemonic(DEMO_MNEMONIC, {
      prefix: 'aethelred',
    });
    client = await AethelredClient.connectWithSigner(
      { rpcUrl: 'https://testnet-rpc.aethelred.io' },
      wallet
    );
    console.log('✓ Connected with signing capability');
  } else {
    // Connect read-only
    client = await AethelredClient.connectToNetwork('testnet');
    console.log('✓ Connected in read-only mode');
    console.log('  (Set MNEMONIC env var for full functionality)');
  }
  console.log();

  // Part 1: Query existing seals
  console.log('-'.repeat(60));
  console.log('PART 1: Querying Existing Seals');
  console.log('-'.repeat(60));

  const sealList = await client.seal.listSeals({
    limit: 5,
    status: 'active',
  });

  console.log(`\nFound ${sealList.total} total seals`);
  console.log(`Showing ${sealList.seals.length} active seals:\n`);

  for (const seal of sealList.seals) {
    console.log(`Seal: ${seal.id}`);
    console.log(`  Status: ${seal.status}`);
    console.log(`  Purpose: ${seal.purpose}`);
    console.log(`  Model: ${seal.modelCommitment.slice(0, 16)}...`);
    console.log(`  Block: ${seal.blockHeight}`);
    console.log(`  Validators: ${seal.validators?.length || 0}`);
    console.log();
  }

  // Part 2: Verify a seal
  if (sealList.seals.length > 0) {
    console.log('-'.repeat(60));
    console.log('PART 2: Verifying a Seal');
    console.log('-'.repeat(60));

    const sealToVerify = sealList.seals[0];
    console.log(`\nVerifying seal: ${sealToVerify.id}`);

    const verification = await client.seal.verifySeal(sealToVerify.id);

    console.log('\nVerification Result:');
    console.log(`  Valid: ${verification.valid ? '✅ Yes' : '❌ No'}`);
    console.log(`  Integrity: ${verification.integrityValid ? '✅ Valid' : '❌ Invalid'}`);
    console.log(`  Signatures: ${verification.signaturesValid ? '✅ Valid' : '❌ Invalid'}`);
    console.log(`  On-Chain: ${verification.onChainValid ? '✅ Confirmed' : '❌ Not found'}`);
    console.log(`  Not Revoked: ${verification.notRevoked ? '✅ Active' : '⚠️ Revoked'}`);

    if (verification.details) {
      console.log('\nDetails:');
      console.log(`  Verified At: ${verification.details.verifiedAt}`);
      console.log(`  Block Height: ${verification.details.blockHeight}`);
    }

    // Quick verify
    const quickResult = await client.seal.quickVerify(sealToVerify.id);
    console.log(`\nQuick Verify: ${quickResult ? '✅ Valid' : '❌ Invalid'}`);
  }

  // Part 3: Generate audit report
  if (sealList.seals.length > 0) {
    console.log('\n' + '-'.repeat(60));
    console.log('PART 3: Generating Audit Report');
    console.log('-'.repeat(60));

    const sealForAudit = sealList.seals[0];
    console.log(`\nGenerating audit for seal: ${sealForAudit.id}`);

    const audit = await client.seal.generateAuditReport({
      sealId: sealForAudit.id,
      format: 'full',
      includeEvidence: true,
      includeTimeline: true,
    });

    console.log('\nAudit Report:');
    console.log(`  Report ID: ${audit.id}`);
    console.log(`  Generated: ${audit.generatedAt}`);
    console.log(`  Status: ${audit.status}`);

    if (audit.compliance) {
      console.log(`\n  Compliance:`);
      for (const [framework, status] of Object.entries(audit.compliance)) {
        console.log(`    ${framework}: ${status ? '✅' : '❌'}`);
      }
    }

    if (audit.timeline && audit.timeline.length > 0) {
      console.log(`\n  Timeline:`);
      for (const event of audit.timeline.slice(0, 5)) {
        console.log(`    ${event.timestamp}: ${event.event}`);
      }
    }
  }

  // Part 4: Hash verification
  console.log('\n' + '-'.repeat(60));
  console.log('PART 4: Hash Utilities Demo');
  console.log('-'.repeat(60));

  // Simulate model and input hashing
  const sampleModel = Buffer.from('sample model weights data');
  const sampleInput = { feature1: 0.5, feature2: 0.8, feature3: 100 };
  const sampleOutput = { score: 750, decision: 'approved' };

  const modelHash = utils.sha256(sampleModel);
  const inputHash = utils.hashInput(sampleInput);
  const outputHash = utils.hashOutput(sampleOutput);

  console.log('\nHash Examples:');
  console.log(`  Model Hash: ${modelHash.slice(0, 32)}...`);
  console.log(`  Input Hash: ${inputHash.slice(0, 32)}...`);
  console.log(`  Output Hash: ${outputHash.slice(0, 32)}...`);

  // Commitment scheme
  const { commitment, salt } = utils.createCommitment('sensitive data');
  console.log(`\nCommitment Scheme:`);
  console.log(`  Commitment: ${commitment.slice(0, 32)}...`);
  console.log(`  Salt: ${salt.slice(0, 16)}...`);

  const verified = utils.verifyCommitment('sensitive data', salt, commitment);
  console.log(`  Verified: ${verified ? '✅ Yes' : '❌ No'}`);

  // Merkle tree
  const items = ['tx1', 'tx2', 'tx3', 'tx4'];
  const merkleRoot = utils.createMerkleRoot(items);
  const proof = utils.createMerkleProof(items, 1);
  const merkleValid = utils.verifyMerkleProof('tx2', proof, merkleRoot, 1);

  console.log(`\nMerkle Tree:`);
  console.log(`  Root: ${merkleRoot.slice(0, 32)}...`);
  console.log(`  Proof for 'tx2': Valid = ${merkleValid ? '✅ Yes' : '❌ No'}`);

  // Part 5: Create a seal (requires signer)
  if (client.canSign()) {
    console.log('\n' + '-'.repeat(60));
    console.log('PART 5: Creating a New Seal');
    console.log('-'.repeat(60));

    console.log('\nCreating seal for verified AI computation...');

    try {
      const sealResponse = await client.seal.createSeal({
        modelHash,
        inputHash,
        outputHash,
        purpose: 'demo_verification',
        metadata: {
          sdk_example: 'true',
          demo_run: new Date().toISOString(),
        },
      });

      console.log('\nSeal Created:');
      console.log(`  Seal ID: ${sealResponse.sealId}`);
      console.log(`  Status: ${sealResponse.status}`);
      console.log(`  TX Hash: ${sealResponse.txHash}`);

      // Wait for seal to be finalized
      console.log('\nWaiting for seal finalization...');
      const finalSeal = await client.seal.waitForStatus(
        sealResponse.sealId,
        'active',
        30000
      );
      console.log(`Seal finalized at block ${finalSeal.blockHeight}`);
    } catch (error) {
      console.log(`Error creating seal: ${error}`);
    }
  } else {
    console.log('\n(Skipping seal creation - no signer available)');
  }

  // Summary
  console.log('\n' + '='.repeat(60));
  console.log('EXAMPLE COMPLETE');
  console.log('='.repeat(60));
  console.log(`
Key Takeaways:

1. Digital Seals provide cryptographic proof of AI computations
2. Seals can be verified independently by anyone
3. Audit reports enable regulatory compliance
4. Hash utilities ensure data integrity
5. Merkle proofs enable efficient batch verification
`);

  // Cleanup
  client.disconnect();
}

main().catch(console.error);
