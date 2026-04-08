/**
 * Digital Seal Verification Example
 *
 * This example demonstrates how to query, verify, and inspect
 * Digital Seals for AI computations using both online (client.verification)
 * and offline (verifySealOffline) approaches.
 *
 * Run with: npx ts-node examples/seal-verification.ts
 */

import {
  AethelredClient,
  Network,
  AethelredError,
  ConnectionError,
  SealError,
  verifySealOffline,
  fingerprintSealSha256,
} from '../src';

async function main() {
  console.log('='.repeat(60));
  console.log('     Aethelred Digital Seal Verification Example');
  console.log('='.repeat(60));
  console.log();

  // Connect to testnet
  const client = new AethelredClient({ network: Network.TESTNET });

  const healthy = await client.healthCheck();
  console.log(`Node health: ${healthy ? 'OK' : 'UNREACHABLE'}\n`);

  // ── Part 1: Query Existing Seals ──────────────────────────
  console.log('-'.repeat(60));
  console.log('PART 1: Querying Existing Seals');
  console.log('-'.repeat(60));

  let sealList: { total: number; seals: any[] } = { total: 0, seals: [] };

  try {
    sealList = await client.seals.list({
      limit: 5,
      status: 'active',
    });

    console.log(`\nFound ${sealList.total} total seals`);
    console.log(`Showing ${sealList.seals.length} active seals:\n`);

    for (const seal of sealList.seals) {
      console.log(`Seal: ${seal.id}`);
      console.log(`  Status: ${seal.status}`);
      console.log(`  Purpose: ${seal.purpose}`);
      console.log(`  Model: ${seal.modelCommitment?.slice(0, 16) ?? 'N/A'}...`);
      console.log(`  Block: ${seal.blockHeight}`);
      console.log(`  Validators: ${seal.validators?.length ?? 0}`);
      console.log();
    }
  } catch (err) {
    if (err instanceof ConnectionError) {
      console.log(`  Could not reach node: ${err.message}\n`);
    } else if (err instanceof AethelredError) {
      console.log(`  Error querying seals: ${err.message}\n`);
    } else {
      throw err;
    }
  }

  // ── Part 2: Online Verification (via client.verification) ─
  if (sealList.seals.length > 0) {
    console.log('-'.repeat(60));
    console.log('PART 2: Online Seal Verification');
    console.log('-'.repeat(60));

    const sealToVerify = sealList.seals[0];
    console.log(`\nVerifying seal on-chain: ${sealToVerify.id}`);

    try {
      const verification = await client.verification.verify_seal(sealToVerify.id);

      console.log('\nVerification Result:');
      console.log(`  Valid       : ${verification.valid ? 'Yes' : 'No'}`);
      console.log(`  On-chain   : ${verification.onChainValid ? 'Confirmed' : 'Not found'}`);
      console.log(`  Proof OK   : ${verification.proofVerified ?? 'N/A'}`);
      console.log(`  TEE OK     : ${verification.teeVerified ?? 'N/A'}`);

      if (verification.details) {
        console.log(`  Verified At: ${verification.details.verifiedAt}`);
        console.log(`  Block      : ${verification.details.blockHeight}`);
      }
    } catch (err) {
      if (err instanceof SealError) {
        console.log(`  Seal error: ${err.message}`);
      } else if (err instanceof AethelredError) {
        console.log(`  Verification error: ${err.message}`);
      } else {
        throw err;
      }
    }
  }

  // ── Part 3: Offline Verification (via devtools) ───────────
  if (sealList.seals.length > 0) {
    console.log('\n' + '-'.repeat(60));
    console.log('PART 3: Offline Seal Verification');
    console.log('-'.repeat(60));

    const sealForOffline = sealList.seals[0];
    console.log(`\nVerifying seal offline: ${sealForOffline.id}`);

    try {
      // Fetch the full seal object
      const fullSeal = await client.seals.get(sealForOffline.id);

      // Offline verification (no network call needed after fetching)
      const offlineResult = verifySealOffline(fullSeal);
      console.log(`  Offline valid: ${offlineResult.valid ? 'Yes' : 'No'}`);

      if (offlineResult.errors && offlineResult.errors.length > 0) {
        console.log(`  Errors:`);
        for (const e of offlineResult.errors) {
          console.log(`    - ${e}`);
        }
      }

      // Fingerprint the seal
      const fingerprint = fingerprintSealSha256(fullSeal);
      console.log(`  Fingerprint: ${fingerprint.slice(0, 32)}...`);
    } catch (err) {
      if (err instanceof AethelredError) {
        console.log(`  Error: ${err.message}`);
      } else {
        throw err;
      }
    }
  }

  // ── Part 4: Inspect a Specific Seal ───────────────────────
  if (sealList.seals.length > 0) {
    console.log('\n' + '-'.repeat(60));
    console.log('PART 4: Detailed Seal Inspection');
    console.log('-'.repeat(60));

    const sealId = sealList.seals[0].id;
    console.log(`\nFetching full seal: ${sealId}`);

    try {
      const seal = await client.seals.get(sealId);

      console.log(`\nSeal Details:`);
      console.log(`  ID          : ${seal.id}`);
      console.log(`  Status      : ${seal.status}`);
      console.log(`  Purpose     : ${seal.purpose}`);
      console.log(`  Block Height: ${seal.blockHeight}`);
      console.log(`  Created     : ${seal.createdAt}`);

      if (seal.teeAttestation) {
        console.log(`\n  TEE Attestation:`);
        console.log(`    Platform    : ${seal.teeAttestation.platform}`);
        console.log(`    Enclave Hash: ${seal.teeAttestation.enclaveHash?.slice(0, 16)}...`);
      }

      if (seal.zkmlProof) {
        console.log(`\n  zkML Proof:`);
        console.log(`    Proof System : ${seal.zkmlProof.proofSystem}`);
        console.log(`    Public Inputs: ${seal.zkmlProof.publicInputs?.length ?? 0} elements`);
      }
    } catch (err) {
      if (err instanceof SealError) {
        console.log(`  Seal not found: ${err.message}`);
      } else if (err instanceof AethelredError) {
        console.log(`  Error: ${err.message}`);
      } else {
        throw err;
      }
    }
  }

  // ── Part 5: Network Info ──────────────────────────────────
  console.log('\n' + '-'.repeat(60));
  console.log('PART 5: Network Info');
  console.log('-'.repeat(60));

  console.log(`\n  RPC URL  : ${client.getRpcUrl()}`);
  console.log(`  Chain ID : ${client.getChainId()}`);

  // Summary
  console.log('\n' + '='.repeat(60));
  console.log('EXAMPLE COMPLETE');
  console.log('='.repeat(60));
  console.log(`
Key Takeaways:

1. Digital Seals provide cryptographic proof of AI computations
2. Online verification (client.verification) checks on-chain state
3. Offline verification (verifySealOffline) validates locally without RPC
4. fingerprintSealSha256 produces a unique identifier for any seal
5. Both TEE attestations and zkML proofs can be inspected
`);
}

main().catch(console.error);
