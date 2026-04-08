/**
 * Credit Scoring Demo Example
 *
 * This example demonstrates a credit scoring verification workflow
 * using the Aethelred SDK: submit a job for a credit scoring model,
 * poll for completion, and verify the resulting seal.
 *
 * Run with: npx ts-node examples/credit-scoring-demo.ts
 */

import {
  AethelredClient,
  Network,
  ProofType,
  AethelredError,
  ConnectionError,
  JobError,
  SealError,
} from '../src';

async function main() {
  console.log('='.repeat(70));
  console.log('       AETHELRED CREDIT SCORING VERIFICATION DEMO');
  console.log('='.repeat(70));
  console.log();
  console.log('This demo shows how Aethelred cryptographically verifies');
  console.log('AI-powered credit scoring decisions using TEE + zkML.');
  console.log();

  // Connect to testnet
  const client = new AethelredClient({ network: Network.TESTNET });

  const healthy = await client.healthCheck();
  console.log(`Node health: ${healthy ? 'OK' : 'UNREACHABLE'}\n`);

  // ── Step 1: List Available Models ─────────────────────────
  console.log('-'.repeat(70));
  console.log('STEP 1: Available Credit Scoring Models');
  console.log('-'.repeat(70));

  let selectedModelHash = '0x...'; // Placeholder

  try {
    const models = await client.models.list({ status: 'active' });
    console.log(`\nFound ${models.length} active models\n`);

    for (const model of models.slice(0, 3)) {
      console.log(`  ${model.name} v${model.version}`);
      console.log(`    Hash: ${model.modelHash.slice(0, 16)}...`);
      console.log(`    Usage: ${model.usageCount} runs`);
      console.log();
    }

    if (models.length > 0) {
      selectedModelHash = models[0].modelHash;
    }
  } catch (err) {
    if (err instanceof AethelredError) {
      console.log(`  Error listing models: ${err.message}\n`);
    } else {
      throw err;
    }
  }

  // ── Step 2: Submit Credit Scoring Jobs ─────────────────────
  console.log('='.repeat(70));
  console.log('STEP 2: RUNNING VERIFICATION DEMO');
  console.log('='.repeat(70));

  // Define three demo credit profiles
  const profiles = [
    {
      label: 'EXCELLENT',
      loanAmount: 50000,
      features: {
        payment_history: 0.98,
        credit_utilization: 0.15,
        credit_history_months: 180,
        num_accounts: 12,
        recent_inquiries: 0,
        derogatory_marks: 0,
        total_debt: 25000,
        annual_income: 150000,
      },
    },
    {
      label: 'FAIR',
      loanAmount: 15000,
      features: {
        payment_history: 0.85,
        credit_utilization: 0.55,
        credit_history_months: 48,
        num_accounts: 5,
        recent_inquiries: 3,
        derogatory_marks: 1,
        total_debt: 18000,
        annual_income: 65000,
      },
    },
    {
      label: 'POOR',
      loanAmount: 5000,
      features: {
        payment_history: 0.60,
        credit_utilization: 0.90,
        credit_history_months: 12,
        num_accounts: 2,
        recent_inquiries: 7,
        derogatory_marks: 3,
        total_debt: 30000,
        annual_income: 35000,
      },
    },
  ];

  for (const profile of profiles) {
    console.log(`\n${'_'.repeat(70)}`);
    console.log(`  SCENARIO: ${profile.label} CREDIT PROFILE`);
    console.log(`${'_'.repeat(70)}`);

    // Build a deterministic input hash from the features
    const inputHash = `0x${Buffer.from(JSON.stringify(profile.features)).toString('hex').slice(0, 64)}`;

    console.log(`\n  Input hash : ${inputHash.slice(0, 32)}...`);
    console.log(`  Loan amount: $${profile.loanAmount.toLocaleString()}`);

    try {
      // Submit a compute job for this credit profile
      console.log(`\n  Submitting for verified scoring...`);

      const submitResponse = await client.jobs.submit({
        modelHash: selectedModelHash,
        inputHash,
        purpose: `credit_scoring_${profile.label.toLowerCase()}`,
        proofType: ProofType.HYBRID,
        priority: 'normal',
        metadata: {
          loan_type: 'personal',
          loan_amount: String(profile.loanAmount),
          loan_term_months: '36',
          profile_category: profile.label,
          demo: 'true',
        },
      });

      console.log(`  Job ID : ${submitResponse.jobId}`);
      console.log(`  TX Hash: ${submitResponse.txHash}`);

      // Poll for completion
      console.log(`\n  Waiting for verified result...`);

      const completedJob = await client.jobs.waitForCompletion(
        submitResponse.jobId,
        { timeout: 120_000, pollInterval: 2000 },
      );

      console.log(`\n  VERIFIED RESULT:`);
      console.log(`     Status      : ${completedJob.status}`);
      console.log(`     Proof Type  : ${completedJob.proofType}`);

      if (completedJob.result) {
        console.log(`     Output Hash : ${completedJob.result.outputHash}`);
        console.log(`     Exec Time   : ${completedJob.result.executionTimeMs}ms`);
      }

      if (completedJob.validatorAddress) {
        console.log(`     Validator   : ${completedJob.validatorAddress}`);
      }

      // Verify the seal if one was created
      if (completedJob.metadata?.seal_id) {
        console.log(`\n  SEAL VERIFICATION:`);
        console.log(`     Seal ID: ${completedJob.metadata.seal_id}`);

        try {
          const verification = await client.verification.verify_seal(
            completedJob.metadata.seal_id,
          );
          console.log(`     Valid  : ${verification.valid ? 'Yes' : 'No'}`);
          console.log(`     Proof  : ${verification.proofVerified ?? 'N/A'}`);
          console.log(`     TEE    : ${verification.teeVerified ?? 'N/A'}`);
        } catch (sealErr) {
          if (sealErr instanceof SealError) {
            console.log(`     Seal verification error: ${sealErr.message}`);
          } else {
            console.log(`     Verification error: ${sealErr}`);
          }
        }
      }
    } catch (err) {
      if (err instanceof JobError) {
        console.log(`  Job error: ${err.message}`);
      } else if (err instanceof ConnectionError) {
        console.log(`  Connection error: ${err.message}`);
      } else if (err instanceof AethelredError) {
        console.log(`  Error: ${err.message}`);
      } else {
        throw err;
      }
    }
  }

  // ── Step 3: Query All Recent Jobs ─────────────────────────
  console.log('\n' + '='.repeat(70));
  console.log('STEP 3: RECENT JOBS SUMMARY');
  console.log('='.repeat(70));

  try {
    const jobs = await client.jobs.list({ limit: 10 });
    console.log(`\n  Total jobs on network: ${jobs.total}`);
    console.log(`  Showing: ${jobs.jobs.length}\n`);

    for (const job of jobs.jobs) {
      const statusTag =
        job.status === 'completed' ? '[OK]' :
        job.status === 'failed'    ? '[FAIL]' :
        `[${job.status.toUpperCase()}]`;
      console.log(`  ${statusTag} ${job.id} (${job.proofType})`);
    }
  } catch (err) {
    if (err instanceof AethelredError) {
      console.log(`  Error listing jobs: ${err.message}`);
    } else {
      throw err;
    }
  }

  // Summary
  console.log('\n' + '='.repeat(70));
  console.log('DEMO SUMMARY');
  console.log('='.repeat(70));
  console.log(`
  This demonstration showed how Aethelred:

  1. Receives loan application with credit features
  2. Executes AI model in secure TEE enclave
  3. Generates cryptographic attestation of computation
  4. Optionally creates zkML proof for mathematical verification
  5. Achieves consensus across multiple validators
  6. Creates immutable Digital Seal for audit trail

  Key Benefits:
    Regulatory Compliance  - Auditable proof of AI decisions
    Tamper-Proof           - Cryptographic guarantees of integrity
    Privacy-Preserving     - Input data never leaves secure enclave
    Fast                   - Sub-second verification for real-time decisions
`);

  console.log('='.repeat(70));
}

main().catch(console.error);
