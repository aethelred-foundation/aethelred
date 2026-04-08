/**
 * Compute Job Submission Example
 *
 * This example demonstrates how to submit AI computation jobs
 * for verified execution, poll for completion, and inspect results.
 *
 * Run with: npx ts-node examples/compute-job.ts
 */

import {
  AethelredClient,
  Network,
  ProofType,
  AethelredError,
  ConnectionError,
  JobError,
} from '../src';

async function main() {
  console.log('='.repeat(60));
  console.log('     Aethelred Compute Job Example');
  console.log('='.repeat(60));
  console.log();

  // Connect to testnet
  const client = new AethelredClient({ network: Network.TESTNET });

  const healthy = await client.healthCheck();
  console.log(`Node health: ${healthy ? 'OK' : 'UNREACHABLE'}\n`);

  // ── Part 1: Available Models ──────────────────────────────
  console.log('-'.repeat(60));
  console.log('PART 1: Available Models');
  console.log('-'.repeat(60));

  try {
    const models = await client.models.list({ status: 'active' });
    console.log(`\nFound ${models.length} active models:\n`);

    for (const model of models.slice(0, 5)) {
      console.log(`Model: ${model.name} v${model.version}`);
      console.log(`  ID: ${model.modelId}`);
      console.log(`  Hash: ${model.modelHash.slice(0, 16)}...`);
      console.log(`  Status: ${model.status}`);
      console.log(`  Usage Count: ${model.usageCount}`);
      if (model.metrics) {
        console.log(`  AUC-ROC: ${model.metrics.aucRoc.toFixed(3)}`);
      }
      console.log();
    }
  } catch (err) {
    if (err instanceof AethelredError) {
      console.log(`  Error listing models: ${err.message}\n`);
    } else {
      throw err;
    }
  }

  // ── Part 2: Query Recent Jobs ─────────────────────────────
  console.log('-'.repeat(60));
  console.log('PART 2: Recent Jobs');
  console.log('-'.repeat(60));

  try {
    const recentJobs = await client.jobs.list({ limit: 5 });
    console.log(`\nFound ${recentJobs.total} total jobs`);
    console.log(`Showing ${recentJobs.jobs.length} recent jobs:\n`);

    for (const job of recentJobs.jobs) {
      const statusIcon = getStatusIcon(job.status);
      console.log(`Job: ${job.id}`);
      console.log(`  Status: ${statusIcon} ${job.status}`);
      console.log(`  Proof Type: ${job.proofType}`);
      console.log(`  Priority: ${job.priority}`);
      console.log(`  Created: ${job.createdAt}`);
      if (job.result) {
        console.log(`  Output Hash: ${job.result.outputHash.slice(0, 16)}...`);
        console.log(`  Execution Time: ${job.result.executionTimeMs}ms`);
      }
      console.log();
    }
  } catch (err) {
    if (err instanceof AethelredError) {
      console.log(`  Error listing jobs: ${err.message}\n`);
    } else {
      throw err;
    }
  }

  // ── Part 3: Submit a Job ──────────────────────────────────
  console.log('-'.repeat(60));
  console.log('PART 3: Job Submission');
  console.log('-'.repeat(60));

  // Prepare input data
  const inputData = {
    features: {
      payment_history: 0.95,
      credit_utilization: 0.30,
      credit_history_months: 84,
      num_accounts: 5,
      recent_inquiries: 2,
    },
    metadata: {
      application_id: 'demo-123',
      timestamp: new Date().toISOString(),
    },
  };

  const modelHash = '0xabc123...'; // Replace with a real model hash
  const inputHash = '0xdef456...'; // Replace with a real input hash

  console.log(`\nInput prepared:`);
  console.log(`  Model Hash: ${modelHash}`);
  console.log(`  Input Hash: ${inputHash}`);

  try {
    console.log('\nSubmitting job...');

    const response = await client.jobs.submit({
      modelHash,
      inputHash,
      purpose: 'demo_credit_scoring',
      proofType: ProofType.HYBRID,
      priority: 'normal',
      metadata: {
        sdk_example: 'true',
      },
    });

    console.log(`\nJob Submitted:`);
    console.log(`  Job ID: ${response.jobId}`);
    console.log(`  Status: ${response.status}`);
    console.log(`  TX Hash: ${response.txHash}`);

    // Poll for completion
    console.log('\nWaiting for job completion...');
    const completedJob = await client.jobs.waitForCompletion(
      response.jobId,
      { timeout: 120_000, pollInterval: 2000 },
    );

    console.log(`\nJob Completed:`);
    console.log(`  Status: ${getStatusIcon(completedJob.status)} ${completedJob.status}`);

    if (completedJob.result) {
      console.log(`  Output Hash: ${completedJob.result.outputHash}`);
      console.log(`  Execution Time: ${completedJob.result.executionTimeMs}ms`);
    }

    if (completedJob.metadata?.seal_id) {
      console.log(`  Seal ID: ${completedJob.metadata.seal_id}`);
    }
  } catch (err) {
    if (err instanceof JobError) {
      console.log(`\nJob error: ${err.message} (job: ${err.jobId})`);
    } else if (err instanceof ConnectionError) {
      console.log(`\nConnection error: ${err.message}`);
    } else if (err instanceof AethelredError) {
      console.log(`\nError: ${err.message}`);
    } else {
      throw err;
    }
  }

  // ── Part 4: Query Validators ──────────────────────────────
  console.log('\n' + '-'.repeat(60));
  console.log('PART 4: Active Validators');
  console.log('-'.repeat(60));

  try {
    const validators = await client.validators.list({ status: 'active' });
    console.log(`\nActive Validators: ${validators.length}\n`);

    for (const v of validators.slice(0, 3)) {
      console.log(`  ${v.moniker ?? v.address}`);
      console.log(`    Status: ${v.status}`);
      console.log(`    Commission: ${v.commission ?? 'N/A'}`);
      console.log();
    }
  } catch (err) {
    if (err instanceof AethelredError) {
      console.log(`  Error listing validators: ${err.message}\n`);
    } else {
      throw err;
    }
  }

  // Summary
  console.log('='.repeat(60));
  console.log('EXAMPLE COMPLETE');
  console.log('='.repeat(60));
  console.log(`
Compute Job Lifecycle:

1. Prepare input data and compute hash
2. Submit job with model hash, input, and proof type
3. Job enters queue with assigned priority
4. Validators execute in TEE enclave
5. Optional zkML proof generated
6. Consensus reached on output
7. Digital Seal created on-chain
8. Result returned with verification

Proof Types:
  TEE     : Fast (~1s), hardware attestation
  zkML    : Slower (~30s), mathematical proof
  HYBRID  : Both for maximum assurance
`);
}

function getStatusIcon(status: string): string {
  switch (status) {
    case 'pending':
      return '[PENDING]';
    case 'assigned':
      return '[ASSIGNED]';
    case 'executing':
      return '[EXECUTING]';
    case 'verifying':
      return '[VERIFYING]';
    case 'completed':
      return '[COMPLETED]';
    case 'failed':
      return '[FAILED]';
    case 'expired':
      return '[EXPIRED]';
    default:
      return '[UNKNOWN]';
  }
}

main().catch(console.error);
