/**
 * Compute Job Submission Example
 *
 * This example demonstrates how to submit AI computation jobs
 * for verified execution.
 *
 * Run with: npx ts-node examples/compute-job.ts
 */

import { AethelredClient, utils, ProofType, JobPriority } from '../src';
import { DirectSecp256k1HdWallet } from '@cosmjs/proto-signing';

async function main() {
  console.log('='.repeat(60));
  console.log('     Aethelred Enterprise Hybrid Compute Job Example');
  console.log('='.repeat(60));
  console.log();

  // Connect to testnet
  const client = await AethelredClient.connectToNetwork('testnet');
  console.log('✓ Connected to Aethelred testnet\n');

  // Part 1: Query registered models
  console.log('-'.repeat(60));
  console.log('PART 1: Available Models');
  console.log('-'.repeat(60));

  const models = await client.compute.listModels({ status: 'active' });
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

  // Part 2: Estimate job time
  console.log('-'.repeat(60));
  console.log('PART 2: Time Estimates');
  console.log('-'.repeat(60));

  if (models.length > 0) {
    const model = models[0];
    console.log(`\nEstimating time for model: ${model.name}`);

    const proofTypes: ProofType[] = ['tee', 'zkml', 'hybrid'];
    for (const proofType of proofTypes) {
      const estimate = await client.compute.estimateTime(
        model.modelHash,
        proofType,
        'normal'
      );
      console.log(`\n  ${proofType.toUpperCase()}:`);
      console.log(`    Estimated: ${estimate.estimatedTimeMs}ms`);
      console.log(`    Queue Wait: ${estimate.queueWaitMs}ms`);
      console.log(`    Execution: ${estimate.executionTimeMs}ms`);
      console.log(`    Queue Position: ${estimate.queuePosition}`);
    }
  }

  // Part 3: Queue status
  console.log('\n' + '-'.repeat(60));
  console.log('PART 3: Queue Status');
  console.log('-'.repeat(60));

  const queueStatus = await client.compute.getQueueStatus();
  console.log(`\nCurrent Queue Status:`);
  console.log(`  Pending Jobs: ${queueStatus.pendingJobs}`);
  console.log(`  Executing Jobs: ${queueStatus.executingJobs}`);
  console.log(`  Estimated Wait: ${queueStatus.estimatedWaitTimeMs}ms`);
  console.log(`  Validator Capacity: ${queueStatus.validatorCapacity}`);
  console.log(`  Current Utilization: ${(queueStatus.currentUtilization * 100).toFixed(1)}%`);

  console.log(`\n  Jobs by Priority:`);
  for (const [priority, count] of Object.entries(queueStatus.jobsByPriority)) {
    console.log(`    ${priority}: ${count}`);
  }

  // Part 4: Query recent jobs
  console.log('\n' + '-'.repeat(60));
  console.log('PART 4: Recent Jobs');
  console.log('-'.repeat(60));

  const recentJobs = await client.compute.listJobs({ limit: 5 });
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

  // Part 5: Submit a job (simulated - needs signer in production)
  console.log('-'.repeat(60));
  console.log('PART 5: Job Submission Demo');
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

  const inputHash = utils.hashInput(inputData);
  console.log(`\nInput prepared:`);
  console.log(`  Input Hash: ${inputHash.slice(0, 32)}...`);

  if (client.canSign()) {
    console.log('\nSubmitting job...');

    try {
      const response = await client.compute.submitJob({
        modelHash: models[0]?.modelHash || 'demo-model-hash',
        inputHash,
        purpose: 'demo_credit_scoring',
        proofType: 'hybrid',
        priority: 'normal',
        maxWaitTime: 60,
        metadata: {
          sdk_example: 'true',
        },
      });

      console.log(`\nJob Submitted:`);
      console.log(`  Job ID: ${response.jobId}`);
      console.log(`  Status: ${response.status}`);
      console.log(`  TX Hash: ${response.txHash}`);

      // Wait for completion
      console.log('\nWaiting for job completion...');
      const completedJob = await client.compute.waitForCompletion(
        response.jobId,
        120000 // 2 minute timeout
      );

      console.log(`\nJob Completed:`);
      console.log(`  Status: ${getStatusIcon(completedJob.status)} ${completedJob.status}`);

      if (completedJob.result) {
        console.log(`  Output Hash: ${completedJob.result.outputHash}`);
        console.log(`  Verification: ${completedJob.result.verificationType}`);
        console.log(`  Consensus: ${completedJob.result.consensusReached ? 'Yes' : 'No'}`);
        console.log(`  Verifications: ${completedJob.result.verifications.length}`);
        console.log(`  Execution Time: ${completedJob.result.executionTimeMs}ms`);

        if (completedJob.sealId) {
          console.log(`  Seal ID: ${completedJob.sealId}`);
        }
      }

      if (completedJob.error) {
        console.log(`  Error: ${completedJob.error}`);
      }
    } catch (error) {
      console.log(`Error: ${error}`);
    }
  } else {
    console.log('\n(Job submission skipped - no signer available)');
    console.log('In production, you would:');
    console.log('  1. Connect with a wallet (mnemonic or Keplr)');
    console.log('  2. Call client.compute.submitJob(request)');
    console.log('  3. Wait for completion with waitForCompletion()');
    console.log('  4. Retrieve the verified result and seal ID');
  }

  // Part 6: Compute statistics
  console.log('\n' + '-'.repeat(60));
  console.log('PART 6: Compute Statistics');
  console.log('-'.repeat(60));

  const stats = await client.compute.getStats();
  console.log(`\nOverall Statistics:`);
  console.log(`  Total Jobs: ${stats.totalJobs}`);
  console.log(`  Pending: ${stats.pendingJobs}`);
  console.log(`  Executing: ${stats.executingJobs}`);
  console.log(`  Completed: ${stats.completedJobs}`);
  console.log(`  Failed: ${stats.failedJobs}`);
  console.log(`  Avg Processing: ${stats.averageProcessingTimeMs}ms`);
  console.log(`  Registered Models: ${stats.registeredModels}`);
  console.log(`  Active Validators: ${stats.activeValidators}`);

  console.log(`\n  Jobs by Proof Type:`);
  for (const [type, count] of Object.entries(stats.jobsByProofType)) {
    console.log(`    ${type}: ${count}`);
  }

  // Summary
  console.log('\n' + '='.repeat(60));
  console.log('EXAMPLE COMPLETE');
  console.log('='.repeat(60));
  console.log(`
Compute Job Lifecycle:

1. 📋 Prepare input data and compute hash
2. 📤 Submit job with model hash, input, and proof type
3. ⏳ Job enters queue with assigned priority
4. 🔐 Validators execute in TEE enclave
5. 📊 Optional zkML proof generated
6. ✅ Consensus reached on output
7. 📜 Digital Seal created on-chain
8. 📩 Result returned with verification

Proof Types:
  • TEE: Fast (~1s), hardware attestation
  • zkML: Slower (~30s), mathematical proof
  • Hybrid: Both for maximum assurance
`);

  // Cleanup
  client.disconnect();
}

function getStatusIcon(status: string): string {
  switch (status) {
    case 'pending':
      return '⏳';
    case 'assigned':
      return '📋';
    case 'executing':
      return '⚙️';
    case 'verifying':
      return '🔍';
    case 'completed':
      return '✅';
    case 'failed':
      return '❌';
    case 'expired':
      return '⏰';
    default:
      return '❓';
  }
}

main().catch(console.error);
