/**
 * Basic SDK Usage Example
 *
 * Run with: npx ts-node examples/basic-usage.ts
 */

import { AethelredClient } from '../src';

async function main() {
  console.log('='.repeat(60));
  console.log('        Aethelred SDK - Basic Usage Example');
  console.log('='.repeat(60));
  console.log();

  // Connect to testnet
  console.log('Connecting to testnet...');
  const client = await AethelredClient.connectToNetwork('testnet');

  // Check connection status
  const status = await client.getStatus();
  console.log('Connection Status:');
  console.log(`  Connected: ${status.connected}`);
  console.log(`  Chain ID: ${status.chainId}`);
  console.log(`  Block Height: ${status.blockHeight}`);
  console.log();

  // Query seals
  console.log('Querying recent seals...');
  const sealList = await client.seal.listSeals({ limit: 5 });
  console.log(`Found ${sealList.total} total seals`);

  if (sealList.seals.length > 0) {
    console.log('\nRecent Seals:');
    for (const seal of sealList.seals) {
      console.log(`  - ${seal.id}`);
      console.log(`    Status: ${seal.status}`);
      console.log(`    Purpose: ${seal.purpose}`);
      console.log(`    Block: ${seal.blockHeight}`);
    }
  }
  console.log();

  // Query compute jobs
  console.log('Querying recent compute jobs...');
  const jobList = await client.compute.listJobs({ limit: 5 });
  console.log(`Found ${jobList.total} total jobs`);

  if (jobList.jobs.length > 0) {
    console.log('\nRecent Jobs:');
    for (const job of jobList.jobs) {
      console.log(`  - ${job.id}`);
      console.log(`    Status: ${job.status}`);
      console.log(`    Proof Type: ${job.proofType}`);
    }
  }
  console.log();

  // Get compute statistics
  console.log('Compute Statistics:');
  const stats = await client.compute.getStats();
  console.log(`  Total Jobs: ${stats.totalJobs}`);
  console.log(`  Completed: ${stats.completedJobs}`);
  console.log(`  Active Validators: ${stats.activeValidators}`);
  console.log();

  // Disconnect
  client.disconnect();
  console.log('Disconnected from network.');
  console.log('='.repeat(60));
}

main().catch(console.error);
