/**
 * Basic SDK Usage Example
 *
 * Demonstrates connecting to the Aethelred network, querying node info,
 * listing seals and jobs, and fetching blocks.
 *
 * Run with: npx ts-node examples/basic-usage.ts
 */

import {
  AethelredClient,
  Network,
  AethelredError,
  ConnectionError,
} from '../src';

async function main() {
  console.log('='.repeat(60));
  console.log('        Aethelred SDK - Basic Usage Example');
  console.log('='.repeat(60));
  console.log();

  // Create a client targeting the testnet
  const client = new AethelredClient({ network: Network.TESTNET });

  // 1. Health check
  console.log('Checking node health...');
  const healthy = await client.healthCheck();
  console.log(`  Node healthy: ${healthy}`);
  console.log();

  // 2. Node information
  console.log('Fetching node info...');
  try {
    const nodeInfo = await client.getNodeInfo();
    console.log('Node Info:');
    console.log(`  Network : ${nodeInfo.network}`);
    console.log(`  Moniker : ${nodeInfo.moniker}`);
    console.log(`  Version : ${nodeInfo.version}`);
  } catch (err) {
    if (err instanceof ConnectionError) {
      console.log(`  Could not reach node: ${err.message}`);
    } else {
      throw err;
    }
  }
  console.log();

  // 3. Latest block
  console.log('Fetching latest block...');
  try {
    const block = await client.getLatestBlock();
    console.log('Latest Block:');
    console.log(`  Height : ${block.block?.header?.height ?? 'N/A'}`);
    console.log(`  Time   : ${block.block?.header?.time ?? 'N/A'}`);
    console.log(`  Chain  : ${block.block?.header?.chain_id ?? 'N/A'}`);
  } catch (err) {
    if (err instanceof AethelredError) {
      console.log(`  Error fetching block: ${err.message}`);
    } else {
      throw err;
    }
  }
  console.log();

  // 4. Query seals
  console.log('Querying recent seals...');
  try {
    const sealList = await client.seals.list({ limit: 5 });
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
  } catch (err) {
    if (err instanceof AethelredError) {
      console.log(`  Error querying seals: ${err.message}`);
    } else {
      throw err;
    }
  }
  console.log();

  // 5. Query compute jobs
  console.log('Querying recent compute jobs...');
  try {
    const jobList = await client.jobs.list({ limit: 5 });
    console.log(`Found ${jobList.total} total jobs`);

    if (jobList.jobs.length > 0) {
      console.log('\nRecent Jobs:');
      for (const job of jobList.jobs) {
        console.log(`  - ${job.id}`);
        console.log(`    Status: ${job.status}`);
        console.log(`    Proof Type: ${job.proofType}`);
      }
    }
  } catch (err) {
    if (err instanceof AethelredError) {
      console.log(`  Error querying jobs: ${err.message}`);
    } else {
      throw err;
    }
  }
  console.log();

  // 6. Network configuration
  console.log('Network Configuration:');
  console.log(`  RPC URL  : ${client.getRpcUrl()}`);
  console.log(`  Chain ID : ${client.getChainId()}`);
  console.log();

  console.log('='.repeat(60));
  console.log('  Basic usage example complete.');
  console.log('='.repeat(60));
}

main().catch(console.error);
