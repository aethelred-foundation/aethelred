/**
 * Credit Scoring Demo Example
 *
 * This example demonstrates the full credit scoring verification flow
 * for investor presentations.
 *
 * Run with: npx ts-node examples/credit-scoring-demo.ts
 */

import { AethelredClient, CreditFeatures, LoanDecision } from '../src';

async function main() {
  console.log('='.repeat(70));
  console.log('       AETHELRED CREDIT SCORING VERIFICATION DEMO');
  console.log('='.repeat(70));
  console.log();
  console.log('This demo shows how Aethelred cryptographically verifies');
  console.log('AI-powered credit scoring decisions using TEE + zkML.');
  console.log();

  // Connect to testnet
  const client = await AethelredClient.connectToNetwork('testnet');
  console.log('✓ Connected to Aethelred testnet\n');

  // List available demo scenarios
  console.log('-'.repeat(70));
  console.log('AVAILABLE DEMO SCENARIOS');
  console.log('-'.repeat(70));

  const scenarios = await client.creditScoring.listScenarios();
  for (const scenario of scenarios) {
    console.log(`\n  ${scenario.id}:`);
    console.log(`    Name: ${scenario.name}`);
    console.log(`    Category: ${scenario.category}`);
    console.log(`    Expected: ${scenario.expectedDecision.toUpperCase()}`);
    console.log(`    Loan: $${scenario.loanAmount.toLocaleString()} ${scenario.loanType}`);
  }

  // Run demo with 3 different credit profiles
  console.log('\n' + '='.repeat(70));
  console.log('RUNNING VERIFICATION DEMO');
  console.log('='.repeat(70));

  const profiles: ('excellent' | 'good' | 'fair' | 'poor')[] = ['excellent', 'fair', 'poor'];

  for (const profile of profiles) {
    console.log(`\n${'─'.repeat(70)}`);
    console.log(`  SCENARIO: ${profile.toUpperCase()} CREDIT PROFILE`);
    console.log(`${'─'.repeat(70)}`);

    // Create sample features
    const features = client.creditScoring.createSampleFeatures(profile);

    // Validate features
    const validation = client.creditScoring.validateFeatures(features);
    if (!validation.valid) {
      console.log('  ⚠ Validation errors:', validation.errors.join(', '));
      continue;
    }

    // Client-side estimate (quick preview)
    const estimate = client.creditScoring.estimateScore(features);
    console.log(`\n  📊 Client-side Estimate:`);
    console.log(`     Score: ~${estimate.estimatedScore} (${estimate.category})`);
    console.log(`     Likely Decision: ${estimate.estimatedDecision}`);

    // Score with on-chain verification
    console.log(`\n  🔐 Submitting for verified scoring...`);

    try {
      const result = await client.creditScoring.scoreVerified({
        applicantId: `demo-${profile}-${Date.now()}`,
        loanType: 'personal',
        loanAmount: profile === 'excellent' ? 50000 : profile === 'fair' ? 15000 : 5000,
        loanTermMonths: 36,
        features,
      });

      // Display results
      console.log(`\n  ✅ VERIFIED RESULT:`);
      console.log(`     Credit Score: ${result.score} (${result.scoreCategory})`);
      console.log(`     Decision: ${getDecisionEmoji(result.decision)} ${result.decision.toUpperCase()}`);
      console.log(`     Confidence: ${(result.confidence * 100).toFixed(1)}%`);
      console.log(`     Default Probability: ${(result.defaultProbability * 100).toFixed(2)}%`);

      if (result.recommendedRate) {
        console.log(`     Recommended Rate: ${result.recommendedRate.toFixed(2)}%`);
      }
      if (result.recommendedLimit) {
        console.log(`     Recommended Limit: $${result.recommendedLimit.toLocaleString()}`);
      }

      // Verification details
      console.log(`\n  🔒 VERIFICATION DETAILS:`);
      console.log(`     Verification Type: ${result.verificationType}`);
      console.log(`     Processing Time: ${result.processingTimeMs}ms`);
      console.log(`     Seal ID: ${result.sealId}`);

      // Risk factors
      if (result.riskFactors.length > 0) {
        console.log(`\n  ⚠️ Risk Factors:`);
        for (const rf of result.riskFactors.slice(0, 3)) {
          console.log(`     - ${rf.description} (impact: ${rf.impact})`);
        }
      }

      // Positive factors
      if (result.positiveFactors.length > 0) {
        console.log(`\n  ✨ Positive Factors:`);
        for (const pf of result.positiveFactors.slice(0, 3)) {
          console.log(`     + ${pf}`);
        }
      }

      // Verify the seal
      if (result.sealId) {
        console.log(`\n  📜 SEAL VERIFICATION:`);
        const isValid = await client.seal.quickVerify(result.sealId);
        console.log(`     Seal Valid: ${isValid ? '✅ Yes' : '❌ No'}`);
      }
    } catch (error) {
      console.log(`  ❌ Error: ${error}`);
    }
  }

  // Show pipeline metrics
  console.log('\n' + '='.repeat(70));
  console.log('PIPELINE METRICS');
  console.log('='.repeat(70));

  const metrics = await client.creditScoring.getMetrics();
  console.log(`\n  Total Applications: ${metrics.totalApplications}`);
  console.log(`  Processed: ${metrics.processedApplications}`);
  console.log(`  Approved: ${metrics.approvedApplications}`);
  console.log(`  Denied: ${metrics.deniedApplications}`);
  console.log(`  Manual Review: ${metrics.reviewApplications}`);
  console.log(`  Average Score: ${metrics.averageScore.toFixed(0)}`);
  console.log(`  Avg Processing Time: ${metrics.averageProcessingTimeMs}ms`);

  // Summary
  console.log('\n' + '='.repeat(70));
  console.log('DEMO SUMMARY');
  console.log('='.repeat(70));
  console.log(`
  This demonstration showed how Aethelred:

  1. ✅ Receives loan application with credit features
  2. ✅ Executes AI model in secure TEE enclave
  3. ✅ Generates cryptographic attestation of computation
  4. ✅ Optionally creates zkML proof for mathematical verification
  5. ✅ Achieves consensus across multiple validators
  6. ✅ Creates immutable Digital Seal for audit trail

  Key Benefits:
  • Regulatory Compliance - Auditable proof of AI decisions
  • Tamper-Proof - Cryptographic guarantees of integrity
  • Privacy-Preserving - Input data never leaves secure enclave
  • Fast - Sub-second verification for real-time decisions
`);

  console.log('='.repeat(70));

  // Cleanup
  client.disconnect();
}

function getDecisionEmoji(decision: LoanDecision): string {
  switch (decision) {
    case 'approved':
      return '🟢';
    case 'review':
      return '🟡';
    case 'denied':
      return '🔴';
    default:
      return '⚪';
  }
}

main().catch(console.error);
