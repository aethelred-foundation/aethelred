import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildProofPath, defaultProofRequest, sha256Hex, verifyLedger, verifyProofRecord } from './proof-path.mjs';
import { buildScenarioRequest, listScenarios } from './scenarios.mjs';

test('buildProofPath writes a verifiable Aethelred Seal path', async () => {
  const outputDir = await mkdtemp(join(tmpdir(), 'aethelred-proof-path-'));
  try {
    const result = await buildProofPath({ outputDir });
    assert.equal(result.verifier_report.valid, true);
    assert.match(result.seal.seal_id, /^seal_[0-9a-f]{24}$/);
    assert.equal(result.assurance_plan.target_tier.tier, 4);
    assert.equal(result.validator_quorum.quorum_reached, true);
    assert.equal(result.jurisdiction_report.jurisdiction_allowed, true);
    assert.equal(result.liability_route.status, 'bound');
    assert.equal(result.pilot_readiness_gate.regulated_pilot_status, 'conditional-pass');
    assert.match(result.anchor_manifest.anchor_id, /^anchor_[0-9a-f]{24}$/);
    assert.match(result.auditor_attestation.attestation_id, /^audit_[0-9a-f]{24}$/);
    assert.ok(result.regulatory_evidence_index.artifacts.some((artifact) => artifact.name === 'validator-quorum.json'));

    const seal = JSON.parse(await readFile(join(outputDir, 'latest', 'aethelred-seal.json'), 'utf8'));
    assert.equal(seal.seal_id, result.seal.seal_id);
    const anchor = JSON.parse(await readFile(join(outputDir, 'latest', 'anchor-manifest.json'), 'utf8'));
    assert.equal(anchor.seal_id, result.seal.seal_id);

    const ledger = await verifyLedger(outputDir);
    assert.equal(ledger.valid, true);
    assert.equal(ledger.entry_count, 1);
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('all sovereign scenario packs produce valid public proof paths', async () => {
  const outputDir = await mkdtemp(join(tmpdir(), 'aethelred-proof-path-'));
  try {
    for (const scenario of listScenarios()) {
      const result = await buildProofPath({ request: buildScenarioRequest(scenario.id), outputDir });
      assert.equal(result.verifier_report.valid, true, scenario.id);
      assert.equal(result.validator_quorum.quorum_reached, true, scenario.id);
      assert.equal(result.pilot_readiness_gate.regulated_pilot_status, 'conditional-pass', scenario.id);
    }

    const ledger = await verifyLedger(outputDir);
    assert.equal(ledger.valid, true);
    assert.equal(ledger.entry_count, listScenarios().length);
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('external confidential-compute proof is wrapped by Aethelred sovereign controls', async () => {
  const outputDir = await mkdtemp(join(tmpdir(), 'aethelred-proof-path-'));
  try {
    const result = await buildProofPath({ request: buildScenarioRequest('external-finance'), outputDir });

    assert.equal(result.verifier_report.valid, true);
    assert.equal(result.external_compute_report.provider, 'external-confidential-vm');
    assert.equal(result.external_compute_report.accepted, true);
    assert.equal(result.attestation.external_compute_provider, 'external-confidential-vm');
    assert.equal(result.seal.commitments.external_compute_report_hash, sha256Hex(result.external_compute_report));
    assert.equal(result.sovereign_differentiation_scorecard.upstream_compute_provider.provider, 'external-confidential-vm');
    assert.ok(result.sovereign_differentiation_scorecard.dimensions.some((dimension) => dimension.id === 'policy-native'));
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('external compute adapter fails closed on mismatched provider output hash', async () => {
  const outputDir = await mkdtemp(join(tmpdir(), 'aethelred-proof-path-'));
  try {
    const request = buildScenarioRequest('external-finance');
    request.external_compute_proof.output_hash = '0'.repeat(64);

    const result = await buildProofPath({ request, outputDir });
    assert.equal(result.external_compute_report.accepted, false);
    assert.equal(result.verifier_report.valid, false);
    assert.ok(result.external_compute_report.failed_required_checks.includes('output-hash-bound'));
    assert.ok(
      result.verifier_report.checks.some(
        (check) => check.id === 'external-compute-provider-accepted' && check.status === 'fail',
      ),
    );
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('external compute adapter rejects unregistered proof providers', async () => {
  const outputDir = await mkdtemp(join(tmpdir(), 'aethelred-proof-path-'));
  try {
    const request = buildScenarioRequest('external-finance');
    request.external_compute_proof.provider = 'unregistered-verifiable-cloud';

    const result = await buildProofPath({ request, outputDir });
    assert.equal(result.external_compute_report.accepted, false);
    assert.equal(result.verifier_report.valid, false);
    assert.ok(result.external_compute_report.failed_required_checks.includes('provider-registered'));
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('verifyProofRecord fails closed on tampered verifier quorum vote', async () => {
  const outputDir = await mkdtemp(join(tmpdir(), 'aethelred-proof-path-'));
  try {
    const result = await buildProofPath({ outputDir });
    const tampered = structuredClone(result);
    tampered.validator_quorum.votes[0].decision = 'reject';

    const report = verifyProofRecord(tampered);
    assert.equal(report.valid, false);
    assert.ok(report.checks.some((check) => check.id === 'validator-vote-signatures' && check.status === 'fail'));
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('verifyProofRecord fails closed on tampered anchor manifest', async () => {
  const outputDir = await mkdtemp(join(tmpdir(), 'aethelred-proof-path-'));
  try {
    const result = await buildProofPath({ outputDir });
    const tampered = structuredClone(result);
    tampered.anchor_manifest.commitments.seal_hash = '00';

    const report = verifyProofRecord(tampered);
    assert.equal(report.valid, false);
    assert.ok(report.checks.some((check) => check.id === 'anchor-manifest-hash' && check.status === 'fail'));
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('public proof policy denies raw PII in proof input', async () => {
  const outputDir = await mkdtemp(join(tmpdir(), 'aethelred-proof-path-'));
  try {
    const request = defaultProofRequest();
    request.evidence_input.raw_pii_present = true;
    request.evidence_input.note = 'customer email: person@example.com';

    const result = await buildProofPath({ request, outputDir });
    assert.equal(result.policy_receipt.decision, 'deny');
    assert.equal(result.verifier_report.valid, false);
    assert.ok(result.policy_receipt.failed_required_checks.includes('pii-guard'));
    assert.ok(result.verifier_report.checks.some((check) => check.id === 'policy-decision' && check.status === 'fail'));
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('verifyProofRecord fails closed on tampered output', async () => {
  const outputDir = await mkdtemp(join(tmpdir(), 'aethelred-proof-path-'));
  try {
    const result = await buildProofPath({ request: defaultProofRequest(), outputDir });
    const tampered = structuredClone(result);
    tampered.model_output.risk_score = 1;

    const report = verifyProofRecord(tampered);
    assert.equal(report.valid, false);
    assert.ok(report.checks.some((check) => check.id === 'output-hash' && check.status === 'fail'));
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});
