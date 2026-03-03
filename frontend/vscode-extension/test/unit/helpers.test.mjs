import test from 'node:test';
import assert from 'node:assert/strict';

import {
  NETWORKS,
  formatStatusBarText,
  normalizeNetworkName,
  iconNameForJobStatus,
  localTestnetUpCommand,
  verifySealJsonPayload,
} from '../../src/helpers.mjs';

test('NETWORKS includes all supported networks', () => {
  assert.deepEqual(NETWORKS, ['Mainnet', 'Testnet', 'Devnet', 'Local']);
});

test('formatStatusBarText formats consistently', () => {
  assert.equal(formatStatusBarText('Mainnet'), '$(globe) Aethelred: Mainnet');
});

test('normalizeNetworkName handles casing and whitespace', () => {
  assert.equal(normalizeNetworkName(' testnet '), 'Testnet');
  assert.equal(normalizeNetworkName('DEVNET'), 'Devnet');
  assert.equal(normalizeNetworkName('unknown'), null);
});

test('iconNameForJobStatus returns deterministic icon mapping', () => {
  assert.equal(iconNameForJobStatus('Completed'), 'check');
  assert.equal(iconNameForJobStatus('pending'), 'clock');
  assert.equal(iconNameForJobStatus('running'), 'sync~spin');
});

test('localTestnetUpCommand targets developer local testnet compose file', () => {
  assert.equal(
    localTestnetUpCommand(),
    'docker compose -f deploy/docker/docker-compose.local-testnet.yml --profile mock up -d'
  );
});

test('verifySealJsonPayload validates a minimal seal export and computes fingerprint', () => {
  const result = verifySealJsonPayload(JSON.stringify({
    seal: {
      id: 'seal_1',
      jobId: 'job_1',
      modelHash: '0xabc',
      inputCommitment: '0x111',
      outputCommitment: '0x222',
      status: 'SEAL_STATUS_ACTIVE',
      requester: 'aeth1abc',
      createdAt: new Date().toISOString(),
      validators: [{ validatorAddress: 'aethval1', signature: '0xsig', votingPower: '67' }],
    }
  }));
  assert.equal(result.valid, true);
  assert.match(result.fingerprintSha256, /^0x[0-9a-f]{64}$/);
  assert.equal(result.validatorCount, 1);
});
