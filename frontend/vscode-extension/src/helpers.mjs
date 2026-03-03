import { createHash } from 'node:crypto';

export const NETWORKS = ['Mainnet', 'Testnet', 'Devnet', 'Local'];
export const LOCAL_TESTNET_COMPOSE_FILE = 'deploy/docker/docker-compose.local-testnet.yml';

export function formatStatusBarText(network) {
  return `$(globe) Aethelred: ${network}`;
}

export function normalizeNetworkName(input) {
  const normalized = input.trim().toLowerCase();
  switch (normalized) {
    case 'mainnet':
      return 'Mainnet';
    case 'testnet':
      return 'Testnet';
    case 'devnet':
      return 'Devnet';
    case 'local':
      return 'Local';
    default:
      return null;
  }
}

export function iconNameForJobStatus(status) {
  const normalized = status.trim().toLowerCase();
  if (normalized === 'completed') {
    return 'check';
  }
  if (normalized === 'pending') {
    return 'clock';
  }
  return 'sync~spin';
}

export function localTestnetUpCommand(profile = 'mock') {
  return `docker compose -f ${LOCAL_TESTNET_COMPOSE_FILE} --profile ${profile} up -d`;
}

export function localTestnetDownCommand() {
  return `docker compose -f ${LOCAL_TESTNET_COMPOSE_FILE} down`;
}

function stableSort(value) {
  if (Array.isArray(value)) {
    return value.map(stableSort);
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      if (value[key] !== undefined) {
        out[key] = stableSort(value[key]);
      }
    }
    return out;
  }
  return value;
}

export function verifySealJsonPayload(raw) {
  const parsed = JSON.parse(raw);
  const seal = parsed && typeof parsed === 'object' && parsed.seal && typeof parsed.seal === 'object'
    ? parsed.seal
    : parsed;

  if (!seal || typeof seal !== 'object' || Array.isArray(seal)) {
    throw new Error('Seal payload must be a JSON object');
  }

  const requiredFields = [
    'id',
    'jobId',
    'modelHash',
    'inputCommitment',
    'outputCommitment',
    'status',
    'requester',
    'createdAt',
    'validators',
  ];

  const checks = requiredFields.map((field) => {
    const ok = seal[field] !== undefined && seal[field] !== null;
    return {
      id: `required:${field}`,
      ok,
      severity: 'error',
      message: ok ? `${field} present` : `Missing required field ${field}`,
    };
  });

  if (seal.expiresAt) {
    const ts = new Date(seal.expiresAt);
    const validTs = !Number.isNaN(ts.getTime());
    checks.push({
      id: 'expiry:timestamp',
      ok: validTs,
      severity: 'error',
      message: validTs ? 'expiresAt timestamp valid' : 'expiresAt is invalid',
    });
    if (validTs) {
      checks.push({
        id: 'expiry:future',
        ok: ts.getTime() > Date.now(),
        severity: 'warning',
        message: ts.getTime() > Date.now() ? 'seal not expired' : 'seal expired',
      });
    }
  }

  const validatorCount = Array.isArray(seal.validators) ? seal.validators.length : 0;
  checks.push({
    id: 'validators:count',
    ok: validatorCount > 0,
    severity: 'error',
    message: validatorCount > 0 ? `${validatorCount} validator attestations present` : 'No validator attestations',
  });

  const canonical = JSON.stringify(stableSort(seal));
  const fingerprint = `0x${createHash('sha256').update(canonical).digest('hex')}`;
  const errors = checks.filter((c) => c.severity === 'error' && !c.ok);
  const warnings = checks.filter((c) => c.severity === 'warning' && !c.ok);

  return {
    valid: errors.length === 0,
    score: Math.max(0, 100 - errors.length * 25 - warnings.length * 8),
    fingerprintSha256: fingerprint,
    validatorCount,
    checks,
    errors,
    warnings,
  };
}
