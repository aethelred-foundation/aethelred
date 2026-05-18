import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildProofPath } from './proof-path.mjs';

const schemaDir = new URL('../schemas/', import.meta.url);

const readSchema = async (name) => JSON.parse(await readFile(new URL(name, schemaDir), 'utf8'));

const assertRequiredFields = (schema, artifact) => {
  for (const field of schema.required || []) {
    assert.ok(Object.hasOwn(artifact, field), `${schema.title} missing required field: ${field}`);
  }
  if (schema.properties?.schema_version?.const) {
    assert.equal(artifact.schema_version, schema.properties.schema_version.const);
  }
};

test('core public proof artifacts satisfy schema contracts', async () => {
  const outputDir = await mkdtemp(join(tmpdir(), 'aethelred-schema-'));
  try {
    const record = await buildProofPath({ outputDir });
    const contracts = [
      ['aethelred-seal-v0.2.schema.json', record.seal],
      ['aethelred-verifier-report-v0.2.schema.json', record.verifier_report],
      ['aethelred-anchor-manifest-v0.2.schema.json', record.anchor_manifest],
      ['aethelred-pilot-readiness-gate-v0.2.schema.json', record.pilot_readiness_gate],
      ['aethelred-external-compute-report-v0.2.schema.json', record.external_compute_report],
      ['aethelred-redaction-manifest-v0.2.schema.json', record.redaction_manifest],
      ['aethelred-verifier-onboarding-pack-v0.2.schema.json', record.verifier_onboarding_pack],
      ['aethelred-procurement-readiness-pack-v0.2.schema.json', record.procurement_readiness_pack],
      ['aethelred-sovereign-differentiation-scorecard-v0.2.schema.json', record.sovereign_differentiation_scorecard],
    ];

    for (const [schemaName, artifact] of contracts) {
      assertRequiredFields(await readSchema(schemaName), artifact);
    }
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});
