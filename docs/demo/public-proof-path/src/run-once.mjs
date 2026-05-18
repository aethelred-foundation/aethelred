import { buildProofPath, DEFAULT_OUTPUT_DIR, verifyLedger } from './proof-path.mjs';
import { buildScenarioRequest } from './scenarios.mjs';

const outputDir = process.env.AETHELRED_PROOF_OUTPUT_DIR || DEFAULT_OUTPUT_DIR;
const scenarioId = process.argv.find((arg) => arg.startsWith('--scenario='))?.split('=')[1] || process.env.AETHELRED_SCENARIO || 'finance';
const result = await buildProofPath({ request: buildScenarioRequest(scenarioId), outputDir });
const ledger = await verifyLedger(outputDir);

console.log(JSON.stringify({
  status: result.verifier_report.valid ? 'verified' : 'failed',
  scenario_id: scenarioId,
  use_case: result.request.use_case,
  run_id: result.run_id,
  seal_id: result.seal.seal_id,
  external_compute_provider: result.external_compute_report.provider,
  pilot_status: result.pilot_readiness_gate.regulated_pilot_status,
  anchor_id: result.anchor_manifest.anchor_id,
  output_dir: outputDir,
  ledger_valid: ledger.valid,
  artifacts: result.storage.run_dir,
}, null, 2));
