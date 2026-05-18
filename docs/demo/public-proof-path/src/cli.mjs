import { readFile } from 'node:fs/promises';
import {
  buildProofPath,
  DEFAULT_OUTPUT_DIR,
  readLatestArtifact,
  readLatestRecord,
  verifyLedger,
  verifyProofRecord,
} from './proof-path.mjs';
import { buildScenarioRequest, listScenarios } from './scenarios.mjs';

const parseArgs = (argv) =>
  argv.reduce(
    (acc, arg) => {
      if (arg.startsWith('--')) {
        const [key, value = 'true'] = arg.slice(2).split('=');
        acc.flags[key] = value;
      } else {
        acc.positionals.push(arg);
      }
      return acc;
    },
    { flags: {}, positionals: [] },
  );

const writeJson = (value) => {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
};

const usage = () => {
  process.stdout.write(`Aethelred sovereign public proof path CLI

Usage:
  node src/cli.mjs list-scenarios
  node src/cli.mjs run --scenario=finance --output-dir=out
  node src/cli.mjs run --request-file=request.json --output-dir=out
  node src/cli.mjs verify --output-dir=out
  node src/cli.mjs verify --record=out/latest/proof-record.json
  node src/cli.mjs external-report --output-dir=out
  node src/cli.mjs regulator-pack --output-dir=out
  node src/cli.mjs sovereign-scorecard --output-dir=out
  node src/cli.mjs anchor --output-dir=out

Scenarios: ${listScenarios().map((scenario) => scenario.id).join(', ')}
`);
};

const { flags, positionals } = parseArgs(process.argv.slice(2));
const command = positionals[0] || 'help';
const outputDir = flags['output-dir'] || process.env.AETHELRED_PROOF_OUTPUT_DIR || DEFAULT_OUTPUT_DIR;

if (command === 'help' || flags.help) {
  usage();
} else if (command === 'list-scenarios') {
  writeJson({ scenarios: listScenarios() });
} else if (command === 'run') {
  const scenarioId = flags.scenario || process.env.AETHELRED_SCENARIO || 'finance';
  const proofRequest = flags['request-file']
    ? JSON.parse(await readFile(flags['request-file'], 'utf8'))
    : buildScenarioRequest(scenarioId);
  const result = await buildProofPath({ request: proofRequest, outputDir });
  const ledger = await verifyLedger(outputDir);
  writeJson({
    status: result.verifier_report.valid ? 'verified' : 'failed',
    scenario_id: flags['request-file'] ? 'custom-request-file' : scenarioId,
    use_case: result.request.use_case,
    run_id: result.run_id,
    seal_id: result.seal.seal_id,
    external_compute_provider: result.external_compute_report.provider,
    assurance_tier: result.assurance_plan.target_tier.tier,
    quorum_reached: result.validator_quorum.quorum_reached,
    pilot_status: result.pilot_readiness_gate.regulated_pilot_status,
    anchor_id: result.anchor_manifest.anchor_id,
    ledger_valid: ledger.valid,
    artifacts: result.storage.run_dir,
  });
  process.exitCode = result.verifier_report.valid && ledger.valid ? 0 : 1;
} else if (command === 'verify') {
  const record = flags.record
    ? JSON.parse(await readFile(flags.record, 'utf8'))
    : await readLatestRecord(outputDir);
  const report = verifyProofRecord(record);
  const ledger = flags.record ? null : await verifyLedger(outputDir);
  writeJson({
    ...report,
    ledger_verification: ledger,
  });
  process.exitCode = report.valid && (!ledger || ledger.valid) ? 0 : 1;
} else if (command === 'external-report') {
  writeJson(await readLatestArtifact('external-compute-report.json', outputDir));
} else if (command === 'regulator-pack') {
  const record = await readLatestRecord(outputDir);
  writeJson({
    schema_version: 'aethelred-regulator-export-v0.2',
    generated_at: new Date().toISOString(),
    seal: record?.seal,
    verifier_report: verifyProofRecord(record),
    institutional_context: record?.institutional_context,
    policy_receipt: record?.policy_receipt,
    external_compute_report: record?.external_compute_report,
    jurisdiction_report: record?.jurisdiction_report,
    liability_route: record?.liability_route,
    assurance_plan: record?.assurance_plan,
    validator_quorum: record?.validator_quorum,
    key_custody_manifest: record?.key_custody_manifest,
    anchor_manifest: record?.anchor_manifest,
    pilot_readiness_gate: record?.pilot_readiness_gate,
    auditor_attestation: record?.auditor_attestation,
    sovereign_differentiation_scorecard: record?.sovereign_differentiation_scorecard,
    regulatory_evidence_index: record?.regulatory_evidence_index,
    public_verifier_manifest: record?.public_verifier_manifest,
    ledger_verification: await verifyLedger(outputDir),
  });
} else if (command === 'sovereign-scorecard') {
  writeJson(await readLatestArtifact('sovereign-differentiation-scorecard.json', outputDir));
} else if (command === 'anchor') {
  writeJson(await readLatestArtifact('anchor-manifest.json', outputDir));
} else {
  usage();
  process.exitCode = 2;
}
