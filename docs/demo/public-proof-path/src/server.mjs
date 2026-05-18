import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, normalize } from 'node:path';
import {
  buildProofPath,
  DEFAULT_OUTPUT_DIR,
  readLatestArtifact,
  readLatestRecord,
  SERVICE_VERSION,
  verifyLedger,
  verifyProofRecord,
} from './proof-path.mjs';
import { buildScenarioRequest, listScenarios } from './scenarios.mjs';

const HOST = process.env.AETHELRED_PROOF_HOST || '127.0.0.1';
const PORT = Number(process.env.AETHELRED_PROOF_PORT || 8088);
const OUTPUT_DIR = process.env.AETHELRED_PROOF_OUTPUT_DIR || DEFAULT_OUTPUT_DIR;

const headers = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Cache-Control': 'no-store',
};

const send = (response, status, body, contentType = 'application/json; charset=utf-8') => {
  response.writeHead(status, { ...headers, 'Content-Type': contentType });
  response.end(contentType.startsWith('application/json') ? JSON.stringify(body, null, 2) : body);
};

const sendError = (response, status, message) => send(response, status, { error: { message } });

const escapeHtml = (value) =>
  String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

const formatValue = (value) => {
  if (value === undefined || value === null) return 'missing';
  if (typeof value === 'object') return escapeHtml(JSON.stringify(value));
  return escapeHtml(value);
};

const statusClass = (status) => {
  if (status === 'pass' || status === true || status === 'complete' || status === 'verified') return 'pass';
  if (status === 'warning' || String(status).includes('conditional')) return 'warning';
  return 'fail';
};

const readJsonBody = (request) =>
  new Promise((resolve, reject) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve(raw ? JSON.parse(raw) : {});
      } catch (error) {
        reject(error);
      }
    });
    request.on('error', reject);
  });

const tableRows = (items, mapper) => items.map(mapper).join('');

const page = (record) => {
  const report = record?.verifier_report;
  const checks = report?.checks || [];
  const passCount = checks.filter((check) => check.status === 'pass').length;
  const warningCount = checks.filter((check) => check.status === 'warning').length;
  const failCount = checks.filter((check) => check.status === 'fail').length;
  const sealId = record?.seal?.seal_id || 'No seal yet';
  const readiness = report?.readiness || {};
  const quorum = record?.validator_quorum || {};
  const assurance = record?.assurance_plan || {};
  const jurisdiction = record?.jurisdiction_report || {};
  const liability = record?.liability_route || {};
  const externalCompute = record?.external_compute_report || {};
  const scorecard = record?.sovereign_differentiation_scorecard || {};
  const artifacts = record?.regulatory_evidence_index?.artifacts || [];
  const productionBlockers = assurance.production_blockers || [];
  const status = report?.valid ? 'Verified Public Proof' : 'Needs Review';
  const scenarioOptions = listScenarios()
    .map(
      (scenario) =>
        `<option value="${escapeHtml(scenario.id)}" ${scenario.use_case === record?.request?.use_case ? 'selected' : ''}>${escapeHtml(scenario.label)}</option>`,
    )
    .join('');

  const checkRows = tableRows(
    checks,
    (check) =>
      `<tr><td>${escapeHtml(check.label)}</td><td><span class="pill ${escapeHtml(check.status)}">${escapeHtml(check.status)}</span></td><td>${formatValue(check.evidence)}</td></tr>`,
  );
  const voteRows = tableRows(
    quorum.votes || [],
    (vote) =>
      `<tr><td>${escapeHtml(vote.verifier_name)}</td><td>${escapeHtml(vote.category)}</td><td><span class="pill ${statusClass(vote.decision === 'accept')}">${escapeHtml(vote.decision)}</span></td><td><code>${escapeHtml(vote.vote_hash)}</code></td></tr>`,
  );
  const artifactRows = tableRows(
    artifacts,
    (artifact) =>
      `<tr><td><a href="/artifacts/latest/${escapeHtml(artifact.name)}">${escapeHtml(artifact.name)}</a></td><td>${escapeHtml(artifact.purpose)}</td><td><code>${escapeHtml(artifact.sha256)}</code></td></tr>`,
  );
  const blockerRows = tableRows(
    productionBlockers,
    (blocker) =>
      `<tr><td>${escapeHtml(blocker.id)}</td><td>${escapeHtml(blocker.owner)}</td><td>${escapeHtml(blocker.requirement)}</td></tr>`,
  );
  const scorecardRows = tableRows(
    scorecard.dimensions || [],
    (dimension) =>
      `<tr><td>${escapeHtml(dimension.dimension)}</td><td><span class="pill ${statusClass(dimension.status)}">${escapeHtml(dimension.status)}</span></td><td>${escapeHtml(dimension.aethelred_10x_control)}</td><td>${escapeHtml(dimension.generic_verifiable_cloud)}</td></tr>`,
  );

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Aethelred Sovereign Proof Console</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #17202c;
      --muted: #5d6a7a;
      --soft: #edf1f4;
      --line: #d6dde5;
      --panel: #ffffff;
      --page: #f7f8f7;
      --green: #126b45;
      --green-bg: #e8f4ee;
      --amber: #8a5a00;
      --amber-bg: #fff4d6;
      --red: #b42318;
      --red-bg: #fdeceb;
      --blue: #1f4f73;
      --blue-bg: #e8f0f6;
      --teal: #0f766e;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--page);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
    }
    main { max-width: 1320px; margin: 0 auto; padding: 26px; }
    header {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 18px;
      align-items: start;
      margin-bottom: 18px;
    }
    h1 { font-size: 28px; line-height: 1.12; margin: 0 0 8px; }
    h2 { font-size: 17px; line-height: 1.25; margin: 0 0 12px; }
    p { margin: 0; color: var(--muted); line-height: 1.5; }
    a { color: var(--blue); }
    code { background: var(--soft); padding: 2px 5px; border-radius: 4px; overflow-wrap: anywhere; }
    .actions { display: flex; gap: 9px; flex-wrap: wrap; justify-content: flex-end; }
    button, a.button, select {
      border: 1px solid var(--line);
      background: var(--panel);
      color: var(--ink);
      border-radius: 6px;
      min-height: 38px;
      padding: 8px 12px;
      text-decoration: none;
      font: inherit;
      cursor: pointer;
      white-space: nowrap;
    }
    select { min-width: 230px; }
    button.primary { background: var(--blue); border-color: var(--blue); color: white; }
    .statusbar {
      display: grid;
      grid-template-columns: repeat(7, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 14px;
    }
    .stat, .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    .stat { padding: 13px; min-height: 98px; }
    .label { color: var(--muted); font-size: 12px; font-weight: 650; text-transform: uppercase; }
    .metric { font-size: 22px; font-weight: 760; margin-top: 8px; overflow-wrap: anywhere; }
    .small { color: var(--muted); font-size: 13px; line-height: 1.4; margin-top: 6px; }
    .panel { padding: 17px; margin-top: 14px; }
    .split { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 14px; }
    .spine {
      display: grid;
      grid-template-columns: repeat(7, minmax(120px, 1fr));
      gap: 9px;
    }
    .step {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fbfcfd;
      min-height: 94px;
    }
    .step strong { display: block; margin-bottom: 7px; }
    .readiness {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 9px;
    }
    .readiness .item {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fbfcfd;
    }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; table-layout: fixed; }
    th, td { text-align: left; border-bottom: 1px solid var(--line); padding: 10px 8px; vertical-align: top; overflow-wrap: anywhere; }
    th { color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }
    .pill {
      display: inline-flex;
      min-width: 72px;
      justify-content: center;
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 12px;
      font-weight: 750;
      text-transform: uppercase;
    }
    .pass { color: var(--green); background: var(--green-bg); }
    .warning { color: var(--amber); background: var(--amber-bg); }
    .fail { color: var(--red); background: var(--red-bg); }
    .badge { display: inline-flex; align-items: center; border-radius: 6px; padding: 4px 7px; background: var(--blue-bg); color: var(--blue); font-weight: 700; font-size: 12px; }
    .seal { font-size: 18px; line-height: 1.35; }
    @media (max-width: 980px) {
      main { padding: 18px; }
      header { grid-template-columns: 1fr; }
      .actions { justify-content: flex-start; }
      .statusbar { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .split { grid-template-columns: 1fr; }
      .spine { grid-template-columns: 1fr; }
      .readiness { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>Aethelred Sovereign Proof Console</h1>
        <p>Seal-grade evidence path for regulated AI decisions: policy, identity, jurisdiction, quorum, liability, audit export.</p>
      </div>
      <div class="actions">
        <select id="scenario" aria-label="Scenario">${scenarioOptions}</select>
        <button class="primary" onclick="runProof()">Run Proof</button>
        <a class="button" href="/v1/regulator-pack/latest">Regulator Pack</a>
        <a class="button" href="/v1/procurement/latest">Procurement</a>
        <a class="button" href="/v1/redaction/latest">Redaction</a>
        <a class="button" href="/v1/external-compute/latest">Compute Report</a>
        <a class="button" href="/v1/sovereign-differentiation/latest">10x Scorecard</a>
        <a class="button" href="/v1/audit/latest.md">Audit Report</a>
        <a class="button" href="/v1/seals/latest/verify">Verify JSON</a>
      </div>
    </header>

    <section class="statusbar">
      <div class="stat"><div class="label">Status</div><div class="metric"><span class="pill ${report?.valid ? 'pass' : 'fail'}">${escapeHtml(status)}</span></div></div>
      <div class="stat"><div class="label">Assurance</div><div class="metric">Tier ${escapeHtml(assurance.target_tier?.tier || '-')}</div><div class="small">${escapeHtml(assurance.target_tier?.name || '')}</div></div>
      <div class="stat"><div class="label">Quorum</div><div class="metric">${escapeHtml(quorum.accepted || 0)}/${escapeHtml(quorum.required_accepts || 0)}</div><div class="small">${escapeHtml(quorum.categories?.length || 0)} verifier categories</div></div>
      <div class="stat"><div class="label">Jurisdiction</div><div class="metric">${escapeHtml(jurisdiction.jurisdiction || '-')}</div><div class="small">${escapeHtml(jurisdiction.regulator || '')}</div></div>
      <div class="stat"><div class="label">Compute Proof</div><div class="metric">${escapeHtml(externalCompute.provider || '-')}</div><div class="small">${escapeHtml(externalCompute.accepted ? 'accepted' : 'not accepted')}</div></div>
      <div class="stat"><div class="label">Pass</div><div class="metric">${passCount}</div></div>
      <div class="stat"><div class="label">Warnings</div><div class="metric">${warningCount}</div><div class="small">${failCount} failures</div></div>
    </section>

    <section class="panel">
      <div class="label">Aethelred Seal</div>
      <div class="metric seal"><code>${escapeHtml(sealId)}</code></div>
      <div class="small">Run <code>${escapeHtml(record?.run_id || '-')}</code> | ${escapeHtml(record?.request?.tenant?.name || '-')} | ${escapeHtml(record?.request?.use_case || '-')}</div>
    </section>

    <section class="panel">
      <h2>Proof Spine</h2>
      <div class="spine">
        <div class="step"><strong>Request</strong><span class="badge">${escapeHtml(record?.request?.tenant?.sector || '-')}</span><div class="small">${escapeHtml(record?.request?.agent?.name || '-')}</div></div>
        <div class="step"><strong>Policy</strong><span class="badge">${escapeHtml(record?.policy_receipt?.decision || '-')}</span><div class="small">${escapeHtml(record?.policy_receipt?.policy_id || '-')}</div></div>
        <div class="step"><strong>Jurisdiction</strong><span class="badge">${escapeHtml(jurisdiction.execution_region || '-')}</span><div class="small">${escapeHtml(jurisdiction.data_residency_zone || '-')} residency</div></div>
        <div class="step"><strong>Compute</strong><span class="badge">${escapeHtml(externalCompute.provider || '-')}</span><div class="small">${escapeHtml(externalCompute.attestation_type || '-')}</div></div>
        <div class="step"><strong>Quorum</strong><span class="badge">${escapeHtml(quorum.quorum_reached ? 'reached' : 'not reached')}</span><div class="small">${escapeHtml(quorum.quorum_id || '-')}</div></div>
        <div class="step"><strong>Liability</strong><span class="badge">${escapeHtml(liability.status || '-')}</span><div class="small">${escapeHtml(liability.liability_model || '-')}</div></div>
        <div class="step"><strong>Audit</strong><span class="badge">${escapeHtml(artifacts.length)} artifacts</span><div class="small">append-only ledger</div></div>
      </div>
    </section>

    <section class="split">
      <div class="panel">
        <h2>Readiness</h2>
        <div class="readiness">
          <div class="item"><div class="label">Public Proof</div><div class="metric"><span class="pill ${statusClass(readiness.public_proof_path)}">${escapeHtml(readiness.public_proof_path || '-')}</span></div></div>
          <div class="item"><div class="label">Regulated Pilot</div><div class="metric"><span class="pill ${statusClass(readiness.regulated_pilot)}">${escapeHtml(readiness.regulated_pilot || '-')}</span></div></div>
          <div class="item"><div class="label">Production Grade</div><div class="metric"><span class="pill ${statusClass(readiness.production_grade)}">${escapeHtml(String(readiness.production_grade ?? false))}</span></div></div>
        </div>
      </div>
      <div class="panel">
        <h2>Production Blockers</h2>
        <table>
          <thead><tr><th>Blocker</th><th>Owner</th><th>Requirement</th></tr></thead>
          <tbody>${blockerRows}</tbody>
        </table>
      </div>
    </section>

    <section class="panel">
      <h2>10x Sovereign Differentiation</h2>
      <p>${escapeHtml(scorecard.positioning || 'Scorecard not generated yet.')}</p>
      <table>
        <thead><tr><th>Dimension</th><th>Status</th><th>Aethelred Control</th><th>Generic Cloud Baseline</th></tr></thead>
        <tbody>${scorecardRows}</tbody>
      </table>
    </section>

    <section class="panel">
      <h2>Verifier Checks</h2>
      <table>
        <thead><tr><th>Check</th><th>Status</th><th>Evidence</th></tr></thead>
        <tbody>${checkRows}</tbody>
      </table>
    </section>

    <section class="panel">
      <h2>Regulated Verifier Quorum</h2>
      <table>
        <thead><tr><th>Verifier</th><th>Category</th><th>Decision</th><th>Vote Hash</th></tr></thead>
        <tbody>${voteRows}</tbody>
      </table>
    </section>

    <section class="panel">
      <h2>Regulatory Evidence Index</h2>
      <table>
        <thead><tr><th>Artifact</th><th>Purpose</th><th>SHA-256</th></tr></thead>
        <tbody>${artifactRows}</tbody>
      </table>
    </section>
  </main>
  <script>
    async function runProof() {
      const scenarioId = document.getElementById('scenario').value;
      const response = await fetch('/v1/proof-path/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario_id: scenarioId })
      });
      if (!response.ok) alert('Proof run failed');
      location.reload();
    }
  </script>
</body>
</html>`;
};

const ensureInitialRun = async () => {
  const existing = await readLatestRecord(OUTPUT_DIR);
  if (!existing || process.env.AETHELRED_AUTO_RUN === '1') {
    return buildProofPath({ outputDir: OUTPUT_DIR });
  }
  return existing;
};

const latestRegulatorPack = async () => {
  const record = await readLatestRecord(OUTPUT_DIR);
  return {
    schema_version: 'aethelred-regulator-export-v0.2',
    generated_at: new Date().toISOString(),
    service_version: SERVICE_VERSION,
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
    redaction_manifest: record?.redaction_manifest,
    verifier_onboarding_pack: record?.verifier_onboarding_pack,
    procurement_readiness_pack: record?.procurement_readiness_pack,
    sovereign_differentiation_scorecard: record?.sovereign_differentiation_scorecard,
    regulatory_evidence_index: record?.regulatory_evidence_index,
    public_verifier_manifest: record?.public_verifier_manifest,
    ledger_verification: await verifyLedger(OUTPUT_DIR),
  };
};

const handle = async (request, response) => {
  if (request.method === 'OPTIONS') {
    response.writeHead(204, headers);
    response.end();
    return;
  }

  const url = new URL(request.url, `http://${request.headers.host}`);
  try {
    if (request.method === 'GET' && url.pathname === '/') {
      send(response, 200, page(await readLatestRecord(OUTPUT_DIR)), 'text/html; charset=utf-8');
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/health') {
      const latest = await readLatestRecord(OUTPUT_DIR);
      send(response, 200, {
        status: 'ok',
        service: 'aethelred-sovereign-public-proof-path',
        version: SERVICE_VERSION,
        output_dir: OUTPUT_DIR,
        latest_run: latest
          ? {
              run_id: latest.run_id,
              seal_id: latest.seal?.seal_id,
              verifier_valid: latest.verifier_report?.valid,
              external_compute_provider: latest.external_compute_report?.provider,
              assurance_tier: latest.assurance_plan?.target_tier?.tier,
              quorum_reached: latest.validator_quorum?.quorum_reached,
              pilot_status: latest.pilot_readiness_gate?.regulated_pilot_status,
            }
          : null,
      });
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/scenarios') {
      send(response, 200, { scenarios: listScenarios() });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/v1/proof-path/run') {
      const body = await readJsonBody(request);
      const proofRequest = body.request || buildScenarioRequest(body.scenario_id || 'finance');
      const result = await buildProofPath({ request: proofRequest, outputDir: OUTPUT_DIR });
      send(response, 201, result);
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/proof-path/latest') {
      send(response, 200, await readLatestRecord(OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/seals/latest') {
      send(response, 200, await readLatestArtifact('aethelred-seal.json', OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/seals/latest/verify') {
      const record = await readLatestRecord(OUTPUT_DIR);
      send(response, 200, verifyProofRecord(record));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/evidence/latest') {
      send(response, 200, await readLatestArtifact('evidence-bundle.json', OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/external-compute/latest') {
      send(response, 200, await readLatestArtifact('external-compute-report.json', OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/institutional/context') {
      send(response, 200, await readLatestArtifact('institutional-context.json', OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/assurance/latest') {
      send(response, 200, await readLatestArtifact('assurance-plan.json', OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/quorum/latest') {
      send(response, 200, await readLatestArtifact('validator-quorum.json', OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/jurisdiction/latest') {
      send(response, 200, await readLatestArtifact('jurisdiction-report.json', OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/liability/latest') {
      send(response, 200, await readLatestArtifact('liability-route.json', OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/key-custody/latest') {
      send(response, 200, await readLatestArtifact('key-custody-manifest.json', OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/anchor/latest') {
      send(response, 200, await readLatestArtifact('anchor-manifest.json', OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/auditor/latest') {
      send(response, 200, await readLatestArtifact('auditor-attestation.json', OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/readiness/latest') {
      send(response, 200, await readLatestArtifact('pilot-readiness-gate.json', OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/redaction/latest') {
      send(response, 200, await readLatestArtifact('redaction-manifest.json', OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/verifier-onboarding/latest') {
      send(response, 200, await readLatestArtifact('verifier-onboarding-pack.json', OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/procurement/latest') {
      send(response, 200, await readLatestArtifact('procurement-readiness-pack.json', OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/sovereign-differentiation/latest') {
      send(response, 200, await readLatestArtifact('sovereign-differentiation-scorecard.json', OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/evidence-index/latest') {
      send(response, 200, await readLatestArtifact('regulatory-evidence-index.json', OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/regulator-pack/latest') {
      send(response, 200, await latestRegulatorPack());
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/ledger/verify') {
      send(response, 200, await verifyLedger(OUTPUT_DIR));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/audit/latest.md') {
      send(response, 200, await readFile(join(OUTPUT_DIR, 'latest', 'audit-report.md'), 'utf8'), 'text/markdown; charset=utf-8');
      return;
    }
    const artifactMatch = url.pathname.match(/^\/artifacts\/latest\/([^/]+)$/);
    if (request.method === 'GET' && artifactMatch) {
      const safeName = normalize(artifactMatch[1]).replace(/^(\.\.[/\\])+/, '');
      const filePath = join(OUTPUT_DIR, 'latest', safeName);
      const contentType = safeName.endsWith('.md') ? 'text/markdown; charset=utf-8' : 'application/json; charset=utf-8';
      send(response, 200, await readFile(filePath, 'utf8'), contentType);
      return;
    }
    sendError(response, 404, `No route for ${request.method} ${url.pathname}`);
  } catch (error) {
    sendError(response, error.status || 500, error.message);
  }
};

await ensureInitialRun();

createServer(handle).listen(PORT, HOST, () => {
  console.log(`Aethelred sovereign public proof path ${SERVICE_VERSION} listening on http://${HOST}:${PORT}`);
  console.log(`Artifacts: ${OUTPUT_DIR}`);
});
