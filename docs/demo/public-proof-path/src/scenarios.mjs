import { defaultProofRequest, runDemoModel, sha256Hex } from './proof-path.mjs';

const clone = (value) => structuredClone(value);

const finance = () => defaultProofRequest();

const buildExternalComputeProof = ({
  request,
  provider,
  workloadId,
  attestationType,
  executionRegion = request.processing?.execution_region || request.tenant?.jurisdiction,
  limitations = [],
}) => {
  const modelHash = sha256Hex(request.model);
  const inputHash = sha256Hex(request.evidence_input);
  const outputHash = sha256Hex(runDemoModel(request));
  const publicClaims = {
    provider,
    workload_id: workloadId,
    execution_region: executionRegion,
    attestation_type: attestationType,
    model_hash: modelHash,
    input_hash: inputHash,
    output_hash: outputHash,
    claim_boundary: 'Synthetic public interop transcript. Production must replace with provider-native quote verification.',
  };

  return {
    schema_version: 'aethelred-external-compute-proof-v0.2',
    provider,
    workload_id: workloadId,
    execution_region: executionRegion,
    attestation_type: attestationType,
    model_hash: modelHash,
    input_hash: inputHash,
    output_hash: outputHash,
    proof_hash: sha256Hex(publicClaims),
    raw_claims_hash: sha256Hex({
      publicClaims,
      raw_attestation_quote: 'redacted-from-public-demo',
      quote_policy: 'never export raw regulated data into public proof artifacts',
    }),
    public_data_exported: false,
    limitations,
  };
};

const healthcare = () => {
  const request = defaultProofRequest();
  request.use_case = 'healthcare.clinical_recommendation_review';
  request.policy_id = 'healthcare-clinical-ai-decision-v0.2';
  request.tenant = {
    name: 'Aethelred Demo Health System',
    institution_did: 'did:aethelred:institution:demo-hospital',
    institution_type: 'regulated-healthcare-provider',
    sector: 'healthcare',
    jurisdiction: 'AE-DOH',
    regulator: 'Abu Dhabi Department of Health',
  };
  request.processing = {
    data_residency_zone: 'AE',
    execution_region: 'AE-DOH',
    permitted_regions: ['AE-DOH', 'AE-SOVEREIGN-DC'],
    cloud_posture: 'sovereign-health-cloud-ready',
    retention_policy: 'public-demo-synthetic-only',
  };
  request.regulatory_context.frameworks = [
    'UAE PDPL-aligned data minimization',
    'health data residency expectation',
    'clinical decision-support human oversight',
  ];
  request.agent = {
    did: 'did:aethelred:agent:clinical-safety-seal',
    name: 'Clinical Safety Review Agent',
    capabilities: ['risk.score', 'policy.evaluate', 'seal.request'],
    sponsor_of_record: 'did:aethelred:institution:demo-hospital',
    liability_model: 'hospital-sponsored-clinician-accountable',
    human_owner: 'Chief Medical Officer',
    max_autonomous_authority_usd: 0,
  };
  request.model = {
    model_id: 'model:aethelred-clinical-safety-reviewer',
    name: 'aethelred-clinical-safety-reviewer',
    version: '2026.05-demo',
    approval_status: 'approved-for-shadow-demo',
    risk_rating: 'high-impact-supporting-control',
  };
  request.evidence_input = {
    case_id: 'case-demo-ae-health-0007',
    data_boundary: 'Synthetic',
    jurisdiction: 'AE-DOH',
    clinical_risk: 'elevated',
    evidence_quality: 'complete',
    consent_verified: true,
    raw_pii_present: false,
    patient_record_exported: false,
    human_approval: {
      approver_role: 'Consultant Physician Reviewer',
      approver_did: 'did:aethelred:human:clinical-reviewer-1',
      approved: true,
      reason: 'Synthetic clinical decision-support case approved for public proof-path demonstration.',
    },
  };
  return request;
};

const carbon = () => {
  const request = defaultProofRequest();
  request.use_case = 'climate.carbon_mrv_seal';
  request.policy_id = 'carbon-mrv-ai-verification-v0.2';
  request.tenant = {
    name: 'Aethelred Demo Carbon Verifier',
    institution_did: 'did:aethelred:institution:demo-carbon-verifier',
    institution_type: 'regulated-carbon-market-verifier',
    sector: 'carbon-markets',
    jurisdiction: 'AE-MOCCAE',
    regulator: 'UAE climate-market authority target',
  };
  request.processing = {
    data_residency_zone: 'AE',
    execution_region: 'AE-MOCCAE',
    permitted_regions: ['AE-MOCCAE', 'AE-SOVEREIGN-DC'],
    cloud_posture: 'sovereign-climate-market-ready',
    retention_policy: 'public-demo-synthetic-and-enterprise-approved-only',
  };
  request.regulatory_context.frameworks = [
    'carbon MRV auditability expectation',
    'sensor provenance controls',
    'credit issuance evidence retention',
  ];
  request.agent = {
    did: 'did:aethelred:agent:carbon-mrv-seal',
    name: 'Carbon MRV Review Agent',
    capabilities: ['risk.score', 'policy.evaluate', 'seal.request'],
    sponsor_of_record: 'did:aethelred:institution:demo-carbon-verifier',
    liability_model: 'mrv-verifier-sponsored-human-accountable',
    human_owner: 'Head of Carbon Assurance',
    max_autonomous_authority_usd: 0,
  };
  request.model = {
    model_id: 'model:aethelred-carbon-mrv-reviewer',
    name: 'aethelred-carbon-mrv-reviewer',
    version: '2026.05-demo',
    approval_status: 'approved-for-shadow-demo',
    risk_rating: 'high-impact-supporting-control',
  };
  request.evidence_input = {
    project_id: 'mrv-demo-ae-0042',
    data_boundary: 'EnterpriseApprovedNonProduction',
    jurisdiction: 'AE-MOCCAE',
    project_type: 'biochar-and-soil-carbon',
    project_risk: 'medium',
    sensor_provenance: 'verified',
    satellite_crosscheck: 'consistent',
    credit_volume_tco2e: 12400,
    raw_pii_present: false,
    human_approval: {
      approver_role: 'Carbon MRV Auditor',
      approver_did: 'did:aethelred:human:mrv-auditor-1',
      approved: true,
      reason: 'Synthetic carbon MRV evidence approved for public proof-path demonstration.',
    },
  };
  return request;
};

const externalFinance = () => {
  const request = finance();
  request.processing = {
    ...request.processing,
    cloud_posture: 'external-verifiable-cloud-plus-aethelred-sovereign-policy',
  };
  request.regulatory_context.frameworks = [
    ...request.regulatory_context.frameworks,
    'external compute proof ingestion',
    'Aethelred sovereign policy wrapper over verifiable cloud execution',
  ];
  request.external_compute_proof = buildExternalComputeProof({
    request,
    provider: 'external-confidential-vm',
    workloadId: 'external-demo-finance-risk-review',
    attestationType: 'demo-external-transcript',
    limitations: [
      'Synthetic external confidential-compute transcript for public proof-path interop.',
      'Production integration must verify provider-native confidential VM quote.',
      'Aethelred remains the policy, jurisdiction, liability, quorum, audit, and anchor layer.',
    ],
  });
  return request;
};

export const SCENARIOS = {
  finance: {
    id: 'finance',
    label: 'Banking AI Decision Seal',
    use_case: 'finance.high_risk_transaction_review',
    description: 'High-value transaction review with policy, human approval, and liability route.',
    request: finance,
  },
  healthcare: {
    id: 'healthcare',
    label: 'Healthcare AI Audit Trail',
    use_case: 'healthcare.clinical_recommendation_review',
    description: 'Clinical decision-support proof path with consent, clinician approval, and health-data residency.',
    request: healthcare,
  },
  carbon: {
    id: 'carbon',
    label: 'Carbon MRV Seal',
    use_case: 'climate.carbon_mrv_seal',
    description: 'Carbon market MRV evidence seal with sensor provenance and human auditor approval.',
    request: carbon,
  },
  'external-finance': {
    id: 'external-finance',
    label: 'External Compute Proof Wrapped By Aethelred',
    use_case: 'finance.high_risk_transaction_review',
    description: 'External confidential-compute proof accepted only after Aethelred policy, jurisdiction, liability, quorum, and audit controls.',
    request: externalFinance,
  },
};

export const listScenarios = () =>
  Object.values(SCENARIOS).map(({ request, ...scenario }) => clone(scenario));

export const buildScenarioRequest = (scenarioId = 'finance') => {
  const scenario = SCENARIOS[scenarioId];
  if (!scenario) {
    const available = Object.keys(SCENARIOS).join(', ');
    throw new Error(`Unknown scenario '${scenarioId}'. Available scenarios: ${available}`);
  }
  return scenario.request();
};
