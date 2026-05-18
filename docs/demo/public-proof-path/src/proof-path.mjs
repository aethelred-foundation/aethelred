import {
  createHash,
  generateKeyPairSync,
  randomUUID,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

export const SERVICE_VERSION = '0.2.0-sovereign-proof-path';
export const DEFAULT_OUTPUT_DIR = process.env.AETHELRED_PROOF_OUTPUT_DIR || join(process.cwd(), 'out');
export const GENESIS_HASH = 'GENESIS';

const SAFE_DATA_BOUNDARIES = new Set(['Synthetic', 'Anonymized', 'EnterpriseApprovedNonProduction']);
const PII_MARKERS = ['ssn:', 'passport:', 'emirates_id:', 'dob:', '@'];
const DEFAULT_POLICY_ID = 'finance-high-risk-ai-decision-v0.2';

export const REGISTRIES = {
  assurance_tiers: {
    1: {
      name: 'Tier 1 Evidence Log',
      summary: 'Hash commitments, timestamps, and immutable audit log.',
      required_controls: ['hash-commitments', 'audit-log'],
    },
    2: {
      name: 'Tier 2 Attested Enterprise Workflow',
      summary: 'Tier 1 plus confidential-compute shaped attestation and identity-bound operator.',
      required_controls: ['hash-commitments', 'audit-log', 'attestation', 'identity'],
    },
    3: {
      name: 'Tier 3 Regulated Workflow',
      summary: 'Tier 2 plus policy receipt, human approval, and validator quorum.',
      required_controls: ['hash-commitments', 'audit-log', 'attestation', 'identity', 'policy', 'quorum', 'human-approval'],
    },
    4: {
      name: 'Tier 4 Sovereign Regulated AI Decision',
      summary: 'Tier 3 plus jurisdiction controls, liability routing, and zkML-ready output commitment.',
      required_controls: [
        'hash-commitments',
        'audit-log',
        'attestation',
        'identity',
        'policy',
        'quorum',
        'human-approval',
        'jurisdiction',
        'liability',
        'zkml-ready',
      ],
    },
    5: {
      name: 'Tier 5 National-Critical AI Decision',
      summary: 'Tier 4 plus external auditor countersignature, real TEE quote, production zk proof, and HSM custody.',
      required_controls: [
        'hash-commitments',
        'audit-log',
        'attestation',
        'identity',
        'policy',
        'quorum',
        'human-approval',
        'jurisdiction',
        'liability',
        'zkml-ready',
        'external-auditor',
        'hardware-tee',
        'production-zk',
        'hsm-custody',
      ],
    },
  },
  policies: {
    [DEFAULT_POLICY_ID]: {
      policy_id: DEFAULT_POLICY_ID,
      title: 'High-risk AI decision policy for regulated finance',
      sector: 'banking',
      regulator: 'ADGM FSRA',
      jurisdiction: 'AE-ADGM',
      min_assurance_tier: 4,
      human_approval_threshold_usd: 500000,
      use_cases: ['finance.high_risk_transaction_review'],
      required_controls: [
        'data-boundary',
        'jurisdiction',
        'data-residency',
        'model-approval',
        'agent-accountability',
        'human-approval',
        'pii-guard',
        'liability-route',
      ],
    },
    'healthcare-clinical-ai-decision-v0.2': {
      policy_id: 'healthcare-clinical-ai-decision-v0.2',
      title: 'Clinical AI decision-support policy for regulated healthcare',
      sector: 'healthcare',
      regulator: 'Abu Dhabi Department of Health',
      jurisdiction: 'AE-DOH',
      min_assurance_tier: 4,
      human_approval_threshold_usd: 0,
      use_cases: ['healthcare.clinical_recommendation_review'],
      required_controls: [
        'data-boundary',
        'jurisdiction',
        'data-residency',
        'model-approval',
        'agent-accountability',
        'human-approval',
        'pii-guard',
        'liability-route',
      ],
    },
    'carbon-mrv-ai-verification-v0.2': {
      policy_id: 'carbon-mrv-ai-verification-v0.2',
      title: 'Carbon MRV AI verification policy for regulated climate markets',
      sector: 'carbon-markets',
      regulator: 'UAE climate-market authority target',
      jurisdiction: 'AE-MOCCAE',
      min_assurance_tier: 4,
      human_approval_threshold_usd: 0,
      use_cases: ['climate.carbon_mrv_seal'],
      required_controls: [
        'data-boundary',
        'jurisdiction',
        'data-residency',
        'model-approval',
        'agent-accountability',
        'human-approval',
        'pii-guard',
        'liability-route',
      ],
    },
  },
  jurisdictions: {
    'AE-ADGM': {
      jurisdiction: 'AE-ADGM',
      country: 'United Arab Emirates',
      regulator: 'ADGM FSRA',
      data_residency_zone: 'AE',
      allowed_processing_regions: ['AE-ADGM', 'AE-CBUAE', 'AE-SOVEREIGN-DC'],
      public_demo_allowed_boundaries: ['Synthetic', 'Anonymized'],
      sovereign_posture: 'regulated-financial-free-zone',
    },
    'AE-CBUAE': {
      jurisdiction: 'AE-CBUAE',
      country: 'United Arab Emirates',
      regulator: 'Central Bank of the UAE',
      data_residency_zone: 'AE',
      allowed_processing_regions: ['AE-CBUAE', 'AE-SOVEREIGN-DC'],
      public_demo_allowed_boundaries: ['Synthetic', 'Anonymized'],
      sovereign_posture: 'central-bank-regulated',
    },
    'AE-DOH': {
      jurisdiction: 'AE-DOH',
      country: 'United Arab Emirates',
      regulator: 'Abu Dhabi Department of Health',
      data_residency_zone: 'AE',
      allowed_processing_regions: ['AE-DOH', 'AE-SOVEREIGN-DC'],
      public_demo_allowed_boundaries: ['Synthetic', 'Anonymized'],
      sovereign_posture: 'regulated-health-data-zone',
    },
    'AE-MOCCAE': {
      jurisdiction: 'AE-MOCCAE',
      country: 'United Arab Emirates',
      regulator: 'Ministry of Climate Change and Environment target',
      data_residency_zone: 'AE',
      allowed_processing_regions: ['AE-MOCCAE', 'AE-SOVEREIGN-DC'],
      public_demo_allowed_boundaries: ['Synthetic', 'Anonymized', 'EnterpriseApprovedNonProduction'],
      sovereign_posture: 'regulated-climate-market-infrastructure',
    },
    'UK-FCA': {
      jurisdiction: 'UK-FCA',
      country: 'United Kingdom',
      regulator: 'Financial Conduct Authority',
      data_residency_zone: 'UK',
      allowed_processing_regions: ['UK-FCA'],
      public_demo_allowed_boundaries: ['Synthetic', 'Anonymized'],
      sovereign_posture: 'regulated-financial-market',
    },
  },
  models: {
    'model:aethelred-risk-reviewer': {
      model_id: 'model:aethelred-risk-reviewer',
      owner: 'did:aethelred:institution:aethelred-labs',
      purpose: 'financial-crime risk review support',
      versions: {
        '2026.05-demo': {
          approval_status: 'approved-for-shadow-demo',
          risk_rating: 'high-impact-supporting-control',
          assurance_floor: 4,
          approved_by: 'did:aethelred:council:model-risk',
        },
      },
    },
    'model:aethelred-clinical-safety-reviewer': {
      model_id: 'model:aethelred-clinical-safety-reviewer',
      owner: 'did:aethelred:institution:aethelred-labs',
      purpose: 'clinical decision-support safety review',
      versions: {
        '2026.05-demo': {
          approval_status: 'approved-for-shadow-demo',
          risk_rating: 'high-impact-supporting-control',
          assurance_floor: 4,
          approved_by: 'did:aethelred:council:model-risk',
        },
      },
    },
    'model:aethelred-carbon-mrv-reviewer': {
      model_id: 'model:aethelred-carbon-mrv-reviewer',
      owner: 'did:aethelred:institution:aethelred-labs',
      purpose: 'carbon MRV evidence consistency review',
      versions: {
        '2026.05-demo': {
          approval_status: 'approved-for-shadow-demo',
          risk_rating: 'high-impact-supporting-control',
          assurance_floor: 4,
          approved_by: 'did:aethelred:council:model-risk',
        },
      },
    },
  },
  identities: {
    institutions: {
      'did:aethelred:institution:demo-bank': {
        legal_name: 'Aethelred Demo Bank',
        institution_type: 'regulated-financial-institution',
        jurisdiction: 'AE-ADGM',
        accountability_role: 'sponsor-of-record',
      },
      'did:aethelred:institution:aethelred-labs': {
        legal_name: 'Aethelred Labs',
        institution_type: 'protocol-operator',
        jurisdiction: 'AE-ADGM',
        accountability_role: 'protocol-maintainer',
      },
      'did:aethelred:institution:demo-hospital': {
        legal_name: 'Aethelred Demo Health System',
        institution_type: 'regulated-healthcare-provider',
        jurisdiction: 'AE-DOH',
        accountability_role: 'clinical-sponsor-of-record',
      },
      'did:aethelred:institution:demo-carbon-verifier': {
        legal_name: 'Aethelred Demo Carbon Verifier',
        institution_type: 'regulated-carbon-market-verifier',
        jurisdiction: 'AE-MOCCAE',
        accountability_role: 'mrv-sponsor-of-record',
      },
    },
    agents: {
      'did:aethelred:agent:finance-risk-seal': {
        name: 'Finance Risk Review Agent',
        owner: 'did:aethelred:institution:demo-bank',
        allowed_actions: ['risk.score', 'policy.evaluate', 'seal.request'],
        max_autonomous_authority_usd: 0,
      },
      'did:aethelred:agent:clinical-safety-seal': {
        name: 'Clinical Safety Review Agent',
        owner: 'did:aethelred:institution:demo-hospital',
        allowed_actions: ['risk.score', 'policy.evaluate', 'seal.request'],
        max_autonomous_authority_usd: 0,
      },
      'did:aethelred:agent:carbon-mrv-seal': {
        name: 'Carbon MRV Review Agent',
        owner: 'did:aethelred:institution:demo-carbon-verifier',
        allowed_actions: ['risk.score', 'policy.evaluate', 'seal.request'],
        max_autonomous_authority_usd: 0,
      },
    },
    humans: {
      'did:aethelred:human:fcc-approver-1': {
        role: 'Financial Crime Compliance Officer',
        institution: 'did:aethelred:institution:demo-bank',
        approval_scope: ['finance.high_risk_transaction_review'],
      },
      'did:aethelred:human:clinical-reviewer-1': {
        role: 'Consultant Physician Reviewer',
        institution: 'did:aethelred:institution:demo-hospital',
        approval_scope: ['healthcare.clinical_recommendation_review'],
      },
      'did:aethelred:human:mrv-auditor-1': {
        role: 'Carbon MRV Auditor',
        institution: 'did:aethelred:institution:demo-carbon-verifier',
        approval_scope: ['climate.carbon_mrv_seal'],
      },
    },
  },
  verifiers: {
    'did:aethelred:verifier:regulated-cloud-ae': {
      name: 'Regulated Cloud Verifier AE',
      category: 'regulated-cloud-provider',
      jurisdiction: 'AE-ADGM',
      controls: ['attestation', 'data-residency'],
    },
    'did:aethelred:verifier:cyber-auditor': {
      name: 'Cyber Assurance Verifier',
      category: 'cybersecurity-auditor',
      jurisdiction: 'AE-ADGM',
      controls: ['container-measurement', 'signature-integrity'],
    },
    'did:aethelred:verifier:policy-auditor': {
      name: 'Policy and Compliance Verifier',
      category: 'compliance-auditor',
      jurisdiction: 'AE-ADGM',
      controls: ['policy', 'human-approval', 'liability'],
    },
    'did:aethelred:verifier:sovereign-observer': {
      name: 'Sovereign Observer Verifier',
      category: 'sovereign-infrastructure-observer',
      jurisdiction: 'AE-ADGM',
      controls: ['jurisdiction', 'audit-export'],
    },
  },
  deployment_modes: {
    'hybrid-public-seal': {
      mode: 'hybrid-public-seal',
      description: 'Private or controlled execution with public seal anchoring.',
      suitable_for: ['banking', 'healthcare', 'carbon-markets', 'public-sector'],
      public_data_allowed: false,
      public_commitments_allowed: true,
    },
    'sovereign-private': {
      mode: 'sovereign-private',
      description: 'Dedicated institutional or national deployment with controlled validators.',
      suitable_for: ['defense', 'public-sector', 'critical-infrastructure'],
      public_data_allowed: false,
      public_commitments_allowed: false,
    },
  },
  compute_substrates: {
    'aethelred-docker-public-proof': {
      name: 'Aethelred Docker Public Proof Path',
      category: 'public-demo',
      jurisdiction_model: 'local-public-proof',
      accepted_attestation_types: ['docker-demo-transcript'],
      production_grade: false,
      strategic_role: 'native public proof path for demonstrations and regression tests',
    },
    'external-confidential-vm': {
      name: 'External Confidential VM',
      category: 'external-verifiable-cloud',
      jurisdiction_model: 'external-cloud',
      accepted_attestation_types: ['confidential-vm-attestation', 'demo-external-transcript'],
      production_grade: false,
      strategic_role: 'external compute proof source that Aethelred can govern, seal, audit, and anchor',
    },
    'aws-nitro-enclave': {
      name: 'AWS Nitro Enclave',
      category: 'cloud-tee',
      jurisdiction_model: 'cloud-region-bound',
      accepted_attestation_types: ['nitro-attestation-document', 'demo-external-transcript'],
      production_grade: false,
      strategic_role: 'cloud TEE proof source for private execution and public seal anchoring',
    },
    'g42-core42-sovereign-cloud': {
      name: 'G42/Core42 Sovereign Cloud',
      category: 'sovereign-cloud',
      jurisdiction_model: 'sovereign-region-bound',
      accepted_attestation_types: ['sovereign-cloud-attestation', 'confidential-vm-attestation', 'demo-external-transcript'],
      production_grade: false,
      strategic_role: 'sovereign-cloud proof source for UAE institutional deployments',
    },
    'onprem-regulated-enclave': {
      name: 'On-prem Regulated Enclave',
      category: 'on-prem',
      jurisdiction_model: 'institution-controlled',
      accepted_attestation_types: ['sgx-quote', 'sev-snp-report', 'tdx-quote', 'demo-external-transcript'],
      production_grade: false,
      strategic_role: 'private deployment proof source for defense, health, and critical infrastructure',
    },
  },
};

export const canonicalize = (value) => {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.keys(value)
      .sort()
      .reduce((acc, key) => {
        const item = value[key];
        if (item !== undefined) acc[key] = canonicalize(item);
        return acc;
      }, {});
  }
  return value;
};

export const stableStringify = (value) => JSON.stringify(canonicalize(value));

export const sha256Hex = (value) =>
  createHash('sha256')
    .update(typeof value === 'string' || Buffer.isBuffer(value) ? value : stableStringify(value))
    .digest('hex');

const base64Json = (value) => Buffer.from(stableStringify(value)).toString('base64');

const nowIso = () => new Date().toISOString();

const omit = (object, keys) => Object.fromEntries(Object.entries(object || {}).filter(([key]) => !keys.includes(key)));

const signerId = (value) => String(value).replace(/[^a-zA-Z0-9:-]/g, '-').slice(0, 64);

const makeSigner = (entityId) => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  return {
    entityId,
    privateKey,
    publicKey,
    publicKeyPem,
    keyId: `${signerId(entityId)}-${sha256Hex(publicKeyPem).slice(0, 16)}`,
  };
};

const signerDescriptor = (signer) => ({
  id: signer.entityId,
  key_id: signer.keyId,
  algorithm: 'Ed25519',
  public_key_pem: signer.publicKeyPem,
});

const signPayload = (payload, signer) =>
  cryptoSign(null, Buffer.from(stableStringify(payload)), signer.privateKey).toString('base64');

const verifyPayload = (payload, signature, publicKeyPem) => {
  try {
    return cryptoVerify(null, Buffer.from(stableStringify(payload)), publicKeyPem, Buffer.from(signature || '', 'base64'));
  } catch {
    return false;
  }
};

const signDocument = (payload, signer, hashField = 'content_hash') => ({
  ...payload,
  [hashField]: sha256Hex(payload),
  signature: signPayload(payload, signer),
});

export const defaultProofRequest = () => ({
  schema_version: 'aethelred-proof-request-v0.2',
  use_case: 'finance.high_risk_transaction_review',
  policy_id: DEFAULT_POLICY_ID,
  requested_assurance_tier: 4,
  deployment_mode: 'hybrid-public-seal',
  tenant: {
    name: 'Aethelred Demo Bank',
    institution_did: 'did:aethelred:institution:demo-bank',
    institution_type: 'regulated-financial-institution',
    sector: 'banking',
    jurisdiction: 'AE-ADGM',
    regulator: 'ADGM FSRA',
  },
  processing: {
    data_residency_zone: 'AE',
    execution_region: 'AE-ADGM',
    permitted_regions: ['AE-ADGM', 'AE-CBUAE', 'AE-SOVEREIGN-DC'],
    cloud_posture: 'sovereign-cloud-ready',
    retention_policy: 'public-demo-synthetic-only',
  },
  regulatory_context: {
    frameworks: ['ADGM FSRA governance expectation', 'UAE PDPL-aligned data minimization', 'financial-crime model-risk controls'],
    control_objectives: [
      'Prove who requested the AI decision.',
      'Prove what model and policy were applied.',
      'Prove where the workflow was allowed to run.',
      'Prove who is accountable for the final decision.',
      'Export a regulator-readable evidence pack without exposing raw sensitive data.',
    ],
  },
  agent: {
    did: 'did:aethelred:agent:finance-risk-seal',
    name: 'Finance Risk Review Agent',
    capabilities: ['risk.score', 'policy.evaluate', 'seal.request'],
    sponsor_of_record: 'did:aethelred:institution:demo-bank',
    liability_model: 'enterprise-sponsored-human-accountable',
    human_owner: 'Head of Financial Crime Controls',
    max_autonomous_authority_usd: 0,
  },
  model: {
    model_id: 'model:aethelred-risk-reviewer',
    name: 'aethelred-risk-reviewer',
    version: '2026.05-demo',
    approval_status: 'approved-for-shadow-demo',
    risk_rating: 'high-impact-supporting-control',
  },
  evidence_input: {
    transaction_id: 'txn-demo-ae-00042',
    data_boundary: 'Synthetic',
    jurisdiction: 'AE-ADGM',
    amount_usd: 920000,
    channel: 'cross-border-corporate-payment',
    counterparty_risk: 'medium',
    sanctions_screen: 'clear',
    adverse_media: 'none',
    raw_pii_present: false,
    human_approval: {
      approver_role: 'Financial Crime Compliance Officer',
      approver_did: 'did:aethelred:human:fcc-approver-1',
      approved: true,
      reason: 'Synthetic high-risk payment approved for public proof-path demonstration.',
    },
  },
});

const getModelVersion = (request) =>
  REGISTRIES.models[request.model?.model_id]?.versions?.[request.model?.version] || null;

const buildPolicyChecks = (request) => {
  const input = request.evidence_input || {};
  const policy = REGISTRIES.policies[request.policy_id || DEFAULT_POLICY_ID];
  const jurisdiction = REGISTRIES.jurisdictions[input.jurisdiction || request.tenant?.jurisdiction];
  const processingRegion = request.processing?.execution_region || input.jurisdiction || request.tenant?.jurisdiction;
  const text = stableStringify(input).toLowerCase();
  const amount = Number(input.amount_usd || 0);
  const modelVersion = getModelVersion(request);
  const agentProfile = REGISTRIES.identities.agents[request.agent?.did];
  const sponsorProfile = REGISTRIES.identities.institutions[request.agent?.sponsor_of_record];
  const humanApprover = REGISTRIES.identities.humans[input.human_approval?.approver_did];
  const requiresHuman = amount >= (policy?.human_approval_threshold_usd || 0) || request.model?.risk_rating?.startsWith('high');
  const rawPiiDetected = input.raw_pii_present === true || PII_MARKERS.some((marker) => text.includes(marker));

  return [
    {
      id: 'policy-supported-use-case',
      label: 'Use case is governed by the selected policy',
      required: true,
      passed: Boolean(policy?.use_cases?.includes(request.use_case)),
      evidence: request.use_case || 'missing',
      control_owner: 'policy-registry',
    },
    {
      id: 'data-boundary',
      label: 'Approved public-demo data boundary',
      required: true,
      passed: SAFE_DATA_BOUNDARIES.has(input.data_boundary),
      evidence: input.data_boundary || 'missing',
      control_owner: 'data-governance',
    },
    {
      id: 'jurisdiction',
      label: 'Jurisdiction is registered and policy allowed',
      required: true,
      passed: Boolean(jurisdiction && policy?.jurisdiction === (input.jurisdiction || request.tenant?.jurisdiction)),
      evidence: input.jurisdiction || request.tenant?.jurisdiction || 'missing',
      control_owner: 'jurisdiction-registry',
    },
    {
      id: 'data-residency',
      label: 'Execution region is allowed for the data residency zone',
      required: true,
      passed: Boolean(jurisdiction?.allowed_processing_regions?.includes(processingRegion)),
      evidence: `${processingRegion || 'missing'} within ${request.processing?.data_residency_zone || 'unknown'}`,
      control_owner: 'jurisdiction-registry',
    },
    {
      id: 'model-approval',
      label: 'Model version is approved for the workflow',
      required: true,
      passed: Boolean(modelVersion && String(request.model?.approval_status || '').startsWith('approved')),
      evidence: `${request.model?.model_id || 'unknown'} ${request.model?.version || ''}`.trim(),
      control_owner: 'model-registry',
    },
    {
      id: 'assurance-floor',
      label: 'Requested assurance tier meets model and policy floor',
      required: true,
      passed: Number(request.requested_assurance_tier || 0) >= Math.max(policy?.min_assurance_tier || 1, modelVersion?.assurance_floor || 1),
      evidence: `requested Tier ${request.requested_assurance_tier || 'missing'}`,
      control_owner: 'assurance-registry',
    },
    {
      id: 'agent-accountability',
      label: 'Agent identity, sponsor, and liability profile are registered',
      required: true,
      passed: Boolean(agentProfile && sponsorProfile && request.agent?.liability_model),
      evidence: request.agent?.sponsor_of_record || 'missing sponsor',
      control_owner: 'identity-registry',
    },
    {
      id: 'agent-permissions',
      label: 'Agent capabilities authorize scoring, policy evaluation, and seal request',
      required: true,
      passed: ['risk.score', 'policy.evaluate', 'seal.request'].every((capability) =>
        agentProfile?.allowed_actions?.includes(capability) && request.agent?.capabilities?.includes(capability),
      ),
      evidence: (request.agent?.capabilities || []).join(', ') || 'missing',
      control_owner: 'identity-registry',
    },
    {
      id: 'human-approval',
      label: 'Human approval is bound for high-risk action',
      required: requiresHuman,
      passed: !requiresHuman || (input.human_approval?.approved === true && Boolean(humanApprover)),
      evidence: input.human_approval?.approver_role || 'not required',
      control_owner: 'human-in-the-loop',
    },
    {
      id: 'autonomy-limit',
      label: 'Agent cannot autonomously execute the high-value transaction',
      required: true,
      passed: amount > Number(request.agent?.max_autonomous_authority_usd || 0) ? input.human_approval?.approved === true : true,
      evidence: `amount=${amount}; autonomous_limit=${request.agent?.max_autonomous_authority_usd || 0}`,
      control_owner: 'human-in-the-loop',
    },
    {
      id: 'pii-guard',
      label: 'No raw PII markers are present in the public proof input',
      required: true,
      passed: !rawPiiDetected,
      evidence: rawPiiDetected ? 'raw PII marker detected' : 'synthetic/public-safe input',
      control_owner: 'privacy-control',
    },
    {
      id: 'liability-route',
      label: 'Sponsor, human owner, and operator liability route can be formed',
      required: true,
      passed: Boolean(request.agent?.sponsor_of_record && request.agent?.human_owner && request.tenant?.institution_did),
      evidence: request.agent?.liability_model || 'missing',
      control_owner: 'liability-engine',
    },
  ];
};

export const runDemoModel = (request) => {
  const input = request.evidence_input || {};

  if (request.use_case === 'healthcare.clinical_recommendation_review') {
    const severity = input.clinical_risk === 'critical' ? 34 : input.clinical_risk === 'elevated' ? 22 : 12;
    const consentRisk = input.consent_verified ? 0 : 28;
    const evidenceRisk = input.evidence_quality === 'complete' ? 4 : 16;
    const riskScore = Math.min(99, 35 + severity + consentRisk + evidenceRisk);

    return {
      schema_version: 'aethelred-model-output-v0.2',
      recommendation: riskScore >= 80 ? 'specialist_review_required' : 'approve_with_clinical_controls',
      risk_score: riskScore,
      decision_boundary: 'clinical-decision-support-only-human-clinician-required',
      reason_codes: [
        `${input.clinical_risk || 'unknown'}-clinical-risk`,
        input.consent_verified ? 'consent-verified' : 'consent-review-required',
        `${input.evidence_quality || 'unknown'}-evidence-quality`,
      ],
      controls_required: [
        'licensed-clinician-approval',
        'patient-consent-evidence',
        'clinical-audit-retention',
      ],
      reviewer_action: input.human_approval?.approved ? 'approved_by_clinical_controller' : 'pending_clinical_controller',
    };
  }

  if (request.use_case === 'climate.carbon_mrv_seal') {
    const projectRisk = input.project_risk === 'high' ? 28 : input.project_risk === 'medium' ? 16 : 8;
    const provenanceRisk = input.sensor_provenance === 'verified' ? 0 : 24;
    const satelliteRisk = input.satellite_crosscheck === 'consistent' ? 0 : 20;
    const riskScore = Math.min(99, 30 + projectRisk + provenanceRisk + satelliteRisk);

    return {
      schema_version: 'aethelred-model-output-v0.2',
      recommendation: riskScore >= 80 ? 'independent_mrv_review_required' : 'issue_with_controls',
      risk_score: riskScore,
      decision_boundary: 'mrv-decision-support-only-human-verifier-required',
      reason_codes: [
        `${input.project_risk || 'unknown'}-project-risk`,
        `${input.sensor_provenance || 'unknown'}-sensor-provenance`,
        `${input.satellite_crosscheck || 'unknown'}-satellite-crosscheck`,
      ],
      controls_required: [
        'human-mrv-auditor-approval',
        'sensor-provenance-retention',
        'post-issuance-reversal-monitoring',
      ],
      reviewer_action: input.human_approval?.approved ? 'approved_by_mrv_controller' : 'pending_mrv_controller',
    };
  }

  const amount = Number(input.amount_usd || 0);
  const amountRisk = Math.min(24, Math.floor(amount / 50000));
  const counterpartyRisk = input.counterparty_risk === 'high' ? 22 : input.counterparty_risk === 'medium' ? 12 : 4;
  const sanctionsRisk = input.sanctions_screen === 'clear' ? 0 : 35;
  const riskScore = Math.min(99, 38 + amountRisk + counterpartyRisk + sanctionsRisk);

  return {
    schema_version: 'aethelred-model-output-v0.2',
    recommendation: riskScore >= 80 ? 'manual_review_required' : 'approve_with_controls',
    risk_score: riskScore,
    decision_boundary: 'supporting-control-only-human-controller-required',
    reason_codes: [
      amount >= 500000 ? 'large-value-transfer' : 'standard-value-transfer',
      `${input.counterparty_risk || 'unknown'}-counterparty-risk`,
      input.sanctions_screen === 'clear' ? 'sanctions-clear' : 'sanctions-review',
    ],
    controls_required: [
      'human-controller-approval',
      'audit-pack-retention',
      'post-decision-monitoring',
    ],
    reviewer_action: input.human_approval?.approved ? 'approved_by_human_controller' : 'pending_human_controller',
  };
};

const buildInstitutionalContext = (request, issuedAt) => {
  const policy = REGISTRIES.policies[request.policy_id || DEFAULT_POLICY_ID] || null;
  const jurisdiction = REGISTRIES.jurisdictions[request.tenant?.jurisdiction] || null;
  const modelProfile = REGISTRIES.models[request.model?.model_id] || null;
  const modelVersion = getModelVersion(request);
  const agentProfile = REGISTRIES.identities.agents[request.agent?.did] || null;
  const sponsorProfile = REGISTRIES.identities.institutions[request.agent?.sponsor_of_record] || null;
  const deploymentProfile = REGISTRIES.deployment_modes[request.deployment_mode] || null;
  const assuranceTarget = REGISTRIES.assurance_tiers[request.requested_assurance_tier] || null;

  return {
    schema_version: 'aethelred-institutional-context-v0.2',
    generated_at: issuedAt,
    tenant: request.tenant,
    policy,
    jurisdiction,
    model_registration: {
      model_id: request.model?.model_id,
      profile: modelProfile
        ? {
            owner: modelProfile.owner,
            purpose: modelProfile.purpose,
            version: request.model?.version,
            version_status: modelVersion,
          }
        : null,
    },
    identity_registration: {
      agent: agentProfile,
      sponsor: sponsorProfile,
      human_controller: REGISTRIES.identities.humans[request.evidence_input?.human_approval?.approver_did] || null,
    },
    deployment_profile: deploymentProfile,
    assurance_target: assuranceTarget
      ? {
          tier: request.requested_assurance_tier,
          ...assuranceTarget,
        }
      : null,
    governance_posture: {
      foundation: 'ADGM DLT Foundation target',
      assurance_council: 'Technical, legal, security, and regulatory review body target',
      regulated_validator_council: 'Banks, sovereign cloud, auditors, research labs, and sector verifiers target',
      public_claim_boundary: 'Public Docker path proves evidence architecture, not production TEE or zkML finality.',
    },
  };
};

const buildJurisdictionReport = ({ request, policyReceipt, policyChecks, issuedAt }) => {
  const input = request.evidence_input || {};
  const jurisdiction = REGISTRIES.jurisdictions[input.jurisdiction || request.tenant?.jurisdiction] || null;
  const dataResidencyCheck = policyChecks.find((item) => item.id === 'data-residency');
  const jurisdictionCheck = policyChecks.find((item) => item.id === 'jurisdiction');

  return {
    schema_version: 'aethelred-jurisdiction-report-v0.2',
    generated_at: issuedAt,
    jurisdiction: input.jurisdiction || request.tenant?.jurisdiction,
    regulator: jurisdiction?.regulator || request.tenant?.regulator || 'unknown',
    data_residency_zone: request.processing?.data_residency_zone || jurisdiction?.data_residency_zone || 'unknown',
    execution_region: request.processing?.execution_region || input.jurisdiction || 'unknown',
    permitted_regions: request.processing?.permitted_regions || jurisdiction?.allowed_processing_regions || [],
    data_boundary: input.data_boundary || 'missing',
    public_demo_safe: jurisdiction?.public_demo_allowed_boundaries?.includes(input.data_boundary) || false,
    jurisdiction_allowed: jurisdictionCheck?.passed === true,
    data_residency_allowed: dataResidencyCheck?.passed === true,
    policy_receipt_hash: policyReceipt.content_hash,
    export_controls: {
      raw_data_exported: false,
      public_artifacts_use_hash_commitments: true,
      regulator_pack_contains_synthetic_input_only: true,
    },
  };
};

const buildLiabilityRoute = ({ request, policyReceipt, modelOutput, issuedAt }) => ({
  schema_version: 'aethelred-liability-route-v0.2',
  route_id: `route_${sha256Hex({ request_id: policyReceipt.request_id, sponsor: request.agent?.sponsor_of_record }).slice(0, 20)}`,
  generated_at: issuedAt,
  status: policyReceipt.decision === 'allow' ? 'bound' : 'blocked-by-policy',
  liability_model: request.agent?.liability_model || 'missing',
  decision_boundary: modelOutput.decision_boundary,
  parties: [
    {
      role: 'sponsor-of-record',
      did: request.agent?.sponsor_of_record,
      obligation: 'Owns institutional accountability for agent deployment and controls.',
      status: request.agent?.sponsor_of_record ? 'bound' : 'missing',
    },
    {
      role: 'human-controller',
      did: request.evidence_input?.human_approval?.approver_did,
      obligation: 'Approves high-risk action and remains final accountable decision controller.',
      status: request.evidence_input?.human_approval?.approved ? 'approved' : 'missing',
    },
    {
      role: 'model-risk-owner',
      did: request.model?.approved_by || REGISTRIES.models[request.model?.model_id]?.versions?.[request.model?.version]?.approved_by,
      obligation: 'Maintains model approval, version control, risk rating, and sunset policy.',
      status: getModelVersion(request) ? 'registered' : 'missing',
    },
    {
      role: 'protocol-operator',
      did: 'did:aethelred:institution:aethelred-labs',
      obligation: 'Maintains seal protocol, verifier policy, and evidence schema.',
      status: 'bound-for-demo',
    },
    {
      role: 'external-auditor',
      did: 'did:aethelred:verifier:policy-auditor',
      obligation: 'Countersigns verifier report for regulated pilot and production use.',
      status: 'simulated-public-proof-path',
    },
  ],
  escalation_matrix: [
    { trigger: 'policy-denied', owner: 'sponsor-of-record', action: 'block seal and create exception review' },
    { trigger: 'verifier-quorum-failed', owner: 'protocol-operator', action: 'quarantine evidence and require independent auditor review' },
    { trigger: 'post-decision-harm', owner: 'human-controller', action: 'activate liability review and regulator evidence export' },
  ],
});

const buildExternalComputeReport = ({ request, modelHash, inputHash, outputHash, issuedAt, signer }) => {
  const externalProof = request.external_compute_proof || {
    schema_version: 'aethelred-external-compute-proof-v0.2',
    provider: 'aethelred-docker-public-proof',
    workload_id: 'docker-local-public-proof-path',
    execution_region: request.processing?.execution_region || request.tenant?.jurisdiction,
    attestation_type: 'docker-demo-transcript',
    model_hash: modelHash,
    input_hash: inputHash,
    output_hash: outputHash,
    proof_hash: sha256Hex({
      provider: 'aethelred-docker-public-proof',
      model_hash: modelHash,
      input_hash: inputHash,
      output_hash: outputHash,
    }),
    raw_claims_hash: sha256Hex({
      service_version: SERVICE_VERSION,
      path: 'native-docker-public-proof',
    }),
    public_data_exported: false,
    limitations: ['Public demo transcript, not production hardware attestation.'],
  };
  const provider = REGISTRIES.compute_substrates[externalProof.provider];
  const jurisdiction = REGISTRIES.jurisdictions[request.tenant?.jurisdiction];
  const executionRegion = externalProof.execution_region || request.processing?.execution_region || request.tenant?.jurisdiction;
  const checks = [
    {
      id: 'provider-registered',
      label: 'Compute proof provider is registered',
      required: true,
      passed: Boolean(provider),
      evidence: externalProof.provider || 'missing',
    },
    {
      id: 'attestation-type-supported',
      label: 'Attestation type is supported for the provider adapter',
      required: true,
      passed: Boolean(provider?.accepted_attestation_types?.includes(externalProof.attestation_type)),
      evidence: externalProof.attestation_type || 'missing',
    },
    {
      id: 'model-hash-bound',
      label: 'External proof binds the expected model hash',
      required: true,
      passed: externalProof.model_hash === modelHash,
      evidence: externalProof.model_hash || 'missing',
    },
    {
      id: 'input-hash-bound',
      label: 'External proof binds the expected input hash',
      required: true,
      passed: externalProof.input_hash === inputHash,
      evidence: externalProof.input_hash || 'missing',
    },
    {
      id: 'output-hash-bound',
      label: 'External proof binds the expected output hash',
      required: true,
      passed: externalProof.output_hash === outputHash,
      evidence: externalProof.output_hash || 'missing',
    },
    {
      id: 'proof-hash-present',
      label: 'External proof has a stable proof hash',
      required: true,
      passed: typeof externalProof.proof_hash === 'string' && externalProof.proof_hash.length >= 32,
      evidence: externalProof.proof_hash || 'missing',
    },
    {
      id: 'execution-region-allowed',
      label: 'External execution region is allowed for the policy jurisdiction',
      required: true,
      passed: Boolean(jurisdiction?.allowed_processing_regions?.includes(executionRegion) || executionRegion === request.processing?.execution_region),
      evidence: executionRegion || 'missing',
    },
    {
      id: 'no-public-data-export',
      label: 'External provider exported commitments only, not raw regulated data',
      required: true,
      passed: externalProof.public_data_exported !== true,
      evidence: externalProof.public_data_exported ? 'raw data export flagged' : 'commitments only',
    },
  ];
  const failedRequired = checks.filter((check) => check.required && !check.passed);
  const payload = {
    schema_version: 'aethelred-external-compute-report-v0.2',
    generated_at: issuedAt,
    provider: externalProof.provider,
    provider_profile: provider || null,
    workload_id: externalProof.workload_id || 'missing',
    execution_region: executionRegion,
    attestation_type: externalProof.attestation_type || 'missing',
    external_proof_hash: sha256Hex(externalProof),
    accepted: failedRequired.length === 0,
    checks,
    failed_required_checks: failedRequired.map((check) => check.id),
    normalized_claims: {
      model_hash: externalProof.model_hash || modelHash,
      input_hash: externalProof.input_hash || inputHash,
      output_hash: externalProof.output_hash || outputHash,
      proof_hash: externalProof.proof_hash || 'missing',
      raw_claims_hash: externalProof.raw_claims_hash || sha256Hex(externalProof),
      public_data_exported: externalProof.public_data_exported === true,
    },
    strategic_interop_note: 'External compute proof source is wrapped by Aethelred sovereign verification controls.',
    signer: signerDescriptor(signer),
  };

  return signDocument(payload, signer, 'report_hash');
};

const buildVote = ({ quorumId, verifierId, profile, signer, evidenceBundleHash, policyReceipt, issuedAt, decision }) => {
  const payload = {
    schema_version: 'aethelred-verifier-vote-v0.2',
    quorum_id: quorumId,
    verifier_id: verifierId,
    verifier_name: profile.name,
    category: profile.category,
    jurisdiction: profile.jurisdiction,
    controls: profile.controls,
    decision,
    evidence_bundle_hash: evidenceBundleHash,
    policy_receipt_hash: policyReceipt.content_hash,
    issued_at: issuedAt,
    signer: signerDescriptor(signer),
  };
  return {
    ...payload,
    vote_hash: sha256Hex(payload),
    signature: signPayload(payload, signer),
  };
};

const buildValidatorQuorum = ({ evidenceBundleHash, policyReceipt, issuedAt, verifierSigners }) => {
  const quorumId = `quorum_${sha256Hex({ evidenceBundleHash, policyReceipt: policyReceipt.content_hash }).slice(0, 20)}`;
  const decision = policyReceipt.decision === 'allow' ? 'accept' : 'reject';
  const votes = Object.entries(REGISTRIES.verifiers).map(([verifierId, profile]) =>
    buildVote({
      quorumId,
      verifierId,
      profile,
      signer: verifierSigners[verifierId],
      evidenceBundleHash,
      policyReceipt,
      issuedAt,
      decision,
    }),
  );
  const accepted = votes.filter((vote) => vote.decision === 'accept').length;
  const rejected = votes.filter((vote) => vote.decision === 'reject').length;
  const requiredAccepts = 3;

  return {
    schema_version: 'aethelred-validator-quorum-v0.2',
    quorum_id: quorumId,
    strategy: 'regulated-multi-verifier-public-proof-path',
    required_accepts: requiredAccepts,
    accepted,
    rejected,
    quorum_reached: accepted >= requiredAccepts && rejected === 0,
    categories: [...new Set(votes.map((vote) => vote.category))],
    votes,
  };
};

const buildAssurancePlan = ({ request, policyReceipt, jurisdictionReport, validatorQuorum, issuedAt }) => {
  const tier = Number(request.requested_assurance_tier || 1);
  const target = REGISTRIES.assurance_tiers[tier] || REGISTRIES.assurance_tiers[1];
  const productionBlockers = [
    {
      id: 'production-hardware-tee',
      status: 'open',
      owner: 'compute-provider',
      requirement: 'Replace Docker demo attestation with Nitro, SGX, SEV-SNP, Intel TDX, or sovereign-cloud attestation.',
    },
    {
      id: 'production-zkml-proof',
      status: 'open',
      owner: 'model-verification',
      requirement: 'Replace demo proof transcript with workflow-appropriate zkML or deterministic verifier evidence.',
    },
    {
      id: 'external-compute-quote-verifier',
      status: 'open',
      owner: 'compute-adapter',
      requirement: 'Replace synthetic external proof transcripts with provider-native sovereign-cloud, confidential-VM, or on-prem quote verification.',
    },
    {
      id: 'governed-key-custody',
      status: 'open',
      owner: 'protocol-governance',
      requirement: 'Move demo Ed25519 keys to governed KMS/HSM custody and publish key rotation policy.',
    },
    {
      id: 'external-audit-countersignature',
      status: 'open',
      owner: 'assurance-council',
      requirement: 'Add independent security and regulatory auditor countersignature before regulated pilot claims.',
    },
  ];

  return {
    schema_version: 'aethelred-assurance-plan-v0.2',
    generated_at: issuedAt,
    target_tier: {
      tier,
      ...target,
    },
    current_path: {
      classification: 'public-docker-proof-path',
      production_grade: false,
      public_verifiability: true,
      regulator_pack_exportable: true,
    },
    controls: [
      {
        id: 'policy-native',
        label: 'Policy receipt is bound into the seal',
        status: policyReceipt.decision === 'allow' ? 'pass' : 'fail',
        evidence: policyReceipt.content_hash,
      },
      {
        id: 'jurisdiction-aware',
        label: 'Jurisdiction and data residency controls are explicit',
        status: jurisdictionReport.jurisdiction_allowed && jurisdictionReport.data_residency_allowed ? 'pass' : 'fail',
        evidence: jurisdictionReport.jurisdiction,
      },
      {
        id: 'regulated-quorum',
        label: 'Multiple verifier categories countersigned the evidence hash',
        status: validatorQuorum.quorum_reached ? 'pass' : 'fail',
        evidence: `${validatorQuorum.accepted}/${validatorQuorum.required_accepts} accepts`,
      },
      {
        id: 'audit-export',
        label: 'Regulator-readable evidence pack is generated',
        status: 'pass',
        evidence: 'audit-pack.json and audit-report.md',
      },
      {
        id: 'external-compute-ingestion',
        label: 'External compute proof is normalized before sealing',
        status: 'pass',
        evidence: 'external-compute-report.json',
      },
      {
        id: 'hardware-tee',
        label: 'Production hardware TEE quote',
        status: 'warning',
        evidence: 'Docker demo attestation only',
      },
      {
        id: 'zkml-production',
        label: 'Production zkML proof',
        status: 'warning',
        evidence: 'Demo proof transcript only',
      },
      {
        id: 'hsm-custody',
        label: 'Governed key custody',
        status: 'warning',
        evidence: 'Ephemeral demo keys only',
      },
    ],
    production_blockers: productionBlockers,
    promotion_path: [
      'Run same proof path in a sovereign cloud confidential VM.',
      'Bind validator identities to legal entities and service-level terms.',
      'Add external auditor countersignature and publish audit letter.',
      'Anchor seal commitments to Aethelred testnet or permissioned institutional zone.',
    ],
  };
};

const buildPublicVerifierManifest = ({ runId, seal, policyReceipt, assurancePlan, issuedAt }) => ({
  schema_version: 'aethelred-public-verifier-manifest-v0.2',
  generated_at: issuedAt,
  run_id: runId,
  seal_id: seal.seal_id,
  policy_id: policyReceipt.policy_id,
  assurance_tier: assurancePlan.target_tier.tier,
  verifier_endpoints: [
    '/v1/proof-path/latest',
    '/v1/seals/latest',
    '/v1/seals/latest/verify',
    '/v1/external-compute/latest',
    '/v1/institutional/context',
    '/v1/assurance/latest',
    '/v1/quorum/latest',
    '/v1/jurisdiction/latest',
    '/v1/liability/latest',
    '/v1/key-custody/latest',
    '/v1/anchor/latest',
    '/v1/auditor/latest',
    '/v1/readiness/latest',
    '/v1/sovereign-differentiation/latest',
    '/v1/evidence-index/latest',
    '/v1/regulator-pack/latest',
    '/v1/ledger/verify',
  ],
  public_claims: [
    'Aethelred can produce a portable AI decision seal.',
    'The seal binds policy, identity, jurisdiction, verifier quorum, liability, and evidence commitments.',
    'External compute proofs can be wrapped by Aethelred policy, jurisdiction, liability, audit, quorum, and anchor controls.',
    'The Docker path is publicly verifiable and regulator-pack exportable.',
  ],
  claim_boundaries: [
    'No production hardware TEE claim is made by this Docker path.',
    'No production zkML claim is made by this Docker path.',
    'No customer funds or private production data should be used in this public proof path.',
  ],
});

const buildSovereignDifferentiationScorecard = ({
  request,
  seal,
  externalComputeReport,
  policyReceipt,
  jurisdictionReport,
  liabilityRoute,
  validatorQuorum,
  assurancePlan,
  pilotReadinessGate,
  issuedAt,
  signer,
}) => {
  const providerName = externalComputeReport.provider_profile?.name || externalComputeReport.provider || 'unknown';
  const dimensions = [
    {
      id: 'compute-proof',
      dimension: 'Compute proof',
      generic_verifiable_cloud: 'Proves a workload ran under a provider attestation boundary.',
      aethelred_10x_control: 'Normalizes Docker, external confidential compute, sovereign-cloud, and on-prem proof claims into one seal-bound compute report.',
      status: externalComputeReport.accepted ? 'pass' : 'fail',
      evidence: externalComputeReport.report_hash,
    },
    {
      id: 'policy-native',
      dimension: 'Policy enforcement',
      generic_verifiable_cloud: 'Usually application-defined or left to integrators.',
      aethelred_10x_control: 'Signed policy receipt with required controls, denial reasons, and policy ID bound into the seal.',
      status: policyReceipt.decision === 'allow' ? 'pass' : 'fail',
      evidence: policyReceipt.content_hash,
    },
    {
      id: 'jurisdiction-native',
      dimension: 'Jurisdiction and data residency',
      generic_verifiable_cloud: 'Region is a cloud deployment parameter.',
      aethelred_10x_control: 'Jurisdiction registry, permitted regions, data boundary, and export posture are first-class verifier inputs.',
      status: jurisdictionReport.jurisdiction_allowed && jurisdictionReport.data_residency_allowed ? 'pass' : 'fail',
      evidence: jurisdictionReport.execution_region,
    },
    {
      id: 'regulated-identity',
      dimension: 'Institutional identity',
      generic_verifiable_cloud: 'Developer or app identity proves deployment ownership.',
      aethelred_10x_control: 'Institution, agent, sponsor, human controller, model owner, verifiers, and auditor roles are registry-backed.',
      status: 'pass',
      evidence: request.tenant?.institution_did || 'missing',
    },
    {
      id: 'liability-route',
      dimension: 'Liability routing',
      generic_verifiable_cloud: 'Proof says what executed, not who is accountable for harm.',
      aethelred_10x_control: 'Sponsor, human controller, model-risk owner, protocol operator, and auditor path are packaged per decision.',
      status: liabilityRoute.status === 'bound' ? 'pass' : 'fail',
      evidence: liabilityRoute.route_id,
    },
    {
      id: 'regulated-quorum',
      dimension: 'Verifier governance',
      generic_verifiable_cloud: 'Provider attestation may be enough for developer trust.',
      aethelred_10x_control: 'Multi-category verifier quorum signs the evidence hash for regulated review.',
      status: validatorQuorum.quorum_reached ? 'pass' : 'fail',
      evidence: `${validatorQuorum.accepted}/${validatorQuorum.required_accepts} accepts`,
    },
    {
      id: 'audit-export',
      dimension: 'Regulator and auditor packaging',
      generic_verifiable_cloud: 'Raw proofs often need bespoke explanation.',
      aethelred_10x_control: 'Regulator pack, evidence index, audit report, readiness gate, and chain-ready anchor are generated every run.',
      status: pilotReadinessGate.public_proof_ready ? 'pass' : 'fail',
      evidence: pilotReadinessGate.gate_hash,
    },
    {
      id: 'sovereign-deployment',
      dimension: 'Deployment posture',
      generic_verifiable_cloud: 'Cloud-first by default.',
      aethelred_10x_control: 'Public seal, permissioned zone, sovereign cloud, and on-prem enclave modes are represented in protocol artifacts.',
      status: 'pass',
      evidence: request.deployment_mode || 'missing',
    },
    {
      id: 'production-honesty',
      dimension: 'Production claim boundary',
      generic_verifiable_cloud: 'Early systems can over-market alpha-grade trust.',
      aethelred_10x_control: 'Verifier returns explicit warnings for hardware TEE, zkML, key custody, auditor, and anchor blockers.',
      status: 'warning',
      evidence: `${assurancePlan.production_blockers.length} blockers disclosed`,
    },
  ];
  const passCount = dimensions.filter((dimension) => dimension.status === 'pass').length;
  const failCount = dimensions.filter((dimension) => dimension.status === 'fail').length;
  const payload = {
    schema_version: 'aethelred-sovereign-differentiation-scorecard-v0.2',
    generated_at: issuedAt,
    seal_id: seal.seal_id,
    use_case: request.use_case,
    upstream_compute_provider: {
      provider: externalComputeReport.provider,
      name: providerName,
      category: externalComputeReport.provider_profile?.category || 'unknown',
      accepted: externalComputeReport.accepted,
      role: 'upstream compute proof source, not the final institutional trust layer',
    },
    positioning:
      'Aethelred is the sovereign verification layer for regulated AI decisions, not a generic verifiable-compute clone.',
    strategic_verdict:
      failCount === 0
        ? 'Aethelred can wrap external compute proof and add policy, jurisdiction, liability, quorum, audit, and anchor evidence.'
        : 'Aethelred must block this proof until the failed sovereign controls are remediated.',
    dimensions,
    '10x_targets': [
      'Match developer proof-path simplicity with Docker, CLI, SDKs, and public verifier APIs.',
      'Add policy-native verification that compute clouds do not own by default.',
      'Make jurisdiction, identity, liability, and audit export inseparable from every sealed AI decision.',
      'Support external compute providers as substrates while keeping Aethelred as the institutional trust layer.',
      'Convert production blockers into dated procurement-ready gates for sovereign cloud, HSM, validators, auditors, and anchoring.',
    ],
    remaining_gaps: assurancePlan.production_blockers.map((blocker) => ({
      id: blocker.id,
      owner: blocker.owner,
      requirement: blocker.requirement,
    })),
    score: {
      dimensions_total: dimensions.length,
      pass_count: passCount,
      warning_count: dimensions.filter((dimension) => dimension.status === 'warning').length,
      fail_count: failCount,
      public_proof_ready: failCount === 0,
    },
    signer: signerDescriptor(signer),
  };

  return signDocument(payload, signer, 'scorecard_hash');
};

const buildKeyCustodyManifest = ({ signers, issuedAt, signer }) => {
  const payload = {
    schema_version: 'aethelred-key-custody-manifest-v0.2',
    generated_at: issuedAt,
    custody_mode: 'ephemeral-demo-keys',
    production_status: 'not-production-custody',
    signers: Object.fromEntries(
      Object.entries(signers).map(([role, roleSigner]) => [
        role,
        {
          ...signerDescriptor(roleSigner),
          custody_class: 'ephemeral-in-memory-demo-key',
          rotation_policy: 'per proof run',
          production_requirement: 'replace with governed KMS/HSM-backed key and published key policy',
        },
      ]),
    ),
    required_production_controls: [
      'HSM or cloud KMS custody for seal authority keys',
      'dual-control rotation procedure',
      'auditor-visible key registry',
      'signer revocation list',
      'break-glass and incident rotation runbook',
    ],
    signer: signerDescriptor(signer),
  };

  return signDocument(payload, signer, 'manifest_hash');
};

const buildAnchorManifest = ({ runId, seal, policyReceipt, evidenceBundleHash, validatorQuorum, issuedAt, signer }) => {
  const payload = {
    schema_version: 'aethelred-anchor-manifest-v0.2',
    anchor_id: `anchor_${sha256Hex({ runId, seal_id: seal.seal_id, seal_hash: seal.seal_hash }).slice(0, 24)}`,
    generated_at: issuedAt,
    run_id: runId,
    seal_id: seal.seal_id,
    mode: 'local-ledger-with-chain-ready-payload',
    status: 'locally-anchored-public-proof',
    target_networks: [
      {
        network: 'aethelred-testnet',
        status: 'ready-payload-not-submitted',
        submission_method: 'future RPC transaction or permissioned-zone anchor',
      },
      {
        network: 'permissioned-institutional-zone',
        status: 'ready-payload-not-submitted',
        submission_method: 'private validator council anchor',
      },
    ],
    commitments: {
      seal_hash: seal.seal_hash,
      seal_id: seal.seal_id,
      policy_receipt_hash: policyReceipt.content_hash,
      evidence_bundle_hash: evidenceBundleHash,
      validator_quorum_hash: sha256Hex(validatorQuorum),
    },
    chain_payload: {
      type_url: '/aethelred.seal.v1.MsgAnchorSeal',
      body: {
        seal_id: seal.seal_id,
        seal_hash: seal.seal_hash,
        evidence_bundle_hash: evidenceBundleHash,
        policy_receipt_hash: policyReceipt.content_hash,
        quorum_hash: sha256Hex(validatorQuorum),
      },
    },
    signer: signerDescriptor(signer),
  };

  return signDocument(payload, signer, 'anchor_hash');
};

const buildPilotReadinessGate = ({
  request,
  policyReceipt,
  externalComputeReport,
  jurisdictionReport,
  validatorQuorum,
  assurancePlan,
  keyCustodyManifest,
  anchorManifest,
  issuedAt,
  signer,
}) => {
  const gates = [
    {
      id: 'public-proof-verification',
      label: 'Public proof path can be independently verified',
      status: policyReceipt.decision === 'allow' ? 'pass' : 'fail',
      evidence: policyReceipt.content_hash,
    },
    {
      id: 'regulated-quorum',
      label: 'Regulated verifier quorum is reached',
      status: validatorQuorum.quorum_reached ? 'pass' : 'fail',
      evidence: `${validatorQuorum.accepted}/${validatorQuorum.required_accepts}`,
    },
    {
      id: 'jurisdiction-readiness',
      label: 'Jurisdiction and residency checks pass',
      status: jurisdictionReport.jurisdiction_allowed && jurisdictionReport.data_residency_allowed ? 'pass' : 'fail',
      evidence: jurisdictionReport.execution_region,
    },
    {
      id: 'external-compute-acceptance',
      label: 'External compute proof adapter accepted the workload claims',
      status: externalComputeReport.accepted ? 'pass' : 'fail',
      evidence: externalComputeReport.provider,
    },
    {
      id: 'regulator-pack-export',
      label: 'Regulator pack can be exported',
      status: 'pass',
      evidence: 'regulator-pack/latest',
    },
    {
      id: 'chain-anchor-payload',
      label: 'Chain anchor payload is ready',
      status: anchorManifest.status === 'locally-anchored-public-proof' ? 'pass' : 'fail',
      evidence: anchorManifest.anchor_id,
    },
    {
      id: 'production-key-custody',
      label: 'Production key custody is configured',
      status: keyCustodyManifest.production_status === 'production-custody' ? 'pass' : 'warning',
      evidence: keyCustodyManifest.custody_mode,
    },
    {
      id: 'production-tee',
      label: 'Production TEE attestation is configured',
      status: 'warning',
      evidence: 'Docker transcript only',
    },
    {
      id: 'production-zkml',
      label: 'Production zkML proof is configured',
      status: 'warning',
      evidence: 'Demo transcript only',
    },
  ];
  const failCount = gates.filter((gate) => gate.status === 'fail').length;
  const warningCount = gates.filter((gate) => gate.status === 'warning').length;
  const payload = {
    schema_version: 'aethelred-pilot-readiness-gate-v0.2',
    generated_at: issuedAt,
    use_case: request.use_case,
    tenant: request.tenant?.name,
    public_proof_ready: failCount === 0,
    regulated_pilot_status: failCount === 0 ? 'conditional-pass' : 'blocked',
    production_status: warningCount === 0 && failCount === 0 ? 'production-ready' : 'not-production-ready',
    gates,
    open_production_blockers: assurancePlan.production_blockers,
    signer: signerDescriptor(signer),
  };

  return signDocument(payload, signer, 'gate_hash');
};

const buildAuditorAttestation = ({ artifacts, issuedAt, runId, sealId, signer }) => {
  const artifactHashes = Object.fromEntries(Object.entries(artifacts).map(([name, value]) => [name, sha256Hex(value)]));
  const payload = {
    schema_version: 'aethelred-auditor-attestation-v0.2',
    attestation_id: `audit_${sha256Hex({ runId, sealId, artifactHashes }).slice(0, 24)}`,
    generated_at: issuedAt,
    run_id: runId,
    seal_id: sealId,
    auditor: {
      did: 'did:aethelred:verifier:policy-auditor',
      role: 'simulated external auditor for public proof path',
      production_claim: false,
    },
    opinion: 'public-proof-path-evidence-consistent',
    scope: [
      'hash commitments',
      'policy receipt',
      'jurisdiction report',
      'validator quorum',
      'liability route',
      'key custody manifest',
      'anchor manifest',
      'sovereign differentiation scorecard',
      'regulatory evidence index',
    ],
    artifact_hashes: artifactHashes,
    claim_boundary: [
      'This attestation is generated by the Docker public proof path.',
      'It is not a substitute for an independent production security audit.',
      'It verifies artifact consistency and readiness packaging only.',
    ],
    signer: signerDescriptor(signer),
  };

  return signDocument(payload, signer, 'attestation_hash');
};

const buildRegulatoryEvidenceIndex = ({ artifacts, signer, issuedAt, runId, sealId }) => {
  const payload = {
    schema_version: 'aethelred-regulatory-evidence-index-v0.2',
    generated_at: issuedAt,
    run_id: runId,
    seal_id: sealId,
    audience: ['regulator', 'external-auditor', 'institutional-buyer', 'sovereign-investor'],
    artifacts: Object.entries(artifacts).map(([name, value]) => ({
      name,
      sha256: sha256Hex(value),
      purpose: {
        'proof-record.json': 'Full public proof record with request, output, proof objects, and verifier report.',
        'aethelred-seal.json': 'Portable Aethelred Seal for the AI decision.',
        'policy-receipt.json': 'Signed policy engine decision and control checklist.',
        'docker-attestation.json': 'Docker public proof path attestation transcript.',
        'external-compute-report.json': 'Normalized compute-substrate proof report for Docker, external confidential compute, sovereign cloud, or on-prem execution.',
        'evidence-bundle.json': 'TEE-shaped and zkML-shaped evidence bundle.',
        'institutional-context.json': 'Registry-backed institutional packaging context.',
        'assurance-plan.json': 'Assurance tier target, production gaps, and promotion path.',
        'validator-quorum.json': 'Signed multi-verifier quorum votes.',
        'jurisdiction-report.json': 'Data residency and jurisdiction control report.',
        'liability-route.json': 'Accountability and escalation route.',
        'key-custody-manifest.json': 'Signer custody posture, rotation expectations, and HSM/KMS production requirements.',
        'anchor-manifest.json': 'Local-ledger anchor plus chain-ready payload for testnet or permissioned-zone anchoring.',
        'pilot-readiness-gate.json': 'Conditional pilot readiness gate with production blockers.',
        'sovereign-differentiation-scorecard.json': 'Aethelred-vs-generic-verifiable-cloud scorecard for sovereign and regulated buyers.',
        'auditor-attestation.json': 'Signed simulated external-auditor attestation over public proof artifacts.',
        'public-verifier-manifest.json': 'Public endpoints, claims, and claim boundaries.',
        'verifier-report.json': 'Machine-readable verification result.',
      }[name] || 'Evidence artifact',
    })),
    control_map: [
      { control: 'identity', artifacts: ['institutional-context.json', 'policy-receipt.json'] },
      { control: 'policy', artifacts: ['policy-receipt.json', 'assurance-plan.json'] },
      { control: 'compute-substrate', artifacts: ['external-compute-report.json', 'docker-attestation.json'] },
      { control: 'jurisdiction', artifacts: ['jurisdiction-report.json', 'evidence-bundle.json'] },
      { control: 'quorum', artifacts: ['validator-quorum.json', 'aethelred-seal.json'] },
      { control: 'liability', artifacts: ['liability-route.json', 'audit-pack.json'] },
      { control: 'key-custody', artifacts: ['key-custody-manifest.json', 'auditor-attestation.json'] },
      { control: 'anchoring', artifacts: ['anchor-manifest.json', 'ledger.json'] },
      { control: 'pilot-readiness', artifacts: ['pilot-readiness-gate.json', 'assurance-plan.json'] },
      { control: 'sovereign-differentiation', artifacts: ['sovereign-differentiation-scorecard.json', 'external-compute-report.json'] },
      { control: 'audit-export', artifacts: ['audit-pack.json', 'audit-report.md'] },
    ],
    signer: signerDescriptor(signer),
  };

  return signDocument(payload, signer, 'index_hash');
};

const buildAuditMarkdown = ({
  runId,
  seal,
  policyReceipt,
  verifierReport,
  evidenceBundle,
  request,
  assurancePlan,
  validatorQuorum,
  jurisdictionReport,
  liabilityRoute,
  externalComputeReport,
  anchorManifest,
  pilotReadinessGate,
  sovereignDifferentiationScorecard,
  auditorAttestation,
}) => {
  const passCount = verifierReport.checks.filter((check) => check.status === 'pass').length;
  const warningCount = verifierReport.checks.filter((check) => check.status === 'warning').length;
  const failCount = verifierReport.checks.filter((check) => check.status === 'fail').length;
  const blockerRows = assurancePlan.production_blockers
    .map((blocker) => `| ${blocker.id} | ${blocker.owner} | ${blocker.requirement} |`)
    .join('\n');

  return `# Aethelred Sovereign Public Proof Path Audit Pack

Run ID: \`${runId}\`

Seal ID: \`${seal.seal_id}\`

Use case: \`${request.use_case}\`

Tenant: \`${request.tenant.name}\`

Assurance target: Tier ${assurancePlan.target_tier.tier} - ${assurancePlan.target_tier.name}

## Verification Summary

| Result | Count |
|---|---:|
| Pass | ${passCount} |
| Warning | ${warningCount} |
| Fail | ${failCount} |

Overall status: **${verifierReport.valid ? 'verified public proof path' : 'failed verification'}**

## Institutional Evidence Chain

1. Institutional context registered tenant, policy, model, agent, sponsor, and deployment mode.
2. Policy receipt \`${policyReceipt.id}\` authorized \`${policyReceipt.action}\`.
3. Jurisdiction report confirmed \`${jurisdictionReport.execution_region}\` for \`${jurisdictionReport.jurisdiction}\`.
4. External compute report \`${externalComputeReport.report_hash}\` normalized \`${externalComputeReport.provider}\` as an upstream proof source.
5. Evidence bundle \`${evidenceBundle.bundle_id}\` linked TEE-shaped evidence and zkML-shaped proof transcript.
6. Validator quorum \`${validatorQuorum.quorum_id}\` reached ${validatorQuorum.accepted}/${validatorQuorum.required_accepts} accepts.
7. Liability route \`${liabilityRoute.route_id}\` bound sponsor, human controller, model-risk owner, operator, and auditor path.
8. Aethelred Seal \`${seal.seal_id}\` bound the full decision evidence into one verifier-friendly record.
9. Anchor manifest \`${anchorManifest.anchor_id}\` produced a local ledger anchor and chain-ready payload.
10. Pilot readiness gate returned \`${pilotReadinessGate.regulated_pilot_status}\` with explicit production blockers.
11. Sovereign differentiation scorecard \`${sovereignDifferentiationScorecard.scorecard_hash}\` documented the Aethelred layer above compute.
12. Auditor attestation \`${auditorAttestation.attestation_id}\` signed the public proof artifact consistency boundary.

## Production Promotion Blockers

| Blocker | Owner | Requirement |
|---|---|---|
${blockerRows}

## Public Claim Boundary

- This Docker proof path is public-demo infrastructure. It does not claim hardware TEE execution.
- The attestation and zkML artifacts are structured demo transcripts, not production Nitro/SGX/SEV/TDX quotes or production proofs.
- Production use must replace the local demo signers with governed KMS/HSM custody and real verifier policy.
`;
};

const readJsonFile = async (path, fallback) => {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return fallback;
    throw error;
  }
};

const writeJsonFile = async (path, value) => {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
};

const writeTextFile = async (path, value) => {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, value.endsWith('\n') ? value : `${value}\n`);
};

export const createProofRecord = (request = defaultProofRequest(), issuedAt = nowIso()) => {
  const policySigner = makeSigner('did:aethelred:signer:policy-engine-demo');
  const attestationSigner = makeSigner('did:aethelred:signer:docker-attestation-demo');
  const externalComputeSigner = makeSigner('did:aethelred:signer:external-compute-adapter-demo');
  const sealSigner = makeSigner('did:aethelred:signer:seal-authority-demo');
  const auditSigner = makeSigner('did:aethelred:signer:audit-vault-demo');
  const verifierSigners = Object.fromEntries(
    Object.keys(REGISTRIES.verifiers).map((verifierId) => [verifierId, makeSigner(verifierId)]),
  );

  const runId = `proof_${Date.now()}_${randomUUID().slice(0, 8)}`;
  const requestId = `req_${sha256Hex({ runId, request }).slice(0, 18)}`;
  const policyId = request.policy_id || DEFAULT_POLICY_ID;
  const modelHash = sha256Hex(request.model);
  const circuitHash = sha256Hex({ circuit: 'aethelred-risk-review-circuit', version: 'demo-v0.2' });
  const verifyingKeyHash = sha256Hex({ verifying_key: 'aethelred-demo-verifying-key', circuitHash });
  const inputHash = sha256Hex(request.evidence_input);
  const modelOutput = runDemoModel(request);
  const outputHash = sha256Hex(modelOutput);
  const policyChecks = buildPolicyChecks(request);
  const failedRequired = policyChecks.filter((check) => check.required && !check.passed);
  const policyDecision = failedRequired.length === 0 ? 'allow' : 'deny';
  const institutionalContext = buildInstitutionalContext(request, issuedAt);
  const institutionalContextHash = sha256Hex(institutionalContext);

  const policyReceiptPayload = {
    schema_version: 'aethelred-policy-receipt-v0.2',
    id: `pol_${sha256Hex({ runId, inputHash, policyChecks }).slice(0, 20)}`,
    request_id: requestId,
    actor: request.agent.did,
    action: `${request.use_case}.seal`,
    resource:
      request.evidence_input.transaction_id
        ? `transaction:${request.evidence_input.transaction_id}`
        : request.evidence_input.case_id
          ? `clinical-case:${request.evidence_input.case_id}`
          : request.evidence_input.project_id
            ? `mrv-project:${request.evidence_input.project_id}`
            : `proof-request:${requestId}`,
    decision: policyDecision,
    policy_id: policyId,
    evaluated_at: issuedAt,
    checks: policyChecks,
    failed_required_checks: failedRequired.map((item) => item.id),
    signer: signerDescriptor(policySigner),
  };
  const policyReceipt = signDocument(policyReceiptPayload, policySigner);
  const jurisdictionReport = buildJurisdictionReport({ request, policyReceipt, policyChecks, issuedAt });
  const jurisdictionReportHash = sha256Hex(jurisdictionReport);
  const liabilityRoute = buildLiabilityRoute({ request, policyReceipt, modelOutput, issuedAt });
  const liabilityRouteHash = sha256Hex(liabilityRoute);
  const externalComputeReport = buildExternalComputeReport({
    request,
    modelHash,
    inputHash,
    outputHash,
    issuedAt,
    signer: externalComputeSigner,
  });
  const externalComputeReportHash = sha256Hex(externalComputeReport);

  const attestationPayload = {
    schema_version: 'aethelred-docker-attestation-v0.2',
    id: `att_${sha256Hex({ runId, inputHash, outputHash }).slice(0, 20)}`,
    mode: 'docker-public-proof-demo',
    production_status: 'demo-only-not-hardware-tee',
    platform_shape: 'nitro-compatible-evidence-shape',
    container_image: 'aethelred/public-proof-path:local',
    container_measurement: sha256Hex({
      service_version: SERVICE_VERSION,
      dockerfile: 'docs/demo/public-proof-path/Dockerfile',
      modelHash,
      policy_id: policyReceipt.policy_id,
      institutional_context_hash: institutionalContextHash,
      external_compute_report_hash: externalComputeReportHash,
    }),
    nonce: sha256Hex({ runId, inputHash, issuedAt }),
    model_hash: modelHash,
    input_hash: inputHash,
    output_hash: outputHash,
    external_compute_report_hash: externalComputeReportHash,
    external_compute_provider: externalComputeReport.provider,
    issued_at: issuedAt,
    signer: signerDescriptor(attestationSigner),
  };
  const attestation = signDocument(attestationPayload, attestationSigner, 'attestation_hash');

  const evidenceBundle = {
    schema_version: '1.0.0',
    bundle_id: randomUUID(),
    job_id: sha256Hex({ runId, inputHash, outputHash }).toUpperCase(),
    timestamp: issuedAt,
    model_hash: modelHash,
    circuit_hash: circuitHash,
    verifying_key_hash: verifyingKeyHash,
    tee_evidence: {
      platform: 'nitro',
      enclave_id: 'docker-local-public-proof-path',
      measurement: attestation.container_measurement,
      quote: base64Json(attestationPayload),
      nonce: attestation.nonce,
    },
    zkml_evidence: {
      proof_system: 'ezkl',
      proof_bytes: base64Json({
        mode: 'demo-transcript',
        model_hash: modelHash,
        input_hash: inputHash,
        output_hash: outputHash,
        verifier_note: 'Production path must replace this transcript with a real proof.',
      }),
      public_inputs: base64Json({ model_hash: modelHash, input_hash: inputHash, output_hash: outputHash }),
      output_commitment: outputHash,
    },
    region: request.processing?.execution_region || request.tenant.jurisdiction,
    operator: 'aethel1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu',
    policy_decision: {
      mode: 'hybrid',
      require_both: true,
      fallback_allowed: false,
      policy_version: policyReceipt.policy_id,
      decision: policyDecision,
      policy_receipt_hash: policyReceipt.content_hash,
    },
    metadata: {
      proof_path: 'docker-public-demo',
      production_status: 'not-production-tee-or-zk-certified',
      requested_assurance_tier: request.requested_assurance_tier,
      data_boundary: request.evidence_input.data_boundary,
      use_case: request.use_case,
      agent_did: request.agent.did,
      sponsor_of_record: request.agent.sponsor_of_record,
      institutional_context_hash: institutionalContextHash,
      jurisdiction_report_hash: jurisdictionReportHash,
      liability_route_hash: liabilityRouteHash,
      external_compute_report_hash: externalComputeReportHash,
      external_compute_provider: externalComputeReport.provider,
    },
  };
  const evidenceBundleHash = sha256Hex(evidenceBundle);
  const validatorQuorum = buildValidatorQuorum({ evidenceBundleHash, policyReceipt, issuedAt, verifierSigners });
  const validatorQuorumHash = sha256Hex(validatorQuorum);
  const assurancePlan = buildAssurancePlan({ request, policyReceipt, jurisdictionReport, validatorQuorum, issuedAt });
  const assurancePlanHash = sha256Hex(assurancePlan);

  const sealPayload = {
    schema_version: 'aethelred-seal-v0.2',
    seal_id: `seal_${sha256Hex({ evidenceBundleHash, runId }).slice(0, 24)}`,
    run_id: runId,
    job_id: evidenceBundle.job_id,
    issued_at: issuedAt,
    status: policyDecision === 'allow' ? 'sealed_public_proof_verified' : 'sealed_public_proof_policy_denied',
    purpose: request.use_case,
    assurance_tier: request.requested_assurance_tier,
    commitments: {
      model_hash: modelHash,
      input_hash: inputHash,
      output_hash: outputHash,
      policy_receipt_hash: policyReceipt.content_hash,
      attestation_hash: attestation.attestation_hash,
      evidence_bundle_hash: evidenceBundleHash,
      institutional_context_hash: institutionalContextHash,
      jurisdiction_report_hash: jurisdictionReportHash,
      liability_route_hash: liabilityRouteHash,
      external_compute_report_hash: externalComputeReportHash,
      validator_quorum_hash: validatorQuorumHash,
      assurance_plan_hash: assurancePlanHash,
    },
    verifier_quorum: {
      quorum_id: validatorQuorum.quorum_id,
      strategy: validatorQuorum.strategy,
      required_accepts: validatorQuorum.required_accepts,
      accepted: validatorQuorum.accepted,
      rejected: validatorQuorum.rejected,
      quorum_reached: validatorQuorum.quorum_reached,
      categories: validatorQuorum.categories,
      quorum_hash: validatorQuorumHash,
    },
    liability: {
      route_id: liabilityRoute.route_id,
      sponsor_of_record: request.agent.sponsor_of_record,
      liability_model: request.agent.liability_model,
      human_owner: request.agent.human_owner,
    },
    jurisdiction: {
      policy_jurisdiction: request.tenant.jurisdiction,
      execution_region: request.processing?.execution_region,
      data_residency_zone: request.processing?.data_residency_zone,
    },
    signer: signerDescriptor(sealSigner),
    caveats: [
      'Docker proof path uses demo attestation and proof transcripts.',
      'Production requires real TEE attestation, real zkML where required, governed key custody, and validator/auditor policy.',
    ],
  };
  const seal = signDocument(sealPayload, sealSigner, 'seal_hash');
  const publicVerifierManifest = buildPublicVerifierManifest({ runId, seal, policyReceipt, assurancePlan, issuedAt });
  const keyCustodyManifest = buildKeyCustodyManifest({
    signers: {
      policy_engine: policySigner,
      attestation_authority: attestationSigner,
      external_compute_adapter: externalComputeSigner,
      seal_authority: sealSigner,
      audit_vault: auditSigner,
      ...verifierSigners,
    },
    issuedAt,
    signer: auditSigner,
  });
  const anchorManifest = buildAnchorManifest({
    runId,
    seal,
    policyReceipt,
    evidenceBundleHash,
    validatorQuorum,
    issuedAt,
    signer: auditSigner,
  });
  const pilotReadinessGate = buildPilotReadinessGate({
    request,
    policyReceipt,
    externalComputeReport,
    jurisdictionReport,
    validatorQuorum,
    assurancePlan,
    keyCustodyManifest,
    anchorManifest,
    issuedAt,
    signer: auditSigner,
  });
  const sovereignDifferentiationScorecard = buildSovereignDifferentiationScorecard({
    request,
    seal,
    externalComputeReport,
    policyReceipt,
    jurisdictionReport,
    liabilityRoute,
    validatorQuorum,
    assurancePlan,
    pilotReadinessGate,
    issuedAt,
    signer: auditSigner,
  });

  const preReportArtifacts = {
    'aethelred-seal.json': seal,
    'policy-receipt.json': policyReceipt,
    'docker-attestation.json': attestation,
    'evidence-bundle.json': evidenceBundle,
    'external-compute-report.json': externalComputeReport,
    'institutional-context.json': institutionalContext,
    'assurance-plan.json': assurancePlan,
    'validator-quorum.json': validatorQuorum,
    'jurisdiction-report.json': jurisdictionReport,
    'liability-route.json': liabilityRoute,
    'key-custody-manifest.json': keyCustodyManifest,
    'anchor-manifest.json': anchorManifest,
    'pilot-readiness-gate.json': pilotReadinessGate,
    'sovereign-differentiation-scorecard.json': sovereignDifferentiationScorecard,
    'public-verifier-manifest.json': publicVerifierManifest,
  };
  const regulatoryEvidenceIndex = buildRegulatoryEvidenceIndex({
    artifacts: preReportArtifacts,
    signer: auditSigner,
    issuedAt,
    runId,
    sealId: seal.seal_id,
  });
  const auditorAttestation = buildAuditorAttestation({
    artifacts: {
      ...preReportArtifacts,
      'regulatory-evidence-index.json': regulatoryEvidenceIndex,
    },
    issuedAt,
    runId,
    sealId: seal.seal_id,
    signer: auditSigner,
  });

  const recordBase = {
    schema_version: 'aethelred-public-proof-path-v0.2',
    service_version: SERVICE_VERSION,
    run_id: runId,
    created_at: issuedAt,
    request,
    model_output: modelOutput,
    institutional_context: institutionalContext,
    policy_receipt: policyReceipt,
    jurisdiction_report: jurisdictionReport,
    liability_route: liabilityRoute,
    external_compute_report: externalComputeReport,
    attestation,
    evidence_bundle: evidenceBundle,
    evidence_bundle_hash: evidenceBundleHash,
    validator_quorum: validatorQuorum,
    assurance_plan: assurancePlan,
    key_custody_manifest: keyCustodyManifest,
    anchor_manifest: anchorManifest,
    pilot_readiness_gate: pilotReadinessGate,
    sovereign_differentiation_scorecard: sovereignDifferentiationScorecard,
    seal,
    regulatory_evidence_index: regulatoryEvidenceIndex,
    auditor_attestation: auditorAttestation,
    public_verifier_manifest: publicVerifierManifest,
  };

  const verifierReport = verifyProofRecord(recordBase);
  const auditArtifacts = {
    ...preReportArtifacts,
    'regulatory-evidence-index.json': regulatoryEvidenceIndex,
    'auditor-attestation.json': auditorAttestation,
    'verifier-report.json': verifierReport,
  };
  const auditPack = {
    schema_version: 'aethelred-audit-pack-v0.2',
    run_id: runId,
    seal_id: seal.seal_id,
    generated_at: issuedAt,
    verifier_report: verifierReport,
    evidence_bundle_hash: evidenceBundleHash,
    regulatory_evidence_index_hash: regulatoryEvidenceIndex.index_hash,
    auditor_attestation_hash: auditorAttestation.attestation_hash,
    anchor_hash: anchorManifest.anchor_hash,
    key_custody_manifest_hash: keyCustodyManifest.manifest_hash,
    pilot_readiness_gate_hash: pilotReadinessGate.gate_hash,
    sovereign_differentiation_scorecard_hash: sovereignDifferentiationScorecard.scorecard_hash,
    assurance_tier: assurancePlan.target_tier,
    jurisdiction: jurisdictionReport,
    liability_route: liabilityRoute,
    artifacts: Object.keys(auditArtifacts).concat('audit-pack.json', 'audit-report.md'),
  };

  return {
    ...recordBase,
    verifier_report: verifierReport,
    audit_pack: auditPack,
    audit_markdown: buildAuditMarkdown({
      runId,
      seal,
      policyReceipt,
      verifierReport,
      evidenceBundle,
      request,
      assurancePlan,
      validatorQuorum,
      jurisdictionReport,
      liabilityRoute,
      externalComputeReport,
      anchorManifest,
      pilotReadinessGate,
      sovereignDifferentiationScorecard,
      auditorAttestation,
    }),
  };
};

const check = (id, label, condition, evidence, severity = 'fail') => ({
  id,
  label,
  status: condition ? 'pass' : severity,
  evidence,
});

const verifySignedDocument = (document, hashField) => {
  const payload = omit(document || {}, [hashField, 'signature']);
  return {
    hash_ok: sha256Hex(payload) === document?.[hashField],
    signature_ok: verifyPayload(payload, document?.signature, document?.signer?.public_key_pem),
  };
};

const verifyVote = (vote) => {
  const payload = omit(vote || {}, ['vote_hash', 'signature']);
  return {
    hash_ok: sha256Hex(payload) === vote?.vote_hash,
    signature_ok: verifyPayload(payload, vote?.signature, vote?.signer?.public_key_pem),
  };
};

const recomputeIndexArtifacts = (record) => ({
  'aethelred-seal.json': record.seal,
  'policy-receipt.json': record.policy_receipt,
  'docker-attestation.json': record.attestation,
  'external-compute-report.json': record.external_compute_report,
  'evidence-bundle.json': record.evidence_bundle,
  'institutional-context.json': record.institutional_context,
  'assurance-plan.json': record.assurance_plan,
  'validator-quorum.json': record.validator_quorum,
  'jurisdiction-report.json': record.jurisdiction_report,
  'liability-route.json': record.liability_route,
  'key-custody-manifest.json': record.key_custody_manifest,
  'anchor-manifest.json': record.anchor_manifest,
  'pilot-readiness-gate.json': record.pilot_readiness_gate,
  'sovereign-differentiation-scorecard.json': record.sovereign_differentiation_scorecard,
  'public-verifier-manifest.json': record.public_verifier_manifest,
});

export const verifyProofRecord = (record = {}) => {
  const policyVerification = verifySignedDocument(record.policy_receipt, 'content_hash');
  const attestationVerification = verifySignedDocument(record.attestation, 'attestation_hash');
  const sealVerification = verifySignedDocument(record.seal, 'seal_hash');
  const indexVerification = verifySignedDocument(record.regulatory_evidence_index, 'index_hash');
  const externalComputeVerification = verifySignedDocument(record.external_compute_report, 'report_hash');
  const keyCustodyVerification = verifySignedDocument(record.key_custody_manifest, 'manifest_hash');
  const anchorVerification = verifySignedDocument(record.anchor_manifest, 'anchor_hash');
  const pilotGateVerification = verifySignedDocument(record.pilot_readiness_gate, 'gate_hash');
  const scorecardVerification = verifySignedDocument(record.sovereign_differentiation_scorecard, 'scorecard_hash');
  const auditorVerification = verifySignedDocument(record.auditor_attestation, 'attestation_hash');
  const votes = record.validator_quorum?.votes || [];
  const voteResults = votes.map(verifyVote);
  const requiredPolicyChecks = record.policy_receipt?.checks?.filter((item) => item.required) || [];
  const failedPolicyChecks = requiredPolicyChecks.filter((item) => !item.passed);
  const modelVersion = getModelVersion(record.request || {});
  const jurisdiction = REGISTRIES.jurisdictions[record.request?.tenant?.jurisdiction];
  const indexedArtifacts = recomputeIndexArtifacts(record);
  const indexArtifactsOk = (record.regulatory_evidence_index?.artifacts || [])
    .filter((artifact) => indexedArtifacts[artifact.name])
    .every((artifact) => artifact.sha256 === sha256Hex(indexedArtifacts[artifact.name]));
  const auditorArtifactsOk = Object.entries(record.auditor_attestation?.artifact_hashes || {}).every(
    ([name, hash]) => indexedArtifacts[name] ? hash === sha256Hex(indexedArtifacts[name]) : name === 'regulatory-evidence-index.json' && hash === sha256Hex(record.regulatory_evidence_index || {}),
  );

  const checks = [
    check(
      'input-hash',
      'Input hash recomputes from public proof request',
      sha256Hex(record.request?.evidence_input || {}) === record.seal?.commitments?.input_hash,
      record.seal?.commitments?.input_hash || 'missing',
    ),
    check(
      'output-hash',
      'Output hash recomputes from model output',
      sha256Hex(record.model_output || {}) === record.seal?.commitments?.output_hash,
      record.seal?.commitments?.output_hash || 'missing',
    ),
    check(
      'institutional-context-hash',
      'Institutional context hash matches seal commitment',
      sha256Hex(record.institutional_context || {}) === record.seal?.commitments?.institutional_context_hash,
      record.seal?.commitments?.institutional_context_hash || 'missing',
    ),
    check(
      'policy-receipt-hash',
      'Policy receipt content hash is stable',
      policyVerification.hash_ok,
      record.policy_receipt?.content_hash || 'missing',
    ),
    check(
      'policy-receipt-signature',
      'Policy receipt signature verifies',
      policyVerification.signature_ok,
      record.policy_receipt?.signer?.key_id || 'missing',
    ),
    check(
      'policy-required-controls',
      'All required policy controls passed',
      requiredPolicyChecks.length > 0 && failedPolicyChecks.length === 0,
      failedPolicyChecks.length ? failedPolicyChecks.map((item) => item.id).join(', ') : `${requiredPolicyChecks.length} controls`,
    ),
    check(
      'policy-decision',
      'Policy decision allowed the sealed action',
      record.policy_receipt?.decision === 'allow',
      record.policy_receipt?.decision || 'missing',
    ),
    check(
      'model-registry',
      'Model version is present in the model registry',
      Boolean(modelVersion),
      `${record.request?.model?.model_id || 'missing'} ${record.request?.model?.version || ''}`.trim(),
    ),
    check(
      'agent-registry',
      'Agent and sponsor identities are registered',
      Boolean(
        REGISTRIES.identities.agents[record.request?.agent?.did] &&
          REGISTRIES.identities.institutions[record.request?.agent?.sponsor_of_record],
      ),
      record.request?.agent?.did || 'missing',
    ),
    check(
      'jurisdiction-report-hash',
      'Jurisdiction report hash matches seal commitment',
      sha256Hex(record.jurisdiction_report || {}) === record.seal?.commitments?.jurisdiction_report_hash,
      record.seal?.commitments?.jurisdiction_report_hash || 'missing',
    ),
    check(
      'jurisdiction-allowed',
      'Jurisdiction and data residency controls are allowed',
      Boolean(jurisdiction && record.jurisdiction_report?.jurisdiction_allowed && record.jurisdiction_report?.data_residency_allowed),
      record.jurisdiction_report?.jurisdiction || 'missing',
    ),
    check(
      'liability-route-hash',
      'Liability route hash matches seal commitment',
      sha256Hex(record.liability_route || {}) === record.seal?.commitments?.liability_route_hash,
      record.seal?.commitments?.liability_route_hash || 'missing',
    ),
    check(
      'liability-route-bound',
      'Liability route binds sponsor, human controller, operator, and auditor path',
      (record.liability_route?.parties || []).filter((party) => party.status && party.status !== 'missing').length >= 4,
      record.liability_route?.route_id || 'missing',
    ),
    check(
      'attestation-hash',
      'Docker attestation hash is stable',
      attestationVerification.hash_ok,
      record.attestation?.attestation_hash || 'missing',
    ),
    check(
      'attestation-signature',
      'Docker attestation signature verifies',
      attestationVerification.signature_ok,
      record.attestation?.signer?.key_id || 'missing',
    ),
    check(
      'external-compute-report-hash',
      'External compute report hash is stable',
      externalComputeVerification.hash_ok,
      record.external_compute_report?.report_hash || 'missing',
    ),
    check(
      'external-compute-report-signature',
      'External compute report signature verifies',
      externalComputeVerification.signature_ok,
      record.external_compute_report?.signer?.key_id || 'missing',
    ),
    check(
      'external-compute-provider-accepted',
      'External compute provider proof is accepted by adapter policy',
      record.external_compute_report?.accepted === true,
      record.external_compute_report?.provider || 'missing',
    ),
    check(
      'external-compute-seal-binding',
      'External compute report hash matches seal commitment',
      sha256Hex(record.external_compute_report || {}) === record.seal?.commitments?.external_compute_report_hash,
      record.seal?.commitments?.external_compute_report_hash || 'missing',
    ),
    check(
      'evidence-bundle-hash',
      'Evidence bundle hash matches seal commitment',
      sha256Hex(record.evidence_bundle || {}) === record.seal?.commitments?.evidence_bundle_hash,
      record.seal?.commitments?.evidence_bundle_hash || 'missing',
    ),
    check(
      'validator-quorum-hash',
      'Validator quorum hash matches seal commitment',
      sha256Hex(record.validator_quorum || {}) === record.seal?.commitments?.validator_quorum_hash,
      record.seal?.commitments?.validator_quorum_hash || 'missing',
    ),
    check(
      'validator-quorum-threshold',
      'Regulated verifier quorum threshold is reached',
      Boolean(record.validator_quorum?.quorum_reached && record.validator_quorum?.accepted >= record.validator_quorum?.required_accepts),
      `${record.validator_quorum?.accepted || 0}/${record.validator_quorum?.required_accepts || 0} accepts`,
    ),
    check(
      'validator-vote-signatures',
      'All verifier vote hashes and signatures verify',
      votes.length >= 3 && voteResults.every((result) => result.hash_ok && result.signature_ok),
      `${voteResults.filter((result) => result.hash_ok && result.signature_ok).length}/${votes.length} votes verified`,
    ),
    check(
      'assurance-plan-hash',
      'Assurance plan hash matches seal commitment',
      sha256Hex(record.assurance_plan || {}) === record.seal?.commitments?.assurance_plan_hash,
      record.seal?.commitments?.assurance_plan_hash || 'missing',
    ),
    check(
      'assurance-tier-target',
      'Requested assurance tier is at least the policy minimum',
      Number(record.assurance_plan?.target_tier?.tier || 0) >= (REGISTRIES.policies[record.request?.policy_id || DEFAULT_POLICY_ID]?.min_assurance_tier || 1),
      `Tier ${record.assurance_plan?.target_tier?.tier || 'missing'}`,
    ),
    check(
      'seal-hash',
      'Aethelred Seal hash is stable',
      sealVerification.hash_ok,
      record.seal?.seal_hash || 'missing',
    ),
    check(
      'seal-signature',
      'Aethelred Seal signature verifies',
      sealVerification.signature_ok,
      record.seal?.signer?.key_id || 'missing',
    ),
    check(
      'key-custody-manifest-hash',
      'Key custody manifest hash is stable',
      keyCustodyVerification.hash_ok,
      record.key_custody_manifest?.manifest_hash || 'missing',
    ),
    check(
      'key-custody-manifest-signature',
      'Key custody manifest signature verifies',
      keyCustodyVerification.signature_ok,
      record.key_custody_manifest?.signer?.key_id || 'missing',
    ),
    check(
      'anchor-manifest-hash',
      'Anchor manifest hash is stable',
      anchorVerification.hash_ok,
      record.anchor_manifest?.anchor_hash || 'missing',
    ),
    check(
      'anchor-manifest-signature',
      'Anchor manifest signature verifies',
      anchorVerification.signature_ok,
      record.anchor_manifest?.signer?.key_id || 'missing',
    ),
    check(
      'anchor-payload-seal-binding',
      'Anchor payload binds the verified seal hash',
      record.anchor_manifest?.commitments?.seal_hash === record.seal?.seal_hash,
      record.anchor_manifest?.anchor_id || 'missing',
    ),
    check(
      'pilot-readiness-gate-hash',
      'Pilot readiness gate hash is stable',
      pilotGateVerification.hash_ok,
      record.pilot_readiness_gate?.gate_hash || 'missing',
    ),
    check(
      'pilot-readiness-gate-signature',
      'Pilot readiness gate signature verifies',
      pilotGateVerification.signature_ok,
      record.pilot_readiness_gate?.signer?.key_id || 'missing',
    ),
    check(
      'pilot-readiness-gate',
      'Pilot readiness gate is not blocked',
      record.pilot_readiness_gate?.regulated_pilot_status !== 'blocked',
      record.pilot_readiness_gate?.regulated_pilot_status || 'missing',
    ),
    check(
      'sovereign-differentiation-scorecard-hash',
      'Sovereign differentiation scorecard hash is stable',
      scorecardVerification.hash_ok,
      record.sovereign_differentiation_scorecard?.scorecard_hash || 'missing',
    ),
    check(
      'sovereign-differentiation-scorecard-signature',
      'Sovereign differentiation scorecard signature verifies',
      scorecardVerification.signature_ok,
      record.sovereign_differentiation_scorecard?.signer?.key_id || 'missing',
    ),
    check(
      'regulatory-index-hash',
      'Regulatory evidence index hash is stable',
      indexVerification.hash_ok,
      record.regulatory_evidence_index?.index_hash || 'missing',
    ),
    check(
      'regulatory-index-signature',
      'Regulatory evidence index signature verifies',
      indexVerification.signature_ok,
      record.regulatory_evidence_index?.signer?.key_id || 'missing',
    ),
    check(
      'regulatory-index-artifacts',
      'Regulatory evidence index artifact hashes match current artifacts',
      indexArtifactsOk,
      `${record.regulatory_evidence_index?.artifacts?.length || 0} indexed artifacts`,
    ),
    check(
      'auditor-attestation-hash',
      'Auditor attestation hash is stable',
      auditorVerification.hash_ok,
      record.auditor_attestation?.attestation_hash || 'missing',
    ),
    check(
      'auditor-attestation-signature',
      'Auditor attestation signature verifies',
      auditorVerification.signature_ok,
      record.auditor_attestation?.signer?.key_id || 'missing',
    ),
    check(
      'auditor-attestation-artifacts',
      'Auditor attestation artifact hashes match current artifacts',
      auditorArtifactsOk,
      `${Object.keys(record.auditor_attestation?.artifact_hashes || {}).length} attested artifacts`,
    ),
    check(
      'hardware-tee-production',
      'Production hardware TEE attestation present',
      record.attestation?.production_status !== 'demo-only-not-hardware-tee',
      'Docker demo attestation only',
      'warning',
    ),
    check(
      'zkml-production',
      'Production zkML proof present where required',
      record.evidence_bundle?.metadata?.production_status !== 'not-production-tee-or-zk-certified',
      'Demo proof transcript only',
      'warning',
    ),
    check(
      'governed-key-custody',
      'Signer keys are governed by KMS/HSM custody',
      false,
      'Ephemeral demo keys only',
      'warning',
    ),
  ];

  const failed = checks.filter((item) => item.status === 'fail');
  return {
    schema_version: 'aethelred-verifier-report-v0.2',
    checked_at: nowIso(),
    valid: failed.length === 0,
    seal_id: record.seal?.seal_id || 'missing',
    run_id: record.run_id || 'missing',
    checks,
    readiness: {
      public_proof_path: failed.length === 0 ? 'complete' : 'blocked',
      regulated_pilot: failed.length === 0 ? 'conditional-after-production-blockers' : 'blocked',
      production_grade: false,
      warning_count: checks.filter((item) => item.status === 'warning').length,
    },
    next_production_steps: [
      'Replace Docker demo attestation with Nitro, SGX, SEV-SNP, Intel TDX, or sovereign-cloud attestation.',
      'Replace demo proof transcript with workflow-appropriate zkML or deterministic verifier evidence.',
      'Bind seal signer to governed KMS/HSM custody and publish verifier public-key policy.',
      'Add external validator or auditor countersignature before regulated pilot use.',
      'Anchor seal commitments to Aethelred testnet or a permissioned institutional zone.',
    ],
  };
};

const appendLedger = async (outputDir, record) => {
  const ledgerPath = join(outputDir, 'ledger.json');
  const ledger = await readJsonFile(ledgerPath, {
    schema_version: 'aethelred-public-proof-ledger-v0.2',
    created_at: nowIso(),
    head_hash: GENESIS_HASH,
    entries: [],
  });
  const previous_hash = ledger.head_hash || GENESIS_HASH;
  const index = ledger.entries.length;
  const entryPayload = {
    index,
    run_id: record.run_id,
    seal_id: record.seal.seal_id,
    created_at: record.created_at,
    previous_hash,
    artifact_hashes: {
      proof_record: sha256Hex(record),
      seal: sha256Hex(record.seal),
      evidence_bundle: record.evidence_bundle_hash,
      external_compute_report: sha256Hex(record.external_compute_report),
      sovereign_differentiation_scorecard: sha256Hex(record.sovereign_differentiation_scorecard),
      validator_quorum: sha256Hex(record.validator_quorum),
      regulatory_evidence_index: sha256Hex(record.regulatory_evidence_index),
      auditor_attestation: sha256Hex(record.auditor_attestation),
      anchor_manifest: sha256Hex(record.anchor_manifest),
      key_custody_manifest: sha256Hex(record.key_custody_manifest),
      pilot_readiness_gate: sha256Hex(record.pilot_readiness_gate),
      verifier_report: sha256Hex(record.verifier_report),
      audit_pack: sha256Hex(record.audit_pack),
    },
  };
  const entry_hash = sha256Hex(entryPayload);
  const entry = { ...entryPayload, entry_hash };
  ledger.entries.push(entry);
  ledger.head_hash = entry_hash;
  ledger.updated_at = nowIso();
  await writeJsonFile(ledgerPath, ledger);
  return { ledger, ledger_entry: entry };
};

export const verifyLedger = async (outputDir = DEFAULT_OUTPUT_DIR) => {
  const ledger = await readJsonFile(join(outputDir, 'ledger.json'), {
    schema_version: 'aethelred-public-proof-ledger-v0.2',
    head_hash: GENESIS_HASH,
    entries: [],
  });
  const failures = [];
  let expectedPrevious = GENESIS_HASH;
  const chain = (ledger.entries || []).map((entry, index) => {
    const payload = omit(entry, ['entry_hash']);
    const recomputed = sha256Hex(payload);
    const previousOk = entry.previous_hash === expectedPrevious;
    const entryOk = recomputed === entry.entry_hash;
    if (!previousOk) failures.push({ index, code: 'previous_hash_mismatch', expected: expectedPrevious, actual: entry.previous_hash });
    if (!entryOk) failures.push({ index, code: 'entry_hash_mismatch', expected: entry.entry_hash, actual: recomputed });
    expectedPrevious = entry.entry_hash;
    return {
      index,
      run_id: entry.run_id,
      seal_id: entry.seal_id,
      entry_hash: entry.entry_hash,
      recomputed_entry_hash: recomputed,
      status: previousOk && entryOk ? 'verified' : 'broken',
    };
  });
  const computedHead = chain.length ? chain[chain.length - 1].entry_hash : GENESIS_HASH;
  if ((ledger.head_hash || GENESIS_HASH) !== computedHead) {
    failures.push({ index: chain.length - 1, code: 'head_hash_mismatch', expected: computedHead, actual: ledger.head_hash });
  }
  return {
    checked_at: nowIso(),
    valid: failures.length === 0,
    head_hash: ledger.head_hash || GENESIS_HASH,
    computed_head_hash: computedHead,
    entry_count: chain.length,
    failures,
    chain,
  };
};

export const writeProofArtifacts = async (record, outputDir = DEFAULT_OUTPUT_DIR) => {
  const runDir = join(outputDir, 'runs', record.run_id);
  const latestDir = join(outputDir, 'latest');
  const artifacts = {
    'proof-record.json': record,
    'aethelred-seal.json': record.seal,
    'policy-receipt.json': record.policy_receipt,
    'docker-attestation.json': record.attestation,
    'external-compute-report.json': record.external_compute_report,
    'evidence-bundle.json': record.evidence_bundle,
    'institutional-context.json': record.institutional_context,
    'assurance-plan.json': record.assurance_plan,
    'validator-quorum.json': record.validator_quorum,
    'jurisdiction-report.json': record.jurisdiction_report,
    'liability-route.json': record.liability_route,
    'key-custody-manifest.json': record.key_custody_manifest,
    'anchor-manifest.json': record.anchor_manifest,
    'pilot-readiness-gate.json': record.pilot_readiness_gate,
    'sovereign-differentiation-scorecard.json': record.sovereign_differentiation_scorecard,
    'regulatory-evidence-index.json': record.regulatory_evidence_index,
    'auditor-attestation.json': record.auditor_attestation,
    'public-verifier-manifest.json': record.public_verifier_manifest,
    'audit-pack.json': record.audit_pack,
    'verifier-report.json': record.verifier_report,
  };

  for (const [name, value] of Object.entries(artifacts)) {
    await writeJsonFile(join(runDir, name), value);
    await writeJsonFile(join(latestDir, name), value);
  }
  await writeTextFile(join(runDir, 'audit-report.md'), record.audit_markdown);
  await writeTextFile(join(latestDir, 'audit-report.md'), record.audit_markdown);
  await writeJsonFile(join(outputDir, 'latest-run.json'), {
    run_id: record.run_id,
    seal_id: record.seal.seal_id,
    created_at: record.created_at,
    verifier_valid: record.verifier_report.valid,
    assurance_tier: record.assurance_plan.target_tier.tier,
    quorum_reached: record.validator_quorum.quorum_reached,
    latest_dir: latestDir,
    run_dir: runDir,
  });

  const ledgerResult = await appendLedger(outputDir, record);
  return {
    run_dir: runDir,
    latest_dir: latestDir,
    ledger: ledgerResult.ledger,
    ledger_entry: ledgerResult.ledger_entry,
  };
};

export const buildProofPath = async ({ request = defaultProofRequest(), outputDir = DEFAULT_OUTPUT_DIR } = {}) => {
  const record = createProofRecord(request);
  const writeResult = await writeProofArtifacts(record, outputDir);
  return {
    ...record,
    storage: writeResult,
  };
};

export const readLatestRecord = async (outputDir = DEFAULT_OUTPUT_DIR) =>
  readJsonFile(join(outputDir, 'latest', 'proof-record.json'), null);

export const readLatestArtifact = async (name, outputDir = DEFAULT_OUTPUT_DIR) =>
  readJsonFile(join(outputDir, 'latest', name), null);
