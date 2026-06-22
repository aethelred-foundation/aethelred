/**
 * Core types for Aethelred SDK.
 */

// ============ Basic Types ============

export type Address = string;
export type Hash = string;
export type TxHash = string;

// ============ Enums ============

export enum JobStatus {
  UNSPECIFIED = 'JOB_STATUS_UNSPECIFIED',
  PENDING = 'JOB_STATUS_PENDING',
  ASSIGNED = 'JOB_STATUS_ASSIGNED',
  COMPUTING = 'JOB_STATUS_COMPUTING',
  VERIFYING = 'JOB_STATUS_VERIFYING',
  COMPLETED = 'JOB_STATUS_COMPLETED',
  FAILED = 'JOB_STATUS_FAILED',
  CANCELLED = 'JOB_STATUS_CANCELLED',
  EXPIRED = 'JOB_STATUS_EXPIRED',
}

export enum SealStatus {
  UNSPECIFIED = 'SEAL_STATUS_UNSPECIFIED',
  ACTIVE = 'SEAL_STATUS_ACTIVE',
  REVOKED = 'SEAL_STATUS_REVOKED',
  EXPIRED = 'SEAL_STATUS_EXPIRED',
  SUPERSEDED = 'SEAL_STATUS_SUPERSEDED',
}

export enum ProofType {
  UNSPECIFIED = 'PROOF_TYPE_UNSPECIFIED',
  TEE = 'PROOF_TYPE_TEE',
  ZKML = 'PROOF_TYPE_ZKML',
  HYBRID = 'PROOF_TYPE_HYBRID',
  OPTIMISTIC = 'PROOF_TYPE_OPTIMISTIC',
}

export enum ProofSystem {
  UNSPECIFIED = 'PROOF_SYSTEM_UNSPECIFIED',
  GROTH16 = 'PROOF_SYSTEM_GROTH16',
  PLONK = 'PROOF_SYSTEM_PLONK',
  STARK = 'PROOF_SYSTEM_STARK',
  EZKL = 'PROOF_SYSTEM_EZKL',
}

export enum TEEPlatform {
  UNSPECIFIED = 'TEE_PLATFORM_UNSPECIFIED',
  INTEL_SGX = 'TEE_PLATFORM_INTEL_SGX',
  AMD_SEV = 'TEE_PLATFORM_AMD_SEV',
  AWS_NITRO = 'TEE_PLATFORM_AWS_NITRO',
  ARM_TRUSTZONE = 'TEE_PLATFORM_ARM_TRUSTZONE',
}

export enum UtilityCategory {
  UNSPECIFIED = 'UTILITY_CATEGORY_UNSPECIFIED',
  MEDICAL = 'UTILITY_CATEGORY_MEDICAL',
  SCIENTIFIC = 'UTILITY_CATEGORY_SCIENTIFIC',
  FINANCIAL = 'UTILITY_CATEGORY_FINANCIAL',
  LEGAL = 'UTILITY_CATEGORY_LEGAL',
  EDUCATIONAL = 'UTILITY_CATEGORY_EDUCATIONAL',
  ENVIRONMENTAL = 'UTILITY_CATEGORY_ENVIRONMENTAL',
  GENERAL = 'UTILITY_CATEGORY_GENERAL',
}

// ============ Interfaces ============

export interface PageRequest {
  key?: string;
  offset?: number;
  limit?: number;
  countTotal?: boolean;
  reverse?: boolean;
}

export interface PageResponse {
  nextKey?: string;
  total: number;
}

export interface ComputeJob {
  id: string;
  creator: Address;
  modelHash: Hash;
  inputHash: Hash;
  outputHash?: Hash;
  status: JobStatus;
  proofType: ProofType;
  priority: number;
  maxGas: string;
  timeoutBlocks: number;
  createdAt: Date;
  completedAt?: Date;
  validatorAddress?: Address;
  metadata: Record<string, string>;
}

export interface SubmitJobRequest {
  modelHash: Hash;
  inputHash: Hash;
  proofType?: ProofType;
  priority?: number;
  maxGas?: string;
  timeoutBlocks?: number;
  callbackUrl?: string;
  metadata?: Record<string, string>;
}

export interface SubmitJobResponse {
  jobId: string;
  txHash: TxHash;
  estimatedBlocks: number;
}

export interface RegulatoryInfo {
  jurisdiction: string;
  complianceFrameworks: string[];
  dataClassification: string;
  retentionPeriod: string;
  auditTrailHash?: Hash;
}

export interface ValidatorAttestation {
  validatorAddress: Address;
  signature: string;
  timestamp: Date;
  votingPower: string;
}

export interface TEEAttestation {
  platform: TEEPlatform;
  quote: string;
  enclaveHash: Hash;
  timestamp: Date;
  pcrValues: Record<string, string>;
  nonce?: string;
}

export interface ZKMLProof {
  proofSystem: ProofSystem;
  proof: string;
  publicInputs: string[];
  verifyingKeyHash: Hash;
}

export interface DigitalSeal {
  id: string;
  jobId: string;
  modelHash: Hash;
  inputCommitment: Hash;
  outputCommitment: Hash;
  modelCommitment: Hash;
  status: SealStatus;
  requester: Address;
  validators: ValidatorAttestation[];
  teeAttestation?: TEEAttestation;
  zkmlProof?: ZKMLProof;
  regulatoryInfo?: RegulatoryInfo;
  createdAt: Date;
  expiresAt?: Date;
  revokedAt?: Date;
  revocationReason?: string;
}

export interface CreateSealRequest {
  jobId: string;
  regulatoryInfo?: RegulatoryInfo;
  expiresInBlocks?: number;
  metadata?: Record<string, string>;
}

export interface CreateSealResponse {
  sealId: string;
  txHash: TxHash;
}

export interface VerifySealResponse {
  valid: boolean;
  seal?: DigitalSeal;
  verificationType?: string;
  verification_type?: string;
  status?: string;
  verificationDetails?: Record<string, boolean>;
  errors?: string[];
}

export type SealExportFormat = 'json' | 'compact' | 'portable' | 'audit';

export interface ExportedSeal {
  version: string;
  format: SealExportFormat;
  seal: DigitalSeal | Record<string, unknown>;
  verification?: Record<string, unknown>;
  metadata: {
    exportedAt?: string;
    exported_at?: string;
    exportedBy?: string;
    exported_by?: string;
    chainId?: string;
    chain_id?: string;
    blockHeight?: number;
    block_height?: number;
    contentHash?: string;
    content_hash?: string;
  };
}

export interface EvidenceBundle {
  schema_version: '1.0.0';
  bundle_id: string;
  job_id: string;
  chain_id: string;
  seal_id: string;
  timestamp: string;
  model_hash: string;
  circuit_hash: string;
  verifying_key_hash: string;
  validator_signature: string;
  confidence_score: number;
  tee_evidence: {
    platform: 'sgx' | 'nitro' | 'sev-snp';
    enclave_id: string;
    measurement: string;
    quote: string;
    nonce: string;
  };
  zkml_evidence: {
    proof_system: 'groth16' | 'plonk' | 'ezkl' | 'halo2' | 'stark';
    proof_bytes: string;
    public_inputs: string;
    output_commitment: string;
  };
  region: string;
  operator: string;
  policy_decision: {
    mode: 'hybrid';
    require_both: true;
    fallback_allowed: false;
    policy_version?: string;
    [key: string]: unknown;
  };
  archive_pointer: {
    archive_type: string;
    index: string;
    document_id: string;
    uri: string;
    retention_days: number;
    write_status: string;
    [key: string]: unknown;
  };
  verification: {
    artifact_mode?: string;
    schema_verified: boolean;
    policy_verified: boolean;
    tee_attestation_verified: boolean;
    zkml_proof_verified: boolean;
    digital_seal_verified: boolean;
    live_verification_required: boolean;
    verifier_version: string;
    [key: string]: unknown;
  };
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface RegisteredModel {
  modelHash: Hash;
  name: string;
  owner: Address;
  architecture: string;
  version: string;
  category: UtilityCategory;
  inputSchema: string;
  outputSchema: string;
  storageUri: string;
  registeredAt: Date;
  verified: boolean;
  totalJobs: number;
}

export interface HardwareCapability {
  teePlatforms: TEEPlatform[];
  zkmlSupported: boolean;
  maxModelSizeMb: number;
  gpuMemoryGb: number;
  cpuCores: number;
  memoryGb: number;
}

export interface ValidatorStats {
  address: Address;
  jobsCompleted: number;
  jobsFailed: number;
  averageLatencyMs: number;
  uptimePercentage: number;
  reputationScore: number;
  totalRewards: string;
  slashingEvents: number;
  hardwareCapabilities?: HardwareCapability;
}

export interface NodeInfo {
  defaultNodeId: string;
  listenAddr: string;
  network: string;
  version: string;
  moniker: string;
}

export interface Block {
  blockId: { hash: string };
  header: { height: number; time: Date; chainId: string };
}
