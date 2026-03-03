/**
 * Compute Job Types
 */

export type JobStatus =
  | 'pending'
  | 'assigned'
  | 'executing'
  | 'verifying'
  | 'completed'
  | 'failed'
  | 'expired';

export type JobPriority = 'low' | 'normal' | 'high' | 'critical';

export type ProofType = 'tee' | 'zkml' | 'hybrid';

export interface ComputeJob {
  /** Unique job ID */
  id: string;

  /** Model hash */
  modelHash: string;

  /** Input hash */
  inputHash: string;

  /** Address that requested the job */
  requestedBy: string;

  /** Purpose */
  purpose: string;

  /** Proof type required */
  proofType: ProofType;

  /** Job priority */
  priority: JobPriority;

  /** Current status */
  status: JobStatus;

  /** Creation timestamp */
  createdAt: string;

  /** Start timestamp */
  startedAt?: string;

  /** Completion timestamp */
  completedAt?: string;

  /** Expiration timestamp */
  expiresAt?: string;

  /** Assigned validators */
  assignedValidators?: string[];

  /** Result if completed */
  result?: ComputeResult;

  /** Error if failed */
  error?: string;

  /** Retry count */
  retryCount: number;

  /** Max retries */
  maxRetries: number;

  /** Seal ID if seal was created */
  sealId?: string;
}

export interface ComputeResult {
  /** Job ID */
  jobId: string;

  /** Output hash */
  outputHash: string;

  /** Output data (may be encrypted) */
  outputData?: string;

  /** Verification type used */
  verificationType: ProofType;

  /** Validator verifications */
  verifications: ValidatorVerification[];

  /** Consensus reached */
  consensusReached: boolean;

  /** Agreement count */
  agreementCount: number;

  /** Execution time in ms */
  executionTimeMs: number;

  /** Processed at */
  processedAt: string;
}

export interface ValidatorVerification {
  /** Validator address */
  validatorAddress: string;

  /** Output hash computed */
  outputHash: string;

  /** Execution time in ms */
  executionTimeMs: number;

  /** TEE attestation */
  attestation?: TEEAttestationResult;

  /** Timestamp */
  timestamp: string;

  /** Signature */
  signature: string;
}

export interface TEEAttestationResult {
  /** Platform */
  platform: string;

  /** Enclave ID */
  enclaveId: string;

  /** Measurement */
  measurement: string;

  /** Nonce */
  nonce?: string;

  /** Valid */
  valid: boolean;
}

// Job submission types

export interface SubmitJobRequest {
  /** Model hash (hex) */
  modelHash: string;

  /** Input data or hash */
  inputData?: string;
  inputHash?: string;

  /** Purpose of computation */
  purpose: string;

  /** Proof type */
  proofType?: ProofType;

  /** Priority */
  priority?: JobPriority;

  /** Max wait time in seconds */
  maxWaitTime?: number;

  /** Callback URL for completion */
  callbackUrl?: string;

  /** Custom metadata */
  metadata?: Record<string, string>;
}

export interface SubmitJobResponse {
  /** Job ID */
  jobId: string;

  /** Status */
  status: JobStatus;

  /** Estimated completion time */
  estimatedCompletionTime?: string;

  /** Transaction hash */
  txHash?: string;
}

// Job query types

export interface JobQuery {
  /** Filter by requester */
  requester?: string;

  /** Filter by status */
  status?: JobStatus;

  /** Filter by model hash */
  modelHash?: string;

  /** Filter by proof type */
  proofType?: ProofType;

  /** Min creation time */
  minCreatedAt?: string;

  /** Max creation time */
  maxCreatedAt?: string;

  /** Pagination limit */
  limit?: number;

  /** Pagination offset */
  offset?: number;
}

export interface JobListResponse {
  /** Jobs */
  jobs: ComputeJob[];

  /** Total count */
  total: number;

  /** Has more */
  hasMore: boolean;
}

// Model types

export interface RegisteredModel {
  /** Model ID */
  modelId: string;

  /** Model hash */
  modelHash: string;

  /** Name */
  name: string;

  /** Version */
  version: string;

  /** Description */
  description?: string;

  /** Circuit hash for zkML */
  circuitHash?: string;

  /** TEE measurement */
  teeMeasurement?: string;

  /** Status */
  status: 'active' | 'inactive' | 'deprecated';

  /** Registered by */
  registeredBy: string;

  /** Registration transaction */
  registrationTx: string;

  /** Registered at */
  registeredAt: string;
}

export interface ModelQuery {
  /** Filter by status */
  status?: 'active' | 'inactive' | 'deprecated';

  /** Filter by owner */
  owner?: string;

  /** Search by name */
  nameContains?: string;

  /** Pagination limit */
  limit?: number;

  /** Pagination offset */
  offset?: number;
}
