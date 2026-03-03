/**
 * Digital Seal Types
 */

export type SealStatus = 'pending' | 'active' | 'revoked' | 'expired';

export type VerificationType = 'tee' | 'zkml' | 'hybrid';

export interface DigitalSeal {
  /** Unique seal identifier */
  id: string;

  /** SHA-256 hash of the model weights */
  modelCommitment: string;

  /** SHA-256 hash of the input data */
  inputCommitment: string;

  /** SHA-256 hash of the output */
  outputCommitment: string;

  /** Current status */
  status: SealStatus;

  /** Block height when created */
  blockHeight: number;

  /** Creation timestamp */
  timestamp: string;

  /** Address that requested the seal */
  requestedBy: string;

  /** Purpose of the verification */
  purpose: string;

  /** Type of verification used */
  verificationType: VerificationType;

  /** Validators who verified */
  validatorSet: string[];

  /** TEE attestations if available */
  teeAttestations?: TEEAttestation[];

  /** zkML proof if available */
  zkProof?: ZKMLProof;

  /** Regulatory information */
  regulatoryInfo: RegulatoryInfo;

  /** Chain ID */
  chainId?: string;

  /** Seal hash */
  sealHash?: string;
}

export interface TEEAttestation {
  /** Validator address */
  validatorAddress: string;

  /** TEE platform (aws-nitro, intel-sgx, etc.) */
  platform: string;

  /** Enclave ID */
  enclaveId: string;

  /** Measurement (PCR values) */
  measurement: string;

  /** Quote data */
  quote: string;

  /** Attestation timestamp */
  timestamp: string;

  /** Signature */
  signature?: string;
}

export interface ZKMLProof {
  /** Proof system used (ezkl, risc0, etc.) */
  proofSystem: string;

  /** Proof bytes (base64) */
  proofBytes: string;

  /** Public inputs */
  publicInputs: string[];

  /** Verifying key hash */
  verifyingKeyHash: string;

  /** Circuit hash */
  circuitHash?: string;

  /** Proof size in bytes */
  proofSizeBytes?: number;
}

export interface RegulatoryInfo {
  /** Compliance frameworks (FCRA, GDPR, etc.) */
  complianceFrameworks: string[];

  /** Data classification */
  dataClassification: string;

  /** Jurisdiction ID */
  jurisdictionId?: string;

  /** Retention period in seconds */
  retentionPeriod?: number;

  /** Whether audit is required */
  auditRequired: boolean;
}

export interface EnhancedDigitalSeal extends DigitalSeal {
  /** Format version */
  version: number;

  /** Associated job ID */
  jobId: string;

  /** Consensus information */
  consensusInfo?: ConsensusInfo;

  /** Verification bundle */
  verificationBundle?: VerificationBundle;

  /** Audit trail */
  auditTrail: AuditEntry[];

  /** Signatures */
  signatures: SealSignature[];

  /** Expiration time */
  expiresAt?: string;

  /** Metadata */
  metadata?: SealMetadata;
}

export interface ConsensusInfo {
  /** Block height */
  height: number;

  /** Consensus round */
  round: number;

  /** Total validators */
  totalValidators: number;

  /** Participating validators */
  participatingValidators: number;

  /** Validators who agreed */
  agreementCount: number;

  /** Consensus threshold percentage */
  consensusThreshold: number;

  /** Consensus timestamp */
  timestamp: string;
}

export interface VerificationBundle {
  /** Verification type */
  verificationType: VerificationType;

  /** TEE verifications */
  teeVerifications: TEEVerification[];

  /** zkML verification */
  zkmlVerification?: ZKMLVerification;

  /** Aggregated output hash */
  aggregatedOutputHash: string;

  /** Bundle hash */
  bundleHash: string;
}

export interface TEEVerification {
  /** Validator address */
  validatorAddress: string;

  /** Platform */
  platform: string;

  /** Enclave ID */
  enclaveId: string;

  /** Output hash computed */
  outputHash: string;

  /** Execution time in ms */
  executionTimeMs: number;

  /** Timestamp */
  timestamp: string;
}

export interface ZKMLVerification {
  /** Proof system */
  proofSystem: string;

  /** Proof bytes (base64) */
  proof: string;

  /** Public inputs */
  publicInputs: ZKMLPublicInputs;

  /** Verified flag */
  verified: boolean;

  /** Generation time in ms */
  generationTimeMs: number;

  /** Verification time in ms */
  verificationTimeMs: number;
}

export interface ZKMLPublicInputs {
  /** Model commitment */
  modelCommitment: string;

  /** Input commitment */
  inputCommitment: string;

  /** Output commitment */
  outputCommitment: string;

  /** Scale factors */
  scaleFactors?: number[];
}

export interface AuditEntry {
  /** Event timestamp */
  timestamp: string;

  /** Event type */
  eventType: AuditEventType;

  /** Actor who performed the action */
  actor: string;

  /** Event details */
  details: string;

  /** Block height */
  blockHeight: number;

  /** Transaction hash */
  transactionHash?: string;
}

export type AuditEventType =
  | 'created'
  | 'verified'
  | 'activated'
  | 'accessed'
  | 'exported'
  | 'revoked'
  | 'expired'
  | 'metadata_updated'
  | 'compliance_check';

export interface SealSignature {
  /** Signer address */
  signerAddress: string;

  /** Signer type */
  signerType: 'validator' | 'authority' | 'user';

  /** Algorithm */
  algorithm: string;

  /** Public key */
  publicKey: string;

  /** Signature bytes (base64) */
  signature: string;

  /** Timestamp */
  timestamp: string;
}

export interface SealMetadata {
  /** Tags */
  tags?: string[];

  /** Description */
  description?: string;

  /** External reference */
  externalRef?: string;

  /** Custom data */
  customData?: Record<string, string>;

  /** Input schema */
  inputSchema?: string;

  /** Output schema */
  outputSchema?: string;

  /** Model architecture */
  modelArchitecture?: string;
}

// Query types

export interface SealQuery {
  /** Filter by model hash */
  modelHash?: string;

  /** Filter by purpose */
  purpose?: string;

  /** Filter by requester */
  requester?: string;

  /** Filter by status */
  status?: SealStatus;

  /** Filter by min block height */
  minBlockHeight?: number;

  /** Filter by max block height */
  maxBlockHeight?: number;

  /** Pagination limit */
  limit?: number;

  /** Pagination offset */
  offset?: number;
}

export interface SealListResponse {
  /** Seals */
  seals: DigitalSeal[];

  /** Total count */
  total: number;

  /** Has more pages */
  hasMore: boolean;
}

// Verification result types

export interface SealVerificationResult {
  /** Seal ID */
  sealId: string;

  /** Is valid */
  valid: boolean;

  /** Verification checks */
  checks: VerificationCheck[];

  /** Summary */
  summary: string;

  /** Verified at */
  verifiedAt: string;
}

export interface VerificationCheck {
  /** Check name */
  name: string;

  /** Passed */
  passed: boolean;

  /** Is warning only */
  warning: boolean;

  /** Message */
  message: string;
}

// Export types

export type ExportFormat = 'json' | 'compact' | 'portable' | 'audit' | 'cbor';

export interface ExportOptions {
  /** Export format */
  format: ExportFormat;

  /** Include proofs */
  includeProofs?: boolean;

  /** Include attestations */
  includeAttestations?: boolean;

  /** Include audit trail */
  includeAuditTrail?: boolean;

  /** Verify before export */
  verifyBeforeExport?: boolean;
}

export interface ExportedSeal {
  /** Version */
  version: string;

  /** Format */
  format: ExportFormat;

  /** Seal data */
  seal: DigitalSeal | Record<string, unknown>;

  /** Verification result if verified */
  verification?: SealVerificationResult;

  /** Export metadata */
  metadata: ExportMetadata;
}

export interface ExportMetadata {
  /** Export timestamp */
  exportedAt: string;

  /** Exported by */
  exportedBy?: string;

  /** Chain ID */
  chainId: string;

  /** Block height at export */
  blockHeight: number;

  /** Content hash */
  contentHash: string;
}
