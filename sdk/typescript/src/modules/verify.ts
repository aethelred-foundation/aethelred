/**
 * Verify Module - Verification operations
 */

import { AxiosInstance } from 'axios';
import { AethelredConfig } from '../client/config';
import {
  TEEAttestation,
  ZKMLProof,
  VerificationEvidence,
} from '../types/seal';

export interface VerificationRequest {
  /** Model hash */
  modelHash: string;

  /** Input data or hash */
  inputData?: string;
  inputHash?: string;

  /** Output hash to verify */
  outputHash: string;

  /** Verification type */
  verificationType: 'tee' | 'zkml' | 'hybrid';

  /** Timeout in seconds */
  timeoutSec?: number;
}

export interface VerificationResponse {
  /** Verification ID */
  verificationId: string;

  /** Is valid */
  valid: boolean;

  /** Verification evidence */
  evidence: VerificationEvidence;

  /** Validator addresses that verified */
  validators: string[];

  /** Consensus reached */
  consensusReached: boolean;

  /** Processing time */
  processingTimeMs: number;

  /** Timestamp */
  timestamp: string;
}

export interface TEEVerificationResult {
  /** Is valid */
  valid: boolean;

  /** Attestation */
  attestation: TEEAttestation;

  /** Validator address */
  validatorAddress: string;

  /** Execution time */
  executionTimeMs: number;
}

export interface ZKMLVerificationResult {
  /** Is valid */
  valid: boolean;

  /** Proof */
  proof: ZKMLProof;

  /** Circuit hash */
  circuitHash: string;

  /** Proving time */
  provingTimeMs: number;
}

export interface ModelInfo {
  /** Model hash */
  modelHash: string;

  /** Model name */
  name: string;

  /** Version */
  version: string;

  /** Is registered */
  registered: boolean;

  /** Supported verification types */
  supportedVerification: ('tee' | 'zkml' | 'hybrid')[];

  /** Circuit available for zkML */
  zkmlCircuitAvailable: boolean;

  /** TEE measurement */
  teeMeasurement?: string;
}

export class VerifyModule {
  private httpClient: AxiosInstance;
  private config: AethelredConfig;

  constructor(httpClient: AxiosInstance, config: AethelredConfig) {
    this.httpClient = httpClient;
    this.config = config;
  }

  /**
   * Verify a computation result
   */
  async verify(request: VerificationRequest): Promise<VerificationResponse> {
    const response = await this.httpClient.post<VerificationResponse>(
      '/aethelred/verify/v1/verify',
      request
    );
    return response.data;
  }

  /**
   * Verify using TEE only
   */
  async verifyWithTEE(
    modelHash: string,
    inputHash: string,
    outputHash: string
  ): Promise<TEEVerificationResult> {
    const response = await this.httpClient.post<TEEVerificationResult>(
      '/aethelred/verify/v1/tee',
      { modelHash, inputHash, outputHash }
    );
    return response.data;
  }

  /**
   * Verify using zkML only
   */
  async verifyWithZKML(
    modelHash: string,
    inputHash: string,
    outputHash: string
  ): Promise<ZKMLVerificationResult> {
    const response = await this.httpClient.post<ZKMLVerificationResult>(
      '/aethelred/verify/v1/zkml',
      { modelHash, inputHash, outputHash }
    );
    return response.data;
  }

  /**
   * Verify using hybrid (TEE + zkML)
   */
  async verifyHybrid(
    modelHash: string,
    inputHash: string,
    outputHash: string
  ): Promise<VerificationResponse> {
    return this.verify({
      modelHash,
      inputHash,
      outputHash,
      verificationType: 'hybrid',
    });
  }

  /**
   * Validate a TEE attestation
   */
  async validateAttestation(attestation: TEEAttestation): Promise<boolean> {
    const response = await this.httpClient.post<{ valid: boolean }>(
      '/aethelred/verify/v1/attestation/validate',
      attestation
    );
    return response.data.valid;
  }

  /**
   * Validate a zkML proof
   */
  async validateProof(proof: ZKMLProof): Promise<boolean> {
    const response = await this.httpClient.post<{ valid: boolean }>(
      '/aethelred/verify/v1/proof/validate',
      proof
    );
    return response.data.valid;
  }

  /**
   * Get model information
   */
  async getModelInfo(modelHash: string): Promise<ModelInfo | null> {
    try {
      const response = await this.httpClient.get<ModelInfo>(
        `/aethelred/verify/v1/model/${modelHash}`
      );
      return response.data;
    } catch (error: any) {
      if (error.response?.status === 404) {
        return null;
      }
      throw error;
    }
  }

  /**
   * Check if a model supports verification type
   */
  async supportsVerification(
    modelHash: string,
    verificationType: 'tee' | 'zkml' | 'hybrid'
  ): Promise<boolean> {
    const info = await this.getModelInfo(modelHash);
    if (!info) return false;
    return info.supportedVerification.includes(verificationType);
  }

  /**
   * Get available validators for verification
   */
  async getAvailableValidators(): Promise<ValidatorCapability[]> {
    const response = await this.httpClient.get<ValidatorCapability[]>(
      '/aethelred/verify/v1/validators'
    );
    return response.data;
  }

  /**
   * Get verification statistics
   */
  async getStats(): Promise<VerificationStats> {
    const response = await this.httpClient.get<VerificationStats>(
      '/aethelred/verify/v1/stats'
    );
    return response.data;
  }

  /**
   * Estimate verification time
   */
  async estimateTime(
    modelHash: string,
    verificationType: 'tee' | 'zkml' | 'hybrid'
  ): Promise<TimeEstimate> {
    const response = await this.httpClient.post<TimeEstimate>(
      '/aethelred/verify/v1/estimate',
      { modelHash, verificationType }
    );
    return response.data;
  }

  /**
   * Generate verification proof for external use
   */
  async generateProofBundle(verificationId: string): Promise<ProofBundle> {
    const response = await this.httpClient.get<ProofBundle>(
      `/aethelred/verify/v1/proof-bundle/${verificationId}`
    );
    return response.data;
  }

  /**
   * Verify a proof bundle offline
   */
  verifyProofBundleOffline(bundle: ProofBundle): boolean {
    // Client-side verification of proof bundle
    // This allows verification without network access

    // Verify TEE attestations
    if (bundle.teeAttestations) {
      for (const attestation of bundle.teeAttestations) {
        if (!this.verifyAttestationSignature(attestation)) {
          return false;
        }
      }
    }

    // Verify zkML proof (basic check)
    if (bundle.zkmlProof) {
      if (!bundle.zkmlProof.valid) {
        return false;
      }
    }

    // Check consensus
    const validatorCount = bundle.teeAttestations?.length || 0;
    const requiredConsensus = Math.floor((validatorCount * 2) / 3) + 1;
    const agreements = bundle.teeAttestations?.filter(
      (a) => a.outputHash === bundle.outputHash
    ).length || 0;

    return agreements >= requiredConsensus;
  }

  // Private helpers

  private verifyAttestationSignature(attestation: TEEAttestation): boolean {
    // In production, this would verify the cryptographic signature
    // For now, return true if required fields are present
    return !!(
      attestation.platform &&
      attestation.enclaveId &&
      attestation.signature
    );
  }
}

// Additional types

export interface ValidatorCapability {
  address: string;
  hasTEE: boolean;
  teeType?: 'nitro' | 'sgx' | 'sev';
  hasZKML: boolean;
  supportedModels: string[];
  currentLoad: number; // 0-1
  estimatedWaitTime: number; // seconds
}

export interface VerificationStats {
  totalVerifications: number;
  teeVerifications: number;
  zkmlVerifications: number;
  hybridVerifications: number;
  averageProcessingTimeMs: number;
  successRate: number;
  validatorCount: number;
}

export interface TimeEstimate {
  estimatedTimeMs: number;
  minTimeMs: number;
  maxTimeMs: number;
  queuePosition: number;
  validatorsAvailable: number;
}

export interface ProofBundle {
  verificationId: string;
  modelHash: string;
  inputHash: string;
  outputHash: string;
  teeAttestations?: (TEEAttestation & { outputHash: string })[];
  zkmlProof?: ZKMLProof & { valid: boolean };
  consensusReached: boolean;
  timestamp: string;
  blockHeight: number;
  chainId: string;
}
