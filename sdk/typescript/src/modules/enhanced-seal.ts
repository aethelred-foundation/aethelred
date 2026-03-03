/**
 * Enhanced Seal Module
 *
 * Advanced Digital Seal operations with streaming, batching,
 * and comprehensive verification.
 */

import { AxiosInstance } from 'axios';
import { SigningStargateClient } from '@cosmjs/stargate';
import { AethelredConfig } from '../client/config';
import { getLogger } from '../core/logger';
import { Cache, memoize } from '../core/cache';
import { retry, RetryConfig } from '../core/retry';
import { EventEmitter, AethelredEventType } from '../core/events';
import { SealError, AethelredErrorCode, Errors } from '../core/errors';
import {
  DigitalSeal,
  SealStatus,
  CreateSealRequest,
  CreateSealResponse,
  SealQuery,
  SealListResponse,
  SealVerificationResult,
  AuditReport,
  AuditReportRequest,
  RevocationRequest,
  RevocationResult,
  TEEAttestation,
  ZKMLProof,
} from '../types/seal';

const logger = getLogger('seal');

/**
 * Seal verification depth
 */
export type VerificationDepth = 'quick' | 'standard' | 'comprehensive';

/**
 * Batch operation result
 */
export interface BatchResult<T> {
  successful: T[];
  failed: { id: string; error: Error }[];
  totalTime: number;
}

/**
 * Seal stream options
 */
export interface SealStreamOptions {
  /** Starting block height */
  fromHeight?: number;
  /** Filter by status */
  status?: SealStatus;
  /** Filter by model hash */
  modelHash?: string;
  /** Buffer size */
  bufferSize?: number;
}

/**
 * Seal comparison result
 */
export interface SealComparisonResult {
  seal1: DigitalSeal;
  seal2: DigitalSeal;
  match: boolean;
  differences: {
    field: string;
    value1: any;
    value2: any;
  }[];
}

/**
 * Enhanced Seal Module
 */
export class EnhancedSealModule {
  private httpClient: AxiosInstance;
  private signingClient: SigningStargateClient | null;
  private config: AethelredConfig;
  private cache: Cache;
  private events: EventEmitter;

  constructor(
    httpClient: AxiosInstance,
    signingClient: SigningStargateClient | null,
    config: AethelredConfig,
    events?: EventEmitter
  ) {
    this.httpClient = httpClient;
    this.signingClient = signingClient;
    this.config = config;
    this.cache = new Cache({ defaultTTLMs: 60000 });
    this.events = events || new EventEmitter();
  }

  // ============ Core Operations ============

  /**
   * Get seal by ID with caching
   */
  async getSeal(sealId: string, options?: { skipCache?: boolean }): Promise<DigitalSeal | null> {
    const cacheKey = `seal:${sealId}`;

    if (!options?.skipCache) {
      const cached = this.cache.get<DigitalSeal>(cacheKey);
      if (cached) {
        logger.trace('Seal cache hit', { sealId });
        return cached;
      }
    }

    try {
      const response = await this.httpClient.get<DigitalSeal>(
        `/aethelred/seal/v1/seal/${sealId}`
      );

      this.cache.set(cacheKey, response.data, {
        ttlMs: 60000,
        tags: ['seal', `model:${response.data.modelCommitment}`],
      });

      return response.data;
    } catch (error: any) {
      if (error.response?.status === 404) {
        return null;
      }
      throw new SealError(
        AethelredErrorCode.SEAL_NOT_FOUND,
        `Failed to get seal: ${error.message}`,
        sealId
      );
    }
  }

  /**
   * Get multiple seals by IDs (batched)
   */
  async getSeals(sealIds: string[]): Promise<Map<string, DigitalSeal | null>> {
    const results = new Map<string, DigitalSeal | null>();

    // Check cache first
    const uncached: string[] = [];
    for (const id of sealIds) {
      const cached = this.cache.get<DigitalSeal>(`seal:${id}`);
      if (cached) {
        results.set(id, cached);
      } else {
        uncached.push(id);
      }
    }

    // Fetch uncached in parallel
    if (uncached.length > 0) {
      const fetched = await Promise.all(
        uncached.map(async (id) => {
          const seal = await this.getSeal(id, { skipCache: true });
          return { id, seal };
        })
      );

      for (const { id, seal } of fetched) {
        results.set(id, seal);
      }
    }

    return results;
  }

  /**
   * List seals with pagination
   */
  async listSeals(query?: SealQuery): Promise<SealListResponse> {
    const params = this.buildQueryParams(query);

    const response = await this.httpClient.get<SealListResponse>(
      `/aethelred/seal/v1/seals?${params.toString()}`
    );

    return response.data;
  }

  /**
   * Iterate over all seals with automatic pagination
   */
  async *iterateSeals(
    query?: Omit<SealQuery, 'offset' | 'limit'>,
    batchSize: number = 100
  ): AsyncGenerator<DigitalSeal> {
    let offset = 0;
    let hasMore = true;

    while (hasMore) {
      const response = await this.listSeals({
        ...query,
        offset,
        limit: batchSize,
      });

      for (const seal of response.seals) {
        yield seal;
      }

      hasMore = response.hasMore;
      offset += batchSize;
    }
  }

  /**
   * Stream seals in real-time (requires WebSocket)
   */
  streamSeals(
    options: SealStreamOptions = {},
    callback: (seal: DigitalSeal) => void
  ): () => void {
    // Subscribe to seal events
    const subscription = this.events.on(AethelredEventType.SEAL_CREATED, async (event) => {
      try {
        const seal = await this.getSeal(event.sealId);
        if (seal) {
          // Apply filters
          if (options.status && seal.status !== options.status) return;
          if (options.modelHash && seal.modelCommitment !== options.modelHash) return;

          callback(seal);
        }
      } catch (error) {
        logger.error('Error in seal stream', error as Error);
      }
    });

    return () => subscription.unsubscribe();
  }

  // ============ Verification ============

  /**
   * Comprehensive seal verification
   */
  async verifySeal(
    sealId: string,
    depth: VerificationDepth = 'standard'
  ): Promise<SealVerificationResult> {
    logger.debug(`Verifying seal: ${sealId}`, { depth });

    const seal = await this.getSeal(sealId, { skipCache: true });
    if (!seal) {
      throw Errors.sealNotFound(sealId);
    }

    const result: SealVerificationResult = {
      sealId,
      valid: true,
      integrityValid: false,
      signaturesValid: false,
      onChainValid: false,
      notRevoked: seal.status !== 'revoked',
      details: {
        verifiedAt: new Date().toISOString(),
        verificationDepth: depth,
        blockHeight: seal.blockHeight,
      },
    };

    // Quick verification
    result.integrityValid = await this.verifyIntegrity(seal);
    if (!result.integrityValid) {
      result.valid = false;
      if (depth === 'quick') return result;
    }

    // Standard verification
    result.signaturesValid = await this.verifySignatures(seal);
    result.onChainValid = await this.verifyOnChain(seal);

    result.valid = result.integrityValid && result.signaturesValid &&
                   result.onChainValid && result.notRevoked;

    if (depth === 'standard') return result;

    // Comprehensive verification
    if (depth === 'comprehensive') {
      result.details!.teeVerification = await this.verifyTEEAttestations(seal);
      result.details!.zkmlVerification = await this.verifyZKMLProofs(seal);
      result.details!.consensusVerification = await this.verifyConsensus(seal);
    }

    return result;
  }

  /**
   * Verify seal integrity (hash validation)
   */
  private async verifyIntegrity(seal: DigitalSeal): Promise<boolean> {
    try {
      // Verify commitment hashes match
      const response = await this.httpClient.post<{ valid: boolean }>(
        `/aethelred/seal/v1/verify/${seal.id}/integrity`
      );
      return response.data.valid;
    } catch {
      return false;
    }
  }

  /**
   * Verify validator signatures
   */
  private async verifySignatures(seal: DigitalSeal): Promise<boolean> {
    if (!seal.validators || seal.validators.length === 0) {
      return false;
    }

    try {
      const response = await this.httpClient.post<{ valid: boolean }>(
        `/aethelred/seal/v1/verify/${seal.id}/signatures`
      );
      return response.data.valid;
    } catch {
      return false;
    }
  }

  /**
   * Verify seal exists on-chain
   */
  private async verifyOnChain(seal: DigitalSeal): Promise<boolean> {
    try {
      const response = await this.httpClient.get<{ exists: boolean }>(
        `/aethelred/seal/v1/verify/${seal.id}/onchain`
      );
      return response.data.exists;
    } catch {
      return false;
    }
  }

  /**
   * Verify TEE attestations
   */
  private async verifyTEEAttestations(
    seal: DigitalSeal
  ): Promise<{ valid: boolean; verified: number; total: number }> {
    if (!seal.teeAttestations || seal.teeAttestations.length === 0) {
      return { valid: true, verified: 0, total: 0 };
    }

    let verified = 0;
    for (const attestation of seal.teeAttestations) {
      const valid = await this.verifyTEEAttestation(attestation);
      if (valid) verified++;
    }

    return {
      valid: verified >= Math.ceil(seal.teeAttestations.length * 2 / 3),
      verified,
      total: seal.teeAttestations.length,
    };
  }

  /**
   * Verify individual TEE attestation
   */
  async verifyTEEAttestation(attestation: TEEAttestation): Promise<boolean> {
    try {
      const response = await this.httpClient.post<{ valid: boolean }>(
        '/aethelred/verify/v1/tee/attestation',
        attestation
      );
      return response.data.valid;
    } catch {
      return false;
    }
  }

  /**
   * Verify zkML proofs
   */
  private async verifyZKMLProofs(
    seal: DigitalSeal
  ): Promise<{ valid: boolean; verified: number; total: number }> {
    if (!seal.zkmlProof) {
      return { valid: true, verified: 0, total: 0 };
    }

    const valid = await this.verifyZKMLProof(seal.zkmlProof);
    return {
      valid,
      verified: valid ? 1 : 0,
      total: 1,
    };
  }

  /**
   * Verify individual zkML proof
   */
  async verifyZKMLProof(proof: ZKMLProof): Promise<boolean> {
    try {
      const response = await this.httpClient.post<{ valid: boolean }>(
        '/aethelred/verify/v1/zkml/proof',
        proof
      );
      return response.data.valid;
    } catch {
      return false;
    }
  }

  /**
   * Verify consensus was reached
   */
  private async verifyConsensus(seal: DigitalSeal): Promise<{ valid: boolean; agreement: number }> {
    try {
      const response = await this.httpClient.get<{ valid: boolean; agreement: number }>(
        `/aethelred/seal/v1/verify/${seal.id}/consensus`
      );
      return response.data;
    } catch {
      return { valid: false, agreement: 0 };
    }
  }

  /**
   * Quick verify - simple boolean check
   */
  async quickVerify(sealId: string): Promise<boolean> {
    const result = await this.verifySeal(sealId, 'quick');
    return result.valid;
  }

  /**
   * Verify output matches seal
   */
  async verifyOutput(sealId: string, outputHash: string): Promise<boolean> {
    const seal = await this.getSeal(sealId);
    if (!seal) return false;

    return seal.outputCommitment.toLowerCase() === outputHash.toLowerCase();
  }

  /**
   * Batch verify multiple seals
   */
  async batchVerify(
    sealIds: string[],
    depth: VerificationDepth = 'quick'
  ): Promise<BatchResult<SealVerificationResult>> {
    const startTime = Date.now();
    const successful: SealVerificationResult[] = [];
    const failed: { id: string; error: Error }[] = [];

    await Promise.all(
      sealIds.map(async (sealId) => {
        try {
          const result = await this.verifySeal(sealId, depth);
          successful.push(result);
        } catch (error) {
          failed.push({ id: sealId, error: error as Error });
        }
      })
    );

    return {
      successful,
      failed,
      totalTime: Date.now() - startTime,
    };
  }

  // ============ Creation ============

  /**
   * Create a new seal
   */
  async createSeal(request: CreateSealRequest): Promise<CreateSealResponse> {
    if (!this.signingClient) {
      throw Errors.noSigner();
    }

    logger.info('Creating seal', {
      modelHash: request.modelHash.slice(0, 16) + '...',
      purpose: request.purpose,
    });

    const msg = {
      typeUrl: '/aethelred.seal.v1.MsgCreateSeal',
      value: {
        modelHash: request.modelHash,
        inputHash: request.inputHash,
        outputHash: request.outputHash,
        purpose: request.purpose,
        metadata: request.metadata,
      },
    };

    const signerAddress = await this.getSignerAddress();

    const result = await this.signingClient.signAndBroadcast(
      signerAddress,
      [msg],
      'auto',
      request.purpose || 'Create digital seal'
    );

    const sealId = this.extractSealIdFromEvents(result);

    // Emit event
    if (sealId) {
      this.events.emitSync(AethelredEventType.SEAL_CREATED, {
        sealId,
        modelHash: request.modelHash,
        blockHeight: result.height,
      });
    }

    return {
      sealId: sealId || '',
      status: 'pending',
      txHash: result.transactionHash,
    };
  }

  /**
   * Create multiple seals in batch
   */
  async batchCreateSeals(
    requests: CreateSealRequest[]
  ): Promise<BatchResult<CreateSealResponse>> {
    const startTime = Date.now();
    const successful: CreateSealResponse[] = [];
    const failed: { id: string; error: Error }[] = [];

    // Process sequentially to avoid nonce issues
    for (let i = 0; i < requests.length; i++) {
      try {
        const result = await this.createSeal(requests[i]);
        successful.push(result);
      } catch (error) {
        failed.push({ id: `request-${i}`, error: error as Error });
      }
    }

    return {
      successful,
      failed,
      totalTime: Date.now() - startTime,
    };
  }

  // ============ Audit & Compliance ============

  /**
   * Generate comprehensive audit report
   */
  async generateAuditReport(request: AuditReportRequest): Promise<AuditReport> {
    const response = await this.httpClient.post<AuditReport>(
      '/aethelred/seal/v1/audit',
      request
    );
    return response.data;
  }

  /**
   * Export seal for external verification
   */
  async exportSeal(
    sealId: string,
    format: 'json' | 'cbor' | 'protobuf' = 'json'
  ): Promise<Buffer> {
    const response = await this.httpClient.get(
      `/aethelred/seal/v1/export/${sealId}`,
      {
        params: { format },
        responseType: 'arraybuffer',
      }
    );
    return Buffer.from(response.data);
  }

  /**
   * Get compliance status for a seal
   */
  async getComplianceStatus(sealId: string): Promise<ComplianceStatus> {
    const response = await this.httpClient.get<ComplianceStatus>(
      `/aethelred/seal/v1/compliance/${sealId}`
    );
    return response.data;
  }

  /**
   * Compare two seals
   */
  async compareSeals(sealId1: string, sealId2: string): Promise<SealComparisonResult> {
    const [seal1, seal2] = await Promise.all([
      this.getSeal(sealId1),
      this.getSeal(sealId2),
    ]);

    if (!seal1) throw Errors.sealNotFound(sealId1);
    if (!seal2) throw Errors.sealNotFound(sealId2);

    const differences: { field: string; value1: any; value2: any }[] = [];
    const compareFields = [
      'modelCommitment',
      'inputCommitment',
      'outputCommitment',
      'purpose',
      'status',
    ];

    for (const field of compareFields) {
      const v1 = (seal1 as any)[field];
      const v2 = (seal2 as any)[field];
      if (v1 !== v2) {
        differences.push({ field, value1: v1, value2: v2 });
      }
    }

    return {
      seal1,
      seal2,
      match: differences.length === 0,
      differences,
    };
  }

  // ============ Revocation ============

  /**
   * Revoke a seal
   */
  async revokeSeal(request: RevocationRequest): Promise<RevocationResult> {
    if (!this.signingClient) {
      throw Errors.noSigner();
    }

    const msg = {
      typeUrl: '/aethelred.seal.v1.MsgRevokeSeal',
      value: {
        sealId: request.sealId,
        reason: request.reason,
        evidence: request.evidence,
      },
    };

    const signerAddress = await this.getSignerAddress();

    const result = await this.signingClient.signAndBroadcast(
      signerAddress,
      [msg],
      'auto',
      `Revoke seal: ${request.reason}`
    );

    // Invalidate cache
    this.cache.delete(`seal:${request.sealId}`);

    // Emit event
    this.events.emitSync(AethelredEventType.SEAL_REVOKED, {
      sealId: request.sealId,
      reason: request.reason,
    });

    return {
      success: result.code === 0,
      sealId: request.sealId,
      txHash: result.transactionHash,
      revokedAt: new Date().toISOString(),
    };
  }

  // ============ Statistics ============

  /**
   * Get seal statistics
   */
  async getStats(): Promise<SealStats> {
    const cacheKey = 'seal:stats';
    const cached = this.cache.get<SealStats>(cacheKey);
    if (cached) return cached;

    const response = await this.httpClient.get<SealStats>(
      '/aethelred/seal/v1/stats'
    );

    this.cache.set(cacheKey, response.data, { ttlMs: 30000 });
    return response.data;
  }

  /**
   * Get seal count by criteria
   */
  async getCount(query?: SealQuery): Promise<number> {
    const response = await this.listSeals({ ...query, limit: 0 });
    return response.total;
  }

  // ============ Waiting & Watching ============

  /**
   * Wait for seal to reach status
   */
  async waitForStatus(
    sealId: string,
    targetStatus: SealStatus,
    timeoutMs: number = 60000
  ): Promise<DigitalSeal> {
    const startTime = Date.now();
    const pollInterval = 1000;

    while (Date.now() - startTime < timeoutMs) {
      const seal = await this.getSeal(sealId, { skipCache: true });

      if (!seal) {
        throw Errors.sealNotFound(sealId);
      }

      if (seal.status === targetStatus) {
        return seal;
      }

      if (seal.status === 'revoked' || seal.status === 'expired') {
        throw new SealError(
          AethelredErrorCode.SEAL_VERIFICATION_FAILED,
          `Seal ${sealId} reached terminal status: ${seal.status}`,
          sealId
        );
      }

      await new Promise((resolve) => setTimeout(resolve, pollInterval));
    }

    throw new SealError(
      AethelredErrorCode.SEAL_VERIFICATION_FAILED,
      `Timeout waiting for seal ${sealId} to reach status ${targetStatus}`,
      sealId,
      { retry: { retryable: true, retryAfterMs: 5000, maxRetries: 3 } }
    );
  }

  /**
   * Watch a seal for changes
   */
  watchSeal(
    sealId: string,
    callback: (seal: DigitalSeal, change: SealChange) => void,
    interval: number = 5000
  ): () => void {
    let previousSeal: DigitalSeal | null = null;
    let stopped = false;

    const poll = async () => {
      if (stopped) return;

      try {
        const seal = await this.getSeal(sealId, { skipCache: true });
        if (seal) {
          const change = this.detectChange(previousSeal, seal);
          if (change) {
            callback(seal, change);
          }
          previousSeal = seal;
        }
      } catch (error) {
        logger.error(`Error watching seal ${sealId}`, error as Error);
      }

      if (!stopped) {
        setTimeout(poll, interval);
      }
    };

    poll();

    return () => {
      stopped = true;
    };
  }

  // ============ Private Helpers ============

  private buildQueryParams(query?: SealQuery): URLSearchParams {
    const params = new URLSearchParams();

    if (query?.requester) params.append('requester', query.requester);
    if (query?.status) params.append('status', query.status);
    if (query?.modelHash) params.append('model_hash', query.modelHash);
    if (query?.purpose) params.append('purpose', query.purpose);
    if (query?.minBlockHeight) params.append('min_height', query.minBlockHeight.toString());
    if (query?.maxBlockHeight) params.append('max_height', query.maxBlockHeight.toString());
    if (query?.limit) params.append('limit', query.limit.toString());
    if (query?.offset) params.append('offset', query.offset.toString());

    return params;
  }

  private async getSignerAddress(): Promise<string> {
    if (!this.signingClient) {
      throw Errors.noSigner();
    }
    // This would be provided by the parent client
    return '';
  }

  private extractSealIdFromEvents(result: any): string | null {
    for (const event of result.events || []) {
      if (event.type === 'create_seal') {
        for (const attr of event.attributes) {
          if (attr.key === 'seal_id') {
            return attr.value;
          }
        }
      }
    }
    return null;
  }

  private detectChange(previous: DigitalSeal | null, current: DigitalSeal): SealChange | null {
    if (!previous) {
      return { type: 'created', timestamp: new Date() };
    }

    if (previous.status !== current.status) {
      return {
        type: 'status_changed',
        timestamp: new Date(),
        previousStatus: previous.status,
        newStatus: current.status,
      };
    }

    return null;
  }
}

// Additional types

export interface SealStats {
  totalSeals: number;
  activeSeals: number;
  revokedSeals: number;
  expiredSeals: number;
  sealsByPurpose: Record<string, number>;
  sealsByModel: Record<string, number>;
  averageVerificationsPerSeal: number;
  sealsByDay: { date: string; count: number }[];
}

export interface ComplianceStatus {
  sealId: string;
  frameworks: {
    name: string;
    compliant: boolean;
    lastChecked: string;
    issues?: string[];
  }[];
  overallCompliant: boolean;
}

export interface SealChange {
  type: 'created' | 'status_changed' | 'verified' | 'revoked';
  timestamp: Date;
  previousStatus?: SealStatus;
  newStatus?: SealStatus;
}

// Export as SealModule for compatibility
export { EnhancedSealModule as SealModule };
