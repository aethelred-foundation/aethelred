/**
 * Seal Module - Digital Seal operations
 */

import { AxiosInstance } from 'axios';
import { SigningStargateClient } from '@cosmjs/stargate';
import { AethelredConfig } from '../client/config';
import {
  DigitalSeal,
  EvidenceBundle,
  SealStatus,
  CreateSealRequest,
  CreateSealResponse,
  SealQuery,
  SealListResponse,
  SealVerificationResult,
  AuditReport,
  AuditReportRequest,
  ExportedSeal,
  ExportFormat,
  RevocationRequest,
  RevocationResult,
} from '../types/seal';
import { TransactionResult } from '../types';

export class SealModule {
  private httpClient: AxiosInstance;
  private signingClient: SigningStargateClient | null;
  private config: AethelredConfig;

  constructor(
    httpClient: AxiosInstance,
    signingClient: SigningStargateClient | null,
    config: AethelredConfig
  ) {
    this.httpClient = httpClient;
    this.signingClient = signingClient;
    this.config = config;
  }

  /**
   * Get a seal by ID
   */
  async getSeal(sealId: string): Promise<DigitalSeal | null> {
    try {
      const response = await this.httpClient.get<{ seal: DigitalSeal }>(
        `/aethelred/seal/v1/seals/${sealId}`
      );
      return response.data.seal;
    } catch (error: any) {
      if (error.response?.status === 404) {
        return null;
      }
      throw error;
    }
  }

  /**
   * List seals with optional filters
   */
  async listSeals(query?: SealQuery): Promise<SealListResponse> {
    this.assertSupportedListQuery(query);

    if (query?.modelHash && query?.requester) {
      throw new Error('modelHash and requester filters must be queried separately');
    }

    if (query?.modelHash) {
      const params = new URLSearchParams();
      params.append('model_hash', this.hexHashToBase64(query.modelHash));
      const response = await this.httpClient.get<{ seals: DigitalSeal[] }>(
        `/aethelred/seal/v1/seals/by_model?${params.toString()}`
      );
      return {
        seals: response.data.seals,
        total: response.data.seals.length,
        hasMore: false,
      };
    }

    if (query?.requester) {
      const params = new URLSearchParams();
      params.append('requester', query.requester);
      const response = await this.httpClient.get<{ seals: DigitalSeal[] }>(
        `/aethelred/seal/v1/seals/by_requester?${params.toString()}`
      );
      return {
        seals: response.data.seals,
        total: response.data.seals.length,
        hasMore: false,
      };
    }

    const params = new URLSearchParams();

    if (query?.limit) params.append('limit', query.limit.toString());
    if (query?.offset) params.append('offset', query.offset.toString());

    const response = await this.httpClient.get<SealListResponse>(
      `/aethelred/seal/v1/seals?${params.toString()}`
    );
    return response.data;
  }

  /**
   * Get seals by model hash
   */
  async getSealsByModel(modelHash: string, limit?: number): Promise<DigitalSeal[]> {
    const response = await this.listSeals({ modelHash, limit });
    return response.seals;
  }

  /**
   * Get seals by requester address
   */
  async getSealsByRequester(address: string, limit?: number): Promise<DigitalSeal[]> {
    const response = await this.listSeals({ requester: address, limit });
    return response.seals;
  }

  /**
   * Create a new seal (requires signer)
   */
  async createSeal(request: CreateSealRequest): Promise<CreateSealResponse> {
    if (!this.signingClient) {
      throw new Error('Signing client required for creating seals');
    }

    // Build and sign the transaction
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
    if (!signerAddress) {
      throw new Error('No signer address available');
    }

    const result = await this.signingClient.signAndBroadcast(
      signerAddress,
      [msg],
      'auto',
      request.purpose || 'Create digital seal'
    );

    // Extract seal ID from events
    const sealId = this.extractSealIdFromEvents(result);

    return {
      sealId: sealId || '',
      status: 'pending',
      txHash: result.transactionHash,
    };
  }

  /**
   * Verify a seal's integrity
   */
  async verifySeal(sealId: string): Promise<SealVerificationResult> {
    const response = await this.httpClient.get<
      SealVerificationResult & { seal_id?: string; verification_type?: SealVerificationResult['verificationType'] }
    >(
      `/aethelred/seal/v1/seals/${sealId}/verify`
    );
    return {
      ...response.data,
      sealId: response.data.sealId ?? response.data.seal_id ?? sealId,
      verificationType: response.data.verificationType ?? response.data.verification_type,
    };
  }

  /**
   * Quick verify - checks seal exists and is valid
   */
  async quickVerify(sealId: string): Promise<boolean> {
    try {
      const result = await this.verifySeal(sealId);
      return result.valid;
    } catch {
      return false;
    }
  }

  /**
   * Verify output hash matches a seal
   */
  async verifyOutputHash(sealId: string, outputHash: string): Promise<boolean> {
    const seal = await this.getSeal(sealId);
    if (!seal) {
      return false;
    }
    return seal.outputCommitment.toLowerCase() === outputHash.toLowerCase();
  }

  /**
   * Generate audit report for a seal
   */
  async generateAuditReport(request: AuditReportRequest): Promise<AuditReport> {
    return this.exportSeal(request.sealId, 'audit');
  }

  /**
   * Export seal for external verification
   */
  async exportSeal(sealId: string, format: ExportFormat = 'json'): Promise<ExportedSeal> {
    const response = await this.httpClient.get<{ export: ExportedSeal }>(
      `/aethelred/seal/v1/seals/${sealId}/export?format=${format}`
    );
    return response.data.export;
  }

  /**
   * Export a canonical enterprise evidence bundle by job ID
   */
  async exportEvidenceBundle(jobId: string): Promise<EvidenceBundle> {
    const response = await this.httpClient.get<{ evidenceBundle?: EvidenceBundle; evidence_bundle?: EvidenceBundle }>(
      `/aethelred/seal/v1/evidence-bundles/${jobId}`
    );
    const bundle = response.data.evidenceBundle ?? response.data.evidence_bundle;
    assertEvidenceBundle(bundle);
    return bundle;
  }

  /**
   * Revoke a seal (requires authority)
   */
  async revokeSeal(request: RevocationRequest): Promise<RevocationResult> {
    if (!this.signingClient) {
      throw new Error('Signing client required for revoking seals');
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
    if (!signerAddress) {
      throw new Error('No signer address available');
    }

    const result = await this.signingClient.signAndBroadcast(
      signerAddress,
      [msg],
      'auto',
      `Revoke seal: ${request.reason}`
    );

    return {
      success: result.code === 0,
      sealId: request.sealId,
      txHash: result.transactionHash,
      revokedAt: new Date().toISOString(),
    };
  }

  /**
   * Get seal statistics
   */
  async getStats(): Promise<SealStats> {
    const response = await this.httpClient.get<SealStats>(
      '/aethelred/seal/v1/stats'
    );
    return response.data;
  }

  /**
   * Subscribe to seal events (WebSocket)
   */
  subscribeSealEvents(
    callback: (event: SealEvent) => void,
    filter?: { sealId?: string; requester?: string }
  ): () => void {
    // WebSocket subscription implementation
    const wsUrl = this.config.rpcUrl.replace('http', 'ws') + '/websocket';
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      const query = filter?.sealId
        ? `seal.id='${filter.sealId}'`
        : filter?.requester
        ? `seal.requester='${filter.requester}'`
        : "tm.event='Tx' AND seal.action EXISTS";

      ws.send(
        JSON.stringify({
          jsonrpc: '2.0',
          method: 'subscribe',
          id: '1',
          params: { query },
        })
      );
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.result?.events) {
          callback(this.parseSealEvent(data.result.events));
        }
      } catch {
        // Ignore parse errors
      }
    };

    // Return unsubscribe function
    return () => {
      ws.close();
    };
  }

  /**
   * Wait for seal to reach a specific status
   */
  async waitForStatus(
    sealId: string,
    targetStatus: SealStatus,
    timeoutMs: number = 30000
  ): Promise<DigitalSeal> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeoutMs) {
      const seal = await this.getSeal(sealId);
      if (seal && seal.status === targetStatus) {
        return seal;
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    throw new Error(`Timeout waiting for seal ${sealId} to reach status ${targetStatus}`);
  }

  // Private helpers

  private async getSignerAddress(): Promise<string | null> {
    if (!this.signingClient) return null;
    // Access the signer through the signing client
    return null; // Will be set from parent client
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

  private parseSealEvent(events: any): SealEvent {
    // Parse raw events into SealEvent
    return {
      type: 'created',
      sealId: '',
      timestamp: new Date().toISOString(),
    };
  }

  private assertSupportedListQuery(query?: SealQuery): void {
    const unsupported: string[] = [];
    if (query?.status) unsupported.push('status');
    if (query?.purpose) unsupported.push('purpose');
    if (query?.minBlockHeight !== undefined) unsupported.push('minBlockHeight');
    if (query?.maxBlockHeight !== undefined) unsupported.push('maxBlockHeight');
    if (unsupported.length > 0) {
      throw new Error(`Unsupported seal query filters: ${unsupported.join(', ')}`);
    }
  }

  private hexHashToBase64(hash: string): string {
    const normalized = hash.startsWith('0x') ? hash.slice(2) : hash;
    if (!/^[0-9a-fA-F]+$/.test(normalized) || normalized.length % 2 !== 0) {
      throw new Error('modelHash must be a hex-encoded SHA-256 hash');
    }
    return Buffer.from(normalized, 'hex').toString('base64');
  }
}

function assertEvidenceBundle(bundle: unknown): asserts bundle is EvidenceBundle {
  if (!bundle || typeof bundle !== 'object') {
    throw new Error('evidence bundle response missing evidence_bundle');
  }
  const value = bundle as Record<string, unknown>;
  const stringFields = [
    'bundle_id',
    'job_id',
    'chain_id',
    'seal_id',
    'timestamp',
    'model_hash',
    'circuit_hash',
    'verifying_key_hash',
    'validator_signature',
    'region',
    'operator',
  ];
  if (value.schema_version !== '1.0.0') {
    throw new Error('evidence bundle schema_version must be 1.0.0');
  }
  for (const field of stringFields) {
    requireNonEmptyString(value, field);
  }
  requireBase64(value.validator_signature, 'validator_signature');
  requireNumberRange(value.confidence_score, 'confidence_score', 0, 1);

  const tee = requireObject(value.tee_evidence, 'tee_evidence');
  for (const field of ['platform', 'enclave_id', 'measurement', 'quote', 'nonce']) {
    requireNonEmptyString(tee, `tee_evidence.${field}`);
  }
  requireBase64(tee.quote, 'tee_evidence.quote');

  const zkml = requireObject(value.zkml_evidence, 'zkml_evidence');
  for (const field of ['proof_system', 'proof_bytes', 'public_inputs', 'output_commitment']) {
    requireNonEmptyString(zkml, `zkml_evidence.${field}`);
  }
  requireBase64(zkml.proof_bytes, 'zkml_evidence.proof_bytes');
  requireBase64(zkml.public_inputs, 'zkml_evidence.public_inputs');

  const policy = requireObject(value.policy_decision, 'policy_decision');
  if (policy.mode !== 'hybrid' || policy.require_both !== true || policy.fallback_allowed !== false) {
    throw new Error('evidence bundle policy_decision must require hybrid/no fallback');
  }

  const archive = requireObject(value.archive_pointer, 'archive_pointer');
  for (const field of ['archive_type', 'index', 'document_id', 'uri', 'write_status']) {
    requireNonEmptyString(archive, `archive_pointer.${field}`);
  }
  requirePositiveNumber(archive.retention_days, 'archive_pointer.retention_days');

  const verification = requireObject(value.verification, 'verification');
  for (const field of [
    'schema_verified',
    'policy_verified',
    'tee_attestation_verified',
    'zkml_proof_verified',
    'digital_seal_verified',
    'live_verification_required',
  ]) {
    requireBoolean(verification, `verification.${field}`);
  }
  if (verification.schema_verified !== true || verification.policy_verified !== true) {
    throw new Error('evidence bundle verification must mark schema and policy as verified');
  }
  requireNonEmptyString(verification, 'verification.verifier_version');
}

function requireObject(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`evidence bundle missing required object: ${field}`);
  }
  return value as Record<string, unknown>;
}

function requireNonEmptyString(value: Record<string, unknown>, field: string): void {
  const key = field.includes('.') ? field.split('.').pop()! : field;
  const item = value[key];
  if (typeof item !== 'string' || item.trim() === '') {
    throw new Error(`evidence bundle missing required string: ${field}`);
  }
}

function requireBase64(value: unknown, field: string): void {
  if (typeof value !== 'string' || value.trim() === '' || !/^[A-Za-z0-9+/]+=*$/.test(value)) {
    throw new Error(`evidence bundle ${field} must be base64`);
  }
}

function requireNumberRange(value: unknown, field: string, min: number, max: number): void {
  if (typeof value !== 'number' || value < min || value > max) {
    throw new Error(`evidence bundle ${field} must be between ${min} and ${max}`);
  }
}

function requirePositiveNumber(value: unknown, field: string): void {
  if (typeof value !== 'number' || value < 1) {
    throw new Error(`evidence bundle ${field} must be positive`);
  }
}

function requireBoolean(value: Record<string, unknown>, field: string): void {
  const key = field.includes('.') ? field.split('.').pop()! : field;
  if (typeof value[key] !== 'boolean') {
    throw new Error(`evidence bundle missing required boolean: ${field}`);
  }
}

// Additional types for this module

export interface SealStats {
  totalSeals: number;
  activeSeals: number;
  revokedSeals: number;
  expiredSeals: number;
  sealsByPurpose: Record<string, number>;
  sealsByModel: Record<string, number>;
  averageVerificationsPerSeal: number;
}

export interface SealEvent {
  type: 'created' | 'verified' | 'revoked' | 'expired';
  sealId: string;
  timestamp: string;
  data?: Record<string, unknown>;
}
