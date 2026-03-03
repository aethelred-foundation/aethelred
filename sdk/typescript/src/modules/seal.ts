/**
 * Seal Module - Digital Seal operations
 */

import { AxiosInstance } from 'axios';
import { SigningStargateClient } from '@cosmjs/stargate';
import { AethelredConfig } from '../client/config';
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
      const response = await this.httpClient.get<DigitalSeal>(
        `/aethelred/seal/v1/seal/${sealId}`
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
   * List seals with optional filters
   */
  async listSeals(query?: SealQuery): Promise<SealListResponse> {
    const params = new URLSearchParams();

    if (query?.requester) params.append('requester', query.requester);
    if (query?.status) params.append('status', query.status);
    if (query?.modelHash) params.append('model_hash', query.modelHash);
    if (query?.purpose) params.append('purpose', query.purpose);
    if (query?.minBlockHeight) params.append('min_height', query.minBlockHeight.toString());
    if (query?.maxBlockHeight) params.append('max_height', query.maxBlockHeight.toString());
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
    const response = await this.httpClient.get<SealVerificationResult>(
      `/aethelred/seal/v1/verify/${sealId}`
    );
    return response.data;
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
    const response = await this.httpClient.post<AuditReport>(
      '/aethelred/seal/v1/audit',
      request
    );
    return response.data;
  }

  /**
   * Export seal for external verification
   */
  async exportSeal(sealId: string, format: 'json' | 'cbor' = 'json'): Promise<string> {
    const response = await this.httpClient.get<string>(
      `/aethelred/seal/v1/export/${sealId}?format=${format}`
    );
    return response.data;
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
