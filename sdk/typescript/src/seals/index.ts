/**
 * Seals module for Aethelred SDK.
 */

import type { AethelredClient } from '../core/client';
import { DigitalSeal, CreateSealRequest, CreateSealResponse, VerifySealResponse, SealStatus, PageRequest } from '../core/types';

export class SealsModule {
  private readonly basePath = '/aethelred/seal/v1';

  constructor(private readonly client: AethelredClient) {}

  async create(request: CreateSealRequest): Promise<CreateSealResponse> {
    return this.client.post(`${this.basePath}/seals`, request);
  }

  async get(sealId: string): Promise<DigitalSeal> {
    const data = await this.client.get<{ seal: DigitalSeal }>(`${this.basePath}/seals/${sealId}`);
    return data.seal;
  }

  async list(options?: { requester?: string; modelHash?: string; status?: SealStatus; pagination?: PageRequest }): Promise<DigitalSeal[]> {
    const data = await this.client.get<{ seals: DigitalSeal[] }>(`${this.basePath}/seals`, options);
    return data.seals || [];
  }

  async listByModel(modelHash: string, pagination?: PageRequest): Promise<DigitalSeal[]> {
    const data = await this.client.get<{ seals: DigitalSeal[] }>(`${this.basePath}/seals/by_model`, { model_hash: modelHash, ...pagination });
    return data.seals || [];
  }

  async verify(sealId: string): Promise<VerifySealResponse> {
    return this.client.get(`${this.basePath}/seals/${sealId}/verify`);
  }

  async revoke(sealId: string, reason: string): Promise<boolean> {
    await this.client.post(`${this.basePath}/seals/${sealId}/revoke`, { reason });
    return true;
  }

  async export(sealId: string, format: 'json' | 'cbor' | 'protobuf' = 'json'): Promise<string> {
    const data = await this.client.get<{ data: string }>(`${this.basePath}/seals/${sealId}/export`, { format });
    return data.data;
  }
}
