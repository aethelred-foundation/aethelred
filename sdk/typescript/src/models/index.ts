/**
 * Models module for Aethelred SDK.
 */

import type { AethelredClient } from '../core/client';
import { RegisteredModel, UtilityCategory, PageRequest } from '../core/types';

export interface RegisterModelRequest {
  modelHash: string;
  name: string;
  architecture?: string;
  version?: string;
  category?: UtilityCategory;
  inputSchema?: string;
  outputSchema?: string;
  storageUri?: string;
  metadata?: Record<string, string>;
}

export interface RegisterModelResponse {
  modelHash: string;
  txHash: string;
}

export class ModelsModule {
  private readonly basePath = '/aethelred/pouw/v1';

  constructor(private readonly client: AethelredClient) {}

  async register(request: RegisterModelRequest): Promise<RegisterModelResponse> {
    return this.client.post(`${this.basePath}/models`, request);
  }

  async get(modelHash: string): Promise<RegisteredModel> {
    const data = await this.client.get<{ model: RegisteredModel }>(`${this.basePath}/models/${modelHash}`);
    return data.model;
  }

  async list(options?: { owner?: string; category?: UtilityCategory; pagination?: PageRequest }): Promise<RegisteredModel[]> {
    const data = await this.client.get<{ models: RegisteredModel[] }>(`${this.basePath}/models`, options);
    return data.models || [];
  }
}
