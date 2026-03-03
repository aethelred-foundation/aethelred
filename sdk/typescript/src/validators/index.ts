/**
 * Validators module for Aethelred SDK.
 */

import type { AethelredClient } from '../core/client';
import { ValidatorStats, HardwareCapability, PageRequest } from '../core/types';

export class ValidatorsModule {
  private readonly basePath = '/aethelred/pouw/v1';

  constructor(private readonly client: AethelredClient) {}

  async getStats(address: string): Promise<ValidatorStats> {
    return this.client.get(`${this.basePath}/validators/${address}/stats`);
  }

  async list(pagination?: PageRequest): Promise<ValidatorStats[]> {
    const params = pagination ? { ...pagination } : undefined;
    const data = await this.client.get<{ validators: ValidatorStats[] }>(`${this.basePath}/validators`, params);
    return data.validators || [];
  }

  async registerCapability(address: string, capability: HardwareCapability): Promise<boolean> {
    await this.client.post(`${this.basePath}/validators/${address}/capability`, { hardware_capabilities: capability });
    return true;
  }
}
