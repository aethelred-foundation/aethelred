/**
 * Main client for Aethelred SDK.
 */

import axios, { AxiosInstance } from 'axios';
import { Config, resolveConfig, NetworkConfig } from './config';
import { AethelredError, ConnectionError, RateLimitError, TimeoutError } from './errors';
import { NodeInfo, Block } from './types';
import { JobsModule } from '../jobs';
import { SealsModule } from '../seals';
import { ModelsModule } from '../models';
import { ValidatorsModule } from '../validators';
import { VerificationModule } from '../verification';

export class AethelredClient {
  private readonly config: ReturnType<typeof resolveConfig>;
  private readonly http: AxiosInstance;
  
  // Modules
  public readonly jobs: JobsModule;
  public readonly seals: SealsModule;
  public readonly models: ModelsModule;
  public readonly validators: ValidatorsModule;
  public readonly verification: VerificationModule;

  constructor(config: Config | string = {}) {
    // Handle string URL input
    if (typeof config === 'string') {
      config = { rpcUrl: config };
    }
    
    this.config = resolveConfig(config);
    
    // Create HTTP client
    this.http = axios.create({
      baseURL: this.config.rpcUrl,
      timeout: this.config.timeout.read,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'aethelred-sdk-js/1.0.0',
        ...(this.config.apiKey && { 'X-API-Key': this.config.apiKey }),
      },
    });

    // Add retry interceptor
    this.setupInterceptors();

    // Initialize modules
    this.jobs = new JobsModule(this);
    this.seals = new SealsModule(this);
    this.models = new ModelsModule(this);
    this.validators = new ValidatorsModule(this);
    this.verification = new VerificationModule(this);
  }

  private setupInterceptors(): void {
    this.http.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (error.response?.status === 429) {
          const retryAfter = error.response.headers['retry-after'];
          throw new RateLimitError('Rate limit exceeded', retryAfter ? parseInt(retryAfter) : undefined);
        }
        if (error.code === 'ECONNABORTED') {
          throw new TimeoutError('Request timed out');
        }
        if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
          throw new ConnectionError('Failed to connect to node', error);
        }
        throw new AethelredError(
          error.response?.data?.message || error.message,
          error.response?.status || 1000,
          error.response?.data || {}
        );
      }
    );
  }

  // HTTP methods
  async get<T = unknown>(path: string, params?: Record<string, unknown>): Promise<T> {
    const response = await this.http.get<T>(path, { params });
    return response.data;
  }

  async post<T = unknown>(path: string, data?: unknown): Promise<T> {
    const response = await this.http.post<T>(path, data);
    return response.data;
  }

  async put<T = unknown>(path: string, data?: unknown): Promise<T> {
    const response = await this.http.put<T>(path, data);
    return response.data;
  }

  async delete<T = unknown>(path: string, params?: Record<string, unknown>): Promise<T> {
    const response = await this.http.delete<T>(path, { params });
    return response.data;
  }

  // Utility methods
  async getNodeInfo(): Promise<NodeInfo> {
    const data = await this.get<{ default_node_info: NodeInfo }>('/cosmos/base/tendermint/v1beta1/node_info');
    return data.default_node_info;
  }

  async getLatestBlock(): Promise<Block> {
    return this.get<Block>('/cosmos/base/tendermint/v1beta1/blocks/latest');
  }

  async getBlock(height: number): Promise<Block> {
    return this.get<Block>(`/cosmos/base/tendermint/v1beta1/blocks/${height}`);
  }

  async healthCheck(): Promise<boolean> {
    try {
      await this.getNodeInfo();
      return true;
    } catch {
      return false;
    }
  }

  getNetworkConfig(): NetworkConfig {
    return this.config.networkConfig;
  }

  getRpcUrl(): string {
    return this.config.rpcUrl!;
  }

  getChainId(): string {
    return this.config.chainId!;
  }
}
