/**
 * Enhanced Aethelred Client
 *
 * Production-ready client with connection pooling, caching,
 * event handling, and advanced features.
 */

import { StargateClient, SigningStargateClient, DeliverTxResponse } from '@cosmjs/stargate';
import { DirectSecp256k1HdWallet, OfflineSigner } from '@cosmjs/proto-signing';
import { Tendermint37Client } from '@cosmjs/tendermint-rpc';
import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';

import {
  AethelredConfig,
  mergeConfig,
  fromNetwork,
  Networks,
  NetworkType,
} from './config';

import {
  AethelredError,
  AethelredErrorCode,
  ConnectionError,
  Errors,
  isAethelredError,
  wrapError,
} from '../core/errors';

import {
  Logger,
  getLogger,
  LogLevel,
  setLogLevel,
} from '../core/logger';

import {
  retry,
  RetryConfig,
  CircuitBreaker,
  CircuitState,
} from '../core/retry';

import {
  EventEmitter,
  AethelredEventType,
  EventSubscription,
  EventPayloads,
} from '../core/events';

import {
  Cache,
  CacheOptions,
  globalCache,
} from '../core/cache';

import {
  ConnectionPool,
  PooledConnection,
  ConnectionHealth,
} from '../core/pool';

import { SealModule } from '../modules/seal';
import { VerifyModule } from '../modules/verify';
import { ComputeModule } from '../modules/compute';
import { CreditScoringModule } from '../modules/credit-scoring';

/**
 * Enhanced client options
 */
export interface EnhancedClientOptions {
  /** Enable connection pooling */
  enablePooling?: boolean;
  /** Enable request caching */
  enableCaching?: boolean;
  /** Enable automatic retries */
  enableRetries?: boolean;
  /** Enable circuit breaker */
  enableCircuitBreaker?: boolean;
  /** Enable WebSocket subscriptions */
  enableWebSocket?: boolean;
  /** Log level */
  logLevel?: LogLevel;
  /** Custom retry configuration */
  retryConfig?: Partial<RetryConfig>;
  /** Cache TTL in milliseconds */
  cacheTTLMs?: number;
  /** Request timeout in milliseconds */
  requestTimeoutMs?: number;
  /** Connection pool size */
  poolSize?: number;
  /** Custom HTTP headers */
  headers?: Record<string, string>;
  /** Interceptors */
  interceptors?: {
    request?: (config: AxiosRequestConfig) => AxiosRequestConfig;
    response?: (response: any) => any;
    error?: (error: any) => any;
  };
}

/**
 * Default enhanced options
 */
const DEFAULT_ENHANCED_OPTIONS: EnhancedClientOptions = {
  enablePooling: false,
  enableCaching: true,
  enableRetries: true,
  enableCircuitBreaker: true,
  enableWebSocket: false,
  logLevel: LogLevel.INFO,
  cacheTTLMs: 30000,
  requestTimeoutMs: 30000,
  poolSize: 3,
};

/**
 * Connection status with detailed info
 */
export interface EnhancedConnectionStatus {
  connected: boolean;
  chainId?: string;
  blockHeight?: number;
  latencyMs?: number;
  nodeInfo?: {
    version: string;
    network: string;
    moniker?: string;
  };
  poolStatus?: {
    total: number;
    healthy: number;
    degraded: number;
  };
  cacheStats?: {
    hitRate: number;
    entries: number;
  };
}

/**
 * Account info with extended details
 */
export interface EnhancedAccountInfo {
  address: string;
  balance: string;
  balanceFormatted: string;
  sequence: number;
  accountNumber: number;
  pubkey?: string;
}

/**
 * Transaction options
 */
export interface TransactionOptions {
  /** Gas limit */
  gas?: number;
  /** Gas price */
  gasPrice?: string;
  /** Memo */
  memo?: string;
  /** Timeout height */
  timeoutHeight?: number;
  /** Skip simulation */
  skipSimulation?: boolean;
}

/**
 * Enhanced Aethelred Client
 */
export class EnhancedAethelredClient {
  private config: AethelredConfig;
  private options: EnhancedClientOptions;
  private logger: Logger;
  private events: EventEmitter;
  private cache: Cache;
  private circuitBreaker: CircuitBreaker;

  // Connection state
  private queryClient: StargateClient | null = null;
  private signingClient: SigningStargateClient | null = null;
  private tmClient: Tendermint37Client | null = null;
  private httpClient: AxiosInstance;
  private signer: OfflineSigner | null = null;
  private wsClient: WebSocket | null = null;

  // Connection pool (optional)
  private pool: ConnectionPool<StargateClient> | null = null;

  // Modules (lazy initialized)
  private _seal: SealModule | null = null;
  private _verify: VerifyModule | null = null;
  private _compute: ComputeModule | null = null;
  private _creditScoring: CreditScoringModule | null = null;

  // State
  private isConnected = false;
  private connectionAttempts = 0;
  private signerAddress: string | null = null;

  private constructor(
    config: AethelredConfig,
    options: EnhancedClientOptions = {}
  ) {
    this.config = config;
    this.options = { ...DEFAULT_ENHANCED_OPTIONS, ...options };
    this.logger = getLogger('client');
    this.events = new EventEmitter();
    this.cache = new Cache({
      defaultTTLMs: this.options.cacheTTLMs,
    });
    this.circuitBreaker = new CircuitBreaker('main', {
      failureThreshold: 5,
      resetTimeoutMs: 30000,
    });

    // Set log level
    if (this.options.logLevel !== undefined) {
      setLogLevel(this.options.logLevel);
    }

    // Create HTTP client with interceptors
    this.httpClient = this.createHttpClient();
  }

  // ============ Static Factory Methods ============

  /**
   * Connect to Aethelred network
   */
  static async connect(
    config: Partial<AethelredConfig>,
    options?: EnhancedClientOptions
  ): Promise<EnhancedAethelredClient> {
    const fullConfig = mergeConfig(config);
    const client = new EnhancedAethelredClient(fullConfig, options);
    await client.initialize();
    return client;
  }

  /**
   * Connect to a preset network
   */
  static async connectToNetwork(
    network: NetworkType,
    options?: EnhancedClientOptions
  ): Promise<EnhancedAethelredClient> {
    const config = fromNetwork(network);
    return EnhancedAethelredClient.connect(config, options);
  }

  /**
   * Connect with a signer
   */
  static async connectWithSigner(
    config: Partial<AethelredConfig>,
    signer: OfflineSigner,
    options?: EnhancedClientOptions
  ): Promise<EnhancedAethelredClient> {
    const fullConfig = mergeConfig(config);
    const client = new EnhancedAethelredClient(fullConfig, options);
    client.signer = signer;
    await client.initialize();
    return client;
  }

  /**
   * Connect with mnemonic
   */
  static async connectWithMnemonic(
    config: Partial<AethelredConfig>,
    mnemonic: string,
    options?: EnhancedClientOptions & { hdPath?: string; prefix?: string }
  ): Promise<EnhancedAethelredClient> {
    const wallet = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, {
      prefix: options?.prefix || 'aethelred',
      hdPaths: options?.hdPath ? [options.hdPath as any] : undefined,
    });
    return EnhancedAethelredClient.connectWithSigner(config, wallet, options);
  }

  /**
   * Create a read-only client (no signer)
   */
  static async createReadOnly(
    config: Partial<AethelredConfig>,
    options?: EnhancedClientOptions
  ): Promise<EnhancedAethelredClient> {
    return EnhancedAethelredClient.connect(config, options);
  }

  // ============ Initialization ============

  /**
   * Initialize the client
   */
  private async initialize(): Promise<void> {
    this.logger.info('Initializing Aethelred client', {
      rpcUrl: this.config.rpcUrl,
      chainId: this.config.chainId,
    });

    try {
      await this.logger.timeAsync('Client initialization', async () => {
        // Initialize connection pool if enabled
        if (this.options.enablePooling) {
          await this.initializePool();
        }

        // Connect to RPC
        await this.connectRpc();

        // Initialize signing client if signer available
        if (this.signer) {
          await this.initializeSigner();
        }

        // Initialize WebSocket if enabled
        if (this.options.enableWebSocket) {
          await this.initializeWebSocket();
        }
      });

      this.isConnected = true;
      this.connectionAttempts = 0;

      // Emit connected event
      const status = await this.getStatus();
      this.events.emit(AethelredEventType.CONNECTED, {
        chainId: status.chainId || '',
        blockHeight: status.blockHeight || 0,
      });

      this.logger.info('Aethelred client initialized successfully');
    } catch (error) {
      this.logger.error('Failed to initialize client', error as Error);
      throw new ConnectionError(
        AethelredErrorCode.CONNECTION_FAILED,
        `Failed to connect to ${this.config.rpcUrl}`,
        { cause: error as Error }
      );
    }
  }

  /**
   * Connect to RPC with retry
   */
  private async connectRpc(): Promise<void> {
    const connectFn = async () => {
      this.tmClient = await Tendermint37Client.connect(this.config.rpcUrl);
      this.queryClient = await StargateClient.create(this.tmClient);
    };

    if (this.options.enableRetries) {
      await retry(connectFn, {
        maxRetries: 3,
        baseDelayMs: 1000,
        strategy: 'exponential',
      });
    } else {
      await connectFn();
    }
  }

  /**
   * Initialize signer
   */
  private async initializeSigner(): Promise<void> {
    if (!this.signer) return;

    this.signingClient = await SigningStargateClient.connectWithSigner(
      this.config.rpcUrl,
      this.signer,
      {
        gasPrice: {
          amount: this.config.gasPrice?.replace(/[^0-9.]/g, '') || '0.025',
          denom: 'uaeth',
        },
      }
    );

    const accounts = await this.signer.getAccounts();
    this.signerAddress = accounts[0]?.address || null;

    this.logger.info('Signer initialized', { address: this.signerAddress });
  }

  /**
   * Initialize connection pool
   */
  private async initializePool(): Promise<void> {
    const endpoints = [
      this.config.rpcUrl,
      // Add backup endpoints if configured
    ];

    this.pool = new ConnectionPool<StargateClient>({
      endpoints,
      createConnection: async (endpoint) => {
        const tm = await Tendermint37Client.connect(endpoint);
        return StargateClient.create(tm);
      },
      healthCheck: async (client) => {
        try {
          await client.getHeight();
          return true;
        } catch {
          return false;
        }
      },
      strategy: 'latency-based',
      healthCheckIntervalMs: 30000,
      connectionTimeoutMs: 10000,
      maxRetries: 3,
      minHealthyConnections: 1,
      autoReconnect: true,
    });

    await this.pool.initialize();
  }

  /**
   * Initialize WebSocket
   */
  private async initializeWebSocket(): Promise<void> {
    const wsUrl = this.config.rpcUrl.replace(/^http/, 'ws') + '/websocket';

    return new Promise((resolve, reject) => {
      this.wsClient = new WebSocket(wsUrl);

      this.wsClient.onopen = () => {
        this.logger.info('WebSocket connected');
        this.subscribeToBlocks();
        resolve();
      };

      this.wsClient.onerror = (error) => {
        this.logger.error('WebSocket error', error as any);
        reject(error);
      };

      this.wsClient.onclose = () => {
        this.logger.info('WebSocket closed');
        // Attempt reconnection
        if (this.isConnected && this.options.enableWebSocket) {
          setTimeout(() => this.initializeWebSocket(), 5000);
        }
      };

      this.wsClient.onmessage = (event) => {
        this.handleWebSocketMessage(event.data);
      };
    });
  }

  /**
   * Subscribe to new blocks via WebSocket
   */
  private subscribeToBlocks(): void {
    if (!this.wsClient) return;

    this.wsClient.send(
      JSON.stringify({
        jsonrpc: '2.0',
        method: 'subscribe',
        id: 'blocks',
        params: { query: "tm.event='NewBlock'" },
      })
    );
  }

  /**
   * Handle WebSocket messages
   */
  private handleWebSocketMessage(data: string): void {
    try {
      const message = JSON.parse(data);

      if (message.result?.data?.value?.block) {
        const block = message.result.data.value.block;
        this.events.emit(AethelredEventType.NEW_BLOCK, {
          height: parseInt(block.header.height),
          hash: block.header.last_block_id?.hash || '',
          time: new Date(block.header.time),
          txCount: block.data.txs?.length || 0,
        });
      }
    } catch (error) {
      this.logger.trace('WebSocket message parse error', { error });
    }
  }

  /**
   * Create HTTP client with interceptors
   */
  private createHttpClient(): AxiosInstance {
    const client = axios.create({
      baseURL: this.config.restUrl || this.config.rpcUrl.replace(':26657', ':1317'),
      timeout: this.options.requestTimeoutMs,
      headers: {
        'Content-Type': 'application/json',
        ...this.options.headers,
      },
    });

    // Request interceptor
    client.interceptors.request.use(
      (config) => {
        this.logger.trace(`HTTP ${config.method?.toUpperCase()} ${config.url}`);

        if (this.options.interceptors?.request) {
          config = this.options.interceptors.request(config);
        }

        return config;
      },
      (error) => {
        this.logger.error('HTTP request error', error);
        return Promise.reject(error);
      }
    );

    // Response interceptor
    client.interceptors.response.use(
      (response) => {
        if (this.options.interceptors?.response) {
          return this.options.interceptors.response(response);
        }
        return response;
      },
      async (error) => {
        if (this.options.interceptors?.error) {
          return this.options.interceptors.error(error);
        }

        // Handle specific error codes
        if (error.response?.status === 429) {
          const retryAfter = parseInt(error.response.headers['retry-after'] || '60');
          throw Errors.rateLimited(retryAfter * 1000);
        }

        throw wrapError(error, 'HTTP request failed');
      }
    );

    return client;
  }

  // ============ Status & Info ============

  /**
   * Get enhanced connection status
   */
  async getStatus(): Promise<EnhancedConnectionStatus> {
    if (!this.queryClient) {
      return { connected: false };
    }

    try {
      const startTime = Date.now();
      const [chainId, height] = await Promise.all([
        this.queryClient.getChainId(),
        this.queryClient.getHeight(),
      ]);
      const latencyMs = Date.now() - startTime;

      const status: EnhancedConnectionStatus = {
        connected: true,
        chainId,
        blockHeight: height,
        latencyMs,
      };

      // Add pool status if available
      if (this.pool) {
        const poolStats = this.pool.getStats();
        status.poolStatus = {
          total: poolStats.totalConnections,
          healthy: poolStats.byHealth.healthy,
          degraded: poolStats.byHealth.degraded,
        };
      }

      // Add cache stats
      if (this.options.enableCaching) {
        const cacheStats = this.cache.getStats();
        status.cacheStats = {
          hitRate: cacheStats.hitRate,
          entries: cacheStats.entries,
        };
      }

      return status;
    } catch {
      return { connected: false };
    }
  }

  /**
   * Get account info with caching
   */
  async getAccount(address: string): Promise<EnhancedAccountInfo | null> {
    const cacheKey = `account:${address}`;

    if (this.options.enableCaching) {
      const cached = this.cache.get<EnhancedAccountInfo>(cacheKey);
      if (cached) return cached;
    }

    if (!this.queryClient) {
      throw Errors.connectionFailed(this.config.rpcUrl);
    }

    const account = await this.queryClient.getAccount(address);
    if (!account) return null;

    const balance = await this.queryClient.getBalance(address, 'uaeth');

    const info: EnhancedAccountInfo = {
      address: account.address,
      balance: balance.amount,
      balanceFormatted: this.formatBalance(balance.amount),
      sequence: account.sequence,
      accountNumber: account.accountNumber,
      pubkey: account.pubkey ? Buffer.from(account.pubkey.value).toString('base64') : undefined,
    };

    if (this.options.enableCaching) {
      this.cache.set(cacheKey, info, { ttlMs: 10000, tags: ['account'] });
    }

    return info;
  }

  /**
   * Get signer address
   */
  getSignerAddress(): string | null {
    return this.signerAddress;
  }

  /**
   * Check if client can sign
   */
  canSign(): boolean {
    return this.signingClient !== null;
  }

  /**
   * Check if client is connected
   */
  isClientConnected(): boolean {
    return this.isConnected && this.queryClient !== null;
  }

  // ============ Module Accessors ============

  get seal(): SealModule {
    if (!this._seal) {
      this._seal = new SealModule(this.httpClient, this.signingClient, this.config);
    }
    return this._seal;
  }

  get verify(): VerifyModule {
    if (!this._verify) {
      this._verify = new VerifyModule(this.httpClient, this.config);
    }
    return this._verify;
  }

  get compute(): ComputeModule {
    if (!this._compute) {
      this._compute = new ComputeModule(this.httpClient, this.signingClient, this.config);
    }
    return this._compute;
  }

  get creditScoring(): CreditScoringModule {
    if (!this._creditScoring) {
      this._creditScoring = new CreditScoringModule(this.httpClient, this.config);
    }
    return this._creditScoring;
  }

  // ============ Events ============

  /**
   * Subscribe to events
   */
  on<T extends AethelredEventType>(
    type: T,
    handler: (payload: EventPayloads[T]) => void | Promise<void>
  ): EventSubscription {
    return this.events.on(type, handler);
  }

  /**
   * Subscribe once
   */
  once<T extends AethelredEventType>(
    type: T,
    handler: (payload: EventPayloads[T]) => void | Promise<void>
  ): EventSubscription {
    return this.events.once(type, handler);
  }

  /**
   * Unsubscribe
   */
  off(subscription: EventSubscription): void {
    subscription.unsubscribe();
  }

  /**
   * Wait for event
   */
  waitFor<T extends AethelredEventType>(
    type: T,
    timeoutMs?: number
  ): Promise<EventPayloads[T]> {
    return this.events.waitFor(type, undefined, timeoutMs);
  }

  // ============ Transaction Helpers ============

  /**
   * Wait for transaction confirmation
   */
  async waitForTx(
    txHash: string,
    timeoutMs: number = 30000
  ): Promise<DeliverTxResponse | null> {
    if (!this.queryClient) {
      throw Errors.connectionFailed(this.config.rpcUrl);
    }

    const startTime = Date.now();

    while (Date.now() - startTime < timeoutMs) {
      try {
        const result = await this.queryClient.getTx(txHash);
        if (result) {
          this.events.emit(AethelredEventType.TX_CONFIRMED, {
            txHash,
            height: result.height,
            gasUsed: result.gasUsed,
          });
          return result as unknown as DeliverTxResponse;
        }
      } catch {
        // Not found yet
      }

      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    return null;
  }

  /**
   * Get block height
   */
  async getBlockHeight(): Promise<number> {
    if (!this.queryClient) {
      throw Errors.connectionFailed(this.config.rpcUrl);
    }
    return this.queryClient.getHeight();
  }

  /**
   * Get chain ID
   */
  async getChainId(): Promise<string> {
    if (!this.queryClient) {
      throw Errors.connectionFailed(this.config.rpcUrl);
    }
    return this.queryClient.getChainId();
  }

  // ============ Cache Control ============

  /**
   * Clear all caches
   */
  clearCache(): void {
    this.cache.clear();
    globalCache.clear();
    this.logger.debug('Cache cleared');
  }

  /**
   * Invalidate cache by tag
   */
  invalidateCache(tag: string): void {
    this.cache.invalidateByTag(tag);
  }

  /**
   * Get cache statistics
   */
  getCacheStats() {
    return this.cache.getStats();
  }

  // ============ Advanced Access ============

  /**
   * Get underlying query client
   */
  getQueryClient(): StargateClient | null {
    return this.queryClient;
  }

  /**
   * Get underlying signing client
   */
  getSigningClient(): SigningStargateClient | null {
    return this.signingClient;
  }

  /**
   * Get HTTP client
   */
  getHttpClient(): AxiosInstance {
    return this.httpClient;
  }

  /**
   * Get event emitter
   */
  getEventEmitter(): EventEmitter {
    return this.events;
  }

  /**
   * Get configuration
   */
  getConfig(): AethelredConfig {
    return { ...this.config };
  }

  /**
   * Execute raw REST query
   */
  async restQuery<T>(path: string, options?: CacheOptions): Promise<T> {
    const cacheKey = `rest:${path}`;

    if (this.options.enableCaching && options?.ttlMs !== 0) {
      const cached = this.cache.get<T>(cacheKey);
      if (cached) return cached;
    }

    const response = await this.httpClient.get<T>(path);

    if (this.options.enableCaching && options?.ttlMs !== 0) {
      this.cache.set(cacheKey, response.data, options);
    }

    return response.data;
  }

  // ============ Cleanup ============

  /**
   * Disconnect from network
   */
  disconnect(): void {
    this.logger.info('Disconnecting from network');

    // Close WebSocket
    if (this.wsClient) {
      this.wsClient.close();
      this.wsClient = null;
    }

    // Disconnect Tendermint client
    if (this.tmClient) {
      this.tmClient.disconnect();
      this.tmClient = null;
    }

    // Destroy pool
    if (this.pool) {
      this.pool.destroy();
      this.pool = null;
    }

    // Destroy cache
    this.cache.destroy();

    // Clear clients
    this.queryClient = null;
    this.signingClient = null;
    this.isConnected = false;

    // Emit disconnected event
    this.events.emit(AethelredEventType.DISCONNECTED, {
      reason: 'Manual disconnect',
    });

    this.logger.info('Disconnected from network');
  }

  // ============ Private Helpers ============

  /**
   * Format balance for display
   */
  private formatBalance(amount: string): string {
    const value = parseInt(amount) / 1_000_000;
    return `${value.toLocaleString()} AETH`;
  }
}

// Re-export as AethelredClient for backwards compatibility
export { EnhancedAethelredClient as AethelredClient };
