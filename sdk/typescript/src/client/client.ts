/**
 * Aethelred Client - Main SDK entry point
 */

import { StargateClient, SigningStargateClient, DeliverTxResponse } from '@cosmjs/stargate';
import { DirectSecp256k1HdWallet, OfflineSigner } from '@cosmjs/proto-signing';
import { Tendermint37Client } from '@cosmjs/tendermint-rpc';
import axios, { AxiosInstance } from 'axios';

import { AethelredConfig, mergeConfig, fromNetwork, Networks } from './config';
import { SealModule } from '../modules/seal';
import { VerifyModule } from '../modules/verify';
import { ComputeModule } from '../modules/compute';
import { CreditScoringModule } from '../modules/credit-scoring';

export interface ConnectionStatus {
  connected: boolean;
  chainId?: string;
  blockHeight?: number;
  nodeInfo?: {
    version: string;
    network: string;
  };
}

export interface AccountInfo {
  address: string;
  balance: string;
  sequence: number;
  accountNumber: number;
}

/**
 * Main Aethelred SDK Client
 *
 * @example
 * ```typescript
 * // Connect to testnet
 * const client = await AethelredClient.connect({
 *   rpcUrl: 'https://testnet-rpc.aethelred.io',
 *   chainId: 'aethelred-testnet-1',
 * });
 *
 * // Or use preset
 * const client = await AethelredClient.connectToNetwork('testnet');
 *
 * // Query a seal
 * const seal = await client.seal.getSeal('seal-id-123');
 * console.log('Seal status:', seal.status);
 * ```
 */
export class AethelredClient {
  private config: AethelredConfig;
  private queryClient: StargateClient | null = null;
  private signingClient: SigningStargateClient | null = null;
  private tmClient: Tendermint37Client | null = null;
  private httpClient: AxiosInstance;
  private signer: OfflineSigner | null = null;

  // Module instances
  private _seal: SealModule | null = null;
  private _verify: VerifyModule | null = null;
  private _compute: ComputeModule | null = null;
  private _creditScoring: CreditScoringModule | null = null;

  private constructor(config: AethelredConfig) {
    this.config = config;
    this.httpClient = axios.create({
      baseURL: config.restUrl || config.rpcUrl.replace(':26657', ':1317'),
      timeout: config.timeout,
    });
  }

  /**
   * Connect to Aethelred network
   */
  static async connect(config: Partial<AethelredConfig>): Promise<AethelredClient> {
    const fullConfig = mergeConfig(config);
    const client = new AethelredClient(fullConfig);
    await client.initialize();
    return client;
  }

  /**
   * Connect to a preset network
   */
  static async connectToNetwork(network: keyof typeof Networks): Promise<AethelredClient> {
    const config = fromNetwork(network);
    return AethelredClient.connect(config);
  }

  /**
   * Connect with a signer for transactions
   */
  static async connectWithSigner(
    config: Partial<AethelredConfig>,
    signer: OfflineSigner
  ): Promise<AethelredClient> {
    const fullConfig = mergeConfig(config);
    const client = new AethelredClient(fullConfig);
    client.signer = signer;
    await client.initialize();
    return client;
  }

  /**
   * Connect with a mnemonic
   */
  static async connectWithMnemonic(
    config: Partial<AethelredConfig>,
    mnemonic: string,
    prefix: string = 'aethelred'
  ): Promise<AethelredClient> {
    const wallet = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, { prefix });
    return AethelredClient.connectWithSigner(config, wallet);
  }

  /**
   * Initialize the client
   */
  private async initialize(): Promise<void> {
    try {
      // Connect Tendermint client
      this.tmClient = await Tendermint37Client.connect(this.config.rpcUrl);

      // Connect Stargate query client
      this.queryClient = await StargateClient.create(this.tmClient);

      // If signer is provided, create signing client
      if (this.signer) {
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
      }

      if (this.config.debug) {
        console.log('[Aethelred SDK] Connected to', this.config.rpcUrl);
      }
    } catch (error) {
      throw new Error(`Failed to connect to Aethelred network: ${error}`);
    }
  }

  /**
   * Get connection status
   */
  async getStatus(): Promise<ConnectionStatus> {
    if (!this.queryClient) {
      return { connected: false };
    }

    try {
      const chainId = await this.queryClient.getChainId();
      const height = await this.queryClient.getHeight();

      return {
        connected: true,
        chainId,
        blockHeight: height,
      };
    } catch {
      return { connected: false };
    }
  }

  /**
   * Get account info
   */
  async getAccount(address: string): Promise<AccountInfo | null> {
    if (!this.queryClient) {
      throw new Error('Client not connected');
    }

    const account = await this.queryClient.getAccount(address);
    if (!account) {
      return null;
    }

    const balance = await this.queryClient.getBalance(address, 'uaeth');

    return {
      address: account.address,
      balance: balance.amount,
      sequence: account.sequence,
      accountNumber: account.accountNumber,
    };
  }

  /**
   * Get signer address
   */
  async getSignerAddress(): Promise<string | null> {
    if (!this.signer) {
      return null;
    }

    const accounts = await this.signer.getAccounts();
    return accounts[0]?.address || null;
  }

  /**
   * Check if client can sign transactions
   */
  canSign(): boolean {
    return this.signingClient !== null;
  }

  /**
   * Get current block height
   */
  async getBlockHeight(): Promise<number> {
    if (!this.queryClient) {
      throw new Error('Client not connected');
    }
    return this.queryClient.getHeight();
  }

  /**
   * Get chain ID
   */
  async getChainId(): Promise<string> {
    if (!this.queryClient) {
      throw new Error('Client not connected');
    }
    return this.queryClient.getChainId();
  }

  /**
   * Wait for a transaction to be included in a block
   */
  async waitForTx(txHash: string, timeoutMs: number = 30000): Promise<DeliverTxResponse | null> {
    if (!this.queryClient) {
      throw new Error('Client not connected');
    }

    const startTime = Date.now();
    while (Date.now() - startTime < timeoutMs) {
      try {
        const result = await this.queryClient.getTx(txHash);
        if (result) {
          return result as unknown as DeliverTxResponse;
        }
      } catch {
        // Transaction not found yet
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    return null;
  }

  // ============ Module Accessors ============

  /**
   * Access the Seal module
   */
  get seal(): SealModule {
    if (!this._seal) {
      this._seal = new SealModule(this.httpClient, this.signingClient, this.config);
    }
    return this._seal;
  }

  /**
   * Access the Verify module
   */
  get verify(): VerifyModule {
    if (!this._verify) {
      this._verify = new VerifyModule(this.httpClient, this.config);
    }
    return this._verify;
  }

  /**
   * Access the Compute module
   */
  get compute(): ComputeModule {
    if (!this._compute) {
      this._compute = new ComputeModule(this.httpClient, this.signingClient, this.config);
    }
    return this._compute;
  }

  /**
   * Access the Credit Scoring demo module
   */
  get creditScoring(): CreditScoringModule {
    if (!this._creditScoring) {
      this._creditScoring = new CreditScoringModule(this.httpClient, this.config);
    }
    return this._creditScoring;
  }

  // ============ Low-level Access ============

  /**
   * Get the underlying Stargate client for advanced queries
   */
  getQueryClient(): StargateClient | null {
    return this.queryClient;
  }

  /**
   * Get the underlying signing client for advanced transactions
   */
  getSigningClient(): SigningStargateClient | null {
    return this.signingClient;
  }

  /**
   * Get HTTP client for REST API calls
   */
  getHttpClient(): AxiosInstance {
    return this.httpClient;
  }

  /**
   * Execute raw REST API call
   */
  async restQuery<T>(path: string): Promise<T> {
    const response = await this.httpClient.get<T>(path);
    return response.data;
  }

  /**
   * Disconnect from the network
   */
  disconnect(): void {
    if (this.tmClient) {
      this.tmClient.disconnect();
    }
    this.queryClient = null;
    this.signingClient = null;
    this.tmClient = null;

    if (this.config.debug) {
      console.log('[Aethelred SDK] Disconnected');
    }
  }
}
