/**
 * Configuration for Aethelred SDK.
 */

export enum Network {
  MAINNET = 'mainnet',
  TESTNET = 'testnet',
  DEVNET = 'devnet',
  LOCAL = 'local',
}

export interface NetworkConfig {
  rpcUrl: string;
  chainId: string;
  wsUrl?: string;
  grpcUrl?: string;
  restUrl?: string;
  explorerUrl?: string;
}

export const NETWORK_CONFIGS: Record<Network, NetworkConfig> = {
  [Network.MAINNET]: {
    rpcUrl: 'https://rpc.mainnet.aethelred.io',
    chainId: 'aethelred-mainnet-1',
    wsUrl: 'wss://ws.mainnet.aethelred.io',
    grpcUrl: 'grpc.mainnet.aethelred.io:9090',
    restUrl: 'https://api.mainnet.aethelred.io',
    explorerUrl: 'https://explorer.aethelred.io',
  },
  [Network.TESTNET]: {
    rpcUrl: 'https://rpc.testnet.aethelred.io',
    chainId: 'aethelred-testnet-1',
    wsUrl: 'wss://ws.testnet.aethelred.io',
    grpcUrl: 'grpc.testnet.aethelred.io:9090',
    restUrl: 'https://api.testnet.aethelred.io',
    explorerUrl: 'https://explorer.testnet.aethelred.io',
  },
  [Network.DEVNET]: {
    rpcUrl: 'https://rpc.devnet.aethelred.io',
    chainId: 'aethelred-devnet-1',
    wsUrl: 'wss://ws.devnet.aethelred.io',
    grpcUrl: 'grpc.devnet.aethelred.io:9090',
    restUrl: 'https://api.devnet.aethelred.io',
    explorerUrl: 'https://explorer.devnet.aethelred.io',
  },
  [Network.LOCAL]: {
    rpcUrl: 'http://127.0.0.1:26657',
    chainId: 'aethelred-local',
    wsUrl: 'ws://127.0.0.1:26657/websocket',
    grpcUrl: '127.0.0.1:9090',
    restUrl: 'http://127.0.0.1:1317',
  },
};

export interface RetryConfig {
  maxRetries: number;
  initialDelay: number;
  maxDelay: number;
  exponentialBase: number;
}

export interface TimeoutConfig {
  connect: number;
  read: number;
  write: number;
}

export interface Config {
  network?: Network;
  rpcUrl?: string;
  chainId?: string;
  apiKey?: string;
  privateKey?: string;
  timeout?: Partial<TimeoutConfig>;
  retry?: Partial<RetryConfig>;
  maxConnections?: number;
  wsEnabled?: boolean;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  logRequests?: boolean;
}

export const DEFAULT_CONFIG: Required<Omit<Config, 'apiKey' | 'privateKey' | 'rpcUrl' | 'chainId'>> = {
  network: Network.MAINNET,
  timeout: { connect: 10000, read: 30000, write: 30000 },
  retry: { maxRetries: 3, initialDelay: 500, maxDelay: 30000, exponentialBase: 2 },
  maxConnections: 10,
  wsEnabled: true,
  logLevel: 'info',
  logRequests: false,
};

export function resolveConfig(config: Config): Required<Config> & { networkConfig: NetworkConfig } {
  const network = config.network ?? DEFAULT_CONFIG.network;
  const networkConfig = NETWORK_CONFIGS[network];
  const timeout = {
    ...DEFAULT_CONFIG.timeout,
    ...(config.timeout ?? {}),
  };
  const retry = {
    ...DEFAULT_CONFIG.retry,
    ...(config.retry ?? {}),
  };
  
  return {
    ...DEFAULT_CONFIG,
    ...config,
    timeout,
    retry,
    network,
    rpcUrl: config.rpcUrl ?? networkConfig.rpcUrl,
    chainId: config.chainId ?? networkConfig.chainId,
    apiKey: config.apiKey,
    privateKey: config.privateKey,
    networkConfig,
  } as Required<Config> & { networkConfig: NetworkConfig };
}
