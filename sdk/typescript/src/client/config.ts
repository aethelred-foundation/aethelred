/**
 * Aethelred SDK Configuration
 */

/**
 * Network type
 */
export type NetworkType = 'mainnet' | 'testnet' | 'local';

export interface AethelredConfig {
  /** RPC endpoint URL */
  rpcUrl: string;

  /** REST/LCD endpoint URL */
  restUrl?: string;

  /** Chain ID */
  chainId: string;

  /** Gas price in uaethel */
  gasPrice?: string;

  /** Default gas limit */
  defaultGasLimit?: number;

  /** Request timeout in milliseconds */
  timeout?: number;

  /** Enable debug logging */
  debug?: boolean;
}

export interface NetworkConfig {
  rpcUrl: string;
  restUrl: string;
  chainId: string;
  gasPrice: string;
  explorer?: string;
}

/**
 * Pre-configured networks
 */
export const Networks: Record<string, NetworkConfig> = {
  mainnet: {
    rpcUrl: 'https://rpc.mainnet.aethelred.io',
    restUrl: 'https://api.mainnet.aethelred.io',
    chainId: 'aethelred-mainnet-1',
    gasPrice: '0.025uaethel',
    explorer: 'https://explorer.aethelred.io',
  },
  testnet: {
    rpcUrl: 'https://rpc.testnet.aethelred.io',
    restUrl: 'https://api.testnet.aethelred.io',
    chainId: 'aethelred-testnet-1',
    gasPrice: '0.001uaethel',
    explorer: 'https://explorer.testnet.aethelred.io',
  },
  local: {
    rpcUrl: 'http://127.0.0.1:26657',
    restUrl: 'http://127.0.0.1:1317',
    chainId: 'aethelred-local',
    gasPrice: '0.001uaethel',
  },
};

/**
 * Default configuration values
 */
/**
 * Alias for DefaultConfig
 */
export const DEFAULT_CONFIG: Partial<AethelredConfig> = {
  gasPrice: '0.025uaethel',
  defaultGasLimit: 200000,
  timeout: 30000,
  debug: false,
};

/**
 * Default configuration values
 * @deprecated Use DEFAULT_CONFIG instead
 */
export const DefaultConfig: Partial<AethelredConfig> = {
  gasPrice: '0.025uaethel',
  defaultGasLimit: 200000,
  timeout: 30000,
  debug: false,
};

/**
 * Merge user config with defaults
 */
export function mergeConfig(userConfig: Partial<AethelredConfig>): AethelredConfig {
  if (!userConfig.rpcUrl) {
    throw new Error('rpcUrl is required');
  }
  if (!userConfig.chainId) {
    throw new Error('chainId is required');
  }

  return {
    ...DefaultConfig,
    ...userConfig,
  } as AethelredConfig;
}

/**
 * Create config from network preset
 */
export function fromNetwork(network: keyof typeof Networks): AethelredConfig {
  const networkConfig = Networks[network];
  if (!networkConfig) {
    throw new Error(`Unknown network: ${network}`);
  }

  return {
    ...DefaultConfig,
    rpcUrl: networkConfig.rpcUrl,
    restUrl: networkConfig.restUrl,
    chainId: networkConfig.chainId,
    gasPrice: networkConfig.gasPrice,
  } as AethelredConfig;
}
