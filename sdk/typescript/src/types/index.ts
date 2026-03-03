/**
 * Aethelred SDK Types - Main Export
 */

// Seal types
export * from './seal';

// Compute types
export * from './compute';

// Credit scoring types
export * from './credit-scoring';

// Common types
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  offset: number;
  limit: number;
  hasMore: boolean;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: ApiError;
}

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface TransactionResult {
  txHash: string;
  height: number;
  gasUsed: number;
  gasWanted: number;
  success: boolean;
  rawLog?: string;
  events?: TransactionEvent[];
}

export interface TransactionEvent {
  type: string;
  attributes: { key: string; value: string }[];
}

// Blockchain types
export interface BlockInfo {
  height: number;
  hash: string;
  time: string;
  proposer: string;
  txCount: number;
}

export interface ValidatorInfo {
  address: string;
  pubkey: string;
  votingPower: number;
  commission: number;
  status: 'bonded' | 'unbonded' | 'unbonding';
  hardwareCapabilities?: HardwareCapabilities;
}

export interface HardwareCapabilities {
  hasTEE: boolean;
  teeType?: 'nitro' | 'sgx' | 'sev';
  hasGPU: boolean;
  gpuModel?: string;
  memoryGB: number;
}

// Cryptographic types
export interface Hash {
  algorithm: 'sha256' | 'sha3-256' | 'blake2b';
  value: string;
}

export interface Signature {
  algorithm: 'secp256k1' | 'ed25519';
  pubkey: string;
  signature: string;
}
