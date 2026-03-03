/**
 * Validation Utilities
 */

import { isValidHash, HashAlgorithm } from './hash';
import { isValidBech32 } from './encoding';

/**
 * Validation result
 */
export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Create empty validation result
 */
export function createValidationResult(): ValidationResult {
  return {
    valid: true,
    errors: [],
    warnings: [],
  };
}

/**
 * Add error to validation result
 */
export function addError(result: ValidationResult, error: string): ValidationResult {
  result.errors.push(error);
  result.valid = false;
  return result;
}

/**
 * Add warning to validation result
 */
export function addWarning(result: ValidationResult, warning: string): ValidationResult {
  result.warnings.push(warning);
  return result;
}

/**
 * Validate Aethelred address
 */
export function validateAddress(address: string): ValidationResult {
  const result = createValidationResult();

  if (!address) {
    return addError(result, 'Address is required');
  }

  if (!isValidBech32(address, 'aethelred')) {
    return addError(result, 'Invalid Aethelred address format');
  }

  return result;
}

/**
 * Validate validator address
 */
export function validateValidatorAddress(address: string): ValidationResult {
  const result = createValidationResult();

  if (!address) {
    return addError(result, 'Validator address is required');
  }

  if (!isValidBech32(address, 'aethelredvaloper')) {
    return addError(result, 'Invalid validator address format');
  }

  return result;
}

/**
 * Validate hash
 */
export function validateHash(
  hash: string,
  fieldName: string = 'Hash',
  algorithm: HashAlgorithm = 'sha256'
): ValidationResult {
  const result = createValidationResult();

  if (!hash) {
    return addError(result, `${fieldName} is required`);
  }

  if (!isValidHash(hash, algorithm)) {
    return addError(result, `${fieldName} is not a valid ${algorithm} hash`);
  }

  return result;
}

/**
 * Validate seal ID
 */
export function validateSealId(sealId: string): ValidationResult {
  const result = createValidationResult();

  if (!sealId) {
    return addError(result, 'Seal ID is required');
  }

  // Seal ID format: seal-{timestamp}-{random}
  if (!/^seal-\d{10,13}-[a-f0-9]{8,}$/i.test(sealId)) {
    return addError(result, 'Invalid seal ID format');
  }

  return result;
}

/**
 * Validate job ID
 */
export function validateJobId(jobId: string): ValidationResult {
  const result = createValidationResult();

  if (!jobId) {
    return addError(result, 'Job ID is required');
  }

  // Job ID format: job-{timestamp}-{random}
  if (!/^job-\d{10,13}-[a-f0-9]{8,}$/i.test(jobId)) {
    return addError(result, 'Invalid job ID format');
  }

  return result;
}

/**
 * Validate amount (AETHEL)
 */
export function validateAmount(
  amount: string | number,
  min?: number,
  max?: number
): ValidationResult {
  const result = createValidationResult();

  const num = typeof amount === 'string' ? parseFloat(amount) : amount;

  if (isNaN(num)) {
    return addError(result, 'Amount must be a valid number');
  }

  if (num < 0) {
    return addError(result, 'Amount cannot be negative');
  }

  if (min !== undefined && num < min) {
    return addError(result, `Amount must be at least ${min}`);
  }

  if (max !== undefined && num > max) {
    return addError(result, `Amount must not exceed ${max}`);
  }

  return result;
}

/**
 * Validate proof type
 */
export function validateProofType(proofType: string): ValidationResult {
  const result = createValidationResult();
  const validTypes = ['tee', 'zkml', 'hybrid'];

  if (!proofType) {
    return addError(result, 'Proof type is required');
  }

  if (!validTypes.includes(proofType.toLowerCase())) {
    return addError(result, `Proof type must be one of: ${validTypes.join(', ')}`);
  }

  return result;
}

/**
 * Validate job priority
 */
export function validateJobPriority(priority: string): ValidationResult {
  const result = createValidationResult();
  const validPriorities = ['low', 'normal', 'high', 'critical'];

  if (!priority) {
    return addError(result, 'Priority is required');
  }

  if (!validPriorities.includes(priority.toLowerCase())) {
    return addError(result, `Priority must be one of: ${validPriorities.join(', ')}`);
  }

  return result;
}

/**
 * Validate URL
 */
export function validateUrl(url: string, requireHttps: boolean = false): ValidationResult {
  const result = createValidationResult();

  if (!url) {
    return addError(result, 'URL is required');
  }

  try {
    const parsed = new URL(url);

    if (requireHttps && parsed.protocol !== 'https:') {
      return addError(result, 'URL must use HTTPS');
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return addError(result, 'URL must use HTTP or HTTPS protocol');
    }
  } catch {
    return addError(result, 'Invalid URL format');
  }

  return result;
}

/**
 * Validate timestamp (ISO 8601)
 */
export function validateTimestamp(timestamp: string): ValidationResult {
  const result = createValidationResult();

  if (!timestamp) {
    return addError(result, 'Timestamp is required');
  }

  const date = new Date(timestamp);
  if (isNaN(date.getTime())) {
    return addError(result, 'Invalid timestamp format');
  }

  // Check if future (with 5 minute tolerance)
  if (date.getTime() > Date.now() + 5 * 60 * 1000) {
    addWarning(result, 'Timestamp is in the future');
  }

  return result;
}

/**
 * Validate block height
 */
export function validateBlockHeight(height: number): ValidationResult {
  const result = createValidationResult();

  if (typeof height !== 'number' || !Number.isInteger(height)) {
    return addError(result, 'Block height must be an integer');
  }

  if (height < 0) {
    return addError(result, 'Block height cannot be negative');
  }

  return result;
}

/**
 * Validate chain ID
 */
export function validateChainId(chainId: string): ValidationResult {
  const result = createValidationResult();

  if (!chainId) {
    return addError(result, 'Chain ID is required');
  }

  // Aethelred chain IDs: aethelred-mainnet-1, aethelred-testnet-1, etc.
  if (!/^aethelred-(mainnet|testnet|local)-\d+$/.test(chainId)) {
    addWarning(result, 'Chain ID does not match expected Aethelred format');
  }

  return result;
}

/**
 * Validate signature
 */
export function validateSignature(signature: string): ValidationResult {
  const result = createValidationResult();

  if (!signature) {
    return addError(result, 'Signature is required');
  }

  // Check if valid base64
  try {
    const decoded = Buffer.from(signature, 'base64');
    if (decoded.length !== 64 && decoded.length !== 65) {
      addWarning(result, 'Unexpected signature length');
    }
  } catch {
    return addError(result, 'Invalid signature encoding');
  }

  return result;
}

/**
 * Validate public key
 */
export function validatePubkey(pubkey: string): ValidationResult {
  const result = createValidationResult();

  if (!pubkey) {
    return addError(result, 'Public key is required');
  }

  // Check if valid base64 or hex
  try {
    let decoded: Buffer;
    if (/^[a-f0-9]+$/i.test(pubkey)) {
      decoded = Buffer.from(pubkey, 'hex');
    } else {
      decoded = Buffer.from(pubkey, 'base64');
    }

    if (decoded.length !== 33 && decoded.length !== 65) {
      addWarning(result, 'Unexpected public key length');
    }
  } catch {
    return addError(result, 'Invalid public key encoding');
  }

  return result;
}

/**
 * Combine multiple validation results
 */
export function combineResults(...results: ValidationResult[]): ValidationResult {
  const combined = createValidationResult();

  for (const result of results) {
    combined.errors.push(...result.errors);
    combined.warnings.push(...result.warnings);
    if (!result.valid) {
      combined.valid = false;
    }
  }

  return combined;
}

/**
 * Validate required fields in object
 */
export function validateRequiredFields(
  obj: Record<string, unknown>,
  requiredFields: string[]
): ValidationResult {
  const result = createValidationResult();

  for (const field of requiredFields) {
    if (obj[field] === undefined || obj[field] === null || obj[field] === '') {
      addError(result, `${field} is required`);
    }
  }

  return result;
}
