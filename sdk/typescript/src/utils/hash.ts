/**
 * Hash Utilities
 */

import { createHash, Hash as CryptoHash } from 'crypto';

export type HashAlgorithm = 'sha256' | 'sha3-256' | 'blake2b256';

/**
 * Hash data using SHA-256
 */
export function sha256(data: string | Buffer): string {
  const hash = createHash('sha256');
  hash.update(typeof data === 'string' ? Buffer.from(data) : data);
  return hash.digest('hex');
}

/**
 * Hash data using SHA3-256
 */
export function sha3_256(data: string | Buffer): string {
  const hash = createHash('sha3-256');
  hash.update(typeof data === 'string' ? Buffer.from(data) : data);
  return hash.digest('hex');
}

/**
 * Hash data using specified algorithm
 */
export function hashData(
  data: string | Buffer,
  algorithm: HashAlgorithm = 'sha256'
): string {
  switch (algorithm) {
    case 'sha256':
      return sha256(data);
    case 'sha3-256':
      return sha3_256(data);
    case 'blake2b256':
      // Blake2b requires special handling
      const blake = createHash('blake2b512');
      blake.update(typeof data === 'string' ? Buffer.from(data) : data);
      return blake.digest('hex').slice(0, 64); // Take first 256 bits
    default:
      throw new Error(`Unsupported hash algorithm: ${algorithm}`);
  }
}

/**
 * Hash JSON object
 */
export function hashJSON(obj: unknown, algorithm: HashAlgorithm = 'sha256'): string {
  const canonical = JSON.stringify(obj, Object.keys(obj as object).sort());
  return hashData(canonical, algorithm);
}

/**
 * Hash model weights (simulated for SDK)
 */
export function hashModel(modelData: Buffer): string {
  return sha256(modelData);
}

/**
 * Hash input features
 */
export function hashInput(features: Record<string, unknown>): string {
  return hashJSON(features);
}

/**
 * Hash output result
 */
export function hashOutput(output: unknown): string {
  return hashJSON(output);
}

/**
 * Create commitment hash (for privacy-preserving verification)
 */
export function createCommitment(
  data: string | Buffer,
  salt?: string
): { commitment: string; salt: string } {
  const actualSalt = salt || generateSalt();
  const combined = typeof data === 'string' ? data + actualSalt : Buffer.concat([data, Buffer.from(actualSalt)]);
  return {
    commitment: sha256(combined),
    salt: actualSalt,
  };
}

/**
 * Verify a commitment
 */
export function verifyCommitment(
  data: string | Buffer,
  salt: string,
  commitment: string
): boolean {
  const combined = typeof data === 'string' ? data + salt : Buffer.concat([data, Buffer.from(salt)]);
  return sha256(combined) === commitment;
}

/**
 * Generate random salt
 */
export function generateSalt(length: number = 32): string {
  const bytes = require('crypto').randomBytes(length);
  return bytes.toString('hex');
}

/**
 * Create merkle root from array of items
 */
export function createMerkleRoot(items: string[]): string {
  if (items.length === 0) {
    return sha256('');
  }

  let leaves = items.map((item) => sha256(item));

  while (leaves.length > 1) {
    const newLeaves: string[] = [];
    for (let i = 0; i < leaves.length; i += 2) {
      if (i + 1 < leaves.length) {
        newLeaves.push(sha256(leaves[i] + leaves[i + 1]));
      } else {
        newLeaves.push(leaves[i]);
      }
    }
    leaves = newLeaves;
  }

  return leaves[0];
}

/**
 * Create merkle proof for an item
 */
export function createMerkleProof(items: string[], index: number): string[] {
  if (index < 0 || index >= items.length) {
    throw new Error('Index out of bounds');
  }

  const proof: string[] = [];
  let leaves = items.map((item) => sha256(item));
  let currentIndex = index;

  while (leaves.length > 1) {
    const newLeaves: string[] = [];

    for (let i = 0; i < leaves.length; i += 2) {
      if (i + 1 < leaves.length) {
        if (i === currentIndex || i + 1 === currentIndex) {
          proof.push(i === currentIndex ? leaves[i + 1] : leaves[i]);
        }
        newLeaves.push(sha256(leaves[i] + leaves[i + 1]));
      } else {
        newLeaves.push(leaves[i]);
      }
    }

    currentIndex = Math.floor(currentIndex / 2);
    leaves = newLeaves;
  }

  return proof;
}

/**
 * Verify merkle proof
 */
export function verifyMerkleProof(
  item: string,
  proof: string[],
  root: string,
  index: number
): boolean {
  let hash = sha256(item);
  let currentIndex = index;

  for (const sibling of proof) {
    if (currentIndex % 2 === 0) {
      hash = sha256(hash + sibling);
    } else {
      hash = sha256(sibling + hash);
    }
    currentIndex = Math.floor(currentIndex / 2);
  }

  return hash === root;
}

/**
 * Compare two hashes (constant time)
 */
export function compareHashes(a: string, b: string): boolean {
  if (a.length !== b.length) return false;

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Validate hash format
 */
export function isValidHash(hash: string, algorithm: HashAlgorithm = 'sha256'): boolean {
  const expectedLength = algorithm === 'sha256' || algorithm === 'sha3-256' || algorithm === 'blake2b256' ? 64 : 0;
  if (hash.length !== expectedLength) return false;
  return /^[a-f0-9]+$/i.test(hash);
}
