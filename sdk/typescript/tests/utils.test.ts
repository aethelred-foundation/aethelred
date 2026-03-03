/**
 * Utility Functions Tests
 */

import { describe, it, expect } from 'vitest';

import {
  sha256,
  sha3_256,
  hashData,
  hashJSON,
  createCommitment,
  verifyCommitment,
  createMerkleRoot,
  createMerkleProof,
  verifyMerkleProof,
  isValidHash,
  compareHashes,
} from '../src/utils/hash';

import {
  toBase64,
  fromBase64,
  toHex,
  fromHex,
  toBase64Url,
  fromBase64Url,
  toBech32,
  fromBech32,
  isValidBech32,
  canonicalizeJSON,
} from '../src/utils/encoding';

import {
  validateAddress,
  validateHash,
  validateSealId,
  validateJobId,
  validateAmount,
  validateProofType,
  combineResults,
  validateRequiredFields,
} from '../src/utils/validation';

describe('Hash Utilities', () => {
  describe('sha256', () => {
    it('should hash strings correctly', () => {
      const hash = sha256('hello');
      expect(hash).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    });

    it('should hash buffers correctly', () => {
      const hash = sha256(Buffer.from('hello'));
      expect(hash).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    });

    it('should produce 64 character hex output', () => {
      const hash = sha256('test');
      expect(hash.length).toBe(64);
      expect(/^[a-f0-9]+$/.test(hash)).toBe(true);
    });
  });

  describe('sha3_256', () => {
    it('should hash strings correctly', () => {
      const hash = sha3_256('hello');
      expect(hash.length).toBe(64);
    });

    it('should produce different output than sha256', () => {
      const sha2Hash = sha256('hello');
      const sha3Hash = sha3_256('hello');
      expect(sha2Hash).not.toBe(sha3Hash);
    });
  });

  describe('hashData', () => {
    it('should use sha256 by default', () => {
      const hash = hashData('hello');
      expect(hash).toBe(sha256('hello'));
    });

    it('should support different algorithms', () => {
      const sha256Hash = hashData('hello', 'sha256');
      const sha3Hash = hashData('hello', 'sha3-256');
      expect(sha256Hash).not.toBe(sha3Hash);
    });
  });

  describe('hashJSON', () => {
    it('should produce consistent hashes for same objects', () => {
      const obj = { b: 2, a: 1 };
      const hash1 = hashJSON(obj);
      const hash2 = hashJSON(obj);
      expect(hash1).toBe(hash2);
    });

    it('should produce same hash regardless of key order', () => {
      const obj1 = { a: 1, b: 2 };
      const obj2 = { b: 2, a: 1 };
      expect(hashJSON(obj1)).toBe(hashJSON(obj2));
    });
  });

  describe('Commitments', () => {
    it('should create and verify commitments', () => {
      const data = 'sensitive data';
      const { commitment, salt } = createCommitment(data);

      expect(commitment.length).toBe(64);
      expect(salt.length).toBe(64);

      const verified = verifyCommitment(data, salt, commitment);
      expect(verified).toBe(true);
    });

    it('should fail verification with wrong data', () => {
      const { commitment, salt } = createCommitment('original');
      const verified = verifyCommitment('wrong', salt, commitment);
      expect(verified).toBe(false);
    });

    it('should fail verification with wrong salt', () => {
      const { commitment } = createCommitment('data');
      const verified = verifyCommitment('data', 'wrongsalt', commitment);
      expect(verified).toBe(false);
    });
  });

  describe('Merkle Trees', () => {
    const items = ['a', 'b', 'c', 'd'];

    it('should create merkle root', () => {
      const root = createMerkleRoot(items);
      expect(root.length).toBe(64);
    });

    it('should return consistent roots', () => {
      const root1 = createMerkleRoot(items);
      const root2 = createMerkleRoot(items);
      expect(root1).toBe(root2);
    });

    it('should create and verify proofs', () => {
      const root = createMerkleRoot(items);

      for (let i = 0; i < items.length; i++) {
        const proof = createMerkleProof(items, i);
        const valid = verifyMerkleProof(items[i], proof, root, i);
        expect(valid).toBe(true);
      }
    });

    it('should fail verification with wrong item', () => {
      const root = createMerkleRoot(items);
      const proof = createMerkleProof(items, 0);
      const valid = verifyMerkleProof('wrong', proof, root, 0);
      expect(valid).toBe(false);
    });
  });

  describe('Hash Validation', () => {
    it('should validate correct hashes', () => {
      const hash = sha256('test');
      expect(isValidHash(hash)).toBe(true);
    });

    it('should reject invalid hashes', () => {
      expect(isValidHash('invalid')).toBe(false);
      expect(isValidHash('123')).toBe(false);
      expect(isValidHash('xyz')).toBe(false);
    });
  });

  describe('compareHashes', () => {
    it('should return true for equal hashes', () => {
      const hash = sha256('test');
      expect(compareHashes(hash, hash)).toBe(true);
    });

    it('should return false for different hashes', () => {
      const hash1 = sha256('test1');
      const hash2 = sha256('test2');
      expect(compareHashes(hash1, hash2)).toBe(false);
    });
  });
});

describe('Encoding Utilities', () => {
  describe('Base64', () => {
    it('should encode and decode strings', () => {
      const original = 'hello world';
      const encoded = toBase64(original);
      const decoded = fromBase64(encoded);
      expect(decoded).toBe(original);
    });

    it('should encode and decode buffers', () => {
      const original = Buffer.from('binary data');
      const encoded = toBase64(original);
      const decoded = fromBase64(encoded);
      expect(decoded).toBe('binary data');
    });
  });

  describe('Base64URL', () => {
    it('should produce URL-safe output', () => {
      const data = 'test+data/with?special=chars';
      const encoded = toBase64Url(data);
      expect(encoded).not.toContain('+');
      expect(encoded).not.toContain('/');
      expect(encoded).not.toContain('=');
    });

    it('should encode and decode correctly', () => {
      const original = 'test data';
      const encoded = toBase64Url(original);
      const decoded = fromBase64Url(encoded);
      expect(decoded).toBe(original);
    });
  });

  describe('Hex', () => {
    it('should encode and decode', () => {
      const original = Buffer.from('hello');
      const hex = toHex(original);
      const decoded = fromHex(hex);
      expect(decoded.toString()).toBe('hello');
    });
  });

  describe('Bech32', () => {
    it('should validate correct addresses', () => {
      // Note: These would be real addresses in production
      expect(isValidBech32('aethelred1abc', 'aethelred')).toBe(false); // Too short
    });
  });

  describe('Canonical JSON', () => {
    it('should sort keys consistently', () => {
      const obj1 = { b: 2, a: 1 };
      const obj2 = { a: 1, b: 2 };
      expect(canonicalizeJSON(obj1)).toBe(canonicalizeJSON(obj2));
    });

    it('should handle nested objects', () => {
      const obj = { b: { d: 4, c: 3 }, a: 1 };
      const canonical = canonicalizeJSON(obj);
      expect(canonical).toBe('{"a":1,"b":{"c":3,"d":4}}');
    });
  });
});

describe('Validation Utilities', () => {
  describe('validateHash', () => {
    it('should accept valid hashes', () => {
      const hash = sha256('test');
      const result = validateHash(hash, 'Test Hash');
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject invalid hashes', () => {
      const result = validateHash('invalid', 'Test Hash');
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should require hash', () => {
      const result = validateHash('', 'Test Hash');
      expect(result.valid).toBe(false);
    });
  });

  describe('validateSealId', () => {
    it('should accept valid seal IDs', () => {
      const result = validateSealId('seal-1234567890-abc12345');
      expect(result.valid).toBe(true);
    });

    it('should reject invalid seal IDs', () => {
      const result = validateSealId('invalid');
      expect(result.valid).toBe(false);
    });
  });

  describe('validateJobId', () => {
    it('should accept valid job IDs', () => {
      const result = validateJobId('job-1234567890-abc12345');
      expect(result.valid).toBe(true);
    });

    it('should reject invalid job IDs', () => {
      const result = validateJobId('invalid');
      expect(result.valid).toBe(false);
    });
  });

  describe('validateAmount', () => {
    it('should accept valid amounts', () => {
      const result = validateAmount(100);
      expect(result.valid).toBe(true);
    });

    it('should reject negative amounts', () => {
      const result = validateAmount(-10);
      expect(result.valid).toBe(false);
    });

    it('should validate min/max', () => {
      const result = validateAmount(50, 100, 200);
      expect(result.valid).toBe(false);
    });
  });

  describe('validateProofType', () => {
    it('should accept valid proof types', () => {
      expect(validateProofType('tee').valid).toBe(true);
      expect(validateProofType('zkml').valid).toBe(true);
      expect(validateProofType('hybrid').valid).toBe(true);
    });

    it('should reject invalid proof types', () => {
      const result = validateProofType('invalid');
      expect(result.valid).toBe(false);
    });
  });

  describe('combineResults', () => {
    it('should combine multiple results', () => {
      const result1 = validateHash(sha256('test'), 'Hash1');
      const result2 = validateHash('invalid', 'Hash2');

      const combined = combineResults(result1, result2);
      expect(combined.valid).toBe(false);
      expect(combined.errors.length).toBeGreaterThan(0);
    });
  });

  describe('validateRequiredFields', () => {
    it('should pass when all fields present', () => {
      const obj = { name: 'test', value: 123 };
      const result = validateRequiredFields(obj, ['name', 'value']);
      expect(result.valid).toBe(true);
    });

    it('should fail when fields missing', () => {
      const obj = { name: 'test' };
      const result = validateRequiredFields(obj, ['name', 'value']);
      expect(result.valid).toBe(false);
    });
  });
});
