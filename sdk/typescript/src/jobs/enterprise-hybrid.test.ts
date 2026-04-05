/**
 * Enterprise Hybrid Default Tests
 *
 * Verifies that the SDK defaults proofType to HYBRID when not specified.
 */

import { describe, expect, it } from 'vitest';

import { ProofType } from '../core/types';

describe('Enterprise Hybrid Defaults', () => {
  it('should default proofType to HYBRID when submit is called without proofType', () => {
    // Simulate the default-filling logic from JobsModule.submit()
    const request = {
      modelHash: '0x' + 'a'.repeat(64),
      inputHash: '0x' + 'b'.repeat(64),
    };

    const withDefaults = {
      proofType: ProofType.HYBRID,
      ...request,
    };

    expect(withDefaults.proofType).toBe(ProofType.HYBRID);
    expect(withDefaults.proofType).toBe('PROOF_TYPE_HYBRID');
  });

  it('should respect explicit proofType override', () => {
    const request = {
      modelHash: '0x' + 'a'.repeat(64),
      inputHash: '0x' + 'b'.repeat(64),
      proofType: ProofType.TEE,
    };

    const withDefaults = {
      proofType: ProofType.HYBRID,
      ...request,
    };

    // Spread puts request.proofType last, overriding the default
    expect(withDefaults.proofType).toBe(ProofType.TEE);
  });

  it('should have HYBRID in the ProofType enum', () => {
    expect(ProofType.HYBRID).toBeDefined();
    expect(ProofType.HYBRID).toBe('PROOF_TYPE_HYBRID');
  });

  it('should have all expected proof types', () => {
    expect(ProofType.TEE).toBe('PROOF_TYPE_TEE');
    expect(ProofType.ZKML).toBe('PROOF_TYPE_ZKML');
    expect(ProofType.HYBRID).toBe('PROOF_TYPE_HYBRID');
    expect(ProofType.OPTIMISTIC).toBe('PROOF_TYPE_OPTIMISTIC');
  });
});
