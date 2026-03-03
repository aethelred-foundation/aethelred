/**
 * Verification module for Aethelred SDK.
 */

import type { AethelredClient } from '../core/client';
import { ProofSystem, TEEAttestation, TEEPlatform } from '../core/types';

export interface VerifyZKProofRequest {
  proof: string;
  publicInputs: string[];
  verifyingKeyHash: string;
  proofSystem?: ProofSystem;
}

export interface VerifyZKProofResponse {
  valid: boolean;
  verificationTimeMs: number;
  error?: string;
}

export interface VerifyTEEResponse {
  valid: boolean;
  platform: TEEPlatform;
  enclaveHash?: string;
  timestamp?: Date;
  error?: string;
}

export class VerificationModule {
  private readonly basePath = '/aethelred/verify/v1';

  constructor(private readonly client: AethelredClient) {}

  async verifyZKProof(request: VerifyZKProofRequest): Promise<VerifyZKProofResponse> {
    return this.client.post(`${this.basePath}/zkproofs:verify`, request);
  }

  async verifyTEEAttestation(attestation: TEEAttestation, expectedEnclaveHash?: string): Promise<VerifyTEEResponse> {
    return this.client.post(`${this.basePath}/tee/attestation:verify`, {
      attestation,
      expected_enclave_hash: expectedEnclaveHash,
    });
  }
}
