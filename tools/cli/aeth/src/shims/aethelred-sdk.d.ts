declare module "@aethelred/sdk" {
  export class AethelredClient {
    constructor(config?: unknown);
    validators: {
      list(pagination?: unknown): Promise<any[]>;
      getStats(address: string): Promise<any>;
    };
    seals: {
      get(sealId: string): Promise<any>;
    };
  }
}

declare module "@aethelred/sdk/devtools" {
  export interface SealVerificationOptions {
    minConsensusBps?: number;
    maxAttestationAgeMs?: number;
    requireTeeNonce?: boolean;
    trustedEnclaveHashes?: string[];
    trustedPcr0Values?: string[];
  }

  export function verifySealOffline(
    input: string | Record<string, unknown>,
    options?: SealVerificationOptions,
  ): {
    valid: boolean;
    score: number;
    fingerprintSha256: string;
    checks: Array<{ id: string; severity: string; ok: boolean; message: string }>;
    errors: string[];
    warnings: string[];
    metadata: {
      validatorCount: number;
      consensusBps?: number;
    };
  };
}

