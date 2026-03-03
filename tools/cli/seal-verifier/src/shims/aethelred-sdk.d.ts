declare module "@aethelred/sdk" {
  export class AethelredClient {
    constructor(config?: unknown);
    seals: {
      get(sealId: string): Promise<any>;
    };
  }
}

declare module "@aethelred/sdk/devtools" {
  export interface SealVerificationOptions {
    now?: Date;
    minConsensusBps?: number;
    requiredValidatorCount?: number;
    maxAttestationAgeMs?: number;
    requireTeeNonce?: boolean;
    trustedEnclaveHashes?: string[];
    trustedPcr0Values?: string[];
    expectedModelHash?: string;
    expectedRequester?: string;
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

