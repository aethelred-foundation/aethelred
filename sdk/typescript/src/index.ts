/**
 * Official Aethelred TypeScript/JavaScript SDK
 *
 * Stable public entrypoint for Node.js and browser clients.
 * Advanced experimental tensor/runtime internals remain in source but are not
 * exported from the root package until their type surfaces are fully stabilized.
 */

export const VERSION = '1.0.0';
export const AUTHOR = 'Aethelred Team';
export const LICENSE = 'Apache-2.0';

// Core client + configuration
export { AethelredClient } from './core/client';
export { Config, Network, type NetworkConfig } from './core/config';
export * from './core/types';
export * from './core/errors';

import { AethelredClient } from './core/client';
import type { Config } from './core/config';

export function createAethelredClient(config: Config | string = {}): AethelredClient {
  return new AethelredClient(config);
}

// Module classes (low-level access)
export { JobsModule } from './jobs';
export { SealsModule } from './seals';
export { ModelsModule } from './models';
export { ValidatorsModule } from './validators';
export { VerificationModule } from './verification';

// Developer tools
export {
  verifySealOffline,
  fingerprintSealSha256,
  canonicalizeSeal,
  parseSealInput,
} from './devtools/seal-verifier';

// Framework integrations (server-side)
export {
  withAethelredApiRoute,
  withAethelredRouteHandler,
} from './integrations/nextjs';
export {
  withAethelredMiddleware,
  withAethelredMiddleware as withAethelredNextMiddleware,
} from './integrations/nextjs-middleware';

export default {
  VERSION,
  AUTHOR,
  LICENSE,
};
