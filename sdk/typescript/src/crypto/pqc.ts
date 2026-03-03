/**
 * Post-Quantum Cryptography (PQC) module for Aethelred TypeScript SDK.
 *
 * This module provides browser-compatible post-quantum cryptographic operations
 * using NIST-standardized algorithms:
 * - ML-KEM (Kyber) for key encapsulation
 * - ML-DSA (Dilithium) for digital signatures
 *
 * Note: Browser PQC support is limited. This module provides:
 * 1. Native implementations where available
 * 2. WASM-based fallbacks for broader compatibility
 * 3. Hybrid schemes combining classical + PQC for defense in depth
 *
 * @module crypto/pqc
 */

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * Supported PQC key encapsulation algorithms
 */
export type KEMAlgorithm = 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024' | 'Kyber512' | 'Kyber768' | 'Kyber1024';

/**
 * Supported PQC signature algorithms
 */
export type SignatureAlgorithm = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87' | 'Dilithium2' | 'Dilithium3' | 'Dilithium5';

/**
 * Security level for PQC operations
 */
export type SecurityLevel = 1 | 3 | 5;

/**
 * Key pair for KEM operations
 */
export interface KEMKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  algorithm: KEMAlgorithm;
}

/**
 * Key pair for signature operations
 */
export interface SignatureKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  algorithm: SignatureAlgorithm;
}

/**
 * Encapsulated key result
 */
export interface EncapsulationResult {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

/**
 * PQC availability status
 */
export interface PQCAvailability {
  nativeSupport: boolean;
  wasmSupport: boolean;
  availableKEMAlgorithms: KEMAlgorithm[];
  availableSignatureAlgorithms: SignatureAlgorithm[];
  configuredProvider: boolean;
}

// ============================================================================
// Constants
// ============================================================================

/**
 * Algorithm parameter sizes (in bytes)
 */
export const ALGORITHM_PARAMS = {
  // Kyber/ML-KEM parameters
  'ML-KEM-512': { publicKeySize: 800, secretKeySize: 1632, ciphertextSize: 768, sharedSecretSize: 32 },
  'ML-KEM-768': { publicKeySize: 1184, secretKeySize: 2400, ciphertextSize: 1088, sharedSecretSize: 32 },
  'ML-KEM-1024': { publicKeySize: 1568, secretKeySize: 3168, ciphertextSize: 1568, sharedSecretSize: 32 },
  'Kyber512': { publicKeySize: 800, secretKeySize: 1632, ciphertextSize: 768, sharedSecretSize: 32 },
  'Kyber768': { publicKeySize: 1184, secretKeySize: 2400, ciphertextSize: 1088, sharedSecretSize: 32 },
  'Kyber1024': { publicKeySize: 1568, secretKeySize: 3168, ciphertextSize: 1568, sharedSecretSize: 32 },

  // Dilithium/ML-DSA parameters
  'ML-DSA-44': { publicKeySize: 1312, secretKeySize: 2560, signatureSize: 2420 },
  'ML-DSA-65': { publicKeySize: 1952, secretKeySize: 4032, signatureSize: 3309 },
  'ML-DSA-87': { publicKeySize: 2592, secretKeySize: 4896, signatureSize: 4627 },
  'Dilithium2': { publicKeySize: 1312, secretKeySize: 2560, signatureSize: 2420 },
  'Dilithium3': { publicKeySize: 1952, secretKeySize: 4032, signatureSize: 3309 },
  'Dilithium5': { publicKeySize: 2592, secretKeySize: 4896, signatureSize: 4627 },
} as const;

/**
 * Map security levels to algorithms
 */
export const SECURITY_LEVEL_MAP: Record<SecurityLevel, { kem: KEMAlgorithm; sig: SignatureAlgorithm }> = {
  1: { kem: 'ML-KEM-512', sig: 'ML-DSA-44' },
  3: { kem: 'ML-KEM-768', sig: 'ML-DSA-65' },
  5: { kem: 'ML-KEM-1024', sig: 'ML-DSA-87' },
};

// ============================================================================
// PQC Provider Interface
// ============================================================================

/**
 * Interface for PQC implementations
 */
export interface PQCProvider {
  // KEM operations
  kemKeypair(algorithm: KEMAlgorithm): Promise<KEMKeyPair>;
  encapsulate(publicKey: Uint8Array, algorithm: KEMAlgorithm): Promise<EncapsulationResult>;
  decapsulate(secretKey: Uint8Array, ciphertext: Uint8Array, algorithm: KEMAlgorithm): Promise<Uint8Array>;

  // Signature operations
  signKeypair(algorithm: SignatureAlgorithm): Promise<SignatureKeyPair>;
  sign(message: Uint8Array, secretKey: Uint8Array, algorithm: SignatureAlgorithm): Promise<Uint8Array>;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array, algorithm: SignatureAlgorithm): Promise<boolean>;
}

// ============================================================================
// Browser-Compatible PQC Implementation
// ============================================================================

export class PQCImplementationUnavailableError extends Error {
  constructor(operation: string) {
    super(
      `PQC operation "${operation}" is unavailable: no production PQC backend is configured. ` +
        `Inject a WASM/native provider (for example liboqs-js) before calling this API.`
    );
    this.name = 'PQCImplementationUnavailableError';
  }
}

/**
 * Browser-compatible PQC provider facade.
 *
 * SECURITY: This class intentionally fails closed unless a real PQC backend is
 * injected. The SDK no longer generates demo signatures or accepts placeholder
 * verification results.
 */
class BrowserPQCProvider implements PQCProvider {
  private initialized = false;
  private backend: PQCProvider | null = null;

  setBackend(backend: PQCProvider | null): void {
    this.backend = backend;
    this.initialized = false;
  }

  hasBackend(): boolean {
    return this.backend !== null;
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;

    this.initialized = true;
  }

  private requireBackend(operation: string): PQCProvider {
    if (!this.backend) {
      throw new PQCImplementationUnavailableError(operation);
    }
    return this.backend;
  }

  async kemKeypair(algorithm: KEMAlgorithm): Promise<KEMKeyPair> {
    await this.initialize();
    return this.requireBackend('kemKeypair').kemKeypair(algorithm);
  }

  async encapsulate(publicKey: Uint8Array, algorithm: KEMAlgorithm): Promise<EncapsulationResult> {
    await this.initialize();
    return this.requireBackend('encapsulate').encapsulate(publicKey, algorithm);
  }

  async decapsulate(secretKey: Uint8Array, ciphertext: Uint8Array, algorithm: KEMAlgorithm): Promise<Uint8Array> {
    await this.initialize();
    return this.requireBackend('decapsulate').decapsulate(secretKey, ciphertext, algorithm);
  }

  async signKeypair(algorithm: SignatureAlgorithm): Promise<SignatureKeyPair> {
    await this.initialize();
    return this.requireBackend('signKeypair').signKeypair(algorithm);
  }

  async sign(message: Uint8Array, secretKey: Uint8Array, algorithm: SignatureAlgorithm): Promise<Uint8Array> {
    await this.initialize();
    return this.requireBackend('sign').sign(message, secretKey, algorithm);
  }

  async verify(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
    algorithm: SignatureAlgorithm
  ): Promise<boolean> {
    await this.initialize();
    return this.requireBackend('verify').verify(message, signature, publicKey, algorithm);
  }
}

// ============================================================================
// Hybrid Cryptography (Classical + PQC)
// ============================================================================

/**
 * Hybrid key encapsulation combining X25519 + Kyber
 */
export interface HybridKEMResult {
  classicalCiphertext: Uint8Array;
  pqcCiphertext: Uint8Array;
  combinedSharedSecret: Uint8Array;
}

/**
 * Hybrid signature combining Ed25519 + Dilithium
 */
export interface HybridSignature {
  classicalSignature: Uint8Array;
  pqcSignature: Uint8Array;
}

/**
 * Hybrid cryptography provider for defense in depth
 */
export class HybridCrypto {
  private pqc: PQCProvider;

  constructor(pqcProvider: PQCProvider = getPQCProvider()) {
    this.pqc = pqcProvider;
  }

  /**
   * Generate hybrid key pair (X25519 + Kyber)
   */
  async generateHybridKEMKeyPair(securityLevel: SecurityLevel = 3): Promise<{
    classical: CryptoKeyPair;
    pqc: KEMKeyPair;
  }> {
    const kemAlgorithm = SECURITY_LEVEL_MAP[securityLevel].kem;

    // Generate classical ECDH key pair
    const classical = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );

    // Generate PQC KEM key pair
    const pqc = await this.pqc.kemKeypair(kemAlgorithm);

    return { classical, pqc };
  }

  /**
   * Perform hybrid key encapsulation
   */
  async hybridEncapsulate(
    classicalPublicKey: CryptoKey,
    pqcPublicKey: Uint8Array,
    securityLevel: SecurityLevel = 3
  ): Promise<HybridKEMResult> {
    const kemAlgorithm = SECURITY_LEVEL_MAP[securityLevel].kem;

    // Classical ECDH
    const ephemeralKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );

    const classicalSharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: classicalPublicKey },
      ephemeralKeyPair.privateKey,
      256
    );

    const classicalCiphertext = await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey);

    // PQC KEM
    const pqcResult = await this.pqc.encapsulate(pqcPublicKey, kemAlgorithm);

    // Combine shared secrets using HKDF
    const combinedInput = new Uint8Array(classicalSharedBits.byteLength + pqcResult.sharedSecret.length);
    combinedInput.set(new Uint8Array(classicalSharedBits));
    combinedInput.set(pqcResult.sharedSecret, classicalSharedBits.byteLength);

    const combinedKey = await crypto.subtle.importKey(
      'raw',
      combinedInput,
      { name: 'HKDF' },
      false,
      ['deriveBits']
    );

    const combinedSharedSecret = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('aethelred-hybrid-kem') },
      combinedKey,
      256
    );

    return {
      classicalCiphertext: new Uint8Array(classicalCiphertext),
      pqcCiphertext: pqcResult.ciphertext,
      combinedSharedSecret: new Uint8Array(combinedSharedSecret),
    };
  }

  /**
   * Generate hybrid signature key pair (ECDSA + Dilithium)
   */
  async generateHybridSignatureKeyPair(securityLevel: SecurityLevel = 3): Promise<{
    classical: CryptoKeyPair;
    pqc: SignatureKeyPair;
  }> {
    const sigAlgorithm = SECURITY_LEVEL_MAP[securityLevel].sig;

    // Generate classical ECDSA key pair
    const classical = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    // Generate PQC signature key pair
    const pqc = await this.pqc.signKeypair(sigAlgorithm);

    return { classical, pqc };
  }

  /**
   * Create hybrid signature (ECDSA + Dilithium)
   */
  async hybridSign(
    message: Uint8Array,
    classicalPrivateKey: CryptoKey,
    pqcSecretKey: Uint8Array,
    securityLevel: SecurityLevel = 3
  ): Promise<HybridSignature> {
    const sigAlgorithm = SECURITY_LEVEL_MAP[securityLevel].sig;

    // Classical ECDSA signature
    const classicalSignature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      classicalPrivateKey,
      message
    );

    // PQC signature
    const pqcSignature = await this.pqc.sign(message, pqcSecretKey, sigAlgorithm);

    return {
      classicalSignature: new Uint8Array(classicalSignature),
      pqcSignature,
    };
  }

  /**
   * Verify hybrid signature
   */
  async hybridVerify(
    message: Uint8Array,
    signature: HybridSignature,
    classicalPublicKey: CryptoKey,
    pqcPublicKey: Uint8Array,
    securityLevel: SecurityLevel = 3
  ): Promise<{ classicalValid: boolean; pqcValid: boolean; bothValid: boolean }> {
    const sigAlgorithm = SECURITY_LEVEL_MAP[securityLevel].sig;

    // Verify classical signature
    const classicalValid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      classicalPublicKey,
      signature.classicalSignature,
      message
    );

    // Verify PQC signature
    const pqcValid = await this.pqc.verify(message, signature.pqcSignature, pqcPublicKey, sigAlgorithm);

    return {
      classicalValid,
      pqcValid,
      bothValid: classicalValid && pqcValid,
    };
  }
}

// ============================================================================
// PQC Singleton and Utilities
// ============================================================================

let pqcProvider: BrowserPQCProvider | null = null;

/**
 * Get the PQC provider instance
 */
export function getPQCProvider(): BrowserPQCProvider {
  if (!pqcProvider) {
    pqcProvider = new BrowserPQCProvider();
  }
  return pqcProvider;
}

/**
 * Inject a production PQC backend (e.g. WASM liboqs wrapper).
 */
export function configurePQCProvider(backend: PQCProvider | null): void {
  getPQCProvider().setBackend(backend);
}

export function hasConfiguredPQCProvider(): boolean {
  return getPQCProvider().hasBackend();
}

/**
 * Check PQC availability in current environment
 */
export async function checkPQCAvailability(): Promise<PQCAvailability> {
  const availability: PQCAvailability = {
    nativeSupport: false,
    wasmSupport: hasConfiguredPQCProvider(),
    availableKEMAlgorithms: ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024', 'Kyber512', 'Kyber768', 'Kyber1024'],
    availableSignatureAlgorithms: ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'Dilithium2', 'Dilithium3', 'Dilithium5'],
    configuredProvider: hasConfiguredPQCProvider(),
  };

  // Check for native PQC support (future browsers may support this)
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    // Test if browser supports PQC algorithms natively
    // Currently no browsers support this, but it may change
    availability.nativeSupport = false;
  }

  return availability;
}

/**
 * Get recommended algorithm for a security level
 */
export function getRecommendedAlgorithms(securityLevel: SecurityLevel): { kem: KEMAlgorithm; sig: SignatureAlgorithm } {
  return SECURITY_LEVEL_MAP[securityLevel];
}

// Export default provider
export const pqc = getPQCProvider();
export const hybridCrypto = new HybridCrypto();
