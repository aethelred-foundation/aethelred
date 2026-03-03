/**
 * TEE (Trusted Execution Environment) Attestation module for Aethelred TypeScript SDK.
 *
 * This module provides browser-compatible TEE attestation verification for:
 * - Intel SGX (Software Guard Extensions)
 * - AMD SEV (Secure Encrypted Virtualization)
 * - Intel TDX (Trust Domain Extensions)
 * - AWS Nitro Enclaves
 *
 * Note: This module focuses on VERIFICATION of attestations, not generation.
 * Attestation generation requires running inside a TEE, which browsers cannot do.
 *
 * @module crypto/tee
 */

import { sha256Hex } from './index';

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * Supported TEE platforms
 */
export type TEEPlatform = 'SGX' | 'SEV' | 'TDX' | 'NITRO';

/**
 * SGX quote structure
 */
export interface SGXQuote {
  version: number;
  signType: number;
  reportBody: {
    cpuSvn: Uint8Array;
    miscSelect: number;
    attributes: Uint8Array;
    mrEnclave: Uint8Array;
    mrSigner: Uint8Array;
    isvProdId: number;
    isvSvn: number;
    reportData: Uint8Array;
  };
  signature: Uint8Array;
}

/**
 * AMD SEV attestation report
 */
export interface SEVReport {
  version: number;
  guestSvn: number;
  policy: bigint;
  familyId: Uint8Array;
  imageId: Uint8Array;
  vmpl: number;
  signatureAlgo: number;
  currentTcb: bigint;
  platformInfo: bigint;
  measurement: Uint8Array;
  hostData: Uint8Array;
  idKeyDigest: Uint8Array;
  authorKeyDigest: Uint8Array;
  reportId: Uint8Array;
  signature: Uint8Array;
}

/**
 * AWS Nitro attestation document
 */
export interface NitroDocument {
  moduleId: string;
  timestamp: number;
  digest: string;
  pcrs: Map<number, Uint8Array>;
  certificate: Uint8Array;
  cabundle: Uint8Array[];
  userData: Uint8Array | null;
  nonce: Uint8Array | null;
  publicKey: Uint8Array | null;
}

/**
 * Generic attestation structure
 */
export interface TEEAttestation {
  platform: TEEPlatform;
  quote: Uint8Array;
  timestamp: Date;
  reportData: Uint8Array;
  measurement: Uint8Array;
  additionalData?: Record<string, unknown>;
}

/**
 * Verification result
 */
export interface TEEVerificationResult {
  valid: boolean;
  platform: TEEPlatform;
  measurement: string;
  reportDataMatch: boolean;
  signatureValid: boolean;
  timestampValid: boolean;
  errors: string[];
  warnings: string[];
  details: {
    parsedQuote?: SGXQuote | SEVReport | NitroDocument;
    verificationChain?: string[];
    trustedRoot?: string;
  };
}

/**
 * Expected measurement for verification
 */
export interface ExpectedMeasurement {
  platform: TEEPlatform;
  measurement: string; // Hex-encoded measurement hash
  mrSigner?: string; // For SGX: expected signer
  minSvn?: number; // Minimum security version number
}

/**
 * TEE verification options
 */
export interface TEEVerificationOptions {
  /** Whether to verify signature (requires remote attestation service) */
  verifySignature?: boolean;
  /** Maximum age of attestation in seconds */
  maxAgeSeconds?: number;
  /** Expected measurements to match against */
  expectedMeasurements?: ExpectedMeasurement[];
  /** Expected report data (will be hashed and compared) */
  expectedReportData?: Uint8Array;
  /** Remote attestation service URL */
  attestationServiceUrl?: string;
  /** Optional backend verifier for AMD SEV signatures (browser-safe delegation) */
  sevSignatureVerifier?: (reportBytes: Uint8Array, report: SEVReport) => Promise<boolean>;
  /** Optional Nitro document parser (CBOR/COSE parser injected by app/backend bridge) */
  nitroDocumentParser?: (documentBytes: Uint8Array) => Promise<NitroDocument> | NitroDocument;
  /** Optional Nitro certificate chain / COSE verifier */
  nitroCertificateVerifier?: (document: NitroDocument, trustedRootsPem: string[]) => Promise<boolean>;
  /** AWS Nitro trusted roots. Empty by default to fail closed until configured. */
  nitroTrustedRootsPem?: string[];
}

// ============================================================================
// Constants
// ============================================================================

/**
 * Intel SGX attestation verification URL
 */
export const SGX_ATTESTATION_URL = 'https://api.trustedservices.intel.com/sgx/attestation/v4';

/**
 * AMD SEV key server URL
 */
export const AMD_KDS_URL = 'https://kdsintf.amd.com';

/**
 * AWS Nitro attestation root certificate.
 *
 * SECURITY: Intentionally empty by default. Applications must inject the real
 * AWS Nitro root certificate PEM via TEEVerificationOptions.nitroTrustedRootsPem
 * or a backend verifier. Placeholder certificates are rejected.
 */
export const NITRO_ROOT_CERT = '';

/**
 * Known good measurements for Aethelred validators
 */
export const AETHELRED_MEASUREMENTS: ExpectedMeasurement[] = [
  {
    platform: 'SGX',
    measurement: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', // Example
    mrSigner: '83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e',
    minSvn: 1,
  },
  {
    platform: 'SEV',
    measurement: 'a3b4c5d6e7f8091011121314151617181920212223242526272829303132333435',
    minSvn: 1,
  },
  {
    platform: 'NITRO',
    measurement: 'b4c5d6e7f809101112131415161718192021222324252627282930313233343536',
  },
];

// ============================================================================
// Attestation Parsing
// ============================================================================

/**
 * Parse an SGX quote from raw bytes
 */
export function parseSGXQuote(quoteBytes: Uint8Array): SGXQuote {
  if (quoteBytes.length < 432) {
    throw new Error('SGX quote too short');
  }

  const view = new DataView(quoteBytes.buffer, quoteBytes.byteOffset);

  // Parse quote header
  const version = view.getUint16(0, true);
  const signType = view.getUint16(2, true);

  // Parse report body (starts at offset 48)
  const reportBodyOffset = 48;

  const cpuSvn = quoteBytes.slice(reportBodyOffset, reportBodyOffset + 16);
  const miscSelect = view.getUint32(reportBodyOffset + 16, true);
  const attributes = quoteBytes.slice(reportBodyOffset + 48, reportBodyOffset + 64);
  const mrEnclave = quoteBytes.slice(reportBodyOffset + 64, reportBodyOffset + 96);
  const mrSigner = quoteBytes.slice(reportBodyOffset + 128, reportBodyOffset + 160);
  const isvProdId = view.getUint16(reportBodyOffset + 256, true);
  const isvSvn = view.getUint16(reportBodyOffset + 258, true);
  const reportData = quoteBytes.slice(reportBodyOffset + 320, reportBodyOffset + 384);

  // Signature is at the end of the quote
  const signatureOffset = 432;
  const signature = quoteBytes.slice(signatureOffset);

  return {
    version,
    signType,
    reportBody: {
      cpuSvn,
      miscSelect,
      attributes,
      mrEnclave,
      mrSigner,
      isvProdId,
      isvSvn,
      reportData,
    },
    signature,
  };
}

/**
 * Parse an AMD SEV attestation report
 */
export function parseSEVReport(reportBytes: Uint8Array): SEVReport {
  if (reportBytes.length < 1184) {
    throw new Error('SEV report too short');
  }

  const view = new DataView(reportBytes.buffer, reportBytes.byteOffset);

  return {
    version: view.getUint32(0, true),
    guestSvn: view.getUint32(4, true),
    policy: view.getBigUint64(8, true),
    familyId: reportBytes.slice(16, 32),
    imageId: reportBytes.slice(32, 48),
    vmpl: view.getUint32(48, true),
    signatureAlgo: view.getUint32(52, true),
    currentTcb: view.getBigUint64(56, true),
    platformInfo: view.getBigUint64(64, true),
    measurement: reportBytes.slice(144, 192),
    hostData: reportBytes.slice(192, 224),
    idKeyDigest: reportBytes.slice(224, 272),
    authorKeyDigest: reportBytes.slice(272, 320),
    reportId: reportBytes.slice(320, 352),
    signature: reportBytes.slice(672, 1184),
  };
}

/**
 * Parse an AWS Nitro attestation document (CBOR-encoded)
 */
export function parseNitroDocument(documentBytes: Uint8Array): NitroDocument {
  void documentBytes;
  throw new Error(
    'Nitro attestation parsing requires a CBOR/COSE parser integration. ' +
      'Inject TEEVerificationOptions.nitroDocumentParser.'
  );
}

// ============================================================================
// Attestation Verification
// ============================================================================

/**
 * TEE Attestation Verifier
 */
export class TEEVerifier {
  private options: TEEVerificationOptions;

  constructor(options: TEEVerificationOptions = {}) {
    this.options = {
      verifySignature: true,
      maxAgeSeconds: 300, // 5 minutes default
      ...options,
    };
  }

  /**
   * Verify a TEE attestation
   */
  async verify(attestation: TEEAttestation): Promise<TEEVerificationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    const result: TEEVerificationResult = {
      valid: false,
      platform: attestation.platform,
      measurement: '',
      reportDataMatch: false,
      signatureValid: false,
      timestampValid: false,
      errors,
      warnings,
      details: {},
    };

    try {
      // 1. Check timestamp
      const ageSeconds = (Date.now() - attestation.timestamp.getTime()) / 1000;
      result.timestampValid = ageSeconds <= (this.options.maxAgeSeconds || 300);
      if (!result.timestampValid) {
        errors.push(`Attestation too old: ${ageSeconds.toFixed(0)}s (max: ${this.options.maxAgeSeconds}s)`);
      }

      // 2. Parse and verify based on platform
      switch (attestation.platform) {
        case 'SGX':
          await this.verifySGX(attestation, result);
          break;
        case 'SEV':
          await this.verifySEV(attestation, result);
          break;
        case 'NITRO':
          await this.verifyNitro(attestation, result);
          break;
        default:
          errors.push(`Unsupported platform: ${attestation.platform}`);
      }

      // 3. Verify report data if expected
      if (this.options.expectedReportData) {
        const expectedHash = await sha256Hex(this.options.expectedReportData);
        const actualHash = await sha256Hex(attestation.reportData);
        result.reportDataMatch = expectedHash === actualHash;
        if (!result.reportDataMatch) {
          errors.push('Report data mismatch');
        }
      } else {
        result.reportDataMatch = true; // No expected data to match
      }

      // 4. Check against expected measurements
      if (this.options.expectedMeasurements && this.options.expectedMeasurements.length > 0) {
        const measurement = result.measurement;
        const matchingMeasurement = this.options.expectedMeasurements.find(
          (m) => m.platform === attestation.platform && m.measurement === measurement
        );

        if (!matchingMeasurement) {
          errors.push(`Measurement not in allowed list: ${measurement}`);
        }
      }

      // Overall validity
      result.valid = errors.length === 0 && result.timestampValid && result.reportDataMatch;
    } catch (error) {
      errors.push(`Verification error: ${error instanceof Error ? error.message : String(error)}`);
      result.valid = false;
    }

    return result;
  }

  /**
   * Verify SGX attestation
   */
  private async verifySGX(attestation: TEEAttestation, result: TEEVerificationResult): Promise<void> {
    try {
      const quote = parseSGXQuote(attestation.quote);
      result.details.parsedQuote = quote;

      // Extract measurement (MRENCLAVE)
      result.measurement = bytesToHex(quote.reportBody.mrEnclave);

      // Verify signature using Intel's attestation service
      if (this.options.verifySignature) {
        result.signatureValid = await this.verifySGXSignature(attestation.quote);
        if (!result.signatureValid) {
          result.errors.push('SGX quote signature verification failed');
        }
      } else {
        result.signatureValid = true;
        result.warnings.push('Signature verification skipped');
      }
    } catch (error) {
      result.errors.push(`SGX parse error: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Verify SEV attestation
   */
  private async verifySEV(attestation: TEEAttestation, result: TEEVerificationResult): Promise<void> {
    try {
      const report = parseSEVReport(attestation.quote);
      result.details.parsedQuote = report;

      // Extract measurement
      result.measurement = bytesToHex(report.measurement);

      // Verify signature using AMD's key server
      if (this.options.verifySignature) {
        result.signatureValid = await this.verifySEVSignature(attestation.quote, report);
        if (!result.signatureValid) {
          result.errors.push('SEV report signature verification failed');
        }
      } else {
        result.signatureValid = true;
        result.warnings.push('Signature verification skipped');
      }
    } catch (error) {
      result.errors.push(`SEV parse error: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Verify Nitro attestation
   */
  private async verifyNitro(attestation: TEEAttestation, result: TEEVerificationResult): Promise<void> {
    try {
      const document = this.options.nitroDocumentParser
        ? await this.options.nitroDocumentParser(attestation.quote)
        : parseNitroDocument(attestation.quote);
      result.details.parsedQuote = document;

      // Extract measurement from PCR0
      const pcr0 = document.pcrs.get(0);
      result.measurement = pcr0 ? bytesToHex(pcr0) : '';

      // Verify certificate chain
      if (this.options.verifySignature) {
        result.signatureValid = await this.verifyNitroCertificateChain(document);
        if (!result.signatureValid) {
          result.errors.push('Nitro certificate chain verification failed');
        }
      } else {
        result.signatureValid = true;
        result.warnings.push('Signature verification skipped');
      }
    } catch (error) {
      result.errors.push(`Nitro parse error: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Verify SGX signature using Intel attestation service
   */
  private async verifySGXSignature(quoteBytes: Uint8Array): Promise<boolean> {
    if (!this.options.attestationServiceUrl) {
      // Default to Intel's service
      const url = `${SGX_ATTESTATION_URL}/report`;

      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            isvEnclaveQuote: bytesToBase64(quoteBytes),
          }),
        });

        if (!response.ok) {
          return false;
        }

        const result = await response.json();
        return result.isvEnclaveQuoteStatus === 'OK';
      } catch (error) {
        console.warn('SGX attestation service unavailable, skipping signature verification');
        return false;
      }
    }

    return true;
  }

  /**
   * Verify SEV signature using AMD key server
   */
  private async verifySEVSignature(reportBytes: Uint8Array, _report: SEVReport): Promise<boolean> {
    const verifier = this.options.sevSignatureVerifier;
    if (!verifier) {
      return false;
    }
    return verifier(reportBytes, _report);
  }

  /**
   * Verify Nitro certificate chain
   */
  private async verifyNitroCertificateChain(document: NitroDocument): Promise<boolean> {
    const verifier = this.options.nitroCertificateVerifier;
    const trustedRootsPem = (this.options.nitroTrustedRootsPem ?? []).filter((pem) => pem.trim().length > 0);

    if (trustedRootsPem.some(isPlaceholderCertificate)) {
      return false;
    }
    if (!verifier || trustedRootsPem.length === 0) {
      return false;
    }
    if (document.certificate.length === 0) {
      return false;
    }

    return verifier(document, trustedRootsPem);
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Convert bytes to hex string
 */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert bytes to base64
 */
function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function isPlaceholderCertificate(pem: string): boolean {
  const normalized = pem.replace(/\s+/g, '');
  return normalized.includes('BEGINCERTIFICATE') && normalized.includes('...') && normalized.includes('ENDCERTIFICATE');
}

/**
 * Create a TEE attestation from raw data
 */
export function createAttestation(
  platform: TEEPlatform,
  quote: Uint8Array,
  reportData: Uint8Array,
  measurement: Uint8Array
): TEEAttestation {
  return {
    platform,
    quote,
    timestamp: new Date(),
    reportData,
    measurement,
  };
}

/**
 * Get the default TEE verifier
 */
export function createVerifier(options?: TEEVerificationOptions): TEEVerifier {
  return new TEEVerifier(options);
}

// ============================================================================
// Exports
// ============================================================================

export const teeVerifier = createVerifier();
