/**
 * Seals module for Aethelred SDK.
 */

import type { AethelredClient } from '../core/client';
import {
  DigitalSeal,
  CreateSealRequest,
  CreateSealResponse,
  VerifySealResponse,
  SealStatus,
  PageRequest,
  ExportedSeal,
  EvidenceBundle,
  SealExportFormat,
} from '../core/types';

export class SealsModule {
  private readonly basePath = '/aethelred/seal/v1';

  constructor(private readonly client: AethelredClient) {}

  async create(request: CreateSealRequest): Promise<CreateSealResponse> {
    return this.client.post(`${this.basePath}/seals`, request);
  }

  async get(sealId: string): Promise<DigitalSeal> {
    const data = await this.client.get<{ seal: DigitalSeal }>(`${this.basePath}/seals/${sealId}`);
    return data.seal;
  }

  async list(options?: { requester?: string; modelHash?: string; status?: SealStatus; pagination?: PageRequest }): Promise<DigitalSeal[]> {
    const data = await this.client.get<{ seals: DigitalSeal[] }>(`${this.basePath}/seals`, options);
    return data.seals || [];
  }

  async listByModel(modelHash: string, pagination?: PageRequest): Promise<DigitalSeal[]> {
    const data = await this.client.get<{ seals: DigitalSeal[] }>(`${this.basePath}/seals/by_model`, { model_hash: hexHashToBase64(modelHash), ...pagination });
    return data.seals || [];
  }

  async verify(sealId: string): Promise<VerifySealResponse> {
    const data = await this.client.get<VerifySealResponse>(`${this.basePath}/seals/${sealId}/verify`);
    return {
      ...data,
      verificationType: data.verificationType ?? data.verification_type,
    };
  }

  async revoke(sealId: string, reason: string): Promise<boolean> {
    await this.client.post(`${this.basePath}/seals/${sealId}:revoke`, { reason });
    return true;
  }

  async export(sealId: string, format: SealExportFormat = 'json'): Promise<ExportedSeal> {
    const data = await this.client.get<{ export: ExportedSeal }>(`${this.basePath}/seals/${sealId}/export`, { format });
    return data.export;
  }

  async exportEvidenceBundle(jobId: string): Promise<EvidenceBundle> {
    const data = await this.client.get<{ evidence_bundle?: EvidenceBundle; evidenceBundle?: EvidenceBundle }>(`${this.basePath}/evidence-bundles/${jobId}`);
    const bundle = data.evidenceBundle ?? data.evidence_bundle;
    assertEvidenceBundle(bundle);
    return bundle;
  }
}

function assertEvidenceBundle(bundle: unknown): asserts bundle is EvidenceBundle {
  if (!bundle || typeof bundle !== 'object') {
    throw new Error('evidence bundle response missing evidence_bundle');
  }
  const value = bundle as Record<string, unknown>;
  const stringFields = [
    'bundle_id',
    'job_id',
    'chain_id',
    'seal_id',
    'timestamp',
    'model_hash',
    'circuit_hash',
    'verifying_key_hash',
    'validator_signature',
    'region',
    'operator',
  ];
  if (value.schema_version !== '1.0.0') {
    throw new Error('evidence bundle schema_version must be 1.0.0');
  }
  for (const field of stringFields) {
    requireNonEmptyString(value, field);
  }
  requireBase64(value.validator_signature, 'validator_signature');
  requireNumberRange(value.confidence_score, 'confidence_score', 0, 1);

  const tee = requireObject(value.tee_evidence, 'tee_evidence');
  for (const field of ['platform', 'enclave_id', 'measurement', 'quote', 'nonce']) {
    requireNonEmptyString(tee, `tee_evidence.${field}`);
  }
  requireBase64(tee.quote, 'tee_evidence.quote');

  const zkml = requireObject(value.zkml_evidence, 'zkml_evidence');
  for (const field of ['proof_system', 'proof_bytes', 'public_inputs', 'output_commitment']) {
    requireNonEmptyString(zkml, `zkml_evidence.${field}`);
  }
  requireBase64(zkml.proof_bytes, 'zkml_evidence.proof_bytes');
  requireBase64(zkml.public_inputs, 'zkml_evidence.public_inputs');

  const policy = requireObject(value.policy_decision, 'policy_decision');
  if (policy.mode !== 'hybrid' || policy.require_both !== true || policy.fallback_allowed !== false) {
    throw new Error('evidence bundle policy_decision must require hybrid/no fallback');
  }

  const archive = requireObject(value.archive_pointer, 'archive_pointer');
  for (const field of ['archive_type', 'index', 'document_id', 'uri', 'write_status']) {
    requireNonEmptyString(archive, `archive_pointer.${field}`);
  }
  requirePositiveNumber(archive.retention_days, 'archive_pointer.retention_days');

  const verification = requireObject(value.verification, 'verification');
  for (const field of [
    'schema_verified',
    'policy_verified',
    'tee_attestation_verified',
    'zkml_proof_verified',
    'digital_seal_verified',
    'live_verification_required',
  ]) {
    requireBoolean(verification, `verification.${field}`);
  }
  if (verification.schema_verified !== true || verification.policy_verified !== true) {
    throw new Error('evidence bundle verification must mark schema and policy as verified');
  }
  requireNonEmptyString(verification, 'verification.verifier_version');
}

function requireObject(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`evidence bundle missing required object: ${field}`);
  }
  return value as Record<string, unknown>;
}

function requireNonEmptyString(value: Record<string, unknown>, field: string): void {
  const key = field.includes('.') ? field.split('.').pop()! : field;
  const item = value[key];
  if (typeof item !== 'string' || item.trim() === '') {
    throw new Error(`evidence bundle missing required string: ${field}`);
  }
}

function requireBase64(value: unknown, field: string): void {
  if (typeof value !== 'string' || value.trim() === '' || !/^[A-Za-z0-9+/]+=*$/.test(value)) {
    throw new Error(`evidence bundle ${field} must be base64`);
  }
}

function requireNumberRange(value: unknown, field: string, min: number, max: number): void {
  if (typeof value !== 'number' || value < min || value > max) {
    throw new Error(`evidence bundle ${field} must be between ${min} and ${max}`);
  }
}

function requirePositiveNumber(value: unknown, field: string): void {
  if (typeof value !== 'number' || value < 1) {
    throw new Error(`evidence bundle ${field} must be positive`);
  }
}

function requireBoolean(value: Record<string, unknown>, field: string): void {
  const key = field.includes('.') ? field.split('.').pop()! : field;
  if (typeof value[key] !== 'boolean') {
    throw new Error(`evidence bundle missing required boolean: ${field}`);
  }
}

function hexHashToBase64(hash: string): string {
  const normalized = hash.startsWith('0x') ? hash.slice(2) : hash;
  if (!/^[0-9a-fA-F]+$/.test(normalized) || normalized.length % 2 !== 0) {
    throw new Error('modelHash must be a hex-encoded SHA-256 hash');
  }
  return Buffer.from(normalized, 'hex').toString('base64');
}
