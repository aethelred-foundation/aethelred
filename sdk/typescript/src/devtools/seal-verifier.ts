import { ed25519 } from "@noble/curves/ed25519";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
import { sha256 } from "@noble/hashes/sha256";

export type SealCheckSeverity = "error" | "warning" | "info";

export interface SealVerificationCheck {
  id: string;
  severity: SealCheckSeverity;
  ok: boolean;
  message: string;
  details?: Record<string, unknown>;
}

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

export interface SealVerificationResult {
  valid: boolean;
  score: number;
  fingerprintSha256: string;
  checks: SealVerificationCheck[];
  errors: string[];
  warnings: string[];
  normalizedSeal: Record<string, unknown>;
  metadata: {
    validatorCount: number;
    attestedVotingPower?: number;
    totalVotingPower?: number;
    consensusBps?: number;
  };
}

export interface SealSignatureEnvelope {
  algorithm?: string;
  publicKeyHex?: string;
  publicKeyBase64?: string;
  signatureHex?: string;
  signatureBase64?: string;
  message?: "fingerprint" | "canonical-json";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeDate(value: unknown): string | undefined {
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (typeof value === "string") {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed.toISOString();
    }
  }
  return undefined;
}

function normalizeValue(value: unknown): unknown {
  if (value === undefined) return undefined;
  if (value === null) return null;
  const asDate = normalizeDate(value);
  if (asDate) return asDate;
  if (Array.isArray(value)) {
    return value.map(normalizeValue);
  }
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const normalized = normalizeValue(value[key]);
      if (normalized !== undefined) {
        out[key] = normalized;
      }
    }
    return out;
  }
  return value;
}

export function parseSealInput(input: string | Record<string, unknown>): Record<string, unknown> {
  const parsed = typeof input === "string" ? JSON.parse(input) : input;
  if (!isRecord(parsed)) {
    throw new Error("Seal input must be a JSON object");
  }

  if (isRecord(parsed.seal)) {
    return parsed.seal;
  }
  return parsed;
}

export function canonicalizeSeal(seal: Record<string, unknown>): string {
  return JSON.stringify(normalizeValue(seal));
}

export function fingerprintSealSha256(seal: Record<string, unknown>): string {
  const canonical = canonicalizeSeal(seal);
  return `0x${bytesToHex(sha256(utf8ToBytes(canonical)))}`;
}

function decodeSigBytes(valueHex?: string, valueBase64?: string): Uint8Array | null {
  if (valueHex) {
    const trimmed = valueHex.startsWith("0x") ? valueHex.slice(2) : valueHex;
    return hexToBytes(trimmed);
  }
  if (valueBase64) {
    if (typeof Buffer !== "undefined") {
      return Uint8Array.from(Buffer.from(valueBase64, "base64"));
    }
    const binary = atob(valueBase64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      out[i] = binary.charCodeAt(i);
    }
    return out;
  }
  return null;
}

function verifyEd25519Signature(
  envelope: SealSignatureEnvelope,
  fingerprintHex: string,
  canonicalJson: string,
): { ok: boolean; message: string } {
  const publicKey = decodeSigBytes(envelope.publicKeyHex, envelope.publicKeyBase64);
  const signature = decodeSigBytes(envelope.signatureHex, envelope.signatureBase64);
  if (!publicKey || !signature) {
    return { ok: false, message: "Missing public key or signature bytes" };
  }

  const messageMode = envelope.message ?? "fingerprint";
  const payload =
    messageMode === "canonical-json"
      ? utf8ToBytes(canonicalJson)
      : hexToBytes(fingerprintHex.startsWith("0x") ? fingerprintHex.slice(2) : fingerprintHex);

  try {
    const ok = ed25519.verify(signature, payload, publicKey);
    return {
      ok,
      message: ok ? "Ed25519 signature valid" : "Ed25519 signature invalid",
    };
  } catch (error) {
    return {
      ok: false,
      message: `Ed25519 verification error: ${(error as Error).message}`,
    };
  }
}

function coerceNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function getNested(obj: Record<string, unknown>, path: string[]): unknown {
  let cur: unknown = obj;
  for (const segment of path) {
    if (!isRecord(cur) || !(segment in cur)) return undefined;
    cur = cur[segment];
  }
  return cur;
}

function collectPcr0(tee: Record<string, unknown>): string | undefined {
  const direct = tee.pcr0;
  if (typeof direct === "string" && direct.trim()) return direct;
  const pcrValues = tee.pcrValues;
  if (isRecord(pcrValues)) {
    const pcr0 = pcrValues["0"] ?? pcrValues.PCR0 ?? pcrValues.pcr0;
    if (typeof pcr0 === "string" && pcr0.trim()) return pcr0;
  }
  return undefined;
}

export function verifySealOffline(
  input: string | Record<string, unknown>,
  options: SealVerificationOptions = {},
): SealVerificationResult {
  const now = options.now ?? new Date();
  const minConsensusBps = options.minConsensusBps ?? 6700;
  const requiredValidatorCount = options.requiredValidatorCount ?? 1;
  const maxAttestationAgeMs = options.maxAttestationAgeMs ?? 24 * 60 * 60 * 1000;

  const checks: SealVerificationCheck[] = [];
  const push = (check: SealVerificationCheck) => checks.push(check);

  const seal = parseSealInput(input);
  const canonicalJson = canonicalizeSeal(seal);
  const fingerprintSha256 = `0x${bytesToHex(sha256(utf8ToBytes(canonicalJson)))}`;

  const requiredFields = [
    "id",
    "jobId",
    "modelHash",
    "inputCommitment",
    "outputCommitment",
    "status",
    "requester",
    "createdAt",
    "validators",
  ];
  for (const field of requiredFields) {
    const present = seal[field] !== undefined && seal[field] !== null;
    push({
      id: `required:${field}`,
      severity: "error",
      ok: present,
      message: present ? `Required field ${field} present` : `Missing required field ${field}`,
    });
  }

  if (options.expectedModelHash) {
    const ok = seal.modelHash === options.expectedModelHash;
    push({
      id: "binding:model-hash",
      severity: "error",
      ok,
      message: ok
        ? "Model hash matches expected value"
        : `Model hash mismatch (expected ${options.expectedModelHash})`,
      details: { actual: seal.modelHash, expected: options.expectedModelHash },
    });
  }

  if (options.expectedRequester) {
    const ok = seal.requester === options.expectedRequester;
    push({
      id: "binding:requester",
      severity: "error",
      ok,
      message: ok
        ? "Requester matches expected value"
        : `Requester mismatch (expected ${options.expectedRequester})`,
      details: { actual: seal.requester, expected: options.expectedRequester },
    });
  }

  const createdAt = normalizeDate(seal.createdAt);
  push({
    id: "timestamp:createdAt",
    severity: "error",
    ok: Boolean(createdAt),
    message: createdAt ? "createdAt is a valid timestamp" : "createdAt is not a valid timestamp",
    details: createdAt ? { createdAt } : { raw: seal.createdAt },
  });

  const expiresAt = normalizeDate(seal.expiresAt);
  if (seal.expiresAt !== undefined) {
    const ok = Boolean(expiresAt);
    push({
      id: "timestamp:expiresAt",
      severity: "error",
      ok,
      message: ok ? "expiresAt is a valid timestamp" : "expiresAt is not a valid timestamp",
    });
  }

  if (expiresAt) {
    const expired = new Date(expiresAt).getTime() <= now.getTime();
    push({
      id: "lifecycle:expiry",
      severity: expired ? "warning" : "info",
      ok: !expired,
      message: expired ? "Seal is expired" : "Seal has not expired",
      details: { expiresAt, now: now.toISOString() },
    });
  }

  const status = typeof seal.status === "string" ? seal.status : "";
  if (status) {
    const normalizedStatus = status.toLowerCase();
    const revokedAt = normalizeDate(seal.revokedAt);
    const isRevoked = normalizedStatus.includes("revoked");
    push({
      id: "status:revocation-consistency",
      severity: isRevoked ? "warning" : "info",
      ok: !isRevoked || Boolean(revokedAt || seal.revocationReason),
      message:
        !isRevoked || revokedAt || seal.revocationReason
          ? "Revocation metadata is consistent with status"
          : "Revoked seal is missing revokedAt/revocationReason metadata",
      details: { status, revokedAt, revocationReason: seal.revocationReason },
    });
  }

  const validatorsRaw = Array.isArray(seal.validators) ? seal.validators : [];
  push({
    id: "validators:present",
    severity: "error",
    ok: validatorsRaw.length >= requiredValidatorCount,
    message:
      validatorsRaw.length >= requiredValidatorCount
        ? `Validator attestations present (${validatorsRaw.length})`
        : `Insufficient validator attestations (${validatorsRaw.length} < ${requiredValidatorCount})`,
    details: { validatorCount: validatorsRaw.length, requiredValidatorCount },
  });

  let attestedVotingPower: number | undefined;
  let totalVotingPower: number | undefined;
  let consensusBps: number | undefined;

  if (validatorsRaw.length > 0) {
    let allValidatorShapeOk = true;
    let signaturesPresent = 0;
    let powerSum = 0;
    for (const validator of validatorsRaw) {
      if (!isRecord(validator)) {
        allValidatorShapeOk = false;
        continue;
      }
      if (typeof validator.signature === "string" && validator.signature.trim() !== "") {
        signaturesPresent += 1;
      }
      const power = coerceNumber(validator.votingPower);
      if (power !== undefined) powerSum += power;
    }
    attestedVotingPower = powerSum > 0 ? powerSum : undefined;
    push({
      id: "validators:shape",
      severity: "error",
      ok: allValidatorShapeOk,
      message: allValidatorShapeOk
        ? "Validator attestation records are structurally valid"
        : "One or more validator attestations are malformed",
    });
    push({
      id: "validators:signatures",
      severity: signaturesPresent === validatorsRaw.length ? "info" : "warning",
      ok: signaturesPresent === validatorsRaw.length,
      message:
        signaturesPresent === validatorsRaw.length
          ? "All validator attestations include signatures"
          : `${signaturesPresent}/${validatorsRaw.length} validator attestations include signatures`,
    });
  }

  totalVotingPower =
    coerceNumber(getNested(seal, ["consensus", "totalVotingPower"])) ??
    coerceNumber(getNested(seal, ["consensus", "total_voting_power"])) ??
    coerceNumber(seal.totalVotingPower);

  const attestedOverride =
    coerceNumber(getNested(seal, ["consensus", "attestedVotingPower"])) ??
    coerceNumber(getNested(seal, ["consensus", "attested_voting_power"]));
  if (attestedOverride !== undefined) {
    attestedVotingPower = attestedOverride;
  }

  const thresholdOverride =
    coerceNumber(getNested(seal, ["consensus", "thresholdBps"])) ??
    coerceNumber(getNested(seal, ["consensus", "threshold_bps"])) ??
    coerceNumber(seal.consensusThresholdBps);

  if (thresholdOverride !== undefined) {
    consensusBps = thresholdOverride;
  } else if (attestedVotingPower !== undefined && totalVotingPower !== undefined && totalVotingPower > 0) {
    consensusBps = Math.floor((attestedVotingPower * 10000) / totalVotingPower);
  }

  if (
    attestedVotingPower !== undefined &&
    totalVotingPower !== undefined &&
    totalVotingPower > 0
  ) {
    const ok = attestedVotingPower * 10000 >= totalVotingPower * minConsensusBps;
    push({
      id: "consensus:threshold",
      severity: "error",
      ok,
      message: ok
        ? `Consensus threshold met (${((attestedVotingPower / totalVotingPower) * 100).toFixed(2)}%)`
        : `Consensus threshold not met (${((attestedVotingPower / totalVotingPower) * 100).toFixed(2)}% < ${(minConsensusBps / 100).toFixed(2)}%)`,
      details: {
        attestedVotingPower,
        totalVotingPower,
        minConsensusBps,
      },
    });
  } else {
    push({
      id: "consensus:threshold",
      severity: "warning",
      ok: false,
      message: "Total voting power unavailable; consensus threshold could not be verified offline",
      details: { attestedVotingPower, totalVotingPower, minConsensusBps },
    });
  }

  if (isRecord(seal.teeAttestation)) {
    const tee = seal.teeAttestation;
    const attestationTs = normalizeDate(tee.timestamp);
    push({
      id: "tee:timestamp",
      severity: "error",
      ok: Boolean(attestationTs),
      message: attestationTs
        ? "TEE attestation timestamp is valid"
        : "TEE attestation timestamp is invalid",
    });

    if (attestationTs) {
      const ageMs = Math.max(0, now.getTime() - new Date(attestationTs).getTime());
      push({
        id: "tee:freshness",
        severity: ageMs > maxAttestationAgeMs ? "warning" : "info",
        ok: ageMs <= maxAttestationAgeMs,
        message:
          ageMs <= maxAttestationAgeMs
            ? "TEE attestation is within freshness window"
            : `TEE attestation is stale (${Math.round(ageMs / 1000)}s old)`,
        details: { ageMs, maxAttestationAgeMs },
      });
    }

    const enclaveHash = typeof tee.enclaveHash === "string" ? tee.enclaveHash : undefined;
    if (options.trustedEnclaveHashes?.length) {
      const ok = Boolean(enclaveHash && options.trustedEnclaveHashes.includes(enclaveHash));
      push({
        id: "tee:trusted-enclave",
        severity: "error",
        ok,
        message: ok
          ? "TEE enclave hash matches trusted allowlist"
          : "TEE enclave hash is not in trusted allowlist",
        details: { enclaveHash, trustedEnclaveHashes: options.trustedEnclaveHashes },
      });
    }

    const pcr0 = collectPcr0(tee);
    if (options.trustedPcr0Values?.length) {
      const ok = Boolean(pcr0 && options.trustedPcr0Values.includes(pcr0));
      push({
        id: "tee:trusted-pcr0",
        severity: "error",
        ok,
        message: ok ? "TEE PCR0 matches trusted allowlist" : "TEE PCR0 is not trusted",
        details: { pcr0, trustedPcr0Values: options.trustedPcr0Values },
      });
    }

    if (options.requireTeeNonce) {
      const nonce = typeof tee.nonce === "string" ? tee.nonce : undefined;
      push({
        id: "tee:nonce",
        severity: "error",
        ok: Boolean(nonce),
        message: nonce ? "TEE attestation nonce present" : "TEE attestation nonce missing",
      });
    }
  } else {
    push({
      id: "tee:presence",
      severity: "warning",
      ok: false,
      message: "TEE attestation missing from seal payload",
    });
  }

  const signatures = Array.isArray(seal.signatures) ? seal.signatures : [];
  if (signatures.length > 0) {
    let anyValid = false;
    for (let idx = 0; idx < signatures.length; idx += 1) {
      const sig = signatures[idx];
      if (!isRecord(sig)) {
        push({
          id: `signature:${idx}`,
          severity: "warning",
          ok: false,
          message: "Signature entry is malformed",
        });
        continue;
      }
      const algorithm = typeof sig.algorithm === "string" ? sig.algorithm.toLowerCase() : "ed25519";
      if (algorithm !== "ed25519") {
        push({
          id: `signature:${idx}`,
          severity: "warning",
          ok: false,
          message: `Unsupported signature algorithm: ${sig.algorithm}`,
        });
        continue;
      }
      const verification = verifyEd25519Signature(sig as SealSignatureEnvelope, fingerprintSha256, canonicalJson);
      if (verification.ok) anyValid = true;
      push({
        id: `signature:${idx}`,
        severity: verification.ok ? "info" : "warning",
        ok: verification.ok,
        message: verification.message,
      });
    }
    push({
      id: "signature:any-valid",
      severity: "warning",
      ok: anyValid,
      message: anyValid
        ? "At least one offline signature verified"
        : "No offline signatures verified successfully",
    });
  }

  const errors = checks.filter((c) => c.severity === "error" && !c.ok).map((c) => c.message);
  const warnings = checks.filter((c) => c.severity === "warning" && !c.ok).map((c) => c.message);

  // Weighted score intended for developer diagnostics, not protocol consensus.
  let score = 100;
  for (const check of checks) {
    if (check.ok) continue;
    if (check.severity === "error") score -= 25;
    else if (check.severity === "warning") score -= 8;
    else score -= 2;
  }
  score = Math.max(0, Math.min(100, score));

  return {
    valid: errors.length === 0,
    score,
    fingerprintSha256,
    checks,
    errors,
    warnings,
    normalizedSeal: seal,
    metadata: {
      validatorCount: Array.isArray(seal.validators) ? seal.validators.length : 0,
      attestedVotingPower,
      totalVotingPower,
      consensusBps,
    },
  };
}
