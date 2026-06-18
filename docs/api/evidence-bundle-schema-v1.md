# Enterprise Evidence Bundle Schema v1

> **Schema Version**: 1.0.0
> **Status**: Canonical
> **Consumers**: SQ08 (Bundle Builder), SQ09 (Bundle Validator), SQ17 (Audit Trail), SQ20 (Compliance Reporter)

## Overview

Every enterprise hybrid job on the Aethelred network produces an **evidence bundle** -- a self-contained, cryptographically-bound record that proves a specific AI inference was executed inside a TEE and verified by a zkML proof system. The bundle is the atomic unit of auditability for enterprise compliance.

Evidence bundles are produced by validators after completing Proof-of-Useful-Work (PoUW) jobs and are stored both on-chain (hash commitment) and off-chain (full bundle in object storage or IPFS).

## Field Reference

### Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | `string` | yes | Schema version. Must be `"1.0.0"` for this version. |
| `bundle_id` | `string` | yes | Unique bundle identifier (UUID v4). |
| `job_id` | `string` | yes | On-chain job identifier (hex-encoded transaction hash). |
| `chain_id` | `string` | yes | Aethelred chain identifier for the evidence-producing network. |
| `seal_id` | `string` | yes | Digital Seal identifier linked to this evidence bundle. |
| `timestamp` | `string` (ISO 8601) | yes | Bundle creation time in UTC. Must include timezone designator `Z`. |
| `model_hash` | `string` (hex, 64 chars) | yes | SHA-256 hash of model weights used for inference. |
| `circuit_hash` | `string` (hex, 64 chars) | yes | SHA-256 hash of the zkML circuit definition. |
| `verifying_key_hash` | `string` (hex, 64 chars) | yes | SHA-256 hash of the verifying key. |
| `validator_signature` | `string` (base64) | yes | Validator/operator signature carried on the accepted evidence transcript, such as the primary TEE attestation signature. |
| `confidence_score` | `number` | yes | Accepted-job confidence score, bounded to `[0, 1]`. |
| `tee_evidence` | `object` | yes | TEE attestation evidence. See below. |
| `zkml_evidence` | `object` | yes | zkML proof evidence. See below. |
| `region` | `string` | yes | Processing region identifier (e.g., `"us-east-1"`, `"eu-west-1"`). |
| `operator` | `string` | yes | Operator identifier (validator address, bech32-encoded). |
| `policy_decision` | `object` | yes | Policy engine output for this job. See below. |
| `archive_pointer` | `object` | yes | Retained audit archive pointer. See below. |
| `verification` | `object` | yes | Verification result flags for schema, policy, TEE, zkML, and Digital Seal checks. |
| `metadata` | `object` | no | Optional extensible metadata. Reserved for future use. |

### `tee_evidence` Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `platform` | `string` (enum) | yes | TEE platform: `"sgx"`, `"nitro"`, or `"sev-snp"`. |
| `enclave_id` | `string` | yes | Platform-specific enclave identifier. |
| `measurement` | `string` (hex) | yes | Platform measurement (MRENCLAVE for SGX, PCR values for Nitro, launch digest for SEV-SNP). |
| `quote` | `string` (base64) | yes | Raw attestation quote, base64-encoded. |
| `nonce` | `string` (hex, 64 chars) | yes | Freshness nonce (32 bytes hex-encoded) binding the quote to this specific job. |

### `zkml_evidence` Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `proof_system` | `string` (enum) | yes | Proof system: `"groth16"`, `"plonk"`, `"ezkl"`, `"halo2"`, or `"stark"`. |
| `proof_bytes` | `string` (base64) | yes | Serialized proof, base64-encoded. |
| `public_inputs` | `string` (base64) | yes | Serialized public inputs, base64-encoded. |
| `output_commitment` | `string` (hex, 64 chars) | yes | SHA-256 commitment to the inference output, binding proof to result. |

### `policy_decision` Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mode` | `string` | yes | Execution mode. Must be `"hybrid"` for enterprise bundles. |
| `require_both` | `boolean` | yes | Whether both TEE and zkML evidence are required. Must be `true` for enterprise. |
| `fallback_allowed` | `boolean` | yes | Whether fallback to single-evidence mode is permitted. Must be `false` for enterprise. |
| `policy_version` | `string` | no | Version of the policy engine that produced this decision. |

### `archive_pointer` Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `archive_type` | `string` | yes | Archive backend type, such as `"opensearch"` or `"object_storage"`. |
| `index` | `string` | yes | Logical archive index or bucket namespace. |
| `document_id` | `string` | yes | Archive document or object identifier. |
| `uri` | `string` | yes | Operator-resolvable archive URI. |
| `retention_days` | `integer` | yes | Minimum retention period for the evidence record. |
| `write_status` | `string` | yes | Archive write state, for example `"committed"` or `"pending_live_archive_write"`. |

### `verification` Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `artifact_mode` | `string` | no | Optional artifact mode, such as `"live"` or `"pretestnet_drill_fixture"`. |
| `schema_verified` | `boolean` | yes | Whether the bundle passed schema validation. Must be `true` for accepted evidence. |
| `policy_verified` | `boolean` | yes | Whether the bundle passed policy validation. Must be `true` for accepted evidence. |
| `tee_attestation_verified` | `boolean` | yes | Whether live TEE attestation verification succeeded. Drill fixtures must set this to `false` and mark live replacement required. |
| `zkml_proof_verified` | `boolean` | yes | Whether live zkML proof verification succeeded. Drill fixtures must set this to `false` and mark live replacement required. |
| `digital_seal_verified` | `boolean` | yes | Whether Digital Seal verification succeeded. Drill fixtures must set this to `false` and mark live replacement required. |
| `live_verification_required` | `boolean` | yes | Whether the artifact still requires replacement with live verification evidence. |
| `verifier_version` | `string` | yes | Version of the verifier that produced the verification status. |

## Validation Rules

### 1. Required Field Presence

All fields marked `Required: yes` must be present and non-null. An empty string (`""`) does not satisfy the requirement.

### 2. Hash Length Validation

All `hex(32)` fields (64-character hex strings representing 32-byte SHA-256 digests) must:
- Be exactly 64 characters long
- Contain only lowercase hexadecimal characters `[0-9a-f]`
- Not be the zero hash (`0000...0000`, 64 zeros)

Affected fields: `model_hash`, `circuit_hash`, `verifying_key_hash`, `tee_evidence.nonce`, `zkml_evidence.output_commitment`.

### 3. Chain, Seal, Signature, and Score Validation

- `chain_id` must be non-empty and must match the network that produced the evidence.
- `seal_id` must be non-empty and must resolve to the Digital Seal associated with `job_id`.
- `validator_signature` must be a non-empty standard base64 value.
- `confidence_score` must be present and must be a number between `0` and `1`, inclusive.

### 4. Platform Enum Validation

`tee_evidence.platform` must be one of the following exact string values:
- `"sgx"` -- Intel Software Guard Extensions
- `"nitro"` -- AWS Nitro Enclaves
- `"sev-snp"` -- AMD SEV-SNP

### 5. Proof System Enum Validation

`zkml_evidence.proof_system` must be one of the following exact string values:
- `"groth16"` -- Groth16 (EZKL, Circom)
- `"plonk"` -- PLONK (various backends)
- `"ezkl"` -- EZKL native proof format
- `"halo2"` -- Halo2 (PSE, Axiom)
- `"stark"` -- STARK (RISC Zero, Plonky2)

### 6. Timestamp Recency Rules

- `timestamp` must be a valid ISO 8601 string with UTC timezone designator `Z`.
- Format: `YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DDTHH:MM:SS.sssZ`.
- The timestamp must not be more than **5 minutes in the future** relative to the validator's clock (allows for clock skew).
- The timestamp must not be older than the block time of the job's originating transaction plus a **configurable maximum age** (default: 1 hour).
- Bundles with timestamps outside these bounds must be rejected by validators.

### 7. Base64 Encoding Rules

All base64-encoded fields (`validator_signature`, `tee_evidence.quote`, `zkml_evidence.proof_bytes`, `zkml_evidence.public_inputs`) must:
- Use standard base64 encoding (RFC 4648, Section 4).
- Decode to a non-empty byte array.
- Not exceed 10 MiB after decoding.

### 8. Archive and Verification Integrity

- `archive_pointer` must contain the backend type, index, document ID, URI, positive retention period, and write status.
- `verification.schema_verified` and `verification.policy_verified` must be `true` for accepted evidence.
- `verification.tee_attestation_verified`, `verification.zkml_proof_verified`, and `verification.digital_seal_verified` must reflect actual verifier results. Drill fixtures may set these to `false` only when `artifact_mode` clearly marks the artifact as a drill fixture and `live_verification_required` is `true`.
- `verification.verifier_version` must be non-empty.

### 9. Bundle Integrity

- The `bundle_id` must be a valid UUID v4 string.
- The `job_id` must reference an existing on-chain job.
- The `operator` must be a valid bech32-encoded address with the `aethel` prefix.
- `policy_decision.mode` must be `"hybrid"`, `require_both` must be `true`, and `fallback_allowed` must be `false`.

### 10. Bundle Signing

The `validator_signature` field is required in v1. It must be a real validator/operator signature carried on the accepted evidence transcript, such as the primary TEE attestation signature. Exporters must fail closed if no validator signature is available; they must not synthesize a digest and label it as a signature. `metadata` remains extensible and is not used as a substitute for any required audit field.

## Examples

### JSON Example

```json
{
  "schema_version": "1.0.0",
  "bundle_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "job_id": "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
  "chain_id": "aethelred-mainnet-1",
  "seal_id": "seal-01HVW2Y5T8C9P5T8M2Z3R4A6B7",
  "timestamp": "2026-03-28T14:30:00Z",
  "model_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "circuit_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "verifying_key_hash": "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
  "validator_signature": "dmFsaWRhdG9yLXNpZ25hdHVyZS1ieXRlcw==",
  "confidence_score": 0.9825,
  "tee_evidence": {
    "platform": "nitro",
    "enclave_id": "i-0abc123def456789a:enc-0def456789abc1230",
    "measurement": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
    "quote": "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBzYW1wbGUgYXR0ZXN0YXRpb24gcXVvdGUgZm9yIGRlbW9uc3RyYXRpb24gcHVycG9zZXMu",
    "nonce": "1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b"
  },
  "zkml_evidence": {
    "proof_system": "groth16",
    "proof_bytes": "eyJwaSI6eyJhIjpbIjB4MDEiLCIweDIiXSwiYiI6W1siMHgwMyIsIjB4MDQiXSxbIjB4MDUiLCIweDA2Il1dLCJjIjpbIjB4MDciLCIweDA4Il19fQ==",
    "public_inputs": "W1siMHgwMSIsIjB4MDIiLCIweDAzIl1d",
    "output_commitment": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
  },
  "region": "us-east-1",
  "operator": "aethel1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu",
  "policy_decision": {
    "mode": "hybrid",
    "require_both": true,
    "fallback_allowed": false,
    "policy_version": "1.2.0"
  },
  "archive_pointer": {
    "archive_type": "opensearch",
    "index": "aethelred-enterprise-evidence",
    "document_id": "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
    "uri": "opensearch://evidence/aethelred-enterprise-evidence/_doc/A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
    "retention_days": 365,
    "write_status": "committed"
  },
  "verification": {
    "artifact_mode": "live",
    "schema_verified": true,
    "policy_verified": true,
    "tee_attestation_verified": true,
    "zkml_proof_verified": true,
    "digital_seal_verified": true,
    "live_verification_required": false,
    "verifier_version": "enterprise-verifier-v1.0.0"
  }
}
```

### Markdown Table Example (for audit logs)

| Field | Value |
|-------|-------|
| Schema Version | 1.0.0 |
| Bundle ID | f47ac10b-58cc-4372-a567-0e02b2c3d479 |
| Job ID | A1B2C3D4...E5F6A1B2 |
| Chain ID | aethelred-mainnet-1 |
| Seal ID | seal-01HVW2Y5T8C9P5T8M2Z3R4A6B7 |
| Timestamp | 2026-03-28T14:30:00Z |
| Model Hash | 9f86d081...0f00a08 |
| Validator Signature | dmFsaWRhdG9y... |
| Confidence Score | 0.9825 |
| TEE Platform | nitro |
| Proof System | groth16 |
| Region | us-east-1 |
| Operator | aethel1qypq...lzv7xu |
| Policy Mode | hybrid (require_both=true, fallback=false) |
| Archive | opensearch/aethelred-enterprise-evidence |
| Verification | schema=true, policy=true, tee=true, zkml=true, seal=true |

## Backward Compatibility

### Pilot-Readiness Hardening Note

Version `1.0.0` was strengthened before the paid M42 pilot readiness gate to require `chain_id`, `seal_id`, `validator_signature`, `confidence_score`, `archive_pointer`, and `verification`. This was a controlled pre-stable hardening of the v1 contract, not a post-production schema break. Consumers used for paid-pilot or enterprise evidence must treat these fields as required.

### Version Bump Rules

- **Patch** (1.0.x): Documentation clarifications, example updates. No structural changes.
- **Minor** (1.x.0): Additive field additions only. New optional fields may be added. Existing fields must not change type, meaning, or validation rules. Consumers must tolerate unknown fields.
- **Major** (x.0.0): Breaking changes. Field removals, type changes, or semantic changes. Requires coordinated migration across all consumers.

### Field Addition Policy

All schema evolution is **additive only** within a major version:
- New fields must be optional (not required).
- New enum values may be added to `tee_evidence.platform` and `zkml_evidence.proof_system` in minor versions.
- Consumers must ignore unknown fields without error (forward compatibility).
- New required fields are only allowed in a new major version.
- Exception: the paid-pilot readiness hardening above is already part of the canonical `1.0.0` baseline and must not be treated as optional by current consumers.

### Deprecation Timeline

When a field is scheduled for removal:
1. **Minor version N**: Field is marked `deprecated` in documentation. A `deprecated_fields` array is added to the schema metadata.
2. **Minor version N+1** (minimum 3 months later): Producers stop populating the field. Consumers must handle its absence.
3. **Major version M**: Field is removed from the schema.

All deprecations are announced in the project changelog and communicated to downstream consumers (SQ08, SQ09, SQ17, SQ20) at least one release cycle in advance.

## Cross-References

- **SQ08** (Bundle Builder): Produces bundles conforming to this schema.
- **SQ09** (Bundle Validator): Validates bundles against the JSON Schema and the rules in this document.
- **SQ17** (Audit Trail): Indexes and stores bundles for compliance queries.
- **SQ20** (Compliance Reporter): Generates reports from stored bundles.
- **Proto definition**: `proto/aethelred/verify/` (on-chain hash commitment message types).
- **JSON Schema**: `docs/api/evidence-bundle-v1.schema.json`.
