# Enterprise Compliance Integration Guide

## Overview

Aethelred provides cryptographic verification of computations through TEE attestations, zero-knowledge proofs, and Digital Seals. Every computation processed by the Aethelred network produces a tamper-evident Digital Seal that binds the input, output, model identity, and execution environment into a single verifiable artifact.

This architecture enables enterprises to satisfy audit and regulatory compliance requirements across multiple frameworks:

- **SOC 2** -- Demonstrate control effectiveness with cryptographic evidence of computation integrity.
- **GDPR** -- Prove data processing occurred within authorized jurisdictions and that PII handling policies were enforced.
- **HIPAA** -- Provide verifiable audit trails for protected health information (PHI) processing.
- **CCPA** -- Document data handling practices with immutable evidence bundles.
- **PCI-DSS** -- Ensure payment-adjacent computations are attested and auditable.

Each Digital Seal contains a TEE attestation, an optional zero-knowledge proof, timestamps, and a cryptographic binding that ties all elements together. These seals can be verified independently by auditors, regulators, or automated compliance systems without requiring access to the underlying data.

---

## TEE Attestation Verification

### Supported Platforms

Aethelred validators run within Trusted Execution Environments across five hardware platforms:

| Platform | Enum Value | Description |
|---|---|---|
| AWS Nitro Enclaves | `AWS_NITRO` | Amazon Nitro Enclave attestation with PCR-based measurement |
| Intel SGX | `INTEL_SGX` | Software Guard Extensions with DCAP-based remote attestation |
| Intel TDX | `INTEL_TDX` | Trust Domain Extensions for VM-level isolation |
| AMD SEV-SNP | `AMD_SEV` | Secure Encrypted Virtualization with Secure Nested Paging |
| ARM TrustZone | `ARM_TRUSTZONE` | Hardware-backed trusted world isolation |

### How TEE Attestation Works

When a validator processes a computation, the following attestation chain is produced:

1. **Enclave Measurement** -- The validator's enclave generates a measurement hash (MRENCLAVE for SGX, PCR values for Nitro) that uniquely identifies the code running inside the trusted environment. This measurement is compared against known-good values published by the Aethelred network.

2. **Certificate Chain** -- The attestation document includes a certificate chain rooted in the hardware manufacturer's root of trust (e.g., AWS Nitro Attestation PKI, Intel SGX DCAP). Verification walks the chain from the leaf certificate to the trusted root.

3. **Nonce Freshness** -- Each attestation includes a cryptographic nonce derived from the computation request. This prevents replay attacks by binding the attestation to the specific job.

4. **Seal Binding** -- The TEE attestation is embedded in the Digital Seal alongside the input hash, output hash, and model identifier, creating an unforgeable record of the computation.

### Verification Examples

#### Python

```python
from aethelred import AethelredClient
from aethelred.verification import TEEPlatform, AttestationResult

client = AethelredClient(api_key="aeth_live_...")

# Verify a Digital Seal with full TEE attestation checking
seal_id = "seal_7f3a9b2e..."

result: AttestationResult = client.verification.verify_seal(
    seal_id=seal_id,
    expected_platform=TEEPlatform.AWS_NITRO,
    check_certificate_chain=True,
    check_nonce_freshness=True,
    max_age_seconds=3600,
)

print(f"Valid: {result.valid}")
print(f"Platform: {result.platform}")
print(f"Enclave measurement: {result.enclave_measurement}")
print(f"Certificate chain valid: {result.certificate_chain_valid}")
print(f"Nonce fresh: {result.nonce_fresh}")
print(f"Attestation timestamp: {result.attested_at}")
```

#### TypeScript

```typescript
import { AethelredClient, TEEPlatform } from '@aethelred/sdk';

const client = new AethelredClient({ apiKey: 'aeth_live_...' });

const result = await client.verification.verifySeal({
  sealId: 'seal_7f3a9b2e...',
  expectedPlatform: TEEPlatform.AWS_NITRO,
  checkCertificateChain: true,
  checkNonceFreshness: true,
  maxAgeSeconds: 3600,
});

console.log(`Valid: ${result.valid}`);
console.log(`Platform: ${result.platform}`);
console.log(`Enclave measurement: ${result.enclaveMeasurement}`);
console.log(`Certificate chain valid: ${result.certificateChainValid}`);
console.log(`Nonce fresh: ${result.nonceFresh}`);
console.log(`Attestation timestamp: ${result.attestedAt}`);
```

### Verifying Specific Platforms

You can restrict verification to a specific TEE platform:

```python
from aethelred.verification import TEEPlatform

# Verify only if the computation ran on Intel SGX
result = client.verification.verify_seal(
    seal_id=seal_id,
    expected_platform=TEEPlatform.INTEL_SGX,
)

# Verify only if the computation ran on AMD SEV-SNP
result = client.verification.verify_seal(
    seal_id=seal_id,
    expected_platform=TEEPlatform.AMD_SEV,
)
```

---

## Zero-Knowledge ML Proofs

### Supported Proof Systems

Aethelred supports three zero-knowledge proof systems for verifying computation correctness without revealing the underlying data:

| Proof System | Use Case | Verification Time | Proof Size |
|---|---|---|---|
| **Halo2** | General-purpose circuits, recursive proofs | ~200ms | ~5 KB |
| **Groth16** | Constant-size proofs, fast verification | ~10ms | ~128 bytes |
| **PLONK** | Universal trusted setup, flexible circuits | ~150ms | ~2 KB |

### How zkML Proofs Work

Zero-knowledge ML (zkML) proofs allow a verifier to confirm that a specific computation was performed correctly on specific inputs, without the verifier seeing the inputs or the model weights.

1. The validator executes the computation inside the TEE.
2. A zkML circuit generates a proof that the output is the correct result of applying the model to the given input.
3. The proof is attached to the Digital Seal.
4. Any party holding the seal can verify the proof against the public verification key.

This is particularly important for compliance scenarios where the data itself is sensitive (e.g., PHI under HIPAA, personal data under GDPR) but regulators need assurance that processing was performed correctly.

### Verification Examples

#### Python

```python
from aethelred import AethelredClient
from aethelred.verification import ProofSystem

client = AethelredClient(api_key="aeth_live_...")

# Verify a seal that includes a zkML proof
result = client.verification.verify_seal(
    seal_id="seal_7f3a9b2e...",
    verify_zkml_proof=True,
    expected_proof_system=ProofSystem.HALO2,
)

print(f"Proof valid: {result.zkml_proof_valid}")
print(f"Proof system: {result.proof_system}")
print(f"Circuit hash: {result.circuit_hash}")
print(f"Public inputs hash: {result.public_inputs_hash}")
```

#### TypeScript

```typescript
import { AethelredClient, ProofSystem } from '@aethelred/sdk';

const client = new AethelredClient({ apiKey: 'aeth_live_...' });

const result = await client.verification.verifySeal({
  sealId: 'seal_7f3a9b2e...',
  verifyZkmlProof: true,
  expectedProofSystem: ProofSystem.HALO2,
});

console.log(`Proof valid: ${result.zkmlProofValid}`);
console.log(`Proof system: ${result.proofSystem}`);
console.log(`Circuit hash: ${result.circuitHash}`);
console.log(`Public inputs hash: ${result.publicInputsHash}`);
```

---

## Regulatory Framework Support

### ComplianceFramework Enum

Aethelred provides first-class support for tagging computations with their applicable regulatory frameworks:

```python
from aethelred.compliance import ComplianceFramework

# Available frameworks
ComplianceFramework.SOC2
ComplianceFramework.GDPR
ComplianceFramework.HIPAA
ComplianceFramework.CCPA
ComplianceFramework.PCI_DSS
```

### Setting Compliance Metadata on Job Submissions

When submitting a computation job, attach compliance metadata so that the resulting Digital Seal includes the relevant regulatory context:

#### Python

```python
from aethelred import AethelredClient
from aethelred.compliance import ComplianceFramework, ComplianceMetadata

client = AethelredClient(api_key="aeth_live_...")

job = client.jobs.submit(
    model="credit-risk-v3",
    input_data={"applicant_id": "a]_12345", "income": 85000},
    compliance=ComplianceMetadata(
        frameworks=[ComplianceFramework.SOC2, ComplianceFramework.CCPA],
        data_controller="Acme Financial Inc.",
        processing_purpose="Credit risk assessment",
        retention_days=2555,
        legal_basis="legitimate_interest",
    ),
)

print(f"Job ID: {job.id}")
print(f"Seal ID: {job.seal_id}")
```

#### TypeScript

```typescript
import { AethelredClient, ComplianceFramework } from '@aethelred/sdk';

const client = new AethelredClient({ apiKey: 'aeth_live_...' });

const job = await client.jobs.submit({
  model: 'credit-risk-v3',
  inputData: { applicantId: 'ap_12345', income: 85000 },
  compliance: {
    frameworks: [ComplianceFramework.SOC2, ComplianceFramework.CCPA],
    dataController: 'Acme Financial Inc.',
    processingPurpose: 'Credit risk assessment',
    retentionDays: 2555,
    legalBasis: 'legitimate_interest',
  },
});

console.log(`Job ID: ${job.id}`);
console.log(`Seal ID: ${job.sealId}`);
```

### How Seals Satisfy Audit Requirements

Each Digital Seal produced by a compliance-tagged job includes:

- **Framework tags** that identify which regulations apply.
- **Data controller identity** linking the seal to the responsible organization.
- **Processing purpose** documenting why the computation was performed.
- **TEE attestation** proving the computation ran in a secure enclave.
- **Timestamp** from a trusted time source, providing non-repudiable evidence of when processing occurred.
- **Optional zkML proof** demonstrating computation correctness without revealing the data.

Auditors can verify any seal independently using the Aethelred SDK or the `seal-verifier` CLI tool.

---

## Sovereign Data Zones

### Jurisdiction Handling

Aethelred enforces data residency constraints by routing computations to validators operating within the specified jurisdiction. Three sovereign data zones are currently supported:

| Zone | Jurisdictions Covered | Validator Regions |
|---|---|---|
| `EU` | European Union, EEA, UK | Frankfurt, Amsterdam, Dublin, London |
| `US` | United States | Virginia, Oregon, Ohio |
| `APAC` | Asia-Pacific | Tokyo, Singapore, Sydney |

### Data Residency Enforcement via Validator Selection

When a jurisdiction is specified on a job submission, the Aethelred network's job router ensures:

1. The computation is assigned only to validators physically located within the specified zone.
2. Input data is encrypted in transit and never leaves the zone boundary.
3. The Digital Seal records the jurisdiction in which the computation was executed.
4. Attestation documents include the validator's geographic binding.

### Specifying Jurisdiction in Job Submissions

#### Python

```python
from aethelred import AethelredClient
from aethelred.compliance import ComplianceFramework, ComplianceMetadata, Jurisdiction

client = AethelredClient(api_key="aeth_live_...")

job = client.jobs.submit(
    model="gdpr-classifier-v2",
    input_data={"user_id": "eu_98765", "text": "..."},
    compliance=ComplianceMetadata(
        frameworks=[ComplianceFramework.GDPR],
        jurisdiction=Jurisdiction.EU,
        data_controller="EuroTech GmbH",
        processing_purpose="Content classification",
        legal_basis="consent",
    ),
)

# The seal will record that computation occurred within the EU zone
print(f"Jurisdiction: {job.jurisdiction}")
print(f"Validator region: {job.validator_region}")
```

#### TypeScript

```typescript
import {
  AethelredClient,
  ComplianceFramework,
  Jurisdiction,
} from '@aethelred/sdk';

const client = new AethelredClient({ apiKey: 'aeth_live_...' });

const job = await client.jobs.submit({
  model: 'gdpr-classifier-v2',
  inputData: { userId: 'eu_98765', text: '...' },
  compliance: {
    frameworks: [ComplianceFramework.GDPR],
    jurisdiction: Jurisdiction.EU,
    dataController: 'EuroTech GmbH',
    processingPurpose: 'Content classification',
    legalBasis: 'consent',
  },
});

console.log(`Jurisdiction: ${job.jurisdiction}`);
console.log(`Validator region: ${job.validatorRegion}`);
```

---

## Evidence Bundles

### What an Evidence Bundle Contains

An evidence bundle is a self-contained, portable archive that encapsulates all cryptographic evidence for a given computation. It is designed to be handed to auditors, regulators, or automated compliance systems.

Each bundle includes:

| Component | Description |
|---|---|
| **TEE Attestation** | Full attestation document from the hardware platform, including the certificate chain |
| **zkML Proof** | Zero-knowledge proof of computation correctness (if enabled) |
| **Digital Seal** | The signed seal binding input hash, output hash, model ID, and attestation |
| **Timestamps** | Trusted timestamps from the Aethelred network's time oracle |
| **Compliance Metadata** | Framework tags, jurisdiction, data controller, processing purpose |
| **Verification Key** | Public key needed to verify the seal signature |

### Exporting Evidence Bundles

#### Python

```python
from aethelred import AethelredClient

client = AethelredClient(api_key="aeth_live_...")

# Export a single evidence bundle
bundle = client.evidence.export_bundle(
    seal_id="seal_7f3a9b2e...",
    format="json",
    include_certificate_chain=True,
    include_zkml_proof=True,
)

# Save to file for auditor delivery
with open("evidence_bundle_seal_7f3a9b2e.json", "w") as f:
    f.write(bundle.to_json(indent=2))

# Export multiple bundles for a compliance audit
bundles = client.evidence.export_bundles(
    seal_ids=["seal_7f3a9b2e...", "seal_4c8d1e5f...", "seal_9a2b3c4d..."],
    format="json",
)

for b in bundles:
    print(f"Seal: {b.seal_id}, Valid: {b.verification_result.valid}")
```

#### TypeScript

```typescript
import { AethelredClient } from '@aethelred/sdk';
import { writeFileSync } from 'fs';

const client = new AethelredClient({ apiKey: 'aeth_live_...' });

const bundle = await client.evidence.exportBundle({
  sealId: 'seal_7f3a9b2e...',
  format: 'json',
  includeCertificateChain: true,
  includeZkmlProof: true,
});

writeFileSync(
  'evidence_bundle_seal_7f3a9b2e.json',
  JSON.stringify(bundle, null, 2),
);
```

### Evidence Bundle JSON Schema Reference

```json
{
  "$schema": "https://schema.aethelred.io/evidence-bundle/v1",
  "version": "1.0",
  "seal_id": "seal_7f3a9b2e...",
  "created_at": "2026-04-08T12:00:00Z",
  "seal": {
    "input_hash": "sha256:a1b2c3d4...",
    "output_hash": "sha256:e5f6a7b8...",
    "model_id": "credit-risk-v3",
    "model_hash": "sha256:9c0d1e2f...",
    "signature": "ed25519:...",
    "signer_public_key": "ed25519:..."
  },
  "tee_attestation": {
    "platform": "AWS_NITRO",
    "attestation_document": "base64:...",
    "enclave_measurement": "sha384:...",
    "certificate_chain": ["base64:...", "base64:..."],
    "nonce": "hex:...",
    "attested_at": "2026-04-08T12:00:00Z"
  },
  "zkml_proof": {
    "proof_system": "HALO2",
    "proof_data": "base64:...",
    "verification_key": "base64:...",
    "circuit_hash": "sha256:...",
    "public_inputs_hash": "sha256:..."
  },
  "compliance": {
    "frameworks": ["SOC2", "CCPA"],
    "jurisdiction": "US",
    "data_controller": "Acme Financial Inc.",
    "processing_purpose": "Credit risk assessment",
    "legal_basis": "legitimate_interest"
  },
  "timestamps": {
    "job_submitted_at": "2026-04-08T11:59:58Z",
    "computation_started_at": "2026-04-08T11:59:59Z",
    "computation_completed_at": "2026-04-08T12:00:00Z",
    "seal_created_at": "2026-04-08T12:00:00Z"
  }
}
```

---

## PII Handling

### PIIScrubber Class

The Aethelred Python SDK includes a `PIIScrubber` utility that detects and redacts personally identifiable information before data is submitted for computation. This ensures sensitive data never leaves the client environment.

```python
from aethelred.privacy import PIIScrubber, PIIType, DataClassification

scrubber = PIIScrubber(
    pii_types=[
        PIIType.EMAIL,
        PIIType.PHONE,
        PIIType.SSN,
        PIIType.NAME,
        PIIType.ADDRESS,
        PIIType.CREDIT_CARD,
    ],
    replacement_strategy="token",  # Replace with deterministic tokens
)

raw_text = "Contact John Smith at john@example.com or 555-123-4567"
scrubbed = scrubber.scrub(raw_text)

print(scrubbed.text)
# Output: "Contact [NAME_1] at [EMAIL_1] or [PHONE_1]"

print(scrubbed.pii_detected)
# Output: [PIIDetection(type=NAME, ...), PIIDetection(type=EMAIL, ...), ...]

# Restore original values after computation (client-side only)
restored = scrubber.restore(scrubbed.text, scrubbed.token_map)
print(restored)
# Output: "Contact John Smith at john@example.com or 555-123-4567"
```

### PIIType Enum

| Value | Description |
|---|---|
| `PIIType.EMAIL` | Email addresses |
| `PIIType.PHONE` | Phone numbers (domestic and international formats) |
| `PIIType.SSN` | Social Security Numbers |
| `PIIType.NAME` | Personal names |
| `PIIType.ADDRESS` | Physical addresses |
| `PIIType.CREDIT_CARD` | Credit and debit card numbers |

### DataClassification

Tag data with its sensitivity level to enforce appropriate handling policies:

```python
from aethelred.privacy import DataClassification

# Available classification levels
DataClassification.PUBLIC       # No restrictions
DataClassification.INTERNAL     # Organization-internal only
DataClassification.CONFIDENTIAL # Restricted access, encrypted at rest
DataClassification.RESTRICTED   # Maximum protection, jurisdiction-bound
```

#### Using DataClassification with Job Submissions

```python
from aethelred import AethelredClient
from aethelred.privacy import DataClassification

client = AethelredClient(api_key="aeth_live_...")

job = client.jobs.submit(
    model="medical-triage-v1",
    input_data={"patient_notes": "..."},
    data_classification=DataClassification.RESTRICTED,
    compliance=ComplianceMetadata(
        frameworks=[ComplianceFramework.HIPAA],
        jurisdiction=Jurisdiction.US,
        data_controller="HealthFirst Inc.",
        processing_purpose="Patient triage classification",
    ),
)
```

When `DataClassification.RESTRICTED` is set, the network enforces:

- Computation runs only on validators with the highest security tier.
- All data is encrypted end-to-end with keys held only by the submitting client.
- Audit logs record access but never the data itself.
- Automatic PII scrubbing is applied if not already performed.

---

## Audit Trail Generation

### Using Seal Verification for Audit-Ready Reports

The Aethelred SDK can generate structured audit reports from verified seals:

#### Python

```python
from aethelred import AethelredClient
from aethelred.compliance import AuditReportGenerator, ComplianceFramework

client = AethelredClient(api_key="aeth_live_...")

generator = AuditReportGenerator(client)

# Generate a compliance report for a date range
report = generator.generate(
    frameworks=[ComplianceFramework.SOC2, ComplianceFramework.HIPAA],
    start_date="2026-01-01",
    end_date="2026-03-31",
    include_seal_details=True,
    include_evidence_summaries=True,
)

print(f"Total computations: {report.total_computations}")
print(f"Valid seals: {report.valid_seals}")
print(f"Invalid seals: {report.invalid_seals}")
print(f"Frameworks covered: {report.frameworks}")

# Export as PDF for auditors
report.export_pdf("q1_2026_compliance_report.pdf")

# Export as JSON for automated systems
report.export_json("q1_2026_compliance_report.json")
```

#### TypeScript

```typescript
import { AethelredClient, ComplianceFramework } from '@aethelred/sdk';

const client = new AethelredClient({ apiKey: 'aeth_live_...' });

const report = await client.compliance.generateReport({
  frameworks: [ComplianceFramework.SOC2, ComplianceFramework.HIPAA],
  startDate: '2026-01-01',
  endDate: '2026-03-31',
  includeSealDetails: true,
  includeEvidenceSummaries: true,
});

console.log(`Total computations: ${report.totalComputations}`);
console.log(`Valid seals: ${report.validSeals}`);
console.log(`Invalid seals: ${report.invalidSeals}`);
```

### Offline Verification with `seal-verifier` CLI

The `seal-verifier` command-line tool allows verification without network access, using only the evidence bundle and public verification keys:

```bash
# Install the CLI
pip install aethelred-cli

# Verify a single seal from an evidence bundle
seal-verifier verify evidence_bundle_seal_7f3a9b2e.json

# Output:
# Seal ID:            seal_7f3a9b2e...
# Status:             VALID
# Platform:           AWS_NITRO
# Enclave:            sha384:...
# Certificate chain:  VALID (3 certs, root: AWS Nitro CA)
# zkML proof:         VALID (HALO2)
# Timestamp:          2026-04-08T12:00:00Z
# Frameworks:         SOC2, CCPA

# Verify with explicit root CA certificate
seal-verifier verify evidence_bundle.json --ca-cert aws_nitro_root.pem

# Output machine-readable JSON
seal-verifier verify evidence_bundle.json --output json
```

### Batch Verification for Compliance Audits

When auditing large numbers of computations, use batch verification:

```bash
# Verify all evidence bundles in a directory
seal-verifier batch-verify ./evidence_bundles/ --output report.json

# Filter by framework
seal-verifier batch-verify ./evidence_bundles/ \
  --framework SOC2 \
  --output soc2_audit.json

# Filter by date range
seal-verifier batch-verify ./evidence_bundles/ \
  --after 2026-01-01 \
  --before 2026-04-01 \
  --output q1_audit.json
```

#### Programmatic Batch Verification in Python

```python
from aethelred import AethelredClient
from aethelred.verification import BatchVerifier

client = AethelredClient(api_key="aeth_live_...")

verifier = BatchVerifier(client)

# Verify all seals from a list of IDs
results = verifier.verify_batch(
    seal_ids=["seal_7f3a...", "seal_4c8d...", "seal_9a2b..."],
    check_certificate_chain=True,
    check_nonce_freshness=True,
    verify_zkml_proof=True,
)

for r in results:
    status = "PASS" if r.valid else "FAIL"
    print(f"[{status}] {r.seal_id} -- {r.platform} -- {r.proof_system}")

# Summary
print(f"\nTotal: {results.total}")
print(f"Passed: {results.passed}")
print(f"Failed: {results.failed}")
```

### Generating Compliance Reports

Combine seal verification with compliance metadata to produce framework-specific audit documentation:

```python
from aethelred.compliance import ComplianceReporter, ComplianceFramework

reporter = ComplianceReporter(client)

# SOC 2 Type II report
soc2_report = reporter.generate_soc2_report(
    start_date="2026-01-01",
    end_date="2026-03-31",
    control_objectives=["CC6.1", "CC6.6", "CC7.1", "CC7.2"],
)

# HIPAA compliance evidence
hipaa_report = reporter.generate_hipaa_report(
    start_date="2026-01-01",
    end_date="2026-03-31",
    covered_entity="HealthFirst Inc.",
)

# GDPR data processing record (Article 30)
gdpr_report = reporter.generate_gdpr_article30_report(
    start_date="2026-01-01",
    end_date="2026-03-31",
    data_controller="EuroTech GmbH",
    jurisdiction=Jurisdiction.EU,
)
```

---

## Further Resources

- [Aethelred SDK Reference](../api/rust/index.md) -- Full API documentation
- [Network Guide](../site/docs/guide/network.md) -- Validator network architecture
- [TEE Overview](../../frontend/website/io/tee.html) -- Trusted Execution Environment explainer
- [Tokenomics](../TOKENOMICS.md) -- Network economics and staking
