# Sovereign Data

Sovereign Data is Aethelred's framework for enforcing data residency, jurisdictional compliance, and access-control constraints at the SDK level. Unlike policy-based approaches that rely on runtime checks, Aethelred's Sovereign Data containers use compile-time type enforcement and hardware-backed TEE boundaries to guarantee that data never crosses unauthorized jurisdictions.

## Core Concepts

### Jurisdiction Tags

Every piece of sovereign data carries a jurisdiction tag that specifies where it may be processed and stored:

| Tag | Description | Constraints |
|---|---|---|
| `EU-GDPR` | European Union GDPR | Must remain in EU-region enclaves; right-to-erasure supported |
| `US-ITAR` | US International Traffic in Arms | US-person access only; no export |
| `US-HIPAA` | US Health Insurance Portability | Encrypted at rest; audit logging required |
| `CN-PIPL` | China Personal Information Protection | Must remain in CN-region infrastructure |
| `GLOBAL` | No geographic restriction | May be processed anywhere |
| `CUSTOM(...)` | User-defined policy | Evaluated against custom predicate |

### Sovereign Containers

A sovereign container wraps arbitrary data with a jurisdiction tag and an encryption envelope. The SDK enforces that:

1. The data can only be decrypted inside a TEE enclave matching the jurisdiction
2. Serialization to a non-compliant destination fails at compile time (Rust) or runtime (Go, TypeScript, Python)
3. All access is logged to an append-only audit trail

## Creating Sovereign Containers

### Rust (Compile-Time Enforcement)

```rust
use aethelred_sovereign::{Sovereign, Jurisdiction, Region};

// This data is tagged EU-GDPR at the type level
let patient_data: Sovereign<PatientRecord, { Jurisdiction::EU_GDPR }> =
    Sovereign::seal(patient_record, Region::Frankfurt)?;

// Compile error: cannot send EU-GDPR data to a US region
// let _ = patient_data.export(Region::Virginia);  // ERROR at compile time

// Allowed: process within EU region
let result = patient_data.process_in(Region::Frankfurt, |data| {
    model.predict(data)
})?;
```

### Go

```go
container, err := sovereign.Seal(patientRecord, sovereign.Options{
    Jurisdiction: sovereign.EU_GDPR,
    Region:       sovereign.RegionFrankfurt,
    EncryptionKey: encryptionKey,
})
if err != nil {
    log.Fatal(err)
}

// Runtime check: panics if region is non-compliant
result, err := container.ProcessIn(sovereign.RegionFrankfurt, func(data *PatientRecord) (any, error) {
    return model.Predict(data)
})
```

### TypeScript

```typescript
const container = await Sovereign.seal(patientRecord, {
  jurisdiction: Jurisdiction.EU_GDPR,
  region: Region.Frankfurt,
});

// Throws if region is non-compliant
const result = await container.processIn(Region.Frankfurt, async (data) => {
  return model.predict(data);
});
```

## Hardware-Backed Enforcement

Sovereign containers leverage TEE enclaves to provide hardware-backed guarantees:

1. **Encryption at rest** -- container payload is encrypted with a key derived from the enclave's sealing key
2. **Decryption only inside TEE** -- the sealing key is bound to the enclave identity (MRENCLAVE for SGX, measurement for SEV-SNP)
3. **Region verification** -- the enclave's [attestation quote](/guide/tee-attestation) includes platform location metadata; the sovereign runtime validates that the enclave is in an approved region

```
┌───────────────────────────────────────────┐
│           Sovereign Container              │
│  ┌─────────────────────────────────────┐  │
│  │  Jurisdiction: EU-GDPR              │  │
│  │  Region: Frankfurt                  │  │
│  │  Encryption: AES-256-GCM           │  │
│  │  Key derivation: HKDF(sealing_key) │  │
│  │  ┌─────────────────────────────┐   │  │
│  │  │  Encrypted Payload          │   │  │
│  │  │  (only decryptable in TEE)  │   │  │
│  │  └─────────────────────────────┘   │  │
│  └─────────────────────────────────────┘  │
│  Audit log: append-only, tamper-evident    │
└───────────────────────────────────────────┘
```

## Cross-Jurisdiction Operations

Some workloads require combining data from multiple jurisdictions. Aethelred supports this through **jurisdiction intersection**:

```rust
// Both containers must be processable in the target region
let eu_data: Sovereign<_, { Jurisdiction::EU_GDPR }> = /* ... */;
let us_data: Sovereign<_, { Jurisdiction::US_HIPAA }> = /* ... */;

// Only possible in a region that satisfies BOTH EU-GDPR and US-HIPAA
// (requires a dual-compliant enclave with appropriate certifications)
let result = sovereign::join_process(
    &eu_data,
    &us_data,
    Region::DualCompliantEnclave,
    |eu, us| combined_model.predict(eu, us),
)?;
```

## Audit Trail

Every operation on a sovereign container is recorded in an append-only audit log:

```go
logs, err := container.AuditLog(ctx)
for _, entry := range logs {
    fmt.Printf("[%s] %s by %s in %s\n",
        entry.Timestamp,
        entry.Operation,   // "seal", "unseal", "process", "export"
        entry.Principal,   // Dilithium3 public key hash
        entry.Region,
    )
}
```

## Compliance Reporting

Generate compliance reports for auditors:

```bash
aethelred sovereign report \
  --jurisdiction EU-GDPR \
  --from 2026-01-01 \
  --to 2026-03-31 \
  --format pdf \
  --output q1-gdpr-report.pdf
```

The report includes:
- All sovereign containers created, accessed, or destroyed
- TEE attestation status for each access
- Any policy violations (attempted unauthorized access)
- Data residency proof (enclave location attestations)

## Related Pages

- [TEE Attestation](/guide/tee-attestation) -- hardware trust for sovereign enclaves
- [Digital Seals](/guide/digital-seals) -- seals include jurisdiction metadata
- [Key Management](/cryptography/key-management) -- encryption keys for sovereign containers
- [Security Parameters](/cryptography/security-parameters) -- encryption algorithms and key sizes
