# Rust Sovereign Data API

The `aethelred-sovereign` crate provides sovereign data containers with compile-time jurisdiction enforcement. Data tagged with a jurisdiction physically cannot be processed outside approved regions.

## Import

```rust
use aethelred_sovereign::{Sovereign, Jurisdiction, Region, AuditEntry};
```

## Sovereign Container

### Sovereign\<T, J\>

A generic container that wraps data of type `T` with jurisdiction `J` enforced at compile time.

```rust
pub struct Sovereign<T, const J: Jurisdiction> { /* private */ }
```

### Sovereign::seal

Encrypts and wraps data into a sovereign container.

```rust
pub fn seal(data: T, region: Region) -> Result<Sovereign<T, J>>
```

```rust
let container: Sovereign<PatientRecord, { Jurisdiction::EU_GDPR }> =
    Sovereign::seal(patient_record, Region::Frankfurt)?;
```

### Sovereign::process_in

Executes a closure on the contained data within a compliant region.

```rust
pub fn process_in<F, R>(&self, region: Region, f: F) -> Result<R>
where
    F: FnOnce(&T) -> R,
```

```rust
let prediction = container.process_in(Region::Frankfurt, |data| {
    model.predict(data)
})?;
```

### Sovereign::export

Exports the container for transfer to another compliant region.

```rust
pub fn export(&self, target: Region) -> Result<ExportedSovereign<T, J>>
```

### Sovereign::audit_log

Returns the immutable audit trail.

```rust
pub fn audit_log(&self) -> &[AuditEntry]
```

## Jurisdiction

```rust
pub enum Jurisdiction {
    EU_GDPR,
    US_ITAR,
    US_HIPAA,
    CN_PIPL,
    Global,
    Custom(u64),
}
```

### Methods

```rust
impl Jurisdiction {
    pub fn approved_regions(&self) -> &[Region];
    pub fn is_compliant(&self, region: &Region) -> bool;
    pub fn intersect(&self, other: &Jurisdiction) -> Vec<Region>;
}
```

## Region

```rust
pub enum Region {
    Frankfurt, Dublin, Paris, Stockholm,    // EU
    Virginia, Oregon, Ohio,                  // US
    Tokyo, Singapore, Sydney,                // APAC
    Beijing, Shanghai,                       // China
    DualCompliantEnclave, Local,             // Special
}
```

## Cross-Jurisdiction Operations

### join_process

```rust
pub fn join_process<T1, T2, F, R, const J1: Jurisdiction, const J2: Jurisdiction>(
    a: &Sovereign<T1, J1>,
    b: &Sovereign<T2, J2>,
    region: Region,
    f: F,
) -> Result<R>
where
    F: FnOnce(&T1, &T2) -> R,
```

## AuditEntry

```rust
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub operation: Operation,
    pub principal: Address,
    pub region: Region,
    pub tee_quote: Option<Vec<u8>>,
}

pub enum Operation {
    Seal, Unseal, Process, Export, Destroy,
}
```

## Serialization

Sovereign containers are encrypted with AES-256-GCM using a key derived from the TEE sealing key. Deserialization only succeeds inside a compliant enclave.

```rust
let bytes = container.to_bytes()?;
let restored: Sovereign<PatientRecord, { Jurisdiction::EU_GDPR }> =
    Sovereign::from_bytes(&bytes)?;
```

## Related Pages

- [Sovereign Data Guide](/guide/sovereign-data) -- conceptual overview
- [Rust Attestation API](/api/rust/attestation) -- TEE attestation for sovereign enclaves
- [Rust Cryptography API](/api/rust/crypto) -- encryption primitives
- [Security Parameters](/cryptography/security-parameters) -- encryption algorithms
