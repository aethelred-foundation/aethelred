# Rust TEE Attestation API

The `aethelred-attestation` crate provides generation and verification of hardware attestation quotes from Intel SGX DCAP, AMD SEV-SNP, and AWS Nitro Enclaves.

## Import

```rust
use aethelred_attestation::{
    sgx, sev_snp, nitro,
    AttestationReport, Platform, VerifyResult, Collateral,
};
```

## Platform Detection

### detect_platform

```rust
pub fn detect_platform() -> Vec<Platform>
```

### Platform

```rust
pub enum Platform {
    SgxDcap,
    SevSnp,
    Nitro,
}
```

## Intel SGX DCAP

### sgx::generate_dcap_quote

```rust
pub fn generate_dcap_quote(user_data: &[u8]) -> Result<SgxQuote>
```

```rust
let quote = sgx::generate_dcap_quote(b"model-hash:0xabcdef...")?;
println!("MRENCLAVE: {}", hex::encode(quote.mr_enclave()));
println!("MRSIGNER:  {}", hex::encode(quote.mr_signer()));
```

### SgxQuote

```rust
impl SgxQuote {
    pub fn version(&self) -> u16;
    pub fn mr_enclave(&self) -> &[u8; 32];
    pub fn mr_signer(&self) -> &[u8; 32];
    pub fn isv_prod_id(&self) -> u16;
    pub fn isv_svn(&self) -> u16;
    pub fn user_data(&self) -> &[u8; 64];
    pub fn as_bytes(&self) -> &[u8];
}
```

### sgx::verify_dcap_quote

```rust
pub fn verify_dcap_quote(quote: &SgxQuote, collateral: &Collateral) -> Result<VerifyResult>
```

## AMD SEV-SNP

### sev_snp::request_attestation_report

```rust
pub fn request_attestation_report(report_data: &[u8; 64]) -> Result<SevSnpReport>
```

### SevSnpReport

```rust
impl SevSnpReport {
    pub fn version(&self) -> u32;
    pub fn guest_svn(&self) -> u32;
    pub fn measurement(&self) -> &[u8; 48];
    pub fn host_data(&self) -> &[u8; 32];
    pub fn report_data(&self) -> &[u8; 64];
    pub fn vmpl(&self) -> u32;
    pub fn platform_version(&self) -> PlatformVersion;
    pub fn as_bytes(&self) -> &[u8];
}
```

### sev_snp::verify_report

```rust
pub fn verify_report(report: &SevSnpReport, vcek_cert: &[u8]) -> Result<VerifyResult>
```

## AWS Nitro Enclaves

### nitro::get_attestation_document

```rust
pub fn get_attestation_document(
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
) -> Result<NitroDocument>
```

### NitroDocument

```rust
impl NitroDocument {
    pub fn pcr(&self, index: usize) -> &[u8];
    pub fn module_id(&self) -> &str;
    pub fn timestamp(&self) -> u64;
    pub fn user_data(&self) -> Option<&[u8]>;
    pub fn certificate(&self) -> &[u8];
    pub fn ca_bundle(&self) -> &[Vec<u8>];
    pub fn as_bytes(&self) -> &[u8];
}
```

### nitro::verify_document

```rust
pub fn verify_document(doc: &NitroDocument, root_cert: &[u8]) -> Result<VerifyResult>
```

## VerifyResult

```rust
pub struct VerifyResult {
    pub valid: bool,
    pub platform: Platform,
    pub tcb_status: TcbStatus,
    pub measurement: Vec<u8>,
    pub collateral_age: Duration,
    pub warnings: Vec<String>,
}

pub enum TcbStatus {
    UpToDate, SWHardeningNeeded, ConfigurationNeeded, OutOfDate, Revoked,
}
```

## Collateral Management

### fetch_collateral

```rust
pub async fn fetch_collateral(platform: Platform) -> Result<Collateral>
```

```rust
pub struct Collateral {
    pub platform: Platform,
    pub root_ca_cert: Vec<u8>,
    pub pck_crl: Vec<u8>,
    pub tcb_info: Vec<u8>,
    pub qe_identity: Vec<u8>,
    pub updated_at: DateTime<Utc>,
}
```

## Related Pages

- [TEE Attestation Guide](/guide/tee-attestation) -- conceptual overview
- [Rust Sovereign API](/api/rust/sovereign) -- sovereign containers use attestation
- [Digital Seals](/guide/digital-seals) -- seals embed attestation quotes
- [Validators](/guide/validators) -- validator TEE requirements
