# TEE Attestation

Trusted Execution Environment (TEE) attestation is the hardware trust anchor for Aethelred. When a validator or user runs computation inside a TEE enclave, the hardware produces a cryptographic quote that proves the specific binary executed on genuine, unmodified hardware. Aethelred verifies these quotes on-chain, making TEE attestation a first-class protocol primitive.

## Supported Platforms

| Platform | Hardware | Quote Format | Key Feature |
|---|---|---|---|
| Intel SGX (DCAP) | Xeon Scalable (3rd gen+) | ECDSA-P256 quote | Per-enclave measurement (MRENCLAVE) |
| AMD SEV-SNP | EPYC (3rd gen+) | Versioned attestation report | Full VM isolation with memory encryption |
| AWS Nitro | Nitro Enclave (any EC2) | COSE_Sign1 document | PCR-based measurement, no hypervisor access |

## Trust Model

```
Hardware Root of Trust
    │
    ├── Platform Certificate (provisioned at manufacturing)
    │       │
    │       └── Attestation Key (derived per-platform)
    │               │
    │               └── Quote / Report (signed per-enclave-session)
    │                       │
    │                       └── On-chain Verification
    │                               │
    │                               └── Digital Seal (includes verified quote)
    │
    └── Collateral (CRL, TCB Info) ── fetched from vendor or cached on-chain
```

The chain of trust flows from the hardware manufacturer's root certificate down to the individual enclave session. Aethelred's on-chain verifiers maintain cached collateral (certificate revocation lists, TCB information) to validate quotes without external network calls during block execution.

## Generating Attestation Quotes

### Intel SGX DCAP

```rust
use aethelred_attestation::{sgx, AttestationReport};

// Inside an SGX enclave
let user_data = b"model-hash:0xabcdef...";
let quote = sgx::generate_dcap_quote(user_data)?;

println!("Quote size: {} bytes", quote.as_bytes().len());
println!("MRENCLAVE: {}", hex::encode(quote.mr_enclave()));
println!("MRSIGNER:  {}", hex::encode(quote.mr_signer()));
```

### AMD SEV-SNP

```rust
use aethelred_attestation::{sev_snp, AttestationReport};

let report_data = [0u8; 64]; // custom data bound into report
let report = sev_snp::request_attestation_report(&report_data)?;

println!("Guest SVN: {}", report.guest_svn());
println!("Measurement: {}", hex::encode(report.measurement()));
println!("Platform version: {}", report.platform_version());
```

### AWS Nitro

```rust
use aethelred_attestation::{nitro, AttestationReport};

let user_data = Some(b"model-hash:0xabcdef...".to_vec());
let document = nitro::get_attestation_document(user_data, None, None)?;

println!("PCR0: {}", hex::encode(document.pcr(0)));
println!("PCR1: {}", hex::encode(document.pcr(1)));
println!("PCR2: {}", hex::encode(document.pcr(2)));
```

## On-Chain Verification

Aethelred nodes verify attestation quotes during block execution. The verification logic is implemented as a native module (not a smart contract) for performance:

```go
// Verify a quote from any supported platform
result, err := client.VerifyAttestation(ctx, quote)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Platform:      %s\n", result.Platform)      // "sgx-dcap"
fmt.Printf("Valid:         %v\n", result.Valid)
fmt.Printf("TCB Status:    %s\n", result.TCBStatus)      // "UpToDate"
fmt.Printf("Measurement:   %s\n", result.Measurement)
fmt.Printf("Collateral Age: %s\n", result.CollateralAge) // "2h15m"
```

### Verification Checks

| Check | Description | Failure Behavior |
|---|---|---|
| Signature validity | Quote signed by valid attestation key | Quote rejected |
| Certificate chain | Attestation key chains to platform root cert | Quote rejected |
| Revocation | Attestation key not on CRL | Quote rejected |
| TCB level | Platform TCB meets minimum threshold | Quote accepted with warning |
| Measurement | MRENCLAVE/PCR matches registered binary | Optional (application-level) |
| Freshness | Quote generated within acceptable time window | Configurable (default: 24h) |

## Collateral Management

TEE verification requires up-to-date collateral (root certificates, CRLs, TCB information). Aethelred manages this through:

1. **On-chain collateral store** -- validators periodically submit updated collateral via governance transactions
2. **Local cache** -- SDKs cache collateral for offline verification
3. **Freshness policy** -- configurable maximum collateral age (default: 30 days)

```go
// Update collateral (requires governance authority)
err := client.UpdateCollateral(ctx, &aethelred.CollateralUpdate{
    Platform:    aethelred.PlatformSGX,
    TCBInfo:     tcbInfoBytes,
    QEIdentity:  qeIdentityBytes,
    RootCACRL:   crlBytes,
})
```

## Binding Attestation to Computation

Attestation quotes contain a user-data field (64 bytes for SGX/SEV-SNP, arbitrary for Nitro) that binds the quote to specific computation. Aethelred uses this field to include:

- `SHA3-256(model_hash || input_hash || output_hash)`

This binding ensures that the quote attests not just the enclave binary, but the specific inference or training execution performed within it.

## Multi-Platform Attestation

For high-assurance workloads, Aethelred supports **multi-platform attestation** where the same computation runs on two different TEE platforms and both quotes must verify:

```rust
let seal = client.create_seal(SealRequest {
    model_path: "/models/critical-system-v1.ckpt".into(),
    attestation_policy: AttestationPolicy::MultiPlatform {
        required: vec![Platform::SgxDcap, Platform::SevSnp],
        threshold: 2, // both must verify
    },
    ..Default::default()
}).await?;
```

## Related Pages

- [Digital Seals](/guide/digital-seals) -- how attestation quotes are embedded in seals
- [zkML Proofs](/guide/zkml-proofs) -- zero-knowledge proofs complement TEE attestation
- [Sovereign Data](/guide/sovereign-data) -- TEE enclaves enforce data residency
- [Validators](/guide/validators) -- validators must run TEE-capable hardware
- [Security Parameters](/cryptography/security-parameters) -- cryptographic strength of attestation
