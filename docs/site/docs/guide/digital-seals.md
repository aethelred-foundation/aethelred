# Digital Seals

A Digital Seal is Aethelred's core provenance primitive. It cryptographically binds an AI model's identity, its training lineage, a TEE attestation quote, and an optional zkML proof into a single on-chain artifact that anyone can verify in constant time.

## Anatomy of a Digital Seal

```
DigitalSeal {
    seal_id:         bytes32          // SHA3-256 of the seal contents
    model_hash:      bytes32          // SHA3-256 of the model checkpoint
    dataset_hash:    bytes32          // Merkle root of training data manifest
    tee_quote:       TEEQuote         // Hardware attestation (SGX/SEV/Nitro)
    zk_proof:        Option<ZKProof>  // Optional zkML inference proof
    jurisdiction:    JurisdictionTag  // Sovereign data classification
    creator:         Address          // Dilithium3 public key hash
    signature:       HybridSig        // ECDSA + Dilithium3 dual signature
    timestamp:       uint64           // Block height at creation
    metadata:        bytes            // Application-specific data (max 4 KB)
}
```

## Creating a Digital Seal

### Go

```go
seal, err := client.CreateSeal(ctx, &aethelred.SealRequest{
    ModelPath:    "/models/fraud-detector-v3.ckpt",
    DataManifest: "/data/manifests/training-2026-q1.json",
    Jurisdiction: aethelred.JurisdictionEU,
    Metadata:     []byte(`{"version":"3.0","accuracy":"0.97"}`),
})
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Seal ID: %s\n", seal.ID.Hex())
fmt.Printf("On-chain TX: %s\n", seal.TxHash.Hex())
```

### Rust

```rust
let seal = client.create_seal(SealRequest {
    model_path: "/models/fraud-detector-v3.ckpt".into(),
    data_manifest: "/data/manifests/training-2026-q1.json".into(),
    jurisdiction: Jurisdiction::EU,
    metadata: br#"{"version":"3.0","accuracy":"0.97"}"#.to_vec(),
}).await?;

println!("Seal ID: {}", seal.id);
```

### TypeScript

```typescript
const seal = await client.createSeal({
  modelPath: '/models/fraud-detector-v3.ckpt',
  dataManifest: '/data/manifests/training-2026-q1.json',
  jurisdiction: Jurisdiction.EU,
  metadata: { version: '3.0', accuracy: '0.97' },
});

console.log(`Seal ID: ${seal.id}`);
```

## Verification Flow

Verification is a three-step process that any party can perform without trusting the seal creator:

1. **Model hash check** -- re-hash the model checkpoint and compare to `model_hash`
2. **TEE quote verification** -- validate the attestation quote against the platform root of trust (Intel DCAP collateral, AMD VCEK, or AWS Nitro root certificate)
3. **zkML proof verification** -- if present, verify the zero-knowledge proof against the on-chain verifier contract

```go
result, err := client.VerifySeal(ctx, sealID)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Model hash valid:  %v\n", result.ModelHashValid)
fmt.Printf("TEE quote valid:   %v\n", result.TEEQuoteValid)
fmt.Printf("ZK proof valid:    %v\n", result.ZKProofValid)
fmt.Printf("Signature valid:   %v\n", result.SignatureValid)
fmt.Printf("Overall:           %v\n", result.IsValid())
```

## On-Chain Storage

Digital Seals are stored in a dedicated state tree with the following properties:

| Property | Value |
|---|---|
| Storage cost | 0.01 AETHEL per seal (includes 1 year of state rent) |
| Maximum metadata size | 4 KB |
| Seal immutability | Seals are append-only; they cannot be modified or deleted |
| Query index | By `seal_id`, `model_hash`, `creator`, or `jurisdiction` |
| Retention | Permanent (state rent can be renewed) |

## Querying Seals

```go
// Find all seals for a specific model
seals, err := client.QuerySeals(ctx, &aethelred.SealQuery{
    ModelHash: modelHash,
})

// Find seals by creator within a jurisdiction
seals, err := client.QuerySeals(ctx, &aethelred.SealQuery{
    Creator:      creatorAddr,
    Jurisdiction: aethelred.JurisdictionUS,
    Limit:        50,
})
```

## Seal Chains

Seals can reference parent seals to form a **seal chain** -- a verifiable lineage from the original training run through fine-tuning, quantization, and deployment:

```
Base Training Seal (v1)
    └── Fine-Tuning Seal (v2)  [parent: v1]
        └── Quantization Seal (v3)  [parent: v2]
            └── Deployment Seal (v3-prod)  [parent: v3]
```

```go
seal, err := client.CreateSeal(ctx, &aethelred.SealRequest{
    ModelPath:    "/models/fraud-detector-v3-int8.ckpt",
    ParentSealID: parentSealID,  // links to the quantization input
    Metadata:     []byte(`{"quantization":"int8","calibration_samples":1000}`),
})
```

## Use Cases

- **Regulatory compliance** -- prove to auditors that a model was trained on approved data inside a certified enclave
- **Supply chain integrity** -- verify that a model served in production matches the audited checkpoint
- **Federated learning** -- each participant seals their local training contribution; the aggregator seals the final model with references to all participant seals
- **Model marketplaces** -- buyers can verify provenance before purchasing or deploying a model

## Related Pages

- [TEE Attestation](/guide/tee-attestation) -- how attestation quotes are generated and verified
- [zkML Proofs](/guide/zkml-proofs) -- zero-knowledge proof generation for model inference
- [Sovereign Data](/guide/sovereign-data) -- jurisdiction enforcement for seal metadata
- [Cryptography Overview](/cryptography/overview) -- hybrid signature scheme details
