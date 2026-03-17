# Model Registry

The Aethelred Model Registry is an on-chain repository for AI model metadata, versioning, and discovery. Models registered here are backed by [Digital Seals](/guide/digital-seals), providing cryptographic proof of provenance, training lineage, and integrity.

## Concepts

| Concept | Description |
|---|---|
| **Model** | A named entry in the registry (e.g., `aethelred/fraud-detector`) |
| **Version** | A specific checkpoint with a seal, tagged by semver (e.g., `v3.1.0`) |
| **Seal** | The Digital Seal proving the model's provenance and integrity |
| **Manifest** | Metadata including architecture, input/output shapes, license, and metrics |

## Publishing a Model

### Go

```go
version, err := client.PublishModel(ctx, &aethelred.ModelPublishRequest{
    Name:        "aethelred/fraud-detector",
    Version:     "3.1.0",
    SealID:      sealID,                          // must exist on-chain
    Description: "Transaction fraud detector for banking",
    Manifest: aethelred.ModelManifest{
        Architecture: "transformer-classifier",
        Framework:    "aethelred-sdk-go",
        InputShape:   []int{1, 128},              // [batch, features]
        OutputShape:  []int{1, 2},                // [batch, classes]
        DType:        "float32",
        License:      "Apache-2.0",
        Metrics: map[string]float64{
            "accuracy": 0.973,
            "f1":       0.968,
            "auc-roc":  0.991,
        },
        Tags: []string{"finance", "fraud", "production"},
    },
})

fmt.Printf("Published: %s@%s\n", version.Name, version.Version)
fmt.Printf("Registry TX: %s\n", version.TxHash)
```

### Rust

```rust
let version = client.publish_model(ModelPublishRequest {
    name: "aethelred/fraud-detector".into(),
    version: "3.1.0".into(),
    seal_id: seal_id,
    description: "Transaction fraud detector for banking".into(),
    manifest: ModelManifest {
        architecture: "transformer-classifier".into(),
        framework: "aethelred-sdk-rust".into(),
        input_shape: vec![1, 128],
        output_shape: vec![1, 2],
        dtype: "float32".into(),
        license: "Apache-2.0".into(),
        metrics: btreemap! {
            "accuracy" => 0.973,
            "f1" => 0.968,
        },
        tags: vec!["finance".into(), "fraud".into()],
    },
}).await?;
```

## Discovering Models

### Search

```go
results, err := client.SearchModels(ctx, &aethelred.ModelQuery{
    Tags:       []string{"finance"},
    MinMetric:  map[string]float64{"accuracy": 0.95},
    License:    "Apache-2.0",
    SortBy:     aethelred.SortByDownloads,
    Limit:      20,
})

for _, model := range results {
    fmt.Printf("%-40s %s  acc=%.3f  downloads=%d\n",
        model.Name, model.LatestVersion, model.Metrics["accuracy"], model.Downloads)
}
```

### CLI

```bash
aethelred model search --tag finance --min-accuracy 0.95
aethelred model info aethelred/fraud-detector
aethelred model versions aethelred/fraud-detector
```

## Downloading and Using a Model

```go
// Fetch model metadata
info, err := client.ModelInfo(ctx, "aethelred/fraud-detector", "3.1.0")

// Verify the seal before using the model
verifyResult, err := client.VerifySeal(ctx, info.SealID)
if !verifyResult.IsValid() {
    log.Fatal("Model seal verification failed")
}

// Download the checkpoint (from decentralized storage)
checkpointPath, err := client.DownloadModel(ctx, "aethelred/fraud-detector", "3.1.0",
    aethelred.WithDownloadDir("/models/cache"))

// Load and run inference
model, err := nn.LoadModel(checkpointPath)
output := model.Forward(inputTensor)
```

## Versioning

The registry enforces semantic versioning. Each version is immutable once published.

```
aethelred/fraud-detector
  ├── v1.0.0  (seal: 0xabc...)  ── initial release
  ├── v2.0.0  (seal: 0xdef...)  ── architecture change
  ├── v3.0.0  (seal: 0x123...)  ── new training data
  └── v3.1.0  (seal: 0x456...)  ── quantized INT8 variant
```

### Version Pinning

```go
// Exact version
client.DownloadModel(ctx, "aethelred/fraud-detector", "3.1.0", opts)

// Latest patch
client.DownloadModel(ctx, "aethelred/fraud-detector", "3.1.*", opts)

// Latest minor
client.DownloadModel(ctx, "aethelred/fraud-detector", "3.*", opts)

// Latest
client.DownloadModel(ctx, "aethelred/fraud-detector", "latest", opts)
```

## Access Control

Model publishers can set visibility and access policies:

| Visibility | Description |
|---|---|
| `Public` | Anyone can discover and download |
| `Unlisted` | Discoverable only by direct name |
| `Private` | Only authorized addresses can access |

```go
err := client.SetModelAccess(ctx, "myorg/internal-model", &aethelred.AccessPolicy{
    Visibility: aethelred.Private,
    AllowList:  []string{addr1, addr2, addr3},
})
```

## Storage

Model checkpoints are stored in Aethelred's decentralized storage layer (backed by IPFS with incentivized pinning). The registry stores only metadata and the content-addressed hash on-chain.

| Component | Storage Location | Cost |
|---|---|---|
| Metadata + manifest | On-chain state | 0.01 AETH per version |
| Checkpoint binary | Decentralized storage | 0.001 AETH per MB/month |

## Related Pages

- [Digital Seals](/guide/digital-seals) -- every model version references a seal
- [Submitting Jobs](/guide/jobs) -- reference registry models in job requests
- [Quantization](/guide/quantization) -- publish quantized model variants
- [Neural Networks](/guide/neural-networks) -- model architecture definition
