# zkML Proofs

Zero-knowledge machine learning (zkML) proofs allow a prover to demonstrate that a specific neural network produced a specific output for a given input -- without revealing the model weights, the input data, or any intermediate activations. Aethelred integrates zkML proof generation and verification as a native protocol feature.

## Why zkML?

TEE attestation proves *where* computation ran (genuine hardware). zkML proofs prove *what* computation ran (correct model, correct execution). Together, they provide the strongest possible guarantee of AI inference integrity.

| Property | TEE Attestation | zkML Proof | Both Combined |
|---|---|---|---|
| Correct hardware | Yes | No | Yes |
| Correct execution | Assumed | Proven | Proven |
| Model weight privacy | Via enclave | Cryptographic | Cryptographic + hardware |
| Post-quantum secure | No (platform-dependent) | STARK backend: yes | With STARK: yes |
| Verification cost | Low (~1ms) | Moderate (~10-100ms) | Moderate |

## Proof Backends

Aethelred supports three zero-knowledge proof systems, each with different trade-offs:

| Backend | Proof Size | Prover Time | Verifier Time | Trusted Setup | PQ-Secure |
|---|---|---|---|---|---|
| **Groth16** | ~200 B | Slow | ~2 ms | Per-circuit | No |
| **PLONK** | ~500 B | Moderate | ~5 ms | Universal (1x) | No |
| **STARK** | ~50 KB | Fast | ~10 ms | None | Yes |

### Choosing a Backend

- **Groth16**: Best for production deployments where proof size and verification gas matter most. Requires a trusted setup ceremony per circuit.
- **PLONK**: Good general-purpose choice. Universal setup means new circuits don't require new ceremonies.
- **STARK**: Best for post-quantum security requirements or environments where trusted setup is unacceptable. Larger proofs but faster proving.

## Circuit Generation

Aethelred compiles neural network architectures into arithmetic circuits automatically. The circuit generator supports:

- Linear (fully connected) layers
- Convolutional layers (Conv1d, Conv2d)
- Activation functions (ReLU, GELU, Sigmoid, Tanh)
- Normalization (LayerNorm, BatchNorm)
- Attention (MultiHeadAttention)
- Pooling (MaxPool, AvgPool)
- Residual connections

### Generating a Circuit

```rust
use aethelred_zktensor::{Circuit, CircuitConfig, ProofBackend};

// Load model and compile to circuit
let model = aethelred::nn::load_model("/models/classifier-v2.ckpt")?;
let config = CircuitConfig {
    backend: ProofBackend::Plonk,
    input_shape: vec![1, 3, 224, 224],
    quantization: Some(QuantizationConfig::Int8),  // reduces circuit size
    optimization_level: 2,
};

let circuit = Circuit::from_model(&model, &config)?;

println!("Circuit constraints: {}", circuit.num_constraints());
println!("Circuit variables:   {}", circuit.num_variables());
println!("Estimated prover RAM: {} GB", circuit.estimated_memory_gb());
```

### Circuit Size Guidelines

| Model | Parameters | Groth16 Constraints | Estimated Prover Time |
|---|---|---|---|
| Small MLP | 10K | ~100K | < 1s |
| ResNet-18 | 11M | ~500M | ~5 min |
| ViT-Base | 86M | ~2B | ~30 min |
| GPT-2 Small | 124M | ~5B | ~2 hours |

::: tip
Use [quantization](/guide/quantization) to reduce model precision to INT8 before circuit generation. This typically reduces constraint count by 4-8x with minimal accuracy loss.
:::

## Proof Generation

```rust
// Generate proof
let input = Tensor::randn(&[1, 3, 224, 224], DType::Float32)?;
let proof = circuit.prove(&input)?;

println!("Proof size: {} bytes", proof.as_bytes().len());
println!("Public output: {:?}", proof.public_outputs());
```

### Go SDK

```go
circuit, err := zk.CompileModel("/models/classifier-v2.ckpt", &zk.CircuitConfig{
    Backend:    zk.BackendPLONK,
    InputShape: []int{1, 3, 224, 224},
})
if err != nil {
    log.Fatal(err)
}

proof, err := circuit.Prove(inputTensor)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Proof size: %d bytes\n", len(proof.Bytes()))
```

## Proof Verification

Verification can happen locally (off-chain) or on-chain:

### Off-Chain Verification

```rust
let valid = circuit.verify(&proof)?;
assert!(valid, "Proof verification failed");
```

### On-Chain Verification

```go
result, err := client.VerifyZKProof(ctx, &aethelred.ZKVerifyRequest{
    Proof:         proof.Bytes(),
    VerifierKeyID: circuit.VerifierKeyID(),
})
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Valid: %v, Gas used: %d\n", result.Valid, result.GasUsed)
```

On-chain verification costs scale with proof size:

| Backend | Verification Gas |
|---|---|
| Groth16 | ~250K gas |
| PLONK | ~350K gas |
| STARK | ~1M gas |

## Trusted Setup

Groth16 and PLONK require a trusted setup. Aethelred provides tooling for both:

### PLONK Universal Setup

Performed once; reusable for all circuits up to a maximum size.

```bash
aethelred zk setup --backend plonk --max-constraints 1000000000 --output setup.params
```

### Groth16 Per-Circuit Setup

Requires a multi-party computation (MPC) ceremony per circuit.

```bash
# Phase 1: Powers of Tau (reusable)
aethelred zk ceremony init --backend groth16 --output phase1.ptau

# Phase 2: Circuit-specific
aethelred zk ceremony contribute --input phase1.ptau --circuit classifier-v2.circuit --output phase2.params
```

## Integration with Digital Seals

zkML proofs are a core component of [Digital Seals](/guide/digital-seals). When creating a seal with a proof:

```rust
let seal = client.create_seal(SealRequest {
    model_path: "/models/classifier-v2.ckpt".into(),
    zk_proof: Some(proof),
    zk_verifier_key: Some(circuit.verifier_key_id()),
    ..Default::default()
}).await?;
```

## Related Pages

- [TEE Attestation](/guide/tee-attestation) -- hardware-based trust complements zkML
- [Digital Seals](/guide/digital-seals) -- zkML proofs are embedded in seals
- [Quantization](/guide/quantization) -- reduce circuit complexity via quantization
- [Security Parameters](/cryptography/security-parameters) -- proof security levels
