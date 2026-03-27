# Rust zkTensor API

The `aethelred-zktensor` crate provides zero-knowledge tensor operations: compiling neural networks into arithmetic circuits, generating proofs of correct inference, and verifying those proofs.

## Import

```rust
use aethelred_zktensor::{
    Circuit, CircuitConfig, ProofBackend,
    Proof, VerifierKey, ProvingKey,
    QuantizationConfig,
};
```

## Circuit Compilation

### Circuit::from_model

Compiles a neural network into an arithmetic circuit.

```rust
pub fn from_model(model: &dyn Module, config: &CircuitConfig) -> Result<Circuit>
```

```rust
let model = nn::load_model("/models/classifier-v2.ckpt")?;
let circuit = Circuit::from_model(&model, &CircuitConfig {
    backend: ProofBackend::Plonk,
    input_shape: vec![1, 3, 224, 224],
    quantization: Some(QuantizationConfig::Int8),
    optimization_level: 2,
})?;

println!("Constraints: {}", circuit.num_constraints());
println!("Variables:   {}", circuit.num_variables());
```

### CircuitConfig

```rust
pub struct CircuitConfig {
    pub backend: ProofBackend,
    pub input_shape: Vec<usize>,
    pub quantization: Option<QuantizationConfig>,
    pub optimization_level: u8,
}
```

### ProofBackend

```rust
pub enum ProofBackend {
    Groth16,  // ~200 B proofs, per-circuit trusted setup
    Plonk,    // ~500 B proofs, universal setup
    Stark,    // ~50 KB proofs, no trusted setup, post-quantum
}
```

### Circuit Methods

```rust
impl Circuit {
    pub fn num_constraints(&self) -> usize;
    pub fn num_variables(&self) -> usize;
    pub fn estimated_memory_gb(&self) -> f64;
    pub fn backend(&self) -> ProofBackend;
    pub fn prove(&self, input: &Tensor) -> Result<Proof>;
    pub fn verify(&self, proof: &Proof) -> Result<bool>;
    pub fn verifier_key(&self) -> &VerifierKey;
    pub fn verifier_key_id(&self) -> [u8; 32];
    pub fn to_bytes(&self) -> Result<Vec<u8>>;
    pub fn from_bytes(data: &[u8]) -> Result<Self>;
}
```

## Proof Generation and Verification

```rust
let input = Tensor::randn(&[1, 3, 224, 224], DType::Float32)?;
let proof = circuit.prove(&input)?;

println!("Proof size: {} bytes", proof.as_bytes().len());
println!("Public outputs: {:?}", proof.public_outputs());

let valid = circuit.verify(&proof)?;
assert!(valid);
```

### Proof

```rust
impl Proof {
    pub fn as_bytes(&self) -> &[u8];
    pub fn from_bytes(data: &[u8], backend: ProofBackend) -> Result<Self>;
    pub fn public_outputs(&self) -> &[Vec<u8>];
    pub fn backend(&self) -> ProofBackend;
    pub fn proving_time(&self) -> Duration;
}
```

### Standalone Verification

```rust
pub fn verify_standalone(
    verifier_key: &VerifierKey,
    proof: &Proof,
    public_inputs: &[Vec<u8>],
) -> Result<bool>
```

## Trusted Setup

### PLONK Universal Setup

```rust
pub fn plonk_setup(max_constraints: usize) -> Result<UniversalSetup>
```

### Groth16 Per-Circuit Setup

```rust
pub fn groth16_setup(circuit: &Circuit) -> Result<(ProvingKey, VerifierKey)>
```

## QuantizationConfig

```rust
pub enum QuantizationConfig {
    Int8,    // W8A8
    W8A16,   // weights INT8, activations FP16
    W4A16,   // weights INT4, activations FP16
}
```

## Supported Layers

| Layer | Constraints per Element | Notes |
|---|---|---|
| Linear | ~4 | Matrix multiply + bias |
| Conv2d | ~8 | Im2col + matmul |
| ReLU | ~1 | Comparison circuit |
| GELU | ~12 | Polynomial approximation |
| LayerNorm | ~10 | Mean, variance, normalize |
| Softmax | ~15 | Exp approximation + normalize |
| MaxPool2d | ~2 | Comparison tree |
| Residual add | ~1 | Simple addition |

## Related Pages

- [zkML Proofs Guide](/guide/zkml-proofs) -- conceptual overview
- [Quantization](/guide/quantization) -- reduce circuit size
- [Digital Seals](/guide/digital-seals) -- embed proofs in seals
- [Rust Cryptography API](/api/rust/crypto) -- underlying primitives
