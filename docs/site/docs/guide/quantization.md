# Quantization

Quantization reduces the numerical precision of model weights and activations to shrink model size, speed up inference, and -- critically for Aethelred -- reduce the constraint count of [zkML proof circuits](/guide/zkml-proofs). Aethelred supports post-training quantization (PTQ) and quantization-aware training (QAT).

## Supported Formats

| Format | Weight Precision | Activation Precision | Typical Speedup | zkML Circuit Reduction |
|---|---|---|---|---|
| FP32 (baseline) | 32-bit float | 32-bit float | 1x | 1x |
| FP16 | 16-bit float | 16-bit float | 1.5-2x | 2x |
| BF16 | BF16 | BF16 | 1.5-2x | 2x |
| INT8 (W8A8) | 8-bit integer | 8-bit integer | 2-4x | 4-8x |
| INT8 (W8A16) | 8-bit integer | 16-bit float | 2-3x | 3-4x |
| INT4 (W4A16) | 4-bit integer | 16-bit float | 3-5x | 6-10x |

## Post-Training Quantization (PTQ)

PTQ converts a pre-trained FP32 model to lower precision using a calibration dataset. No retraining is required.

### Go

```go
import "github.com/aethelred/sdk-go/quantize"

model := loadPretrainedModel("/models/classifier-v1.ckpt")

config := quantize.PTQConfig{
    WeightPrecision:     quantize.Int8,
    ActivationPrecision: quantize.Int8,
    CalibrationSamples:  1000,
    PerChannel:          true,  // per-channel weight quantization
}

quantizedModel, err := quantize.PostTraining(model, calibrationLoader, config)
if err != nil {
    log.Fatal(err)
}

// Save quantized model
nn.Save(quantizedModel, "/models/classifier-v1-int8.ckpt")

// Compare sizes
fmt.Printf("Original:   %.1f MB\n", originalSize/1e6)   // 44.2 MB
fmt.Printf("Quantized:  %.1f MB\n", quantizedSize/1e6)   // 11.1 MB
```

### Rust

```rust
use aethelred::quantize::{self, PTQConfig, Precision};

let model = nn::load_model("/models/classifier-v1.ckpt")?;

let config = PTQConfig {
    weight_precision: Precision::Int8,
    activation_precision: Precision::Int8,
    calibration_samples: 1000,
    per_channel: true,
    symmetric: true,
};

let quantized = quantize::post_training(&model, &calibration_loader, &config)?;
nn::save(&quantized, "/models/classifier-v1-int8.ckpt")?;
```

## Calibration

Calibration determines the quantization scale and zero-point for each layer by observing activation ranges on representative data.

### Calibration Strategies

| Strategy | Description | Quality | Speed |
|---|---|---|---|
| MinMax | Uses observed min/max values | Good | Fast |
| Percentile | Uses 99.99th percentile to clip outliers | Better | Fast |
| MSE | Minimizes mean squared error between FP32 and quantized output | Best | Slow |
| Entropy | Minimizes KL divergence | Best | Slow |

```go
config := quantize.PTQConfig{
    WeightPrecision:     quantize.Int8,
    ActivationPrecision: quantize.Int8,
    CalibrationStrategy: quantize.StrategyPercentile,
    Percentile:          99.99,
    CalibrationSamples:  500,
}
```

## Quantization-Aware Training (QAT)

QAT simulates quantization during training so the model learns to be robust to reduced precision. It typically yields better accuracy than PTQ.

```go
import "github.com/aethelred/sdk-go/quantize"

model := NewClassifier(784, 256, 10)

// Prepare model for QAT (inserts fake quantization nodes)
qatModel := quantize.PrepareQAT(model, quantize.QATConfig{
    WeightPrecision:     quantize.Int8,
    ActivationPrecision: quantize.Int8,
    PerChannel:          true,
})

optimizer := nn.NewAdamW(qatModel.Parameters(), &nn.AdamWConfig{LR: 1e-4})

// Train normally -- fake quant nodes simulate quantization
for epoch := 0; epoch < 10; epoch++ {
    for batch := range trainLoader.Iter() {
        optimizer.ZeroGrad()
        logits := qatModel.Forward(batch.Inputs)
        loss := nn.CrossEntropyLoss(logits, batch.Labels)
        loss.Backward()
        optimizer.Step()
    }
}

// Convert to actual quantized model
finalModel := quantize.ConvertQAT(qatModel)
nn.Save(finalModel, "/models/classifier-v1-qat-int8.ckpt")
```

## Accuracy Comparison

Typical accuracy impact on ImageNet (ResNet-50):

| Method | Top-1 Accuracy | Model Size | Inference Speedup |
|---|---|---|---|
| FP32 (baseline) | 76.1% | 97 MB | 1x |
| PTQ INT8 (MinMax) | 75.6% (-0.5) | 24 MB | 3.2x |
| PTQ INT8 (Percentile) | 75.9% (-0.2) | 24 MB | 3.2x |
| QAT INT8 | 76.0% (-0.1) | 24 MB | 3.2x |
| PTQ INT4 (W4A16) | 74.8% (-1.3) | 12 MB | 4.1x |

## Quantization for zkML

Quantization is especially important for [zkML proof generation](/guide/zkml-proofs) because lower precision means fewer constraints in the arithmetic circuit:

```rust
use aethelred_zktensor::{Circuit, CircuitConfig, ProofBackend};

// INT8 quantized model produces a much smaller circuit
let quantized_model = quantize::post_training(&model, &cal_loader, &ptq_config)?;

let circuit = Circuit::from_model(&quantized_model, &CircuitConfig {
    backend: ProofBackend::Plonk,
    input_shape: vec![1, 3, 224, 224],
    quantization: None,  // already quantized
    optimization_level: 2,
})?;

println!("Constraints: {}", circuit.num_constraints());
// INT8: ~62M constraints vs FP32: ~500M constraints
```

## Deployment

Quantized models deploy identically to full-precision models. The runtime automatically selects optimized INT8/INT4 kernels when available:

```go
model, err := nn.LoadQuantized("/models/classifier-v1-int8.ckpt")
if err != nil {
    log.Fatal(err)
}

// Inference
input := tensor.Randn([]int{1, 784}, tensor.Float32, device)
output := model.Forward(input)  // internally uses INT8 kernels
```

## Related Pages

- [Tensor Operations](/guide/tensors) -- supported dtypes
- [Neural Networks](/guide/neural-networks) -- model definition and training
- [zkML Proofs](/guide/zkml-proofs) -- proof circuits benefit from quantization
- [Model Registry](/guide/model-registry) -- publish quantized models on-chain
