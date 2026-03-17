# Go Neural Network API

The `nn` package provides neural network modules, loss functions, optimizers, and training utilities following the PyTorch `nn.Module` pattern.

## Import

```go
import "github.com/aethelred/sdk-go/nn"
```

## Module Interface

```go
type Module interface {
    Forward(input *tensor.Tensor) *tensor.Tensor
    Parameters() []*tensor.Tensor
    Train()
    Eval()
    IsTraining() bool
    To(device runtime.Device)
    RegisterSubmodules(modules ...Module)
}
```

## Layer Modules

### Linear

Fully connected layer: `y = xW^T + b`.

```go
func NewLinear(inFeatures, outFeatures int, opts ...LinearOption) *Linear
```

| Option | Description | Default |
|---|---|---|
| `WithBias(bool)` | Include bias parameter | `true` |

```go
layer := nn.NewLinear(768, 256)
output := layer.Forward(input)  // [batch, 768] -> [batch, 256]
```

### Conv2d

```go
func NewConv2d(inChannels, outChannels, kernelSize int, opts ...Conv2dOption) *Conv2d
```

| Option | Description | Default |
|---|---|---|
| `WithStride(s)` | Convolution stride | `1` |
| `WithPadding(p)` | Zero-padding | `0` |
| `WithDilation(d)` | Dilation factor | `1` |
| `WithGroups(g)` | Grouped convolution | `1` |

### LayerNorm

```go
func NewLayerNorm(normalizedShape int, opts ...LayerNormOption) *LayerNorm
```

### BatchNorm2d

```go
func NewBatchNorm2d(numFeatures int, opts ...BatchNormOption) *BatchNorm2d
```

### MultiHeadAttention

```go
func NewMultiHeadAttention(embedDim, numHeads int, opts ...MHAOption) *MultiHeadAttention
```

### Embedding

```go
func NewEmbedding(numEmbeddings, embeddingDim int) *Embedding
```

### Dropout

```go
func NewDropout(p float64) *Dropout
```

### LSTM

```go
func NewLSTM(inputSize, hiddenSize int, opts ...LSTMOption) *LSTM
```

### MaxPool2d / AvgPool2d

```go
func NewMaxPool2d(kernelSize int, opts ...PoolOption) *MaxPool2d
func NewAvgPool2d(kernelSize int, opts ...PoolOption) *AvgPool2d
```

## Loss Functions

```go
func CrossEntropyLoss(logits, targets *tensor.Tensor) *tensor.Tensor
func MSELoss(predictions, targets *tensor.Tensor) *tensor.Tensor
func BCEWithLogitsLoss(logits, targets *tensor.Tensor) *tensor.Tensor
func L1Loss(predictions, targets *tensor.Tensor) *tensor.Tensor
func HuberLoss(predictions, targets *tensor.Tensor, delta float64) *tensor.Tensor
func NLLLoss(logProbs, targets *tensor.Tensor) *tensor.Tensor
```

## Optimizers

### Adam / AdamW

```go
func NewAdam(params []*tensor.Tensor, config *AdamConfig) *Adam
func NewAdamW(params []*tensor.Tensor, config *AdamWConfig) *AdamW
```

```go
type AdamWConfig struct {
    LR          float64
    Betas       [2]float64
    Eps         float64
    WeightDecay float64
}
```

### SGD

```go
func NewSGD(params []*tensor.Tensor, config *SGDConfig) *SGD
```

### Optimizer Interface

```go
type Optimizer interface {
    ZeroGrad()
    Step()
    State() map[string]interface{}
    LoadState(state map[string]interface{})
}
```

## Learning Rate Schedulers

```go
func NewCosineAnnealingLR(optimizer Optimizer, totalSteps int) *CosineAnnealingLR
func NewStepLR(optimizer Optimizer, stepSize int, gamma float64) *StepLR
func NewLinearWarmup(optimizer Optimizer, warmupSteps int) *LinearWarmup
func NewOneCycleLR(optimizer Optimizer, maxLR float64, totalSteps int) *OneCycleLR
```

## Utility Functions

### ClipGradNorm

```go
func ClipGradNorm(params []*tensor.Tensor, maxNorm float64) float64
```

### Save / Load

```go
func Save(module Module, path string) error
func Load(module Module, path string) error
```

### ParameterCount

```go
func ParameterCount(module Module) int64
```

## Related Pages

- [Neural Networks Guide](/guide/neural-networks) -- conceptual overview
- [Go Tensor API](/api/go/tensor) -- underlying tensor operations
- [Go Runtime API](/api/go/runtime) -- device management
- [Distributed Training](/guide/distributed) -- multi-GPU training
