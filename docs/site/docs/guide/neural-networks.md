# Neural Networks

Aethelred's neural network module system mirrors the PyTorch `nn.Module` pattern across all SDKs. You define models as composable modules with parameters, forward methods, and automatic differentiation support.

## Defining a Module

### Go

```go
import (
    "github.com/aethelred/sdk-go/nn"
    "github.com/aethelred/sdk-go/tensor"
)

type Classifier struct {
    nn.Module
    FC1   *nn.Linear
    FC2   *nn.Linear
    FC3   *nn.Linear
    Norm  *nn.LayerNorm
}

func NewClassifier(inputDim, hiddenDim, numClasses int) *Classifier {
    m := &Classifier{
        FC1:  nn.NewLinear(inputDim, hiddenDim),
        FC2:  nn.NewLinear(hiddenDim, hiddenDim),
        FC3:  nn.NewLinear(hiddenDim, numClasses),
        Norm: nn.NewLayerNorm(hiddenDim),
    }
    m.RegisterSubmodules(m.FC1, m.FC2, m.FC3, m.Norm)
    return m
}

func (m *Classifier) Forward(x *tensor.Tensor) *tensor.Tensor {
    x = m.FC1.Forward(x).ReLU()
    x = m.Norm.Forward(x)
    x = m.FC2.Forward(x).ReLU()
    x = m.FC3.Forward(x)
    return x
}
```

### Rust

```rust
use aethelred::nn::{self, Module, Linear, LayerNorm};
use aethelred::tensor::Tensor;

struct Classifier {
    fc1: Linear,
    fc2: Linear,
    fc3: Linear,
    norm: LayerNorm,
}

impl Classifier {
    fn new(input_dim: usize, hidden_dim: usize, num_classes: usize) -> Self {
        Self {
            fc1: Linear::new(input_dim, hidden_dim),
            fc2: Linear::new(hidden_dim, hidden_dim),
            fc3: Linear::new(hidden_dim, num_classes),
            norm: LayerNorm::new(hidden_dim),
        }
    }
}

impl Module for Classifier {
    fn forward(&self, x: &Tensor) -> Tensor {
        let x = self.fc1.forward(x).relu();
        let x = self.norm.forward(&x);
        let x = self.fc2.forward(&x).relu();
        self.fc3.forward(&x)
    }
}
```

### TypeScript

```typescript
import { nn, Tensor } from '@aethelred/sdk';

class Classifier extends nn.Module {
  fc1: nn.Linear;
  fc2: nn.Linear;
  fc3: nn.Linear;
  norm: nn.LayerNorm;

  constructor(inputDim: number, hiddenDim: number, numClasses: number) {
    super();
    this.fc1 = new nn.Linear(inputDim, hiddenDim);
    this.fc2 = new nn.Linear(hiddenDim, hiddenDim);
    this.fc3 = new nn.Linear(hiddenDim, numClasses);
    this.norm = new nn.LayerNorm(hiddenDim);
  }

  forward(x: Tensor): Tensor {
    x = this.fc1.forward(x).relu();
    x = this.norm.forward(x);
    x = this.fc2.forward(x).relu();
    return this.fc3.forward(x);
  }
}
```

## Available Layers

| Layer | Description | Parameters |
|---|---|---|
| `Linear` | Fully connected | `in_features`, `out_features`, `bias` |
| `Conv1d` | 1D convolution | `in_channels`, `out_channels`, `kernel_size`, `stride`, `padding` |
| `Conv2d` | 2D convolution | `in_channels`, `out_channels`, `kernel_size`, `stride`, `padding` |
| `LayerNorm` | Layer normalization | `normalized_shape`, `eps` |
| `BatchNorm1d/2d` | Batch normalization | `num_features`, `momentum`, `eps` |
| `MultiHeadAttention` | Multi-head self/cross attention | `embed_dim`, `num_heads`, `dropout` |
| `Embedding` | Embedding lookup | `num_embeddings`, `embedding_dim` |
| `Dropout` | Dropout regularization | `p` |
| `LSTM` | Long short-term memory | `input_size`, `hidden_size`, `num_layers` |
| `GRU` | Gated recurrent unit | `input_size`, `hidden_size`, `num_layers` |
| `MaxPool2d` | Max pooling | `kernel_size`, `stride` |
| `AvgPool2d` | Average pooling | `kernel_size`, `stride` |

## Activation Functions

```go
x.ReLU()
x.GELU()
x.Sigmoid()
x.Tanh()
x.Softmax(dim)
x.LogSoftmax(dim)
x.SiLU()    // Swish
x.Mish()
```

## Loss Functions

```go
loss := nn.CrossEntropyLoss(logits, targets)
loss := nn.MSELoss(predictions, targets)
loss := nn.BCEWithLogitsLoss(logits, targets)
loss := nn.L1Loss(predictions, targets)
loss := nn.HuberLoss(predictions, targets, delta)
```

## Optimizers

```go
optimizer := nn.NewAdam(model.Parameters(), &nn.AdamConfig{
    LR:          1e-3,
    Betas:       [2]float64{0.9, 0.999},
    WeightDecay: 1e-2,
})

// Training step
optimizer.ZeroGrad()
logits := model.Forward(inputs)
loss := nn.CrossEntropyLoss(logits, targets)
loss.Backward()
optimizer.Step()
```

Available optimizers: `SGD`, `Adam`, `AdamW`, `LAMB`, `Adafactor`.

## Training Loop

```go
model := NewClassifier(784, 256, 10)
optimizer := nn.NewAdamW(model.Parameters(), &nn.AdamWConfig{LR: 3e-4})
scheduler := nn.NewCosineAnnealingLR(optimizer, 100)

for epoch := 0; epoch < 100; epoch++ {
    model.Train()  // set training mode
    var epochLoss float64

    for batch := range dataloader.Iter() {
        optimizer.ZeroGrad()

        logits := model.Forward(batch.Inputs)
        loss := nn.CrossEntropyLoss(logits, batch.Labels)
        loss.Backward()

        nn.ClipGradNorm(model.Parameters(), 1.0)
        optimizer.Step()

        epochLoss += loss.Item()
    }

    scheduler.Step()

    // Evaluation
    model.Eval()  // set evaluation mode (disables dropout, etc.)
    accuracy := evaluate(model, testLoader)
    fmt.Printf("Epoch %d  loss=%.4f  acc=%.2f%%\n", epoch, epochLoss, accuracy*100)
}
```

## Saving and Loading Models

```go
// Save
err := nn.Save(model, "/models/classifier-v1.ckpt")

// Load
loaded := NewClassifier(784, 256, 10)
err := nn.Load(loaded, "/models/classifier-v1.ckpt")
```

### Checkpoint Format

Aethelred uses a platform-independent checkpoint format (`.ckpt`) compatible across all SDKs. A model saved in Go can be loaded in Rust or Python.

```rust
// Load a checkpoint saved from Go
let model = Classifier::new(784, 256, 10);
nn::load(&model, "/models/classifier-v1.ckpt")?;
```

## Pre-Built Models

Aethelred ships common architectures via the model zoo:

```go
import "github.com/aethelred/sdk-go/nn/models"

resnet := models.ResNet50(models.ResNet50Config{NumClasses: 1000})
vit := models.ViTBase(models.ViTBaseConfig{NumClasses: 1000, ImageSize: 224})
bert := models.BertBase(models.BertConfig{VocabSize: 30522})
```

## Related Pages

- [Tensor Operations](/guide/tensors) -- underlying tensor API
- [Runtime & Devices](/guide/runtime) -- device assignment for modules
- [Distributed Training](/guide/distributed) -- scaling to multiple devices
- [Quantization](/guide/quantization) -- compressing models for deployment
- [Model Registry](/guide/model-registry) -- publishing trained models on-chain
