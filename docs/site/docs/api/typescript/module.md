# TypeScript SDK -- Module API

## Overview

The `nn` namespace provides a PyTorch-compatible neural network API with modular layers, loss functions, and initialization utilities. Import from the core package:

```typescript
import {
  Module, Parameter, Sequential, Linear, LayerNorm,
  ReLU, GELU, Dropout, MultiheadAttention, CrossEntropyLoss,
} from '@aethelred/sdk';
```

---

## `Module` Base Class

All layers extend `Module`. It manages parameters, child modules, and training/eval mode.

### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `forward` | `forward(...args: Tensor[]): Tensor` | Override to define computation |
| `parameters` | `parameters(): Parameter[]` | All trainable parameters (recursive) |
| `train` | `train(mode?: boolean): this` | Set training mode |
| `eval` | `eval(): this` | Set evaluation mode |
| `stateDict` | `stateDict(): Record<string, Tensor>` | Serializable parameter map |
| `loadStateDict` | `loadStateDict(dict: Record<string, Tensor>): void` | Restore parameters |
| `registerParameter` | `registerParameter(name, param): void` | Register a named parameter |
| `registerModule` | `registerModule(name, module): void` | Register a child module |
| `to` | `to(device: string): this` | Move all parameters to a device |

### Example

```typescript
import { Module, Parameter, Tensor, Linear, ReLU } from '@aethelred/sdk';

class MLP extends Module {
  private fc1: Linear;
  private fc2: Linear;
  private act: ReLU;

  constructor(inDim: number, hiddenDim: number, outDim: number) {
    super();
    this.fc1 = new Linear(inDim, hiddenDim);
    this.fc2 = new Linear(hiddenDim, outDim);
    this.act = new ReLU();
    this.registerModule('fc1', this.fc1);
    this.registerModule('fc2', this.fc2);
  }

  forward(x: Tensor): Tensor {
    return this.fc2.forward(this.act.forward(this.fc1.forward(x)));
  }
}
```

---

## Container Modules

| Class | Description |
|-------|-------------|
| `Sequential` | Chain layers in order; `forward` pipes input through each |
| `ModuleList` | Indexed list of sub-modules |
| `ModuleDict` | Named dictionary of sub-modules |

```typescript
const model = new Sequential(
  new Linear(784, 256),
  new ReLU(),
  new Dropout(0.2),
  new Linear(256, 10),
);

const output = model.forward(input);
```

---

## Layer Reference

### Linear Layers

| Class | Constructor | Description |
|-------|-------------|-------------|
| `Linear` | `(inFeatures, outFeatures, { bias? })` | Fully connected layer |
| `Embedding` | `(numEmbeddings, embeddingDim, { paddingIdx? })` | Lookup table |

### Normalization

| Class | Constructor | Description |
|-------|-------------|-------------|
| `LayerNorm` | `(normalizedShape, { eps?, elementwiseAffine? })` | Layer normalization |
| `BatchNorm1d` | `(numFeatures, { eps?, momentum?, affine? })` | Batch normalization |
| `RMSNorm` | `(normalizedShape, { eps? })` | Root mean square normalization |

### Activations

| Class | Description |
|-------|-------------|
| `ReLU` | Rectified linear unit |
| `GELU` | Gaussian error linear unit |
| `SiLU` | Sigmoid linear unit (swish) |
| `Sigmoid` | Logistic sigmoid |
| `Tanh` | Hyperbolic tangent |
| `Softmax` | Softmax over a dimension |
| `LeakyReLU` | Leaky rectified linear unit |
| `ELU` | Exponential linear unit |

### Dropout

| Class | Constructor | Description |
|-------|-------------|-------------|
| `Dropout` | `(p?: number)` | Random element zeroing |
| `Dropout2d` | `(p?: number)` | Drop entire channels |

### Attention and Transformer

| Class | Constructor | Description |
|-------|-------------|-------------|
| `MultiheadAttention` | `(embedDim, numHeads, { dropout?, bias?, batchFirst? })` | Scaled dot-product multi-head attention |
| `TransformerEncoderLayer` | `(dModel, nHead, { dimFeedforward?, dropout?, activation? })` | Single encoder block |
| `TransformerDecoderLayer` | `(dModel, nHead, { dimFeedforward?, dropout?, activation? })` | Single decoder block |

---

## Loss Functions

| Class | Constructor | Description |
|-------|-------------|-------------|
| `MSELoss` | `({ reduction? })` | Mean squared error |
| `CrossEntropyLoss` | `({ reduction?, labelSmoothing? })` | Cross-entropy with log-softmax |
| `BCEWithLogitsLoss` | `({ reduction? })` | Binary cross-entropy with sigmoid |
| `FocalLoss` | `({ alpha?, gamma?, reduction? })` | Focal loss for imbalanced classes |
| `TripletMarginLoss` | `({ margin?, reduction? })` | Triplet margin loss |
| `KLDivLoss` | `({ reduction? })` | KL divergence |

---

## Initialization (`nn.init`)

| Function | Signature | Description |
|----------|-----------|-------------|
| `xavier_uniform_` | `(tensor, gain?)` | Xavier/Glorot uniform |
| `xavier_normal_` | `(tensor, gain?)` | Xavier/Glorot normal |
| `kaiming_uniform_` | `(tensor, a?, mode?, nonlinearity?)` | He uniform |
| `kaiming_normal_` | `(tensor, a?, mode?, nonlinearity?)` | He normal |
| `zeros_` | `(tensor)` | Fill with zeros |
| `ones_` | `(tensor)` | Fill with ones |
| `normal_` | `(tensor, mean?, std?)` | Normal distribution |
| `uniform_` | `(tensor, a?, b?)` | Uniform distribution |

---

## Model Serialization

```typescript
// Save
const dict = model.stateDict();
const json = JSON.stringify(dict);

// Load
const restored = new MLP(784, 256, 10);
restored.loadStateDict(JSON.parse(json));
restored.eval();
```

---

## Training Loop Example

```typescript
import { Adam } from '@aethelred/sdk';

const model = new Sequential(
  new Linear(784, 256), new ReLU(), new Linear(256, 10),
);
const loss_fn = new CrossEntropyLoss();
const optimizer = new Adam(model.parameters(), { lr: 1e-3 });

for (const { input, target } of dataloader) {
  const output = model.forward(input);
  const loss = loss_fn.forward(output, target);

  optimizer.zeroGrad();
  loss.backward();
  optimizer.step();
}
```

---

## See Also

- [TypeScript SDK Overview](./) -- Installation and client setup
- [Tensor API](./tensor) -- Tensor creation and operations
- [Runtime API](./runtime) -- Device selection and memory pools
- [Python SDK](/api/python/) -- Python equivalent API
