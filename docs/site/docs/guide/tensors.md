# Tensor Operations

The Aethelred tensor engine provides a multi-dimensional array API compatible with NumPy and PyTorch semantics. Tensors are the fundamental data structure for all compute operations, from simple linear algebra to neural network training.

## Creating Tensors

### Go

```go
import "github.com/aethelred/sdk-go/tensor"

// From literal data
t := tensor.FromSlice([]float32{1, 2, 3, 4, 5, 6}, []int{2, 3})

// Random initialization
t := tensor.Randn([]int{3, 224, 224}, tensor.Float32, device)
t := tensor.Zeros([]int{64, 128}, tensor.Float32, device)
t := tensor.Ones([]int{10}, tensor.Int64, device)

// Range
t := tensor.Arange(0, 100, 1, tensor.Float32, device)
```

### Rust

```rust
use aethelred::tensor::{Tensor, DType};

let t = Tensor::from_slice(&[1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0], &[2, 3])?;
let t = Tensor::randn(&[3, 224, 224], DType::Float32)?;
let t = Tensor::zeros(&[64, 128], DType::Float32)?;
```

### TypeScript

```typescript
import { Tensor, DType } from '@aethelred/sdk';

const t = Tensor.from([1, 2, 3, 4, 5, 6], [2, 3]);
const t = Tensor.randn([3, 224, 224], DType.Float32);
const t = Tensor.zeros([64, 128], DType.Float32);
```

## Supported Data Types

| DType | Size | Range | Use Case |
|---|---|---|---|
| `Float64` | 8 bytes | IEEE 754 double | High-precision computation |
| `Float32` | 4 bytes | IEEE 754 single | Default for training |
| `Float16` | 2 bytes | IEEE 754 half | Mixed-precision training |
| `BFloat16` | 2 bytes | Brain float | Transformer training |
| `Int64` | 8 bytes | -2^63 to 2^63-1 | Indices, labels |
| `Int32` | 4 bytes | -2^31 to 2^31-1 | Indices |
| `Int8` | 1 byte | -128 to 127 | Quantized inference |
| `UInt8` | 1 byte | 0 to 255 | Image pixel data |
| `Bool` | 1 byte | true/false | Masks |

## Arithmetic Operations

All operations support broadcasting following NumPy rules.

```go
a := tensor.Randn([]int{3, 4}, tensor.Float32, device)
b := tensor.Randn([]int{3, 4}, tensor.Float32, device)

c := a.Add(b)       // element-wise addition
c := a.Sub(b)       // element-wise subtraction
c := a.Mul(b)       // element-wise multiplication
c := a.Div(b)       // element-wise division
c := a.Pow(2.0)     // element-wise power
```

### Broadcasting

```go
// [3, 4] + [4] -> broadcasts scalar across rows
matrix := tensor.Randn([]int{3, 4}, tensor.Float32, device)
bias := tensor.Randn([]int{4}, tensor.Float32, device)
result := matrix.Add(bias)  // shape: [3, 4]
```

## Linear Algebra

```go
// Matrix multiplication
c := a.MatMul(b)  // [M, K] x [K, N] -> [M, N]

// Batched matmul
c := a.MatMul(b)  // [B, M, K] x [B, K, N] -> [B, M, N]

// Transpose
t := a.T()           // 2D transpose
t := a.Transpose(0, 2)  // swap dims 0 and 2

// Determinant, inverse, eigenvalues
det := a.Det()
inv := a.Inverse()
eigenvalues, eigenvectors := a.Eig()
```

## Reduction Operations

```go
sum := t.Sum(nil)           // total sum
sum := t.Sum([]int{1})      // sum along axis 1
mean := t.Mean(nil)
max := t.Max([]int{0})
min := t.Min(nil)
argmax := t.Argmax(1)       // indices of max values along axis 1
```

## Reshaping

```go
t := tensor.Randn([]int{2, 3, 4}, tensor.Float32, device)

r := t.Reshape([]int{6, 4})     // reshape to [6, 4]
r := t.View([]int{2, 12})       // view (no copy) to [2, 12]
r := t.Flatten(0, -1)           // flatten to [24]
r := t.Unsqueeze(0)             // [1, 2, 3, 4]
r := t.Squeeze(0)               // remove dim 0 if size 1
r := t.Permute([]int{2, 0, 1})  // reorder dimensions
```

## Indexing and Slicing

```go
// Basic indexing
val := t.Index(0, 1, 2)       // scalar at [0, 1, 2]

// Slicing
s := t.Slice(0, 0, 2)         // first two elements along dim 0
s := t.SliceRange(1, 1, 3)    // elements 1..3 along dim 1

// Boolean masking
mask := t.Gt(0.0)             // boolean tensor
positive := t.MaskedSelect(mask)

// Gather / Scatter
gathered := t.Gather(1, indices)
```

## Autograd

Tensors support automatic differentiation for training:

```rust
let x = Tensor::randn(&[10, 5], DType::Float32)?.requires_grad(true);
let w = Tensor::randn(&[5, 3], DType::Float32)?.requires_grad(true);

let y = x.matmul(&w)?;
let loss = y.sum()?;

loss.backward()?;

println!("dL/dw shape: {:?}", w.grad()?.shape());  // [5, 3]
```

## Device Transfer and Type Casting

```go
// Move to device
tGPU := t.To(device)

// Cast dtype
tF16 := t.ToType(tensor.Float16)

// Contiguous (ensure memory layout is C-contiguous)
tContig := t.Contiguous()
```

## Interoperability

### NumPy (Python)

```python
import numpy as np
import aethelred

np_array = np.random.randn(3, 4).astype(np.float32)
t = aethelred.Tensor.from_numpy(np_array)

back_to_numpy = t.numpy()
```

### PyTorch (Python)

```python
import torch
import aethelred

torch_tensor = torch.randn(3, 4)
t = aethelred.Tensor.from_torch(torch_tensor)

back_to_torch = t.to_torch()
```

## Related Pages

- [Runtime & Devices](/guide/runtime) -- device management for tensors
- [Neural Networks](/guide/neural-networks) -- tensors as module parameters
- [Quantization](/guide/quantization) -- reduced-precision tensor operations
- [zkML Proofs](/guide/zkml-proofs) -- proving tensor computations in zero knowledge
