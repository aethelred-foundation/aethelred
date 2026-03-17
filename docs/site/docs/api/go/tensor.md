# Go Tensor API

The `tensor` package provides multi-dimensional array operations with NumPy-compatible semantics, automatic differentiation, and GPU acceleration.

## Import

```go
import "github.com/aethelred/sdk-go/tensor"
```

## Creation Functions

### FromSlice

Creates a tensor from a Go slice with the given shape.

```go
func FromSlice[T Number](data []T, shape []int) *Tensor
```

```go
t := tensor.FromSlice([]float32{1, 2, 3, 4, 5, 6}, []int{2, 3})
```

### Zeros / Ones / Full

```go
func Zeros(shape []int, dtype DType, device Device) *Tensor
func Ones(shape []int, dtype DType, device Device) *Tensor
func Full(shape []int, value float64, dtype DType, device Device) *Tensor
```

### Randn / Rand / RandInt

```go
func Randn(shape []int, dtype DType, device Device) *Tensor    // normal distribution
func Rand(shape []int, dtype DType, device Device) *Tensor     // uniform [0, 1)
func RandInt(low, high int, shape []int, device Device) *Tensor
```

### Arange / Linspace

```go
func Arange(start, end, step float64, dtype DType, device Device) *Tensor
func Linspace(start, end float64, steps int, dtype DType, device Device) *Tensor
```

### Eye / Diag

```go
func Eye(n int, dtype DType, device Device) *Tensor
func Diag(input *Tensor, diagonal int) *Tensor
```

## Tensor Properties

```go
func (t *Tensor) Shape() []int        // dimension sizes
func (t *Tensor) Rank() int           // number of dimensions
func (t *Tensor) DType() DType        // data type
func (t *Tensor) Device() Device      // storage device
func (t *Tensor) NumElements() int    // total element count
func (t *Tensor) IsContiguous() bool  // memory layout check
func (t *Tensor) RequiresGrad() bool  // autograd tracking
```

## DType Constants

```go
const (
    Float64  DType = "float64"
    Float32  DType = "float32"
    Float16  DType = "float16"
    BFloat16 DType = "bfloat16"
    Int64    DType = "int64"
    Int32    DType = "int32"
    Int8     DType = "int8"
    UInt8    DType = "uint8"
    Bool     DType = "bool"
)
```

## Arithmetic Operations

All operations support broadcasting.

```go
func (t *Tensor) Add(other *Tensor) *Tensor
func (t *Tensor) Sub(other *Tensor) *Tensor
func (t *Tensor) Mul(other *Tensor) *Tensor
func (t *Tensor) Div(other *Tensor) *Tensor
func (t *Tensor) Pow(exponent float64) *Tensor
func (t *Tensor) Neg() *Tensor
func (t *Tensor) Abs() *Tensor
func (t *Tensor) Sqrt() *Tensor
func (t *Tensor) Exp() *Tensor
func (t *Tensor) Log() *Tensor
func (t *Tensor) Clamp(min, max float64) *Tensor
```

## Linear Algebra

```go
func (t *Tensor) MatMul(other *Tensor) *Tensor
func (t *Tensor) T() *Tensor                      // 2D transpose
func (t *Tensor) Transpose(dim0, dim1 int) *Tensor
func (t *Tensor) Det() *Tensor
func (t *Tensor) Inverse() *Tensor
func (t *Tensor) Eig() (values *Tensor, vectors *Tensor)
func (t *Tensor) SVD() (u, s, v *Tensor)
func (t *Tensor) Norm(ord float64, dim int, keepDim bool) *Tensor
```

## Reduction Operations

```go
func (t *Tensor) Sum(dims []int) *Tensor
func (t *Tensor) Mean(dims []int) *Tensor
func (t *Tensor) Max(dims []int) *Tensor
func (t *Tensor) Min(dims []int) *Tensor
func (t *Tensor) Argmax(dim int) *Tensor
func (t *Tensor) Argmin(dim int) *Tensor
func (t *Tensor) Var(dims []int, unbiased bool) *Tensor
func (t *Tensor) Std(dims []int, unbiased bool) *Tensor
```

## Reshaping

```go
func (t *Tensor) Reshape(shape []int) *Tensor
func (t *Tensor) View(shape []int) *Tensor
func (t *Tensor) Flatten(startDim, endDim int) *Tensor
func (t *Tensor) Unsqueeze(dim int) *Tensor
func (t *Tensor) Squeeze(dim int) *Tensor
func (t *Tensor) Permute(dims []int) *Tensor
func (t *Tensor) Contiguous() *Tensor
func (t *Tensor) Expand(shape []int) *Tensor
```

## Indexing and Slicing

```go
func (t *Tensor) Index(indices ...int) *Tensor
func (t *Tensor) Slice(dim, start, end int) *Tensor
func (t *Tensor) MaskedSelect(mask *Tensor) *Tensor
func (t *Tensor) MaskedFill(mask *Tensor, value float64) *Tensor
func (t *Tensor) Gather(dim int, index *Tensor) *Tensor
func (t *Tensor) Scatter(dim int, index *Tensor, src *Tensor) *Tensor
```

## Comparison Operations

```go
func (t *Tensor) Eq(other *Tensor) *Tensor
func (t *Tensor) Ne(other *Tensor) *Tensor
func (t *Tensor) Gt(value float64) *Tensor
func (t *Tensor) Ge(value float64) *Tensor
func (t *Tensor) Lt(value float64) *Tensor
func (t *Tensor) Le(value float64) *Tensor
```

## Activation Functions

```go
func (t *Tensor) ReLU() *Tensor
func (t *Tensor) GELU() *Tensor
func (t *Tensor) Sigmoid() *Tensor
func (t *Tensor) Tanh() *Tensor
func (t *Tensor) Softmax(dim int) *Tensor
func (t *Tensor) LogSoftmax(dim int) *Tensor
func (t *Tensor) SiLU() *Tensor
```

## Device and Type Conversion

```go
func (t *Tensor) To(device Device) *Tensor
func (t *Tensor) ToType(dtype DType) *Tensor
func (t *Tensor) Item() float64                // scalar tensor to Go value
func (t *Tensor) ToSlice() []float64           // flatten to Go slice
```

## Autograd

```go
func (t *Tensor) SetRequiresGrad(requires bool) *Tensor
func (t *Tensor) Grad() *Tensor
func (t *Tensor) Backward() error
func (t *Tensor) DetachGrad() *Tensor
```

## Concatenation and Stacking

```go
func Cat(tensors []*Tensor, dim int) *Tensor
func Stack(tensors []*Tensor, dim int) *Tensor
func Split(t *Tensor, splitSize int, dim int) []*Tensor
func Chunk(t *Tensor, chunks int, dim int) []*Tensor
```

## Related Pages

- [Tensor Operations Guide](/guide/tensors) -- conceptual overview
- [Go Runtime API](/api/go/runtime) -- device management
- [Go Neural Network API](/api/go/nn) -- modules that operate on tensors
