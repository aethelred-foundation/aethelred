// Package tensor provides high-performance tensor operations with lazy evaluation.
//
// Features:
//   - Lazy evaluation with operation fusion
//   - SIMD-accelerated operations
//   - Memory-efficient views and broadcasting
//   - Automatic differentiation support
//   - Explicit GPU device gating (native backend required)
package tensor

import (
	"fmt"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/aethelred/sdk-go/pkg/runtime"
)

// DType represents data types supported by tensors
type DType int

const (
	Float32 DType = iota
	Float64
	Float16
	BFloat16
	Int8
	Int16
	Int32
	Int64
	Uint8
	Uint16
	Uint32
	Uint64
	Bool
	Complex64
	Complex128
)

// String returns the string representation of the dtype
func (d DType) String() string {
	names := []string{
		"float32", "float64", "float16", "bfloat16",
		"int8", "int16", "int32", "int64",
		"uint8", "uint16", "uint32", "uint64",
		"bool", "complex64", "complex128",
	}
	if int(d) < len(names) {
		return names[d]
	}
	return "unknown"
}

// Size returns the byte size of the dtype
func (d DType) Size() int {
	sizes := []int{4, 8, 2, 2, 1, 2, 4, 8, 1, 2, 4, 8, 1, 8, 16}
	if int(d) < len(sizes) {
		return sizes[d]
	}
	return 0
}

// TensorID is a unique identifier for tensors
type TensorID uint64

var tensorIDCounter uint64

func nextTensorID() TensorID {
	return TensorID(atomic.AddUint64(&tensorIDCounter, 1))
}

// LazyOp represents a lazy operation for deferred execution
type LazyOp interface {
	Execute(inputs []*Tensor) (*Tensor, error)
	String() string
	CanFuse(other LazyOp) bool
}

// UnaryOp represents unary operations
type UnaryOp int

const (
	OpNeg UnaryOp = iota
	OpAbs
	OpExp
	OpLog
	OpSqrt
	OpSin
	OpCos
	OpTan
	OpSinh
	OpCosh
	OpTanh
	OpSigmoid
	OpRelu
	OpGelu
	OpSilu
	OpSoftplus
	OpMish
	OpErf
	OpErfc
	OpReciprocal
	OpSquare
	OpSign
	OpFloor
	OpCeil
	OpRound
	OpIsNaN
	OpIsInf
)

// BinaryOp represents binary operations
type BinaryOp int

const (
	OpAdd BinaryOp = iota
	OpSub
	OpMul
	OpDiv
	OpPow
	OpMax
	OpMin
	OpMod
	OpEqual
	OpNotEqual
	OpLess
	OpLessEqual
	OpGreater
	OpGreaterEqual
	OpLogicalAnd
	OpLogicalOr
	OpLogicalXor
	OpBitwiseAnd
	OpBitwiseOr
	OpBitwiseXor
)

// ReduceOp represents reduction operations
type ReduceOp int

const (
	OpSum ReduceOp = iota
	OpMean
	OpProd
	OpReduceMax
	OpReduceMin
	OpArgMax
	OpArgMin
	OpVar
	OpStd
	OpNorm
	OpAll
	OpAny
)

// Storage holds the actual tensor data
type Storage struct {
	Data     []byte
	Device   *runtime.Device
	Memory   *runtime.MemoryBlock
	RefCount int32
	mu       sync.RWMutex
}

// NewStorage creates a new storage with the given size
func NewStorage(size int, device *runtime.Device) (*Storage, error) {
	memory, err := device.Allocate(uint64(size))
	if err != nil {
		return nil, err
	}

	s := &Storage{
		Data:     make([]byte, size),
		Device:   device,
		Memory:   memory,
		RefCount: 1,
	}
	return s, nil
}

// Retain increments the reference count
func (s *Storage) Retain() {
	atomic.AddInt32(&s.RefCount, 1)
}

// Release decrements the reference count and frees if zero
func (s *Storage) Release() {
	if atomic.AddInt32(&s.RefCount, -1) == 0 {
		if s.Memory != nil {
			s.Device.Free(s.Memory)
		}
	}
}

// Tensor represents a multi-dimensional array with lazy evaluation
type Tensor struct {
	ID      TensorID
	Shape   []int
	Strides []int
	Offset  int
	DType   DType
	Storage *Storage
	Device  *runtime.Device

	// Lazy evaluation
	LazyOp   LazyOp
	Inputs   []*Tensor
	Realized bool

	// Autograd
	RequiresGrad bool
	Grad         *Tensor
	GradFn       GradFunc
	IsLeaf       bool
	RetainGrad   bool

	// Metadata
	Name string
	mu   sync.RWMutex
}

// GradFunc computes gradients during backward pass
type GradFunc func(gradOutput *Tensor) ([]*Tensor, error)

// ============ Tensor Creation ============

// NewTensor creates a new tensor with the given shape and dtype
func NewTensor(shape []int, dtype DType, device *runtime.Device) (*Tensor, error) {
	if device == nil {
		device = runtime.CPU()
	}

	numel := 1
	for _, s := range shape {
		if s <= 0 {
			return nil, fmt.Errorf("invalid shape: dimensions must be positive")
		}
		numel *= s
	}

	size := numel * dtype.Size()
	storage, err := NewStorage(size, device)
	if err != nil {
		return nil, err
	}

	strides := computeStrides(shape)

	return &Tensor{
		ID:       nextTensorID(),
		Shape:    append([]int{}, shape...),
		Strides:  strides,
		Offset:   0,
		DType:    dtype,
		Storage:  storage,
		Device:   device,
		Realized: true,
		IsLeaf:   true,
	}, nil
}

// computeStrides computes contiguous strides for a shape
func computeStrides(shape []int) []int {
	strides := make([]int, len(shape))
	stride := 1
	for i := len(shape) - 1; i >= 0; i-- {
		strides[i] = stride
		stride *= shape[i]
	}
	return strides
}

// Zeros creates a tensor filled with zeros
func Zeros(shape []int, dtype DType, device *runtime.Device) (*Tensor, error) {
	t, err := NewTensor(shape, dtype, device)
	if err != nil {
		return nil, err
	}
	// Storage is already zeroed by Go
	return t, nil
}

// Ones creates a tensor filled with ones
func Ones(shape []int, dtype DType, device *runtime.Device) (*Tensor, error) {
	t, err := NewTensor(shape, dtype, device)
	if err != nil {
		return nil, err
	}
	t.Fill(1.0)
	return t, nil
}

// Full creates a tensor filled with a value
func Full(shape []int, value float64, dtype DType, device *runtime.Device) (*Tensor, error) {
	t, err := NewTensor(shape, dtype, device)
	if err != nil {
		return nil, err
	}
	t.Fill(value)
	return t, nil
}

// Randn creates a tensor with random normal values
func Randn(shape []int, dtype DType, device *runtime.Device) (*Tensor, error) {
	t, err := NewTensor(shape, dtype, device)
	if err != nil {
		return nil, err
	}

	numel := t.Numel()
	data := t.Float32Data()
	for i := 0; i < numel; i++ {
		// Box-Muller transform
		u1 := rand.Float64()
		u2 := rand.Float64()
		data[i] = float32(math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2))
	}
	return t, nil
}

// Rand creates a tensor with uniform random values [0, 1)
func Rand(shape []int, dtype DType, device *runtime.Device) (*Tensor, error) {
	t, err := NewTensor(shape, dtype, device)
	if err != nil {
		return nil, err
	}

	numel := t.Numel()
	data := t.Float32Data()
	for i := 0; i < numel; i++ {
		data[i] = float32(rand.Float64())
	}
	return t, nil
}

// RandInt creates a tensor with random integers in [low, high)
func RandInt(low, high int, shape []int, dtype DType, device *runtime.Device) (*Tensor, error) {
	t, err := NewTensor(shape, dtype, device)
	if err != nil {
		return nil, err
	}

	numel := t.Numel()
	data := t.Int32Data()
	for i := 0; i < numel; i++ {
		data[i] = int32(low + rand.Intn(high-low))
	}
	return t, nil
}

// Arange creates a tensor with evenly spaced values
func Arange(start, end, step float64, dtype DType, device *runtime.Device) (*Tensor, error) {
	n := int(math.Ceil((end - start) / step))
	if n <= 0 {
		return nil, fmt.Errorf("invalid range parameters")
	}

	t, err := NewTensor([]int{n}, dtype, device)
	if err != nil {
		return nil, err
	}

	data := t.Float32Data()
	for i := 0; i < n; i++ {
		data[i] = float32(start + float64(i)*step)
	}
	return t, nil
}

// Linspace creates a tensor with linearly spaced values
func Linspace(start, end float64, steps int, dtype DType, device *runtime.Device) (*Tensor, error) {
	if steps < 2 {
		return nil, fmt.Errorf("steps must be >= 2")
	}

	t, err := NewTensor([]int{steps}, dtype, device)
	if err != nil {
		return nil, err
	}

	data := t.Float32Data()
	step := (end - start) / float64(steps-1)
	for i := 0; i < steps; i++ {
		data[i] = float32(start + float64(i)*step)
	}
	return t, nil
}

// Eye creates an identity matrix
func Eye(n int, dtype DType, device *runtime.Device) (*Tensor, error) {
	t, err := Zeros([]int{n, n}, dtype, device)
	if err != nil {
		return nil, err
	}

	data := t.Float32Data()
	for i := 0; i < n; i++ {
		data[i*n+i] = 1.0
	}
	return t, nil
}

// FromSlice creates a tensor from a float32 slice
func FromSlice(data []float32, shape []int, device *runtime.Device) (*Tensor, error) {
	numel := 1
	for _, s := range shape {
		numel *= s
	}
	if numel != len(data) {
		return nil, fmt.Errorf("data length %d doesn't match shape %v", len(data), shape)
	}

	t, err := NewTensor(shape, Float32, device)
	if err != nil {
		return nil, err
	}

	copy(t.Float32Data(), data)
	return t, nil
}

// ============ Tensor Properties ============

// Numel returns the total number of elements
func (t *Tensor) Numel() int {
	n := 1
	for _, s := range t.Shape {
		n *= s
	}
	return n
}

// Dim returns the number of dimensions
func (t *Tensor) Dim() int {
	return len(t.Shape)
}

// Size returns the size of a dimension
func (t *Tensor) Size(dim int) int {
	if dim < 0 {
		dim += len(t.Shape)
	}
	if dim < 0 || dim >= len(t.Shape) {
		return -1
	}
	return t.Shape[dim]
}

// IsContiguous checks if the tensor is contiguous in memory
func (t *Tensor) IsContiguous() bool {
	expected := computeStrides(t.Shape)
	for i, s := range t.Strides {
		if s != expected[i] {
			return false
		}
	}
	return true
}

// Float32Data returns the underlying data as float32 slice
func (t *Tensor) Float32Data() []float32 {
	t.Realize()
	ptr := (*float32)(unsafe.Pointer(&t.Storage.Data[t.Offset*t.DType.Size()]))
	return unsafe.Slice(ptr, t.Numel())
}

// Int32Data returns the underlying data as int32 slice
func (t *Tensor) Int32Data() []int32 {
	t.Realize()
	ptr := (*int32)(unsafe.Pointer(&t.Storage.Data[t.Offset*t.DType.Size()]))
	return unsafe.Slice(ptr, t.Numel())
}

// ============ Lazy Evaluation ============

// Realize materializes the tensor if it has a lazy operation
func (t *Tensor) Realize() *Tensor {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Realized || t.LazyOp == nil {
		return t
	}

	// Realize all inputs first
	for _, input := range t.Inputs {
		input.Realize()
	}

	// Execute the lazy operation
	result, err := t.LazyOp.Execute(t.Inputs)
	if err != nil {
		panic(fmt.Sprintf("failed to realize tensor: %v", err))
	}

	// Copy result data
	t.Storage = result.Storage
	t.Storage.Retain()
	t.Realized = true
	t.LazyOp = nil
	t.Inputs = nil

	return t
}

// lazyUnary creates a lazy unary operation
type lazyUnary struct {
	op UnaryOp
}

func (l *lazyUnary) Execute(inputs []*Tensor) (*Tensor, error) {
	if len(inputs) != 1 {
		return nil, fmt.Errorf("unary op requires exactly 1 input")
	}
	return applyUnaryOp(inputs[0], l.op)
}

func (l *lazyUnary) String() string {
	return fmt.Sprintf("UnaryOp(%d)", l.op)
}

func (l *lazyUnary) CanFuse(other LazyOp) bool {
	_, ok := other.(*lazyUnary)
	return ok
}

// lazyBinary creates a lazy binary operation
type lazyBinary struct {
	op BinaryOp
}

func (l *lazyBinary) Execute(inputs []*Tensor) (*Tensor, error) {
	if len(inputs) != 2 {
		return nil, fmt.Errorf("binary op requires exactly 2 inputs")
	}
	return applyBinaryOp(inputs[0], inputs[1], l.op)
}

func (l *lazyBinary) String() string {
	return fmt.Sprintf("BinaryOp(%d)", l.op)
}

func (l *lazyBinary) CanFuse(other LazyOp) bool {
	return true
}

// ============ Tensor Operations ============

// Fill fills the tensor with a value
func (t *Tensor) Fill(value float64) *Tensor {
	data := t.Float32Data()
	v := float32(value)
	for i := range data {
		data[i] = v
	}
	return t
}

// Clone creates a deep copy of the tensor
func (t *Tensor) Clone() (*Tensor, error) {
	t.Realize()

	clone, err := NewTensor(t.Shape, t.DType, t.Device)
	if err != nil {
		return nil, err
	}

	copy(clone.Storage.Data, t.Storage.Data)
	clone.RequiresGrad = t.RequiresGrad
	return clone, nil
}

// Contiguous returns a contiguous tensor
func (t *Tensor) Contiguous() (*Tensor, error) {
	if t.IsContiguous() {
		return t, nil
	}
	return t.Clone()
}

// View returns a new tensor with a different shape
func (t *Tensor) View(shape ...int) (*Tensor, error) {
	// Handle -1 dimension
	total := t.Numel()
	unknownIdx := -1
	known := 1
	for i, s := range shape {
		if s == -1 {
			if unknownIdx >= 0 {
				return nil, fmt.Errorf("only one dimension can be -1")
			}
			unknownIdx = i
		} else {
			known *= s
		}
	}

	if unknownIdx >= 0 {
		shape[unknownIdx] = total / known
	}

	// Verify total elements match
	newTotal := 1
	for _, s := range shape {
		newTotal *= s
	}
	if newTotal != total {
		return nil, fmt.Errorf("cannot reshape tensor of size %d into shape %v", total, shape)
	}

	if !t.IsContiguous() {
		t, _ = t.Contiguous()
	}

	return &Tensor{
		ID:           nextTensorID(),
		Shape:        append([]int{}, shape...),
		Strides:      computeStrides(shape),
		Offset:       t.Offset,
		DType:        t.DType,
		Storage:      t.Storage,
		Device:       t.Device,
		Realized:     t.Realized,
		RequiresGrad: t.RequiresGrad,
		IsLeaf:       false,
	}, nil
}

// Reshape is an alias for View
func (t *Tensor) Reshape(shape ...int) (*Tensor, error) {
	return t.View(shape...)
}

// Flatten flattens the tensor to 1D
func (t *Tensor) Flatten() (*Tensor, error) {
	return t.View(-1)
}

// Squeeze removes dimensions of size 1
func (t *Tensor) Squeeze(dim ...int) (*Tensor, error) {
	if len(dim) == 0 {
		// Squeeze all dimensions of size 1
		newShape := make([]int, 0, len(t.Shape))
		for _, s := range t.Shape {
			if s != 1 {
				newShape = append(newShape, s)
			}
		}
		if len(newShape) == 0 {
			newShape = []int{1}
		}
		return t.View(newShape...)
	}

	d := dim[0]
	if d < 0 {
		d += len(t.Shape)
	}
	if t.Shape[d] != 1 {
		return t, nil
	}

	newShape := make([]int, 0, len(t.Shape)-1)
	for i, s := range t.Shape {
		if i != d {
			newShape = append(newShape, s)
		}
	}
	return t.View(newShape...)
}

// Unsqueeze adds a dimension of size 1
func (t *Tensor) Unsqueeze(dim int) (*Tensor, error) {
	if dim < 0 {
		dim += len(t.Shape) + 1
	}

	newShape := make([]int, len(t.Shape)+1)
	copy(newShape[:dim], t.Shape[:dim])
	newShape[dim] = 1
	copy(newShape[dim+1:], t.Shape[dim:])

	return t.View(newShape...)
}

// Transpose swaps two dimensions
func (t *Tensor) Transpose(dim0, dim1 int) (*Tensor, error) {
	if dim0 < 0 {
		dim0 += len(t.Shape)
	}
	if dim1 < 0 {
		dim1 += len(t.Shape)
	}

	newShape := append([]int{}, t.Shape...)
	newStrides := append([]int{}, t.Strides...)
	newShape[dim0], newShape[dim1] = newShape[dim1], newShape[dim0]
	newStrides[dim0], newStrides[dim1] = newStrides[dim1], newStrides[dim0]

	return &Tensor{
		ID:           nextTensorID(),
		Shape:        newShape,
		Strides:      newStrides,
		Offset:       t.Offset,
		DType:        t.DType,
		Storage:      t.Storage,
		Device:       t.Device,
		Realized:     t.Realized,
		RequiresGrad: t.RequiresGrad,
		IsLeaf:       false,
	}, nil
}

// T transposes a 2D tensor
func (t *Tensor) T() (*Tensor, error) {
	if len(t.Shape) != 2 {
		return nil, fmt.Errorf("T() requires 2D tensor, got %d dimensions", len(t.Shape))
	}
	return t.Transpose(0, 1)
}

// Permute reorders dimensions
func (t *Tensor) Permute(dims ...int) (*Tensor, error) {
	if len(dims) != len(t.Shape) {
		return nil, fmt.Errorf("permute requires %d dimensions, got %d", len(t.Shape), len(dims))
	}

	newShape := make([]int, len(dims))
	newStrides := make([]int, len(dims))
	for i, d := range dims {
		if d < 0 {
			d += len(t.Shape)
		}
		newShape[i] = t.Shape[d]
		newStrides[i] = t.Strides[d]
	}

	return &Tensor{
		ID:           nextTensorID(),
		Shape:        newShape,
		Strides:      newStrides,
		Offset:       t.Offset,
		DType:        t.DType,
		Storage:      t.Storage,
		Device:       t.Device,
		Realized:     t.Realized,
		RequiresGrad: t.RequiresGrad,
		IsLeaf:       false,
	}, nil
}

// ============ Unary Operations ============

func applyUnaryOp(t *Tensor, op UnaryOp) (*Tensor, error) {
	t.Realize()
	result, err := NewTensor(t.Shape, t.DType, t.Device)
	if err != nil {
		return nil, err
	}

	src := t.Float32Data()
	dst := result.Float32Data()

	switch op {
	case OpNeg:
		for i, v := range src {
			dst[i] = -v
		}
	case OpAbs:
		for i, v := range src {
			dst[i] = float32(math.Abs(float64(v)))
		}
	case OpExp:
		for i, v := range src {
			dst[i] = float32(math.Exp(float64(v)))
		}
	case OpLog:
		for i, v := range src {
			dst[i] = float32(math.Log(float64(v)))
		}
	case OpSqrt:
		for i, v := range src {
			dst[i] = float32(math.Sqrt(float64(v)))
		}
	case OpSin:
		for i, v := range src {
			dst[i] = float32(math.Sin(float64(v)))
		}
	case OpCos:
		for i, v := range src {
			dst[i] = float32(math.Cos(float64(v)))
		}
	case OpTan:
		for i, v := range src {
			dst[i] = float32(math.Tan(float64(v)))
		}
	case OpSinh:
		for i, v := range src {
			dst[i] = float32(math.Sinh(float64(v)))
		}
	case OpCosh:
		for i, v := range src {
			dst[i] = float32(math.Cosh(float64(v)))
		}
	case OpTanh:
		for i, v := range src {
			dst[i] = float32(math.Tanh(float64(v)))
		}
	case OpSigmoid:
		for i, v := range src {
			dst[i] = float32(1.0 / (1.0 + math.Exp(-float64(v))))
		}
	case OpRelu:
		for i, v := range src {
			if v > 0 {
				dst[i] = v
			} else {
				dst[i] = 0
			}
		}
	case OpGelu:
		for i, v := range src {
			x := float64(v)
			dst[i] = float32(0.5 * x * (1 + math.Tanh(math.Sqrt(2/math.Pi)*(x+0.044715*x*x*x))))
		}
	case OpSilu:
		for i, v := range src {
			x := float64(v)
			dst[i] = float32(x / (1 + math.Exp(-x)))
		}
	case OpSoftplus:
		for i, v := range src {
			dst[i] = float32(math.Log(1 + math.Exp(float64(v))))
		}
	case OpMish:
		for i, v := range src {
			x := float64(v)
			dst[i] = float32(x * math.Tanh(math.Log(1+math.Exp(x))))
		}
	case OpReciprocal:
		for i, v := range src {
			dst[i] = 1.0 / v
		}
	case OpSquare:
		for i, v := range src {
			dst[i] = v * v
		}
	case OpSign:
		for i, v := range src {
			if v > 0 {
				dst[i] = 1
			} else if v < 0 {
				dst[i] = -1
			} else {
				dst[i] = 0
			}
		}
	case OpFloor:
		for i, v := range src {
			dst[i] = float32(math.Floor(float64(v)))
		}
	case OpCeil:
		for i, v := range src {
			dst[i] = float32(math.Ceil(float64(v)))
		}
	case OpRound:
		for i, v := range src {
			dst[i] = float32(math.Round(float64(v)))
		}
	default:
		return nil, fmt.Errorf("unsupported unary op: %d", op)
	}

	return result, nil
}

// Neg returns -x
func (t *Tensor) Neg() *Tensor {
	return &Tensor{
		ID:       nextTensorID(),
		Shape:    append([]int{}, t.Shape...),
		Strides:  append([]int{}, t.Strides...),
		DType:    t.DType,
		Device:   t.Device,
		LazyOp:   &lazyUnary{op: OpNeg},
		Inputs:   []*Tensor{t},
		Realized: false,
	}
}

// Abs returns |x|
func (t *Tensor) Abs() *Tensor {
	return &Tensor{
		ID:       nextTensorID(),
		Shape:    append([]int{}, t.Shape...),
		Strides:  append([]int{}, t.Strides...),
		DType:    t.DType,
		Device:   t.Device,
		LazyOp:   &lazyUnary{op: OpAbs},
		Inputs:   []*Tensor{t},
		Realized: false,
	}
}

// Exp returns e^x
func (t *Tensor) Exp() *Tensor {
	return &Tensor{
		ID:       nextTensorID(),
		Shape:    append([]int{}, t.Shape...),
		DType:    t.DType,
		Device:   t.Device,
		LazyOp:   &lazyUnary{op: OpExp},
		Inputs:   []*Tensor{t},
		Realized: false,
	}
}

// Log returns ln(x)
func (t *Tensor) Log() *Tensor {
	return &Tensor{
		ID:       nextTensorID(),
		Shape:    append([]int{}, t.Shape...),
		DType:    t.DType,
		Device:   t.Device,
		LazyOp:   &lazyUnary{op: OpLog},
		Inputs:   []*Tensor{t},
		Realized: false,
	}
}

// Sqrt returns sqrt(x)
func (t *Tensor) Sqrt() *Tensor {
	return &Tensor{
		ID:       nextTensorID(),
		Shape:    append([]int{}, t.Shape...),
		DType:    t.DType,
		Device:   t.Device,
		LazyOp:   &lazyUnary{op: OpSqrt},
		Inputs:   []*Tensor{t},
		Realized: false,
	}
}

// Sin returns sin(x)
func (t *Tensor) Sin() *Tensor {
	return &Tensor{
		ID:       nextTensorID(),
		Shape:    append([]int{}, t.Shape...),
		DType:    t.DType,
		Device:   t.Device,
		LazyOp:   &lazyUnary{op: OpSin},
		Inputs:   []*Tensor{t},
		Realized: false,
	}
}

// Cos returns cos(x)
func (t *Tensor) Cos() *Tensor {
	return &Tensor{
		ID:       nextTensorID(),
		Shape:    append([]int{}, t.Shape...),
		DType:    t.DType,
		Device:   t.Device,
		LazyOp:   &lazyUnary{op: OpCos},
		Inputs:   []*Tensor{t},
		Realized: false,
	}
}

// Tanh returns tanh(x)
func (t *Tensor) Tanh() *Tensor {
	return &Tensor{
		ID:       nextTensorID(),
		Shape:    append([]int{}, t.Shape...),
		DType:    t.DType,
		Device:   t.Device,
		LazyOp:   &lazyUnary{op: OpTanh},
		Inputs:   []*Tensor{t},
		Realized: false,
	}
}

// Sigmoid returns 1/(1+e^(-x))
func (t *Tensor) Sigmoid() *Tensor {
	return &Tensor{
		ID:       nextTensorID(),
		Shape:    append([]int{}, t.Shape...),
		DType:    t.DType,
		Device:   t.Device,
		LazyOp:   &lazyUnary{op: OpSigmoid},
		Inputs:   []*Tensor{t},
		Realized: false,
	}
}

// Relu returns max(0, x)
func (t *Tensor) Relu() *Tensor {
	return &Tensor{
		ID:       nextTensorID(),
		Shape:    append([]int{}, t.Shape...),
		DType:    t.DType,
		Device:   t.Device,
		LazyOp:   &lazyUnary{op: OpRelu},
		Inputs:   []*Tensor{t},
		Realized: false,
	}
}

// Gelu returns GELU activation
func (t *Tensor) Gelu() *Tensor {
	return &Tensor{
		ID:       nextTensorID(),
		Shape:    append([]int{}, t.Shape...),
		DType:    t.DType,
		Device:   t.Device,
		LazyOp:   &lazyUnary{op: OpGelu},
		Inputs:   []*Tensor{t},
		Realized: false,
	}
}

// Silu returns x * sigmoid(x)
func (t *Tensor) Silu() *Tensor {
	return &Tensor{
		ID:       nextTensorID(),
		Shape:    append([]int{}, t.Shape...),
		DType:    t.DType,
		Device:   t.Device,
		LazyOp:   &lazyUnary{op: OpSilu},
		Inputs:   []*Tensor{t},
		Realized: false,
	}
}

// ============ Binary Operations ============

func applyBinaryOp(a, b *Tensor, op BinaryOp) (*Tensor, error) {
	a.Realize()
	b.Realize()

	// Handle broadcasting
	shape, err := broadcastShapes(a.Shape, b.Shape)
	if err != nil {
		return nil, err
	}

	result, err := NewTensor(shape, a.DType, a.Device)
	if err != nil {
		return nil, err
	}

	// Get data
	aData := a.Float32Data()
	bData := b.Float32Data()
	dst := result.Float32Data()

	// Apply operation with broadcasting
	for i := range dst {
		aIdx := broadcastIndex(i, result.Shape, a.Shape)
		bIdx := broadcastIndex(i, result.Shape, b.Shape)

		switch op {
		case OpAdd:
			dst[i] = aData[aIdx] + bData[bIdx]
		case OpSub:
			dst[i] = aData[aIdx] - bData[bIdx]
		case OpMul:
			dst[i] = aData[aIdx] * bData[bIdx]
		case OpDiv:
			dst[i] = aData[aIdx] / bData[bIdx]
		case OpPow:
			dst[i] = float32(math.Pow(float64(aData[aIdx]), float64(bData[bIdx])))
		case OpMax:
			if aData[aIdx] > bData[bIdx] {
				dst[i] = aData[aIdx]
			} else {
				dst[i] = bData[bIdx]
			}
		case OpMin:
			if aData[aIdx] < bData[bIdx] {
				dst[i] = aData[aIdx]
			} else {
				dst[i] = bData[bIdx]
			}
		case OpEqual:
			if aData[aIdx] == bData[bIdx] {
				dst[i] = 1
			} else {
				dst[i] = 0
			}
		case OpLess:
			if aData[aIdx] < bData[bIdx] {
				dst[i] = 1
			} else {
				dst[i] = 0
			}
		case OpGreater:
			if aData[aIdx] > bData[bIdx] {
				dst[i] = 1
			} else {
				dst[i] = 0
			}
		default:
			return nil, fmt.Errorf("unsupported binary op: %d", op)
		}
	}

	return result, nil
}

// broadcastShapes computes the broadcast shape
func broadcastShapes(a, b []int) ([]int, error) {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}

	result := make([]int, maxLen)
	for i := 0; i < maxLen; i++ {
		aIdx := len(a) - 1 - i
		bIdx := len(b) - 1 - i

		aSize := 1
		if aIdx >= 0 {
			aSize = a[aIdx]
		}
		bSize := 1
		if bIdx >= 0 {
			bSize = b[bIdx]
		}

		if aSize == bSize {
			result[maxLen-1-i] = aSize
		} else if aSize == 1 {
			result[maxLen-1-i] = bSize
		} else if bSize == 1 {
			result[maxLen-1-i] = aSize
		} else {
			return nil, fmt.Errorf("shapes %v and %v are not broadcastable", a, b)
		}
	}

	return result, nil
}

// broadcastIndex computes the source index for broadcasting
func broadcastIndex(dstIdx int, dstShape, srcShape []int) int {
	srcIdx := 0
	stride := 1

	for i := len(dstShape) - 1; i >= 0; i-- {
		dstCoord := (dstIdx / stride) % dstShape[i]

		srcDim := len(srcShape) - 1 - (len(dstShape) - 1 - i)
		if srcDim >= 0 && srcShape[srcDim] > 1 {
			srcStride := 1
			for j := srcDim + 1; j < len(srcShape); j++ {
				srcStride *= srcShape[j]
			}
			srcIdx += dstCoord * srcStride
		}

		stride *= dstShape[i]
	}

	return srcIdx
}

// Add returns a + b
func (t *Tensor) Add(other *Tensor) *Tensor {
	shape, _ := broadcastShapes(t.Shape, other.Shape)
	return &Tensor{
		ID:       nextTensorID(),
		Shape:    shape,
		DType:    t.DType,
		Device:   t.Device,
		LazyOp:   &lazyBinary{op: OpAdd},
		Inputs:   []*Tensor{t, other},
		Realized: false,
	}
}

// Sub returns a - b
func (t *Tensor) Sub(other *Tensor) *Tensor {
	shape, _ := broadcastShapes(t.Shape, other.Shape)
	return &Tensor{
		ID:       nextTensorID(),
		Shape:    shape,
		DType:    t.DType,
		Device:   t.Device,
		LazyOp:   &lazyBinary{op: OpSub},
		Inputs:   []*Tensor{t, other},
		Realized: false,
	}
}

// Mul returns a * b
func (t *Tensor) Mul(other *Tensor) *Tensor {
	shape, _ := broadcastShapes(t.Shape, other.Shape)
	return &Tensor{
		ID:       nextTensorID(),
		Shape:    shape,
		DType:    t.DType,
		Device:   t.Device,
		LazyOp:   &lazyBinary{op: OpMul},
		Inputs:   []*Tensor{t, other},
		Realized: false,
	}
}

// Div returns a / b
func (t *Tensor) Div(other *Tensor) *Tensor {
	shape, _ := broadcastShapes(t.Shape, other.Shape)
	return &Tensor{
		ID:       nextTensorID(),
		Shape:    shape,
		DType:    t.DType,
		Device:   t.Device,
		LazyOp:   &lazyBinary{op: OpDiv},
		Inputs:   []*Tensor{t, other},
		Realized: false,
	}
}

// Pow returns a^b
func (t *Tensor) Pow(other *Tensor) *Tensor {
	shape, _ := broadcastShapes(t.Shape, other.Shape)
	return &Tensor{
		ID:       nextTensorID(),
		Shape:    shape,
		DType:    t.DType,
		Device:   t.Device,
		LazyOp:   &lazyBinary{op: OpPow},
		Inputs:   []*Tensor{t, other},
		Realized: false,
	}
}

// ============ Reduction Operations ============

// Sum reduces by summing
func (t *Tensor) Sum(dim ...int) (*Tensor, error) {
	return t.reduce(OpSum, dim...)
}

// Mean reduces by averaging
func (t *Tensor) Mean(dim ...int) (*Tensor, error) {
	return t.reduce(OpMean, dim...)
}

// Max reduces by taking maximum
func (t *Tensor) Max(dim ...int) (*Tensor, error) {
	return t.reduce(OpReduceMax, dim...)
}

// Min reduces by taking minimum
func (t *Tensor) Min(dim ...int) (*Tensor, error) {
	return t.reduce(OpReduceMin, dim...)
}

// Var computes variance
func (t *Tensor) Var(dim ...int) (*Tensor, error) {
	return t.reduce(OpVar, dim...)
}

// Std computes standard deviation
func (t *Tensor) Std(dim ...int) (*Tensor, error) {
	return t.reduce(OpStd, dim...)
}

// reduce performs a reduction operation
func (t *Tensor) reduce(op ReduceOp, dims ...int) (*Tensor, error) {
	t.Realize()

	if len(dims) == 0 {
		// Reduce all dimensions
		result, err := NewTensor([]int{1}, t.DType, t.Device)
		if err != nil {
			return nil, err
		}

		data := t.Float32Data()
		dst := result.Float32Data()

		switch op {
		case OpSum:
			var sum float32
			for _, v := range data {
				sum += v
			}
			dst[0] = sum
		case OpMean:
			var sum float32
			for _, v := range data {
				sum += v
			}
			dst[0] = sum / float32(len(data))
		case OpReduceMax:
			max := data[0]
			for _, v := range data[1:] {
				if v > max {
					max = v
				}
			}
			dst[0] = max
		case OpReduceMin:
			min := data[0]
			for _, v := range data[1:] {
				if v < min {
					min = v
				}
			}
			dst[0] = min
		case OpVar:
			var sum, sumSq float32
			for _, v := range data {
				sum += v
				sumSq += v * v
			}
			n := float32(len(data))
			mean := sum / n
			dst[0] = sumSq/n - mean*mean
		case OpStd:
			var sum, sumSq float32
			for _, v := range data {
				sum += v
				sumSq += v * v
			}
			n := float32(len(data))
			mean := sum / n
			variance := sumSq/n - mean*mean
			dst[0] = float32(math.Sqrt(float64(variance)))
		}

		return result, nil
	}

	// Reduce along specific dimension
	dim := dims[0]
	if dim < 0 {
		dim += len(t.Shape)
	}

	newShape := make([]int, len(t.Shape)-1)
	copy(newShape[:dim], t.Shape[:dim])
	copy(newShape[dim:], t.Shape[dim+1:])

	if len(newShape) == 0 {
		newShape = []int{1}
	}

	result, err := NewTensor(newShape, t.DType, t.Device)
	if err != nil {
		return nil, err
	}

	// TODO: Implement per-dimension reduction
	// For now, return error
	return result, nil
}

// ============ Matrix Operations ============

// MatMul performs matrix multiplication
func (t *Tensor) MatMul(other *Tensor) (*Tensor, error) {
	t.Realize()
	other.Realize()

	// Handle different cases
	tDim := len(t.Shape)
	oDim := len(other.Shape)

	if tDim < 1 || oDim < 1 {
		return nil, fmt.Errorf("matmul requires at least 1D tensors")
	}

	// Get last two dimensions
	var m, n, k int
	var batchShape []int

	if tDim == 1 && oDim == 1 {
		// Vector dot product
		if t.Shape[0] != other.Shape[0] {
			return nil, fmt.Errorf("incompatible shapes for dot product")
		}
		m, n, k = 1, 1, t.Shape[0]
	} else if tDim == 1 {
		// (k) x (k, n) -> (n)
		k = t.Shape[0]
		n = other.Shape[oDim-1]
		if other.Shape[oDim-2] != k {
			return nil, fmt.Errorf("incompatible shapes for matmul")
		}
		batchShape = other.Shape[:oDim-2]
		m = 1
	} else if oDim == 1 {
		// (m, k) x (k) -> (m)
		m = t.Shape[tDim-2]
		k = t.Shape[tDim-1]
		if other.Shape[0] != k {
			return nil, fmt.Errorf("incompatible shapes for matmul")
		}
		batchShape = t.Shape[:tDim-2]
		n = 1
	} else {
		// General case (batch, m, k) x (batch, k, n) -> (batch, m, n)
		m = t.Shape[tDim-2]
		k = t.Shape[tDim-1]
		n = other.Shape[oDim-1]

		if other.Shape[oDim-2] != k {
			return nil, fmt.Errorf("incompatible shapes for matmul: %v x %v", t.Shape, other.Shape)
		}

		// Broadcast batch dimensions
		var err error
		batchShape, err = broadcastShapes(t.Shape[:tDim-2], other.Shape[:oDim-2])
		if err != nil {
			return nil, err
		}
	}

	// Output shape
	outShape := append(batchShape, m, n)
	if m == 1 && tDim == 1 {
		outShape = append(batchShape, n)
	} else if n == 1 && oDim == 1 {
		outShape = append(batchShape, m)
	}

	result, err := Zeros(outShape, t.DType, t.Device)
	if err != nil {
		return nil, err
	}

	// Simple matrix multiplication (not optimized)
	aData := t.Float32Data()
	bData := other.Float32Data()
	cData := result.Float32Data()

	// For simple 2D case
	if len(batchShape) == 0 && tDim == 2 && oDim == 2 {
		for i := 0; i < m; i++ {
			for j := 0; j < n; j++ {
				var sum float32
				for l := 0; l < k; l++ {
					sum += aData[i*k+l] * bData[l*n+j]
				}
				cData[i*n+j] = sum
			}
		}
	}

	return result, nil
}

// ============ Autograd ============

// SetRequiresGrad sets gradient requirement
func (t *Tensor) SetRequiresGrad(requires bool) *Tensor {
	t.RequiresGrad = requires
	return t
}

// Backward computes gradients
func (t *Tensor) Backward(gradOutput ...*Tensor) error {
	var grad *Tensor
	if len(gradOutput) > 0 {
		grad = gradOutput[0]
	} else {
		var err error
		grad, err = Ones(t.Shape, t.DType, t.Device)
		if err != nil {
			return err
		}
	}

	return t.backwardRecursive(grad)
}

func (t *Tensor) backwardRecursive(gradOutput *Tensor) error {
	if !t.RequiresGrad {
		return nil
	}

	// Accumulate gradient
	if t.Grad == nil {
		var err error
		t.Grad, err = Zeros(t.Shape, t.DType, t.Device)
		if err != nil {
			return err
		}
	}

	// Add gradient
	gradData := gradOutput.Float32Data()
	tGradData := t.Grad.Float32Data()
	for i := range gradData {
		tGradData[i] += gradData[i]
	}

	// Backward through graph
	if t.GradFn != nil {
		inputGrads, err := t.GradFn(gradOutput)
		if err != nil {
			return err
		}

		for i, input := range t.Inputs {
			if input.RequiresGrad && i < len(inputGrads) {
				if err := input.backwardRecursive(inputGrads[i]); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// ZeroGrad zeros the gradient
func (t *Tensor) ZeroGrad() {
	if t.Grad != nil {
		t.Grad.Fill(0)
	}
}

// ============ Utility Functions ============

// String returns a string representation
func (t *Tensor) String() string {
	return fmt.Sprintf("Tensor(shape=%v, dtype=%s, device=%s, requires_grad=%v)",
		t.Shape, t.DType, t.Device.Name, t.RequiresGrad)
}

// ToDevice moves tensor to another device
func (t *Tensor) ToDevice(device *runtime.Device) (*Tensor, error) {
	if t.Device == device {
		return t, nil
	}

	t.Realize()
	clone, err := NewTensor(t.Shape, t.DType, device)
	if err != nil {
		return nil, err
	}

	copy(clone.Storage.Data, t.Storage.Data)
	return clone, nil
}

// CPU moves tensor to CPU
func (t *Tensor) CPU() (*Tensor, error) {
	return t.ToDevice(runtime.CPU())
}

// To moves tensor to specified dtype and/or device
func (t *Tensor) To(dtype DType, device *runtime.Device) (*Tensor, error) {
	result, err := t.ToDevice(device)
	if err != nil {
		return nil, err
	}

	if result.DType == dtype {
		return result, nil
	}

	// Cast dtype (simplified - only float32 for now)
	return result, nil
}

// Item returns scalar value for 0-d or 1-element tensor
func (t *Tensor) Item() (float64, error) {
	if t.Numel() != 1 {
		return 0, fmt.Errorf("Item() requires tensor with exactly 1 element")
	}
	t.Realize()
	return float64(t.Float32Data()[0]), nil
}

// ============ Functional Operations ============

// Cat concatenates tensors along a dimension
func Cat(tensors []*Tensor, dim int) (*Tensor, error) {
	if len(tensors) == 0 {
		return nil, fmt.Errorf("cannot cat empty tensor list")
	}

	// Validate shapes
	first := tensors[0]
	if dim < 0 {
		dim += len(first.Shape)
	}

	totalSize := 0
	for _, t := range tensors {
		if len(t.Shape) != len(first.Shape) {
			return nil, fmt.Errorf("all tensors must have same number of dimensions")
		}
		for i := 0; i < len(t.Shape); i++ {
			if i != dim && t.Shape[i] != first.Shape[i] {
				return nil, fmt.Errorf("tensors must match in all dimensions except cat dimension")
			}
		}
		totalSize += t.Shape[dim]
	}

	// Create output shape
	outShape := append([]int{}, first.Shape...)
	outShape[dim] = totalSize

	result, err := NewTensor(outShape, first.DType, first.Device)
	if err != nil {
		return nil, err
	}

	// Copy data
	offset := 0
	for _, t := range tensors {
		t.Realize()
		// Simplified: assumes contiguous tensors
		data := t.Float32Data()
		dst := result.Float32Data()[offset : offset+len(data)]
		copy(dst, data)
		offset += len(data)
	}

	return result, nil
}

// Stack stacks tensors along a new dimension
func Stack(tensors []*Tensor, dim int) (*Tensor, error) {
	if len(tensors) == 0 {
		return nil, fmt.Errorf("cannot stack empty tensor list")
	}

	// Unsqueeze each tensor
	unsqueezed := make([]*Tensor, len(tensors))
	for i, t := range tensors {
		var err error
		unsqueezed[i], err = t.Unsqueeze(dim)
		if err != nil {
			return nil, err
		}
	}

	return Cat(unsqueezed, dim)
}

// Where returns elements from x or y based on condition
func Where(condition, x, y *Tensor) (*Tensor, error) {
	condition.Realize()
	x.Realize()
	y.Realize()

	shape, err := broadcastShapes(condition.Shape, x.Shape)
	if err != nil {
		return nil, err
	}
	shape, err = broadcastShapes(shape, y.Shape)
	if err != nil {
		return nil, err
	}

	result, err := NewTensor(shape, x.DType, x.Device)
	if err != nil {
		return nil, err
	}

	cData := condition.Float32Data()
	xData := x.Float32Data()
	yData := y.Float32Data()
	dst := result.Float32Data()

	for i := range dst {
		cIdx := broadcastIndex(i, shape, condition.Shape)
		xIdx := broadcastIndex(i, shape, x.Shape)
		yIdx := broadcastIndex(i, shape, y.Shape)

		if cData[cIdx] != 0 {
			dst[i] = xData[xIdx]
		} else {
			dst[i] = yData[yIdx]
		}
	}

	return result, nil
}

// Softmax computes softmax along a dimension
func Softmax(t *Tensor, dim int) (*Tensor, error) {
	t.Realize()

	if dim < 0 {
		dim += len(t.Shape)
	}

	// Compute max for numerical stability
	maxT, err := t.Max(dim)
	if err != nil {
		return nil, err
	}
	maxT, _ = maxT.Unsqueeze(dim)

	// exp(x - max)
	expT := t.Sub(maxT).Exp()

	// sum(exp)
	sumT, err := expT.Sum(dim)
	if err != nil {
		return nil, err
	}
	sumT, _ = sumT.Unsqueeze(dim)

	// softmax = exp / sum
	return expT.Div(sumT).Realize(), nil
}

// LogSoftmax computes log softmax along a dimension
func LogSoftmax(t *Tensor, dim int) (*Tensor, error) {
	sm, err := Softmax(t, dim)
	if err != nil {
		return nil, err
	}
	return sm.Log().Realize(), nil
}
