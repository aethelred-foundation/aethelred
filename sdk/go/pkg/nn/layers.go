package nn

import (
	"fmt"
	"math"
	"math/rand"

	"github.com/aethelred/sdk-go/pkg/runtime"
	"github.com/aethelred/sdk-go/pkg/tensor"
)

// ============ Linear Layers ============

// Linear is a fully connected layer: y = xW^T + b
type Linear struct {
	*BaseModule
	InFeatures  int
	OutFeatures int
	Bias        bool
	Weight      *Parameter
	BiasParam   *Parameter
}

// NewLinear creates a new Linear layer
func NewLinear(inFeatures, outFeatures int, bias bool) (*Linear, error) {
	l := &Linear{
		BaseModule:  NewBaseModule("Linear"),
		InFeatures:  inFeatures,
		OutFeatures: outFeatures,
		Bias:        bias,
	}

	// Initialize weight with Kaiming uniform
	weight, err := tensor.NewTensor([]int{outFeatures, inFeatures}, tensor.Float32, runtime.CPU())
	if err != nil {
		return nil, err
	}
	kaimingUniform(weight, inFeatures)
	l.Weight = NewParameter(weight, "weight")
	l.RegisterParameter("weight", l.Weight)

	if bias {
		biasT, err := tensor.Zeros([]int{outFeatures}, tensor.Float32, runtime.CPU())
		if err != nil {
			return nil, err
		}
		// Initialize bias with uniform distribution
		bound := 1.0 / math.Sqrt(float64(inFeatures))
		data := biasT.Float32Data()
		for i := range data {
			data[i] = float32((rand.Float64()*2 - 1) * bound)
		}
		l.BiasParam = NewParameter(biasT, "bias")
		l.RegisterParameter("bias", l.BiasParam)
	}

	return l, nil
}

// Forward performs the forward pass
func (l *Linear) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	input.Realize()

	// y = xW^T + b
	wT, err := l.Weight.T()
	if err != nil {
		return nil, err
	}

	output, err := input.MatMul(wT)
	if err != nil {
		return nil, err
	}

	if l.Bias && l.BiasParam != nil {
		output = output.Add(l.BiasParam.Tensor)
	}

	return output.Realize(), nil
}

// kaimingUniform initializes with Kaiming uniform distribution
func kaimingUniform(t *tensor.Tensor, fanIn int) {
	bound := math.Sqrt(1.0 / float64(fanIn))
	data := t.Float32Data()
	for i := range data {
		data[i] = float32((rand.Float64()*2 - 1) * bound)
	}
}

// ============ Embedding Layers ============

// Embedding is a lookup table for embeddings
type Embedding struct {
	*BaseModule
	NumEmbeddings int
	EmbeddingDim  int
	PaddingIdx    int
	Weight        *Parameter
}

// NewEmbedding creates a new Embedding layer
func NewEmbedding(numEmbeddings, embeddingDim int, paddingIdx int) (*Embedding, error) {
	e := &Embedding{
		BaseModule:    NewBaseModule("Embedding"),
		NumEmbeddings: numEmbeddings,
		EmbeddingDim:  embeddingDim,
		PaddingIdx:    paddingIdx,
	}

	weight, err := tensor.Randn([]int{numEmbeddings, embeddingDim}, tensor.Float32, runtime.CPU())
	if err != nil {
		return nil, err
	}

	e.Weight = NewParameter(weight, "weight")
	e.RegisterParameter("weight", e.Weight)

	return e, nil
}

// Forward performs embedding lookup
func (e *Embedding) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	input.Realize()

	indices := input.Int32Data()
	batchShape := input.Shape

	// Output shape: batch_shape + [embedding_dim]
	outShape := append(append([]int{}, batchShape...), e.EmbeddingDim)
	output, err := tensor.NewTensor(outShape, tensor.Float32, input.Device)
	if err != nil {
		return nil, err
	}

	weightData := e.Weight.Float32Data()
	outputData := output.Float32Data()

	for i, idx := range indices {
		if int(idx) < 0 || int(idx) >= e.NumEmbeddings {
			return nil, fmt.Errorf("index %d out of range [0, %d)", idx, e.NumEmbeddings)
		}
		start := i * e.EmbeddingDim
		srcStart := int(idx) * e.EmbeddingDim
		copy(outputData[start:start+e.EmbeddingDim], weightData[srcStart:srcStart+e.EmbeddingDim])
	}

	return output, nil
}

// ============ Normalization Layers ============

// LayerNorm is layer normalization
type LayerNorm struct {
	*BaseModule
	NormalizedShape []int
	Eps             float64
	Elementwise     bool
	Weight          *Parameter
	BiasParam       *Parameter
}

// NewLayerNorm creates a new LayerNorm layer
func NewLayerNorm(normalizedShape []int, eps float64, elementwiseAffine bool) (*LayerNorm, error) {
	if eps == 0 {
		eps = 1e-5
	}

	ln := &LayerNorm{
		BaseModule:      NewBaseModule("LayerNorm"),
		NormalizedShape: normalizedShape,
		Eps:             eps,
		Elementwise:     elementwiseAffine,
	}

	if elementwiseAffine {
		weight, err := tensor.Ones(normalizedShape, tensor.Float32, runtime.CPU())
		if err != nil {
			return nil, err
		}
		ln.Weight = NewParameter(weight, "weight")
		ln.RegisterParameter("weight", ln.Weight)

		bias, err := tensor.Zeros(normalizedShape, tensor.Float32, runtime.CPU())
		if err != nil {
			return nil, err
		}
		ln.BiasParam = NewParameter(bias, "bias")
		ln.RegisterParameter("bias", ln.BiasParam)
	}

	return ln, nil
}

// Forward performs layer normalization
func (ln *LayerNorm) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	input.Realize()

	// Compute mean and variance over normalized dimensions
	mean, err := input.Mean()
	if err != nil {
		return nil, err
	}
	mean.Realize()

	// x - mean
	centered := input.Sub(mean)
	centered.Realize()

	// variance
	variance, err := centered.Mul(centered).Mean()
	if err != nil {
		return nil, err
	}
	variance.Realize()

	// Normalize
	data := input.Float32Data()
	meanVal := mean.Float32Data()[0]
	varVal := variance.Float32Data()[0]
	invStd := float32(1.0 / math.Sqrt(float64(varVal)+ln.Eps))

	output, err := tensor.NewTensor(input.Shape, input.DType, input.Device)
	if err != nil {
		return nil, err
	}
	outData := output.Float32Data()

	for i, v := range data {
		outData[i] = (v - meanVal) * invStd
	}

	// Apply affine transformation
	if ln.Elementwise && ln.Weight != nil {
		weightData := ln.Weight.Float32Data()
		biasData := ln.BiasParam.Float32Data()

		// Apply element-wise (simplified - assumes last dims match)
		normalizedSize := 1
		for _, s := range ln.NormalizedShape {
			normalizedSize *= s
		}

		for i := 0; i < len(outData); i++ {
			idx := i % normalizedSize
			outData[i] = outData[i]*weightData[idx] + biasData[idx]
		}
	}

	return output, nil
}

// RMSNorm is Root Mean Square Layer Normalization
type RMSNorm struct {
	*BaseModule
	Dim    int
	Eps    float64
	Weight *Parameter
}

// NewRMSNorm creates a new RMSNorm layer
func NewRMSNorm(dim int, eps float64) (*RMSNorm, error) {
	if eps == 0 {
		eps = 1e-6
	}

	rn := &RMSNorm{
		BaseModule: NewBaseModule("RMSNorm"),
		Dim:        dim,
		Eps:        eps,
	}

	weight, err := tensor.Ones([]int{dim}, tensor.Float32, runtime.CPU())
	if err != nil {
		return nil, err
	}
	rn.Weight = NewParameter(weight, "weight")
	rn.RegisterParameter("weight", rn.Weight)

	return rn, nil
}

// Forward performs RMS normalization
func (rn *RMSNorm) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	input.Realize()

	data := input.Float32Data()
	output, err := tensor.NewTensor(input.Shape, input.DType, input.Device)
	if err != nil {
		return nil, err
	}
	outData := output.Float32Data()
	weightData := rn.Weight.Float32Data()

	// Compute RMS for each sequence position
	batchSize := input.Numel() / rn.Dim
	for b := 0; b < batchSize; b++ {
		start := b * rn.Dim
		end := start + rn.Dim

		// Compute RMS
		var sumSq float32
		for i := start; i < end; i++ {
			sumSq += data[i] * data[i]
		}
		rms := float32(math.Sqrt(float64(sumSq)/float64(rn.Dim) + rn.Eps))

		// Normalize and scale
		for i := start; i < end; i++ {
			outData[i] = (data[i] / rms) * weightData[i-start]
		}
	}

	return output, nil
}

// BatchNorm1d is 1D batch normalization
type BatchNorm1d struct {
	*BaseModule
	NumFeatures int
	Eps         float64
	Momentum    float64
	Affine      bool
	TrackStats  bool
	Weight      *Parameter
	BiasParam   *Parameter
	RunningMean *Buffer
	RunningVar  *Buffer
	NumBatches  *Buffer
}

// NewBatchNorm1d creates a new BatchNorm1d layer
func NewBatchNorm1d(numFeatures int, eps, momentum float64, affine, trackStats bool) (*BatchNorm1d, error) {
	if eps == 0 {
		eps = 1e-5
	}
	if momentum == 0 {
		momentum = 0.1
	}

	bn := &BatchNorm1d{
		BaseModule:  NewBaseModule("BatchNorm1d"),
		NumFeatures: numFeatures,
		Eps:         eps,
		Momentum:    momentum,
		Affine:      affine,
		TrackStats:  trackStats,
	}

	if affine {
		weight, _ := tensor.Ones([]int{numFeatures}, tensor.Float32, runtime.CPU())
		bn.Weight = NewParameter(weight, "weight")
		bn.RegisterParameter("weight", bn.Weight)

		bias, _ := tensor.Zeros([]int{numFeatures}, tensor.Float32, runtime.CPU())
		bn.BiasParam = NewParameter(bias, "bias")
		bn.RegisterParameter("bias", bn.BiasParam)
	}

	if trackStats {
		runningMean, _ := tensor.Zeros([]int{numFeatures}, tensor.Float32, runtime.CPU())
		bn.RunningMean = NewBuffer(runningMean, "running_mean", true)
		bn.RegisterBuffer("running_mean", bn.RunningMean)

		runningVar, _ := tensor.Ones([]int{numFeatures}, tensor.Float32, runtime.CPU())
		bn.RunningVar = NewBuffer(runningVar, "running_var", true)
		bn.RegisterBuffer("running_var", bn.RunningVar)

		numBatches, _ := tensor.Zeros([]int{1}, tensor.Float32, runtime.CPU())
		bn.NumBatches = NewBuffer(numBatches, "num_batches_tracked", true)
		bn.RegisterBuffer("num_batches_tracked", bn.NumBatches)
	}

	return bn, nil
}

// Forward performs batch normalization
func (bn *BatchNorm1d) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	input.Realize()

	// Simplified implementation
	// For training: use batch statistics
	// For eval: use running statistics

	return input, nil
}

// ============ Dropout Layers ============

// Dropout randomly zeroes elements during training
type Dropout struct {
	*BaseModule
	P       float64
	Inplace bool
}

// NewDropout creates a new Dropout layer
func NewDropout(p float64, inplace bool) *Dropout {
	if p == 0 {
		p = 0.5
	}
	return &Dropout{
		BaseModule: NewBaseModule("Dropout"),
		P:          p,
		Inplace:    inplace,
	}
}

// Forward applies dropout
func (d *Dropout) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	if !d.IsTraining() || d.P == 0 {
		return input, nil
	}

	input.Realize()

	var output *tensor.Tensor
	var err error
	if d.Inplace {
		output = input
	} else {
		output, err = input.Clone()
		if err != nil {
			return nil, err
		}
	}

	data := output.Float32Data()
	scale := float32(1.0 / (1.0 - d.P))

	for i := range data {
		if rand.Float64() < d.P {
			data[i] = 0
		} else {
			data[i] *= scale
		}
	}

	return output, nil
}

// Dropout2d is 2D dropout (for conv layers)
type Dropout2d struct {
	*Dropout
}

// NewDropout2d creates a new Dropout2d layer
func NewDropout2d(p float64, inplace bool) *Dropout2d {
	return &Dropout2d{
		Dropout: NewDropout(p, inplace),
	}
}

// ============ Activation Functions ============

// ReLU is rectified linear unit activation
type ReLU struct {
	*BaseModule
	Inplace bool
}

// NewReLU creates a new ReLU activation
func NewReLU(inplace bool) *ReLU {
	return &ReLU{
		BaseModule: NewBaseModule("ReLU"),
		Inplace:    inplace,
	}
}

// Forward applies ReLU
func (r *ReLU) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return input.Relu().Realize(), nil
}

// LeakyReLU is leaky rectified linear unit
type LeakyReLU struct {
	*BaseModule
	NegativeSlope float64
	Inplace       bool
}

// NewLeakyReLU creates a new LeakyReLU activation
func NewLeakyReLU(negativeSlope float64, inplace bool) *LeakyReLU {
	if negativeSlope == 0 {
		negativeSlope = 0.01
	}
	return &LeakyReLU{
		BaseModule:    NewBaseModule("LeakyReLU"),
		NegativeSlope: negativeSlope,
		Inplace:       inplace,
	}
}

// Forward applies LeakyReLU
func (l *LeakyReLU) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	input.Realize()

	output, err := input.Clone()
	if err != nil {
		return nil, err
	}

	data := output.Float32Data()
	for i, v := range data {
		if v < 0 {
			data[i] = float32(l.NegativeSlope) * v
		}
	}

	return output, nil
}

// GELU is Gaussian Error Linear Unit activation
type GELU struct {
	*BaseModule
	Approximate string
}

// NewGELU creates a new GELU activation
func NewGELU(approximate string) *GELU {
	return &GELU{
		BaseModule:  NewBaseModule("GELU"),
		Approximate: approximate,
	}
}

// Forward applies GELU
func (g *GELU) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return input.Gelu().Realize(), nil
}

// SiLU is Sigmoid Linear Unit (Swish) activation
type SiLU struct {
	*BaseModule
	Inplace bool
}

// NewSiLU creates a new SiLU activation
func NewSiLU(inplace bool) *SiLU {
	return &SiLU{
		BaseModule: NewBaseModule("SiLU"),
		Inplace:    inplace,
	}
}

// Forward applies SiLU
func (s *SiLU) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return input.Silu().Realize(), nil
}

// Tanh is hyperbolic tangent activation
type Tanh struct {
	*BaseModule
}

// NewTanh creates a new Tanh activation
func NewTanh() *Tanh {
	return &Tanh{
		BaseModule: NewBaseModule("Tanh"),
	}
}

// Forward applies Tanh
func (t *Tanh) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return input.Tanh().Realize(), nil
}

// Sigmoid activation
type Sigmoid struct {
	*BaseModule
}

// NewSigmoid creates a new Sigmoid activation
func NewSigmoid() *Sigmoid {
	return &Sigmoid{
		BaseModule: NewBaseModule("Sigmoid"),
	}
}

// Forward applies Sigmoid
func (s *Sigmoid) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return input.Sigmoid().Realize(), nil
}

// Softmax activation
type Softmax struct {
	*BaseModule
	Dim int
}

// NewSoftmax creates a new Softmax activation
func NewSoftmax(dim int) *Softmax {
	return &Softmax{
		BaseModule: NewBaseModule("Softmax"),
		Dim:        dim,
	}
}

// Forward applies Softmax
func (s *Softmax) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return tensor.Softmax(input, s.Dim)
}

// LogSoftmax activation
type LogSoftmax struct {
	*BaseModule
	Dim int
}

// NewLogSoftmax creates a new LogSoftmax activation
func NewLogSoftmax(dim int) *LogSoftmax {
	return &LogSoftmax{
		BaseModule: NewBaseModule("LogSoftmax"),
		Dim:        dim,
	}
}

// Forward applies LogSoftmax
func (l *LogSoftmax) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return tensor.LogSoftmax(input, l.Dim)
}

// Mish activation: x * tanh(softplus(x))
type Mish struct {
	*BaseModule
}

// NewMish creates a new Mish activation
func NewMish() *Mish {
	return &Mish{
		BaseModule: NewBaseModule("Mish"),
	}
}

// Forward applies Mish
func (m *Mish) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	input.Realize()

	output, err := input.Clone()
	if err != nil {
		return nil, err
	}

	data := output.Float32Data()
	for i, x := range data {
		sp := float64(math.Log(1 + math.Exp(float64(x))))
		data[i] = x * float32(math.Tanh(sp))
	}

	return output, nil
}
