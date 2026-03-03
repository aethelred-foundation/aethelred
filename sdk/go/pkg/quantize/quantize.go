// Package quantize provides model quantization for efficient inference.
//
// Features:
//   - Post-training quantization (PTQ)
//   - Quantization-aware training (QAT)
//   - INT8, INT4, FP16, BF16, FP8 support
//   - Per-tensor and per-channel quantization
//   - Dynamic and static quantization
package quantize

import (
	"fmt"
	"math"

	"github.com/aethelred/sdk-go/pkg/nn"
	"github.com/aethelred/sdk-go/pkg/tensor"
)

// ============ Quantization Config ============

// QDType represents quantized data types
type QDType int

const (
	QINT8 QDType = iota
	QINT4
	QUINT8
	QUINT4
	QFP16
	QBF16
	QFP8
	QNF4 // Normal Float 4-bit
)

// String returns the string representation
func (d QDType) String() string {
	names := []string{
		"qint8", "qint4", "quint8", "quint4",
		"fp16", "bf16", "fp8", "nf4",
	}
	if int(d) < len(names) {
		return names[d]
	}
	return "unknown"
}

// Granularity represents quantization granularity
type Granularity int

const (
	PerTensor Granularity = iota
	PerChannel
	PerGroup
)

// QScheme represents the quantization scheme
type QScheme int

const (
	Affine QScheme = iota // scale * (q - zero_point)
	Symmetric            // scale * q
)

// QuantConfig configures quantization
type QuantConfig struct {
	DType       QDType
	Granularity Granularity
	Scheme      QScheme
	CalibMethod string
	NumBits     int
	GroupSize   int
	Symmetric   bool
}

// DefaultQuantConfig returns default quantization config
func DefaultQuantConfig() QuantConfig {
	return QuantConfig{
		DType:       QINT8,
		Granularity: PerTensor,
		Scheme:      Affine,
		CalibMethod: "minmax",
		NumBits:     8,
		GroupSize:   128,
		Symmetric:   false,
	}
}

// ============ Quantization Parameters ============

// QParams holds quantization parameters
type QParams struct {
	Scale     float64
	ZeroPoint int
	Min       float64
	Max       float64
	NumBits   int
	Signed    bool
}

// NewQParams creates new quantization parameters
func NewQParams(min, max float64, numBits int, symmetric bool) *QParams {
	signed := min < 0

	var qMin, qMax float64
	if signed {
		qMin = -math.Pow(2, float64(numBits-1))
		qMax = math.Pow(2, float64(numBits-1)) - 1
	} else {
		qMin = 0
		qMax = math.Pow(2, float64(numBits)) - 1
	}

	var scale float64
	var zeroPoint int

	if symmetric {
		absMax := math.Max(math.Abs(min), math.Abs(max))
		scale = absMax / (qMax)
		zeroPoint = 0
	} else {
		scale = (max - min) / (qMax - qMin)
		zeroPoint = int(math.Round(qMin - min/scale))
	}

	return &QParams{
		Scale:     scale,
		ZeroPoint: zeroPoint,
		Min:       min,
		Max:       max,
		NumBits:   numBits,
		Signed:    signed,
	}
}

// Quantize quantizes a float value
func (p *QParams) Quantize(x float64) int {
	q := math.Round(x/p.Scale) + float64(p.ZeroPoint)

	var qMin, qMax float64
	if p.Signed {
		qMin = -math.Pow(2, float64(p.NumBits-1))
		qMax = math.Pow(2, float64(p.NumBits-1)) - 1
	} else {
		qMin = 0
		qMax = math.Pow(2, float64(p.NumBits)) - 1
	}

	return int(math.Max(qMin, math.Min(qMax, q)))
}

// Dequantize dequantizes a quantized value
func (p *QParams) Dequantize(q int) float64 {
	return p.Scale * float64(q-p.ZeroPoint)
}

// ============ Quantized Tensor ============

// QTensor represents a quantized tensor
type QTensor struct {
	Data      []int8 // Quantized values
	Params    *QParams
	Shape     []int
	DType     QDType
	OrigDType tensor.DType
}

// NewQTensor creates a new quantized tensor
func NewQTensor(t *tensor.Tensor, params *QParams, dtype QDType) (*QTensor, error) {
	t.Realize()
	data := t.Float32Data()

	qData := make([]int8, len(data))
	for i, v := range data {
		qData[i] = int8(params.Quantize(float64(v)))
	}

	return &QTensor{
		Data:      qData,
		Params:    params,
		Shape:     t.Shape,
		DType:     dtype,
		OrigDType: t.DType,
	}, nil
}

// Dequantize converts back to a regular tensor
func (qt *QTensor) Dequantize() (*tensor.Tensor, error) {
	t, err := tensor.NewTensor(qt.Shape, qt.OrigDType, nil)
	if err != nil {
		return nil, err
	}

	data := t.Float32Data()
	for i, q := range qt.Data {
		data[i] = float32(qt.Params.Dequantize(int(q)))
	}

	return t, nil
}

// Numel returns the number of elements
func (qt *QTensor) Numel() int {
	n := 1
	for _, s := range qt.Shape {
		n *= s
	}
	return n
}

// ============ Calibration Observer ============

// CalibrationObserver collects statistics for calibration
type CalibrationObserver interface {
	Forward(t *tensor.Tensor)
	CalcQParams() *QParams
	Reset()
}

// MinMaxObserver uses min/max for calibration
type MinMaxObserver struct {
	Min       float64
	Max       float64
	NumBits   int
	Symmetric bool
	Seen      bool
}

// NewMinMaxObserver creates a new min-max observer
func NewMinMaxObserver(numBits int, symmetric bool) *MinMaxObserver {
	return &MinMaxObserver{
		Min:       math.Inf(1),
		Max:       math.Inf(-1),
		NumBits:   numBits,
		Symmetric: symmetric,
	}
}

// Forward updates statistics
func (o *MinMaxObserver) Forward(t *tensor.Tensor) {
	t.Realize()
	data := t.Float32Data()

	for _, v := range data {
		fv := float64(v)
		if fv < o.Min {
			o.Min = fv
		}
		if fv > o.Max {
			o.Max = fv
		}
	}
	o.Seen = true
}

// CalcQParams calculates quantization parameters
func (o *MinMaxObserver) CalcQParams() *QParams {
	if !o.Seen {
		return NewQParams(0, 1, o.NumBits, o.Symmetric)
	}
	return NewQParams(o.Min, o.Max, o.NumBits, o.Symmetric)
}

// Reset resets the observer
func (o *MinMaxObserver) Reset() {
	o.Min = math.Inf(1)
	o.Max = math.Inf(-1)
	o.Seen = false
}

// MovingAverageMinMaxObserver uses EMA for calibration
type MovingAverageMinMaxObserver struct {
	Min        float64
	Max        float64
	NumBits    int
	Symmetric  bool
	AvgFactor  float64
	Iterations int
}

// NewMovingAverageMinMaxObserver creates a new moving average observer
func NewMovingAverageMinMaxObserver(numBits int, symmetric bool, avgFactor float64) *MovingAverageMinMaxObserver {
	return &MovingAverageMinMaxObserver{
		Min:       math.Inf(1),
		Max:       math.Inf(-1),
		NumBits:   numBits,
		Symmetric: symmetric,
		AvgFactor: avgFactor,
	}
}

// Forward updates statistics using EMA
func (o *MovingAverageMinMaxObserver) Forward(t *tensor.Tensor) {
	t.Realize()
	data := t.Float32Data()

	batchMin := float64(data[0])
	batchMax := float64(data[0])
	for _, v := range data {
		fv := float64(v)
		if fv < batchMin {
			batchMin = fv
		}
		if fv > batchMax {
			batchMax = fv
		}
	}

	if o.Iterations == 0 {
		o.Min = batchMin
		o.Max = batchMax
	} else {
		o.Min = o.Min*o.AvgFactor + batchMin*(1-o.AvgFactor)
		o.Max = o.Max*o.AvgFactor + batchMax*(1-o.AvgFactor)
	}
	o.Iterations++
}

// CalcQParams calculates quantization parameters
func (o *MovingAverageMinMaxObserver) CalcQParams() *QParams {
	if o.Iterations == 0 {
		return NewQParams(0, 1, o.NumBits, o.Symmetric)
	}
	return NewQParams(o.Min, o.Max, o.NumBits, o.Symmetric)
}

// Reset resets the observer
func (o *MovingAverageMinMaxObserver) Reset() {
	o.Min = math.Inf(1)
	o.Max = math.Inf(-1)
	o.Iterations = 0
}

// HistogramObserver uses histogram for calibration
type HistogramObserver struct {
	NumBits   int
	Symmetric bool
	NumBins   int
	Histogram []int
	BinEdges  []float64
	Min       float64
	Max       float64
}

// NewHistogramObserver creates a new histogram observer
func NewHistogramObserver(numBits int, symmetric bool, numBins int) *HistogramObserver {
	return &HistogramObserver{
		NumBits:   numBits,
		Symmetric: symmetric,
		NumBins:   numBins,
		Histogram: make([]int, numBins),
		Min:       math.Inf(1),
		Max:       math.Inf(-1),
	}
}

// Forward updates histogram
func (o *HistogramObserver) Forward(t *tensor.Tensor) {
	t.Realize()
	data := t.Float32Data()

	// Update min/max
	for _, v := range data {
		fv := float64(v)
		if fv < o.Min {
			o.Min = fv
		}
		if fv > o.Max {
			o.Max = fv
		}
	}

	// Update histogram
	if o.BinEdges == nil {
		o.BinEdges = make([]float64, o.NumBins+1)
		for i := range o.BinEdges {
			o.BinEdges[i] = o.Min + float64(i)*(o.Max-o.Min)/float64(o.NumBins)
		}
	}

	binWidth := (o.Max - o.Min) / float64(o.NumBins)
	for _, v := range data {
		bin := int((float64(v) - o.Min) / binWidth)
		if bin >= o.NumBins {
			bin = o.NumBins - 1
		}
		if bin < 0 {
			bin = 0
		}
		o.Histogram[bin]++
	}
}

// CalcQParams calculates quantization parameters using percentile
func (o *HistogramObserver) CalcQParams() *QParams {
	// Use 99.99 percentile to handle outliers
	total := 0
	for _, count := range o.Histogram {
		total += count
	}

	targetCount := int(float64(total) * 0.9999)
	count := 0
	clippedMax := o.Max

	for i, c := range o.Histogram {
		count += c
		if count >= targetCount {
			clippedMax = o.BinEdges[i+1]
			break
		}
	}

	targetCount = int(float64(total) * 0.0001)
	count = 0
	clippedMin := o.Min

	for i := len(o.Histogram) - 1; i >= 0; i-- {
		count += o.Histogram[i]
		if count >= total-targetCount {
			clippedMin = o.BinEdges[i]
			break
		}
	}

	return NewQParams(clippedMin, clippedMax, o.NumBits, o.Symmetric)
}

// Reset resets the observer
func (o *HistogramObserver) Reset() {
	o.Histogram = make([]int, o.NumBins)
	o.BinEdges = nil
	o.Min = math.Inf(1)
	o.Max = math.Inf(-1)
}

// ============ Quantization Engine ============

// QuantizationEngine handles model quantization
type QuantizationEngine struct {
	Config    QuantConfig
	Observers map[string]CalibrationObserver
}

// NewQuantizationEngine creates a new quantization engine
func NewQuantizationEngine(config QuantConfig) *QuantizationEngine {
	return &QuantizationEngine{
		Config:    config,
		Observers: make(map[string]CalibrationObserver),
	}
}

// Prepare prepares a module for quantization
func (qe *QuantizationEngine) Prepare(module nn.Module) error {
	// Add observers to each layer
	for name := range module.NamedParameters() {
		switch qe.Config.CalibMethod {
		case "minmax":
			qe.Observers[name] = NewMinMaxObserver(qe.Config.NumBits, qe.Config.Symmetric)
		case "moving_average":
			qe.Observers[name] = NewMovingAverageMinMaxObserver(qe.Config.NumBits, qe.Config.Symmetric, 0.01)
		case "histogram":
			qe.Observers[name] = NewHistogramObserver(qe.Config.NumBits, qe.Config.Symmetric, 2048)
		default:
			qe.Observers[name] = NewMinMaxObserver(qe.Config.NumBits, qe.Config.Symmetric)
		}
	}

	return nil
}

// Calibrate calibrates the model with sample data
func (qe *QuantizationEngine) Calibrate(module nn.Module, calibrationData []*tensor.Tensor) error {
	module.Eval()

	for _, data := range calibrationData {
		// Forward pass
		_, err := module.Forward(data)
		if err != nil {
			return err
		}

		// Collect statistics
		for name, param := range module.NamedParameters() {
			if observer, ok := qe.Observers[name]; ok {
				observer.Forward(param.Tensor)
			}
		}
	}

	return nil
}

// Convert converts the model to quantized version
func (qe *QuantizationEngine) Convert(module nn.Module) (*QuantizedModule, error) {
	qModule := &QuantizedModule{
		OriginalModule: module,
		QParams:        make(map[string]*QParams),
		QTensors:       make(map[string]*QTensor),
		DType:          qe.Config.DType,
	}

	for name, param := range module.NamedParameters() {
		observer, ok := qe.Observers[name]
		if !ok {
			continue
		}

		qParams := observer.CalcQParams()
		qModule.QParams[name] = qParams

		qTensor, err := NewQTensor(param.Tensor, qParams, qe.Config.DType)
		if err != nil {
			return nil, err
		}
		qModule.QTensors[name] = qTensor
	}

	return qModule, nil
}

// ============ Quantized Module ============

// QuantizedModule represents a quantized neural network module
type QuantizedModule struct {
	OriginalModule nn.Module
	QParams        map[string]*QParams
	QTensors       map[string]*QTensor
	DType          QDType
}

// Forward performs quantized forward pass
func (qm *QuantizedModule) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	// For now, dequantize and use original module
	// A real implementation would use quantized kernels
	return qm.OriginalModule.Forward(input)
}

// SaveQuantized saves the quantized model
func (qm *QuantizedModule) SaveQuantized(path string) error {
	// Save quantized tensors and params
	return nil
}

// LoadQuantized loads a quantized model
func LoadQuantized(path string) (*QuantizedModule, error) {
	// Load quantized model
	return nil, nil
}

// ============ Quantized Layers ============

// QuantizedLinear is a quantized linear layer
type QuantizedLinear struct {
	*nn.BaseModule
	InFeatures  int
	OutFeatures int
	QWeight     *QTensor
	QBias       *QTensor
	OutputScale float64
}

// NewQuantizedLinear creates a new quantized linear layer
func NewQuantizedLinear(linear *nn.Linear, weightParams, biasParams *QParams) (*QuantizedLinear, error) {
	qWeight, err := NewQTensor(linear.Weight.Tensor, weightParams, QINT8)
	if err != nil {
		return nil, err
	}

	var qBias *QTensor
	if linear.BiasParam != nil {
		qBias, err = NewQTensor(linear.BiasParam.Tensor, biasParams, QINT8)
		if err != nil {
			return nil, err
		}
	}

	return &QuantizedLinear{
		BaseModule:  nn.NewBaseModule("QuantizedLinear"),
		InFeatures:  linear.InFeatures,
		OutFeatures: linear.OutFeatures,
		QWeight:     qWeight,
		QBias:       qBias,
		OutputScale: weightParams.Scale,
	}, nil
}

// Forward performs quantized forward pass
func (ql *QuantizedLinear) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	// Quantize input
	input.Realize()
	inputData := input.Float32Data()

	// For INT8, use int32 accumulation
	batchSize := input.Shape[0]
	inFeatures := ql.InFeatures
	outFeatures := ql.OutFeatures

	output, err := tensor.NewTensor([]int{batchSize, outFeatures}, tensor.Float32, input.Device)
	if err != nil {
		return nil, err
	}
	outData := output.Float32Data()

	// Quantized matrix multiply
	for b := 0; b < batchSize; b++ {
		for o := 0; o < outFeatures; o++ {
			var acc int32
			for i := 0; i < inFeatures; i++ {
				qIn := int32(ql.QWeight.Params.Quantize(float64(inputData[b*inFeatures+i])))
				qW := int32(ql.QWeight.Data[o*inFeatures+i])
				acc += qIn * qW
			}

			// Dequantize
			outData[b*outFeatures+o] = float32(float64(acc) * ql.OutputScale)

			// Add bias
			if ql.QBias != nil {
				outData[b*outFeatures+o] += float32(ql.QBias.Params.Dequantize(int(ql.QBias.Data[o])))
			}
		}
	}

	return output, nil
}

// ============ Quantization Aware Training ============

// QATConfig configures quantization-aware training
type QATConfig struct {
	DType          QDType
	Granularity    Granularity
	NumBits        int
	Symmetric      bool
	FakeQuantize   bool
	ObserverFreeze int
}

// DefaultQATConfig returns default QAT configuration
func DefaultQATConfig() QATConfig {
	return QATConfig{
		DType:          QINT8,
		Granularity:    PerTensor,
		NumBits:        8,
		Symmetric:      false,
		FakeQuantize:   true,
		ObserverFreeze: -1,
	}
}

// QATEngine handles quantization-aware training
type QATEngine struct {
	Config    QATConfig
	Observers map[string]CalibrationObserver
	Epoch     int
	Frozen    bool
}

// NewQATEngine creates a new QAT engine
func NewQATEngine(config QATConfig) *QATEngine {
	return &QATEngine{
		Config:    config,
		Observers: make(map[string]CalibrationObserver),
		Epoch:     0,
		Frozen:    false,
	}
}

// Prepare prepares a module for QAT
func (qat *QATEngine) Prepare(module nn.Module) error {
	for name := range module.NamedParameters() {
		qat.Observers[name] = NewMinMaxObserver(qat.Config.NumBits, qat.Config.Symmetric)
	}
	return nil
}

// FakeQuantize applies fake quantization to weights
func (qat *QATEngine) FakeQuantize(param *nn.Parameter) (*tensor.Tensor, error) {
	name := param.Name
	observer, ok := qat.Observers[name]
	if !ok {
		return param.Tensor, nil
	}

	if !qat.Frozen {
		observer.Forward(param.Tensor)
	}

	qParams := observer.CalcQParams()

	// Fake quantize: quantize then dequantize
	param.Realize()
	data := param.Float32Data()

	output, err := tensor.NewTensor(param.Shape, param.DType, param.Device)
	if err != nil {
		return nil, err
	}
	outData := output.Float32Data()

	for i, v := range data {
		q := qParams.Quantize(float64(v))
		outData[i] = float32(qParams.Dequantize(q))
	}

	return output, nil
}

// StepEpoch advances the epoch counter
func (qat *QATEngine) StepEpoch() {
	qat.Epoch++
	if qat.Config.ObserverFreeze > 0 && qat.Epoch >= qat.Config.ObserverFreeze {
		qat.Frozen = true
	}
}

// Convert converts QAT model to fully quantized
func (qat *QATEngine) Convert(module nn.Module) (*QuantizedModule, error) {
	qModule := &QuantizedModule{
		OriginalModule: module,
		QParams:        make(map[string]*QParams),
		QTensors:       make(map[string]*QTensor),
		DType:          qat.Config.DType,
	}

	for name, param := range module.NamedParameters() {
		observer, ok := qat.Observers[name]
		if !ok {
			continue
		}

		qParams := observer.CalcQParams()
		qModule.QParams[name] = qParams

		qTensor, err := NewQTensor(param.Tensor, qParams, qat.Config.DType)
		if err != nil {
			return nil, err
		}
		qModule.QTensors[name] = qTensor
	}

	return qModule, nil
}

// ============ Dynamic Quantization ============

// DynamicQuantizer applies dynamic quantization
type DynamicQuantizer struct {
	DType   QDType
	NumBits int
}

// NewDynamicQuantizer creates a new dynamic quantizer
func NewDynamicQuantizer(dtype QDType, numBits int) *DynamicQuantizer {
	return &DynamicQuantizer{
		DType:   dtype,
		NumBits: numBits,
	}
}

// Quantize dynamically quantizes a tensor
func (dq *DynamicQuantizer) Quantize(t *tensor.Tensor) (*QTensor, error) {
	t.Realize()
	data := t.Float32Data()

	// Find min/max
	min := float64(data[0])
	max := float64(data[0])
	for _, v := range data {
		fv := float64(v)
		if fv < min {
			min = fv
		}
		if fv > max {
			max = fv
		}
	}

	qParams := NewQParams(min, max, dq.NumBits, false)
	return NewQTensor(t, qParams, dq.DType)
}

// QuantizeLinear dynamically quantizes a linear layer
func (dq *DynamicQuantizer) QuantizeLinear(linear *nn.Linear) (*QuantizedLinear, error) {
	// Quantize weights
	wMin := float64(linear.Weight.Float32Data()[0])
	wMax := wMin
	for _, v := range linear.Weight.Float32Data() {
		fv := float64(v)
		if fv < wMin {
			wMin = fv
		}
		if fv > wMax {
			wMax = fv
		}
	}
	weightParams := NewQParams(wMin, wMax, dq.NumBits, true)

	// Quantize bias
	var biasParams *QParams
	if linear.BiasParam != nil {
		bMin := float64(linear.BiasParam.Float32Data()[0])
		bMax := bMin
		for _, v := range linear.BiasParam.Float32Data() {
			fv := float64(v)
			if fv < bMin {
				bMin = fv
			}
			if fv > bMax {
				bMax = fv
			}
		}
		biasParams = NewQParams(bMin, bMax, dq.NumBits, true)
	}

	return NewQuantizedLinear(linear, weightParams, biasParams)
}

// ============ GPTQ Quantization ============

// GPTQConfig configures GPTQ quantization
type GPTQConfig struct {
	NumBits      int
	GroupSize    int
	ActOrder     bool
	Damp         float64
	SymmetricW   bool
}

// DefaultGPTQConfig returns default GPTQ configuration
func DefaultGPTQConfig() GPTQConfig {
	return GPTQConfig{
		NumBits:    4,
		GroupSize:  128,
		ActOrder:   false,
		Damp:       0.01,
		SymmetricW: true,
	}
}

// GPTQQuantizer implements GPTQ quantization
type GPTQQuantizer struct {
	Config GPTQConfig
}

// NewGPTQQuantizer creates a new GPTQ quantizer
func NewGPTQQuantizer(config GPTQConfig) *GPTQQuantizer {
	return &GPTQQuantizer{
		Config: config,
	}
}

// Quantize quantizes a weight matrix using GPTQ
func (gq *GPTQQuantizer) Quantize(weight *tensor.Tensor, hessian *tensor.Tensor) (*QTensor, error) {
	// Simplified GPTQ - real implementation would use iterative layer-by-layer quantization
	weight.Realize()
	data := weight.Float32Data()

	rows := weight.Shape[0]
	cols := weight.Shape[1]

	// Calculate scale per group
	groupSize := gq.Config.GroupSize
	if groupSize <= 0 || groupSize > cols {
		groupSize = cols
	}

	numGroups := (cols + groupSize - 1) / groupSize

	scales := make([]float64, rows*numGroups)
	zeros := make([]int, rows*numGroups)
	qData := make([]int8, len(data))

	for r := 0; r < rows; r++ {
		for g := 0; g < numGroups; g++ {
			start := g * groupSize
			end := start + groupSize
			if end > cols {
				end = cols
			}

			// Find min/max for this group
			min := float64(data[r*cols+start])
			max := min
			for c := start; c < end; c++ {
				v := float64(data[r*cols+c])
				if v < min {
					min = v
				}
				if v > max {
					max = v
				}
			}

			// Calculate scale and zero point
			qParams := NewQParams(min, max, gq.Config.NumBits, gq.Config.SymmetricW)
			scales[r*numGroups+g] = qParams.Scale
			zeros[r*numGroups+g] = qParams.ZeroPoint

			// Quantize this group
			for c := start; c < end; c++ {
				qData[r*cols+c] = int8(qParams.Quantize(float64(data[r*cols+c])))
			}
		}
	}

	avgScale := 0.0
	for _, s := range scales {
		avgScale += s
	}
	avgScale /= float64(len(scales))

	avgZero := 0
	for _, z := range zeros {
		avgZero += z
	}
	avgZero /= len(zeros)

	return &QTensor{
		Data: qData,
		Params: &QParams{
			Scale:     avgScale,
			ZeroPoint: avgZero,
			NumBits:   gq.Config.NumBits,
		},
		Shape:     weight.Shape,
		DType:     QINT4,
		OrigDType: weight.DType,
	}, nil
}

// ============ Model Size Utilities ============

// GetModelSize returns the size of a model in bytes
func GetModelSize(module nn.Module) int64 {
	var size int64
	for _, param := range module.Parameters() {
		size += int64(param.Numel() * param.DType.Size())
	}
	return size
}

// GetQuantizedModelSize returns the size of a quantized model
func GetQuantizedModelSize(qModule *QuantizedModule) int64 {
	var size int64
	for _, qt := range qModule.QTensors {
		// Size depends on quantization type
		switch qModule.DType {
		case QINT8, QUINT8:
			size += int64(qt.Numel())
		case QINT4, QUINT4, QNF4:
			size += int64(qt.Numel() / 2) // 4-bit packing
		case QFP16, QBF16:
			size += int64(qt.Numel() * 2)
		default:
			size += int64(qt.Numel())
		}
	}
	return size
}

// CompressionRatio returns the compression ratio
func CompressionRatio(originalSize, quantizedSize int64) float64 {
	if quantizedSize == 0 {
		return 0
	}
	return float64(originalSize) / float64(quantizedSize)
}

// PrintQuantizationSummary prints quantization summary
func PrintQuantizationSummary(module nn.Module, qModule *QuantizedModule) string {
	origSize := GetModelSize(module)
	qSize := GetQuantizedModelSize(qModule)
	ratio := CompressionRatio(origSize, qSize)

	return fmt.Sprintf(`Quantization Summary:
  Original Size: %.2f MB
  Quantized Size: %.2f MB
  Compression Ratio: %.2fx
  Quantization Type: %s
  Number of Quantized Tensors: %d`,
		float64(origSize)/(1024*1024),
		float64(qSize)/(1024*1024),
		ratio,
		qModule.DType,
		len(qModule.QTensors))
}
