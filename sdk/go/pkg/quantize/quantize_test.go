package quantize

import (
	"math"
	"testing"

	"github.com/aethelred/sdk-go/pkg/nn"
	"github.com/aethelred/sdk-go/pkg/tensor"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// QDType
// ---------------------------------------------------------------------------

func TestQDType_String(t *testing.T) {
	t.Parallel()

	cases := []struct {
		dtype QDType
		want  string
	}{
		{QINT8, "qint8"},
		{QINT4, "qint4"},
		{QUINT8, "quint8"},
		{QUINT4, "quint4"},
		{QFP16, "fp16"},
		{QBF16, "bf16"},
		{QFP8, "fp8"},
		{QNF4, "nf4"},
		{QDType(99), "unknown"},
	}

	for _, tc := range cases {
		require.Equal(t, tc.want, tc.dtype.String())
	}
}

// ---------------------------------------------------------------------------
// QParams
// ---------------------------------------------------------------------------

func TestNewQParams_Affine(t *testing.T) {
	t.Parallel()

	qp := NewQParams(-1.0, 1.0, 8, false)
	require.NotNil(t, qp)
	require.Equal(t, 8, qp.NumBits)
	require.True(t, qp.Signed)
	require.NotZero(t, qp.Scale)
}

func TestNewQParams_Symmetric(t *testing.T) {
	t.Parallel()

	qp := NewQParams(-2.0, 2.0, 8, true)
	require.NotNil(t, qp)
	require.Equal(t, 0, qp.ZeroPoint)
}

func TestQParams_QuantizeDequantize_Roundtrip(t *testing.T) {
	t.Parallel()

	qp := NewQParams(-1.0, 1.0, 8, false)

	testValues := []float64{-1.0, -0.5, 0.0, 0.5, 1.0}
	for _, v := range testValues {
		q := qp.Quantize(v)
		dq := qp.Dequantize(q)
		// Allow for quantization error
		require.InDelta(t, v, dq, 0.02, "value %f: quantized=%d, dequantized=%f", v, q, dq)
	}
}

func TestQParams_ClipsToRange(t *testing.T) {
	t.Parallel()

	qp := NewQParams(0, 1.0, 8, false)

	q := qp.Quantize(10.0) // well above max
	require.LessOrEqual(t, q, int(math.Pow(2, 8)-1))

	q = qp.Quantize(-10.0) // well below min
	require.GreaterOrEqual(t, q, 0)
}

// ---------------------------------------------------------------------------
// DefaultQuantConfig
// ---------------------------------------------------------------------------

func TestDefaultQuantConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultQuantConfig()
	require.Equal(t, QINT8, cfg.DType)
	require.Equal(t, PerTensor, cfg.Granularity)
	require.Equal(t, Affine, cfg.Scheme)
	require.Equal(t, "minmax", cfg.CalibMethod)
	require.Equal(t, 8, cfg.NumBits)
	require.Equal(t, 128, cfg.GroupSize)
	require.False(t, cfg.Symmetric)
}

// ---------------------------------------------------------------------------
// QTensor
// ---------------------------------------------------------------------------

func TestNewQTensor_AndDequantize(t *testing.T) {
	t.Parallel()

	data, err := tensor.Randn([]int{4, 4}, tensor.Float32, nil)
	require.NoError(t, err)

	qp := NewQParams(-3.0, 3.0, 8, false)
	qt, err := NewQTensor(data, qp, QINT8)
	require.NoError(t, err)
	require.NotNil(t, qt)
	require.Equal(t, 16, qt.Numel())
	require.Equal(t, QINT8, qt.DType)
	require.Equal(t, []int{4, 4}, qt.Shape)

	dequantized, err := qt.Dequantize()
	require.NoError(t, err)
	require.Equal(t, data.Shape, dequantized.Shape)
}

// ---------------------------------------------------------------------------
// MinMaxObserver
// ---------------------------------------------------------------------------

func TestMinMaxObserver(t *testing.T) {
	t.Parallel()

	obs := NewMinMaxObserver(8, false)
	require.False(t, obs.Seen)

	data, err := tensor.Randn([]int{100}, tensor.Float32, nil)
	require.NoError(t, err)

	obs.Forward(data)
	require.True(t, obs.Seen)
	require.True(t, obs.Min < obs.Max)

	qp := obs.CalcQParams()
	require.NotNil(t, qp)
	require.Equal(t, 8, qp.NumBits)

	obs.Reset()
	require.False(t, obs.Seen)
	require.Equal(t, math.Inf(1), obs.Min)
	require.Equal(t, math.Inf(-1), obs.Max)
}

func TestMinMaxObserver_UnseenReturnsDefault(t *testing.T) {
	t.Parallel()

	obs := NewMinMaxObserver(8, false)
	qp := obs.CalcQParams()
	require.Equal(t, 0.0, qp.Min)
	require.Equal(t, 1.0, qp.Max)
}

// ---------------------------------------------------------------------------
// MovingAverageMinMaxObserver
// ---------------------------------------------------------------------------

func TestMovingAverageObserver(t *testing.T) {
	t.Parallel()

	obs := NewMovingAverageMinMaxObserver(8, false, 0.9)
	require.Equal(t, 0, obs.Iterations)

	for i := 0; i < 10; i++ {
		data, err := tensor.Randn([]int{50}, tensor.Float32, nil)
		require.NoError(t, err)
		obs.Forward(data)
	}

	require.Equal(t, 10, obs.Iterations)

	qp := obs.CalcQParams()
	require.NotNil(t, qp)

	obs.Reset()
	require.Equal(t, 0, obs.Iterations)
}

func TestMovingAverageObserver_UnseenReturnsDefault(t *testing.T) {
	t.Parallel()

	obs := NewMovingAverageMinMaxObserver(8, false, 0.9)
	qp := obs.CalcQParams()
	require.Equal(t, 0.0, qp.Min)
	require.Equal(t, 1.0, qp.Max)
}

// ---------------------------------------------------------------------------
// HistogramObserver
// ---------------------------------------------------------------------------

func TestHistogramObserver(t *testing.T) {
	t.Parallel()

	obs := NewHistogramObserver(8, false, 256)

	data, err := tensor.Randn([]int{1000}, tensor.Float32, nil)
	require.NoError(t, err)
	obs.Forward(data)

	qp := obs.CalcQParams()
	require.NotNil(t, qp)
	require.Equal(t, 8, qp.NumBits)

	obs.Reset()
	require.Nil(t, obs.BinEdges)
	require.Equal(t, math.Inf(1), obs.Min)
}

// ---------------------------------------------------------------------------
// QuantizationEngine
// ---------------------------------------------------------------------------

func TestQuantizationEngine_PrepareAndConvert(t *testing.T) {
	t.Parallel()

	linear, err := nn.NewLinear(4, 2, true)
	require.NoError(t, err)
	model := nn.NewSequential(linear)

	engine := NewQuantizationEngine(DefaultQuantConfig())
	err = engine.Prepare(model)
	require.NoError(t, err)
	require.NotEmpty(t, engine.Observers)

	// Feed observers directly (simulating calibration)
	for _, param := range model.NamedParameters() {
		for name, obs := range engine.Observers {
			if name != "" {
				obs.Forward(param.Tensor)
			}
		}
	}

	qModel, err := engine.Convert(model)
	require.NoError(t, err)
	require.NotNil(t, qModel)
	require.NotEmpty(t, qModel.QParams)
	require.NotEmpty(t, qModel.QTensors)
}

// ---------------------------------------------------------------------------
// Dynamic Quantization
// ---------------------------------------------------------------------------

func TestDynamicQuantizer_Quantize(t *testing.T) {
	t.Parallel()

	dq := NewDynamicQuantizer(QINT8, 8)

	data, err := tensor.Randn([]int{32}, tensor.Float32, nil)
	require.NoError(t, err)

	qt, err := dq.Quantize(data)
	require.NoError(t, err)
	require.NotNil(t, qt)
	require.Equal(t, QINT8, qt.DType)
}

func TestDynamicQuantizer_QuantizeLinear(t *testing.T) {
	t.Parallel()

	dq := NewDynamicQuantizer(QINT8, 8)

	linear, err := nn.NewLinear(8, 4, true)
	require.NoError(t, err)

	ql, err := dq.QuantizeLinear(linear)
	require.NoError(t, err)
	require.NotNil(t, ql)
	require.Equal(t, 8, ql.InFeatures)
	require.Equal(t, 4, ql.OutFeatures)
}

// ---------------------------------------------------------------------------
// QuantizedLinear Forward
// ---------------------------------------------------------------------------

func TestQuantizedLinear_Forward(t *testing.T) {
	t.Parallel()

	dq := NewDynamicQuantizer(QINT8, 8)
	linear, err := nn.NewLinear(4, 2, true)
	require.NoError(t, err)

	ql, err := dq.QuantizeLinear(linear)
	require.NoError(t, err)

	input, err := tensor.Randn([]int{2, 4}, tensor.Float32, nil)
	require.NoError(t, err)

	output, err := ql.Forward(input)
	require.NoError(t, err)
	require.Equal(t, []int{2, 2}, output.Shape)
}

// ---------------------------------------------------------------------------
// GPTQ Quantization
// ---------------------------------------------------------------------------

func TestGPTQ_Quantize(t *testing.T) {
	t.Parallel()

	gq := NewGPTQQuantizer(DefaultGPTQConfig())
	require.Equal(t, 4, gq.Config.NumBits)

	weight, err := tensor.Randn([]int{16, 32}, tensor.Float32, nil)
	require.NoError(t, err)
	hessian, err := tensor.Randn([]int{32, 32}, tensor.Float32, nil)
	require.NoError(t, err)

	qt, err := gq.Quantize(weight, hessian)
	require.NoError(t, err)
	require.NotNil(t, qt)
	require.Equal(t, QINT4, qt.DType)
	require.Equal(t, []int{16, 32}, qt.Shape)
}

func TestDefaultGPTQConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultGPTQConfig()
	require.Equal(t, 4, cfg.NumBits)
	require.Equal(t, 128, cfg.GroupSize)
	require.False(t, cfg.ActOrder)
	require.Equal(t, 0.01, cfg.Damp)
	require.True(t, cfg.SymmetricW)
}

// ---------------------------------------------------------------------------
// QAT Engine
// ---------------------------------------------------------------------------

func TestQAT_PrepareAndFakeQuantize(t *testing.T) {
	t.Parallel()

	linear, err := nn.NewLinear(4, 2, true)
	require.NoError(t, err)
	model := nn.NewSequential(linear)

	qat := NewQATEngine(DefaultQATConfig())
	err = qat.Prepare(model)
	require.NoError(t, err)
	require.NotEmpty(t, qat.Observers)
	require.False(t, qat.Frozen)

	for _, param := range model.Parameters() {
		_, err := qat.FakeQuantize(param)
		require.NoError(t, err)
	}
}

func TestQAT_StepEpoch_FreezesObservers(t *testing.T) {
	t.Parallel()

	qat := NewQATEngine(QATConfig{
		DType:          QINT8,
		NumBits:        8,
		ObserverFreeze: 3,
	})

	for i := 0; i < 5; i++ {
		qat.StepEpoch()
	}
	require.True(t, qat.Frozen)
	require.Equal(t, 5, qat.Epoch)
}

func TestQAT_Convert(t *testing.T) {
	t.Parallel()

	linear, err := nn.NewLinear(4, 2, true)
	require.NoError(t, err)
	model := nn.NewSequential(linear)

	qat := NewQATEngine(DefaultQATConfig())
	_ = qat.Prepare(model)

	// Feed observers
	for _, param := range model.Parameters() {
		_, _ = qat.FakeQuantize(param)
	}

	qModel, err := qat.Convert(model)
	require.NoError(t, err)
	require.NotNil(t, qModel)
}

func TestDefaultQATConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultQATConfig()
	require.Equal(t, QINT8, cfg.DType)
	require.Equal(t, 8, cfg.NumBits)
	require.True(t, cfg.FakeQuantize)
	require.Equal(t, -1, cfg.ObserverFreeze)
}

// ---------------------------------------------------------------------------
// Model Size Utilities
// ---------------------------------------------------------------------------

func TestGetModelSize(t *testing.T) {
	t.Parallel()

	linear, err := nn.NewLinear(16, 8, true)
	require.NoError(t, err)
	model := nn.NewSequential(linear)

	size := GetModelSize(model)
	require.Greater(t, size, int64(0))
}

func TestCompressionRatio(t *testing.T) {
	t.Parallel()

	require.Equal(t, 4.0, CompressionRatio(400, 100))
	require.Equal(t, 0.0, CompressionRatio(400, 0))
}

func TestPrintQuantizationSummary(t *testing.T) {
	t.Parallel()

	linear, err := nn.NewLinear(16, 8, true)
	require.NoError(t, err)
	model := nn.NewSequential(linear)

	dq := NewDynamicQuantizer(QINT8, 8)
	ql, err := dq.QuantizeLinear(linear)
	require.NoError(t, err)

	qModule := &QuantizedModule{
		OriginalModule: model,
		QParams:        map[string]*QParams{"weight": ql.QWeight.Params},
		QTensors:       map[string]*QTensor{"weight": ql.QWeight},
		DType:          QINT8,
	}

	summary := PrintQuantizationSummary(model, qModule)
	require.Contains(t, summary, "Quantization Summary")
	require.Contains(t, summary, "Compression Ratio")
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkQParams_Quantize(b *testing.B) {
	qp := NewQParams(-1.0, 1.0, 8, false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = qp.Quantize(0.42)
	}
}

func BenchmarkQParams_Dequantize(b *testing.B) {
	qp := NewQParams(-1.0, 1.0, 8, false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = qp.Dequantize(42)
	}
}
