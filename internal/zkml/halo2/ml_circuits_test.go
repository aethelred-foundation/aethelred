package halo2

import (
	"testing"
)

func TestDefaultQuantizationConfig(t *testing.T) {
	t.Parallel()
	qc := DefaultQuantizationConfig()
	if qc.Bits != 8 {
		t.Errorf("expected 8 bits, got %d", qc.Bits)
	}
	if qc.Scale != 256 {
		t.Errorf("expected scale=256, got %d", qc.Scale)
	}
	if qc.ZeroPoint != 0 {
		t.Errorf("expected zero point=0, got %d", qc.ZeroPoint)
	}
	if !qc.Symmetric {
		t.Error("expected Symmetric=true")
	}
}

func TestNewMLCircuitBuilder(t *testing.T) {
	t.Parallel()
	b := NewMLCircuitBuilder("test-model")
	if b.name != "test-model" {
		t.Errorf("expected name 'test-model', got %q", b.name)
	}
	if len(b.layers) != 0 {
		t.Error("expected empty layers")
	}
	if b.quantization == nil {
		t.Error("expected default quantization")
	}
}

func TestMLCircuitBuilder_WithQuantization(t *testing.T) {
	t.Parallel()
	b := NewMLCircuitBuilder("test")
	qc := &QuantizationConfig{Bits: 16, Scale: 1024}
	result := b.WithQuantization(qc)
	if result != b {
		t.Error("WithQuantization should return same builder")
	}
	if b.quantization.Bits != 16 {
		t.Error("quantization not applied")
	}
}

func TestMLCircuitBuilder_AddLinearLayer(t *testing.T) {
	t.Parallel()
	b := NewMLCircuitBuilder("test")
	result := b.AddLinearLayer(64, 32, "relu")
	if result != b {
		t.Error("AddLinearLayer should return same builder")
	}
	if len(b.layers) != 1 {
		t.Fatalf("expected 1 layer, got %d", len(b.layers))
	}
	if b.layers[0].Type != "linear" {
		t.Error("expected linear type")
	}
	if b.layers[0].InputSize != 64 {
		t.Errorf("expected input=64, got %d", b.layers[0].InputSize)
	}
	if b.layers[0].OutputSize != 32 {
		t.Errorf("expected output=32, got %d", b.layers[0].OutputSize)
	}
	if b.layers[0].Activation != "relu" {
		t.Errorf("expected activation 'relu', got %q", b.layers[0].Activation)
	}
}

func TestMLCircuitBuilder_AddConv2DLayer(t *testing.T) {
	t.Parallel()
	b := NewMLCircuitBuilder("test")
	b.AddConv2DLayer(3, 32, 3, 1, 1)
	if len(b.layers) != 1 {
		t.Fatal("expected 1 layer")
	}
	if b.layers[0].Type != "conv2d" {
		t.Error("expected conv2d type")
	}
	if b.layers[0].Params["kernel_size"] != 3 {
		t.Error("expected kernel_size=3")
	}
}

func TestMLCircuitBuilder_AddMaxPoolLayer(t *testing.T) {
	t.Parallel()
	b := NewMLCircuitBuilder("test")
	b.AddMaxPoolLayer(2, 2)
	if b.layers[0].Type != "maxpool" {
		t.Error("expected maxpool type")
	}
}

func TestMLCircuitBuilder_AddBatchNormLayer(t *testing.T) {
	t.Parallel()
	b := NewMLCircuitBuilder("test")
	b.AddBatchNormLayer()
	if b.layers[0].Type != "batchnorm" {
		t.Error("expected batchnorm type")
	}
}

func TestMLCircuitBuilder_AddDropoutLayer(t *testing.T) {
	t.Parallel()
	b := NewMLCircuitBuilder("test")
	result := b.AddDropoutLayer(0.5)
	if result != b {
		t.Error("should return same builder")
	}
	// Dropout should be a no-op (not added to layers)
	if len(b.layers) != 0 {
		t.Error("dropout should not add a layer")
	}
}

func TestMLCircuitBuilder_Build_NoLayers(t *testing.T) {
	t.Parallel()
	b := NewMLCircuitBuilder("empty")
	_, err := b.Build()
	if err == nil {
		t.Error("expected error for no layers")
	}
}

func TestMLCircuitBuilder_Build_SimpleModel(t *testing.T) {
	t.Parallel()
	b := NewMLCircuitBuilder("simple")
	b.AddLinearLayer(64, 32, "relu")
	b.AddLinearLayer(32, 1, "sigmoid")

	circuit, err := b.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if circuit == nil {
		t.Fatal("circuit is nil")
	}
	if circuit.Config.InputSize != 64 {
		t.Errorf("expected InputSize=64, got %d", circuit.Config.InputSize)
	}
	if circuit.Config.OutputSize != 1 {
		t.Errorf("expected OutputSize=1, got %d", circuit.Config.OutputSize)
	}
	if circuit.Config.NumLayers != 2 {
		t.Errorf("expected 2 layers, got %d", circuit.Config.NumLayers)
	}
}

func TestEstimateLayerConstraints(t *testing.T) {
	t.Parallel()
	b := NewMLCircuitBuilder("test")

	tests := []struct {
		layer    LayerConfig
		expected int
	}{
		{
			LayerConfig{Type: "linear", InputSize: 4, OutputSize: 2},
			4*2 + 2, // 10
		},
		{
			LayerConfig{Type: "relu", InputSize: 10},
			10,
		},
		{
			LayerConfig{Type: "softmax", InputSize: 10},
			30,
		},
		{
			LayerConfig{Type: "batchnorm", InputSize: 10},
			40,
		},
		{
			LayerConfig{Type: "unknown"},
			100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.layer.Type, func(t *testing.T) {
			t.Parallel()
			got := b.estimateLayerConstraints(tt.layer)
			if got != tt.expected {
				t.Errorf("estimateLayerConstraints(%q) = %d, want %d", tt.layer.Type, got, tt.expected)
			}
		})
	}
}

func TestNewTreeEnsembleCircuitBuilder(t *testing.T) {
	t.Parallel()
	b := NewTreeEnsembleCircuitBuilder(10, 5, 20, 2)
	if b.numTrees != 10 {
		t.Errorf("expected 10 trees, got %d", b.numTrees)
	}
	if b.maxDepth != 5 {
		t.Errorf("expected depth 5, got %d", b.maxDepth)
	}
	if b.numFeatures != 20 {
		t.Errorf("expected 20 features, got %d", b.numFeatures)
	}
	if b.numClasses != 2 {
		t.Errorf("expected 2 classes, got %d", b.numClasses)
	}
}

func TestTreeEnsembleCircuitBuilder_AddTree(t *testing.T) {
	t.Parallel()
	b := NewTreeEnsembleCircuitBuilder(5, 3, 10, 2)
	tree := TreeDefinition{
		Features:      []int{0, 1, 2},
		Thresholds:    []float64{0.5, 0.3, 0.7},
		LeftChildren:  []int{1, -1, -1},
		RightChildren: []int{2, -1, -1},
		LeafValues:    []float64{0.0, 1.0, 0.0, 1.0},
	}
	result := b.AddTree(tree)
	if result != b {
		t.Error("AddTree should return same builder")
	}
	if len(b.trees) != 1 {
		t.Errorf("expected 1 tree, got %d", len(b.trees))
	}
}

func TestTreeEnsembleCircuitBuilder_Build_NoTrees(t *testing.T) {
	t.Parallel()
	b := NewTreeEnsembleCircuitBuilder(5, 3, 10, 2)
	_, err := b.Build()
	if err == nil {
		t.Error("expected error for no trees")
	}
}

func TestTreeEnsembleCircuitBuilder_Build(t *testing.T) {
	t.Parallel()
	b := NewTreeEnsembleCircuitBuilder(2, 3, 5, 2)
	tree := TreeDefinition{
		Features:      make([]int, 7),
		Thresholds:    make([]float64, 7),
		LeftChildren:  make([]int, 7),
		RightChildren: make([]int, 7),
		LeafValues:    make([]float64, 8),
	}
	b.AddTree(tree)
	b.AddTree(tree)

	circuit, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if circuit == nil {
		t.Fatal("circuit is nil")
	}
	if circuit.Type != TreeEnsembleCircuit {
		t.Error("expected TreeEnsembleCircuit type")
	}
}

func TestCreditScoringCircuit(t *testing.T) {
	t.Parallel()
	circuit, err := CreditScoringCircuit(20, []int{64, 32})
	if err != nil {
		t.Fatalf("CreditScoringCircuit() error: %v", err)
	}
	if circuit == nil {
		t.Fatal("circuit is nil")
	}
}

func TestFraudDetectionCircuit(t *testing.T) {
	t.Parallel()
	circuit, err := FraudDetectionCircuit(15, 10, 5)
	if err != nil {
		t.Fatalf("FraudDetectionCircuit() error: %v", err)
	}
	if circuit == nil {
		t.Fatal("circuit is nil")
	}
}

func TestImageClassificationCircuit(t *testing.T) {
	t.Parallel()
	// Use small input size to keep constraints under 1M limit
	circuit, err := ImageClassificationCircuit(1, 8, 2)
	if err != nil {
		t.Fatalf("ImageClassificationCircuit() error: %v", err)
	}
	if circuit == nil {
		t.Fatal("circuit is nil")
	}
}

func TestConvertONNXToCircuit(t *testing.T) {
	t.Parallel()
	circuit, err := ConvertONNXToCircuit([]byte("onnx data"))
	if err != nil {
		t.Fatalf("ConvertONNXToCircuit() error: %v", err)
	}
	if circuit == nil {
		t.Fatal("circuit is nil")
	}
}

func TestConvertONNXToCircuit_Empty(t *testing.T) {
	t.Parallel()
	_, err := ConvertONNXToCircuit(nil)
	if err == nil {
		t.Error("expected error for empty ONNX data")
	}
}

func TestConvertPyTorchToCircuit(t *testing.T) {
	t.Parallel()
	circuit, err := ConvertPyTorchToCircuit([]byte("torch data"))
	if err != nil {
		t.Fatalf("ConvertPyTorchToCircuit() error: %v", err)
	}
	if circuit == nil {
		t.Fatal("circuit is nil")
	}
}

func TestConvertPyTorchToCircuit_Empty(t *testing.T) {
	t.Parallel()
	_, err := ConvertPyTorchToCircuit(nil)
	if err == nil {
		t.Error("expected error for empty TorchScript data")
	}
}
