package halo2

import (
	"testing"
)

func TestNewField(t *testing.T) {
	t.Parallel()
	f := NewField(42)
	if f.Limbs[0] != 42 {
		t.Errorf("expected Limbs[0]=42, got %d", f.Limbs[0])
	}
	for i := 1; i < 4; i++ {
		if f.Limbs[i] != 0 {
			t.Errorf("expected Limbs[%d]=0, got %d", i, f.Limbs[i])
		}
	}
}

func TestNewFieldFromBytes(t *testing.T) {
	t.Parallel()
	b := make([]byte, 32)
	b[0] = 1
	f := NewFieldFromBytes(b)
	if f.Limbs[0] != 1 {
		t.Errorf("expected Limbs[0]=1, got %d", f.Limbs[0])
	}
}

func TestNewFieldFromBytes_Short(t *testing.T) {
	t.Parallel()
	b := []byte{1, 0, 0, 0, 0, 0, 0, 0} // Only 8 bytes (1 limb)
	f := NewFieldFromBytes(b)
	if f.Limbs[0] != 1 {
		t.Errorf("expected Limbs[0]=1, got %d", f.Limbs[0])
	}
}

func TestField_ToBytes(t *testing.T) {
	t.Parallel()
	f := NewField(256)
	b := f.ToBytes()
	if len(b) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(b))
	}
	// 256 = 0x100, little-endian: [0, 1, 0, 0, ...]
	if b[0] != 0 || b[1] != 1 {
		t.Errorf("unexpected bytes: %v", b[:8])
	}
}

func TestField_RoundTrip(t *testing.T) {
	t.Parallel()
	original := NewField(123456789)
	bytes := original.ToBytes()
	restored := NewFieldFromBytes(bytes)
	if original.Limbs[0] != restored.Limbs[0] {
		t.Error("round-trip failed")
	}
}

func TestCircuitTypeConstants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ct   CircuitType
		want string
	}{
		{LinearLayerCircuit, "linear"},
		{Conv2DCircuit, "conv2d"},
		{ReLUCircuit, "relu"},
		{SoftmaxCircuit, "softmax"},
		{BatchNormCircuit, "batchnorm"},
		{MaxPoolCircuit, "maxpool"},
		{TreeEnsembleCircuit, "tree_ensemble"},
	}
	for _, tt := range tests {
		if string(tt.ct) != tt.want {
			t.Errorf("expected %q, got %q", tt.want, tt.ct)
		}
	}
}

func TestNewCircuitBuilder(t *testing.T) {
	t.Parallel()
	b := NewCircuitBuilder(LinearLayerCircuit)
	if b.circuitType != LinearLayerCircuit {
		t.Error("circuit type mismatch")
	}
	if b.config == nil {
		t.Error("config should not be nil")
	}
}

func TestCircuitBuilder_WithConfig(t *testing.T) {
	t.Parallel()
	b := NewCircuitBuilder(LinearLayerCircuit)
	cfg := &CircuitConfig{InputSize: 64, OutputSize: 32}
	result := b.WithConfig(cfg)
	if result != b {
		t.Error("WithConfig should return same builder")
	}
	if b.config.InputSize != 64 {
		t.Error("config not applied")
	}
}

func TestCircuitBuilder_Build_Linear(t *testing.T) {
	t.Parallel()
	b := NewCircuitBuilder(LinearLayerCircuit)
	b.WithConfig(&CircuitConfig{InputSize: 64, OutputSize: 32})
	circuit, err := b.Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if circuit == nil {
		t.Fatal("circuit is nil")
	}
	if circuit.Type != LinearLayerCircuit {
		t.Errorf("expected LinearLayerCircuit, got %v", circuit.Type)
	}
	if circuit.ID == "" {
		t.Error("circuit ID should not be empty")
	}
	if circuit.K == 0 {
		t.Error("K should not be 0")
	}
	if circuit.NumAdvice != 3 {
		t.Errorf("expected 3 advice cols for linear, got %d", circuit.NumAdvice)
	}
}

func TestCircuitBuilder_Build_Conv2D(t *testing.T) {
	t.Parallel()
	b := NewCircuitBuilder(Conv2DCircuit)
	b.WithConfig(&CircuitConfig{InChannels: 3, OutChannels: 32, KernelSize: 3})
	circuit, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if circuit.NumAdvice != 5 {
		t.Errorf("expected 5 advice cols for conv2d, got %d", circuit.NumAdvice)
	}
}

func TestCircuitBuilder_Build_TreeEnsemble(t *testing.T) {
	t.Parallel()
	b := NewCircuitBuilder(TreeEnsembleCircuit)
	b.WithConfig(&CircuitConfig{NumTrees: 10, MaxDepth: 5})
	circuit, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if circuit.NumAdvice != 4 {
		t.Errorf("expected 4 advice cols for tree ensemble, got %d", circuit.NumAdvice)
	}
}

func TestCeilLog2(t *testing.T) {
	t.Parallel()
	tests := []struct {
		n    uint32
		want uint32
	}{
		{0, 1},
		{1, 1},
		{2, 1},
		{3, 2},
		{4, 2},
		{5, 3},
		{8, 3},
		{9, 4},
		{1024, 10},
	}
	for _, tt := range tests {
		got := ceilLog2(tt.n)
		if got != tt.want {
			t.Errorf("ceilLog2(%d) = %d, want %d", tt.n, got, tt.want)
		}
	}
}

func TestNewProver(t *testing.T) {
	t.Parallel()
	setup := &KZGSetup{MaxDegree: 1 << 16}
	p := NewProver(setup)
	if p == nil {
		t.Fatal("prover is nil")
	}
	if p.setup != setup {
		t.Error("setup mismatch")
	}
}

func TestProver_LoadCircuit(t *testing.T) {
	t.Parallel()
	p := NewProver(&KZGSetup{})
	circuit := &Circuit{ID: "test-circuit"}
	err := p.LoadCircuit(circuit)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.circuits["test-circuit"]; !ok {
		t.Error("circuit not loaded")
	}
}

func TestProver_Prove(t *testing.T) {
	t.Parallel()
	b := NewCircuitBuilder(LinearLayerCircuit)
	b.WithConfig(&CircuitConfig{InputSize: 4, OutputSize: 2})
	circuit, _ := b.Build()

	p := NewProver(&KZGSetup{})
	_ = p.LoadCircuit(circuit)

	witness := []Field{NewField(1), NewField(2)}
	publicInputs := []Field{NewField(3)}

	proof, err := p.Prove(circuit.ID, witness, publicInputs)
	if err != nil {
		t.Fatalf("Prove() error: %v", err)
	}
	if proof == nil {
		t.Fatal("proof is nil")
	}
	if proof.CircuitID != circuit.ID {
		t.Error("circuit ID mismatch")
	}
	if len(proof.ProofData) < 32 {
		t.Error("proof data too short")
	}
	if proof.Metadata == nil {
		t.Error("metadata is nil")
	}
}

func TestProver_Prove_CircuitNotFound(t *testing.T) {
	t.Parallel()
	p := NewProver(&KZGSetup{})
	_, err := p.Prove("nonexistent", nil, nil)
	if err == nil {
		t.Error("expected circuit not found error")
	}
}

func TestNewVerifier(t *testing.T) {
	t.Parallel()
	v := NewVerifier(&KZGSetup{})
	if v == nil {
		t.Fatal("verifier is nil")
	}
}

func TestVerifier_LoadVerifyingKey(t *testing.T) {
	t.Parallel()
	v := NewVerifier(&KZGSetup{})
	vk := &VerifyingKey{CircuitID: "test"}
	err := v.LoadVerifyingKey(vk)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifier_Verify_Valid(t *testing.T) {
	t.Parallel()
	v := NewVerifier(&KZGSetup{})
	vk := &VerifyingKey{CircuitID: "test"}
	_ = v.LoadVerifyingKey(vk)

	proof := &Proof{
		CircuitID:    "test",
		ProofData:    make([]byte, 192),
		PublicInputs: []Field{NewField(1)},
	}

	valid, err := v.Verify(proof)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if !valid {
		t.Error("expected valid proof")
	}
}

func TestVerifier_Verify_MissingVK(t *testing.T) {
	t.Parallel()
	v := NewVerifier(&KZGSetup{})
	proof := &Proof{CircuitID: "nonexistent"}
	_, err := v.Verify(proof)
	if err == nil {
		t.Error("expected verifying key not found error")
	}
}

func TestVerifier_Verify_ShortProof(t *testing.T) {
	t.Parallel()
	v := NewVerifier(&KZGSetup{})
	_ = v.LoadVerifyingKey(&VerifyingKey{CircuitID: "test"})
	proof := &Proof{
		CircuitID:    "test",
		ProofData:    make([]byte, 10), // too short
		PublicInputs: []Field{NewField(1)},
	}
	valid, err := v.Verify(proof)
	if err == nil {
		t.Error("expected error for short proof")
	}
	if valid {
		t.Error("should not be valid")
	}
}

func TestVerifier_Verify_NoPublicInputs(t *testing.T) {
	t.Parallel()
	v := NewVerifier(&KZGSetup{})
	_ = v.LoadVerifyingKey(&VerifyingKey{CircuitID: "test"})
	proof := &Proof{
		CircuitID:    "test",
		ProofData:    make([]byte, 192),
		PublicInputs: nil,
	}
	valid, err := v.Verify(proof)
	if err == nil {
		t.Error("expected error for no public inputs")
	}
	if valid {
		t.Error("should not be valid")
	}
}

func TestGenerateVerifyingKey(t *testing.T) {
	t.Parallel()
	b := NewCircuitBuilder(LinearLayerCircuit)
	b.WithConfig(&CircuitConfig{InputSize: 4, OutputSize: 2})
	circuit, _ := b.Build()

	setup := &KZGSetup{Hash: [32]byte{1, 2, 3}}
	vk, err := GenerateVerifyingKey(circuit, setup)
	if err != nil {
		t.Fatal(err)
	}
	if vk.CircuitID != circuit.ID {
		t.Error("circuit ID mismatch")
	}
	if vk.Hash == [32]byte{} {
		t.Error("VK hash should not be zero")
	}
	if vk.SetupHash != setup.Hash {
		t.Error("setup hash mismatch")
	}
}

func TestLoadKZGSetup(t *testing.T) {
	t.Parallel()
	data := make([]byte, 128)
	setup, err := LoadKZGSetup(data)
	if err != nil {
		t.Fatal(err)
	}
	if setup.MaxDegree != 1<<16 {
		t.Errorf("expected MaxDegree 2^16, got %d", setup.MaxDegree)
	}
	if setup.Hash == [32]byte{} {
		t.Error("hash should not be zero")
	}
}

func TestLoadKZGSetup_TooShort(t *testing.T) {
	t.Parallel()
	_, err := LoadKZGSetup([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for short setup data")
	}
}

func TestGenerateKZGSetup(t *testing.T) {
	t.Parallel()
	setup, err := GenerateKZGSetup(16)
	if err != nil {
		t.Fatal(err)
	}
	if setup.MaxDegree != 1<<16 {
		t.Errorf("expected MaxDegree 2^16, got %d", setup.MaxDegree)
	}
}
