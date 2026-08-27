package confidential

import (
	"bytes"
	"testing"
)

func TestLinearModel_Validate(t *testing.T) {
	valid := fheTestModel()
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid model rejected: %v", err)
	}
	cases := map[string]LinearModel{
		"no rows":       {ID: "a"},
		"zero dim":      {ID: "b", Weights: [][]float64{{}}, Bias: []float64{0}},
		"ragged":        {ID: "c", Weights: [][]float64{{1, 2}, {1}}, Bias: []float64{0, 0}},
		"bias mismatch": {ID: "d", Weights: [][]float64{{1, 2}}, Bias: []float64{0, 0}},
	}
	for name, m := range cases {
		if err := m.Validate(); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestLinearModel_Dims(t *testing.T) {
	m := fheTestModel()
	if m.InputDim() != 3 || m.OutputDim() != 2 {
		t.Errorf("dims = %d×%d, want 2×3", m.OutputDim(), m.InputDim())
	}
	empty := LinearModel{}
	if empty.InputDim() != 0 || empty.OutputDim() != 0 {
		t.Error("empty model must report zero dims")
	}
}

func TestLinearModel_HashStableAndSensitive(t *testing.T) {
	m1 := fheTestModel()
	m2 := fheTestModel()
	if !bytes.Equal(m1.Hash(), m2.Hash()) {
		t.Fatal("hash must be deterministic")
	}
	m2.Weights[0][0] += 1e-9
	if bytes.Equal(m1.Hash(), m2.Hash()) {
		t.Fatal("hash must change when any weight changes")
	}
	m3 := fheTestModel()
	m3.Bias[1] = 42
	if bytes.Equal(m1.Hash(), m3.Hash()) {
		t.Fatal("hash must change when a bias changes")
	}
}

func TestLinearModel_Apply(t *testing.T) {
	m := fheTestModel()
	got, err := m.Apply([]float64{1, 1, 1})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Row 0: 0.5 - 1.25 + 2.0 + 0.25 = 1.5; Row 1: 1.0 + 0.75 - 0.5 - 1.0 = 0.25
	if got[0] != 1.5 || got[1] != 0.25 {
		t.Errorf("apply = %v, want [1.5 0.25]", got)
	}
	if _, err := m.Apply([]float64{1}); err == nil {
		t.Error("dimension mismatch must be rejected")
	}
}

func TestCheckModelRef(t *testing.T) {
	m := fheTestModel()
	models := map[string]LinearModel{m.ID: m}

	if _, err := checkModelRef(models, ModelRef{ModelID: "missing"}); err == nil {
		t.Error("unregistered model must be rejected")
	}
	if _, err := checkModelRef(models, ModelRef{ModelID: m.ID, ModelHash: []byte("bad")}); err == nil {
		t.Error("hash mismatch must be rejected")
	}
	if _, err := checkModelRef(models, ModelRef{ModelID: m.ID}); err != nil {
		t.Errorf("hashless ref must resolve: %v", err)
	}
	if _, err := checkModelRef(models, ModelRef{ModelID: m.ID, ModelHash: m.Hash()}); err != nil {
		t.Errorf("matching hash must resolve: %v", err)
	}
}

func TestBytesEqual(t *testing.T) {
	if !bytesEqual([]byte{1, 2}, []byte{1, 2}) {
		t.Error("equal slices")
	}
	if bytesEqual([]byte{1, 2}, []byte{1, 3}) {
		t.Error("differing content")
	}
	if bytesEqual([]byte{1}, []byte{1, 2}) {
		t.Error("differing length")
	}
}
