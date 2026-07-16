package confidential

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
)

// LinearModel is the model class the confidential backends execute today:
// y = W·x + b. This is the honest scope of the FHE and MPC engines — linear /
// affine inference (risk scoring, logistic-regression logits, linear probes).
// Deeper architectures under FHE/MPC are frontier work and are NOT claimed;
// the engines reject models they cannot faithfully execute.
type LinearModel struct {
	ID      string
	Weights [][]float64 // m×n: m outputs, n inputs
	Bias    []float64   // m
}

// Validate checks the model is well-formed (rectangular, bias matches rows).
func (m LinearModel) Validate() error {
	if len(m.Weights) == 0 {
		return fmt.Errorf("linear model %q has no weight rows", m.ID)
	}
	n := len(m.Weights[0])
	if n == 0 {
		return fmt.Errorf("linear model %q has zero input dimension", m.ID)
	}
	for i, row := range m.Weights {
		if len(row) != n {
			return fmt.Errorf("linear model %q row %d has %d columns, expected %d", m.ID, i, len(row), n)
		}
	}
	if len(m.Bias) != len(m.Weights) {
		return fmt.Errorf("linear model %q has %d bias terms for %d rows", m.ID, len(m.Bias), len(m.Weights))
	}
	return nil
}

// InputDim returns the model's input dimension n.
func (m LinearModel) InputDim() int {
	if len(m.Weights) == 0 {
		return 0
	}
	return len(m.Weights[0])
}

// OutputDim returns the model's output dimension m.
func (m LinearModel) OutputDim() int { return len(m.Weights) }

// Hash is the canonical commitment to the model: dimensions, weights, and bias
// in a fixed binary encoding. Bound into ModelRef and the attestation
// measurement so a verifier knows exactly which parameters produced the output.
func (m LinearModel) Hash() []byte {
	h := sha256.New()
	h.Write([]byte("ceap/linear-model/v1;"))
	h.Write([]byte(m.ID))
	var dims [16]byte
	binary.BigEndian.PutUint64(dims[0:8], uint64(m.OutputDim()))
	binary.BigEndian.PutUint64(dims[8:16], uint64(m.InputDim()))
	h.Write(dims[:])
	var buf [8]byte
	for _, row := range m.Weights {
		for _, w := range row {
			binary.BigEndian.PutUint64(buf[:], math.Float64bits(w))
			h.Write(buf[:])
		}
	}
	for _, b := range m.Bias {
		binary.BigEndian.PutUint64(buf[:], math.Float64bits(b))
		h.Write(buf[:])
	}
	return h.Sum(nil)
}

// Apply evaluates the model in the clear: y = W·x + b. Used by tests and by
// verifiers to cross-check confidential results against plaintext ground truth.
func (m LinearModel) Apply(x []float64) ([]float64, error) {
	if len(x) != m.InputDim() {
		return nil, fmt.Errorf("input dimension %d, model expects %d", len(x), m.InputDim())
	}
	out := make([]float64, m.OutputDim())
	for i, row := range m.Weights {
		s := m.Bias[i]
		for j, w := range row {
			s += w * x[j]
		}
		out[i] = s
	}
	return out, nil
}

// checkModelRef verifies the caller-supplied ModelRef matches a registered
// model: the ID must be registered and, when the ref carries a hash, it must
// equal the registered model's canonical hash. This is real enforcement — a
// backend never executes weights the chain did not commit to.
func checkModelRef(models map[string]LinearModel, ref ModelRef) (LinearModel, error) {
	model, ok := models[ref.ModelID]
	if !ok {
		return LinearModel{}, fmt.Errorf("model %q not registered with backend", ref.ModelID)
	}
	if len(ref.ModelHash) > 0 {
		if !bytesEqual(ref.ModelHash, model.Hash()) {
			return LinearModel{}, fmt.Errorf("model %q hash mismatch: ref does not match registered weights", ref.ModelID)
		}
	}
	return model, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
