package optim

import (
	"testing"

	"github.com/aethelred/sdk-go/pkg/nn"
	"github.com/aethelred/sdk-go/pkg/runtime"
	"github.com/aethelred/sdk-go/pkg/tensor"
)

func makeTestParams() []*nn.Parameter {
	device := runtime.NewCPUDevice()
	t1, err := tensor.FromSlice([]float32{1.0, 2.0, 3.0}, []int{3}, device)
	if err != nil {
		panic(err)
	}
	t2, err := tensor.FromSlice([]float32{4.0, 5.0}, []int{2}, device)
	if err != nil {
		panic(err)
	}
	return []*nn.Parameter{
		nn.NewParameter(t1, "weight"),
		nn.NewParameter(t2, "bias"),
	}
}

func TestDefaultParamGroup(t *testing.T) {
	t.Parallel()

	params := makeTestParams()
	pg := DefaultParamGroup(params, 0.01)
	if pg.LR != 0.01 {
		t.Fatalf("LR = %f, want 0.01", pg.LR)
	}
	if len(pg.Params) != 2 {
		t.Fatalf("Params len = %d, want 2", len(pg.Params))
	}
}

func TestNewSGD(t *testing.T) {
	t.Parallel()

	params := makeTestParams()
	sgd := NewSGD(params, 0.01, 0.9, 0.0, 0.001, false)
	if sgd == nil {
		t.Fatal("NewSGD returned nil")
	}
	if sgd.GetLR() != 0.01 {
		t.Fatalf("LR = %f", sgd.GetLR())
	}
}

func TestNewAdam(t *testing.T) {
	t.Parallel()

	params := makeTestParams()
	adam := NewAdam(params, 0.001, [2]float64{0.9, 0.999}, 1e-8, 0.0, false)
	if adam == nil {
		t.Fatal("NewAdam returned nil")
	}
	if adam.GetLR() != 0.001 {
		t.Fatalf("LR = %f", adam.GetLR())
	}
}

func TestNewAdamW(t *testing.T) {
	t.Parallel()

	params := makeTestParams()
	adamw := NewAdamW(params, 0.001, [2]float64{0.9, 0.999}, 1e-8, 0.01, false)
	if adamw == nil {
		t.Fatal("NewAdamW returned nil")
	}
}

func TestSetLR(t *testing.T) {
	t.Parallel()

	params := makeTestParams()
	sgd := NewSGD(params, 0.01, 0.0, 0.0, 0.0, false)
	sgd.SetLR(0.05)
	if sgd.GetLR() != 0.05 {
		t.Fatalf("SetLR: got %f, want 0.05", sgd.GetLR())
	}
}

func TestZeroGrad(t *testing.T) {
	t.Parallel()

	params := makeTestParams()
	sgd := NewSGD(params, 0.01, 0.0, 0.0, 0.0, false)
	// Should not panic
	sgd.ZeroGrad()
}

func TestParamGroups(t *testing.T) {
	t.Parallel()

	params := makeTestParams()
	sgd := NewSGD(params, 0.01, 0.0, 0.0, 0.0, false)
	pgs := sgd.ParamGroups()
	if len(pgs) != 1 {
		t.Fatalf("ParamGroups len = %d, want 1", len(pgs))
	}
}

func TestState(t *testing.T) {
	t.Parallel()

	params := makeTestParams()
	adam := NewAdam(params, 0.001, [2]float64{0.9, 0.999}, 1e-8, 0.0, false)
	state := adam.State()
	if state == nil {
		t.Fatal("State returned nil")
	}
}
