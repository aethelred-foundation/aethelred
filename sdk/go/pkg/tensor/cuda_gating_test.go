package tensor

import (
	"testing"

	runtimepkg "github.com/aethelred/sdk-go/pkg/runtime"
)

func TestNewTensorRejectsSimulatedGPUWithoutFlag(t *testing.T) {
	t.Setenv("AETH_SDK_ALLOW_SIMULATED_GPU", "0")
	device := runtimepkg.NewSimulatedGPUDevice(0)

	_, err := NewTensor([]int{2, 2}, Float32, device)
	if err != runtimepkg.ErrNativeBackendRequired {
		t.Fatalf("expected ErrNativeBackendRequired, got %v", err)
	}
}

func TestNewTensorAllowsSimulatedGPUWithExplicitFlag(t *testing.T) {
	t.Setenv("AETH_SDK_ALLOW_SIMULATED_GPU", "1")
	device := runtimepkg.NewSimulatedGPUDevice(0)

	tensor, err := NewTensor([]int{2, 2}, Float32, device)
	if err != nil {
		t.Fatalf("expected tensor creation on simulated GPU to succeed with explicit flag, got %v", err)
	}
	tensor.Storage.Release()
}
