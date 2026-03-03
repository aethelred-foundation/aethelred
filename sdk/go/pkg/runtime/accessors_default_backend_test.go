//go:build !aethelred_gpu_native

package runtime

import "testing"

func TestNativeGPUBackendDefaultDisabled(t *testing.T) {
	if HasNativeGPUBackend() {
		t.Fatalf("expected native GPU backend to be disabled without build tag")
	}
}
