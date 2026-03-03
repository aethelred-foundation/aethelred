//go:build aethelred_gpu_native

package runtime

import "testing"

func TestNativeGPUBackendEnabledWithTag(t *testing.T) {
	if !HasNativeGPUBackend() {
		t.Fatalf("expected native GPU backend to be enabled with build tag")
	}
}
