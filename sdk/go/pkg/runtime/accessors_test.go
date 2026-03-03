package runtime

import "testing"

func TestCPUDeviceAlwaysAvailable(t *testing.T) {
	device := CPU()
	if device == nil {
		t.Fatalf("CPU() returned nil device")
	}
	if device.Type != DeviceCPU {
		t.Fatalf("expected CPU device, got %s", device.Type.String())
	}
	if !device.IsAvailable {
		t.Fatalf("CPU device should be available")
	}
}

func TestSimulatedGPURequiresExplicitFlag(t *testing.T) {
	device := NewSimulatedGPUDevice(0)
	if device.Type != DeviceGPU {
		t.Fatalf("expected simulated GPU device type, got %s", device.Type.String())
	}

	// Without explicit simulation flag, allocation must fail closed.
	t.Setenv(simulatedGPUEnv, "0")
	if _, err := device.Allocate(256); err != ErrNativeBackendRequired {
		t.Fatalf("expected ErrNativeBackendRequired, got %v", err)
	}

	// With explicit simulation flag, allocation is allowed for local/dev tests.
	t.Setenv(simulatedGPUEnv, "1")
	block, err := device.Allocate(256)
	if err != nil {
		t.Fatalf("expected simulated allocation to succeed, got %v", err)
	}
	if err := device.Free(block); err != nil {
		t.Fatalf("expected free to succeed, got %v", err)
	}
}

func TestGPUFallbackDeviceUnavailable(t *testing.T) {
	// Very high index should always be unavailable even on GPU hosts.
	device := GPU(9999)
	if device == nil {
		t.Fatalf("GPU fallback returned nil")
	}
	if device.Type != DeviceGPU {
		t.Fatalf("expected GPU device type, got %s", device.Type.String())
	}
	if device.IsAvailable {
		t.Fatalf("fallback GPU index should not be available")
	}
}
