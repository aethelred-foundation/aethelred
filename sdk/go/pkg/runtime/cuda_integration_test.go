package runtime

import (
	"os"
	"testing"
)

func TestGPUHardwareProbeIntegration(t *testing.T) {
	if os.Getenv("AETH_SDK_RUN_GPU_INTEGRATION") != "1" {
		t.Skip("set AETH_SDK_RUN_GPU_INTEGRATION=1 to run GPU hardware integration checks")
	}
	if !HasPhysicalGPU() {
		t.Skip("no GPU hardware detected on host")
	}

	device := GPU(0)
	if device == nil {
		t.Fatalf("expected GPU(0) to return a device")
	}
	if device.Type != DeviceGPU {
		t.Fatalf("expected GPU device type, got %s", device.Type.String())
	}

	// Enforce native backend only when explicitly required by the operator.
	if os.Getenv("AETH_SDK_REQUIRE_NATIVE_GPU") == "1" && !device.NativeBackend {
		t.Fatalf("native GPU backend required but not enabled")
	}
	if !device.NativeBackend {
		t.Setenv(simulatedGPUEnv, "1")
	}

	block, err := device.Allocate(1024)
	if err != nil {
		t.Fatalf("expected GPU allocation smoke check to pass, got %v", err)
	}
	if err := device.Free(block); err != nil {
		t.Fatalf("expected GPU allocation cleanup to succeed, got %v", err)
	}
}
