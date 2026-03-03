package runtime

import (
	"os"
	"strconv"
)

const simulatedGPUEnv = "AETHEL_SDK_ALLOW_SIMULATED_GPU"

// NewRuntime returns the singleton runtime instance.
func NewRuntime() *Runtime {
	return Instance()
}

// CPU returns the default CPU device.
func CPU() *Device {
	rt := Instance()
	if !rt.IsInitialized() {
		_ = rt.Initialize()
	}

	for _, device := range rt.Devices() {
		if device.Type == DeviceCPU {
			return device
		}
	}
	return NewCPUDevice()
}

// GPU returns a GPU accelerator device by index.
//
// If no physical GPU device exists, the returned device will be marked unavailable.
// Tensor allocation on this device will fail closed unless simulated GPU mode is
// explicitly enabled via AETHEL_SDK_ALLOW_SIMULATED_GPU=1.
func GPU(index int) *Device {
	rt := Instance()
	if !rt.IsInitialized() {
		_ = rt.Initialize()
	}

	gpuDevices := make([]*Device, 0, 2)
	for _, device := range rt.Devices() {
		if device.Type == DeviceGPU {
			gpuDevices = append(gpuDevices, device)
		}
	}

	if index >= 0 && index < len(gpuDevices) {
		return gpuDevices[index]
	}

	return &Device{
		ID:            index,
		Type:          DeviceGPU,
		Name:          "GPU (unavailable)",
		Capabilities:  DeviceCapabilities{},
		IsAvailable:   false,
		NativeBackend: false,
		BackendName:   "none",
		memoryPool:    NewMemoryPool(1024 * 1024),
	}
}

// HasPhysicalGPU returns true when GPU hardware is detected on the host.
func HasPhysicalGPU() bool {
	rt := Instance()
	if !rt.IsInitialized() {
		_ = rt.Initialize()
	}
	for _, device := range rt.Devices() {
		if device.Type == DeviceGPU {
			return true
		}
	}
	return false
}

// HasNativeGPUBackend reports whether this build includes native GPU dispatch.
func HasNativeGPUBackend() bool {
	return nativeGPUEnabled()
}

// NewSimulatedGPUDevice creates an explicit simulation-only GPU device for
// local development and testing.
func NewSimulatedGPUDevice(index int) *Device {
	return &Device{
		ID:   index,
		Type: DeviceGPU,
		Name: "GPU (simulated)",
		Capabilities: DeviceCapabilities{
			ComputeCapability: [2]int{8, 0},
			TotalMemory:       8 * 1024 * 1024 * 1024,
			WarpSize:          32,
		},
		IsAvailable:   true,
		NativeBackend: false,
		BackendName:   "simulated",
		memoryPool:    NewMemoryPool(4 * 1024 * 1024 * 1024),
	}
}

// AllowSimulatedGPU returns true only when explicit simulation mode is enabled.
func AllowSimulatedGPU() bool {
	value := os.Getenv(simulatedGPUEnv)
	enabled, err := strconv.ParseBool(value)
	return err == nil && enabled
}
