package runtime

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// detectGPUDevices probes for available GPU accelerators on the host.
// Currently supports NVIDIA GPUs via nvidia-smi. Additional backends
// (ROCm, Metal, Vulkan) can be added by extending this function.
func detectGPUDevices() []*Device {
	if _, err := exec.LookPath("nvidia-smi"); err != nil {
		return nil
	}

	cmd := exec.Command(
		"nvidia-smi",
		"--query-gpu=name,memory.total,compute_cap",
		"--format=csv,noheader,nounits",
	)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	devices := make([]*Device, 0, len(lines))
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) == 0 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		var totalMemoryBytes uint64 = 8 * 1024 * 1024 * 1024 // conservative default
		if len(parts) > 1 {
			if mib, parseErr := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64); parseErr == nil {
				totalMemoryBytes = mib * 1024 * 1024
			}
		}
		native := nativeGPUEnabled()

		caps := DeviceCapabilities{
			ComputeCapability:       [2]int{0, 0},
			TotalMemory:             totalMemoryBytes,
			MaxThreadsPerBlock:      1024,
			MaxSharedMemoryPerBlock: 49152,
			WarpSize:                32,
			MultiProcessorCount:     1,
			SupportsFP16:            true,
			SupportsBF16:            true,
			SupportsFP8:             false,
			SupportsInt8:            true,
			SupportsInt4:            false,
			SupportsTensorCores:     true,
			SupportsAsyncCopy:       true,
		}

		devices = append(devices, &Device{
			ID:            i,
			Type:          DeviceGPU,
			Name:          fmt.Sprintf("GPU %d: %s", i, name),
			Capabilities:  caps,
			IsAvailable:   true,
			NativeBackend: native,
			BackendName:   gpuBackendName(native),
			memoryPool:    NewMemoryPool(totalMemoryBytes / 2),
		})
	}

	return devices
}

func gpuBackendName(native bool) string {
	if native {
		return "gpu-native"
	}
	return "gpu-detected-no-native-backend"
}
