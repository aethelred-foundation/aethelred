// Package fpga provides FPGA acceleration support for Aethelred
// Implements hardware acceleration for zkML proof generation and verification
package fpga

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

// FPGAModel represents supported FPGA hardware
type FPGAModel string

const (
	// XilinxAlveoU200 is the Xilinx Alveo U200 accelerator
	XilinxAlveoU200 FPGAModel = "xilinx_alveo_u200"
	// XilinxAlveoU250 is the Xilinx Alveo U250 accelerator
	XilinxAlveoU250 FPGAModel = "xilinx_alveo_u250"
	// XilinxAlveoU280 is the Xilinx Alveo U280 accelerator (primary for Aethelred)
	XilinxAlveoU280 FPGAModel = "xilinx_alveo_u280"
	// IntelPACD210 is the Intel PAC D210 accelerator
	IntelPACD210 FPGAModel = "intel_pac_d210"
)

// BitstreamType defines FPGA bitstream types
type BitstreamType string

const (
	// MSMBitstream for Multi-Scalar Multiplication
	MSMBitstream BitstreamType = "msm"
	// NTTBitstream for Number Theoretic Transform
	NTTBitstream BitstreamType = "ntt"
	// PoseidonBitstream for Poseidon hash
	PoseidonBitstream BitstreamType = "poseidon"
	// KeccakBitstream for Keccak hash
	KeccakBitstream BitstreamType = "keccak"
	// ECDSABitstream for ECDSA operations
	ECDSABitstream BitstreamType = "ecdsa"
)

// DeviceInfo contains FPGA device information
type DeviceInfo struct {
	Model         FPGAModel
	DeviceID      string
	VendorID      uint16
	DeviceClass   uint16
	MemoryMB      uint64
	PCIeSlot      string
	Temperature   float32
	PowerWatts    float32
	Utilization   float32
	Available     bool
	CurrentKernel string
}

// Bitstream represents an FPGA bitstream
type Bitstream struct {
	Type          BitstreamType
	Version       string
	Hash          [32]byte
	Data          []byte
	SupportedFPGA []FPGAModel
	LoadedOn      *DeviceInfo
}

// OperationResult contains the result of an FPGA operation
type OperationResult struct {
	Success       bool
	Data          []byte
	ExecutionTime time.Duration
	PowerUsed     float32
	Throughput    float64 // Operations per second
}

// FPGAAccelerator manages FPGA hardware acceleration
type FPGAAccelerator struct {
	mu sync.RWMutex

	// Available devices
	devices map[string]*DeviceInfo

	// Loaded bitstreams
	bitstreams map[BitstreamType]*Bitstream

	// Active kernels
	activeKernels map[string]*KernelInstance

	// Configuration
	config *AcceleratorConfig
}

// AcceleratorConfig configures the FPGA accelerator
type AcceleratorConfig struct {
	// Preferred FPGA model
	PreferredModel FPGAModel

	// Maximum power budget in watts
	MaxPowerWatts float32

	// Enable dynamic kernel switching
	DynamicKernelSwitch bool

	// Kernel preload list
	PreloadKernels []BitstreamType
}

// DefaultAcceleratorConfig returns default configuration
func DefaultAcceleratorConfig() *AcceleratorConfig {
	return &AcceleratorConfig{
		PreferredModel:      XilinxAlveoU280,
		MaxPowerWatts:       225, // U280 TDP
		DynamicKernelSwitch: true,
		PreloadKernels:      []BitstreamType{MSMBitstream, NTTBitstream},
	}
}

// KernelInstance represents a loaded FPGA kernel
type KernelInstance struct {
	Type        BitstreamType
	Device      *DeviceInfo
	LoadedAt    time.Time
	CallCount   uint64
	TotalTime   time.Duration
	Handle      uint64
}

// NewFPGAAccelerator creates a new FPGA accelerator
func NewFPGAAccelerator(config *AcceleratorConfig) (*FPGAAccelerator, error) {
	if config == nil {
		config = DefaultAcceleratorConfig()
	}

	acc := &FPGAAccelerator{
		devices:       make(map[string]*DeviceInfo),
		bitstreams:    make(map[BitstreamType]*Bitstream),
		activeKernels: make(map[string]*KernelInstance),
		config:        config,
	}

	// Discover available FPGAs
	if err := acc.discoverDevices(); err != nil {
		return nil, err
	}

	// Preload specified kernels
	for _, kernelType := range config.PreloadKernels {
		if err := acc.LoadBitstream(kernelType); err != nil {
			// Non-fatal: log and continue
			fmt.Printf("Warning: failed to preload kernel %s: %v\n", kernelType, err)
		}
	}

	return acc, nil
}

// discoverDevices discovers available FPGA devices
func (a *FPGAAccelerator) discoverDevices() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// In production, this would:
	// 1. Scan PCIe bus for FPGA devices
	// 2. Query XRT (Xilinx Runtime) or OPAE (Intel)
	// 3. Get device capabilities and status

	// Simulate device discovery
	devices := []DeviceInfo{
		{
			Model:       XilinxAlveoU280,
			DeviceID:    "0000:3b:00.0",
			VendorID:    0x10EE,
			DeviceClass: 0x1200,
			MemoryMB:    8192,
			PCIeSlot:    "3b:00.0",
			Temperature: 45.0,
			PowerWatts:  50.0,
			Utilization: 0.0,
			Available:   true,
		},
	}

	for i := range devices {
		a.devices[devices[i].DeviceID] = &devices[i]
	}

	return nil
}

// GetAvailableDevices returns available FPGA devices
func (a *FPGAAccelerator) GetAvailableDevices() []*DeviceInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()

	devices := make([]*DeviceInfo, 0, len(a.devices))
	for _, d := range a.devices {
		devices = append(devices, d)
	}
	return devices
}

// LoadBitstream loads a bitstream to an available FPGA
func (a *FPGAAccelerator) LoadBitstream(bsType BitstreamType) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Find available device
	var targetDevice *DeviceInfo
	for _, d := range a.devices {
		if d.Available && d.Model == a.config.PreferredModel {
			targetDevice = d
			break
		}
	}

	if targetDevice == nil {
		// Try any available device
		for _, d := range a.devices {
			if d.Available {
				targetDevice = d
				break
			}
		}
	}

	if targetDevice == nil {
		return errors.New("no available FPGA device")
	}

	// In production, this would:
	// 1. Load bitstream file from disk
	// 2. Verify bitstream compatibility
	// 3. Program FPGA using XRT or OPAE
	// 4. Initialize kernel

	// Simulate bitstream loading
	bs := &Bitstream{
		Type:          bsType,
		Version:       "1.0.0",
		SupportedFPGA: []FPGAModel{XilinxAlveoU280, XilinxAlveoU250},
		LoadedOn:      targetDevice,
	}
	bs.Hash = sha256.Sum256([]byte(fmt.Sprintf("%s-%s", bsType, bs.Version)))

	a.bitstreams[bsType] = bs

	// Create kernel instance
	kernelID := fmt.Sprintf("%s-%s", targetDevice.DeviceID, bsType)
	a.activeKernels[kernelID] = &KernelInstance{
		Type:     bsType,
		Device:   targetDevice,
		LoadedAt: time.Now(),
		Handle:   uint64(time.Now().UnixNano()),
	}

	targetDevice.CurrentKernel = string(bsType)
	targetDevice.Available = false

	return nil
}

// UnloadBitstream unloads a bitstream from FPGA
func (a *FPGAAccelerator) UnloadBitstream(bsType BitstreamType) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	bs, exists := a.bitstreams[bsType]
	if !exists {
		return errors.New("bitstream not loaded")
	}

	// Free device
	if bs.LoadedOn != nil {
		bs.LoadedOn.Available = true
		bs.LoadedOn.CurrentKernel = ""
	}

	// Remove kernel instance
	for id, kernel := range a.activeKernels {
		if kernel.Type == bsType {
			delete(a.activeKernels, id)
		}
	}

	delete(a.bitstreams, bsType)
	return nil
}

// ExecuteMSM executes Multi-Scalar Multiplication on FPGA
func (a *FPGAAccelerator) ExecuteMSM(ctx context.Context, points [][]byte, scalars [][]byte) (*OperationResult, error) {
	kernel, err := a.getKernel(MSMBitstream)
	if err != nil {
		return nil, err
	}

	startTime := time.Now()

	// In production, this would:
	// 1. Transfer points and scalars to FPGA memory
	// 2. Start kernel execution
	// 3. Wait for completion
	// 4. Read result from FPGA memory

	// Simulate MSM execution
	result := make([]byte, 64) // G1 point
	h := sha256.New()
	for _, p := range points {
		h.Write(p)
	}
	for _, s := range scalars {
		h.Write(s)
	}
	copy(result, h.Sum(nil))

	// Update kernel stats
	a.mu.Lock()
	kernel.CallCount++
	execTime := time.Since(startTime)
	kernel.TotalTime += execTime
	a.mu.Unlock()

	return &OperationResult{
		Success:       true,
		Data:          result,
		ExecutionTime: execTime,
		PowerUsed:     100.0,
		Throughput:    float64(len(points)) / execTime.Seconds(),
	}, nil
}

// ExecuteNTT executes Number Theoretic Transform on FPGA
func (a *FPGAAccelerator) ExecuteNTT(ctx context.Context, coefficients []uint64, inverse bool) (*OperationResult, error) {
	kernel, err := a.getKernel(NTTBitstream)
	if err != nil {
		return nil, err
	}

	startTime := time.Now()

	// In production, this would:
	// 1. Transfer coefficients to FPGA
	// 2. Execute NTT kernel
	// 3. Return transformed coefficients

	// Simulate NTT execution
	result := make([]byte, len(coefficients)*8)
	for i, c := range coefficients {
		result[i*8] = byte(c)
	}

	a.mu.Lock()
	kernel.CallCount++
	execTime := time.Since(startTime)
	kernel.TotalTime += execTime
	a.mu.Unlock()

	return &OperationResult{
		Success:       true,
		Data:          result,
		ExecutionTime: execTime,
		PowerUsed:     80.0,
		Throughput:    float64(len(coefficients)) / execTime.Seconds(),
	}, nil
}

// ExecutePoseidonHash executes Poseidon hash on FPGA
func (a *FPGAAccelerator) ExecutePoseidonHash(ctx context.Context, inputs [][]byte) (*OperationResult, error) {
	kernel, err := a.getKernel(PoseidonBitstream)
	if err != nil {
		return nil, err
	}

	startTime := time.Now()

	// Simulate Poseidon hash
	result := make([]byte, 32)
	h := sha256.New()
	h.Write([]byte("poseidon"))
	for _, input := range inputs {
		h.Write(input)
	}
	copy(result, h.Sum(nil))

	a.mu.Lock()
	kernel.CallCount++
	execTime := time.Since(startTime)
	kernel.TotalTime += execTime
	a.mu.Unlock()

	return &OperationResult{
		Success:       true,
		Data:          result,
		ExecutionTime: execTime,
		PowerUsed:     60.0,
		Throughput:    float64(len(inputs)) / execTime.Seconds(),
	}, nil
}

// getKernel gets or loads a kernel
func (a *FPGAAccelerator) getKernel(bsType BitstreamType) (*KernelInstance, error) {
	a.mu.RLock()

	// Find existing kernel
	for _, kernel := range a.activeKernels {
		if kernel.Type == bsType {
			a.mu.RUnlock()
			return kernel, nil
		}
	}
	a.mu.RUnlock()

	// Need to load kernel
	if a.config.DynamicKernelSwitch {
		if err := a.LoadBitstream(bsType); err != nil {
			return nil, err
		}
		return a.getKernel(bsType)
	}

	return nil, fmt.Errorf("kernel %s not loaded", bsType)
}

// GetStats returns accelerator statistics
type AcceleratorStats struct {
	TotalDevices     int
	AvailableDevices int
	LoadedKernels    int
	TotalOperations  uint64
	TotalComputeTime time.Duration
	AveragePower     float32
}

// GetStats returns current statistics
func (a *FPGAAccelerator) GetStats() AcceleratorStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	stats := AcceleratorStats{
		TotalDevices:  len(a.devices),
		LoadedKernels: len(a.activeKernels),
	}

	var totalPower float32
	for _, d := range a.devices {
		if d.Available {
			stats.AvailableDevices++
		}
		totalPower += d.PowerWatts
	}
	if len(a.devices) > 0 {
		stats.AveragePower = totalPower / float32(len(a.devices))
	}

	for _, k := range a.activeKernels {
		stats.TotalOperations += k.CallCount
		stats.TotalComputeTime += k.TotalTime
	}

	return stats
}

// Close shuts down the accelerator
func (a *FPGAAccelerator) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Unload all bitstreams
	for bsType := range a.bitstreams {
		if bs := a.bitstreams[bsType]; bs.LoadedOn != nil {
			bs.LoadedOn.Available = true
			bs.LoadedOn.CurrentKernel = ""
		}
	}

	a.bitstreams = make(map[BitstreamType]*Bitstream)
	a.activeKernels = make(map[string]*KernelInstance)

	return nil
}

// BitstreamManager manages FPGA bitstream files
type BitstreamManager struct {
	// Bitstream storage path
	storagePath string

	// Registry of available bitstreams
	registry map[BitstreamType]BitstreamInfo
}

// BitstreamInfo contains bitstream metadata
type BitstreamInfo struct {
	Type          BitstreamType
	Version       string
	Hash          string
	FilePath      string
	SupportedFPGA []FPGAModel
	Size          int64
}

// NewBitstreamManager creates a new bitstream manager
func NewBitstreamManager(storagePath string) *BitstreamManager {
	return &BitstreamManager{
		storagePath: storagePath,
		registry:    make(map[BitstreamType]BitstreamInfo),
	}
}

// RegisterBitstream registers a bitstream in the manager
func (m *BitstreamManager) RegisterBitstream(info BitstreamInfo) {
	m.registry[info.Type] = info
}

// GetBitstream retrieves bitstream info
func (m *BitstreamManager) GetBitstream(bsType BitstreamType) (BitstreamInfo, bool) {
	info, exists := m.registry[bsType]
	return info, exists
}

// ListBitstreams returns all registered bitstreams
func (m *BitstreamManager) ListBitstreams() []BitstreamInfo {
	list := make([]BitstreamInfo, 0, len(m.registry))
	for _, info := range m.registry {
		list = append(list, info)
	}
	return list
}

// GetBitstreamHash returns the hash of a bitstream
func (m *BitstreamManager) GetBitstreamHash(bsType BitstreamType) (string, error) {
	info, exists := m.registry[bsType]
	if !exists {
		return "", fmt.Errorf("bitstream %s not found", bsType)
	}
	return info.Hash, nil
}
