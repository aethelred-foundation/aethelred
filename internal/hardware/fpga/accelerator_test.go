package fpga

import (
	"context"
	"testing"
)

func TestDefaultAcceleratorConfig(t *testing.T) {
	t.Parallel()
	cfg := DefaultAcceleratorConfig()
	if cfg.PreferredModel != XilinxAlveoU280 {
		t.Errorf("expected XilinxAlveoU280, got %v", cfg.PreferredModel)
	}
	if cfg.MaxPowerWatts != 225 {
		t.Errorf("expected 225W, got %v", cfg.MaxPowerWatts)
	}
	if !cfg.DynamicKernelSwitch {
		t.Error("expected DynamicKernelSwitch=true")
	}
	if len(cfg.PreloadKernels) != 2 {
		t.Errorf("expected 2 preload kernels, got %d", len(cfg.PreloadKernels))
	}
}

func TestNewFPGAAccelerator(t *testing.T) {
	t.Parallel()
	acc, err := NewFPGAAccelerator(nil)
	if err != nil {
		t.Fatalf("NewFPGAAccelerator() error: %v", err)
	}
	if acc == nil {
		t.Fatal("accelerator is nil")
	}
	devices := acc.GetAvailableDevices()
	if len(devices) == 0 {
		t.Error("expected at least one discovered device")
	}
}

func TestNewFPGAAccelerator_CustomConfig(t *testing.T) {
	t.Parallel()
	cfg := &AcceleratorConfig{
		PreferredModel:      XilinxAlveoU250,
		MaxPowerWatts:       200,
		DynamicKernelSwitch: false,
		PreloadKernels:      nil,
	}
	acc, err := NewFPGAAccelerator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if acc.config.PreferredModel != XilinxAlveoU250 {
		t.Error("config not applied")
	}
}

func TestGetAvailableDevices(t *testing.T) {
	t.Parallel()
	acc, _ := NewFPGAAccelerator(&AcceleratorConfig{
		PreferredModel:      XilinxAlveoU280,
		DynamicKernelSwitch: false,
		PreloadKernels:      nil,
	})
	devices := acc.GetAvailableDevices()
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
	d := devices[0]
	if d.Model != XilinxAlveoU280 {
		t.Errorf("expected XilinxAlveoU280, got %v", d.Model)
	}
	if !d.Available {
		t.Error("device should be available")
	}
	if d.MemoryMB != 8192 {
		t.Errorf("expected 8192MB, got %d", d.MemoryMB)
	}
}

func TestLoadBitstream(t *testing.T) {
	t.Parallel()
	acc, _ := NewFPGAAccelerator(&AcceleratorConfig{
		PreferredModel:      XilinxAlveoU280,
		DynamicKernelSwitch: false,
		PreloadKernels:      nil,
	})
	err := acc.LoadBitstream(MSMBitstream)
	if err != nil {
		t.Fatalf("LoadBitstream() error: %v", err)
	}

	// Device should now be unavailable
	devices := acc.GetAvailableDevices()
	for _, d := range devices {
		if d.CurrentKernel == string(MSMBitstream) && d.Available {
			t.Error("device with loaded bitstream should not be available")
		}
	}
}

func TestLoadBitstream_NoDevice(t *testing.T) {
	t.Parallel()
	acc, _ := NewFPGAAccelerator(&AcceleratorConfig{
		PreferredModel:      XilinxAlveoU280,
		DynamicKernelSwitch: false,
		PreloadKernels:      nil,
	})
	// Load first bitstream to make device unavailable
	acc.LoadBitstream(MSMBitstream)
	// Second load should fail
	err := acc.LoadBitstream(NTTBitstream)
	if err == nil {
		t.Error("expected error when no device available")
	}
}

func TestUnloadBitstream(t *testing.T) {
	t.Parallel()
	acc, _ := NewFPGAAccelerator(&AcceleratorConfig{
		PreferredModel:      XilinxAlveoU280,
		DynamicKernelSwitch: false,
		PreloadKernels:      nil,
	})
	acc.LoadBitstream(MSMBitstream)
	err := acc.UnloadBitstream(MSMBitstream)
	if err != nil {
		t.Fatalf("UnloadBitstream() error: %v", err)
	}
}

func TestUnloadBitstream_NotLoaded(t *testing.T) {
	t.Parallel()
	acc, _ := NewFPGAAccelerator(&AcceleratorConfig{
		PreferredModel:      XilinxAlveoU280,
		DynamicKernelSwitch: false,
		PreloadKernels:      nil,
	})
	err := acc.UnloadBitstream(MSMBitstream)
	if err == nil {
		t.Error("expected error for not-loaded bitstream")
	}
}

func TestExecuteMSM(t *testing.T) {
	t.Parallel()
	acc, _ := NewFPGAAccelerator(&AcceleratorConfig{
		PreferredModel:      XilinxAlveoU280,
		DynamicKernelSwitch: true,
		PreloadKernels:      nil,
	})
	points := [][]byte{{1, 2, 3}, {4, 5, 6}}
	scalars := [][]byte{{7, 8, 9}, {10, 11, 12}}

	result, err := acc.ExecuteMSM(context.Background(), points, scalars)
	if err != nil {
		t.Fatalf("ExecuteMSM() error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if len(result.Data) != 64 {
		t.Errorf("expected 64 byte result, got %d", len(result.Data))
	}
	if result.ExecutionTime <= 0 {
		t.Error("execution time should be positive")
	}
}

func TestExecuteNTT(t *testing.T) {
	t.Parallel()
	acc, _ := NewFPGAAccelerator(&AcceleratorConfig{
		PreferredModel:      XilinxAlveoU280,
		DynamicKernelSwitch: true,
		PreloadKernels:      nil,
	})
	coefficients := []uint64{1, 2, 3, 4}
	result, err := acc.ExecuteNTT(context.Background(), coefficients, false)
	if err != nil {
		t.Fatalf("ExecuteNTT() error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
}

func TestExecutePoseidonHash(t *testing.T) {
	t.Parallel()
	acc, _ := NewFPGAAccelerator(&AcceleratorConfig{
		PreferredModel:      XilinxAlveoU280,
		DynamicKernelSwitch: true,
		PreloadKernels:      nil,
	})
	inputs := [][]byte{{1, 2}, {3, 4}}
	result, err := acc.ExecutePoseidonHash(context.Background(), inputs)
	if err != nil {
		t.Fatalf("ExecutePoseidonHash() error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if len(result.Data) != 32 {
		t.Errorf("expected 32 byte hash, got %d", len(result.Data))
	}
}

func TestGetStats(t *testing.T) {
	t.Parallel()
	acc, _ := NewFPGAAccelerator(&AcceleratorConfig{
		PreferredModel:      XilinxAlveoU280,
		DynamicKernelSwitch: true,
		PreloadKernels:      nil,
	})
	stats := acc.GetStats()
	if stats.TotalDevices != 1 {
		t.Errorf("expected 1 device, got %d", stats.TotalDevices)
	}
	if stats.AvailableDevices != 1 {
		t.Errorf("expected 1 available, got %d", stats.AvailableDevices)
	}

	// Execute an operation and check stats again
	acc.ExecuteMSM(context.Background(), [][]byte{{1}}, [][]byte{{2}})
	stats = acc.GetStats()
	if stats.TotalOperations == 0 {
		t.Error("expected non-zero operations after execution")
	}
}

func TestClose(t *testing.T) {
	t.Parallel()
	acc, _ := NewFPGAAccelerator(&AcceleratorConfig{
		PreferredModel:      XilinxAlveoU280,
		DynamicKernelSwitch: true,
		PreloadKernels:      nil,
	})
	acc.LoadBitstream(MSMBitstream)
	err := acc.Close()
	if err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	stats := acc.GetStats()
	if stats.LoadedKernels != 0 {
		t.Errorf("expected 0 loaded kernels after close, got %d", stats.LoadedKernels)
	}
}

func TestNewBitstreamManager(t *testing.T) {
	t.Parallel()
	m := NewBitstreamManager("/path/to/bitstreams")
	if m == nil {
		t.Fatal("manager is nil")
	}
	if m.storagePath != "/path/to/bitstreams" {
		t.Errorf("unexpected storage path: %q", m.storagePath)
	}
}

func TestBitstreamManager_RegisterAndGet(t *testing.T) {
	t.Parallel()
	m := NewBitstreamManager("/tmp")
	info := BitstreamInfo{
		Type:          MSMBitstream,
		Version:       "1.0",
		Hash:          "abc123",
		FilePath:      "/tmp/msm.xclbin",
		SupportedFPGA: []FPGAModel{XilinxAlveoU280},
		Size:          1024,
	}
	m.RegisterBitstream(info)

	got, exists := m.GetBitstream(MSMBitstream)
	if !exists {
		t.Fatal("expected bitstream to exist")
	}
	if got.Version != "1.0" {
		t.Errorf("expected version 1.0, got %q", got.Version)
	}
}

func TestBitstreamManager_GetNotFound(t *testing.T) {
	t.Parallel()
	m := NewBitstreamManager("/tmp")
	_, exists := m.GetBitstream(NTTBitstream)
	if exists {
		t.Error("expected bitstream to not exist")
	}
}

func TestBitstreamManager_ListBitstreams(t *testing.T) {
	t.Parallel()
	m := NewBitstreamManager("/tmp")
	m.RegisterBitstream(BitstreamInfo{Type: MSMBitstream})
	m.RegisterBitstream(BitstreamInfo{Type: NTTBitstream})

	list := m.ListBitstreams()
	if len(list) != 2 {
		t.Errorf("expected 2 bitstreams, got %d", len(list))
	}
}

func TestBitstreamManager_GetBitstreamHash(t *testing.T) {
	t.Parallel()
	m := NewBitstreamManager("/tmp")
	m.RegisterBitstream(BitstreamInfo{Type: MSMBitstream, Hash: "abc"})

	hash, err := m.GetBitstreamHash(MSMBitstream)
	if err != nil {
		t.Fatal(err)
	}
	if hash != "abc" {
		t.Errorf("expected hash 'abc', got %q", hash)
	}

	_, err = m.GetBitstreamHash(NTTBitstream)
	if err == nil {
		t.Error("expected error for missing bitstream")
	}
}

func TestFPGAModelConstants(t *testing.T) {
	t.Parallel()
	if XilinxAlveoU200 != "xilinx_alveo_u200" {
		t.Error("constant mismatch")
	}
	if XilinxAlveoU250 != "xilinx_alveo_u250" {
		t.Error("constant mismatch")
	}
	if XilinxAlveoU280 != "xilinx_alveo_u280" {
		t.Error("constant mismatch")
	}
	if IntelPACD210 != "intel_pac_d210" {
		t.Error("constant mismatch")
	}
}

func TestBitstreamTypeConstants(t *testing.T) {
	t.Parallel()
	if MSMBitstream != "msm" {
		t.Error("constant mismatch")
	}
	if NTTBitstream != "ntt" {
		t.Error("constant mismatch")
	}
	if PoseidonBitstream != "poseidon" {
		t.Error("constant mismatch")
	}
	if KeccakBitstream != "keccak" {
		t.Error("constant mismatch")
	}
	if ECDSABitstream != "ecdsa" {
		t.Error("constant mismatch")
	}
}

func TestGetKernel_DynamicSwitchDisabled(t *testing.T) {
	t.Parallel()
	acc, _ := NewFPGAAccelerator(&AcceleratorConfig{
		PreferredModel:      XilinxAlveoU280,
		DynamicKernelSwitch: false,
		PreloadKernels:      nil,
	})
	// Without loading any bitstream and dynamic switching off,
	// executing should fail because no kernel is loaded
	_, err := acc.ExecuteMSM(context.Background(), [][]byte{{1}}, [][]byte{{2}})
	if err == nil {
		t.Error("expected error when kernel not loaded and dynamic switch disabled")
	}
}

func TestExecuteNTT_Inverse(t *testing.T) {
	t.Parallel()
	acc, _ := NewFPGAAccelerator(&AcceleratorConfig{
		PreferredModel:      XilinxAlveoU280,
		DynamicKernelSwitch: true,
		PreloadKernels:      nil,
	})
	coefficients := []uint64{1, 2, 3, 4}
	result, err := acc.ExecuteNTT(context.Background(), coefficients, true) // inverse=true
	if err != nil {
		t.Fatalf("ExecuteNTT(inverse=true) error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
}

func TestGetStats_AfterMultipleOps(t *testing.T) {
	t.Parallel()
	acc, _ := NewFPGAAccelerator(&AcceleratorConfig{
		PreferredModel:      XilinxAlveoU280,
		DynamicKernelSwitch: true,
		PreloadKernels:      nil,
	})

	// Perform multiple operations
	acc.ExecuteMSM(context.Background(), [][]byte{{1}}, [][]byte{{2}})
	acc.ExecuteMSM(context.Background(), [][]byte{{3}}, [][]byte{{4}})

	stats := acc.GetStats()
	if stats.TotalOperations < 2 {
		t.Errorf("expected at least 2 total operations, got %d", stats.TotalOperations)
	}
	if stats.TotalComputeTime <= 0 {
		t.Error("expected positive total compute time")
	}
}

func TestClose_NoKernels(t *testing.T) {
	t.Parallel()
	acc, _ := NewFPGAAccelerator(&AcceleratorConfig{
		PreferredModel:      XilinxAlveoU280,
		DynamicKernelSwitch: false,
		PreloadKernels:      nil,
	})
	// Close without loading any kernels
	err := acc.Close()
	if err != nil {
		t.Fatalf("Close() error: %v", err)
	}
}

func TestLoadBitstream_NonPreferredDevice(t *testing.T) {
	t.Parallel()
	// Use a non-matching preferred model so it falls through to any available device
	acc, _ := NewFPGAAccelerator(&AcceleratorConfig{
		PreferredModel:      IntelPACD210, // Doesn't match discovered device (U280)
		DynamicKernelSwitch: false,
		PreloadKernels:      nil,
	})
	err := acc.LoadBitstream(MSMBitstream)
	if err != nil {
		t.Fatalf("LoadBitstream() error: %v", err)
	}
}
